"""Concurrent TCP file-sharing server (line-based protocol).

Protocol (every control message is one UTF-8 line ending in \\n):
  C: AUTH <user> <password>        S: OK | ERR <reason>
  C: LIST                          S: OK <nbytes>\\n then <nbytes> of text
  C: UPLOAD <name> <size>          S: READY | ERR <reason>
     C: <size> raw bytes           S: OK | ERR <reason>
  C: DOWNLOAD <name>               S: OK <size>\\n then <size> raw bytes | ERR <reason>
  C: QUIT                          S: BYE

Application events are appended (one JSON object per line) to events.jsonl so
the SDN controller can react to them. Mininet hosts share the filesystem with
the controller process, so a file is the simplest reliable channel.
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import socket
import threading
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.join(BASE_DIR, "shared_files")
METADATA_FILE = os.path.join(BASE_DIR, "metadata.json")
EVENTS_FILE = os.path.join(BASE_DIR, "events.jsonl")

MAX_FILE_SIZE = 1 << 30          # 1 GiB
MAX_LOGIN_ATTEMPTS = 3           # per connection
SOCKET_TIMEOUT = 60              # seconds of silence before dropping a client
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")

_meta_lock = threading.Lock()
_event_lock = threading.Lock()


# ---------------------------------------------------------------- users
def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)


def _make_users():
    users = {}
    for name, pw in (("admin", "1234"), ("alice", "alice123"), ("bob", "bob123"),
                     ("carol", "carol123"), ("prof", "prof123")):
        salt = os.urandom(16)
        users[name] = (salt, _hash(pw, salt))
    return users


USERS = _make_users()


def check_login(user, password):
    entry = USERS.get(user)
    if entry is None:
        _hash(password, b"x" * 16)  # keep timing similar for unknown users
        return False
    salt, digest = entry
    return hmac.compare_digest(digest, _hash(password, salt))


# --------------------------------------------------------------- helpers
def log_event(kind, **fields):
    rec = {"ts": round(time.time(), 3), "event": kind}
    rec.update(fields)
    line = json.dumps(rec)
    with _event_lock:
        with open(EVENTS_FILE, "a") as f:
            f.write(line + "\n")
    print(line, flush=True)


def safe_name(name):
    return bool(NAME_RE.match(name)) and name not in (".", "..")


def update_metadata(name, size, uploader):
    with _meta_lock:
        meta = {}
        if os.path.exists(METADATA_FILE):
            try:
                with open(METADATA_FILE) as f:
                    meta = json.load(f)
            except (ValueError, OSError):
                meta = {}
        meta[name] = {
            "size": size,
            "uploader": uploader,
            "upload_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        tmp = METADATA_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(meta, f, indent=4)
        os.replace(tmp, METADATA_FILE)


class Conn:
    """Buffered reader/writer so message boundaries never depend on recv()."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def readline(self, limit=1024):
        while b"\n" not in self.buf:
            if len(self.buf) > limit:
                raise ValueError("line too long")
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("peer closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").strip()

    def read_exact(self, n):
        """Yield chunks totalling exactly n bytes."""
        while n > 0:
            if self.buf:
                chunk, self.buf = self.buf[:n], self.buf[n:]
            else:
                chunk = self.sock.recv(min(65536, n))
                if not chunk:
                    raise ConnectionError("peer closed mid-transfer")
            n -= len(chunk)
            yield chunk

    def send_line(self, text):
        self.sock.sendall(text.encode() + b"\n")


# --------------------------------------------------------------- handler
def handle_client(sock, addr):
    ip = addr[0]
    c = Conn(sock)
    user = None
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        # ---- authentication
        attempts = 0
        while user is None:
            parts = c.readline().split(" ", 2)
            if len(parts) == 3 and parts[0] == "AUTH" and check_login(parts[1], parts[2]):
                user = parts[1]
                c.send_line("OK")
                log_event("AUTH_OK", ip=ip, user=user)
            else:
                attempts += 1
                log_event("AUTH_FAIL", ip=ip, attempt=attempts)
                c.send_line("ERR authentication failed")
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    return

        # ---- commands
        while True:
            line = c.readline()
            cmd, _, rest = line.partition(" ")
            cmd = cmd.upper()

            if cmd == "LIST":
                meta = {}
                if os.path.exists(METADATA_FILE):
                    with _meta_lock, open(METADATA_FILE) as f:
                        try:
                            meta = json.load(f)
                        except ValueError:
                            meta = {}
                rows = []
                for n in sorted(os.listdir(SHARED_DIR)):
                    p = os.path.join(SHARED_DIR, n)
                    if os.path.isfile(p) and not n.endswith(".part"):
                        who = meta.get(n, {}).get("uploader", "-")
                        rows.append(f"{n}\t{os.path.getsize(p)}\t{who}")
                body = ("\n".join(rows) if rows else "(no files)").encode()
                c.send_line(f"OK {len(body)}")
                sock.sendall(body)

            elif cmd == "UPLOAD":
                try:
                    name, size_s = rest.rsplit(" ", 1)
                    size = int(size_s)
                except ValueError:
                    c.send_line("ERR usage: UPLOAD <name> <size>")
                    continue
                if not safe_name(name):
                    c.send_line("ERR invalid file name")
                    continue
                if not 0 <= size <= MAX_FILE_SIZE:
                    c.send_line("ERR invalid size")
                    continue
                c.send_line("READY")
                final = os.path.join(SHARED_DIR, name)
                part = f"{final}.{threading.get_ident()}.part"
                try:
                    with open(part, "wb") as f:
                        for chunk in c.read_exact(size):
                            f.write(chunk)
                    os.replace(part, final)
                except Exception:
                    if os.path.exists(part):
                        os.remove(part)  # never keep a partial upload
                    log_event("UPLOAD_FAILED", ip=ip, user=user, name=name)
                    raise
                update_metadata(name, size, user)
                log_event("UPLOAD", ip=ip, user=user, name=name, bytes=size)
                c.send_line("OK")

            elif cmd == "DOWNLOAD":
                name = rest.strip()
                path = os.path.join(SHARED_DIR, name)
                if not safe_name(name) or not os.path.isfile(path):
                    c.send_line("ERR file not found")
                    continue
                size = os.path.getsize(path)
                c.send_line(f"OK {size}")
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        sock.sendall(chunk)
                log_event("DOWNLOAD", ip=ip, user=user, name=name, bytes=size)

            elif cmd == "QUIT":
                c.send_line("BYE")
                return

            else:
                c.send_line("ERR unknown command")

    except (ConnectionError, socket.timeout, ValueError, OSError) as e:
        print(f"[{ip}] connection ended: {e}", flush=True)
    finally:
        try:
            sock.close()
        except OSError:
            pass
        print(f"[{ip}] disconnected", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    os.makedirs(SHARED_DIR, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(128)
    print(f"File server listening on {args.host}:{args.port}", flush=True)
    while True:
        sock, addr = srv.accept()
        threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()


if __name__ == "__main__":
    main()

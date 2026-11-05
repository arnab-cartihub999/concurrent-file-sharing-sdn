"""CampusShare - assignment submission and course-material portal.

An application built on top of the TCP file-sharing system.  Students submit
assignments, faculty publish course materials and grade submissions, and the
admin can see everything.  The files themselves are stored on the file server
(server.py) and every upload / download travels over a normal TCP connection
made with fsclient.py, through the Open vSwitch and the OS-Ken controller.

This process is the application layer:
  * roles (student / faculty / admin) and access rules,
  * courses, assignments, due dates, late flags, grades (portal.json),
  * the HTTP/JSON API and the browser page,
  * a live panel with the controller's bandwidth and policy events.

    python3 webapp.py                              # then open http://localhost:8080
    python3 webapp.py --server-host 127.0.0.1      # local test without Mininet
"""
import argparse
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
from collections import deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from fsclient import FSClient, FSError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_UPLOAD = 1 << 30                      # same limit as the server (1 GiB)
CONNECT_TIMEOUT = 6                       # a blocked host times out here
PORT_LABELS = {1: "h1", 2: "h2", 3: "h3", 4: "File server", 5: "Web gateway (this app)"}
EVENT_RE = re.compile(r"(BLOCK|UNBLOCK|HOG_LIMIT|HOG_UNLIMIT|STATIC_BLOCK)")

# --- roles: the file server only knows user names and passwords; the portal adds roles
ROLES = {"admin": "admin", "prof": "faculty", "alice": "student", "bob": "student",
         "carol": "student"}
STUDENTS = [u for u, r in ROLES.items() if r == "student"]
DUE_FMT = "%Y-%m-%d %H:%M"

CFG = {}                                   # filled from the command line
SESSIONS = {}                              # token -> (user, password), kept in memory only
_plock = threading.Lock()
ACT = deque(maxlen=80)                     # recent actions, shown on the Network activity page
_alock = threading.Lock()


def rate(size, ms):
    return round(size * 8 / 1e6 / (ms / 1000.0), 2) if size and ms else None


def log_act(user, role, action, detail="", size=0, ms=None, ok=True, sha=None):
    rec = {"ts": time.time(), "t": time.strftime("%H:%M:%S"), "user": user, "role": role,
           "action": action, "detail": detail, "bytes": size,
           "ms": None if ms is None else round(ms), "mbps": rate(size, ms), "ok": ok, "sha": sha}
    with _alock:
        ACT.appendleft(rec)


class Blocked(Exception):
    """The file server could not be reached (timeout / refused)."""


class Denied(Exception):
    def __init__(self, msg, status=403):
        super().__init__(msg)
        self.status = status


def role_of(user):
    return ROLES.get(user, "student")


# ------------------------------------------------------------ portal data
def _seed():
    def due(days):
        return time.strftime("%Y-%m-%d", time.localtime(time.time() + days * 86400)) + " 23:59"
    return {
        "courses": [{"code": "CN101", "name": "Computer Networks"},
                    {"code": "DS201", "name": "Data Structures"}],
        "assignments": [
            {"id": "CN101-A1", "course": "CN101", "title": "Socket programming lab report",
             "desc": "Submit your TCP client/server report as a PDF.", "due": due(3), "by": "prof"},
            {"id": "CN101-A2", "course": "CN101", "title": "SDN mini-project proposal",
             "desc": "One page: topology, controller policies and test plan.", "due": due(9), "by": "prof"},
            {"id": "DS201-A1", "course": "DS201", "title": "Linked list implementation",
             "desc": "Source file plus a short README.", "due": due(6), "by": "prof"},
        ],
        "submissions": {}, "grades": {},
    }


def load_portal():
    path = CFG["portal"]
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return _seed()


def mutate(fn):
    """Load portal.json, apply fn(data), save atomically."""
    with _plock:
        data = load_portal()
        result = fn(data)
        tmp = CFG["portal"] + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, CFG["portal"])
        return result


def is_late(due, now=None):
    try:
        return (now or time.time()) > time.mktime(time.strptime(due, DUE_FMT))
    except ValueError:
        return False


def find_assignment(data, aid):
    return next((a for a in data["assignments"] if a["id"] == aid), None)


def course_ok(data, code):
    return any(c["code"] == code for c in data["courses"])


# ------------------------------------------------------------ file naming
def clean_name(raw):
    """Turn a browser file name into one the server accepts."""
    name = os.path.basename(raw.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:100]
    if not name or not name[0].isalnum():
        name = "f" + name
    return name[:100]


def server_name(prefix, orig):
    room = 100 - len(prefix)
    base = clean_name(orig)
    return prefix + (base[-room:] if len(base) > room else base)


def can_download(user, role, fname):
    """Access rule enforced by the portal for every download."""
    if fname.startswith("MAT_"):
        return True                                   # course materials: everyone signed in
    if fname.startswith("SUB_"):
        parts = fname.split("_", 3)                   # SUB, assignment, student, file
        if len(parts) < 4:
            return False
        return role in ("faculty", "admin") or parts[2] == user
    return False


def open_client(user, password):
    try:
        c = FSClient(CFG["server_host"], CFG["server_port"], timeout=CONNECT_TIMEOUT)
    except OSError as e:                    # includes timeouts and refused connections
        raise Blocked(str(e))
    c.sock.settimeout(120)
    try:
        c.login(user, password)
    except FSError:
        c.sock.close()
        raise
    except OSError as e:
        c.sock.close()
        raise Blocked(str(e))
    return c


# --------------------------------------------------------------- SDN panel
def tail_lines(path, max_bytes=16384):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []


def sdn_status():
    lines = tail_lines(CFG["events_log"])
    starts = [i for i, l in enumerate(lines) if "CONTROLLER_START" in l]
    if starts:
        lines = lines[starts[-1]:]               # only what this controller run has done
    events = [l for l in lines if EVENT_RE.search(l)][-8:]
    latest, ts_max = {}, 0.0
    for line in tail_lines(CFG["stats"], 4096)[1:]:
        parts = line.split(",")
        if len(parts) != 4:
            continue
        try:
            ts, port, rx, tx = float(parts[0]), int(parts[1]), float(parts[2]), float(parts[3])
        except ValueError:
            continue
        if ts >= latest.get(port, (0,))[0]:
            latest[port] = (ts, rx, tx)
        ts_max = max(ts_max, ts)
    age = time.time() - ts_max if ts_max else None
    ports = []
    for port in sorted(latest):
        _, rx, tx = latest[port]
        label = PORT_LABELS.get(port, "port %d" % port)
        # rx/tx are from the switch's point of view. "down" = data flowing towards
        # clients (downloads), "up" = data flowing towards the server (uploads).
        down, up = (rx, tx) if port == 4 else (tx, rx)
        ports.append({"port": port, "label": label, "up": round(up, 2), "down": round(down, 2)})
    return {"events": events, "ports": ports, "age": None if age is None else round(age, 1)}


# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "CampusShare/1.0"

    def log_message(self, fmt, *args):
        pass

    # -- helpers
    def send_json(self, obj, status=200, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 8192:
            return {}
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    def token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = SimpleCookie()
        c.load(raw)
        return c["fs_session"].value if "fs_session" in c else None

    def creds(self):
        return SESSIONS.get(self.token())

    def fail(self, e):
        try:
            self._fail(e)
        except OSError:
            pass                              # browser went away; nothing more to send

    def _fail(self, e):
        if isinstance(e, Blocked):
            self.send_json({"error": "Cannot reach the file server. If you just failed several "
                            "logins, the SDN controller has blocked this host for 30 seconds.",
                            "blocked": True}, 503)
        elif isinstance(e, Denied):
            self.send_json({"error": str(e)}, e.status)
        elif isinstance(e, FSError):
            msg = str(e)
            if msg.startswith("ERR "):
                msg = msg[4:]
            self.send_json({"error": msg}, 401 if "authentication" in msg else 400)
        else:
            self.send_json({"error": "Transfer failed: %s" % e}, 502)

    def need(self, *roles):
        creds = self.creds()
        if not creds:
            raise Denied("Please log in.", 401)
        if roles and role_of(creds[0]) not in roles:
            raise Denied("Your role is not allowed to do this.", 403)
        return creds[0], role_of(creds[0])

    def guarded(self, fn):
        try:
            fn()
        except (Blocked, Denied, FSError, OSError) as e:
            self.fail(e)

    # -- routing
    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/":
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif url.path == "/api/sdn":
            self.send_json(sdn_status())
        elif url.path == "/api/me":
            c = self.creds()
            self.send_json({"user": c[0] if c else None, "role": role_of(c[0]) if c else None,
                            "server": "%s:%s" % (CFG["server_host"], CFG["server_port"])})
        elif url.path == "/api/activity":
            self.guarded(self.api_activity)
        elif url.path == "/api/portal":
            self.guarded(self.api_portal)
        elif url.path == "/api/review":
            self.guarded(lambda: self.api_review(q.get("aid", [""])[0]))
        elif url.path == "/api/download":
            self.guarded(lambda: self.api_download(q.get("name", [""])[0]))
        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/api/login":
            self.guarded(self.api_login)
        elif url.path == "/api/logout":
            SESSIONS.pop(self.token(), None)
            self.send_json({"ok": True},
                           headers={"Set-Cookie": "fs_session=; Max-Age=0; Path=/; HttpOnly"})
        elif url.path == "/api/assignment":
            self.guarded(self.api_new_assignment)
        elif url.path == "/api/grade":
            self.guarded(self.api_grade)
        elif url.path == "/api/submit":
            self.guarded(lambda: self.api_submit(q.get("aid", [""])[0], q.get("name", [""])[0]))
        elif url.path == "/api/material":
            self.guarded(lambda: self.api_material(q.get("course", [""])[0], q.get("name", [""])[0]))
        else:
            self.send_json({"error": "not found"}, 404)

    # -- API: session
    def api_login(self):
        data = self.read_json()
        user, pw = str(data.get("user", "")).strip(), str(data.get("password", ""))
        if not user or not pw or any(ch.isspace() for ch in user + pw):
            raise Denied("Enter a username and password (no spaces).", 400)
        try:
            c = open_client(user, pw)
        except FSError:
            log_act(user, "-", "Sign-in failed", "Wrong username or password", ok=False)
            raise
        except Blocked:
            log_act(user, "-", "Sign-in blocked", "File server unreachable (network policy)", ok=False)
            raise
        c.quit()
        log_act(user, role_of(user), "Signed in")
        tok = secrets.token_hex(16)
        SESSIONS[tok] = (user, pw)
        self.send_json({"user": user, "role": role_of(user)}, headers={
            "Set-Cookie": "fs_session=%s; Path=/; HttpOnly; SameSite=Strict" % tok})

    def with_client(self, fn):
        creds = self.creds()
        if not creds:
            raise Denied("Please log in.", 401)
        c = open_client(*creds)
        try:
            return fn(c)
        finally:
            c.quit()

    # -- API: portal overview
    def api_portal(self):
        user, role = self.need()
        listing = self.with_client(lambda c: c.list())
        materials = []
        for line in listing.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[0].startswith("MAT_"):
                _, course, orig = (parts[0].split("_", 2) + ["", ""])[:3]
                materials.append({"file": parts[0], "course": course, "name": orig,
                                  "size": int(parts[1]), "uploader": parts[2]})
        data = load_portal()
        out = []
        for a in data["assignments"]:
            item = dict(a, late_now=is_late(a["due"]))
            subs = data["submissions"].get(a["id"], {})
            grades = data["grades"].get(a["id"], {})
            if role == "student":
                item["submission"] = subs.get(user)
                item["grade"] = grades.get(user)
            else:
                item["submitted"] = len(subs)
                item["graded"] = len(grades)
                item["students"] = len(STUDENTS)
            out.append(item)
        self.send_json({"courses": data["courses"], "assignments": out,
                        "materials": materials, "user": user, "role": role})

    def api_activity(self):
        user, role = self.need()
        with _alock:
            items = list(ACT)
        if role == "student":
            items = [i for i in items if i["user"] == user]
        self.send_json({"items": items[:40], "scope": "your" if role == "student" else "everyone's"})

    def api_review(self, aid):
        user, role = self.need("faculty", "admin")
        data = load_portal()
        a = find_assignment(data, aid)
        if not a:
            raise Denied("Unknown assignment.", 404)
        subs = data["submissions"].get(aid, {})
        grades = data["grades"].get(aid, {})
        rows = [{"student": s, "submission": subs.get(s), "grade": grades.get(s)} for s in STUDENTS]
        self.send_json({"assignment": a, "rows": rows})

    # -- API: faculty actions
    def api_new_assignment(self):
        user, role = self.need("faculty", "admin")
        d = self.read_json()
        course = str(d.get("course", ""))
        title = str(d.get("title", "")).strip()
        desc = str(d.get("desc", "")).strip()[:300]
        due = str(d.get("due", "")).replace("T", " ")[:16]
        try:
            time.strptime(due, DUE_FMT)
        except ValueError:
            raise Denied("Choose a valid due date and time.", 400)
        if not 3 <= len(title) <= 80:
            raise Denied("Title must be 3 to 80 characters.", 400)

        def add(data):
            if not course_ok(data, course):
                raise Denied("Unknown course.", 400)
            n = sum(1 for a in data["assignments"] if a["course"] == course) + 1
            a = {"id": "%s-A%d" % (course, n), "course": course, "title": title,
                 "desc": desc, "due": due, "by": user}
            data["assignments"].append(a)
            return a
        a = mutate(add)
        log_act(user, role, "Published assignment", "%s: %s" % (a["id"], title))
        self.send_json(a)

    def api_grade(self):
        user, role = self.need("faculty", "admin")
        d = self.read_json()
        aid, student = str(d.get("aid", "")), str(d.get("student", ""))
        try:
            marks = int(d.get("marks"))
        except (TypeError, ValueError):
            raise Denied("Marks must be a whole number from 0 to 100.", 400)
        if not 0 <= marks <= 100:
            raise Denied("Marks must be a whole number from 0 to 100.", 400)
        feedback = str(d.get("feedback", "")).strip()[:300]

        def save(data):
            if not find_assignment(data, aid) or student not in data["submissions"].get(aid, {}):
                raise Denied("That student has not submitted yet.", 400)
            g = {"marks": marks, "feedback": feedback, "by": user,
                 "time": time.strftime(DUE_FMT)}
            data["grades"].setdefault(aid, {})[student] = g
            return g
        g = mutate(save)
        log_act(user, role, "Graded", "%s on %s: %d/100" % (student, aid, marks))
        self.send_json(g)

    # -- API: uploads
    def receive_upload(self, fname):
        """Stream the request body to a temp file, send it to the file server over TCP."""
        try:
            length = int(self.headers.get("Content-Length"))
        except (TypeError, ValueError):
            raise Denied("Content-Length required.", 411)
        if length > MAX_UPLOAD:
            raise Denied("File too large (limit 1 GiB).", 413)
        tmp = tempfile.mkdtemp(prefix="fsweb_")
        try:
            path = os.path.join(tmp, fname)
            left = length
            with open(path, "wb") as f:
                while left > 0:
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        raise OSError("browser closed the connection during upload")
                    f.write(chunk)
                    left -= len(chunk)
            t0 = time.time()
            size = self.with_client(lambda c: c.upload(path))
            return size, (time.time() - t0) * 1000
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def api_submit(self, aid, raw_name):
        user, role = self.need("student")
        data = load_portal()
        a = find_assignment(data, aid)
        if not a:
            raise Denied("Unknown assignment.", 404)
        fname = server_name("SUB_%s_%s_" % (aid, user), raw_name)
        size, ms = self.receive_upload(fname)
        rec = {"file": fname, "orig": clean_name(raw_name), "size": size,
               "time": time.strftime(DUE_FMT), "late": is_late(a["due"])}

        def save(d):
            d["submissions"].setdefault(aid, {})[user] = rec
            d["grades"].get(aid, {}).pop(user, None)      # a new file invalidates an old grade
        mutate(save)
        log_act(user, role, "Submitted", "%s to %s%s" % (rec["orig"], aid, " (late)" if rec["late"] else ""),
                size, ms)
        self.send_json(dict(rec, ms=round(ms), mbps=rate(size, ms)))

    def api_material(self, course, raw_name):
        user, role = self.need("faculty", "admin")
        if not course_ok(load_portal(), course):
            raise Denied("Unknown course.", 400)
        fname = server_name("MAT_%s_" % course, raw_name)
        size, ms = self.receive_upload(fname)
        log_act(user, role, "Published material", "%s for %s" % (clean_name(raw_name), course), size, ms)
        self.send_json({"file": fname, "size": size, "orig": clean_name(raw_name),
                        "ms": round(ms), "mbps": rate(size, ms)})

    # -- API: download (with access rule)
    def api_download(self, name):
        user, role = self.need()
        if not name or name != clean_name(name):
            raise Denied("invalid file name", 400)
        if not can_download(user, role, name):
            raise Denied("You are not allowed to download this file.", 403)
        tmp = tempfile.mkdtemp(prefix="fsweb_")
        try:
            def run(c):
                t0 = time.time()
                dest, size, digest = c.download(name, tmp)
                ms = (time.time() - t0) * 1000
                shown = name.split("_", 3)[-1] if name.startswith("SUB_") else name.split("_", 2)[-1]
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", 'attachment; filename="%s"' % shown)
                self.send_header("X-Content-SHA256", digest)
                log_act(user, role, "Downloaded", shown, size, ms, sha=digest)
                self.end_headers()
                with open(dest, "rb") as f:
                    shutil.copyfileobj(f, self.wfile)
            self.with_client(run)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CampusShare</title>
<style>
:root{--bg:#f5f6f8;--surface:#fff;--ink:#1c2430;--ink2:#566274;--line:#e4e7ec;--line2:#cfd5de;
--brand:#2f5bea;--brand-ink:#fff;--brand-tint:#eef2ff;--brand-deep:#1d3a8a;
--ok:#12805c;--ok-tint:#e6f6ef;--warn:#9a5b00;--warn-tint:#fff3df;--bad:#c0341d;--bad-tint:#fdeceb;
--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08)}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--surface:#171e28;--ink:#e9eef5;--ink2:#97a4b6;--line:#263041;--line2:#37445a;
--brand:#6b8cff;--brand-ink:#0b1220;--brand-tint:#1b2744;--brand-deep:#0f1b3d;
--ok:#4cd6a0;--ok-tint:#12302a;--warn:#f5b84b;--warn-tint:#352a10;--bad:#ff8b78;--bad-tint:#3a1d19;--shadow:none}}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",sans-serif}
h1,h2,h3,h4,p{margin:0}
button,input,select,textarea{font:inherit;color:inherit}
button{cursor:pointer}
:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
.ic{display:inline-flex;flex:none}
.sp{flex:1}

/* ---------- buttons and fields ---------- */
.btn{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:8px;border:1px solid var(--line2);background:var(--surface);font-weight:600;font-size:14px}
.btn:hover{background:var(--bg)}
.btn.primary{background:var(--brand);border-color:var(--brand);color:var(--brand-ink)}
.btn.primary:hover{filter:brightness(1.07)}
.btn.sm{padding:5px 10px;font-size:13px}
.btn:disabled{opacity:.55;cursor:default}
.link{background:none;border:0;padding:0;color:var(--brand);font-weight:600;text-decoration:none}
.link:hover{text-decoration:underline}
label.f{display:block;font-size:13px;font-weight:600;color:var(--ink2);margin:14px 0 5px}
.in{width:100%;padding:10px 12px;border:1px solid var(--line2);border-radius:8px;background:var(--surface)}
textarea.in{resize:vertical;min-height:70px}
.in:focus-visible{outline-offset:0;border-color:var(--brand)}

/* ---------- sign-in screen ---------- */
.auth{min-height:100vh;display:grid;grid-template-columns:1.05fr 1fr}
.auth .hero{background:linear-gradient(155deg,var(--brand-deep),#2f5bea);color:#fff;padding:56px 56px 40px;display:flex;flex-direction:column;gap:28px}
.auth .logo{display:flex;align-items:center;gap:12px;font-size:22px;font-weight:700;letter-spacing:-.01em}
.mark{width:38px;height:38px;border-radius:10px;background:#fff;color:var(--brand);display:grid;place-items:center}
.auth h1{font-size:34px;line-height:1.15;letter-spacing:-.02em;max-width:460px}
.auth .lead{font-size:16px;opacity:.9;max-width:460px}
.feat{display:flex;flex-direction:column;gap:16px;max-width:460px}
.feat div{display:flex;gap:14px;align-items:flex-start}
.feat .ic{width:36px;height:36px;border-radius:10px;background:rgba(255,255,255,.16);align-items:center;justify-content:center}
.feat b{display:block}.feat span.d{opacity:.85;font-size:14px}
.auth .hero .btn{align-self:flex-start;background:rgba(255,255,255,.14);border-color:rgba(255,255,255,.4);color:#fff}
.auth .hero .btn:hover{background:rgba(255,255,255,.24)}
.auth .formside{display:grid;place-items:center;padding:32px 24px}
.signin{width:100%;max-width:400px}
.signin h2{font-size:26px;letter-spacing:-.01em}
.signin .sub{color:var(--ink2);margin:4px 0 6px}
.quick{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}
.chipbtn{display:inline-flex;align-items:center;gap:8px;padding:5px 12px 5px 6px;border-radius:99px;border:1px solid var(--line2);background:var(--surface);font-size:13px;font-weight:600}
.chipbtn:hover{background:var(--brand-tint);border-color:var(--brand)}
.avatar{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;color:#fff;font-size:12px;font-weight:700;flex:none}
.note{margin-top:14px;padding:10px 12px;border-radius:8px;font-size:13.5px}
.note.bad{background:var(--bad-tint);color:var(--bad)}
.note.ok{background:var(--ok-tint);color:var(--ok)}
.note.info{background:var(--brand-tint);color:var(--brand)}
.helptext{color:var(--ink2);font-size:13px;margin-top:18px}
@media (max-width:860px){.auth{grid-template-columns:1fr}.auth .hero{padding:28px 24px;gap:18px}.auth h1{font-size:26px}.feat{display:none}}

/* ---------- app shell ---------- */
.app{display:grid;grid-template-columns:248px 1fr;min-height:100vh}
.side{background:var(--surface);border-right:1px solid var(--line);padding:18px 14px;display:flex;flex-direction:column;gap:6px;position:sticky;top:0;height:100vh}
.side .logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px;padding:4px 8px 16px}
.side .mark{width:32px;height:32px;background:var(--brand);color:#fff}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{display:flex;align-items:center;gap:12px;padding:9px 12px;border:0;background:none;border-radius:8px;color:var(--ink2);font-weight:600;font-size:14.5px;text-align:left;width:100%}
.nav button:hover{background:var(--bg);color:var(--ink)}
.nav button.on{background:var(--brand-tint);color:var(--brand)}
.nav .badge{margin-left:auto;background:var(--brand);color:var(--brand-ink);border-radius:99px;font-size:12px;padding:0 8px;min-width:22px;text-align:center}
.nav .sep{height:1px;background:var(--line);margin:10px 8px}
.srvbox{margin-top:auto;border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:12.5px;color:var(--ink2)}
.srvbox b{display:flex;align-items:center;gap:8px;color:var(--ink);font-size:13px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--ok);display:inline-block}
.dot.off{background:var(--bad)}
.main{min-width:0}
.top{display:flex;align-items:center;gap:12px;padding:14px 32px;background:var(--surface);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.top h1{font-size:19px;letter-spacing:-.01em}
.usermenu{position:relative}
.userbtn{display:flex;align-items:center;gap:10px;border:1px solid var(--line);background:var(--surface);border-radius:99px;padding:4px 14px 4px 4px}
.userbtn:hover{background:var(--bg)}
.userbtn .who{line-height:1.2;text-align:left}
.userbtn .who b{display:block;font-size:13.5px}.userbtn .who small{color:var(--ink2);font-size:12px}
.menu{position:absolute;right:0;top:calc(100% + 6px);background:var(--surface);border:1px solid var(--line);border-radius:10px;box-shadow:0 8px 24px rgba(16,24,40,.16);min-width:170px;padding:6px;z-index:10}
.menu button{display:flex;align-items:center;gap:10px;width:100%;padding:8px 10px;border:0;background:none;border-radius:6px;text-align:left}
.menu button:hover{background:var(--bg)}
#page{padding:28px 32px 56px;max-width:1120px}
.pagehead{display:flex;align-items:flex-start;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.pagehead h2{font-size:26px;letter-spacing:-.015em;line-height:1.2}
.pagehead p{color:var(--ink2);margin-top:4px;max-width:640px}
@media (max-width:860px){
  .app{grid-template-columns:1fr}
  .side{position:fixed;top:auto;bottom:0;left:0;right:0;height:auto;flex-direction:row;padding:6px;z-index:20;border-right:0;border-top:1px solid var(--line)}
  .side .logo,.srvbox,.nav .sep{display:none}
  .nav{flex-direction:row;width:100%;justify-content:space-around}
  .nav button{flex-direction:column;gap:2px;font-size:11px;padding:6px 4px;text-align:center;justify-content:center;width:auto;flex:1}
  .nav .badge{position:absolute;margin:0;transform:translate(14px,-10px)}
  .nav button{position:relative}
  .top{padding:12px 16px}.userbtn .who{display:none}.userbtn{padding:4px}
  #page{padding:20px 16px 96px}
}

/* ---------- content ---------- */
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
.card .hd{padding:16px 20px 0;display:flex;align-items:center;gap:10px}
.card .hd h3{font-size:16px}
.card .hd .sub{color:var(--ink2);font-size:13px}
.card .bd{padding:14px 20px 18px}
.grid2{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:20px;align-items:start}
.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
@media (max-width:980px){.grid2{grid-template-columns:1fr}}
@media (max-width:600px){.grid3{grid-template-columns:1fr}}
.stat{display:flex;align-items:center;gap:14px;padding:16px 18px}
.stat .ic{width:42px;height:42px;border-radius:10px;align-items:center;justify-content:center;background:var(--brand-tint);color:var(--brand)}
.stat .n{font-size:26px;font-weight:700;line-height:1.1}
.stat .l{color:var(--ink2);font-size:13px}
.stat.ok .ic{background:var(--ok-tint);color:var(--ok)}
.stat.warn .ic{background:var(--warn-tint);color:var(--warn)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;font-weight:600;padding:2px 10px;border-radius:99px;white-space:nowrap}
.pill.ok{background:var(--ok-tint);color:var(--ok)}.pill.warn{background:var(--warn-tint);color:var(--warn)}
.pill.bad{background:var(--bad-tint);color:var(--bad)}.pill.info{background:var(--brand-tint);color:var(--brand)}
.pill.mute{background:var(--bg);color:var(--ink2);border:1px solid var(--line)}
.cc{display:inline-block;font-size:12px;font-weight:700;padding:2px 8px;border-radius:6px;color:#fff;background:#64748b}
.cc.c0{background:#2f5bea}.cc.c1{background:#0f9d8a}.cc.c2{background:#c27a0e}.cc.c3{background:#7c4ddb}
.muted{color:var(--ink2)}
.small{font-size:13px}
.list>*{border-top:1px solid var(--line)}.list>*:first-child{border-top:0}
.item{display:flex;align-items:center;gap:14px;padding:12px 4px;width:100%;background:none;border:0;text-align:left}
button.item:hover{background:var(--bg)}
.sico{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;flex:none;background:var(--bg);color:var(--ink2)}
.sico.ok{background:var(--ok-tint);color:var(--ok)}.sico.info{background:var(--brand-tint);color:var(--brand)}
.sico.warn{background:var(--warn-tint);color:var(--warn)}.sico.bad{background:var(--bad-tint);color:var(--bad)}
.item .t{font-weight:600}
.courses{display:grid;gap:12px}
.course{overflow:hidden}
.course .bar{height:6px}
.course .bar.c0{background:#2f5bea}.course .bar.c1{background:#0f9d8a}.course .bar.c2{background:#c27a0e}.course .bar.c3{background:#7c4ddb}
.course .in2{padding:12px 16px}
.course b{display:block}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.chip{border:1px solid var(--line2);background:var(--surface);border-radius:99px;padding:5px 14px;font-size:13.5px;font-weight:600;color:var(--ink2)}
.chip.on{background:var(--brand);border-color:var(--brand);color:var(--brand-ink)}
.acc{margin-bottom:12px;overflow:hidden}
.acc>.head{display:flex;align-items:center;gap:14px;padding:14px 18px;width:100%;background:none;border:0;text-align:left}
.acc>.head:hover{background:var(--bg)}
.acc .title{font-weight:600;font-size:15.5px}
.acc .chev{transition:transform .15s;color:var(--ink2)}
.acc.open .chev{transform:rotate(180deg)}
.acc .body{padding:4px 18px 18px 68px;border-top:1px solid var(--line)}
@media (max-width:600px){.acc .body{padding-left:18px}}
.acc .body p.desc{margin:12px 0}
.block{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-top:12px}
.block .cap{font-size:13px;font-weight:600;color:var(--ink2);margin-bottom:6px}
.filerow{display:flex;align-items:center;gap:12px}
.fico{flex:none;width:38px;height:38px;border-radius:8px;display:grid;place-items:center;font-size:10.5px;font-weight:700;color:#fff;background:#64748b}
.fico.img{background:#d9467a}.fico.doc{background:#2f5bea}.fico.arc{background:#c27a0e}.fico.code{background:#0f9d8a}.fico.media{background:#7c4ddb}.fico.data{background:#0e8aa8}
.drop{margin-top:12px;border:2px dashed var(--line2);border-radius:10px;padding:16px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;color:var(--ink2)}
.drop.over{border-color:var(--brand);background:var(--brand-tint)}
.prog{height:6px;border-radius:99px;background:var(--line);overflow:hidden;margin-top:10px;display:none}
.prog div{height:100%;width:0;background:var(--brand);transition:width .15s}
.gradebox{margin-top:12px;border-radius:10px;padding:12px 14px;background:var(--ok-tint);color:var(--ok);display:flex;gap:16px;align-items:center}
.gradebox .big{font-size:26px;font-weight:700;line-height:1}
.gradebox .fbk{color:var(--ink)}
.meter{height:6px;border-radius:99px;background:var(--line);overflow:hidden;width:130px}
.meter div{height:100%;background:var(--ok)}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-weight:600;font-size:13px;color:var(--ink2);padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:middle;font-size:14px}
tr:last-child td{border-bottom:0}
.tw{overflow-x:auto}
td .in{padding:6px 8px}
.empty{padding:36px 16px;text-align:center;color:var(--ink2)}
.empty b{display:block;color:var(--ink);margin-bottom:2px}
dialog{border:0;border-radius:14px;padding:0;width:min(880px,calc(100% - 24px));box-shadow:0 20px 60px rgba(16,24,40,.35);background:var(--surface);color:var(--ink)}
dialog::backdrop{background:rgba(15,23,42,.5)}
dialog .dh{display:flex;align-items:center;padding:16px 22px;border-bottom:1px solid var(--line)}
dialog .dh h3{font-size:18px}
dialog .db{padding:18px 22px 22px;max-height:78vh;overflow:auto}
dialog .df{display:flex;gap:10px;justify-content:flex-end;margin-top:18px}
.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}
@media (max-width:600px){.formgrid{grid-template-columns:1fr}}
#toasts{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:10px;z-index:50;max-width:380px}
@media (max-width:860px){#toasts{bottom:84px;right:12px;left:12px;max-width:none}}
.toast{background:var(--ink);color:var(--bg);border-radius:12px;padding:12px 16px;box-shadow:0 10px 30px rgba(16,24,40,.3);display:flex;gap:12px;align-items:flex-start}
.toast.bad{background:var(--bad);color:#fff}
.toast b{display:block}.toast .m{font-size:13.5px;opacity:.9}
.toast button{color:inherit;text-decoration:underline;background:none;border:0;padding:0;font-size:13.5px;margin-top:4px}

/* ---------- journey diagram ---------- */
.journey{width:100%;height:auto;display:block}
.journey .node{fill:var(--surface);stroke:var(--line2);stroke-width:1.5}
.journey .nt{fill:var(--ink);font-weight:600;font-size:14.5px}
.journey .ns{fill:var(--ink2);font-size:12px}
.journey .edge{stroke:var(--line2);stroke-width:3;fill:none}
.journey .edge.on{stroke:var(--brand);stroke-dasharray:7 7;animation:flow .7s linear infinite}
.journey .ctl{stroke-dasharray:4 5;stroke-width:2}
.journey .el{fill:var(--ink2);font-size:12px;text-anchor:middle}
.journey .j-ctl.block{stroke:var(--bad);fill:var(--bad-tint)}
.journey .j-ctl.limit{stroke:var(--warn);fill:var(--warn-tint)}
.journey .node.hot{stroke:var(--brand);stroke-width:2}
@keyframes flow{to{stroke-dashoffset:-14}}
@media (prefers-reduced-motion:reduce){.journey .edge.on{animation:none}}
.legend{display:flex;gap:18px;flex-wrap:wrap;font-size:13px;color:var(--ink2);margin-top:8px}
.legend i{display:inline-block;width:22px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle;background:var(--line2)}
.legend i.on{background:var(--brand)}
.steps{counter-reset:s;display:grid;gap:12px;margin-top:6px}
.steps>div{display:flex;gap:14px;align-items:flex-start}
.steps>div::before{counter-increment:s;content:counter(s);flex:none;width:28px;height:28px;border-radius:50%;background:var(--brand);color:var(--brand-ink);display:grid;place-items:center;font-weight:700;font-size:13.5px}
.steps b{display:block}
.port{margin:12px 0}
.port .top2{display:flex;justify-content:space-between;gap:10px;align-items:baseline;font-size:14px}
.port .top2 small{color:var(--ink2);display:block;font-size:12px}
.port .top2 .rate{text-align:right;max-width:55%}
.port .rate{color:var(--ink2);font-size:13px;font-variant-numeric:tabular-nums}
.track{height:8px;border-radius:99px;background:var(--line);margin-top:6px;overflow:hidden}
.track div{height:100%;background:var(--brand);width:0;transition:width .4s}
.ev{display:flex;gap:12px;padding:10px 0;align-items:flex-start;border-top:1px solid var(--line)}
.ev:first-child{border-top:0}
.ev .when{font-size:12.5px;color:var(--ink2);font-variant-numeric:tabular-nums}
.ev code{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;word-break:break-all;color:var(--ink2)}
.tip{background:var(--brand-tint);border-radius:10px;padding:14px 16px}
.tip ol{margin:8px 0 0;padding-left:20px}

/* ---------- live network dock ---------- */
.btn.on{background:var(--brand-tint);border-color:var(--brand);color:var(--brand)}
.dock{display:none;background:var(--surface);border-left:1px solid var(--line)}
.app.dock-open .dock{display:block}
@media (min-width:1200px){
  .app.dock-open{grid-template-columns:248px minmax(0,1fr) 350px}
  .dock{position:sticky;top:0;height:100vh;overflow:auto}
  #page{padding:24px 24px 56px}
}
@media (max-width:1199px){
  .dock{position:fixed;top:0;right:0;bottom:0;width:min(380px,100%);z-index:30;box-shadow:-12px 0 40px rgba(16,24,40,.25);overflow:auto}
}
.dkhead{display:flex;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surface);z-index:2}
.dkhead b{font-size:16px}.dkhead small{display:block;color:var(--ink2);font-size:12.5px}
.dkbody{padding:14px;display:grid;gap:14px}
.dkcard{border:1px solid var(--line);border-radius:12px;padding:14px}
.dkcard h4{font-size:14px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.tstep{display:flex;gap:10px;padding:7px 0;align-items:flex-start;font-size:14px}
.tstep .tic{width:22px;height:22px;flex:none;display:grid;place-items:center;color:var(--line2)}
.tstep.done .tic{color:var(--ok)}.tstep.fail .tic{color:var(--bad)}
.tstep.wait{color:var(--ink2)}
.tstep small{display:block;color:var(--ink2);font-size:12.5px}
.spin{width:16px;height:16px;border:2px solid var(--line2);border-top-color:var(--brand);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation:none;border-top-color:var(--line2);border-right-color:var(--brand)}}
.mini{display:flex;flex-direction:column}
.hop{border:1px solid var(--line2);border-radius:10px;padding:8px 12px;font-weight:600;font-size:14px;background:var(--surface)}
.hop small{display:block;font-weight:400;color:var(--ink2);font-size:12.5px}
.conn{height:28px;margin-left:24px;position:relative}
.conn::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:2px;background:var(--line2)}
.conn span{position:absolute;left:14px;top:5px;font-size:12px;color:var(--ink2)}
.conn.on::before{background:repeating-linear-gradient(to bottom,var(--brand) 0 6px,transparent 6px 12px);background-size:3px 12px;animation:slideY .6s linear infinite}
@keyframes slideY{to{background-position-y:12px}}
@media (prefers-reduced-motion:reduce){.conn.on::before{animation:none;background:var(--brand)}}
.mini .ctl{margin-top:8px;border:1.5px dashed var(--line2);border-radius:10px;padding:8px 12px;font-size:13px}
.mini .ctl b{display:block;font-size:13.5px}
.mini .ctl.block{border-color:var(--bad);background:var(--bad-tint);color:var(--bad)}
.mini .ctl.limit{border-color:var(--warn);background:var(--warn-tint);color:var(--warn)}
.hop{transition:box-shadow .25s,border-color .25s,background .25s}
.hop.lit{border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-tint,rgba(37,99,235,.18));background:var(--brand-tint,rgba(37,99,235,.08))}
.conn .dot{display:none;position:absolute;left:-4px;width:11px;height:11px;border-radius:50%;background:var(--brand);box-shadow:0 0 0 4px rgba(37,99,235,.25)}
.conn.pkt .dot{display:block;animation:dotDown var(--dur,2.4s) linear forwards}
.conn.pkt.rev .dot{animation-name:dotUp}
@keyframes dotDown{from{top:-4px}to{top:21px}}
@keyframes dotUp{from{top:21px}to{top:-4px}}
.slowbox{margin-top:10px;border-radius:10px;padding:10px 12px;background:var(--brand-tint,rgba(37,99,235,.08));border:1px solid var(--line2)}
.slowbox .sn{font-size:12px;color:var(--ink2);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.slowbox .st{font-weight:600;margin:2px 0}
.slowbox .sd{font-size:13.5px;color:var(--ink2)}
.slowbar{height:4px;border-radius:2px;background:var(--line);margin-top:8px;overflow:hidden}
.slowbar i{display:block;height:100%;background:var(--brand);width:0}
.dkhead .tgl{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--ink2);cursor:pointer;margin-right:8px;white-space:nowrap}
.dkcard .port{margin:10px 0}
.dkcard .port .rate{max-width:none;text-align:left;margin-top:1px}
</style>
</head>
<body>

<!-- ============ sign-in ============ -->
<div class="auth" id="auth">
  <div class="hero">
    <div class="logo"><span class="mark" id="markA"></span>CampusShare</div>
    <h1>Hand in work and share course files, and watch how they travel.</h1>
    <p class="lead">CampusShare is a college portal for assignments and course materials. Every file moves over a real network that is watched and protected by a software-defined network (SDN) controller.</p>
    <div class="feat" id="feat"></div>
    <button class="btn" id="howBtn">See how it works</button>
  </div>
  <div class="formside">
    <div class="signin">
      <h2>Sign in</h2>
      <p class="sub">Use your campus account.</p>
      <form id="loginForm" autocomplete="off">
        <label class="f" for="u">Username</label><input class="in" id="u" required autocapitalize="none">
        <label class="f" for="p">Password</label><input class="in" id="p" type="password" required>
        <button class="btn primary" id="loginBtn" style="width:100%;justify-content:center;margin-top:18px;padding:11px">Sign in</button>
      </form>
      <div id="loginMsg"></div>
      <p class="helptext">Demo accounts: pick one to fill in the form.</p>
      <div class="quick" id="quick"></div>
    </div>
  </div>
</div>

<!-- ============ app ============ -->
<div class="app" id="app" hidden>
  <aside class="side">
    <div class="logo"><span class="mark" id="markB"></span>CampusShare</div>
    <nav class="nav" id="nav"></nav>
    <div class="srvbox"><b><span class="dot" id="srvDot"></span>File server</b><span id="srvText">Checking connection</span></div>
  </aside>
  <div class="main">
    <header class="top">
      <h1 id="pageTitle"></h1>
      <div class="sp"></div>
      <button class="btn sm" id="dockBtn" type="button" aria-pressed="false"></button>
      <div class="usermenu">
        <button class="userbtn" id="userBtn" aria-haspopup="true">
          <span class="avatar" id="uAvatar"></span>
          <span class="who"><b id="uName"></b><small id="uRole"></small></span>
        </button>
        <div class="menu" id="menu" hidden><button id="signout"><span id="outIc"></span>Sign out</button></div>
      </div>
    </header>
    <div id="page"></div>
  </div>
  <aside class="dock" id="dock" aria-label="Live network"></aside>
</div>

<dialog id="dlg"></dialog>
<div id="toasts" aria-live="polite"></div>

<script>
const $=id=>document.getElementById(id);
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
const IC={
 home:'<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
 clip:'<rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4h6v3H9z"/><path d="M9 12h6M9 16h4"/>',
 folder:'<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
 pulse:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
 help:'<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7"/><path d="M12 17h.01"/>',
 out:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
 up:'<path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 20h16"/>',
 down:'<path d="M12 4v12M7 11l5 5 5-5"/><path d="M4 20h16"/>',
 check:'<circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 alert:'<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
 shield:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
 gauge:'<path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-6"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',
 chev:'<path d="M6 9l6 6 6-6"/>',
 users:'<circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><path d="M16 5a3.5 3.5 0 0 1 0 7M18 14c2 .7 3 2.6 3 6"/>',
 book:'<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 19V5"/>',
 file:'<path d="M6 3h8l5 5v13H6z"/><path d="M14 3v5h5"/>',
 network:'<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5L6 17M12 11.5l6 5.5"/>',
 grad:'<path d="M2 9l10-5 10 5-10 5z"/><path d="M6 11v5c0 1.5 3 3 6 3s6-1.5 6-3v-5"/>'
};
function ic(name,size){const s=el('span','ic');s.innerHTML='<svg viewBox="0 0 24 24" width="'+(size||18)+'" height="'+(size||18)+'" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+IC[name]+'</svg>';return s}
const fmt=n=>n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(1)+" MB";
const cap=s=>s.charAt(0).toUpperCase()+s.slice(1);
const SHOW={prof:"Professor",admin:"Admin"};
const nameOf=u=>SHOW[u]||cap(u);
const HUES=["#2f5bea","#0f9d8a","#c27a0e","#7c4ddb","#d9467a","#0e8aa8"];
function avatar(u,size){const a=el('span','avatar',nameOf(u).charAt(0));let h=0;for(const c of u)h=(h*31+c.charCodeAt(0))%HUES.length;a.style.background=HUES[h];if(size){a.style.width=a.style.height=size+'px';a.style.fontSize=Math.round(size*.45)+'px'}return a}
async function api(path,opts){const r=await fetch(path,opts);let d={};try{d=await r.json()}catch(e){}return{ok:r.ok,status:r.status,d}}
const post=(p,o)=>api(p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});
const TYPES={img:"png jpg jpeg gif webp svg bmp",doc:"pdf doc docx txt md rtf odt ppt pptx",arc:"zip tar gz tgz rar 7z",code:"py js ts c cpp h java sh json html css",media:"mp3 mp4 wav mkv avi mov",data:"csv xls xlsx bin dat db log gch"};
function kind(n){const e=(n.split(".").pop()||"").toLowerCase();for(const k in TYPES)if(TYPES[k].split(" ").includes(e))return k;return""}
function ext(n){return n.includes(".")?n.split(".").pop().slice(0,4).toUpperCase():"FILE"}
function fileIcon(n){return el('div','fico '+kind(n),ext(n))}
const dt=s=>new Date(s.replace(" ","T"));
function when(s){return dt(s).toLocaleString(undefined,{weekday:"short",day:"numeric",month:"short",hour:"numeric",minute:"2-digit"})}
function rel(s){const ms=dt(s)-Date.now(),h=Math.round(Math.abs(ms)/36e5);const t=h<1?"under an hour":h<48?h+(h===1?" hour":" hours"):Math.round(h/24)+" days";return ms>=0?"Due in "+t:"Overdue by "+t}
function overdue(s){return dt(s)<Date.now()}

/* ---------------- state ---------------- */
const S={user:null,role:null,server:"",P:null,N:null,A:null,open:new Set(),filter:"all",cfilter:"all",showRaw:false,dock:false,T:null};
const staff=()=>S.role==="faculty"||S.role==="admin";
const PAGES=[["home","Home","home"],["assign","Assignments","clip"],["materials","Course materials","folder"],["activity","Network activity","pulse"],["how","How it works","help"]];
function page(){const h=(location.hash||"").replace(/^#\/?/,"");return PAGES.some(p=>p[0]===h)?h:"home"}
function go(p){if(location.hash==="#/"+p)render();else location.hash="#/"+p}
window.addEventListener("hashchange",()=>{if(S.user)render()});

/* ---------------- toasts and dialogs ---------------- */
function toast(title,msg,kind,action){
  const t=el('div','toast'+(kind==="bad"?" bad":""));const b=el('div');b.append(el('b',null,title));
  if(msg)b.append(el('div','m',msg));
  if(action){const a=el('button',null,action[0]);a.onclick=()=>{t.remove();action[1]()};b.append(a)}
  t.append(b);$("toasts").append(t);setTimeout(()=>t.remove(),kind==="bad"?9000:8000)}
const dlg=$("dlg");
function openDialog(title,body){dlg.textContent="";const h=el('div','dh');h.append(el('h3',null,title),el('div','sp'));
  const x=el('button','btn sm','Close');x.onclick=()=>dlg.close();h.append(x);const b=el('div','db');b.append(body);dlg.append(h,b);dlg.showModal()}
dlg.addEventListener("click",e=>{if(e.target===dlg)dlg.close()});

/* ---------------- sign-in screen ---------------- */
$("markA").append(ic('grad',22));$("markB").append(ic('grad',18));
[["network","The network is part of the app","Files travel through a real switch that an SDN controller programs."],
 ["shield","Protected automatically","Three wrong sign-ins block a computer for 30 seconds, then access returns by itself."],
 ["gauge","Fair for everyone","A computer that hogs the link is slowed down so others can finish."]].forEach(f=>{
  const d=el('div');d.append(ic(f[0],20));const t=el('div');t.append(el('b',null,f[1]),el('span','d',f[2]));d.append(t);$("feat").append(d)});
[["alice","alice123","student"],["bob","bob123","student"],["carol","carol123","student"],["prof","prof123","faculty"],["admin","1234","admin"]].forEach(([u,p,r])=>{
  const b=el('button','chipbtn');b.type="button";b.append(avatar(u,24),document.createTextNode(nameOf(u)+" ("+r+")"));
  b.onclick=()=>{$("u").value=u;$("p").value=p;$("loginMsg").textContent=""};$("quick").append(b)});
$("howBtn").onclick=()=>openDialog("How CampusShare works",howView());
function note(target,text,kind,extra){const n=el('div','note '+kind,text);if(extra){n.append(el('div','small',extra))}target.textContent="";target.append(n)}
$("loginForm").addEventListener("submit",async e=>{
  e.preventDefault();$("loginBtn").disabled=true;note($("loginMsg"),"Signing in...","info");
  const r=await post("/api/login",{user:$("u").value.trim(),password:$("p").value});
  $("loginBtn").disabled=false;
  if(r.ok){$("loginMsg").textContent="";$("p").value="";S.user=r.d.user;S.role=r.d.role;enter(true)}
  else if(r.d.blocked)note($("loginMsg"),"Can't reach the file server.","bad","If you entered a wrong password three times, the SDN controller has blocked this computer for 30 seconds. Access comes back automatically. Open Network activity after signing in to see the block.");
  else note($("loginMsg"),r.d.error==="authentication failed"?"Wrong username or password. Check the details and try again.":(r.d.error||"Sign-in failed"),"bad")
});
async function init(){
  const r=await api("/api/me");S.server=r.d.server||"";
  if(r.d.user){S.user=r.d.user;S.role=r.d.role;enter(false)}
}
async function enter(fresh){
  $("auth").hidden=true;$("app").hidden=false;
  $("uAvatar").replaceWith(Object.assign(avatar(S.user),{id:"uAvatar"}));
  $("uName").textContent=nameOf(S.user);$("uRole").textContent=cap(S.role);
  $("outIc").textContent="";$("outIc").append(ic('out',16));
  $("srvText").textContent=S.server||"connected";
  const db=$("dockBtn");db.textContent="";db.append(ic('pulse',16),document.createTextNode("Live network"));
  try{S.slowAuto=localStorage.getItem("cs_slow")==="1"}catch(e){}
  let want=window.innerWidth>=1360;try{const v=localStorage.getItem("cs_dock");if(v!==null)want=v==="1"&&window.innerWidth>=1200||v==="1"&&S.dock}catch(e){}
  setDock(want);
  if(fresh&&!location.hash)location.hash="#/home";
  await loadPortal();
}
$("userBtn").onclick=e=>{e.stopPropagation();$("menu").hidden=!$("menu").hidden};
document.addEventListener("click",()=>{$("menu").hidden=true});
$("signout").onclick=async()=>{await api("/api/logout",{method:"POST"});S.user=null;S.P=null;S.T=null;S.slow=null;clearTimeout(slowTimer);$("dock").textContent="";S.open.clear();location.hash="";$("app").hidden=true;$("auth").hidden=false;$("loginMsg").textContent=""};

/* ---------------- data ---------------- */
async function loadPortal(){
  const r=await api("/api/portal");
  if(r.status===401&&!r.d.blocked){$("signout").click();return}
  if(!r.ok){$("srvDot").className="dot off";$("srvText").textContent="Unreachable";toast("Can't reach the file server",r.d.error,"bad");return}
  $("srvDot").className="dot";S.P=r.d;render()
}
async function loadActivity(){const r=await api("/api/activity");if(r.ok){S.A=r.d;if(S.user&&page()==="activity")renderActivityBody()}}
async function pollSdn(){
  if(document.hidden)return;
  const r=await api("/api/sdn");if(!r.ok)return;S.N=r.d;
  S.peak=S.peak||{};const now=Date.now();(S.N.ports||[]).forEach(p=>{const v=p.up+p.down,k=S.peak[p.port];if(!k||v>=k.v*0.999||now-k.t>20000)S.peak[p.port]={v,t:now,up:p.up,down:p.down}});
  updateJourney();if(S.user&&S.dock){renderDockTraffic();renderDockEvents()}if(S.user&&page()==="activity")renderLive();
}
setInterval(pollSdn,2000);setInterval(()=>{if(S.user&&page()==="activity")loadActivity()},3000);

/* ---------------- shell ---------------- */
function todoCount(){if(!S.P||S.role!=="student")return 0;return S.P.assignments.filter(a=>!a.submission).length}
function waitingCount(){if(!S.P||!staff())return 0;return S.P.assignments.reduce((n,a)=>n+Math.max(0,a.submitted-a.graded),0)}
function render(){
  if(!S.user||!S.P)return;const cur=page();
  const nav=$("nav");nav.textContent="";
  PAGES.forEach(([k,label,icon],i)=>{
    if(k==="activity")nav.append(el('div','sep'));
    const b=el('button',k===cur?"on":"");b.append(ic(icon,19),document.createTextNode(label));
    const n=k==="assign"?(staff()?waitingCount():todoCount()):0;if(n){b.append(el('span','badge',String(n)))}
    b.onclick=()=>go(k);nav.append(b)});
  $("pageTitle").textContent=PAGES.find(p=>p[0]===cur)[1];
  const root=$("page");root.textContent="";
  root.append(cur==="home"?viewHome():cur==="assign"?viewAssign():cur==="materials"?viewMaterials():cur==="activity"?viewActivity():viewHow());
  if(S.lastPage!==cur){window.scrollTo(0,0);S.lastPage=cur}
  if(cur==="activity"){loadActivity();updateJourney()}
}
function courseIdx(code){const i=S.P.courses.findIndex(c=>c.code===code);return i<0?9:i%4}
function courseTag(code){return el('span','cc c'+courseIdx(code),code)}
function head(title,sub,action){const h=el('div','pagehead');const t=el('div');t.append(el('h2',null,title));if(sub)t.append(el('p',null,sub));h.append(t,el('div','sp'));if(action)h.append(action);return h}

/* ---------------- home ---------------- */
function statCard(icon,n,label,tone){const c=el('div','card stat '+(tone||""));c.append(ic(icon,22));const t=el('div');t.append(el('div','n',String(n)),el('div','l',label));c.append(t);return c}
function statusOf(a){
  if(a.grade)return{key:"graded",label:"Graded "+a.grade.marks+"/100",tone:"ok",icon:"check"};
  if(a.submission)return a.submission.late?{key:"submitted",label:"Submitted late",tone:"warn",icon:"check"}:{key:"submitted",label:"Submitted",tone:"info",icon:"check"};
  return overdue(a.due)?{key:"todo",label:"Overdue",tone:"bad",icon:"alert"}:{key:"todo",label:"To do",tone:"mute",icon:"clock"}}
function viewHome(){
  const root=el('div'),A=S.P.assignments,h=new Date().getHours();
  const greet=h<12?"Good morning":h<17?"Good afternoon":"Good evening";
  let sub;
  if(S.role==="student"){const t=A.filter(a=>!a.submission).sort((a,b)=>a.due.localeCompare(b.due));
    sub=t.length?"You have "+t.length+(t.length===1?" assignment":" assignments")+" to hand in. The next one is due "+when(t[0].due)+".":"You're all caught up. Nothing is waiting to be handed in."}
  else{const w=waitingCount();sub=w?w+(w===1?" submission is":" submissions are")+" waiting to be graded.":"Nothing is waiting to be graded right now."}
  root.append(head(greet+", "+nameOf(S.user),sub));
  const stats=el('div','grid3');stats.style.marginBottom="20px";
  if(S.role==="student"){
    stats.append(statCard('clock',A.filter(a=>!a.submission).length,"To hand in","warn"),statCard('clip',A.filter(a=>a.submission&&!a.grade).length,"Handed in, not graded yet"),statCard('check',A.filter(a=>a.grade).length,"Graded","ok"))
  }else{
    const subs=A.reduce((n,a)=>n+a.submitted,0);
    stats.append(statCard('clip',A.length,"Assignments published"),statCard('file',subs,"Submissions received"),statCard('clock',waitingCount(),"Waiting to be graded","warn"))}
  root.append(stats);
  const cols=el('div','grid2'),left=el('div','card'),right=el('div');
  const lh=el('div','hd');lh.append(el('h3',null,S.role==="student"?"Coming up":"Needs your attention"));left.append(lh);
  const lb=el('div','bd list');
  const rows=S.role==="student"?A.filter(a=>!a.submission).sort((a,b)=>a.due.localeCompare(b.due)):A.filter(a=>a.submitted>a.graded);
  rows.slice(0,5).forEach(a=>{
    const b=el('button','item');const st=S.role==="student"?statusOf(a):{tone:"warn",icon:"clock",label:(a.submitted-a.graded)+" to grade"};
    const i=el('span','sico '+st.tone);i.append(ic(st.icon,18));
    const t=el('div');const l=el('div','t',a.title);const m=el('div','muted small');m.append(courseTag(a.course),document.createTextNode("  "+(S.role==="student"?rel(a.due):a.submitted+" of "+a.students+" students submitted")));
    t.append(l,m);b.append(i,t,el('div','sp'),el('span','pill '+(st.tone==="mute"?"mute":st.tone),st.label));
    b.onclick=()=>{S.open.add(a.id);go("assign")};lb.append(b)});
  if(!rows.length){const e=el('div','empty');e.append(el('b',null,S.role==="student"?"Nothing to hand in":"All caught up"),document.createTextNode(S.role==="student"?"New assignments from your professor will appear here.":"New submissions will appear here."));lb.append(e)}
  left.append(lb);
  const ch=el('div','courses');
  const title=el('h3',null,"Your courses");title.style.margin="0 0 2px";right.append(title);
  S.P.courses.forEach((c,i)=>{
    const as=A.filter(a=>a.course===c.code),card=el('button','card course');card.style.textAlign="left";card.style.width="100%";
    card.append(el('div','bar c'+(i%4)));const b=el('div','in2');b.append(el('b',null,c.name));
    const todo=S.role==="student"?as.filter(a=>!a.submission).length+" to hand in":as.reduce((n,a)=>n+a.submitted,0)+" submissions";
    b.append(el('span','muted small',c.code+", "+as.length+(as.length===1?" assignment":" assignments")+", "+todo));
    card.append(b);card.onclick=()=>{S.cfilter=c.code;go("materials")};ch.append(card)});
  right.append(ch);
  cols.append(left,right);root.append(cols);
  const tip=el('div','tip');tip.style.marginTop="20px";
  tip.append(el('b',null,"Curious how your files travel?"),el('div','small','Every upload and download crosses a real network switch watched by an SDN controller. '));
  const a=el('button','link','Watch it happen on the Network activity page');a.onclick=()=>go("activity");tip.lastChild.append(a);root.append(tip);
  return root}

/* ---------------- assignments ---------------- */
function xhrUpload(url,file,prog){return new Promise(resolve=>{
  const x=new XMLHttpRequest(),bar=prog.firstElementChild;x.open("POST",url);prog.style.display="block";bar.style.width="0";
  startTransfer("upload",file.name);
  const fail=msg=>{const i=S.T?S.T.steps.findIndex(s=>s.state==="active"):-1;stepSet(i>=0?i:1,"fail",msg);endTransfer(false)};
  x.upload.onprogress=e=>{if(e.lengthComputable){bar.style.width=(100*e.loaded/e.total)+"%";stepSet(0,"active",Math.round(100*e.loaded/e.total)+"% of "+fmt(e.total))}};
  x.upload.onload=()=>{stepSet(0,"done",fmt(file.size)+" sent");stepSet(1,"active","sending over TCP...")};
  x.onload=()=>{prog.style.display="none";let d={};try{d=JSON.parse(x.responseText)}catch(e){}
    if(x.status===200){stepSet(0,"done",fmt(file.size)+" sent");stepSet(1,"done",(d.ms/1000).toFixed(2)+" s"+(d.mbps?" at "+d.mbps+" Mbit/s":"")+", measured");stepSet(2,"done","saved");endTransfer(true)}
    else fail(d.error||"failed");
    resolve({ok:x.status===200,d})};
  x.onerror=()=>{prog.style.display="none";fail("connection lost");resolve({ok:false,d:{error:"Upload failed. The connection was lost."}})};
  x.send(file)})}
function receipt(verb,name,d){
  const sp=d.mbps?" ("+d.mbps+" Mbit/s)":"";
  toast(verb+" "+name,"Sent from the portal to the file server over a TCP connection through the campus network in "+(d.ms/1000).toFixed(1)+" s"+sp+".",null,["See how it travelled",()=>go("activity")])}
function dropZone(buttonText,primary,onFiles,hint){
  const z=el('div','drop');const inp=el('input');inp.type="file";inp.hidden=true;inp.multiple=!!onFiles.multiple;
  const b=el('button','btn sm'+(primary?" primary":""),buttonText);b.type="button";b.onclick=()=>inp.click();
  z.append(b,inp,el('span','small',hint||"or drag a file here"));
  inp.onchange=()=>{if(inp.files.length)onFiles([...inp.files],b);inp.value=""};
  ["dragenter","dragover"].forEach(t=>z.addEventListener(t,e=>{e.preventDefault();z.classList.add("over")}));
  ["dragleave","drop"].forEach(t=>z.addEventListener(t,e=>{e.preventDefault();z.classList.remove("over")}));
  z.addEventListener("drop",e=>{if(e.dataTransfer.files.length)onFiles([...e.dataTransfer.files],b)});
  return z}
function viewAssign(){
  const root=el('div'),A=S.P.assignments;
  let act=null;
  if(staff()){act=el('button','btn primary');act.append(ic('plus',16),document.createTextNode("New assignment"));act.onclick=newAssignmentDialog}
  root.append(head("Assignments",S.role==="student"?"Open an assignment to hand in your work and see your marks.":"Publish assignments, then open one to download submissions and give marks.",act));
  if(S.role==="student"){
    const chips=el('div','chips');
    [["all","All"],["todo","To do"],["submitted","Handed in"],["graded","Graded"]].forEach(([k,l])=>{
      const b=el('button','chip'+(S.filter===k?" on":""),l);b.onclick=()=>{S.filter=k;render()};chips.append(b)});
    root.append(chips)}
  let list=A.slice().sort((a,b)=>a.due.localeCompare(b.due));
  if(S.role==="student"&&S.filter!=="all")list=list.filter(a=>statusOf(a).key===S.filter);
  if(!list.length){const e=el('div','card empty');e.append(el('b',null,"No assignments here"),document.createTextNode(S.role==="student"?"Try another filter.":"Use New assignment to publish one."));root.append(e)}
  list.forEach(a=>root.append(assignCard(a)));
  return root}
function assignCard(a){
  const open=S.open.has(a.id),c=el('div','card acc'+(open?" open":""));
  const h=el('button','head');h.setAttribute("aria-expanded",open);
  const st=S.role==="student"?statusOf(a):{tone:a.submitted>a.graded?"warn":"ok",icon:a.submitted>a.graded?"clock":"check"};
  const i=el('span','sico '+(st.tone==="mute"?"":st.tone));i.append(ic(st.icon,18));
  const t=el('div');t.append(el('div','title',a.title));
  const m=el('div','muted small');m.append(courseTag(a.course));
  const due=el('span',null,"  Due "+when(a.due)+" ");const r=el('span',null,"("+rel(a.due).replace(/^Due /,"").replace(/^Overdue/,"overdue")+")");if(overdue(a.due)&&S.role==="student"&&!a.submission)r.style.color="var(--bad)";m.append(due,r);t.append(m);
  h.append(i,t,el('div','sp'));
  if(S.role==="student")h.append(el('span','pill '+st.tone,st.label));
  else{const tx=a.submitted+" of "+a.students+" handed in";h.append(el('span','small muted',tx));if(a.submitted>a.graded)h.append(el('span','pill warn',(a.submitted-a.graded)+" to grade"))}
  const ch=ic('chev',18);ch.classList.add('chev');h.append(ch);
  h.onclick=()=>{if(S.open.has(a.id))S.open.delete(a.id);else S.open.add(a.id);render()};
  c.append(h);
  if(open){const b=el('div','body');if(a.desc)b.append(el('p','desc',a.desc));
    if(S.role==="student")studentBody(a,b);else staffBody(a,b);c.append(b)}
  return c}
function studentBody(a,b){
  const blk=el('div','block');blk.append(el('div','cap',"Your work"));
  if(a.submission){const s=a.submission,row=el('div','filerow');row.append(fileIcon(s.orig));
    const t=el('div'),l=el('a','link',s.orig);l.href="/api/download?name="+encodeURIComponent(s.file);
    const m=el('div','muted small',fmt(s.size)+", handed in "+when(s.time));if(s.late)m.append(document.createTextNode(" "),el('span','pill warn','Late'));
    t.append(l,m);row.append(t);blk.append(row)}
  else blk.append(el('div','muted',"You haven't handed anything in yet."));
  const prog=el('div','prog');prog.append(el('div'));
  blk.append(dropZone(a.submission?"Replace file":"Choose file",!a.submission,async(files,btn)=>{
    const f=files[0];btn.disabled=true;
    const r=await xhrUpload("/api/submit?aid="+encodeURIComponent(a.id)+"&name="+encodeURIComponent(f.name),f,prog);btn.disabled=false;
    if(r.ok){receipt("Handed in",r.d.orig,r.d);loadPortal()}else toast("Couldn't hand in your file",r.d.error||"Try again.","bad")},
    "or drag a file here. It is sent to the file server over a TCP connection."),prog);
  b.append(blk);
  if(a.grade){const g=el('div','gradebox'),n=el('div');n.append(el('div','big',a.grade.marks+" / 100"));
    const t=el('div');t.append(el('b',null,"Graded by "+nameOf(a.grade.by)));if(a.grade.feedback)t.append(el('div','fbk',a.grade.feedback));
    g.append(n,t);b.append(g)}
  else if(a.submission&&a.submission.file)b.append(el('p','muted small',"Your professor hasn't graded this yet."))}
function staffBody(a,b){
  const box=el('div','tw');box.style.marginTop="12px";box.textContent="Loading submissions...";b.append(box);loadReview(a.id,box)}
async function loadReview(aid,box){
  const r=await api("/api/review?aid="+encodeURIComponent(aid));
  if(!r.ok){box.textContent=r.d.error||"Couldn't load submissions";return}
  box.textContent="";const t=el('table'),hd=el('tr');
  ["Student","Submission","Marks (0-100)","Feedback",""].forEach(x=>hd.append(el('th',null,x)));{const th=el('thead');th.append(hd);t.append(th)};
  const tb=el('tbody');t.append(tb);
  r.d.rows.forEach(row=>{
    const tr=el('tr'),sc=el('td'),w=el('div','filerow');w.append(avatar(row.student,28),el('b',null,nameOf(row.student)));sc.append(w);tr.append(sc);
    const fc=el('td');
    if(row.submission){const s=row.submission,l=el('a','link',s.orig);l.href="/api/download?name="+encodeURIComponent(s.file);
      fc.append(l,el('div','muted small',fmt(s.size)+", "+when(s.time)));if(s.late)fc.append(el('span','pill warn','Late'))}
    else fc.append(el('span','muted',"Not handed in"));
    tr.append(fc);
    const mk=el('input','in');mk.type="number";mk.min=0;mk.max=100;mk.style.width="80px";mk.disabled=!row.submission;mk.value=row.grade?row.grade.marks:"";mk.setAttribute("aria-label","Marks for "+row.student);
    const fb=el('input','in');fb.type="text";fb.maxLength=300;fb.placeholder="Add feedback";fb.style.minWidth="190px";fb.disabled=!row.submission;fb.value=row.grade?row.grade.feedback:"";fb.setAttribute("aria-label","Feedback for "+row.student);
    const sv=el('button','btn sm',row.grade?"Update marks":"Save marks");sv.disabled=!row.submission;
    sv.onclick=async()=>{const g=await post("/api/grade",{aid,student:row.student,marks:mk.value,feedback:fb.value});
      if(g.ok){toast("Saved marks for "+nameOf(row.student),mk.value+" out of 100");loadPortal()}else toast("Couldn't save marks",g.d.error,"bad")};
    [mk,fb,sv].forEach(x=>{const td=el('td');td.append(x);tr.append(td)});tb.append(tr)});
  box.append(t)}
function newAssignmentDialog(){
  const f=el('div');const g=el('div','formgrid');
  const cs=el('select','in');S.P.courses.forEach(c=>{const o=el('option',null,c.code+": "+c.name);o.value=c.code;cs.append(o)});
  const ti=el('input','in');ti.maxLength=80;ti.placeholder="For example, Packet analysis lab";
  const du=el('input','in');du.type="datetime-local";
  const de=el('textarea','in');de.maxLength=300;de.placeholder="What should students hand in?";
  const fld=(l,x)=>{const w=el('div');w.append(el('label','f',l),x);return w};
  g.append(fld("Course",cs),fld("Due date and time",du),fld("Title",ti),fld("Instructions (optional)",de));
  const msg=el('div');const foot=el('div','df');
  const cancel=el('button','btn','Cancel');cancel.onclick=()=>dlg.close();
  const ok=el('button','btn primary','Publish assignment');
  ok.onclick=async()=>{const r=await post("/api/assignment",{course:cs.value,title:ti.value,due:du.value,desc:de.value});
    if(r.ok){dlg.close();toast("Published "+r.d.title,"Students in "+r.d.course+" can see it now.");S.open.add(r.d.id);loadPortal()}else note(msg,r.d.error||"Couldn't publish","bad")};
  foot.append(cancel,ok);f.append(g,msg,foot);openDialog("New assignment",f)}

/* ---------------- materials ---------------- */
function viewMaterials(){
  const root=el('div');root.append(head("Course materials",staff()?"Share notes, slides and readings with the students in a course.":"Notes, slides and readings shared by your professors."));
  const chips=el('div','chips');
  [{code:"all",name:"All courses"}].concat(S.P.courses).forEach(c=>{
    const b=el('button','chip'+(S.cfilter===c.code?" on":""),c.code==="all"?"All courses":c.code);b.onclick=()=>{S.cfilter=c.code;render()};chips.append(b)});
  root.append(chips);
  if(staff()){
    const card=el('div','card');const bd=el('div','bd');const cs=el('select','in');cs.style.width="auto";cs.style.marginRight="8px";
    S.P.courses.forEach(c=>{const o=el('option',null,c.code+": "+c.name);o.value=c.code;cs.append(o)});if(S.cfilter!=="all")cs.value=S.cfilter;
    const prog=el('div','prog');prog.append(el('div'));
    const row=el('div','filerow');row.append(el('b',null,"Share with"),cs);
    const share=async(files,btn)=>{btn.disabled=true;let n=0;
      for(const f of files){const r=await xhrUpload("/api/material?course="+encodeURIComponent(cs.value)+"&name="+encodeURIComponent(f.name),f,prog);
        if(r.ok){n++;receipt("Shared",r.d.orig,r.d)}else{toast("Couldn't share "+f.name,r.d.error||"Try again.","bad");break}}
      btn.disabled=false;if(n)loadPortal()};
    share.multiple=true;
    const z=dropZone("Choose files",true,share,"or drag files here");
    bd.append(row,z,prog);card.append(bd);card.style.marginBottom="16px";root.append(card)}
  const items=S.P.materials.filter(m=>S.cfilter==="all"||m.course===S.cfilter);
  if(!items.length){const e=el('div','card empty');e.append(el('b',null,"No materials yet"),document.createTextNode(staff()?"Choose a file above to share it with the course.":"Your professor hasn't shared anything for this course yet."));root.append(e);return root}
  S.P.courses.forEach(c=>{
    const mi=items.filter(m=>m.course===c.code);if(!mi.length)return;
    const card=el('div','card');card.style.marginBottom="14px";const hd=el('div','hd');hd.append(courseTag(c.code),el('h3',null,c.name));card.append(hd);
    const bd=el('div','bd list');
    mi.forEach(m=>{const r=el('div','item');const t=el('div');t.append(el('div','t',m.name),el('div','muted small',fmt(m.size)+", shared by "+nameOf(m.uploader)));
      const a=el('a','btn sm');a.href="/api/download?name="+encodeURIComponent(m.file);a.style.textDecoration="none";a.append(ic('down',15),document.createTextNode("Download"));
      r.append(fileIcon(m.name),t,el('div','sp'),a);bd.append(r)});
    card.append(bd);root.append(card)});
  return root}


/* ---------------- live network dock ---------------- */
function setDock(v){S.dock=v;$("app").classList.toggle("dock-open",v);$("dockBtn").classList.toggle("on",v);$("dockBtn").setAttribute("aria-pressed",v);
  try{localStorage.setItem("cs_dock",v?"1":"0")}catch(e){}
  if(v){buildDock();updateJourney()}}
function buildDock(){
  const d=$("dock");if(d.firstChild)return;
  const h=el('div','dkhead'),t=el('div');t.append(el('b',null,"Live network"),el('small',null,"Live view of your files"));
  const x=el('button','btn sm',"Hide");x.onclick=()=>setDock(false);
  const tg=el('label','tgl'),cb=document.createElement('input');cb.type='checkbox';cb.id='slowTgl';cb.checked=!!S.slowAuto;cb.onchange=()=>{S.slowAuto=cb.checked;try{localStorage.setItem("cs_slow",cb.checked?"1":"0")}catch(e){}};tg.title="Replay every transfer in slow motion when it finishes";tg.append(cb,document.createTextNode("Slow motion"));
  h.append(t,el('div','sp'),tg,x);
  const body=el('div','dkbody');
  const c1=el('div','dkcard');c1.id="dkTransfer";
  const c2=el('div','dkcard');c2.append(el('h4',null,"The journey of a file"),miniJourney());
  const c3=el('div','dkcard');c3.id="dkTraffic";const c4=el('div','dkcard');c4.id="dkEvents";
  body.append(c1,c2,c3,c4);d.append(h,body);renderTransfer();renderDockTraffic();renderDockEvents()}
function miniJourney(){
  const m=el('div','mini');
  const hop=(a,b)=>{const h=el('div','hop',a);h.append(el('small',null,b));return h};
  const conn=(cls,label)=>{const c=el('div','conn '+cls);c.append(el('span',null,label));return c};
  const sw=hop("Network switch","Open vSwitch");
  const ctl=el('div','ctl j-ctl');ctl.append(el('b',null,"SDN controller"),el('span','j-ctl-text',"Watching all traffic"));sw.append(ctl);
  const hs=[hop("Your browser","where you click"),hop("CampusShare portal","roles and rules"),sw,hop("File server","stores your files")];
  const cs=[conn('j-e1',"HTTP"),conn('j-e2',"TCP socket"),conn('j-e3',"TCP socket")];cs.forEach(c=>c.append(el('i','dot')));
  hs.forEach((h,i)=>h.dataset.hop=i);cs.forEach((c,i)=>c.dataset.conn=i);
  m.append(hs[0],cs[0],hs[1],cs[1],hs[2],cs[2],hs[3]);
  return m}
function dispName(f){return f.startsWith("SUB_")?f.split("_").slice(3).join("_"):f.startsWith("MAT_")?f.split("_").slice(2).join("_"):f}
function startTransfer(kind,name){
  const up=kind==="upload";
  const labels=up?["Your browser sends the file to the portal","The portal sends it to the file server over TCP, through the switch","The file server stores it"]
    :["Your browser asks the portal for the file","The portal fetches it from the file server over TCP, through the switch","The portal sends it to your browser"];
  S.T={kind,name,state:"running",t0:Date.now(),steps:labels.map(l=>({label:l,state:"wait",detail:""}))};
  S.T.steps[0].state=up?"active":"done";if(!up){S.T.steps[1].state="active"}
  if(window.innerWidth>=1200&&!S.dock)setDock(true);
  renderTransfer()}
function stepSet(i,state,detail){if(!S.T)return;const s=S.T.steps[i];if(!s)return;s.state=state;if(detail!=null)s.detail=detail;renderTransfer()}
function endTransfer(ok){if(!S.T)return;S.T.state=ok?"done":"failed";S.T.took=(Date.now()-S.T.t0)/1000;renderTransfer();if(ok&&S.slowAuto){if(!S.dock)setDock(true);setTimeout(()=>S.T&&playSlow(S.T),400)}}
function renderTransfer(){
  const c=$("dkTransfer");if(!c)return;c.textContent="";const T=S.T;
  c.append(el('h4',null,!T?"Transfers":T.state==="running"?"Transfer in progress":T.state==="done"?"Last transfer":"Transfer failed"));
  if(!T){c.append(el('p','muted small',"Nothing is moving right now. Hand in or download a file and each step will appear here."));return}
  const row=el('div','filerow');row.style.marginBottom="6px";row.append(fileIcon(T.name),el('div',null,T.name));row.lastChild.style.fontWeight="600";row.lastChild.style.wordBreak="break-all";c.append(row);
  T.steps.forEach(s=>{
    const r=el('div','tstep '+s.state),i=el('span','tic');
    if(s.state==="active")i.append(el('span','spin'));else i.append(ic(s.state==="done"?"check":s.state==="fail"?"alert":"clock",20));
    const t=el('div',null,s.label);if(s.detail)t.append(el('small',null,s.detail));r.append(i,t);c.append(r)});
  if(T.state==="done"){const f=el('div','muted small',"Finished in "+T.took.toFixed(1)+" s.");f.style.marginTop="6px";
    if(T.sha)f.append(document.createElement("br"),document.createTextNode("Checksum (SHA-256) "+T.sha.slice(0,12)+"..."));
    f.append(document.createElement("br"));const l=el('button','link small',"See all transfers");l.onclick=()=>go("activity");f.append(l);c.append(f);
    const pb=el('button','btn sm primary',"Watch it again in slow motion");pb.style.marginTop="10px";pb.onclick=()=>playSlow(T);c.append(pb)}
  if(S.slow)c.append(S.slow.box)}
const SLOWV=0;
function slowStages(T){
  const up=T.kind==="upload",n=T.name;
  const base=up?[
   {h:[0],c:null,t:"1. You pick the file",d:"Your browser reads "+n+" and sends it to the CampusShare portal over HTTP."},
   {h:[0,1],c:0,t:"2. Browser to portal (HTTP)",d:"The file travels to the portal. The portal checks who you are and whether you may hand in work here."},
   {h:[1],c:null,t:"3. Portal opens a TCP socket",d:"The portal connects to the file server on port 5000 and logs in with AUTH, then announces the file with UPLOAD name size."},
   {h:[1,2],c:1,t:"4. Portal to switch (TCP)",d:"The bytes leave the portal and enter the Open vSwitch on port 5."},
   {h:[2],c:null,t:"5. The switch asks the controller",d:"The SDN controller has rules for this traffic: not blocked, within the fair-use limit, so the packets are forwarded."},
   {h:[2,3],c:2,t:"6. Switch to file server (TCP)",d:"The switch forwards the packets out of port 4 to the file server."},
   {h:[3],c:null,t:"7. The file server stores it",d:"It reads exactly the announced number of bytes, saves the file, records it in metadata and replies OK."}
  ]:[
   {h:[0],c:null,t:"1. You click Download",d:"Your browser asks the portal for "+n+" over HTTP."},
   {h:[1],c:null,t:"2. The portal checks the rules",d:"A student may fetch only their own work and course materials. Staff may fetch any submission."},
   {h:[1,2],c:1,t:"3. Portal to switch (TCP)",d:"The portal opens a TCP socket and sends DOWNLOAD name. The request enters the switch."},
   {h:[2],c:null,t:"4. The controller allows it",d:"The controller's rules let the request through to the file server."},
   {h:[2,3],c:2,t:"5. Switch to file server (TCP)",d:"The request reaches the file server, which looks up the file."},
   {h:[3],c:null,t:"6. The file server sends the bytes",d:"It replies with the exact size, then streams the file back."},
   {h:[3,2],c:2,rev:1,t:"7. File server to switch",d:"The data flows back through the switch, again checked by the controller."},
   {h:[2,1],c:1,rev:1,t:"8. Switch to portal",d:"The portal receives every byte and works out a SHA-256 checksum."},
   {h:[1,0],c:0,rev:1,t:"9. Portal to your browser",d:"The portal sends the file to you over HTTP. Your browser saves it."}
  ];
  return base}
let slowTimer=null;
function stopSlow(){clearTimeout(slowTimer);slowTimer=null;S.slow=null;document.querySelectorAll(".hop.lit").forEach(x=>x.classList.remove("lit"));document.querySelectorAll(".conn.pkt").forEach(x=>{x.classList.remove("pkt","rev")});renderTransfer()}
function playSlow(T){
  clearTimeout(slowTimer);const st=slowStages(T),DUR=3200;let i=0;
  const box=el('div','slowbox'),sn=el('div','sn'),tt=el('div','st'),dd=el('div','sd'),bar=el('div','slowbar'),bi=el('i');bar.append(bi);
  const ctrl=el('div');ctrl.style.cssText="display:flex;gap:8px;margin-top:8px";
  const pause=el('button','btn sm',"Pause"),skip=el('button','btn sm',"Skip"),stp=el('button','btn sm',"Stop");ctrl.append(pause,skip,stp);
  box.append(sn,tt,dd,bar,ctrl);S.slow={box};let paused=false;
  const show=()=>{
    document.querySelectorAll(".hop.lit").forEach(x=>x.classList.remove("lit"));document.querySelectorAll(".conn.pkt").forEach(x=>x.classList.remove("pkt","rev"));
    if(i>=st.length){tt.textContent="Done";sn.textContent="Finished";dd.textContent="That is the whole journey. In real life it took "+(T.took!=null?T.took.toFixed(1):"a fraction of a")+" s.";bi.style.width="100%";ctrl.remove();const b=el('button','btn sm',"Close");b.style.marginTop="8px";b.onclick=stopSlow;box.append(b);return}
    const s=st[i];sn.textContent="Step "+(i+1)+" of "+st.length;tt.textContent=s.t;dd.textContent=s.d;bi.style.transition="none";bi.style.width="0";void bi.offsetWidth;bi.style.transition="width "+DUR+"ms linear";bi.style.width="100%";
    s.h.forEach(k=>{const e=document.querySelector('.hop[data-hop="'+k+'"]');if(e)e.classList.add("lit")});
    if(s.c!=null){const c=document.querySelector('.conn[data-conn="'+s.c+'"]');if(c){c.style.setProperty("--dur",(DUR/1000)+"s");c.classList.toggle("rev",!!s.rev);c.classList.add("pkt")}}
    slowTimer=setTimeout(()=>{if(!paused){i++;show()}},DUR)};
  pause.onclick=()=>{paused=!paused;pause.textContent=paused?"Resume":"Pause";if(paused){clearTimeout(slowTimer);bi.style.transition="none"}else{i++;show()}};
  skip.onclick=()=>{clearTimeout(slowTimer);paused=false;pause.textContent="Pause";i++;show()};
  stp.onclick=stopSlow;
  renderTransfer();show();
  const j=document.querySelector(".mini");if(j&&j.scrollIntoView)j.closest(".dkcard").scrollIntoView({block:"nearest",behavior:"smooth"})}
function barPct(v){return Math.max(v>0.005?4:0,Math.min(100,100*Math.log10(1+v*100)/5))}
function trafficInto(c,title){
  c.textContent="";c.append(el('h4',null,title));const N=S.N||{ports:[],age:null};
  if(!N.ports.length||N.age===null||N.age>15){c.append(el('p','muted small',"No live data. The controller is not reporting yet."));return}
  c.append(el('p','muted small',"How much data is moving through each connection to the switch (updates every 2 s; small files pass in less than that)."));
  N.ports.forEach(p=>{const [nm,sub]=portLabel(p.port);const w2=el('div','port'),t=el('div','top2');const l=el('div');l.append(el('b',null,nm),el('small',null,sub));t.append(l);
    const rt=el('div','rate',p.port===4?"Serving "+p.down.toFixed(2)+", receiving "+p.up.toFixed(2)+" Mbit/s":"Downloading "+p.down.toFixed(2)+", uploading "+p.up.toFixed(2)+" Mbit/s");
    const tr=el('div','track'),f=el('div');f.style.width=barPct(p.up+p.down)+"%";tr.append(f);const pk=(S.peak||{})[p.port],pt=el('div','muted small',pk&&pk.v>0.005&&(p.up+p.down)<pk.v*0.5?"Peak in the last 20 s: "+pk.v.toFixed(2)+" Mbit/s":"");w2.append(t,rt,tr);if(pt.textContent)w2.append(pt);c.append(w2)})}
function renderDockTraffic(){const c=$("dkTraffic");if(c)trafficInto(c,"Traffic right now")}
function renderDockEvents(){
  const c=$("dkEvents");if(!c)return;c.textContent="";c.append(el('h4',null,"What the controller did"));
  const evs=((S.N&&S.N.events)||[]).slice().reverse().slice(0,3);
  if(!evs.length)c.append(el('p','muted small',"Nothing yet. Enter a wrong password three times to see it react."));
  evs.forEach(l=>{const f=friendly(l),row=el('div','ev'),i=el('span','sico '+(f.tone==="mute"?"":f.tone));i.append(ic(f.icon,16));i.style.width=i.style.height="30px";
    const t=el('div');t.append(el('div','small',f.text),el('div','when',f.time));row.append(i,t);c.append(row)});
  const l=el('button','link small',"See full history");l.style.marginTop="6px";l.onclick=()=>go("activity");c.append(l)}
function dispFromHref(h){return dispName(decodeURIComponent((h.split("name=")[1]||"")))}
document.addEventListener("click",e=>{
  const a=e.target.closest&&e.target.closest('a[href^="/api/download"]');
  if(!a||e.ctrlKey||e.metaKey||e.shiftKey)return;e.preventDefault();downloadFile(a.getAttribute("href"))});
async function downloadFile(href){
  const label=dispFromHref(href);startTransfer("download",label);
  stepSet(0,"done","request sent");stepSet(1,"active","fetching over TCP...");
  const t0=performance.now();let r;
  try{r=await fetch(href)}catch(e){stepSet(1,"fail","connection lost");endTransfer(false);toast("Download failed","The connection was lost.","bad");return}
  if(!r.ok){let d={};try{d=await r.json()}catch(e){}stepSet(1,"fail",d.error||"refused");endTransfer(false);toast("Couldn't download "+label,d.error||"Try again.","bad");return}
  const total=+r.headers.get("Content-Length")||0,sha=r.headers.get("X-Content-SHA256")||"",sec=Math.max((performance.now()-t0)/1000,0.001);
  stepSet(1,"done","portal had the file after "+sec.toFixed(2)+" s"+(total?", about "+(total*8/1e6/sec).toFixed(1)+" Mbit/s":""));
  stepSet(2,"active","0%");
  const reader=r.body.getReader(),chunks=[];let got=0;
  for(;;){const x=await reader.read();if(x.done)break;chunks.push(x.value);got+=x.value.length;if(total)stepSet(2,"active",Math.round(100*got/total)+"% of "+fmt(total))}
  stepSet(2,"done",fmt(got)+" received");if(S.T)S.T.sha=sha;endTransfer(true);
  const m=(r.headers.get("Content-Disposition")||"").match(/filename="([^"]+)"/);
  const url=URL.createObjectURL(new Blob(chunks)),a=document.createElement("a");a.href=url;a.download=m?m[1]:label;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),4000)}
$("dockBtn").onclick=()=>setDock(!S.dock);

/* ---------------- how it works ---------------- */
function journey(){
  const wrap=el('div');
  wrap.innerHTML='<svg class="journey" viewBox="0 0 900 250" role="img" aria-label="A file travels from your browser to the CampusShare portal, through a network switch, to the file server. An SDN controller watches the switch.">'+
  '<rect class="node" x="20" y="108" width="150" height="76" rx="12"/><text class="nt" x="95" y="142" text-anchor="middle">Your browser</text><text class="ns" x="95" y="162" text-anchor="middle">where you click</text>'+
  '<rect class="node" x="250" y="108" width="170" height="76" rx="12"/><text class="nt" x="335" y="142" text-anchor="middle">CampusShare portal</text><text class="ns" x="335" y="162" text-anchor="middle">roles and rules</text>'+
  '<rect class="node" x="500" y="108" width="150" height="76" rx="12"/><text class="nt" x="575" y="142" text-anchor="middle">Network switch</text><text class="ns" x="575" y="162" text-anchor="middle">Open vSwitch</text>'+
  '<rect class="node" x="730" y="108" width="150" height="76" rx="12"/><text class="nt" x="805" y="142" text-anchor="middle">File server</text><text class="ns" x="805" y="162" text-anchor="middle">stores your files</text>'+
  '<rect class="node j-ctl" x="470" y="8" width="210" height="56" rx="12"/><text class="nt" x="575" y="32" text-anchor="middle">SDN controller</text><text class="ns j-ctl-text" x="575" y="51" text-anchor="middle">Watching all traffic</text>'+
  '<line class="edge j-e1" x1="170" y1="146" x2="250" y2="146"/><text class="el" x="210" y="136">HTTP</text>'+
  '<line class="edge j-e2" x1="420" y1="146" x2="500" y2="146"/><text class="el" x="460" y="136">TCP</text>'+
  '<line class="edge j-e3" x1="650" y1="146" x2="730" y2="146"/><text class="el" x="690" y="136">TCP</text>'+
  '<line class="edge ctl" x1="575" y1="64" x2="575" y2="108"/><text class="el" x="640" y="92" text-anchor="start" style="text-anchor:start">rules sent with OpenFlow</text>'+
  '<text class="ns" x="95" y="214" text-anchor="middle">1. You pick a file</text><text class="ns" x="335" y="214" text-anchor="middle">2. Checks who you are</text><text class="ns" x="575" y="214" text-anchor="middle">3. Traffic is watched</text><text class="ns" x="805" y="214" text-anchor="middle">4. File is saved</text>'+
  '</svg>';
  const lg=el('div','legend');lg.innerHTML='<span><i></i>No data moving</span><span><i class="on"></i>Data moving right now</span>';wrap.append(lg);return wrap}
function ipName(ip){return({"10.0.0.1":"Lab PC 1","10.0.0.2":"Lab PC 2","10.0.0.3":"Lab PC 3","10.0.0.4":"the file server","10.0.0.254":"this computer"})[ip]||ip}
function friendly(line){
  let m;const time=(line.match(/^(\d\d:\d\d:\d\d)/)||[])[1]||"";
  if(m=line.match(/UNBLOCK ip=(\S+)/))return{time,tone:"ok",icon:"check",text:"Access restored for "+ipName(m[1])+" ("+m[1]+")."};
  if(m=line.match(/\bBLOCK ip=(\S+) reason=3_failed_logins timeout=(\d+)s response_ms=([\d.]+)/))return{time,tone:"bad",icon:"shield",text:"Blocked "+ipName(m[1])+" ("+m[1]+") for "+m[2]+" seconds after 3 failed sign-ins. The controller reacted in "+Math.round(m[3])+" ms."};
  if(m=line.match(/HOG_UNLIMIT ip=(\S+)/))return{time,tone:"ok",icon:"check",text:"Speed limit removed for "+ipName(m[1])+"."};
  if(m=line.match(/HOG_LIMIT ip=(\S+) limit=(\d+)kbps duration=(\d+)s/))return{time,tone:"warn",icon:"gauge",text:ipName(m[1])+" was using most of the link, so its speed was capped at "+(m[2]/1000)+" Mbit/s for "+m[3]+" seconds to keep things fair."};
  return{time,tone:"mute",icon:"shield",text:line.replace(/^\d\d:\d\d:\d\d\s*/,"")}}
function updateJourney(){
  const N=S.N;if(!N)return;
  const live=N.age!==null&&N.age<=15;const rate=p=>{const x=(N.ports||[]).find(q=>q.port===p);return x?x.up+x.down:0};
  const on=(sel,v)=>document.querySelectorAll(sel).forEach(e=>e.classList.toggle("on",!!v));
  on(".j-e1",live&&rate(5)>0.05);on(".j-e2",live&&rate(5)>0.05);on(".j-e3",live&&rate(4)>0.05);
  const blocked=new Set(),limited=new Set();
  (N.events||[]).forEach(l=>{let m;if(m=l.match(/UNBLOCK ip=(\S+)/))blocked.delete(m[1]);else if(m=l.match(/\bBLOCK ip=(\S+)/))blocked.add(m[1]);
    else if(m=l.match(/HOG_UNLIMIT ip=(\S+)/))limited.delete(m[1]);else if(m=l.match(/HOG_LIMIT ip=(\S+)/))limited.add(m[1])});
  let text="Watching all traffic",cls="";
  if(blocked.size){text="Blocking "+[...blocked].map(ipName).join(", ");cls="block"}
  else if(limited.size){text="Slowing "+[...limited].map(ipName).join(", ");cls="limit"}
  document.querySelectorAll(".j-ctl").forEach(e=>{e.classList.toggle("block",cls==="block");e.classList.toggle("limit",cls==="limit")});
  document.querySelectorAll(".j-ctl-text").forEach(e=>e.textContent=text)}
function howView(){
  const root=el('div');
  const p=el('p',null,"CampusShare lets students hand in assignments and download course materials. Behind the screen, each file travels across a small campus network that this project builds and controls. Here is the journey.");p.style.marginBottom="14px";root.append(p);
  root.append(journey());
  const h=el('h3',null,"What happens when you hand in a file");h.style.margin="22px 0 8px";root.append(h);
  const steps=el('div','steps');
  [["Your browser sends the file to the portal.","The portal is the CampusShare application. It receives the file over normal web traffic (HTTP)."],
   ["The portal checks who you are.","It knows if you are a student, professor or admin, and applies the rules: students only see their own work and course materials."],
   ["The portal sends the file to the file server over a TCP socket.","This is the core of the project. The two programs talk using our own protocol with sign-in, upload and download commands, and an exact byte count so no file is ever cut short."],
   ["The file crosses the network switch, and the SDN controller watches.","The controller measures the traffic, blocks a computer for 30 seconds after 3 failed sign-ins, and slows a computer that hogs the link."],
   ["The file server stores it and reports back.","You see a confirmation with how long the transfer took. The Network activity page lists every transfer."]].forEach(([t,d])=>{
    const s=el('div');const x=el('div');x.append(el('b',null,t),el('span','muted',d));s.append(x);steps.append(s)});
  root.append(steps);
  const g=el('div','grid3');g.style.marginTop="22px";
  [["shield","Security","After 3 wrong passwords in a row, the controller blocks that computer for 30 seconds, then lets it back in on its own."],
   ["gauge","Fair use","If one computer takes most of the link while others are waiting, the controller caps its speed for 20 seconds."],
   ["pulse","Monitoring","The controller counts the data passing each switch port every 2 seconds. You can see it live on Network activity."]].forEach(([i,t,d])=>{
    const c=el('div','card');const b=el('div','bd');const hh=el('div','filerow');hh.append(ic(i,20),el('b',null,t));b.append(hh);const dd=el('p','muted small',d);dd.style.marginTop="6px";b.append(dd);c.append(b);g.append(c)});
  root.append(g);
  const tip=el('div','tip');tip.style.marginTop="22px";tip.append(el('b',null,"Try it yourself"));
  const ol=el('ol');["Sign out, then sign in with a wrong password three times.","Sign in correctly after the 30-second wait, then open Network activity.","Find the red block message and the green message that access was restored."].forEach(t=>ol.append(el('li',null,t)));tip.append(ol);root.append(tip);
  return root}
function viewHow(){const r=el('div');r.append(head("How it works","What the network does for you while you use CampusShare."));const c=el('div','card');const b=el('div','bd');b.append(howView());c.append(b);r.append(c);return r}

/* ---------------- network activity ---------------- */
function viewActivity(){
  const root=el('div');root.append(head("Network activity","See what the network does while you use CampusShare. Hand in a file or download one and watch it appear here."));
  const jc=el('div','card');const jb=el('div','bd');jb.append(journey());jc.append(jb);jc.style.marginBottom="20px";root.append(jc);
  const cols=el('div','grid2');
  const left=el('div','card');const lh=el('div','hd');lh.append(el('h3',null,"Recent file transfers"));left.append(lh);
  const lb=el('div','bd');lb.id="actBody";left.append(lb);
  const right=el('div');right.id="liveBody";
  cols.append(left,right);root.append(cols);renderActivityBody();renderLive();return root}
function renderActivityBody(){
  const b=$("actBody");if(!b)return;b.textContent="";
  const items=(S.A&&S.A.items)||[];
  b.append(el('p','muted small',"Showing "+((S.A&&S.A.scope)||"your")+" recent activity. Speed is measured between the portal and the file server."));
  if(!items.length){const e=el('div','empty');e.append(el('b',null,"No transfers yet"),document.createTextNode("Hand in a file or download one and it will show up here."));b.append(e);return}
  const w=el('div','tw'),t=el('table'),hd=el('tr');["Time","Who","What happened","Size","Speed",""].forEach(x=>hd.append(el('th',null,x)));{const th=el('thead');th.append(hd);t.append(th)};const tb=el('tbody');t.append(tb);
  items.forEach(i=>{const tr=el('tr');tr.append(el('td','muted small',i.t));
    const who=el('td'),f=el('div','filerow');f.append(avatar(i.user==="-"?"?":i.user,24),el('span',null,i.user));who.append(f);tr.append(who);
    const wh=el('td');wh.append(el('b',null,i.action));if(i.detail)wh.append(el('div','muted small',i.detail));if(i.sha)wh.append(el('div','muted small',"Checksum (SHA-256) "+i.sha.slice(0,12)+"..."));tr.append(wh);
    tr.append(el('td',null,i.bytes?fmt(i.bytes):"-"));
    tr.append(el('td','small',i.ms!=null&&i.bytes?(i.ms/1000).toFixed(1)+" s, "+(i.mbps||0)+" Mbit/s":"-"));
    const rs=el('td');rs.append(el('span','pill '+(i.ok?"ok":"bad"),i.ok?"Done":"Refused"));tr.append(rs);tb.append(tr)});
  w.append(t);b.append(w)}
function portLabel(p){
  const names={1:["Lab PC 1","switch port 1"],2:["Lab PC 2","switch port 2"],3:["Lab PC 3","switch port 3"],4:["File server","switch port 4"],5:["This computer, via the portal","switch port 5"]};
  return names[p]||["Port "+p,""]}
function renderLive(){
  const r=$("liveBody");if(!r)return;r.textContent="";const N=S.N||{ports:[],events:[],age:null};
  const c1=el('div','card');const h1=el('div','hd');h1.append(el('h3',null,"Traffic right now"));c1.append(h1);
  const b1=el('div','bd');b1.append(el('p','muted small',"Each bar shows how much data is moving through that connection to the network switch."));
  if(!N.ports.length||N.age===null||N.age>15){const e=el('div','empty');e.append(el('b',null,"No live data"),document.createTextNode("The controller is not reporting. Start it to see traffic here."));b1.append(e)}
  else N.ports.forEach(p=>{const [nm,sub]=portLabel(p.port);const w=el('div','port'),t=el('div','top2');const l=el('div');l.append(el('b',null,nm),el('small',null,sub));
    const rt=el('div','rate',p.port===4?"Serving "+p.down.toFixed(2)+", receiving "+p.up.toFixed(2)+" Mbit/s":"Downloading "+p.down.toFixed(2)+", uploading "+p.up.toFixed(2)+" Mbit/s");
    t.append(l,rt);const tr=el('div','track'),f=el('div');f.style.width=barPct(p.up+p.down)+"%";tr.append(f);w.append(t,tr);b1.append(w)});
  c1.append(b1);r.append(c1);
  const c2=el('div','card');c2.style.marginTop="20px";const h2=el('div','hd');h2.append(el('h3',null,"Security and fair use"),el('div','sp'));
  const tg=el('button','link small',S.showRaw?"Show plain text":"Show technical log");tg.onclick=()=>{S.showRaw=!S.showRaw;renderLive()};h2.append(tg);c2.append(h2);
  const b2=el('div','bd');b2.append(el('p','muted small',"What the SDN controller decided, newest first."));
  const evs=(N.events||[]).slice().reverse();
  if(!evs.length){const e=el('div','empty');e.append(el('b',null,"Nothing to report"),document.createTextNode("Enter a wrong password three times to see the controller react."));b2.append(e)}
  evs.forEach(l=>{const f=friendly(l),row=el('div','ev'),i=el('span','sico '+(f.tone==="mute"?"":f.tone));i.append(ic(f.icon,16));i.style.width=i.style.height="30px";
    const t=el('div');if(S.showRaw)t.append(el('code',null,l));else{t.append(el('div',null,f.text),el('div','when',f.time))}row.append(i,t);b2.append(row)});
  c2.append(b2);r.append(c2)}

init();pollSdn();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-host", default="10.0.0.4")
    ap.add_argument("--server-port", type=int, default=5000)
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--events-log", default=os.path.join(BASE_DIR, "controller_events.log"))
    ap.add_argument("--stats", default=os.path.join(BASE_DIR, "stats.csv"))
    ap.add_argument("--portal", default=os.path.join(BASE_DIR, "portal.json"))
    a = ap.parse_args()
    CFG.update(server_host=a.server_host, server_port=a.server_port,
               events_log=a.events_log, stats=a.stats, portal=a.portal)
    if not os.path.exists(a.portal):
        mutate(lambda d: None)               # write the seed data (courses, sample assignments)
    httpd = ThreadingHTTPServer((a.listen, a.port), Handler)
    httpd.daemon_threads = True
    print("CampusShare on http://%s:%d  ->  file server %s:%d"
          % (a.listen, a.port, a.server_host, a.server_port), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

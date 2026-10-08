"""FastAPI + WebSocket server for OpenTUI GUI integration.

Provides REST endpoints and real-time WebSocket streaming for:
- System health (server, controller, mininet)
- Events (auth, upload, download, blocks)
- Bandwidth statistics
- Dynamic blocks (with manual unblock)
- OpenFlow rules
- File operations (list, upload, download)
- Authentication (JWT)
"""
import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

from controller import set_ws_broadcast as set_controller_ws_broadcast
from server import set_ws_broadcast as set_server_ws_broadcast

BASE_DIR = Path(__file__).parent
EVENTS_FILE = BASE_DIR / "events.jsonl"
CONTROLLER_LOG_FILE = BASE_DIR / "controller_events.log"
STATS_FILE = BASE_DIR / "stats.csv"
METADATA_FILE = BASE_DIR / "metadata.json"
SHARED_DIR = BASE_DIR / "shared_files"

SECRET_KEY = os.environ.get("GUI_SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth")

USERS = {
    "admin": "1234",
    "alice": "alice123",
    "bob": "bob123",
}


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections[:]:
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


ws_manager = ConnectionManager()


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in USERS:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username


def read_jsonl_tail(filepath: Path, max_lines: int = 100) -> list[dict]:
    if not filepath.exists():
        return []
    lines = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return lines[-max_lines:]


def read_stats_csv() -> dict[str, Any]:
    if not STATS_FILE.exists():
        return {"ports": {}, "timestamp": time.time()}
    ports = {}
    latest_ts = 0
    with open(STATS_FILE, "r") as f:
        for line in f:
            if line.startswith("ts,"):
                continue
            parts = line.strip().split(",")
            if len(parts) >= 4:
                try:
                    ts = float(parts[0])
                    port = int(parts[1])
                    rx = float(parts[2])
                    tx = float(parts[3])
                    if ts > latest_ts:
                        latest_ts = ts
                        ports[port] = {"rx_mbps": rx, "tx_mbps": tx}
                except ValueError:
                    pass
    return {"ports": ports, "timestamp": latest_ts or time.time()}


def read_metadata() -> dict:
    if not METADATA_FILE.exists():
        return {}
    try:
        with open(METADATA_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def get_file_list() -> list[dict]:
    meta = read_metadata()
    files = []
    if SHARED_DIR.exists():
        for name in sorted(SHARED_DIR.iterdir()):
            if name.is_file() and not name.name.endswith(".part"):
                stat = name.stat()
                m = meta.get(name.name, {})
                files.append({
                    "name": name.name,
                    "size": stat.st_size,
                    "uploader": m.get("uploader", "-"),
                    "upload_time": m.get("upload_time", "-"),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
    return files


def read_controller_log_tail(max_lines: int = 50) -> list[str]:
    if not CONTROLLER_LOG_FILE.exists():
        return []
    with open(CONTROLLER_LOG_FILE, "r") as f:
        lines = f.readlines()
    return [l.strip() for l in lines[-max_lines:]]


def get_blocks_from_log() -> list[dict]:
    blocks = []
    for line in read_controller_log_tail(200):
        if "BLOCK ip=" in line:
            parts = line.split()
            ip = None
            timeout = None
            for p in parts:
                if p.startswith("ip="):
                    ip = p.split("=")[1]
                elif p.startswith("timeout="):
                    timeout = int(p.split("=")[1].rstrip("s"))
            if ip:
                blocks.append({
                    "ip": ip,
                    "reason": "3_failed_logins",
                    "expiry": time.time() + (timeout or 30),
                    "timestamp": line.split()[0],
                })
        elif "UNBLOCK ip=" in line:
            for p in line.split():
                if p.startswith("ip="):
                    ip = p.split("=")[1]
                    blocks = [b for b in blocks if b["ip"] != ip]
    return blocks


def get_flows_from_log() -> list[dict]:
    flows = []
    for line in read_controller_log_tail(200):
        if "HOG_LIMIT ip=" in line:
            parts = line.split()
            ip = None
            limit = None
            duration = None
            for p in parts:
                if p.startswith("ip="):
                    ip = p.split("=")[1]
                elif p.startswith("limit="):
                    limit = p.split("=")[1].rstrip("kbps")
                elif p.startswith("duration="):
                    duration = int(p.split("=")[1].rstrip("s"))
            if ip:
                flows.append({
                    "priority": 160,
                    "match": f"ipv4_src=10.0.0.4,ipv4_dst={ip},tcp_src=5000",
                    "actions": f"meter=100+port,output=port",
                    "timeout": duration or 20,
                    "type": "hog_limiter",
                })
        elif "STATIC_BLOCK" in line and "installed" in line:
            for p in line.split():
                if p.startswith("10.0.0."):
                    flows.append({
                        "priority": 150,
                        "match": f"ipv4_src={p},ipv4_dst=10.0.0.4,tcp_dst=5000",
                        "actions": "drop",
                        "timeout": 0,
                        "type": "static_block",
                    })
    return flows


@asynccontextmanager
async def lifespan(app: FastAPI):
    set_controller_ws_broadcast(ws_manager.broadcast)
    set_server_ws_broadcast(ws_manager.broadcast)
    yield
    for ws in ws_manager.active_connections[:]:
        await ws.close()


app = FastAPI(title="SDN File Sharing GUI API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Token(BaseModel):
    access_token: str
    token_type: str


class FileInfo(BaseModel):
    name: str
    size: int
    uploader: str
    upload_time: str
    modified: str


class BlockInfo(BaseModel):
    ip: str
    reason: str
    expiry: float
    timestamp: str


class FlowInfo(BaseModel):
    priority: int
    match: str
    actions: str
    timeout: int
    type: str


class StatsInfo(BaseModel):
    ports: dict
    timestamp: float


class EventInfo(BaseModel):
    events: list
    cursor: int


@app.get("/api/health")
async def health_check():
    server_ok = SHARED_DIR.exists()
    controller_ok = CONTROLLER_LOG_FILE.exists()
    return {
        "server": "ok" if server_ok else "down",
        "controller": "ok" if controller_ok else "down",
        "mininet": "unknown",
        "timestamp": time.time(),
    }


@app.get("/api/events", response_model=EventInfo)
async def get_events(since: int = 0, limit: int = 100):
    events = read_jsonl_tail(EVENTS_FILE, max_lines=limit * 2)
    filtered = [e for e in events if e.get("ts", 0) > since]
    return {"events": filtered[-limit:], "cursor": int(time.time() * 1000)}


@app.get("/api/stats", response_model=StatsInfo)
async def get_stats():
    return read_stats_csv()


@app.get("/api/blocks", response_model=list[BlockInfo])
async def get_blocks():
    return get_blocks_from_log()


@app.post("/api/blocks/{ip}/unblock")
async def unblock_ip(ip: str):
    from controller import FileShareController
    import os_ken.lib.hub as hub

    for dp in FileShareController.datapaths.values():
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip, ipv4_dst="10.0.0.4", ip_proto=6, tcp_dst=5000)
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, priority=200, match=match))
    ws_manager.broadcast({"type": "unblock", "data": {"ip": ip}})
    return {"success": True, "ip": ip}


@app.get("/api/flows", response_model=list[FlowInfo])
async def get_flows():
    return get_flows_from_log()


@app.get("/api/files", response_model=list[FileInfo])
async def list_files():
    return get_file_list()


@app.post("/api/auth", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username not in USERS or USERS[form_data.username] != form_data.password:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(data={"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    if not file.filename:
        raise HTTPException(400, "No filename")
    safe_name = "".join(c for c in file.filename if c.isalnum() or c in "._-")
    if not safe_name or safe_name in (".", ".."):
        raise HTTPException(400, "Invalid filename")
    dest = SHARED_DIR / safe_name
    part = f"{dest}.part"
    try:
        content = await file.read()
        if len(content) > (1 << 30):
            raise HTTPException(413, "File too large")
        with open(part, "wb") as f:
            f.write(content)
        os.replace(part, dest)
        meta = read_metadata()
        meta[safe_name] = {
            "size": len(content),
            "uploader": user,
            "upload_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(METADATA_FILE, "w") as f:
            json.dump(meta, f, indent=4)
        ws_manager.broadcast({"type": "event", "data": {
            "ts": time.time(), "event": "UPLOAD", "ip": "api", "user": user, "name": safe_name, "bytes": len(content)
        }})
        return {"success": True, "name": safe_name, "size": len(content)}
    except Exception as e:
        if part.exists():
            part.unlink()
        raise HTTPException(500, str(e))


@app.get("/api/download/{name}")
async def download_file(name: str, user: str = Depends(get_current_user)):
    safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
    path = SHARED_DIR / safe_name
    if not path.is_file() or safe_name.endswith(".part"):
        raise HTTPException(404, "File not found")
    ws_manager.broadcast({"type": "event", "data": {
        "ts": time.time(), "event": "DOWNLOAD", "ip": "api", "user": user, "name": safe_name, "bytes": path.stat().st_size
    }})
    return FileResponse(path, filename=safe_name)


@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "data": {"timestamp": time.time()}})
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong", "data": {"timestamp": time.time()}})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
"""Tenant-scoped Sentinel API with individual operator accounts and per-device credentials."""
from __future__ import annotations
import hashlib, hmac, os, secrets, sqlite3, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from contextlib import contextmanager
from fastapi import Request
from fastapi.responses import JSONResponse
from typing import Any
import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sentinel.schema import ENDPOINT_SCHEMA_VERSION, validate_endpoint_frame
from sentinel.operator_auth import hash_password, verify_password, new_session, session_expiry

DATABASE_PATH = Path(os.getenv("SENTINEL_DB_PATH", "sentinel_events.sqlite3"))
app = FastAPI(title="Sentinel API", version="0.4.0")
MAX_REQUEST_BYTES = 1_048_576
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_LOCKOUT = timedelta(minutes=15)
LOGIN_MAX_ATTEMPTS = 8
DUMMY_PASSWORD_HASH = hash_password("sentinel-dummy-password-never-used")

class EventBatch(BaseModel):
    schema_version: str = ENDPOINT_SCHEMA_VERSION
    events: list[dict[str, Any]] = Field(min_length=1, max_length=500)
class BootstrapRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)
class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)
class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
class OperatorCreate(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern=r"^(admin|analyst|viewer)$")

def _connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DATABASE_PATH, timeout=10); c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA busy_timeout=10000')
    c.execute("""CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT, last_seen TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS endpoint_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL, schema_version TEXT NOT NULL,
        timestamp TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_port INTEGER NOT NULL,
        dst_port INTEGER NOT NULL, protocol TEXT NOT NULL, duration REAL NOT NULL, status TEXT,
        pid INTEGER, process TEXT, device_id TEXT, tenant_id TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS operators (
        operator_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL,
        disabled_at TEXT, UNIQUE(tenant_id,email))""")
    c.execute("""CREATE TABLE IF NOT EXISTS operator_sessions (
        token_hash TEXT PRIMARY KEY, operator_id TEXT NOT NULL, created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, revoked_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        email TEXT NOT NULL, client_ip TEXT NOT NULL, window_started TEXT NOT NULL,
        attempts INTEGER NOT NULL, blocked_until TEXT, PRIMARY KEY(email,client_ip))""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
        action TEXT NOT NULL, target_id TEXT, created_at TEXT NOT NULL)""")
    device_cols = {r["name"] for r in c.execute("PRAGMA table_info(devices)")}
    if "last_seen" not in device_cols: c.execute("ALTER TABLE devices ADD COLUMN last_seen TEXT")
    event_cols = {r["name"] for r in c.execute("PRAGMA table_info(endpoint_events)")}
    for col in ("device_id", "tenant_id"):
        if col not in event_cols: c.execute(f"ALTER TABLE endpoint_events ADD COLUMN {col} TEXT")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_tenant_device ON endpoint_events(tenant_id,device_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_received_at ON endpoint_events(received_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_operator ON operator_sessions(operator_id)")
    c.commit()
    return c

@contextmanager
def _db():
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

@app.middleware("http")
async def enforce_request_size(request: Request, call_next):
    raw_length = request.headers.get("content-length")
    if raw_length:
        try:
            if int(raw_length) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body exceeds 1 MiB limit."})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
    return await call_next(request)

def _now() -> str: return datetime.now(timezone.utc).isoformat()
def _audit(c: sqlite3.Connection, actor: dict[str,str], action: str, target: str | None = None) -> None:
    c.execute("INSERT INTO audit_log(tenant_id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)",
              (actor["tenant_id"], actor["operator_id"], action, target, _now()))

def require_operator(authorization: str | None = Header(default=None)) -> dict[str,str]:
    parts=(authorization or "").split()
    scheme, token = (parts[0],parts[1]) if len(parts)==2 else ("","")
    if scheme.lower() != "bearer" or len(token) < 32:
        raise HTTPException(status_code=401, detail="Operator login required.")
    digest = hashlib.sha256(token.encode()).hexdigest()
    with _db() as c:
        row = c.execute("""SELECT o.operator_id,o.tenant_id,o.email,o.role
            FROM operator_sessions s JOIN operators o ON o.operator_id=s.operator_id
            WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND o.disabled_at IS NULL""",
            (digest,_now())).fetchone()
    if row is None: raise HTTPException(status_code=401, detail="Invalid or expired operator session.")
    return dict(row)

def require_admin(operator: dict[str,str] = Depends(require_operator)) -> dict[str,str]:
    if operator["role"] not in ("owner","admin"):
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return operator

def require_owner(operator: dict[str,str] = Depends(require_operator)) -> dict[str,str]:
    if operator["role"] != "owner":
        raise HTTPException(status_code=403, detail="Organization owner role required.")
    return operator

def require_device(authorization: str | None = Header(default=None)) -> dict[str,str]:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or len(token) < 32: raise HTTPException(status_code=401, detail="Invalid device credential.")
    digest = hashlib.sha256(token.encode()).hexdigest()
    with _connect() as c:
        row = c.execute("SELECT device_id,tenant_id,name FROM devices WHERE token_hash=? AND revoked_at IS NULL",(digest,)).fetchone()
    if row is None: raise HTTPException(status_code=401, detail="Invalid or revoked device credential.")
    return dict(row)

@app.get("/health")
def health(): return {"status":"ok","schema_version":ENDPOINT_SCHEMA_VERSION}

@app.post("/v1/auth/bootstrap")
def bootstrap(request: BootstrapRequest, x_sentinel_bootstrap: str | None = Header(default=None)):
    expected=os.getenv("SENTINEL_BOOTSTRAP_TOKEN","")
    if len(expected)<32: raise HTTPException(status_code=503,detail="Configure SENTINEL_BOOTSTRAP_TOKEN with at least 32 characters.")
    if not x_sentinel_bootstrap or not hmac.compare_digest(x_sentinel_bootstrap,expected):
        raise HTTPException(status_code=401,detail="Invalid bootstrap credential.")
    email=request.email.strip().lower()
    if "@" not in email: raise HTTPException(status_code=422,detail="A valid email address is required.")
    with _connect() as c:
        if c.execute("SELECT 1 FROM operators LIMIT 1").fetchone():
            raise HTTPException(status_code=409,detail="Bootstrap is already complete.")
        c.execute("INSERT INTO operators VALUES(?,?,?,?,?,?,NULL)",
                  (str(uuid.uuid4()),request.tenant_id,email,hash_password(request.password),"owner",_now()))
    return {"status":"created","tenant_id":request.tenant_id,"email":email,"role":"owner"}

@app.post("/v1/auth/login")
def login(request: LoginRequest, http_request: Request):
    email=request.email.strip().lower()
    client_ip=http_request.client.host if http_request.client else "unknown"
    now=datetime.now(timezone.utc)
    with _db() as c:
        throttle=c.execute("SELECT window_started,attempts,blocked_until FROM login_attempts WHERE email=? AND client_ip=?",(email,client_ip)).fetchone()
        if throttle and throttle["blocked_until"]:
            try:
                if datetime.fromisoformat(throttle["blocked_until"]) > now:
                    raise HTTPException(status_code=429,detail="Too many login attempts. Try again later.")
            except ValueError:
                pass
        rows=c.execute("SELECT operator_id,tenant_id,email,password_hash,role FROM operators WHERE email=? AND disabled_at IS NULL",(email,)).fetchall()
        match=next((r for r in rows if verify_password(request.password,r["password_hash"])),None)
        if not rows:
            verify_password(request.password,DUMMY_PASSWORD_HASH)
        if match is None:
            window_start=now
            attempts=1
            if throttle:
                try:
                    previous=datetime.fromisoformat(throttle["window_started"])
                    if now-previous < LOGIN_WINDOW:
                        window_start=previous
                        attempts=int(throttle["attempts"])+1
                except (ValueError,TypeError):
                    pass
            blocked=(now+LOGIN_LOCKOUT).isoformat() if attempts>=LOGIN_MAX_ATTEMPTS else None
            c.execute("""INSERT INTO login_attempts(email,client_ip,window_started,attempts,blocked_until)
                VALUES(?,?,?,?,?) ON CONFLICT(email,client_ip) DO UPDATE SET
                window_started=excluded.window_started,attempts=excluded.attempts,blocked_until=excluded.blocked_until""",
                (email,client_ip,window_start.isoformat(),attempts,blocked))
            if blocked:
                raise HTTPException(status_code=429,detail="Too many login attempts. Try again later.")
            raise HTTPException(status_code=401,detail="Invalid email or password.")
        c.execute("DELETE FROM login_attempts WHERE email=? AND client_ip=?",(email,client_ip))
        token,digest=new_session()
        c.execute("INSERT INTO operator_sessions VALUES(?,?,?,?,NULL)",(digest,match["operator_id"],_now(),session_expiry()))
        return {"access_token":token,"token_type":"bearer","expires_in":43200,
                "operator":{"email":match["email"],"tenant_id":match["tenant_id"],"role":match["role"]}}

@app.post("/v1/auth/logout")
def logout(operator: dict[str,str] = Depends(require_operator), authorization: str | None = Header(default=None)):
    token=authorization.split()[1]
    digest=hashlib.sha256(token.encode()).hexdigest()
    with _connect() as c: c.execute("UPDATE operator_sessions SET revoked_at=? WHERE token_hash=?",(_now(),digest))
    return {"status":"logged_out"}

@app.post("/v1/operators")
def create_operator(request: OperatorCreate, owner: dict[str,str] = Depends(require_owner)):
    email=request.email.strip().lower()
    if "@" not in email: raise HTTPException(status_code=422,detail="A valid email address is required.")
    with _connect() as c:
        try:
            operator_id=str(uuid.uuid4())
            c.execute("INSERT INTO operators VALUES(?,?,?,?,?,?,NULL)",
                      (operator_id,owner["tenant_id"],email,hash_password(request.password),request.role,_now()))
            _audit(c,owner,"operator.created",operator_id)
        except sqlite3.IntegrityError: raise HTTPException(status_code=409,detail="Operator email already exists in this organization.")
    return {"operator_id":operator_id,"email":email,"tenant_id":owner["tenant_id"],"role":request.role}

@app.get("/v1/me")
def me(operator: dict[str,str] = Depends(require_operator)): return operator

@app.post("/v1/devices")
def create_device(request: DeviceCreate, operator: dict[str,str] = Depends(require_admin)):
    device_id=str(uuid.uuid4()); token=secrets.token_urlsafe(32); digest=hashlib.sha256(token.encode()).hexdigest()
    with _connect() as c:
        c.execute("INSERT INTO devices(device_id,tenant_id,name,token_hash,created_at) VALUES(?,?,?,?,?)",
                  (device_id,operator["tenant_id"],request.name.strip(),digest,_now()))
        _audit(c,operator,"device.enrolled",device_id)
    return {"device_id":device_id,"tenant_id":operator["tenant_id"],"name":request.name.strip(),"device_token":token}

@app.post("/v1/heartbeat")
def heartbeat(device: dict[str,str] = Depends(require_device)):
    seen=_now()
    with _connect() as c: c.execute("UPDATE devices SET last_seen=? WHERE device_id=? AND revoked_at IS NULL",(seen,device["device_id"]))
    return {"status":"ok","device_id":device["device_id"],"last_seen":seen}

@app.get("/v1/devices")
def list_devices(operator: dict[str,str] = Depends(require_operator)):
    with _connect() as c:
        rows=c.execute("""SELECT d.device_id,d.tenant_id,d.name,d.created_at,d.revoked_at,COUNT(e.id) event_count,
            MAX(COALESCE(d.last_seen,e.received_at)) last_seen FROM devices d
            LEFT JOIN endpoint_events e ON e.device_id=d.device_id
            WHERE d.tenant_id=? GROUP BY d.device_id ORDER BY d.created_at DESC""",(operator["tenant_id"],)).fetchall()
    return {"devices":[dict(r) for r in rows]}

@app.get("/v1/overview")
def fleet_overview(operator: dict[str,str] = Depends(require_operator)):
    with _connect() as c:
        totals=c.execute("SELECT COUNT(*) devices,SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) active_devices FROM devices WHERE tenant_id=?",(operator["tenant_id"],)).fetchone()
        events=c.execute("SELECT COUNT(*) total_events,MAX(received_at) last_event FROM endpoint_events WHERE tenant_id=?",(operator["tenant_id"],)).fetchone()
    return {"devices":int(totals["devices"] or 0),"active_devices":int(totals["active_devices"] or 0),
            "revoked_devices":int((totals["devices"] or 0)-(totals["active_devices"] or 0)),
            "total_events":int(events["total_events"] or 0),"last_event":events["last_event"]}

@app.get("/v1/audit")
def audit_log(operator: dict[str,str] = Depends(require_admin)):
    with _connect() as c:
        rows=c.execute("SELECT actor_id,action,target_id,created_at FROM audit_log WHERE tenant_id=? ORDER BY id DESC LIMIT 500",(operator["tenant_id"],)).fetchall()
    return {"entries":[dict(r) for r in rows]}

@app.delete("/v1/devices/{device_id}")
def revoke_device(device_id: str, operator: dict[str,str] = Depends(require_admin)):
    with _connect() as c:
        cur=c.execute("UPDATE devices SET revoked_at=? WHERE device_id=? AND tenant_id=? AND revoked_at IS NULL",
                      (_now(),device_id,operator["tenant_id"]))
        if cur.rowcount==0: raise HTTPException(status_code=404,detail="Active device not found.")
        _audit(c,operator,"device.revoked",device_id)
    return {"device_id":device_id,"status":"revoked"}

@app.post("/v1/events")
def ingest_events(batch: EventBatch, device: dict[str,str] = Depends(require_device)):
    if batch.schema_version!=ENDPOINT_SCHEMA_VERSION:
        raise HTTPException(status_code=422,detail=f"Unsupported schema_version. Expected {ENDPOINT_SCHEMA_VERSION}.")
    frame=pd.DataFrame(batch.events); valid,errors=validate_endpoint_frame(frame)
    if errors or len(valid)!=len(frame): raise HTTPException(status_code=422,detail={"validation_errors":errors})
    optional=[]
    for index,event in valid.iterrows():
        raw=event.get("pid"); pid=None
        if pd.notna(raw) and str(raw).strip():
            try:
                number=float(raw)
                if not number.is_integer() or number<0: raise ValueError
                pid=int(number)
            except (TypeError,ValueError,OverflowError):
                raise HTTPException(status_code=422,detail={"validation_errors":[f"Row {index}: pid must be a non-negative integer."]})
        status=str(event.get("status","")).strip() if pd.notna(event.get("status")) else ""
        process=str(event.get("process","")).strip() if pd.notna(event.get("process")) else ""
        if len(status)>128 or len(process)>256: raise HTTPException(status_code=422,detail={"validation_errors":[f"Row {index}: status/process is too long."]})
        optional.append((pid,status or None,process or None))
    received=_now(); rows=[]
    for (_,event),(pid,status,process) in zip(valid.iterrows(),optional):
        rows.append((received,batch.schema_version,pd.Timestamp(event["timestamp"]).isoformat(),str(event["src_ip"]),str(event["dst_ip"]),
            int(event["src_port"]),int(event["dst_port"]),str(event["protocol"]),float(event["duration"]),status,pid,process,
            device["device_id"],device["tenant_id"]))
    with _connect() as c:
        c.executemany("""INSERT INTO endpoint_events(received_at,schema_version,timestamp,src_ip,dst_ip,src_port,dst_port,
            protocol,duration,status,pid,process,device_id,tenant_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",rows)
        c.execute("UPDATE devices SET last_seen=? WHERE device_id=?",(received,device["device_id"]))
    return {"accepted":len(rows),"rejected":0,"schema_version":batch.schema_version,"device_id":device["device_id"]}

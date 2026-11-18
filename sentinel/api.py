"""Authenticated ingestion API with per-device credentials for Sentinel."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from sentinel.schema import ENDPOINT_SCHEMA_VERSION, validate_endpoint_frame

DATABASE_PATH = Path(os.getenv("SENTINEL_DB_PATH", "sentinel_events.sqlite3"))
app = FastAPI(title="Sentinel Ingestion API", version="0.2.0")


class EventBatch(BaseModel):
    schema_version: str = ENDPOINT_SCHEMA_VERSION
    events: list[dict[str, Any]] = Field(min_length=1, max_length=500)


class DeviceCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(min_length=1, max_length=120)


def _connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            duration REAL NOT NULL,
            status TEXT,
            pid INTEGER,
            process TEXT,
            device_id TEXT,
            tenant_id TEXT
        )
    """)
    # Upgrade databases created by the shared-token prototype in place.
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(endpoint_events)")}
    if "device_id" not in columns:
        connection.execute("ALTER TABLE endpoint_events ADD COLUMN device_id TEXT")
    if "tenant_id" not in columns:
        connection.execute("ALTER TABLE endpoint_events ADD COLUMN tenant_id TEXT")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_tenant_device ON endpoint_events(tenant_id, device_id)")
    return connection


def _constant_time_secret_check(supplied: str | None, expected_env: str) -> None:
    expected = os.getenv(expected_env, "")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail=f"Configure {expected_env} with at least 32 characters.")
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid administrator credential.")


def require_admin(authorization: str | None = Header(default=None)) -> None:
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer":
        supplied = ""
    _constant_time_secret_check(supplied, "SENTINEL_ADMIN_TOKEN")


def require_device(authorization: str | None = Header(default=None)) -> dict[str, str]:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or len(token) < 32:
        raise HTTPException(status_code=401, detail="Invalid device credential.")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _connect() as connection:
        row = connection.execute(
            "SELECT device_id, tenant_id, name FROM devices WHERE token_hash = ? AND revoked_at IS NULL",
            (digest,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked device credential.")
    return dict(row)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "schema_version": ENDPOINT_SCHEMA_VERSION}


@app.post("/v1/devices", dependencies=[Depends(require_admin)])
def create_device(request: DeviceCreate) -> dict[str, str]:
    """Provision one device. The plaintext token is returned exactly once."""
    device_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect() as connection:
        connection.execute(
            "INSERT INTO devices(device_id, tenant_id, name, token_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (device_id, request.tenant_id, request.name.strip(), token_hash, created_at),
        )
    return {"device_id": device_id, "tenant_id": request.tenant_id, "name": request.name.strip(), "device_token": token}


@app.get("/v1/devices", dependencies=[Depends(require_admin)])
def list_devices() -> dict[str, Any]:
    """List registered devices and their latest server-received event time."""
    with _connect() as connection:
        rows = connection.execute("""
            SELECT d.device_id, d.tenant_id, d.name, d.created_at, d.revoked_at,
                   COUNT(e.id) AS event_count, MAX(e.received_at) AS last_seen
            FROM devices AS d
            LEFT JOIN endpoint_events AS e ON e.device_id = d.device_id
            GROUP BY d.device_id
            ORDER BY d.created_at DESC
        """).fetchall()
    return {"devices": [dict(row) for row in rows]}


@app.get("/v1/overview", dependencies=[Depends(require_admin)])
def fleet_overview() -> dict[str, Any]:
    """Return fleet-wide counters without exposing event payloads."""
    with _connect() as connection:
        totals = connection.execute("""
            SELECT COUNT(*) AS devices,
                   SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) AS active_devices
            FROM devices
        """).fetchone()
        events = connection.execute("""
            SELECT COUNT(*) AS total_events, MAX(received_at) AS last_event
            FROM endpoint_events
        """).fetchone()
    return {
        "devices": int(totals["devices"] or 0),
        "active_devices": int(totals["active_devices"] or 0),
        "revoked_devices": int((totals["devices"] or 0) - (totals["active_devices"] or 0)),
        "total_events": int(events["total_events"] or 0),
        "last_event": events["last_event"],
    }


@app.delete("/v1/devices/{device_id}", dependencies=[Depends(require_admin)])
def revoke_device(device_id: str) -> dict[str, str]:
    with _connect() as connection:
        cursor = connection.execute(
            "UPDATE devices SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), device_id),
        )
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Active device not found.")
    return {"device_id": device_id, "status": "revoked"}


@app.post("/v1/events")
def ingest_events(batch: EventBatch, device: dict[str, str] = Depends(require_device)) -> dict[str, Any]:
    if batch.schema_version != ENDPOINT_SCHEMA_VERSION:
        raise HTTPException(status_code=422, detail=f"Unsupported schema_version. Expected {ENDPOINT_SCHEMA_VERSION}.")

    frame = pd.DataFrame(batch.events)
    valid, errors = validate_endpoint_frame(frame)
    if errors or len(valid) != len(frame):
        raise HTTPException(status_code=422, detail={"validation_errors": errors})

    optional: list[tuple[int | None, str | None, str | None]] = []
    for index, event in valid.iterrows():
        raw_pid = event.get("pid")
        pid: int | None = None
        if pd.notna(raw_pid) and str(raw_pid).strip():
            try:
                number = float(raw_pid)
                if not number.is_integer() or number < 0:
                    raise ValueError
                pid = int(number)
            except (TypeError, ValueError, OverflowError):
                raise HTTPException(status_code=422, detail={"validation_errors": [f"Row {index}: pid must be a non-negative integer."]})
        status = str(event.get("status", "")).strip() if pd.notna(event.get("status")) else ""
        process = str(event.get("process", "")).strip() if pd.notna(event.get("process")) else ""
        if len(status) > 128 or len(process) > 256:
            raise HTTPException(status_code=422, detail={"validation_errors": [f"Row {index}: status/process is too long."]})
        optional.append((pid, status or None, process or None))

    received_at = datetime.now(timezone.utc).isoformat()
    rows = []
    for (_, event), (pid, status, process) in zip(valid.iterrows(), optional):
        rows.append((
            received_at, batch.schema_version, pd.Timestamp(event["timestamp"]).isoformat(),
            str(event["src_ip"]), str(event["dst_ip"]), int(event["src_port"]),
            int(event["dst_port"]), str(event["protocol"]), float(event["duration"]),
            status, pid, process, device["device_id"], device["tenant_id"],
        ))
    with _connect() as connection:
        connection.executemany("""
            INSERT INTO endpoint_events
            (received_at, schema_version, timestamp, src_ip, dst_ip, src_port,
             dst_port, protocol, duration, status, pid, process, device_id, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    return {"accepted": len(rows), "rejected": 0, "schema_version": batch.schema_version,
            "device_id": device["device_id"]}

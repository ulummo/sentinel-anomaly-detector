"""Minimal authenticated ingestion API for the Sentinel SMB MVP.

Run with: uvicorn sentinel.api:app --host 127.0.0.1 --port 8000
Set SENTINEL_INGEST_TOKEN to a long random secret before starting.
This first iteration uses one shared token; per-device enrollment is a later step.
"""
from __future__ import annotations

import hmac
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from sentinel.schema import ENDPOINT_SCHEMA_VERSION, validate_endpoint_frame

DATABASE_PATH = Path(os.getenv("SENTINEL_DB_PATH", "sentinel_events.sqlite3"))
app = FastAPI(title="Sentinel Ingestion API", version="0.1.0")


class EventBatch(BaseModel):
    schema_version: str = ENDPOINT_SCHEMA_VERSION
    events: list[dict[str, Any]] = Field(min_length=1, max_length=500)


def _configured_token() -> str:
    token = os.getenv("SENTINEL_INGEST_TOKEN", "")
    if len(token) < 32:
        raise HTTPException(
            status_code=503,
            detail="Ingestion is disabled: configure SENTINEL_INGEST_TOKEN (32+ characters).",
        )
    return token


def require_token(authorization: str | None = Header(default=None)) -> None:
    expected = _configured_token()
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid bearer token.")


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute(
        """
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
            process TEXT
        )
        """
    )
    return connection


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "schema_version": ENDPOINT_SCHEMA_VERSION}


@app.post("/v1/events", dependencies=[Depends(require_token)])
def ingest_events(batch: EventBatch) -> dict[str, Any]:
    if batch.schema_version != ENDPOINT_SCHEMA_VERSION:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported schema_version. Expected {ENDPOINT_SCHEMA_VERSION}.",
        )

    frame = pd.DataFrame(batch.events)
    valid, errors = validate_endpoint_frame(frame)
    if errors or len(valid) != len(frame):
        raise HTTPException(status_code=422, detail={"validation_errors": errors})

    received_at = datetime.now(timezone.utc).isoformat()
    columns = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "duration", "status", "pid", "process",
    ]
    rows = []
    for _, event in valid.iterrows():
        timestamp = pd.Timestamp(event["timestamp"]).isoformat()
        rows.append((
            received_at, batch.schema_version, timestamp,
            str(event["src_ip"]), str(event["dst_ip"]),
            int(event["src_port"]), int(event["dst_port"]),
            str(event["protocol"]), float(event["duration"]),
            str(event.get("status", "")) or None,
            int(event["pid"]) if pd.notna(event.get("pid")) and str(event.get("pid")).strip() else None,
            str(event.get("process", "")) or None,
        ))

    placeholders = ",".join(["?"] * 12)
    with _connect() as connection:
        connection.executemany(
            f"""INSERT INTO endpoint_events
            (received_at, schema_version, timestamp, src_ip, dst_ip, src_port,
             dst_port, protocol, duration, status, pid, process)
            VALUES ({placeholders})""",
            rows,
        )

    return {"accepted": len(rows), "rejected": 0, "schema_version": batch.schema_version}

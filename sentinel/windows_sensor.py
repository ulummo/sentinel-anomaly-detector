"""Windows endpoint sensor: collects TCP socket metadata for this host only."""
from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import psutil

FIELDS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
          "duration", "status", "pid", "process"]
MAX_BATCH_SIZE = 500


def validate_server_url(server_url: str) -> str:
    parsed = urlparse(server_url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("Server URL must use HTTPS (HTTP is allowed only for localhost).")
    if not parsed.netloc:
        raise ValueError("Server URL must include a host.")
    return server_url.rstrip("/") + "/v1/events"


def _post_json(url: str, token: str, payload: dict, timeout: int = 10) -> dict:
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"
    }, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def send_batch(endpoint: str, token: str, events: list[dict]) -> None:
    for offset in range(0, len(events), MAX_BATCH_SIZE):
        try:
            result = _post_json(endpoint, token, {
                "schema_version": "1.0", "events": events[offset:offset + MAX_BATCH_SIZE]
            })
            print(f"Central API accepted {result.get('accepted', 0)} observation(s).")
        except urllib.error.HTTPError as exc:
            print(f"Central API rejected batch (HTTP {exc.code}); local CSV is retained.")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"Central API unavailable ({exc}); local CSV is retained.")


def send_heartbeat(server_url: str, token: str) -> None:
    """Send liveness independently of whether this endpoint has open TCP sockets."""
    heartbeat_url = server_url.rstrip("/") + "/v1/heartbeat"
    try:
        result = _post_json(heartbeat_url, token, {})
        print(f"Central API heartbeat: {result.get('status', 'ok')}.")
    except urllib.error.HTTPError as exc:
        print(f"Central API heartbeat rejected (HTTP {exc.code}).")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"Central API heartbeat unavailable ({exc}).")


def collect(output: Path, interval: float, seconds: int,
            server_url: str | None = None, token: str | None = None) -> None:
    started = time.monotonic()
    first_seen: dict[tuple, float] = {}
    known: set[tuple] = set()
    new_file = not output.exists() or output.stat().st_size == 0
    output.parent.mkdir(parents=True, exist_ok=True)
    endpoint = validate_server_url(server_url) if server_url else None
    with output.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
        print(f"Sentinel Sensor running. Writing connection metadata to: {output}")
        print("Only this Windows computer is monitored; no packet payloads are collected.")
        try:
            while seconds <= 0 or time.monotonic() - started < seconds:
                now = time.monotonic()
                if server_url and token:
                    send_heartbeat(server_url, token)
                try:
                    connections = psutil.net_connections(kind="inet")
                except (psutil.AccessDenied, OSError) as exc:
                    print(f"Cannot enumerate sockets: {exc}. Try running as Administrator.")
                    time.sleep(interval)
                    continue
                observations = []
                for conn in connections:
                    if not conn.laddr or not conn.raddr or conn.type != socket.SOCK_STREAM:
                        continue
                    local_ip, local_port = conn.laddr.ip, conn.laddr.port
                    remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
                    key = (local_ip, local_port, remote_ip, remote_port, conn.pid)
                    first_seen.setdefault(key, now)
                    known.add(key)
                    try:
                        process = psutil.Process(conn.pid).name() if conn.pid else ""
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process = ""
                    observation = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "src_ip": local_ip, "dst_ip": remote_ip,
                        "src_port": local_port, "dst_port": remote_port,
                        "protocol": "TCP", "duration": round(now - first_seen[key], 3),
                        "status": conn.status or "", "pid": conn.pid or "", "process": process,
                    }
                    writer.writerow(observation)
                    observations.append(observation)
                handle.flush()
                if endpoint and observations:
                    send_batch(endpoint, token or "", observations)
                print(f"Observed {len(known)} unique TCP connections so far.")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopping sensor.")
    print(f"Saved observations to {output.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel Windows endpoint connection sensor")
    parser.add_argument("--output", default="sentinel_endpoint_flows.csv")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--seconds", type=int, default=300, help="Duration; 0 runs until Ctrl+C")
    parser.add_argument("--server-url", default=None, help="Optional Sentinel API base URL")
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    if args.seconds < 0:
        parser.error("--seconds cannot be negative")
    token = os.getenv("SENTINEL_DEVICE_TOKEN")
    if args.server_url and (not token or len(token) < 32):
        parser.error("Set SENTINEL_DEVICE_TOKEN to the per-device token issued by the Sentinel administrator.")
    try:
        if args.server_url:
            validate_server_url(args.server_url)
    except ValueError as exc:
        parser.error(str(exc))
    collect(Path(args.output), args.interval, args.seconds, args.server_url, token)


if __name__ == "__main__":
    main()

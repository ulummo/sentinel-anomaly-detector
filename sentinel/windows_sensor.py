"""Windows endpoint sensor for Sentinel.

Collects metadata about TCP connections visible to this Windows host.
It does NOT capture packet contents or observe other devices on the LAN.
Run as Administrator for the broadest socket visibility.
"""
from __future__ import annotations

import argparse
import csv
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "duration", "status", "pid", "process",
]


def collect(output: Path, interval: float, seconds: int) -> None:
    started = time.monotonic()
    first_seen: dict[tuple, float] = {}
    known: set[tuple] = set()
    new_file = not output.exists() or output.stat().st_size == 0
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()

        print(f"Sentinel Sensor running. Writing connection metadata to: {output}")
        print("Only this Windows computer is monitored; no packet payloads are collected.")
        try:
            while seconds <= 0 or time.monotonic() - started < seconds:
                now = time.monotonic()
                try:
                    connections = psutil.net_connections(kind="inet")
                except (psutil.AccessDenied, OSError) as exc:
                    print(f"Cannot enumerate sockets: {exc}. Try running as Administrator.")
                    time.sleep(interval)
                    continue

                for conn in connections:
                    if not conn.laddr or not conn.raddr:
                        continue
                    if conn.type != socket.SOCK_STREAM:
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
                    writer.writerow({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "src_ip": local_ip,
                        "dst_ip": remote_ip,
                        "src_port": local_port,
                        "dst_port": remote_port,
                        "protocol": "TCP",
                        "duration": round(now - first_seen[key], 3),
                        "status": conn.status or "",
                        "pid": conn.pid or "",
                        "process": process,
                    })
                handle.flush()
                print(f"Observed {len(known)} unique TCP connections so far.")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopping sensor.")
    print(f"Saved observations to {output.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel Windows endpoint connection sensor")
    parser.add_argument("--output", default="sentinel_endpoint_flows.csv")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--seconds", type=int, default=300,
                        help="Collection duration; 0 runs until Ctrl+C (default: 300)")
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    if args.seconds < 0:
        parser.error("--seconds cannot be negative")
    collect(Path(args.output), args.interval, args.seconds)


if __name__ == "__main__":
    main()

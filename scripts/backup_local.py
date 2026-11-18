#!/usr/bin/env python3
"""Create a consistent local SQLite backup using SQLite's online backup API."""
from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


def create_backup(database: Path, output_dir: Path, retention_days: int = 14) -> Path:
    database = database.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    if not database.is_file():
        raise FileNotFoundError(f"Database does not exist: {database}")
    if retention_days < 1:
        raise ValueError("retention_days must be at least 1")

    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = output_dir / f"sentinel-{stamp}.sqlite3"

    try:
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as source:
            with sqlite3.connect(destination) as target:
                source.backup(target)
                result = target.execute("PRAGMA integrity_check").fetchone()
                if not result or result[0] != "ok":
                    raise RuntimeError(f"Backup integrity check failed: {result}")
    except Exception:
        destination.unlink(missing_ok=True)
        raise

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    for old_backup in output_dir.glob("sentinel-*.sqlite3"):
        modified = datetime.fromtimestamp(old_backup.stat().st_mtime, timezone.utc)
        if modified < cutoff and old_backup != destination:
            old_backup.unlink(missing_ok=True)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("sentinel_events.sqlite3"))
    parser.add_argument("--output-dir", type=Path, default=Path("backups"))
    parser.add_argument("--retention-days", type=int, default=14)
    args = parser.parse_args()
    path = create_backup(args.database, args.output_dir, args.retention_days)
    print(f"Backup created and integrity-checked: {path}")


if __name__ == "__main__":
    main()

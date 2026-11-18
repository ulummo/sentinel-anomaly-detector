#!/usr/bin/env sh
set -eu
# Run on the host; creates a consistent SQLite backup from the Docker volume.
BACKUP_DIR="${BACKUP_DIR:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"
docker compose exec -T api python -c 'import os,sqlite3; src=sqlite3.connect(os.environ.get("SENTINEL_DB_PATH","/data/sentinel_events.sqlite3")); dst=sqlite3.connect("/tmp/sentinel-backup.sqlite3"); src.backup(dst); dst.close(); src.close()'
docker compose cp api:/tmp/sentinel-backup.sqlite3 "$BACKUP_DIR/sentinel-$STAMP.sqlite3"
find "$BACKUP_DIR" -type f -name 'sentinel-*.sqlite3' -mtime +14 -delete

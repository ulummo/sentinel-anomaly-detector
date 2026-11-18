from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from scripts.backup_local import create_backup


def test_create_backup_copies_database_and_checks_integrity(tmp_path: Path) -> None:
    source = tmp_path / "sentinel.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE sample (value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('sentinel')")

    backup = create_backup(source, tmp_path / "backups")

    assert backup.is_file()
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT value FROM sample").fetchone() == ("sentinel",)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_backup_rejects_missing_database(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        create_backup(tmp_path / "missing.sqlite3", tmp_path / "backups")


def test_backup_rejects_invalid_retention(tmp_path: Path) -> None:
    source = tmp_path / "sentinel.sqlite3"
    sqlite3.connect(source).close()
    with pytest.raises(ValueError):
        create_backup(source, tmp_path / "backups", retention_days=0)

import sqlite3

import pytest
from fastapi.testclient import TestClient

from sentinel import api


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_INGEST_TOKEN", "test-token-that-is-long-enough-123456")
    monkeypatch.setattr(api, "DATABASE_PATH", tmp_path / "nested" / "events.sqlite3")
    return TestClient(api.app)


def valid_event():
    return {
        "timestamp": "2026-11-18T05:08:00Z",
        "src_ip": "192.168.1.10",
        "dst_ip": "1.1.1.1",
        "src_port": 50123,
        "dst_port": 443,
        "protocol": "tcp",
        "duration": 2.5,
        "status": "ESTABLISHED",
        "pid": 1234,
        "process": "example.exe",
    }


def test_health_is_available_without_ingest_token(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["schema_version"] == "1.0"


def test_ingestion_requires_bearer_token(client):
    response = client.post("/v1/events", json={"events": [valid_event()]})
    assert response.status_code == 401


def test_ingestion_persists_validated_events(client):
    response = client.post(
        "/v1/events",
        headers={"Authorization": "Bearer test-token-that-is-long-enough-123456"},
        json={"schema_version": "1.0", "events": [valid_event()]},
    )
    assert response.status_code == 200
    assert response.json()["accepted"] == 1

    with sqlite3.connect(api.DATABASE_PATH) as connection:
        count = connection.execute("SELECT COUNT(*) FROM endpoint_events").fetchone()[0]
    assert count == 1


def test_ingestion_rejects_invalid_event_without_persisting(client):
    event = valid_event()
    event["dst_ip"] = "not-an-ip"
    response = client.post(
        "/v1/events",
        headers={"Authorization": "Bearer test-token-that-is-long-enough-123456"},
        json={"events": [event]},
    )
    assert response.status_code == 422
    assert "validation_errors" in response.json()["detail"]
    assert not api.DATABASE_PATH.exists()


def test_ingestion_rejects_invalid_optional_pid(client):
    event = valid_event()
    event["pid"] = "not-a-pid"
    response = client.post(
        "/v1/events",
        headers={"Authorization": "Bearer test-token-that-is-long-enough-123456"},
        json={"events": [event]},
    )
    assert response.status_code == 422

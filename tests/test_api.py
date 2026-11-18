import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from sentinel import api

ADMIN = "admin-token-for-tests-that-is-long-enough-123"
DEVICE = "device-token-for-tests-that-is-long-enough-123"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", ADMIN)
    monkeypatch.setattr(api, "DATABASE_PATH", tmp_path / "nested" / "events.sqlite3")
    return TestClient(api.app)


def create_device(client, name="Workstation 01", tenant="acme"):
    response = client.post("/v1/devices", headers={"Authorization": f"Bearer {ADMIN}"},
                           json={"tenant_id": tenant, "name": name})
    assert response.status_code == 200
    return response.json()


def valid_event():
    return {"timestamp": "2026-11-18T05:08:00Z", "src_ip": "192.168.1.10",
            "dst_ip": "1.1.1.1", "src_port": 50123, "dst_port": 443,
            "protocol": "tcp", "duration": 2.5, "status": "ESTABLISHED",
            "pid": 1234, "process": "example.exe"}


def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["schema_version"] == "1.0"


def test_device_provisioning_requires_admin(client):
    assert client.post("/v1/devices", json={"tenant_id": "acme", "name": "PC"}).status_code == 401


def test_provisioned_token_is_returned_once_and_only_hash_is_stored(client):
    device = create_device(client)
    assert len(device["device_token"]) >= 32
    with sqlite3.connect(api.DATABASE_PATH) as connection:
        stored = connection.execute("SELECT token_hash FROM devices").fetchone()[0]
    assert stored == hashlib.sha256(device["device_token"].encode()).hexdigest()
    assert stored != device["device_token"]


def test_device_token_ingests_and_binds_tenant_and_device(client):
    device = create_device(client)
    response = client.post("/v1/events", headers={"Authorization": f"Bearer {device['device_token']}"},
                           json={"schema_version": "1.0", "events": [valid_event()]})
    assert response.status_code == 200
    assert response.json()["device_id"] == device["device_id"]
    with sqlite3.connect(api.DATABASE_PATH) as connection:
        row = connection.execute("SELECT device_id, tenant_id FROM endpoint_events").fetchone()
    assert row == (device["device_id"], "acme")


def test_unknown_token_cannot_ingest(client):
    response = client.post("/v1/events", headers={"Authorization": f"Bearer {DEVICE}"},
                           json={"events": [valid_event()]})
    assert response.status_code == 401


def test_revoked_device_cannot_ingest(client):
    device = create_device(client)
    revoked = client.delete(f"/v1/devices/{device['device_id']}",
                            headers={"Authorization": f"Bearer {ADMIN}"})
    assert revoked.status_code == 200
    response = client.post("/v1/events", headers={"Authorization": f"Bearer {device['device_token']}"},
                           json={"events": [valid_event()]})
    assert response.status_code == 401


def test_invalid_event_is_rejected_without_persistence(client):
    device = create_device(client)
    event = valid_event()
    event["dst_ip"] = "not-an-ip"
    response = client.post("/v1/events", headers={"Authorization": f"Bearer {device['device_token']}"},
                           json={"events": [event]})
    assert response.status_code == 422
    with sqlite3.connect(api.DATABASE_PATH) as connection:
        count = connection.execute("SELECT COUNT(*) FROM endpoint_events").fetchone()[0]
    assert count == 0


def test_invalid_optional_pid_is_rejected(client):
    device = create_device(client)
    event = valid_event()
    event["pid"] = "not-a-pid"
    response = client.post("/v1/events", headers={"Authorization": f"Bearer {device['device_token']}"},
                           json={"events": [event]})
    assert response.status_code == 422



def test_admin_can_view_device_inventory_and_last_seen(client):
    device = create_device(client, tenant="north")
    response = client.get("/v1/devices", headers={"Authorization": f"Bearer {ADMIN}"})
    assert response.status_code == 200
    assert response.json()["devices"][0]["device_id"] == device["device_id"]
    assert response.json()["devices"][0]["event_count"] == 0
    assert response.json()["devices"][0]["last_seen"] is None


def test_fleet_overview_counts_devices_and_events(client):
    device = create_device(client, tenant="north")
    client.post("/v1/events", headers={"Authorization": f"Bearer {device['device_token']}"},
                json={"schema_version": "1.0", "events": [valid_event()]})
    response = client.get("/v1/overview", headers={"Authorization": f"Bearer {ADMIN}"})
    assert response.status_code == 200
    assert response.json()["devices"] == 1
    assert response.json()["active_devices"] == 1
    assert response.json()["total_events"] == 1


def test_device_inventory_requires_admin(client):
    response = client.get("/v1/devices")
    assert response.status_code == 401

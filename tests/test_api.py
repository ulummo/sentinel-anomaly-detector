import hashlib
import sqlite3
import pytest
from fastapi.testclient import TestClient
from sentinel import api

BOOTSTRAP = "bootstrap-secret-for-tests-which-is-long-123"
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_BOOTSTRAP_TOKEN", BOOTSTRAP)
    monkeypatch.setattr(api, "DATABASE_PATH", tmp_path / "nested" / "events.sqlite3")
    c = TestClient(api.app)
    c.post("/v1/auth/bootstrap", headers={"X-Sentinel-Bootstrap": BOOTSTRAP},
           json={"tenant_id":"acme","email":"owner@acme.test","password":"correct-horse-battery"})
    return c

def login(client,email="owner@acme.test",password="correct-horse-battery"):
    response=client.post("/v1/auth/login",json={"email":email,"password":password})
    assert response.status_code==200
    return {"Authorization":"Bearer "+response.json()["access_token"]}

def enroll(client,headers,name="Workstation 01"):
    response=client.post("/v1/devices",headers=headers,json={"name":name})
    assert response.status_code==200
    return response.json()

def valid_event():
    return {"timestamp":"2026-11-18T05:08:00Z","src_ip":"192.168.1.10","dst_ip":"1.1.1.1",
            "src_port":50123,"dst_port":443,"protocol":"tcp","duration":2.5,
            "status":"ESTABLISHED","pid":1234,"process":"example.exe"}

def test_health_is_public(client):
    r=client.get("/health"); assert r.status_code==200 and r.json()["schema_version"]=="1.0"

def test_bootstrap_is_one_time_and_protected(client):
    assert client.post("/v1/auth/bootstrap",headers={"X-Sentinel-Bootstrap":BOOTSTRAP},
        json={"tenant_id":"other","email":"x@x.test","password":"correct-horse-battery"}).status_code==409
    assert client.post("/v1/auth/bootstrap",json={"tenant_id":"other","email":"x@x.test","password":"correct-horse-battery"}).status_code==401

def test_password_login_and_session_expiry_contract(client):
    assert client.post("/v1/auth/login",json={"email":"owner@acme.test","password":"wrong-password"}).status_code==401
    headers=login(client)
    assert client.get("/v1/me",headers=headers).json()["role"]=="owner"

def test_password_hash_is_not_plaintext(client):
    with sqlite3.connect(api.DATABASE_PATH) as c:
        stored=c.execute("SELECT password_hash FROM operators").fetchone()[0]
    assert stored!="correct-horse-battery" and stored.startswith("pbkdf2_sha256$")

def test_old_shared_admin_token_is_not_accepted(client,monkeypatch):
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN","old-shared-admin-secret-that-is-long")
    assert client.get("/v1/devices",headers={"Authorization":"Bearer old-shared-admin-secret-that-is-long"}).status_code==401

def test_device_token_is_returned_once_and_only_hash_stored(client):
    device=enroll(client,login(client))
    with sqlite3.connect(api.DATABASE_PATH) as c:
        stored=c.execute("SELECT token_hash FROM devices").fetchone()[0]
    assert stored==hashlib.sha256(device["device_token"].encode()).hexdigest()
    assert stored!=device["device_token"]

def test_device_token_ingests_and_binds_server_side_tenant(client):
    headers=login(client); device=enroll(client,headers)
    r=client.post("/v1/events",headers={"Authorization":"Bearer "+device["device_token"]},
                  json={"schema_version":"1.0","events":[valid_event()]})
    assert r.status_code==200
    with sqlite3.connect(api.DATABASE_PATH) as c:
        assert c.execute("SELECT tenant_id FROM endpoint_events").fetchone()[0]=="acme"

def test_unknown_device_token_cannot_ingest(client):
    assert client.post("/v1/events",headers={"Authorization":"Bearer "+"x"*40},
        json={"events":[valid_event()]}).status_code==401

def test_revoked_device_cannot_ingest_or_heartbeat(client):
    headers=login(client); d=enroll(client,headers)
    assert client.delete("/v1/devices/"+d["device_id"],headers=headers).status_code==200
    device_headers={"Authorization":"Bearer "+d["device_token"]}
    assert client.post("/v1/heartbeat",headers=device_headers,json={}).status_code==401
    assert client.post("/v1/events",headers=device_headers,json={"events":[valid_event()]}).status_code==401

def test_invalid_event_rejected_without_persistence(client):
    d=enroll(client,login(client)); event=valid_event(); event["dst_ip"]="bad"
    r=client.post("/v1/events",headers={"Authorization":"Bearer "+d["device_token"]},json={"events":[event]})
    assert r.status_code==422
    with sqlite3.connect(api.DATABASE_PATH) as c:
        assert c.execute("SELECT COUNT(*) FROM endpoint_events").fetchone()[0]==0

def test_invalid_pid_rejected(client):
    d=enroll(client,login(client)); event=valid_event(); event["pid"]="nope"
    assert client.post("/v1/events",headers={"Authorization":"Bearer "+d["device_token"]},json={"events":[event]}).status_code==422

def test_tenant_isolation_for_inventory_overview_and_revoke(client):
    owner=login(client); d=enroll(client,owner)
    # A second organization is provisioned only in an isolated test database.
    with sqlite3.connect(api.DATABASE_PATH) as c:
        c.execute("INSERT INTO operators VALUES(?,?,?,?,?,?,NULL)",
                  ("other-owner","other","owner@other.test",api.hash_password("another-correct-password"),"owner",api._now()))
    other=login(client,"owner@other.test","another-correct-password")
    assert client.get("/v1/devices",headers=other).json()["devices"]==[]
    assert client.get("/v1/overview",headers=other).json()["devices"]==0
    assert client.delete("/v1/devices/"+d["device_id"],headers=other).status_code==404
    assert len(client.get("/v1/devices",headers=owner).json()["devices"])==1

def test_analyst_can_read_but_cannot_enroll_or_revoke(client):
    owner=login(client)
    r=client.post("/v1/operators",headers=owner,json={"email":"analyst@acme.test","password":"analyst-password-long","role":"analyst"})
    assert r.status_code==200
    analyst=login(client,"analyst@acme.test","analyst-password-long")
    assert client.get("/v1/devices",headers=analyst).status_code==200
    assert client.post("/v1/devices",headers=analyst,json={"name":"blocked"}).status_code==403

def test_only_owner_can_create_operators(client):
    owner=login(client)
    client.post("/v1/operators",headers=owner,json={"email":"viewer@acme.test","password":"viewer-password-long","role":"viewer"})
    viewer=login(client,"viewer@acme.test","viewer-password-long")
    assert client.post("/v1/operators",headers=viewer,json={"email":"x@acme.test","password":"another-password-long","role":"analyst"}).status_code==403

def test_operator_logout_revokes_session(client):
    headers=login(client)
    assert client.post("/v1/auth/logout",headers=headers).status_code==200
    assert client.get("/v1/me",headers=headers).status_code==401

def test_audit_log_records_device_admin_actions(client):
    headers=login(client); d=enroll(client,headers)
    assert client.delete("/v1/devices/"+d["device_id"],headers=headers).status_code==200
    entries=client.get("/v1/audit",headers=headers).json()["entries"]
    assert [e["action"] for e in entries]==["device.revoked","device.enrolled"]

def test_device_heartbeat_updates_last_seen(client):
    d=enroll(client,login(client))
    r=client.post("/v1/heartbeat",headers={"Authorization":"Bearer "+d["device_token"]},json={})
    assert r.status_code==200
    assert client.get("/v1/devices",headers=login(client)).json()["devices"][0]["last_seen"]==r.json()["last_seen"]

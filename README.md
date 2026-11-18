# Sentinel — Network Anomaly Watchtower

Sentinel is an early-stage network anomaly monitoring project for small and medium-sized businesses. It combines a Streamlit dashboard with an experimental Windows endpoint sensor and a central ingestion API.

> Anomaly scores are investigation signals, not proof of malicious activity. Sentinel is not an antivirus or EDR replacement.

## Quick start

Requires Python 3.10+.

```powershell
git clone https://github.com/ulummo/sentinel-anomaly-detector.git
cd sentinel-anomaly-detector
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Choose **Generate demo traffic** or upload a supported CSV.

## Windows endpoint sensor

The experimental sensor records TCP socket metadata visible to one Windows computer. It does not capture packet payloads, per-flow byte counters, or other devices' traffic.

```powershell
python -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300
```

Use `--seconds 0` to run until Ctrl+C. Run PowerShell as Administrator for broader socket visibility. The local CSV is retained even when central upload fails.

## Central API: per-device enrollment

The API stores validated observations in SQLite. Each endpoint has its own random credential; only a SHA-256 hash of that credential is stored. The API derives device and tenant identity from the authenticated credential rather than trusting fields supplied by the endpoint.

### 1. Start the API

Set two different random secrets (32+ characters). Keep the admin token private.

```powershell
$env:SENTINEL_ADMIN_TOKEN = "replace-with-a-long-random-admin-secret"
uvicorn sentinel.api:app --host 127.0.0.1 --port 8000
```

The development server binds to loopback. Do not expose it directly to the public internet.

### 2. Enroll a device

In another PowerShell window, use the admin token to provision a device:

```powershell
$admin = $env:SENTINEL_ADMIN_TOKEN
$body = @{ tenant_id = "acme"; name = "Office-PC-01" } | ConvertTo-Json
$enrollment = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/v1/devices" -Headers @{ Authorization = "Bearer $admin" } -ContentType "application/json" -Body $body
$enrollment
```

The response contains `device_id` and `device_token`. The plaintext device token is shown only at enrollment time. Store it securely; do not commit it to source control or share it in support tickets.

### 3. Run the sensor with its device credential

```powershell
$env:SENTINEL_DEVICE_TOKEN = $enrollment.device_token
python -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300 --server-url http://127.0.0.1:8000
```

For a remote server, use HTTPS behind a correctly configured TLS reverse proxy.

### 4. Revoke a device

Use the admin token and the device ID:

```powershell
Invoke-RestMethod -Method Delete -Uri "http://127.0.0.1:8000/v1/devices/$($enrollment.device_id)" -Headers @{ Authorization = "Bearer $admin" }
```

A revoked credential can no longer submit observations. Enroll a replacement device credential if rotation is required.

## Data and security notes

- `SENTINEL_DB_PATH` optionally selects the SQLite database path; default is `sentinel_events.sqlite3`.
- `SENTINEL_ADMIN_TOKEN` protects device provisioning and revocation. Never use the device token for admin operations.
- Device credentials are random, returned once, and stored as SHA-256 hashes.
- Events are bound server-side to the authenticated device and tenant. Do not accept tenant identity from event payloads.
- The current API is a development MVP, not a production multi-tenant service. Before customer deployment add managed secrets, TLS termination, rate limiting, audit logs, backup/retention controls, tenant-scoped operator access, monitoring, and an independent security review.
- The sensor sees only TCP sockets visible to its own Windows host. Network-wide monitoring requires an approved network sensor or supported router/firewall/switch telemetry.
- Monitor only systems you own or are authorized to administer.

## Tests

```powershell
python -m pytest -q
```

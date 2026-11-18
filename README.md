# Sentinel — Network Anomaly Watchtower

Sentinel is an early-stage network anomaly monitoring project for small and medium-sized businesses. It combines a Streamlit dashboard, an experimental Windows endpoint sensor and a central ingestion API.

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

## Windows endpoint sensor

The experimental sensor records TCP socket metadata visible to one Windows computer. It does not capture packet payloads, per-flow byte counters, or other devices' traffic.

```powershell
python -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300
```

Use `--seconds 0` to run until Ctrl+C. Run PowerShell as Administrator for broader socket visibility. The local CSV is retained even when central upload fails.

## Central API and operator accounts

The API uses individual operator accounts for human access and separate per-device credentials for endpoint ingestion. The old shared `SENTINEL_ADMIN_TOKEN` is no longer used by the API or dashboard.

### 1. One-time organization bootstrap

Set a one-time bootstrap secret (32+ characters) and start the API on loopback:

```powershell
$env:SENTINEL_BOOTSTRAP_TOKEN = "replace-with-a-long-random-bootstrap-secret"
uvicorn sentinel.api:app --host 127.0.0.1 --port 8000
```

In a second PowerShell window, create the first organization owner. Bootstrap can succeed only once per database:

```powershell
$bootstrap = $env:SENTINEL_BOOTSTRAP_TOKEN
$body = @{ tenant_id = "acme"; email = "owner@acme.example"; password = "replace-with-a-unique-password-12chars-min" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/v1/auth/bootstrap" -Headers @{ "X-Sentinel-Bootstrap" = $bootstrap } -ContentType "application/json" -Body $body
```

Keep the bootstrap secret offline and remove it from the running environment after setup. It is not a normal login credential and must never be used by the dashboard.

### 2. Sign in and manage operators

The first owner signs in through **Device Management** with their email and password. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes; opaque bearer sessions are stored as SHA-256 hashes and expire after 12 hours.

The owner can create operators with `POST /v1/operators` using an owner session:

```powershell
$loginBody = @{ email = "owner@acme.example"; password = "your-owner-password" } | ConvertTo-Json
$session = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/v1/auth/login" -ContentType "application/json" -Body $loginBody
$headers = @{ Authorization = "Bearer $($session.access_token)" }
$operator = @{ email = "analyst@acme.example"; password = "a-different-password-12chars"; role = "analyst" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/v1/operators" -Headers $headers -ContentType "application/json" -Body $operator
```

Roles:
- `owner`: organization owner; can create operators, administer endpoints and view audit history.
- `admin`: can enroll/revoke endpoints and view audit history.
- `analyst`: read-only access to organization inventory and overview.
- `viewer`: read-only organization access.

Human operator access is scoped to the operator's organization. Device enrollment no longer accepts a tenant ID from the caller; the API assigns the authenticated operator's tenant. Inventory, overview, and revocation are tenant-filtered server-side. Administrative enrollment/revocation and operator creation are written to the tenant audit log.

### 3. Enroll a Windows endpoint

In Device Management, sign in as an owner or admin, choose **Enroll device**, and generate a device credential. Each endpoint gets a unique random token; only its SHA-256 hash is stored and the plaintext is displayed once.

Run the generated PowerShell command on that workstation:

```powershell
$env:SENTINEL_DEVICE_TOKEN = "paste-the-one-time-device-token"
python -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300 --server-url http://127.0.0.1:8000
```

The sensor sends authenticated heartbeat messages and event batches. Revoking a device immediately prevents further uploads.

### 4. API endpoints

- `POST /v1/auth/bootstrap` — one-time first-owner creation; requires `X-Sentinel-Bootstrap`.
- `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/me` — operator sessions.
- `POST /v1/operators` — owner-only operator creation.
- `POST /v1/devices`, `GET /v1/devices`, `DELETE /v1/devices/{device_id}` — tenant-scoped endpoint administration.
- `GET /v1/overview`, `GET /v1/audit` — tenant-scoped fleet and audit data.
- `POST /v1/events`, `POST /v1/heartbeat` — device-token authenticated endpoint ingestion.
- `GET /health` — public health check.

## Security and deployment notes

- `SENTINEL_BOOTSTRAP_TOKEN` is a one-time setup secret, not an everyday administrator password. Keep it private and unset it after bootstrap.
- Operator sessions expire after 12 hours. Passwords use PBKDF2-HMAC-SHA256 with per-password random salts.
- Device credentials are random, returned once, and stored as SHA-256 hashes.
- Events and device records are bound server-side to the authenticated device and tenant.
- This is still an early MVP, not a production-ready multi-tenant service. Before customer deployment add rate limits, request-size limits, account recovery/MFA, session/device session management, robust audit retention, managed secrets, TLS termination, backups, monitoring, migration/rollback procedures and independent security review.
- Keep the development API bound to loopback. For remote use, deploy behind a correctly configured HTTPS reverse proxy; do not expose the development server directly to the public internet.
- The sensor sees only TCP sockets visible to its own Windows host. Network-wide monitoring requires an approved network sensor or supported router/firewall/switch telemetry.
- Monitor only systems you own or are authorized to administer.

## Tests

```powershell
python -m pytest -q
```

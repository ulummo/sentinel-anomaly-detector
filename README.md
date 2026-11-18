# Sentinel — Network Anomaly Watchtower

Sentinel is a reproducible network-traffic anomaly detection lab. It combines a scikit-learn Isolation Forest model with an interactive Streamlit dashboard to inspect traffic records, investigate unusual events, and export findings.

> Educational analytics only: anomaly scores are signals for investigation, not proof of malicious activity or a production intrusion-detection system.

## Features

- Upload network-flow CSV files or generate deterministic demo traffic.
- Prepare numeric flow features and score records with Isolation Forest.
- Explore traffic volume, anomaly rate, score distribution, and event timeline.
- Filter suspicious records, inspect flow details, and export findings to CSV.
- Run a test suite for the detection pipeline.

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/ulummo/sentinel-anomaly-detector.git
cd sentinel-anomaly-detector
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit. Choose **Generate demo traffic** or upload a CSV.

## CSV input

Common flow columns include `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `duration`, `bytes`, and `packets`. At least one numeric feature is required. Derived rates are calculated when possible.

## Detection approach

Sentinel uses an Isolation Forest model. It prepares numeric flow features, fits on the supplied dataset, and returns a binary anomaly label plus a continuous anomaly score. Higher displayed scores indicate records that are more unusual relative to the fitted data.

Interpret results in context: model output depends on the dataset and parameter settings. Validate suspicious activity against your own environment before taking action.

## Tests

```bash
pytest -q
```

## Project layout

```text
sentinel-anomaly-detector/
├── app.py
├── requirements.txt
├── sentinel/
│   ├── __init__.py
│   ├── data.py
│   └── detector.py
└── tests/
    └── test_detector.py
```

## Responsible use

Analyze only traffic data you are authorized to inspect. Do not upload sensitive captures or personal data to environments you do not control.

## Windows endpoint sensor (first monitoring step)

The repository includes an **experimental Windows endpoint sensor** that records TCP connection metadata visible to one Windows computer. It does not capture packet payloads, measure per-flow byte counts, or see traffic belonging only to other devices.

Install dependencies and run PowerShell (Administrator is recommended):

```powershell
python -m pip install -r requirements.txt
python -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300
```

The sensor records observations for five minutes by default. Use `--seconds 0` to run until Ctrl+C. When it finishes, open Sentinel, choose **Upload CSV**, and upload `sentinel_endpoint_flows.csv`.

**Important scope limitation:** on a typical home Wi-Fi network, a computer cannot passively see all other devices' unicast traffic. Network-wide monitoring requires a supported router/firewall export, a managed switch with port mirroring, or a sensor deployed on each device. This endpoint sensor is a safe first step and must not be described as whole-LAN visibility. This sensor enumerates sockets rather than capturing packets, so it does not provide per-flow byte or packet counters.

Only monitor devices and networks you own or are authorized to administer.

## Central ingestion API (MVP)

The first server-side ingestion component accepts validated endpoint observations and stores them in a local SQLite database. It currently uses one shared bearer token; per-device enrollment and revocation are planned next. Do not expose this development API directly to the public internet.

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Set a long random token and start the API on the local machine:

```powershell
$env:SENTINEL_INGEST_TOKEN = "replace-with-a-random-secret-at-least-32-characters"
uvicorn sentinel.api:app --host 127.0.0.1 --port 8000
```

Health check: `http://127.0.0.1:8000/health`

Authenticated ingestion endpoint: `POST http://127.0.0.1:8000/v1/events`

Request body uses schema version `1.0` and an `events` array containing the endpoint fields documented in [the event schema](docs/ENDPOINT_EVENT_SCHEMA_V1.md). Supply the token as an HTTP header: `Authorization: Bearer <token>`.

The API stores accepted observations in `sentinel_events.sqlite3` (override with `SENTINEL_DB_PATH`). The Windows sensor can now both retain its local CSV and optionally forward observations to this API.

In a second PowerShell window on the same computer, set the same token and run:

```powershell
$env:SENTINEL_INGEST_TOKEN = "the-same-random-secret"
python -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300 --server-url http://127.0.0.1:8000
```

For a separate server, use its HTTPS URL (for example, `https://sentinel.example.com`) behind a properly configured TLS reverse proxy. The API's development command binds to loopback only; do not bind it to a public interface or expose it directly to the internet. Keep the local CSV as a fallback: failed API requests are reported and do not stop local collection.

**Current limitation:** the API still uses one shared bearer token, not per-device enrollment. This is suitable only for a controlled development test on a trusted machine/network. Before any customer pilot, implement per-device credentials and revocation, tenant isolation, HTTPS deployment, rate limiting, retention controls, and a security review.

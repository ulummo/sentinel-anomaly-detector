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

**Important scope limitation:** on a typical home Wi-Fi network, a computer cannot passively see all other devices' unicast traffic. Network-wide monitoring requires a supported router/firewall export, a managed switch with port mirroring, or a sensor deployed on each device. This endpoint sensor is a safe first step and must not be described as whole-LAN visibility. The exported `bytes` and `packets` fields are zero placeholders because this sensor enumerates sockets rather than capturing packets; do not interpret them as measured traffic volume.

Only monitor devices and networks you own or are authorized to administer.

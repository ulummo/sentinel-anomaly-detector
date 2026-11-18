# Local development (Windows / PowerShell)

Sentinel can be developed and tested without a cloud server or paid hosting.

## 1. Open the project folder

Open PowerShell in the repository folder (the folder containing `app.py`).

## 2. Create and activate a virtual environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run this once in the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 3. Run the dashboard

```powershell
streamlit run app.py
```

Open http://localhost:8501. The demo environment works without an API or sensor.

## 4. Run the API locally (optional)

Open a second PowerShell window in the same project folder, activate the virtual environment, then run:

```powershell
$env:SENTINEL_DB_PATH = "$PWD\sentinel_events.sqlite3"
$env:SENTINEL_BOOTSTRAP_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
uvicorn sentinel.api:app --host 127.0.0.1 --port 8000
```

Check http://127.0.0.1:8000/health. Keep the bootstrap token private. Use the one-time `POST /v1/auth/bootstrap` flow documented in the API before signing in to Device Management. Do not reuse a production secret for local development.

The Streamlit Device Management page is available from the dashboard's Pages navigation. Its default API address is http://127.0.0.1:8000.

## 5. Run automated tests

In another terminal with the virtual environment activated:

```powershell
python -m pytest -q
```

## Data and security boundaries

- The dashboard's demo mode uses generated sample data.
- The Windows sensor observes TCP socket metadata on the computer where it runs; it is not whole-network monitoring.
- Do not upload customer or sensitive production data to a development instance.
- Keep `.env`, database files, device tokens, operator passwords and private SSH keys out of Git.
- The local SQLite database is not an off-site backup. Back up important test data separately.

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Sentinel | Device Fleet", page_icon="◈", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --line:#263951; --muted:#91a5bc; --cyan:#5ce1ee; }
html,body,[class*="css"]{font-family:'Manrope',sans-serif}
.stApp{background:radial-gradient(ellipse at 75% -10%,#17364b 0%,#0a1422 42%,#070c14 100%);color:#eaf2fb}
.block-container{max-width:1450px;padding-top:2rem;padding-bottom:3rem}
section[data-testid="stSidebar"]{background:#0a1320;border-right:1px solid #203149}
.eyebrow{color:#5ce1ee;font:500 10px 'DM Mono',monospace;letter-spacing:.2em;text-transform:uppercase}
.hero{padding:8px 0 22px;border-bottom:1px solid #22334a;margin-bottom:22px}
.hero h1{font-size:clamp(30px,4vw,44px);line-height:1.08;margin:8px 0;font-weight:800;letter-spacing:-.045em}
.hero p{color:#91a2b8;margin:0;font-size:14px}
.metric{background:linear-gradient(145deg,#14243a,#101a29);border:1px solid #293c55;border-radius:14px;padding:17px;min-height:108px}
.metric-label{color:#91a5bc;font:10px 'DM Mono',monospace;letter-spacing:.13em}
.metric-value{color:#f1f7ff;font-size:29px;font-weight:800;margin-top:9px}
div[data-testid="stDataFrame"]{border:1px solid #263951;border-radius:10px}
.stButton button,.stDownloadButton button{border-radius:9px}
</style>
""", unsafe_allow_html=True)


def api_request(base_url: str, token: str, method: str, path: str, payload=None):
    parsed = urlparse(base_url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("Use HTTPS for remote servers. HTTP is allowed only for localhost.")
    if not parsed.netloc:
        raise ValueError("Enter a valid API base URL.")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", str(exc))
        except Exception:
            detail = str(exc)
        raise RuntimeError(f"API returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Cannot reach Sentinel API: {exc}") from exc


with st.sidebar:
    st.markdown('<div class="eyebrow">◈ SENTINEL / CONTROL ROOM</div>', unsafe_allow_html=True)
    st.markdown("### Server connection")
    base_url = st.text_input("API base URL", value=os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000"))
    admin_token = st.text_input("Administrator token", value=os.getenv("SENTINEL_ADMIN_TOKEN", ""),
                                type="password", help="Used only for device administration.")
    st.caption("Remote connections must use HTTPS. Credentials are not saved by this page.")
    connect = st.button("Connect and refresh", type="primary", use_container_width=True)

if "fleet_refresh" not in st.session_state:
    st.session_state.fleet_refresh = 0
if connect:
    st.session_state.fleet_refresh += 1

st.markdown("""
<div class="hero">
 <div class="eyebrow">SENTINEL / ENDPOINT MANAGEMENT</div>
 <h1>DEVICE FLEET <span style="color:#5ce1ee">//</span> INVENTORY</h1>
 <p>Enroll workstations · Monitor check-ins · Revoke compromised credentials</p>
</div>
""", unsafe_allow_html=True)

if not admin_token:
    st.info("Enter the administrator token in the sidebar to manage enrolled devices.")
    st.stop()

try:
    overview = api_request(base_url, admin_token, "GET", "/v1/overview")
    inventory = api_request(base_url, admin_token, "GET", "/v1/devices")
except (ValueError, RuntimeError) as exc:
    st.error(str(exc))
    st.stop()

cards = [
    ("REGISTERED DEVICES", overview["devices"], "All enrolled endpoints"),
    ("ACTIVE CREDENTIALS", overview["active_devices"], "Can currently submit events"),
    ("REVOKED DEVICES", overview["revoked_devices"], "Credentials disabled"),
    ("EVENTS RECEIVED", overview["total_events"], "Accepted endpoint observations"),
]
cols = st.columns(4)
for col, (label, value, note) in zip(cols, cards):
    with col:
        st.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value:,}</div><div style="color:#8195ad;font-size:11px;margin-top:6px">{note}</div></div>', unsafe_allow_html=True)

st.write("")
enroll_tab, inventory_tab, guide_tab = st.tabs(["＋ Enroll device", "▦ Device inventory", "ⓘ Connection guide"])

with enroll_tab:
    st.subheader("Register a Windows workstation")
    st.caption("A unique credential is generated for this device. The secret is displayed only once.")
    with st.form("enroll_device", clear_on_submit=True):
        left, right = st.columns(2)
        with left:
            tenant_id = st.text_input("Organization ID", placeholder="e.g. acme")
        with right:
            device_name = st.text_input("Device name", placeholder="e.g. Office-PC-01")
        submitted = st.form_submit_button("Generate device credential", type="primary")
    if submitted:
        try:
            created = api_request(base_url, admin_token, "POST", "/v1/devices",
                                  {"tenant_id": tenant_id.strip(), "name": device_name.strip()})
            st.success(f"Device {created['name']} enrolled.")
            st.warning("Copy the token now. It cannot be retrieved from the server later.")
            st.code(created["device_token"], language="text")
            st.code(f'$env:SENTINEL_DEVICE_TOKEN = "{created["device_token"]}"\npython -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300 --server-url {base_url.rstrip("/")}', language="powershell")
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))

with inventory_tab:
    st.subheader("Registered endpoints")
    devices = inventory.get("devices", [])
    if not devices:
        st.info("No devices enrolled yet. Use the Enroll device tab to add the first workstation.")
    else:
        frame = pd.DataFrame(devices)
        frame["status"] = frame["revoked_at"].apply(lambda value: "REVOKED" if value else "ACTIVE")
        frame["last_seen"] = frame["last_seen"].fillna("Never connected")
        visible = frame[["name", "tenant_id", "status", "event_count", "last_seen", "created_at", "device_id"]]
        st.dataframe(visible, use_container_width=True, hide_index=True,
                     column_config={"device_id": st.column_config.TextColumn("Device ID"),
                                    "event_count": st.column_config.NumberColumn("Events", format="%d")})
        active = frame[frame["revoked_at"].isna()]
        if not active.empty:
            st.markdown("#### Access control")
            options = {f'{row["name"]} · {row["tenant_id"]} · {row["device_id"][:8]}': row["device_id"]
                       for _, row in active.iterrows()}
            selected_label = st.selectbox("Choose a device to revoke", list(options))
            confirm = st.checkbox("I understand this device will immediately lose permission to upload events.")
            if st.button("Revoke device credential", type="secondary", disabled=not confirm):
                try:
                    result = api_request(base_url, admin_token, "DELETE",
                                         f'/v1/devices/{options[selected_label]}')
                    st.success(f'Device access revoked: {result["device_id"]}')
                    st.rerun()
                except (ValueError, RuntimeError) as exc:
                    st.error(str(exc))
    st.caption(f'Last event received: {overview["last_event"] or "No events received yet"}')

with guide_tab:
    st.subheader("Connect a Windows endpoint")
    st.markdown("""
1. Start the Sentinel API on a trusted server.
2. Create a device credential in **Enroll device**.
3. Copy the one-time token into the PowerShell session on that workstation.
4. Run the sensor command shown after enrollment.
5. Return to **Device inventory** to confirm events are arriving.

**Important:** the current sensor sees TCP connections visible to its own Windows computer only. It does not inspect packet contents or monitor every device on the LAN. The API and dashboard are an early MVP; do not expose the development server directly to the public internet.
""")

st.markdown("---")
st.caption("SENTINEL · DEVICE MANAGEMENT · Credentials are never displayed in the inventory.")

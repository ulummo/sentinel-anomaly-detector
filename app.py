from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel.data import generate_demo_data, prepare_flows
from sentinel.detector import score_flows
from sentinel.schema import REQUIRED_ENDPOINT_COLUMNS, validate_endpoint_frame

st.set_page_config(
    page_title="Sentinel | Security Operations",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Visual system ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --bg:#080e18; --panel:#101b2b; --line:#22334a; --cyan:#5ce1ee; --muted:#91a2b8; }
html, body, [class*="css"] { font-family:'Manrope',sans-serif; }
.stApp { background:radial-gradient(ellipse at 75% -10%,#17364b 0%,#0a1422 42%,#070c14 100%); color:#eaf2fb; }
.block-container { max-width:1580px; padding-top:1.5rem; padding-bottom:3rem; }
section[data-testid="stSidebar"] { background:#0a1320; border-right:1px solid #203149; }
h1,h2,h3 { letter-spacing:-.045em; }
.eyebrow { color:var(--cyan); font:500 10px 'DM Mono',monospace; letter-spacing:.2em; text-transform:uppercase; }
.hero { padding:8px 0 20px; border-bottom:1px solid var(--line); margin-bottom:22px; }
.hero h1 { font-size:clamp(30px,4vw,46px); line-height:1.08; margin:8px 0 5px; font-weight:800; }
.hero p { color:var(--muted); margin:0; font-size:14px; }
.status-pill { display:inline-block; border:1px solid #1d796f; background:#0d302f; color:#7cf0d3; padding:6px 10px; border-radius:30px; font:11px 'DM Mono',monospace; }
.metric-card { background:linear-gradient(145deg,#14243a,#101a29); border:1px solid #293c55; border-radius:14px; padding:17px 18px; min-height:118px; box-shadow:0 8px 28px #0002; }
.metric-label { color:#91a5bc; font:10px 'DM Mono',monospace; letter-spacing:.13em; }
.metric-value { color:#f1f7ff; font-size:29px; font-weight:800; margin-top:9px; line-height:1.1; }
.metric-note { color:#7f93aa; font-size:11px; margin-top:7px; }
.section-head { font-size:17px; font-weight:750; margin:5px 0 12px; }
.panel { background:#101a29; border:1px solid #263951; border-radius:14px; padding:15px 17px; }
div[data-testid="stDataFrame"] { border:1px solid #263951; border-radius:10px; }
.stButton button, .stDownloadButton button { border-radius:9px; border:1px solid #2b4961; }
div[data-testid="stAlert"] { border-radius:10px; }
small, .stCaption { color:#8ea1b8 !important; }
</style>
""", unsafe_allow_html=True)

SENSOR_FILE = Path("sentinel_endpoint_flows.csv")

def validate_sensor_source(frame: pd.DataFrame, label: str) -> pd.DataFrame:
    """Validate endpoint sensor CSVs and show actionable row-level feedback."""
    columns = {str(c).strip().lower() for c in frame.columns}
    if not set(REQUIRED_ENDPOINT_COLUMNS).issubset(columns):
        st.error(f"{label} does not match endpoint schema v1. Required: {', '.join(REQUIRED_ENDPOINT_COLUMNS)}")
        st.stop()
    valid, errors = validate_endpoint_frame(frame)
    if errors:
        st.warning(f"Validation found {len(errors)} issue(s). Invalid rows are excluded.")
        with st.expander("View validation details", expanded=True):
            for message in errors[:30]:
                st.write(f"• {message}")
            if len(errors) > 30:
                st.caption(f"{len(errors) - 30} additional issues not shown.")
    if valid.empty:
        st.error("No valid endpoint observations remain after validation.")
        st.stop()
    return valid


def enrich_endpoint_data(frame: pd.DataFrame) -> pd.DataFrame:
    """Add frequency signals to endpoint socket metadata without inventing traffic volume."""
    data = frame.copy()
    data.columns = [str(c).strip().lower() for c in data.columns]
    if "pid" in data.columns:
        data["pid"] = data["pid"].astype(str)
    for column in ("dst_ip", "dst_port", "process", "status"):
        if column in data.columns:
            counts = data[column].fillna("unknown").astype(str).value_counts()
            data[f"{column}_frequency"] = data[column].fillna("unknown").astype(str).map(counts).astype(float)
    if "timestamp" in data.columns:
        data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce", utc=True)
    return data

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown('<div class="eyebrow">◈ SENTINEL / CONTROL ROOM</div>', unsafe_allow_html=True)
    st.markdown("### Workspace")
    choices = ["Auto-detect sensor CSV", "Upload CSV", "Demo environment"]
    default_choice = 0 if SENSOR_FILE.exists() else 2
    source = st.radio("Data source", choices, index=default_choice, label_visibility="collapsed")
    uploaded = st.file_uploader("Choose connection metadata", type=["csv"]) if source == "Upload CSV" else None
    st.divider()
    contamination = st.slider("Detection sensitivity", 0.01, 0.20, 0.04, 0.01,
                              help="Expected share of records the model may flag as unusual.")
    st.caption("Higher sensitivity can flag more records. Alerts require human review.")
    st.divider()
    st.markdown('<div class="eyebrow">ENGINE STATUS</div>', unsafe_allow_html=True)
    st.success("ANALYSIS ENGINE READY")
    st.caption("Local processing · Data stays on this computer")
    st.caption("Sensor scope: this Windows endpoint only")

# ---------- Header ----------
st.markdown("""
<div class="hero">
  <div class="eyebrow">NETWORK DEFENCE / SECURITY OPERATIONS CENTER</div>
  <h1>SENTINEL <span style="color:#5ce1ee">//</span> COMMAND</h1>
  <p>Endpoint visibility · Behaviour analytics · Investigation workspace</p>
</div>
""", unsafe_allow_html=True)

# ---------- Load data ----------
try:
    if source == "Auto-detect sensor CSV":
        if not SENSOR_FILE.exists():
            st.warning("The sensor CSV was not found beside app.py. Start the sensor or choose another data source.")
            st.stop()
        raw = validate_sensor_source(pd.read_csv(SENSOR_FILE), "Local sensor CSV")
        source_label = "LOCAL WINDOWS SENSOR · VALIDATED"
        raw = enrich_endpoint_data(raw)
    elif source == "Upload CSV":
        if uploaded is None:
            st.info("Upload a Sentinel CSV file to begin analysis.")
            st.stop()
        raw = pd.read_csv(uploaded)
        columns = {str(c).strip().lower() for c in raw.columns}
        if set(REQUIRED_ENDPOINT_COLUMNS).issubset(columns):
            raw = validate_sensor_source(raw, "Uploaded endpoint CSV")
            source_label = "ENDPOINT CSV · VALIDATED"
            raw = enrich_endpoint_data(raw)
        else:
            source_label = "UPLOADED DATASET"
    else:
        raw = generate_demo_data()
        source_label = "DEMO ENVIRONMENT"

    prepared, features = prepare_flows(raw)
    results = score_flows(prepared, features, contamination)
except Exception as exc:
    st.error(f"Could not analyze this dataset: {exc}")
    st.stop()

total = len(results)
flagged = int(results["is_anomaly"].sum())
rate = (flagged / total * 100) if total else 0.0
unique_destinations = results["dst_ip"].nunique() if "dst_ip" in results else 0
unique_processes = results["process"].nunique() if "process" in results else 0
posture = "REVIEW" if rate >= 8 else "WATCH" if rate >= 3 else "NOMINAL"

st.markdown(
    f'<span class="status-pill">● {source_label}</span> &nbsp; '
    f'<span style="color:#8296ad;font:11px DM Mono,monospace"> {total:,} RECORDS LOADED</span>',
    unsafe_allow_html=True,
)
st.write("")

# ---------- KPI cards ----------
kpis = [
    ("CONNECTION RECORDS", f"{total:,}", "Rows available for analysis"),
    ("FLAGGED FOR REVIEW", f"{flagged:,}", f"{rate:.1f}% of current records"),
    ("UNIQUE DESTINATIONS", f"{unique_destinations:,}", "Distinct remote IP addresses"),
    ("PROCESSES OBSERVED", f"{unique_processes:,}", "Distinct process names"),
]
cols = st.columns(4)
for col, (label, value, note) in zip(cols, kpis):
    with col:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
            unsafe_allow_html=True,
        )

st.write("")
left, right = st.columns([1.55, 1])
with left:
    st.markdown('<div class="section-head">◉ Activity timeline</div>', unsafe_allow_html=True)
    if "timestamp" in results.columns and results["timestamp"].notna().any():
        timeline = results.dropna(subset=["timestamp"]).copy()
        timeline["time_bucket"] = timeline["timestamp"].dt.floor("5min")
        timeline = timeline.groupby("time_bucket").agg(
            connections=("anomaly_score", "size"),
            flagged=("is_anomaly", "sum"),
        ).reset_index()
        fig = px.area(timeline, x="time_bucket", y="connections",
                      color_discrete_sequence=["#247b98"])
        fig.add_scatter(x=timeline["time_bucket"], y=timeline["flagged"],
                        mode="lines+markers", name="Flagged",
                        line=dict(color="#ff7184", width=2))
        fig.update_layout(
            height=315, margin=dict(l=8, r=8, t=18, b=8),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#9cafc5", legend=dict(orientation="h", y=1.12),
            xaxis_title="", yaxis_title="Records",
        )
        fig.update_xaxes(gridcolor="#1e3045")
        fig.update_yaxes(gridcolor="#1e3045")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("A valid timestamp column is needed to draw the activity timeline.")

with right:
    st.markdown('<div class="section-head">◈ Risk overview</div>', unsafe_allow_html=True)
    dist = results.loc[results["is_anomaly"], "severity"].value_counts()
    levels = pd.DataFrame({"severity": ["HIGH", "MEDIUM", "LOW"],
                           "count": [int(dist.get(x, 0)) for x in ["HIGH", "MEDIUM", "LOW"]]})
    fig = px.bar(levels, x="severity", y="count", color="severity",
                 color_discrete_map={"HIGH": "#ff6478", "MEDIUM": "#f4b65f", "LOW": "#5ce1ee"})
    fig.update_layout(
        height=315, showlegend=False, margin=dict(l=8, r=8, t=18, b=8),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#9cafc5", xaxis_title="", yaxis_title="Records",
    )
    fig.update_xaxes(gridcolor="#1e3045")
    fig.update_yaxes(gridcolor="#1e3045")
    st.plotly_chart(fig, use_container_width=True)
    st.markdown(f'<div class="panel"><div class="eyebrow">MODEL POSTURE</div>'
                f'<div style="font-size:23px;font-weight:800;margin-top:5px">{posture}</div>'
                f'<div style="color:#91a2b8;font-size:11px">Statistical signal only — not a confirmed incident</div></div>',
                unsafe_allow_html=True)

# ---------- Investigation ----------
st.write("")
st.markdown('<div class="section-head">⌕ Investigation queue</div>', unsafe_allow_html=True)
c1, c2, c3 = st.columns([1, 1, 2])
with c1:
    flagged_only = st.toggle("Flagged records only", value=True)
with c2:
    min_score = st.slider("Minimum score", 0.0, 1.0, 0.0, 0.01)
with c3:
    search = st.text_input("Search IP, process, or status", placeholder="e.g. 192.168.0.108")

view = results[results["anomaly_score"] >= min_score].copy()
if flagged_only:
    view = view[view["is_anomaly"]]
if search.strip():
    searchable = [c for c in ["src_ip", "dst_ip", "process", "status"] if c in view.columns]
    mask = pd.Series(False, index=view.index)
    for col in searchable:
        mask |= view[col].astype(str).str.contains(search.strip(), case=False, na=False)
    view = view[mask]

display_cols = [c for c in [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "status", "process", "anomaly_score", "severity"
] if c in view.columns]
st.dataframe(
    view[display_cols], use_container_width=True, hide_index=True, height=390,
    column_config={
        "anomaly_score": st.column_config.ProgressColumn(
            "Anomaly score", min_value=0, max_value=1, format="%.3f"
        ),
        "timestamp": st.column_config.DatetimeColumn("Observed at", format="YYYY-MM-DD HH:mm:ss"),
    },
)
st.caption(f"Showing {len(view):,} of {total:,} records. An anomaly score is a model ranking, not proof of malicious activity.")

if not view.empty:
    selected = st.selectbox(
        "Inspect a record",
        view.index.tolist(),
        format_func=lambda i: (
            f"{str(view.loc[i].get('dst_ip', 'unknown'))} · "
            f"{str(view.loc[i].get('process', 'unknown'))} · "
            f"{float(view.loc[i]['anomaly_score']):.3f}"
        ),
    )
    with st.expander("Connection details", expanded=False):
        st.json({k: (str(v) if pd.notna(v) else None)
                 for k, v in view.loc[selected].to_dict().items()})

st.download_button(
    "↓  Export current results (CSV)",
    data=view.to_csv(index=False).encode("utf-8"),
    file_name="sentinel_investigation.csv",
    mime="text/csv",
)
st.markdown(
    '<div style="border-top:1px solid #22334a;margin-top:28px;padding-top:13px;'
    'color:#71859c;font:10px DM Mono,monospace;letter-spacing:.08em">'
    'SENTINEL SECURITY OPERATIONS · LOCAL ANALYSIS · VERIFY CONTEXT BEFORE RESPONDING TO ALERTS'
    '</div>',
    unsafe_allow_html=True,
)

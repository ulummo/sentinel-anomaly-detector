from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel.data import generate_demo_data, prepare_flows
from sentinel.detector import score_flows

st.set_page_config(page_title="Sentinel | Watchtower", page_icon="◈", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --ink:#e8edf5; --muted:#8492a6; --panel:#111a28; --line:#243247; --cyan:#63d9e8; }
html, body, [class*="css"] { font-family:'Manrope',sans-serif; }
.stApp { background: radial-gradient(ellipse at 80% 0%, #142a3b 0%, #0a111c 48%, #080d15 100%); color:var(--ink); }
.block-container { padding-top:2rem; max-width:1500px; }
section[data-testid="stSidebar"] { background:#0c1420; border-right:1px solid var(--line); }
h1,h2,h3 { letter-spacing:-.04em; }
.eyebrow { color:var(--cyan); font:500 11px 'DM Mono',monospace; letter-spacing:.18em; }
.hero { padding:8px 0 22px 0; border-bottom:1px solid var(--line); margin-bottom:22px; }
.hero h1 { font-size:42px; margin:4px 0 2px; font-weight:800; }
.hero p { color:var(--muted); margin:0; }
.metric { background:linear-gradient(145deg,#142235,#101927); border:1px solid #26364b; padding:17px 18px; border-radius:13px; min-height:112px; }
.metric-label { color:#92a2b7; font:11px 'DM Mono',monospace; letter-spacing:.12em; text-transform:uppercase; }
.metric-value { font-size:29px; font-weight:800; margin-top:7px; }
.metric-note { color:#7f91a8; font-size:12px; margin-top:1px; }
.panel { background:#101a28; border:1px solid #253449; border-radius:14px; padding:16px 18px; }
div[data-testid="stDataFrame"] { border:1px solid #26364b; border-radius:10px; }
.stButton button { border-radius:9px; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown('<div class="eyebrow">SENTINEL // CONTROL</div>', unsafe_allow_html=True)
    st.markdown("### Data source")
    source = st.radio("Choose input", ["Demo traffic", "Upload CSV"], label_visibility="collapsed")
    uploaded = st.file_uploader("Network flow CSV", type=["csv"]) if source == "Upload CSV" else None
    st.divider()
    contamination = st.slider("Expected anomaly share", 0.01, 0.20, 0.04, 0.01)
    st.caption("This controls the Isolation Forest's expected outlier proportion.")
    st.divider()
    st.markdown('<span class="eyebrow">ENGINE STATUS</span>', unsafe_allow_html=True)
    st.success("SCORING ENGINE READY")
    st.caption("Local analysis · No data is sent to a remote service")

st.markdown("""
<div class="hero">
  <div class="eyebrow">NETWORK INTELLIGENCE PLATFORM / 01</div>
  <h1>SENTINEL <span style="color:#63d9e8">//</span> WATCHTOWER</h1>
  <p>Traffic anomaly observability · Inspect the signal, investigate the outlier.</p>
</div>
""", unsafe_allow_html=True)

try:
    if source == "Upload CSV":
        if uploaded is None:
            st.info("Upload a CSV file from the left panel, or switch to Demo traffic to explore the dashboard.")
            st.stop()
        raw = pd.read_csv(uploaded)
    else:
        raw = generate_demo_data()

    prepared, features = prepare_flows(raw)
    results = score_flows(prepared, features, contamination)
except Exception as exc:
    st.error(f"Could not analyze this dataset: {exc}")
    st.stop()

total = len(results)
flagged = int(results["is_anomaly"].sum())
rate = flagged / total * 100
mean_score = results["anomaly_score"].mean()
risk = "ELEVATED" if rate >= 8 else "GUARDED" if rate >= 3 else "LOW"

m1,m2,m3,m4 = st.columns(4)
metrics = [
    (m1, "FLOWS ANALYZED", f"{total:,}", "records in current dataset"),
    (m2, "ANOMALIES FLAGGED", f"{flagged:,}", f"{rate:.1f}% of observed flows"),
    (m3, "MEAN ANOMALY SCORE", f"{mean_score:.3f}", "normalized model score"),
    (m4, "POSTURE INDICATOR", risk, "model-derived · review required"),
]
for col,label,value,note in metrics:
    with col:
        st.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>', unsafe_allow_html=True)

st.write("")
left,right = st.columns([1.55,1])
with left:
    st.markdown("#### Anomaly landscape")
    if "timestamp" in results.columns:
        timeline = results.copy()
        timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], errors="coerce")
        timeline = timeline.dropna(subset=["timestamp"]).set_index("timestamp").resample("15min").agg(
            flows=("anomaly_score","size"), anomalies=("is_anomaly","sum")
        ).reset_index()
        if not timeline.empty:
            fig = px.area(timeline, x="timestamp", y="flows", color_discrete_sequence=["#2c7189"])
            fig.add_scatter(x=timeline["timestamp"], y=timeline["anomalies"], mode="lines",
                            name="Flagged", line=dict(color="#ff6b78", width=2))
            fig.update_layout(height=300, margin=dict(l=8,r=8,t=12,b=8), paper_bgcolor="rgba(0,0,0,0)",
                              plot_bgcolor="rgba(0,0,0,0)", font_color="#9cacc0",
                              legend=dict(orientation="h",y=1.12), xaxis_title="", yaxis_title="Flow count")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption("No valid timestamps available for the timeline.")
    else:
        st.caption("Add a timestamp column to enable the event timeline.")
with right:
    st.markdown("#### Severity distribution")
    dist = results.loc[results["is_anomaly"], "severity"].value_counts().reindex(["HIGH","MEDIUM","LOW"], fill_value=0).reset_index()
    dist.columns = ["severity","count"]
    fig = px.bar(dist, x="severity", y="count", color="severity",
                 color_discrete_map={"HIGH":"#ff6877","MEDIUM":"#f2b35e","LOW":"#63d9e8"})
    fig.update_layout(height=300, showlegend=False, margin=dict(l=8,r=8,t=12,b=8),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font_color="#9cacc0", xaxis_title="", yaxis_title="Flagged flows")
    st.plotly_chart(fig, use_container_width=True)

st.write("")
st.markdown("#### Investigation queue")
only_anomalies = st.toggle("Show flagged flows only", value=True)
min_score = st.slider("Minimum anomaly score", 0.0, 1.0, 0.0, 0.01)
view = results[results["anomaly_score"] >= min_score]
if only_anomalies:
    view = view[view["is_anomaly"]]
display_cols = [c for c in ["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","duration","bytes","packets","anomaly_score","severity"] if c in view.columns]
st.dataframe(view[display_cols], use_container_width=True, hide_index=True, height=360,
             column_config={"anomaly_score":st.column_config.ProgressColumn("Anomaly score",min_value=0,max_value=1,format="%.3f")})

if not view.empty:
    selected = st.selectbox("Inspect a record", view.index.tolist(), format_func=lambda i: f"Score {view.loc[i,'anomaly_score']:.3f} · {view.loc[i,'severity']}")
    row = view.loc[selected]
    with st.expander("Flow details", expanded=False):
        st.json({k: (str(v) if pd.notna(v) else None) for k,v in row.to_dict().items()})
else:
    st.caption("No records match the current filters.")

csv = view.to_csv(index=False).encode("utf-8")
st.download_button("Export current view · CSV", data=csv, file_name="sentinel_findings.csv", mime="text/csv")
st.caption("SENTINEL / Results are relative to the dataset being analyzed. Investigate context before drawing conclusions.")

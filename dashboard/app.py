"""Streamlit security dashboard.  Run: streamlit run dashboard/app.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.express as px
import streamlit as st

from config.config import DATA_PROCESSED
from database import db

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLORS = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}

st.set_page_config(page_title="Threat Intelligence & Anomaly Detection", layout="wide")
st.title("Threat Intelligence & Network Anomaly Detection")
st.caption("Defensive research prototype. Alerts are leads for investigation, not confirmed incidents.")


@st.cache_data(ttl=30)
def load():
    conn = db.get_conn(); db.init_db(conn)
    return db.fetch_alerts(conn, limit=100000), db.load_indicators(conn)


alerts, indicators = load()
if alerts.empty:
    st.warning("No alerts yet. Run `python main.py demo` first.")
    st.stop()

with st.sidebar:
    st.header("Filters")
    sev = st.multiselect("Severity", SEV_ORDER, default=SEV_ORDER)
    min_risk = st.slider("Minimum risk score", 0, 100, 0)
    ioc_only = st.checkbox("Only threat-intel matches")
view = alerts[alerts.severity.isin(sev) & (alerts.risk_score >= min_risk)]
if ioc_only:
    view = view[view.ioc_match == 1]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts", f"{len(view):,}")
c2.metric("Critical + High", int(view.severity.isin(["critical", "high"]).sum()))
c3.metric("IOC-matched alerts", int((view.ioc_match == 1).sum()))
c4.metric("Indicators loaded", f"{len(indicators):,}")

tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Investigate", "Threat intel", "Model evaluation"])

with tab1:
    left, right = st.columns(2)
    counts = view.severity.value_counts().reindex(SEV_ORDER).dropna().reset_index()
    counts.columns = ["severity", "alerts"]
    left.plotly_chart(px.bar(counts, x="severity", y="alerts", color="severity",
                             color_discrete_map=SEV_COLORS, title="Alerts by severity"), use_container_width=True)
    top = view.groupby("src_ip").agg(alerts=("id", "count"), max_risk=("risk_score", "max")).nlargest(10, "alerts").reset_index()
    right.plotly_chart(px.bar(top, x="alerts", y="src_ip", orientation="h", color="max_risk",
                              title="Top source hosts by alert count"), use_container_width=True)
    if view.event_time.notna().any():
        t = view.assign(t=pd.to_datetime(view.event_time).dt.floor("h")).groupby(["t", "severity"]).size().reset_index(name="n")
        st.plotly_chart(px.bar(t, x="t", y="n", color="severity", color_discrete_map=SEV_COLORS,
                               title="Alerts over time"), use_container_width=True)
    st.plotly_chart(px.histogram(view, x="anomaly_pct", nbins=40, color="severity",
                                 color_discrete_map=SEV_COLORS,
                                 title="Anomaly percentile vs. benign baseline"), use_container_width=True)

with tab2:
    st.dataframe(view[["id", "event_time", "src_ip", "dst_ip", "dst_port", "risk_score", "severity",
                       "ioc_match", "rules_triggered"]], use_container_width=True, hide_index=True)
    if len(view):
        pick = st.selectbox("Select alert ID to investigate", view["id"].tolist())
        row = view[view["id"] == pick].iloc[0]
        st.subheader(f"Alert {pick}: {row.severity.upper()} (risk {row.risk_score:.1f})")
        st.write(row.explanation)
        st.json({k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()})
        if pd.notna(row.get("attack_type")):
            st.info(f"Ground-truth label (synthetic/labelled data only): {row.attack_type}")

with tab3:
    st.write("Indicators by type and source")
    st.dataframe(indicators.groupby(["source", "ioc_type"]).size().reset_index(name="count"), hide_index=True)
    st.write("Most frequently matched indicators")
    hits = view[view.ioc_match == 1].groupby(["dst_ip", "ioc_source", "ioc_threat"]).size().reset_index(name="alerts")
    st.dataframe(hits.sort_values("alerts", ascending=False), hide_index=True)

with tab4:
    res_path = DATA_PROCESSED / "results.json"
    if not res_path.exists():
        st.info("Run `python main.py evaluate` to generate results.")
    else:
        res = json.loads(res_path.read_text())
        st.subheader("Dataset and split")
        st.json(res["dataset"])
        st.subheader("Leakage / duplicate checks")
        st.json(res.get("leakage", {}))
        st.subheader("Model comparison (test split)")
        table = pd.DataFrame({k: {m: v.get(m) for m in ["precision", "recall", "f1", "false_positive_rate", "roc_auc"]}
                              for k, v in res["models"].items()}).T
        st.dataframe(table.style.format("{:.3f}"), use_container_width=True)
        rec = pd.DataFrame({k: v["recall_by_attack"] for k, v in res["models"].items()}).T
        st.plotly_chart(px.imshow(rec, text_auto=".2f", aspect="auto", color_continuous_scale="Blues",
                                  title="Recall by attack type"), use_container_width=True)
        if res.get("unseen_attack_generalization"):
            st.subheader("Generalisation to attack types not seen in training")
            st.dataframe(pd.DataFrame(res["unseen_attack_generalization"]).T, use_container_width=True)
        st.subheader("Risk-score calibration (fitted on validation only)")
        st.json(res.get("calibration", {}))
        st.write("Performance", res["performance"])

"""VPRP — SSVC Priority Dashboard"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone

st.set_page_config(page_title="SSVC Priority", page_icon="🎯", layout="wide")

from app.utils.auth_guard import require_auth, show_user_sidebar, is_authenticated, HIDE_SIDEBAR_CSS
if not is_authenticated():
    st.markdown(HIDE_SIDEBAR_CSS, unsafe_allow_html=True)
require_auth()
st.session_state["_page_id"] = "ssvc"
show_user_sidebar()

st.title("🎯 SSVC Priority Dashboard")
st.caption("CISA Stakeholder-Specific Vulnerability Categorization — Deployer Decision Tree")

# ── Helpers ──────────────────────────────────────────────
from app.models.database import SessionLocal
from app.models.schemas import Finding
from app.engine.ssvc import evaluate_ssvc, get_ssvc_summary
import logging

log = logging.getLogger(__name__)

PRIORITY_COLORS = {
    "Immediate": "#d32f2f",
    "Out-of-Cycle": "#f57c00",
    "Scheduled": "#fbc02d",
    "Defer": "#388e3c",
}

PRIORITY_ORDER = ["Immediate", "Out-of-Cycle", "Scheduled", "Defer"]


@st.cache_data(ttl=120)
def load_findings() -> pd.DataFrame:
    """Load all findings into a DataFrame."""
    session = SessionLocal()
    try:
        rows = session.query(Finding).all()
        if not rows:
            return pd.DataFrame()
        records = []
        for r in rows:
            records.append({c.name: getattr(r, c.name) for c in Finding.__table__.columns})
        return pd.DataFrame(records)
    finally:
        session.close()


def save_ssvc_to_db(df: pd.DataFrame):
    """Persist SSVC columns back to the database."""
    session = SessionLocal()
    try:
        ssvc_cols = [
            "ssvc_exploitation", "ssvc_system_exposure", "ssvc_automatable",
            "ssvc_human_impact", "ssvc_priority", "ssvc_evaluated_at",
        ]
        updated = 0
        for _, row in df.iterrows():
            finding = session.query(Finding).filter(Finding.id == row["id"]).first()
            if finding:
                for col in ssvc_cols:
                    if col in row and pd.notna(row[col]):
                        setattr(finding, col, row[col])
                updated += 1
        session.commit()
        return updated
    except Exception as e:
        session.rollback()
        log.error(f"save_ssvc_to_db error: {e}")
        raise
    finally:
        session.close()


# ── Main UI ──────────────────────────────────────────────
df = load_findings()

if df.empty:
    st.warning("No findings in the database. Upload vulnerability data first.")
    st.stop()

# ── Evaluate / Re-evaluate SSVC ──
col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([2, 2, 4])
with col_ctrl1:
    already_evaluated = df["ssvc_priority"].notna().sum() if "ssvc_priority" in df.columns else 0
    st.metric("Already Evaluated", f"{already_evaluated} / {len(df)}")
with col_ctrl2:
    if st.button("🔄 Run SSVC Evaluation", type="primary", use_container_width=True):
        with st.spinner("Evaluating SSVC decision tree..."):
            df = evaluate_ssvc(df)
            df["ssvc_evaluated_at"] = datetime.now(timezone.utc)
            saved = save_ssvc_to_db(df)
            st.cache_data.clear()
        st.success(f"SSVC evaluated and saved for {saved} findings.")
        st.rerun()
with col_ctrl3:
    st.info(
        "The SSVC Deployer Tree uses **Exploitation Status**, **System Exposure**, "
        "**Automatable**, and **Human Impact** to produce a priority: "
        "Immediate → Out-of-Cycle → Scheduled → Defer."
    )

st.divider()

# ── Check if we have SSVC data ──
has_ssvc = "ssvc_priority" in df.columns and df["ssvc_priority"].notna().any()

if not has_ssvc:
    st.warning("SSVC has not been evaluated yet. Click **Run SSVC Evaluation** above.")
    st.stop()

# Filter to evaluated rows
df_ssvc = df[df["ssvc_priority"].notna()].copy()

# ── KPI Row ──
st.subheader("Priority Overview")
k1, k2, k3, k4, k5 = st.columns(5)
summary = get_ssvc_summary(df_ssvc)
with k1:
    st.metric("Total Evaluated", summary.get("total", 0))
with k2:
    imm = summary.get("priority_counts", {}).get("Immediate", 0)
    st.metric("🔴 Immediate", imm)
with k3:
    ooc = summary.get("priority_counts", {}).get("Out-of-Cycle", 0)
    st.metric("🟠 Out-of-Cycle", ooc)
with k4:
    sch = summary.get("priority_counts", {}).get("Scheduled", 0)
    st.metric("🟡 Scheduled", sch)
with k5:
    dfr = summary.get("priority_counts", {}).get("Defer", 0)
    st.metric("🟢 Defer", dfr)

st.divider()

# ── Charts Row ──
chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("Priority Distribution")
    pri_counts = df_ssvc["ssvc_priority"].value_counts().reindex(PRIORITY_ORDER).fillna(0)
    fig_pie = px.pie(
        names=pri_counts.index,
        values=pri_counts.values,
        color=pri_counts.index,
        color_discrete_map=PRIORITY_COLORS,
        hole=0.4,
    )
    fig_pie.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=350)
    st.plotly_chart(fig_pie, use_container_width=True)

with chart2:
    st.subheader("Decision-Point Breakdown")
    dp_data = []
    for dp in ["ssvc_exploitation", "ssvc_system_exposure", "ssvc_automatable", "ssvc_human_impact"]:
        if dp in df_ssvc.columns:
            vc = df_ssvc[dp].value_counts()
            for val, cnt in vc.items():
                dp_label = dp.replace("ssvc_", "").replace("_", " ").title()
                dp_data.append({"Decision Point": dp_label, "Value": str(val), "Count": cnt})
    if dp_data:
        dp_df = pd.DataFrame(dp_data)
        fig_dp = px.bar(
            dp_df, x="Decision Point", y="Count", color="Value",
            barmode="group", text_auto=True,
        )
        fig_dp.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=350)
        st.plotly_chart(fig_dp, use_container_width=True)

st.divider()

# ── Priority by Team ──
st.subheader("Priority by Team")
if "assigned_team" in df_ssvc.columns:
    team_pri = df_ssvc.groupby(["assigned_team", "ssvc_priority"]).size().reset_index(name="count")
    fig_team = px.bar(
        team_pri, x="assigned_team", y="count", color="ssvc_priority",
        color_discrete_map=PRIORITY_COLORS,
        category_orders={"ssvc_priority": PRIORITY_ORDER},
        barmode="stack", text_auto=True,
    )
    fig_team.update_layout(
        xaxis_title="Team", yaxis_title="Findings",
        margin=dict(t=20, b=20), height=400,
    )
    st.plotly_chart(fig_team, use_container_width=True)
else:
    st.info("No team assignment data available.")

st.divider()

# ── Priority vs Severity Heatmap ──
st.subheader("SSVC Priority vs CVSS Severity")
if "vulnerability_severity" in df_ssvc.columns:
    sev_order = ["Critical", "High", "Medium", "Low"]
    heat = df_ssvc.groupby(["ssvc_priority", "vulnerability_severity"]).size().reset_index(name="count")
    heat_pivot = heat.pivot_table(index="ssvc_priority", columns="vulnerability_severity", values="count", fill_value=0)
    # Reindex for consistent ordering
    heat_pivot = heat_pivot.reindex(index=PRIORITY_ORDER, columns=[s for s in sev_order if s in heat_pivot.columns], fill_value=0)
    fig_heat = go.Figure(data=go.Heatmap(
        z=heat_pivot.values,
        x=heat_pivot.columns.tolist(),
        y=heat_pivot.index.tolist(),
        colorscale="YlOrRd",
        text=heat_pivot.values,
        texttemplate="%{text}",
        hovertemplate="Priority: %{y}<br>Severity: %{x}<br>Count: %{z}<extra></extra>",
    ))
    fig_heat.update_layout(
        xaxis_title="CVSS Severity", yaxis_title="SSVC Priority",
        margin=dict(t=20, b=20), height=350,
    )
    st.plotly_chart(fig_heat, use_container_width=True)

st.divider()

# ── SSVC Decision Tree Explainer ──
with st.expander("📖 SSVC Decision Tree Reference", expanded=False):
    st.markdown("""
    **CISA SSVC Deployer Decision Tree** evaluates four decision points:

    **1. Exploitation Status** — Is the vulnerability being actively exploited?
    - `active` — Exploit seen in the wild (CISA KEV, high EPSS)
    - `poc` — Proof-of-concept exists
    - `none` — No known exploitation

    **2. System Exposure** — How exposed is the affected system?
    - `open` — Internet-facing / publicly accessible
    - `controlled` — Internal network with some controls
    - `small` — Air-gapped or highly restricted

    **3. Automatable** — Can an attacker automate exploitation?
    - `yes` — Network-based, no auth required, common software
    - `no` — Requires physical access, credentials, or complex setup

    **4. Human Impact** — What is the consequence of exploitation?
    - `very_high` — Critical asset, safety/mission impact
    - `high` — Important system, significant data at risk
    - `medium` — Standard business system
    - `low` — Non-critical / test system

    **Priority Outcomes:**
    | Priority | Action |
    |----------|--------|
    | 🔴 **Immediate** | Act now — drop everything |
    | 🟠 **Out-of-Cycle** | Patch outside normal cycle ASAP |
    | 🟡 **Scheduled** | Patch in next regular maintenance |
    | 🟢 **Defer** | Accept risk or schedule at convenience |
    """)

st.divider()

# ── Detailed Findings Table ──
st.subheader("Findings — SSVC Detail")

# Filters
fc1, fc2, fc3 = st.columns(3)
with fc1:
    pri_filter = st.multiselect("Priority", PRIORITY_ORDER, default=PRIORITY_ORDER, key="ssvc_pri_f")
with fc2:
    expl_options = sorted(df_ssvc["ssvc_exploitation"].dropna().unique().tolist()) if "ssvc_exploitation" in df_ssvc.columns else []
    expl_filter = st.multiselect("Exploitation", expl_options, default=expl_options, key="ssvc_expl_f")
with fc3:
    team_options = sorted(df_ssvc["assigned_team"].dropna().unique().tolist()) if "assigned_team" in df_ssvc.columns else []
    team_filter = st.multiselect("Team", team_options, default=team_options, key="ssvc_team_f")

mask = df_ssvc["ssvc_priority"].isin(pri_filter)
if "ssvc_exploitation" in df_ssvc.columns and expl_filter:
    mask &= df_ssvc["ssvc_exploitation"].isin(expl_filter)
if "assigned_team" in df_ssvc.columns and team_filter:
    mask &= df_ssvc["assigned_team"].isin(team_filter)

display_cols = [
    "cve_id", "device_name", "cvss_score", "vulnerability_severity",
    "ssvc_priority", "ssvc_exploitation", "ssvc_system_exposure",
    "ssvc_automatable", "ssvc_human_impact", "assigned_team",
    "remediation_status", "epss_score",
]
display_cols = [c for c in display_cols if c in df_ssvc.columns]

st.dataframe(
    df_ssvc[mask][display_cols].sort_values(
        by="ssvc_priority",
        key=lambda x: x.map({p: i for i, p in enumerate(PRIORITY_ORDER)}),
    ),
    use_container_width=True,
    height=500,
)

# ── Export ──
st.subheader("Export")
ec1, ec2 = st.columns(2)
with ec1:
    csv_data = df_ssvc[mask][display_cols].to_csv(index=False)
    st.download_button(
        "📥 Download SSVC Report (CSV)",
        csv_data,
        file_name=f"ssvc_priority_report_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv",
        use_container_width=True,
    )
with ec2:
    imm_df = df_ssvc[df_ssvc["ssvc_priority"] == "Immediate"]
    if not imm_df.empty:
        imm_csv = imm_df[display_cols].to_csv(index=False)
        st.download_button(
            "🚨 Download Immediate-Action Items (CSV)",
            imm_csv,
            file_name=f"ssvc_immediate_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    else:
        st.success("No Immediate-priority findings!")

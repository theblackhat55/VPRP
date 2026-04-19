"""
VPRP — Reporting & Analytics
Executive reports, trend analytics, team performance, MTTR tracking.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone
from io import BytesIO

from app.utils.auth_guard import require_auth, show_user_sidebar
st.session_state["_page_id"] = "reports"
from app.models.remediation_service import get_remediation_summary, get_findings_for_remediation
from app.models.notification_service import get_sla_alerts
from app.models.db_service import get_scan_history, get_trend_data
from app.models.database import get_session
from app.models.schemas import Finding, ScanUpload, ScanSummary, Asset
from app.engine.reporter import generate_excel_report
from sqlalchemy import func, case, and_, distinct

st.set_page_config(page_title="VPRP — Reports", page_icon="📊", layout="wide")
st.title("📊 Reports & Analytics")

current_user = require_auth()
st.session_state["_page_id"] = "reports"
show_user_sidebar()


# ── Helper: query analytics data ────────────────────────
@st.cache_data(ttl=300)
def load_analytics():
    """Load all analytics data from the database."""
    session = get_session()
    try:
        # Total counts
        total_findings = session.query(func.count(Finding.id)).scalar() or 0
        total_cves = session.query(func.count(distinct(Finding.cve_id))).scalar() or 0
        total_devices = session.query(func.count(distinct(Finding.device_name))).scalar() or 0
        total_scans = session.query(func.count(ScanUpload.id)).scalar() or 0
        total_assets = session.query(func.count(Asset.id)).scalar() or 0

        # Severity breakdown
        severity = dict(
            session.query(Finding.vulnerability_severity, func.count(Finding.id))
            .group_by(Finding.vulnerability_severity).all()
        )

        # Status breakdown
        status = dict(
            session.query(Finding.remediation_status, func.count(Finding.id))
            .group_by(Finding.remediation_status).all()
        )

        # Team workload
        team_data = session.query(
            Finding.assigned_team,
            func.count(Finding.id).label("total"),
            func.count(case((Finding.remediation_status == "remediated", 1))).label("remediated"),
            func.count(case((Finding.sla_breached == True, 1))).label("sla_breached"),
            func.avg(Finding.risk_score).label("avg_risk"),
        ).group_by(Finding.assigned_team).all()

        teams = []
        for t in team_data:
            total = t.total or 1
            teams.append({
                "Team": t.assigned_team or "Unassigned",
                "Total": t.total,
                "Remediated": t.remediated,
                "Open": total - t.remediated,
                "SLA Breached": t.sla_breached,
                "Avg Risk": round(t.avg_risk or 0, 1),
                "Remediation Rate": round((t.remediated / total) * 100, 1),
            })

        # Top 10 riskiest CVEs
        top_cves = session.query(
            Finding.cve_id,
            func.max(Finding.cvss_score).label("cvss"),
            func.max(Finding.risk_score).label("risk"),
            func.max(Finding.vulnerability_severity).label("severity"),
            func.count(Finding.device_name).label("affected_devices"),
            func.max(Finding.assigned_team).label("team"),
            func.max(Finding.remediation_status).label("status"),
        ).group_by(Finding.cve_id).order_by(func.max(Finding.risk_score).desc()).limit(10).all()

        top_cves_list = [{
            "CVE": c.cve_id, "CVSS": c.cvss, "Risk Score": c.risk,
            "Severity": c.severity, "Affected Devices": c.affected_devices,
            "Team": c.team, "Status": c.status,
        } for c in top_cves]

        # Risk distribution
        risk_bins = session.query(
            case(
                (Finding.risk_score >= 80, "Critical (80-100)"),
                (Finding.risk_score >= 60, "High (60-79)"),
                (Finding.risk_score >= 40, "Medium (40-59)"),
                else_="Low (0-39)",
            ).label("risk_band"),
            func.count(Finding.id),
        ).group_by("risk_band").all()

        # MTTR calculation (for remediated findings with timestamps)
        mttr_data = session.query(
            Finding.assigned_team,
            func.avg(
                func.extract("epoch", Finding.remediation_updated_at) -
                func.extract("epoch", Finding.first_seen)
            ).label("avg_seconds"),
            func.count(Finding.id).label("count"),
        ).filter(
            Finding.remediation_status == "remediated",
            Finding.remediation_updated_at.isnot(None),
            Finding.first_seen.isnot(None),
        ).group_by(Finding.assigned_team).all()

        mttr = [{
            "Team": m.assigned_team or "Unassigned",
            "MTTR (days)": round((m.avg_seconds or 0) / 86400, 1),
            "Remediated Count": m.count,
        } for m in mttr_data]

        return {
            "total_findings": total_findings,
            "total_cves": total_cves,
            "total_devices": total_devices,
            "total_scans": total_scans,
            "total_assets": total_assets,
            "severity": severity,
            "status": status,
            "teams": teams,
            "top_cves": top_cves_list,
            "risk_bins": dict(risk_bins),
            "mttr": mttr,
        }
    finally:
        session.close()


# ── Load Data ───────────────────────────────────────────
data = load_analytics()
summary = get_remediation_summary()
alerts = get_sla_alerts()

# ── Executive Summary KPIs ──────────────────────────────
st.header("Executive Summary")

e1, e2, e3, e4, e5 = st.columns(5)
e1.metric("Total Findings", f"{data['total_findings']:,}")
e2.metric("Unique CVEs", f"{data['total_cves']:,}")
e3.metric("Devices Affected", f"{data['total_devices']:,}")
e4.metric("Remediation Rate", f"{summary['remediation_rate']}%")
e5.metric("SLA Breached", f"{alerts['total_breached']:,}")

e6, e7, e8, e9, e10 = st.columns(5)
e6.metric("Critical", f"{data['severity'].get('critical', 0):,}")
e7.metric("High", f"{data['severity'].get('high', 0):,}")
e8.metric("Medium", f"{data['severity'].get('medium', 0):,}")
e9.metric("Low", f"{data['severity'].get('low', 0):,}")
e10.metric("Scans Processed", f"{data['total_scans']:,}")

# ── Risk & Severity Charts ──────────────────────────────
st.divider()
st.header("Risk & Severity Analysis")

rc1, rc2 = st.columns(2)

with rc1:
    sev_df = pd.DataFrame(
        list(data["severity"].items()), columns=["Severity", "Count"]
    )
    if not sev_df.empty:
        fig = px.pie(sev_df, names="Severity", values="Count",
                     title="Findings by Severity",
                     color="Severity",
                     color_discrete_map={
                         "critical": "#dc2626", "high": "#f59e0b",
                         "medium": "#3b82f6", "low": "#22c55e",
                     })
        fig.update_layout(height=380)
        st.plotly_chart(fig, use_container_width=True)

with rc2:
    if data["risk_bins"]:
        risk_df = pd.DataFrame(
            list(data["risk_bins"].items()), columns=["Risk Band", "Count"]
        )
        order = ["Critical (80-100)", "High (60-79)", "Medium (40-59)", "Low (0-39)"]
        risk_df["Risk Band"] = pd.Categorical(risk_df["Risk Band"], categories=order, ordered=True)
        risk_df = risk_df.sort_values("Risk Band")
        fig2 = px.bar(risk_df, x="Risk Band", y="Count", title="Risk Score Distribution",
                      color="Risk Band",
                      color_discrete_map={
                          "Critical (80-100)": "#dc2626", "High (60-79)": "#f59e0b",
                          "Medium (40-59)": "#3b82f6", "Low (0-39)": "#22c55e",
                      })
        fig2.update_layout(height=380, showlegend=False)
        st.plotly_chart(fig2, use_container_width=True)

# ── Remediation Status ──────────────────────────────────
st.divider()
st.header("Remediation Status")

rs1, rs2 = st.columns(2)

with rs1:
    status_df = pd.DataFrame(
        list(data["status"].items()), columns=["Status", "Count"]
    )
    if not status_df.empty:
        color_map = {
            "open": "#ef4444", "in_progress": "#f59e0b", "remediated": "#22c55e",
            "accepted_risk": "#6366f1", "exception": "#a855f7", "false_positive": "#64748b",
        }
        fig3 = px.pie(status_df, names="Status", values="Count",
                      title="Findings by Remediation Status",
                      color="Status", color_discrete_map=color_map)
        fig3.update_layout(height=380)
        st.plotly_chart(fig3, use_container_width=True)

with rs2:
    if data["teams"]:
        team_df = pd.DataFrame(data["teams"])
        fig4 = px.bar(team_df, x="Team", y=["Remediated", "Open", "SLA Breached"],
                      title="Team Remediation Progress", barmode="stack",
                      color_discrete_map={
                          "Remediated": "#22c55e", "Open": "#ef4444", "SLA Breached": "#f59e0b",
                      })
        fig4.update_layout(height=380, xaxis_tickangle=-45)
        st.plotly_chart(fig4, use_container_width=True)

# ── Top 10 Riskiest CVEs ────────────────────────────────
st.divider()
st.header("Top 10 Riskiest Vulnerabilities")

if data["top_cves"]:
    top_df = pd.DataFrame(data["top_cves"])
    st.dataframe(top_df, use_container_width=True, hide_index=True)

    fig5 = px.bar(top_df, x="CVE", y="Risk Score", color="Severity",
                  hover_data=["CVSS", "Affected Devices", "Team"],
                  title="Top 10 CVEs by Risk Score",
                  color_discrete_map={
                      "critical": "#dc2626", "high": "#f59e0b",
                      "medium": "#3b82f6", "low": "#22c55e",
                  })
    fig5.update_layout(height=400, xaxis_tickangle=-45)
    st.plotly_chart(fig5, use_container_width=True)

# ── Team Performance ────────────────────────────────────
st.divider()
st.header("Team Performance")

if data["teams"]:
    team_perf = pd.DataFrame(data["teams"])

    tp1, tp2 = st.columns(2)
    with tp1:
        fig6 = px.bar(team_perf, x="Team", y="Remediation Rate",
                      title="Team Remediation Rate (%)",
                      color="Remediation Rate",
                      color_continuous_scale=["#ef4444", "#f59e0b", "#22c55e"])
        fig6.update_layout(height=380, xaxis_tickangle=-45, showlegend=False)
        st.plotly_chart(fig6, use_container_width=True)

    with tp2:
        fig7 = px.bar(team_perf, x="Team", y="Avg Risk",
                      title="Average Risk Score by Team",
                      color="Avg Risk",
                      color_continuous_scale=["#22c55e", "#f59e0b", "#ef4444"])
        fig7.update_layout(height=380, xaxis_tickangle=-45, showlegend=False)
        st.plotly_chart(fig7, use_container_width=True)

    st.subheader("Team Summary Table")
    st.dataframe(team_perf, use_container_width=True, hide_index=True)

# ── MTTR (Mean Time to Remediate) ───────────────────────
st.divider()
st.header("Mean Time to Remediate (MTTR)")

if data["mttr"]:
    mttr_df = pd.DataFrame(data["mttr"])
    fig8 = px.bar(mttr_df, x="Team", y="MTTR (days)",
                  title="Average MTTR by Team (days)",
                  color="MTTR (days)",
                  color_continuous_scale=["#22c55e", "#f59e0b", "#ef4444"],
                  hover_data=["Remediated Count"])
    fig8.update_layout(height=380, xaxis_tickangle=-45, showlegend=False)
    st.plotly_chart(fig8, use_container_width=True)

    st.dataframe(mttr_df, use_container_width=True, hide_index=True)
else:
    st.info("No remediated findings with timestamps yet. MTTR will appear after findings are marked as remediated.")

# ── Scan History ────────────────────────────────────────
st.divider()
st.header("Scan Upload History")

scan_hist = get_scan_history(limit=20)
if scan_hist:
    scan_df = pd.DataFrame(scan_hist)
    st.dataframe(scan_df, use_container_width=True, hide_index=True)
else:
    st.info("No scan history available.")

# ── Export Reports ──────────────────────────────────────
st.divider()
st.header("Export Reports")

exp1, exp2 = st.columns(2)

with exp1:
    st.subheader("Executive Excel Report")
    st.caption("Full vulnerability report with executive summary, all findings, patch actions, and per-team sheets.")
    if st.button("Generate Executive Report", type="primary"):
        with st.spinner("Generating report..."):
            # Load all findings
            all_findings = get_findings_for_remediation(limit=10000)
            if not all_findings.empty:
                # Build executive summary text
                exec_text = (
                    f"VPRP Executive Vulnerability Report\n"
                    f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                    f"Total Findings: {data['total_findings']}\n"
                    f"Unique CVEs: {data['total_cves']}\n"
                    f"Devices Affected: {data['total_devices']}\n"
                    f"Remediation Rate: {summary['remediation_rate']}%\n"
                    f"SLA Breached: {alerts['total_breached']}\n\n"
                    f"Severity Breakdown:\n"
                    f"  Critical: {data['severity'].get('critical', 0)}\n"
                    f"  High: {data['severity'].get('high', 0)}\n"
                    f"  Medium: {data['severity'].get('medium', 0)}\n"
                    f"  Low: {data['severity'].get('low', 0)}\n"
                )

                team_summaries = {}
                if data["teams"]:
                    for t in data["teams"]:
                        team_summaries[t["Team"]] = (
                            f"Total: {t['Total']} | Remediated: {t['Remediated']} | "
                            f"Open: {t['Open']} | SLA Breached: {t['SLA Breached']} | "
                            f"Rate: {t['Remediation Rate']}%"
                        )

                excel_bytes = generate_excel_report(
                    all_findings, all_findings, exec_text, team_summaries
                )
                st.download_button(
                    label="Download Executive Report (.xlsx)",
                    data=excel_bytes,
                    file_name=f"VPRP_Executive_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            else:
                st.warning("No findings to export.")

with exp2:
    st.subheader("Analytics CSV Export")
    st.caption("Export current analytics data for external processing.")

    if data["teams"]:
        team_csv = pd.DataFrame(data["teams"]).to_csv(index=False).encode()
        st.download_button(
            label="Download Team Performance (.csv)",
            data=team_csv,
            file_name=f"VPRP_Team_Performance_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )

    if data["top_cves"]:
        cve_csv = pd.DataFrame(data["top_cves"]).to_csv(index=False).encode()
        st.download_button(
            label="Download Top CVEs (.csv)",
            data=cve_csv,
            file_name=f"VPRP_Top_CVEs_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )

    if data["mttr"]:
        mttr_csv = pd.DataFrame(data["mttr"]).to_csv(index=False).encode()
        st.download_button(
            label="Download MTTR Data (.csv)",
            data=mttr_csv,
            file_name=f"VPRP_MTTR_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )

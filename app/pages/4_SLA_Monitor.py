"""
VPRP — SLA Monitoring & Notifications
Track SLA compliance, send alerts, configure notification channels.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

from app.models.notification_service import (
    get_sla_alerts,
    send_teams_sla_alert,
    send_email_sla_alert,
    send_teams_notification,
    send_email,
    run_sla_check_and_notify,
    TEAMS_WEBHOOK_URL,
    SMTP_HOST,
)
from app.models.remediation_service import get_remediation_summary

st.set_page_config(page_title="VPRP — SLA Monitor", page_icon="⏰", layout="wide")
st.title("⏰ SLA Monitoring & Notifications")

from app.utils.auth_guard import require_auth, show_user_sidebar
st.session_state["_page_id"] = "sla"
current_user = require_auth()
st.session_state["_page_id"] = "sla"
show_user_sidebar()

# ── Notification Channel Status ─────────────────────────
st.header("Notification Channels")
nc1, nc2 = st.columns(2)
with nc1:
    if TEAMS_WEBHOOK_URL:
        st.success("Microsoft Teams: Configured")
    else:
        st.warning("Microsoft Teams: Not configured — set TEAMS_WEBHOOK_URL in .env")
with nc2:
    if SMTP_HOST:
        st.success(f"Email (SMTP): Configured ({SMTP_HOST})")
    else:
        st.warning("Email: Not configured — set SMTP_HOST in .env")

# ── SLA Overview ────────────────────────────────────────
st.divider()
st.header("SLA Compliance")

alerts = get_sla_alerts()
summary = get_remediation_summary()

s1, s2, s3, s4 = st.columns(4)
s1.metric("SLA Breached", f"{alerts['total_breached']}",
          delta="Action Required" if alerts["total_breached"] > 0 else "All Clear",
          delta_color="inverse" if alerts["total_breached"] > 0 else "normal")
s2.metric("Approaching SLA (7d)", f"{alerts['total_approaching']}",
          delta="Monitor" if alerts["total_approaching"] > 0 else "Clear",
          delta_color="inverse" if alerts["total_approaching"] > 0 else "normal")
s3.metric("Critical Breached", f"{alerts['breached_critical']}")
s4.metric("High Breached", f"{alerts['breached_high']}")

# ── Breached Findings Table ─────────────────────────────
if alerts["total_breached"] > 0:
    st.divider()
    st.subheader("SLA Breached Findings")

    breach_rows = []
    for team, items in alerts["team_breaches"].items():
        for item in items:
            item["team"] = team
            breach_rows.append(item)

    breach_df = pd.DataFrame(breach_rows)
    if not breach_df.empty:
        # Color by overdue severity
        fig = px.bar(
            breach_df.sort_values("days_overdue", ascending=False).head(20),
            x="cve_id", y="days_overdue", color="severity",
            hover_data=["device_name", "team", "risk_score"],
            title="Top 20 Overdue Findings (days past SLA)",
            color_discrete_map={
                "critical": "#dc2626", "high": "#f59e0b",
                "medium": "#3b82f6", "low": "#22c55e",
            },
        )
        fig.update_layout(height=400, xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)

        st.dataframe(
            breach_df[["cve_id", "device_name", "severity", "risk_score",
                       "days_overdue", "team", "status"]].sort_values("days_overdue", ascending=False),
            use_container_width=True, hide_index=True,
        )

# ── Approaching SLA Table ───────────────────────────────
if alerts["total_approaching"] > 0:
    st.divider()
    st.subheader("Approaching SLA Deadline (within 7 days)")

    approach_rows = []
    for team, items in alerts["team_approaching"].items():
        for item in items:
            item["team"] = team
            approach_rows.append(item)

    approach_df = pd.DataFrame(approach_rows)
    if not approach_df.empty:
        st.dataframe(
            approach_df[["cve_id", "device_name", "severity", "risk_score",
                         "days_remaining", "team"]].sort_values("days_remaining"),
            use_container_width=True, hide_index=True,
        )

# ── Team SLA Compliance ─────────────────────────────────
st.divider()
st.subheader("Team SLA Compliance")

if alerts["team_breaches"]:
    team_summary = []
    all_teams = set(list(alerts["team_breaches"].keys()) + list(alerts["team_approaching"].keys()))
    for team in sorted(all_teams):
        team_summary.append({
            "Team": team,
            "Breached": len(alerts["team_breaches"].get(team, [])),
            "Approaching": len(alerts["team_approaching"].get(team, [])),
        })
    team_comp_df = pd.DataFrame(team_summary)
    fig2 = px.bar(team_comp_df, x="Team", y=["Breached", "Approaching"],
                  title="SLA Status by Team", barmode="group",
                  color_discrete_map={"Breached": "#dc2626", "Approaching": "#f59e0b"})
    fig2.update_layout(height=350, xaxis_tickangle=-45)
    st.plotly_chart(fig2, use_container_width=True)
else:
    st.success("All teams within SLA compliance.")

# ── Manual Notification Trigger ─────────────────────────
st.divider()
st.header("Send Notifications")

col_t, col_e = st.columns(2)

with col_t:
    st.subheader("Microsoft Teams")
    if st.button("Send SLA Alert to Teams", type="primary",
                 disabled=not TEAMS_WEBHOOK_URL):
        result = send_teams_sla_alert(alerts)
        if result:
            st.success("Teams alert sent successfully.")
        else:
            st.error("Failed to send Teams alert. Check webhook URL.")

    if st.button("Send Test Message to Teams", disabled=not TEAMS_WEBHOOK_URL):
        result = send_teams_notification(
            "Test Alert",
            "This is a test notification from VPRP.",
            color="3B82F6",
            facts=[{"name": "Status", "value": "Test successful"}],
        )
        if result:
            st.success("Test message sent to Teams.")
        else:
            st.error("Test failed. Verify TEAMS_WEBHOOK_URL.")

with col_e:
    st.subheader("Email")
    email_override = st.text_input("Override recipients (comma-separated)", key="email_override")

    if st.button("Send SLA Alert Email", type="primary", disabled=not SMTP_HOST):
        recip = [r.strip() for r in email_override.split(",") if r.strip()] if email_override else None
        result = send_email_sla_alert(alerts, recipients=recip)
        if result:
            st.success("Email alert sent.")
        else:
            st.error("Failed to send email. Check SMTP settings.")

    if st.button("Send Test Email", disabled=not SMTP_HOST):
        recip = [r.strip() for r in email_override.split(",") if r.strip()] if email_override else None
        result = send_email(
            "Test Alert",
            "<h2>VPRP Test</h2><p>This is a test notification.</p>",
            recipients=recip,
        )
        if result:
            st.success("Test email sent.")
        else:
            st.error("Test failed. Check SMTP config.")

# ── Run Full SLA Check ──────────────────────────────────
st.divider()
with st.expander("Run Full SLA Check & Notify"):
    st.caption("This runs the complete SLA analysis and sends alerts via all configured channels.")
    if st.button("Run SLA Check Now"):
        with st.spinner("Running SLA check..."):
            results = run_sla_check_and_notify()
        st.json(results)

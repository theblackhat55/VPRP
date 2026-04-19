"""
VPRP — Remediation Tracking Dashboard
Manage vulnerability remediation lifecycle: status updates, exceptions, audit trail.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from app.models.remediation_service import (
    get_findings_for_remediation,
    update_finding_status,
    bulk_update_status,
    request_exception,
    approve_exception,
    deny_exception,
    get_remediation_summary,
    get_audit_log,
    check_expired_exceptions,
    VALID_STATUSES,
    VALID_SUBSTATUSES,
    VALID_TRANSITIONS,
)

st.set_page_config(page_title="VPRP — Remediation", page_icon="🔧", layout="wide")
st.title("🔧 Remediation Tracking")

from app.utils.auth_guard import require_login, show_user_sidebar
current_user = require_login()
show_user_sidebar()

# ── Auto-check expired exceptions on page load ──────────
expired_count = check_expired_exceptions()
if expired_count > 0:
    st.warning(f"Auto-reopened {expired_count} finding(s) with expired exceptions.")

# ── KPI Summary ─────────────────────────────────────────
summary = get_remediation_summary()

if summary["total_findings"] == 0:
    st.info("No findings in database. Upload a scan on the main page first.")
    st.stop()

st.header("Remediation Overview")
k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Total Findings", f"{summary['total_findings']:,}")
k2.metric("Open", f"{summary['open_count']:,}",
          delta=f"{summary['sla_breached_active']} SLA breached" if summary['sla_breached_active'] > 0 else None,
          delta_color="inverse")
k3.metric("In Progress", f"{summary['in_progress_count']:,}")
k4.metric("Remediated", f"{summary['remediated_count']:,}")
k5.metric("Remediation Rate", f"{summary['remediation_rate']}%")
k6.metric("Pending Exceptions", f"{summary['pending_exceptions']:,}")

# ── Status Distribution Charts ──────────────────────────
st.divider()
ch1, ch2 = st.columns(2)

with ch1:
    status_df = pd.DataFrame(
        list(summary["status_counts"].items()),
        columns=["Status", "Count"],
    )
    if not status_df.empty:
        color_map = {
            "open": "#ef4444", "in_progress": "#f59e0b", "remediated": "#22c55e",
            "accepted_risk": "#6366f1", "exception": "#a855f7", "false_positive": "#64748b",
        }
        fig = px.pie(status_df, names="Status", values="Count",
                     title="Findings by Remediation Status",
                     color="Status", color_discrete_map=color_map)
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)

with ch2:
    if summary["team_status"]:
        team_rows = [{"Team": t, "Status": s, "Count": c} for t, s, c in summary["team_status"]]
        team_df = pd.DataFrame(team_rows)
        fig2 = px.bar(team_df, x="Team", y="Count", color="Status",
                      title="Remediation Status by Team",
                      color_discrete_map=color_map, barmode="stack")
        fig2.update_layout(height=350, xaxis_tickangle=-45)
        st.plotly_chart(fig2, use_container_width=True)

# ── Filters ─────────────────────────────────────────────
st.divider()
st.header("Findings")

fc1, fc2, fc3, fc4, fc5 = st.columns(5)
with fc1:
    filter_status = st.multiselect("Status", VALID_STATUSES, default=["open", "in_progress"])
with fc2:
    all_teams = sorted(set(t for t, _, _ in summary["team_status"])) if summary["team_status"] else []
    filter_team = st.multiselect("Team", all_teams)
with fc3:
    filter_severity = st.multiselect("Severity", ["critical", "high", "medium", "low"])
with fc4:
    filter_sla = st.checkbox("SLA Breached Only")
with fc5:
    filter_cve = st.text_input("Search CVE")

# ── Load Findings ───────────────────────────────────────
findings_df = get_findings_for_remediation(
    status_filter=filter_status or None,
    team_filter=filter_team or None,
    severity_filter=filter_severity or None,
    sla_breached_only=filter_sla,
    search_cve=filter_cve or None,
)

if findings_df.empty:
    st.info("No findings match the selected filters.")
    st.stop()

st.caption(f"Showing {len(findings_df)} findings")

# ── Bulk Actions ────────────────────────────────────────
with st.expander("Bulk Status Update", expanded=False):
    st.caption("Select findings below, then apply a bulk status change.")
    bc1, bc2, bc3 = st.columns(3)
    with bc1:
        bulk_status = st.selectbox("New Status", VALID_STATUSES, key="bulk_status")
    with bc2:
        bulk_substatus = st.selectbox(
            "Substatus",
            ["(none)"] + VALID_SUBSTATUSES.get(bulk_status, []),
            key="bulk_sub",
        )
    with bc3:
        bulk_notes = st.text_input("Notes", key="bulk_notes")
    bulk_by = st.text_input("Performed by", value="admin", key="bulk_by")

# ── Findings Table ──────────────────────────────────────
display_cols = [
    "cve_id", "vulnerability_severity", "risk_score", "device_name",
    "assigned_team", "remediation_status", "remediation_substatus",
    "sla_breached", "assigned_to", "ticket_id",
]
available_cols = [c for c in display_cols if c in findings_df.columns]

edited_df = st.data_editor(
    findings_df[["id"] + available_cols],
    column_config={
        "id": st.column_config.CheckboxColumn("Select", default=False)
        if False else st.column_config.TextColumn("ID", width="small"),
        "risk_score": st.column_config.NumberColumn("Risk", format="%.1f"),
        "sla_breached": st.column_config.CheckboxColumn("SLA Breached", disabled=True),
    },
    use_container_width=True,
    hide_index=True,
    key="findings_table",
)

# ── Apply Bulk Update ───────────────────────────────────
selected_ids = st.multiselect(
    "Select Finding IDs for bulk action",
    findings_df["id"].tolist(),
    key="selected_findings",
)

if st.button("Apply Bulk Status Update", type="primary", disabled=len(selected_ids) == 0):
    sub = bulk_substatus if bulk_substatus != "(none)" else None
    count = bulk_update_status(
        selected_ids, bulk_status, sub, bulk_notes or None, bulk_by,
    )
    st.success(f"Updated {count} of {len(selected_ids)} findings to '{bulk_status}'.")
    st.rerun()

# ── Single Finding Detail ───────────────────────────────
st.divider()
st.header("Finding Detail & Actions")

selected_finding = st.selectbox(
    "Select a finding",
    findings_df["id"].tolist(),
    format_func=lambda x: f"{findings_df[findings_df['id']==x]['cve_id'].iloc[0]} — "
                          f"{findings_df[findings_df['id']==x]['device_name'].iloc[0]}",
    key="detail_select",
)

if selected_finding:
    row = findings_df[findings_df["id"] == selected_finding].iloc[0]

    d1, d2, d3, d4 = st.columns(4)
    d1.metric("CVE", row["cve_id"])
    d2.metric("Risk Score", f"{row['risk_score']:.1f}")
    d3.metric("Status", row["remediation_status"])
    d4.metric("SLA Breached", "Yes" if row["sla_breached"] else "No")

    st.markdown(f"**Device:** {row['device_name']} | **Team:** {row['assigned_team']} | "
                f"**Severity:** {row['vulnerability_severity']} | **CVSS:** {row.get('cvss_score', 'N/A')}")

    # ── Status Update Form ──
    with st.form("status_update_form"):
        st.subheader("Update Status")
        current = row["remediation_status"]
        allowed = VALID_TRANSITIONS.get(current, [])
        uf1, uf2 = st.columns(2)
        with uf1:
            new_status = st.selectbox("New Status", [current] + allowed)
        with uf2:
            new_sub = st.selectbox("Substatus", ["(none)"] + VALID_SUBSTATUSES.get(new_status, []))

        uf3, uf4 = st.columns(2)
        with uf3:
            update_notes = st.text_area("Notes")
        with uf4:
            update_by = st.text_input("Performed by", value="admin")
            update_assigned = st.text_input("Assign to", value=row.get("assigned_to") or "")
            update_ticket = st.text_input("Ticket ID", value=row.get("ticket_id") or "")

        if st.form_submit_button("Update Finding", type="primary"):
            success = update_finding_status(
                selected_finding, new_status,
                substatus=new_sub if new_sub != "(none)" else None,
                notes=update_notes or None,
                performed_by=update_by,
                assigned_to=update_assigned or None,
                ticket_id=update_ticket or None,
            )
            if success:
                st.success(f"Status updated: {current} → {new_status}")
                st.rerun()
            else:
                st.error("Update failed. Check logs.")

    # ── Exception Request Form ──
    if current in ["open", "in_progress"]:
        with st.expander("Request Exception / Risk Acceptance"):
            with st.form("exception_form"):
                exc_reason = st.text_area("Business justification")
                exc_by = st.text_input("Requested by", value="admin", key="exc_by")
                exc_days = st.number_input("Exception duration (days)", min_value=7, max_value=365, value=90)

                if st.form_submit_button("Submit Exception Request"):
                    if exc_reason:
                        ok = request_exception(selected_finding, exc_reason, exc_by, exc_days)
                        if ok:
                            st.success("Exception request submitted for approval.")
                            st.rerun()
                        else:
                            st.error("Request failed.")
                    else:
                        st.warning("Please provide a business justification.")

    # ── Exception Approval (for pending items) ──
    if row.get("exception_status") == "pending_approval":
        st.warning("This finding has a pending exception request.")
        ac1, ac2 = st.columns(2)
        with ac1:
            approve_by = st.text_input("Approver name", key="approve_by")
            if st.button("Approve Exception", type="primary"):
                if approve_by:
                    approve_exception(selected_finding, approve_by)
                    st.success("Exception approved.")
                    st.rerun()
        with ac2:
            deny_notes = st.text_input("Denial reason", key="deny_notes")
            if st.button("Deny Exception"):
                deny_exception(selected_finding, approve_by or "admin", deny_notes)
                st.info("Exception denied. Finding reopened.")
                st.rerun()

    # ── Audit Trail ──
    st.subheader("Audit Trail")
    audit_df = get_audit_log(finding_id=selected_finding, limit=20)
    if not audit_df.empty:
        st.dataframe(
            audit_df[["performed_at", "action", "old_status", "new_status", "notes", "performed_by"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("No audit entries yet.")

# ── Global Audit Log ────────────────────────────────────
st.divider()
with st.expander("Global Audit Log (recent 50)"):
    global_audit = get_audit_log(limit=50)
    if not global_audit.empty:
        st.dataframe(global_audit, use_container_width=True, hide_index=True)
    else:
        st.caption("No audit entries.")

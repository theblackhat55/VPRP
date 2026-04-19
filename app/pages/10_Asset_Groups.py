"""VPRP — Asset Groups Management"""
import streamlit as st
import pandas as pd
import plotly.express as px
import json
from datetime import datetime, timezone

st.set_page_config(page_title="Asset Groups", page_icon="🏢", layout="wide")

from app.utils.auth_guard import require_auth, show_user_sidebar, is_authenticated, HIDE_SIDEBAR_CSS, get_current_user
if not is_authenticated():
    st.markdown(HIDE_SIDEBAR_CSS, unsafe_allow_html=True)
require_auth()
st.session_state["_page_id"] = "asset_groups"
show_user_sidebar()

st.title("🏢 Asset Groups Management")
st.caption("Organize devices into logical groups by application, service, team, or location")

from app.models.database import SessionLocal
from app.models.schemas import Finding, AssetGroup
from app.engine.asset_groups import (
    load_asset_groups, save_asset_groups,
    create_asset_group, update_asset_group, delete_asset_group,
    apply_asset_groups, get_group_vulnerability_summary,
)
import logging

log = logging.getLogger(__name__)
user = get_current_user() or {}


# ── DB-backed group CRUD ──
def load_groups_from_db() -> list:
    session = SessionLocal()
    try:
        groups = session.query(AssetGroup).filter(AssetGroup.is_active == True).all()
        result = []
        for g in groups:
            result.append({
                "id": g.id,
                "name": g.name,
                "description": g.description or "",
                "group_type": g.group_type,
                "match_patterns": json.loads(g.match_patterns) if g.match_patterns else [],
                "criticality": g.criticality,
                "owner": g.owner or "",
                "team": g.team or "",
                "created_at": str(g.created_at) if g.created_at else "",
                "created_by": g.created_by or "system",
            })
        return result
    finally:
        session.close()


def save_group_to_db(group_data: dict):
    session = SessionLocal()
    try:
        existing = session.query(AssetGroup).filter(AssetGroup.id == group_data["id"]).first()
        if existing:
            existing.name = group_data["name"]
            existing.description = group_data.get("description", "")
            existing.group_type = group_data.get("group_type", "custom")
            existing.match_patterns = json.dumps(group_data.get("match_patterns", []))
            existing.criticality = group_data.get("criticality", "medium")
            existing.owner = group_data.get("owner", "")
            existing.team = group_data.get("team", "")
            existing.updated_at = datetime.now(timezone.utc)
        else:
            new_group = AssetGroup(
                id=group_data["id"],
                name=group_data["name"],
                description=group_data.get("description", ""),
                group_type=group_data.get("group_type", "custom"),
                match_patterns=json.dumps(group_data.get("match_patterns", [])),
                criticality=group_data.get("criticality", "medium"),
                owner=group_data.get("owner", ""),
                team=group_data.get("team", ""),
                created_by=user.get("username", "system"),
            )
            session.add(new_group)
        session.commit()
    except Exception as e:
        session.rollback()
        log.error(f"save_group_to_db error: {e}")
        raise
    finally:
        session.close()


def delete_group_from_db(group_id: str):
    session = SessionLocal()
    try:
        group = session.query(AssetGroup).filter(AssetGroup.id == group_id).first()
        if group:
            group.is_active = False
            session.commit()
            return True
        return False
    finally:
        session.close()


def save_asset_group_assignments(df: pd.DataFrame):
    """Persist asset_group columns to findings."""
    session = SessionLocal()
    try:
        cols = ["asset_group_id", "asset_group_name", "asset_group_criticality"]
        updated = 0
        for _, row in df.iterrows():
            finding = session.query(Finding).filter(Finding.id == row["id"]).first()
            if finding:
                for col in cols:
                    if col in row and pd.notna(row[col]):
                        setattr(finding, col, str(row[col]))
                updated += 1
        session.commit()
        return updated
    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()


@st.cache_data(ttl=120)
def load_findings() -> pd.DataFrame:
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


# ═════════════════════════════════════════════════════════
# TABS
# ═════════════════════════════════════════════════════════
tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Manage Groups", "🔗 Assign Devices",
    "📊 Group Analytics", "⚙️ Import/Export",
])

# ══════════════════════════════════════════════════════════
# TAB 1: Manage Groups
# ══════════════════════════════════════════════════════════
with tab1:
    st.subheader("Asset Group Definitions")

    groups = load_groups_from_db()

    # ── Create New Group ──
    with st.expander("➕ Create New Asset Group", expanded=False):
        with st.form("create_group_form", clear_on_submit=True):
            cg1, cg2 = st.columns(2)
            with cg1:
                new_name = st.text_input("Group Name *", placeholder="e.g., Production Web Servers")
                new_type = st.selectbox("Group Type", ["application", "service", "team", "location", "environment", "custom"])
                new_crit = st.selectbox("Criticality", ["critical", "high", "medium", "low"])
            with cg2:
                new_desc = st.text_area("Description", placeholder="What does this group represent?")
                new_owner = st.text_input("Owner", placeholder="e.g., John Smith")
                new_team = st.text_input("Team", placeholder="e.g., Platform Engineering")

            new_patterns = st.text_input(
                "Match Patterns (comma-separated)",
                placeholder="e.g., web-prod-*, srv-prod-*, app-frontend-*",
                help="Wildcard patterns to auto-match device names. Use * as wildcard.",
            )

            submitted = st.form_submit_button("Create Group", type="primary", use_container_width=True)

            if submitted and new_name:
                import uuid
                group_id = str(uuid.uuid4())[:8]
                patterns = [p.strip() for p in new_patterns.split(",") if p.strip()] if new_patterns else []
                group_data = {
                    "id": group_id,
                    "name": new_name,
                    "description": new_desc,
                    "group_type": new_type,
                    "match_patterns": patterns,
                    "criticality": new_crit,
                    "owner": new_owner,
                    "team": new_team,
                }
                try:
                    save_group_to_db(group_data)
                    # Also save to JSON for engine compatibility
                    groups.append(group_data)
                    save_asset_groups(groups)
                    st.success(f"Created group **{new_name}** (ID: {group_id})")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error creating group: {e}")
            elif submitted:
                st.warning("Group name is required.")

    # ── List Existing Groups ──
    if groups:
        st.markdown(f"**{len(groups)} active groups**")
        for g in groups:
            with st.expander(f"{'🔴' if g.get('criticality') == 'critical' else '🟠' if g.get('criticality') == 'high' else '🟡' if g.get('criticality') == 'medium' else '🟢'} {g['name']} — {g.get('group_type', 'custom')} ({g.get('criticality', 'medium')})", expanded=False):
                gc1, gc2 = st.columns(2)
                with gc1:
                    st.markdown(f"**ID:** `{g['id']}`")
                    st.markdown(f"**Type:** {g.get('group_type', 'custom')}")
                    st.markdown(f"**Criticality:** {g.get('criticality', 'medium')}")
                    st.markdown(f"**Owner:** {g.get('owner', 'N/A')}")
                with gc2:
                    st.markdown(f"**Team:** {g.get('team', 'N/A')}")
                    st.markdown(f"**Description:** {g.get('description', 'N/A')}")
                    patterns = g.get("match_patterns", [])
                    st.markdown(f"**Match Patterns:** `{', '.join(patterns) if patterns else 'None'}`")
                    st.markdown(f"**Created by:** {g.get('created_by', 'system')}")

                # Delete button
                if st.button(f"🗑️ Delete {g['name']}", key=f"del_{g['id']}"):
                    delete_group_from_db(g["id"])
                    updated_groups = [gx for gx in groups if gx["id"] != g["id"]]
                    save_asset_groups(updated_groups)
                    st.success(f"Deleted group **{g['name']}**")
                    st.rerun()
    else:
        st.info("No asset groups defined. Create one above.")

# ══════════════════════════════════════════════════════════
# TAB 2: Assign Devices
# ══════════════════════════════════════════════════════════
with tab2:
    st.subheader("Auto-Assign Devices to Groups")

    groups = load_groups_from_db()
    df = load_findings()

    if df.empty:
        st.warning("No findings available.")
    elif not groups:
        st.warning("No asset groups defined. Create groups first.")
    else:
        ac1, ac2 = st.columns([3, 5])
        with ac1:
            if st.button("🔄 Run Auto-Assignment", type="primary", use_container_width=True):
                with st.spinner("Matching devices to groups..."):
                    # Save groups to JSON for engine compatibility
                    save_asset_groups(groups)
                    df = apply_asset_groups(df)
                    saved = save_asset_group_assignments(df)
                    st.cache_data.clear()
                st.success(f"Assigned groups to {saved} findings based on pattern matching.")
                st.rerun()
        with ac2:
            st.info("Auto-assignment matches device names against group patterns using wildcards.")

        st.divider()

        # Show current assignments
        if "asset_group_name" in df.columns and df["asset_group_name"].notna().any():
            assigned = df[df["asset_group_name"].notna()]
            unassigned = df[df["asset_group_name"].isna()]

            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Assigned Findings", len(assigned))
            with m2:
                st.metric("Unassigned Findings", len(unassigned))
            with m3:
                pct = (len(assigned) / len(df) * 100) if len(df) > 0 else 0
                st.metric("Coverage", f"{pct:.0f}%")

            # Assignment summary
            asg = assigned.groupby("asset_group_name").agg(
                findings=("id", "count"),
                devices=("device_name", "nunique"),
                criticality=("asset_group_criticality", "first"),
            ).reset_index().sort_values("findings", ascending=False)

            st.dataframe(asg, use_container_width=True)

            # Unassigned devices
            if not unassigned.empty:
                st.markdown("### Unassigned Devices")
                unassigned_devices = unassigned["device_name"].unique()
                st.markdown(f"**{len(unassigned_devices)} devices** not matching any group pattern:")
                st.code("\n".join(sorted(unassigned_devices)[:20]))
        else:
            st.info("No device assignments yet. Click **Run Auto-Assignment** above.")

        # Manual assignment
        st.divider()
        st.markdown("### Manual Assignment")
        with st.form("manual_assign_form"):
            devices_list = sorted(df["device_name"].dropna().unique().tolist()) if "device_name" in df.columns else []
            group_names = {g["name"]: g for g in groups}

            selected_devices = st.multiselect("Select Devices", devices_list, key="manual_devices")
            selected_group = st.selectbox("Assign to Group", list(group_names.keys()), key="manual_group")

            if st.form_submit_button("Assign", type="primary"):
                if selected_devices and selected_group:
                    session = SessionLocal()
                    try:
                        g = group_names[selected_group]
                        count = 0
                        for dev in selected_devices:
                            findings = session.query(Finding).filter(Finding.device_name == dev).all()
                            for f in findings:
                                f.asset_group_id = g["id"]
                                f.asset_group_name = g["name"]
                                f.asset_group_criticality = g.get("criticality", "medium")
                                count += 1
                        session.commit()
                        st.cache_data.clear()
                        st.success(f"Assigned {count} findings on {len(selected_devices)} devices to **{selected_group}**")
                        st.rerun()
                    except Exception as e:
                        session.rollback()
                        st.error(f"Error: {e}")
                    finally:
                        session.close()
                else:
                    st.warning("Select at least one device and a group.")

# ══════════════════════════════════════════════════════════
# TAB 3: Group Analytics
# ══════════════════════════════════════════════════════════
with tab3:
    st.subheader("Group Vulnerability Analytics")

    df = load_findings()

    if df.empty or "asset_group_name" not in df.columns or not df["asset_group_name"].notna().any():
        st.info("No group assignments found. Assign devices to groups first.")
    else:
        assigned_df = df[df["asset_group_name"].notna()]

        # Group summary
        grp_summary = assigned_df.groupby(["asset_group_name", "asset_group_criticality"]).agg(
            total_findings=("id", "count"),
            critical_findings=("vulnerability_severity", lambda x: (x == "Critical").sum()),
            high_findings=("vulnerability_severity", lambda x: (x == "High").sum()),
            devices=("device_name", "nunique"),
            unique_cves=("cve_id", "nunique"),
            avg_cvss=("cvss_score", "mean"),
            max_cvss=("cvss_score", "max"),
        ).reset_index().sort_values("total_findings", ascending=False)

        # KPIs
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.metric("Active Groups", grp_summary["asset_group_name"].nunique())
        with k2:
            st.metric("Total Grouped Findings", assigned_df.shape[0])
        with k3:
            crit_groups = grp_summary[grp_summary["asset_group_criticality"] == "critical"]
            st.metric("Critical Groups", len(crit_groups))
        with k4:
            avg_cvss_all = assigned_df["cvss_score"].mean() if "cvss_score" in assigned_df.columns else 0
            st.metric("Avg CVSS (Grouped)", f"{avg_cvss_all:.1f}")

        st.divider()

        # Chart: findings by group (stacked by severity)
        if "vulnerability_severity" in assigned_df.columns:
            sev_by_group = assigned_df.groupby(["asset_group_name", "vulnerability_severity"]).size().reset_index(name="count")
            sev_colors = {"Critical": "#d32f2f", "High": "#f57c00", "Medium": "#fbc02d", "Low": "#388e3c"}
            fig_sev = px.bar(
                sev_by_group, x="asset_group_name", y="count",
                color="vulnerability_severity",
                color_discrete_map=sev_colors,
                category_orders={"vulnerability_severity": ["Critical", "High", "Medium", "Low"]},
                barmode="stack", text_auto=True,
            )
            fig_sev.update_layout(
                xaxis_title="Asset Group", yaxis_title="Findings",
                xaxis_tickangle=-45, margin=dict(t=20, b=100), height=450,
            )
            st.plotly_chart(fig_sev, use_container_width=True)

        # Chart: group criticality vs avg CVSS
        if not grp_summary.empty:
            fig_bubble = px.scatter(
                grp_summary, x="total_findings", y="avg_cvss",
                size="devices", color="asset_group_criticality",
                color_discrete_map={"critical": "#d32f2f", "high": "#f57c00", "medium": "#fbc02d", "low": "#388e3c"},
                hover_name="asset_group_name",
                text="asset_group_name",
            )
            fig_bubble.update_layout(
                xaxis_title="Total Findings", yaxis_title="Average CVSS",
                margin=dict(t=20, b=20), height=400,
            )
            fig_bubble.update_traces(textposition="top center")
            st.plotly_chart(fig_bubble, use_container_width=True)

        # SSVC priority by group
        if "ssvc_priority" in assigned_df.columns and assigned_df["ssvc_priority"].notna().any():
            st.divider()
            st.markdown("### SSVC Priority by Asset Group")
            ssvc_grp = assigned_df.groupby(["asset_group_name", "ssvc_priority"]).size().reset_index(name="count")
            pri_colors = {"Immediate": "#d32f2f", "Out-of-Cycle": "#f57c00", "Scheduled": "#fbc02d", "Defer": "#388e3c"}
            fig_ssvc_grp = px.bar(
                ssvc_grp, x="asset_group_name", y="count",
                color="ssvc_priority", color_discrete_map=pri_colors,
                category_orders={"ssvc_priority": ["Immediate", "Out-of-Cycle", "Scheduled", "Defer"]},
                barmode="stack", text_auto=True,
            )
            fig_ssvc_grp.update_layout(
                xaxis_title="Asset Group", yaxis_title="Findings",
                xaxis_tickangle=-45, margin=dict(t=20, b=100), height=400,
            )
            st.plotly_chart(fig_ssvc_grp, use_container_width=True)

        # Detail table
        st.divider()
        st.markdown("### Detailed Group Summary")
        st.dataframe(grp_summary, use_container_width=True, height=400)

# ══════════════════════════════════════════════════════════
# TAB 4: Import / Export
# ══════════════════════════════════════════════════════════
with tab4:
    st.subheader("Import / Export Asset Groups")

    ie1, ie2 = st.columns(2)

    with ie1:
        st.markdown("### 📥 Export")
        groups = load_groups_from_db()
        if groups:
            export_json = json.dumps(groups, indent=2, default=str)
            st.download_button(
                "Download Asset Groups (JSON)",
                export_json,
                file_name=f"asset_groups_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True,
            )
            st.code(export_json[:500] + ("..." if len(export_json) > 500 else ""), language="json")
        else:
            st.info("No groups to export.")

    with ie2:
        st.markdown("### 📤 Import")
        uploaded = st.file_uploader("Upload Asset Groups JSON", type=["json"], key="import_groups")
        if uploaded:
            try:
                import_data = json.loads(uploaded.read())
                if isinstance(import_data, list):
                    st.json(import_data[:3])
                    if st.button("Confirm Import", type="primary"):
                        for g in import_data:
                            if "id" in g and "name" in g:
                                save_group_to_db(g)
                        save_asset_groups(import_data)
                        st.success(f"Imported {len(import_data)} groups.")
                        st.rerun()
                else:
                    st.error("JSON must be an array of group objects.")
            except Exception as e:
                st.error(f"Invalid JSON: {e}")

    st.divider()

    # Template
    st.markdown("### 📝 Template")
    template = [
        {
            "id": "example-01",
            "name": "Production Web Servers",
            "description": "All customer-facing web servers",
            "group_type": "application",
            "match_patterns": ["web-prod-*", "srv-www-*"],
            "criticality": "critical",
            "owner": "Jane Doe",
            "team": "Platform Engineering",
        }
    ]
    st.download_button(
        "Download Template (JSON)",
        json.dumps(template, indent=2),
        file_name="asset_groups_template.json",
        mime="application/json",
        use_container_width=True,
    )

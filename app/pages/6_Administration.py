"""VPRP — Administration (Settings, Users, Asset Groups, SLA)"""
import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime, timezone
from pathlib import Path

st.set_page_config(page_title="Administration", page_icon="⚙️", layout="wide")

from app.utils.auth_guard import require_auth, show_user_sidebar, is_authenticated, HIDE_SIDEBAR_CSS, get_current_user, require_role
if not is_authenticated():
    st.markdown(HIDE_SIDEBAR_CSS, unsafe_allow_html=True)
require_auth()
st.session_state["_page_id"] = "admin"
show_user_sidebar()

st.title("⚙️ Administration")
st.caption("Platform settings, user management, asset groups, and SLA monitoring")

user = get_current_user() or {}
user_role = user.get("role", "viewer")

# ═══════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════
tab_list = ["🔧 Settings", "👥 User Management", "🏢 Asset Groups", "⏰ SLA Monitor"]
tab_settings, tab_users, tab_groups, tab_sla = st.tabs(tab_list)

# ═══════════════════════════════════════════════════════════
# TAB 1 — SETTINGS
# ═══════════════════════════════════════════════════════════
with tab_settings:
    st.subheader("Platform Settings")

    s1, s2 = st.columns(2)

    with s1:
        st.markdown("### Branding")
        logo_path = Path("/data/branding/logo.png")

        if logo_path.exists():
            st.image(str(logo_path), width=200)
            if st.button("🗑️ Remove Logo", key="remove_logo"):
                logo_path.unlink()
                st.success("Logo removed.")
                st.rerun()

        uploaded_logo = st.file_uploader("Upload Logo (PNG/JPG)", type=["png", "jpg", "jpeg"], key="logo_upload")
        if uploaded_logo:
            logo_path.parent.mkdir(parents=True, exist_ok=True)
            with open(str(logo_path), "wb") as f:
                f.write(uploaded_logo.getvalue())
            st.success("Logo uploaded!")
            st.rerun()

        # Favicon
        favicon_path = Path("/data/branding/favicon.ico")
        uploaded_favicon = st.file_uploader("Upload Favicon (ICO/PNG)", type=["ico", "png"], key="favicon_upload")
        if uploaded_favicon:
            favicon_path.parent.mkdir(parents=True, exist_ok=True)
            with open(str(favicon_path), "wb") as f:
                f.write(uploaded_favicon.getvalue())
            st.success("Favicon uploaded!")
            st.rerun()

    with s2:
        st.markdown("### Platform Info")
        st.markdown(f"**Version:** 1.0.0")
        st.markdown(f"**Environment:** Production")
        st.markdown(f"**Server Time:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

        st.markdown("### Database Statistics")
        try:
            from app.models.database import SessionLocal
            from app.models.schemas import Finding, Asset, ScanUpload, User
            session = SessionLocal()
            st.markdown(f"- **Findings:** {session.query(Finding).count()}")
            st.markdown(f"- **Assets:** {session.query(Asset).count()}")
            st.markdown(f"- **Scan Uploads:** {session.query(ScanUpload).count()}")
            st.markdown(f"- **Users:** {session.query(User).count()}")
            session.close()
        except Exception as e:
            st.error(f"DB error: {e}")

    st.divider()

    st.markdown("### Notification Configuration")
    nc1, nc2 = st.columns(2)
    with nc1:
        teams_url = os.environ.get("TEAMS_WEBHOOK_URL", "")
        st.markdown(f"**Teams Webhook:** {'✅ Configured' if teams_url else '❌ Not set'}")
    with nc2:
        smtp_host = os.environ.get("SMTP_HOST", "")
        st.markdown(f"**SMTP:** {'✅ Configured' if smtp_host else '❌ Not set'}")

    st.divider()

    st.markdown("### Data Management")
    dm1, dm2 = st.columns(2)
    with dm1:
        if st.button("🗑️ Clear Cache", use_container_width=True):
            st.cache_data.clear()
            st.success("Cache cleared.")
    with dm2:
        # Storage info
        data_path = Path("/data")
        if data_path.exists():
            total_size = sum(f.stat().st_size for f in data_path.rglob("*") if f.is_file())
            st.metric("Storage Used", f"{total_size / 1024 / 1024:.1f} MB")

# ═══════════════════════════════════════════════════════════
# TAB 2 — USER MANAGEMENT
# ═══════════════════════════════════════════════════════════
with tab_users:
    if user_role not in ("admin",):
        st.warning("Admin access required for user management.")
        st.stop()

    st.subheader("User Management")

    try:
        from app.models.auth_service import (
            list_users, create_user, update_user,
            change_password, delete_user, ROLES,
        )
    except ImportError:
        st.error("Auth service not available.")
        st.stop()

    # ── Create User ──
    with st.expander("➕ Create New User", expanded=False):
        with st.form("create_user_form", clear_on_submit=True):
            cu1, cu2 = st.columns(2)
            with cu1:
                new_username = st.text_input("Username *")
                new_email = st.text_input("Email *")
                new_password = st.text_input("Password *", type="password")
            with cu2:
                new_fullname = st.text_input("Full Name")
                new_role = st.selectbox("Role", list(ROLES.keys()))
                new_team = st.text_input("Team")

            if st.form_submit_button("Create User", type="primary", use_container_width=True):
                if new_username and new_email and new_password:
                    try:
                        result = create_user(
                            username=new_username,
                            email=new_email,
                            password=new_password,
                            full_name=new_fullname,
                            role=new_role,
                            team=new_team,
                            created_by=user.get("username", "admin"),
                        )
                        if result:
                            st.success(f"User **{new_username}** created.")
                            st.rerun()
                        else:
                            st.error("Failed to create user (username or email may exist).")
                    except Exception as e:
                        st.error(f"Error: {e}")
                else:
                    st.warning("Username, email, and password are required.")

    # ── User List ──
    users = list_users(include_inactive=False)
    if users:
        st.markdown(f"**{len(users)} users**")
        for u in users:
            status_icon = "✅" if u.get("is_active", True) else "❌"
            with st.expander(f"{status_icon} {u['username']} — {u.get('role', 'viewer')} ({u.get('full_name', 'N/A')})", expanded=False):
                ue1, ue2 = st.columns(2)
                with ue1:
                    st.markdown(f"**Email:** {u.get('email', 'N/A')}")
                    st.markdown(f"**Role:** {u.get('role', 'viewer')}")
                    st.markdown(f"**Team:** {u.get('team', 'N/A')}")
                with ue2:
                    st.markdown(f"**Active:** {u.get('is_active', True)}")
                    st.markdown(f"**Created:** {u.get('created_at', 'N/A')}")
                    st.markdown(f"**Last Login:** {u.get('last_login_at', 'Never')}")

                if u["username"] != "admin":
                    bc1, bc2, bc3 = st.columns(3)
                    with bc1:
                        new_pw = st.text_input("New password", type="password", key=f"pw_{u['username']}")
                        if st.button("Reset Password", key=f"reset_{u['username']}"):
                            if new_pw:
                                change_password(str(u.get("id", "")), new_pw)
                                st.success("Password reset.")
                    with bc2:
                        if u.get("is_active", True):
                            if st.button("🚫 Deactivate", key=f"deact_{u['username']}"):
                                delete_user(str(u.get("id", "")))
                                st.success(f"User {u['username']} deactivated.")
                                st.rerun()
                    with bc3:
                        new_role = st.selectbox("Change role", list(ROLES.keys()),
                                                index=list(ROLES.keys()).index(u.get("role", "viewer")),
                                                key=f"role_{u['username']}")
                        if st.button("Update Role", key=f"urole_{u['username']}"):
                            update_user(str(u.get("id", "")), role=new_role)
                            st.success(f"Role updated to {new_role}.")
                            st.rerun()
    else:
        st.info("No users found.")

    # Role reference
    with st.expander("📖 Role Permissions", expanded=False):
        for role_name, role_info in ROLES.items():
            st.markdown(f"**{role_name}** (level {role_info.get('level', 0)}): {role_info.get('description', '')}")

# ═══════════════════════════════════════════════════════════
# TAB 3 — ASSET GROUPS
# ═══════════════════════════════════════════════════════════
with tab_groups:
    st.subheader("Asset Groups")

    from app.models.database import SessionLocal
    from app.models.schemas import Finding
    from app.engine.asset_groups import (
        load_asset_groups, save_asset_groups,
        apply_asset_groups, get_group_vulnerability_summary,
    )

    try:
        from app.models.schemas import AssetGroup
    except ImportError:
        st.error("AssetGroup model not available.")
        st.stop()

    def _load_groups_from_db():
        session = SessionLocal()
        try:
            groups = session.query(AssetGroup).filter(AssetGroup.is_active == True).all()
            result = []
            for g in groups:
                result.append({
                    "id": g.id, "name": g.name,
                    "description": g.description or "",
                    "group_type": g.group_type,
                    "match_patterns": json.loads(g.match_patterns) if g.match_patterns else [],
                    "criticality": g.criticality,
                    "owner": g.owner or "", "team": g.team or "",
                    "created_by": g.created_by or "system",
                })
            return result
        finally:
            session.close()

    def _save_group_to_db(gd):
        session = SessionLocal()
        try:
            existing = session.query(AssetGroup).filter(AssetGroup.id == gd["id"]).first()
            if existing:
                existing.name = gd["name"]
                existing.description = gd.get("description", "")
                existing.group_type = gd.get("group_type", "custom")
                existing.match_patterns = json.dumps(gd.get("match_patterns", []))
                existing.criticality = gd.get("criticality", "medium")
                existing.owner = gd.get("owner", "")
                existing.team = gd.get("team", "")
                existing.updated_at = datetime.now(timezone.utc)
            else:
                session.add(AssetGroup(
                    id=gd["id"], name=gd["name"],
                    description=gd.get("description", ""),
                    group_type=gd.get("group_type", "custom"),
                    match_patterns=json.dumps(gd.get("match_patterns", [])),
                    criticality=gd.get("criticality", "medium"),
                    owner=gd.get("owner", ""),
                    team=gd.get("team", ""),
                    created_by=user.get("username", "system"),
                ))
            session.commit()
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()

    def _delete_group(gid):
        session = SessionLocal()
        try:
            g = session.query(AssetGroup).filter(AssetGroup.id == gid).first()
            if g:
                g.is_active = False
                session.commit()
        finally:
            session.close()

    # Sub-tabs inside Asset Groups
    gt1, gt2, gt3 = st.tabs(["📋 Manage", "🔗 Assign Devices", "📊 Analytics"])

    with gt1:
        groups = _load_groups_from_db()

        with st.expander("➕ Create New Asset Group", expanded=False):
            with st.form("create_ag_form", clear_on_submit=True):
                ag1, ag2 = st.columns(2)
                with ag1:
                    ag_name = st.text_input("Group Name *", placeholder="e.g., Production Web Servers")
                    ag_type = st.selectbox("Type", ["application", "service", "team", "location", "environment", "custom"])
                    ag_crit = st.selectbox("Criticality", ["critical", "high", "medium", "low"])
                with ag2:
                    ag_desc = st.text_area("Description")
                    ag_owner = st.text_input("Owner")
                    ag_team = st.text_input("Team")
                ag_patterns = st.text_input("Match Patterns (comma-separated)", placeholder="web-prod-*, srv-www-*")

                if st.form_submit_button("Create", type="primary", use_container_width=True):
                    if ag_name:
                        import uuid
                        gid = str(uuid.uuid4())[:8]
                        patterns = [p.strip() for p in ag_patterns.split(",") if p.strip()] if ag_patterns else []
                        gd = {"id": gid, "name": ag_name, "description": ag_desc, "group_type": ag_type,
                              "match_patterns": patterns, "criticality": ag_crit, "owner": ag_owner, "team": ag_team}
                        _save_group_to_db(gd)
                        groups.append(gd)
                        save_asset_groups(groups)
                        st.success(f"Created **{ag_name}**")
                        st.rerun()

        if groups:
            st.markdown(f"**{len(groups)} active groups**")
            for g in groups:
                crit_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(g.get("criticality"), "⚪")
                with st.expander(f"{crit_icon} {g['name']} — {g.get('group_type')} ({g.get('criticality')})", expanded=False):
                    st.markdown(f"**ID:** `{g['id']}` | **Owner:** {g.get('owner', 'N/A')} | **Team:** {g.get('team', 'N/A')}")
                    st.markdown(f"**Patterns:** `{', '.join(g.get('match_patterns', [])) or 'None'}`")
                    st.markdown(f"**Description:** {g.get('description', 'N/A')}")
                    if st.button(f"🗑️ Delete", key=f"delag_{g['id']}"):
                        _delete_group(g["id"])
                        st.success(f"Deleted **{g['name']}**")
                        st.rerun()
        else:
            st.info("No asset groups. Create one above.")

    with gt2:
        groups = _load_groups_from_db()

        @st.cache_data(ttl=120)
        def _load_findings_ag():
            session = SessionLocal()
            try:
                rows = session.query(Finding).all()
                if not rows:
                    return pd.DataFrame()
                return pd.DataFrame([{c.name: getattr(r, c.name) for c in Finding.__table__.columns} for r in rows])
            finally:
                session.close()

        df_ag = _load_findings_ag()

        if df_ag.empty:
            st.warning("No findings.")
        elif not groups:
            st.warning("Create groups first.")
        else:
            if st.button("🔄 Run Auto-Assignment", type="primary", key="run_ag_assign"):
                with st.spinner("Matching..."):
                    save_asset_groups(groups)
                    df_ag = apply_asset_groups(df_ag)
                    session = SessionLocal()
                    try:
                        cnt = 0
                        for _, row in df_ag.iterrows():
                            f = session.query(Finding).filter(Finding.id == row["id"]).first()
                            if f:
                                for col in ["asset_group_id", "asset_group_name", "asset_group_criticality"]:
                                    if col in row and row[col] is not None:
                                        try:
                                            if not (isinstance(row[col], float) and pd.isna(row[col])):
                                                setattr(f, col, str(row[col]))
                                        except (ValueError, TypeError):
                                            pass
                                cnt += 1
                        session.commit()
                        st.cache_data.clear()
                    finally:
                        session.close()
                st.success(f"Assigned {cnt} findings.")
                st.rerun()

            if "asset_group_name" in df_ag.columns and df_ag["asset_group_name"].notna().any():
                assigned = df_ag[df_ag["asset_group_name"].notna()]
                unassigned = df_ag[df_ag["asset_group_name"].isna()]
                m1, m2, m3 = st.columns(3)
                with m1:
                    st.metric("Assigned", len(assigned))
                with m2:
                    st.metric("Unassigned", len(unassigned))
                with m3:
                    pct = len(assigned) / len(df_ag) * 100 if len(df_ag) > 0 else 0
                    st.metric("Coverage", f"{pct:.0f}%")

                asg = assigned.groupby("asset_group_name").agg(
                    findings=("id", "count"), devices=("device_name", "nunique"),
                ).reset_index().sort_values("findings", ascending=False)
                st.dataframe(asg, use_container_width=True)

    with gt3:
        @st.cache_data(ttl=120)
        def _load_findings_analytics():
            session = SessionLocal()
            try:
                rows = session.query(Finding).all()
                if not rows:
                    return pd.DataFrame()
                return pd.DataFrame([{c.name: getattr(r, c.name) for c in Finding.__table__.columns} for r in rows])
            finally:
                session.close()

        df_ga = _load_findings_analytics()
        if df_ga.empty or "asset_group_name" not in df_ga.columns or not df_ga["asset_group_name"].notna().any():
            st.info("No group assignments. Assign devices first.")
        else:
            import plotly.express as px
            assigned = df_ga[df_ga["asset_group_name"].notna()]
            grp_sum = assigned.groupby(["asset_group_name", "asset_group_criticality"]).agg(
                total=("id", "count"), devices=("device_name", "nunique"),
                avg_cvss=("cvss_score", "mean"),
            ).reset_index().sort_values("total", ascending=False)

            st.dataframe(grp_sum, use_container_width=True)

            if "vulnerability_severity" in assigned.columns:
                sev_grp = assigned.groupby(["asset_group_name", "vulnerability_severity"]).size().reset_index(name="count")
                fig = px.bar(sev_grp, x="asset_group_name", y="count", color="vulnerability_severity",
                             color_discrete_map={"Critical": "#d32f2f", "High": "#f57c00", "Medium": "#fbc02d", "Low": "#388e3c"},
                             barmode="stack", text_auto=True)
                fig.update_layout(xaxis_tickangle=-45, margin=dict(t=20, b=100), height=400)
                st.plotly_chart(fig, use_container_width=True)

# ═══════════════════════════════════════════════════════════
# TAB 4 — SLA MONITOR
# ═══════════════════════════════════════════════════════════
with tab_sla:
    st.subheader("SLA Monitoring")

    try:
        from app.models.notification_service import (
            get_sla_alerts, send_teams_sla_alert,
            send_email_sla_alert, run_sla_check_and_notify,
        )
        sla_available = True
    except ImportError:
        sla_available = False

    if not sla_available:
        st.warning("Notification service not available.")
        st.stop()

    # Config status
    sc1, sc2 = st.columns(2)
    with sc1:
        teams_ok = bool(os.environ.get("TEAMS_WEBHOOK_URL"))
        st.markdown(f"**Teams Webhook:** {'✅ Ready' if teams_ok else '❌ Not configured'}")
    with sc2:
        smtp_ok = bool(os.environ.get("SMTP_HOST"))
        st.markdown(f"**Email (SMTP):** {'✅ Ready' if smtp_ok else '❌ Not configured'}")

    st.divider()

    # SLA alerts
    try:
        alerts = get_sla_alerts()
        breached = alerts.get("breached", [])
        approaching = alerts.get("approaching", [])

        a1, a2 = st.columns(2)
        with a1:
            st.metric("🚨 SLA Breached", len(breached))
        with a2:
            st.metric("⚠️ Approaching SLA", len(approaching))

        if breached:
            st.markdown("### Breached Findings")
            st.dataframe(pd.DataFrame(breached), use_container_width=True, height=300)

        if approaching:
            st.markdown("### Approaching Deadline")
            st.dataframe(pd.DataFrame(approaching), use_container_width=True, height=300)

    except Exception as e:
        st.error(f"Error loading SLA data: {e}")

    st.divider()

    # Manual actions
    st.markdown("### Manual Actions")
    ma1, ma2, ma3 = st.columns(3)
    with ma1:
        if st.button("📤 Send Teams Alert", use_container_width=True, disabled=not teams_ok):
            try:
                result = send_teams_sla_alert()
                st.json(result)
            except Exception as e:
                st.error(f"Error: {e}")
    with ma2:
        if st.button("📧 Send Email Alert", use_container_width=True, disabled=not smtp_ok):
            try:
                result = send_email_sla_alert()
                st.json(result)
            except Exception as e:
                st.error(f"Error: {e}")
    with ma3:
        if st.button("🔄 Run Full SLA Check", use_container_width=True, type="primary"):
            with st.spinner("Running..."):
                try:
                    result = run_sla_check_and_notify()
                    st.json(result)
                except Exception as e:
                    st.error(f"Error: {e}")

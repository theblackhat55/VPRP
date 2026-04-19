"""VPRP — Vulnerability Correlation & Grouping"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="Correlation & Grouping", page_icon="🔗", layout="wide")

from app.utils.auth_guard import require_auth, show_user_sidebar, is_authenticated, HIDE_SIDEBAR_CSS
if not is_authenticated():
    st.markdown(HIDE_SIDEBAR_CSS, unsafe_allow_html=True)
require_auth()
st.session_state["_page_id"] = "correlation"
show_user_sidebar()

st.title("🔗 Vulnerability Correlation & Grouping")
st.caption("Identify related vulnerabilities — group by patch, software, device risk, and CVE blast radius")

from app.models.database import SessionLocal
from app.models.schemas import Finding
from app.engine.correlation import (
    group_by_patch, group_by_software, group_by_device_risk,
    group_by_cve_blast_radius, get_correlation_summary,
)
import logging

log = logging.getLogger(__name__)


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


def save_correlation_to_db(df: pd.DataFrame):
    """Persist correlation columns back to the database."""
    session = SessionLocal()
    try:
        corr_cols = ["patch_group", "software_group", "correlation_cluster"]
        updated = 0
        for _, row in df.iterrows():
            finding = session.query(Finding).filter(Finding.id == row["id"]).first()
            if finding:
                for col in corr_cols:
                    if col in row and pd.notna(row[col]):
                        setattr(finding, col, str(row[col]))
                updated += 1
        session.commit()
        return updated
    except Exception as e:
        session.rollback()
        log.error(f"save_correlation_to_db error: {e}")
        raise
    finally:
        session.close()


# ── Load data ──
df = load_findings()

if df.empty:
    st.warning("No findings in the database. Upload vulnerability data first.")
    st.stop()

# ── Run Correlation ──
ctrl1, ctrl2 = st.columns([3, 5])
with ctrl1:
    if st.button("🔄 Run Correlation Analysis", type="primary", use_container_width=True):
        with st.spinner("Analyzing correlations..."):
            df = group_by_patch(df)
            df = group_by_software(df)
            df_dev = group_by_device_risk(df)
            df_blast = group_by_cve_blast_radius(df)

            # Store patch_group and software_group as correlation_cluster
            if "patch_group" in df.columns:
                df["correlation_cluster"] = df.apply(
                    lambda r: f"patch:{r.get('patch_group', '')}" if pd.notna(r.get("patch_group")) else (
                        f"sw:{r.get('software_group', '')}" if pd.notna(r.get("software_group")) else None
                    ), axis=1
                )

            saved = save_correlation_to_db(df)
            st.cache_data.clear()
        st.success(f"Correlation analysis complete — {saved} findings updated.")
        st.rerun()
with ctrl2:
    st.info(
        "Correlation groups related findings by **common patch**, **shared software stack**, "
        "**device risk concentration**, and **CVE blast radius** to help you remediate efficiently."
    )

st.divider()

# ═════════════════════════════════════════════════════════
# TAB LAYOUT
# ═════════════════════════════════════════════════════════
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📦 Patch Groups", "🖥️ Software Groups",
    "⚠️ Device Risk", "💥 CVE Blast Radius", "📊 Summary",
])

# ── Tab 1: Patch Groups ──
with tab1:
    st.subheader("Patch-Based Grouping")
    st.markdown("Findings that share the same recommended security update — **one patch resolves multiple findings**.")

    df_patch = group_by_patch(df)

    if "patch_group" in df_patch.columns and df_patch["patch_group"].notna().any():
        patch_summary = df_patch.groupby("patch_group").agg(
            findings=("id", "count"),
            devices=("device_name", "nunique"),
            max_cvss=("cvss_score", "max"),
            cves=("cve_id", "nunique"),
        ).reset_index().sort_values("findings", ascending=False)

        k1, k2, k3 = st.columns(3)
        with k1:
            st.metric("Patch Groups", len(patch_summary))
        with k2:
            multi_finding = (patch_summary["findings"] > 1).sum()
            st.metric("Multi-Finding Patches", multi_finding)
        with k3:
            max_impact = patch_summary["findings"].max() if not patch_summary.empty else 0
            st.metric("Largest Group", f"{max_impact} findings")

        # Chart: top 15 patches by finding count
        top_patches = patch_summary.head(15)
        fig_patch = px.bar(
            top_patches, x="patch_group", y="findings",
            color="max_cvss", color_continuous_scale="YlOrRd",
            text_auto=True, hover_data=["devices", "cves"],
        )
        fig_patch.update_layout(
            xaxis_title="Patch / Security Update", yaxis_title="Findings Resolved",
            xaxis_tickangle=-45, margin=dict(t=20, b=100), height=450,
        )
        st.plotly_chart(fig_patch, use_container_width=True)

        # Detail table
        with st.expander("📋 Full Patch Group Details", expanded=False):
            st.dataframe(patch_summary, use_container_width=True, height=400)

        # Drill-down
        selected_patch = st.selectbox(
            "Drill into patch group",
            patch_summary["patch_group"].tolist(),
            key="patch_drill",
        )
        if selected_patch:
            drill = df_patch[df_patch["patch_group"] == selected_patch]
            drill_cols = [c for c in ["cve_id", "device_name", "cvss_score", "vulnerability_severity",
                                       "ssvc_priority", "remediation_status", "assigned_team"] if c in drill.columns]
            st.dataframe(drill[drill_cols], use_container_width=True)
    else:
        st.info("Run correlation analysis to see patch groups.")

# ── Tab 2: Software Groups ──
with tab2:
    st.subheader("Software-Based Grouping")
    st.markdown("Findings affecting the same vendor + product combination.")

    df_sw = group_by_software(df)

    if "software_group" in df_sw.columns and df_sw["software_group"].notna().any():
        sw_summary = df_sw.groupby("software_group").agg(
            findings=("id", "count"),
            devices=("device_name", "nunique"),
            max_cvss=("cvss_score", "max"),
            cves=("cve_id", "nunique"),
        ).reset_index().sort_values("findings", ascending=False)

        k1, k2, k3 = st.columns(3)
        with k1:
            st.metric("Software Groups", len(sw_summary))
        with k2:
            st.metric("Total CVEs", sw_summary["cves"].sum())
        with k3:
            st.metric("Most Affected Software", sw_summary.iloc[0]["software_group"] if not sw_summary.empty else "N/A")

        fig_sw = px.treemap(
            sw_summary.head(20),
            path=["software_group"],
            values="findings",
            color="max_cvss",
            color_continuous_scale="YlOrRd",
            hover_data=["devices", "cves"],
        )
        fig_sw.update_layout(margin=dict(t=20, b=20), height=450)
        st.plotly_chart(fig_sw, use_container_width=True)

        with st.expander("📋 Full Software Group Details", expanded=False):
            st.dataframe(sw_summary, use_container_width=True, height=400)

        selected_sw = st.selectbox(
            "Drill into software group",
            sw_summary["software_group"].tolist(),
            key="sw_drill",
        )
        if selected_sw:
            drill = df_sw[df_sw["software_group"] == selected_sw]
            drill_cols = [c for c in ["cve_id", "device_name", "cvss_score", "vulnerability_severity",
                                       "ssvc_priority", "remediation_status"] if c in drill.columns]
            st.dataframe(drill[drill_cols], use_container_width=True)
    else:
        st.info("Run correlation analysis to see software groups.")

# ── Tab 3: Device Risk ──
with tab3:
    st.subheader("Device Risk Concentration")
    st.markdown("Devices with the highest aggregate risk — prioritize these for maximum impact reduction.")

    df_dev = group_by_device_risk(df)

    if not df_dev.empty:
        k1, k2, k3 = st.columns(3)
        with k1:
            st.metric("Devices Analyzed", len(df_dev))
        with k2:
            high_risk = (df_dev["total_risk_score"].ge(df_dev["total_risk_score"].quantile(0.75))).sum() if len(df_dev) > 3 else 0
            st.metric("High-Risk Devices (P75+)", high_risk)
        with k3:
            st.metric("Top Device", df_dev.iloc[0]["device_name"] if not df_dev.empty else "N/A")

        fig_dev = px.bar(
            df_dev.head(20),
            x="device_name", y="total_risk_score",
            color="finding_count", color_continuous_scale="Reds",
            text_auto=True,
            hover_data=["finding_count", "max_cvss", "unique_cves"],
        )
        fig_dev.update_layout(
            xaxis_title="Device", yaxis_title="Aggregate Risk Score",
            xaxis_tickangle=-45, margin=dict(t=20, b=100), height=450,
        )
        st.plotly_chart(fig_dev, use_container_width=True)

        with st.expander("📋 Full Device Risk Table", expanded=False):
            st.dataframe(df_dev, use_container_width=True, height=400)
    else:
        st.info("Run correlation analysis to see device risk data.")

# ── Tab 4: CVE Blast Radius ──
with tab4:
    st.subheader("CVE Blast Radius")
    st.markdown("Which CVEs affect the most devices? High blast-radius CVEs have outsized organizational impact.")

    df_blast = group_by_cve_blast_radius(df)

    if not df_blast.empty:
        k1, k2, k3 = st.columns(3)
        with k1:
            st.metric("Unique CVEs", len(df_blast))
        with k2:
            widespread = (df_blast["affected_devices"] > 1).sum() if "affected_devices" in df_blast.columns else 0
            st.metric("Multi-Device CVEs", widespread)
        with k3:
            max_blast = df_blast["affected_devices"].max() if "affected_devices" in df_blast.columns else 0
            st.metric("Max Blast Radius", f"{max_blast} devices")

        fig_blast = px.scatter(
            df_blast.head(30),
            x="affected_devices",
            y="max_cvss" if "max_cvss" in df_blast.columns else "cvss_score",
            size="affected_devices",
            color="affected_devices",
            color_continuous_scale="Reds",
            hover_name="cve_id",
            text="cve_id",
            hover_data=df_blast.columns.tolist()[:6],
        )
        fig_blast.update_layout(
            xaxis_title="Affected Devices", yaxis_title="Max CVSS Score",
            margin=dict(t=20, b=20), height=450,
        )
        fig_blast.update_traces(textposition="top center")
        st.plotly_chart(fig_blast, use_container_width=True)

        with st.expander("📋 Full CVE Blast Radius Table", expanded=False):
            st.dataframe(df_blast, use_container_width=True, height=400)
    else:
        st.info("Run correlation analysis to see blast-radius data.")

# ── Tab 5: Summary ──
with tab5:
    st.subheader("Correlation Summary")
    summary = get_correlation_summary(df)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Findings", summary.get("total_findings", 0))
    with m2:
        st.metric("Patch Groups", summary.get("patch_groups", 0))
    with m3:
        st.metric("Software Groups", summary.get("software_groups", 0))
    with m4:
        st.metric("Unique Devices", summary.get("unique_devices", 0))

    st.divider()

    st.markdown("### Remediation Efficiency Insights")

    # Calculate potential savings
    df_p = group_by_patch(df)
    if "patch_group" in df_p.columns:
        pg = df_p.groupby("patch_group").size()
        multi = pg[pg > 1]
        if len(multi) > 0:
            total_findings_in_groups = multi.sum()
            patches_needed = len(multi)
            st.success(
                f"**{patches_needed} patches** can resolve **{total_findings_in_groups} findings** "
                f"(avg {total_findings_in_groups / patches_needed:.1f} findings per patch). "
                f"Focus on these for maximum efficiency."
            )

    # Top action items
    st.markdown("### 🎯 Top Action Items")
    actions = []

    # Most impactful patches
    if "patch_group" in df_p.columns:
        pg_counts = df_p.groupby("patch_group").size().sort_values(ascending=False)
        for patch, count in pg_counts.head(3).items():
            if count > 1:
                actions.append(f"Apply **{patch}** — resolves {count} findings across multiple devices")

    # Most vulnerable devices
    df_d = group_by_device_risk(df)
    if not df_d.empty:
        for _, dev_row in df_d.head(3).iterrows():
            actions.append(
                f"Remediate **{dev_row['device_name']}** — "
                f"{dev_row.get('finding_count', 0)} findings, "
                f"risk score {dev_row.get('total_risk_score', 0):.0f}"
            )

    if actions:
        for i, action in enumerate(actions, 1):
            st.markdown(f"{i}. {action}")
    else:
        st.info("Run correlation analysis to generate action items.")

    # Export
    st.divider()
    from datetime import datetime
    if st.button("📥 Export Full Correlation Report", use_container_width=True):
        export_df = df.copy()
        for func in [group_by_patch, group_by_software]:
            export_df = func(export_df)
        csv = export_df.to_csv(index=False)
        st.download_button(
            "Download CSV",
            csv,
            file_name=f"correlation_report_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

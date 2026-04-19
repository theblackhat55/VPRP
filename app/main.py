"""
VPRP — Vulnerability Prioritization & Remediation Platform
Main Streamlit application entry point.
"""
import streamlit as st
import pandas as pd
import plotly.express as px

from app.engine.parser import parse_uploaded_file, merge_multi_upload, FileParseResult
from app.engine.classifier import (
    classify_teams,
    classify_with_llm,
    get_unmatched_summary,
    add_custom_rule,
    remove_custom_rule,
)
from app.engine.prioritizer import compute_risk_scores
from app.engine.deduplicator import deduplicate_by_patch
from app.engine.enricher import (
    enrich_with_kev,
    enrich_with_epss,
    ai_generate_executive_summary,
    ai_generate_team_summary,
)
from app.engine.reporter import generate_excel_report, generate_team_csv
from app.config import (
    DEFAULT_TEAM, load_custom_rules, get_all_team_names,
)
from app.utils.logger import setup_logging
from app.utils.constants import APP_NAME, APP_VERSION, APP_ICON

setup_logging()

st.set_page_config(page_title="VPRP", page_icon=APP_ICON, layout="wide")
st.title(f"{APP_ICON} {APP_NAME}")
st.caption(f"v{APP_VERSION} — Upload Defender CSV/JSON exports to get prioritized, team-specific remediation reports")


# ── Helper: Custom Rules Manager UI ──────────────────────
def _show_custom_rules_manager():
    """Display custom rules table and add/remove UI."""
    existing_rules = load_custom_rules()

    if existing_rules:
        st.markdown(f"**{len(existing_rules)} custom rule(s) active**")
        rules_display = pd.DataFrame(
            existing_rules,
            columns=["Field", "Match Type", "Match Value", "Team"],
        )
        st.dataframe(rules_display, use_container_width=True, hide_index=False)

        del_idx = st.number_input(
            "Rule index to delete", min_value=0,
            max_value=max(0, len(existing_rules) - 1),
            value=0, key="del_rule_idx",
        )
        if st.button("Delete Rule", key="del_rule_btn"):
            if remove_custom_rule(del_idx):
                st.success(f"Rule {del_idx} deleted")
                st.rerun()
            else:
                st.error("Failed to delete rule")
    else:
        st.info("No custom rules defined yet. Add rules below to classify unmatched findings.")

    st.markdown("---")
    st.markdown("**Add New Rule**")
    acol1, acol2 = st.columns(2)
    with acol1:
        new_field = st.selectbox(
            "Match field",
            ["softwareName", "softwareVendor", "recommendationReference"],
            key="new_rule_field",
        )
        new_match = st.selectbox(
            "Match type",
            ["contains", "equals", "startswith"],
            key="new_rule_match",
        )
    with acol2:
        new_value = st.text_input("Match value (case-insensitive)", key="new_rule_value")
        all_teams = get_all_team_names()
        new_team = st.selectbox("Assign to team", all_teams, key="new_rule_team")

    if st.button("Add Rule", key="add_rule_btn", type="primary"):
        if new_value.strip():
            if add_custom_rule(new_field, new_match, new_value.strip().lower(), new_team):
                st.success(f"Rule added: {new_field} {new_match} '{new_value}' → {new_team}")
                st.rerun()
            else:
                st.warning("Rule already exists or invalid")
        else:
            st.warning("Match value cannot be empty")


# ── Sidebar ───────────────────────────────────────────────
with st.sidebar:
    st.header("Settings")
    enable_kev = st.checkbox("Enrich with CISA KEV", value=True,
                             help="Flag CVEs in CISA Known Exploited Vulnerabilities catalog")
    enable_epss = st.checkbox("Enrich with EPSS scores", value=False,
                              help="Fetch exploit prediction scores (requires internet)")
    enable_ai = st.checkbox("Enable AI summaries", value=False,
                            help="Generate AI-powered summaries via Azure AI Foundry")
    enable_llm_classify = st.checkbox("Enable AI classification", value=False,
                                       help="Use LLM to classify unmatched findings (requires Azure AI)")

    st.divider()
    st.header("Upload Vulnerability Data")
    st.markdown("""
    **Supported formats:**
    - Defender TVM Portal CSV
    - Defender API JSON
    - Defender for Cloud CSV
    - Multiple files at once
    """)

    uploaded_files = st.file_uploader(
        "Drop files here",
        type=["csv", "json"],
        accept_multiple_files=True,
    )

# ── Landing Page ──────────────────────────────────────────
if not uploaded_files:
    st.markdown("""
    ### Getting Started

    1. **Export** vulnerability data from Microsoft Defender
    2. **Upload** one or more files using the sidebar
    3. **Review** the auto-generated dashboard and reports
    4. **Download** team-specific remediation reports

    ### Multi-Asset Upload Support

    | Scenario | Supported |
    |---|---|
    | Multiple CSVs from different Defender tenants | Yes |
    | Mix of CSV (portal) and JSON (API) files | Yes |
    | Defender for Endpoint + Defender for Cloud | Yes |
    | Overlapping time-period exports (auto-deduped) | Yes |
    | Different RBAC group scopes | Yes |
    | Different column naming conventions (auto-mapped) | Yes |
    """)

    with st.expander("Manage Custom Classification Rules"):
        _show_custom_rules_manager()
    st.stop()

# ── Step 1: Parse All Files ──────────────────────────────
st.header("File Processing")

parse_results: list[FileParseResult] = []
parse_errors: list[tuple] = []

progress = st.progress(0, text="Parsing files...")
for i, f in enumerate(uploaded_files):
    try:
        result = parse_uploaded_file(f)
        parse_results.append(result)
    except Exception as e:
        parse_errors.append((f.name, str(e)))
    progress.progress((i + 1) / len(uploaded_files), text=f"Parsed {i + 1}/{len(uploaded_files)}")
progress.empty()

if parse_results:
    file_summary = pd.DataFrame([
        {
            "File": r.filename,
            "Source Type": r.source_type,
            "Rows Parsed": f"{r.row_count:,}",
            "Warnings": len(r.warnings),
            "Status": "OK",
        }
        for r in parse_results
    ])
    st.dataframe(file_summary, use_container_width=True, hide_index=True)

    all_warnings = [(r.filename, w) for r in parse_results for w in r.warnings]
    if all_warnings:
        with st.expander(f"{len(all_warnings)} warning(s) during parsing"):
            for fname, warning in all_warnings:
                st.warning(f"**{fname}**: {warning}")

if parse_errors:
    for fname, err in parse_errors:
        st.error(f"**{fname}**: {err}")

if not parse_results:
    st.error("No files were successfully parsed. Please check the format.")
    st.stop()

# ── Step 2: Merge & Deduplicate ──────────────────────────
with st.spinner("Merging and deduplicating across files..."):
    combined, merge_stats = merge_multi_upload(parse_results)

st.divider()
st.subheader("Merge Summary")

mcol1, mcol2, mcol3, mcol4 = st.columns(4)
mcol1.metric("Files Processed", merge_stats["files_processed"])
mcol2.metric("Total Rows (pre-dedup)", f"{merge_stats['total_rows_before_dedup']:,}")
mcol3.metric("Duplicates Removed", f"{merge_stats['duplicates_removed']:,}")
mcol4.metric("Final Row Count", f"{merge_stats['total_rows_after_dedup']:,}")

st.info(f"**Source types detected**: {', '.join(merge_stats['source_types_detected'])}")

# ── Step 3: Classify, Prioritize, Enrich ─────────────────
with st.spinner("Classifying team ownership (Tier 1: rules)..."):
    combined = classify_teams(combined)

# Tier 2: Optional LLM classification
if enable_llm_classify:
    unmatched_count = (combined["assignedTeam"] == DEFAULT_TEAM).sum()
    if unmatched_count > 0:
        with st.spinner(f"AI classifying {unmatched_count} unmatched findings (Tier 2: LLM)..."):
            combined = classify_with_llm(combined)

with st.spinner("Computing risk scores..."):
    combined = compute_risk_scores(combined)

if enable_kev:
    with st.spinner("Enriching with CISA KEV..."):
        combined = enrich_with_kev(combined)

if enable_epss:
    with st.spinner("Fetching EPSS scores..."):
        combined = enrich_with_epss(combined)

with st.spinner("Grouping by root-cause patches..."):
    dedup = deduplicate_by_patch(combined)

# ── Classification Summary ───────────────────────────────
st.divider()
st.header("Classification Summary")

if "classificationTier" in combined.columns:
    tier_counts = combined["classificationTier"].value_counts()
    tcl1, tcl2, tcl3, tcl4 = st.columns(4)
    tcl1.metric("Rule-Matched", tier_counts.get("rule", 0))
    tcl2.metric("Custom Rule", tier_counts.get("custom_rule", 0))
    tcl3.metric("AI-Classified", tier_counts.get("llm", 0))
    tcl4.metric("Unmatched", tier_counts.get("unmatched", 0))

# ── Dashboard ─────────────────────────────────────────────
st.divider()
st.header("Vulnerability Dashboard")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Findings", f"{len(combined):,}")
col2.metric("Unique CVEs", f"{combined['cveId'].nunique():,}")
col3.metric("Affected Devices", f"{combined['deviceName'].nunique():,}")
kev_count = int(combined["cisaKev"].sum()) if "cisaKev" in combined.columns else "N/A"
col4.metric("CISA KEV Matches", kev_count)

col5, col6, col7, col8 = st.columns(4)
sev = combined["vulnerabilitySeverityLevel"].value_counts()
col5.metric("Critical", sev.get("Critical", 0))
col6.metric("High", sev.get("High", 0))
col7.metric("Medium", sev.get("Medium", 0))
sla_breached = int(combined["slaBreached"].sum()) if "slaBreached" in combined.columns else 0
col8.metric("SLA Breached", sla_breached)

# Source breakdown
if "_sourceFile" in combined.columns:
    st.subheader("Data Source Breakdown")
    source_breakdown = combined.groupby("_sourceFile").agg(
        rows=("cveId", "count"),
        unique_cves=("cveId", "nunique"),
        devices=("deviceName", "nunique"),
        source_type=("_sourceType", "first"),
    ).reset_index()
    source_breakdown.columns = ["Source File", "Rows", "Unique CVEs", "Devices", "Source Type"]
    st.dataframe(source_breakdown, use_container_width=True, hide_index=True)

# Charts
chart1, chart2 = st.columns(2)

with chart1:
    fig_sev = px.pie(
        combined, names="vulnerabilitySeverityLevel",
        title="By Severity",
        color="vulnerabilitySeverityLevel",
        color_discrete_map={
            "Critical": "#FF4444", "High": "#FF8C00",
            "Medium": "#FFD700", "Low": "#4CAF50", "Unknown": "#999999",
        },
    )
    st.plotly_chart(fig_sev, use_container_width=True)

with chart2:
    tc = combined["assignedTeam"].value_counts().reset_index()
    tc.columns = ["Team", "Count"]
    fig_team = px.bar(tc, x="Team", y="Count", title="By Team", color="Count",
                      color_continuous_scale="Reds")
    fig_team.update_xaxes(tickangle=45)
    st.plotly_chart(fig_team, use_container_width=True)

# Heatmap
st.subheader("Risk Heatmap: Team x Severity")
heatmap_data = combined.groupby(
    ["assignedTeam", "vulnerabilitySeverityLevel"]
).size().reset_index(name="count")

if not heatmap_data.empty:
    fig_heat = px.density_heatmap(
        heatmap_data, x="vulnerabilitySeverityLevel", y="assignedTeam",
        z="count", color_continuous_scale="YlOrRd",
        category_orders={
            "vulnerabilitySeverityLevel": ["Critical", "High", "Medium", "Low", "Unknown"]
        },
    )
    fig_heat.update_layout(height=400)
    st.plotly_chart(fig_heat, use_container_width=True)

# ── Unmatched / Admin Review ─────────────────────────────
unmatched_df = combined[combined["assignedTeam"] == DEFAULT_TEAM]
if not unmatched_df.empty:
    st.divider()
    st.header("Unmatched Findings — Admin Review")
    st.warning(
        f"**{len(unmatched_df):,}** findings ({unmatched_df['cveId'].nunique()} unique CVEs) "
        f"could not be auto-classified. Review below and create rules to assign them."
    )

    # Show grouped summary
    unmatched_summary = get_unmatched_summary(combined)
    if not unmatched_summary.empty:
        st.dataframe(unmatched_summary, use_container_width=True, hide_index=True)

    # Quick-assign form
    st.subheader("Quick-Assign Rule")
    st.caption("Select a row above, then create a rule to classify similar findings in future uploads.")

    qcol1, qcol2 = st.columns(2)
    with qcol1:
        q_field = st.selectbox(
            "Match field",
            ["softwareName", "softwareVendor", "recommendationReference"],
            key="q_field",
        )
        q_match = st.selectbox(
            "Match type",
            ["contains", "equals", "startswith"],
            key="q_match",
        )
    with qcol2:
        # Suggest values from unmatched data
        if q_field in unmatched_df.columns:
            unique_vals = sorted(unmatched_df[q_field].dropna().unique()[:50])
            q_value = st.selectbox(
                "Match value (from unmatched data)",
                [""] + [str(v) for v in unique_vals],
                key="q_value",
            )
        else:
            q_value = st.text_input("Match value", key="q_value_text")

        all_teams = get_all_team_names()
        q_team = st.selectbox("Assign to team", all_teams, key="q_team")

    if st.button("Create Rule & Re-classify", key="quick_assign_btn", type="primary"):
        if q_value:
            val = q_value.strip().lower() if isinstance(q_value, str) else str(q_value).lower()
            if add_custom_rule(q_field, q_match, val, q_team):
                st.success(f"Rule created: {q_field} {q_match} '{val}' → {q_team}")
                st.info("The page will refresh to apply the new rule.")
                st.rerun()
            else:
                st.warning("Rule already exists or invalid")
        else:
            st.warning("Select or enter a match value")

# ── Team Drill-Down ───────────────────────────────────────
st.divider()
st.header("Team-Specific Views")

teams = sorted(combined["assignedTeam"].unique())
selected_team = st.selectbox("Select team", teams)

team_data = combined[combined["assignedTeam"] == selected_team]

tcol1, tcol2, tcol3, tcol4 = st.columns(4)
tcol1.metric("Findings", f"{len(team_data):,}")
tcol2.metric("Unique CVEs", f"{team_data['cveId'].nunique():,}")
tcol3.metric("Devices", f"{team_data['deviceName'].nunique():,}")
team_sla = int(team_data["slaBreached"].sum()) if "slaBreached" in team_data.columns else 0
tcol4.metric("SLA Breached", team_sla)

if "_sourceFile" in team_data.columns:
    st.caption(f"Data from: {', '.join(team_data['_sourceFile'].unique())}")

display_cols = [
    "cveId", "cvssScore", "riskScore", "riskRating",
    "vulnerabilitySeverityLevel", "exploitabilityLevel",
    "softwareName", "softwareVersion", "deviceName",
    "recommendedSecurityUpdate", "slaBreached",
]
if "classificationTier" in team_data.columns:
    display_cols.append("classificationTier")
if "_sourceFile" in team_data.columns:
    display_cols.append("_sourceFile")
display_cols = [c for c in display_cols if c in team_data.columns]

st.dataframe(team_data[display_cols].head(200), use_container_width=True, height=400)

# ── Report Generation ─────────────────────────────────────
st.divider()
st.header("Generate & Download Reports")

if st.button("Generate Full Excel Report", type="primary"):
    with st.spinner("Building report..."):
        exec_summary = ai_generate_executive_summary(combined)
        team_sums = {}
        for t in teams:
            tdf = combined[combined["assignedTeam"] == t]
            team_sums[t] = ai_generate_team_summary(t, tdf)
        excel_bytes = generate_excel_report(combined, dedup, exec_summary, team_sums)

    st.download_button(
        "Download Full Excel Report",
        data=excel_bytes,
        file_name=f"vuln_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M')}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

st.subheader("Per-Team Downloads")
dl_cols = st.columns(min(len(teams), 4))
for i, team in enumerate(teams):
    with dl_cols[i % len(dl_cols)]:
        csv_bytes = generate_team_csv(combined, team)
        st.download_button(
            f"{team}",
            data=csv_bytes,
            file_name=f"{team.replace(' ', '_').replace('/', '_')}_vulns.csv",
            mime="text/csv",
            key=f"dl_{team}",
        )

# ── Custom Rules Manager (bottom) ────────────────────────
st.divider()
with st.expander("Manage Custom Classification Rules"):
    _show_custom_rules_manager()

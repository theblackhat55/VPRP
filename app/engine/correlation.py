"""
VPRP — Vulnerability Correlation & Grouping Engine
Groups findings by root-cause patch, attack chain, and asset cluster.

Grouping strategies:
  1. Patch Group: Same security update resolves multiple CVEs across devices
  2. Software Group: Same software/version affected by multiple CVEs
  3. Device Risk Group: Single device with multiple high-risk findings (attack chain)
  4. CVE Impact Group: Same CVE across multiple devices (blast radius)
"""
import logging
from collections import defaultdict
from typing import List, Dict

import pandas as pd

logger = logging.getLogger(__name__)


def group_by_patch(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group findings by recommended security update (root-cause patch).
    Returns a summary DataFrame showing how many CVEs and devices each patch resolves.
    """
    if df.empty:
        return pd.DataFrame()

    patch_col = None
    for col in ["recommendedSecurityUpdateId", "recommendedSecurityUpdate",
                 "recommendation_reference"]:
        if col in df.columns:
            patch_col = col
            break

    if not patch_col:
        logger.warning("No patch column found for grouping")
        return pd.DataFrame()

    # Filter rows with actual patches
    patched = df[df[patch_col].notna() & (df[patch_col] != "")].copy()
    if patched.empty:
        return pd.DataFrame()

    groups = []
    for patch_id, group in patched.groupby(patch_col):
        cves = group["cveId"].nunique() if "cveId" in group.columns else 0
        devices = group["deviceName"].nunique() if "deviceName" in group.columns else 0
        max_risk = group["riskScore"].max() if "riskScore" in group.columns else 0
        max_cvss = group["cvssScore"].max() if "cvssScore" in group.columns else 0
        severities = group["vulnerabilitySeverity"].value_counts().to_dict() if "vulnerabilitySeverity" in group.columns else {}
        teams = group["assignedTeam"].unique().tolist() if "assignedTeam" in group.columns else []

        # SSVC highest priority
        ssvc_decision = "N/A"
        if "ssvc_decision" in group.columns:
            ssvc_decision = group.sort_values("ssvc_priority").iloc[0]["ssvc_decision"]

        groups.append({
            "patch_id": str(patch_id),
            "cve_count": cves,
            "device_count": devices,
            "finding_count": len(group),
            "max_risk_score": round(max_risk, 1),
            "max_cvss": round(max_cvss, 1),
            "critical_count": severities.get("critical", 0),
            "high_count": severities.get("high", 0),
            "ssvc_decision": ssvc_decision,
            "teams": ", ".join(teams),
            "cves": ", ".join(group["cveId"].unique().tolist()[:5]) if "cveId" in group.columns else "",
            "impact_score": round(cves * devices * (max_risk / 100), 1),
        })

    result = pd.DataFrame(groups)
    result = result.sort_values("impact_score", ascending=False)
    logger.info(f"Patch grouping: {len(result)} groups from {len(patched)} findings")
    return result


def group_by_software(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group findings by affected software (vendor + name + version).
    Shows which software components carry the most risk.
    """
    if df.empty:
        return pd.DataFrame()

    sw_cols = []
    for col in ["softwareVendor", "softwareName", "softwareVersion"]:
        if col in df.columns:
            sw_cols.append(col)

    if len(sw_cols) < 2:
        return pd.DataFrame()

    # Create composite key
    df = df.copy()
    df["_sw_key"] = df[sw_cols].fillna("").agg(" | ".join, axis=1)
    df["_sw_key"] = df["_sw_key"].str.strip(" |")

    groups = []
    for sw_key, group in df.groupby("_sw_key"):
        if not sw_key or sw_key == "|" or sw_key.strip() == "":
            continue

        cves = group["cveId"].nunique() if "cveId" in group.columns else 0
        devices = group["deviceName"].nunique() if "deviceName" in group.columns else 0
        max_risk = group["riskScore"].max() if "riskScore" in group.columns else 0
        avg_risk = group["riskScore"].mean() if "riskScore" in group.columns else 0

        groups.append({
            "software": sw_key,
            "cve_count": cves,
            "device_count": devices,
            "finding_count": len(group),
            "max_risk": round(max_risk, 1),
            "avg_risk": round(avg_risk, 1),
            "aggregate_risk": round(cves * devices * (avg_risk / 100), 1),
        })

    result = pd.DataFrame(groups)
    result = result.sort_values("aggregate_risk", ascending=False)
    return result


def group_by_device_risk(df: pd.DataFrame, min_findings: int = 2) -> pd.DataFrame:
    """
    Group findings by device to identify attack chain potential.
    Devices with multiple high-risk findings are prioritized (chaining risk).
    """
    if df.empty or "deviceName" not in df.columns:
        return pd.DataFrame()

    groups = []
    for device, group in df.groupby("deviceName"):
        if len(group) < min_findings:
            continue

        cves = group["cveId"].nunique() if "cveId" in group.columns else 0
        max_risk = group["riskScore"].max() if "riskScore" in group.columns else 0
        avg_risk = group["riskScore"].mean() if "riskScore" in group.columns else 0
        critical = (group["vulnerabilitySeverity"] == "critical").sum() if "vulnerabilitySeverity" in group.columns else 0
        high = (group["vulnerabilitySeverity"] == "high").sum() if "vulnerabilitySeverity" in group.columns else 0

        # Chain risk: more vulns on same device = higher exploitation potential
        chain_multiplier = min(len(group) / 5.0, 2.0)  # caps at 2x
        chain_risk = round(avg_risk * chain_multiplier, 1)

        os_info = group["osPlatform"].iloc[0] if "osPlatform" in group.columns else "Unknown"
        team = group["assignedTeam"].iloc[0] if "assignedTeam" in group.columns else "Unassigned"

        groups.append({
            "device_name": device,
            "os_platform": os_info,
            "finding_count": len(group),
            "cve_count": cves,
            "critical_count": critical,
            "high_count": high,
            "max_risk": round(max_risk, 1),
            "avg_risk": round(avg_risk, 1),
            "chain_risk": chain_risk,
            "assigned_team": team,
        })

    result = pd.DataFrame(groups)
    result = result.sort_values("chain_risk", ascending=False)
    return result


def group_by_cve_blast_radius(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group by CVE to show blast radius — how many devices each CVE affects.
    Useful for prioritizing CVEs that have the widest impact.
    """
    if df.empty or "cveId" not in df.columns:
        return pd.DataFrame()

    groups = []
    for cve, group in df.groupby("cveId"):
        devices = group["deviceName"].nunique() if "deviceName" in group.columns else 0
        max_cvss = group["cvssScore"].max() if "cvssScore" in group.columns else 0
        max_risk = group["riskScore"].max() if "riskScore" in group.columns else 0
        severity = group["vulnerabilitySeverity"].iloc[0] if "vulnerabilitySeverity" in group.columns else "unknown"
        teams = group["assignedTeam"].unique().tolist() if "assignedTeam" in group.columns else []
        kev = any(group["cisaKev"] == True) if "cisaKev" in group.columns else False

        ssvc = "N/A"
        if "ssvc_decision" in group.columns:
            ssvc = group.sort_values("ssvc_priority").iloc[0]["ssvc_decision"]

        blast_score = round(devices * (max_risk / 100) * (1.5 if kev else 1.0), 1)

        groups.append({
            "cve_id": cve,
            "cvss": round(max_cvss, 1),
            "severity": severity,
            "affected_devices": devices,
            "max_risk": round(max_risk, 1),
            "ssvc_decision": ssvc,
            "cisa_kev": kev,
            "teams": ", ".join(teams),
            "blast_score": blast_score,
        })

    result = pd.DataFrame(groups)
    result = result.sort_values("blast_score", ascending=False)
    return result


def get_correlation_summary(df: pd.DataFrame) -> dict:
    """Generate overall correlation statistics."""
    patch_groups = group_by_patch(df)
    device_groups = group_by_device_risk(df)
    cve_groups = group_by_cve_blast_radius(df)
    software_groups = group_by_software(df)

    return {
        "patch_groups": len(patch_groups),
        "single_patch_max_resolve": int(patch_groups["finding_count"].max()) if not patch_groups.empty else 0,
        "multi_vuln_devices": len(device_groups),
        "highest_chain_risk_device": device_groups.iloc[0]["device_name"] if not device_groups.empty else "N/A",
        "widest_blast_cve": cve_groups.iloc[0]["cve_id"] if not cve_groups.empty else "N/A",
        "widest_blast_devices": int(cve_groups.iloc[0]["affected_devices"]) if not cve_groups.empty else 0,
        "riskiest_software": software_groups.iloc[0]["software"] if not software_groups.empty else "N/A",
    }

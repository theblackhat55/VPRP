"""
VPRP — CISA SSVC (Stakeholder-Specific Vulnerability Categorization) Engine
Implements the Deployer Decision Tree for patch deployment priority.

Decision Points:
  1. Exploitation: None / Public PoC / Active
  2. System Exposure: Small / Controlled / Open
  3. Automatable: No / Yes
  4. Human Impact: Low / Medium / High / Very High

Outcomes: Defer / Scheduled / Out-of-Cycle / Immediate
"""
import logging
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# ── SSVC Decision Tree (72 rows from CISA deployer model) ──
# Format: (exploitation, exposure, automatable, human_impact) -> decision
DEPLOYER_TREE = {
    # Exploitation: None
    ("none", "small", "no", "low"): "defer",
    ("none", "small", "no", "medium"): "defer",
    ("none", "small", "no", "high"): "scheduled",
    ("none", "small", "no", "very_high"): "scheduled",
    ("none", "small", "yes", "low"): "defer",
    ("none", "small", "yes", "medium"): "scheduled",
    ("none", "small", "yes", "high"): "scheduled",
    ("none", "small", "yes", "very_high"): "scheduled",
    ("none", "controlled", "no", "low"): "defer",
    ("none", "controlled", "no", "medium"): "scheduled",
    ("none", "controlled", "no", "high"): "scheduled",
    ("none", "controlled", "no", "very_high"): "scheduled",
    ("none", "controlled", "yes", "low"): "scheduled",
    ("none", "controlled", "yes", "medium"): "scheduled",
    ("none", "controlled", "yes", "high"): "scheduled",
    ("none", "controlled", "yes", "very_high"): "scheduled",
    ("none", "open", "no", "low"): "defer",
    ("none", "open", "no", "medium"): "scheduled",
    ("none", "open", "no", "high"): "scheduled",
    ("none", "open", "no", "very_high"): "scheduled",
    ("none", "open", "yes", "low"): "scheduled",
    ("none", "open", "yes", "medium"): "scheduled",
    ("none", "open", "yes", "high"): "scheduled",
    ("none", "open", "yes", "very_high"): "out-of-cycle",
    # Exploitation: Public PoC
    ("poc", "small", "no", "low"): "defer",
    ("poc", "small", "no", "medium"): "scheduled",
    ("poc", "small", "no", "high"): "scheduled",
    ("poc", "small", "no", "very_high"): "scheduled",
    ("poc", "small", "yes", "low"): "scheduled",
    ("poc", "small", "yes", "medium"): "scheduled",
    ("poc", "small", "yes", "high"): "scheduled",
    ("poc", "small", "yes", "very_high"): "scheduled",
    ("poc", "controlled", "no", "low"): "defer",
    ("poc", "controlled", "no", "medium"): "scheduled",
    ("poc", "controlled", "no", "high"): "scheduled",
    ("poc", "controlled", "no", "very_high"): "scheduled",
    ("poc", "controlled", "yes", "low"): "scheduled",
    ("poc", "controlled", "yes", "medium"): "scheduled",
    ("poc", "controlled", "yes", "high"): "scheduled",
    ("poc", "controlled", "yes", "very_high"): "out-of-cycle",
    ("poc", "open", "no", "low"): "scheduled",
    ("poc", "open", "no", "medium"): "scheduled",
    ("poc", "open", "no", "high"): "scheduled",
    ("poc", "open", "no", "very_high"): "out-of-cycle",
    ("poc", "open", "yes", "low"): "scheduled",
    ("poc", "open", "yes", "medium"): "scheduled",
    ("poc", "open", "yes", "high"): "out-of-cycle",
    ("poc", "open", "yes", "very_high"): "out-of-cycle",
    # Exploitation: Active
    ("active", "small", "no", "low"): "scheduled",
    ("active", "small", "no", "medium"): "scheduled",
    ("active", "small", "no", "high"): "out-of-cycle",
    ("active", "small", "no", "very_high"): "out-of-cycle",
    ("active", "small", "yes", "low"): "scheduled",
    ("active", "small", "yes", "medium"): "out-of-cycle",
    ("active", "small", "yes", "high"): "out-of-cycle",
    ("active", "small", "yes", "very_high"): "out-of-cycle",
    ("active", "controlled", "no", "low"): "scheduled",
    ("active", "controlled", "no", "medium"): "scheduled",
    ("active", "controlled", "no", "high"): "out-of-cycle",
    ("active", "controlled", "no", "very_high"): "out-of-cycle",
    ("active", "controlled", "yes", "low"): "out-of-cycle",
    ("active", "controlled", "yes", "medium"): "out-of-cycle",
    ("active", "controlled", "yes", "high"): "out-of-cycle",
    ("active", "controlled", "yes", "very_high"): "out-of-cycle",
    ("active", "open", "no", "low"): "scheduled",
    ("active", "open", "no", "medium"): "out-of-cycle",
    ("active", "open", "no", "high"): "out-of-cycle",
    ("active", "open", "no", "very_high"): "immediate",
    ("active", "open", "yes", "low"): "out-of-cycle",
    ("active", "open", "yes", "medium"): "out-of-cycle",
    ("active", "open", "yes", "high"): "immediate",
    ("active", "open", "yes", "very_high"): "immediate",
}

# Priority ordering for sorting
PRIORITY_ORDER = {"immediate": 0, "out-of-cycle": 1, "scheduled": 2, "defer": 3}

# SLA mapping for SSVC decisions (calendar days)
SSVC_SLA_DAYS = {
    "immediate": 3,
    "out-of-cycle": 14,
    "scheduled": 30,
    "defer": 90,
}


# ── Decision Point Derivation ────────────────────────────

def derive_exploitation(row: pd.Series) -> str:
    """
    Derive exploitation status from available data.
    Uses: cisaKev, exploitabilityLevel, epssScore
    """
    # CISA KEV = actively exploited
    kev = row.get("cisaKev", False)
    if kev is True or str(kev).lower() == "true":
        return "active"

    # Exploitability level from Defender
    exploit_level = str(row.get("exploitabilityLevel", "")).lower()
    if "isInKit" in exploit_level or "kit" in exploit_level:
        return "active"
    if "verified" in exploit_level or "isverified" in exploit_level:
        return "poc"
    if "public" in exploit_level or "ispublic" in exploit_level:
        return "poc"

    # EPSS score as a proxy
    epss = row.get("epssScore", 0)
    try:
        epss = float(epss) if epss else 0
    except (ValueError, TypeError):
        epss = 0

    if epss >= 0.5:
        return "active"
    if epss >= 0.1:
        return "poc"

    return "none"


def derive_system_exposure(row: pd.Series, asset_exposure_map: dict = None) -> str:
    """
    Derive system exposure from asset context.
    Uses: asset exposure map, os_platform, device_name patterns
    """
    device = str(row.get("deviceName", "")).lower()

    # Check asset-level exposure override
    if asset_exposure_map and device in asset_exposure_map:
        return asset_exposure_map[device]

    # Heuristic: internet-facing services
    internet_facing_patterns = [
        "web", "www", "dns", "mail", "smtp", "mx", "proxy",
        "vpn", "gateway", "lb", "load", "cdn", "api", "edge",
        "dmz", "public", "ext-", "external",
    ]
    for pattern in internet_facing_patterns:
        if pattern in device:
            return "open"

    # Servers typically controlled network
    server_patterns = ["srv", "server", "dc-", "db-", "app-", "sql"]
    for pattern in server_patterns:
        if pattern in device:
            return "controlled"

    # Workstations are typically small exposure
    ws_patterns = ["ws-", "desktop", "laptop", "pc-", "wks"]
    for pattern in ws_patterns:
        if pattern in device:
            return "small"

    return "controlled"  # default


def derive_automatable(row: pd.Series) -> str:
    """
    Derive whether exploitation is automatable.
    Uses: CVSS attack vector/complexity, exploitability
    """
    cvss = row.get("cvssScore", 0)
    try:
        cvss = float(cvss) if cvss else 0
    except (ValueError, TypeError):
        cvss = 0

    exploit_level = str(row.get("exploitabilityLevel", "")).lower()

    # Kit-based exploits are automatable
    if "kit" in exploit_level:
        return "yes"

    # High CVSS + remote typically automatable
    if cvss >= 9.0:
        return "yes"

    # Network-based, low complexity
    if cvss >= 7.0 and ("public" in exploit_level or "verified" in exploit_level):
        return "yes"

    return "no"


def derive_human_impact(row: pd.Series, asset_criticality_map: dict = None) -> str:
    """
    Derive human impact from asset criticality and severity.
    Combines mission impact (asset criticality) with technical severity.
    """
    device = str(row.get("deviceName", "")).lower()
    severity = str(row.get("vulnerabilitySeverity", "")).lower()

    # Get asset criticality (1-5 scale)
    criticality = 3  # default
    if asset_criticality_map and device in asset_criticality_map:
        criticality = asset_criticality_map[device]

    cvss = row.get("cvssScore", 0)
    try:
        cvss = float(cvss) if cvss else 0
    except (ValueError, TypeError):
        cvss = 0

    # Mission-critical + critical severity = very high
    if criticality >= 5 and severity == "critical":
        return "very_high"
    if criticality >= 5 and severity == "high":
        return "high"
    if criticality >= 5:
        return "medium"

    if criticality >= 4 and severity == "critical":
        return "high"
    if criticality >= 4 and severity == "high":
        return "high"
    if criticality >= 4:
        return "medium"

    if severity == "critical" and cvss >= 9.0:
        return "high"
    if severity == "critical":
        return "medium"
    if severity == "high" and cvss >= 8.0:
        return "medium"
    if severity == "high":
        return "medium"

    return "low"


# ── Main SSVC Evaluation ─────────────────────────────────

def evaluate_ssvc(
    df: pd.DataFrame,
    asset_criticality_map: dict = None,
    asset_exposure_map: dict = None,
) -> pd.DataFrame:
    """
    Apply CISA SSVC Deployer Decision Tree to each finding.

    Adds columns:
      - ssvc_exploitation: none / poc / active
      - ssvc_exposure: small / controlled / open
      - ssvc_automatable: no / yes
      - ssvc_human_impact: low / medium / high / very_high
      - ssvc_decision: defer / scheduled / out-of-cycle / immediate
      - ssvc_priority: numeric (0=immediate, 3=defer)
      - ssvc_sla_days: SLA days based on SSVC decision
    """
    if df.empty:
        return df

    logger.info(f"Evaluating SSVC for {len(df)} findings...")

    decisions = []
    for _, row in df.iterrows():
        exploitation = derive_exploitation(row)
        exposure = derive_system_exposure(row, asset_exposure_map)
        automatable = derive_automatable(row)
        human_impact = derive_human_impact(row, asset_criticality_map)

        key = (exploitation, exposure, automatable, human_impact)
        decision = DEPLOYER_TREE.get(key, "scheduled")

        decisions.append({
            "ssvc_exploitation": exploitation,
            "ssvc_exposure": exposure,
            "ssvc_automatable": automatable,
            "ssvc_human_impact": human_impact,
            "ssvc_decision": decision,
            "ssvc_priority": PRIORITY_ORDER.get(decision, 2),
            "ssvc_sla_days": SSVC_SLA_DAYS.get(decision, 30),
        })

    ssvc_df = pd.DataFrame(decisions, index=df.index)
    result = pd.concat([df, ssvc_df], axis=1)

    # Log summary
    decision_counts = result["ssvc_decision"].value_counts()
    logger.info(f"SSVC results: {decision_counts.to_dict()}")

    return result


def get_ssvc_summary(df: pd.DataFrame) -> dict:
    """Generate SSVC summary statistics."""
    if "ssvc_decision" not in df.columns:
        return {}

    counts = df["ssvc_decision"].value_counts().to_dict()
    total = len(df)

    # Team breakdown
    team_ssvc = {}
    if "assignedTeam" in df.columns:
        for team in df["assignedTeam"].unique():
            team_df = df[df["assignedTeam"] == team]
            team_ssvc[team] = team_df["ssvc_decision"].value_counts().to_dict()

    return {
        "total": total,
        "immediate": counts.get("immediate", 0),
        "out_of_cycle": counts.get("out-of-cycle", 0),
        "scheduled": counts.get("scheduled", 0),
        "defer": counts.get("defer", 0),
        "immediate_pct": round(counts.get("immediate", 0) / total * 100, 1) if total else 0,
        "urgent_pct": round(
            (counts.get("immediate", 0) + counts.get("out-of-cycle", 0)) / total * 100, 1
        ) if total else 0,
        "team_breakdown": team_ssvc,
    }

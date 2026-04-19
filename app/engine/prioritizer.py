"""
Compute a composite risk score for each vulnerability finding.
Phase 2: includes asset criticality from database.
"""
import logging
import pandas as pd
from datetime import datetime, timezone
from app.config import (
    WEIGHT_CVSS, WEIGHT_EXPLOITABILITY, WEIGHT_AGE,
    WEIGHT_ASSET_EXPOSURE, WEIGHT_THREAT_INTEL, WEIGHT_EXPOSURE_COUNT,
    EXPLOITABILITY_SCORES, SEVERITY_SLA,
)

logger = logging.getLogger(__name__)


def compute_risk_scores(
    df: pd.DataFrame,
    asset_criticality_map: dict = None,
) -> pd.DataFrame:
    """Add riskScore (0-100), riskRating, and SLA columns.

    Args:
        df: DataFrame with vulnerability findings.
        asset_criticality_map: Optional dict of {device_name: criticality_score (1-5)}.
            If None, uses default criticality of 3 (High).
    """
    df = df.copy()
    now = datetime.now(timezone.utc)

    # CVSS Component (0-10 normalized to 0-1)
    cvss_norm = df["cvssScore"].clip(0, 10) / 10.0

    # Exploitability Component (0-1)
    exploit_norm = df["exploitabilityLevel"].map(EXPLOITABILITY_SCORES).fillna(0.1)

    # Age Component (days since first seen, capped at 365)
    if "firstSeenTimestamp" in df.columns:
        first_seen = df["firstSeenTimestamp"]
        if first_seen.dt.tz is None:
            first_seen = first_seen.dt.tz_localize("UTC")
        age_days = (now - first_seen).dt.days.clip(0, 365)
    else:
        age_days = pd.Series(0, index=df.index)
    age_norm = age_days / 365.0

    # Asset Criticality Component (1-5 normalized to 0-1)
    if asset_criticality_map:
        asset_scores = df["deviceName"].map(asset_criticality_map).fillna(3)
        logger.info(
            f"Asset criticality applied: {len(asset_criticality_map)} devices mapped, "
            f"range {asset_scores.min()}-{asset_scores.max()}"
        )
    else:
        asset_scores = pd.Series(3, index=df.index)  # Default: High (3)
    # Normalize: 1=0.2, 2=0.4, 3=0.6, 4=0.8, 5=1.0
    asset_norm = asset_scores / 5.0

    # Threat Intel Component (CISA KEV + EPSS)
    threat_norm = pd.Series(0.0, index=df.index)
    if "cisaKev" in df.columns:
        threat_norm = df["cisaKev"].astype(float)
    if "epssScore" in df.columns:
        threat_norm = threat_norm + df["epssScore"].fillna(0.0)
    threat_norm = threat_norm.clip(0, 1)

    # Exposure Component (device count per CVE)
    cve_device_count = df.groupby("cveId")["deviceName"].transform("nunique")
    max_devices = cve_device_count.max() if cve_device_count.max() > 0 else 1
    exposure_norm = cve_device_count / max_devices

    # Composite Score
    df["riskScore"] = (
        WEIGHT_CVSS * cvss_norm
        + WEIGHT_EXPLOITABILITY * exploit_norm
        + WEIGHT_AGE * age_norm
        + WEIGHT_ASSET_EXPOSURE * asset_norm
        + WEIGHT_THREAT_INTEL * threat_norm
        + WEIGHT_EXPOSURE_COUNT * exposure_norm
    ) * 100

    df["riskScore"] = df["riskScore"].round(1).clip(0, 100)

    # Store asset criticality for reporting
    df["assetCriticality"] = asset_scores.astype(int)

    # Risk Rating
    df["riskRating"] = pd.cut(
        df["riskScore"],
        bins=[-1, 25, 50, 75, 100],
        labels=["Low", "Medium", "High", "Critical"],
    )

    # SLA — adjusted by asset criticality
    # Mission-critical assets (4-5) get tighter SLAs (halved)
    base_sla = df["vulnerabilitySeverityLevel"].map(SEVERITY_SLA).fillna(90)
    sla_multiplier = pd.Series(1.0, index=df.index)
    sla_multiplier[asset_scores >= 5] = 0.5   # Mission-critical: half SLA
    sla_multiplier[asset_scores >= 4] = 0.75  # Critical: 75% SLA
    df["slaDays"] = (base_sla * sla_multiplier).astype(int)

    if "firstSeenTimestamp" in df.columns:
        df["slaDeadline"] = df["firstSeenTimestamp"] + pd.to_timedelta(
            df["slaDays"], unit="D"
        )
        sla_deadline = df["slaDeadline"]
        if sla_deadline.dt.tz is None:
            sla_deadline = sla_deadline.dt.tz_localize("UTC")
        df["slaBreached"] = sla_deadline < now
    else:
        df["slaDeadline"] = pd.NaT
        df["slaBreached"] = False

    df = df.sort_values("riskScore", ascending=False).reset_index(drop=True)
    return df

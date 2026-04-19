"""
Compute a composite risk score for each vulnerability finding.
"""
import pandas as pd
from datetime import datetime, timezone
from app.config import (
    WEIGHT_CVSS, WEIGHT_EXPLOITABILITY, WEIGHT_AGE,
    WEIGHT_ASSET_EXPOSURE, WEIGHT_THREAT_INTEL, WEIGHT_EXPOSURE_COUNT,
    EXPLOITABILITY_SCORES, SEVERITY_SLA,
)


def compute_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Add riskScore (0-100), riskRating, and SLA columns."""
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

    # Threat Intel Component (CISA KEV boost — enriched later, placeholder)
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
        + WEIGHT_ASSET_EXPOSURE * 0.5  # Placeholder until Phase 2 asset criticality
        + WEIGHT_THREAT_INTEL * threat_norm
        + WEIGHT_EXPOSURE_COUNT * exposure_norm
    ) * 100

    df["riskScore"] = df["riskScore"].round(1).clip(0, 100)

    # Risk Rating
    df["riskRating"] = pd.cut(
        df["riskScore"],
        bins=[-1, 25, 50, 75, 100],
        labels=["Low", "Medium", "High", "Critical"],
    )

    # SLA
    df["slaDays"] = df["vulnerabilitySeverityLevel"].map(SEVERITY_SLA).fillna(90)
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

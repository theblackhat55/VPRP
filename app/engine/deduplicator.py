"""
Group vulnerabilities by root-cause remediation action.
One KB patch may fix many CVEs — show it as one action item.
"""
import pandas as pd


def deduplicate_by_patch(df: pd.DataFrame) -> pd.DataFrame:
    """Create summary grouped by recommended patch action."""
    if "recommendedSecurityUpdate" not in df.columns:
        return pd.DataFrame()

    has_patch = df[
        df["recommendedSecurityUpdate"].notna()
        & (df["recommendedSecurityUpdate"].astype(str).str.strip() != "")
        & (df["recommendedSecurityUpdate"].astype(str).str.lower() != "nan")
    ].copy()

    if has_patch.empty:
        return pd.DataFrame()

    grouped = (
        has_patch.groupby(
            ["assignedTeam", "softwareVendor", "softwareName",
             "softwareVersion", "recommendedSecurityUpdate"],
            dropna=False,
        )
        .agg(
            cveCount=("cveId", "nunique"),
            maxCvss=("cvssScore", "max"),
            maxRiskScore=("riskScore", "max"),
            affectedDevices=("deviceName", "nunique"),
            cveList=("cveId", lambda x: ", ".join(sorted(x.unique()))),
            severities=(
                "vulnerabilitySeverityLevel",
                lambda x: ", ".join(sorted(x.unique())),
            ),
        )
        .reset_index()
    )

    grouped = grouped.sort_values("maxRiskScore", ascending=False).reset_index(
        drop=True
    )
    return grouped

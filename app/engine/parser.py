"""
Parse and normalize raw Defender CSV/JSON exports into a clean DataFrame.
Handles multiple file formats, deduplicates across uploads, and tracks source.
"""
import pandas as pd
import io
import json
from typing import List, Tuple


# Canonical column mapping — maps Defender column variations to standard names
COLUMN_MAP = {
    # Defender Portal CSV columns (title case & variations)
    "CVE ID": "cveId", "CVE Id": "cveId", "Cve Id": "cveId", "cve_id": "cveId",
    "CVSS Score": "cvssScore", "Cvss Score": "cvssScore", "cvss_score": "cvssScore",
    "Device ID": "deviceId", "Device Id": "deviceId", "device_id": "deviceId",
    "Machine ID": "deviceId", "Machine Id": "deviceId",
    "Device Name": "deviceName", "Device name": "deviceName", "device_name": "deviceName",
    "Machine Name": "deviceName", "Computer Name": "deviceName",
    "ComputerName": "deviceName", "Hostname": "deviceName",
    "OS Platform": "osPlatform", "Os Platform": "osPlatform",
    "os_platform": "osPlatform", "Operating System": "osPlatform", "OS": "osPlatform",
    "Software Vendor": "softwareVendor", "software_vendor": "softwareVendor",
    "Vendor": "softwareVendor",
    "Software Name": "softwareName", "software_name": "softwareName",
    "Product": "softwareName", "Product Name": "softwareName",
    "Software Version": "softwareVersion", "software_version": "softwareVersion",
    "Version": "softwareVersion", "Installed Version": "softwareVersion",
    "Vulnerability Severity Level": "vulnerabilitySeverityLevel",
    "Vulnerability Severity": "vulnerabilitySeverityLevel",
    "Severity": "vulnerabilitySeverityLevel", "severity": "vulnerabilitySeverityLevel",
    "Risk Level": "vulnerabilitySeverityLevel",
    "Exploitability Level": "exploitabilityLevel",
    "Exploitability": "exploitabilityLevel", "exploitability_level": "exploitabilityLevel",
    "Recommendation Reference": "recommendationReference",
    "recommendation_reference": "recommendationReference",
    "Recommended Security Update": "recommendedSecurityUpdate",
    "recommended_security_update": "recommendedSecurityUpdate",
    "Patch": "recommendedSecurityUpdate", "KB": "recommendedSecurityUpdate",
    "Recommended Security Update ID": "recommendedSecurityUpdateId",
    "KB ID": "recommendedSecurityUpdateId",
    "Security Update Available": "securityUpdateAvailable",
    "Patch Available": "securityUpdateAvailable",
    "First Seen Timestamp": "firstSeenTimestamp", "First Seen": "firstSeenTimestamp",
    "first_seen": "firstSeenTimestamp", "First Detected": "firstSeenTimestamp",
    "Last Seen Timestamp": "lastSeenTimestamp", "Last Seen": "lastSeenTimestamp",
    "last_seen": "lastSeenTimestamp", "Last Detected": "lastSeenTimestamp",
    "RBAC Group Name": "rbacGroupName", "RBAC Group": "rbacGroupName",
    "Device Group": "rbacGroupName",
    # Defender for Cloud
    "Resource Name": "deviceName", "Resource Id": "resourceId",
    "Resource ID": "resourceId", "Subscription": "subscription",
    "Subscription Name": "subscription", "Resource Group": "resourceGroup",
    # API JSON (camelCase pass-through)
    "cveId": "cveId", "cvssScore": "cvssScore", "deviceId": "deviceId",
    "deviceName": "deviceName", "osPlatform": "osPlatform",
    "softwareVendor": "softwareVendor", "softwareName": "softwareName",
    "softwareVersion": "softwareVersion",
    "vulnerabilitySeverityLevel": "vulnerabilitySeverityLevel",
    "exploitabilityLevel": "exploitabilityLevel",
    "recommendationReference": "recommendationReference",
    "recommendedSecurityUpdate": "recommendedSecurityUpdate",
    "recommendedSecurityUpdateId": "recommendedSecurityUpdateId",
    "securityUpdateAvailable": "securityUpdateAvailable",
    "firstSeenTimestamp": "firstSeenTimestamp",
    "lastSeenTimestamp": "lastSeenTimestamp",
    "rbacGroupName": "rbacGroupName",
}

REQUIRED_COLUMNS = [
    "cveId", "softwareVendor", "softwareName", "softwareVersion",
    "deviceName", "vulnerabilitySeverityLevel",
]

DEDUP_KEYS = ["cveId", "deviceName", "softwareName", "softwareVersion"]


class FileParseResult:
    """Result of parsing a single uploaded file."""

    def __init__(self, filename: str, df: pd.DataFrame,
                 source_type: str, row_count: int, warnings: list):
        self.filename = filename
        self.df = df
        self.source_type = source_type
        self.row_count = row_count
        self.warnings = warnings


def detect_source_type(df: pd.DataFrame, filename: str) -> str:
    """Auto-detect the source type of the uploaded file."""
    cols_lower = {c.lower() for c in df.columns}
    if "resource id" in cols_lower or "resourceid" in cols_lower:
        return "Defender for Cloud"
    if "exploitability level" in cols_lower or "exploitabilitylevel" in cols_lower:
        return "Defender TVM (CSV)"
    if filename.lower().endswith(".json"):
        return "Defender API (JSON)"
    return "Generic CSV"


def parse_uploaded_file(uploaded_file) -> FileParseResult:
    """Parse a Streamlit UploadedFile (CSV or JSON) into a FileParseResult."""
    filename = uploaded_file.name
    raw = uploaded_file.read()
    uploaded_file.seek(0)
    warnings = []

    if filename.lower().endswith(".json"):
        data = json.loads(raw)
        if "value" in data:
            data = data["value"]
        raw_df = pd.DataFrame(data)
    else:
        raw_df = None
        for encoding in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
            try:
                raw_df = pd.read_csv(
                    io.BytesIO(raw), low_memory=False, encoding=encoding
                )
                break
            except (UnicodeDecodeError, Exception):
                continue
        if raw_df is None:
            raise ValueError(f"Could not decode {filename} with any supported encoding")

    source_type = detect_source_type(raw_df, filename)
    df = _normalize(raw_df, warnings)
    df["_sourceFile"] = filename
    df["_sourceType"] = source_type

    return FileParseResult(
        filename=filename,
        df=df,
        source_type=source_type,
        row_count=len(df),
        warnings=warnings,
    )


def _normalize(df: pd.DataFrame, warnings: list) -> pd.DataFrame:
    """Rename columns, coerce types, fill gaps."""
    df.columns = df.columns.str.strip()

    # Rename to canonical names
    rename = {col: COLUMN_MAP[col] for col in df.columns if col in COLUMN_MAP}
    df = df.rename(columns=rename)

    # Keep known columns
    known = set(COLUMN_MAP.values()) | {"resourceId", "subscription", "resourceGroup"}
    available = [c for c in df.columns if c in known]
    dropped = [c for c in df.columns if c not in known and not c.startswith("_")]
    if dropped:
        sample = dropped[:10]
        suffix = "..." if len(dropped) > 10 else ""
        warnings.append(f"Dropped unmapped columns: {sample}{suffix}")
    df = df[available].copy()

    # Check required columns
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Missing required columns: {missing}. "
            f"Available after mapping: {list(df.columns)}"
        )

    # Type coercions
    if "cvssScore" in df.columns:
        df["cvssScore"] = pd.to_numeric(df["cvssScore"], errors="coerce")

    for ts_col in ("firstSeenTimestamp", "lastSeenTimestamp"):
        if ts_col in df.columns:
            df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")

    if "securityUpdateAvailable" in df.columns:
        bool_map = {
            True: True, False: False, "true": True, "false": False,
            "True": True, "False": False, "Yes": True, "No": False,
            "yes": True, "no": False, 1: True, 0: False,
        }
        df["securityUpdateAvailable"] = df["securityUpdateAvailable"].map(bool_map)

    # Fill defaults
    if "cvssScore" not in df.columns:
        df["cvssScore"] = 0.0
    df["cvssScore"] = df["cvssScore"].fillna(0.0)

    if "exploitabilityLevel" not in df.columns:
        df["exploitabilityLevel"] = "NoExploit"
    df["exploitabilityLevel"] = df["exploitabilityLevel"].fillna("NoExploit")

    df["vulnerabilitySeverityLevel"] = df["vulnerabilitySeverityLevel"].fillna("Unknown")

    # Lowercase key text fields for reliable matching
    for col in ("softwareVendor", "softwareName", "recommendationReference"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().str.strip()

    if "deviceName" in df.columns:
        df["deviceName"] = df["deviceName"].astype(str).str.lower().str.strip()

    # Drop rows with no CVE
    df = df[
        df["cveId"].notna()
        & (df["cveId"].astype(str).str.strip() != "")
        & (df["cveId"].astype(str).str.lower() != "nan")
        & (df["cveId"].astype(str).str.lower() != "none")
    ].copy()

    df = df.reset_index(drop=True)
    return df


def merge_multi_upload(parse_results: List[FileParseResult]) -> Tuple[pd.DataFrame, dict]:
    """Merge multiple parsed DataFrames with cross-file deduplication."""
    if not parse_results:
        raise ValueError("No files to merge")

    frames = [r.df for r in parse_results]
    combined = pd.concat(frames, ignore_index=True)
    total_before = len(combined)

    # Deduplicate: keep latest lastSeenTimestamp for each unique finding
    dedup_cols = [c for c in DEDUP_KEYS if c in combined.columns]
    if "lastSeenTimestamp" in combined.columns:
        combined = combined.sort_values(
            "lastSeenTimestamp", ascending=False, na_position="last"
        )
    combined = combined.drop_duplicates(subset=dedup_cols, keep="first")
    combined = combined.reset_index(drop=True)
    total_after = len(combined)

    stats = {
        "files_processed": len(parse_results),
        "file_details": [
            {
                "filename": r.filename,
                "source_type": r.source_type,
                "rows_parsed": r.row_count,
                "warnings": r.warnings,
            }
            for r in parse_results
        ],
        "total_rows_before_dedup": total_before,
        "total_rows_after_dedup": total_after,
        "duplicates_removed": total_before - total_after,
        "unique_cves": int(combined["cveId"].nunique()),
        "unique_devices": int(combined["deviceName"].nunique()),
        "source_types_detected": list({r.source_type for r in parse_results}),
    }

    return combined, stats

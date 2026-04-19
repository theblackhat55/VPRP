"""
Database service layer — save and query scan data.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import pandas as pd
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.models.database import get_session
from app.models.schemas import (
    ScanUpload, Finding, Asset, ClassificationRule, ScanSummary,
)

logger = logging.getLogger(__name__)


# ── Scan Upload ──────────────────────────────────────────

def save_scan_upload(
    filename: str,
    source_type: str,
    rows_parsed: int,
    rows_after_dedup: int,
    duplicates_removed: int,
    unique_cves: int,
    unique_devices: int,
    uploaded_by: str = "system",
    notes: str = None,
    session: Optional[Session] = None,
) -> ScanUpload:
    """Record a scan upload in the database."""
    own_session = session is None
    if own_session:
        session = get_session()
    try:
        upload = ScanUpload(
            filename=filename,
            source_type=source_type,
            rows_parsed=rows_parsed,
            rows_after_dedup=rows_after_dedup,
            duplicates_removed=duplicates_removed,
            unique_cves=unique_cves,
            unique_devices=unique_devices,
            uploaded_by=uploaded_by,
            notes=notes,
        )
        session.add(upload)
        if own_session:
            session.commit()
            session.refresh(upload)
        return upload
    except Exception as e:
        if own_session:
            session.rollback()
        logger.error(f"Failed to save scan upload: {e}")
        raise
    finally:
        if own_session:
            session.close()


# ── Findings ─────────────────────────────────────────────

def save_findings(df: pd.DataFrame, scan_upload_id, session: Optional[Session] = None) -> int:
    """Bulk-save processed findings DataFrame to the database.

    Returns number of rows saved.
    """
    own_session = session is None
    if own_session:
        session = get_session()

    col_map = {
        "cveId": "cve_id",
        "cvssScore": "cvss_score",
        "vulnerabilitySeverityLevel": "vulnerability_severity",
        "exploitabilityLevel": "exploitability_level",
        "softwareVendor": "software_vendor",
        "softwareName": "software_name",
        "softwareVersion": "software_version",
        "deviceId": "device_id",
        "deviceName": "device_name",
        "osPlatform": "os_platform",
        "recommendedSecurityUpdate": "recommended_security_update",
        "recommendedSecurityUpdateId": "recommended_security_update_id",
        "securityUpdateAvailable": "security_update_available",
        "recommendationReference": "recommendation_reference",
        "assignedTeam": "assigned_team",
        "classificationTier": "classification_tier",
        "riskScore": "risk_score",
        "riskRating": "risk_rating",
        "slaDays": "sla_days",
        "slaDeadline": "sla_deadline",
        "slaBreached": "sla_breached",
        "cisaKev": "cisa_kev",
        "epssScore": "epss_score",
        "firstSeenTimestamp": "first_seen",
        "lastSeenTimestamp": "last_seen",
        "_sourceFile": "source_file",
        "_sourceType": "source_type",
    }

    try:
        records = []
        for _, row in df.iterrows():
            finding_data = {"scan_upload_id": scan_upload_id}
            for df_col, db_col in col_map.items():
                if df_col in row.index:
                    val = row[df_col]
                    # Handle NaN/None
                    if pd.isna(val):
                        val = None
                    # Handle boolean
                    elif db_col in ("security_update_available", "sla_breached", "cisa_kev"):
                        val = bool(val) if val is not None else False
                    # Handle float
                    elif db_col in ("cvss_score", "risk_score", "epss_score"):
                        val = float(val) if val is not None else 0.0
                    # Handle int
                    elif db_col == "sla_days":
                        val = int(val) if val is not None else None
                    finding_data[db_col] = val

            records.append(Finding(**finding_data))

        # Bulk insert in batches
        batch_size = 1000
        for i in range(0, len(records), batch_size):
            session.bulk_save_objects(records[i:i + batch_size])

        if own_session:
            session.commit()

        logger.info(f"Saved {len(records)} findings to database")
        return len(records)

    except Exception as e:
        if own_session:
            session.rollback()
        logger.error(f"Failed to save findings: {e}")
        raise
    finally:
        if own_session:
            session.close()


# ── Scan Summary ─────────────────────────────────────────

def save_scan_summary(df: pd.DataFrame, scan_upload_id, session: Optional[Session] = None) -> ScanSummary:
    """Compute and save summary statistics for a scan."""
    own_session = session is None
    if own_session:
        session = get_session()

    try:
        sev_counts = df["vulnerabilitySeverityLevel"].value_counts()
        team_breakdown = (
            df.groupby("assignedTeam")
            .agg(
                count=("cveId", "count"),
                unique_cves=("cveId", "nunique"),
                max_risk=("riskScore", "max") if "riskScore" in df.columns else ("cvssScore", "max"),
            )
            .to_dict("index")
        )

        summary = ScanSummary(
            scan_upload_id=scan_upload_id,
            total_findings=len(df),
            unique_cves=df["cveId"].nunique(),
            unique_devices=df["deviceName"].nunique(),
            critical_count=int(sev_counts.get("Critical", 0)),
            high_count=int(sev_counts.get("High", 0)),
            medium_count=int(sev_counts.get("Medium", 0)),
            low_count=int(sev_counts.get("Low", 0)),
            kev_count=int(df["cisaKev"].sum()) if "cisaKev" in df.columns else 0,
            sla_breached_count=int(df["slaBreached"].sum()) if "slaBreached" in df.columns else 0,
            unmatched_count=int((df.get("classificationTier", pd.Series()) == "unmatched").sum()),
            avg_risk_score=float(df["riskScore"].mean()) if "riskScore" in df.columns else 0.0,
            max_risk_score=float(df["riskScore"].max()) if "riskScore" in df.columns else 0.0,
            team_breakdown=team_breakdown,
        )
        session.add(summary)

        if own_session:
            session.commit()
            session.refresh(summary)

        logger.info(f"Saved scan summary: {summary.total_findings} findings")
        return summary

    except Exception as e:
        if own_session:
            session.rollback()
        logger.error(f"Failed to save scan summary: {e}")
        raise
    finally:
        if own_session:
            session.close()


# ── Assets ───────────────────────────────────────────────

def upsert_assets_from_findings(df: pd.DataFrame, session: Optional[Session] = None) -> int:
    """Create or update assets from finding data. Returns count of new assets."""
    own_session = session is None
    if own_session:
        session = get_session()

    try:
        devices = (
            df.groupby("deviceName", dropna=False)
            .agg(
                device_id=("deviceId", "first") if "deviceId" in df.columns else ("deviceName", "first"),
                os_platform=("osPlatform", "first") if "osPlatform" in df.columns else ("deviceName", "first"),
                last_seen=("lastSeenTimestamp", "max") if "lastSeenTimestamp" in df.columns else ("deviceName", "first"),
            )
            .reset_index()
        )

        new_count = 0
        for _, row in devices.iterrows():
            device_name = str(row["deviceName"])
            if not device_name or device_name == "nan":
                continue

            existing = session.query(Asset).filter(Asset.device_name == device_name).first()
            if existing:
                existing.last_seen = datetime.now(timezone.utc)
                if row.get("os_platform") and str(row["os_platform"]) != "nan":
                    existing.os_platform = str(row["os_platform"])
            else:
                asset = Asset(
                    device_name=device_name,
                    device_id=str(row.get("device_id", "")) if str(row.get("device_id", "")) != "nan" else None,
                    os_platform=str(row.get("os_platform", "")) if str(row.get("os_platform", "")) != "nan" else None,
                )
                session.add(asset)
                new_count += 1

        if own_session:
            session.commit()

        logger.info(f"Upserted assets: {new_count} new, {len(devices) - new_count} updated")
        return new_count

    except Exception as e:
        if own_session:
            session.rollback()
        logger.error(f"Failed to upsert assets: {e}")
        raise
    finally:
        if own_session:
            session.close()


# ── Query Helpers ────────────────────────────────────────

def get_scan_history(limit: int = 20) -> list[dict]:
    """Return recent scan uploads."""
    session = get_session()
    try:
        uploads = (
            session.query(ScanUpload)
            .order_by(desc(ScanUpload.uploaded_at))
            .limit(limit)
            .all()
        )
        return [
            {
                "id": str(u.id),
                "filename": u.filename,
                "source_type": u.source_type,
                "rows_parsed": u.rows_parsed,
                "rows_after_dedup": u.rows_after_dedup,
                "unique_cves": u.unique_cves,
                "unique_devices": u.unique_devices,
                "uploaded_at": u.uploaded_at.isoformat() if u.uploaded_at else None,
                "status": u.status,
            }
            for u in uploads
        ]
    finally:
        session.close()


def get_trend_data(limit: int = 30) -> pd.DataFrame:
    """Return scan summaries for trend analysis."""
    session = get_session()
    try:
        summaries = (
            session.query(ScanSummary)
            .order_by(ScanSummary.scan_date)
            .limit(limit)
            .all()
        )
        if not summaries:
            return pd.DataFrame()

        return pd.DataFrame([
            {
                "scan_date": s.scan_date,
                "total_findings": s.total_findings,
                "unique_cves": s.unique_cves,
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
                "low": s.low_count,
                "kev_count": s.kev_count,
                "sla_breached": s.sla_breached_count,
                "avg_risk": s.avg_risk_score,
            }
            for s in summaries
        ])
    finally:
        session.close()


def get_asset_criticality_map() -> dict:
    """Return {device_name: criticality_score} for risk scoring."""
    session = get_session()
    try:
        assets = session.query(Asset.device_name, Asset.asset_criticality).all()
        return {a.device_name: a.asset_criticality for a in assets}
    finally:
        session.close()

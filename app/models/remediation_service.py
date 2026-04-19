"""
Remediation workflow service layer.
Handles status transitions, exception management, and audit logging.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

import pandas as pd
from sqlalchemy import func, case, and_
from sqlalchemy.orm import Session

from app.models.database import get_session
from app.models.schemas import Finding, RemediationAuditLog, ScanUpload

logger = logging.getLogger(__name__)

# ── Valid status transitions ─────────────────────────────
VALID_STATUSES = ["open", "in_progress", "remediated", "accepted_risk", "exception", "false_positive"]
VALID_SUBSTATUSES = {
    "open": ["new", "reopened", "sla_breached"],
    "in_progress": ["patch_scheduled", "patch_testing", "awaiting_change_window", "blocked"],
    "remediated": ["patch_applied", "config_changed", "compensating_control"],
    "accepted_risk": ["business_justified", "temporary", "permanent"],
    "exception": ["pending_approval", "approved", "denied", "expired"],
    "false_positive": ["verified", "disputed"],
}
VALID_TRANSITIONS = {
    "open": ["in_progress", "accepted_risk", "exception", "false_positive", "remediated"],
    "in_progress": ["remediated", "open", "accepted_risk", "exception"],
    "remediated": ["open"],  # reopen if regression
    "accepted_risk": ["open", "in_progress"],
    "exception": ["open", "in_progress"],
    "false_positive": ["open"],
}


def get_findings_for_remediation(
    status_filter: list = None,
    team_filter: list = None,
    severity_filter: list = None,
    sla_breached_only: bool = False,
    search_cve: str = None,
    limit: int = 500,
    session: Session = None,
) -> pd.DataFrame:
    """Query findings with remediation context for the dashboard."""
    _session = session or get_session()
    try:
        q = _session.query(Finding)

        if status_filter:
            q = q.filter(Finding.remediation_status.in_(status_filter))
        if team_filter:
            q = q.filter(Finding.assigned_team.in_(team_filter))
        if severity_filter:
            q = q.filter(Finding.vulnerability_severity.in_(severity_filter))
        if sla_breached_only:
            q = q.filter(Finding.sla_breached == True)
        if search_cve:
            q = q.filter(Finding.cve_id.ilike(f"%{search_cve}%"))

        q = q.order_by(Finding.risk_score.desc()).limit(limit)
        rows = q.all()

        if not rows:
            return pd.DataFrame()

        data = []
        for f in rows:
            data.append({
                "id": str(f.id),
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "vulnerability_severity": f.vulnerability_severity,
                "risk_score": f.risk_score,
                "risk_rating": f.risk_rating,
                "device_name": f.device_name,
                "software_name": f.software_name,
                "assigned_team": f.assigned_team,
                "assigned_to": f.assigned_to,
                "remediation_status": f.remediation_status,
                "remediation_substatus": f.remediation_substatus,
                "remediation_notes": f.remediation_notes,
                "remediation_updated_at": f.remediation_updated_at,
                "remediation_updated_by": f.remediation_updated_by,
                "sla_days": f.sla_days,
                "sla_deadline": f.sla_deadline,
                "sla_breached": f.sla_breached,
                "ticket_id": f.ticket_id,
                "ticket_url": f.ticket_url,
                "exception_status": f.exception_status,
                "exception_expiry": f.exception_expiry,
                "first_seen": f.first_seen,
                "scan_upload_id": str(f.scan_upload_id),
            })
        return pd.DataFrame(data)
    finally:
        if not session:
            _session.close()


def update_finding_status(
    finding_id: str,
    new_status: str,
    substatus: str = None,
    notes: str = None,
    performed_by: str = "admin",
    assigned_to: str = None,
    ticket_id: str = None,
    ticket_url: str = None,
    session: Session = None,
) -> bool:
    """Update remediation status with validation and audit logging."""
    _session = session or get_session()
    try:
        finding = _session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.error(f"Finding {finding_id} not found")
            return False

        old_status = finding.remediation_status
        old_substatus = finding.remediation_substatus

        # Validate transition
        if new_status not in VALID_STATUSES:
            logger.error(f"Invalid status: {new_status}")
            return False
        allowed = VALID_TRANSITIONS.get(old_status, [])
        if new_status != old_status and new_status not in allowed:
            logger.error(f"Invalid transition: {old_status} -> {new_status}")
            return False
        if substatus and substatus not in VALID_SUBSTATUSES.get(new_status, []):
            logger.warning(f"Unknown substatus '{substatus}' for status '{new_status}'")

        # Update finding
        finding.remediation_status = new_status
        finding.remediation_substatus = substatus
        finding.remediation_updated_at = datetime.utcnow()
        finding.remediation_updated_by = performed_by
        if notes:
            finding.remediation_notes = notes
        if assigned_to is not None:
            finding.assigned_to = assigned_to
        if ticket_id is not None:
            finding.ticket_id = ticket_id
        if ticket_url is not None:
            finding.ticket_url = ticket_url

        # Audit log
        audit = RemediationAuditLog(
            finding_id=finding.id,
            action="status_change",
            old_status=old_status,
            new_status=new_status,
            old_substatus=old_substatus,
            new_substatus=substatus,
            notes=notes,
            performed_by=performed_by,
        )
        _session.add(audit)
        _session.commit()
        logger.info(f"Finding {finding_id}: {old_status} -> {new_status} by {performed_by}")
        return True
    except Exception as e:
        _session.rollback()
        logger.error(f"Status update failed: {e}")
        return False
    finally:
        if not session:
            _session.close()


def bulk_update_status(
    finding_ids: list,
    new_status: str,
    substatus: str = None,
    notes: str = None,
    performed_by: str = "admin",
) -> int:
    """Bulk status update with audit trail for each finding."""
    updated = 0
    for fid in finding_ids:
        if update_finding_status(fid, new_status, substatus, notes, performed_by):
            updated += 1
    return updated


def request_exception(
    finding_id: str,
    reason: str,
    requested_by: str,
    expiry_days: int = 90,
    session: Session = None,
) -> bool:
    """Submit a risk-acceptance / exception request."""
    _session = session or get_session()
    try:
        finding = _session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return False

        old_status = finding.remediation_status
        finding.remediation_status = "exception"
        finding.remediation_substatus = "pending_approval" if old_status != "exception" else finding.remediation_substatus
        finding.exception_status = "pending_approval"
        finding.exception_reason = reason
        finding.exception_requested_by = requested_by
        finding.exception_requested_at = datetime.utcnow()
        finding.exception_expiry = datetime.utcnow() + timedelta(days=expiry_days)
        finding.remediation_updated_at = datetime.utcnow()
        finding.remediation_updated_by = requested_by

        audit = RemediationAuditLog(
            finding_id=finding.id,
            action="exception_requested",
            old_status=old_status,
            new_status="exception",
            notes=f"Reason: {reason} | Expiry: {expiry_days} days",
            performed_by=requested_by,
        )
        _session.add(audit)
        _session.commit()
        return True
    except Exception as e:
        _session.rollback()
        logger.error(f"Exception request failed: {e}")
        return False
    finally:
        if not session:
            _session.close()


def approve_exception(
    finding_id: str,
    approved_by: str,
    notes: str = None,
    session: Session = None,
) -> bool:
    """Approve a pending exception request."""
    _session = session or get_session()
    try:
        finding = _session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding or finding.exception_status != "pending_approval":
            return False

        finding.exception_status = "approved"
        finding.exception_approved_by = approved_by
        finding.exception_approved_at = datetime.utcnow()
        finding.remediation_substatus = "approved"
        finding.remediation_updated_at = datetime.utcnow()
        finding.remediation_updated_by = approved_by

        audit = RemediationAuditLog(
            finding_id=finding.id,
            action="exception_approved",
            old_status="exception",
            new_status="exception",
            old_substatus="pending_approval",
            new_substatus="approved",
            notes=notes,
            performed_by=approved_by,
        )
        _session.add(audit)
        _session.commit()
        return True
    except Exception as e:
        _session.rollback()
        logger.error(f"Exception approval failed: {e}")
        return False
    finally:
        if not session:
            _session.close()


def deny_exception(
    finding_id: str,
    denied_by: str,
    notes: str = None,
    session: Session = None,
) -> bool:
    """Deny exception — revert finding to open."""
    _session = session or get_session()
    try:
        finding = _session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return False

        finding.exception_status = "denied"
        finding.remediation_status = "open"
        finding.remediation_substatus = "reopened"
        finding.remediation_updated_at = datetime.utcnow()
        finding.remediation_updated_by = denied_by

        audit = RemediationAuditLog(
            finding_id=finding.id,
            action="exception_denied",
            old_status="exception",
            new_status="open",
            notes=notes,
            performed_by=denied_by,
        )
        _session.add(audit)
        _session.commit()
        return True
    except Exception as e:
        _session.rollback()
        logger.error(f"Exception denial failed: {e}")
        return False
    finally:
        if not session:
            _session.close()


def get_remediation_summary(session: Session = None) -> dict:
    """Aggregate remediation KPIs across all findings."""
    _session = session or get_session()
    try:
        total = _session.query(func.count(Finding.id)).scalar() or 0
        status_counts = dict(
            _session.query(Finding.remediation_status, func.count(Finding.id))
            .group_by(Finding.remediation_status).all()
        )
        sla_breached = _session.query(func.count(Finding.id)).filter(
            Finding.sla_breached == True,
            Finding.remediation_status.in_(["open", "in_progress"]),
        ).scalar() or 0

        severity_status = _session.query(
            Finding.vulnerability_severity,
            Finding.remediation_status,
            func.count(Finding.id),
        ).group_by(Finding.vulnerability_severity, Finding.remediation_status).all()

        team_status = _session.query(
            Finding.assigned_team,
            Finding.remediation_status,
            func.count(Finding.id),
        ).group_by(Finding.assigned_team, Finding.remediation_status).all()

        pending_exceptions = _session.query(func.count(Finding.id)).filter(
            Finding.exception_status == "pending_approval"
        ).scalar() or 0

        return {
            "total_findings": total,
            "status_counts": status_counts,
            "sla_breached_active": sla_breached,
            "open_count": status_counts.get("open", 0),
            "in_progress_count": status_counts.get("in_progress", 0),
            "remediated_count": status_counts.get("remediated", 0),
            "accepted_risk_count": status_counts.get("accepted_risk", 0),
            "exception_count": status_counts.get("exception", 0),
            "false_positive_count": status_counts.get("false_positive", 0),
            "pending_exceptions": pending_exceptions,
            "remediation_rate": round(
                (status_counts.get("remediated", 0) / total * 100) if total > 0 else 0, 1
            ),
            "severity_status": severity_status,
            "team_status": team_status,
        }
    finally:
        if not session:
            _session.close()


def get_audit_log(finding_id: str = None, limit: int = 100, session: Session = None) -> pd.DataFrame:
    """Retrieve audit log entries."""
    _session = session or get_session()
    try:
        q = _session.query(RemediationAuditLog)
        if finding_id:
            q = q.filter(RemediationAuditLog.finding_id == finding_id)
        q = q.order_by(RemediationAuditLog.performed_at.desc()).limit(limit)
        rows = q.all()

        if not rows:
            return pd.DataFrame()

        data = []
        for r in rows:
            data.append({
                "performed_at": r.performed_at,
                "action": r.action,
                "old_status": r.old_status,
                "new_status": r.new_status,
                "notes": r.notes,
                "performed_by": r.performed_by,
                "finding_id": str(r.finding_id),
            })
        return pd.DataFrame(data)
    finally:
        if not session:
            _session.close()


def check_expired_exceptions(session: Session = None) -> int:
    """Reopen findings with expired exceptions. Run periodically."""
    _session = session or get_session()
    try:
        now = datetime.utcnow()
        expired = _session.query(Finding).filter(
            Finding.exception_status == "approved",
            Finding.exception_expiry < now,
            Finding.remediation_status == "exception",
        ).all()

        count = 0
        for f in expired:
            f.remediation_status = "open"
            f.remediation_substatus = "reopened"
            f.exception_status = "expired"
            f.remediation_updated_at = now
            f.remediation_updated_by = "system"

            audit = RemediationAuditLog(
                finding_id=f.id,
                action="exception_expired",
                old_status="exception",
                new_status="open",
                notes="Exception expired — auto-reopened",
                performed_by="system",
            )
            _session.add(audit)
            count += 1

        if count > 0:
            _session.commit()
            logger.info(f"Reopened {count} expired exceptions")
        return count
    except Exception as e:
        _session.rollback()
        logger.error(f"Exception expiry check failed: {e}")
        return 0
    finally:
        if not session:
            _session.close()

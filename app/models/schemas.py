"""
SQLAlchemy ORM models for VPRP platform.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Float, Integer, Boolean, DateTime,
    Text, ForeignKey, Index, UniqueConstraint, JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.models.database import Base


def utcnow():
    return datetime.now(timezone.utc)


# ── Scan Upload Tracking ─────────────────────────────────
class ScanUpload(Base):
    __tablename__ = "scan_uploads"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(String(500), nullable=False)
    source_type = Column(String(100))

    rows_parsed = Column(Integer, default=0)
    rows_after_dedup = Column(Integer, default=0)
    duplicates_removed = Column(Integer, default=0)
    unique_cves = Column(Integer, default=0)
    unique_devices = Column(Integer, default=0)
    uploaded_at = Column(DateTime(timezone=True), default=utcnow)
    uploaded_by = Column(String(200), default="system")
    status = Column(String(50), default="completed")  # completed, failed, processing
    notes = Column(Text)

    findings = relationship("Finding", back_populates="scan_upload", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanUpload {self.filename} ({self.rows_parsed} rows)>"


# ── Vulnerability Findings ────────────────────────────────
class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_upload_id = Column(UUID(as_uuid=True), ForeignKey("scan_uploads.id"), nullable=False)

    # Core vulnerability data
    cve_id = Column(String(30), nullable=False, index=True)
    cvss_score = Column(Float, default=0.0)
    vulnerability_severity = Column(String(20))
    exploitability_level = Column(String(50))

    # Software context
    software_vendor = Column(String(300))
    software_name = Column(String(300))
    software_version = Column(String(100))

    # Device context
    device_id = Column(String(200))
    device_name = Column(String(300), index=True)
    os_platform = Column(String(100))

    # Remediation
    recommended_security_update = Column(String(500))
    recommended_security_update_id = Column(String(200))
    security_update_available = Column(Boolean, default=False)
    recommendation_reference = Column(String(500))

    # Classification
    assigned_team = Column(String(200), index=True)
    classification_tier = Column(String(20))  # rule, custom_rule, llm, unmatched

    # Risk scoring
    risk_score = Column(Float, default=0.0)
    risk_rating = Column(String(20))
    sla_days = Column(Integer)
    sla_deadline = Column(DateTime(timezone=True))
    sla_breached = Column(Boolean, default=False)

    # Enrichment
    cisa_kev = Column(Boolean, default=False)
    epss_score = Column(Float)

    # Timestamps
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Source tracking
    source_file = Column(String(500))
    source_type = Column(String(100))

    # ── Remediation tracking ──
    remediation_status = Column(String(30), nullable=False, default="open")
    remediation_substatus = Column(String(50))
    remediation_notes = Column(Text)
    remediation_updated_at = Column(DateTime)
    remediation_updated_by = Column(String(200))
    assigned_to = Column(String(200))
    ticket_id = Column(String(100))
    ticket_url = Column(String(500))

    # ── Exception / risk-acceptance ──
    exception_status = Column(String(30))
    exception_reason = Column(Text)
    exception_requested_by = Column(String(200))
    exception_requested_at = Column(DateTime)
    exception_approved_by = Column(String(200))
    exception_approved_at = Column(DateTime)
    exception_expiry = Column(DateTime)

    scan_upload = relationship("ScanUpload", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_cve_device", "cve_id", "device_name"),
        Index("ix_findings_team_severity", "assigned_team", "vulnerability_severity"),
        Index("ix_findings_risk", "risk_score"),
        Index("ix_findings_scan", "scan_upload_id"),
    )

    def __repr__(self):
        return f"<Finding {self.cve_id} on {self.device_name}>"


# ── Asset Registry ────────────────────────────────────────
class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_name = Column(String(300), unique=True, nullable=False, index=True)
    device_id = Column(String(200))
    os_platform = Column(String(100))
    ip_address = Column(String(50))
    fqdn = Column(String(500))

    # Business context
    asset_criticality = Column(Integer, default=3)  # 1=Low, 2=Medium, 3=High, 4=Critical, 5=Mission-Critical
    business_unit = Column(String(200))
    environment = Column(String(50), default="production")  # production, staging, development, test
    owner = Column(String(200))
    location = Column(String(200))
    tags = Column(JSON, default=dict)

    # Metadata
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    def __repr__(self):
        return f"<Asset {self.device_name} (criticality={self.asset_criticality})>"


# ── Custom Classification Rules (DB-backed) ──────────────
class ClassificationRule(Base):
    __tablename__ = "classification_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    match_field = Column(String(100), nullable=False)
    match_type = Column(String(20), nullable=False)  # contains, equals, startswith
    match_value = Column(String(500), nullable=False)
    team_name = Column(String(200), nullable=False)
    created_by = Column(String(200), default="admin")
    created_at = Column(DateTime(timezone=True), default=utcnow)
    is_active = Column(Boolean, default=True)
    notes = Column(Text)

    __table_args__ = (
        UniqueConstraint("match_field", "match_type", "match_value", "team_name",
                         name="uq_classification_rule"),
    )

    def __repr__(self):
        return f"<Rule {self.match_field} {self.match_type} '{self.match_value}' → {self.team_name}>"


# ── Scan Summary (for historical trends) ─────────────────
class ScanSummary(Base):
    __tablename__ = "scan_summaries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_upload_id = Column(UUID(as_uuid=True), ForeignKey("scan_uploads.id"))
    scan_date = Column(DateTime(timezone=True), default=utcnow)

    total_findings = Column(Integer, default=0)
    unique_cves = Column(Integer, default=0)
    unique_devices = Column(Integer, default=0)

    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    kev_count = Column(Integer, default=0)
    sla_breached_count = Column(Integer, default=0)
    unmatched_count = Column(Integer, default=0)

    avg_risk_score = Column(Float, default=0.0)
    max_risk_score = Column(Float, default=0.0)

    # Per-team breakdown stored as JSON
    team_breakdown = Column(JSON, default=dict)

    created_at = Column(DateTime(timezone=True), default=utcnow)

    def __repr__(self):
        return f"<ScanSummary {self.scan_date} ({self.total_findings} findings)>"


class RemediationAuditLog(Base):
    """Tracks all status changes for audit compliance."""
    __tablename__ = "remediation_audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(50), nullable=False)
    old_status = Column(String(30))
    new_status = Column(String(30))
    old_substatus = Column(String(50))
    new_substatus = Column(String(50))
    notes = Column(Text)
    performed_by = Column(String(200), nullable=False, default="system")
    performed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    finding = relationship("Finding", backref="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action} on {self.finding_id} by {self.performed_by}>"


class User(Base):
    """Local user accounts with hashed passwords."""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), nullable=False, unique=True, index=True)
    email = Column(String(300), nullable=False, unique=True, index=True)
    password_hash = Column(String(500), nullable=False)
    full_name = Column(String(200))
    role = Column(String(30), nullable=False, default="viewer")  # admin, analyst, team_lead, viewer
    team = Column(String(200))
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime)
    login_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(100), default="system")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

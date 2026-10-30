import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Float, Integer, Boolean, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Organization
# ─────────────────────────────────────────────────────────────────────────────
class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(200))
    industry: Mapped[str] = mapped_column(String(100))
    domain: Mapped[str] = mapped_column(String(100))
    risk_threshold: Mapped[int] = mapped_column(Integer, default=70)
    compliance_frameworks: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    logs: Mapped[List["SecurityLog"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    incidents: Mapped[List["Incident"]] = relationship(back_populates="organization", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────────────────
# SecurityLog — raw uploaded file record
# ─────────────────────────────────────────────────────────────────────────────
class SecurityLog(Base):
    __tablename__ = "security_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    original_filename: Mapped[str] = mapped_column(String(500))
    stored_filename: Mapped[str] = mapped_column(String(500))
    sha256_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    domain: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(50), default="UPLOADED")
    # UPLOADED | PARSING | PARSED | ANALYZING | ANALYZED | INVESTIGATING | COMPLETE | ERROR
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    attack_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="logs")
    events: Mapped[List["NormalizedEvent"]] = relationship(back_populates="log", cascade="all, delete-orphan")
    alerts: Mapped[List["Alert"]] = relationship(back_populates="log", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────────────────
# NormalizedEvent — CES-format events parsed from log file
# ─────────────────────────────────────────────────────────────────────────────
class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    log_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_logs.id"))
    org_id: Mapped[str] = mapped_column(String(36))
    domain: Mapped[str] = mapped_column(String(100))
    timestamp: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    severity: Mapped[int] = mapped_column(Integer, default=0)
    severity_label: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    is_attack: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    attack_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    raw_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra_fields: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    log: Mapped["SecurityLog"] = relationship(back_populates="events")


# ─────────────────────────────────────────────────────────────────────────────
# Alert — threat detection output
# ─────────────────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    log_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_logs.id"))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    severity_score: Mapped[float] = mapped_column(Float, default=0.0)   # 0–10
    confidence: Mapped[float] = mapped_column(Float, default=0.0)        # 0–100 %
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    attack_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    domain: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(50), default="OPEN")   # OPEN | ACKNOWLEDGED | RESOLVED
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    event_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    log: Mapped["SecurityLog"] = relationship(back_populates="alerts")
    incident: Mapped[Optional["Incident"]] = relationship(back_populates="alert", uselist=False)


# ─────────────────────────────────────────────────────────────────────────────
# Incident — investigation record
# ─────────────────────────────────────────────────────────────────────────────
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"))
    title: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(50), default="OPEN")
    # OPEN | INVESTIGATING | AWAITING_APPROVAL | APPROVED | REJECTED | REMEDIATING | COMPLETE
    risk_score: Mapped[int] = mapped_column(Integer, default=0)     # 0–100
    timeline: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    integrity_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    # VERIFIED | TAMPERED | PENDING
    integrity_original_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    integrity_current_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    recommended_playbook_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    operator_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="incidents")
    alert: Mapped["Alert"] = relationship(back_populates="incident")
    audit_entries: Mapped[List["AuditEntry"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    response_logs: Mapped[List["ResponseLog"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    reports: Mapped[List["Report"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────────────────
# Playbook — response action library
# ─────────────────────────────────────────────────────────────────────────────
class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    code: Mapped[str] = mapped_column(String(50), unique=True)   # e.g. PB-NET-001
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(100))
    trigger: Mapped[str] = mapped_column(String(200))
    actions: Mapped[list] = mapped_column(JSON)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    estimated_duration: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# ResponseLog — human approval decision + execution result
# ─────────────────────────────────────────────────────────────────────────────
class ResponseLog(Base):
    __tablename__ = "response_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"))
    playbook_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("playbooks.id"), nullable=True)
    decision: Mapped[str] = mapped_column(String(20))            # APPROVED | REJECTED
    operator_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    execution_status: Mapped[str] = mapped_column(String(50), default="PENDING")
    outcome: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="response_logs")
    playbook: Mapped[Optional["Playbook"]] = relationship()


# ─────────────────────────────────────────────────────────────────────────────
# AuditEntry — tamper-evident log of every agent action
# ─────────────────────────────────────────────────────────────────────────────
class AuditEntry(Base):
    __tablename__ = "audit_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=True)
    log_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    agent_name: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(300))
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped[Optional["Incident"]] = relationship(back_populates="audit_entries")


# ─────────────────────────────────────────────────────────────────────────────
# Report — generated PDF investigation report
# ─────────────────────────────────────────────────────────────────────────────
class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"))
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    filename: Mapped[str] = mapped_column(String(500))
    file_path: Mapped[str] = mapped_column(String(1000))
    compliance_mapping: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="reports")
    organization: Mapped["Organization"] = relationship()

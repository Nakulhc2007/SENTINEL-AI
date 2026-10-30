from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field
import uuid


# ─────────────────────────────────────────────────────────────────────────────
# Organization Schemas
# ─────────────────────────────────────────────────────────────────────────────
class OrganizationBase(BaseModel):
    name: str
    industry: str
    domain: str
    risk_threshold: int = 70
    compliance_frameworks: Optional[List[str]] = None
    description: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationRead(OrganizationBase):
    id: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# SecurityLog Schemas
# ─────────────────────────────────────────────────────────────────────────────
class SecurityLogRead(BaseModel):
    id: str
    org_id: str
    original_filename: str
    sha256_hash: Optional[str]
    domain: str
    status: str
    record_count: int
    attack_count: int
    error_message: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# NormalizedEvent Schemas
# ─────────────────────────────────────────────────────────────────────────────
class NormalizedEventRead(BaseModel):
    id: str
    log_id: str
    org_id: str
    domain: str
    timestamp: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    action: Optional[str]
    severity: int
    severity_label: Optional[str]
    is_attack: Optional[bool]
    attack_type: Optional[str]
    username: Optional[str]
    hostname: Optional[str]

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Alert Schemas
# ─────────────────────────────────────────────────────────────────────────────
class AlertRead(BaseModel):
    id: str
    org_id: str
    log_id: str
    title: str
    description: str
    severity_score: float
    confidence: float
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    mitre_technique_id: Optional[str]
    attack_type: Optional[str]
    domain: str
    status: str
    event_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Incident Schemas
# ─────────────────────────────────────────────────────────────────────────────
class IncidentRead(BaseModel):
    id: str
    org_id: str
    alert_id: str
    title: str
    status: str
    risk_score: int
    timeline: Optional[List[Any]]
    root_cause: Optional[str]
    integrity_status: Optional[str]
    integrity_original_hash: Optional[str]
    integrity_current_hash: Optional[str]
    recommended_playbook_id: Optional[str]
    operator_notes: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class IncidentStatusUpdate(BaseModel):
    status: str
    operator_notes: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Playbook Schemas
# ─────────────────────────────────────────────────────────────────────────────
class PlaybookRead(BaseModel):
    id: str
    code: str
    name: str
    description: str
    domain: str
    trigger: str
    actions: List[str]
    requires_approval: bool
    risk_level: str
    mitre_tactic: Optional[str]
    estimated_duration: Optional[str]

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Response Schemas
# ─────────────────────────────────────────────────────────────────────────────
class ApprovalRequest(BaseModel):
    decision: str           # APPROVED | REJECTED
    operator_notes: Optional[str] = None


class ResponseLogRead(BaseModel):
    id: str
    incident_id: str
    playbook_id: Optional[str]
    decision: str
    operator_notes: Optional[str]
    execution_status: str
    outcome: Optional[dict]
    executed_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Audit Schemas
# ─────────────────────────────────────────────────────────────────────────────
class AuditEntryRead(BaseModel):
    id: str
    incident_id: Optional[str]
    log_id: Optional[str]
    agent_name: str
    action: str
    details: Optional[dict]
    confidence: Optional[float]
    timestamp: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Report Schemas
# ─────────────────────────────────────────────────────────────────────────────
class ReportRead(BaseModel):
    id: str
    incident_id: str
    org_id: str
    filename: str
    compliance_mapping: Optional[dict]
    created_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Upload Response
# ─────────────────────────────────────────────────────────────────────────────
class UploadResponse(BaseModel):
    log_id: str
    message: str
    filename: str


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard KPIs
# ─────────────────────────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_alerts: int
    resolved_today: int
    avg_risk_score: float
    pending_approvals: int
    total_logs: int
    total_events: int


# ─────────────────────────────────────────────────────────────────────────────
# Agent Status
# ─────────────────────────────────────────────────────────────────────────────
class AgentStatus(BaseModel):
    name: str
    status: str   # IDLE | RUNNING | ERROR
    last_run: Optional[str]
    tasks_completed: int


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Event
# ─────────────────────────────────────────────────────────────────────────────
class WSEvent(BaseModel):
    type: str         # alert_created | incident_updated | agent_status | pipeline_progress
    data: Any
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

# SENTINEL-AI — Database Schema
**Database:** PostgreSQL 16  
**ORM:** SQLAlchemy (async)  
**Migrations:** Alembic  
**Conventions:** snake_case, UUID primary keys, UTC timestamps, soft deletes where applicable

---

## Entity Relationship Overview

```
organizations (1) ──── (∞) domains
organizations (1) ──── (∞) security_logs
security_logs  (1) ──── (∞) normalized_events
normalized_events (∞) ──── (∞) alerts  [via alert_events join table]
alerts  (∞) ──── (1) incidents
incidents (1) ──── (∞) agent_actions
incidents (1) ──── (∞) timeline_events
incidents (1) ──── (1) risk_scores
incidents (1) ──── (∞) response_logs
incidents (1) ──── (1) reports
incidents (1) ──── (∞) audit_entries
playbooks (∞) ──── (∞) incidents [via incident_playbooks]
```

---

## Table Definitions

### `organizations`
Stores the 8 configurable organizational profiles.

```sql
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL UNIQUE,
    description     TEXT,
    logo_url        VARCHAR(500),
    risk_threshold  INTEGER NOT NULL DEFAULT 70,  -- 0-100, alerts above this = critical
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    compliance_frameworks  VARCHAR[] DEFAULT ARRAY['gdpr','iso27001'],
    -- e.g. ['gdpr', 'hipaa', 'soc2', 'iso27001']
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed data: 8 organizations
INSERT INTO organizations (name, description, compliance_frameworks) VALUES
  ('Apex Financial Corp',     'Banking and financial services',   ARRAY['pci_dss','soc2','gdpr']),
  ('MedCore Hospital Group',  'Healthcare provider network',      ARRAY['hipaa','gdpr']),
  ('CloudNexus Inc',          'Cloud SaaS provider',              ARRAY['soc2','iso27001','gdpr']),
  ('SecureGov Agency',        'Government cybersecurity agency',  ARRAY['nist_csf','fisma']),
  ('RetailEdge Stores',       'National retail chain',            ARRAY['pci_dss','gdpr']),
  ('TechForge Startup',       'Tech startup — engineering',       ARRAY['soc2','iso27001']),
  ('EduSafe University',      'Higher education institution',     ARRAY['ferpa','gdpr']),
  ('LogiChain Logistics',     'Supply chain and logistics',       ARRAY['iso27001','gdpr']);
```

---

### `security_domains`
Reference table for the 8 supported security domains.

```sql
CREATE TABLE security_domains (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            VARCHAR(50) NOT NULL UNIQUE,
    -- network_security | endpoint_security | cloud_infrastructure |
    -- iam | application_security | dlp | insider_threat | compliance
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    criticality_weight  DECIMAL(3,2) NOT NULL DEFAULT 1.0,
    -- multiplier used in risk score calculation (1.0–2.0)
    icon            VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### `security_logs`
Raw uploaded or synthetically generated log files.

```sql
CREATE TABLE security_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_slug     VARCHAR(50) NOT NULL,
    file_name       VARCHAR(500),
    file_path       VARCHAR(1000),           -- local FS path to stored file
    file_size_bytes BIGINT,
    file_format     VARCHAR(20),             -- csv | json | plaintext | syslog | cef
    sha256_hash     VARCHAR(64) NOT NULL,    -- SHA-256 of original file content
    event_count     INTEGER,                 -- populated after parsing
    is_synthetic    BOOLEAN NOT NULL DEFAULT FALSE,
    status          VARCHAR(30) NOT NULL DEFAULT 'uploaded',
    -- uploaded | parsing | parsed | failed
    error_message   TEXT,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    parsed_at       TIMESTAMPTZ
);

CREATE INDEX idx_security_logs_org_id ON security_logs(organization_id);
CREATE INDEX idx_security_logs_status ON security_logs(status);
```

---

### `normalized_events`
Structured events produced by `Sentinel-Parser` from raw logs.

```sql
CREATE TABLE normalized_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    security_log_id UUID NOT NULL REFERENCES security_logs(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL,
    domain_slug     VARCHAR(50) NOT NULL,
    
    -- Core CEF fields
    event_timestamp TIMESTAMPTZ NOT NULL,    -- source timestamp
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(20),             -- tcp | udp | icmp | http | etc
    action          VARCHAR(100),            -- deny | allow | block | login | etc
    username        VARCHAR(255),
    hostname        VARCHAR(255),
    process_name    VARCHAR(255),
    file_path       VARCHAR(1000),
    
    -- Classification
    event_type      VARCHAR(50),             -- auth | network | process | file | etc
    severity        INTEGER,                 -- 0=info, 1=low, 2=medium, 3=high, 4=critical
    raw_log         TEXT NOT NULL,           -- original log line for reference
    extra_fields    JSONB,                   -- any domain-specific additional fields
    
    -- Processing
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_anomalous    BOOLEAN,                 -- null = not yet analyzed
    anomaly_score   DECIMAL(5,4)             -- Isolation Forest score (-1 to 1)
);

CREATE INDEX idx_normalized_events_log_id ON normalized_events(security_log_id);
CREATE INDEX idx_normalized_events_org ON normalized_events(organization_id);
CREATE INDEX idx_normalized_events_timestamp ON normalized_events(event_timestamp);
CREATE INDEX idx_normalized_events_is_anomalous ON normalized_events(is_anomalous);
```

---

### `alerts`
Threat detections produced by `Sentinel-Analyst`.

```sql
CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    security_log_id UUID NOT NULL REFERENCES security_logs(id),
    domain_slug     VARCHAR(50) NOT NULL,
    
    -- Detection metadata
    alert_type      VARCHAR(100) NOT NULL,   -- e.g. "port_scan_detected", "brute_force_attack"
    title           VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL,
    
    -- Severity & confidence
    severity        DECIMAL(4,1) NOT NULL,   -- 0.0–10.0
    severity_label  VARCHAR(20) NOT NULL,    -- low | medium | high | critical
    confidence      DECIMAL(4,3) NOT NULL,   -- 0.000–1.000
    
    -- MITRE ATT&CK
    mitre_tactic    VARCHAR(100),            -- e.g. "Initial Access"
    mitre_technique VARCHAR(20),             -- e.g. "T1190"
    mitre_sub_technique VARCHAR(30),         -- e.g. "T1190.001"
    
    -- Detection method
    detection_method VARCHAR(50),            -- rule_based | ml_anomaly | correlation | llm
    rule_id         VARCHAR(50),             -- Sigma rule ID if rule_based
    
    -- Source events (correlated event IDs)
    event_ids       UUID[],                  -- array of normalized_event IDs
    
    -- Status
    status          VARCHAR(30) NOT NULL DEFAULT 'new',
    -- new | investigated | false_positive | resolved
    
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_org_id ON alerts(organization_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity DESC);
CREATE INDEX idx_alerts_detected_at ON alerts(detected_at DESC);
```

---

### `incidents`
Full investigation records produced by `Sentinel-Investigator`.

```sql
CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    alert_id        UUID NOT NULL REFERENCES alerts(id),
    security_log_id UUID NOT NULL REFERENCES security_logs(id),
    domain_slug     VARCHAR(50) NOT NULL,
    
    -- Identification
    incident_number VARCHAR(20) NOT NULL UNIQUE,
    -- Format: INC-{YYYYMMDD}-{seq}, e.g. INC-20261030-0001
    title           VARCHAR(255) NOT NULL,
    
    -- Investigation results
    risk_score      INTEGER NOT NULL,        -- 0–100
    risk_label      VARCHAR(20) NOT NULL,    -- low | medium | high | critical
    risk_explanation TEXT NOT NULL,          -- natural language explanation
    root_cause      TEXT,                    -- LLM-generated hypothesis
    
    -- Document integrity
    sha256_log_stored    VARCHAR(64),        -- hash stored at upload time
    sha256_log_verified  VARCHAR(64),        -- hash recomputed by investigator
    integrity_status     VARCHAR(20),        -- verified | tampered | unchecked
    
    -- Timeline (stored as ordered JSON array)
    timeline        JSONB NOT NULL DEFAULT '[]',
    -- [{timestamp, event_type, description, severity, raw_log}]
    
    -- Workflow status
    status          VARCHAR(30) NOT NULL DEFAULT 'investigating',
    -- investigating | awaiting_approval | approved | rejected | remediating 
    -- | remediated | auditing | closed | false_positive
    
    -- Compliance
    applicable_frameworks  VARCHAR[] DEFAULT '{}',
    -- e.g. ['gdpr_art32', 'hipaa_164.312', 'iso_a.16.1.1']
    
    -- Timestamps
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approval_requested_at TIMESTAMPTZ,
    approved_at     TIMESTAMPTZ,
    rejected_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Operator notes
    operator_notes  TEXT
);

CREATE INDEX idx_incidents_org_id ON incidents(organization_id);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_risk_score ON incidents(risk_score DESC);
CREATE INDEX idx_incidents_opened_at ON incidents(opened_at DESC);
```

---

### `agent_actions`
Immutable audit log of every action taken by each agent.

```sql
CREATE TABLE agent_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID REFERENCES incidents(id),
    security_log_id UUID REFERENCES security_logs(id),
    
    -- Agent identification
    agent_name      VARCHAR(50) NOT NULL,
    -- sentinel-parser | sentinel-analyst | sentinel-investigator
    -- | sentinel-remediator | sentinel-auditor
    
    -- Action details
    action_type     VARCHAR(100) NOT NULL,
    -- parse_log | detect_anomaly | match_rule | correlate | create_incident
    -- | calculate_risk | check_integrity | recommend_playbook | execute_response
    -- | generate_report | log_audit
    
    action_description TEXT NOT NULL,
    
    -- State
    status          VARCHAR(20) NOT NULL,    -- running | success | failed | skipped
    error_message   TEXT,
    
    -- LLM metadata (if LLM was used)
    llm_model       VARCHAR(100),
    llm_prompt_tokens INTEGER,
    llm_completion_tokens INTEGER,
    
    -- Output
    output_summary  TEXT,
    output_data     JSONB,                   -- structured output from the agent
    confidence      DECIMAL(4,3),
    
    -- Timing
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    duration_ms     INTEGER
);

CREATE INDEX idx_agent_actions_incident ON agent_actions(incident_id);
CREATE INDEX idx_agent_actions_agent ON agent_actions(agent_name);
CREATE INDEX idx_agent_actions_started ON agent_actions(started_at DESC);
```

---

### `playbooks`
Response playbook library used by `Sentinel-Remediator`.

```sql
CREATE TABLE playbooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     VARCHAR(20) NOT NULL UNIQUE,
    -- Format: PB-{DOMAIN_CODE}-{seq}, e.g. PB-NET-001
    
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL,
    domain_slug     VARCHAR(50) NOT NULL,
    
    -- Triggers
    trigger_alert_types  VARCHAR[] NOT NULL,
    -- alert_types this playbook applies to
    
    -- Actions (ordered list)
    actions         JSONB NOT NULL,
    -- [{action_id, name, description, is_destructive, estimated_impact}]
    
    -- Risk
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    risk_level      VARCHAR(20) NOT NULL DEFAULT 'medium',
    -- low | medium | high | critical
    estimated_duration_minutes INTEGER DEFAULT 5,
    
    -- Compliance note
    compliance_note TEXT,
    
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### `response_logs`
Records of executed or simulated responses.

```sql
CREATE TABLE response_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id),
    playbook_id     UUID NOT NULL REFERENCES playbooks(id),
    
    -- Execution details
    execution_mode  VARCHAR(20) NOT NULL DEFAULT 'simulated',
    -- simulated | executed
    
    actions_taken   JSONB NOT NULL DEFAULT '[]',
    -- [{action_id, name, status: executed|failed|skipped, timestamp, output}]
    
    -- Outcome verification
    outcome_status  VARCHAR(20),             -- neutralized | partial | failed | unverified
    outcome_description TEXT,
    outcome_verified_at TIMESTAMPTZ,
    
    -- Approval tracking
    approved_by     VARCHAR(255),            -- operator identifier
    approved_at     TIMESTAMPTZ,
    rejected_by     VARCHAR(255),
    rejection_reason TEXT,
    
    executed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_response_logs_incident ON response_logs(incident_id);
```

---

### `reports`
Generated investigation reports by `Sentinel-Auditor`.

```sql
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) UNIQUE,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    
    -- Report metadata
    report_number   VARCHAR(20) NOT NULL UNIQUE,
    -- Format: RPT-{YYYYMMDD}-{seq}
    title           VARCHAR(255) NOT NULL,
    
    -- File storage
    pdf_path        VARCHAR(1000),
    json_path       VARCHAR(1000),
    
    -- Content summary
    executive_summary TEXT,
    compliance_findings JSONB DEFAULT '{}',
    -- {framework_id: {controls_triggered: [], findings: [], severity: ''}}
    
    -- Metadata
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    file_size_bytes INTEGER
);

CREATE INDEX idx_reports_org_id ON reports(organization_id);
CREATE INDEX idx_reports_generated ON reports(generated_at DESC);
```

---

### `audit_entries`
Tamper-evident audit trail — append-only log of all significant system events.

```sql
CREATE TABLE audit_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Context
    incident_id     UUID REFERENCES incidents(id),
    organization_id UUID REFERENCES organizations(id),
    agent_action_id UUID REFERENCES agent_actions(id),
    
    -- Event
    event_type      VARCHAR(100) NOT NULL,
    -- incident_opened | alert_created | risk_scored | approval_requested
    -- | response_approved | response_rejected | response_executed | report_generated
    -- | audit_logged | log_uploaded | integrity_verified | integrity_failed
    
    actor           VARCHAR(100) NOT NULL,
    -- 'sentinel-parser' | 'sentinel-analyst' | 'operator:{username}' | 'system'
    
    description     TEXT NOT NULL,
    details         JSONB,
    
    -- Integrity chain (simple linked hash for tamper evidence)
    event_hash      VARCHAR(64) NOT NULL,    -- SHA-256 of (prev_hash + event_data)
    prev_entry_id   UUID REFERENCES audit_entries(id),
    
    -- Timestamp (immutable)
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- NOTE: No UPDATE or DELETE on this table — append only
-- Enforce at application level + DB policy
CREATE INDEX idx_audit_entries_incident ON audit_entries(incident_id);
CREATE INDEX idx_audit_entries_occurred ON audit_entries(occurred_at DESC);
CREATE INDEX idx_audit_entries_org ON audit_entries(organization_id);
```

---

## Alembic Migration Sequence

```
001_initial_schema.py           ← organizations, security_domains
002_log_tables.py               ← security_logs, normalized_events
003_detection_tables.py         ← alerts
004_investigation_tables.py     ← incidents
005_agent_tables.py             ← agent_actions
006_response_tables.py          ← playbooks, response_logs
007_reporting_tables.py         ← reports, audit_entries
008_seed_data.py                ← 8 orgs, 8 domains, 30+ playbooks
```

---

## Key Query Patterns

### Live Incident Feed (Dashboard)
```sql
SELECT i.*, a.severity, a.mitre_tactic, a.mitre_technique, o.name as org_name
FROM incidents i
JOIN alerts a ON a.id = i.alert_id
JOIN organizations o ON o.id = i.organization_id
WHERE i.organization_id = :org_id
  AND i.status NOT IN ('closed', 'false_positive')
ORDER BY i.risk_score DESC, i.opened_at DESC
LIMIT 20;
```

### Pending Approval Queue
```sql
SELECT i.*, p.name as playbook_name, p.risk_level, p.actions
FROM incidents i
JOIN incident_playbooks ip ON ip.incident_id = i.id
JOIN playbooks p ON p.id = ip.playbook_id
WHERE i.status = 'awaiting_approval'
  AND i.organization_id = :org_id
ORDER BY i.risk_score DESC;
```

### Audit Trail for Incident
```sql
SELECT ae.*, aa.agent_name, aa.action_type
FROM audit_entries ae
LEFT JOIN agent_actions aa ON aa.id = ae.agent_action_id
WHERE ae.incident_id = :incident_id
ORDER BY ae.occurred_at ASC;
```

---

## SQLAlchemy Model Example (Python)

```python
# backend/app/models/incident.py
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, Boolean, ARRAY, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, TIMESTAMPTZ, DECIMAL
from sqlalchemy.orm import relationship
from app.core.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    alert_id = Column(UUID(as_uuid=True), nullable=False)
    incident_number = Column(String(20), nullable=False, unique=True)
    title = Column(String(255), nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_label = Column(String(20), nullable=False)
    risk_explanation = Column(Text, nullable=False)
    root_cause = Column(Text)
    sha256_log_stored = Column(String(64))
    sha256_log_verified = Column(String(64))
    integrity_status = Column(String(20), default="unchecked")
    timeline = Column(JSONB, default=list)
    status = Column(String(30), nullable=False, default="investigating")
    applicable_frameworks = Column(ARRAY(String), default=list)
    opened_at = Column(TIMESTAMPTZ, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(TIMESTAMPTZ, default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc))
    operator_notes = Column(Text)

    # Relationships
    alert = relationship("Alert", back_populates="incident")
    agent_actions = relationship("AgentAction", back_populates="incident")
    response_logs = relationship("ResponseLog", back_populates="incident")
    report = relationship("Report", back_populates="incident", uselist=False)
    audit_entries = relationship("AuditEntry", back_populates="incident")
```

# SENTINEL-AI — Project Architecture
**Team:** SYNTHETIX | **Team ID:** AH-45  
**Members:** Deepak R · Bharath B · Shrishanth B L · Nakul H C  
**Hackathon:** AfterHours 1.0 — Offline Round  
**Theme:** Agentic AI and Multi-Agent Systems

---

## 1. Project Overview

**SENTINEL-AI** is an **Autonomous Multi-Agent Security Operations Center (SOC)** that addresses the core problem: *the lack of a unified intelligent platform to detect cyber threats, identify unauthorized access, investigate suspicious activities, assess risks, and recommend appropriate security responses across different organizations.*

The system ingests security logs from **eight configurable organizational profiles**, routes them through a pipeline of **five specialized AI agents**, and produces actionable, human-approved security responses — all within a unified web dashboard.

---

## 2. The Eight Organizational Domains

Each organization has a distinct security profile, log format, and threat surface. SENTINEL-AI supports all eight:

| # | Domain | Primary Threat Vectors | Typical Log Sources |
|---|--------|------------------------|---------------------|
| 1 | **Network Security** | DDoS, port scans, lateral movement, firewall bypass | Firewall logs, IDS/IPS alerts, NetFlow records |
| 2 | **Endpoint Security** | Malware execution, ransomware, privilege escalation | Windows Event Logs, Sysmon, EDR telemetry, process trees |
| 3 | **Cloud Infrastructure** | Misconfigured S3 buckets, IAM abuse, cryptomining, data exfiltration | AWS CloudTrail, Azure Monitor, GCP Audit Logs |
| 4 | **Identity & Access Management (IAM)** | Brute-force attacks, credential stuffing, impossible travel, MFA bypass | LDAP/AD logs, SSO logs, VPN access logs |
| 5 | **Application Security** | SQL injection, XSS, API abuse, OWASP Top 10 | WAF logs, API gateway logs, web server access logs |
| 6 | **Data Loss Prevention (DLP)** | Unauthorized data exfiltration, USB transfers, mass cloud downloads | DLP platform alerts, email gateway logs, USB device logs |
| 7 | **Insider Threat** | Credential harvesting, abnormal access hours, data hoarding | UEBA platform logs, HR system events, badge access logs |
| 8 | **Compliance & Governance** | Policy violations, audit failures, regulatory non-compliance | GDPR/HIPAA/SOC2/ISO 27001 audit event streams |

---

## 3. System Architecture — High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SENTINEL-AI PLATFORM                            │
│                                                                         │
│  ┌──────────────────┐    ┌─────────────────────────────────────────┐   │
│  │   Frontend (UI)  │    │              Backend API                │   │
│  │  React 18 + TS   │◄──►│   FastAPI  │  Celery  │  WebSocket     │   │
│  │  Dashboard       │    │   Gateway  │  Workers │  Server         │   │
│  └──────────────────┘    └──────────────────┬────────────────────-┘   │
│                                              │                          │
│  ┌───────────────────────────────────────────▼────────────────────┐   │
│  │                    ORCHESTRATION LAYER (LangGraph)              │   │
│  │                                                                  │   │
│  │   ┌────────────┐  ┌────────────┐  ┌─────────────┐             │   │
│  │   │  Agent 1   │  │  Agent 2   │  │   Agent 3   │             │   │
│  │   │  Parser    │─►│  Analyst   │─►│ Investigator│             │   │
│  │   └────────────┘  └────────────┘  └──────┬──────┘             │   │
│  │                                           │                     │   │
│  │                    ┌──────────────────────▼──────────────────┐ │   │
│  │                    │  Agent 4: Remediator (Human-in-the-Loop) │ │   │
│  │                    └─────────────────────────────────────────┘ │   │
│  │                                           │                     │   │
│  │                    ┌──────────────────────▼──────────────────┐ │   │
│  │                    │       Agent 5: Auditor                   │ │   │
│  │                    └─────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────── ┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      DATA & STORAGE TIER                        │   │
│  │  PostgreSQL 16  │  Redis Cache  │  ChromaDB/Qdrant  │   FS     │   │
│  │  (State/Events) │  (Sessions)   │  (Vector RAG)     │  (Logs)  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. The Five AI Agents — Roles & Communication

### Agent 1: `Sentinel-Parser` (Log Ingestion & Normalization)
- **Role:** Ingests raw security logs (uploaded CSV/JSON/plaintext or synthetic), normalizes them into a unified **Common Event Format (CEF)**, tags events with domain label, extracts key fields (timestamp, source IP, destination, action, severity).
- **Input:** Raw log file uploaded via UI
- **Output:** Structured JSON event batch → pushed to internal queue
- **Tools:** Regex parsers, Grok patterns, LLM-based log interpretation (for unstructured logs), file hash (SHA-256) generator

### Agent 2: `Sentinel-Analyst` (Threat Detection & Correlation)
- **Role:** Analyzes normalized events against threat intelligence. Performs anomaly detection (statistical baseline + ML model), rule-based signature matching, and cross-event correlation to surface suspicious patterns.
- **Input:** Structured event batch from Parser
- **Output:** List of `Alert` objects with severity scores (0–10), tactic/technique labels (MITRE ATT&CK), and correlation chains
- **Tools:** Scikit-learn anomaly models, MITRE ATT&CK lookup, rule engine (Sigma rules), RAG retrieval from vector threat-intel DB

### Agent 3: `Sentinel-Investigator` (Incident Investigation & Risk Scoring)
- **Role:** For each alert, constructs a full incident timeline, calculates an explainable risk score (incorporating asset criticality + severity + blast radius), and verifies document/log integrity using SHA-256 hashing.
- **Input:** Alert objects from Analyst
- **Output:** `Incident` record with timeline, risk score (0–100), integrity check result, root-cause hypothesis
- **Tools:** Timeline builder, SHA-256 integrity verifier, LLM reasoning chain (chain-of-thought), knowledge graph lookup

### Agent 4: `Sentinel-Remediator` (Response Recommendation + Execution)
- **Role:** Recommends the optimal security response playbook for each incident. Recommends actions for **human approval** before execution. Upon approval, simulates or executes the response and verifies outcome.
- **Input:** Incident records from Investigator + human approval signal
- **Output:** Executed/simulated response log, outcome verification result
- **Tools:** Playbook library (block IP, isolate endpoint, revoke token, alert SIEM), human-in-the-loop approval gate, response simulator, outcome verifier
- **Human-in-the-Loop:** All destructive actions (block, isolate, revoke) require explicit operator approval via UI before execution

### Agent 5: `Sentinel-Auditor` (Compliance, Reporting & Audit Trail)
- **Role:** Generates comprehensive investigation reports, maintains a tamper-evident audit trail of all agent actions, maps incidents to compliance frameworks (GDPR, HIPAA, SOC 2, ISO 27001), and stores/exports downloadable PDF/JSON reports.
- **Input:** All agent outputs, incident records, response logs
- **Output:** PDF investigation report, compliance mapping table, audit log entry
- **Tools:** Report template engine (Jinja2), PDF generator (ReportLab/WeasyPrint), compliance rule mapper, audit logger

---

## 5. Agent Communication Protocol

Agents communicate through a **shared state machine** orchestrated by **LangGraph**, with a **Redis-backed message queue** for inter-agent messaging.

### Message Schema (JSON)
```json
{
  "message_id": "uuid4",
  "sender": "sentinel-parser",
  "recipient": "sentinel-analyst",
  "task_id": "incident-uuid",
  "organization_id": "org-uuid",
  "domain": "network_security",
  "payload": { ... },
  "confidence": 0.92,
  "timestamp": "2026-10-30T10:43:01+05:30",
  "requires_approval": false
}
```

### Communication Flow
```
[User Upload] 
    │
    ▼
[Sentinel-Parser] ──────────────────► Normalized Events (Redis Queue)
                                              │
                                              ▼
                                   [Sentinel-Analyst] ──► Alerts (State Store)
                                                               │
                                                               ▼
                                              [Sentinel-Investigator] ──► Incidents
                                                                               │
                                                               ┌──────────────┘
                                                               │
                                              ┌────────────────▼────────────────┐
                                              │    HUMAN APPROVAL GATE (UI)     │
                                              └────────────────┬────────────────┘
                                                               │  (Approved)
                                                               ▼
                                                   [Sentinel-Remediator]
                                                               │
                                                               ▼
                                                   [Sentinel-Auditor] ──► Report
```

### LangGraph State Machine States
```
IDLE → PARSING → ANALYZING → INVESTIGATING → AWAITING_APPROVAL → REMEDIATING → AUDITING → COMPLETE
                                                │
                                                └── REJECTED → RE_INVEST → ...
```

---

## 6. Frontend Architecture

### Pages & Views
| Page | Path | Description |
|------|------|-------------|
| Dashboard Home | `/` | Org selector, live incident feed, summary KPIs |
| Log Upload | `/upload` | Drag-drop log files, org + domain selector |
| Threat Analysis | `/threats` | Real-time alert feed with MITRE tags |
| Incident Detail | `/incidents/:id` | Timeline view, risk score gauge, agent chain |
| Response Center | `/response` | Human approval queue, playbook selector |
| Audit & Reports | `/reports` | Downloadable reports, audit trail table |
| Compliance Map | `/compliance` | Framework mapping (GDPR/HIPAA/SOC2/ISO27001) |
| Settings | `/settings` | Org profile config, agent config |

### Component Architecture
```
src/
├── components/
│   ├── layout/       (Sidebar, Navbar, StatusBar)
│   ├── dashboard/    (KPICard, ThreatFeed, AgentStatusPanel)
│   ├── upload/       (LogDropzone, OrgSelector, DomainPicker)
│   ├── threats/      (AlertCard, MITRETag, SeverityBadge)
│   ├── incidents/    (Timeline, RiskGauge, AgentChain)
│   ├── response/     (ApprovalQueue, PlaybookCard, OutcomePanel)
│   ├── reports/      (ReportCard, AuditTable, ComplianceMatrix)
│   └── common/       (Modal, Toast, Loader, Badge)
├── pages/            (each route maps to a page component)
├── hooks/            (useWebSocket, useIncidents, useAgentStatus)
├── store/            (Zustand slices: incidents, alerts, orgs, ui)
├── api/              (Axios client, typed API hooks)
└── utils/            (formatters, severity mappers, hash utils)
```

---

## 7. Backend Architecture

### API Layers
```
FastAPI Application
├── /api/v1/logs          (POST upload, GET list)
├── /api/v1/alerts        (GET feed, GET by ID)
├── /api/v1/incidents     (GET list, GET detail, PATCH status)
├── /api/v1/response      (POST approve, POST reject, GET queue)
├── /api/v1/reports       (GET list, GET download)
├── /api/v1/audit         (GET trail)
├── /api/v1/organizations (CRUD for org profiles)
├── /api/v1/agents/status (GET live agent status)
└── /ws/events            (WebSocket: real-time incident streaming)
```

### Background Workers (Celery)
- `parse_logs_task` — Triggers Parser agent
- `analyze_events_task` — Triggers Analyst agent
- `investigate_incident_task` — Triggers Investigator agent
- `remediate_incident_task` — Triggers Remediator (post-approval)
- `generate_report_task` — Triggers Auditor

---

## 8. Technology Stack

### Backend & Agents
| Layer | Technology |
|-------|------------|
| Language | Python 3.11 |
| Agent Orchestration | LangGraph 0.2 |
| LLM | Google Gemini 1.5 Pro / GPT-4o (via API) |
| API Framework | FastAPI 0.111 |
| Task Queue | Celery 5.3 + Redis |
| Log Parser | Python-logparser, Grok, custom regex |
| ML / Anomaly | scikit-learn, Isolation Forest |
| SHA-256 | Python `hashlib` |
| PDF Reports | ReportLab / WeasyPrint + Jinja2 |

### Data Layer
| Component | Technology |
|-----------|------------|
| Primary DB | PostgreSQL 16 |
| Cache / Queue | Redis 7 |
| Vector DB | ChromaDB (local) / Qdrant (scalable) |
| Log Storage | Local filesystem / MinIO |

### Frontend
| Layer | Technology |
|-------|------------|
| Framework | React 18 + TypeScript |
| Build Tool | Vite 5 |
| State Management | Zustand |
| HTTP Client | Axios + React Query |
| Real-time | WebSocket (native) |
| Charts | Recharts |
| Icons | Lucide React |
| Styling | Vanilla CSS / CSS Modules |

### DevOps
| Component | Technology |
|-----------|------------|
| Containerization | Docker + Docker Compose |
| Version Control | Git + GitHub |
| Environment | Python `venv` / `uv` |
| API Documentation | FastAPI auto-docs (Swagger/ReDoc) |

---

## 9. Complete Workflow: Log Upload → Final Response

```
Step 1: User Action
  └── Selects organization profile (1 of 8)
  └── Selects security domain
  └── Uploads log file (CSV/JSON/plaintext) OR generates synthetic logs

Step 2: Sentinel-Parser Agent
  └── Receives file, identifies format
  └── Parses & normalizes to Common Event Format
  └── Computes SHA-256 hash of original document
  └── Stores normalized events in DB
  └── Pushes event batch to Redis queue

Step 3: Sentinel-Analyst Agent
  └── Pulls event batch from queue
  └── Runs anomaly detection (Isolation Forest / Z-score)
  └── Matches events against Sigma rules
  └── Cross-correlates events into attack chains
  └── Tags with MITRE ATT&CK tactic/technique
  └── Creates Alert objects (severity 0–10, confidence %)
  └── Streams alerts to frontend via WebSocket

Step 4: Sentinel-Investigator Agent
  └── For each Alert, opens an Incident
  └── Builds chronological event timeline
  └── Calculates Risk Score (0–100):
       Risk = f(severity × asset_criticality × blast_radius × recency)
  └── Runs SHA-256 integrity check on referenced documents
  └── Generates root-cause hypothesis (LLM chain-of-thought)
  └── Updates Incident record + notifies UI

Step 5: Human Review (UI)
  └── Operator reviews Incident detail page
  └── Views recommended playbook from Remediator
  └── Clicks APPROVE or REJECT

Step 6: Sentinel-Remediator Agent (post-approval)
  └── Retrieves approved playbook
  └── Executes / simulates response action:
      - Block IP at firewall
      - Isolate endpoint
      - Revoke compromised token
      - Alert SIEM
      - Enforce MFA
  └── Verifies response outcome (checks if threat is neutralized)
  └── Logs execution result

Step 7: Sentinel-Auditor Agent
  └── Compiles all agent outputs for this incident
  └── Generates structured investigation report (PDF + JSON)
  └── Maps incident to applicable compliance frameworks
  └── Appends tamper-evident audit trail entry
  └── Makes report available for download in UI
```

---

## 10. Key Design Principles

1. **Human-in-the-Loop by Default** — No destructive action executes without operator approval
2. **Domain Isolation** — Each org profile has isolated log storage and incident namespacing
3. **Explainability First** — Every risk score and decision includes a natural language explanation
4. **Auditability** — Every agent action is logged with timestamp, confidence, and rationale
5. **Modular Agents** — Each agent is independently testable and replaceable
6. **Graceful Degradation** — If an agent fails, the pipeline continues with a "manual review required" flag

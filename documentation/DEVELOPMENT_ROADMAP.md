# SENTINEL-AI — Development Roadmap
**Team:** SYNTHETIX | **Team ID:** AH-45  
**Total Timeline:** 6 Phases across the hackathon sprint  
**Approach:** Iterative — each phase produces a working, demonstrable increment

---

## Phase Overview

```
Phase 1 ─── Foundation & Project Setup (Core Scaffolding)
   │
Phase 2 ─── Data Layer & Synthetic Generator (Data Plumbing)
   │
Phase 3 ─── Agent Pipeline (Core Intelligence)
   │
Phase 4 ─── Frontend Dashboard (User Interface)
   │
Phase 5 ─── Integration & Human-in-the-Loop (End-to-End Flow)
   │
Phase 6 ─── Polish, Reports & Demo Prep (Final Hardening)
```

---

## Phase 1: Foundation & Project Setup

**Goal:** Create the project skeleton, configure the environment, and get a "hello world" API + React app running locally.

### Tasks

#### 1.1 Repository Structure
```
SENTINAL-AI/
├── backend/
│   ├── app/
│   │   ├── api/v1/         # FastAPI routers
│   │   ├── agents/         # Agent modules
│   │   ├── core/           # Config, DB, security
│   │   ├── models/         # SQLAlchemy models
│   │   ├── schemas/        # Pydantic schemas
│   │   ├── services/       # Business logic
│   │   └── main.py         # FastAPI entrypoint
│   ├── synthetic/          # Synthetic log generators
│   ├── tests/              # pytest tests
│   ├── requirements.txt    
│   └── Dockerfile          
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── store/
│   │   ├── api/
│   │   └── utils/
│   ├── package.json
│   └── vite.config.ts
├── documentation/          ← (this folder)
├── data/                   # Sample/processed datasets
├── docker-compose.yml
└── README.md
```

#### 1.2 Backend Setup
- [ ] Initialize Python 3.11 virtual environment with `uv`
- [ ] Install: FastAPI, Uvicorn, SQLAlchemy, Alembic, psycopg2, Redis, Celery, python-dotenv, pytest
- [ ] Set up PostgreSQL 16 (via Docker)
- [ ] Set up Redis (via Docker)
- [ ] Create `docker-compose.yml` with postgres + redis services
- [ ] Write `backend/app/core/config.py` (environment variables)
- [ ] Write `backend/app/core/database.py` (SQLAlchemy async engine)
- [ ] Create `backend/app/main.py` with CORS, health check endpoint
- [ ] Run Alembic migrations: `alembic init` + baseline migration

#### 1.3 Frontend Setup
- [ ] `npx create-vite@latest frontend --template react-ts`
- [ ] Install: Axios, Zustand, React Query, Recharts, Lucide React
- [ ] Set up Vite proxy to backend (`/api` → `localhost:8000`)
- [ ] Create base layout (Sidebar, Navbar)
- [ ] Configure CSS design system (color tokens, typography, spacing)
- [ ] Verify frontend connects to backend health check

#### 1.4 Agent Framework Setup
- [ ] Install: LangGraph, langchain, langchain-google-genai (or openai)
- [ ] Create `backend/app/agents/base.py` — base agent class with: `run()`, `log_action()`, `report_status()` 
- [ ] Create `backend/app/agents/orchestrator.py` — LangGraph state machine skeleton
- [ ] Define agent state schema:
  ```python
  class SentinelState(TypedDict):
      task_id: str
      organization_id: str
      domain: str
      raw_logs: list[str]
      normalized_events: list[dict]
      alerts: list[dict]
      incidents: list[dict]
      approved_playbooks: list[dict]
      response_logs: list[dict]
      audit_report: dict
  ```

**Deliverable:** Docker Compose up, API health check returns 200, React app loads ✅

---

## Phase 2: Data Layer & Synthetic Generator

**Goal:** Database schema live, all models created, synthetic log generator working for all 8 domains.

### Tasks

#### 2.1 Database Models (SQLAlchemy)
- [ ] Create models: `Organization`, `Domain`, `SecurityLog`, `NormalizedEvent`, `Alert`, `Incident`, `AgentAction`, `Playbook`, `ResponseLog`, `AuditEntry`, `Report`
- [ ] Run Alembic migration to create all tables
- [ ] Seed database with 8 default organization profiles

#### 2.2 Pydantic Schemas
- [ ] Create request/response schemas for each model
- [ ] Create inter-agent message schema: `AgentMessage`
- [ ] Create incident timeline event schema: `TimelineEvent`

#### 2.3 API Stubs (All Endpoints)
- [ ] Implement all CRUD endpoints (return mock data initially)
- [ ] Implement WebSocket endpoint for live event streaming
- [ ] Verify all endpoints return correct Pydantic-validated responses

#### 2.4 Synthetic Log Generator
- [ ] Create `backend/synthetic/generator.py`
- [ ] Implement generators for all 8 domains:
  - `NetworkSecurityGenerator` — firewall deny logs, IDS alerts, NetFlow anomalies
  - `EndpointSecurityGenerator` — Sysmon-format process/file/network events
  - `CloudInfraGenerator` — CloudTrail-format JSON events
  - `IAMGenerator` — auth log events with brute force + impossible travel patterns
  - `AppSecGenerator` — HTTP access log with SQLi/XSS payloads
  - `DLPGenerator` — file transfer + USB + email event logs
  - `InsiderThreatGenerator` — behavioral event logs with anomaly injection
  - `ComplianceGenerator` — audit event logs with policy violation markers
- [ ] Each generator: configurable `num_events`, `anomaly_ratio`, `attack_type`
- [ ] Output format: list of CEF-compatible dicts + raw log strings

#### 2.5 File Upload Endpoint
- [ ] Implement `POST /api/v1/logs/upload` — accept CSV/JSON/plaintext
- [ ] Store raw file, compute SHA-256 hash, save `SecurityLog` record
- [ ] Return task_id for polling

**Deliverable:** All 8 synthetic generators working, DB tables created, file upload stores to DB ✅

---

## Phase 3: Agent Pipeline (Core Intelligence)

**Goal:** All five agents functional in sequence. Real threat detection working.

### Tasks

#### 3.1 Agent 1: Sentinel-Parser
- [ ] Implement `backend/app/agents/parser.py`
- [ ] Auto-detect log format (CSV, JSON, Apache CLF, Syslog, CEF, custom)
- [ ] Normalize to unified schema: `{timestamp, src_ip, dst_ip, action, severity, raw_log, domain, org_id}`
- [ ] Compute SHA-256 hash of each log file (store hash for later integrity check)
- [ ] Save normalized events to DB
- [ ] Push event batch to Redis queue (key: `task:{task_id}:events`)
- [ ] Test: upload network CSV → verify normalized JSON in DB

#### 3.2 Agent 2: Sentinel-Analyst
- [ ] Implement `backend/app/agents/analyst.py`
- [ ] Load pre-trained Isolation Forest model (trained on CIC-IDS sample)
- [ ] Rule-based detection: implement 20+ Sigma-style rules per domain
- [ ] Correlation engine: group related alerts into attack chains
- [ ] MITRE ATT&CK tagging: map detected patterns to tactic/technique IDs
- [ ] Create `Alert` records with: severity (0–10), confidence (%), mitre_id, description
- [ ] Stream alerts to frontend via WebSocket
- [ ] Test: inject known attack events → verify alerts generated with correct MITRE tags

#### 3.3 Agent 3: Sentinel-Investigator
- [ ] Implement `backend/app/agents/investigator.py`
- [ ] For each alert, open/update `Incident` record
- [ ] Build timeline: sort correlated events chronologically with event descriptions
- [ ] Risk Score calculation:
  ```python
  risk_score = min(100, int(
      (alert.severity * 10) * 
      domain_criticality_weight[domain] * 
      (1 + (num_correlated_events / 10)) *
      recency_multiplier
  ))
  ```
- [ ] SHA-256 integrity check: compare stored log file hash with re-computed hash
- [ ] LLM chain-of-thought: generate root-cause hypothesis paragraph
- [ ] Get recommended playbook from Playbook library → store in Incident
- [ ] Test: verify risk scores are explainable, timeline builds correctly

#### 3.4 Agent 4: Sentinel-Remediator
- [ ] Implement `backend/app/agents/remediator.py`
- [ ] Playbook library: JSON file with 30+ playbooks mapped to incident type + domain
  ```json
  {
    "playbook_id": "PB-NET-001",
    "name": "Block Scanning IP",
    "domain": "network_security",
    "trigger": "port_scan_detected",
    "actions": ["block_ip_firewall", "alert_soc_team", "log_event"],
    "requires_approval": true,
    "risk_level": "medium"
  }
  ```
- [ ] Approval gate: incident status must be `APPROVED` before execution
- [ ] Response simulator: simulates execution, generates outcome log
- [ ] Outcome verifier: checks if post-response events still show threat activity
- [ ] Test: approve an incident via API → verify response log created

#### 3.5 Agent 5: Sentinel-Auditor
- [ ] Implement `backend/app/agents/auditor.py`
- [ ] Compile all agent actions for the incident into structured report
- [ ] Compliance mapper: JSON rules map `{incident_type} → [gdpr_articles, hipaa_rules, soc2_criteria, iso_controls]`
- [ ] Jinja2 template: render HTML investigation report
- [ ] PDF generation: WeasyPrint converts HTML → PDF
- [ ] Save report file, create Report record in DB
- [ ] Append audit log entry (immutable, timestamped, signed)
- [ ] Test: complete full pipeline → verify PDF report generated and downloadable

#### 3.6 LangGraph Orchestrator
- [ ] Wire all 5 agents into LangGraph state machine
- [ ] Define edges: PARSING → ANALYZING → INVESTIGATING → AWAITING_APPROVAL → REMEDIATING → AUDITING → COMPLETE
- [ ] Implement conditional edges: rejection → re-investigation flow
- [ ] Connect to Celery for background execution
- [ ] Test: end-to-end pipeline with synthetic logs, no human approval step (automated test)

**Deliverable:** Full 5-agent pipeline runs, PDF report generated ✅

---

## Phase 4: Frontend Dashboard

**Goal:** Beautiful, functional UI showing all pipeline stages.

### Tasks

#### 4.1 Design System
- [ ] Define CSS variables: colors, typography, spacing, shadows, radius
- [ ] Create dark theme with accent colors (threat level = color)
- [ ] Typography: Inter font (Google Fonts)
- [ ] Component library: Button, Card, Badge, Modal, Toast, Loader, Table

#### 4.2 Core Pages
- [ ] **Dashboard (/):** KPI cards (active incidents, alerts today, resolved, risk score avg), live alert feed, agent status indicators
- [ ] **Log Upload (/upload):** Drag-drop zone, org selector (8 orgs), domain picker, synthetic mode toggle, upload progress
- [ ] **Threats (/threats):** Alert table with severity filter, MITRE ATT&CK heatmap, domain breakdown chart
- [ ] **Incident Detail (/incidents/:id):** Timeline component, risk gauge (circular), agent chain visualization, recommended playbook preview
- [ ] **Response Center (/response):** Approval queue cards, playbook detail modal, APPROVE/REJECT buttons, outcome panel
- [ ] **Reports (/reports):** Report cards with download button, audit trail table (paginated)
- [ ] **Compliance (/compliance):** Framework matrix (GDPR/HIPAA/SOC2/ISO27001 × incident types)
- [ ] **Settings (/settings):** Org profile configuration form

#### 4.3 Real-time Updates
- [ ] Implement `useWebSocket` hook
- [ ] Connect to `ws://localhost:8000/ws/events`
- [ ] Dispatch incoming events to Zustand store
- [ ] Animate new alerts appearing in feed

**Deliverable:** All pages navigable, real-time alerts streaming to UI ✅

---

## Phase 5: Integration & Human-in-the-Loop

**Goal:** Full end-to-end flow working from log upload to final report download.

### Tasks

#### 5.1 End-to-End Integration
- [ ] Connect Upload page → triggers Parser agent via Celery task
- [ ] WebSocket streams Parser → Analyst → Investigator updates to UI in real time
- [ ] Incident Detail page loads all investigation data from API
- [ ] Response Center shows pending-approval incidents correctly
- [ ] Approval/Rejection flows through to Remediator correctly
- [ ] Report generated and downloadable after completion

#### 5.2 Human-in-the-Loop Flow Polish
- [ ] Approval confirmation modal with playbook details + risk warning
- [ ] Rejection flow: returns to investigator with operator notes
- [ ] Live status indicator for each stage of the pipeline
- [ ] "Manual Review Required" flag for failed/stalled agents

#### 5.3 SHA-256 Document Integrity
- [ ] Upload stores SHA-256 hash
- [ ] Investigator re-computes hash and compares
- [ ] UI shows: ✅ VERIFIED or ⚠️ TAMPERED with hash diff display

#### 5.4 Eight Organization Profiles
- [ ] Each org has: name, logo (placeholder), default domain, risk threshold, compliance frameworks
- [ ] Org switcher in navbar
- [ ] All data scoped to selected org

**Deliverable:** Complete demo flow works end-to-end in browser ✅

---

## Phase 6: Polish, Reports & Demo Prep

**Goal:** Demo-ready, stable, impressive.

### Tasks

#### 6.1 UI Polish
- [ ] Animations: page transitions, card appear animations, loading skeletons
- [ ] Responsive layout (works on laptop screen at 1080p)
- [ ] Error handling: failed uploads, API errors, empty states
- [ ] Loading states for every async operation

#### 6.2 Demo Data Prep
- [ ] Create 3 pre-built demo scenarios (one-click load):
  - "Network DDoS Attack" — Network domain, high severity
  - "Cloud IAM Breach" — Cloud domain, critical severity  
  - "Insider Data Exfiltration" — Insider Threat domain, medium severity
- [ ] Each scenario: pre-loaded logs → alerts → incident → report (cached, instant)

#### 6.3 Report Quality
- [ ] PDF report includes: incident summary, timeline, risk score, evidence, response taken, compliance impact
- [ ] Report has SENTINEL-AI letterhead, org logo placeholder, page numbers

#### 6.4 Testing
- [ ] Unit tests for each agent (pytest)
- [ ] API integration tests (httpx test client)
- [ ] End-to-end: upload → report download

#### 6.5 Documentation
- [ ] README.md with setup + run instructions
- [ ] API documentation (FastAPI auto-generates Swagger)
- [ ] Architecture diagram (in PROJECT_ARCHITECTURE.md — complete)

#### 6.6 Demo Checklist
- [ ] Docker Compose starts all services cleanly
- [ ] Frontend loads without console errors
- [ ] Upload synthetic logs for "Network DDoS" scenario
- [ ] Alerts appear in real time
- [ ] Navigate to incident, show risk score + timeline
- [ ] Approve response in Response Center
- [ ] Download generated PDF report
- [ ] Show audit trail table

**Deliverable:** Judge-ready demo, clean codebase, all documentation ✅

---

## Technology Installation Commands

### Backend
```bash
# Create and activate virtual environment
uv init backend
cd backend
uv add fastapi uvicorn sqlalchemy alembic psycopg2-binary redis celery
uv add langgraph langchain langchain-google-genai
uv add scikit-learn pandas numpy
uv add reportlab weasyprint jinja2
uv add python-multipart python-dotenv pytest httpx
uv add websockets
```

### Frontend
```bash
cd frontend
npm create vite@latest . -- --template react-ts
npm install
npm install axios @tanstack/react-query zustand
npm install recharts lucide-react
npm install react-router-dom
```

### Docker Services
```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: sentinelai
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: sentinel_secure_pass
    ports: ["5432:5432"]
    volumes: ["postgres_data:/var/lib/postgresql/data"]
  
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
```

---

## Risk & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| LLM API rate limits | Medium | High | Cache LLM responses; use local Ollama fallback |
| Dataset download time | High | Medium | Use synthetic generators for demo; pre-process samples |
| PDF generation errors | Low | Medium | Fallback to JSON report if PDF fails |
| WebSocket disconnects | Medium | Low | Auto-reconnect with exponential backoff |
| PostgreSQL setup issues | Low | High | Include Docker Compose; fallback to SQLite for dev |
| Agent timeout | Medium | Medium | Set per-agent max execution time (30s); graceful degradation |

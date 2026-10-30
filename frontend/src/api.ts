import axios from 'axios'

const api = axios.create({ baseURL: '/api/v1' })

// ── Types ─────────────────────────────────────────────────────────────────────
export interface Org {
  id: string; name: string; industry: string; domain: string;
  risk_threshold: number; compliance_frameworks: string[];
  description: string; created_at: string;
}

export interface Log {
  id: string; org_id: string; original_filename: string;
  sha256_hash: string; domain: string; status: string;
  record_count: number; attack_count: number;
  error_message?: string; created_at: string;
}

export interface Alert {
  id: string; org_id: string; log_id: string;
  title: string; description: string;
  severity_score: number; confidence: number;
  mitre_tactic?: string; mitre_technique?: string; mitre_technique_id?: string;
  attack_type?: string; domain: string; status: string;
  event_count: number; created_at: string;
}

export interface Incident {
  id: string; org_id: string; alert_id: string;
  title: string; status: string; risk_score: number;
  root_cause?: string; timeline?: any[]; integrity_status?: string;
  integrity_original_hash?: string; integrity_current_hash?: string;
  operator_notes?: string; recommended_playbook_id?: string;
  created_at: string; updated_at: string;
  alert?: Partial<Alert>;
  playbook?: Partial<Playbook>;
  audit_trail?: any[];
}

export interface Playbook {
  id: string; code: string; name: string;
  description: string; domain: string;
  actions: string[]; risk_level: string;
  requires_approval: boolean; mitre_tactic?: string;
  estimated_duration?: string;
}

export interface Report {
  id: string; incident_id: string; org_id: string;
  filename: string; compliance_mapping?: any; created_at: string;
}

export interface AlertStats {
  total: number; critical: number; high: number; medium: number; low: number;
  avg_confidence: number; domain_breakdown: Record<string,number>;
  tactic_breakdown: Record<string,number>;
}

export interface IncidentStats {
  total: number; awaiting_approval: number; active: number;
  resolved: number; avg_risk_score: number;
}

// ── Orgs ──────────────────────────────────────────────────────────────────────
export const fetchOrgs = () => api.get<Org[]>('/orgs').then(r => r.data)

// ── Logs ──────────────────────────────────────────────────────────────────────
export const fetchLogs = (orgId?: string) =>
  api.get<Log[]>('/logs', { params: { org_id: orgId } }).then(r => r.data)

export const uploadLog = (form: FormData) =>
  api.post('/logs/upload', form).then(r => r.data)

export const runSynthetic = (domain: string, orgId?: string) =>
  api.post(`/logs/synthetic/${domain}`, null, { params: { org_id: orgId } }).then(r => r.data)

// ── Alerts ────────────────────────────────────────────────────────────────────
export const fetchAlerts = (params?: any) =>
  api.get<Alert[]>('/alerts', { params }).then(r => r.data)

export const fetchAlertStats = (orgId?: string) =>
  api.get<AlertStats>('/alerts/stats', { params: { org_id: orgId } }).then(r => r.data)

// ── Incidents ─────────────────────────────────────────────────────────────────
export const fetchIncidents = (params?: any) =>
  api.get<Incident[]>('/incidents', { params }).then(r => r.data)

export const fetchIncident = (id: string) =>
  api.get<Incident>(`/incidents/${id}`).then(r => r.data)

export const fetchIncidentStats = (orgId?: string) =>
  api.get<IncidentStats>('/incidents/stats', { params: { org_id: orgId } }).then(r => r.data)

export const decideIncident = (id: string, decision: string, notes?: string) =>
  api.post(`/incidents/${id}/decide`, { decision, operator_notes: notes }).then(r => r.data)

// ── Playbooks ─────────────────────────────────────────────────────────────────
export const fetchPlaybooks = (domain?: string) =>
  api.get<Playbook[]>('/playbooks', { params: { domain } }).then(r => r.data)

// ── Reports ───────────────────────────────────────────────────────────────────
export const fetchReports = (orgId?: string) =>
  api.get<Report[]>('/reports', { params: { org_id: orgId } }).then(r => r.data)

export const downloadReport = (id: string) =>
  window.open(`/api/v1/reports/${id}/download`, '_blank')

// ── Audit ─────────────────────────────────────────────────────────────────────
export const fetchAudit = (limit?: number) =>
  api.get('/audit', { params: { limit } }).then(r => r.data)

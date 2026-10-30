import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertOctagon, CheckCircle2, XCircle, Clock, ChevronDown, ChevronRight, Shield } from 'lucide-react'
import { fetchIncidents, fetchIncidentStats, fetchIncident, decideIncident, Incident } from '../api'
import { useAppStore } from '../store'

const STATUS_CONFIG: Record<string, { color: string; badge: string }> = {
  open:              { color: 'var(--high)',     badge: 'badge-high' },
  awaiting_approval: { color: 'var(--medium)',   badge: 'badge-medium' },
  approved:          { color: 'var(--cyan)',     badge: 'badge-cyan' },
  active:            { color: 'var(--critical)', badge: 'badge-critical' },
  resolved:          { color: 'var(--low)',      badge: 'badge-low' },
  rejected:          { color: 'var(--text-muted)', badge: 'badge-gray' },
}

function RiskGauge({ score }: { score: number }) {
  const pct = Math.min(score / 10, 1)
  const color = pct > 0.8 ? 'var(--critical)' : pct > 0.6 ? 'var(--high)' : pct > 0.4 ? 'var(--medium)' : 'var(--low)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 36, height: 36, borderRadius: '50%', background: `conic-gradient(${color} ${pct*360}deg, var(--bg-elevated) 0)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ width: 26, height: 26, borderRadius: '50%', background: 'var(--bg-surface)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, fontWeight: 800, color }}>
          {score.toFixed(1)}
        </div>
      </div>
    </div>
  )
}

function IncidentDetailModal({ id, onClose }: { id: string; onClose: () => void }) {
  const qc = useQueryClient()
  const [notes, setNotes] = useState('')
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null)

  const { data: incident, isLoading } = useQuery({
    queryKey: ['incident', id],
    queryFn: () => fetchIncident(id),
  })

  const decideMutation = useMutation({
    mutationFn: ({ decision, notes }: { decision: string; notes: string }) =>
      decideIncident(id, decision, notes),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident', id] })
      setToast({ msg: 'Decision recorded successfully', type: 'success' })
      setTimeout(() => setToast(null), 3000)
    },
    onError: (e: any) => {
      setToast({ msg: e?.response?.data?.detail ?? 'Failed', type: 'error' })
      setTimeout(() => setToast(null), 3000)
    },
  })

  if (isLoading) return (
    <div className="modal-backdrop">
      <div className="modal" style={{ textAlign: 'center', padding: 60 }}>
        <div style={{ color: 'var(--cyan)', fontSize: 14 }}>Loading incident…</div>
      </div>
    </div>
  )

  if (!incident) return null
  const cfg = STATUS_CONFIG[incident.status] ?? STATUS_CONFIG['open']

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 680 }} onClick={e => e.stopPropagation()}>
        {toast && (
          <div className={`toast ${toast.type}`} style={{ marginBottom: 16 }}>
            {toast.type === 'success' ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            {toast.msg}
          </div>
        )}

        <div className="modal-header">
          <div>
            <div className="modal-title">{incident.title}</div>
            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              <span className={`badge ${cfg.badge}`}>{incident.status.replace('_', ' ')}</span>
              <span className="badge badge-gray">Risk: {incident.risk_score?.toFixed(1)}/10</span>
              {incident.integrity_status && (
                <span className={`badge ${incident.integrity_status === 'verified' ? 'badge-low' : 'badge-critical'}`}>
                  🔐 {incident.integrity_status}
                </span>
              )}
            </div>
          </div>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        {incident.root_cause && (
          <div style={{ background: 'var(--bg-elevated)', borderRadius: 8, padding: '12px 16px', marginBottom: 16, fontSize: 13, color: 'var(--text-secondary)', borderLeft: '3px solid var(--cyan)' }}>
            <strong style={{ color: 'var(--text-primary)' }}>Root Cause:</strong> {incident.root_cause}
          </div>
        )}

        {/* Alert & Playbook */}
        <div className="grid-2" style={{ gap: 12, marginBottom: 16 }}>
          {incident.alert && (
            <div style={{ background: 'var(--bg-elevated)', borderRadius: 8, padding: '12px 16px' }}>
              <div className="form-label">Linked Alert</div>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{incident.alert.title}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{incident.alert.domain} · {incident.alert.mitre_tactic}</div>
            </div>
          )}
          {incident.playbook && (
            <div style={{ background: 'var(--bg-elevated)', borderRadius: 8, padding: '12px 16px' }}>
              <div className="form-label">Recommended Playbook</div>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{incident.playbook.name}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{incident.playbook.code} · {incident.playbook.risk_level}</div>
            </div>
          )}
        </div>

        {/* Timeline */}
        {incident.timeline && incident.timeline.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div className="form-label">Event Timeline</div>
            <div className="timeline">
              {incident.timeline.map((ev: any, i: number) => (
                <div key={i} className="timeline-item">
                  <div style={{ position: 'relative' }}>
                    <div className="timeline-dot" />
                    {i < incident.timeline!.length - 1 && <div className="timeline-line" />}
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-ts">{ev.timestamp ?? ev.ts ?? ''}</div>
                    <div className="timeline-action">{ev.action ?? ev.description ?? JSON.stringify(ev)}</div>
                    {ev.details && <div className="timeline-meta">{ev.details}</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Playbook actions */}
        {incident.playbook?.actions && incident.playbook.actions.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div className="form-label">Playbook Steps</div>
            {incident.playbook.actions.map((action: string, i: number) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '6px 0', borderBottom: '1px solid rgba(0,212,255,0.05)' }}>
                <span style={{ background: 'var(--cyan-glow)', color: 'var(--cyan)', borderRadius: 4, padding: '1px 7px', fontSize: 11, fontWeight: 700, flexShrink: 0 }}>{i+1}</span>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{action}</span>
              </div>
            ))}
          </div>
        )}

        {/* Approval panel */}
        {incident.status === 'awaiting_approval' && (
          <div style={{ background: 'rgba(255,149,0,0.07)', border: '1px solid rgba(255,149,0,0.25)', borderRadius: 10, padding: 16, marginBottom: 16 }}>
            <div style={{ fontWeight: 700, color: 'var(--high)', marginBottom: 10, fontSize: 13 }}>⚠️ Operator Approval Required</div>
            <textarea
              className="form-control"
              placeholder="Add operator notes (optional)…"
              style={{ resize: 'vertical', minHeight: 70, marginBottom: 10, fontSize: 12 }}
              value={notes}
              onChange={e => setNotes(e.target.value)}
            />
            <div className="modal-footer" style={{ marginTop: 0 }}>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => decideMutation.mutate({ decision: 'reject', notes })}
                disabled={decideMutation.isPending}
              >
                <XCircle size={14} /> Reject
              </button>
              <button
                className="btn btn-success btn-sm"
                onClick={() => decideMutation.mutate({ decision: 'approve', notes })}
                disabled={decideMutation.isPending}
              >
                <CheckCircle2 size={14} /> Approve & Execute
              </button>
            </div>
          </div>
        )}

        {/* Audit trail */}
        {incident.audit_trail && incident.audit_trail.length > 0 && (
          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--text-muted)', padding: '6px 0' }}>
              Audit Trail ({incident.audit_trail.length} entries)
            </summary>
            <div style={{ marginTop: 8, maxHeight: 180, overflowY: 'auto' }}>
              {incident.audit_trail.map((entry: any, i: number) => (
                <div key={i} style={{ fontSize: 11, padding: '4px 0', borderBottom: '1px solid rgba(0,212,255,0.05)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                  {entry.timestamp} · {entry.action}
                </div>
              ))}
            </div>
          </details>
        )}
      </div>
    </div>
  )
}

export default function IncidentsPage() {
  const { selectedOrg } = useAppStore()
  const orgId = selectedOrg?.id
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data: incidents = [], isLoading } = useQuery({
    queryKey: ['incidents', orgId, statusFilter],
    queryFn: () => fetchIncidents({ org_id: orgId, status: statusFilter || undefined }),
    refetchInterval: 10_000,
  })

  const { data: stats } = useQuery({
    queryKey: ['incidentStats', orgId],
    queryFn: () => fetchIncidentStats(orgId),
  })

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">Incidents</div>
          <div className="page-subtitle">AI-generated incidents requiring operator review</div>
        </div>
      </div>

      <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(5,1fr)', marginBottom: 24 }}>
        {[
          { label: 'Total',      value: stats?.total ?? 0,              color: 'var(--cyan)' },
          { label: 'Awaiting',   value: stats?.awaiting_approval ?? 0,  color: 'var(--medium)',   filter: 'awaiting_approval' },
          { label: 'Active',     value: stats?.active ?? 0,             color: 'var(--high)',     filter: 'active' },
          { label: 'Resolved',   value: stats?.resolved ?? 0,           color: 'var(--low)',      filter: 'resolved' },
          { label: 'Avg Risk',   value: stats?.avg_risk_score?.toFixed(1) ?? '—', color: 'var(--critical)' },
        ].map(({ label, value, color, filter }) => (
          <div
            key={label}
            className="kpi-card"
            style={{ '--accent': color, cursor: filter ? 'pointer' : 'default' } as React.CSSProperties}
            onClick={() => filter && setStatusFilter(prev => prev === filter ? '' : filter)}
          >
            <div className="kpi-label">{label}</div>
            <div className="kpi-value" style={{ color }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <select className="form-control" style={{ width: 'auto', minWidth: 150 }} value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All Statuses</option>
          {['open','awaiting_approval','approved','active','resolved','rejected'].map(s => (
            <option key={s} value={s}>{s.replace('_', ' ')}</option>
          ))}
        </select>
        {statusFilter && <button className="btn btn-ghost btn-sm" onClick={() => setStatusFilter('')}>Clear</button>}
      </div>

      {selectedId && <IncidentDetailModal id={selectedId} onClose={() => setSelectedId(null)} />}

      <div className="card">
        <div className="section-title"><AlertOctagon size={16} className="text-cyan" /> Incidents ({incidents.length})</div>
        {isLoading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading…</div>
        ) : incidents.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🔒</div>
            <div className="empty-title">No incidents</div>
            <div className="empty-sub">Incidents are auto-generated when high-severity alerts are detected</div>
          </div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Incident</th>
                  <th>Risk</th>
                  <th>Integrity</th>
                  <th>Playbook</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {incidents.map(inc => {
                  const cfg = STATUS_CONFIG[inc.status] ?? STATUS_CONFIG['open']
                  return (
                    <tr key={inc.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedId(inc.id)}>
                      <td>
                        <span className={`badge ${cfg.badge}`} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          {inc.status === 'awaiting_approval' && <Clock size={10} />}
                          {inc.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td style={{ maxWidth: 260 }}>
                        <div style={{ fontWeight: 600, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.title}</div>
                        {inc.root_cause && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                            {inc.root_cause.slice(0, 80)}
                          </div>
                        )}
                      </td>
                      <td><RiskGauge score={inc.risk_score} /></td>
                      <td>
                        {inc.integrity_status ? (
                          <span className={`badge ${inc.integrity_status === 'verified' ? 'badge-low' : 'badge-critical'}`}>
                            {inc.integrity_status === 'verified' ? '🔐 Verified' : '⚠️ ' + inc.integrity_status}
                          </span>
                        ) : '—'}
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {inc.playbook?.code ?? '—'}
                      </td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {new Date(inc.created_at).toLocaleString()}
                      </td>
                      <td>
                        {inc.status === 'awaiting_approval' && (
                          <span style={{ fontSize: 10, color: 'var(--medium)', fontWeight: 700 }}>NEEDS REVIEW</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

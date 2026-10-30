import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldAlert, Filter, RefreshCw } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { fetchAlerts, fetchAlertStats, Alert } from '../api'
import { useAppStore } from '../store'

function severityClass(score: number) {
  if (score >= 8) return 'critical'
  if (score >= 6) return 'high'
  if (score >= 4) return 'medium'
  return 'low'
}

function severityBadge(score: number) {
  const s = severityClass(score)
  return <span className={`badge badge-${s}`}>{s.toUpperCase()}</span>
}

function AlertRow({ alert, onClick }: { alert: Alert; onClick: () => void }) {
  const sev = severityClass(alert.severity_score)
  return (
    <tr style={{ cursor: 'pointer' }} onClick={onClick}>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className={`status-dot ${sev}`} />
          {severityBadge(alert.severity_score)}
        </div>
      </td>
      <td style={{ maxWidth: 280 }}>
        <div style={{ fontWeight: 600, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {alert.title}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {alert.description}
        </div>
      </td>
      <td><span className="badge badge-cyan">{alert.domain}</span></td>
      <td>
        {alert.mitre_tactic && (
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-primary)' }}>{alert.mitre_tactic}</div>
            {alert.mitre_technique && (
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {alert.mitre_technique_id} · {alert.mitre_technique}
              </div>
            )}
          </div>
        )}
      </td>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 36, height: 36, borderRadius: '50%', background: `conic-gradient(var(--cyan) ${alert.confidence * 360}deg, var(--bg-elevated) 0)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--bg-surface)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, fontWeight: 700, color: 'var(--cyan)' }}>
              {(alert.confidence * 100).toFixed(0)}
            </div>
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>%</span>
        </div>
      </td>
      <td><span className={`badge badge-${alert.status === 'open' ? 'high' : alert.status === 'escalated' ? 'critical' : 'gray'}`}>{alert.status}</span></td>
      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
        {new Date(alert.created_at).toLocaleString()}
      </td>
    </tr>
  )
}

export default function AlertsPage() {
  const { selectedOrg } = useAppStore()
  const orgId = selectedOrg?.id
  const qc = useQueryClient()
  const [domainFilter, setDomainFilter] = useState('')
  const [sevFilter,    setSevFilter]    = useState('')
  const [selected, setSelected] = useState<Alert | null>(null)

  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['alerts', orgId, domainFilter, sevFilter],
    queryFn: () => fetchAlerts({ org_id: orgId, domain: domainFilter || undefined, severity: sevFilter || undefined }),
    refetchInterval: 15_000,
  })

  const { data: stats } = useQuery({
    queryKey: ['alertStats', orgId],
    queryFn: () => fetchAlertStats(orgId),
  })

  const DOMAINS = [...new Set(alerts.map(a => a.domain))].sort()

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">Alerts</div>
          <div className="page-subtitle">{alerts.length} alert{alerts.length !== 1 ? 's' : ''} · AI-generated detections</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={() => qc.invalidateQueries({ queryKey: ['alerts'] })}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(5,1fr)', marginBottom: 24 }}>
        {[
          { label: 'Critical', value: stats?.critical ?? 0, color: 'var(--critical)' },
          { label: 'High',     value: stats?.high ?? 0,     color: 'var(--high)' },
          { label: 'Medium',   value: stats?.medium ?? 0,   color: 'var(--medium)' },
          { label: 'Low',      value: stats?.low ?? 0,      color: 'var(--low)' },
          { label: 'Total',    value: stats?.total ?? 0,    color: 'var(--cyan)' },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="kpi-card"
            style={{ '--accent': color, cursor: 'pointer' } as React.CSSProperties}
            onClick={() => setSevFilter(label === 'Total' ? '' : label.toLowerCase())}
          >
            <div className="kpi-label">{label}</div>
            <div className="kpi-value" style={{ color }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Filter size={14} color="var(--text-muted)" />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Filter:</span>
        </div>
        <select className="form-control" style={{ width: 'auto', minWidth: 130 }} value={domainFilter} onChange={e => setDomainFilter(e.target.value)}>
          <option value="">All Domains</option>
          {DOMAINS.map(d => <option key={d} value={d}>{d}</option>)}
        </select>
        <select className="form-control" style={{ width: 'auto', minWidth: 130 }} value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All Severities</option>
          {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(domainFilter || sevFilter) && (
          <button className="btn btn-ghost btn-sm" onClick={() => { setDomainFilter(''); setSevFilter('') }}>Clear</button>
        )}
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="modal-backdrop" onClick={() => setSelected(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <div className="modal-title">{selected.title}</div>
                <div style={{ marginTop: 6, display: 'flex', gap: 8 }}>
                  {severityBadge(selected.severity_score)}
                  <span className="badge badge-cyan">{selected.domain}</span>
                  <span className={`badge badge-${selected.status === 'open' ? 'high' : 'gray'}`}>{selected.status}</span>
                </div>
              </div>
              <button className="modal-close" onClick={() => setSelected(null)}>✕</button>
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>{selected.description}</p>
            <div className="grid-2" style={{ gap: 12, marginBottom: 16 }}>
              <div>
                <div className="form-label">MITRE Tactic</div>
                <div style={{ fontSize: 13 }}>{selected.mitre_tactic ?? '—'}</div>
              </div>
              <div>
                <div className="form-label">MITRE Technique</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                  {selected.mitre_technique_id} {selected.mitre_technique ?? '—'}
                </div>
              </div>
              <div>
                <div className="form-label">Confidence</div>
                <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--cyan)' }}>
                  {(selected.confidence * 100).toFixed(1)}%
                </div>
              </div>
              <div>
                <div className="form-label">Severity Score</div>
                <div style={{ fontSize: 20, fontWeight: 800, color: selected.severity_score >= 8 ? 'var(--critical)' : 'var(--high)' }}>
                  {selected.severity_score.toFixed(1)} / 10
                </div>
              </div>
              <div>
                <div className="form-label">Attack Type</div>
                <div style={{ fontSize: 13 }}>{selected.attack_type ?? '—'}</div>
              </div>
              <div>
                <div className="form-label">Events</div>
                <div style={{ fontSize: 13 }}>{selected.event_count?.toLocaleString()}</div>
              </div>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', borderTop: '1px solid var(--border)', paddingTop: 12 }}>
              Alert ID: {selected.id}<br />
              Detected: {new Date(selected.created_at).toLocaleString()}
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="card">
        <div className="section-title">
          <ShieldAlert size={16} className="text-cyan" /> Detections ({alerts.length})
        </div>
        {isLoading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading…</div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🛡️</div>
            <div className="empty-title">No alerts detected</div>
            <div className="empty-sub">Run a log ingestion or synthetic pipeline to generate alerts</div>
          </div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Domain</th>
                  <th>MITRE</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => <AlertRow key={a.id} alert={a} onClick={() => setSelected(a)} />)}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

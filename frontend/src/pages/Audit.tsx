import { useQuery } from '@tanstack/react-query'
import { ClipboardList } from 'lucide-react'
import { fetchAudit } from '../api'

const ACTION_COLOR: Record<string, string> = {
  log_ingest:          'var(--cyan)',
  alert_created:       'var(--high)',
  incident_created:    'var(--critical)',
  incident_approved:   'var(--low)',
  incident_rejected:   'var(--text-muted)',
  playbook_executed:   'var(--purple)',
  report_generated:    'var(--cyan)',
}

export default function AuditPage() {
  const { data: entries = [], isLoading } = useQuery({
    queryKey: ['audit'],
    queryFn: () => fetchAudit(200),
    refetchInterval: 15_000,
  })

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">Audit Trail</div>
          <div className="page-subtitle">Tamper-evident log of all system actions — {entries.length} entries</div>
        </div>
      </div>

      {isLoading ? (
        <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)' }}>Loading audit trail…</div>
      ) : entries.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <div className="empty-title">No audit entries yet</div>
          <div className="empty-sub">All system actions will appear here in real-time</div>
        </div>
      ) : (
        <div className="card">
          <div className="section-title"><ClipboardList size={16} className="text-cyan" /> System Activity</div>
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Entity</th>
                  <th>Details</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry: any) => (
                  <tr key={entry.id}>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(entry.timestamp ?? entry.created_at).toLocaleString()}
                    </td>
                    <td>
                      <span style={{ fontSize: 12, fontWeight: 600, color: ACTION_COLOR[entry.action] ?? 'var(--text-secondary)' }}>
                        {entry.action?.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{entry.actor ?? 'system'}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{entry.entity_type ?? '—'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {entry.details ? (typeof entry.details === 'string' ? entry.details : JSON.stringify(entry.details)).slice(0, 100) : '—'}
                    </td>
                    <td className="mono" style={{ fontSize: 9, color: 'var(--text-muted)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {entry.hash ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

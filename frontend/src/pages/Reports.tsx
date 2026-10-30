import { useQuery } from '@tanstack/react-query'
import { FileText, Download } from 'lucide-react'
import { fetchReports, downloadReport } from '../api'
import { useAppStore } from '../store'

export default function ReportsPage() {
  const { selectedOrg } = useAppStore()
  const orgId = selectedOrg?.id

  const { data: reports = [], isLoading } = useQuery({
    queryKey: ['reports', orgId],
    queryFn: () => fetchReports(orgId),
    refetchInterval: 30_000,
  })

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">Reports</div>
          <div className="page-subtitle">AI-generated compliance and incident reports</div>
        </div>
      </div>

      {isLoading ? (
        <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)' }}>Loading reports…</div>
      ) : reports.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📊</div>
          <div className="empty-title">No reports generated yet</div>
          <div className="empty-sub">Reports are auto-generated when incidents are resolved</div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 20 }}>
          {reports.map(report => (
            <div key={report.id} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ width: 42, height: 42, borderRadius: 10, background: 'var(--cyan-glow)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <FileText size={20} color="var(--cyan)" />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {report.filename}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {new Date(report.created_at).toLocaleString()}
                  </div>
                </div>
              </div>

              {report.compliance_mapping && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: 0.8, textTransform: 'uppercase', marginBottom: 8 }}>Compliance Mapping</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {Object.entries(report.compliance_mapping).map(([framework, controls]) => (
                      <span key={framework} className="badge badge-info">
                        {framework}: {Array.isArray(controls) ? controls.slice(0, 2).join(', ') : String(controls)}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <button
                className="btn btn-ghost btn-sm w-full"
                onClick={() => downloadReport(report.id)}
                style={{ marginTop: 'auto' }}
              >
                <Download size={14} /> Download PDF
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

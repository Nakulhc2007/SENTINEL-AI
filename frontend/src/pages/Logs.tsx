import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, RefreshCw, Database, CheckCircle2, XCircle, Clock, ChevronRight } from 'lucide-react'
import { useDropzone } from 'react-dropzone'
import { fetchLogs, uploadLog, runSynthetic, Log } from '../api'
import { useAppStore } from '../store'

const DOMAINS = ['network','endpoint','identity','cloud','appsec','email','data','physical']

const STATUS_COLOR: Record<string, string> = {
  completed: 'var(--low)',
  processing: 'var(--cyan)',
  failed: 'var(--critical)',
  pending: 'var(--medium)',
}

function LogRow({ log }: { log: Log }) {
  const statusColor = STATUS_COLOR[log.status] ?? 'var(--text-muted)'
  return (
    <tr>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="status-dot" style={{ background: statusColor, boxShadow: `0 0 6px ${statusColor}`, animation: log.status === 'processing' ? 'pulse 2s infinite' : 'none' }} />
          {log.status}
        </div>
      </td>
      <td className="mono" style={{ fontSize: 12, color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {log.original_filename || log.id.slice(0, 12) + '…'}
      </td>
      <td><span className="badge badge-cyan">{log.domain}</span></td>
      <td style={{ color: 'var(--text-secondary)' }}>{log.record_count?.toLocaleString() ?? '—'}</td>
      <td style={{ color: log.attack_count > 0 ? 'var(--critical)' : 'var(--low)' }}>
        {log.attack_count?.toLocaleString() ?? '—'}
      </td>
      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
        {new Date(log.created_at).toLocaleString()}
      </td>
      {log.error_message && (
        <td style={{ color: 'var(--critical)', fontSize: 11 }}>{log.error_message.slice(0, 60)}</td>
      )}
    </tr>
  )
}

export default function LogsPage() {
  const { selectedOrg } = useAppStore()
  const orgId = selectedOrg?.id
  const qc = useQueryClient()
  const [syntheticDomain, setSyntheticDomain] = useState('network')
  const [toast, setToast] = useState<{ msg: string; type: 'success'|'error' } | null>(null)

  const showToast = (msg: string, type: 'success'|'error' = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 4000)
  }

  const { data: logs = [], isLoading } = useQuery({
    queryKey: ['logs', orgId],
    queryFn: () => fetchLogs(orgId),
    refetchInterval: 10_000,
  })

  const uploadMutation = useMutation({
    mutationFn: (form: FormData) => uploadLog(form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['logs'] })
      showToast('Log uploaded — processing started', 'success')
    },
    onError: (e: any) => showToast(e?.response?.data?.detail ?? 'Upload failed', 'error'),
  })

  const syntheticMutation = useMutation({
    mutationFn: () => runSynthetic(syntheticDomain, orgId),
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ['logs'] })
      showToast(`Synthetic pipeline complete: ${d.alerts_generated ?? 0} alerts generated`, 'success')
    },
    onError: (e: any) => showToast(e?.response?.data?.detail ?? 'Synthetic run failed', 'error'),
  })

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: { 'text/csv': ['.csv'], 'text/plain': ['.log', '.txt'], 'application/json': ['.json'] },
    multiple: false,
    onDrop: (files) => {
      if (!files[0]) return
      const form = new FormData()
      form.append('file', files[0])
      if (orgId) form.append('org_id', orgId)
      uploadMutation.mutate(form)
    },
  })

  const completed = logs.filter(l => l.status === 'completed').length
  const processing = logs.filter(l => l.status === 'processing').length
  const failed = logs.filter(l => l.status === 'failed').length
  const totalAttacks = logs.reduce((s, l) => s + (l.attack_count || 0), 0)

  return (
    <div className="page">
      {toast && (
        <div className="toast-stack">
          <div className={`toast ${toast.type}`}>
            {toast.type === 'success' ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            {toast.msg}
          </div>
        </div>
      )}

      <div className="page-header">
        <div>
          <div className="page-title">Log Pipeline</div>
          <div className="page-subtitle">Upload security logs or generate synthetic training data</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={() => qc.invalidateQueries({ queryKey: ['logs'] })}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Stats row */}
      <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)', marginBottom: 24 }}>
        {[
          { label: 'Total Logs', value: logs.length, icon: Database, accent: 'var(--cyan)' },
          { label: 'Completed', value: completed, icon: CheckCircle2, accent: 'var(--low)' },
          { label: 'Processing', value: processing, icon: Clock, accent: 'var(--high)' },
          { label: 'Attacks Found', value: totalAttacks, icon: XCircle, accent: 'var(--critical)' },
        ].map(({ label, value, icon: Icon, accent }) => (
          <div key={label} className="kpi-card" style={{ '--accent': accent } as React.CSSProperties}>
            <div className="kpi-label">{label}</div>
            <div className="kpi-value" style={{ color: accent }}>{value}</div>
            <div className="kpi-icon"><Icon size={22} color={accent} /></div>
          </div>
        ))}
      </div>

      <div className="grid-2 mb-6">
        {/* Upload zone */}
        <div className="card">
          <div className="section-title"><Upload size={16} className="text-cyan" /> Upload Log File</div>
          <div {...getRootProps()} className={`upload-zone ${isDragActive ? 'drag-over' : ''}`}>
            <input {...getInputProps()} />
            <div className="upload-icon">📂</div>
            <div className="upload-text">
              {uploadMutation.isPending ? 'Uploading…' : isDragActive ? 'Drop here!' : 'Drop a log file here'}
            </div>
            <div className="upload-sub">Supports .csv, .log, .txt, .json — max 50 MB</div>
          </div>
          {uploadMutation.isPending && (
            <div style={{ marginTop: 12, textAlign: 'center', color: 'var(--cyan)', fontSize: 13 }}>
              <RefreshCw size={14} style={{ animation: 'spin 1s linear infinite', marginRight: 6 }} />
              Processing through AI pipeline…
            </div>
          )}
        </div>

        {/* Synthetic run */}
        <div className="card">
          <div className="section-title"><RefreshCw size={16} className="text-cyan" /> Synthetic Log Generator</div>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
            Generate realistic synthetic security logs for any domain. Data is seeded from real-world attack patterns and processed through the full AI agent pipeline.
          </p>
          <div className="form-group">
            <label className="form-label">Target Domain</label>
            <select
              className="form-control"
              value={syntheticDomain}
              onChange={e => setSyntheticDomain(e.target.value)}
            >
              {DOMAINS.map(d => (
                <option key={d} value={d}>{d.charAt(0).toUpperCase() + d.slice(1)}</option>
              ))}
            </select>
          </div>
          <button
            className="btn btn-primary w-full"
            onClick={() => syntheticMutation.mutate()}
            disabled={syntheticMutation.isPending}
          >
            {syntheticMutation.isPending
              ? <><RefreshCw size={14} style={{ animation: 'spin 1s linear infinite' }} /> Running pipeline…</>
              : <><ChevronRight size={14} /> Run Synthetic Pipeline</>
            }
          </button>
          {syntheticMutation.isSuccess && (
            <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(52,199,89,0.1)', borderRadius: 8, border: '1px solid rgba(52,199,89,0.3)', fontSize: 12, color: 'var(--low)' }}>
              ✓ Pipeline complete — check alerts for results
            </div>
          )}
        </div>
      </div>

      {/* Logs table */}
      <div className="card">
        <div className="section-title"><Database size={16} className="text-cyan" /> Log Ingestion History ({logs.length})</div>
        {isLoading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading…</div>
        ) : logs.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📋</div>
            <div className="empty-title">No logs ingested yet</div>
            <div className="empty-sub">Upload a log file or run the synthetic generator above</div>
          </div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>File</th>
                  <th>Domain</th>
                  <th>Records</th>
                  <th>Attacks</th>
                  <th>Ingested</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => <LogRow key={log.id} log={log} />)}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}

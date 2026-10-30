import { useQuery } from '@tanstack/react-query'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, RadialBarChart, RadialBar
} from 'recharts'
import {
  ShieldAlert, Activity, AlertTriangle, CheckCircle2,
  Cpu, ArrowRight, Zap, TrendingUp, Globe, Lock
} from 'lucide-react'
import {
  fetchAlertStats, fetchIncidentStats, fetchAlerts, fetchIncidents
} from '../api'
import { useAppStore } from '../store'
import { useWebSocket } from '../hooks/useWebSocket'

const COLORS = ['#ff2d55', '#ff9500', '#ffcc00', '#34c759']

function KpiCard({
  label, value, sub, icon: Icon, accent = 'var(--cyan)', pulse = false
}: {
  label: string; value: string | number; sub?: string;
  icon: React.ElementType; accent?: string; pulse?: boolean
}) {
  return (
    <div className="kpi-card" style={{ '--accent': accent } as React.CSSProperties}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={{ color: accent }}>{value}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
      <div className="kpi-icon">
        <Icon size={24} color={accent} style={pulse ? { animation: 'pulse 2s infinite' } : {}} />
      </div>
    </div>
  )
}

const PIPELINE_AGENTS = [
  { name: 'Parser', emoji: '📋', status: 'done' },
  { name: 'Analyst', emoji: '🔍', status: 'done' },
  { name: 'Investigator', emoji: '🕵️', status: 'active' },
  { name: 'Auditor', emoji: '📝', status: 'active' },
  { name: 'Remediator', emoji: '🛡️', status: 'pending' },
]

const DOMAINS = [
  { name: 'Network', count: 42, color: '#00d4ff' },
  { name: 'Endpoint', count: 31, color: '#7c3aed' },
  { name: 'Identity', count: 18, color: '#ff9500' },
  { name: 'Cloud', count: 14, color: '#34c759' },
  { name: 'AppSec', count: 9, color: '#ff2d55' },
  { name: 'Email', count: 7, color: '#ffcc00' },
  { name: 'Data', count: 5, color: '#5856d6' },
  { name: 'Physical', count: 3, color: '#ff6b35' },
]

export default function Dashboard() {
  const { selectedOrg } = useAppStore()
  const orgId = selectedOrg?.id

  const { data: alertStats } = useQuery({
    queryKey: ['alertStats', orgId],
    queryFn: () => fetchAlertStats(orgId),
    refetchInterval: 30_000,
  })

  const { data: incidentStats } = useQuery({
    queryKey: ['incidentStats', orgId],
    queryFn: () => fetchIncidentStats(orgId),
    refetchInterval: 30_000,
  })

  const { data: recentAlerts } = useQuery({
    queryKey: ['recentAlerts', orgId],
    queryFn: () => fetchAlerts({ org_id: orgId, limit: 10 }),
    refetchInterval: 15_000,
  })

  const { events, connected } = useWebSocket()

  // Build chart data from real API or fallback
  const severityData = [
    { name: 'Critical', value: alertStats?.critical ?? 0 },
    { name: 'High',     value: alertStats?.high ?? 0 },
    { name: 'Medium',   value: alertStats?.medium ?? 0 },
    { name: 'Low',      value: alertStats?.low ?? 0 },
  ]

  const domainData = alertStats?.domain_breakdown
    ? Object.entries(alertStats.domain_breakdown).map(([name, value]) => ({ name, value }))
    : DOMAINS.map(d => ({ name: d.name, value: d.count }))

  const tacticData = alertStats?.tactic_breakdown
    ? Object.entries(alertStats.tactic_breakdown).slice(0, 8).map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="page">
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">
            <span className="text-cyan">●</span> Security Operations Center
          </div>
          <div className="page-subtitle">
            {selectedOrg ? `Monitoring: ${selectedOrg.name}` : 'All Organizations'} · Real-time threat intelligence
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div className="ws-indicator">
            <div className={`ws-dot ${connected ? 'connected' : 'disconnected'}`} />
            {connected ? 'Live' : 'Reconnecting…'}
          </div>
        </div>
      </div>

      {/* KPI Grid */}
      <div className="kpi-grid">
        <KpiCard
          label="Total Alerts"
          value={alertStats?.total ?? '—'}
          sub={`${alertStats?.critical ?? 0} critical`}
          icon={ShieldAlert}
          accent="var(--critical)"
          pulse={(alertStats?.critical ?? 0) > 0}
        />
        <KpiCard
          label="Active Incidents"
          value={incidentStats?.active ?? '—'}
          sub={`${incidentStats?.awaiting_approval ?? 0} awaiting approval`}
          icon={AlertTriangle}
          accent="var(--high)"
        />
        <KpiCard
          label="Avg Confidence"
          value={alertStats?.avg_confidence != null ? `${(alertStats.avg_confidence * 100).toFixed(0)}%` : '—'}
          sub="AI detection accuracy"
          icon={Activity}
          accent="var(--cyan)"
        />
        <KpiCard
          label="Resolved"
          value={incidentStats?.resolved ?? '—'}
          sub="incidents closed"
          icon={CheckCircle2}
          accent="var(--low)"
        />
        <KpiCard
          label="Avg Risk Score"
          value={incidentStats?.avg_risk_score?.toFixed(1) ?? '—'}
          sub="out of 10.0"
          icon={TrendingUp}
          accent="var(--purple)"
        />
        <KpiCard
          label="Domains Covered"
          value="8"
          sub="security domains active"
          icon={Globe}
          accent="#818cf8"
        />
      </div>

      {/* Charts row 1 */}
      <div className="grid-2 mb-6">
        {/* Severity breakdown pie */}
        <div className="card">
          <div className="section-title"><Zap size={16} className="text-cyan" /> Alert Severity Distribution</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={severityData} cx="50%" cy="50%" innerRadius={60} outerRadius={95}
                dataKey="value" paddingAngle={3}
                label={({ name, value }) => value > 0 ? `${name}: ${value}` : ''}>
                {severityData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                formatter={(v: number) => [v, 'Alerts']}
              />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', justifyContent: 'center', marginTop: 8 }}>
            {['Critical','High','Medium','Low'].map((s, i) => (
              <span key={s} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--text-secondary)' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: COLORS[i], display: 'inline-block' }} />
                {s}
              </span>
            ))}
          </div>
        </div>

        {/* Domain heatmap */}
        <div className="card">
          <div className="section-title"><Globe size={16} className="text-cyan" /> Alerts by Domain</div>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={domainData} layout="vertical" margin={{ left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.06)" horizontal={false} />
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} width={70} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {domainData.map((_, i) => (
                  <Cell key={i} fill={DOMAINS[i % DOMAINS.length]?.color ?? 'var(--cyan)'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* MITRE Tactics + Agent Pipeline */}
      <div className="grid-2 mb-6">
        {/* MITRE tactics bar chart */}
        <div className="card">
          <div className="section-title"><Lock size={16} className="text-cyan" /> MITRE ATT&CK Tactics</div>
          {tacticData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={tacticData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.06)" />
                <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} angle={-30} textAnchor="end" height={40} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" fill="var(--purple)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: 40 }}>
              <div className="empty-icon">🎯</div>
              <div className="empty-title">No tactics yet</div>
              <div className="empty-sub">Process logs to populate MITRE breakdown</div>
            </div>
          )}
        </div>

        {/* Agent pipeline */}
        <div className="card">
          <div className="section-title"><Cpu size={16} className="text-cyan" /> AI Agent Pipeline</div>
          <div className="pipeline" style={{ overflowX: 'auto', paddingBottom: 8 }}>
            {PIPELINE_AGENTS.map((agent, i) => (
              <div key={agent.name} style={{ display: 'flex', alignItems: 'center' }}>
                <div className="pipeline-agent">
                  <div className={`pipeline-icon ${agent.status}`}>{agent.emoji}</div>
                  <span className="pipeline-label">{agent.name}</span>
                  <span style={{ fontSize: 10, color: agent.status === 'done' ? 'var(--low)' : agent.status === 'active' ? 'var(--cyan)' : 'var(--text-muted)' }}>
                    {agent.status === 'done' ? '✓ Done' : agent.status === 'active' ? '⟳ Running' : '○ Pending'}
                  </span>
                </div>
                {i < PIPELINE_AGENTS.length - 1 && (
                  <ArrowRight size={16} color="var(--text-muted)" style={{ margin: '0 4px', flexShrink: 0 }} />
                )}
              </div>
            ))}
          </div>

          <div style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
            <div className="section-title" style={{ marginBottom: 10 }}>Recent Alerts</div>
            {recentAlerts?.slice(0, 4).map(alert => (
              <div key={alert.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid rgba(0,212,255,0.05)' }}>
                <span className={`status-dot ${alert.severity_score >= 8 ? 'critical' : alert.severity_score >= 6 ? 'high' : 'active'}`} />
                <span style={{ flex: 1, fontSize: 12, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{alert.title}</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>{alert.domain}</span>
              </div>
            ))}
            {(!recentAlerts || recentAlerts.length === 0) && (
              <div style={{ color: 'var(--text-muted)', fontSize: 13, textAlign: 'center', padding: '20px 0' }}>No alerts yet</div>
            )}
          </div>
        </div>
      </div>

      {/* Live Event Feed */}
      <div className="card">
        <div className="section-title">
          <Activity size={16} className="text-cyan" />
          Live Event Stream
          <div className="ws-indicator" style={{ marginLeft: 0 }}>
            <div className={`ws-dot ${connected ? 'connected' : 'disconnected'}`} />
            {connected ? 'Connected' : 'Reconnecting'}
          </div>
        </div>
        <div className="live-feed">
          {events.length === 0 && (
            <div className="empty-state" style={{ padding: 30 }}>
              <div className="empty-icon">📡</div>
              <div className="empty-title">Awaiting events…</div>
              <div className="empty-sub">Upload logs or run a synthetic pipeline to see real-time events</div>
            </div>
          )}
          {events.map(ev => (
            <div key={ev.id} className={`feed-item ${ev.type}`}>
              <span className="feed-ts">{new Date(ev.ts).toLocaleTimeString()}</span>
              <span className="feed-msg">{ev.message}</span>
              {ev.org && <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>{ev.org}</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

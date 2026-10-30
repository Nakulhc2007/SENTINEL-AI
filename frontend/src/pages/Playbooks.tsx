import { useQuery } from '@tanstack/react-query'
import { BookOpen, CheckSquare, Clock, AlertTriangle } from 'lucide-react'
import { fetchPlaybooks, Playbook } from '../api'

const RISK_BADGE: Record<string, string> = {
  low:      'badge-low',
  medium:   'badge-medium',
  high:     'badge-high',
  critical: 'badge-critical',
}

const DOMAIN_EMOJI: Record<string, string> = {
  network:'🌐', endpoint:'💻', identity:'🔑', cloud:'☁️',
  appsec:'🔍', email:'📧', data:'🗄️', physical:'🏢',
}

function PlaybookCard({ pb }: { pb: Playbook }) {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--cyan)', marginBottom: 4 }}>{pb.code}</div>
          <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-primary)', marginBottom: 6 }}>{pb.name}</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <span className={`badge ${RISK_BADGE[pb.risk_level] ?? 'badge-gray'}`}>{pb.risk_level}</span>
            <span className="badge badge-cyan">{DOMAIN_EMOJI[pb.domain] ?? '🔒'} {pb.domain}</span>
            {pb.requires_approval && (
              <span className="badge badge-medium">⚠️ Approval Required</span>
            )}
          </div>
        </div>
        <div style={{ fontSize: 32, opacity: 0.6 }}>{DOMAIN_EMOJI[pb.domain] ?? '🛡️'}</div>
      </div>

      <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{pb.description}</p>

      {pb.mitre_tactic && (
        <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 8 }}>
          <span>MITRE: <strong style={{ color: 'var(--text-secondary)' }}>{pb.mitre_tactic}</strong></span>
          {pb.estimated_duration && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <Clock size={10} /> {pb.estimated_duration}
            </span>
          )}
        </div>
      )}

      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: 0.8, marginBottom: 8, textTransform: 'uppercase' }}>
          Response Steps ({pb.actions.length})
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {pb.actions.map((action, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, fontSize: 12, color: 'var(--text-secondary)', alignItems: 'flex-start' }}>
              <span style={{
                minWidth: 18, height: 18, borderRadius: 4,
                background: 'var(--cyan-glow)', color: 'var(--cyan)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 10, fontWeight: 700, flexShrink: 0
              }}>{i + 1}</span>
              {action}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

const DOMAINS = ['', 'network', 'endpoint', 'identity', 'cloud', 'appsec', 'email', 'data', 'physical']

export default function PlaybooksPage() {
  const [domainFilter, setDomainFilter] = React.useState('')

  const { data: playbooks = [], isLoading } = useQuery({
    queryKey: ['playbooks', domainFilter],
    queryFn: () => fetchPlaybooks(domainFilter || undefined),
  })

  const grouped = playbooks.reduce<Record<string, Playbook[]>>((acc, pb) => {
    (acc[pb.domain] ??= []).push(pb)
    return acc
  }, {})

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">Playbooks</div>
          <div className="page-subtitle">{playbooks.length} automated response playbooks seeded</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 24, flexWrap: 'wrap' }}>
        {DOMAINS.map(d => (
          <button
            key={d}
            className={`btn btn-sm ${domainFilter === d ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setDomainFilter(d)}
          >
            {d ? `${DOMAIN_EMOJI[d] ?? ''} ${d}` : '🌐 All'}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)' }}>Loading playbooks…</div>
      ) : playbooks.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📖</div>
          <div className="empty-title">No playbooks found</div>
          <div className="empty-sub">Start the backend to seed the playbook library</div>
        </div>
      ) : domainFilter ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: 20 }}>
          {playbooks.map(pb => <PlaybookCard key={pb.id} pb={pb} />)}
        </div>
      ) : (
        Object.entries(grouped).map(([domain, pbs]) => (
          <div key={domain} style={{ marginBottom: 32 }}>
            <div className="section-title" style={{ marginBottom: 16, fontSize: 16 }}>
              {DOMAIN_EMOJI[domain] ?? '🛡️'} {domain.charAt(0).toUpperCase() + domain.slice(1)} Domain
              <span style={{ marginLeft: 8, fontSize: 12, color: 'var(--text-muted)', fontWeight: 400 }}>({pbs.length} playbooks)</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: 16 }}>
              {pbs.map(pb => <PlaybookCard key={pb.id} pb={pb} />)}
            </div>
          </div>
        ))
      )}
    </div>
  )
}

// React needs to be in scope for JSX
import React from 'react'

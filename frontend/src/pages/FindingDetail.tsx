import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bot } from 'lucide-react'
import { api } from '../api/client'
import { P, can, label } from '../access'
import { ErrorState, Loading, PageTitle, RiskBadge, formatDate } from '../components/ui'
import type { Factor, User } from '../types'

type FindingDetail = {
  id: string
  title: string
  description: string | null
  severity: string
  cvss_score: number | null
  sources: string[] | null
  status: string
  risk_score: number
  risk_band: string
  risk_breakdown: Factor[] | Record<string, { points: number; weight: number; reason: string }> | null
  asset: { id: string; name: string } | null
  history: Array<{ score: number; band: string; calculated_at: string }>
  first_seen: string | null
  last_seen: string | null
  reopened_count: number
  finding_type: string
  threat_intel: {
    cve_id: string
    epss_score: number
    in_kev_list: boolean
    actively_exploited: boolean
    ransomware_used: boolean
    exploit_maturity: string
    cvss_base_score: number
  } | null
  source_records: Array<{ source: string; seen_at: string; raw: Record<string, unknown> | null }>
  task: { id: string; status: string; priority: string; sla_due_date: string | null; assigned_group: string | null; ticket_ref: string | null } | null
  attack_paths: Array<{ id: string; name: string; path_risk_score: number }>
}

type PathFactor = Factor & { base_score?: number; final_score?: number; path_influence?: number }

function normalizeFactors(raw: FindingDetail['risk_breakdown']): Factor[] {
  if (!raw) return []
  if (Array.isArray(raw)) return raw
  // Legacy weighted format: weight is a fraction of 100 points.
  return Object.entries(raw).map(([factor, x]) => ({
    factor,
    points: x.points,
    max_points: x.weight * 100,
    reason: x.reason,
  }))
}

export function FindingDetailPage({ user }: { user: User }) {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { data, error } = useQuery({
    queryKey: ['finding', id],
    queryFn: () => api<FindingDetail>(`/findings/${id}`),
  })
  const status = useMutation({
    mutationFn: (next: string) =>
      api(`/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status: next }) }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['finding', id] })
      void qc.invalidateQueries({ queryKey: ['findings'] })
    },
  })
  if (error) return <ErrorState message={(error as Error).message} />
  if (!data) return <Loading />
  const factors = normalizeFactors(data.risk_breakdown).sort((a, b) => b.points - a.points)
  const pathFactor = factors.find((f) => f.factor === 'attack_path_influence') as PathFactor | undefined
  const ti = data.threat_intel
  function explainFinding() {
    navigate('/assistant', {
      state: {
        findingId: data!.id,
        question: `Explain why “${data!.title}” is prioritized. Describe its risk score, strongest risk drivers, evidence, and what to validate first.`,
      },
    })
  }
  return (
    <>
      <Link to="/findings" className="back-link">
        ← Back to findings
      </Link>
      <PageTitle
        eyebrow="FINDING DETAIL"
        title={data.title}
        description={`${data.severity} severity · ${label(data.status)} · ${data.asset?.name ?? 'Asset'}`}
      />
      <div className="detail-grid">
        <section className="panel">
          <div className="panel-head">
            <div>
              <span className="panel-kicker">EXPLAINABLE RISK</span>
              <h2>
                Risk score <b className="large-score">{Number(data.risk_score).toFixed(1)}</b>
                <small className="muted"> / 100</small>
              </h2>
            </div>
            <RiskBadge band={data.risk_band} />
          </div>
          <div className="factor-list">
            {factors.map((factor) => (
              <div className="factor" key={factor.factor}>
                <div>
                  <strong>{label(factor.factor)}</strong>
                  <span>
                    {factor.points.toFixed(1)} / {factor.max_points.toFixed(1)} pts
                  </span>
                </div>
                <div className="factor-bar">
                  <i style={{ width: `${(factor.points / Math.max(0.01, factor.max_points)) * 100}%` }} />
                </div>
                <p>{factor.reason}</p>
              </div>
            ))}
            {!factors.length && <p className="muted">This finding has not been scored yet.</p>}
          </div>
        </section>
        <div className="stack">
          <section className="panel">
            <span className="panel-kicker">EVIDENCE</span>
            <h2>Finding context</h2>
            <p className="muted">{data.description ?? 'No description supplied.'}</p>
            <div className="detail-pair">
              <span>CVSS</span>
              <strong>{data.cvss_score ?? '—'}</strong>
            </div>
            <div className="detail-pair">
              <span>Source tools</span>
              <strong>{(data.sources ?? []).join(', ') || '—'}</strong>
            </div>
            <div className="detail-pair">
              <span>Asset</span>
              <strong>
                {data.asset && can(user, P.assetRead) ? (
                  <Link to={`/assets/${data.asset.id}`}>{data.asset.name}</Link>
                ) : (
                  (data.asset?.name ?? '—')
                )}
              </strong>
            </div>
            {can(user, P.findingTriage) && (
              <div className="detail-pair">
                <span>Triage status</span>
                <select
                  aria-label="Finding status"
                  value={data.status}
                  disabled={status.isPending}
                  onChange={(e) => status.mutate(e.target.value)}
                >
                  {['open', 'in_remediation', 'risk_accepted', 'closed'].map((x) => (
                    <option key={x} value={x}>
                      {label(x)}
                    </option>
                  ))}
                </select>
              </div>
            )}
            {status.error && <ErrorState message={(status.error as Error).message} />}
            <div className="button-row spaced">
              {can(user, P.aiUse) && (
                <button className="secondary-btn" onClick={explainFinding}>
                  Explain with AI <Bot size={15} />
                </button>
              )}
              {can(user, P.exceptionRequest) && data.status !== 'closed' && (
                <Link className="secondary-btn" to={`/exceptions?finding=${data.id}`}>
                  Request exception
                </Link>
              )}
            </div>
          </section>
          <section className="panel">
            <span className="panel-kicker">THREAT INTELLIGENCE</span>
            <h2>{ti ? ti.cve_id : 'No CVE linked'}</h2>
            {ti ? (
              <>
                <div className="tag-list">
                  {ti.in_kev_list && <span className="tag-hot">CISA KEV</span>}
                  {ti.actively_exploited && <span className="tag-hot">Actively exploited</span>}
                  {ti.ransomware_used && <span className="tag-hot">Ransomware</span>}
                  <span>Exploit: {ti.exploit_maturity}</span>
                  <span>EPSS {(ti.epss_score * 100).toFixed(1)}%</span>
                  <span>CVSS {ti.cvss_base_score}</span>
                </div>
                <p className="muted">Synthetic enrichment for the academic dataset; signals feed the exploitability and threat factors.</p>
              </>
            ) : (
              <p className="muted">Configuration, identity, pentest or EASM issue — scored without CVE threat signals.</p>
            )}
          </section>
          {pathFactor?.base_score !== undefined && (
            <section className="panel">
              <span className="panel-kicker">ATTACK PATH CONTEXT</span>
              <h2>
                {pathFactor.base_score.toFixed(1)} → {Number(pathFactor.final_score).toFixed(1)}
              </h2>
              <p className="muted">
                This finding sits on {data.attack_paths.length} modeled route(s) to a crown jewel, adding {pathFactor.points.toFixed(1)}{' '}
                attack-path points.
              </p>
              {data.attack_paths.slice(0, 4).map((p) => (
                <div className="detail-pair" key={p.id}>
                  <span>{p.name}</span>
                  <strong>{p.path_risk_score}</strong>
                </div>
              ))}
            </section>
          )}
          <section className="panel">
            <span className="panel-kicker">REMEDIATION</span>
            <h2>{data.task ? `Task ${label(data.task.status)}` : 'No remediation task'}</h2>
            {data.task ? (
              <>
                <div className="detail-pair">
                  <span>SLA due</span>
                  <strong>{formatDate(data.task.sla_due_date)}</strong>
                </div>
                {data.task.assigned_group && (
                  <div className="detail-pair">
                    <span>Group</span>
                    <strong>{data.task.assigned_group}</strong>
                  </div>
                )}
                {data.task.ticket_ref && (
                  <div className="detail-pair">
                    <span>Ticket</span>
                    <strong>{data.task.ticket_ref}</strong>
                  </div>
                )}
                {can(user, P.taskRead) && (
                  <Link className="text-btn" to={`/tasks?task=${data.task.id}`}>
                    Open task →
                  </Link>
                )}
              </>
            ) : (
              <p className="muted">Tasks are created automatically for high and critical findings.</p>
            )}
          </section>
          <section className="panel">
            <span className="panel-kicker">SOURCE RECORDS · SURVIVORSHIP</span>
            <h2>
              {data.source_records.length
                ? `${data.source_records.length} observation(s) from ${new Set(data.source_records.map((r) => r.source)).size} source(s)`
                : 'Seeded from the vulnerability catalog'}
            </h2>
            <p className="muted">
              First seen {formatDate(data.first_seen)} · last seen {formatDate(data.last_seen)}
              {data.reopened_count ? ` · reopened ${data.reopened_count}×` : ''}. The surviving record keeps the highest severity and CVSS
              and the most specific description.
            </p>
            {data.source_records.slice(0, 6).map((r, i) => (
              <details className="raw-record" key={`${r.source}-${i}`}>
                <summary>
                  {r.source} · {formatDate(r.seen_at)}
                </summary>
                <pre>{JSON.stringify(r.raw, null, 2)}</pre>
              </details>
            ))}
          </section>
          <section className="panel">
            <span className="panel-kicker">HISTORY</span>
            <h2>Score changes</h2>
            {data.history.length ? (
              <div className="mini-list">
                {data.history
                  .slice(-8)
                  .reverse()
                  .map((h) => (
                    <div key={h.calculated_at}>
                      <span className="muted">{formatDate(h.calculated_at)}</span>
                      <RiskBadge band={h.band} />
                      <strong>{h.score.toFixed(1)}</strong>
                    </div>
                  ))}
              </div>
            ) : (
              <p className="muted">No recalculations recorded yet.</p>
            )}
          </section>
        </div>
      </div>
    </>
  )
}

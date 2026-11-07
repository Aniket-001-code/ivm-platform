import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, ArrowDownRight, CheckCircle2, CircleHelp, ShieldAlert, Sparkles } from 'lucide-react'
import { api, downloadCsv, downloadFile } from '../api/client'
import { P, can, dashboardView, label } from '../access'
import { FindingTable } from '../components/FindingTable'
import { Empty, ErrorState, Loading, Metric, PageTitle, RiskBadge, formatDate } from '../components/ui'
import type { Dashboard, TrendPoint, User } from '../types'

const BANDS = ['critical', 'high', 'medium', 'low'] as const
const VIEW_TITLES = {
  executive: 'Executive risk overview',
  analyst: 'Analyst workbench',
  manager: 'Remediation command',
  auditor: 'Assurance overview',
}

function greeting() {
  const hour = new Date().getHours()
  return hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'
}

export function DashboardPage({ user }: { user: User }) {
  const view = dashboardView(user.role)
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', view],
    queryFn: () => api<Dashboard>(`/dashboards/${view}`),
  })
  if (isLoading) return <Loading />
  if (error || !data) return <ErrorState message={(error as Error)?.message ?? 'Dashboard unavailable'} />
  const k = data.kpis
  const today = new Date().toLocaleDateString(undefined, {
    weekday: 'long',
    day: '2-digit',
    month: 'long',
    year: 'numeric',
  })
  return (
    <>
      <PageTitle
        eyebrow={`${today.toUpperCase()} · ${view.toUpperCase()} VIEW`}
        title={VIEW_TITLES[view]}
        description={`${greeting()}, ${user.full_name} · ${label(user.role)}`}
        action={
          <>
            {can(user, P.reportRead) && (
              <button
                className="secondary-btn"
                onClick={() => void downloadFile('/reports/executive?format=html', 'ivm-executive-report.html')}
              >
                Executive report <ArrowDownRight size={15} />
              </button>
            )}
            {can(user, P.auditRead) && (
              <button className="secondary-btn" onClick={() => void downloadCsv('/audit/export', 'ivm-audit.csv')}>
                Download audit CSV <ArrowDownRight size={15} />
              </button>
            )}
          </>
        }
      />
      <div className="metric-grid">
        <Metric
          label="Open findings"
          value={k.open_findings.toLocaleString()}
          foot={`Across ${k.assets.toLocaleString()} assets in scope`}
          icon={<ShieldAlert />}
        />
        <Metric
          label="Critical risk"
          value={k.critical_count.toLocaleString()}
          foot={`${k.high_count.toLocaleString()} more rated high`}
          icon={<AlertTriangle />}
          accent="coral"
        />
        <Metric
          label="SLA compliance"
          value={`${k.sla_compliance_percent}%`}
          foot={`${k.overdue_count} overdue of ${k.task_count.toLocaleString()} actions`}
          icon={<CheckCircle2 />}
          accent="green"
        />
        {view === 'manager' ? (
          <Metric
            label="Mean time to remediate"
            value={mttrHeadline(k.mttr_by_band)}
            foot="Critical findings, closed tasks"
            icon={<Activity />}
            accent="blue"
          />
        ) : (
          <Metric
            label="Triage effort saved"
            value={`${Math.round(k.effort_saved_minutes / 60)}h`}
            foot={`${(k.duplicates_merged ?? 0).toLocaleString()} duplicate rows merged · ${k.raw_records.toLocaleString()} raw → ${k.prioritized_actions.toLocaleString()} distinct`}
            icon={<Activity />}
            accent="blue"
          />
        )}
      </div>
      <div className="dashboard-grid">
        <TrendPanel trend={data.trend ?? []} />
        <BandPanel bands={data.risk_bands} total={k.open_findings} linkable={can(user, P.findingRead)} />
      </div>
      {view === 'executive' && <ExecutiveSections data={data} user={user} />}
      {view === 'analyst' && <AnalystSections data={data} user={user} />}
      {view === 'manager' && <ManagerSections data={data} />}
      {view === 'auditor' && <AuditorSections data={data} />}
      {view !== 'auditor' && (
        <div className="panel table-panel">
          <div className="panel-head">
            <div>
              <span className="panel-kicker">FOCUS AREAS</span>
              <h2>Highest priority open findings</h2>
            </div>
            {can(user, P.findingRead) && (
              <Link to="/findings" className="text-btn">
                See all findings <span>→</span>
              </Link>
            )}
          </div>
          <FindingTable rows={data.top_findings.slice(0, 5)} linkable={can(user, P.findingRead)} />
        </div>
      )}
      {data.assumption && (
        <p className="assumption-note">
          <CircleHelp size={14} />
          {data.assumption}
        </p>
      )}
    </>
  )
}

function mttrHeadline(rows: Dashboard['kpis']['mttr_by_band']) {
  const critical = rows.find((row) => row.risk_band === 'critical')
  if (!critical || !critical.closed_tasks) return '—'
  return critical.mttr_days < 1 ? '< 1 day' : `${critical.mttr_days.toFixed(1)} days`
}

function TrendPanel({ trend }: { trend: TrendPoint[] }) {
  const [weeks, setWeeks] = useState(13)
  const { points, low, high } = useMemo(() => {
    const rows = trend.slice(-weeks)
    // Scale the y-axis to the data (with padding) so small weekly movements stay visible.
    const scores = rows.map((row) => row.average_score)
    const lo = Math.max(0, Math.floor(Math.min(...scores, 100) - 5))
    const hi = Math.min(100, Math.ceil(Math.max(...scores, 0) + 5))
    const span = Math.max(1, hi - lo)
    return {
      low: lo,
      high: hi,
      points: rows.map((row, index) => ({
        x: 46 + (index * 582) / Math.max(1, rows.length - 1),
        y: 185 - ((row.average_score - lo) / span) * 150,
        row,
      })),
    }
  }, [trend, weeks])
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
  const area = line ? `${line} L ${points[points.length - 1].x.toFixed(1)} 185 L 46 185 Z` : ''
  const latest = trend[trend.length - 1]
  const first = points[0]?.row
  const change = latest && first ? latest.average_score - first.average_score : 0
  const labelEvery = Math.max(1, Math.ceil(points.length / 7))
  return (
    <section className="panel risk-trend">
      <div className="panel-head">
        <div>
          <span className="panel-kicker">PORTFOLIO HEALTH</span>
          <h2>Risk score trend</h2>
        </div>
        <select aria-label="Trend window" value={weeks} onChange={(e) => setWeeks(Number(e.target.value))}>
          <option value={8}>Last 8 weeks</option>
          <option value={13}>Last 3 months</option>
          <option value={26}>Last 6 months</option>
        </select>
      </div>
      <div className="chart-key">
        <span />
        <span>Average contextual risk score of open findings</span>
        <strong>
          {latest ? latest.average_score.toFixed(1) : '—'}{' '}
          <small className={change > 0 ? 'trend-up' : 'trend-down'}>
            {latest ? `${change <= 0 ? '▼' : '▲'} ${Math.abs(change).toFixed(1)} over window` : 'No history'}
          </small>
        </strong>
      </div>
      <div className="chart-area">
        {points.length ? (
          <svg viewBox="0 0 640 220" role="img" aria-label="Average risk score history">
            <defs>
              <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#118b86" stopOpacity=".23" />
                <stop offset="95%" stopColor="#118b86" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path d="M46 35H628M46 110H628M46 185H628" stroke="#e9eef4" />
            <g fill="#a0aab4" fontSize="10" textAnchor="end">
              <text x="40" y="38">{high}</text>
              <text x="40" y="113">{((high + low) / 2).toFixed(0)}</text>
              <text x="40" y="188">{low}</text>
            </g>
            <path d={area} fill="url(#riskFill)" />
            <path d={line} fill="none" stroke="#118b86" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
            {points.map((p) => (
              <circle key={p.row.week} cx={p.x} cy={p.y} r="3" fill="#118b86">
                <title>
                  Week of {formatDate(p.row.week)}: {p.row.average_score.toFixed(1)} ({p.row.sample_count} findings)
                </title>
              </circle>
            ))}
            <g fill="#8390a3" fontSize="11" textAnchor="middle">
              {points.map((p, i) =>
                i % labelEvery === 0 || i === points.length - 1 ? (
                  <text key={p.row.week} x={p.x} y="212">
                    {new Date(p.row.week).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })}
                  </text>
                ) : null,
              )}
            </g>
          </svg>
        ) : (
          <Empty>No score history yet. Run a risk recalculation to start the trend.</Empty>
        )}
      </div>
      <div className="chart-foot">
        <span>
          <i className="legend-dot" />
          Weekly average
        </span>
        <span>Lower score indicates reduced exposure</span>
      </div>
    </section>
  )
}

function BandPanel({ bands, total, linkable }: { bands: Record<string, number>; total: number; linkable: boolean }) {
  return (
    <section className="panel band-panel">
      <div className="panel-head">
        <div>
          <span className="panel-kicker">RISK DISTRIBUTION</span>
          <h2>Open findings by risk band</h2>
        </div>
        {linkable && (
          <Link to="/findings" className="text-btn">
            View all <span>→</span>
          </Link>
        )}
      </div>
      <div className="band-stack">
        {BANDS.map((band) => (
          <div className="band-row" key={band}>
            <div className="band-label">
              <span className={`band-dot ${band}`} />
              {linkable ? <Link to={`/findings?band=${band}`}>{band}</Link> : band}
              <strong>{Number(bands[band] ?? 0).toLocaleString()}</strong>
            </div>
            <div className="band-track">
              <div
                className={`band-fill ${band}`}
                style={{ width: `${Math.max(2, ((bands[band] ?? 0) / Math.max(1, total)) * 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
      <div className="band-callout">
        <span className="callout-icon">
          <Activity size={16} />
        </span>
        <span>
          <strong>Threat intelligence is active</strong>
          <small>KEV, exploit maturity and EPSS signals are included in every score.</small>
        </span>
      </div>
    </section>
  )
}

function BarList({
  rows,
  empty,
}: {
  rows: Array<{ key: string; label: React.ReactNode; value: number; suffix?: string }>
  empty: string
}) {
  const max = Math.max(1, ...rows.map((row) => row.value))
  if (!rows.length) return <Empty>{empty}</Empty>
  return (
    <div className="bar-list">
      {rows.map((row) => (
        <div className="bar-row" key={row.key}>
          <span className="bar-label">{row.label}</span>
          <div className="band-track">
            <div className="band-fill bar-fill" style={{ width: `${(row.value / max) * 100}%` }} />
          </div>
          <strong>
            {row.value.toLocaleString()}
            {row.suffix}
          </strong>
        </div>
      ))}
    </div>
  )
}

function Section({ kicker, title, children }: { kicker: string; title: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <span className="panel-kicker">{kicker}</span>
      <h2>{title}</h2>
      {children}
    </section>
  )
}

function ExecutiveSections({ data, user }: { data: Dashboard; user: User }) {
  const byUnit = useMemo(() => {
    const units = new Map<string, Record<string, number>>()
    for (const row of data.risk_by_business_unit ?? []) {
      const entry = units.get(row.business_unit) ?? {}
      entry[row.risk_band] = (entry[row.risk_band] ?? 0) + row.count
      units.set(row.business_unit, entry)
    }
    return [...units.entries()]
      .map(([unit, bands]) => ({ unit, bands, total: Object.values(bands).reduce((a, b) => a + b, 0) }))
      .sort((a, b) => (b.bands.critical ?? 0) - (a.bands.critical ?? 0) || b.total - a.total)
  }, [data.risk_by_business_unit])
  return (
    <div className="section-grid">
      <Section kicker="BUSINESS EXPOSURE" title="Risk by business unit">
        {byUnit.length ? (
          <div className="bar-list">
            {byUnit.map(({ unit, bands, total }) => (
              <div className="bar-row" key={unit}>
                <span className="bar-label">{unit}</span>
                <div className="band-track stack-track" title={BANDS.map((b) => `${b}: ${bands[b] ?? 0}`).join(' · ')}>
                  {BANDS.map((band) => (
                    <div
                      key={band}
                      className={`band-fill ${band}`}
                      style={{ width: `${((bands[band] ?? 0) / Math.max(1, total)) * 100}%` }}
                    />
                  ))}
                </div>
                <strong>{(bands.critical ?? 0).toLocaleString()} crit</strong>
              </div>
            ))}
          </div>
        ) : (
          <Empty>No business-unit data in scope.</Empty>
        )}
      </Section>
      <Section kicker="CROWN JEWELS" title="Most exposed assets">
        <BarList
          rows={(data.top_assets ?? []).slice(0, 6).map((a) => ({
            key: a.asset_id,
            label: can(user, P.assetRead) ? <Link to={`/assets/${a.asset_id}`}>{a.asset}</Link> : a.asset,
            value: Math.round(a.max_risk),
            suffix: ' max',
          }))}
          empty="No open findings on assets."
        />
      </Section>
      <Section kicker="RISK REDUCTION" title={`${data.risk_reduction_percent ?? 0}% lower average risk`}>
        <p className="muted">
          Average contextual risk score now versus six months ago, from recorded score history after remediation.
        </p>
      </Section>
      <InternetFacing rows={data.internet_facing_high_risk ?? []} user={user} />
      <CrownPaths rows={data.crown_jewel_paths ?? []} user={user} />
      {can(user, P.aiExecutive) && <ExecutiveSummary />}
      <ExpiringExceptions rows={data.exceptions_expiring ?? []} />
      <OverdueByCategory rows={data.overdue_by_owner_and_category ?? []} />
      <Heatmap rows={data.heatmap ?? []} />
    </div>
  )
}

function Heatmap({ rows }: { rows: NonNullable<Dashboard['heatmap']> }) {
  const sorted = [...rows].sort(
    (a, b) =>
      (b.risk_bands.critical ?? 0) * 3 + (b.risk_bands.high ?? 0) - ((a.risk_bands.critical ?? 0) * 3 + (a.risk_bands.high ?? 0)),
  )
  const max = Math.max(1, ...sorted.map((r) => (r.risk_bands.critical ?? 0) * 3 + (r.risk_bands.high ?? 0)))
  return (
    <section className="panel heatmap-panel">
      <span className="panel-kicker">EXECUTIVE HEATMAP</span>
      <h2>Risk by business service</h2>
      {sorted.length ? (
        <div className="heatmap" role="list">
          {sorted.map((row) => {
            const weight = ((row.risk_bands.critical ?? 0) * 3 + (row.risk_bands.high ?? 0)) / max
            return (
              <div
                role="listitem"
                key={`${row.business_unit}-${row.business_service}`}
                className="heat-cell"
                style={{ background: `rgba(214, 102, 80, ${0.08 + weight * 0.72})`, color: weight > 0.55 ? '#fff' : '#17273e' }}
                title={BANDS.map((b) => `${b}: ${row.risk_bands[b] ?? 0}`).join(' · ')}
              >
                <strong>{row.business_service}</strong>
                <small>{row.business_unit}</small>
                <span>
                  {row.risk_bands.critical ?? 0} critical · {row.risk_bands.high ?? 0} high
                </span>
              </div>
            )
          })}
        </div>
      ) : (
        <Empty>No service mapping in scope.</Empty>
      )}
    </section>
  )
}

function InternetFacing({ rows, user }: { rows: NonNullable<Dashboard['internet_facing_high_risk']>; user: User }) {
  return (
    <Section kicker="INTERNET-FACING" title="High-risk assets exposed to the internet">
      {rows.length ? (
        <div className="mini-list">
          {rows.slice(0, 6).map((a) => (
            <div key={a.asset_id}>
              {can(user, P.assetRead) ? <Link to={`/assets/${a.asset_id}`}>{a.asset}</Link> : <span>{a.asset}</span>}
              {a.crown_jewel && <span className="tag-hot">crown jewel</span>}
              <span className="muted">{a.high_risk_findings} high/critical</span>
              <strong>{a.max_risk.toFixed(0)}</strong>
            </div>
          ))}
        </div>
      ) : (
        <Empty>No internet-facing assets carry high or critical findings.</Empty>
      )}
    </Section>
  )
}

function CrownPaths({ rows, user }: { rows: NonNullable<Dashboard['crown_jewel_paths']>; user: User }) {
  return (
    <Section kicker="ATTACK PATHS" title="Routes leading to crown-jewel assets">
      {rows.length ? (
        <div className="mini-list">
          {rows.slice(0, 6).map((p) => (
            <div key={p.id}>
              <span>{p.name}</span>
              <span className="muted">{p.hops} hops</span>
              <strong>{p.path_risk_score.toFixed(0)}</strong>
            </div>
          ))}
          {can(user, P.attackPathRead) && (
            <Link to="/attack-paths" className="text-btn">
              Explore attack paths →
            </Link>
          )}
        </div>
      ) : (
        <Empty>No modeled paths reach crown jewels in your scope.</Empty>
      )}
    </Section>
  )
}

function OverdueByCategory({ rows }: { rows: NonNullable<Dashboard['overdue_by_owner_and_category']> }) {
  return (
    <Section kicker="SLA ACCOUNTABILITY" title="Overdue by owner and SLA category">
      {rows.length ? (
        <table className="compact" aria-label="Overdue tasks by owner and SLA category">
          <thead>
            <tr>
              <th>Owner</th>
              <th>SLA category</th>
              <th>Overdue</th>
            </tr>
          </thead>
          <tbody>
            {rows
              .slice()
              .sort((a, b) => b.overdue_tasks - a.overdue_tasks)
              .slice(0, 8)
              .map((r) => (
                <tr key={`${r.owner}-${r.sla_category}`}>
                  <td>{r.owner}</td>
                  <td>
                    <RiskBadge band={r.sla_category} />
                  </td>
                  <td>{r.overdue_tasks}</td>
                </tr>
              ))}
          </tbody>
        </table>
      ) : (
        <Empty>Nothing is overdue.</Empty>
      )}
    </Section>
  )
}

function ExecutiveSummary() {
  const summary = useMutation({
    mutationFn: () => api<{ summary: string; label: string; used_llm: boolean }>('/ai/executive-summary', { method: 'POST' }),
  })
  return (
    <Section kicker="AI BRIEFING" title="Executive summary">
      {summary.data ? (
        <>
          <p className="muted">{summary.data.summary}</p>
          <small className="ai-note">
            {summary.data.label} · {summary.data.used_llm ? 'Claude-assisted' : 'offline rules engine'}
          </small>
        </>
      ) : (
        <p className="muted">Generate a short, data-grounded briefing on today’s top priorities.</p>
      )}
      {summary.error && <ErrorState message={(summary.error as Error).message} />}
      <button className="secondary-btn" onClick={() => summary.mutate()} disabled={summary.isPending}>
        {summary.isPending ? 'Generating…' : summary.data ? 'Regenerate' : 'Generate briefing'} <Sparkles size={14} />
      </button>
    </Section>
  )
}

function ExpiringExceptions({ rows }: { rows: NonNullable<Dashboard['exceptions_expiring']> }) {
  return (
    <Section kicker="GOVERNANCE" title="Exceptions expiring in 30 days">
      {rows.length ? (
        <div className="mini-list">
          {rows.slice(0, 6).map((row) => (
            <div key={row.id}>
              <span className="mono">{row.finding_id.slice(0, 8)}</span>
              <span className={`exception-status ${row.status}`}>{row.status}</span>
              <strong>{formatDate(row.expiry)}</strong>
            </div>
          ))}
        </div>
      ) : (
        <Empty>No approved exceptions expire in the next 30 days.</Empty>
      )}
    </Section>
  )
}

function AnalystSections({ data, user }: { data: Dashboard; user: User }) {
  return (
    <div className="section-grid">
      <Section kicker="DATA PIPELINE" title="Open findings by source">
        <BarList
          rows={(data.findings_by_source ?? []).map((row) => ({ key: row.source, label: row.source, value: row.findings }))}
          empty="No findings imported yet."
        />
      </Section>
      <Section kicker="RECENT IMPORTS" title="Batch quality">
        {data.recent_imports?.length ? (
          <div className="mini-list">
            {data.recent_imports.slice(0, 6).map((row) => (
              <div key={row.id}>
                <span>
                  <strong>{row.source}</strong> · {row.file}
                </span>
                <span className="muted">
                  {row.total} rows · {row.duplicates} dup · {row.failed} failed
                </span>
              </div>
            ))}
            <Link to="/imports" className="text-btn">
              Open imports →
            </Link>
          </div>
        ) : (
          <Empty>No imports yet.</Empty>
        )}
      </Section>
      <Section kicker="CROWN JEWELS" title="Assets with the highest risk">
        <BarList
          rows={(data.top_assets ?? []).slice(0, 6).map((a) => ({
            key: a.asset_id,
            label: <Link to={`/assets/${a.asset_id}`}>{a.asset}</Link>,
            value: a.open_findings,
            suffix: ' open',
          }))}
          empty="No open findings on assets."
        />
      </Section>
      <InternetFacing rows={data.internet_facing_high_risk ?? []} user={user} />
      <CrownPaths rows={data.crown_jewel_paths ?? []} user={user} />
    </div>
  )
}

function ManagerSections({ data }: { data: Dashboard }) {
  const status = data.tasks_by_status ?? {}
  return (
    <div className="section-grid">
      <Section kicker="WORKFLOW" title="Remediation tasks by status">
        <BarList
          rows={Object.entries(status).map(([key, value]) => ({ key, label: label(key), value }))}
          empty="No remediation tasks in scope."
        />
      </Section>
      <Section kicker="AGING" title="Open task age (days)">
        <BarList
          rows={Object.entries(data.aging_buckets ?? {}).map(([key, value]) => ({ key, label: key, value }))}
          empty="No open tasks."
        />
      </Section>
      <Section kicker="ACCOUNTABILITY" title="Overdue tasks by owner">
        <BarList
          rows={(data.overdue_by_owner ?? []).map((row) => ({ key: row.owner_id, label: row.owner, value: row.overdue_tasks }))}
          empty="Nothing is overdue."
        />
      </Section>
      <OverdueByCategory rows={data.overdue_by_owner_and_category ?? []} />
      <Section kicker="ESCALATIONS" title="Open escalations">
        {data.escalations?.length ? (
          <div className="mini-list">
            {data.escalations.slice(0, 6).map((row) => (
              <div key={row.id}>
                <span className="path-risk">L{row.level}</span>
                <span className="muted">{row.reason}</span>
                {!row.acknowledged && <RiskBadge band="high" />}
              </div>
            ))}
          </div>
        ) : (
          <Empty>No escalations.</Empty>
        )}
      </Section>
    </div>
  )
}

function AuditorSections({ data }: { data: Dashboard }) {
  const counts = (data.exceptions ?? []).reduce<Record<string, number>>((acc, row) => {
    acc[row.status] = (acc[row.status] ?? 0) + 1
    return acc
  }, {})
  return (
    <div className="section-grid">
      <Section kicker="AUDIT TRAIL" title="Recent recorded events">
        {data.recent_audit?.length ? (
          <div className="mini-list">
            {data.recent_audit.slice(0, 8).map((row) => (
              <div key={row.id}>
                <strong>{label(row.action)}</strong>
                <span className="muted">{row.entity_type}</span>
                <span className="muted">{new Date(row.timestamp).toLocaleString()}</span>
              </div>
            ))}
            <Link to="/auditor" className="text-btn">
              Open full audit trail →
            </Link>
          </div>
        ) : (
          <Empty>No audit events yet.</Empty>
        )}
      </Section>
      <Section kicker="RISK ACCEPTANCE" title="Exception register by status">
        <BarList
          rows={Object.entries(counts).map(([key, value]) => ({ key, label: key, value }))}
          empty="No exceptions recorded."
        />
        <Link to="/exceptions" className="text-btn">
          Review exceptions →
        </Link>
      </Section>
      <ExpiringExceptions rows={data.exceptions_expiring ?? []} />
    </div>
  )
}

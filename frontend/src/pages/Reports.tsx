import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { FileText, TrendingUp } from 'lucide-react'
import { api, downloadFile } from '../api/client'
import { P, can } from '../access'
import { Empty, ErrorState, Loading, PageTitle, RiskBadge, formatDate } from '../components/ui'
import type { User } from '../types'

type Criterion = { id: string; criterion: string; passed: boolean; evidence: string }
type PlanAction = {
  step: number
  action: string
  findings: number
  assets: number
  max_risk: number
  effort_hours: number
  known_exploited: boolean
  value_per_hour: number
  cumulative_hours: number
  cumulative_risk_reduction_percent: number
  finding_ids: string[]
}
type Plan = {
  open_high_and_critical: number
  candidate_actions: number
  first_five_actions_reduce_percent: number
  effort_model: Record<string, unknown>
  actions: PlanAction[]
}
type Forecast = {
  history: Array<{ week: string; average_score: number }>
  trend: { slope_per_period: number; projection: number[]; r_squared: number; direction: string }
  sla_breach_forecast: {
    horizon_days: number
    already_breached: number
    expected_new_breaches: number
    high_risk_tasks: number
    model: { median_days_to_close: Record<string, number>; portfolio_on_time_rate: number; closed_tasks_learned_from: number }
  }
  at_risk_tasks: Array<{ task_id: string; finding_id: string; priority: string; probability: number; level: string; factors: string[]; sla_due_date: string }>
}
type Impact = {
  raw_records_processed: number
  consolidated_findings: number
  duplicates_merged: number
  duplicate_rate_percent: number
  multi_source_findings: number
  tasks_auto_assigned: number
  auto_assignment_percent: number
  escalations_automated: number
  exceptions_auto_expired: number
  ai_questions_answered: number
  hours_saved: number
  minutes_saved: Record<string, number>
  assumptions_minutes: Record<string, number>
}
type Ownership = {
  task_accuracy_percent: number | null
  tasks_evaluated: number
  routing_accuracy_percent: number | null
  manual_overrides: number
  meets_target: boolean
  mismatches: Array<{ asset: string; expected_owner: string; assigned_owner: string | null; reason: string }>
  ground_truth: string
}

export function ReportsPage({ user }: { user: User }) {
  const criteria = useQuery({
    queryKey: ['success-criteria'],
    queryFn: () => api<{ criteria: Criterion[]; generated_at: string }>('/reports/success-criteria'),
  })
  const plan = useQuery({ queryKey: ['remediation-plan'], queryFn: () => api<Plan>('/reports/remediation-plan') })
  const forecast = useQuery({ queryKey: ['forecast'], queryFn: () => api<Forecast>('/analytics/forecast') })
  const impact = useQuery({ queryKey: ['automation-impact'], queryFn: () => api<Impact>('/reports/automation-impact') })
  const ownership = useQuery({ queryKey: ['ownership-accuracy'], queryFn: () => api<Ownership>('/reports/ownership-accuracy') })
  const passed = criteria.data?.criteria.filter((c) => c.passed).length ?? 0
  return (
    <>
      <PageTitle
        eyebrow="REPORTING & DECISION SUPPORT"
        title="Reports & insights"
        description="Board-ready reporting, measured success criteria, forecasts and a recommended remediation sequence."
        action={
          <button className="primary-btn" onClick={() => void downloadFile('/reports/executive?format=html', 'ivm-executive-report.html')}>
            Executive report <FileText size={14} />
          </button>
        }
      />
      <section className="panel table-panel">
        <div className="panel-head">
          <div>
            <span className="panel-kicker">SUCCESS CRITERIA · MEASURED LIVE</span>
            <h2>
              {criteria.data ? `${passed} of ${criteria.data.criteria.length} criteria met` : 'Success criteria'}
            </h2>
          </div>
          {criteria.data && <span className="result-count">Measured {new Date(criteria.data.generated_at).toLocaleString()}</span>}
        </div>
        {criteria.isLoading ? (
          <Loading />
        ) : criteria.error ? (
          <ErrorState message={(criteria.error as Error).message} />
        ) : (
          <div className="table-scroll">
            <table aria-label="Success criteria">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Criterion</th>
                  <th>Status</th>
                  <th>Evidence from the live data</th>
                </tr>
              </thead>
              <tbody>
                {criteria.data?.criteria.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <strong>{c.id}</strong>
                    </td>
                    <td className="wrap-cell">{c.criterion}</td>
                    <td>
                      <span className={`exception-status ${c.passed ? 'approved' : 'rejected'}`}>{c.passed ? 'Met' : 'Not met'}</span>
                    </td>
                    <td className="wrap-cell">{c.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <RemediationPlan plan={plan.data} loading={plan.isLoading} error={plan.error as Error | null} user={user} />

      <div className="section-grid">
        <ForecastPanel data={forecast.data} />
        <section className="panel">
          <span className="panel-kicker">SC-12 · AUTOMATION IMPACT</span>
          <h2>{impact.data ? `≈ ${impact.data.hours_saved} analyst hours saved` : 'Automation impact'}</h2>
          {impact.data ? (
            <div className="mini-list">
              {[
                ['Raw records processed', impact.data.raw_records_processed],
                ['Duplicates merged', `${impact.data.duplicates_merged} (${impact.data.duplicate_rate_percent}%)`],
                ['Findings corroborated by 2+ sources', impact.data.multi_source_findings],
                ['Tasks auto-assigned', `${impact.data.tasks_auto_assigned} (${impact.data.auto_assignment_percent}%)`],
                ['Escalations automated', impact.data.escalations_automated],
                ['Exceptions auto-expired', impact.data.exceptions_auto_expired],
                ['AI questions answered', impact.data.ai_questions_answered],
              ].map(([label, value]) => (
                <div key={String(label)}>
                  <span className="muted">{label}</span>
                  <strong>{value}</strong>
                </div>
              ))}
              <p className="muted">
                Assumptions (minutes):{' '}
                {Object.entries(impact.data.assumptions_minutes)
                  .map(([k, v]) => `${k.replaceAll('_', ' ')} ${v}`)
                  .join(' · ')}
              </p>
            </div>
          ) : (
            <Loading />
          )}
        </section>
        <section className="panel">
          <span className="panel-kicker">SC-6 · OWNERSHIP ACCURACY</span>
          <h2>
            {ownership.data?.task_accuracy_percent != null
              ? `${ownership.data.task_accuracy_percent}% of tasks correctly owned`
              : 'Ownership accuracy'}
          </h2>
          {ownership.data ? (
            <>
              <p className="muted">
                {ownership.data.tasks_evaluated} tasks compared with the dataset owner ({ownership.data.ground_truth}). The routing
                engine predicts the right owner for {ownership.data.routing_accuracy_percent}% of assets; {ownership.data.manual_overrides}{' '}
                manual overrides. Target: 90%.
              </p>
              <span className={`exception-status ${ownership.data.meets_target ? 'approved' : 'rejected'}`}>
                {ownership.data.meets_target ? 'Target met' : 'Below target'}
              </span>
              {ownership.data.mismatches.length > 0 && (
                <div className="mini-list">
                  {ownership.data.mismatches.slice(0, 5).map((m) => (
                    <div key={`${m.asset}-${m.expected_owner}`}>
                      <span>{m.asset}</span>
                      <span className="muted">
                        expected {m.expected_owner}, got {m.assigned_owner ?? 'nobody'} ({m.reason})
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <Loading />
          )}
        </section>
      </div>
    </>
  )
}

function RemediationPlan({ plan, loading, error, user }: { plan?: Plan; loading: boolean; error: Error | null; user: User }) {
  return (
    <section className="panel table-panel">
      <div className="panel-head">
        <div>
          <span className="panel-kicker">RECOMMENDATION ENGINE · REMEDIATION SEQUENCING</span>
          <h2>
            {plan
              ? `First five campaigns remove ${plan.first_five_actions_reduce_percent}% of open high/critical risk`
              : 'Recommended remediation sequence'}
          </h2>
        </div>
        {plan && (
          <span className="result-count">
            {plan.open_high_and_critical} findings grouped into {plan.candidate_actions} actions
          </span>
        )}
      </div>
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState message={error.message} />
      ) : !plan?.actions.length ? (
        <Empty>No open high or critical findings in your scope.</Empty>
      ) : (
        <div className="table-scroll">
          <table aria-label="Remediation plan">
            <thead>
              <tr>
                <th>#</th>
                <th>Action</th>
                <th>Assets</th>
                <th>Max risk</th>
                <th>Effort</th>
                <th>Risk removed / hour</th>
                <th>Cumulative risk removed</th>
              </tr>
            </thead>
            <tbody>
              {plan.actions.slice(0, 15).map((a) => (
                <tr key={a.step}>
                  <td>{a.step}</td>
                  <td className="wrap-cell">
                    {can(user, P.findingRead) && a.finding_ids[0] ? (
                      <Link className="table-primary" to={`/findings/${a.finding_ids[0]}`}>
                        {a.action}
                      </Link>
                    ) : (
                      <span className="table-primary">{a.action}</span>
                    )}
                    <small>
                      {a.findings} findings{a.known_exploited ? ' · known exploited' : ''}
                    </small>
                  </td>
                  <td>{a.assets}</td>
                  <td>
                    <RiskBadge band={a.max_risk >= 80 ? 'critical' : 'high'} /> {a.max_risk}
                  </td>
                  <td>{a.effort_hours} h</td>
                  <td>{a.value_per_hour}</td>
                  <td>
                    <div className="score-cell">
                      <strong>{a.cumulative_risk_reduction_percent}%</strong>
                      <div className="score-track">
                        <i style={{ width: `${a.cumulative_risk_reduction_percent}%` }} />
                      </div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function ForecastPanel({ data }: { data?: Forecast }) {
  const chart = useMemo(() => {
    if (!data?.history.length) return null
    const history = data.history.slice(-12).map((r) => r.average_score)
    const all = [...history, ...data.trend.projection]
    const lo = Math.floor(Math.min(...all) - 2)
    const hi = Math.ceil(Math.max(...all) + 2)
    const x = (i: number) => 20 + (i * 360) / Math.max(1, all.length - 1)
    const y = (v: number) => 110 - ((v - lo) / Math.max(1, hi - lo)) * 90
    const actual = history.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ')
    const start = history.length - 1
    const projected = [history[start], ...data.trend.projection]
      .map((v, i) => `${i ? 'L' : 'M'}${x(start + i).toFixed(1)} ${y(v).toFixed(1)}`)
      .join(' ')
    return { actual, projected, lo, hi }
  }, [data])
  if (!data) {
    return (
      <section className="panel">
        <Loading />
      </section>
    )
  }
  const b = data.sla_breach_forecast
  return (
    <section className="panel">
      <span className="panel-kicker">PREDICTIVE ANALYTICS</span>
      <h2>
        <TrendingUp size={15} /> Risk is {data.trend.direction} ({data.trend.slope_per_period >= 0 ? '+' : ''}
        {data.trend.slope_per_period}/week)
      </h2>
      {chart && (
        <svg viewBox="0 0 400 120" className="forecast-chart" role="img" aria-label="Risk history and four-week projection">
          <path d={chart.actual} fill="none" stroke="#118b86" strokeWidth="2.5" />
          <path d={chart.projected} fill="none" stroke="#118b86" strokeWidth="2" strokeDasharray="5 4" />
          <text x="4" y="22" fontSize="9" fill="#8390a3">
            {chart.hi}
          </text>
          <text x="4" y="112" fontSize="9" fill="#8390a3">
            {chart.lo}
          </text>
        </svg>
      )}
      <p className="muted">
        Solid: last 12 weeks. Dashed: 4-week projection ({data.trend.projection.join(', ')}), R² {data.trend.r_squared}.
      </p>
      <div className="mini-list">
        <div>
          <span className="muted">SLA breaches expected in {b.horizon_days} days</span>
          <strong>{b.expected_new_breaches}</strong>
        </div>
        <div>
          <span className="muted">Tasks at high breach risk</span>
          <strong>{b.high_risk_tasks}</strong>
        </div>
        <div>
          <span className="muted">Already breached</span>
          <strong>{b.already_breached}</strong>
        </div>
      </div>
      <p className="muted">
        Model learned from {b.model.closed_tasks_learned_from} closed tasks: median days to close{' '}
        {Object.entries(b.model.median_days_to_close)
          .map(([band, d]) => `${band} ${d}`)
          .join(', ') || 'n/a'}
        ; portfolio on-time rate {(b.model.portfolio_on_time_rate * 100).toFixed(0)}%.
      </p>
      {data.at_risk_tasks.filter((t) => t.level !== 'breached').slice(0, 3).map((t) => (
        <div className="mini-list" key={t.task_id}>
          <div>
            <RiskBadge band={t.priority} />
            <span className="muted">Task {t.task_id.slice(0, 8)} due {formatDate(t.sla_due_date)}</span>
            <strong>{Math.round(t.probability * 100)}%</strong>
          </div>
        </div>
      ))}
      <Link className="text-btn" to="/tasks">
        Open remediation queue →
      </Link>
    </section>
  )
}

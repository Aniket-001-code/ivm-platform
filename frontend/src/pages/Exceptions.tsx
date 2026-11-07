import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDownRight } from 'lucide-react'
import { api, downloadCsv, downloadFile, qs } from '../api/client'
import { P, can, label } from '../access'
import { Empty, ErrorState, PageTitle, formatDate, useDebounced } from '../components/ui'
import type { Finding, RiskException, User } from '../types'

const MAX_DAYS = { temporary: 90, long_term: 365 } as const

const isoDay = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10)

export function ExceptionsPage({ user }: { user: User }) {
  const [params] = useSearchParams()
  const qc = useQueryClient()
  const register = useQuery({ queryKey: ['exceptions'], queryFn: () => api<RiskException[]>('/exceptions') })
  const [statusFilter, setStatusFilter] = useState('')
  const canRequest = can(user, P.exceptionRequest)
  const canReview = can(user, P.exceptionApproveTemp, P.exceptionApproveAll)
  const canApproveLongTerm = can(user, P.exceptionApproveAll)
  const [reviewComment, setReviewComment] = useState('')
  const review = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'approve' | 'reject' | 'revoke' }) =>
      api(`/exceptions/${id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ comment: reviewComment.trim() || `${label(action)}d in the IVM workspace.` }),
      }),
    onSuccess: () => {
      setReviewComment('')
      void qc.invalidateQueries({ queryKey: ['exceptions'] })
      void qc.invalidateQueries({ queryKey: ['findings'] })
    },
  })
  const rows = (register.data ?? []).filter((x) => !statusFilter || x.status === statusFilter)
  return (
    <>
      <PageTitle
        eyebrow="GOVERNANCE"
        title="Risk exceptions"
        description="Document, review, and track time-bound risk acceptance. Requesters cannot approve their own requests."
        action={
          <button className="secondary-btn" onClick={() => void downloadCsv('/exceptions/export', 'ivm-exceptions.csv')}>
            Download exception CSV <ArrowDownRight size={14} />
          </button>
        }
      />
      {canRequest && <RequestForm initialFinding={params.get('finding') ?? ''} />}
      <section className="panel table-panel">
        <div className="panel-head">
          <h2>Exception register</h2>
          <div className="button-row">
            <select aria-label="Exception status filter" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="">All statuses</option>
              {[
                ['pending', 'Awaiting review'],
                ['approved', 'Accepted risk'],
                ['rejected', 'Declined'],
                ['expired', 'Lapsed'],
                ['revoked', 'Withdrawn'],
              ].map(([value, text]) => (
                <option key={value} value={value}>
                  {text}
                </option>
              ))}
            </select>
            <span className="result-count">{rows.length} records</span>
          </div>
        </div>
        {canReview && (
          <div className="review-bar">
            <input
              aria-label="Review comment"
              placeholder="Review comment recorded with your next approve / reject / revoke"
              value={reviewComment}
              onChange={(e) => setReviewComment(e.target.value)}
            />
          </div>
        )}
        {review.error && <ErrorState message={(review.error as Error).message} />}
        {register.error && <ErrorState message={(register.error as Error).message} />}
        {!rows.length && !register.isLoading && <Empty>No exceptions match this filter.</Empty>}
        {rows.map((item) => {
          const own = item.requested_by === user.id
          const typeAllowed = item.exception_type === 'temporary' || canApproveLongTerm
          return (
            <div className="exception-row" key={item.id}>
              <span className={`exception-status ${item.status}`}>{item.status}</span>
              <span className="exception-copy">
                <strong>
                  {can(user, P.findingRead) ? (
                    <Link to={`/findings/${item.finding_id}`}>Finding {item.finding_id.slice(0, 8)}</Link>
                  ) : (
                    `Finding ${item.finding_id.slice(0, 8)}`
                  )}{' '}
                  · {label(item.exception_type)}
                </strong>
                <small>{item.justification}</small>
                <small>Controls: {item.compensating_controls}</small>
                {item.review_comment && <small>Review: {item.review_comment}</small>}
              </span>
              <span className="muted">Expires {formatDate(item.requested_expiry_date)}</span>
              <button
                type="button"
                className="text-btn"
                aria-label={`Download review pack for exception ${item.id.slice(0, 8)}`}
                onClick={() => void downloadFile(`/exceptions/${item.id}/review-pack?format=html`, `exception-review-${item.id.slice(0, 8)}.html`)}
              >
                Review pack
              </button>
              {canReview && item.status === 'pending' && (
                <div className="button-row">
                  {own ? (
                    <span className="muted">Your request</span>
                  ) : typeAllowed ? (
                    <>
                      <button
                        className="text-btn"
                        disabled={review.isPending}
                        onClick={() => review.mutate({ id: item.id, action: 'approve' })}
                      >
                        Approve
                      </button>
                      <button
                        className="text-btn danger-text"
                        disabled={review.isPending}
                        onClick={() => review.mutate({ id: item.id, action: 'reject' })}
                      >
                        Reject
                      </button>
                    </>
                  ) : (
                    <span className="muted">Needs security architect</span>
                  )}
                </div>
              )}
              {canReview && item.status === 'approved' && (
                <button
                  className="text-btn danger-text"
                  disabled={review.isPending}
                  onClick={() => review.mutate({ id: item.id, action: 'revoke' })}
                >
                  Revoke
                </button>
              )}
            </div>
          )
        })}
      </section>
    </>
  )
}

function RequestForm({ initialFinding }: { initialFinding: string }) {
  const qc = useQueryClient()
  const [finding, setFinding] = useState(initialFinding)
  const [search, setSearch] = useState('')
  const debounced = useDebounced(search)
  const [type, setType] = useState<'temporary' | 'long_term'>('temporary')
  const [expiry, setExpiry] = useState('')
  const [justification, setJustification] = useState('')
  const [controls, setControls] = useState('')
  const options = useQuery({
    queryKey: ['exception-finding-options', debounced],
    // Any finding that is not closed can carry an exception (including renewals of accepted risk).
    queryFn: async () =>
      (await api<Finding[]>(`/findings${qs({ search: debounced, limit: 250 })}`)).filter((x) => x.status !== 'closed'),
  })
  const preselected = useQuery({
    queryKey: ['finding', initialFinding],
    queryFn: () => api<Finding>(`/findings/${initialFinding}`),
    enabled: Boolean(initialFinding),
  })
  const choices = [...(options.data ?? [])]
  if (preselected.data && !choices.some((x) => x.id === preselected.data!.id)) choices.unshift(preselected.data)
  const request = useMutation({
    mutationFn: () =>
      api('/exceptions', {
        method: 'POST',
        body: JSON.stringify({
          finding_id: finding,
          justification,
          compensating_controls: controls.trim() || 'Compensating controls to be confirmed by the asset owner.',
          exception_type: type,
          requested_expiry_date: new Date(`${expiry}T23:59:00`).toISOString(),
        }),
      }),
    onSuccess: () => {
      setFinding('')
      setJustification('')
      setControls('')
      void qc.invalidateQueries({ queryKey: ['exceptions'] })
    },
  })
  const tooFar = expiry && expiry > isoDay(MAX_DAYS[type])
  return (
    <section className="panel form-panel">
      <div>
        <span className="panel-kicker">NEW REQUEST</span>
        <h2>Request an exception</h2>
      </div>
      <div className="form-row">
        <label>
          Find a finding
          <input placeholder="Filter findings by title…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label>
          Finding
          <select aria-label="Finding" value={finding} onChange={(e) => setFinding(e.target.value)}>
            <option value="">Choose a finding</option>
            {choices.map((x) => (
              <option key={x.id} value={x.id}>
                {x.title} · {x.risk_band} · {x.id.slice(0, 8)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-row">
        <label>
          Exception type
          <select aria-label="Exception type" value={type} onChange={(e) => setType(e.target.value as typeof type)}>
            <option value="temporary">Temporary (up to 90 days)</option>
            <option value="long_term">Long-term (up to 365 days, architect approval)</option>
          </select>
        </label>
        <label>
          Expiry date
          <input
            aria-label="Expiry date"
            type="date"
            min={isoDay(1)}
            max={isoDay(MAX_DAYS[type])}
            value={expiry}
            onChange={(e) => setExpiry(e.target.value)}
          />
        </label>
      </div>
      <label>
        Business justification
        <textarea
          aria-label="Business justification"
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
          placeholder="Why is remediation deferred? (at least 10 characters)"
        />
      </label>
      <label>
        Compensating controls
        <textarea
          aria-label="Compensating controls"
          value={controls}
          onChange={(e) => setControls(e.target.value)}
          placeholder="e.g. network segmentation, WAF rule, weekly monitoring"
        />
      </label>
      {tooFar && <ErrorState message={`A ${label(type)} exception can last at most ${MAX_DAYS[type]} days.`} />}
      <button
        className="primary-btn"
        disabled={!finding || justification.trim().length < 10 || !expiry || Boolean(tooFar) || request.isPending}
        onClick={() => request.mutate()}
      >
        Submit request <span>→</span>
      </button>
      {request.isSuccess && <p className="success-note">Request submitted for review.</p>}
      {request.error && <ErrorState message={(request.error as Error).message} />}
    </section>
  )
}

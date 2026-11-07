import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Ticket, X } from 'lucide-react'
import { api, apiPage, downloadFile, qs } from '../api/client'
import { P, can, label, usesOwnTaskQueue } from '../access'
import { Empty, ErrorState, Loading, PageTitle, Pager, RiskBadge, formatDate } from '../components/ui'
import type { Task, User } from '../types'

const PAGE_SIZE = 50
const STATUSES = ['open', 'in_progress', 'pending_verification', 'blocked', 'closed']

type TaskRow = Task & { breach_probability?: number; breach_level?: string; assigned_group?: string | null }

export function TasksPage({ user }: { user: User }) {
  const ownQueue = usesOwnTaskQueue(user.role)
  const taskPath = ownQueue ? '/tasks/my' : '/tasks'
  const [params, setParams] = useSearchParams()
  const [status, setStatus] = useState('')
  const [priority, setPriority] = useState('')
  const [overdue, setOverdue] = useState(params.get('overdue') === 'true')
  const [offset, setOffset] = useState(0)
  const [comment, setComment] = useState('')
  const [evidence, setEvidence] = useState('')
  const openTask = params.get('task')
  const canUpdate = can(user, P.taskAssigned, P.taskManage)
  const filters = { status, priority, overdue: overdue || undefined }
  const query = useQuery({
    queryKey: ['tasks', taskPath, filters, offset],
    queryFn: () => apiPage<TaskRow>(`${taskPath}${qs({ ...filters, limit: PAGE_SIZE, offset })}`),
    placeholderData: keepPreviousData,
  })
  const qc = useQueryClient()
  const update = useMutation({
    mutationFn: ({ id, status: next }: { id: string; status: string }) =>
      api(`/tasks/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: next, comment: comment || undefined, evidence_notes: evidence.trim() || undefined }),
      }),
    onSuccess: (_data, variables) => {
      if (variables.status === 'closed') setEvidence('')
      setComment('')
      // Update the row in place so it does not jump away; the list re-sorts on next load.
      qc.setQueryData<{ rows: TaskRow[]; total: number }>(['tasks', taskPath, filters, offset], (page) =>
        page
          ? { ...page, rows: page.rows.map((row) => (row.id === variables.id ? { ...row, status: variables.status } : row)) }
          : page,
      )
      void qc.invalidateQueries({ queryKey: ['task'] })
      void qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
  const setFilter = (fn: () => void) => {
    fn()
    setOffset(0)
  }
  const showTask = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('task', id)
    else next.delete('task')
    setParams(next, { replace: true })
  }
  const tasks = query.data?.rows ?? []
  const now = Date.now()
  return (
    <>
      <PageTitle
        eyebrow="REMEDIATION OPERATIONS"
        title={ownQueue ? 'My remediation tasks' : 'Remediation tasks'}
        description={`Assigned work, SLA deadlines and predicted breach risk · signed in as ${label(user.role)}`}
        action={
          <button
            className="secondary-btn"
            onClick={() => void downloadFile(`/tasks/export${qs(filters)}`, 'ivm-sla-report.csv')}
          >
            SLA report CSV <Download size={14} />
          </button>
        }
      />
      <div className="filter-bar">
        <select aria-label="Task status filter" value={status} onChange={(e) => setFilter(() => setStatus(e.target.value))}>
          <option value="">All statuses</option>
          {STATUSES.map((x) => (
            <option key={x} value={x}>
              {label(x)}
            </option>
          ))}
        </select>
        <select aria-label="Priority filter" value={priority} onChange={(e) => setFilter(() => setPriority(e.target.value))}>
          <option value="">All priorities</option>
          {['critical', 'high', 'medium', 'low'].map((x) => (
            <option key={x}>{x}</option>
          ))}
        </select>
        <label className="check">
          <input type="checkbox" checked={overdue} onChange={(e) => setFilter(() => setOverdue(e.target.checked))} />
          Overdue only
        </label>
        <span className="result-count">{(query.data?.total ?? 0).toLocaleString()} actions</span>
      </div>
      {canUpdate && (
        <div className="filter-bar update-bar">
          <input
            aria-label="Update comment"
            placeholder="Comment for the next status change (optional)"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
          <input
            aria-label="Remediation evidence"
            placeholder="Evidence notes (required to close)"
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
          />
        </div>
      )}
      {update.error && <ErrorState message={(update.error as Error).message} />}
      <section className="panel table-panel">
        {query.isLoading ? (
          <Loading />
        ) : query.error ? (
          <ErrorState message={(query.error as Error).message} />
        ) : !tasks.length ? (
          <Empty>No remediation tasks match these filters.</Empty>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Task / finding</th>
                  <th>Priority</th>
                  <th>SLA due</th>
                  <th>Breach risk</th>
                  <th>Status</th>
                  <th>Evidence</th>
                  {canUpdate && <th>Update</th>}
                </tr>
              </thead>
              <tbody>
                {tasks.map((t) => {
                  const late = t.status !== 'closed' && t.sla_due_date && new Date(t.sla_due_date).getTime() < now
                  return (
                    <tr key={t.id}>
                      <td>
                        <button type="button" className="link-button table-primary" onClick={() => showTask(t.id)}>
                          Finding {t.finding_id.slice(0, 8)}
                        </button>
                        <small>
                          Task {t.id.slice(0, 8)}
                          {t.assigned_group ? ` · ${t.assigned_group}` : ''}
                          {t.ticket_ref ? ` · ${t.ticket_ref}` : ''}
                        </small>
                      </td>
                      <td>
                        <RiskBadge band={t.priority} />
                      </td>
                      <td className={late ? 'overdue' : ''}>
                        {formatDate(t.sla_due_date)}
                        {late ? ' · overdue' : ''}
                      </td>
                      <td>
                        {t.breach_level && t.breach_level !== 'none' ? (
                          <span className={`breach breach-${t.breach_level}`}>
                            {t.breach_level === 'breached' ? 'Breached' : `${Math.round((t.breach_probability ?? 0) * 100)}%`}
                          </span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td>
                        <span className="status-pill">{t.status}</span>
                      </td>
                      <td>{t.evidence_notes ? 'Added' : 'Pending'}</td>
                      {canUpdate && (
                        <td>
                          <select
                            aria-label={`Update task ${t.id}`}
                            value={t.status}
                            disabled={update.isPending}
                            onChange={(e) => update.mutate({ id: t.id, status: e.target.value })}
                          >
                            <option value="open">Open</option>
                            <option value="in_progress">In progress</option>
                            <option value="pending_verification">Verify</option>
                            <option value="closed" disabled={t.status !== 'closed' && !evidence.trim()}>
                              {t.status === 'closed' ? 'Closed' : 'Close (evidence required)'}
                            </option>
                            <option value="blocked">Blocked</option>
                          </select>
                        </td>
                      )}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <Pager offset={offset} limit={PAGE_SIZE} total={query.data?.total ?? 0} onChange={setOffset} />
      </section>
      {openTask && <TaskDrawer id={openTask} user={user} onClose={() => showTask(null)} />}
    </>
  )
}

type TaskDetail = TaskRow & {
  owner_email: string | null
  assigned_by_rule: string | null
  finding: { id: string; title: string; risk_score: number; risk_band: string; status: string } | null
  asset: { id: string; name: string }
  breach: { probability: number; level: string; factors: string[] }
  updates: Array<{ old_status: string | null; new_status: string; comment: string | null; user: string | null; created_at: string }>
  escalations: Array<{ id: string; level: number; reason: string; escalated_to: string | null; acknowledged: boolean }>
  tickets: Array<{ system: string; ticket_key: string; status: string }>
}

function TaskDrawer({ id, user, onClose }: { id: string; user: User; onClose: () => void }) {
  const qc = useQueryClient()
  const detail = useQuery({ queryKey: ['task', id], queryFn: () => api<TaskDetail>(`/tasks/${id}`) })
  const users = useQuery({
    queryKey: ['users'],
    queryFn: () => api<Array<{ id: string; email: string; full_name: string; is_active: boolean }>>('/users'),
    enabled: can(user, P.taskManage) && can(user, P.userRead),
  })
  const [owner, setOwner] = useState('')
  const [group, setGroup] = useState('')
  const [reason, setReason] = useState('')
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ['task', id] })
    void qc.invalidateQueries({ queryKey: ['tasks'] })
  }
  const assign = useMutation({
    mutationFn: () =>
      api(`/tasks/${id}/assign`, {
        method: 'POST',
        body: JSON.stringify({ user_id: owner || null, group: group || null, reason }),
      }),
    onSuccess: () => {
      setReason('')
      refresh()
    },
  })
  const ticket = useMutation({
    mutationFn: (system: string) =>
      api(`/ticketing/${system}/issues`, { method: 'POST', body: JSON.stringify({ task_id: id }) }),
    onSuccess: refresh,
  })
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])
  const d = detail.data
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Task details" onClick={(e) => e.stopPropagation()}>
        <button className="icon-button drawer-close" aria-label="Close task details" onClick={onClose} autoFocus>
          <X size={18} />
        </button>
        {!d ? (
          detail.error ? <ErrorState message={(detail.error as Error).message} /> : <Loading />
        ) : (
          <>
            <span className="panel-kicker">REMEDIATION TASK {d.id.slice(0, 8)}</span>
            <h2>{d.finding?.title ?? 'Finding'}</h2>
            <p className="muted">
              {d.asset.name} · <RiskBadge band={d.priority} /> · status {label(d.status)} · due {formatDate(d.sla_due_date)}
            </p>
            {d.finding && can(user, P.findingRead) && (
              <Link className="text-btn" to={`/findings/${d.finding.id}`}>
                Open finding (risk {d.finding.risk_score.toFixed(1)}) →
              </Link>
            )}
            <h3>Ownership</h3>
            <div className="detail-pair">
              <span>Owner</span>
              <strong>{d.owner_email ?? 'Unassigned'}</strong>
            </div>
            <div className="detail-pair">
              <span>Group</span>
              <strong>{d.assigned_group ?? '—'}</strong>
            </div>
            <div className="detail-pair">
              <span>Assigned by</span>
              <strong>{label(d.assigned_by_rule ?? 'unknown')}</strong>
            </div>
            {can(user, P.taskManage) && (
              <div className="inline-form">
                <select aria-label="New owner" value={owner} onChange={(e) => setOwner(e.target.value)}>
                  <option value="">Keep owner</option>
                  {(users.data ?? [])
                    .filter((u) => u.is_active)
                    .map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.full_name} · {u.email}
                      </option>
                    ))}
                </select>
                <input aria-label="Group" placeholder="Group (optional)" value={group} onChange={(e) => setGroup(e.target.value)} />
                <input aria-label="Reassignment reason" placeholder="Reason (required)" value={reason} onChange={(e) => setReason(e.target.value)} />
                <button
                  className="secondary-btn"
                  disabled={reason.trim().length < 3 || (!owner && !group) || assign.isPending}
                  onClick={() => assign.mutate()}
                >
                  Reassign
                </button>
              </div>
            )}
            {assign.error && <ErrorState message={(assign.error as Error).message} />}
            <h3>SLA breach risk</h3>
            <p>
              <span className={`breach breach-${d.breach.level}`}>
                {d.breach.level === 'breached' ? 'Breached' : `${Math.round(d.breach.probability * 100)}% · ${d.breach.level}`}
              </span>
            </p>
            <ul className="factor-notes">
              {d.breach.factors.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            <h3>Ticketing</h3>
            {d.tickets.map((t) => (
              <div className="detail-pair" key={t.ticket_key}>
                <span>{t.system}</span>
                <strong>
                  {t.ticket_key} · {t.status}
                </strong>
              </div>
            ))}
            {can(user, P.ticketCreate) && (
              <div className="button-row">
                <button className="secondary-btn" disabled={ticket.isPending} onClick={() => ticket.mutate('jira-sim')}>
                  Create Jira ticket <Ticket size={14} />
                </button>
                <button className="secondary-btn" disabled={ticket.isPending} onClick={() => ticket.mutate('servicenow-sim')}>
                  Create ServiceNow incident <Ticket size={14} />
                </button>
              </div>
            )}
            {ticket.error && <ErrorState message={(ticket.error as Error).message} />}
            <h3>Escalations</h3>
            {d.escalations.length ? (
              d.escalations.map((e) => (
                <div className="detail-pair" key={e.id}>
                  <span>
                    L{e.level} → {e.escalated_to ?? 'unrouted'}
                  </span>
                  <strong>{e.acknowledged ? 'acknowledged' : 'open'}</strong>
                </div>
              ))
            ) : (
              <p className="muted">No escalations.</p>
            )}
            <h3>Timeline</h3>
            <ol className="timeline">
              {d.updates.map((u, i) => (
                <li key={`${u.created_at}-${i}`}>
                  <b>
                    {u.old_status ? `${label(u.old_status)} → ` : ''}
                    {label(u.new_status)}
                  </b>
                  <small>
                    {new Date(u.created_at).toLocaleString()} · {u.user ?? 'system'}
                  </small>
                  {u.comment && <p>{u.comment}</p>}
                </li>
              ))}
              {!d.updates.length && <li className="muted">No updates yet.</li>}
            </ol>
          </>
        )}
      </aside>
    </div>
  )
}

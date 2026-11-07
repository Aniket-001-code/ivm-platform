import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Plus, Trash2 } from 'lucide-react'
import { api } from '../api/client'
import { P, can, label } from '../access'
import { Empty, ErrorState, PageTitle, RiskBadge } from '../components/ui'
import type { User } from '../types'

type Scoring = { version: number; weights: Record<string, number>; band_thresholds: Record<string, number> }
type Sla = { risk_band: string; sla_days: number; escalation_level_1_days: number; escalation_level_2_days: number }
type Rule = {
  id: string
  priority_order: number
  match_field: string
  match_value: string
  assign_to_user_id: string | null
  assign_to_group: string | null
}
type Escalation = { id: string; task_id: string; level: number; reason: string }
type UserRow = { id: string; email: string; full_name: string; role: string; is_active: boolean; mfa_enabled?: boolean }

const ROLES = [
  'platform_admin',
  'security_analyst',
  'vulnerability_manager',
  'security_architect',
  'it_asset_owner',
  'system_administrator',
  'business_unit_manager',
  'executive_ciso',
  'auditor',
]

export function AdminPage({ user }: { user: User }) {
  return (
    <>
      <PageTitle
        eyebrow="PLATFORM SETTINGS"
        title="Administration"
        description="Manage scoring posture, SLAs, ownership routing, users, and scheduled operations."
      />
      <div className="admin-grid">
        {can(user, P.configRead) && <ScoringPanel user={user} />}
        {can(user, P.configRead) && <SlaPanel user={user} />}
        {can(user, P.schedulerRun) && <SchedulerPanel user={user} />}
        {can(user, P.configRead) && <OwnershipPanel user={user} />}
        {can(user, P.userRead) && <UsersPanel user={user} />}
      </div>
    </>
  )
}

function ScoringPanel({ user }: { user: User }) {
  const qc = useQueryClient()
  const scoring = useQuery({ queryKey: ['scoring'], queryFn: () => api<Scoring>('/config/scoring') })
  const [draft, setDraft] = useState<Record<string, number> | null>(null)
  useEffect(() => {
    if (scoring.data && !draft) setDraft({ ...scoring.data.weights })
  }, [scoring.data, draft])
  const editable = can(user, P.configManage)
  const total = Object.values(draft ?? {}).reduce((sum, value) => sum + Number(value || 0), 0)
  const valid = Math.abs(total - 100) < 0.001 && Object.values(draft ?? {}).every((v) => v >= 0)
  const save = useMutation({
    mutationFn: () =>
      api<Scoring>('/config/scoring', {
        method: 'PUT',
        body: JSON.stringify({ weights: draft, band_thresholds: scoring.data?.band_thresholds }),
      }),
    onSuccess: (data) => {
      setDraft({ ...data.weights })
      void qc.invalidateQueries()
    },
  })
  const whatIf = useMutation({
    mutationFn: () =>
      api<{ top_findings: Array<{ finding_id: string; title: string; base_score: number; what_if_score: number; risk_band: string }> }>(
        '/risk/what-if',
        { method: 'POST', body: JSON.stringify({ weights: draft }) },
      ),
  })
  const recalc = useMutation({
    mutationFn: () => api('/risk/recalculate', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries(),
  })
  const max = Math.max(1, ...Object.values(draft ?? {}))
  return (
    <section className="panel">
      <span className="panel-kicker">RISK MODEL</span>
      <h2>Scoring factor weights</h2>
      <p className="muted">
        Version {scoring.data?.version ?? '—'} · each factor’s maximum points; the eight must total 100.
      </p>
      {Object.entries(draft ?? {}).map(([name, value]) => (
        <div className="weight-row editable" key={name}>
          <span>{label(name)}</span>
          <div className="weight-track">
            <i style={{ width: `${(Number(value) / max) * 100}%` }} />
          </div>
          {editable ? (
            <input
              type="number"
              min={0}
              max={100}
              step={0.5}
              aria-label={`${label(name)} max points`}
              value={value}
              onChange={(e) => setDraft({ ...draft!, [name]: Number(e.target.value) })}
            />
          ) : (
            <strong>{value}</strong>
          )}
        </div>
      ))}
      <p className={valid ? 'muted' : 'error-text'}>Total: {total.toFixed(1)} / 100</p>
      <div className="button-row wrap">
        {editable && (
          <button className="primary-btn" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving & rescoring…' : 'Save new version'}
          </button>
        )}
        {can(user, P.riskWhatIf) && (
          <button className="secondary-btn" disabled={!valid || whatIf.isPending} onClick={() => whatIf.mutate()}>
            {whatIf.isPending ? 'Simulating…' : 'Preview impact'}
          </button>
        )}
        {can(user, P.riskManage) && (
          <button className="secondary-btn" onClick={() => recalc.mutate()} disabled={recalc.isPending}>
            {recalc.isPending ? 'Recalculating…' : 'Run risk rescore'} <Activity size={15} />
          </button>
        )}
      </div>
      {save.isSuccess && <p className="success-note">Saved version {save.data.version}; all findings rescored.</p>}
      {recalc.isSuccess && <p className="success-note">Risk recalculated successfully.</p>}
      {[save.error, whatIf.error, recalc.error].filter(Boolean).map((error) => (
        <ErrorState key={(error as Error).message} message={(error as Error).message} />
      ))}
      {whatIf.data && (
        <div className="mini-list">
          <strong>Top findings under these weights</strong>
          {whatIf.data.top_findings.slice(0, 8).map((row) => (
            <div key={row.finding_id}>
              <span className="muted ellipsis">{row.title}</span>
              <span className="muted">{row.base_score.toFixed(1)} →</span>
              <strong>{row.what_if_score.toFixed(1)}</strong>
              <RiskBadge band={row.risk_band} />
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

function SlaPanel({ user }: { user: User }) {
  const qc = useQueryClient()
  const sla = useQuery({ queryKey: ['sla'], queryFn: () => api<Sla[]>('/config/sla') })
  const [draft, setDraft] = useState<Sla[] | null>(null)
  useEffect(() => {
    if (sla.data && !draft) setDraft(sla.data.map((row) => ({ ...row })))
  }, [sla.data, draft])
  const editable = can(user, P.configManage)
  const save = useMutation({
    mutationFn: () => api<Sla[]>('/config/sla', { method: 'PUT', body: JSON.stringify(draft) }),
    onSuccess: (data) => {
      setDraft(data.map((row) => ({ ...row })))
      void qc.invalidateQueries({ queryKey: ['sla'] })
    },
  })
  const set = (band: string, field: keyof Sla, value: number) =>
    setDraft((rows) => rows!.map((row) => (row.risk_band === band ? { ...row, [field]: value } : row)))
  return (
    <section className="panel">
      <span className="panel-kicker">SERVICE LEVELS</span>
      <h2>Remediation targets</h2>
      <div className="table-scroll">
        <table className="compact">
          <thead>
            <tr>
              <th>Band</th>
              <th>SLA days</th>
              <th>Escalate L1 after</th>
              <th>Escalate L2 after</th>
            </tr>
          </thead>
          <tbody>
            {(draft ?? []).map((row) => (
              <tr key={row.risk_band}>
                <td>
                  <RiskBadge band={row.risk_band} />
                </td>
                {(['sla_days', 'escalation_level_1_days', 'escalation_level_2_days'] as const).map((field) => (
                  <td key={field}>
                    {editable ? (
                      <input
                        type="number"
                        min={field === 'sla_days' ? 1 : 0}
                        max={365}
                        aria-label={`${row.risk_band} ${label(field)}`}
                        value={row[field]}
                        onChange={(e) => set(row.risk_band, field, Number(e.target.value))}
                      />
                    ) : (
                      `${row[field]} d`
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted">Escalation days count from the SLA due date.</p>
      {editable && (
        <button className="primary-btn" disabled={save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : 'Save SLA policy'}
        </button>
      )}
      {save.isSuccess && <p className="success-note">SLA policy saved and audited.</p>}
      {save.error && <ErrorState message={(save.error as Error).message} />}
    </section>
  )
}

function SchedulerPanel({ user }: { user: User }) {
  const qc = useQueryClient()
  const jobs = useMutation({
    mutationFn: () => api<{ escalations_created: number; exceptions_expired: number }>('/jobs/run', { method: 'POST' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['escalations'] })
      void qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
  const escalations = useQuery({
    queryKey: ['escalations'],
    queryFn: () => api<Escalation[]>('/escalations'),
    enabled: can(user, P.notificationRead),
  })
  return (
    <section className="panel admin-note">
      <span className="panel-kicker">SCHEDULED JOBS</span>
      <h2>Review SLA and exception deadlines</h2>
      <p>The scheduler runs these checks automatically; run them now to create overdue escalations and expire lapsed exceptions.</p>
      <button className="secondary-btn" onClick={() => jobs.mutate()} disabled={jobs.isPending}>
        {jobs.isPending ? 'Running jobs…' : 'Run scheduler jobs now'} <Activity size={15} />
      </button>
      {jobs.data && (
        <p className="success-note">
          Escalations created: {jobs.data.escalations_created} · Exceptions expired: {jobs.data.exceptions_expired}
        </p>
      )}
      {jobs.error && <ErrorState message={(jobs.error as Error).message} />}
      {can(user, P.notificationRead) && (
        <div className="path-list">
          <strong>Recent escalations</strong>
          {(escalations.data ?? []).slice(0, 5).map((item) => (
            <div className="path-item" key={item.id}>
              <span className="path-risk">L{item.level}</span>
              <span>
                <strong>{item.reason}</strong>
                <small>Task {item.task_id.slice(0, 10)}</small>
              </span>
            </div>
          ))}
          {!escalations.data?.length && <Empty>No escalations yet.</Empty>}
        </div>
      )}
    </section>
  )
}

function OwnershipPanel({ user }: { user: User }) {
  const qc = useQueryClient()
  const rules = useQuery({ queryKey: ['ownership-rules'], queryFn: () => api<Rule[]>('/config/ownership-rules') })
  const editable = can(user, P.configManage)
  const [field, setField] = useState('environment')
  const [value, setValue] = useState('')
  const [group, setGroup] = useState('')
  const [priority, setPriority] = useState(100)
  const refresh = () => qc.invalidateQueries({ queryKey: ['ownership-rules'] })
  const create = useMutation({
    mutationFn: () =>
      api('/config/ownership-rules', {
        method: 'POST',
        body: JSON.stringify({ match_field: field, match_value: value, assign_to_group: group || null, priority_order: priority }),
      }),
    onSuccess: () => {
      setValue('')
      setGroup('')
      void refresh()
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api(`/config/ownership-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => void refresh(),
  })
  return (
    <section className="panel">
      <span className="panel-kicker">ROUTING</span>
      <h2>Ownership rules</h2>
      <p className="muted">New remediation tasks are assigned by the first matching rule, lowest priority number first.</p>
      {rules.data?.length ? (
        <div className="mini-list">
          {rules.data.map((rule) => (
            <div key={rule.id}>
              <span className="path-risk">{rule.priority_order}</span>
              <span>
                {label(rule.match_field)} = <strong>{rule.match_value}</strong>
              </span>
              <span className="muted">→ {rule.assign_to_group ?? (rule.assign_to_user_id ? 'named user' : 'unassigned')}</span>
              {editable && (
                <button className="icon-button" aria-label={`Delete rule ${rule.match_value}`} onClick={() => remove.mutate(rule.id)}>
                  <Trash2 size={14} />
                </button>
              )}
            </div>
          ))}
        </div>
      ) : (
        <Empty>No ownership rules configured; tasks fall back to the asset owner.</Empty>
      )}
      {editable && (
        <div className="inline-form">
          <select aria-label="Match field" value={field} onChange={(e) => setField(e.target.value)}>
            {['business_service', 'business_unit', 'asset_type', 'environment', 'tag'].map((x) => (
              <option key={x} value={x}>
                {label(x)}
              </option>
            ))}
          </select>
          <input aria-label="Match value" placeholder="Match value" value={value} onChange={(e) => setValue(e.target.value)} />
          <input aria-label="Assign to group" placeholder="Assign to group" value={group} onChange={(e) => setGroup(e.target.value)} />
          <input
            aria-label="Rule priority"
            type="number"
            min={1}
            value={priority}
            onChange={(e) => setPriority(Number(e.target.value))}
          />
          <button className="secondary-btn" disabled={!value.trim() || create.isPending} onClick={() => create.mutate()}>
            Add rule <Plus size={14} />
          </button>
        </div>
      )}
      {[create.error, remove.error].filter(Boolean).map((error) => (
        <ErrorState key={(error as Error).message} message={(error as Error).message} />
      ))}
    </section>
  )
}

function UsersPanel({ user }: { user: User }) {
  const qc = useQueryClient()
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<UserRow[]>('/users') })
  const editable = can(user, P.userManage) && can(user, P.configManage)
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<UserRow> }) =>
      api(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
  const units = useQuery({
    queryKey: ['business-units'],
    queryFn: () => api<Array<{ id: string; name: string }>>('/business-units'),
    enabled: editable,
  })
  const [draft, setDraft] = useState({ email: '', full_name: '', role: 'security_analyst', business_unit_id: '', password: '' })
  const [notice, setNotice] = useState('')
  const create = useMutation({
    mutationFn: () =>
      api('/users', { method: 'POST', body: JSON.stringify({ ...draft, business_unit_id: draft.business_unit_id || null }) }),
    onSuccess: () => {
      setNotice(`Created ${draft.email}. Share the temporary password through a separate channel.`)
      setDraft({ email: '', full_name: '', role: 'security_analyst', business_unit_id: '', password: '' })
      void qc.invalidateQueries({ queryKey: ['users'] })
    },
  })
  const resetPassword = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      api(`/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) }),
    onSuccess: () => setNotice('Password reset; the user’s sessions were revoked.'),
  })
  const resetMfa = useMutation({
    mutationFn: (id: string) => api(`/users/${id}/reset-mfa`, { method: 'POST' }),
    onSuccess: () => {
      setNotice('MFA cleared; the user can enroll a new authenticator.')
      void qc.invalidateQueries({ queryKey: ['users'] })
    },
  })
  return (
    <section className="panel admin-note">
      <span className="panel-kicker">ACCESS</span>
      <h2>Users and roles</h2>
      {editable && (
        <div className="inline-form">
          <input aria-label="New user email" placeholder="email@demo.bank" value={draft.email} onChange={(e) => setDraft({ ...draft, email: e.target.value })} />
          <input aria-label="New user name" placeholder="Full name" value={draft.full_name} onChange={(e) => setDraft({ ...draft, full_name: e.target.value })} />
          <select aria-label="New user role" value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value })}>
            {ROLES.map((role) => (
              <option key={role} value={role}>
                {label(role)}
              </option>
            ))}
          </select>
          <select
            aria-label="New user business unit"
            value={draft.business_unit_id}
            onChange={(e) => setDraft({ ...draft, business_unit_id: e.target.value })}
          >
            <option value="">No business unit</option>
            {(units.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.name}
              </option>
            ))}
          </select>
          <input
            aria-label="Temporary password"
            type="password"
            placeholder="Temporary password (12+ chars)"
            value={draft.password}
            onChange={(e) => setDraft({ ...draft, password: e.target.value })}
          />
          <button className="secondary-btn" disabled={!draft.email || draft.password.length < 12 || create.isPending} onClick={() => create.mutate()}>
            Add user <Plus size={14} />
          </button>
        </div>
      )}
      {notice && <p className="success-note">{notice}</p>}
      {[update.error, create.error, resetPassword.error, resetMfa.error].filter(Boolean).map((error) => (
        <ErrorState key={(error as Error).message} message={(error as Error).message} />
      ))}
      <div className="table-scroll">
        <table className="compact">
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Status</th>
              <th>MFA</th>
              {editable && <th>Recovery</th>}
            </tr>
          </thead>
          <tbody>
            {(users.data ?? []).map((row) => (
              <tr key={row.id}>
                <td>
                  <span className="table-primary">{row.full_name}</span>
                  <small>{row.email}</small>
                </td>
                <td>
                  {editable && row.id !== user.id ? (
                    <select
                      aria-label={`Role for ${row.email}`}
                      value={row.role}
                      onChange={(e) => update.mutate({ id: row.id, body: { role: e.target.value } })}
                    >
                      {ROLES.map((role) => (
                        <option key={role} value={role}>
                          {label(role)}
                        </option>
                      ))}
                    </select>
                  ) : (
                    label(row.role)
                  )}
                </td>
                <td>
                  {editable && row.id !== user.id ? (
                    <button
                      className={`text-btn ${row.is_active ? 'danger-text' : ''}`}
                      onClick={() => update.mutate({ id: row.id, body: { is_active: !row.is_active } })}
                    >
                      {row.is_active ? 'Deactivate' : 'Reactivate'}
                    </button>
                  ) : (
                    <span className="status-pill">{row.is_active ? 'active' : 'inactive'}</span>
                  )}
                </td>
                <td>{row.mfa_enabled ? 'on' : 'off'}</td>
                {editable && (
                  <td>
                    {row.id !== user.id && (
                      <div className="button-row">
                        <button
                          className="text-btn"
                          onClick={() => {
                            const password = window.prompt(`Temporary password for ${row.email} (12+ chars, mixed case, number, symbol)`)
                            if (password) resetPassword.mutate({ id: row.id, password })
                          }}
                        >
                          Reset password
                        </button>
                        {row.mfa_enabled && (
                          <button className="text-btn danger-text" onClick={() => resetMfa.mutate(row.id)}>
                            Reset MFA
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

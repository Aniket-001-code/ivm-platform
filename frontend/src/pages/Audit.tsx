import { useState } from 'react'
import { keepPreviousData, useMutation, useQuery } from '@tanstack/react-query'
import { ArrowDownRight, ShieldCheck } from 'lucide-react'
import { api, apiPage, downloadCsv, qs } from '../api/client'
import { label } from '../access'
import { Empty, ErrorState, Loading, PageTitle, Pager, useDebounced } from '../components/ui'

type AuditRow = {
  id: string
  actor_user_id: string | null
  actor_email: string | null
  action: string
  entity_type: string
  entity_id: string | null
  new_value: unknown
  timestamp: string
}

const PAGE_SIZE = 50

export function AuditPage() {
  const [action, setAction] = useState('')
  const [entityType, setEntityType] = useState('')
  const [actor, setActor] = useState('')
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  const [offset, setOffset] = useState(0)
  const debouncedActor = useDebounced(actor)
  const facets = useQuery({
    queryKey: ['audit-facets'],
    queryFn: () => api<{ actions: string[]; entity_types: string[] }>('/audit/facets'),
  })
  const filters = {
    action,
    entity_type: entityType,
    actor: debouncedActor,
    since: since ? `${since}T00:00:00` : '',
    until: until ? `${until}T23:59:59` : '',
  }
  const query = useQuery({
    queryKey: ['audit', filters, offset],
    queryFn: () => apiPage<AuditRow>(`/audit${qs({ ...filters, limit: PAGE_SIZE, offset })}`),
    placeholderData: keepPreviousData,
  })
  const verify = useMutation({
    mutationFn: () =>
      api<{ valid: boolean; checked: number; legacy_unchained: number; broken_at?: string; sequence?: number }>('/audit/verify'),
  })
  const reset = (fn: () => void) => {
    fn()
    setOffset(0)
  }
  return (
    <>
      <PageTitle
        eyebrow="ASSURANCE"
        title="Audit trail"
        description="Append-only record of security, configuration, and workflow events."
        action={
          <>
            <button className="secondary-btn" onClick={() => verify.mutate()} disabled={verify.isPending}>
              {verify.isPending ? 'Verifying…' : 'Verify integrity'} <ShieldCheck size={14} />
            </button>
            <button className="secondary-btn" onClick={() => void downloadCsv(`/audit/export${qs(filters)}`, 'ivm-audit.csv')}>
              Download CSV <ArrowDownRight size={14} />
            </button>
          </>
        }
      />
      {verify.data && (
        <p className={verify.data.valid ? 'success-note' : 'error-box'} role="status">
          {verify.data.valid
            ? `Hash chain intact: ${verify.data.checked} events verified${verify.data.legacy_unchained ? ` (${verify.data.legacy_unchained} pre-chain events not covered)` : ''}. The database also rejects edits and deletions of audit rows.`
            : `Tampering detected at event #${verify.data.sequence} (${verify.data.broken_at}). Events after this point cannot be trusted.`}
        </p>
      )}
      {verify.error && <ErrorState message={(verify.error as Error).message} />}
      <div className="filter-bar wrap">
        <select aria-label="Action" value={action} onChange={(e) => reset(() => setAction(e.target.value))}>
          <option value="">All actions</option>
          {(facets.data?.actions ?? []).map((x) => (
            <option key={x} value={x}>
              {label(x)}
            </option>
          ))}
        </select>
        <select aria-label="Entity type" value={entityType} onChange={(e) => reset(() => setEntityType(e.target.value))}>
          <option value="">All entities</option>
          {(facets.data?.entity_types ?? []).map((x) => (
            <option key={x} value={x}>
              {label(x)}
            </option>
          ))}
        </select>
        <input
          className="text-input"
          aria-label="Actor email"
          placeholder="Actor email contains…"
          value={actor}
          onChange={(e) => reset(() => setActor(e.target.value))}
        />
        <label className="inline-label">
          From
          <input type="date" aria-label="From date" value={since} onChange={(e) => reset(() => setSince(e.target.value))} />
        </label>
        <label className="inline-label">
          To
          <input type="date" aria-label="To date" value={until} onChange={(e) => reset(() => setUntil(e.target.value))} />
        </label>
        <span className="result-count">{(query.data?.total ?? 0).toLocaleString()} events</span>
      </div>
      <section className="panel table-panel">
        {query.isLoading ? (
          <Loading />
        ) : query.error ? (
          <ErrorState message={(query.error as Error).message} />
        ) : !query.data?.rows.length ? (
          <Empty>No audit events match these filters.</Empty>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Entity</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {query.data.rows.map((row) => (
                  <tr key={row.id}>
                    <td>{new Date(row.timestamp).toLocaleString()}</td>
                    <td>{row.actor_email ?? 'system'}</td>
                    <td>{label(row.action)}</td>
                    <td>
                      {row.entity_type}
                      {row.entity_id ? ` · ${row.entity_id.slice(0, 8)}` : ''}
                    </td>
                    <td className="details-cell" title={JSON.stringify(row.new_value ?? {})}>
                      {JSON.stringify(row.new_value ?? {})}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pager offset={offset} limit={PAGE_SIZE} total={query.data?.total ?? 0} onChange={setOffset} />
      </section>
    </>
  )
}

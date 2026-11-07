import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Download, Search } from 'lucide-react'
import { apiPage, downloadCsv, qs } from '../api/client'
import { P, can, label } from '../access'
import { FindingTable } from '../components/FindingTable'
import { ErrorState, Loading, PageTitle, Pager, useDebounced, type Sort } from '../components/ui'
import type { Finding, User } from '../types'

const PAGE_SIZE = 50
const STATUSES = ['open', 'in_remediation', 'risk_accepted', 'closed']

export function FindingsPage({ user }: { user: User }) {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState(params.get('search') ?? '')
  const debouncedSearch = useDebounced(search)
  const searchParam = params.get('search') ?? ''
  useEffect(() => {
    // Keep the box in sync when the global search changes the URL while this page is open.
    setSearch((current) => (current === searchParam ? current : searchParam))
  }, [searchParam])
  const band = params.get('band') ?? ''
  const status = params.get('status') ?? ''
  const offset = Number(params.get('offset') ?? 0)
  const sort: Sort = {
    field: params.get('sort') ?? 'risk_score',
    order: params.get('order') === 'asc' ? 'asc' : 'desc',
  }
  const update = (changes: Record<string, string>) => {
    const next = new URLSearchParams(params)
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value)
      else next.delete(key)
    }
    if (!('offset' in changes)) next.delete('offset')
    setParams(next, { replace: true })
  }
  const filters = { search: debouncedSearch, band, status, sort: sort.field, order: sort.order }
  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['findings', filters, offset],
    queryFn: () => apiPage<Finding>(`/findings${qs({ ...filters, limit: PAGE_SIZE, offset })}`),
    placeholderData: keepPreviousData,
  })
  return (
    <>
      <PageTitle
        eyebrow="RISK REGISTER"
        title="Findings"
        description="Correlated, risk-ranked issues across your inventory."
        action={
          <>
            <button
              className="secondary-btn"
              onClick={() => void downloadCsv(`/findings/export${qs(filters)}`, 'ivm-findings.csv')}
            >
              Export CSV <Download size={14} />
            </button>
            {can(user, P.import) && (
              <button className="primary-btn" onClick={() => navigate('/imports')}>
                Import findings <span>＋</span>
              </button>
            )}
          </>
        }
      />
      <div className="filter-bar">
        <label className="search-box">
          <Search size={16} />
          <input
            aria-label="Search findings"
            placeholder="Search findings…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              update({ search: e.target.value })
            }}
          />
        </label>
        <select aria-label="Risk band" value={band} onChange={(e) => update({ band: e.target.value })}>
          <option value="">All risk bands</option>
          {['critical', 'high', 'medium', 'low'].map((x) => (
            <option key={x} value={x}>
              {x}
            </option>
          ))}
        </select>
        <select aria-label="Status" value={status} onChange={(e) => update({ status: e.target.value })}>
          <option value="">All statuses</option>
          {STATUSES.map((x) => (
            <option key={x} value={x}>
              {label(x)}
            </option>
          ))}
        </select>
        <span className="result-count">
          {isFetching && !isLoading ? 'Updating… ' : ''}
          {(data?.total ?? 0).toLocaleString()} findings
        </span>
      </div>
      <section className="panel table-panel">
        {isLoading ? (
          <Loading />
        ) : error ? (
          <ErrorState message={(error as Error).message} />
        ) : (
          <>
            <FindingTable
              rows={data?.rows ?? []}
              sort={sort}
              onSort={(next) => update({ sort: next.field, order: next.order })}
            />
            <Pager
              offset={offset}
              limit={PAGE_SIZE}
              total={data?.total ?? 0}
              onChange={(next) => update({ offset: String(next) })}
            />
          </>
        )}
      </section>
    </>
  )
}

import { useEffect, useState, type ReactNode } from 'react'
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight } from 'lucide-react'

export function PageTitle({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="page-title">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-actions">{action}</div>}
    </div>
  )
}

export function Loading() {
  return (
    <div className="skeleton" aria-label="Loading data">
      <i />
      <i />
      <i />
    </div>
  )
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="error-box" role="alert">
      {message}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty-state">{children}</p>
}

export function RiskBadge({ band }: { band: string }) {
  return (
    <span className={`risk-badge ${band.toLowerCase()}`}>
      <i />
      {band}
    </span>
  )
}

export function Metric({
  label,
  value,
  foot,
  icon,
  accent = 'teal',
}: {
  label: string
  value: string
  foot: string
  icon: ReactNode
  accent?: string
}) {
  return (
    <article className="metric-card">
      <div className="metric-top">
        <span>{label}</span>
        <span className={`metric-icon ${accent}`}>{icon}</span>
      </div>
      <strong>{value}</strong>
      <small>{foot}</small>
    </article>
  )
}

export type Sort = { field: string; order: 'asc' | 'desc' }

/** Column header that toggles server-side sorting. */
export function SortTh({
  field,
  sort,
  onSort,
  children,
}: {
  field: string
  sort: Sort
  onSort: (sort: Sort) => void
  children: ReactNode
}) {
  const active = sort.field === field
  const next: Sort = { field, order: active && sort.order === 'desc' ? 'asc' : 'desc' }
  return (
    <th aria-sort={active ? (sort.order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="sort-btn" onClick={() => onSort(next)}>
        {children}
        {active && (sort.order === 'asc' ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}
      </button>
    </th>
  )
}

export function Pager({
  offset,
  limit,
  total,
  onChange,
}: {
  offset: number
  limit: number
  total: number
  onChange: (offset: number) => void
}) {
  if (total <= limit) return null
  const page = Math.floor(offset / limit) + 1
  const pages = Math.max(1, Math.ceil(total / limit))
  return (
    <nav className="pager" aria-label="Pagination">
      <span>
        {(offset + 1).toLocaleString()}–{Math.min(offset + limit, total).toLocaleString()} of{' '}
        {total.toLocaleString()}
      </span>
      <button
        type="button"
        className="secondary-btn"
        disabled={page <= 1}
        onClick={() => onChange(Math.max(0, offset - limit))}
        aria-label="Previous page"
      >
        <ChevronLeft size={14} />
      </button>
      <span>
        Page {page} / {pages}
      </span>
      <button
        type="button"
        className="secondary-btn"
        disabled={page >= pages}
        onClick={() => onChange(offset + limit)}
        aria-label="Next page"
      >
        <ChevronRight size={14} />
      </button>
    </nav>
  )
}

/** Debounce a value so typing in search boxes does not fire a request per keystroke. */
export function useDebounced<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(timer)
  }, [value, delay])
  return debounced
}

export const formatDate = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' }) : '—'

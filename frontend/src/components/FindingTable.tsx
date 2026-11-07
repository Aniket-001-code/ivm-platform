import { Link } from 'react-router-dom'
import type { Finding } from '../types'
import { label } from '../access'
import { RiskBadge, SortTh, type Sort } from './ui'

/** Risk-ranked finding table. Sorting is optional; links are hidden for roles without finding access. */
export function FindingTable({
  rows,
  linkable = true,
  sort,
  onSort,
}: {
  rows: Finding[]
  linkable?: boolean
  sort?: Sort
  onSort?: (sort: Sort) => void
}) {
  const header = (field: string, text: string) =>
    sort && onSort ? (
      <SortTh field={field} sort={sort} onSort={onSort}>
        {text}
      </SortTh>
    ) : (
      <th>{text}</th>
    )
  return (
    <div className="table-scroll">
      <table aria-label="Prioritized findings">
        <thead>
          <tr>
            {header('title', 'Finding')}
            {header('severity', 'Severity')}
            {header('risk_score', 'Risk score')}
            <th>Sources</th>
            {header('status', 'Status')}
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>
                {linkable ? (
                  <Link className="table-primary" to={`/findings/${row.id}`}>
                    {row.title}
                  </Link>
                ) : (
                  <span className="table-primary">{row.title}</span>
                )}
                <small>
                  {row.id.slice(0, 8)} · asset {row.asset_id.slice(0, 8)}
                </small>
              </td>
              <td>
                <RiskBadge band={row.severity} />
              </td>
              <td>
                <div className="score-cell">
                  <strong>{Number(row.risk_score).toFixed(1)}</strong>
                  <div className="score-track">
                    <i style={{ width: `${row.risk_score}%` }} />
                  </div>
                </div>
              </td>
              <td>{row.sources?.slice(0, 2).join(', ') || '—'}</td>
              <td>
                <span className="status-pill">{label(row.status)}</span>
              </td>
              <td>
                {linkable && (
                  <Link className="row-arrow" to={`/findings/${row.id}`} aria-label={`Open ${row.title}`}>
                    →
                  </Link>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

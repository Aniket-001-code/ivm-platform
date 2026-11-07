import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { api } from '../api/client'
import { P, can } from '../access'
import { Empty, ErrorState, Loading, PageTitle, RiskBadge } from '../components/ui'
import type { User } from '../types'

type Path = {
  id: string
  name: string
  entry_asset_id: string
  target_asset_id: string
  path_asset_ids: string[]
  path_finding_ids: string[]
  path_risk_score: number
  base_score: number
  final_score: number
  path_influence: number
}

type GraphNode = {
  id: string
  name: string
  risk_band: string
  is_crown_jewel: boolean
  internet_exposed?: boolean
  findings: Array<{ id: string; title: string; risk_score: number; risk_band: string }>
}

export function AttackPathsPage({ user }: { user: User }) {
  const qc = useQueryClient()
  const paths = useQuery({ queryKey: ['attack-paths'], queryFn: () => api<Path[]>('/attack-paths') })
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [after, setAfter] = useState(true)
  const selected = paths.data?.find((p) => p.id === selectedId) ?? paths.data?.[0]
  const graph = useQuery({
    queryKey: ['graph', selected?.entry_asset_id],
    queryFn: () =>
      api<{ nodes: GraphNode[]; links: Array<{ source: string; target: string; type: string }> }>(
        `/attack-paths/graph?asset_id=${selected!.entry_asset_id}`,
      ),
    enabled: Boolean(selected),
  })
  const recalc = useMutation({
    mutationFn: () => api<{ calculated: number }>('/attack-paths/recalculate', { method: 'POST' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['attack-paths'] })
      void qc.invalidateQueries({ queryKey: ['graph'] })
    },
  })
  const nodes = useMemo(() => new Map((graph.data?.nodes ?? []).map((n) => [n.id, n])), [graph.data])
  if (paths.error) return <ErrorState message={(paths.error as Error).message} />
  return (
    <>
      <PageTitle
        eyebrow="EXPOSURE GRAPH"
        title="Attack paths"
        description="Modeled routes from internet-facing assets to crown jewels, and how they raise finding risk."
        action={
          can(user, P.riskManage) && (
            <button className="secondary-btn" onClick={() => recalc.mutate()} disabled={recalc.isPending}>
              {recalc.isPending ? 'Recalculating…' : 'Recalculate paths'} <RefreshCw size={14} />
            </button>
          )
        }
      />
      {recalc.data && <p className="success-note">Recalculated {recalc.data.calculated} paths.</p>}
      {recalc.error && <ErrorState message={(recalc.error as Error).message} />}
      {paths.isLoading ? (
        <Loading />
      ) : !paths.data?.length ? (
        <Empty>No attack paths are modeled for assets in your scope.</Empty>
      ) : (
        <div className="path-layout">
          <section className="panel graph-panel">
            <div className="graph-legend">
              <span>
                <i className="legend-entry" />
                Internet entry
              </span>
              <span>
                <i className="legend-hop" />
                Asset hop
              </span>
              <span>
                <i className="legend-crown" />
                Crown jewel
              </span>
            </div>
            {selected && (
              <>
                <h2 className="route-title">{selected.name}</h2>
                <ol className="route" aria-label="Selected attack route">
                  {selected.path_asset_ids.map((assetId, index) => {
                    const node = nodes.get(assetId)
                    const role =
                      index === 0 ? 'entry' : index === selected.path_asset_ids.length - 1 ? 'crown' : 'hop'
                    return (
                      <li key={assetId} className={`route-node ${role}`}>
                        <span className="route-dot" />
                        <div>
                          {can(user, P.assetRead) ? (
                            <Link to={`/assets/${assetId}`}>{node?.name ?? assetId.slice(0, 8)}</Link>
                          ) : (
                            <strong>{node?.name ?? assetId.slice(0, 8)}</strong>
                          )}
                          <small>
                            {role === 'entry' ? 'Entry point' : role === 'crown' ? 'Crown jewel target' : `Hop ${index}`}
                            {node ? ` · ${node.findings.length} open findings` : ''}
                          </small>
                          {node?.findings[0] && (
                            <small className="route-finding">
                              Worst: {node.findings[0].title} ({node.findings[0].risk_score.toFixed(0)})
                            </small>
                          )}
                        </div>
                      </li>
                    )
                  })}
                </ol>
                <div className="score-compare">
                  <div>
                    <span className="panel-kicker">BEFORE PATH CONTEXT</span>
                    <strong>{selected.base_score.toFixed(1)}</strong>
                  </div>
                  <span>→</span>
                  <div>
                    <span className="panel-kicker">AFTER PATH CONTEXT</span>
                    <strong>{selected.final_score.toFixed(1)}</strong>
                  </div>
                  <p className="muted">
                    Average risk of the {selected.path_finding_ids.length} findings on this route, without and with the
                    attack-path factor. Findings on this route gain up to {(selected.path_influence * 10).toFixed(1)} of
                    the 10 attack-path points.
                  </p>
                </div>
                {graph.isLoading && <Loading />}
              </>
            )}
          </section>
          <aside className="panel path-list">
            <span className="panel-kicker">PRIORITY ROUTES</span>
            <h2>{paths.data.length} modeled paths</h2>
            <div className="compare-toggle" role="group" aria-label="Score shown">
              <button className={!after ? 'selected' : ''} onClick={() => setAfter(false)}>
                Before feedback
              </button>
              <button className={after ? 'selected' : ''} onClick={() => setAfter(true)}>
                After feedback
              </button>
            </div>
            {paths.data.slice(0, 25).map((path) => (
              <button
                type="button"
                className={`path-item ${path.id === selected?.id ? 'active' : ''}`}
                key={path.id}
                onClick={() => setSelectedId(path.id)}
                aria-pressed={path.id === selected?.id}
              >
                <span className="path-risk">{(after ? path.final_score : path.base_score).toFixed(0)}</span>
                <span>
                  <strong>{path.name}</strong>
                  <small>
                    {path.path_asset_ids.length} asset hops · {path.path_finding_ids.length} linked findings
                  </small>
                </span>
                <RiskBadge band={path.path_risk_score >= 80 ? 'critical' : path.path_risk_score >= 60 ? 'high' : 'medium'} />
              </button>
            ))}
          </aside>
        </div>
      )}
    </>
  )
}

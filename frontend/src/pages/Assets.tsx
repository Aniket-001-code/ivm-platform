import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Boxes, Download, Pencil, Plus, Search } from 'lucide-react'
import { api, apiPage, downloadCsv, qs } from '../api/client'
import { P, can, label } from '../access'
import { FindingTable } from '../components/FindingTable'
import { AssetEditor, EMPTY_ASSET } from '../components/AssetEditor'
import { Empty, ErrorState, Loading, PageTitle, Pager, RiskBadge, useDebounced } from '../components/ui'
import type { Asset, Finding, User } from '../types'

const PAGE_SIZE = 30

const postureBand = (a: Asset) => (a.is_crown_jewel ? 'critical' : a.internet_exposed ? 'high' : a.criticality_tier <= 2 ? 'medium' : 'low')

export function AssetsPage({ user }: { user: User }) {
  const [params, setParams] = useSearchParams()
  const [creating, setCreating] = useState(false)
  const navigate = useNavigate()
  const [search, setSearch] = useState(params.get('search') ?? '')
  const debounced = useDebounced(search)
  const get = (key: string) => params.get(key) ?? ''
  const offset = Number(get('offset') || 0)
  const update = (changes: Record<string, string>) => {
    const next = new URLSearchParams(params)
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value)
      else next.delete(key)
    }
    if (!('offset' in changes)) next.delete('offset')
    setParams(next, { replace: true })
  }
  const filters = {
    search: debounced,
    environment: get('environment'),
    internet_exposed: get('exposed'),
    crown_jewel: get('crown'),
    tier: get('tier'),
    sort: get('sort') || 'criticality_tier',
    order: get('order') || 'asc',
  }
  const { data, isLoading, error } = useQuery({
    queryKey: ['assets', filters, offset],
    queryFn: () => apiPage<Asset>(`/assets${qs({ ...filters, limit: PAGE_SIZE, offset })}`),
    placeholderData: keepPreviousData,
  })
  return (
    <>
      <PageTitle
        eyebrow="INVENTORY"
        title="Asset inventory"
        description="Business context for systems, applications, and data stores."
        action={
          <>
            <button className="secondary-btn" onClick={() => void downloadCsv(`/assets/export${qs(filters)}`, 'ivm-assets.csv')}>
              Export CSV <Download size={14} />
            </button>
            {can(user, P.assetManage) && (
              <button className="primary-btn" onClick={() => setCreating(true)}>
                Register asset <Plus size={14} />
              </button>
            )}
          </>
        }
      />
      {creating && (
        <AssetEditor
          initial={EMPTY_ASSET}
          canListUsers={can(user, P.userRead)}
          onCancel={() => setCreating(false)}
          onDone={(result) => {
            setCreating(false)
            navigate(`/assets/${result.id}`)
          }}
        />
      )}
      <div className="filter-bar">
        <label className="search-box">
          <Search size={16} />
          <input
            aria-label="Search assets"
            placeholder="Search name or hostname…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              update({ search: e.target.value })
            }}
          />
        </label>
        <select aria-label="Environment" value={get('environment')} onChange={(e) => update({ environment: e.target.value })}>
          <option value="">All environments</option>
          {['prod', 'uat', 'dev'].map((x) => (
            <option key={x}>{x}</option>
          ))}
        </select>
        <select aria-label="Exposure" value={get('exposed')} onChange={(e) => update({ exposed: e.target.value })}>
          <option value="">Any exposure</option>
          <option value="true">Internet exposed</option>
          <option value="false">Internal only</option>
        </select>
        <select aria-label="Crown jewel" value={get('crown')} onChange={(e) => update({ crown: e.target.value })}>
          <option value="">All assets</option>
          <option value="true">Crown jewels</option>
        </select>
        <select aria-label="Criticality tier" value={get('tier')} onChange={(e) => update({ tier: e.target.value })}>
          <option value="">Any tier</option>
          {[1, 2, 3, 4, 5].map((x) => (
            <option key={x} value={x}>
              Tier {x}
            </option>
          ))}
        </select>
        <select
          aria-label="Sort assets"
          value={`${filters.sort}:${filters.order}`}
          onChange={(e) => {
            const [sort, order] = e.target.value.split(':')
            update({ sort, order })
          }}
        >
          <option value="criticality_tier:asc">Most critical first</option>
          <option value="name:asc">Name A–Z</option>
          <option value="name:desc">Name Z–A</option>
          <option value="environment:asc">Environment</option>
          <option value="asset_type:asc">Type</option>
        </select>
        <span className="result-count">{(data?.total ?? 0).toLocaleString()} assets</span>
      </div>
      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorState message={(error as Error).message} />
      ) : (
        <>
          <div className="asset-grid">
            {(data?.rows ?? []).map((a) => (
              <article className="panel asset-card" key={a.id}>
                <div className="asset-card-top">
                  <span className="asset-symbol">
                    <Boxes size={17} />
                  </span>
                  <RiskBadge band={postureBand(a)} />
                </div>
                <h3>
                  <Link to={`/assets/${a.id}`}>{a.name}</Link>
                </h3>
                <p>
                  {a.hostname} · {a.environment}
                </p>
                <div className="asset-tags">
                  <span>Tier {a.criticality_tier}</span>
                  {a.internet_exposed && <span>Internet exposed</span>}
                  {a.is_crown_jewel && <span>Crown jewel</span>}
                  {a.has_sensitive_data && <span>Sensitive data</span>}
                </div>
                <div className="asset-card-foot">
                  <span>{label(a.asset_type)}</span>
                  <Link to={`/assets/${a.id}`} aria-label={`Open ${a.name}`}>
                    ↗
                  </Link>
                </div>
              </article>
            ))}
          </div>
          {!data?.rows.length && <Empty>No assets match these filters.</Empty>}
          <Pager offset={offset} limit={PAGE_SIZE} total={data?.total ?? 0} onChange={(next) => update({ offset: String(next) })} />
        </>
      )}
    </>
  )
}

type AssetDetail = Asset & {
  business_unit_id: string | null
  business_unit: string | null
  business_service_id: string | null
  business_service: string | null
  owner_user_id: string | null
  owner_email: string | null
  ip_address: string | null
  regulatory_tags: string[]
  open_findings: number
  max_risk: number
}
type Connection = {
  source_asset_id: string
  target_asset_id: string
  source_name: string | null
  target_name: string | null
  direction: 'inbound' | 'outbound'
  connection_type: string
  port_or_protocol: string | null
}

export function AssetDetailPage({ user }: { user: User }) {
  const { id = '' } = useParams()
  const asset = useQuery({ queryKey: ['asset', id], queryFn: () => api<AssetDetail>(`/assets/${id}`) })
  const connections = useQuery({
    queryKey: ['asset-connections', id],
    queryFn: () => api<Connection[]>(`/assets/${id}/connections`),
  })
  const findings = useQuery({
    queryKey: ['asset-findings', id],
    queryFn: () => api<Finding[]>(`/findings${qs({ asset_id: id, limit: 25 })}`),
    enabled: can(user, P.findingRead),
  })
  const [editing, setEditing] = useState(false)
  const [notice, setNotice] = useState('')
  if (asset.error) return <ErrorState message={(asset.error as Error).message} />
  if (!asset.data) return <Loading />
  const a = asset.data
  return (
    <>
      <Link to="/assets" className="back-link">
        ← Back to assets
      </Link>
      <PageTitle
        eyebrow="ASSET PROFILE"
        title={a.name}
        description={`${a.hostname ?? 'no hostname'} · ${a.environment} environment · ${a.status}`}
        action={
          can(user, P.assetManage) &&
          !editing && (
            <button className="secondary-btn" onClick={() => setEditing(true)}>
              Edit asset <Pencil size={14} />
            </button>
          )
        }
      />
      {notice && <p className="success-note">{notice}</p>}
      {editing && (
        <AssetEditor
          assetId={a.id}
          canListUsers={can(user, P.userRead)}
          initial={{
            name: a.name,
            hostname: a.hostname ?? '',
            ip_address: a.ip_address ?? '',
            asset_type: a.asset_type,
            environment: a.environment,
            business_unit_id: a.business_unit_id ?? '',
            business_service_id: a.business_service_id ?? '',
            owner_user_id: a.owner_user_id ?? '',
            criticality_tier: a.criticality_tier,
            internet_exposed: a.internet_exposed,
            is_customer_facing: Boolean(a.is_customer_facing),
            is_crown_jewel: a.is_crown_jewel,
            has_sensitive_data: Boolean(a.has_sensitive_data),
            regulatory_tags: (a.regulatory_tags ?? []).join(', '),
            status: a.status ?? 'active',
          }}
          onCancel={() => setEditing(false)}
          onDone={(result) => {
            setEditing(false)
            setNotice(
              result.findings_rescored
                ? `Saved. ${result.findings_rescored} open finding(s) were rescored with the new context.`
                : 'Saved.',
            )
          }}
        />
      )}
      <div className="detail-grid">
        <section className="panel">
          <span className="panel-kicker">BUSINESS CONTEXT</span>
          <h2>Asset posture</h2>
          {[
            ['Criticality tier', `Tier ${a.criticality_tier}`],
            ['Type', label(a.asset_type)],
            ['Business unit', a.business_unit ?? '—'],
            ['Business service', a.business_service ?? '—'],
            ['Owner', a.owner_email ?? 'Unassigned'],
            ['Internet exposed', a.internet_exposed ? 'Yes' : 'No'],
            ['Customer facing', a.is_customer_facing ? 'Yes' : 'No'],
            ['Crown jewel', a.is_crown_jewel ? 'Yes' : 'No'],
            ['Sensitive data', a.has_sensitive_data ? 'Yes' : 'No'],
            ['Regulatory tags', (a.regulatory_tags ?? []).join(', ') || '—'],
            ['Open findings / max risk', `${a.open_findings} / ${Number(a.max_risk).toFixed(1)}`],
          ].map(([name, value]) => (
            <div className="detail-pair" key={name}>
              <span>{name}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </section>
        <section className="panel">
          <span className="panel-kicker">NETWORK</span>
          <h2>Connections</h2>
          {connections.data?.length ? (
            <div className="mini-list">
              {connections.data.map((edge) => {
                const peerId = edge.direction === 'outbound' ? edge.target_asset_id : edge.source_asset_id
                const peerName = edge.direction === 'outbound' ? edge.target_name : edge.source_name
                return (
                  <div key={`${edge.source_asset_id}-${edge.target_asset_id}-${edge.connection_type}`}>
                    <span className="muted">{edge.direction === 'outbound' ? '→' : '←'}</span>
                    {peerName ? <Link to={`/assets/${peerId}`}>{peerName}</Link> : <span className="muted">Outside your scope</span>}
                    <span className="muted">
                      {edge.connection_type}
                      {edge.port_or_protocol ? ` · ${edge.port_or_protocol}` : ''}
                    </span>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="muted">No connections recorded.</p>
          )}
        </section>
      </div>
      {can(user, P.findingRead) && (
        <section className="panel table-panel spaced-top">
          <div className="panel-head">
            <div>
              <span className="panel-kicker">EXPOSURE</span>
              <h2>Findings on this asset</h2>
            </div>
          </div>
          {findings.data?.length ? <FindingTable rows={findings.data} /> : <Empty>No findings recorded on this asset.</Empty>}
        </section>
      )}
    </>
  )
}

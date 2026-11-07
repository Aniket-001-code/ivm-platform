import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { ErrorState } from './ui'

export type AssetForm = {
  name: string
  hostname: string
  ip_address: string
  asset_type: string
  environment: string
  business_unit_id: string
  business_service_id: string
  owner_user_id: string
  criticality_tier: number
  internet_exposed: boolean
  is_customer_facing: boolean
  is_crown_jewel: boolean
  has_sensitive_data: boolean
  regulatory_tags: string
  status: string
}

export const EMPTY_ASSET: AssetForm = {
  name: '',
  hostname: '',
  ip_address: '',
  asset_type: 'server',
  environment: 'dev',
  business_unit_id: '',
  business_service_id: '',
  owner_user_id: '',
  criticality_tier: 3,
  internet_exposed: false,
  is_customer_facing: false,
  is_crown_jewel: false,
  has_sensitive_data: false,
  regulatory_tags: '',
  status: 'active',
}

const TYPES = ['server', 'application', 'database', 'container', 'cloud_resource', 'network_device', 'endpoint', 'saas', 'identity']
const ENVIRONMENTS = ['prod', 'uat', 'dev', 'test', 'dr']

/** Asset registration (UC-1) and criticality / ownership context (UC-2). */
export function AssetEditor({
  initial,
  assetId,
  canListUsers,
  onDone,
  onCancel,
}: {
  initial: AssetForm
  assetId?: string
  canListUsers: boolean
  onDone: (result: { id: string; findings_rescored?: number }) => void
  onCancel: () => void
}) {
  const [form, setForm] = useState<AssetForm>(initial)
  const qc = useQueryClient()
  const units = useQuery({
    queryKey: ['business-units'],
    queryFn: () => api<Array<{ id: string; name: string }>>('/business-units'),
  })
  const services = useQuery({
    queryKey: ['business-services'],
    queryFn: () => api<Array<{ id: string; name: string; business_unit_id: string }>>('/business-services'),
  })
  const users = useQuery({
    queryKey: ['users'],
    queryFn: () => api<Array<{ id: string; email: string; full_name: string; is_active: boolean }>>('/users'),
    enabled: canListUsers,
  })
  const save = useMutation({
    mutationFn: () => {
      const payload = {
        ...form,
        hostname: form.hostname || null,
        ip_address: form.ip_address || null,
        business_unit_id: form.business_unit_id || null,
        business_service_id: form.business_service_id || null,
        owner_user_id: form.owner_user_id || null,
        regulatory_tags: form.regulatory_tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      }
      if (!assetId) {
        delete (payload as Partial<typeof payload>).status
      }
      return api<{ id: string; findings_rescored?: number }>(assetId ? `/assets/${assetId}` : '/assets', {
        method: assetId ? 'PATCH' : 'POST',
        body: JSON.stringify(payload),
      })
    },
    onSuccess: (result) => {
      void qc.invalidateQueries({ queryKey: ['assets'] })
      void qc.invalidateQueries({ queryKey: ['asset'] })
      void qc.invalidateQueries({ queryKey: ['findings'] })
      onDone(result)
    },
  })
  const set = <K extends keyof AssetForm>(key: K, value: AssetForm[K]) => setForm((f) => ({ ...f, [key]: value }))
  function submit(event: FormEvent) {
    event.preventDefault()
    save.mutate()
  }
  const unitServices = (services.data ?? []).filter((s) => !form.business_unit_id || s.business_unit_id === form.business_unit_id)
  return (
    <form className="panel form-panel asset-editor" onSubmit={submit} aria-label={assetId ? 'Edit asset' : 'Register asset'}>
      <div>
        <span className="panel-kicker">{assetId ? 'ASSET CONTEXT' : 'NEW ASSET'}</span>
        <h2>{assetId ? 'Edit criticality, ownership and inventory' : 'Register an asset'}</h2>
        <p className="muted">Changes to criticality, exposure, sensitivity or regulatory tags rescore this asset's findings immediately.</p>
      </div>
      <div className="form-row">
        <label>
          Name
          <input required value={form.name} onChange={(e) => set('name', e.target.value)} />
        </label>
        <label>
          Hostname
          <input value={form.hostname} onChange={(e) => set('hostname', e.target.value)} placeholder="host.bank.local" />
        </label>
      </div>
      <div className="form-row">
        <label>
          IP address
          <input value={form.ip_address} onChange={(e) => set('ip_address', e.target.value)} placeholder="10.0.0.10" />
        </label>
        <label>
          Type
          <select value={form.asset_type} onChange={(e) => set('asset_type', e.target.value)}>
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {t.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-row">
        <label>
          Environment
          <select value={form.environment} onChange={(e) => set('environment', e.target.value)}>
            {ENVIRONMENTS.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <label>
          Criticality tier (1 = most critical)
          <select value={form.criticality_tier} onChange={(e) => set('criticality_tier', Number(e.target.value))}>
            {[1, 2, 3, 4, 5].map((t) => (
              <option key={t} value={t}>
                Tier {t}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-row">
        <label>
          Business unit
          <select
            value={form.business_unit_id}
            onChange={(e) => setForm((f) => ({ ...f, business_unit_id: e.target.value, business_service_id: '' }))}
          >
            <option value="">—</option>
            {(units.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Business service
          <select value={form.business_service_id} onChange={(e) => set('business_service_id', e.target.value)}>
            <option value="">—</option>
            {unitServices.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-row">
        <label>
          Owner
          <select value={form.owner_user_id} onChange={(e) => set('owner_user_id', e.target.value)} disabled={!canListUsers}>
            <option value="">{canListUsers ? 'Unassigned (routing rules / BU manager)' : 'Owner list unavailable for your role'}</option>
            {(users.data ?? [])
              .filter((u) => u.is_active)
              .map((u) => (
                <option key={u.id} value={u.id}>
                  {u.full_name} · {u.email}
                </option>
              ))}
          </select>
        </label>
        <label>
          Regulatory tags (comma separated)
          <input value={form.regulatory_tags} onChange={(e) => set('regulatory_tags', e.target.value)} placeholder="PCI-DSS, SOX, GDPR" />
        </label>
      </div>
      <fieldset className="check-grid">
        <legend>Criticality intelligence</legend>
        {(
          [
            ['internet_exposed', 'Internet exposed'],
            ['is_customer_facing', 'Customer facing'],
            ['is_crown_jewel', 'Crown jewel'],
            ['has_sensitive_data', 'Holds sensitive data'],
          ] as const
        ).map(([key, text]) => (
          <label className="check" key={key}>
            <input type="checkbox" checked={form[key]} onChange={(e) => set(key, e.target.checked)} />
            {text}
          </label>
        ))}
      </fieldset>
      {assetId && (
        <label>
          Lifecycle status
          <select value={form.status} onChange={(e) => set('status', e.target.value)}>
            <option value="active">active</option>
            <option value="maintenance">maintenance</option>
            <option value="retired">retired (decommissioned)</option>
          </select>
        </label>
      )}
      {save.error && <ErrorState message={(save.error as Error).message} />}
      <div className="button-row">
        <button className="primary-btn" disabled={!form.name.trim() || save.isPending}>
          {save.isPending ? 'Saving…' : assetId ? 'Save changes' : 'Register asset'}
        </button>
        <button type="button" className="secondary-btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  )
}

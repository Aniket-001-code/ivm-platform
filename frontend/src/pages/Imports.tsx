import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, FileUp } from 'lucide-react'
import { api } from '../api/client'
import { ErrorState, PageTitle, formatDate } from '../components/ui'

type Batch = {
  id: string
  source_name: string
  file_name?: string
  status: string
  total_records: number
  success_count: number
  failed_count: number
  duplicate_count: number
  created_at?: string
  errors?: Array<Record<string, unknown>> | null
}

const SOURCES = [
  ['scanner', 'Host scanner (CSV)'],
  ['cspm', 'Cloud posture (JSON)'],
  ['pentest', 'Penetration test (JSON)'],
  ['container', 'Container / Kubernetes (JSON)'],
  ['identity', 'Identity (CSV)'],
  ['easm', 'External attack surface / EASM (JSON)'],
  ['threat_intel', 'Threat intelligence feed (JSON/CSV)'],
]

type ThreatResult = { updated: number; skipped: Array<{ row: number; error: string }>; findings_rescored: number; band_changes: number }

export function ImportsPage() {
  const [source, setSource] = useState('scanner')
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<Batch | null>(null)
  const [threatResult, setThreatResult] = useState<ThreatResult | null>(null)
  const [openBatch, setOpenBatch] = useState<string | null>(null)
  const batches = useQuery({ queryKey: ['imports'], queryFn: () => api<Batch[]>('/imports') })
  const detail = useQuery({
    queryKey: ['import', openBatch],
    queryFn: () => api<Batch>(`/imports/${openBatch}`),
    enabled: Boolean(openBatch),
  })
  const qc = useQueryClient()
  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('Select a file first')
      if (file.size > 10 * 1024 * 1024) throw new Error('Files must be 10 MB or smaller')
      const form = new FormData()
      form.append('file', file)
      if (source === 'threat_intel') {
        const feed = await api<ThreatResult>('/threat-intel/import/file', { method: 'POST', body: form })
        return { feed }
      }
      return { batch: await api<Batch>(`/imports/${source}`, { method: 'POST', body: form }) }
    },
    onSuccess: (data: { batch?: Batch; feed?: ThreatResult }) => {
      setResult(data.batch ?? null)
      setThreatResult(data.feed ?? null)
      void qc.invalidateQueries({ queryKey: ['imports'] })
      void qc.invalidateQueries({ queryKey: ['findings'] })
      void qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
  const retry = useMutation({
    mutationFn: (id: string) => api<Batch>(`/imports/${id}/retry`, { method: 'POST' }),
    onSuccess: (data) => {
      setResult(data)
      setOpenBatch(null)
      void qc.invalidateQueries({ queryKey: ['imports'] })
      void qc.invalidateQueries({ queryKey: ['findings'] })
    },
  })
  const failedRows = useQuery({
    queryKey: ['import-failed', openBatch],
    queryFn: () => api<Array<{ id: string; payload: Record<string, unknown>; error: string | null }>>(`/imports/${openBatch}/failed-rows`),
    enabled: Boolean(openBatch),
  })
  return (
    <>
      <PageTitle
        eyebrow="DATA PIPELINE"
        title="Import findings"
        description="Load simulated scanner exports and track normalization, de-duplication, and errors."
      />
      <section className="panel upload-panel">
        <div className="upload-icon">
          <FileUp size={22} />
        </div>
        <div className="upload-copy">
          <h2>Upload a source export</h2>
          <p>CSV or JSON, up to 10 MB. Synthetic data only. Samples live in backend/data/synthetic/.</p>
        </div>
        <div className="upload-controls">
          <label>
            Source type
            <select aria-label="Source type" value={source} onChange={(e) => setSource(e.target.value)}>
              {SOURCES.map(([value, text]) => (
                <option key={value} value={value}>
                  {text}
                </option>
              ))}
            </select>
          </label>
          <label className="file-picker">
            {file ? 'Change file' : 'Choose file'}
            <input type="file" accept=".csv,.json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
          <button className="primary-btn" disabled={!file || upload.isPending} onClick={() => upload.mutate()}>
            {upload.isPending ? 'Importing…' : 'Run import'} <span>→</span>
          </button>
        </div>
        {file && (
          <div className="selected-file">
            Selected: {file.name} ({Math.ceil(file.size / 1024)} KB)
          </div>
        )}
        {upload.error && <ErrorState message={(upload.error as Error).message} />}
      </section>
      {threatResult && (
        <section className="import-result panel">
          <CheckCircle2 size={20} />
          <div>
            <strong>Threat feed applied</strong>
            <p>
              {threatResult.updated} CVE records updated · {threatResult.findings_rescored} findings rescored ·{' '}
              {threatResult.band_changes} changed risk band · {threatResult.skipped.length} rows skipped
            </p>
            {threatResult.skipped.length > 0 && <ErrorList errors={threatResult.skipped} />}
          </div>
        </section>
      )}
      {result && (
        <section className="import-result panel">
          <CheckCircle2 size={20} />
          <div>
            <strong>Import finished · {result.status}</strong>
            <p>
              {result.total_records} rows · {result.success_count} new findings · {result.duplicate_count} duplicates ·{' '}
              {result.failed_count} errors
            </p>
            {Boolean(result.errors?.length) && <ErrorList errors={result.errors!} />}
          </div>
        </section>
      )}
      <section className="panel table-panel">
        <div className="panel-head">
          <h2>Recent batches</h2>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>File</th>
                <th>Imported</th>
                <th>Records</th>
                <th>New</th>
                <th>Duplicates</th>
                <th>Failed</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {(batches.data ?? []).map((row) => (
                <tr key={row.id}>
                  <td>{row.source_name}</td>
                  <td>{row.file_name ?? '—'}</td>
                  <td>{formatDate(row.created_at)}</td>
                  <td>{row.total_records}</td>
                  <td>{row.success_count}</td>
                  <td>{row.duplicate_count}</td>
                  <td>
                    {row.failed_count > 0 ? (
                      <button className="text-btn danger-text" onClick={() => setOpenBatch(openBatch === row.id ? null : row.id)}>
                        {row.failed_count} · {openBatch === row.id ? 'hide' : 'view'}
                      </button>
                    ) : (
                      0
                    )}
                  </td>
                  <td>
                    <span className="status-pill">{row.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {openBatch && (
          <div className="panel-inset">
            <div className="panel-head">
              <strong>Rows kept for recovery</strong>
              <button className="secondary-btn" disabled={retry.isPending || !failedRows.data?.length} onClick={() => retry.mutate(openBatch)}>
                {retry.isPending ? 'Retrying…' : `Retry ${failedRows.data?.length ?? 0} failed row(s)`}
              </button>
            </div>
            <p className="muted">
              Failed rows are stored with their error. Fix the cause (for example register the missing asset) and retry; recovered rows
              join a new linked batch.
            </p>
            {retry.error && <ErrorState message={(retry.error as Error).message} />}
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Error</th>
                    <th>Original row</th>
                  </tr>
                </thead>
                <tbody>
                  {(failedRows.data ?? []).slice(0, 50).map((row) => (
                    <tr key={row.id}>
                      <td className="wrap-cell">{row.error}</td>
                      <td className="wrap-cell">
                        <code>{JSON.stringify(row.payload)}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!failedRows.data?.length && detail.data?.errors && <ErrorList errors={detail.data.errors} />}
          </div>
        )}
      </section>
    </>
  )
}

function ErrorList({ errors }: { errors: Array<Record<string, unknown>> }) {
  return (
    <details className="error-details" open={errors.length <= 5}>
      <summary>{errors.length} rows could not be imported</summary>
      <ul>
        {errors.slice(0, 50).map((error, index) => (
          <li key={index}>
            {Object.entries(error)
              .map(([key, value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : String(value)}`)
              .join(' · ')}
          </li>
        ))}
      </ul>
      {errors.length > 50 && <small>Showing the first 50 errors.</small>}
    </details>
  )
}

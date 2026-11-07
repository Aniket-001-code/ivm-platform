let accessToken: string | null = null
export const setAccessToken = (token: string | null) => { accessToken = token }

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const response = await fetch(path.startsWith('/api') ? path : `/api/v1${path}`, { ...options, headers })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data?.detail ?? data?.error?.message ?? `Request failed (${response.status})`)
  return data as T
}


export async function downloadCsv(path: string, filename: string): Promise<void> {
  const headers = new Headers()
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  const response = await fetch(path.startsWith('/api') ? path : `/api/v1${path}`, { headers })
  if (!response.ok) throw new Error(`CSV download failed (${response.status})`)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

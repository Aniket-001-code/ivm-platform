// API client: attaches the access token, refreshes it once on expiry, and reports
// session loss to the app shell.

const REFRESH_KEY = 'ivm.refresh'
let accessToken: string | null = null
let refreshInFlight: Promise<boolean> | null = null
let onSessionExpired: (() => void) | null = null
let onTokenRefreshed: ((token: string) => void) | null = null

export const setAccessToken = (token: string | null) => {
  accessToken = token
}

export function setSessionHandlers(handlers: {
  expired: () => void
  refreshed: (token: string) => void
}) {
  onSessionExpired = handlers.expired
  onTokenRefreshed = handlers.refreshed
}

/** Clears any refresh token left in storage by older versions (it now lives in an HttpOnly cookie). */
export function clearLegacyRefreshToken() {
  try {
    sessionStorage.removeItem(REFRESH_KEY)
  } catch {
    /* storage unavailable */
  }
}

const url = (path: string) => (path.startsWith('/api') ? path : `/api/v1${path}`)

// Refresh tokens rotate on every use, so concurrent 401s must share one refresh call.
function refreshAccessToken(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      // The refresh token travels only as an HttpOnly, SameSite=Strict cookie set by the API.
      const response = await fetch(url('/auth/refresh'), { method: 'POST', credentials: 'same-origin' })
      if (!response.ok) return false
      const data = (await response.json()) as { access_token: string }
      accessToken = data.access_token
      onTokenRefreshed?.(data.access_token)
      return true
    })().finally(() => {
      refreshInFlight = null
    })
  }
  return refreshInFlight
}

async function send(path: string, options: RequestInit = {}, retry = true): Promise<Response> {
  const headers = new Headers(options.headers)
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const response = await fetch(url(path), { ...options, headers })
  if (response.status === 401 && retry && accessToken && !path.startsWith('/auth/')) {
    if (await refreshAccessToken()) return send(path, options, false)
    onSessionExpired?.()
  }
  return response
}

async function parse<T>(response: Response): Promise<T> {
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    const details = data?.error?.details
    if (Array.isArray(details) && details.length) {
      // Validation errors: name the field and the problem instead of a generic message.
      const first = details[0] as { loc?: unknown[]; msg?: string }
      const field = (first.loc ?? []).filter((part) => part !== 'body').join('.')
      throw new Error(`${field ? `${field}: ` : ''}${first.msg ?? 'Invalid input'}`)
    }
    throw new Error(data?.detail ?? data?.error?.message ?? `Request failed (${response.status})`)
  }
  return data as T
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  return parse<T>(await send(path, options))
}

export type Page<T> = { rows: T[]; total: number }

/** GET a list endpoint and read the unpaged total from X-Total-Count. */
export async function apiPage<T>(path: string): Promise<Page<T>> {
  const response = await send(path)
  const rows = await parse<T[]>(response)
  const total = Number(response.headers.get('X-Total-Count') ?? rows.length)
  return { rows, total }
}

/** Build a query string, skipping empty values. */
export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== '' && value !== null && value !== undefined) search.set(key, String(value))
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}

/** Download any authenticated file (CSV exports, HTML reports and review packs). */
export async function downloadCsv(path: string, filename: string): Promise<void> {
  const response = await send(path)
  if (!response.ok) throw new Error(`Download failed (${response.status})`)
  const blob = await response.blob()
  const href = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = href
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(href)
}

export const downloadFile = downloadCsv

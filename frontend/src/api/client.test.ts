import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, apiPage, qs, setAccessToken, setSessionHandlers, storeRefreshToken } from './client'

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })

describe('api client', () => {
  const expired = vi.fn()
  const refreshed = vi.fn()

  beforeEach(() => {
    setAccessToken('old-access')
    storeRefreshToken('refresh-1')
    setSessionHandlers({ expired, refreshed })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    expired.mockReset()
    refreshed.mockReset()
    sessionStorage.clear()
  })

  it('refreshes once and retries when the access token has expired', async () => {
    let refreshCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.endsWith('/auth/refresh')) {
        refreshCalls += 1
        return json({ access_token: 'new-access', refresh_token: 'refresh-2' })
      }
      const auth = new Headers(init?.headers).get('Authorization')
      return auth === 'Bearer new-access' ? json({ ok: true }) : json({ detail: 'expired' }, 401)
    })
    // Two concurrent requests must share one refresh, because refresh tokens rotate.
    const [a, b] = await Promise.all([api('/findings'), api('/assets')])
    expect(a).toEqual({ ok: true })
    expect(b).toEqual({ ok: true })
    expect(refreshCalls).toBe(1)
    expect(refreshed).toHaveBeenCalledWith('new-access')
    expect(sessionStorage.getItem('ivm.refresh')).toBe('refresh-2')
  })

  it('reports session loss when the refresh token is rejected', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ detail: 'nope' }, 401))
    await expect(api('/findings')).rejects.toThrow('nope')
    expect(expired).toHaveBeenCalledTimes(1)
  })

  it('reads the unpaged total from X-Total-Count', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json([{ id: 1 }], 200, { 'X-Total-Count': '42' }))
    await expect(apiPage('/findings?limit=1')).resolves.toEqual({ rows: [{ id: 1 }], total: 42 })
  })

  it('builds query strings without empty values', () => {
    expect(qs({ band: 'critical', search: '', status: undefined, limit: 50, overdue: false })).toBe(
      '?band=critical&limit=50&overdue=false',
    )
    expect(qs({ search: '' })).toBe('')
  })
})

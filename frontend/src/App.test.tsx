import { cleanup, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

function renderApp(path = '/') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  cleanup()
  sessionStorage.clear()
  vi.restoreAllMocks()
})

describe('login screen', () => {
  it('shows the seeded local demo sign-in without requesting data', () => {
    renderApp()
    expect(screen.getByRole('heading', { name: 'Sign in to IVM' })).toBeInTheDocument()
    expect(screen.getByLabelText('Email address')).toHaveValue('user2@demo.bank')
    expect(screen.getByLabelText('Password')).toHaveValue('DemoPass!234')
  })

  it('asks sessions saved without permissions to sign in again', () => {
    sessionStorage.setItem('ivm.user', JSON.stringify({ id: '1', email: 'a@b', full_name: 'A', role: 'auditor' }))
    sessionStorage.setItem('ivm.token', 'token')
    renderApp()
    expect(screen.getByRole('heading', { name: 'Sign in to IVM' })).toBeInTheDocument()
  })
})

describe('signed-in shell', () => {
  it('builds navigation from permissions and redirects guarded routes', async () => {
    sessionStorage.setItem(
      'ivm.user',
      JSON.stringify({
        id: '1',
        email: 'user5@demo.bank',
        full_name: 'Demo Auditor',
        role: 'auditor',
        permissions: ['authenticated', 'exception:read', 'audit:read', 'risk:read', 'report:read'],
      }),
    )
    sessionStorage.setItem('ivm.token', 'token')
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () => new Response(JSON.stringify({ detail: 'not in test' }), { status: 500 }),
    )
    renderApp('/imports')
    const nav = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(within(nav).getByRole('link', { name: /audit trail/i })).toBeInTheDocument()
    expect(within(nav).queryByRole('link', { name: /data imports/i })).toBeNull()
    expect(within(nav).queryByRole('link', { name: 'Findings' })).toBeNull()
    // /imports is not permitted for auditors, so the guard falls back to the overview.
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Import findings' })).toBeNull()
  })
})

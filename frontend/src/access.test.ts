import { describe, expect, it } from 'vitest'
import { NAV, can, dashboardView, usesOwnTaskQueue } from './access'
import type { User } from './types'

const user = (role: string, permissions: string[]): User => ({
  id: '1',
  email: `${role}@demo.bank`,
  full_name: role,
  role,
  permissions,
})

const visible = (u: User) => NAV.filter((item) => can(u, ...item.anyOf)).map((item) => item.label)

describe('permission-driven navigation', () => {
  it('hides finding and path pages from the CISO, who cannot read them', () => {
    const ciso = user('executive_ciso', ['authenticated', 'risk:read', 'ai:executive_summary', 'report:read'])
    expect(visible(ciso)).toEqual(['Overview', 'Reports & insights'])
  })

  it('shows the audit trail to auditors but not remediation or imports', () => {
    const auditor = user('auditor', ['authenticated', 'exception:read', 'audit:read', 'risk:read', 'report:read'])
    expect(visible(auditor)).toEqual(['Overview', 'Risk exceptions', 'Reports & insights', 'Audit trail'])
  })

  it('does not offer the audit trail to vulnerability managers without audit:read', () => {
    const manager = user('vulnerability_manager', ['risk:read', 'finding:read', 'task:read', 'scheduler:run'])
    expect(visible(manager)).toContain('Administration')
    expect(visible(manager)).not.toContain('Audit trail')
  })
})

describe('role routing helpers', () => {
  it('maps each role to its dashboard view', () => {
    expect(dashboardView('executive_ciso')).toBe('executive')
    expect(dashboardView('platform_admin')).toBe('executive')
    expect(dashboardView('security_analyst')).toBe('analyst')
    expect(dashboardView('business_unit_manager')).toBe('manager')
    expect(dashboardView('auditor')).toBe('auditor')
  })

  it('sends owners and system administrators to their own task queue', () => {
    expect(usesOwnTaskQueue('it_asset_owner')).toBe(true)
    expect(usesOwnTaskQueue('system_administrator')).toBe(true)
    expect(usesOwnTaskQueue('vulnerability_manager')).toBe(false)
  })
})

import {
  Activity,
  ChartColumn,
  Bot,
  Boxes,
  FileUp,
  GitBranch,
  LayoutDashboard,
  ListChecks,
  Shield,
  ShieldAlert,
  Users,
  type LucideIcon,
} from 'lucide-react'
import type { User } from './types'

/** Permission names mirror backend/app/core/rbac.py; the server sends each user's list at login. */
export const P = {
  assetRead: 'asset:read',
  findingRead: 'finding:read',
  findingTriage: 'finding:triage',
  import: 'import:run',
  riskManage: 'risk:manage',
  riskWhatIf: 'risk:what_if',
  attackPathRead: 'attack_path:read',
  taskRead: 'task:read',
  taskManage: 'task:manage',
  taskAssigned: 'task:assigned',
  exceptionRead: 'exception:read',
  exceptionRequest: 'exception:request',
  exceptionApproveTemp: 'exception:approve_temporary',
  exceptionApproveAll: 'exception:approve_all',
  auditRead: 'audit:read',
  aiUse: 'ai:use',
  aiExecutive: 'ai:executive_summary',
  configRead: 'config:read',
  configManage: 'config:manage',
  schedulerRun: 'scheduler:run',
  userRead: 'user:read',
  userManage: 'user:manage',
  notificationRead: 'notification:read',
  reportRead: 'report:read',
  assetManage: 'asset:manage',
  ticketCreate: 'ticket:create',
} as const

export const can = (user: User, ...permissions: string[]) =>
  permissions.some((permission) => user.permissions.includes(permission))

export type NavItem = { to: string; label: string; icon: LucideIcon; anyOf: string[] }

/** Sidebar entries; a route is shown and reachable when the user holds any listed permission. */
export const NAV: NavItem[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, anyOf: ['risk:read'] },
  { to: '/findings', label: 'Findings', icon: ShieldAlert, anyOf: [P.findingRead] },
  { to: '/assets', label: 'Asset inventory', icon: Boxes, anyOf: [P.assetRead] },
  { to: '/attack-paths', label: 'Attack paths', icon: GitBranch, anyOf: [P.attackPathRead] },
  { to: '/tasks', label: 'Remediation', icon: ListChecks, anyOf: [P.taskRead] },
  { to: '/exceptions', label: 'Risk exceptions', icon: Shield, anyOf: [P.exceptionRead] },
  { to: '/imports', label: 'Data imports', icon: FileUp, anyOf: [P.import] },
  { to: '/assistant', label: 'AI assistant', icon: Bot, anyOf: [P.aiUse] },
  { to: '/reports', label: 'Reports & insights', icon: ChartColumn, anyOf: ['report:read'] },
  { to: '/auditor', label: 'Audit trail', icon: Activity, anyOf: [P.auditRead] },
  { to: '/admin', label: 'Administration', icon: Users, anyOf: [P.configManage, P.schedulerRun] },
]

/** Which role-specific dashboard payload each role sees. */
export function dashboardView(role: string): 'executive' | 'analyst' | 'manager' | 'auditor' {
  if (role === 'auditor') return 'auditor'
  if (['vulnerability_manager', 'business_unit_manager', 'it_asset_owner', 'system_administrator'].includes(role))
    return 'manager'
  if (['security_analyst', 'security_architect'].includes(role)) return 'analyst'
  return 'executive'
}

/** Owners and system administrators work from their own queue. */
export const usesOwnTaskQueue = (role: string) => ['it_asset_owner', 'system_administrator'].includes(role)

export const label = (value: string) => value.replaceAll('_', ' ')

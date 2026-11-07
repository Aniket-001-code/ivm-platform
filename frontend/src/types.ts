export type User = {
  id: string
  email: string
  full_name: string
  role: string
  permissions: string[]
  mfa_enabled?: boolean
}

export type Finding = {
  id: string
  asset_id: string
  title: string
  severity: string
  risk_score: number
  risk_band: string
  status: string
  sources: string[]
}

export type Factor = { factor: string; points: number; max_points: number; reason: string }

export type TrendPoint = { week: string; average_score: number; sample_count: number }

export type Kpis = {
  open_findings: number
  critical_count: number
  high_count: number
  overdue_count: number
  sla_compliance_percent: number
  task_count: number
  assets: number
  raw_records: number
  prioritized_actions: number
  effort_saved_minutes: number
  duplicates_merged?: number
  risk_reduction_percent: number
  mttr_by_band: Array<{ risk_band: string; mttr_days: number; closed_tasks: number }>
}

export type Dashboard = {
  view: 'executive' | 'analyst' | 'manager' | 'auditor'
  kpis: Kpis
  risk_bands: Record<string, number>
  top_findings: Finding[]
  trend?: TrendPoint[]
  assumption?: string
  top_assets?: Array<{ asset_id: string; asset: string; open_findings: number; average_risk: number; max_risk: number }>
  heatmap?: Array<{ business_service: string; business_unit: string; risk_bands: Record<string, number> }>
  risk_by_business_unit?: Array<{ business_unit: string; risk_band: string; count: number }>
  exceptions_expiring?: Array<{ id: string; finding_id: string; expiry: string; status: string }>
  findings_by_source?: Array<{ source: string; findings: number }>
  recent_imports?: Array<{ id: string; source: string; file: string; total: number; failed: number; duplicates: number }>
  overdue_by_owner?: Array<{ owner_id: string; owner: string; overdue_tasks: number }>
  aging_buckets?: Record<string, number>
  escalations?: Array<{ id: string; task_id: string; level: number; reason: string; acknowledged: boolean }>
  tasks_by_status?: Record<string, number>
  recent_audit?: Array<{ id: string; action: string; entity_type: string; timestamp: string }>
  exceptions?: Array<{ id: string; finding_id: string; status: string; expiry: string }>
  internet_facing_high_risk?: Array<{ asset_id: string; asset: string; crown_jewel: boolean; high_risk_findings: number; max_risk: number }>
  crown_jewel_paths?: Array<{ id: string; name: string; path_risk_score: number; hops: number }>
  overdue_by_owner_and_category?: Array<{ owner: string; sla_category: string; overdue_tasks: number }>
  risk_reduction_percent?: number
}

export type Task = {
  id: string
  finding_id: string
  asset_id: string
  status: string
  priority: string
  sla_due_date: string | null
  evidence_notes: string | null
  ticket_ref: string | null
}

export type Asset = {
  id: string
  name: string
  hostname: string
  asset_type: string
  environment: string
  criticality_tier: number
  internet_exposed: boolean
  is_crown_jewel: boolean
  is_customer_facing?: boolean
  has_sensitive_data?: boolean
  status?: string
}

export type RiskException = {
  id: string
  finding_id: string
  requested_by: string
  justification: string
  compensating_controls: string
  exception_type: string
  requested_expiry_date: string
  status: string
  review_comment: string | null
}

export type AiSource = { table: string; description: string; rows: number }

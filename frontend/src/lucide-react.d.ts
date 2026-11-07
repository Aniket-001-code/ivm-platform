declare module 'lucide-react' {
  import type { ComponentType, SVGProps } from 'react'

  export type LucideIcon = ComponentType<
    SVGProps<SVGSVGElement> & { size?: number; absoluteStrokeWidth?: boolean }
  >
  type Icon = LucideIcon

  export const Activity: Icon
  export const TrendingUp: Icon
  export const ShieldCheck: Icon
  export const FileText: Icon
  export const X: Icon
  export const Ticket: Icon
  export const Pencil: Icon
  export const KeyRound: Icon
  export const Bell: Icon
  export const ChartColumn: Icon
  export const AlertTriangle: Icon
  export const ArrowDown: Icon
  export const ArrowDownRight: Icon
  export const ArrowUp: Icon
  export const Bot: Icon
  export const Boxes: Icon
  export const CheckCircle2: Icon
  export const ChevronDown: Icon
  export const ChevronLeft: Icon
  export const ChevronRight: Icon
  export const CircleHelp: Icon
  export const Download: Icon
  export const FileUp: Icon
  export const GitBranch: Icon
  export const LayoutDashboard: Icon
  export const ListChecks: Icon
  export const LogOut: Icon
  export const Plus: Icon
  export const RefreshCw: Icon
  export const Search: Icon
  export const Shield: Icon
  export const ShieldAlert: Icon
  export const Sparkles: Icon
  export const Trash2: Icon
  export const Users: Icon
}

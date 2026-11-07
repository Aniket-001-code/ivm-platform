declare module 'lucide-react' {
  import type { ComponentType, SVGProps } from 'react'

  type Icon = ComponentType<SVGProps<SVGSVGElement> & { size?: number; absoluteStrokeWidth?: boolean }>

  export const Activity: Icon
  export const AlertTriangle: Icon
  export const ArrowDownRight: Icon
  export const Bot: Icon
  export const Boxes: Icon
  export const CheckCircle2: Icon
  export const ChevronDown: Icon
  export const CircleHelp: Icon
  export const FileUp: Icon
  export const GitBranch: Icon
  export const LayoutDashboard: Icon
  export const ListChecks: Icon
  export const LogOut: Icon
  export const Search: Icon
  export const Shield: Icon
  export const ShieldAlert: Icon
  export const Users: Icon
}

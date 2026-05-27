import { cn } from '../../lib/utils'

interface Props {
  variant?: 'green' | 'red' | 'gray' | 'blue' | 'yellow' | 'purple'
  children: React.ReactNode
  className?: string
}

const styles = {
  green: 'bg-green-50 text-green-700 border-green-200',
  red: 'bg-red-50 text-red-700 border-red-200',
  gray: 'bg-slate-100 text-slate-700 border-slate-200',
  blue: 'bg-blue-50 text-blue-700 border-blue-200',
  yellow: 'bg-amber-50 text-amber-700 border-amber-200',
  purple: 'bg-purple-50 text-purple-700 border-purple-200',
}

export function Badge({ variant = 'gray', children, className }: Props) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border', styles[variant], className)}>
      {children}
    </span>
  )
}

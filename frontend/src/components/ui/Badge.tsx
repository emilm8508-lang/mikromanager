import { cn } from '../../lib/utils'

interface Props {
  variant?: 'green' | 'red' | 'gray' | 'blue' | 'yellow'
  children: React.ReactNode
  className?: string
}

const styles = {
  green: 'bg-green-900/40 text-green-400 border-green-800',
  red: 'bg-red-900/40 text-red-400 border-red-800',
  gray: 'bg-gray-800 text-gray-400 border-gray-700',
  blue: 'bg-blue-900/40 text-blue-400 border-blue-800',
  yellow: 'bg-yellow-900/40 text-yellow-400 border-yellow-800',
}

export function Badge({ variant = 'gray', children, className }: Props) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border', styles[variant], className)}>
      {children}
    </span>
  )
}

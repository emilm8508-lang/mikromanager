import { cn } from '../../lib/utils'
import { InputHTMLAttributes } from 'react'

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
}

export function Input({ label, error, className, ...props }: Props) {
  return (
    <div className="flex flex-col gap-1">
      {label && <label className="text-xs font-medium text-gray-400">{label}</label>}
      <input
        className={cn(
          'bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100',
          'placeholder-gray-500 focus:outline-none focus:border-indigo-500 transition-colors',
          error && 'border-red-500',
          className
        )}
        {...props}
      />
      {error && <span className="text-xs text-red-400">{error}</span>}
    </div>
  )
}

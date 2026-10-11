import { cn } from '../../lib/utils'

/**
 * Color palette for tenant badges. We pick a stable color per tenant name
 * via a small hash so the same customer always shows the same color across
 * tables, no matter which order they were configured.
 *
 * bar/dot are written out in full on purpose: Tailwind only generates classes it finds as literal strings,
 * so they cannot be derived from bg/text with .replace().
 *
 * Palette deliberately avoids semantic colors used elsewhere
 * (green=online, red=offline, amber=warning, blue/indigo=action).
 */
const PALETTE = [
  { bg: 'bg-violet-100', text: 'text-violet-800', border: 'border-violet-300', bar: 'bg-violet-500', dot: 'bg-violet-700' },
  { bg: 'bg-fuchsia-100', text: 'text-fuchsia-800', border: 'border-fuchsia-300', bar: 'bg-fuchsia-500', dot: 'bg-fuchsia-700' },
  { bg: 'bg-pink-100', text: 'text-pink-800', border: 'border-pink-300', bar: 'bg-pink-500', dot: 'bg-pink-700' },
  { bg: 'bg-rose-100', text: 'text-rose-800', border: 'border-rose-300', bar: 'bg-rose-500', dot: 'bg-rose-700' },
  { bg: 'bg-orange-100', text: 'text-orange-800', border: 'border-orange-300', bar: 'bg-orange-500', dot: 'bg-orange-700' },
  { bg: 'bg-teal-100', text: 'text-teal-800', border: 'border-teal-300', bar: 'bg-teal-500', dot: 'bg-teal-700' },
  { bg: 'bg-cyan-100', text: 'text-cyan-800', border: 'border-cyan-300', bar: 'bg-cyan-500', dot: 'bg-cyan-700' },
  { bg: 'bg-sky-100', text: 'text-sky-800', border: 'border-sky-300', bar: 'bg-sky-500', dot: 'bg-sky-700' },
  { bg: 'bg-emerald-100', text: 'text-emerald-800', border: 'border-emerald-300', bar: 'bg-emerald-500', dot: 'bg-emerald-700' },
  { bg: 'bg-lime-100', text: 'text-lime-800', border: 'border-lime-300', bar: 'bg-lime-500', dot: 'bg-lime-700' },
]

function hashString(s: string): number {
  // Lightweight FNV-1a-ish hash. Deterministic and short.
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = (h * 16777619) >>> 0
  }
  return h
}

export function tenantColor(tenantId: string): typeof PALETTE[number] {
  return PALETTE[hashString(tenantId) % PALETTE.length]
}

interface Props {
  tenant: string
  className?: string
  withDot?: boolean
}

export function TenantBadge({ tenant, className, withDot = false }: Props) {
  const c = tenantColor(tenant)
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border',
      c.bg, c.text, c.border, className,
    )}>
      {withDot && <span className={cn('inline-block w-1.5 h-1.5 rounded-full', c.dot)} />}
      {tenant}
    </span>
  )
}

import { Cpu, MemoryStick, Zap, Fan, HardDrive, Gauge } from 'lucide-react'
import { DellHealth } from '../lib/api'

// Shared between the agent's own DellServers.tsx page and Central's
// cross-tenant physical-servers view, so both render server health
// identically — solid color-filled stat tiles (green/amber/red), one per
// component with an icon. See DellServers.tsx's git history for the
// design rationale (the user pointed at a PRTG gauge dashboard and a
// Grafana stat-panel dashboard as references, asking for something more
// graphical/spacious than a row of small text badges).

export function healthBadgeVariant(h: DellHealth): 'red' | 'yellow' | 'green' | 'gray' {
  if (h === 'Critical') return 'red'
  if (h === 'Warning') return 'yellow'
  if (h === 'OK') return 'green'
  return 'gray'
}

export const VENDOR_LABELS: Record<string, string> = {
  dell: 'Dell', hp: 'HP/HPE', fujitsu: 'Fujitsu', lenovo: 'Lenovo',
}

export const COMPONENT_ICONS: Record<string, React.ComponentType<any>> = {
  system: Gauge, cpu: Cpu, memory: MemoryStick, power: Zap, fans_temperature: Fan, storage: HardDrive,
}

const TILE_COLORS: Record<string, string> = {
  OK: 'bg-green-500 text-white',
  Warning: 'bg-amber-500 text-white',
  Critical: 'bg-red-500 text-white',
}

export function ComponentTile({ label, value, Icon }: {
  label: string; value: DellHealth | string | null | undefined; Icon: React.ComponentType<any>
}) {
  const known = value === 'OK' || value === 'Warning' || value === 'Critical'
  const colorClass = known ? TILE_COLORS[value as string] : 'bg-slate-100 text-slate-400'
  return (
    <div className={`flex flex-col items-center justify-center gap-1 rounded-lg py-3 px-2 min-w-[84px] flex-1 ${colorClass}`}>
      <Icon size={20} />
      <span className="text-[10px] font-medium text-center leading-tight opacity-90">{label}</span>
      <span className="text-xs font-bold">{value || '—'}</span>
    </div>
  )
}

export const DELL_COMPONENT_KEYS = ['system', 'cpu', 'memory', 'power', 'fans_temperature', 'storage'] as const

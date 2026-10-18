import { useTranslation } from 'react-i18next'
import type { AssetLifecycle, AssetScanLevel, AssetType, AssetVulnCounts } from '../lib/api'
import { cn } from '../lib/utils'
import { Monitor, Terminal, Router, Printer, Layers, Server, HelpCircle, Camera, Smartphone, Tv, AlertTriangle, CheckCircle2, ShieldCheck, Radio, Eye } from 'lucide-react'

// Small shared pieces of the asset pages: type icon / colour, and the pills used in the list and on the card.

export const TYPE_ICON: Record<AssetType, typeof Monitor> = {
  windows: Monitor, linux: Terminal, network: Router, printer: Printer, virtual: Layers, server: Server, camera: Camera, mobile: Smartphone, monitor: Tv, other: HelpCircle,
}

// colour follows the type everywhere (reference categorical order; grey for "other")
export const TYPE_COLOR: Record<AssetType, string> = {
  windows: '#2a78d6', linux: '#eb6834', network: '#1baf7a', printer: '#eda100', virtual: '#4a3aa7', server: '#e87ba4', camera: '#008300', mobile: '#e34948', monitor: '#12a4b4', other: '#898781',
}

export const TYPE_ORDER: AssetType[] = ['windows', 'linux', 'virtual', 'server', 'network', 'printer', 'camera', 'mobile', 'monitor', 'other']

export function TypeIcon({ type, size = 16, className }: { type: AssetType; size?: number; className?: string }) {
  const I = TYPE_ICON[type] ?? HelpCircle
  return <I size={size} className={className} style={{ color: TYPE_COLOR[type] }} />
}

export function Pill({ children, tone = 'gray', icon, className }: { children: React.ReactNode; tone?: 'gray' | 'red' | 'orange' | 'amber' | 'blue' | 'green'; icon?: React.ReactNode; className?: string }) {
  const tones = {
    gray: 'bg-slate-100 text-slate-700 border-slate-200',
    red: 'bg-red-50 text-red-700 border-red-200',
    orange: 'bg-orange-50 text-orange-700 border-orange-200',
    amber: 'bg-amber-50 text-amber-800 border-amber-200',
    blue: 'bg-blue-50 text-blue-700 border-blue-200',
    green: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  }
  return <span className={cn('inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium border whitespace-nowrap', tones[tone], className)}>{icon}{children}</span>
}

export function TypePill({ type, role, cls }: { type: AssetType; role?: string | null; cls?: string | null }) {
  const { t } = useTranslation()
  const base = type === 'windows' || type === 'linux' ? t(`assets.role.${role === 'workstation' ? 'workstation' : 'server'}${type === 'windows' ? 'Win' : 'Linux'}`, { defaultValue: t(`assets.type.${type}`) }) : t(`assets.type.${type}`)
  // what it does on the network (switch, router, access point ...) replaces the bare "network device"; for the others it is added
  const c = cls ? t(`assets.class.${cls}`, { defaultValue: '' }) as string : ''
  const label = c ? (type === 'network' ? c : `${base} · ${c}`) : base
  return <Pill>{label as string}</Pill>
}

const SEV_TONE = { critical: 'red', high: 'orange', medium: 'amber', low: 'blue' } as const

/** the worst severity present with its count, like "4 Critical" */
export function VulnPill({ v }: { v: AssetVulnCounts }) {
  const { t } = useTranslation()
  const sev = (['critical', 'high', 'medium', 'low'] as const).find(s => v[s] > 0)
  if (!sev) return <span className="text-slate-300">—</span>
  const dot = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-400', low: 'bg-blue-500' }[sev]
  return <Pill tone={SEV_TONE[sev]} icon={<i className={cn('w-2 h-2 rounded-full inline-block', dot)} />}>{v[sev]} {t(`assets.sev.${sev}`)}</Pill>
}

export function LifecyclePill({ status, days }: { status: AssetLifecycle; days?: number | null }) {
  const { t } = useTranslation()
  if (status === 'unknown') return <span className="text-slate-300">—</span>
  if (status === 'eol') return <Pill tone="red" icon={<AlertTriangle size={12} />}>{t('assets.lifecycle.eol')}</Pill>
  if (status === 'ending') return <Pill tone="amber" icon={<AlertTriangle size={12} />}>{t('assets.lifecycle.ending')}{days != null ? ` · ${days} d` : ''}</Pill>
  return <Pill tone="blue" icon={<CheckCircle2 size={12} />}>{t('assets.lifecycle.supported')}</Pill>
}

export function ScanLevelPill({ level }: { level: AssetScanLevel }) {
  const { t } = useTranslation()
  const map = { credentialed: { tone: 'green', icon: <ShieldCheck size={12} /> }, snmp: { tone: 'blue', icon: <Radio size={12} /> }, passive: { tone: 'gray', icon: <Eye size={12} /> } } as const
  return <Pill tone={map[level].tone} icon={map[level].icon}>{t(`assets.scanLevel.${level}`)}</Pill>
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return '—'
  const min = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000))
  if (min < 1) return '<1 min'
  if (min < 90) return `${min} min`
  const h = Math.round(min / 60)
  return h < 48 ? `${h} h` : `${Math.round(h / 24)} d`
}

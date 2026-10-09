import { useTranslation } from 'react-i18next'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Badge } from './ui/Badge'
import {
  type HypervOverviewHost, type HypervInsight, type HypervSeverity, type HypervTile, type HypervTrendPoint,
  type CentralHypervHostStatus, type CentralHypervVm,
} from '../lib/api'
import { cn, formatBytes } from '../lib/utils'
import { Camera, Repeat, HeartPulse, MemoryStick, Moon, Cpu, Server } from 'lucide-react'

// Presentational pieces of the Hyper-V board — shared by the agent's "Hyper-V" tab and Central's page.
// Both feed them the same view model (HvHost / HvVm); the mappers below build it from each source.

export type HvVm = {
  key: string; id?: number; name: string; state: string | null; tile: HypervTile
  cpu: number | null; vcpu: number | null; memAssigned: number | null; memDemand: number | null
  uptime: number | null; heartbeat: string | null; snapshots: number | null; replication: string | null; flags: string[]
}

export type HvProblem = { kind: string; severity: HypervSeverity; vm: string | null; params?: Record<string, string | number | null> }

export type HvHost = {
  key: string; tenant?: string; hostId: number; windowsHostId?: number
  name: string; ip: string | null; down: boolean; error?: string | null; os: string | null; cluster: string | null
  cpu: number | null; mem: number | null
  storageFree: number | null; storageTotal: number | null
  lp: number | null; vcpu: number; memAssigned: number; memCapacity: number | null
  vms: HvVm[]; trend: HypervTrendPoint[]; problems: HvProblem[]; lastCheck: string | null
}

export function fromLocal(h: HypervOverviewHost, insights: HypervInsight[]): HvHost {
  return {
    key: String(h.id), hostId: h.id, windowsHostId: h.windows_host_id, name: h.hostname || h.ip, ip: h.ip, down: h.down, error: h.last_error,
    os: h.os_name, cluster: h.cluster_name, cpu: h.cpu_used_pct, mem: h.mem_used_pct,
    storageFree: h.storage_free_bytes, storageTotal: h.storage_total_bytes,
    lp: h.logical_processor_count, vcpu: h.vcpu_assigned, memAssigned: h.memory_assigned_bytes, memCapacity: h.memory_capacity_bytes,
    vms: h.vms.map(v => ({
      key: String(v.id), id: v.id, name: v.name, state: v.state, tile: v.tile, cpu: v.cpu_usage_pct, vcpu: v.vcpu_count,
      memAssigned: v.memory_assigned_bytes, memDemand: v.memory_demand_bytes, uptime: v.uptime_sec, heartbeat: v.heartbeat,
      snapshots: v.snapshot_count, replication: v.replication_state && v.replication_state !== 'Disabled' ? v.replication_health : null, flags: v.flags,
    })),
    trend: h.trend, lastCheck: h.last_ok_at ?? h.last_check_at,
    problems: insights.filter(i => i.hyperv_host_id === h.id).map(i => ({ kind: i.kind, severity: i.severity, vm: i.vm, params: i.params })),
  }
}

export function fromCentral(h: CentralHypervHostStatus, tenant: string): HvHost {
  // An agent older than the dashboard sends only counts and the names of the VMs that are not running.
  const vms: CentralHypervVm[] = h.vms ?? (h.vms_not_running ?? []).map(n => ({
    name: n, state: 'Off', tile: 'off' as HypervTile, cpu: null, vcpu: null, mem_assigned: null, mem_demand: null,
    uptime_sec: null, heartbeat: null, snapshots: null, replication: null, flags: [],
  }))
  return {
    key: `${tenant}:${h.id}`, tenant, hostId: h.id, name: h.hostname || h.ip, ip: h.ip, down: h.status === 'error', os: h.os_name ?? null,
    cluster: h.cluster_name ?? null, cpu: h.cpu_used_pct ?? null, mem: h.mem_used_pct ?? null,
    storageFree: h.storage_free_bytes ?? null, storageTotal: h.storage_total_bytes ?? null,
    lp: h.logical_processor_count, vcpu: h.vcpu_assigned ?? 0, memAssigned: h.memory_assigned_bytes ?? 0, memCapacity: h.memory_capacity_bytes,
    vms: vms.map(v => ({
      key: v.name, name: v.name, state: v.state, tile: v.tile, cpu: v.cpu, vcpu: v.vcpu, memAssigned: v.mem_assigned, memDemand: v.mem_demand,
      uptime: v.uptime_sec, heartbeat: v.heartbeat, snapshots: v.snapshots, replication: v.replication, flags: v.flags,
    })),
    trend: [], lastCheck: h.last_check_at ? `${h.last_check_at}Z` : null,
    problems: (h.problems ?? []).map(p => ({ kind: p.kind, severity: p.severity, vm: p.vm })),
  }
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return '—'
  const min = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000))
  if (min < 1) return '<1 min'
  if (min < 90) return `${min} min`
  const h = Math.round(min / 60)
  return h < 48 ? `${h} h` : `${Math.round(h / 24)} d`
}

export function minutesSince(iso: string | null | undefined): number | null {
  return iso ? Math.max(0, (Date.now() - new Date(iso).getTime()) / 60000) : null
}

const SEV_ORDER: Record<HypervSeverity, number> = { high: 0, medium: 1, low: 2 }
export const sevColor: Record<HypervSeverity, string> = { high: 'bg-red-500', medium: 'bg-amber-400', low: 'bg-slate-300' }

// ── Colours ──────────────────────────────────────────────────────────────────

export type HeatMode = 'state' | 'cpu' | 'mem'

const TILE_CLASS: Record<HypervTile, string> = {
  ok: 'bg-emerald-500 text-white',
  warn: 'bg-amber-400 text-slate-900',
  crit: 'bg-red-500 text-white ring-2 ring-red-200',
  off: 'bg-slate-200 text-slate-500',
}

/** green (idle) -> amber -> red (saturated) */
function heat(pct: number): string {
  const p = Math.min(100, Math.max(0, pct))
  return `hsl(${Math.round(135 - p * 1.35)} 62% 48%)`
}

function loadColor(pct: number | null): string {
  return pct == null ? '#cbd5e1' : pct >= 90 ? '#ef4444' : pct >= 75 ? '#f59e0b' : '#10b981'
}

const FLAG_ICON: Record<string, typeof Camera> = {
  vm_snapshot_old: Camera, vm_replication: Repeat, vm_no_heartbeat: HeartPulse, vm_memory_pressure: MemoryStick, vm_idle: Moon,
}

// ── Gauge, sparkline, bars ───────────────────────────────────────────────────

export function Ring({ pct, label, sub, size = 64 }: { pct: number | null; label: string; sub?: string; size?: number }) {
  const r = size / 2 - 6
  const c = 2 * Math.PI * r
  const frac = pct == null ? 0 : Math.min(100, Math.max(0, pct)) / 100
  return (
    <div className="flex flex-col items-center" style={{ width: size + 8 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#e2e8f0" strokeWidth="6" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={loadColor(pct)} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={`${c * frac} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} style={{ transition: 'stroke-dasharray .6s' }} />
        <text x={size / 2} y={size / 2 + 4} textAnchor="middle" className="fill-slate-800" style={{ fontSize: size / 4.4, fontWeight: 600 }}>
          {pct == null ? '—' : `${Math.round(pct)}%`}
        </text>
      </svg>
      <div className="text-[11px] font-medium text-slate-600 -mt-0.5">{label}</div>
      {sub && <div className="text-[10px] text-slate-400 leading-none">{sub}</div>}
    </div>
  )
}

export function Spark({ points, height = 44, className }: { points: HypervTrendPoint[]; height?: number; className?: string }) {
  const W = 200
  const series = (key: 'cpu' | 'mem') => points.map((p, i) => ({ x: points.length > 1 ? (i / (points.length - 1)) * W : 0, y: p[key] }))
  const path = (key: 'cpu' | 'mem') => {
    let d = ''
    let pen = false
    for (const p of series(key)) {
      if (p.y == null) { pen = false; continue }
      d += `${pen ? 'L' : 'M'}${p.x.toFixed(1)} ${(height - 2 - (Math.min(100, p.y) / 100) * (height - 4)).toFixed(1)} `
      pen = true
    }
    return d
  }
  if (points.length < 2) return <div className={cn('text-[10px] text-slate-300 flex items-center justify-center', className)} style={{ height }}>—</div>
  const cpuPath = path('cpu')
  return (
    <svg viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" className={cn('w-full', className)} style={{ height }}>
      {[25, 50, 75].map(g => <line key={g} x1="0" x2={W} y1={height - 2 - (g / 100) * (height - 4)} y2={height - 2 - (g / 100) * (height - 4)} stroke="#f1f5f9" strokeWidth="1" />)}
      {cpuPath && <path d={`${cpuPath} L${W} ${height} L0 ${height} Z`} fill="#6366f1" opacity="0.08" />}
      <path d={path('mem')} fill="none" stroke="#14b8a6" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      <path d={cpuPath} fill="none" stroke="#6366f1" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

export function CapBar({ used, total, label, right, color }: { used: number | null; total: number | null; label: string; right?: string; color?: string }) {
  const pct = used != null && total ? Math.min(100, (used / total) * 100) : null
  return (
    <div>
      <div className="flex justify-between text-[11px] text-slate-500 mb-0.5"><span>{label}</span><span className="tabular-nums">{right ?? (pct == null ? '—' : `${Math.round(pct)}%`)}</span></div>
      <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct ?? 0}%`, background: color ?? loadColor(pct) }} />
      </div>
    </div>
  )
}

// ── VM tile ──────────────────────────────────────────────────────────────────

const gb = (b: number | null) => (b == null ? '—' : `${(b / 1024 ** 3).toFixed(b >= 10 * 1024 ** 3 ? 0 : 1)}G`)

export function tileHint(v: HvVm, t: (k: string, o?: any) => string): string {
  return [
    `${v.name} — ${v.state ?? '?'}`,
    v.cpu != null ? `CPU ${v.cpu}%${v.vcpu ? ` (${v.vcpu} vCPU)` : ''}` : v.vcpu ? `${v.vcpu} vCPU` : '',
    v.memAssigned ? `${t('hyperv.memory')}: ${formatBytes(v.memDemand)} / ${formatBytes(v.memAssigned)}` : '',
    v.heartbeat ? `${t('hyperv.heartbeat')}: ${v.heartbeat}` : '',
    ...v.flags.map(f => `⚠ ${t(`hyperv.problem.${f}`)}`),
  ].filter(Boolean).join('\n')
}

export function VmTile({ vm, mode, onClick, selected }: { vm: HvVm; mode: HeatMode; onClick?: () => void; selected?: boolean }) {
  const { t } = useTranslation()
  const running = vm.state === 'Running'
  const value = mode === 'cpu' ? vm.cpu : mode === 'mem' ? (vm.memAssigned && vm.memDemand != null ? (vm.memDemand / vm.memAssigned) * 100 : null) : null
  const heatStyle = mode !== 'state' && running && value != null ? { background: heat(value), color: value > 62 ? '#fff' : '#0f172a' } : undefined
  const cls = mode !== 'state' && (!running || value == null) ? TILE_CLASS.off : mode === 'state' || !heatStyle ? TILE_CLASS[vm.tile] : ''
  const second = !running ? (vm.state ?? '—')
    : mode === 'mem' ? (value == null ? '—' : `${Math.round(value)}% · ${gb(vm.memAssigned)}`)
    : `${vm.cpu ?? '—'}% · ${gb(vm.memAssigned)}`
  return (
    <button type="button" onClick={onClick} title={tileHint(vm, t as any)} style={heatStyle}
      className={cn('relative w-[92px] h-[48px] rounded-md px-1.5 py-1 text-left leading-tight overflow-hidden transition-transform hover:scale-105 hover:z-10 focus:outline-none',
        cls, selected && 'outline outline-2 outline-offset-1 outline-indigo-600')}>
      <div className="text-[11px] font-semibold truncate pr-3">{vm.name}</div>
      <div className="text-[10px] opacity-90 truncate tabular-nums">{second}</div>
      <div className="absolute top-1 right-1 flex flex-col gap-0.5">
        {vm.flags.filter(f => FLAG_ICON[f]).slice(0, 3).map(f => { const I = FLAG_ICON[f]; return <I key={f} size={9} className="opacity-90" /> })}
      </div>
    </button>
  )
}

// ── Host card ────────────────────────────────────────────────────────────────

export function HostBoard({ host, mode, onVm, selectedVm, tools, staleMin = 20 }: {
  host: HvHost; mode: HeatMode; onVm?: (vm: HvVm) => void; selectedVm?: string | null; tools?: React.ReactNode; staleMin?: number
}) {
  const { t } = useTranslation()
  const age = minutesSince(host.lastCheck)
  const stale = age != null && age > staleMin
  const used = host.storageTotal && host.storageFree != null ? host.storageTotal - host.storageFree : null
  const ratio = host.lp ? host.vcpu / host.lp : null
  const running = host.vms.filter(v => v.state === 'Running').length
  const worst = host.problems.length ? host.problems.reduce((a, p) => (SEV_ORDER[p.severity] < SEV_ORDER[a] ? p.severity : a), 'low' as HypervSeverity) : null
  const edge = host.down ? 'border-l-red-500' : worst === 'high' ? 'border-l-red-400' : worst === 'medium' ? 'border-l-amber-400' : 'border-l-emerald-400'
  return (
    <Card className={cn('border-l-4', edge)}>
      <CardHeader>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2 min-w-0">
            <span className={cn('inline-block w-2.5 h-2.5 rounded-full shrink-0', host.down ? 'bg-red-500' : stale ? 'bg-amber-400' : 'bg-emerald-500')} />
            <Server size={15} className="text-indigo-600 shrink-0" />
            {host.tenant && <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">{host.tenant}</span>}
            <h3 className="text-sm font-semibold text-slate-800 truncate">{host.name}</h3>
            {host.ip && <span className="text-xs text-slate-400 font-mono">{host.ip}</span>}
            {host.cluster && <Badge variant="purple">{t('hyperv.cluster')}: {host.cluster}</Badge>}
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            {host.down ? <Badge variant="red">{t('hyperv.hostDown')}</Badge>
              : <Badge variant="green">{running}/{host.vms.length} {t('hyperv.running')}</Badge>}
            <span className={cn(stale && 'text-amber-700')} title={host.lastCheck ?? ''}>{t('hyperv.checked')}: {ago(host.lastCheck)}</span>
            {tools}
          </div>
        </div>
        {host.os && <div className="text-[11px] text-slate-400 mt-0.5 truncate">{host.os}</div>}
      </CardHeader>
      <CardContent className="space-y-3">
        {host.down && host.error && <p className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-2 py-1 break-words">{host.error.slice(0, 240)}</p>}
        <div className="flex flex-wrap items-start gap-x-5 gap-y-3">
          <div className="flex gap-1">
            <Ring pct={host.cpu} label="CPU" sub={host.lp ? `${host.lp} ${t('hyperv.logicalShort')}` : undefined} />
            <Ring pct={host.mem} label={t('hyperv.memory') as string} sub={host.memCapacity ? formatBytes(host.memCapacity) : undefined} />
            <Ring pct={used != null && host.storageTotal ? (used / host.storageTotal) * 100 : null} label={t('hyperv.storage') as string}
              sub={host.storageFree != null ? `${formatBytes(host.storageFree)} ${t('hyperv.free')}` : undefined} />
          </div>
          <div className="flex-1 min-w-[200px] space-y-2">
            <CapBar used={host.vcpu} total={host.lp ? host.lp * 4 : null} label={t('hyperv.vcpuAssigned') as string}
              right={host.lp ? `${host.vcpu} vCPU / ${host.lp} ${t('hyperv.logicalShort')}${ratio != null ? ` (${ratio.toFixed(1)}:1)` : ''}` : `${host.vcpu} vCPU`}
              color={ratio != null && ratio > 4 ? '#f59e0b' : '#6366f1'} />
            <CapBar used={host.memAssigned} total={host.memCapacity} label={t('hyperv.memAssigned') as string}
              right={`${formatBytes(host.memAssigned)} / ${formatBytes(host.memCapacity)}`} color="#14b8a6" />
            {host.trend.length > 1 && (
              <div>
                <div className="flex justify-between text-[10px] text-slate-400"><span>{t('hyperv.trend24')}</span>
                  <span><i className="inline-block w-2 h-0.5 bg-indigo-500 align-middle mr-0.5" />CPU <i className="inline-block w-2 h-0.5 bg-teal-500 align-middle mx-0.5 ml-1.5" />{t('hyperv.memory')}</span></div>
                <Spark points={host.trend} height={34} />
              </div>
            )}
          </div>
        </div>
        {host.vms.length === 0 ? <p className="text-xs text-slate-400">{t('hyperv.noVms')}</p> : (
          <div className={cn('flex flex-wrap gap-1.5', host.down && 'opacity-50')}>
            {host.vms.map(v => <VmTile key={v.key} vm={v} mode={mode} selected={selectedVm === v.key} onClick={onVm ? () => onVm(v) : undefined} />)}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Summary strip ────────────────────────────────────────────────────────────

export function summarize(hosts: HvHost[]) {
  const tiles: Record<HypervTile, number> = { ok: 0, warn: 0, crit: 0, off: 0 }
  let vms = 0, running = 0, vcpu = 0, lp = 0, memAssigned = 0, memCapacity = 0
  const problems: Record<HypervSeverity, number> = { high: 0, medium: 0, low: 0 }
  for (const h of hosts) {
    for (const v of h.vms) { tiles[v.tile]++; vms++; if (v.state === 'Running') running++ }
    vcpu += h.vcpu; lp += h.lp ?? 0; memAssigned += h.memAssigned; memCapacity += h.memCapacity ?? 0
    for (const p of h.problems) problems[p.severity]++
  }
  const down = hosts.filter(h => h.down).length
  return { hosts: hosts.length, down, vms, running, tiles, vcpu, lp, memAssigned, memCapacity, problems }
}

export function SummaryStrip({ hosts }: { hosts: HvHost[] }) {
  const { t } = useTranslation()
  const s = summarize(hosts)
  const seg: Array<[HypervTile, string, string]> = [['ok', 'bg-emerald-500', 'hyperv.tileOk'], ['warn', 'bg-amber-400', 'hyperv.tileWarn'], ['crit', 'bg-red-500', 'hyperv.tileCrit'], ['off', 'bg-slate-300', 'hyperv.tileOff']]
  const r = 24, c = 2 * Math.PI * r, okFrac = s.hosts ? (s.hosts - s.down) / s.hosts : 0
  const ratio = s.lp ? s.vcpu / s.lp : null
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
      <Card><CardContent className="flex items-center gap-4">
        <svg width="64" height="64" viewBox="0 0 64 64" className="shrink-0">
          <circle cx="32" cy="32" r={r} fill="none" stroke={s.down ? '#fecaca' : '#e2e8f0'} strokeWidth="8" />
          <circle cx="32" cy="32" r={r} fill="none" stroke="#10b981" strokeWidth="8" strokeDasharray={`${c * okFrac} ${c}`} transform="rotate(-90 32 32)" />
          <text x="32" y="37" textAnchor="middle" className="fill-slate-800" style={{ fontSize: 16, fontWeight: 700 }}>{s.hosts}</text>
        </svg>
        <div>
          <div className="text-sm font-medium text-slate-800">{t('hyperv.hosts')}</div>
          <div className="text-xs text-slate-500">{s.hosts - s.down} {t('hyperv.hostsOk')}</div>
          {s.down > 0 && <div className="text-xs text-red-600 font-medium">{s.down} {t('hyperv.hostsDown')}</div>}
        </div>
      </CardContent></Card>
      <Card><CardContent className="space-y-2">
        <div className="flex items-baseline justify-between">
          <div className="text-sm font-medium text-slate-800">{t('hyperv.vms')}</div>
          <div className="text-xs text-slate-500"><b className="text-slate-800 text-base">{s.running}</b> / {s.vms} {t('hyperv.running')}</div>
        </div>
        <div className="flex h-3 rounded-full overflow-hidden bg-slate-100">
          {seg.map(([k, color]) => s.tiles[k] > 0 && <div key={k} className={color} style={{ width: `${(s.tiles[k] / Math.max(1, s.vms)) * 100}%` }} title={`${t(`hyperv.tile${k[0].toUpperCase()}${k.slice(1)}`)}: ${s.tiles[k]}`} />)}
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-slate-500">
          {seg.map(([k, color, label]) => <span key={k} className="flex items-center gap-1"><i className={cn('w-2 h-2 rounded-sm inline-block', color)} />{t(label)} {s.tiles[k]}</span>)}
        </div>
      </CardContent></Card>
      <Card><CardContent className="space-y-2">
        <div className="text-sm font-medium text-slate-800 flex items-center gap-1.5"><Cpu size={14} className="text-indigo-600" />{t('hyperv.capacity')}</div>
        <CapBar used={s.vcpu} total={s.lp ? s.lp * 4 : null} label="vCPU" right={s.lp ? `${s.vcpu} / ${s.lp} (${ratio?.toFixed(1)}:1)` : `${s.vcpu}`} color={ratio != null && ratio > 4 ? '#f59e0b' : '#6366f1'} />
        <CapBar used={s.memAssigned} total={s.memCapacity} label={t('hyperv.memory') as string} right={`${formatBytes(s.memAssigned)} / ${formatBytes(s.memCapacity)}`} color="#14b8a6" />
      </CardContent></Card>
      <Card><CardContent className="space-y-2">
        <div className="text-sm font-medium text-slate-800">{t('hyperv.problems')}</div>
        {s.problems.high + s.problems.medium + s.problems.low === 0
          ? <div className="text-sm text-emerald-700">{t('hyperv.noProblems')}</div>
          : <div className="flex gap-2 flex-wrap">
            {(['high', 'medium', 'low'] as HypervSeverity[]).map(k => s.problems[k] > 0 && (
              <div key={k} className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-2.5 py-1">
                <i className={cn('w-2.5 h-2.5 rounded-full inline-block', sevColor[k])} />
                <span className="text-lg font-semibold text-slate-800 leading-none">{s.problems[k]}</span>
                <span className="text-[11px] text-slate-500">{t(`hyperv.sev.${k}`)}</span>
              </div>
            ))}
          </div>}
      </CardContent></Card>
    </div>
  )
}

// ── Problems ─────────────────────────────────────────────────────────────────

export function paramDetail(kind: string, p?: Record<string, string | number | null>): string {
  if (!p) return ''
  const parts: string[] = []
  if (p.pct != null) parts.push(`${p.pct}%`)
  if (p.free_pct != null) parts.push(`${p.free_pct}% (${p.free_gb} GB)`)
  if (p.ratio != null) parts.push(`${p.vcpu} vCPU / ${p.lp} → ${p.ratio}:1`)
  if (p.days != null) parts.push(`${p.days} d${p.count ? ` · ${p.count}×` : ''}`)
  if (p.avg != null) parts.push(`⌀ ${p.avg}%`)
  if (p.demand_gb != null) parts.push(`${p.demand_gb} / ${p.assigned_gb} GB`)
  if (p.heartbeat) parts.push(String(p.heartbeat))
  if (p.health || p.state) parts.push([p.health, p.state].filter(Boolean).join(' / '))
  if (p.polls != null) parts.push(`${p.polls}×`)
  return parts.join(' · ')
}

export type ProblemRow = HvProblem & { host: string; tenant?: string; hostKey: string }

export function ProblemsCard({ rows, onPick }: { rows: ProblemRow[]; onPick?: (r: ProblemRow) => void }) {
  const { t } = useTranslation()
  const sorted = [...rows].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.host.localeCompare(b.host) || (a.vm ?? '').localeCompare(b.vm ?? ''))
  return (
    <Card>
      <CardHeader><div className="flex items-center justify-between"><h2 className="text-sm font-semibold text-slate-700">{t('hyperv.problemsCard')}</h2><span className="text-xs text-slate-400">{rows.length}</span></div></CardHeader>
      <CardContent className="p-0">
        {sorted.length === 0 ? <p className="p-4 text-sm text-emerald-700">{t('hyperv.noProblems')}</p> : (
          <ul className="max-h-96 overflow-y-auto divide-y divide-slate-100">
            {sorted.map((r, i) => (
              <li key={`${r.hostKey}:${r.kind}:${r.vm}:${i}`}>
                <button type="button" onClick={onPick ? () => onPick(r) : undefined} className="w-full text-left px-4 py-2 flex items-start gap-2.5 hover:bg-slate-50">
                  <i className={cn('mt-1.5 w-2.5 h-2.5 rounded-full shrink-0', sevColor[r.severity])} />
                  <div className="min-w-0">
                    <div className="text-sm text-slate-800">{t(`hyperv.problem.${r.kind}`)}</div>
                    <div className="text-xs text-slate-500 truncate">
                      {r.tenant && <span className="px-1 mr-1 rounded bg-slate-100 text-slate-600">{r.tenant}</span>}
                      {r.host}{r.vm ? ` › ${r.vm}` : ''}{paramDetail(r.kind, r.params) ? ` — ${paramDetail(r.kind, r.params)}` : ''}
                    </div>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

export function HeatModeSwitch({ mode, onChange }: { mode: HeatMode; onChange: (m: HeatMode) => void }) {
  const { t } = useTranslation()
  return (
    <div className="inline-flex rounded-lg border border-slate-300 overflow-hidden text-xs">
      {(['state', 'cpu', 'mem'] as HeatMode[]).map(m => (
        <button key={m} type="button" onClick={() => onChange(m)}
          className={cn('px-3 py-1.5', mode === m ? 'bg-indigo-600 text-white' : 'bg-white text-slate-600 hover:bg-slate-50')}>{t(`hyperv.heat.${m}`)}</button>
      ))}
    </div>
  )
}

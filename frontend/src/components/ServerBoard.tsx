import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import type { HostGroupOut, HostJobView, LinuxHostOut, WindowsHostOut } from '../lib/api'
import { cn } from '../lib/utils'
import { Download, Power, Pencil, Trash2, Plus, X, Check, RefreshCw, AlertTriangle, CheckCircle2, Server, Laptop } from 'lucide-react'

// Presentational pieces of the Linux and Windows server pages (graphical board, groups, group-wide actions).
// Both pages map their own host rows into SrvHost, so everything below is platform-neutral.

export type SrvPlatform = 'linux' | 'windows'

export type SrvHost = {
  id: number
  tenant?: string                  // Central: which client the server belongs to (ids repeat across clients)
  name: string
  ip: string
  os: string | null
  domain: string | null            // Windows
  distroId: string | null          // Linux
  managed: boolean
  pending: boolean                 // discovered, not switched on yet
  workstation: boolean             // Windows workstation: no patching / restarting from here
  actionable: boolean              // managed and able to take an update / restart
  groupId: number | null
  cpu: number | null
  mem: number | null
  disk: number | null
  upgradable: number | null
  reboot: boolean
  status: 'ok' | 'error' | 'timeout' | null
  error: string | null
  lastCheck: string | null
  job: HostJobView | null
}

const ACTIVE_JOB = ['starting', 'checking', 'updating', 'upgrading', 'restarting', 'running_script']
export const isBusy = (h: SrvHost) => !!h.job && ACTIVE_JOB.includes(h.job.status ?? '')

export function fromLinux(h: LinuxHostOut): SrvHost {
  return {
    id: h.id, name: h.hostname || h.ip, ip: h.ip, os: h.distro_pretty, domain: null, distroId: h.distro_id,
    managed: h.managed, pending: h.source === 'auto' && !h.managed, workstation: false,
    actionable: h.managed && (h.package_manager === 'apt' || h.package_manager === 'dnf'),
    groupId: h.group_id, cpu: h.cpu_used_pct, mem: h.mem_used_pct, disk: h.disk_max_pct,
    upgradable: h.upgradable_count, reboot: h.reboot_required, status: h.last_status, error: h.last_error,
    lastCheck: h.last_check_at, job: h.job,
  }
}

export function fromWindows(h: WindowsHostOut): SrvHost {
  const workstation = h.host_type === 'workstation'
  return {
    id: h.id, name: h.hostname || h.ip, ip: h.ip, os: h.os_name, domain: h.domain, distroId: null,
    managed: h.managed, pending: h.source === 'auto' && !h.managed, workstation,
    actionable: h.managed && !workstation,
    groupId: h.group_id, cpu: h.cpu_used_pct, mem: h.mem_used_pct, disk: h.disk_max_pct,
    upgradable: h.upgradable_count, reboot: h.reboot_required, status: h.last_status, error: h.last_error,
    lastCheck: h.last_check_at, job: h.job,
  }
}

// ── Sections ─────────────────────────────────────────────────────────────────

export type SrvSection = {
  key: string
  kind: 'group' | 'auto' | 'workstations' | 'pending'
  title: string
  groupId?: number
  hosts: SrvHost[]
}

/** Operator groups first (even empty ones, so they can be filled), then what is left, arranged by itself:
 *  Windows by domain, Linux by distribution, workstations apart, and hosts that still wait to be switched on. */
export function buildSections(hosts: SrvHost[], groups: HostGroupOut[], platform: SrvPlatform, t: (k: string, o?: any) => string): SrvSection[] {
  const out: SrvSection[] = groups.map(g => ({ key: `g${g.id}`, kind: 'group', title: g.name, groupId: g.id, hosts: hosts.filter(h => h.groupId === g.id) }))
  const free = hosts.filter(h => h.groupId == null || !groups.some(g => g.id === h.groupId))
  const auto = new Map<string, SrvSection>()
  const pending: SrvHost[] = [], stations: SrvHost[] = []
  for (const h of free) {
    if (h.pending) { pending.push(h); continue }
    if (h.workstation) { stations.push(h); continue }
    const label = platform === 'windows' ? (h.domain || t('serverBoard.workgroup')) : (h.distroId || t('serverBoard.otherDistro'))
    const key = `a:${h.tenant ?? ''}:${label.toLowerCase()}`
    const title = platform === 'windows' ? (h.domain ? t('serverBoard.domain', { name: label }) : label) : label.charAt(0).toUpperCase() + label.slice(1)
    if (!auto.has(key)) auto.set(key, { key, kind: 'auto', title: h.tenant ? `${h.tenant} · ${title}` : title, hosts: [] })
    auto.get(key)!.hosts.push(h)
  }
  out.push(...[...auto.values()].sort((a, b) => a.title.localeCompare(b.title)))
  const perTenant = (hs: SrvHost[]) => [...new Set(hs.map(h => h.tenant ?? ''))].sort()
  for (const tn of perTenant(stations)) out.push({ key: `stations:${tn}`, kind: 'workstations', title: tn ? `${tn} · ${t('serverBoard.workstations')}` : t('serverBoard.workstations'), hosts: stations.filter(h => (h.tenant ?? '') === tn) })
  for (const tn of perTenant(pending)) out.push({ key: `pending:${tn}`, kind: 'pending', title: tn ? `${tn} · ${t('serverBoard.pending')}` : t('serverBoard.pending'), hosts: pending.filter(h => (h.tenant ?? '') === tn) })
  return out
}

// ── Colours ──────────────────────────────────────────────────────────────────

const load = (pct: number | null) => (pct == null ? '#cbd5e1' : pct >= 90 ? '#ef4444' : pct >= 75 ? '#f59e0b' : '#10b981')

type Health = 'bad' | 'warn' | 'ok' | 'idle'
export function healthOf(h: SrvHost): Health {
  if (h.pending || (!h.managed)) return 'idle'
  if (h.status === 'error' || h.status === 'timeout') return 'bad'
  if (h.reboot || (h.upgradable ?? 0) > 0 || [h.cpu, h.mem, h.disk].some(v => v != null && v >= 90)) return 'warn'
  return 'ok'
}
const EDGE: Record<Health, string> = { bad: 'border-l-red-500', warn: 'border-l-amber-400', ok: 'border-l-emerald-400', idle: 'border-l-slate-300' }
const DOT: Record<Health, string> = { bad: 'bg-red-500', warn: 'bg-amber-400', ok: 'bg-emerald-500', idle: 'bg-slate-300' }

function MiniBar({ label, pct }: { label: string; pct: number | null }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-7 text-[10px] text-slate-400">{label}</span>
      <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(100, pct ?? 0)}%`, background: load(pct) }} />
      </div>
      <span className="w-8 text-right text-[10px] tabular-nums text-slate-600">{pct == null ? '—' : `${Math.round(pct)}%`}</span>
    </div>
  )
}

// ── Tile ─────────────────────────────────────────────────────────────────────

export function SrvTile({ host, selected, onToggleSelect, onOpen }: {
  host: SrvHost; selected: boolean; onToggleSelect?: () => void; onOpen: () => void
}) {
  const { t } = useTranslation()
  const health = healthOf(host)
  const busy = isBusy(host)
  return (
    <div className={cn('relative w-[210px] rounded-lg border border-slate-200 border-l-4 bg-white p-2.5 text-left shadow-sm hover:shadow transition-shadow cursor-pointer', EDGE[health],
      selected && 'ring-2 ring-indigo-500')} onClick={onOpen}>
      {host.managed && onToggleSelect && (
        <input type="checkbox" checked={selected} onClick={e => e.stopPropagation()} onChange={onToggleSelect}
          className="absolute top-2 right-2" title={t('runScript.selectForBulk') as string} />
      )}
      <div className="flex items-center gap-1.5 pr-5">
        <i className={cn('inline-block w-2 h-2 rounded-full shrink-0', DOT[health])} />
        {host.workstation ? <Laptop size={12} className="text-slate-400 shrink-0" /> : <Server size={12} className="text-indigo-500 shrink-0" />}
        <span className="text-sm font-semibold text-slate-800 truncate" title={host.name}>{host.name}</span>
      </div>
      <div className="text-[10px] font-mono text-slate-400 truncate">{host.ip}{host.os ? <span className="font-sans"> · {host.os}</span> : null}</div>
      <div className="mt-2 space-y-1">
        <MiniBar label="CPU" pct={host.cpu} />
        <MiniBar label="RAM" pct={host.mem} />
        <MiniBar label={t('serverBoard.disk') as string} pct={host.disk} />
      </div>
      <div className="mt-2 flex flex-wrap gap-1 min-h-[20px]">
        {host.pending && <Badge variant="gray" className="text-[10px]">{t('serverBoard.waiting')}</Badge>}
        {busy && <Badge variant="blue" className="text-[10px]"><RefreshCw size={9} className="animate-spin" /> {t(`serverBoard.job.${host.job!.status}`, host.job!.status ?? '')}</Badge>}
        {!busy && host.job?.status === 'error' && <Badge variant="red" className="text-[10px]" >{t('serverBoard.jobFailed')}</Badge>}
        {(host.status === 'error' || host.status === 'timeout') && !host.pending && <Badge variant="red" className="text-[10px]"><AlertTriangle size={9} /> {t('serverBoard.error')}</Badge>}
        {host.managed && (host.upgradable ?? 0) > 0 && <Badge variant="yellow" className="text-[10px]"><Download size={9} /> {host.upgradable}</Badge>}
        {host.managed && host.upgradable === 0 && <Badge variant="green" className="text-[10px]"><CheckCircle2 size={9} /> {t('serverBoard.upToDate')}</Badge>}
        {host.reboot && <Badge variant="red" className="text-[10px]"><Power size={9} /> {t('serverBoard.rebootShort')}</Badge>}
      </div>
    </div>
  )
}

// ── Summary strip ────────────────────────────────────────────────────────────

export function SrvSummary({ hosts }: { hosts: SrvHost[] }) {
  const { t } = useTranslation()
  const managed = hosts.filter(h => h.managed)
  const bad = managed.filter(h => h.status === 'error' || h.status === 'timeout')
  const current = managed.filter(h => h.upgradable === 0).length
  const stale = managed.filter(h => (h.upgradable ?? 0) > 0)
  const unknown = managed.length - current - stale.length
  const packages = stale.reduce((n, h) => n + (h.upgradable ?? 0), 0)
  const reboot = managed.filter(h => h.reboot)
  const hot = managed.filter(h => [h.cpu, h.mem, h.disk].some(v => v != null && v >= 90))
  const r = 24, c = 2 * Math.PI * r, frac = hosts.length ? managed.length / hosts.length : 0
  const seg = [[current, 'bg-emerald-500', 'serverBoard.upToDate'], [stale.length, 'bg-amber-400', 'serverBoard.needUpdates'], [unknown, 'bg-slate-300', 'serverBoard.unknown']] as const
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
      <Card><CardContent className="flex items-center gap-4">
        <svg width="64" height="64" viewBox="0 0 64 64" className="shrink-0">
          <circle cx="32" cy="32" r={r} fill="none" stroke="#e2e8f0" strokeWidth="8" />
          <circle cx="32" cy="32" r={r} fill="none" stroke={bad.length ? '#f59e0b' : '#10b981'} strokeWidth="8" strokeDasharray={`${c * frac} ${c}`} transform="rotate(-90 32 32)" />
          <text x="32" y="37" textAnchor="middle" className="fill-slate-800" style={{ fontSize: 16, fontWeight: 700 }}>{hosts.length}</text>
        </svg>
        <div>
          <div className="text-sm font-medium text-slate-800">{t('serverBoard.servers')}</div>
          <div className="text-xs text-slate-500">{managed.length} {t('serverBoard.managed')}</div>
          {bad.length > 0 && <div className="text-xs text-red-600 font-medium">{bad.length} {t('serverBoard.withErrors')}</div>}
        </div>
      </CardContent></Card>
      <Card><CardContent className="space-y-2">
        <div className="flex items-baseline justify-between">
          <div className="text-sm font-medium text-slate-800">{t('serverBoard.updates')}</div>
          <div className="text-xs text-slate-500">{packages > 0 ? t('serverBoard.packagesTotal', { count: packages }) : t('serverBoard.nothingToInstall')}</div>
        </div>
        <div className="flex h-3 rounded-full overflow-hidden bg-slate-100">
          {seg.map(([n, color, label]) => n > 0 && <div key={label} className={color} style={{ width: `${(n / Math.max(1, managed.length)) * 100}%` }} />)}
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-slate-500">
          {seg.map(([n, color, label]) => <span key={label} className="flex items-center gap-1"><i className={cn('w-2 h-2 rounded-sm inline-block', color)} />{t(label)} {n}</span>)}
        </div>
      </CardContent></Card>
      <Card><CardContent className="space-y-1">
        <div className="text-sm font-medium text-slate-800">{t('serverBoard.restartTitle')}</div>
        {reboot.length === 0 ? <div className="text-sm text-emerald-700">{t('serverBoard.restartNone')}</div> : (
          <>
            <div className="text-2xl font-semibold text-red-600 leading-none">{reboot.length}</div>
            <div className="text-[11px] text-slate-500 truncate" title={reboot.map(h => h.name).join(', ')}>{reboot.map(h => h.name).join(', ')}</div>
          </>
        )}
      </CardContent></Card>
      <Card><CardContent className="space-y-1">
        <div className="text-sm font-medium text-slate-800">{t('serverBoard.resources')}</div>
        {hot.length === 0 ? <div className="text-sm text-emerald-700">{t('serverBoard.resourcesOk')}</div> : (
          <>
            <div className="text-2xl font-semibold text-amber-600 leading-none">{hot.length}</div>
            <div className="text-[11px] text-slate-500 truncate" title={hot.map(h => h.name).join(', ')}>{t('serverBoard.resourcesHigh')}: {hot.map(h => h.name).join(', ')}</div>
          </>
        )}
      </CardContent></Card>
    </div>
  )
}

// ── Group section ────────────────────────────────────────────────────────────

export function SrvSectionView({ section, selected, enabled, showRestart = true, onToggleSelect, onOpen, onAction, onRename, onDelete }: {
  section: SrvSection; selected: Set<number>; enabled: boolean; showRestart?: boolean
  onToggleSelect?: (id: number) => void; onOpen: (h: SrvHost) => void
  onAction: (kind: 'upgrade' | 'restart', section: SrvSection) => void
  onRename?: (name: string) => void; onDelete?: () => void
}) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState<string | null>(null)
  const targets = section.hosts.filter(h => h.actionable)
  const reboot = section.hosts.filter(h => h.reboot).length
  const stale = section.hosts.filter(h => (h.upgradable ?? 0) > 0).length
  const bad = section.hosts.filter(h => h.status === 'error' || h.status === 'timeout').length
  const canAct = section.kind !== 'pending' && section.kind !== 'workstations'
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            {editing !== null ? (
              <form className="flex items-center gap-1" onSubmit={e => { e.preventDefault(); if (editing.trim()) { onRename?.(editing.trim()); setEditing(null) } }}>
                <input autoFocus value={editing} onChange={e => setEditing(e.target.value)} maxLength={64} className="border border-slate-300 rounded px-2 py-1 text-sm" />
                <button type="submit" className="text-emerald-600"><Check size={15} /></button>
                <button type="button" onClick={() => setEditing(null)} className="text-slate-400"><X size={15} /></button>
              </form>
            ) : <h2 className="text-sm font-semibold text-slate-800 truncate">{section.title}</h2>}
            <Badge variant="gray">{section.hosts.length}</Badge>
            {section.kind === 'group' && <Badge variant="purple">{t('serverBoard.yourGroup')}</Badge>}
            {stale > 0 && <Badge variant="yellow">{t('serverBoard.needUpdatesN', { count: stale })}</Badge>}
            {reboot > 0 && <Badge variant="red">{t('serverBoard.needRestartN', { count: reboot })}</Badge>}
            {bad > 0 && <Badge variant="red">{t('serverBoard.errorsN', { count: bad })}</Badge>}
          </div>
          <div className="flex items-center gap-1.5">
            {canAct && (
              <>
                <Button size="sm" variant="secondary" disabled={!enabled || targets.length === 0} onClick={() => onAction('upgrade', section)}
                  title={!enabled ? (t('serverBoard.actionsOff') as string) : undefined}>
                  <Download size={12} /> {t('serverBoard.groupUpdate', { count: targets.length })}
                </Button>
                {showRestart && <Button size="sm" variant="danger" disabled={!enabled || targets.length === 0} onClick={() => onAction('restart', section)}
                  title={!enabled ? (t('serverBoard.actionsOff') as string) : undefined}>
                  <Power size={12} /> {t('serverBoard.groupRestart', { count: targets.length })}
                </Button>}
              </>
            )}
            {section.kind === 'group' && editing === null && (
              <>
                <Button size="sm" variant="ghost" onClick={() => setEditing(section.title)} title={t('serverBoard.rename') as string}><Pencil size={12} /></Button>
                <Button size="sm" variant="ghost" onClick={() => { if (confirm(t('serverBoard.deleteGroupConfirm', { name: section.title }) as string)) onDelete?.() }}
                  title={t('serverBoard.deleteGroup') as string}><Trash2 size={12} /></Button>
              </>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {section.hosts.length === 0 ? <p className="text-xs text-slate-400">{t('serverBoard.groupEmpty')}</p> : (
          <div className="flex flex-wrap gap-3">
            {section.hosts.map(h => <SrvTile key={`${h.tenant ?? ''}:${h.id}`} host={h} selected={selected.has(h.id)} onToggleSelect={onToggleSelect ? () => onToggleSelect(h.id) : undefined} onOpen={() => onOpen(h)} />)}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── New group ────────────────────────────────────────────────────────────────

export function NewGroupButton({ onCreate }: { onCreate: (name: string) => Promise<unknown> }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const submit = async () => {
    setErr(null)
    try { await onCreate(name.trim()); setName(''); setOpen(false) } catch (e) { setErr((e as any)?.response?.data?.detail || (e as Error).message) }
  }
  if (!open) return <Button size="sm" variant="secondary" onClick={() => setOpen(true)}><Plus size={13} /> {t('serverBoard.newGroup')}</Button>
  return (
    <form className="flex items-center gap-1.5" onSubmit={e => { e.preventDefault(); if (name.trim()) submit() }}>
      <input autoFocus value={name} onChange={e => setName(e.target.value)} maxLength={64} placeholder={t('serverBoard.groupName') as string}
        className="border border-slate-300 rounded-lg px-2 py-1 text-sm" />
      <Button size="sm" variant="primary" type="submit" disabled={!name.trim()}>{t('serverBoard.create')}</Button>
      <Button size="sm" variant="ghost" type="button" onClick={() => { setOpen(false); setErr(null) }}><X size={13} /></Button>
      {err && <span className="text-xs text-red-600">{err}</span>}
    </form>
  )
}

// ── Group-wide action ────────────────────────────────────────────────────────

export type GroupActionRequest = { ids: number[]; reason: string; staggerSec: number }

export function GroupActionModal({ kind, section, platform, footnote, onClose, onRun }: {
  kind: 'upgrade' | 'restart'; section: SrvSection; platform: SrvPlatform; footnote?: string
  onClose: () => void; onRun: (req: GroupActionRequest) => Promise<unknown>
}) {
  const { t } = useTranslation()
  const eligible = section.hosts.filter(h => h.actionable)
  const skipped = section.hosts.length - eligible.length
  const needing = eligible.filter(h => h.reboot)
  const [scope, setScope] = useState<'all' | 'needing'>(kind === 'restart' && needing.length > 0 ? 'needing' : 'all')
  const [picked, setPicked] = useState<Set<number>>(new Set())      // ids switched OFF
  const [reason, setReason] = useState('')
  const [stagger, setStagger] = useState(kind === 'restart' ? 120 : 0)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [done, setDone] = useState<number | null>(null)
  const base = scope === 'needing' ? needing : eligible
  const ids = base.filter(h => !picked.has(h.id)).map(h => h.id)
  const needsReason = kind === 'restart' || platform === 'windows'
  const toggle = (id: number) => setPicked(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })

  const submit = async () => {
    setBusy(true); setErr(null)
    try { await onRun({ ids, reason: reason.trim(), staggerSec: kind === 'restart' ? stagger : 0 }); setDone(ids.length) }
    catch (e) { setErr((e as any)?.response?.data?.detail || (e as Error).message) }
    finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/40 p-4" onClick={onClose}>
      <div className="w-full max-w-lg bg-white rounded-xl shadow-2xl p-5 space-y-3 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-2">
          <h3 className="text-base font-semibold text-slate-900">{t(kind === 'upgrade' ? 'serverBoard.updateTitle' : 'serverBoard.restartModalTitle', { name: section.title })}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-800"><X size={18} /></button>
        </div>
        {done !== null ? (
          <>
            <p className="text-sm text-emerald-700">{t('serverBoard.queued', { count: done })}</p>
            <div className="flex justify-end"><Button size="sm" variant="primary" onClick={onClose}>{t('serverBoard.close')}</Button></div>
          </>
        ) : (
          <>
            <p className={cn('text-xs rounded px-2 py-1.5 border', kind === 'restart' ? 'bg-red-50 border-red-200 text-red-800' : 'bg-amber-50 border-amber-200 text-amber-800')}>
              {t(kind === 'restart' ? 'serverBoard.restartWarn' : 'serverBoard.updateWarn')}
            </p>
            {kind === 'restart' && needing.length > 0 && eligible.length > needing.length && (
              <div className="flex gap-4 text-sm">
                <label className="flex items-center gap-1.5"><input type="radio" checked={scope === 'needing'} onChange={() => setScope('needing')} />{t('serverBoard.onlyNeeding', { count: needing.length })}</label>
                <label className="flex items-center gap-1.5"><input type="radio" checked={scope === 'all'} onChange={() => setScope('all')} />{t('serverBoard.allInGroup', { count: eligible.length })}</label>
              </div>
            )}
            <div>
              <div className="text-xs font-medium text-slate-600 mb-1">{t('serverBoard.serversInRun', { count: ids.length })}</div>
              <div className="max-h-40 overflow-y-auto border border-slate-200 rounded divide-y divide-slate-100">
                {base.length === 0 && <p className="p-2 text-xs text-slate-400">{t('serverBoard.noneEligible')}</p>}
                {base.map((h, i) => (
                  <label key={h.id} className="flex items-center gap-2 px-2 py-1 text-xs cursor-pointer hover:bg-slate-50">
                    <input type="checkbox" checked={!picked.has(h.id)} onChange={() => toggle(h.id)} />
                    <span className="w-5 text-slate-400">{i + 1}.</span>
                    <span className="flex-1 truncate text-slate-800">{h.name}</span>
                    {h.reboot && <Badge variant="red" className="text-[10px]">{t('serverBoard.rebootShort')}</Badge>}
                    {(h.upgradable ?? 0) > 0 && <Badge variant="yellow" className="text-[10px]">{h.upgradable}</Badge>}
                  </label>
                ))}
              </div>
              {skipped > 0 && <p className="text-[11px] text-slate-400 mt-1">{t('serverBoard.skipped', { count: skipped })}</p>}
            </div>
            {kind === 'restart' && (
              <label className="flex flex-col text-xs text-slate-600 gap-0.5">{t('serverBoard.stagger')}
                <select value={stagger} onChange={e => setStagger(Number(e.target.value))} className="border border-slate-300 rounded px-2 py-1.5 text-sm bg-white">
                  <option value={0}>{t('serverBoard.staggerNone')}</option>
                  {[120, 300, 600, 900].map(s => <option key={s} value={s}>{t('serverBoard.staggerEvery', { min: s / 60 })}</option>)}
                </select>
              </label>
            )}
            {needsReason && (
              <textarea value={reason} onChange={e => setReason(e.target.value)} rows={2} maxLength={500} placeholder={t('serverBoard.reasonPlaceholder') as string}
                className="w-full border border-slate-300 rounded px-2 py-1.5 text-sm" />
            )}
            <p className="text-[11px] text-slate-400">{footnote ?? t('serverBoard.oneByOne')}</p>
            {err && <p className="text-xs text-red-700">{err}</p>}
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={onClose}>{t('common.cancel')}</Button>
              <Button size="sm" variant={kind === 'restart' ? 'danger' : 'primary'} disabled={busy || ids.length === 0 || (needsReason && !reason.trim())} onClick={submit}>
                {kind === 'restart' ? <Power size={12} /> : <Download size={12} />} {t('serverBoard.run', { count: ids.length })}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ── Drawer around the existing host card ─────────────────────────────────────

export function HostDrawer({ host, groups, onGroup, onClose, children }: {
  host: SrvHost; groups?: HostGroupOut[]; onGroup?: (groupId: number | null) => void; onClose: () => void; children: React.ReactNode
}) {
  const { t } = useTranslation()
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-900/30" onClick={onClose}>
      <div className="w-full max-w-2xl h-full bg-slate-50 shadow-2xl overflow-y-auto p-4 space-y-3" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-lg font-semibold text-slate-900 truncate">{host.name}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-800"><X size={18} /></button>
        </div>
        {onGroup && groups && (
          <label className="flex items-center gap-2 text-xs text-slate-600">{t('serverBoard.group')}
            <select value={host.groupId ?? ''} onChange={e => onGroup(e.target.value ? Number(e.target.value) : null)}
              className="border border-slate-300 rounded px-2 py-1 text-sm bg-white">
              <option value="">{t('serverBoard.noGroup')}</option>
              {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </label>
        )}
        {children}
      </div>
    </div>
  )
}

export function useSections(hosts: SrvHost[], groups: HostGroupOut[], platform: SrvPlatform) {
  const { t } = useTranslation()
  return useMemo(() => buildSections(hosts, groups, platform, t as any), [hosts, groups, platform, t])
}

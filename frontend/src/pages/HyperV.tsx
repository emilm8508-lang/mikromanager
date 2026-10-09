import { Fragment, useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { hypervApi, type HypervActionKind, type HypervActionLogEntry, type HypervOverview, type HypervOverviewHost } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import {
  fromLocal, HostBoard, SummaryStrip, ProblemsCard, HeatModeSwitch, Spark, ago, paramDetail, sevColor,
  type HeatMode, type HvHost, type HvVm, type ProblemRow,
} from '../components/HypervWidgets'
import { Layers, RefreshCw, Download, X, Play, Power, RotateCcw, Camera, ChevronDown, ChevronRight } from 'lucide-react'
import { cn, formatBytes } from '../lib/utils'

function formatUptime(sec: number | null | undefined): string {
  if (sec == null || sec <= 0) return '—'
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60)
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`
}

// Same OWASP CSV-formula-injection guard + BOM as the other CSV exports in the app.
function csvSafe(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v)
  return `"${(s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s).replace(/"/g, '""')}"`
}

function errText(e: unknown): string {
  const anyE = e as any
  return anyE?.response?.data?.detail || anyE?.message || String(e)
}

const stateVariant = (s: string | null): 'green' | 'gray' | 'yellow' | 'red' =>
  s === 'Running' ? 'green' : s === 'Off' ? 'gray' : s === 'Saved' || s === 'Paused' ? 'yellow' : 'red'

// ── VM drawer ────────────────────────────────────────────────────────────────

const ACTION_META: Record<HypervActionKind, { icon: typeof Play; danger?: boolean; needsRunning?: boolean; needsStopped?: boolean }> = {
  start: { icon: Play, needsStopped: true },
  shutdown: { icon: Power, needsRunning: true },
  restart: { icon: RotateCcw, needsRunning: true },
  poweroff: { icon: Power, danger: true, needsRunning: true },
  checkpoint: { icon: Camera },
}

function ActionsBlock({ vm, host, enabled }: { vm: NonNullable<ReturnType<typeof useVm>['data']>; host: HvHost; enabled: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [pending, setPending] = useState<HypervActionKind | null>(null)
  const [reason, setReason] = useState('')
  const [snap, setSnap] = useState('')
  const running = vm.state === 'Running'
  const { data: log } = useQuery({
    queryKey: ['hyperv-actions'], queryFn: () => hypervApi.actions(50),
    refetchInterval: q => (q.state.data?.actions.some(a => a.status === 'running') ? 2000 : 15000),
  })
  const mine = (log?.actions ?? []).filter(a => a.vm_name === vm.name && a.windows_host_id === host.windowsHostId).slice(0, 4)
  const run = useMutation({
    mutationFn: () => hypervApi.action(vm.id, { action: pending!, reason, snapshot_name: pending === 'checkpoint' ? snap : undefined }),
    onSuccess: () => {
      setPending(null); setReason(''); setSnap('')
      qc.invalidateQueries({ queryKey: ['hyperv-actions'] })
      setTimeout(() => qc.invalidateQueries({ queryKey: ['hyperv-overview'] }), 6000)
    },
  })
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wide">{t('hyperv.actions')}</h4>
      {!enabled ? <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1.5">{t('hyperv.actionsOff')}</p> : (
        <div className="flex flex-wrap gap-1.5">
          {(Object.keys(ACTION_META) as HypervActionKind[]).map(a => {
            const m = ACTION_META[a]
            const disabled = (m.needsRunning && !running) || (m.needsStopped && running)
            const I = m.icon
            return (
              <Button key={a} size="sm" variant={m.danger ? 'danger' : 'secondary'} disabled={disabled || run.isPending}
                onClick={() => { setPending(a); run.reset() }}><I size={12} /> {t(`hyperv.action.${a}`)}</Button>
            )
          })}
        </div>
      )}
      {pending && (
        <div className="border border-indigo-200 bg-indigo-50/40 rounded-lg p-3 space-y-2">
          <p className="text-sm text-slate-800">{t(`hyperv.confirm.${pending}`, { name: vm.name })}</p>
          {pending === 'checkpoint' && (
            <input value={snap} onChange={e => setSnap(e.target.value)} placeholder={t('hyperv.checkpointName') as string}
              className="w-full border border-slate-300 rounded px-2 py-1.5 text-sm" maxLength={64} />
          )}
          <textarea value={reason} onChange={e => setReason(e.target.value)} rows={2} maxLength={500} placeholder={t('hyperv.reasonPlaceholder') as string}
            className="w-full border border-slate-300 rounded px-2 py-1.5 text-sm" />
          {run.isError && <p className="text-xs text-red-700">{errText(run.error)}</p>}
          <div className="flex gap-2 justify-end">
            <Button size="sm" variant="ghost" onClick={() => setPending(null)}>{t('common.cancel')}</Button>
            <Button size="sm" variant={ACTION_META[pending].danger ? 'danger' : 'primary'} disabled={!reason.trim() || run.isPending} onClick={() => run.mutate()}>{t('hyperv.run')}</Button>
          </div>
        </div>
      )}
      {mine.length > 0 && (
        <ul className="text-xs space-y-1">
          {mine.map(a => (
            <li key={a.id} className="flex items-start gap-2">
              <Badge variant={a.status === 'ok' ? 'green' : a.status === 'error' ? 'red' : 'blue'}>{t(`hyperv.actionStatus.${a.status}`)}</Badge>
              <span className="text-slate-700">{t(`hyperv.action.${a.action}`)} · {a.created_by} · {ago(a.created_at)} — <i>{a.reason}</i>
                {a.status === 'error' && a.output && <span className="block text-red-700 break-words">{a.output.slice(0, 240)}</span>}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function useVm(id: number) {
  return useQuery({ queryKey: ['hyperv-vm', id], queryFn: () => hypervApi.vm(id), refetchInterval: 30_000 })
}

function Fact({ label, value }: { label: string; value: React.ReactNode }) {
  return <div><div className="text-[10px] uppercase tracking-wide text-slate-400">{label}</div><div className="text-sm text-slate-800 break-words">{value ?? '—'}</div></div>
}

function VmDrawer({ vmRef, host, insights, actionsEnabled, onClose }: {
  vmRef: HvVm; host: HvHost; insights: ProblemRow[]; actionsEnabled: boolean; onClose: () => void
}) {
  const { t } = useTranslation()
  const [hours, setHours] = useState(24)
  const { data: vm } = useVm(vmRef.id!)
  const { data: points = [] } = useQuery({ queryKey: ['hyperv-vm-history', vmRef.id, hours], queryFn: () => hypervApi.history('vm', vmRef.id!, hours), refetchInterval: 60_000 })
  const problems = insights.filter(p => p.hostKey === host.key && p.vm === vmRef.name)
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-900/30" onClick={onClose}>
      <div className="w-full max-w-lg h-full bg-white shadow-2xl overflow-y-auto p-5 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="text-lg font-semibold text-slate-900 truncate">{vmRef.name}</h3>
            <div className="text-xs text-slate-500">{host.name}</div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={stateVariant(vmRef.state)}>{vmRef.state ?? '—'}</Badge>
            <button onClick={onClose} className="text-slate-400 hover:text-slate-800"><X size={18} /></button>
          </div>
        </div>

        {problems.length > 0 && (
          <ul className="space-y-1">
            {problems.map(p => (
              <li key={p.kind} className="flex items-start gap-2 text-sm">
                <i className={cn('mt-1.5 w-2.5 h-2.5 rounded-full shrink-0', sevColor[p.severity])} />
                <span>{t(`hyperv.problem.${p.kind}`)}{paramDetail(p.kind, p.params) && <span className="text-slate-500"> — {paramDetail(p.kind, p.params)}</span>}</span>
              </li>
            ))}
          </ul>
        )}

        {!vm ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : (
          <>
            <div>
              <div className="flex items-center justify-between mb-1">
                <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wide">{t('hyperv.history')}</h4>
                <div className="flex gap-1 text-xs">
                  {[[24, '24 h'], [168, '7 d']].map(([h, l]) => (
                    <button key={h} onClick={() => setHours(h as number)} className={cn('px-2 py-0.5 rounded', hours === h ? 'bg-indigo-600 text-white' : 'text-slate-500 hover:bg-slate-100')}>{l}</button>
                  ))}
                </div>
              </div>
              <div className="border border-slate-200 rounded-lg p-2">
                <Spark points={points} height={90} />
                <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                  <span><i className="inline-block w-2 h-0.5 bg-indigo-500 align-middle mr-0.5" />CPU <i className="inline-block w-2 h-0.5 bg-teal-500 align-middle mx-0.5 ml-2" />{t('hyperv.memDemandPct')}</span>
                  <span>{points.length < 2 ? t('hyperv.noHistoryYet') : `${points.length} ${t('hyperv.points')}`}</span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <Fact label="vCPU" value={vm.vcpu_count} />
              <Fact label="CPU" value={vm.cpu_usage_pct != null ? `${vm.cpu_usage_pct}%` : null} />
              <Fact label={t('hyperv.uptime')} value={formatUptime(vm.uptime_sec)} />
              <Fact label={t('hyperv.memory')} value={`${formatBytes(vm.memory_demand_bytes)} / ${formatBytes(vm.memory_assigned_bytes)}`} />
              <Fact label={t('hyperv.dynamicMemory')} value={vm.dynamic_memory == null ? null : vm.dynamic_memory ? `${formatBytes(vm.memory_min_bytes)} – ${formatBytes(vm.memory_max_bytes)}` : t('common.no')} />
              <Fact label={t('hyperv.heartbeat')} value={vm.heartbeat} />
              <Fact label={t('hyperv.generation')} value={vm.generation ? `Gen ${vm.generation}` : null} />
              <Fact label={t('hyperv.replication')} value={vm.replication_state && vm.replication_state !== 'Disabled' ? `${vm.replication_state} (${vm.replication_health})` : t('hyperv.replOff')} />
              <Fact label={t('hyperv.stateSince')} value={ago(vm.state_since)} />
              <Fact label={t('hyperv.network')} value={vm.switches.join(', ') || null} />
              <Fact label="IP" value={vm.ips.join(', ') || null} />
              <Fact label={t('hyperv.checkpointType')} value={vm.checkpoint_type} />
            </div>

            <div>
              <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1">{t('hyperv.disks')}</h4>
              {vm.disks.length === 0 ? <p className="text-xs text-slate-400">—</p> : (
                <table className="w-full text-xs">
                  <tbody>
                    {vm.disks.map((d, i) => {
                      const pct = d.file_bytes != null && d.max_bytes ? (d.file_bytes / d.max_bytes) * 100 : null
                      return (
                        <tr key={i} className="border-b border-slate-100">
                          <td className="py-1 pr-2 font-mono text-slate-700 truncate max-w-[10rem]">{d.file}</td>
                          <td className="text-slate-500">{d.type}</td>
                          <td className="w-28"><div className="h-1.5 bg-slate-100 rounded-full overflow-hidden"><div className="h-full bg-indigo-500" style={{ width: `${pct ?? 0}%` }} /></div></td>
                          <td className="text-right text-slate-600 whitespace-nowrap pl-2">{formatBytes(d.file_bytes)} / {formatBytes(d.max_bytes)}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>

            <div>
              <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1">{t('hyperv.checkpoints')} ({vm.snapshot_count ?? 0})</h4>
              {vm.snapshots.length === 0 ? <p className="text-xs text-slate-400">—</p> : (
                <ul className="text-xs space-y-0.5">
                  {vm.snapshots.map((s, i) => <li key={i} className="flex justify-between"><span className="text-slate-700 truncate">{s.name}</span><span className="text-slate-400 whitespace-nowrap pl-2">{ago(s.created)}</span></li>)}
                </ul>
              )}
            </div>

            <ActionsBlock vm={vm} host={host} enabled={actionsEnabled} />
          </>
        )}
      </div>
    </div>
  )
}

// ── Tabs ─────────────────────────────────────────────────────────────────────

function Board({ hosts, data, onVm, selected }: { hosts: HvHost[]; data: HypervOverview; onVm: (h: HvHost, v: HvVm) => void; selected: string | null }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [mode, setMode] = useState<HeatMode>('state')
  const refresh = useMutation({
    mutationFn: (windowsHostId: number) => hypervApi.refresh(windowsHostId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hyperv-overview'] }),
  })
  const problems: ProblemRow[] = hosts.flatMap(h => h.problems.map(p => ({ ...p, host: h.name, hostKey: h.key })))
  const vmByName = (hostKey: string, name: string | null) => { const h = hosts.find(x => x.key === hostKey); return { h, v: h?.vms.find(x => x.name === name) } }
  return (
    <div className="space-y-4">
      <SummaryStrip hosts={hosts} />
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 items-start">
        <div className="xl:col-span-2 space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <HeatModeSwitch mode={mode} onChange={setMode} />
            <span className="text-xs text-slate-400">{t('hyperv.clickTile')}</span>
          </div>
          {hosts.map(h => (
            <HostBoard key={h.key} host={h} mode={mode} selectedVm={selected?.startsWith(`${h.key}:`) ? selected.slice(h.key.length + 1) : null}
              staleMin={Math.max(15, (data.poll_sec / 60) * 3)} onVm={v => onVm(h, v)}
              tools={<Button size="sm" variant="ghost" onClick={() => refresh.mutate(h.windowsHostId!)} disabled={refresh.isPending}><RefreshCw size={13} className={refresh.isPending && refresh.variables === h.windowsHostId ? 'animate-spin' : ''} /></Button>} />
          ))}
        </div>
        <ProblemsCard rows={problems} onPick={r => { const { h, v } = vmByName(r.hostKey, r.vm); if (h && v) onVm(h, v) }} />
      </div>
    </div>
  )
}

function Machines({ hosts, onVm }: { hosts: HvHost[]; onVm: (h: HvHost, v: HvVm) => void }) {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState<'all' | 'running' | 'stopped' | 'problems'>('all')
  const needle = q.trim().toLowerCase()
  const rows = useMemo(() => hosts.flatMap(h => h.vms.map(v => ({ h, v }))).filter(({ h, v }) =>
    (filter === 'all' || (filter === 'running' ? v.state === 'Running' : filter === 'stopped' ? v.state !== 'Running' : v.flags.length > 0 || v.tile === 'crit'))
    && (!needle || [v.name, h.name, v.state].some(s => (s ?? '').toLowerCase().includes(needle)))), [hosts, filter, needle])
  const total = hosts.reduce((n, h) => n + h.vms.length, 0)
  const exportCsv = () => {
    const lines = [['host', 'vm', 'state', 'vcpu', 'cpu_pct', 'memory_assigned_bytes', 'memory_demand_bytes', 'uptime_sec', 'heartbeat', 'checkpoints', 'replication', 'problems'].map(csvSafe).join(',')]
    for (const { h, v } of rows) lines.push([h.name, v.name, v.state, v.vcpu, v.cpu, v.memAssigned, v.memDemand, v.uptime, v.heartbeat, v.snapshots, v.replication, v.flags.join(' ')].map(csvSafe).join(','))
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }))
    a.download = 'hyperv-vms.csv'; a.click(); URL.revokeObjectURL(a.href)
  }
  const tileDot = { ok: 'bg-emerald-500', warn: 'bg-amber-400', crit: 'bg-red-500', off: 'bg-slate-300' }
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2 flex-wrap">
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('hyperv.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm flex-1 min-w-[12rem]" />
          <select value={filter} onChange={e => setFilter(e.target.value as typeof filter)} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm">
            <option value="all">{t('hyperv.filterAll')}</option><option value="running">{t('hyperv.filterRunning')}</option>
            <option value="stopped">{t('hyperv.filterStopped')}</option><option value="problems">{t('hyperv.filterProblems')}</option>
          </select>
          <Button size="sm" variant="secondary" onClick={exportCsv}><Download size={13} /> CSV</Button>
          <span className="text-xs text-slate-400">{rows.length} / {total}</span>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {rows.length === 0 ? <p className="p-5 text-sm text-slate-500">{t('hyperv.noVms')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-slate-500 border-b">
                <th className="px-4 py-2" /><th>{t('hyperv.vmName')}</th><th>{t('hyperv.host')}</th><th>{t('hyperv.state')}</th><th>vCPU</th><th>CPU</th>
                <th>{t('hyperv.memory')}</th><th>{t('hyperv.uptime')}</th><th>{t('hyperv.checkpoints')}</th><th>{t('hyperv.problems')}</th>
              </tr></thead>
              <tbody>
                {rows.map(({ h, v }) => (
                  <tr key={`${h.key}:${v.key}`} onClick={() => onVm(h, v)} className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer">
                    <td className="px-4 py-2"><i className={cn('inline-block w-2.5 h-2.5 rounded-full', tileDot[v.tile])} /></td>
                    <td className="py-2 pr-3 font-medium text-slate-800">{v.name}</td>
                    <td className="pr-3 text-slate-600">{h.name}</td>
                    <td className="pr-3"><Badge variant={stateVariant(v.state)}>{v.state ?? '—'}</Badge></td>
                    <td className="pr-3 text-slate-600">{v.vcpu ?? '—'}</td>
                    <td className="pr-3 text-slate-600">{v.cpu != null ? `${v.cpu}%` : '—'}</td>
                    <td className="pr-3 text-xs text-slate-600 whitespace-nowrap">{formatBytes(v.memDemand)} / {formatBytes(v.memAssigned)}</td>
                    <td className="pr-3 text-xs text-slate-600">{formatUptime(v.uptime)}</td>
                    <td className="pr-3 text-slate-600">{v.snapshots ?? '—'}</td>
                    <td className="pr-4 text-xs text-slate-600">{v.flags.length ? v.flags.map(f => t(`hyperv.problem.${f}`)).join(' · ') : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function ActionLog() {
  const { t } = useTranslation()
  const [open, setOpen] = useState<number | null>(null)
  const { data } = useQuery({ queryKey: ['hyperv-actions'], queryFn: () => hypervApi.actions(100), refetchInterval: 10_000 })
  const rows: HypervActionLogEntry[] = data?.actions ?? []
  return (
    <Card>
      <CardHeader><h2 className="text-sm font-semibold text-slate-700">{t('hyperv.actionLog')}</h2></CardHeader>
      <CardContent className="p-0">
        {rows.length === 0 ? <p className="p-5 text-sm text-slate-500">{t('hyperv.noActions')}</p> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-slate-500 border-b"><th className="px-4 py-2">{t('hyperv.when')}</th><th>{t('hyperv.host')}</th><th>{t('hyperv.vmName')}</th><th>{t('hyperv.actions')}</th><th>{t('hyperv.who')}</th><th>{t('hyperv.state')}</th></tr></thead>
            <tbody>
              {rows.map(a => (
                <Fragment key={a.id}>
                  <tr className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer align-top" onClick={() => setOpen(open === a.id ? null : a.id)}>
                    <td className="px-4 py-2 text-xs text-slate-600 whitespace-nowrap">{a.created_at ? new Date(a.created_at).toLocaleString() : '—'}</td>
                    <td className="pr-3 text-slate-700">{a.host_name}</td><td className="pr-3 font-medium text-slate-800">{a.vm_name}</td>
                    <td className="pr-3">{t(`hyperv.action.${a.action}`)}</td><td className="pr-3 text-slate-600">{a.created_by}</td>
                    <td className="pr-3"><Badge variant={a.status === 'ok' ? 'green' : a.status === 'error' ? 'red' : 'blue'}>{t(`hyperv.actionStatus.${a.status}`)}</Badge></td>
                  </tr>
                  {open === a.id && <tr className="bg-slate-50 border-b border-slate-100"><td colSpan={6} className="px-4 py-2 text-xs"><b>{t('hyperv.reason')}:</b> {a.reason}{a.output && a.output !== 'OK' && <pre className="mt-1 whitespace-pre-wrap text-red-700">{a.output}</pre>}</td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'board' | 'machines' | 'log'

export function HyperV() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('board')
  const [sel, setSel] = useState<{ hostKey: string; vm: HvVm } | null>(null)
  const { data, isLoading } = useQuery({ queryKey: ['hyperv-overview'], queryFn: hypervApi.overview, refetchInterval: 30_000 })
  const refresh = useMutation({
    mutationFn: hypervApi.refreshAll,
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['hyperv-overview'] }), 10_000),
  })
  const hosts: HvHost[] = useMemo(() => (data?.hosts ?? []).map((h: HypervOverviewHost) => fromLocal(h, data!.insights)), [data])
  const problems: ProblemRow[] = hosts.flatMap(h => h.problems.map(p => ({ ...p, host: h.name, hostKey: h.key })))
  const pick = (h: HvHost, v: HvVm) => setSel({ hostKey: h.key, vm: v })
  const selHost = sel ? hosts.find(h => h.key === sel.hostKey) : undefined

  const tabs: Array<[Tab, string]> = [['board', 'hyperv.tabBoard'], ['machines', 'hyperv.tabMachines'], ['log', 'hyperv.tabLog']]
  return (
    <div className="p-6 space-y-4 max-w-7xl">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Layers size={20} className="text-indigo-600" /> {t('nav.hyperv')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('hyperv.intro')}</p>
        </div>
        <div className="flex items-center gap-3">
          {data && <span className="text-xs text-slate-400">{t('hyperv.polledEvery', { min: Math.round(data.poll_sec / 60) })}</span>}
          <Button size="sm" variant="secondary" onClick={() => refresh.mutate()} disabled={refresh.isPending}>
            <RefreshCw size={13} className={refresh.isPending ? 'animate-spin' : ''} /> {t('hyperv.refresh')}
          </Button>
        </div>
      </div>

      <div className="flex gap-1 border-b border-slate-200">
        {tabs.map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)}
            className={cn('px-4 py-2 text-sm -mb-px border-b-2', tab === k ? 'border-indigo-600 text-indigo-700 font-medium' : 'border-transparent text-slate-500 hover:text-slate-800')}>
            {t(label)}
          </button>
        ))}
      </div>

      {tab === 'log' ? <ActionLog /> : isLoading || !data ? <p className="text-sm text-slate-500">{t('common.loading')}</p>
        : hosts.length === 0 ? <p className="text-sm text-slate-500">{t('hyperv.noHosts')}</p>
        : tab === 'board' ? <Board hosts={hosts} data={data} onVm={pick} selected={sel ? `${sel.hostKey}:${sel.vm.key}` : null} />
        : <Machines hosts={hosts} onVm={pick} />}

      {sel && selHost && data && (
        <VmDrawer vmRef={sel.vm} host={selHost} insights={problems} actionsEnabled={data.actions_enabled} onClose={() => setSel(null)} />
      )}
    </div>
  )
}

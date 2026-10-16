import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { assetsApi, devicesApi, fleetActionsApi, hypervApi, linuxApi, windowsApi, type AssetDetail as Detail, type AssetRow, type HypervActionKind } from '../lib/api'
import { Button } from './ui/Button'
import { Pill, TYPE_ORDER } from './AssetBits'
import { ExternalLink, Play, Power, PowerOff, RefreshCw, RotateCcw, Download, Camera, ShieldCheck, Loader2, Trash2 } from 'lucide-react'
import { cn } from '../lib/utils'

// "Akcje" tab of the asset card: the actions the agent already has for this kind of device (check / install updates and restart for
// Linux and Windows hosts, start / stop / restart / checkpoint for Hyper-V machines, firmware and reboot for Mikrotik routers),
// run from the card instead of the dedicated page. They are the same calls, with the same checks (opt-in "managed", reason required).

const ACTIVE_JOB = ['starting', 'checking', 'updating', 'upgrading', 'restarting', 'running_script']

function Section({ title, children, link }: { title: string; children: React.ReactNode; link?: { to: string; label: string } }) {
  return (
    <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
      <h3 className="px-4 py-2.5 text-sm font-semibold text-slate-800 border-b border-slate-100 flex items-center justify-between gap-2">
        {title}
        {link && <Link to={link.to} className="text-xs font-normal text-indigo-600 hover:underline inline-flex items-center gap-1">{link.label}<ExternalLink size={11} /></Link>}
      </h3>
      <div className="p-4 space-y-3">{children}</div>
    </section>
  )
}

function useAction(assetId: number) {
  const qc = useQueryClient()
  const { t } = useTranslation()
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const run = async (key: string, fn: () => Promise<any>) => {
    setBusy(key); setMsg(null)
    try {
      const r = await fn()
      if (r && typeof r === 'object' && 'error' in r && r.error) throw new Error(String(r.error))
      setMsg({ ok: true, text: t('assets.act.queued') as string })
      qc.invalidateQueries({ queryKey: ['asset', assetId] })
      qc.invalidateQueries({ queryKey: ['linux-hosts'] }); qc.invalidateQueries({ queryKey: ['windows-hosts'] })
    } catch (e: any) {
      setMsg({ ok: false, text: e?.response?.data?.detail ?? e?.message ?? String(e) })
    } finally { setBusy(null) }
  }
  return { msg, busy, run }
}

function askReason(t: (k: string) => any, promptKey: string): string | null {
  const r = window.prompt(t(promptKey) as string)
  if (r === null) return null
  if (!r.trim()) { alert(t('assets.act.reasonRequired') as string); return null }
  return r.trim()
}

function Msg({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null
  return <p className={cn('text-sm rounded-lg px-3 py-2 border', msg.ok ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-red-50 border-red-200 text-red-700')}>{msg.text}</p>
}

function Btn({ busy, k, onClick, icon, children, danger, disabled }: { busy: string | null; k: string; onClick: () => void; icon: React.ReactNode; children: React.ReactNode; danger?: boolean; disabled?: boolean }) {
  return (
    <Button size="sm" variant={danger ? 'danger' : 'secondary'} disabled={disabled || busy !== null} onClick={onClick}>
      {busy === k ? <Loader2 size={13} className="animate-spin" /> : icon} {children}
    </Button>
  )
}

// ── Linux / Windows computers ────────────────────────────────────────────────

function HostActions({ a, platform, hostId }: { a: Detail; platform: 'linux' | 'windows'; hostId: number }) {
  const { t } = useTranslation()
  const isLinux = platform === 'linux'
  const api = isLinux ? linuxApi : windowsApi
  const { data } = useQuery({
    queryKey: [`${platform}-hosts`],
    queryFn: () => (isLinux ? linuxApi.hosts() : windowsApi.hosts()) as Promise<{ hosts: any[]; enabled: boolean }>,
    refetchInterval: q => (q.state.data?.hosts.find(h => h.id === hostId)?.job?.status && ACTIVE_JOB.includes(q.state.data.hosts.find(h => h.id === hostId).job.status) ? 3000 : 30_000),
  })
  const host = data?.hosts.find(h => h.id === hostId)
  const { msg, busy, run } = useAction(a.id)
  const jobActive = !!host?.job?.status && ACTIVE_JOB.includes(host.job.status)
  const workstation = !isLinux && host?.host_type === 'workstation'
  const title = isLinux ? t('assets.act.linuxTitle') : t('assets.act.windowsTitle')

  return (
    <Section title={title as string} link={{ to: isLinux ? '/linux' : '/windows', label: t('assets.act.openPage') as string }}>
      {!host ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : (
        <>
          <div className="flex flex-wrap gap-2 items-center text-sm">
            <Pill tone={host.managed ? 'green' : 'gray'}>{host.managed ? t('assets.act.managed') : t('assets.act.notManaged')}</Pill>
            {host.upgradable_count != null && <Pill tone={host.upgradable_count > 0 ? 'amber' : 'green'}>{host.upgradable_count > 0 ? t('assets.act.updatesPending', { count: host.upgradable_count }) : t('assets.act.upToDate')}</Pill>}
            {host.reboot_required && <Pill tone="orange">{t('assets.act.rebootRequired')}</Pill>}
            {jobActive && <Pill tone="blue" icon={<Loader2 size={11} className="animate-spin" />}>{t('assets.act.jobRunning', { status: host.job.status })}</Pill>}
          </div>
          {host.job?.error && !jobActive && <p className="text-xs text-red-600 break-words">{host.job.error}</p>}
          {data && !data.enabled && <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">{t('assets.act.disabled')}</p>}
          {workstation && <p className="text-xs text-slate-500">{t('assets.act.workstationNote')}</p>}
          <div className="flex flex-wrap gap-2">
            {!host.managed && (
              <Btn busy={busy} k="manage" icon={<ShieldCheck size={13} />} onClick={() => run('manage', () => api.setManaged(hostId, true))}>{t('assets.act.enableManage')}</Btn>
            )}
            <Btn busy={busy} k="check" disabled={!host.managed || jobActive} icon={<RefreshCw size={13} />} onClick={() => run('check', () => api.check(hostId))}>{t('assets.act.check')}</Btn>
            <Btn busy={busy} k="install" disabled={!host.managed || jobActive || workstation} icon={<Download size={13} />} onClick={() => {
              if (!confirm(t('assets.act.confirmInstall', { name: a.name }) as string)) return
              if (isLinux) { run('install', () => linuxApi.upgrade(hostId)); return }
              const reason = askReason(t as any, 'assets.act.reasonPromptUpdate'); if (reason) run('install', () => windowsApi.upgrade(hostId, reason))
            }}>{t('assets.act.install')}</Btn>
            <Btn busy={busy} k="restart" danger disabled={!host.managed || jobActive} icon={<RotateCcw size={13} />} onClick={() => {
              const reason = askReason(t as any, 'assets.act.reasonPromptRestart'); if (!reason) return
              run('restart', () => api.restart(hostId, reason))
            }}>{t('assets.act.restart')}</Btn>
          </div>
          <Msg msg={msg} />
        </>
      )}
    </Section>
  )
}

// ── Hyper-V virtual machine ──────────────────────────────────────────────────

function VmActions({ a, vmId }: { a: Detail; vmId: number }) {
  const { t } = useTranslation()
  const { msg, busy, run } = useAction(a.id)
  const { data } = useQuery({ queryKey: ['hyperv-actions-enabled'], queryFn: () => hypervApi.actions(1) })
  const state = String(a.hardware.vm?.state ?? '')
  const running = /running/i.test(state)
  const off = /^off/i.test(state)
  const act = (kind: HypervActionKind, confirmKey?: string) => {
    if (confirmKey && !confirm(t(confirmKey, { name: a.name }) as string)) return
    const reason = askReason(t as any, 'assets.act.vmReasonPrompt'); if (!reason) return
    run(kind, () => hypervApi.action(vmId, { action: kind, reason }))
  }
  return (
    <Section title={t('assets.act.vmTitle') as string} link={{ to: '/hyperv', label: t('assets.act.openPage') as string }}>
      <div className="flex flex-wrap gap-2 items-center text-sm"><Pill tone={running ? 'green' : 'gray'}>{state || '—'}</Pill></div>
      {data && !data.enabled && <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">{t('assets.act.disabled')}</p>}
      <div className="flex flex-wrap gap-2">
        <Btn busy={busy} k="start" disabled={running} icon={<Play size={13} />} onClick={() => act('start')}>{t('assets.act.vmStart')}</Btn>
        <Btn busy={busy} k="shutdown" disabled={off} icon={<Power size={13} />} onClick={() => act('shutdown', 'assets.act.vmConfirmShutdown')}>{t('assets.act.vmShutdown')}</Btn>
        <Btn busy={busy} k="restart" disabled={off} icon={<RotateCcw size={13} />} onClick={() => act('restart', 'assets.act.vmConfirmRestart')}>{t('assets.act.vmRestart')}</Btn>
        <Btn busy={busy} k="checkpoint" icon={<Camera size={13} />} onClick={() => act('checkpoint')}>{t('assets.act.vmCheckpoint')}</Btn>
        <Btn busy={busy} k="poweroff" danger disabled={off} icon={<PowerOff size={13} />} onClick={() => act('poweroff', 'assets.act.vmConfirmPoweroff')}>{t('assets.act.vmPoweroff')}</Btn>
      </div>
      <Msg msg={msg} />
    </Section>
  )
}

// ── Mikrotik router ──────────────────────────────────────────────────────────

function DeviceActions({ a, deviceId }: { a: Detail; deviceId: number }) {
  const { t } = useTranslation()
  const { msg, busy, run } = useAction(a.id)
  const [backup, setBackup] = useState(true)
  const nd = a.hardware.network_device as Record<string, any> | undefined
  return (
    <Section title={t('assets.act.deviceTitle') as string} link={{ to: `/devices/${deviceId}`, label: t('assets.act.openPage') as string }}>
      {nd && (
        <div className="flex flex-wrap gap-2 items-center text-sm">
          {nd.routeros && <Pill>RouterOS {nd.routeros}</Pill>}
          {nd.latest_routeros && nd.latest_routeros !== nd.routeros && <Pill tone="amber">{t('assets.act.latest', { version: nd.latest_routeros })}</Pill>}
          {nd.firmware_available && <Pill tone="amber">{t('assets.act.firmwareAvailable', { version: nd.firmware_available })}</Pill>}
        </div>
      )}
      <label className="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" checked={backup} onChange={e => setBackup(e.target.checked)} className="rounded border-slate-300" /> {t('assets.act.fwBackup')}</label>
      <div className="flex flex-wrap gap-2">
        <Btn busy={busy} k="fwcheck" icon={<RefreshCw size={13} />} onClick={() => run('fwcheck', () => devicesApi.firmwareCheck(deviceId))}>{t('assets.act.fwCheck')}</Btn>
        <Btn busy={busy} k="fwupgrade" icon={<Download size={13} />} onClick={() => {
          if (!confirm(t('assets.act.fwConfirm', { name: a.name }) as string)) return
          run('fwupgrade', () => devicesApi.firmwareUpgrade(deviceId, backup))
        }}>{t('assets.act.fwUpgrade')}</Btn>
        <Btn busy={busy} k="reboot" danger icon={<RotateCcw size={13} />} onClick={() => {
          const reason = askReason(t as any, 'assets.act.reasonPromptRestart'); if (!reason) return
          run('reboot', () => fleetActionsApi.start({ action: 'reboot', device_ids: [deviceId], reason }))
        }}>{t('assets.act.reboot')}</Btn>
      </div>
      <Msg msg={msg} />
    </Section>
  )
}

export function hasActions(a: Detail): boolean {
  const r = a.refs ?? {}
  return !!(r.linux_host_id || r.windows_host_id || r.hyperv_vm_id || r.device_id || r.dell_server_id)
}

export function AssetActions({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const r = a.refs ?? {}
  return (
    <div className="space-y-4">
      {r.linux_host_id && <HostActions a={a} platform="linux" hostId={r.linux_host_id} />}
      {r.windows_host_id && <HostActions a={a} platform="windows" hostId={r.windows_host_id} />}
      {r.hyperv_vm_id && <VmActions a={a} vmId={r.hyperv_vm_id} />}
      {r.device_id && a.type === 'network' && a.manufacturer === 'MikroTik' && <DeviceActions a={a} deviceId={r.device_id} />}
      {r.dell_server_id && (
        <Section title={t('assets.act.dellTitle') as string} link={{ to: '/dell-servers', label: t('assets.act.openPage') as string }}>
          <p className="text-sm text-slate-600">{t('assets.act.dellNote')}</p>
        </Section>
      )}
    </div>
  )
}

// ── Bulk actions on the selected rows of the asset list ──────────────────────

/** The managed objects behind a set of assets, by kind; what is left (printers, phones, ...) has no action. */
export function partition(rows: AssetRow[]) {
  const linux: number[] = [], windows: number[] = [], routers: number[] = []
  let skipped = 0
  for (const a of rows) {
    const r = a.refs ?? {}
    if (r.linux_host_id) linux.push(r.linux_host_id)
    else if (r.windows_host_id) windows.push(r.windows_host_id)
    else if (r.device_id && a.type === 'network' && a.manufacturer === 'MikroTik') routers.push(r.device_id)
    else skipped++
  }
  return { linux, windows, routers, skipped }
}

export function AssetBulkBar({ rows, onClear, total, onSelectAll }: { rows: AssetRow[]; onClear: () => void; total?: number; onSelectAll?: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const p = partition(rows)
  const [stagger, setStagger] = useState(60)
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [newType, setNewType] = useState('')
  const done = (queued: number) => { setMsg({ ok: true, text: t('assets.bulk.queued', { count: queued }) as string }); qc.invalidateQueries({ queryKey: ['linux-hosts'] }); qc.invalidateQueries({ queryKey: ['windows-hosts'] }) }
  const fail = (e: any) => setMsg({ ok: false, text: e?.response?.data?.detail ?? e?.message ?? String(e) })
  const reason = (key: string) => askReason(t as any, key)

  const install = async () => {
    if (!confirm(t('assets.bulk.confirmInstall', { linux: p.linux.length, windows: p.windows.length }) as string)) return
    let why = ''
    if (p.windows.length) { const r = reason('assets.act.reasonPromptUpdate'); if (!r) return; why = r }
    setBusy('install'); setMsg(null)
    try {
      let n = 0
      if (p.linux.length) n += (await linuxApi.upgradeBulk(p.linux)).queued ?? 0
      if (p.windows.length) n += (await windowsApi.upgradeBulk(p.windows, why)).queued ?? 0
      done(n)
    } catch (e) { fail(e) } finally { setBusy(null) }
  }
  const restart = async () => {
    if (!confirm(t('assets.bulk.confirmRestart', { count: p.linux.length + p.windows.length + p.routers.length, seconds: stagger }) as string)) return
    const why = reason('assets.act.reasonPromptRestart'); if (!why) return
    setBusy('restart'); setMsg(null)
    try {
      let n = 0
      if (p.linux.length) n += (await linuxApi.restartBulk({ ids: p.linux, reason: why, stagger_sec: stagger })).queued ?? 0
      if (p.windows.length) n += (await windowsApi.restartBulk({ ids: p.windows, reason: why, stagger_sec: stagger })).queued ?? 0
      if (p.routers.length) { await fleetActionsApi.start({ action: 'reboot', device_ids: p.routers, reason: why }); n += p.routers.length }
      done(n)
    } catch (e) { fail(e) } finally { setBusy(null) }
  }
  const refreshAssets = () => { qc.invalidateQueries({ queryKey: ['assets'] }); qc.invalidateQueries({ queryKey: ['asset-summary'] }) }
  const ids = rows.map(r => r.id)
  const changeType = async () => {
    if (!newType) return
    setBusy('type'); setMsg(null)
    try { const r = await assetsApi.bulkType(ids, newType); refreshAssets(); setMsg({ ok: true, text: t('assets.bulk.typeChanged', { count: r.changed }) as string }) }
    catch (e) { fail(e) } finally { setBusy(null) }
  }
  const remove = async () => {
    if (!confirm(t('assets.bulk.confirmDelete', { count: ids.length }) as string)) return
    setBusy('delete'); setMsg(null)
    try {
      const r = await assetsApi.bulkDelete(ids); refreshAssets(); onClear()
      window.alert((t('assets.bulk.deleted', { count: r.deleted }) as string) + (r.managed ? ' ' + (t('assets.bulk.deletedManaged', { count: r.managed }) as string) : ''))
    } catch (e) { fail(e) } finally { setBusy(null) }
  }
  const actionable = p.linux.length + p.windows.length + p.routers.length

  return (
    <div className="bg-indigo-50 border border-indigo-200 rounded-xl px-4 py-3 space-y-2">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="font-semibold text-indigo-900">{t('assets.bulk.selected', { count: rows.length })}</span>
        <span className="text-xs text-indigo-800">{t('assets.bulk.breakdown', { linux: p.linux.length, windows: p.windows.length, routers: p.routers.length, skipped: p.skipped })}</span>
        <span className="flex-1" />
        <label className="text-xs text-indigo-900 inline-flex items-center gap-1.5">{t('assets.bulk.stagger')}
          <select value={stagger} onChange={e => setStagger(Number(e.target.value))} className="border border-indigo-200 rounded px-1.5 py-1 bg-white">
            {[0, 30, 60, 300, 600].map(sec => <option key={sec} value={sec}>{sec === 0 ? t('assets.bulk.noStagger') : t('assets.bulk.seconds', { count: sec })}</option>)}
          </select>
        </label>
        <Btn busy={busy} k="install" disabled={p.linux.length + p.windows.length === 0} icon={<Download size={13} />} onClick={install}>{t('assets.act.install')}</Btn>
        <Btn busy={busy} k="restart" danger disabled={actionable === 0} icon={<RotateCcw size={13} />} onClick={restart}>{t('assets.act.restart')}</Btn>
        <button className="text-xs text-indigo-700 hover:underline" onClick={onClear}>{t('assets.bulk.clear')}</button>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="text-xs text-indigo-900 inline-flex items-center gap-1.5">{t('assets.bulk.setType')}
          <select value={newType} onChange={e => setNewType(e.target.value)} className="border border-indigo-200 rounded px-1.5 py-1 bg-white">
            <option value="">—</option>
            <option value="auto">{t('assets.bulk.typeAuto')}</option>
            {TYPE_ORDER.map(k => <option key={k} value={k}>{t(`assets.type.${k}`)}</option>)}
          </select>
        </label>
        <Btn busy={busy} k="type" disabled={!newType} icon={<RefreshCw size={13} />} onClick={changeType}>{t('assets.bulk.apply')}</Btn>
        <Btn busy={busy} k="delete" danger icon={<Trash2 size={13} />} onClick={remove}>{t('assets.bulk.delete')}</Btn>
        {onSelectAll && total != null && total > rows.length && <button className="text-xs text-indigo-700 hover:underline" onClick={onSelectAll}>{t('assets.bulk.selectAll', { count: total })}</button>}
      </div>
      <Msg msg={msg} />
    </div>
  )
}

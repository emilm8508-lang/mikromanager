import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  centralApi, type CentralLinuxHostStatus, type CentralWindowsHostStatus, type CentralHostDiskStatus, type HostGroupOut,
} from '../lib/api'
import {
  SrvSummary, SrvSectionView, GroupActionModal, HostDrawer, buildSections, type SrvHost, type SrvSection, type SrvPlatform, type GroupActionRequest,
} from './ServerBoard'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { Download, Power } from 'lucide-react'
import { formatBytes } from '../lib/utils'

// Central's Linux / Windows server board: the same look as the agent's page (summary strip, tiles, groups), fed by the
// redacted host summaries the agents send. Groups are the agent's own (read-only here). From Central a server can be
// updated or restarted one at a time (as before), and a group can be updated (queued per server); restarting a whole
// group stays local to the agent, where it can be staggered.

// the agent sends naive UTC timestamps
const utc = (s: string | null | undefined) => (s ? (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`) : null)
const maxPct = (disks: CentralHostDiskStatus[] | undefined) => {
  const v = (disks ?? []).map(d => d.pct).filter((x): x is number => x != null)
  return v.length ? Math.max(...v) : null
}

type Row<H> = { tenant: string; host: H }

export function CentralServerBoard({ platform, tenantFilter, onTenants }: { platform: SrvPlatform; tenantFilter: string; onTenants?: (tenants: string[]) => void }) {
  const { t } = useTranslation()
  const isLinux = platform === 'linux'
  const [rows, setRows] = useState<Array<Row<CentralLinuxHostStatus | CentralWindowsHostStatus>>>([])
  const [manage, setManage] = useState<Record<string, boolean>>({})
  const [pendingUp, setPendingUp] = useState<Set<string>>(new Set())
  const [pendingRs, setPendingRs] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [open, setOpen] = useState<{ tenant: string; id: number } | null>(null)
  const [action, setAction] = useState<SrvSection | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const reload = async () => {
    try {
      if (isLinux) {
        const [s, pu, pr] = await Promise.all([centralApi.linuxHostsStatusAll(), centralApi.pendingLinuxAptUpgrades(), centralApi.pendingLinuxRestarts()])
        setRows(s.tenants.flatMap(tr => tr.linux_hosts.map(h => ({ tenant: tr.tenant, host: h }))))
        onTenants?.(s.tenants.filter(tr => tr.linux_hosts.length).map(tr => tr.tenant))
        setPendingUp(new Set((pu.pending ?? []).map(p => `${p.tenant}:${p.host_id}`)))
        setPendingRs(new Set((pr.pending ?? []).map(p => `${p.tenant}:${p.host_id}`)))
      } else {
        const [s, pu, pr] = await Promise.all([centralApi.windowsHostsStatusAll(), centralApi.pendingWindowsUpdates(), centralApi.pendingWindowsRestarts()])
        setRows(s.tenants.flatMap(tr => tr.windows_hosts.map(h => ({ tenant: tr.tenant, host: h }))))
        onTenants?.(s.tenants.filter(tr => tr.windows_hosts.length).map(tr => tr.tenant))
        setManage(Object.fromEntries(s.tenants.map(tr => [tr.tenant, tr.manage_enabled])))
        setPendingUp(new Set((pu.pending ?? []).map(p => `${p.tenant}:${p.host_id}`)))
        setPendingRs(new Set((pr.pending ?? []).map(p => `${p.tenant}:${p.host_id}`)))
      }
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => {
    reload()
    const iv = setInterval(reload, 30000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [platform])

  const vis = useMemo(() => rows.filter(r => tenantFilter === 'all' || r.tenant === tenantFilter), [rows, tenantFilter])

  // the agent's group names, turned into groups with an id of our own (one per client and name)
  const { hosts, groups } = useMemo(() => {
    const ids = new Map<string, number>()
    const gs: HostGroupOut[] = []
    const out: SrvHost[] = vis.map(({ tenant, host }) => {
      let groupId: number | null = null
      if (host.group) {
        const k = `${tenant}\u0000${host.group}`
        if (!ids.has(k)) { ids.set(k, ids.size + 1); gs.push({ id: ids.size, name: `${tenant} · ${host.group}`, hosts: 0 }) }
        groupId = ids.get(k)!
      }
      const lh = host as CentralLinuxHostStatus, wh = host as CentralWindowsHostStatus
      const workstation = !isLinux && wh.host_type === 'workstation'
      return {
        id: host.id, tenant, name: host.hostname || host.ip, ip: host.ip,
        os: isLinux ? lh.distro_pretty : wh.os_name, domain: isLinux ? null : wh.domain ?? null, distroId: isLinux ? lh.distro_id ?? null : null,
        managed: true, pending: false, workstation,
        actionable: isLinux ? lh.package_manager == null || lh.package_manager === 'apt' || lh.package_manager === 'dnf' : !workstation && (manage[tenant] ?? false),
        groupId, cpu: host.cpu_used_pct, mem: host.mem_used_pct, disk: maxPct(host.disks),
        upgradable: host.upgradable_count, reboot: host.reboot_required,
        status: (host.last_status as SrvHost['status']) ?? null, error: null, lastCheck: utc(host.last_check_at), job: null,
      }
    })
    return { hosts: out, groups: gs }
  }, [vis, isLinux, manage])

  const sections = useMemo(() => buildSections(hosts, groups, platform, t as any), [hosts, groups, platform, t])
  const selHost = open ? hosts.find(h => h.tenant === open.tenant && h.id === open.id) : undefined
  const selRaw = open ? vis.find(r => r.tenant === open.tenant && r.host.id === open.id)?.host : undefined

  const update = async (tenant: string, hostId: number) => {
    let reason = ''
    if (!isLinux) {
      const r = window.prompt(t('windowsCentral.reasonPromptUpdate') as string)
      if (r === null) return
      if (!r.trim()) { alert(t('windowsCentral.reasonRequired') as string); return }
      reason = r.trim()
    }
    setBusy(`${tenant}:${hostId}`)
    try { await (isLinux ? centralApi.requestLinuxAptUpgrade(tenant, hostId) : centralApi.requestWindowsUpdate(tenant, hostId, reason)); await reload() }
    catch (e) { alert((e as Error).message) } finally { setBusy(null) }
  }
  const restart = async (tenant: string, hostId: number) => {
    const r = window.prompt(t(isLinux ? 'linuxCentral.reasonPromptRestart' : 'windowsCentral.reasonPromptRestart') as string)
    if (r === null) return
    if (!r.trim()) { alert(t(isLinux ? 'linuxCentral.reasonRequired' : 'windowsCentral.reasonRequired') as string); return }
    setBusy(`${tenant}:${hostId}`)
    try { await (isLinux ? centralApi.requestLinuxRestart(tenant, hostId, r.trim()) : centralApi.requestWindowsRestart(tenant, hostId, r.trim())); await reload() }
    catch (e) { alert((e as Error).message) } finally { setBusy(null) }
  }
  const runGroup = async (req: GroupActionRequest) => {
    const tenant = action?.hosts[0]?.tenant
    if (!tenant) return
    for (const id of req.ids) {
      if (isLinux) await centralApi.requestLinuxAptUpgrade(tenant, id)
      else await centralApi.requestWindowsUpdate(tenant, id, req.reason)
    }
    await reload()
  }

  if (loading) return <p className="text-sm text-slate-500">{t('common.loading')}</p>
  if (hosts.length === 0) return <p className="text-sm text-slate-500">{t(isLinux ? 'linuxCentral.noHosts' : 'windowsCentral.noHosts')}</p>

  const key = open ? `${open.tenant}:${open.id}` : ''
  return (
    <div className="space-y-4">
      {err && <div className="text-sm text-red-600">{err}</div>}
      <SrvSummary hosts={hosts} />
      {sections.map(sec => (
        <SrvSectionView key={sec.key} section={sec} selected={new Set()} showRestart={false}
          enabled={isLinux || (manage[sec.hosts[0]?.tenant ?? ''] ?? false)} onOpen={h => setOpen({ tenant: h.tenant!, id: h.id })}
          onAction={(_kind, section) => setAction(section)} />
      ))}

      {selHost && selRaw && (
        <HostDrawer host={selHost} onClose={() => setOpen(null)}>
          <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-3 text-sm">
            <div className="flex flex-wrap gap-1.5">
              <Badge variant="gray">{selHost.tenant}</Badge>
              <span className="font-mono text-xs text-slate-500 self-center">{selHost.ip}</span>
              {selHost.os && <Badge variant="blue">{selHost.os}</Badge>}
              {selHost.upgradable != null && (selHost.upgradable > 0 ? <Badge variant="yellow">{t(isLinux ? 'linux.upgradableCount' : 'windows.upgradableCount', { count: selHost.upgradable })}</Badge> : <Badge variant="green">{t('serverBoard.upToDate')}</Badge>)}
              {selHost.reboot && <Badge variant="red">{t('serverBoard.rebootShort')}</Badge>}
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <dt className="text-slate-400">CPU</dt><dd>{selHost.cpu != null ? `${Math.round(selHost.cpu)}%` : '—'}</dd>
              <dt className="text-slate-400">RAM</dt><dd>{selHost.mem != null ? `${Math.round(selHost.mem)}%` : '—'}{(selRaw.mem_total_bytes ?? 0) > 0 ? ` · ${formatBytes(selRaw.mem_total_bytes)}` : ''}</dd>
              <dt className="text-slate-400">{t('linux.lastCheck')}</dt><dd>{selHost.lastCheck ? new Date(selHost.lastCheck).toLocaleString() : '—'}</dd>
              <dt className="text-slate-400">{t('linux.lastUpgrade')}</dt><dd>{selRaw.last_upgrade_at ? new Date(utc(selRaw.last_upgrade_at)!).toLocaleString() : '—'}</dd>
            </dl>
            {(selRaw.disks ?? []).length > 0 && (
              <ul className="text-xs space-y-1">
                {selRaw.disks.map((d, i) => (
                  <li key={i} className="flex items-center gap-2"><span className="w-16 font-mono text-slate-600 truncate">{d.mount_point ?? d.drive_letter}</span>
                    <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden"><div className="h-full rounded-full" style={{ width: `${Math.min(100, d.pct ?? 0)}%`, background: (d.pct ?? 0) >= 90 ? '#ef4444' : (d.pct ?? 0) >= 75 ? '#f59e0b' : '#10b981' }} /></div>
                    <span className="w-24 text-right text-slate-500">{d.pct ?? '—'}% · {formatBytes(d.total_bytes)}</span></li>
                ))}
              </ul>
            )}
            {selHost.workstation ? <p className="text-xs text-slate-400">{t('windows.workstationOnlyNote')}</p> : !selHost.actionable ? (
              <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1.5">{t('serverBoard.central.manageOff')}</p>
            ) : (
              <div className="flex gap-2 flex-wrap">
                {pendingUp.has(key) ? <Badge variant="yellow">{t('serverBoard.central.queued')}</Badge>
                  : <Button size="sm" variant="danger" disabled={busy === key} onClick={() => update(open!.tenant, open!.id)}><Download size={12} /> {t(isLinux ? 'linuxCentral.upgradeNow' : 'windowsCentral.updateNow')}</Button>}
                {pendingRs.has(key) ? <Badge variant="yellow">{t('serverBoard.central.queued')}</Badge>
                  : <Button size="sm" variant="danger" disabled={busy === key} onClick={() => restart(open!.tenant, open!.id)}><Power size={12} /> {t(isLinux ? 'linuxCentral.restartNow' : 'windowsCentral.restartNow')}</Button>}
              </div>
            )}
            <p className="text-[11px] text-slate-400">{t('serverBoard.central.delay')}</p>
          </div>
        </HostDrawer>
      )}

      {action && (
        <GroupActionModal kind="upgrade" section={action} platform={platform} footnote={t('serverBoard.central.groupNote') as string}
          onClose={() => setAction(null)} onRun={runGroup} />
      )}
    </div>
  )
}

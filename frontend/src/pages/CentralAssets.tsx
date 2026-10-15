import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type AssetsPublicRow, type AssetType, type CentralVulnFinding, type HypervActionKind } from '../lib/api'
import { Widget, Empty, Donut, NumberTiles, OTHER, type Seg } from '../components/SecCharts'
import { Button } from '../components/ui/Button'
import { TypeIcon, TYPE_COLOR, TYPE_ORDER, TypePill, VulnPill, LifecyclePill, ScanLevelPill, Pill } from '../components/AssetBits'
import { SeverityPill } from '../components/VulnViews'
import { Boxes, ArrowUp, ArrowDown, X, Download, RotateCcw, Loader2, Play, Power, PowerOff, Camera } from 'lucide-react'
import { cn } from '../lib/utils'

type Part = { tenant: string; lastSeen: string | null; assets: NonNullable<Awaited<ReturnType<typeof centralApi.assetsStatusAll>>['tenants'][number]['assets']> }
type Row = AssetsPublicRow & { tenant: string }
const LC_ORDER: Record<string, number> = { eol: 0, ending: 1, supported: 2, unknown: 3 }
const PAGE = 50

const ago = (epoch: number | null) => {
  if (!epoch) return '—'
  const min = Math.max(0, Math.round((Date.now() / 1000 - epoch) / 60))
  return min < 90 ? `${min} min` : min < 2880 ? `${Math.round(min / 60)} h` : `${Math.round(min / 1440)} d`
}

// Drawer with what Central knows about one device and the commands it may send to the agent for it (the same ones as on the
// server boards: updates and restart for Linux / Windows hosts, firmware for Mikrotik routers). A command is queued at Central and
// the agent carries it out on its next synchronisation.
function AssetDrawer({ row, onClose }: { row: Row; onClose: () => void }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [backup, setBackup] = useState(true)
  const x = row.x
  const [findings, setFindings] = useState<CentralVulnFinding[] | null>(null)
  useEffect(() => {
    let live = true
    centralApi.vulnFindingsStatusAll().then(r => {
      if (!live) return
      const host = r.tenants.find(tn => tn.tenant === row.tenant)?.hosts?.find(h => h.ip === row.ip)
      setFindings(host?.findings ?? [])
    }).catch(() => live && setFindings([]))
    return () => { live = false }
  }, [row.tenant, row.ip])
  const send = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key); setMsg(null)
    try { await fn(); setMsg({ ok: true, text: t('assetsCentral.requested') as string }) }
    catch (e) { setMsg({ ok: false, text: (e as Error).message }) }
    finally { setBusy(null) }
  }
  const reasonFor = (key: string) => {
    const r = window.prompt(t(key) as string)
    if (r === null) return null
    if (!r.trim()) { alert(t('assets.act.reasonRequired') as string); return null }
    return r.trim()
  }
  const fact = (label: string, value: React.ReactNode) => (
    <div className="grid grid-cols-5 border-b border-slate-100 last:border-0"><dt className="col-span-2 px-3 py-2 text-sm font-semibold text-slate-800">{label}</dt><dd className="col-span-3 px-3 py-2 text-sm text-slate-700 break-words">{value ?? '—'}</dd></div>
  )
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-900/30" onClick={onClose}>
      <div className="w-full max-w-lg h-full bg-slate-50 shadow-2xl overflow-y-auto p-4 space-y-3" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-lg font-semibold text-slate-900 truncate inline-flex items-center gap-2"><TypeIcon type={row.t as AssetType} size={20} />{row.n}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-800" aria-label="close"><X size={18} /></button>
        </div>
        <dl className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          {fact(t('assetsCentral.client') as string, row.tenant)}
          {fact(t('assets.colIp') as string, <span className="font-mono">{row.ip ?? '—'}</span>)}
          {fact(t('assets.colType') as string, <TypePill type={row.t} role={row.r} />)}
          {fact(t('assets.manufacturer') as string, [row.mf, row.md].filter(Boolean).join(' · ') || null)}
          {fact(t('assets.osVersion') as string, row.os)}
          {fact(t('assets.colLifecycle') as string, <LifecyclePill status={row.lc} />)}
          {fact(t('assets.colVulns') as string, row.v.some(n => n > 0) ? <VulnPill v={{ critical: row.v[0], high: row.v[1], medium: row.v[2], low: row.v[3], total: row.v[0] + row.v[1] + row.v[2] + row.v[3] }} /> : <span className="text-emerald-700">{t('assets.noVulns')}</span>)}
          {fact(t('assets.colLocation') as string, row.loc)}
          {fact(t('assets.colScan') as string, <ScanLevelPill level={row.sl} />)}
          {fact(t('assets.colLastSeen') as string, ago(row.seen))}
        </dl>
        <p className="text-[11px] text-slate-400">{t('assetsCentral.drawerNote')}</p>

        {findings && findings.length > 0 && (
          <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
            <h4 className="px-4 py-2.5 text-sm font-semibold text-slate-800 border-b border-slate-100">{t('assetsCentral.findingsTitle')} ({findings.length})</h4>
            <ul className="divide-y divide-slate-100 max-h-64 overflow-y-auto">
              {findings.map(f => (
                <li key={`${f.cve_id}:${f.product}:${f.version}`} className="px-4 py-2 text-sm flex items-center gap-2">
                  <SeverityPill severity={f.severity} />
                  <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer" className="font-mono text-xs text-blue-600 hover:underline">{f.cve_id}</a>
                  <span className="text-xs text-slate-500 truncate">{f.product} {f.version}</span>
                  <span className="ml-auto text-xs text-slate-400 shrink-0">{f.cvss_score ?? ''}</span>
                </li>
              ))}
            </ul>
            <p className="px-4 py-1.5 text-[11px] text-slate-400">{t('assetsCentral.findingsNote')}</p>
          </section>
        )}

        <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
          <h4 className="px-4 py-2.5 text-sm font-semibold text-slate-800 border-b border-slate-100">{t('assetsCentral.actionsTitle')}</h4>
          <div className="p-4 space-y-3">
            {!x && <p className="text-sm text-slate-500">{t('assetsCentral.noActions')}</p>}
            {x && (x.k === 'linux' || x.k === 'windows') && (
              <>
                <div className="flex flex-wrap gap-2 text-sm">
                  <Pill tone={x.m ? 'green' : 'gray'}>{x.m ? t('assets.act.managed') : t('assets.act.notManaged')}</Pill>
                  {x.u != null && <Pill tone={x.u > 0 ? 'amber' : 'green'}>{x.u > 0 ? t('assets.act.updatesPending', { count: x.u }) : t('assets.act.upToDate')}</Pill>}
                  {x.rb && <Pill tone="orange">{t('assets.act.rebootRequired')}</Pill>}
                </div>
                {!x.m && <p className="text-xs text-slate-500">{t('assetsCentral.needManage')}</p>}
                {x.ws && <p className="text-xs text-slate-500">{t('assets.act.workstationNote')}</p>}
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="secondary" disabled={!x.m || x.ws || busy !== null} onClick={() => {
                    if (!confirm(t('assets.act.confirmInstall', { name: row.n }) as string)) return
                    if (x.k === 'linux') { send('install', () => centralApi.requestLinuxAptUpgrade(row.tenant, x.id)); return }
                    const reason = reasonFor('assets.act.reasonPromptUpdate'); if (reason) send('install', () => centralApi.requestWindowsUpdate(row.tenant, x.id, reason))
                  }}>{busy === 'install' ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />} {t('assets.act.install')}</Button>
                  <Button size="sm" variant="danger" disabled={!x.m || busy !== null} onClick={() => {
                    const reason = reasonFor('assets.act.reasonPromptRestart'); if (!reason) return
                    send('restart', () => x.k === 'linux' ? centralApi.requestLinuxRestart(row.tenant, x.id, reason) : centralApi.requestWindowsRestart(row.tenant, x.id, reason))
                  }}>{busy === 'restart' ? <Loader2 size={13} className="animate-spin" /> : <RotateCcw size={13} />} {t('assets.act.restart')}</Button>
                </div>
              </>
            )}
            {x && x.k === 'vm' && (
              <>
                <div className="flex flex-wrap gap-2 text-sm"><Pill tone={/running/i.test(x.st ?? '') ? 'green' : 'gray'}>{x.st || '—'}</Pill></div>
                <div className="flex flex-wrap gap-2">
                  {([['start', Play, 'vmStart', null], ['shutdown', Power, 'vmShutdown', 'vmConfirmShutdown'], ['restart', RotateCcw, 'vmRestart', 'vmConfirmRestart'], ['checkpoint', Camera, 'vmCheckpoint', null], ['poweroff', PowerOff, 'vmPoweroff', 'vmConfirmPoweroff']] as const).map(([kind, Icon, label, conf]) => {
                    const running = /running/i.test(x.st ?? ''), off = /^off/i.test(x.st ?? '')
                    const disabled = busy !== null || (kind === 'start' ? running : (kind === 'checkpoint' ? false : off))
                    return (
                      <Button key={kind} size="sm" variant={kind === 'poweroff' ? 'danger' : 'secondary'} disabled={disabled} onClick={() => {
                        if (conf && !confirm(t(`assets.act.${conf}`, { name: row.n }) as string)) return
                        const reason = reasonFor('assets.act.vmReasonPrompt'); if (!reason) return
                        send(kind, () => centralApi.requestHypervVmAction(row.tenant, x.id, kind as HypervActionKind, reason))
                      }}>{busy === kind ? <Loader2 size={13} className="animate-spin" /> : <Icon size={13} />} {t(`assets.act.${label}`)}</Button>
                    )
                  })}
                </div>
              </>
            )}
            {x && x.k === 'device' && (
              <>
                <label className="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" checked={backup} onChange={e => setBackup(e.target.checked)} className="rounded border-slate-300" /> {t('assets.act.fwBackup')}</label>
                <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => {
                  if (!confirm(t('assets.act.fwConfirm', { name: row.n }) as string)) return
                  send('fw', () => centralApi.requestFirmwareUpgrade(row.tenant, x.id, backup))
                }}>{busy === 'fw' ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />} {t('assets.act.fwUpgrade')}</Button>
                <Button size="sm" variant="danger" disabled={busy !== null} onClick={() => {
                  const reason = reasonFor('assets.act.reasonPromptRestart'); if (!reason) return
                  send('reboot', () => centralApi.requestDeviceReboot(row.tenant, x.id, reason))
                }}>{busy === 'reboot' ? <Loader2 size={13} className="animate-spin" /> : <RotateCcw size={13} />} {t('assets.act.reboot')}</Button>
              </>
            )}
            {msg && <p className={cn('text-sm rounded-lg px-3 py-2 border', msg.ok ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-red-50 border-red-200 text-red-700')}>{msg.text}</p>}
          </div>
        </section>
      </div>
    </div>
  )
}

const rowKey = (r: Row) => `${r.tenant}:${r.x?.k}:${r.x?.id}`
const bulkable = (r: Row) => !!r.x && (r.x.k === 'linux' || r.x.k === 'windows' || r.x.k === 'device')

// Bulk bar for the selected rows (any mix of clients): the same commands as the drawer, one per device. Central queues them; every agent
// then applies its own checks, so a host that is not managed there (or a workstation) simply does nothing.
function CentralBulkBar({ rows, onClear }: { rows: Row[]; onClear: () => void }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const count = (k: string) => rows.filter(r => r.x?.k === k).length
  const tenants = new Set(rows.map(r => r.tenant)).size
  const run = async (key: 'install' | 'restart') => {
    const targets = rows.filter(r => r.x && (key === 'restart' ? true : r.x.k !== 'device' && !r.x.ws && r.x.m))
    if (targets.length === 0) { setMsg({ ok: false, text: t('assetsCentral.bulkNothing') as string }); return }
    if (!confirm(t(key === 'install' ? 'assetsCentral.bulkConfirmInstall' : 'assetsCentral.bulkConfirmRestart', { count: targets.length, clients: tenants }) as string)) return
    const needReason = key === 'restart' || targets.some(r => r.x!.k === 'windows')
    let reason = ''
    if (needReason) {
      const r = window.prompt(t(key === 'restart' ? 'assets.act.reasonPromptRestart' : 'assets.act.reasonPromptUpdate') as string)
      if (r === null) return
      if (!r.trim()) { alert(t('assets.act.reasonRequired') as string); return }
      reason = r.trim()
    }
    setBusy(key); setMsg(null)
    let ok = 0; const errors: string[] = []
    for (const r of targets) {
      const x = r.x!
      try {
        if (key === 'install') await (x.k === 'linux' ? centralApi.requestLinuxAptUpgrade(r.tenant, x.id) : centralApi.requestWindowsUpdate(r.tenant, x.id, reason))
        else if (x.k === 'linux') await centralApi.requestLinuxRestart(r.tenant, x.id, reason)
        else if (x.k === 'windows') await centralApi.requestWindowsRestart(r.tenant, x.id, reason)
        else await centralApi.requestDeviceReboot(r.tenant, x.id, reason)
        ok++
      } catch (e) { errors.push(`${r.n}: ${(e as Error).message}`) }
    }
    setMsg({ ok: errors.length === 0, text: `${t('assetsCentral.bulkQueued', { count: ok })}${errors.length ? ` ${errors.slice(0, 3).join('; ')}` : ''}` })
    setBusy(null)
  }
  return (
    <div className="bg-indigo-50 border border-indigo-200 rounded-xl px-4 py-3 space-y-2">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="font-semibold text-indigo-900">{t('assets.bulk.selected', { count: rows.length })}</span>
        <span className="text-xs text-indigo-800">Linux {count('linux')} · Windows {count('windows')} · Mikrotik {count('device')} · {tenants} {t('assetsCentral.bulkClients')}</span>
        <span className="flex-1" />
        <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => run('install')}>{busy === 'install' ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />} {t('assets.act.install')}</Button>
        <Button size="sm" variant="danger" disabled={busy !== null} onClick={() => run('restart')}>{busy === 'restart' ? <Loader2 size={13} className="animate-spin" /> : <RotateCcw size={13} />} {t('assets.act.restart')}</Button>
        <button className="text-xs text-indigo-700 hover:underline" onClick={onClear}>{t('assets.bulk.clear')}</button>
      </div>
      {msg && <p className={cn('text-sm rounded-lg px-3 py-2 border', msg.ok ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-red-50 border-red-200 text-red-700')}>{msg.text}</p>}
    </div>
  )
}

// The asset inventory of every client at once. Central only ever gets numbers and compact rows (no serial numbers, MAC addresses
// or hardware details), so this page has no device cards - those are on the agent.
export function CentralAssets() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [parts, setParts] = useState<Part[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenant, setTenant] = useState('all')
  const [q, setQ] = useState('')
  const [type, setType] = useState('all')
  const [lifecycle, setLifecycle] = useState('all')
  const [vuln, setVuln] = useState('all')
  const [level, setLevel] = useState('all')
  const tableRef = useRef<HTMLElement>(null)
  const [selected, setSelected] = useState<Row | null>(null)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const pick = (f: { type?: string; lifecycle?: string; vuln?: string; level?: string }) => {
    setType(f.type ?? 'all'); setLifecycle(f.lifecycle ?? 'all'); setVuln(f.vuln ?? 'all'); setLevel(f.level ?? 'all'); setQ('')
    setTimeout(() => tableRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
  }
  const [page, setPage] = useState(0)

  const reload = async () => {
    try {
      const r = await centralApi.assetsStatusAll()
      setParts(r.tenants.filter(x => x.assets && !Array.isArray(x.assets)).map(x => ({ tenant: x.tenant, lastSeen: x.last_seen, assets: x.assets! })))
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    reload()
    const iv = setInterval(reload, 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const vis = useMemo(() => parts.filter(p => tenant === 'all' || p.tenant === tenant), [parts, tenant])
  const agg = useMemo(() => {
    const sum = (f: (s: Part['assets']['summary']) => number) => vis.reduce((n, p) => n + f(p.assets.summary), 0)
    const types = new Map<string, number>()
    vis.forEach(p => p.assets.summary.by_type.forEach(x => types.set(x.key, (types.get(x.key) ?? 0) + x.n)))
    return {
      total: sum(s => s.total), then: sum(s => s.total_7d_ago), fresh: sum(s => s.new_7d), inactive: sum(s => s.inactive), types,
      lc: { supported: sum(s => s.by_lifecycle.supported), ending: sum(s => s.by_lifecycle.ending), eol: sum(s => s.by_lifecycle.eol), unknown: sum(s => s.by_lifecycle.unknown) },
      sl: { credentialed: sum(s => s.by_scan_level.credentialed), snmp: sum(s => s.by_scan_level.snmp), passive: sum(s => s.by_scan_level.passive) },
      v: { assets: sum(s => s.vulnerable.assets), critical: sum(s => s.vulnerable.critical), high: sum(s => s.vulnerable.high) },
    }
  }, [vis])

  const rows: Row[] = useMemo(() => vis.flatMap(p => p.assets.rows.map(r => ({ ...r, tenant: p.tenant }))), [vis])
  const needle = q.trim().toLowerCase()
  const shown = useMemo(() => rows.filter(r =>
    (type === 'all' || r.t === type) && (lifecycle === 'all' || r.lc === lifecycle) && (level === 'all' || r.sl === level)
    && (vuln === 'all' || (vuln === 'any' ? r.v.some(x => x > 0) : r.v.every(x => x === 0)))
    && (!needle || [r.n, r.ip, r.mf, r.md, r.os, r.loc, r.tenant].some(v => (v ?? '').toLowerCase().includes(needle))))
    .sort((a, b) => (b.v[0] - a.v[0]) || (b.v[1] - a.v[1]) || (LC_ORDER[a.lc] - LC_ORDER[b.lc]) || a.n.localeCompare(b.n)), [rows, type, lifecycle, vuln, level, needle])
  useEffect(() => setPage(0), [tenant, q, type, lifecycle, vuln, level])
  const pickedRows = useMemo(() => rows.filter(r => bulkable(r) && picked.has(rowKey(r))), [rows, picked])

  if (!cfg) {
    return <div className="p-6 max-w-5xl"><div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">{t('alerts.needsCentral')}</div></div>
  }

  const typeSegs: Seg[] = TYPE_ORDER.filter(k => (agg.types.get(k) ?? 0) > 0).map(k => ({ key: k, label: t(`assets.type.${k}`) as string, value: agg.types.get(k)!, color: TYPE_COLOR[k] }))
  const lifecycleSegs: Seg[] = [
    { key: 'supported', label: t('assets.lifecycle.supported') as string, value: agg.lc.supported, color: '#0ca30c' },
    { key: 'ending', label: t('assets.lifecycle.ending') as string, value: agg.lc.ending, color: '#fab219' },
    { key: 'eol', label: t('assets.lifecycle.eol') as string, value: agg.lc.eol, color: '#d03b3b' },
    { key: 'unknown', label: t('assets.lifecycle.unknown') as string, value: agg.lc.unknown, color: OTHER },
  ]
  const scanSegs: Seg[] = [
    { key: 'credentialed', label: t('assets.scanLevel.credentialed') as string, value: agg.sl.credentialed, color: '#0ca30c' },
    { key: 'snmp', label: t('assets.scanLevel.snmp') as string, value: agg.sl.snmp, color: '#2a78d6' },
    { key: 'passive', label: t('assets.scanLevel.passive') as string, value: agg.sl.passive, color: OTHER },
  ]
  const change = agg.then > 0 ? ((agg.total - agg.then) / agg.then) * 100 : null
  const truncated = vis.filter(p => p.assets.truncated).map(p => p.tenant)
  const pages = Math.max(1, Math.ceil(shown.length / PAGE))
  const sel = 'text-xs border border-slate-300 rounded-lg px-2 py-1.5 bg-white'

  return (
    <div className="p-6 space-y-4 max-w-[1500px]">
      <div>
        <h1 className="text-lg font-semibold text-slate-900 flex items-center gap-2"><Boxes size={20} className="text-indigo-600" /> {t('assetsCentral.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('assetsCentral.intro')}</p>
      </div>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}
      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : parts.length === 0 ? <p className="text-sm text-slate-500">{t('assetsCentral.noData')}</p> : (
        <>
          <div className="flex items-center gap-3">
            <select value={tenant} onChange={e => setTenant(e.target.value)} className={sel}>
              <option value="all">{t('alerts.allTenants')}</option>
              {parts.map(p => p.tenant).sort().map(tn => <option key={tn} value={tn}>{tn}</option>)}
            </select>
            <button onClick={reload} className="ml-auto text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
            <div className="xl:col-span-3 lg:col-span-3 space-y-4">
              <Widget title={t('assets.totalDiscovered') as string}>
                <div className="flex items-end justify-between gap-2">
                  <div className="text-5xl font-semibold text-slate-900 leading-none">{agg.total.toLocaleString()}</div>
                  {change != null && (
                    <span className={cn('inline-flex items-center gap-1 text-xs font-medium rounded-full px-2 py-0.5', change >= 0 ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700')} title={t('assets.vs7d') as string}>
                      {change >= 0 ? <ArrowUp size={11} /> : <ArrowDown size={11} />}{Math.abs(change).toFixed(1)}%
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-2">{t('assetsCentral.newN', { count: agg.fresh })}{agg.inactive > 0 ? ` · ${t('assets.inactiveN', { count: agg.inactive })}` : ''}</p>
              </Widget>
              <Widget title={t('assets.exposure') as string} subtitle={t('assets.exposureSub') as string}>
                <NumberTiles tiles={[
                  { label: t('assets.assetsWithVulns') as string, value: agg.v.assets, onClick: () => pick({ vuln: 'any' }) },
                  { label: t('assets.sev.critical') as string, value: agg.v.critical, tone: 'critical', onClick: () => pick({ vuln: 'any' }) },
                  { label: t('assets.sev.high') as string, value: agg.v.high, tone: 'high', onClick: () => pick({ vuln: 'any' }) },
                ]} />
              </Widget>
            </div>
            <Widget className="xl:col-span-3 lg:col-span-3" title={t('assets.types') as string}>
              {typeSegs.length === 0 ? <Empty text={t('assets.none') as string} /> : <Donut segs={typeSegs} size={140} centerLabel={t('assets.assets') as string} onSelect={k => pick({ type: k })} />}
            </Widget>
            <Widget className="xl:col-span-3 lg:col-span-3" title={t('assets.osLifecycle') as string} subtitle={t('assets.osLifecycleSub') as string}>
              <Donut segs={lifecycleSegs} size={130} centerLabel={t('assets.assets') as string} onSelect={k => pick({ lifecycle: k })} />
            </Widget>
            <Widget className="xl:col-span-3 lg:col-span-3" title={t('assets.scanLevels') as string} subtitle={t('assets.scanLevelsSub') as string}>
              <Donut segs={scanSegs} size={130} centerLabel={t('assets.assets') as string} onSelect={k => pick({ level: k })} />
            </Widget>
          </div>

          {tenant === 'all' && parts.length > 1 && (
            <section className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-x-auto">
              <h3 className="px-4 pt-3 pb-2 text-sm font-semibold text-slate-800">{t('assetsCentral.byClient')}</h3>
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-slate-400 border-y border-slate-200 bg-slate-50">
                  <th className="px-4 py-2 font-normal">{t('assetsCentral.client')}</th><th className="font-normal">{t('assets.assets')}</th><th className="font-normal">{t('assets.assetsWithVulns')}</th>
                  <th className="font-normal">{t('assets.sev.critical')}</th><th className="font-normal">{t('assets.lifecycle.eol')}</th><th className="font-normal pr-4">{t('assets.scanLevel.credentialed')}</th></tr></thead>
                <tbody>{[...parts].sort((a, b) => b.assets.summary.vulnerable.critical - a.assets.summary.vulnerable.critical || b.assets.summary.total - a.assets.summary.total).map(p => (
                  <tr key={p.tenant} onClick={() => setTenant(p.tenant)} className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer">
                    <td className="px-4 py-2 font-medium text-slate-800">{p.tenant}</td><td className="tabular-nums">{p.assets.summary.total}</td>
                    <td className="tabular-nums">{p.assets.summary.vulnerable.assets}</td>
                    <td className={cn('tabular-nums', p.assets.summary.vulnerable.critical > 0 && 'text-red-700 font-medium')}>{p.assets.summary.vulnerable.critical}</td>
                    <td className={cn('tabular-nums', p.assets.summary.by_lifecycle.eol > 0 && 'text-amber-700')}>{p.assets.summary.by_lifecycle.eol}</td>
                    <td className="tabular-nums pr-4">{p.assets.summary.by_scan_level.credentialed}</td>
                  </tr>))}</tbody>
              </table>
            </section>
          )}

          {pickedRows.length > 0 && <CentralBulkBar rows={pickedRows} onClear={() => setPicked(new Set())} />}
          <section ref={tableRef} className="bg-white border border-slate-200 rounded-xl shadow-sm scroll-mt-4">
            <div className="px-4 pt-3 pb-3 flex flex-wrap gap-2 items-center">
              <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('assetsCentral.search') as string} className="text-sm border border-slate-300 rounded-lg px-3 py-1.5 flex-1 min-w-[12rem] max-w-sm" />
              <select value={type} onChange={e => setType(e.target.value)} className={sel}>
                <option value="all">{t('assets.allTypes')}</option>{TYPE_ORDER.map(k => <option key={k} value={k}>{t(`assets.type.${k}`)}</option>)}
              </select>
              <select value={lifecycle} onChange={e => setLifecycle(e.target.value)} className={sel}>
                <option value="all">{t('assets.allLifecycle')}</option>{(['eol', 'ending', 'supported', 'unknown'] as const).map(k => <option key={k} value={k}>{t(`assets.lifecycle.${k}`)}</option>)}
              </select>
              <select value={level} onChange={e => setLevel(e.target.value)} className={sel}>
                <option value="all">{t('assets.allScanLevels')}</option>{(['credentialed', 'snmp', 'passive'] as const).map(k => <option key={k} value={k}>{t(`assets.scanLevel.${k}`)}</option>)}
              </select>
              <select value={vuln} onChange={e => setVuln(e.target.value)} className={sel}>
                <option value="all">{t('assets.allVulns')}</option><option value="any">{t('assets.withVulns')}</option><option value="none">{t('assets.noVulns')}</option>
              </select>
              <span className="ml-auto text-xs text-slate-500">{t('assets.showing', { from: shown.length ? page * PAGE + 1 : 0, to: Math.min(shown.length, (page + 1) * PAGE), total: shown.length })}</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-slate-400 border-y border-slate-200 bg-slate-50">
                  <th className="pl-4 w-8"><input type="checkbox" aria-label={t('assets.bulk.selectPage') as string} title={t('assets.bulk.selectPage') as string}
                    checked={shown.slice(page * PAGE, (page + 1) * PAGE).some(bulkable) && shown.slice(page * PAGE, (page + 1) * PAGE).filter(bulkable).every(r => picked.has(rowKey(r)))}
                    onChange={e => setPicked(prev => { const n = new Set(prev); shown.slice(page * PAGE, (page + 1) * PAGE).filter(bulkable).forEach(r => e.target.checked ? n.add(rowKey(r)) : n.delete(rowKey(r))); return n })} /></th>
                  <th className="px-2 py-2 font-normal">{t('assets.colName')}</th><th className="font-normal">{t('assetsCentral.client')}</th><th className="font-normal">{t('assets.colType')}</th>
                  <th className="font-normal">{t('assets.colVulns')}</th><th className="font-normal">{t('assets.colLifecycle')}</th><th className="font-normal">{t('assets.colIp')}</th>
                  <th className="font-normal">{t('assets.colLocation')}</th><th className="font-normal">{t('assets.colScan')}</th><th className="font-normal pr-4">{t('assets.colLastSeen')}</th></tr></thead>
                <tbody>
                  {shown.slice(page * PAGE, (page + 1) * PAGE).map((r, i) => (
                    <tr key={`${r.tenant}:${r.ip}:${r.n}:${i}`} onClick={() => setSelected(r)} className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer">
                      <td className="pl-4 w-8" onClick={e => e.stopPropagation()}>
                        {bulkable(r) && <input type="checkbox" checked={picked.has(rowKey(r))} onChange={e => setPicked(prev => { const n = new Set(prev); e.target.checked ? n.add(rowKey(r)) : n.delete(rowKey(r)); return n })} />}
                      </td>
                      <td className="px-2 py-2"><span className="inline-flex items-center gap-2 text-slate-800 font-medium"><TypeIcon type={r.t as AssetType} />{r.n}</span>
                        {(r.mf || r.md) && <div className="text-[11px] text-slate-400 ml-6">{[r.mf, r.md].filter(Boolean).join(' · ')}</div>}</td>
                      <td className="text-slate-600">{r.tenant}</td>
                      <td><TypePill type={r.t} role={r.r} /></td>
                      <td><VulnPill v={{ critical: r.v[0], high: r.v[1], medium: r.v[2], low: r.v[3], total: r.v[0] + r.v[1] + r.v[2] + r.v[3] }} /></td>
                      <td><LifecyclePill status={r.lc} /></td>
                      <td className="font-mono text-xs text-slate-600">{r.ip ?? '—'}</td>
                      <td className="text-xs text-slate-600">{r.loc ?? '—'}</td>
                      <td><ScanLevelPill level={r.sl} /></td>
                      <td className="pr-4 text-xs text-slate-500">{ago(r.seen)}</td>
                    </tr>
                  ))}
                  {shown.length === 0 && <tr><td colSpan={10} className="px-4 py-6 text-center text-slate-400">{t('assets.none')}</td></tr>}
                </tbody>
              </table>
            </div>
            {pages > 1 && (
              <div className="px-4 py-2 flex items-center justify-end gap-2 text-xs">
                <button disabled={page === 0} onClick={() => setPage(page - 1)} className="px-2 py-1 border rounded disabled:opacity-40">‹</button>
                <span className="text-slate-500">{page + 1} / {pages}</span>
                <button disabled={page >= pages - 1} onClick={() => setPage(page + 1)} className="px-2 py-1 border rounded disabled:opacity-40">›</button>
              </div>
            )}
          </section>
          {selected && <AssetDrawer row={selected} onClose={() => setSelected(null)} />}
          {truncated.length > 0 && <p className="text-xs text-slate-400">{t('assetsCentral.truncated', { clients: truncated.join(', ') })}</p>}
        </>
      )}
    </div>
  )
}

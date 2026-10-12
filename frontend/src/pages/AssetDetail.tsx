import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { assetsApi, type AssetDetail as Detail, type AssetFinding, type AssetType } from '../lib/api'
import { TypeIcon, Pill, TypePill, VulnPill, LifecyclePill, ScanLevelPill, ago } from '../components/AssetBits'
import { Button } from '../components/ui/Button'
import { ArrowLeft, Trash2, ExternalLink, Save, X } from 'lucide-react'
import { cn, formatBytes } from '../lib/utils'

const COMPUTER: AssetType[] = ['windows', 'linux', 'virtual', 'server']

type TabKey = 'overview' | 'hardware' | 'config' | 'software' | 'vulns' | 'services' | 'lifecycle' | 'peripherals' | 'supplies'

function tabsFor(a: Detail): TabKey[] {
  if (COMPUTER.includes(a.type)) return ['overview', 'hardware', 'software', 'vulns', 'services', 'lifecycle', ...(a.type === 'windows' || a.type === 'linux' ? ['peripherals' as TabKey] : [])]
  if (a.type === 'network') return ['overview', 'config', 'services', 'vulns', 'lifecycle']
  if (a.type === 'printer') return ['overview', 'supplies', 'services', 'vulns']
  return ['overview', 'services', 'vulns']
}

const humanize = (k: string) => k.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())

function fmtDur(sec: number): string {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60)
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`
}

/** one value of a hardware section, formatted by what its key says it is */
function Val({ k, v }: { k: string; v: unknown }) {
  const { t } = useTranslation()
  if (v === null || v === undefined || v === '') return <>—</>
  if (typeof v === 'boolean') return <>{v ? t('common.yes') : t('common.no')}</>
  if (typeof v === 'number') {
    if (k.endsWith('_bytes')) return <>{formatBytes(v)}</>
    if (k.endsWith('_pct')) return <>{Math.round(v)}%</>
    if (k.endsWith('_sec')) return <>{fmtDur(v)}</>
    if (k.endsWith('_c')) return <>{v} °C</>
    return <>{v}</>
  }
  if (Array.isArray(v)) return <>{v.map(x => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ') || '—'}</>
  if (typeof v === 'object') return <>{JSON.stringify(v)}</>
  return <>{String(v)}</>
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
      <h3 className="px-4 py-2.5 text-sm font-semibold text-slate-800 border-b border-slate-100">{title}</h3>
      <div className="p-4">{children}</div>
    </section>
  )
}

function KeyValues({ data }: { data: Record<string, unknown> }) {
  const { t } = useTranslation()
  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0) && typeof v !== 'object' || Array.isArray(v) && v.length > 0 && typeof v[0] !== 'object')
  if (entries.length === 0) return <p className="text-sm text-slate-400">—</p>
  return (
    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
      {entries.map(([k, v]) => (
        <div key={k} className="flex justify-between gap-3 border-b border-slate-100 py-1">
          <dt className="text-slate-500">{t(`assets.hw.${k}`, { defaultValue: humanize(k) })}</dt>
          <dd className="text-slate-900 text-right break-words min-w-0"><Val k={k} v={v} /></dd>
        </div>
      ))}
    </dl>
  )
}

function DiskTable({ disks }: { disks: Array<{ name?: string; pct?: number | null; total_bytes?: number | null; used_bytes?: number | null; file?: string; file_bytes?: number | null; max_bytes?: number | null; type?: string }> }) {
  const { t } = useTranslation()
  if (!disks.length) return null
  return (
    <ul className="space-y-1.5 text-sm">
      {disks.map((d, i) => {
        const pct = d.pct ?? (d.file_bytes != null && d.max_bytes ? (d.file_bytes / d.max_bytes) * 100 : null)
        const total = d.total_bytes ?? d.max_bytes
        return (
          <li key={i} className="flex items-center gap-3">
            <span className="w-28 font-mono text-xs text-slate-700 truncate" title={d.name ?? d.file}>{d.name ?? d.file}</span>
            <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden"><div className="h-full rounded-full" style={{ width: `${Math.min(100, pct ?? 0)}%`, background: (pct ?? 0) >= 90 ? '#ef4444' : (pct ?? 0) >= 75 ? '#f59e0b' : '#10b981' }} /></div>
            <span className="w-36 text-right text-xs text-slate-500">{pct != null ? `${Math.round(pct)}%` : '—'} · {formatBytes(total)}</span>
            {d.type && <span className="text-[11px] text-slate-400">{d.type}</span>}
          </li>
        )
      })}
      <li className="sr-only">{t('assets.hw.disks')}</li>
    </ul>
  )
}

// ── Tabs ─────────────────────────────────────────────────────────────────────

function Overview({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [location, setLocation] = useState(a.location_override ?? '')
  const [notes, setNotes] = useState(a.notes ?? '')
  const [tags, setTags] = useState<string[]>(a.manual_groups)
  const [tag, setTag] = useState('')
  const save = useMutation({
    mutationFn: () => assetsApi.update(a.id, { location_override: location, notes, manual_groups: tags }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['asset', a.id] }); qc.invalidateQueries({ queryKey: ['assets'] }); qc.invalidateQueries({ queryKey: ['asset-summary'] }) },
  })
  const dirty = location !== (a.location_override ?? '') || notes !== (a.notes ?? '') || tags.join('\u0000') !== a.manual_groups.join('\u0000')
  return (
    <div className="space-y-4">
      <Section title={t('assets.scanInfo') as string}>
        <div className="flex items-center gap-2 flex-wrap mb-2"><ScanLevelPill level={a.scan_level} />
          <span className="text-xs text-slate-500">{a.last_scan_at ? `${t('assets.lastScan')}: ${ago(a.last_scan_at)}` : t('assets.neverScanned')}</span></div>
        <p className="text-sm text-slate-600">{t(`assets.scanLevelHint.${a.scan_level}`)}</p>
        {a.scan.error && <p className="text-xs text-red-600 mt-2 break-words">{a.scan.error}</p>}
        {a.scan_level !== 'credentialed' && <p className="text-xs mt-2"><Link to="/credentials" className="text-indigo-600 hover:underline">{t('assets.goCredentials')}</Link></p>}
      </Section>
      <Section title={t('assets.yourData') as string}>
        <div className="space-y-3 text-sm">
          <label className="block"><span className="text-xs text-slate-500">{t('assets.location')}</span>
            <input value={location} onChange={e => setLocation(e.target.value)} placeholder={a.location && !a.location_override ? a.location : (t('assets.locationPlaceholder') as string)}
              className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" maxLength={128} /></label>
          <div>
            <span className="text-xs text-slate-500">{t('assets.tags')}</span>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {tags.map(g => <Pill key={g} tone="blue">{g}<button onClick={() => setTags(tags.filter(x => x !== g))} className="ml-1 text-blue-400 hover:text-blue-700"><X size={11} /></button></Pill>)}
              <form className="inline-flex" onSubmit={e => { e.preventDefault(); const v = tag.trim(); if (v && !tags.includes(v)) setTags([...tags, v]); setTag('') }}>
                <input value={tag} onChange={e => setTag(e.target.value)} placeholder={t('assets.addTag') as string} className="border border-slate-300 rounded-md px-2 py-0.5 text-xs w-32" maxLength={40} />
              </form>
            </div>
          </div>
          <label className="block"><span className="text-xs text-slate-500">{t('assets.notes')}</span>
            <textarea value={notes} onChange={e => setNotes(e.target.value)} rows={3} maxLength={2000} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" /></label>
          <Button size="sm" variant="primary" disabled={!dirty || save.isPending} onClick={() => save.mutate()}><Save size={12} /> {t('common.save')}</Button>
        </div>
      </Section>
    </div>
  )
}

function Hardware({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const hw = a.hardware
  const scalarSections = Object.entries(hw).filter(([k, v]) => k !== 'disks' && k !== 'components' && v && typeof v === 'object' && !Array.isArray(v))
  const diskRows = [...(hw.disks ?? []), ...((hw.vm?.disks as any[]) ?? [])]
  if (scalarSections.length === 0 && diskRows.length === 0) {
    return <Section title={t('assets.tab.hardware') as string}><p className="text-sm text-slate-500">{t('assets.noHardware')}</p></Section>
  }
  return (
    <div className="space-y-4">
      {scalarSections.map(([k, v]) => <Section key={k} title={t(`assets.hwSection.${k}`, { defaultValue: humanize(k) }) as string}><KeyValues data={v as Record<string, unknown>} /></Section>)}
      {diskRows.length > 0 && <Section title={t('assets.hw.disks') as string}><DiskTable disks={diskRows} /></Section>}
      {hw.components && Object.keys(hw.components).length > 0 && (
        <Section title={t('assets.hwSection.components') as string}><KeyValues data={Object.fromEntries(Object.entries(hw.components as Record<string, any>).map(([k, v]) => [k, typeof v === 'object' ? (v?.status ?? v?.health ?? JSON.stringify(v)) : v]))} /></Section>
      )}
    </div>
  )
}

function Software({ id }: { id: number }) {
  const { t } = useTranslation()
  const { data = [], isLoading } = useQuery({ queryKey: ['asset-software', id], queryFn: () => assetsApi.software(id) })
  const [q, setQ] = useState('')
  const rows = data.filter(s => !q.trim() || s.name.toLowerCase().includes(q.trim().toLowerCase()))
  return (
    <Section title={`${t('assets.tab.software')} (${data.length})`}>
      <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('assets.filterKeyword') as string} className="mb-3 border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-full max-w-sm" />
      {isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : rows.length === 0 ? <p className="text-sm text-slate-500">{t('assets.noSoftware')}</p> : (
        <div className="max-h-[28rem] overflow-y-auto">
          <table className="w-full text-sm"><thead><tr className="text-left text-xs text-slate-400 border-b"><th className="py-1 font-normal">{t('assets.colName')}</th><th className="font-normal">{t('assets.version')}</th></tr></thead>
            <tbody>{rows.map((s, i) => <tr key={i} className="border-b border-slate-100"><td className="py-1.5 text-slate-800">{s.name}</td><td className="font-mono text-xs text-slate-600">{s.version ?? '—'}</td></tr>)}</tbody></table>
        </div>
      )}
    </Section>
  )
}

const SEV_TONE: Record<string, 'red' | 'orange' | 'amber' | 'blue'> = { CRITICAL: 'red', HIGH: 'orange', MEDIUM: 'amber', LOW: 'blue' }
const SEV_BG: Record<string, string> = { CRITICAL: 'bg-red-700 text-white', HIGH: 'bg-orange-600 text-white', MEDIUM: 'bg-amber-300 text-slate-900', LOW: 'bg-slate-100 text-slate-700' }

function Vulns({ id }: { id: number }) {
  const { t } = useTranslation()
  const { data = [], isLoading } = useQuery({ queryKey: ['asset-vulns', id], queryFn: () => assetsApi.vulnerabilities(id) })
  const [q, setQ] = useState('')
  const [sev, setSev] = useState('all')
  const rows = useMemo(() => data.filter((f: AssetFinding) => (sev === 'all' || f.severity === sev) && (!q.trim() || [f.cve_id, f.product, f.summary].some(v => (v ?? '').toLowerCase().includes(q.trim().toLowerCase())))), [data, q, sev])
  return (
    <Section title={`${t('assets.tab.vulns')} (${data.length})`}>
      <div className="flex gap-2 mb-3 flex-wrap">
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('assets.filterKeyword') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm flex-1 min-w-[12rem] max-w-sm" />
        <select value={sev} onChange={e => setSev(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white">
          <option value="all">{t('assets.allSeverities')}</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{t(`assets.sev.${s.toLowerCase()}`)}</option>)}
        </select>
      </div>
      {isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : rows.length === 0 ? <p className="text-sm text-emerald-700">{t('assets.noVulnsHere')}</p> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-slate-400 border-b"><th className="py-1.5 font-normal">CVE</th><th className="font-normal">{t('assets.riskScore')}</th><th className="font-normal">{t('assets.colSeverity')}</th><th className="font-normal">{t('assets.affected')}</th><th className="font-normal">{t('assets.status')}</th></tr></thead>
            <tbody>
              {rows.map(f => (
                <tr key={`${f.cve_id}:${f.product}:${f.version}`} className="border-b border-slate-100 align-top">
                  <td className="py-2"><a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline font-mono inline-flex items-center gap-1">{f.cve_id}<ExternalLink size={10} /></a>
                    {f.summary && <div className="text-[11px] text-slate-400 max-w-md line-clamp-2">{f.summary}</div>}</td>
                  <td><span className={cn('inline-block min-w-[2.5rem] text-center rounded-full px-2 py-0.5 text-xs font-semibold', SEV_BG[f.severity] ?? SEV_BG.LOW)}>{f.cvss_score ?? '—'}</span></td>
                  <td><Pill tone={SEV_TONE[f.severity] ?? 'blue'}>{t(`assets.sev.${(f.severity ?? 'low').toLowerCase()}`)}</Pill></td>
                  <td className="text-slate-700">{f.product} <span className="font-mono text-xs text-slate-500">{f.version}</span></td>
                  <td className="text-xs text-slate-600">{t(`vuln.status.${f.status}`, { defaultValue: f.status })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  )
}

function Services({ a }: { a: Detail }) {
  const { t } = useTranslation()
  return (
    <Section title={`${t('assets.tab.services')} (${a.services.length})`}>
      {a.services.length === 0 ? <p className="text-sm text-slate-500">{t('assets.noServices')}</p> : (
        <table className="w-full text-sm"><thead><tr className="text-left text-xs text-slate-400 border-b"><th className="py-1.5 font-normal">{t('assets.port')}</th><th className="font-normal">{t('assets.service')}</th><th className="font-normal">{t('assets.product')}</th><th className="font-normal">{t('assets.version')}</th></tr></thead>
          <tbody>{a.services.map(s => <tr key={`${s.port}${s.proto}`} className="border-b border-slate-100"><td className="py-1.5 font-mono">{s.port}/{s.proto ?? 'tcp'}</td><td>{s.service ?? '—'}</td><td>{s.product ?? '—'}</td><td className="font-mono text-xs">{s.version ?? '—'}</td></tr>)}</tbody></table>
      )}
    </Section>
  )
}

function Lifecycle({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const lc = a.lifecycle_detail
  const nd = a.hardware.network_device as Record<string, any> | undefined
  return (
    <div className="space-y-4">
      <Section title={t('assets.osLifecycle') as string}>
        {!a.os_name ? <p className="text-sm text-slate-500">{t('assets.noOs')}</p> : (
          <dl className="grid grid-cols-2 gap-y-2 text-sm max-w-md">
            <dt className="text-slate-500">{t('assets.os')}</dt><dd className="text-slate-900">{a.os_name} {a.os_version}</dd>
            <dt className="text-slate-500">{t('assets.product')}</dt><dd>{lc.product ?? '—'}</dd>
            <dt className="text-slate-500">{t('assets.status')}</dt><dd><LifecyclePill status={lc.status} days={lc.days_left} />{lc.status === 'unknown' && <span className="text-slate-400">—</span>}</dd>
            <dt className="text-slate-500">{t('assets.eolDate')}</dt><dd>{lc.eol ? `${new Date(lc.eol).toLocaleDateString()}${lc.days_left != null ? ` (${lc.days_left >= 0 ? t('assets.inDays', { count: lc.days_left }) : t('assets.daysAgo', { count: -lc.days_left })})` : ''}` : t('assets.eolUnknown')}</dd>
          </dl>
        )}
        <p className="text-[11px] text-slate-400 mt-3">{t('assets.lifecycleNote')}</p>
      </Section>
      {nd && (nd.routeros || nd.firmware) && (
        <Section title={t('assets.updates') as string}>
          <KeyValues data={{ routeros: nd.routeros, channel: nd.channel, latest_routeros: nd.latest_routeros, firmware: nd.firmware, firmware_available: nd.firmware_available }} />
        </Section>
      )}
    </div>
  )
}

function Peripherals({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const groups = (['monitor', 'printer', 'usb', 'other'] as const).map(k => ({ k, items: a.peripherals.filter(p => p.kind === k) })).filter(g => g.items.length)
  if (groups.length === 0) return <Section title={t('assets.tab.peripherals') as string}><p className="text-sm text-slate-500">{t(a.scan_level === 'credentialed' ? 'assets.noPeripherals' : 'assets.peripheralsNeedScan')}</p></Section>
  return (
    <div className="space-y-4">
      {groups.map(g => (
        <Section key={g.k} title={`${t(`assets.peripheral.${g.k}`)} (${g.items.length})`}>
          <table className="w-full text-sm"><thead><tr className="text-left text-xs text-slate-400 border-b"><th className="py-1.5 font-normal">{t('assets.colName')}</th><th className="font-normal">{t('assets.manufacturer')}</th><th className="font-normal">{t('assets.model')}</th><th className="font-normal">{t('assets.serial')}</th></tr></thead>
            <tbody>{g.items.map(p => <tr key={p.id} className="border-b border-slate-100"><td className="py-1.5 text-slate-800">{p.name ?? '—'}</td><td>{p.manufacturer ?? '—'}</td><td>{p.model ?? '—'}</td><td className="font-mono text-xs">{p.serial ?? '—'}</td></tr>)}</tbody></table>
        </Section>
      ))}
    </div>
  )
}

function Supplies({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const p = a.hardware.printer as Record<string, any> | undefined
  if (!p) return <Section title={t('assets.tab.supplies') as string}><p className="text-sm text-slate-500">{t('assets.noSupplies')}</p></Section>
  const supplies: Array<{ name: string; level_pct: number | null }> = Array.isArray(p.supplies) ? p.supplies : []
  return (
    <div className="space-y-4">
      {supplies.length > 0 && (
        <Section title={t('assets.tab.supplies') as string}>
          <ul className="space-y-2 text-sm">{supplies.map(s => (
            <li key={s.name} className="flex items-center gap-3"><span className="w-40 truncate text-slate-700">{s.name}</span>
              <div className="flex-1 h-2.5 bg-slate-100 rounded-full overflow-hidden"><div className="h-full rounded-full" style={{ width: `${Math.max(0, s.level_pct ?? 0)}%`, background: (s.level_pct ?? 100) <= 10 ? '#ef4444' : (s.level_pct ?? 100) <= 25 ? '#f59e0b' : '#10b981' }} /></div>
              <span className="w-12 text-right tabular-nums text-xs text-slate-600">{s.level_pct != null && s.level_pct >= 0 ? `${s.level_pct}%` : '—'}</span></li>
          ))}</ul>
        </Section>
      )}
      <Section title={t('assets.hwSection.printer') as string}><KeyValues data={Object.fromEntries(Object.entries(p).filter(([k]) => k !== 'supplies'))} /></Section>
    </div>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export function AssetDetail() {
  const { t } = useTranslation()
  const nav = useNavigate()
  const qc = useQueryClient()
  const { id } = useParams()
  const assetId = Number(id)
  const { data: a, isLoading, isError } = useQuery({ queryKey: ['asset', assetId], queryFn: () => assetsApi.get(assetId), refetchInterval: 60_000 })
  const [tab, setTab] = useState<TabKey>('overview')
  const remove = useMutation({ mutationFn: () => assetsApi.remove(assetId), onSuccess: () => { qc.invalidateQueries({ queryKey: ['assets'] }); nav('/inventory/list') } })

  if (isLoading) return <div className="p-6"><p className="text-sm text-slate-500">{t('common.loading')}</p></div>
  if (isError || !a) return <div className="p-6 space-y-2"><p className="text-sm text-red-600">{t('assets.notFound')}</p><Link to="/inventory/list" className="text-sm text-indigo-600 hover:underline">{t('assets.openList')}</Link></div>

  const tabs = tabsFor(a)
  const active = tabs.includes(tab) ? tab : 'overview'
  const worst = a.vulns.critical ? 'critical' : a.vulns.high ? 'high' : a.vulns.medium ? 'medium' : null
  const header = worst === 'critical' ? 'bg-red-100 border-red-300' : worst === 'high' ? 'bg-orange-100 border-orange-300' : worst === 'medium' ? 'bg-amber-50 border-amber-200' : 'bg-slate-100 border-slate-200'
  const count = (k: TabKey) => k === 'software' ? a.software_count : k === 'vulns' ? a.vulns.total : k === 'services' ? a.services.length : k === 'peripherals' ? a.peripherals.length : null
  const fact = (label: string, value: React.ReactNode) => (
    <div className="grid grid-cols-5 border-b border-slate-100 last:border-0"><dt className="col-span-2 px-3 py-2.5 text-sm font-semibold text-slate-800">{label}</dt><dd className="col-span-3 px-3 py-2.5 text-sm text-slate-700 break-words">{value ?? '—'}</dd></div>
  )

  return (
    <div className="p-6 space-y-4 max-w-[1400px]">
      <div className="flex items-center justify-between">
        <Link to="/inventory/list" className="text-sm text-slate-500 hover:text-indigo-600 inline-flex items-center gap-1"><ArrowLeft size={14} /> {t('assets.listTitle')}</Link>
        <Button size="sm" variant="ghost" onClick={() => { if (confirm(t('assets.removeConfirm') as string)) remove.mutate() }}><Trash2 size={13} /> {t('assets.remove')}</Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[22rem_1fr] gap-5 items-start">
        <div className="space-y-3">
          <div className={cn('rounded-xl border px-4 py-3 flex items-center gap-3', header)}>
            <span className="w-11 h-11 rounded-lg bg-white/70 flex items-center justify-center shrink-0"><TypeIcon type={a.type} size={24} /></span>
            <div className="min-w-0"><h1 className="text-lg font-bold text-slate-900 truncate">{a.name}</h1>
              <p className="text-xs text-slate-600 font-mono truncate">{[a.ip, a.mac].filter(Boolean).join(' • ') || '—'}</p></div>
          </div>
          <dl className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            {fact(t('assets.assetType') as string, <TypePill type={a.type} role={a.role} />)}
            {fact(t('assets.manufacturer') as string, a.manufacturer)}
            {fact(t('assets.osVersion') as string, [a.os_name, a.os_version && !/^\s*10\.0/.test(a.os_version) ? a.os_version : null].filter(Boolean).join(' ') || null)}
            {fact(t('assets.model') as string, a.model)}
            {fact(t('assets.serial') as string, a.serial)}
            {fact(t('assets.location') as string, a.location)}
            {a.parent && fact(t('assets.parentHost') as string, a.parent)}
            {fact(t('assets.groups') as string, a.groups.length ? <span className="flex flex-wrap gap-1">{a.groups.map(g => <Pill key={g}>{t(`assets.group.${g}`, { defaultValue: g }) as string}</Pill>)}</span> : null)}
            {fact(t('assets.osLifecycle') as string, <span className="flex flex-col gap-0.5 items-start"><LifecyclePill status={a.lifecycle} days={a.lifecycle_detail.days_left} />{a.lifecycle_product && <span className="text-[11px] text-slate-400">{a.lifecycle_product}</span>}</span>)}
            {fact(t('assets.riskInsights') as string, a.vulns.total ? <VulnPill v={a.vulns} /> : <span className="text-emerald-700 text-sm">{t('assets.noVulns')}</span>)}
            {fact(t('assets.colScan') as string, <ScanLevelPill level={a.scan_level} />)}
            {fact(t('assets.lastSuccessfulScan') as string, a.last_scan_at ? ago(a.last_scan_at) : t('assets.neverScanned'))}
            {fact(t('assets.colLastSeen') as string, ago(a.last_seen_at))}
          </dl>
        </div>

        <div className="space-y-4 min-w-0">
          <div className="flex gap-1 border-b border-slate-200 overflow-x-auto">
            {tabs.map(k => (
              <button key={k} onClick={() => setTab(k)} className={cn('px-4 py-2 text-sm -mb-px border-b-2 whitespace-nowrap inline-flex items-center gap-1.5', active === k ? 'border-blue-600 text-blue-700 font-medium' : 'border-transparent text-slate-600 hover:text-slate-900')}>
                {t(`assets.tab.${k}`)}{count(k) ? <span className="text-[11px] bg-slate-100 text-slate-600 rounded-full px-1.5">{count(k)}</span> : null}
              </button>
            ))}
          </div>
          {active === 'overview' && <Overview key={a.id} a={a} />}
          {(active === 'hardware' || active === 'config') && <Hardware a={a} />}
          {active === 'software' && <Software id={a.id} />}
          {active === 'vulns' && <Vulns id={a.id} />}
          {active === 'services' && <Services a={a} />}
          {active === 'lifecycle' && <Lifecycle a={a} />}
          {active === 'peripherals' && <Peripherals a={a} />}
          {active === 'supplies' && <Supplies a={a} />}
        </div>
      </div>
    </div>
  )
}

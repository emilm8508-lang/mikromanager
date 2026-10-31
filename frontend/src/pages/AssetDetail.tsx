import { Fragment, useMemo, useState, useEffect } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { assetsApi, vulnApi, type AssetDetail as Detail, type AssetType, type VulnFindingOut } from '../lib/api'
import { TypeIcon, Pill, TypePill, VulnPill, LifecyclePill, ScanLevelPill, AttachDetail, ago } from '../components/AssetBits'
import { Button } from '../components/ui/Button'
import { ScorePill, SeverityPill, RemediationPanel } from '../components/VulnViews'
import { AssetActions, hasActions } from '../components/AssetActions'
import { ArrowLeft, Trash2, Save, X, ScanSearch, Loader2, Search, ArrowUp, ArrowDown, ChevronRight, FileDown } from 'lucide-react'
import { cn, formatBytes } from '../lib/utils'

const COMPUTER: AssetType[] = ['windows', 'linux', 'virtual', 'server']

type TabKey = 'overview' | 'hardware' | 'config' | 'software' | 'vulns' | 'services' | 'lifecycle' | 'peripherals' | 'supplies' | 'actions' | 'tools'

function tabsFor(a: Detail): TabKey[] {
  const tabs = baseTabs(a)
  const withTools = a.ip && a.type !== 'monitor' ? [...tabs, 'tools' as TabKey] : tabs
  return hasActions(a) ? [...withTools, 'actions'] : withTools
}

function baseTabs(a: Detail): TabKey[] {
  if (COMPUTER.includes(a.type)) return ['overview', 'hardware', 'software', 'vulns', 'services', ...(a.type === 'windows' || a.type === 'linux' ? ['peripherals' as TabKey] : [])]
  if (a.type === 'network') return ['overview', 'config', 'services', 'vulns']
  if (a.type === 'printer') return ['overview', 'supplies', 'services', 'vulns']
  if (a.type === 'monitor') return ['overview', 'hardware']
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

// list-of-object sections of a hardware scan, shown as small tables in this order
const TABLE_SECTIONS = ['memory_modules', 'physical_disks', 'network_adapters', 'gpu'] as const

function ObjectTable({ rows }: { rows: Array<Record<string, unknown>> }) {
  const { t } = useTranslation()
  const cols = Array.from(new Set(rows.flatMap(r => Object.keys(r))))
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs text-slate-400 border-b">{cols.map(c => <th key={c} className="py-1.5 pr-3 font-normal whitespace-nowrap">{t(`assets.hw.${c}`, { defaultValue: humanize(c) })}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={i} className="border-b border-slate-100 align-top">{cols.map(c => <td key={c} className={cn('py-1.5 pr-3 text-slate-800', /mac|serial|id$/.test(c) && 'font-mono text-xs')}><Val k={c} v={r[c]} /></td>)}</tr>
        ))}</tbody>
      </table>
    </div>
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
  const [place, setPlace] = useState(a.place ?? '')
  const [notes, setNotes] = useState(a.notes ?? '')
  const [owner, setOwner] = useState(a.owner ?? '')
  const [criticality, setCriticality] = useState(a.criticality ?? '')
  const [tags, setTags] = useState<string[]>(a.manual_groups)
  const [tag, setTag] = useState('')
  const [kind, setKind] = useState(a.override.type ?? 'auto')
  const [role, setRole] = useState(a.override.role ?? 'auto')
  const save = useMutation({
    mutationFn: () => assetsApi.update(a.id, { location_override: location, place, notes, owner, criticality, manual_groups: tags, asset_type: kind, role }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['asset', a.id] }); qc.invalidateQueries({ queryKey: ['assets'] }); qc.invalidateQueries({ queryKey: ['asset-summary'] }) },
  })
  const dirty = kind !== (a.override.type ?? 'auto') || role !== (a.override.role ?? 'auto') || location !== (a.location_override ?? '') || place !== (a.place ?? '') || notes !== (a.notes ?? '') || owner !== (a.owner ?? '') || criticality !== (a.criticality ?? '') || tags.join('\u0000') !== a.manual_groups.join('\u0000')
  return (
    <div className="space-y-4">
      {a.type === 'monitor' && (a.installed_on ?? []).length > 0 && (
        <Section title={t('assets.attachedTo') as string}>
          <ul className="text-sm space-y-1">{a.installed_on!.map(x => <li key={x.id}><Link to={`/inventory/${x.id}`} className="text-indigo-600 hover:underline">{x.name}</Link></li>)}</ul>
        </Section>
      )}
      {(a.hints?.length ?? 0) > 0 && (
        <Section title={t('assets.hintsTitle') as string}>
          <ul className="text-sm text-slate-700 list-disc pl-5 mb-2">{a.hints!.map(h => <li key={h}>{t(`assets.hint.${h}`)}</li>)}</ul>
          <p className="text-xs text-slate-500">{t('assets.hintsAdvice')}</p>
          {a.ip && <p className="text-xs mt-1.5"><a href={`http://${a.ip}`} target="_blank" rel="noreferrer noopener" className="text-indigo-600 hover:underline">{t('assets.hintsOpen', { ip: a.ip })}</a></p>}
        </Section>
      )}
      <Section title={t('assets.scanInfo') as string}>
        <div className="flex items-center gap-2 flex-wrap mb-2"><ScanLevelPill level={a.scan_level} />
          <span className="text-xs text-slate-500">{a.last_scan_at ? `${t('assets.lastScan')}: ${ago(a.last_scan_at)}` : t('assets.neverScanned')}</span></div>
        <p className="text-sm text-slate-600">{t(`assets.scanLevelHint.${a.scan_level}`)}</p>
        {a.scan.error && <p className={cn('text-xs mt-2 break-words', a.scan.status === 'error' || a.scan.status === 'auth_error' ? 'text-red-600' : 'text-slate-500')}>{a.scan.error}</p>}
        {a.scan_level !== 'credentialed' && <p className="text-xs mt-2"><Link to="/credentials" className="text-indigo-600 hover:underline">{t('assets.goCredentials')}</Link></p>}
      </Section>
      <Section title={t('assets.yourData') as string}>
        <div className="space-y-3 text-sm">
          <div className="flex gap-3 flex-wrap">
            <label className="block"><span className="text-xs text-slate-500">{t('assets.assetType')}</span>
              <select value={kind} onChange={e => setKind(e.target.value)} className="mt-0.5 block border border-slate-300 rounded-lg px-2 py-1.5 bg-white">
                <option value="auto">{t('assets.typeAuto')}</option>{(['windows', 'linux', 'virtual', 'server', 'network', 'printer', 'other'] as const).map(k => <option key={k} value={k}>{t(`assets.type.${k}`)}</option>)}
              </select></label>
            {(COMPUTER.includes((kind === 'auto' ? a.type : kind) as AssetType)) && (
              <label className="block"><span className="text-xs text-slate-500">{t('assets.roleLabel')}</span>
                <select value={role} onChange={e => setRole(e.target.value)} className="mt-0.5 block border border-slate-300 rounded-lg px-2 py-1.5 bg-white">
                  <option value="auto">{t('assets.typeAuto')}</option><option value="server">{t('assets.roleServer')}</option><option value="workstation">{t('assets.roleWorkstation')}</option>
                </select></label>
            )}
          </div>
          <label className="block"><span className="text-xs text-slate-500">{t('assets.location')}</span>
            <input value={location} onChange={e => setLocation(e.target.value)} placeholder={a.location && !a.location_override ? a.location : (t('assets.locationPlaceholder') as string)}
              className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" maxLength={128} /></label>
          <label className="block"><span className="text-xs text-slate-500">{t('assets.place')}</span>
            <input value={place} onChange={e => setPlace(e.target.value)} placeholder={t('assets.placePlaceholder') as string}
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
          <label className="block"><span className="text-xs text-slate-500">{t('assets.owner')}</span>
            <input value={owner} onChange={e => setOwner(e.target.value)} maxLength={128} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5 text-sm" />
          </label>
          <label className="block"><span className="text-xs text-slate-500">{t('assets.criticality')}</span>
            <select value={criticality} onChange={e => setCriticality(e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white">
              <option value="">—</option>{(['low', 'medium', 'high', 'critical'] as const).map(k => <option key={k} value={k}>{t(`assets.crit.${k}`)}</option>)}
            </select>
          </label>
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
  const tables = TABLE_SECTIONS.filter(k => Array.isArray(hw[k]) && hw[k].length > 0)
  if (scalarSections.length === 0 && diskRows.length === 0 && tables.length === 0) {
    return <Section title={t('assets.tab.hardware') as string}><p className="text-sm text-slate-500">{t('assets.noHardware')}</p></Section>
  }
  return (
    <div className="space-y-4">
      {scalarSections.map(([k, v]) => <Section key={k} title={t(`assets.hwSection.${k}`, { defaultValue: humanize(k) }) as string}><KeyValues data={v as Record<string, unknown>} /></Section>)}
      {diskRows.length > 0 && <Section title={t('assets.hw.disks') as string}><DiskTable disks={diskRows} /></Section>}
      {tables.map(k => <Section key={k} title={`${t(`assets.hwSection.${k}`, { defaultValue: humanize(k) })} (${hw[k].length})`}><ObjectTable rows={hw[k]} /></Section>)}
      {hw.components && Object.keys(hw.components).length > 0 && (
        <Section title={t('assets.hwSection.components') as string}><KeyValues data={Object.fromEntries(Object.entries(hw.components as Record<string, any>).map(([k, v]) => [k, typeof v === 'object' ? (v?.status ?? v?.health ?? JSON.stringify(v)) : v]))} /></Section>
      )}
    </div>
  )
}

function Software({ id, hostId }: { id: number; hostId?: number }) {
  const { t } = useTranslation()
  const { data = [], isLoading } = useQuery({ queryKey: ['asset-software', id], queryFn: () => assetsApi.software(id) })
  const [q, setQ] = useState('')
  const rows = data.filter(s => !q.trim() || s.name.toLowerCase().includes(q.trim().toLowerCase()))
  return (
    <Section title={`${t('assets.tab.software')} (${data.length})`}>
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('assets.filterKeyword') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-full max-w-sm" />
        {hostId && <Link to={`/software?host=${hostId}`} className="text-xs text-indigo-600 hover:underline">{t('assets.openInSoftware')}</Link>}
      </div>
      {isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : rows.length === 0 ? <p className="text-sm text-slate-500">{t('assets.noSoftware')}</p> : (
        <div className="max-h-[28rem] overflow-y-auto">
          <table className="w-full text-sm"><thead><tr className="text-left text-xs text-slate-400 border-b"><th className="py-1 font-normal">{t('assets.colName')}</th><th className="font-normal">{t('assets.version')}</th></tr></thead>
            <tbody>{rows.map((s, i) => <tr key={i} className="border-b border-slate-100"><td className="py-1.5 text-slate-800">{s.name}</td><td className="font-mono text-xs text-slate-600">{s.version ?? '—'}</td></tr>)}</tbody></table>
        </div>
      )}
    </Section>
  )
}

const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

/** Risk insights of a device: a sub-menu (vulnerabilities / lifecycle) and the CVE table in the layout of the vulnerabilities page. */
function RiskInsights({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const [sub, setSub] = useState<'vulns' | 'lifecycle'>('vulns')
  const hasLifecycle = COMPUTER.includes(a.type) || a.type === 'network'
  const item = (k: 'vulns' | 'lifecycle', label: string) => (
    <button key={k} onClick={() => setSub(k)} className={cn('w-full text-left text-sm font-semibold rounded-lg px-3 py-2', sub === k ? 'bg-slate-200/70 text-slate-900' : 'bg-slate-100 text-slate-700 hover:bg-slate-200/50')}>{label}</button>
  )
  if (!hasLifecycle) return <AssetVulns a={a} />
  return (
    <div className="grid grid-cols-1 md:grid-cols-[11rem_1fr] gap-4 items-start">
      <div className="space-y-2">{item('vulns', t('vulnDash.tabCves') as string)}{item('lifecycle', t('assets.tab.lifecycle') as string)}</div>
      <div className="min-w-0">{sub === 'vulns' ? <AssetVulns a={a} /> : <Lifecycle a={a} />}</div>
    </div>
  )
}

type VSort = 'cve' | 'score'

function AssetVulns({ a }: { a: Detail }) {
  const { t, i18n } = useTranslation()
  const [pbErr, setPbErr] = useState<string | null>(null)
  // the remediation plan of this asset as a Markdown file
  const downloadPlaybook = async () => {
    try {
      const r = await assetsApi.playbook(a.id, i18n.language.startsWith('pl') ? 'pl' : 'en')
      const url = URL.createObjectURL(new Blob([r.markdown], { type: 'text/markdown;charset=utf-8' }))
      const el = document.createElement('a')
      el.href = url; el.download = r.filename; el.click()
      URL.revokeObjectURL(url)
      setPbErr(null)
    } catch (e) { setPbErr((e as Error).message) }
  }
  const { data: all = [], isLoading } = useQuery({ queryKey: ['vuln-findings', undefined], queryFn: () => vulnApi.findings(), refetchInterval: 60_000 })
  const [q, setQ] = useState('')
  const [sev, setSev] = useState('all')
  const [sort, setSort] = useState<{ key: VSort; dir: 1 | -1 }>({ key: 'score', dir: -1 })
  const [open, setOpen] = useState<number | null>(null)
  const mine = useMemo(() => all.filter(f => a.ip && f.affected.some(x => x.ip === a.ip)), [all, a.ip])
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const f = mine.filter(x => (sev === 'all' || x.severity === sev) && (!needle || [x.cve_id, x.product, x.summary].some(v => (v ?? '').toLowerCase().includes(needle))))
    const val = (x: VulnFindingOut) => sort.key === 'cve' ? x.cve_id : (x.cvss_score ?? -1)
    return f.sort((x, y) => { const A = val(x), B = val(y); return (A < B ? -1 : A > B ? 1 : 0) * sort.dir || (SEV_RANK[x.severity ?? ''] ?? 9) - (SEV_RANK[y.severity ?? ''] ?? 9) })
  }, [mine, q, sev, sort])
  const th = (key: VSort, label: string) => (
    <th className={cn('font-normal cursor-pointer select-none whitespace-nowrap py-2', sort.key === key && 'text-indigo-600')} onClick={() => setSort(s => ({ key, dir: s.key === key ? (-s.dir as 1 | -1) : -1 }))}>
      <span className="inline-flex items-center gap-0.5">{label}{sort.key === key && (sort.dir === 1 ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}</span>
    </th>
  )
  return (
    <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
      <div className="px-4 pt-3 pb-3 flex flex-wrap gap-2 items-center">
        <h3 className="text-sm font-semibold text-slate-800 mr-2">{t('vulnDash.tabCves')} ({rows.length})</h3>
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('assets.filterKeyword') as string} className="text-sm border border-slate-300 rounded-lg pl-7 pr-3 py-1.5 w-52" />
        </div>
        <select value={sev} onChange={e => setSev(e.target.value)} className="text-xs border border-slate-300 rounded-lg px-2 py-1.5 bg-white">
          <option value="all">{t('assets.allSeverities')}</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{t(`assets.sev.${s.toLowerCase()}`)}</option>)}
        </select>
        <button onClick={() => void downloadPlaybook()} title={t('playbook.hint') as string} className="ml-auto inline-flex items-center gap-1.5 text-xs border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50"><FileDown size={13} /> {t('playbook.button')}</button>
        {pbErr && <span className="text-xs text-red-600">{pbErr}</span>}
      </div>
      {isLoading ? <p className="px-4 pb-4 text-sm text-slate-500">{t('common.loading')}</p> : rows.length === 0 ? <p className="px-4 pb-4 text-sm text-emerald-700">{t('assets.noVulnsHere')}</p> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-slate-400 border-y border-slate-200 bg-slate-50">
              <th className="w-6" />{th('cve', 'CVE')}{th('score', t('assets.riskScore') as string)}<th className="font-normal">{t('assets.colSeverity')}</th>
              <th className="font-normal">{t('assets.status')}</th><th className="font-normal pr-4">{t('assets.affected')}</th></tr></thead>
            <tbody>
              {rows.map(f => (
                <Fragment key={f.id}>
                  <tr onClick={() => setOpen(open === f.id ? null : f.id)} className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer align-top">
                    <td className="pl-3 py-2"><ChevronRight size={14} className={cn('text-slate-400 transition-transform', open === f.id && 'rotate-90')} /></td>
                    <td className="py-2 font-mono text-xs text-blue-600">{f.cve_id}{f.overdue && <span className="ml-1.5 text-[10px] text-red-600 font-sans">{t('vuln.overdue')}</span>}</td>
                    <td className="py-2"><ScorePill f={f} /></td><td className="py-2"><SeverityPill severity={f.severity} /></td>
                    <td className="py-2 text-xs text-slate-600">{t(`vuln.status.${f.status}`)}</td>
                    <td className="py-2 pr-4 text-xs text-slate-700">{f.product} <span className="font-mono text-slate-400">{f.version}</span></td>
                  </tr>
                  {open === f.id && <tr className="border-b border-slate-100 bg-slate-50/60"><td /><td colSpan={5} className="py-3 pr-4"><RemediationPanel finding={f} /></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
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
          <table className="w-full text-sm"><thead><tr className="text-left text-xs text-slate-400 border-b"><th className="py-1.5 font-normal">{t('assets.colName')}</th><th className="font-normal">{t('assets.manufacturer')}</th><th className="font-normal">{t('assets.model')}</th><th className="font-normal">{t('assets.serial')}</th><th className="font-normal">{t('assets.details')}</th></tr></thead>
            <tbody>{g.items.map(p => <tr key={p.id} className="border-b border-slate-100 align-top"><td className="py-1.5 text-slate-800">{p.details?.asset_id ? <Link to={`/inventory/${p.details.asset_id}`} className="text-indigo-600 hover:underline" title={t('assets.openAsset', { name: p.details.asset_name }) as string}>{p.name ?? '—'}</Link> : (p.name ?? '—')}</td><td>{p.manufacturer ?? '—'}</td><td>{p.model ?? '—'}</td><td className="font-mono text-xs">{p.serial ?? '—'}</td>
              <td className="text-xs text-slate-600">{Object.entries(p.details ?? {}).filter(([k]) => k !== 'asset_id' && k !== 'asset_name').map(([k, v]) => <span key={k} className="mr-3 whitespace-nowrap">{t(`assets.hw.${k}`, { defaultValue: humanize(k) })}: <Val k={k} v={v} /></span>)}</td></tr>)}</tbody></table>
        </Section>
      ))}
    </div>
  )
}

// ping / traceroute / port scan of this device, run by the agent, the output arriving as it is produced
function NetTools({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const [job, setJob] = useState<{ id: string; tool: string } | null>(null)
  const [lines, setLines] = useState<string[]>([])
  const [done, setDone] = useState(true)
  const [ports, setPorts] = useState('')
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    if (!job) return
    let live = true, since = 0
    const tick = async () => {
      try {
        const r = await assetsApi.toolOutput(job.id, since)
        if (!live) return
        since = r.next
        if (r.lines.length) setLines(l => [...l, ...r.lines])
        if (r.done) { setDone(true); return }
      } catch { if (live) { setDone(true); return } }
      if (live) setTimeout(tick, 900)
    }
    void tick()
    return () => { live = false }
  }, [job])
  const run = async (tool: 'ping' | 'traceroute' | 'portscan') => {
    setErr(null); setLines([]); setDone(false)
    try { const r = await assetsApi.tool(a.id, tool, tool === 'portscan' ? ports : undefined); setJob({ id: r.job, tool }) }
    catch (e: any) { setDone(true); setErr(e?.response?.data?.detail ?? e?.message ?? String(e)) }
  }
  return (
    <Section title={t('assets.tab.tools') as string}>
      <p className="text-xs text-slate-500 mb-3">{t('assets.tools.hint', { ip: a.ip })}</p>
      <div className="flex items-center gap-2 flex-wrap mb-3">
        <Button size="sm" variant="secondary" disabled={!done} onClick={() => run('ping')}>{t('assets.tools.ping')}</Button>
        <Button size="sm" variant="secondary" disabled={!done} onClick={() => run('traceroute')}>{t('assets.tools.traceroute')}</Button>
        <Button size="sm" variant="secondary" disabled={!done} onClick={() => run('portscan')}>{t('assets.tools.portscan')}</Button>
        <input value={ports} onChange={e => setPorts(e.target.value)} placeholder={t('assets.tools.portsHint') as string} className="border border-slate-300 rounded-lg px-2.5 py-1.5 text-sm w-60" />
        {!done && <span className="text-xs text-slate-500 inline-flex items-center gap-1"><Loader2 size={12} className="animate-spin" /> {t('assets.tools.running')}</span>}
      </div>
      {err && <p className="text-xs text-red-600 mb-2">{err}</p>}
      <pre className="bg-slate-900 text-slate-100 text-xs rounded-lg p-3 min-h-[8rem] max-h-[26rem] overflow-auto whitespace-pre-wrap">{lines.length ? lines.join('\n') : t('assets.tools.empty')}</pre>
    </Section>
  )
}

function Supplies({ a }: { a: Detail }) {
  const { t } = useTranslation()
  const p = a.hardware.printer as Record<string, any> | undefined
  const installed = (a.installed_on ?? []).length > 0 && (
    <Section title={t('assets.installedOn') as string}>
      <ul className="text-sm space-y-1">{a.installed_on!.map(x => <li key={`${x.id}:${x.queue}`}><Link to={`/inventory/${x.id}`} className="text-indigo-600 hover:underline">{x.name}</Link>{x.queue && <span className="text-slate-400"> · {x.queue}</span>}</li>)}</ul>
    </Section>
  )
  if (!p) return <div className="space-y-4"><Section title={t('assets.tab.supplies') as string}><p className="text-sm text-slate-500">{t('assets.noSupplies')}</p></Section>{installed}</div>
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
      {installed}
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
  const { data: a, isLoading, isError } = useQuery({ queryKey: ['asset', assetId], queryFn: () => assetsApi.get(assetId), refetchInterval: q => q.state.data?.scan.running ? 3000 : 60_000 })
  const [tab, setTab] = useState<TabKey>('overview')
  const scan = useMutation({ mutationFn: () => assetsApi.scan(assetId), onSuccess: () => qc.invalidateQueries({ queryKey: ['asset', assetId] }) })
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
        <div className="flex items-center gap-1">
          {a.scan.available && (
            <Button size="sm" variant="secondary" disabled={a.scan.running || scan.isPending} onClick={() => scan.mutate()}>
              {a.scan.running ? <Loader2 size={13} className="animate-spin" /> : <ScanSearch size={13} />} {a.scan.running ? t('assets.scanning') : t('assets.scanNow')}
            </Button>
          )}
        <Button size="sm" variant="ghost" onClick={() => { if (confirm(t('assets.removeConfirm') as string)) remove.mutate() }}><Trash2 size={13} /> {t('assets.remove')}</Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[22rem_1fr] gap-5 items-start">
        <div className="space-y-3">
          <div className={cn('rounded-xl border px-4 py-3 flex items-center gap-3', header)}>
            <span className="w-11 h-11 rounded-lg bg-white/70 flex items-center justify-center shrink-0"><TypeIcon type={a.type} size={24} /></span>
            <div className="min-w-0"><h1 className="text-lg font-bold text-slate-900 truncate">{a.name}</h1>
              <p className="text-xs text-slate-600 font-mono truncate">{[a.ip, a.mac].filter(Boolean).join(' • ') || '—'}</p></div>
          </div>
          <dl className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            {fact(t('assets.assetType') as string, <TypePill type={a.type} role={a.role} cls={a.dclass} />)}
            {fact(t('assets.manufacturer') as string, a.manufacturer)}
            {a.via && fact(t('assets.via') as string, `${a.via}${a.hops ? ` (${t('assets.hops', { count: a.hops })})` : ''}`)}
            {fact(t('assets.osVersion') as string, [a.os_name, a.os_version && !/^\s*10\.0/.test(a.os_version) ? a.os_version : null].filter(Boolean).join(' ') || null)}
            {fact(t('assets.model') as string, a.model)}
            {fact(t('assets.serial') as string, a.serial)}
            {fact(t('assets.location') as string, a.location)}
            {fact(t('assets.place') as string, a.place)}
            {fact(t('assets.colAttach') as string, <AttachDetail at={a.attach} />)}
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
          {active === 'software' && <Software id={a.id} hostId={a.refs.vuln_host_id} />}
          {active === 'vulns' && <RiskInsights a={a} />}
          {active === 'services' && <Services a={a} />}
          {active === 'peripherals' && <Peripherals a={a} />}
          {active === 'tools' && <NetTools a={a} />}
          {active === 'supplies' && <Supplies a={a} />}
          {active === 'actions' && <AssetActions a={a} />}
        </div>
      </div>
    </div>
  )
}

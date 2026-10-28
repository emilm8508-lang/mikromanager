import { Fragment, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { assetsApi, vulnApi, type VulnFindingOut, type VulnRemediationStatus } from '../lib/api'
import { Widget, Empty, Donut, HBars, AreaChart, SEV_COLOR, OTHER, CAT, fmt, type Seg } from './SecCharts'
import { Pill } from './AssetBits'
import { useAuth } from '../pages/Login'
import { ExternalLink, Search, ArrowDown, ArrowUp, ChevronRight, Download } from 'lucide-react'
import { cn } from '../lib/utils'
import { HostLink } from './HostLink'

export const STATUSES: VulnRemediationStatus[] = ['open', 'in_progress', 'accepted_risk', 'resolved']
const ACTIVE = new Set<string>(['open', 'in_progress'])
const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
const SEV_TONE = { CRITICAL: 'red', HIGH: 'orange', MEDIUM: 'amber', LOW: 'blue' } as const
const SEV_DOT = { CRITICAL: 'bg-red-500', HIGH: 'bg-orange-500', MEDIUM: 'bg-amber-400', LOW: 'bg-blue-500' } as const
const DAY = 86_400_000

const uniqueIps = (f: VulnFindingOut) => [...new Set(f.affected.map(a => a.ip))]
const sevKey = (s: string | null) => (s ?? 'LOW').toLowerCase() as 'critical' | 'high' | 'medium' | 'low'

/** Risk score (CVSS) as a coloured pill with a dot, like the severity it belongs to. */
/** "KEV" when the CVE is exploited in attacks now (CISA), and its EPSS (probability of exploitation in 30 days) when that is not negligible. */
export function ExploitPills({ kev, epss, due }: { kev?: boolean; epss?: number | null; due?: string | null }) {
  const { t } = useTranslation()
  return (
    <>
      {kev && <Pill tone="red" className="font-bold"><span title={t('vuln.sources.kevTitle', { due: due ?? '—' }) as string}>KEV</span></Pill>}
      {epss != null && epss >= 0.1 && <Pill tone="orange"><span title={t('vuln.sources.epssTitle', { pct: Math.round(epss * 100) }) as string}>EPSS {Math.round(epss * 100)}%</span></Pill>}
    </>
  )
}

export function ScorePill({ f }: { f: VulnFindingOut }) {
  const sev = (f.severity ?? 'LOW') as keyof typeof SEV_TONE
  return (
    <span className="inline-flex items-center gap-1 flex-wrap">
      <Pill tone={SEV_TONE[sev] ?? 'blue'} icon={<i className={cn('w-2 h-2 rounded-full inline-block', SEV_DOT[sev] ?? SEV_DOT.LOW)} />}>{f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}</Pill>
      <ExploitPills kev={f.kev} epss={f.epss} due={f.kev_due} />
    </span>
  )
}

export function SeverityPill({ severity }: { severity: string | null }) {
  const { t } = useTranslation()
  const sev = (severity ?? 'LOW') as keyof typeof SEV_TONE
  return <Pill tone={SEV_TONE[sev] ?? 'blue'}>{t(`assets.sev.${sevKey(severity)}`)}</Pill>
}

/** The expanded part of a finding: description, recommendation, link, due date, and (for admins) the remediation status + note. */
export function RemediationPanel({ finding, assetLinks }: { finding: VulnFindingOut; assetLinks?: Map<string, { id: number; name: string }> }) {
  const { t } = useTranslation()
  const { role } = useAuth()
  const qc = useQueryClient()
  const [note, setNote] = useState(finding.note ?? '')
  const setRemediation = useMutation({
    mutationFn: (data: { status: VulnRemediationStatus; note?: string }) =>
      vulnApi.setRemediation({ product: finding.product, version: finding.version, cve_id: finding.cve_id, status: data.status, note: data.note }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vuln-findings'] }),
  })
  return (
    <div className="space-y-2 text-sm">
      {finding.summary && <p className="text-slate-700 text-xs">{finding.summary}</p>}
      {finding.recommendation && <p className="text-xs text-indigo-700 bg-indigo-50 border border-indigo-100 rounded p-2">{finding.recommendation}</p>}
      {assetLinks && finding.affected.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-xs text-slate-500">{t('vulnDash.affectedAssets')}:</span>
          {uniqueIps(finding).map(ip => {
            const a = assetLinks.get(ip)
            return a
              ? <HostLink key={ip} ip={ip} assetId={a.id} name={a.name} className="text-[11px] bg-slate-100 border border-slate-200 rounded px-1.5 py-0.5 text-indigo-700 hover:bg-indigo-50 no-underline">{a.name} <span className="font-mono text-slate-400">{ip}</span></HostLink>
              : <span key={ip} className="text-[11px] bg-slate-100 border border-slate-200 rounded px-1.5 py-0.5 font-mono text-slate-600">{ip}</span>
          })}
        </div>
      )}
      {finding.ref_url && (
        <a href={finding.ref_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-indigo-600 hover:text-indigo-500 text-xs"><ExternalLink size={12} /> {t('vuln.viewCve')}</a>
      )}
      {finding.due_date && <p className="text-xs text-slate-500">{t('vuln.dueDate')}: {new Date(finding.due_date).toLocaleDateString()}</p>}
      {finding.updated_by && (
        <p className="text-xs text-slate-400">{t('vuln.lastUpdatedBy', { username: finding.updated_by })}{finding.updated_at ? ` · ${new Date(finding.updated_at).toLocaleString()}` : ''}</p>
      )}
      {role === 'admin' && (
        <div className="flex items-center gap-2 pt-1">
          <select value={finding.status} onChange={e => setRemediation.mutate({ status: e.target.value as VulnRemediationStatus, note })} className="text-xs border border-slate-300 rounded px-1.5 py-1">
            {STATUSES.map(s => <option key={s} value={s}>{t(`vuln.status.${s}`)}</option>)}
          </select>
          <input value={note} onChange={e => setNote(e.target.value)} onBlur={() => { if (note !== (finding.note ?? '')) setRemediation.mutate({ status: finding.status, note }) }}
            placeholder={t('vuln.notePlaceholder') as string} className="flex-1 text-xs border border-slate-300 rounded px-2 py-1" />
        </div>
      )}
    </div>
  )
}

// ── Overview ─────────────────────────────────────────────────────────────────

type Metric = 'assets' | 'critical' | 'high' | 'medium' | 'low'

export function VulnOverview({ onOpen }: { onOpen: (tab: 'cves' | 'hosts', filters?: Record<string, string>) => void }) {
  const { t } = useTranslation()
  const { data: findings = [], isLoading } = useQuery({ queryKey: ['vuln-findings', undefined], queryFn: () => vulnApi.findings(), refetchInterval: 30_000 })
  const { data: hist } = useQuery({ queryKey: ['vuln-history'], queryFn: () => assetsApi.vulnHistory(90), refetchInterval: 300_000 })
  const [metric, setMetric] = useState<Metric>('assets')

  const m = useMemo(() => {
    const active = findings.filter(f => ACTIVE.has(f.status))
    const weekAgo = Date.now() - 7 * DAY
    const bySev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    const ips = new Set<string>()
    let instances = 0, fresh = 0
    for (const f of active) {
      const n = uniqueIps(f).length
      instances += n
      if (f.first_seen_at && new Date(f.first_seen_at).getTime() >= weekAgo) fresh += n
      bySev[f.severity ?? 'LOW'] = (bySev[f.severity ?? 'LOW'] ?? 0) + n
      uniqueIps(f).forEach(ip => ips.add(ip))
    }
    const status = STATUSES.map(s => findings.filter(f => f.status === s).length)
    const overdue = active.filter(f => f.overdue).length
    const withDue = active.filter(f => f.due_date && !f.overdue).length
    const top = [...active].sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0) || uniqueIps(b).length - uniqueIps(a).length).slice(0, 10)
    return { instances, fresh, assets: ips.size, bySev, status, overdue, withDue, noDue: active.length - overdue - withDue, top, activeCount: active.length }
  }, [findings])

  if (isLoading) return <p className="text-sm text-slate-500">{t('common.loading')}</p>

  const statusColors = [SEV_COLOR.critical, SEV_COLOR.medium, CAT[0], '#0ca30c']
  const statusSegs: Seg[] = STATUSES.map((s, i) => ({ key: s, label: t(`vuln.status.${s}`) as string, value: m.status[i], color: statusColors[i] }))
  const slaSegs: Seg[] = [
    { key: 'overdue', label: t('vulnDash.slaOverdue') as string, value: m.overdue, color: SEV_COLOR.critical },
    { key: 'due', label: t('vulnDash.slaOnTime') as string, value: m.withDue, color: '#0ca30c' },
    { key: 'none', label: t('vulnDash.slaNone') as string, value: m.noDue, color: OTHER },
  ]
  const sevBars = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => ({ key: s, label: t(`assets.sev.${sevKey(s)}`) as string, value: m.bySev[s], color: SEV_COLOR[sevKey(s)] }))
  const points = (hist?.points ?? []).map(p => ({ t: p.day, n: p[metric] }))
  const kpi = (label: string, value: number, sub: string | undefined, onClick: () => void) => (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden cursor-pointer hover:border-indigo-300" onClick={onClick} role="button" tabIndex={0} onKeyDown={e => { if (e.key === 'Enter') onClick() }}>
      <div className="px-4 py-2 text-sm font-semibold text-slate-800 border-b border-slate-100 bg-slate-50/60">{label}</div>
      <div className="px-4 py-3"><div className="text-4xl font-semibold text-slate-900 leading-none">{fmt(value)}</div>{sub && <div className="text-[11px] text-slate-400 mt-1.5">{sub}</div>}</div>
    </div>
  )

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
      <div className="xl:col-span-8 space-y-4 min-w-0">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {kpi(t('vulnDash.kpiVulns') as string, m.instances, t('vulnDash.kpiVulnsSub', { count: m.activeCount }) as string, () => onOpen('cves', { status: 'active' }))}
          {kpi(t('vulnDash.kpiNew') as string, m.fresh, t('vulnDash.last7') as string, () => onOpen('cves', { status: 'active', new: '1' }))}
          {kpi(t('vulnDash.kpiAssets') as string, m.assets, undefined, () => onOpen('hosts'))}
        </div>

        <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
          <header className="px-4 pt-3 pb-2 flex items-center justify-between">
            <div><h3 className="text-sm font-semibold text-slate-800">{t('vulnDash.topCves')}</h3><p className="text-[11px] text-slate-400">{t('vulnDash.topCvesSub')}</p></div>
            <button onClick={() => onOpen('cves', { status: 'active' })} className="text-xs text-indigo-600 hover:underline">{t('vulnDash.showAll')}</button>
          </header>
          {m.top.length === 0 ? <div className="px-4 pb-4"><Empty text={t('vulnDash.none') as string} /></div> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-slate-400 border-y border-slate-200 bg-slate-50">
                  <th className="px-4 py-2 font-normal">CVE</th><th className="font-normal">{t('assets.riskScore')}</th><th className="font-normal">{t('assets.colSeverity')}</th>
                  <th className="font-normal">{t('assets.affected')}</th><th className="font-normal text-right pr-4">{t('vulnDash.assetsAffected')}</th></tr></thead>
                <tbody>{m.top.map(f => (
                  <tr key={f.id} className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer" onClick={() => onOpen('cves', { q: f.cve_id, status: 'all', open: String(f.id) })}>
                    <td className="px-4 py-2"><a onClick={e => e.stopPropagation()} href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline font-mono text-xs">{f.cve_id}</a></td>
                    <td><ScorePill f={f} /></td><td><SeverityPill severity={f.severity} /></td>
                    <td className="text-slate-700 text-xs">{f.product} <span className="font-mono text-slate-400">{f.version}</span></td>
                    <td className="text-right pr-4 tabular-nums font-medium">{uniqueIps(f).length}</td>
                  </tr>))}</tbody>
              </table>
            </div>
          )}
        </section>

        <Widget title={t('vulnDash.overTime') as string} subtitle={t('vulnDash.overTimeSub') as string}
          right={<select value={metric} onChange={e => setMetric(e.target.value as Metric)} className="text-xs border border-slate-300 rounded px-1.5 py-1 bg-white">
            <option value="assets">{t('vulnDash.mAssets')}</option>{(['critical', 'high', 'medium', 'low'] as const).map(k => <option key={k} value={k}>{t(`assets.sev.${k}`)}</option>)}
          </select>}>
          {points.length < 2
            ? <Empty text={t('vulnDash.historyCollecting') as string} />
            : <AreaChart points={points} label={t('vulnDash.overTime') as string} color={metric === 'assets' ? CAT[0] : SEV_COLOR[metric]} tickEvery={Math.max(1, Math.ceil(points.length / 6))} tickLabel={iso => new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })} />}
        </Widget>
      </div>

      <div className="xl:col-span-4 space-y-4 min-w-0">
        <Widget title={t('vulnDash.bySeverity') as string} subtitle={t('vulnDash.bySeveritySub') as string}>
          {m.instances === 0 ? <Empty text={t('vulnDash.none') as string} /> : <HBars bars={sevBars} onSelect={k => onOpen('cves', { status: 'active', sev: k })} />}
        </Widget>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-1 gap-4">
          <Widget title={t('vulnDash.remediation') as string}><Donut segs={statusSegs} size={120} centerLabel={t('vulnDash.findings') as string} onSelect={k => onOpen('cves', { status: k })} /></Widget>
          <Widget title={t('vulnDash.sla') as string} subtitle={t('vulnDash.slaSub') as string}><Donut segs={slaSegs} size={120} centerLabel={t('vulnDash.findings') as string} onSelect={k => onOpen('cves', { status: 'active', sla: k })} /></Widget>
        </div>
      </div>
    </div>
  )
}

// ── CVE list ─────────────────────────────────────────────────────────────────

type SortKey = 'cve' | 'score' | 'assets'

export function VulnCveList() {
  const { t } = useTranslation()
  const { data: findings = [], isLoading } = useQuery({ queryKey: ['vuln-findings', undefined], queryFn: () => vulnApi.findings(), refetchInterval: 30_000 })
  const { data: assets = [] } = useQuery({ queryKey: ['assets'], queryFn: assetsApi.list })
  const links = useMemo(() => new Map(assets.filter(a => a.ip).map(a => [a.ip!, { id: a.id, name: a.name }])), [assets])
  const [params] = useSearchParams()
  const [q, setQ] = useState(params.get('q') ?? '')
  const [sev, setSev] = useState(params.get('sev') ?? 'all')
  const [status, setStatus] = useState(params.get('status') ?? 'active')
  const [sla, setSla] = useState(params.get('sla') ?? 'all')
  const [onlyNew, setOnlyNew] = useState(params.get('new') === '1')
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'score', dir: -1 })
  const [open, setOpen] = useState<number | null>(params.get('open') ? Number(params.get('open')) : null)
  const [page, setPage] = useState(0)
  const SIZE = 25

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const f = findings.filter(x =>
      (status === 'all' || (status === 'active' ? ACTIVE.has(x.status) : status === 'ignored' ? !ACTIVE.has(x.status) : x.status === status))
      && (sev === 'all' || x.severity === sev)
      && (sla === 'all' || (sla === 'overdue' ? x.overdue : sla === 'due' ? !!x.due_date && !x.overdue : !x.due_date))
      && (!onlyNew || (x.first_seen_at != null && Date.now() - new Date(x.first_seen_at).getTime() < 7 * DAY))
      && (!needle || [x.cve_id, x.product, x.summary, ...x.affected.map(a => a.ip)].some(v => (v ?? '').toLowerCase().includes(needle))))
    const val = (x: VulnFindingOut) => sort.key === 'cve' ? x.cve_id : sort.key === 'assets' ? uniqueIps(x).length : (x.cvss_score ?? -1)
    return f.sort((a, b) => { const A = val(a), B = val(b); return (A < B ? -1 : A > B ? 1 : 0) * sort.dir || (SEV_RANK[a.severity ?? ''] ?? 9) - (SEV_RANK[b.severity ?? ''] ?? 9) })
  }, [findings, q, sev, status, sla, onlyNew, sort])
  const pages = Math.max(1, Math.ceil(rows.length / SIZE))
  const th = (key: SortKey, label: string, cls = '') => (
    <th className={cn('font-normal cursor-pointer select-none whitespace-nowrap', sort.key === key && 'text-indigo-600', cls)} onClick={() => { setSort(s => ({ key, dir: s.key === key ? (-s.dir as 1 | -1) : -1 })); setPage(0) }}>
      <span className="inline-flex items-center gap-0.5">{label}{sort.key === key && (sort.dir === 1 ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}</span>
    </th>
  )
  const sel = 'text-xs border border-slate-300 rounded-lg px-2 py-1.5 bg-white'

  return (
    <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
      <div className="px-4 pt-3 pb-3 flex flex-wrap gap-2 items-center">
        <h3 className="text-sm font-semibold text-slate-800 mr-2">{t('vulnDash.tabCves')}</h3>
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input value={q} onChange={e => { setQ(e.target.value); setPage(0) }} placeholder={t('assets.filterKeyword') as string} className="text-sm border border-slate-300 rounded-lg pl-7 pr-3 py-1.5 w-56" />
        </div>
        <select value={sev} onChange={e => { setSev(e.target.value); setPage(0) }} className={sel}>
          <option value="all">{t('assets.allSeverities')}</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{t(`assets.sev.${sevKey(s)}`)}</option>)}
        </select>
        <select value={status} onChange={e => { setStatus(e.target.value); setPage(0) }} className={sel}>
          <option value="active">{t('vulnDash.stActive')}</option><option value="ignored">{t('vulnDash.stIgnored')}</option><option value="all">{t('vulnDash.stAll')}</option>
          {STATUSES.map(s => <option key={s} value={s}>{t(`vuln.status.${s}`)}</option>)}
        </select>
        {(sla !== 'all' || onlyNew) && (
          <button className="text-xs bg-indigo-50 border border-indigo-100 text-indigo-700 rounded-full px-2.5 py-1" onClick={() => { setSla('all'); setOnlyNew(false) }}>
            {sla !== 'all' ? t(sla === 'overdue' ? 'vulnDash.slaOverdue' : sla === 'due' ? 'vulnDash.slaOnTime' : 'vulnDash.slaNone') : t('vulnDash.kpiNew')} ×
          </button>
        )}
        <span className="ml-auto text-xs text-slate-500">{t('assets.showing', { from: rows.length ? page * SIZE + 1 : 0, to: Math.min(rows.length, (page + 1) * SIZE), total: rows.length })}</span>
        <a href={vulnApi.exportUrl(sev === 'all' ? undefined : sev)} className="inline-flex items-center gap-1 text-xs px-2.5 py-1.5 rounded border border-slate-200 text-slate-600 hover:text-indigo-600 bg-white"><Download size={12} /> CSV</a>
      </div>
      {isLoading ? <p className="px-4 pb-4 text-sm text-slate-500">{t('common.loading')}</p> : rows.length === 0 ? <div className="px-4 pb-4"><Empty text={t('vulnDash.none') as string} /></div> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-slate-400 border-y border-slate-200 bg-slate-50">
              <th className="w-6" />{th('cve', 'CVE', 'py-2')}{th('score', t('assets.riskScore') as string)}<th className="font-normal">{t('assets.colSeverity')}</th>
              <th className="font-normal">{t('assets.status')}</th><th className="font-normal">{t('assets.affected')}</th>{th('assets', t('vulnDash.assetsAffected') as string, 'text-right pr-4')}</tr></thead>
            <tbody>
              {rows.slice(page * SIZE, (page + 1) * SIZE).map(f => (
                <Fragment key={f.id}>
                  <tr onClick={() => setOpen(open === f.id ? null : f.id)} className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer align-top">
                    <td className="pl-3 py-2"><ChevronRight size={14} className={cn('text-slate-400 transition-transform', open === f.id && 'rotate-90')} /></td>
                    <td className="py-2 font-mono text-xs text-blue-600">{f.cve_id}{f.overdue && <span className="ml-1.5 text-[10px] text-red-600 font-sans">{t('vuln.overdue')}</span>}</td>
                    <td className="py-2"><ScorePill f={f} /></td><td className="py-2"><SeverityPill severity={f.severity} /></td>
                    <td className="py-2 text-xs text-slate-600">{t(`vuln.status.${f.status}`)}</td>
                    <td className="py-2 text-xs text-slate-700">{f.product} <span className="font-mono text-slate-400">{f.version}</span></td>
                    <td className="py-2 text-right pr-4 tabular-nums font-medium">{uniqueIps(f).length}</td>
                  </tr>
                  {open === f.id && <tr className="border-b border-slate-100 bg-slate-50/60"><td /><td colSpan={6} className="py-3 pr-4"><RemediationPanel finding={f} assetLinks={links} /></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pages > 1 && (
        <div className="px-4 py-2 flex items-center justify-end gap-2 text-xs">
          <button disabled={page === 0} onClick={() => setPage(page - 1)} className="px-2 py-1 border rounded disabled:opacity-40">‹</button>
          <span className="text-slate-500">{page + 1} / {pages}</span>
          <button disabled={page >= pages - 1} onClick={() => setPage(page + 1)} className="px-2 py-1 border rounded disabled:opacity-40">›</button>
        </div>
      )}
    </section>
  )
}

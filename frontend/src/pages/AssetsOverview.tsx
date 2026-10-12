import { useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { assetsApi, type AssetType } from '../lib/api'
import { Widget, Empty, Donut, HBars, NumberTiles, fmt, OTHER, type Seg } from '../components/SecCharts'
import { TypeIcon, TYPE_COLOR, TYPE_ORDER, VulnPill, LifecyclePill, TypePill, ago } from '../components/AssetBits'
import { VulnScanStatusPanel } from '../components/VulnScanStatusPanel'
import { Button } from '../components/ui/Button'
import { Boxes, RefreshCw, ArrowUp, ArrowDown, MapPin } from 'lucide-react'
import { cn } from '../lib/utils'

// Asset overview: how many things are on the network, what they are, where, how old their systems are, how exposed.
export function AssetsOverview() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const nav = useNavigate()
  const { data, isLoading } = useQuery({ queryKey: ['asset-summary'], queryFn: assetsApi.summary, refetchInterval: 60_000 })
  const refresh = useMutation({
    mutationFn: assetsApi.refresh,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['asset-summary'] }); qc.invalidateQueries({ queryKey: ['assets'] }) },
  })

  const typeSegs: Seg[] = useMemo(() => {
    const n = new Map((data?.by_type ?? []).map(x => [x.key, x.n]))
    return TYPE_ORDER.filter(k => (n.get(k) ?? 0) > 0).map(k => ({ key: k, label: t(`assets.type.${k}`) as string, value: n.get(k)!, color: TYPE_COLOR[k] }))
  }, [data, t])

  if (isLoading || !data) {
    return <div className="p-6"><p className="text-sm text-slate-500">{t('common.loading')}</p></div>
  }
  const change = data.total_7d_ago > 0 ? ((data.total - data.total_7d_ago) / data.total_7d_ago) * 100 : null
  const maxDay = Math.max(1, ...data.new_by_day.map(d => d.n))
  const lc = data.by_lifecycle
  const lifecycleSegs: Seg[] = [
    { key: 'supported', label: t('assets.lifecycle.supported') as string, value: lc.supported, color: '#0ca30c' },
    { key: 'ending', label: t('assets.lifecycle.ending') as string, value: lc.ending, color: '#fab219' },
    { key: 'eol', label: t('assets.lifecycle.eol') as string, value: lc.eol, color: '#d03b3b' },
    { key: 'unknown', label: t('assets.lifecycle.unknown') as string, value: lc.unknown, color: OTHER },
  ]
  const sl = data.by_scan_level
  const scanSegs: Seg[] = [
    { key: 'credentialed', label: t('assets.scanLevel.credentialed') as string, value: sl.credentialed, color: '#0ca30c' },
    { key: 'snmp', label: t('assets.scanLevel.snmp') as string, value: sl.snmp, color: '#2a78d6' },
    { key: 'passive', label: t('assets.scanLevel.passive') as string, value: sl.passive, color: OTHER },
  ]
  const v = data.vulnerable

  return (
    <div className="p-6 space-y-4 max-w-[1400px]">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Boxes size={20} className="text-indigo-600" /> {t('assets.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('assets.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/inventory/list" className="text-sm text-indigo-600 hover:underline">{t('assets.openList')}</Link>
          <Button size="sm" variant="secondary" onClick={() => refresh.mutate()} disabled={refresh.isPending}>
            <RefreshCw size={13} className={refresh.isPending ? 'animate-spin' : ''} /> {t('assets.rebuild')}
          </Button>
        </div>
      </div>

      <VulnScanStatusPanel hint={t('assets.scanHint') as string} />

      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-3 lg:col-span-3 space-y-4">
          <Widget title={t('assets.totalDiscovered') as string}>
            <div className="flex items-end justify-between gap-2">
              <div className="text-5xl font-semibold text-slate-900 leading-none">{data.total.toLocaleString()}</div>
              {change != null && (
                <span className={cn('inline-flex items-center gap-1 text-xs font-medium rounded-full px-2 py-0.5', change >= 0 ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700')}
                  title={t('assets.vs7d') as string}>
                  {change >= 0 ? <ArrowUp size={11} /> : <ArrowDown size={11} />}{Math.abs(change).toFixed(1)}%
                </span>
              )}
            </div>
            {data.inactive > 0 && <p className="text-xs text-slate-400 mt-2">{t('assets.inactiveN', { count: data.inactive })}</p>}
          </Widget>
          <Widget title={t('assets.newAssets') as string} subtitle={t('assets.last7') as string}>
            <div className="flex items-end justify-between gap-3">
              <div className="text-4xl font-semibold text-slate-900 leading-none">+{data.new_7d.toLocaleString()}</div>
              <div className="flex items-end gap-1 h-10" aria-label={t('assets.newAssets') as string}>
                {data.new_by_day.map(d => (
                  <div key={d.day} className="w-3 rounded-t" title={`${new Date(d.day).toLocaleDateString()}: ${d.n}`}
                    style={{ height: `${Math.max(3, (d.n / maxDay) * 40)}px`, background: d.n ? '#1baf7a' : '#d9efe6' }} />
                ))}
              </div>
            </div>
          </Widget>
        </div>

        <Widget className="xl:col-span-5 lg:col-span-3" title={t('assets.types') as string}>
          {typeSegs.length === 0 ? <Empty text={t('assets.none') as string} /> : <Donut segs={typeSegs} size={150} centerLabel={t('assets.assets') as string} />}
        </Widget>

        <Widget className="xl:col-span-4 lg:col-span-6" title={t('assets.byLocation') as string} subtitle={t('assets.topSites') as string}>
          {data.by_location.length === 0 ? <Empty text={t('assets.none') as string} /> : (
            <ul className="space-y-3">
              {data.by_location.slice(0, 6).map(l => (
                <li key={l.name} className="flex items-center gap-3">
                  <span className="w-8 h-8 rounded-lg bg-orange-50 text-orange-500 flex items-center justify-center shrink-0"><MapPin size={15} /></span>
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between text-sm"><span className="truncate text-slate-800">{l.name || t('assets.noLocation')}</span><span className="tabular-nums text-slate-500">{fmt(l.n)}</span></div>
                    <div className="h-1.5 bg-slate-100 rounded-full mt-1 overflow-hidden"><div className="h-full bg-orange-400 rounded-full" style={{ width: `${(l.n / data.by_location[0].n) * 100}%` }} /></div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Widget>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <Widget className="xl:col-span-4 lg:col-span-3" title={t('assets.exposure') as string} subtitle={t('assets.exposureSub') as string}>
          <NumberTiles tiles={[
            { label: t('assets.assetsWithVulns') as string, value: v.assets },
            { label: t('assets.sev.critical') as string, value: v.critical, tone: 'critical' },
            { label: t('assets.sev.high') as string, value: v.high, tone: 'high' },
          ]} />
        </Widget>
        <Widget className="xl:col-span-4 lg:col-span-3" title={t('assets.osLifecycle') as string} subtitle={t('assets.osLifecycleSub') as string}>
          <Donut segs={lifecycleSegs} size={130} centerLabel={t('assets.assets') as string} />
        </Widget>
        <Widget className="xl:col-span-4 lg:col-span-6" title={t('assets.scanLevels') as string} subtitle={t('assets.scanLevelsSub') as string}>
          <Donut segs={scanSegs} size={130} centerLabel={t('assets.assets') as string} />
        </Widget>
      </div>

      <section className="bg-white border border-slate-200 rounded-xl shadow-sm">
        <header className="px-4 pt-3 pb-2 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-800">{t('assets.topRisk')}</h3>
            <p className="text-[11px] text-slate-400">{t('assets.topRiskSub')}</p>
          </div>
          <Link to="/inventory/list" className="text-xs text-indigo-600 hover:underline">{t('assets.openList')}</Link>
        </header>
        {data.top_risk.length === 0 ? <div className="px-4 pb-4"><Empty text={t('assets.noRisk') as string} /></div> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-slate-400 border-y border-slate-200 bg-slate-50">
                <th className="px-4 py-2 font-normal">{t('assets.colName')}</th><th className="font-normal">{t('assets.colType')}</th><th className="font-normal">{t('assets.colVulns')}</th>
                <th className="font-normal">{t('assets.colLifecycle')}</th><th className="font-normal">{t('assets.colIp')}</th><th className="font-normal pr-4">{t('assets.colLastSeen')}</th>
              </tr></thead>
              <tbody>
                {data.top_risk.map(a => (
                  <tr key={a.id} onClick={() => nav(`/inventory/${a.id}`)} className="border-b border-slate-100 hover:bg-slate-50 cursor-pointer">
                    <td className="px-4 py-2.5"><span className="inline-flex items-center gap-2 text-slate-800 font-medium"><TypeIcon type={a.type as AssetType} />{a.name}</span></td>
                    <td><TypePill type={a.type} role={a.role} /></td>
                    <td><VulnPill v={a.vulns} /></td>
                    <td><LifecyclePill status={a.lifecycle} /></td>
                    <td className="font-mono text-xs text-slate-600">{a.ip ?? '—'}</td>
                    <td className="pr-4 text-xs text-slate-500">{ago(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

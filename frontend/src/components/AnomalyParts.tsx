import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { anomaliesApi, AnomalyBand, AnomalyItem } from '../lib/api'
import { cn } from '../lib/utils'

// Shared by the agent's Anomalies page and Central's: the table of what is unusual on a host, and the chart of one series with its
// learned normal range (services/anomaly.py).

const n = (v: number | null | undefined) => v == null ? '—' : v.toLocaleString(undefined, { maximumFractionDigits: v >= 100 ? 0 : 1 })

export function scoreTone(z: number) {
  return z >= 8 ? 'bg-red-100 text-red-700' : z >= 4 ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'
}

export function AnomalyItems({ items, onPick, picked }: { items: AnomalyItem[]; onPick?: (key: string) => void; picked?: string | null }) {
  const { t } = useTranslation()
  return (
    <table className="w-full text-xs">
      <thead><tr className="text-left text-slate-400">
        <th className="font-medium px-1.5 py-1">{t('anomaly.col.series')}</th><th className="font-medium px-1.5 py-1 text-right">{t('anomaly.col.now')}</th>
        <th className="font-medium px-1.5 py-1 text-right">{t('anomaly.col.usual')}</th><th className="font-medium px-1.5 py-1 text-right">{t('anomaly.col.limit')}</th>
        <th className="font-medium px-1.5 py-1 text-right" title={t('anomaly.scoreHelp') as string}>{t('anomaly.col.score')}</th>
      </tr></thead>
      <tbody>
        {[...items].sort((a, b) => b.score - a.score).map((i, k) => {
          const above = i.value >= i.expected
          return (
            <tr key={i.key ?? k} onClick={() => i.key && onPick?.(i.key)}
              className={cn('border-t border-slate-100', onPick && i.key && 'cursor-pointer hover:bg-slate-50', picked && picked === i.key && 'bg-indigo-50')}>
              <td className="px-1.5 py-1 text-slate-700">{i.label}</td>
              <td className="px-1.5 py-1 text-right font-mono font-semibold text-slate-900">{n(i.value)} {i.unit}</td>
              <td className="px-1.5 py-1 text-right font-mono text-slate-600">{n(i.expected)} {i.unit}</td>
              <td className="px-1.5 py-1 text-right font-mono text-slate-500">{above ? '≤ ' + n(i.high) : '≥ ' + n(i.low)} {i.unit}</td>
              <td className="px-1.5 py-1 text-right"><span className={cn('rounded px-1.5 py-0.5 font-semibold font-mono', scoreTone(i.score))}>{i.score.toFixed(1)}</span></td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

export function AnomalyBandChart({ seriesKey, days = 3 }: { seriesKey: string; days?: number }) {
  const { t } = useTranslation()
  const q = useQuery({ queryKey: ['anomaly-band', seriesKey, days], queryFn: () => anomaliesApi.band(seriesKey, days) })
  const d = q.data
  const W = 760, H = 200, P = { l: 44, r: 10, t: 8, b: 22 }
  const geo = useMemo(() => {
    if (!d || d.points.length < 2) return null
    const xs = d.points.map(p => new Date(p.t).getTime())
    const ys = d.points.flatMap(p => [p.v, p.m, p.lo, p.hi].filter((x): x is number => x != null))
    let lo = Math.min(...ys), hi = Math.max(...ys)
    if (hi - lo < 1) { hi += 0.5; lo -= 0.5 }
    const x0 = xs[0], x1 = xs[xs.length - 1]
    const X = (x: number) => P.l + ((x - x0) / Math.max(1, x1 - x0)) * (W - P.l - P.r)
    const Y = (y: number) => P.t + (1 - (y - lo) / (hi - lo)) * (H - P.t - P.b)
    const withBand = d.points.filter(p => p.m != null)
    const top = withBand.map(p => `${X(new Date(p.t).getTime()).toFixed(1)},${Y(p.hi ?? hi).toFixed(1)}`)
    const bottom = [...withBand].reverse().map(p => `${X(new Date(p.t).getTime()).toFixed(1)},${Y(p.lo ?? lo).toFixed(1)}`)
    const path = (f: (p: AnomalyBand['points'][number]) => number | null | undefined) =>
      d.points.filter(p => f(p) != null).map((p, i) => `${i ? 'L' : 'M'}${X(new Date(p.t).getTime()).toFixed(1)},${Y(f(p)!).toFixed(1)}`).join(' ')
    return {
      band: withBand.length > 1 ? `M${top.join(' L')} L${bottom.join(' L')} Z` : null, med: path(p => p.m), val: path(p => p.v),
      out: d.points.filter(p => (p.z ?? 0) >= 4).map(p => ({ x: X(new Date(p.t).getTime()), y: Y(p.v) })), lo, hi, x0, x1, Y,
    }
  }, [d])
  if (q.isLoading) return <p className="text-xs text-slate-500">{t('common.loading')}</p>
  if (!d || !geo) return <p className="text-xs text-slate-500">{t('anomaly.noChart')}</p>
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-3 text-[11px] text-slate-500 flex-wrap">
        <span className="font-medium text-slate-700">{d.name}</span>
        <span className="flex items-center gap-1"><span className="inline-block w-3 h-2 rounded-sm bg-emerald-100 border border-emerald-300" />{t('anomaly.legend.band')}</span>
        <span className="flex items-center gap-1"><span className="inline-block w-3 border-t border-dashed border-emerald-600" />{t('anomaly.legend.median')}</span>
        <span className="flex items-center gap-1"><span className="inline-block w-3 border-t-2 border-indigo-600" />{t('anomaly.legend.value')}</span>
        <span className="flex items-center gap-1"><span className="inline-block w-2 h-2 rounded-full bg-red-500" />{t('anomaly.legend.out')}</span>
        {d.learning && <span className="text-amber-700">{t('anomaly.learningSeries')}</span>}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-52 bg-white border border-slate-200 rounded-lg">
        {[0, 0.5, 1].map(f => {
          const v = geo.lo + (geo.hi - geo.lo) * f
          return <g key={f}><line x1={P.l} x2={W - P.r} y1={geo.Y(v)} y2={geo.Y(v)} className="text-slate-100" stroke="currentColor" /><text x={P.l - 4} y={geo.Y(v) + 3} textAnchor="end" fontSize="9" className="fill-slate-400">{n(v)}</text></g>
        })}
        {geo.band && <path d={geo.band} fill="#10b981" fillOpacity="0.15" stroke="#10b981" strokeOpacity="0.4" strokeWidth="0.5" />}
        {geo.med && <path d={geo.med} fill="none" stroke="#059669" strokeWidth="1" strokeDasharray="4 3" />}
        <path d={geo.val} fill="none" stroke="#4f46e5" strokeWidth="1.5" />
        {geo.out.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#ef4444" />)}
        <text x={P.l} y={H - 6} fontSize="9" className="fill-slate-400">{new Date(geo.x0).toLocaleString()}</text>
        <text x={W - P.r} y={H - 6} fontSize="9" textAnchor="end" className="fill-slate-400">{new Date(geo.x1).toLocaleString()}</text>
      </svg>
    </div>
  )
}

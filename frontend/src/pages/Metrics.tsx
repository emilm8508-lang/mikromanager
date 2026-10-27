import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LineChart, Plus, Trash2 } from 'lucide-react'
import { metricsApi, MetricRule, MetricSeriesRow } from '../lib/api'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const KINDS = ['cpu', 'mem', 'disk', 'temp', 'ups_charge', 'ups_load', 'ups_runtime', 'ups_temp', 'other']

function Chart({ s }: { s: MetricSeriesRow }) {
  const { t } = useTranslation()
  const [days, setDays] = useState(7)
  const q = useQuery({ queryKey: ['metric-series', s.key, days], queryFn: () => metricsApi.series(s.key, days) })
  const d = q.data
  const W = 760, H = 220, P = { l: 40, r: 12, t: 10, b: 24 }
  const geo = useMemo(() => {
    if (!d || d.points.length < 2) return null
    const xs = d.points.map(p => new Date(p.t).getTime()), ys = d.points.map(p => p.v)
    const x0 = xs[0], x1 = xs[xs.length - 1]
    let lo = Math.min(...ys), hi = Math.max(...ys)
    if (s.kind === 'disk' || s.kind === 'mem' || s.unit === '%') { lo = Math.min(lo, 0); hi = Math.max(hi, 100) }
    if (hi - lo < 1) hi = lo + 1
    const X = (x: number) => P.l + ((x - x0) / Math.max(1, x1 - x0)) * (W - P.l - P.r)
    const Y = (y: number) => P.t + (1 - (y - lo) / (hi - lo)) * (H - P.t - P.b)
    const path = d.points.map((p, i) => `${i ? 'L' : 'M'}${X(new Date(p.t).getTime()).toFixed(1)},${Y(p.v).toFixed(1)}`).join(' ')
    // the fitted line over the last week, from the trend: value now and slope per day
    let fit: string | null = null
    const tr = d.trend
    if (tr.slope != null && tr.current != null) {
      const spanMs = Math.min(days, 7) * 86400000
      const yEnd = tr.current, yStart = tr.current - tr.slope * (spanMs / 86400000)
      fit = `M${X(x1 - spanMs).toFixed(1)},${Y(yStart).toFixed(1)} L${X(x1).toFixed(1)},${Y(yEnd).toFixed(1)}`
    }
    return { path, fit, lo, hi, x0, x1, Y }
  }, [d, days, s.kind, s.unit])
  return (
    <div className="px-4 py-3 bg-slate-50 space-y-2">
      <div className="flex items-center gap-2 text-xs">
        {[1, 7, 30, 90].map(n => <button key={n} onClick={() => setDays(n)} className={cn('px-2 py-0.5 rounded border', days === n ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white border-slate-300 text-slate-600')}>{n} {t('metrics.days')}</button>)}
        {d?.trend.slope != null && <span className="ml-auto text-slate-500">{t('metrics.trend', { slope: d.trend.slope.toFixed(2), unit: s.unit, r2: d.trend.r2 })}</span>}
      </div>
      {!geo ? <div className="text-xs text-slate-500">{q.isLoading ? t('common.loading') : t('metrics.notEnough')}</div> : (
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-56 bg-white border border-slate-200 rounded-lg">
          {[0, 0.25, 0.5, 0.75, 1].map(f => {
            const v = geo.lo + (geo.hi - geo.lo) * f
            return <g key={f}><line x1={P.l} x2={W - P.r} y1={geo.Y(v)} y2={geo.Y(v)} stroke="currentColor" className="text-slate-100" /><text x={P.l - 4} y={geo.Y(v) + 3} textAnchor="end" className="fill-slate-400" fontSize="9">{v.toFixed(v >= 100 ? 0 : 1)}</text></g>
          })}
          <text x={P.l} y={H - 6} className="fill-slate-400" fontSize="9">{new Date(geo.x0).toLocaleDateString()}</text>
          <text x={W - P.r} y={H - 6} textAnchor="end" className="fill-slate-400" fontSize="9">{new Date(geo.x1).toLocaleString()}</text>
          {geo.fit && <path d={geo.fit} fill="none" stroke="#f59e0b" strokeWidth="1.5" strokeDasharray="5 4" />}
          <path d={geo.path} fill="none" stroke="#4f46e5" strokeWidth="1.5" />
        </svg>
      )}
    </div>
  )
}

function Rules({ rules }: { rules: MetricRule[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const blank = (): MetricRule => ({ name: '', kind: 'cpu', op: '>', threshold: 90, minutes: 15, severity: 'medium', match: '', enabled: true })
  const [draft, setDraft] = useState<MetricRule | null>(null)
  const save = useMutation({ mutationFn: (r: MetricRule[]) => metricsApi.saveRules(r), onSuccess: () => { setDraft(null); void qc.invalidateQueries({ queryKey: ['metrics'] }) } })
  const strip = (r: MetricRule): MetricRule => ({ name: r.name, kind: r.kind, op: r.op, threshold: r.threshold, minutes: r.minutes, severity: r.severity, match: r.match, enabled: r.enabled })
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-sm">
      <div className="flex items-center gap-3">
        <h2 className="font-semibold text-slate-900 flex-1">{t('metrics.rules.title')}</h2>
        <button onClick={() => setDraft(blank())} className="flex items-center gap-1 text-xs border border-slate-300 rounded-lg px-2.5 py-1 hover:bg-slate-50"><Plus size={12} /> {t('metrics.rules.add')}</button>
      </div>
      <p className="text-xs text-slate-500">{t('metrics.rules.intro')}</p>
      {rules.length === 0 && !draft && <p className="text-xs text-slate-400">{t('metrics.rules.none')}</p>}
      <div className="divide-y divide-slate-100">
        {rules.map(r => (
          <div key={r.id} className="flex items-center gap-3 py-1.5">
            <input type="checkbox" checked={r.enabled} onChange={e => save.mutate(rules.map(x => strip(x.id === r.id ? { ...x, enabled: e.target.checked } : x)))} />
            <div className="flex-1 min-w-0">
              <div className="text-slate-900">{r.name}</div>
              <div className="text-xs text-slate-500">{t(`metrics.kind.${r.kind}`)} {r.op} {r.threshold}{r.minutes ? ` · ${t('metrics.rules.forMin', { n: r.minutes })}` : ''}{r.match ? ` · /${r.match}/` : ''} · {t(`syslog.sev.${r.severity}`)}</div>
            </div>
            <button className="p-1 text-slate-400 hover:text-red-600" onClick={() => save.mutate(rules.filter(x => x.id !== r.id).map(strip))}><Trash2 size={14} /></button>
          </div>
        ))}
      </div>
      {draft && (
        <div className="border border-slate-200 rounded-lg p-3 space-y-2 bg-slate-50">
          <input placeholder={t('metrics.rules.name') as string} value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} className="w-full border border-slate-300 rounded-lg px-2 py-1 text-sm" />
          <div className="flex gap-2 flex-wrap items-end text-xs text-slate-500">
            <label>{t('metrics.rules.kind')}<select value={draft.kind} onChange={e => setDraft({ ...draft, kind: e.target.value })} className="block border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900">{KINDS.map(k => <option key={k} value={k}>{t(`metrics.kind.${k}`)}</option>)}</select></label>
            <label>{t('metrics.rules.when')}<select value={draft.op} onChange={e => setDraft({ ...draft, op: e.target.value })} className="block border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900"><option value=">">{'>'}</option><option value="<">{'<'}</option></select></label>
            <label>{t('metrics.rules.threshold')}<input type="number" value={draft.threshold} onChange={e => setDraft({ ...draft, threshold: Number(e.target.value) })} className="block w-24 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
            <label>{t('metrics.rules.minutes')}<input type="number" min={0} value={draft.minutes} onChange={e => setDraft({ ...draft, minutes: Number(e.target.value) })} className="block w-24 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
            <label>{t('metrics.rules.severity')}<select value={draft.severity} onChange={e => setDraft({ ...draft, severity: e.target.value })} className="block border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900">{['low', 'medium', 'high', 'critical'].map(k => <option key={k} value={k}>{t(`syslog.sev.${k}`)}</option>)}</select></label>
            <label className="flex-1 min-w-[8rem]">{t('metrics.rules.match')}<input value={draft.match ?? ''} onChange={e => setDraft({ ...draft, match: e.target.value })} placeholder="DC1|SRV" className="block w-full border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900 font-mono" /></label>
            <button disabled={!draft.name.trim() || save.isPending} onClick={() => save.mutate([...rules.map(strip), draft])} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('maint.form.save')}</button>
          </div>
        </div>
      )}
      {save.isError && <div className="text-xs text-red-700">{errText(save.error)}</div>}
    </div>
  )
}

// What the agent measures, with history: charts, the forecast of when a disk is full, and thresholds that must hold for a while to alert.
export function Metrics() {
  const { t } = useTranslation()
  const [open, setOpen] = useState<string | null>(null)
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  const m = useQuery({ queryKey: ['metrics'], queryFn: metricsApi.overview, refetchInterval: 60000 })
  const rows = (m.data?.series ?? []).filter(s => (!kind || s.kind === kind) && (!q.trim() || s.name.toLowerCase().includes(q.trim().toLowerCase())))
  const grid = 'grid-cols-[minmax(0,2fr)_5rem_5rem_6rem_6rem]'
  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><LineChart size={20} className="text-indigo-600" /> {t('metrics.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('metrics.subtitle')}</p>
      </div>
      <div className="flex gap-2 flex-wrap items-center">
        <select value={kind} onChange={e => setKind(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white">
          <option value="">{t('metrics.allKinds')}</option>{KINDS.map(k => <option key={k} value={k}>{t(`metrics.kind.${k}`)}</option>)}
        </select>
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('soc.filter.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56" />
      </div>
      {m.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : rows.length === 0 ? <p className="text-sm text-slate-500">{t('metrics.empty')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className={cn('grid bg-slate-50 text-xs text-slate-500 px-4 py-2', grid)}><div>{t('metrics.col.series')}</div><div>{t('metrics.col.kind')}</div><div className="text-right">{t('metrics.col.now')}</div><div className="text-right">{t('metrics.col.trend')}</div><div className="text-right">{t('metrics.col.full')}</div></div>
          {rows.map(s => (
            <div key={s.key}>
              <div className={cn('grid px-4 py-2 border-t border-slate-100 items-center cursor-pointer hover:bg-slate-50', grid, s.stale && 'opacity-50')} onClick={() => setOpen(open === s.key ? null : s.key)}>
                <div className="min-w-0 truncate text-slate-900">{s.name}</div>
                <div className="text-xs text-slate-500">{t(`metrics.kind.${s.kind}`)}</div>
                <div className="text-right tabular-nums">{s.value != null ? `${s.value.toFixed(1)}${s.unit}` : '—'}</div>
                <div className={cn('text-right tabular-nums text-xs', s.slope != null && s.r2 != null && s.r2 >= 0.6 ? (s.slope > 0 ? 'text-amber-700' : 'text-green-700') : 'text-slate-400')}>{s.slope != null ? `${s.slope > 0 ? '+' : ''}${s.slope.toFixed(1)}${s.unit}/${t('metrics.day')}` : '—'}</div>
                <div className={cn('text-right tabular-nums', s.days_to_full != null && s.days_to_full <= 14 ? 'text-red-600 font-semibold' : 'text-slate-500')}>{s.days_to_full != null ? `~${Math.round(s.days_to_full)} ${t('metrics.days')}` : ''}</div>
              </div>
              {open === s.key && <Chart s={s} />}
            </div>
          ))}
        </div>
      )}
      {m.data && <Rules rules={m.data.rules} />}
      <p className="text-xs text-slate-400">{t('metrics.note')}</p>
    </div>
  )
}

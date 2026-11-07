import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { BrainCircuit, Check, X, RefreshCw, Download } from 'lucide-react'
import { anomaliesApi, AnomalyEvent } from '../lib/api'
import { AnomalyItems, AnomalyBandChart, scoreTone } from '../components/AnomalyParts'
import { cn } from '../lib/utils'

// Anomaly detection, stage 1 of the ML work (services/anomaly.py): every host's series against their own learned range per hour of
// the week, with the operator's verdict on each event — the labels the detector is measured against.

const ago = (iso: string) => new Date(iso).toLocaleString()

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl px-4 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-2xl font-bold text-slate-900 tabular-nums">{value}</div>
      {sub && <div className="text-[11px] text-slate-400">{sub}</div>}
    </div>
  )
}

function Verdict({ ev }: { ev: AnomalyEvent }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const set = useMutation({
    mutationFn: (v: 'true' | 'false' | null) => anomaliesApi.verdict(ev.id, v),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['anomalies'] }),
  })
  const btn = (v: 'true' | 'false', Icon: typeof Check, label: string, on: string) => (
    <button disabled={set.isPending} onClick={() => set.mutate(ev.verdict === v ? null : v)} title={label}
      className={cn('flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px]', ev.verdict === v ? on : 'border-slate-300 text-slate-500 hover:bg-slate-50')}>
      <Icon size={11} /> {label}
    </button>
  )
  return (
    <div className="flex items-center gap-1">
      {btn('true', Check, t('anomaly.verdict.true'), 'bg-green-100 border-green-300 text-green-800')}
      {btn('false', X, t('anomaly.verdict.false'), 'bg-slate-200 border-slate-300 text-slate-700')}
      {ev.verdict && !ev.verdict_set && <span className="text-[10px] text-slate-400" title={t('anomaly.verdict.fromSoc') as string}>SOC</span>}
    </div>
  )
}

export function Anomalies() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['anomalies'], queryFn: () => anomaliesApi.overview(90), refetchInterval: 60_000 })
  const run = useMutation({ mutationFn: anomaliesApi.run, onSuccess: () => qc.invalidateQueries({ queryKey: ['anomalies'] }) })
  const [picked, setPicked] = useState<string | null>(null)
  const st = q.data?.stats
  const events = q.data?.events ?? []
  const open = events.filter(e => !e.ended_at)
  const past = events.filter(e => e.ended_at)

  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><BrainCircuit size={20} className="text-indigo-600" /> {t('anomaly.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('anomaly.subtitle')}</p>
        </div>
        <a href="/api/anomalies/events.csv" className="flex items-center gap-1 text-xs border border-slate-300 rounded-lg px-2.5 py-1.5 hover:bg-slate-50"><Download size={12} /> CSV</a>
        <button onClick={() => run.mutate()} disabled={run.isPending} className="flex items-center gap-1 text-xs border border-slate-300 rounded-lg px-2.5 py-1.5 hover:bg-slate-50">
          <RefreshCw size={12} className={run.isPending ? 'animate-spin' : ''} /> {t('anomaly.runNow')}
        </button>
      </div>

      <details className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs text-slate-600">
        <summary className="cursor-pointer font-medium text-slate-700">{t('anomaly.howTitle')}</summary>
        <p className="mt-1.5">{t('anomaly.how', { z: st?.z_open ?? 4, zc: st?.z_close ?? 2.5, days: st?.min_span_days ?? 3 })}</p>
      </details>

      {st && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Stat label={t('anomaly.stat.judged')} value={String(st.judged)} sub={t('anomaly.stat.series', { n: st.series })} />
          <Stat label={t('anomaly.stat.learning')} value={String(st.learning)} sub={t('anomaly.stat.learningSub', { days: st.min_span_days })} />
          <Stat label={t('anomaly.stat.open')} value={String(open.length)} />
          <Stat label={t('anomaly.stat.events')} value={String(st.events)} sub={t('anomaly.stat.labelled', { n: st.labelled })} />
          <Stat label={t('anomaly.stat.precision')} value={st.precision == null ? '—' : `${Math.round(st.precision * 100)} %`}
            sub={st.labelled ? t('anomaly.stat.precisionSub', { t: st.true, f: st.false }) : t('anomaly.stat.noLabels')} />
        </div>
      )}

      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-slate-700">{t('anomaly.openTitle')}</h2>
        {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p>
          : open.length === 0 ? <p className="text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2">{t('anomaly.noneOpen')}</p>
          : open.map(e => (
            <div key={e.id} className={cn('bg-white border rounded-xl p-3 space-y-2', e.severity === 'high' ? 'border-red-300' : 'border-amber-300')}>
              <div className="flex items-center gap-2 flex-wrap text-sm">
                <span className="font-semibold text-slate-900">{e.host || e.host_key}</span>
                <span className="text-xs text-slate-500">{t(`anomaly.cat.${e.category}`)}</span>
                <span className={cn('text-[11px] rounded px-1.5 py-0.5 font-semibold', scoreTone(e.peak_score))}>{t('anomaly.peak')} {e.peak_score.toFixed(1)}</span>
                <span className="text-xs text-slate-500 ml-auto">{t('anomaly.since', { at: ago(e.started_at), min: e.minutes })}</span>
                <Verdict ev={e} />
              </div>
              <AnomalyItems items={e.series} onPick={k => setPicked(p => p === k ? null : k)} picked={picked} />
              {picked && e.series.some(s => s.key === picked) && <AnomalyBandChart seriesKey={picked} />}
            </div>
          ))}
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-3 space-y-2">
        <h2 className="text-sm font-semibold text-slate-700">{t('anomaly.historyTitle')}</h2>
        <p className="text-xs text-slate-500">{t('anomaly.historyIntro')}</p>
        {past.length === 0 ? <p className="text-xs text-slate-400">{t('anomaly.noHistory')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-slate-400 border-b border-slate-200">
                <th className="font-medium px-2 py-1.5">{t('anomaly.col.host')}</th><th className="font-medium px-2 py-1.5">{t('anomaly.col.start')}</th>
                <th className="font-medium px-2 py-1.5 text-right">{t('anomaly.col.minutes')}</th><th className="font-medium px-2 py-1.5 text-right">{t('anomaly.col.peak')}</th>
                <th className="font-medium px-2 py-1.5">{t('anomaly.col.what')}</th><th className="font-medium px-2 py-1.5">{t('anomaly.col.verdict')}</th>
              </tr></thead>
              <tbody>
                {past.map(e => (
                  <tr key={e.id} className="border-t border-slate-100 align-top">
                    <td className="px-2 py-1.5 font-medium text-slate-800 whitespace-nowrap">{e.host || e.host_key}</td>
                    <td className="px-2 py-1.5 whitespace-nowrap text-slate-600">{ago(e.started_at)}</td>
                    <td className="px-2 py-1.5 text-right font-mono">{e.minutes}</td>
                    <td className="px-2 py-1.5 text-right"><span className={cn('rounded px-1.5 py-0.5 font-mono font-semibold', scoreTone(e.peak_score))}>{e.peak_score.toFixed(1)}</span></td>
                    <td className="px-2 py-1.5 text-slate-600">{[...e.series].sort((a, b) => b.score - a.score).slice(0, 3).map(s => `${s.label} ${s.value}${s.unit} (${t('anomaly.usuallyShort')} ${s.expected}${s.unit})`).join(' · ')}</td>
                    <td className="px-2 py-1.5"><Verdict ev={e} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

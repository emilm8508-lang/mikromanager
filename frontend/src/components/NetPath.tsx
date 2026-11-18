import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, RefreshCw, Route } from 'lucide-react'
import { netPathApi, NetPathHop, NetPathItem } from '../lib/api'
import { useAgo } from './SocBits'
import { cn } from '../lib/utils'

function hopTone(h: NetPathHop, culprit: number | null, kind: string | null): string {
  if (culprit != null && h.n >= culprit) return kind === 'loss' ? 'border-red-300 bg-red-50' : 'border-amber-300 bg-amber-50'
  if (!h.ip) return 'border-dashed border-slate-300 bg-white'
  return 'border-slate-200 bg-white'
}

function Path({ x }: { x: NetPathItem }) {
  const { t } = useTranslation()
  const last = x.last
  if (!last) return <p className="px-4 pb-3 text-xs text-slate-500">{t('npath.noTrace')}</p>
  return (
    <div className="px-4 pb-3 overflow-x-auto">
      <div className="flex items-stretch gap-1 min-w-max">
        <div className="flex items-center text-[11px] text-slate-500 pr-1">{t('npath.agent')}</div>
        {last.hops.map(h => (
          <div key={h.n} className="flex items-center gap-1">
            <span className="text-slate-300">→</span>
            <div className={cn('border rounded-md px-2 py-1 text-[11px] leading-tight min-w-[6.5rem]', hopTone(h, last.culprit, last.culprit_kind),
                               last.culprit === h.n ? 'ring-2 ring-offset-1 ' + (last.culprit_kind === 'loss' ? 'ring-red-400' : 'ring-amber-400') : '')}>
              <div className="text-slate-400">#{h.n}{last.culprit === h.n ? ` · ${t(`npath.starts.${last.culprit_kind}`)}` : ''}</div>
              <div className="font-mono text-slate-800">{h.ip ?? '* * *'}</div>
              {h.ip && (
                <div className="tabular-nums text-slate-600">
                  {h.rtt != null ? `${h.rtt >= 100 ? Math.round(h.rtt) : h.rtt.toFixed(1)} ms` : '—'}
                  {h.loss != null ? <span className={cn(h.loss > 0 ? 'text-red-600' : 'text-slate-400')}> · {h.loss}%</span> : null}
                </div>
              )}
            </div>
          </div>
        ))}
        {!last.reached && <div className="flex items-center text-[11px] text-red-600 pl-1">✕ {t('npath.notReached')}</div>}
      </div>
    </div>
  )
}

// The path to the own link-quality targets hop by hop, where loss / delay starts, and the path changes (services/net_path.py).
export function NetPath() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const [open, setOpen] = useState<string | null>(null)
  const q = useQuery({ queryKey: ['net-path'], queryFn: netPathApi.overview, refetchInterval: 120000 })
  const run = useMutation({ mutationFn: netPathApi.run, onSuccess: () => qc.invalidateQueries({ queryKey: ['net-path'] }) })
  const d = q.data
  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
      <div className="flex items-start gap-3 px-4 py-3">
        <div className="flex-1">
          <h2 className="font-semibold text-slate-900 flex items-center gap-2"><Route size={16} className="text-indigo-600" /> {t('npath.title')}</h2>
          <p className="text-xs text-slate-500 mt-0.5">{t('npath.subtitle')}</p>
        </div>
        <button onClick={() => run.mutate()} disabled={run.isPending} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">
          <RefreshCw size={14} className={run.isPending ? 'animate-spin' : ''} /> {run.isPending ? t('npath.tracing') : t('npath.runNow')}
        </button>
      </div>
      {q.isLoading ? <p className="px-4 pb-3 text-sm text-slate-500">{t('common.loading')}</p> : !d || d.items.length === 0 ? <p className="px-4 pb-3 text-sm text-slate-500">{t('npath.empty')}</p> : (
        <div className="divide-y divide-slate-100 border-t border-slate-100">
          {d.items.map(x => (
            <div key={x.ip}>
              <div className="flex items-center gap-3 px-4 py-2 text-sm cursor-pointer hover:bg-slate-50" onClick={() => setOpen(open === x.ip ? null : x.ip)}>
                {open === x.ip ? <ChevronDown size={14} className="text-slate-400" /> : <ChevronRight size={14} className="text-slate-400" />}
                <span className="font-medium text-slate-900">{x.name}</span>
                <span className="text-xs text-slate-400">{x.ip}</span>
                {x.last && <span className="text-xs text-slate-500">{t('npath.hops', { n: x.last.hops.length })}</span>}
                {x.last?.culprit != null && <span className={cn('text-xs', x.last.culprit_kind === 'loss' ? 'text-red-700' : 'text-amber-700')}>{t(`npath.problem.${x.last.culprit_kind}`, { n: x.last.culprit })}</span>}
                {x.last?.changed && <span className="text-xs text-amber-700">{t('npath.changedNow')}</span>}
                <span className="ml-auto text-xs text-slate-500">{t('npath.day', { changes: x.changes_24h, degraded: x.degraded_24h, traces: x.traces_24h })}</span>
                <span className="text-xs text-slate-400 w-24 text-right">{x.last ? ago(x.last.at) : ''}</span>
              </div>
              <Path x={x} />
              {open === x.ip && (
                <div className="px-4 pb-3 text-xs">
                  <div className="font-medium text-slate-700 mb-1">{t('npath.events')}</div>
                  {x.events.length === 0 ? <div className="text-slate-500">{t('npath.eventsNone')}</div> : x.events.map((e, i) => (
                    <div key={i} className="flex gap-3">
                      <span className="text-slate-500 w-40">{e.at ? new Date(e.at).toLocaleString() : ''}</span>
                      <span className="text-slate-700">
                        {e.changed ? t('npath.changed', { n: e.hop_count }) : ''}{e.changed && e.culprit != null ? ' · ' : ''}
                        {e.culprit != null ? t(`npath.problem.${e.culprit_kind}`, { n: e.culprit }) : ''}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <p className="px-4 py-2 text-xs text-slate-400 border-t border-slate-100">{t('npath.note')}{d?.last?.at ? ` ${t('avail.lastCheck', { when: ago(d.last.at) })}` : ''}</p>
    </div>
  )
}

import { useState, Fragment } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, HeartPulse, RefreshCw } from 'lucide-react'
import { availApi, AvailItem } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'
import { HostLink } from '../components/HostLink'

const STATE_STYLE: Record<string, string> = {
  up: 'bg-green-50 text-green-700 border-green-200',
  down: 'bg-red-50 text-red-700 border-red-200',
  unreachable: 'bg-amber-50 text-amber-700 border-amber-200',
}

export function formatDur(sec: number): string {
  if (sec < 60) return `${sec} s`
  const m = Math.floor(sec / 60)
  if (m < 60) return `${m} min`
  const h = Math.floor(m / 60)
  return h < 24 ? `${h} h ${m % 60} min` : `${Math.floor(h / 24)} d ${h % 24} h`
}

export function StatePill({ s }: { s: string | null }) {
  const { t } = useTranslation()
  if (!s) return <span className="text-slate-400">—</span>
  return <span className={cn('inline-block text-xs border rounded-full px-2 py-0.5', STATE_STYLE[s])}>{t(`avail.state.${s}`)}</span>
}

function Uptime({ v }: { v: number | null | undefined }) {
  if (v == null) return <span className="text-slate-300">—</span>
  return <span className={cn('tabular-nums', v >= 99.9 ? 'text-green-700' : v >= 99 ? 'text-slate-700' : v >= 95 ? 'text-amber-600' : 'text-red-600')}>{v.toFixed(v >= 99.9 ? 2 : 1)}%</span>
}

function Outages({ id }: { id: number }) {
  const { t } = useTranslation()
  const q = useQuery({ queryKey: ['avail-outages', id], queryFn: () => availApi.outages(id, 30), refetchInterval: 60000 })
  const d = q.data
  if (!d) return <div className="px-4 py-3 text-xs text-slate-500">{t('common.loading')}</div>
  return (
    <div className="px-4 py-3 bg-slate-50 space-y-3 text-xs">
      {d.affected.length > 0 && (
        <div>
          <div className="font-medium text-slate-700 mb-1">{t('avail.affected', { count: d.affected.length })}</div>
          <div className="flex flex-wrap gap-x-3 gap-y-1">
            {d.affected.map(a => <HostLink key={a.id} assetId={a.id} name={a.name}>{a.name}</HostLink>)}
          </div>
        </div>
      )}
      <div>
        <div className="font-medium text-slate-700 mb-1">{t('avail.outages', { days: d.days })}</div>
        {d.outages.length === 0 ? <div className="text-slate-500">{t('avail.outagesNone')}</div> : (
          <div className="space-y-0.5">
            {d.outages.slice(0, 40).map((o, i) => (
              <div key={i} className="flex gap-3 items-baseline">
                <span className="text-slate-500 w-40 shrink-0">{new Date(o.from).toLocaleString()}</span>
                <span className="tabular-nums w-28 shrink-0 text-slate-700">{formatDur(o.seconds)}{o.to == null ? ` (${t('avail.ongoing')})` : ''}</span>
                <span className={o.kind === 'down' ? 'text-red-700' : 'text-amber-700'}>{o.kind === 'down' ? t('avail.outageDown') : t('avail.outageUnreachable', { cause: o.cause ?? '?' })}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// Whether the equipment answers, since when, and how long it was away - with the topology taken into account: what hangs on a device that is down is
// "unreachable" (a consequence), not another fault.
export function Availability() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const [open, setOpen] = useState<number | null>(null)
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState('')
  const ov = useQuery({ queryKey: ['avail'], queryFn: availApi.overview, refetchInterval: 30000 })
  const run = useMutation({ mutationFn: availApi.run, onSuccess: () => qc.invalidateQueries({ queryKey: ['avail'] }) })
  const mode = useMutation({
    mutationFn: ({ id, mode }: { id: number; mode: number | null }) => availApi.setMonitor(id, mode),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['avail'] }),
  })
  const d = ov.data
  const items = (d?.items ?? []).filter((r: AvailItem) => (!filter || r.state === filter) && (!q.trim() || `${r.name} ${r.ip ?? ''}`.toLowerCase().includes(q.trim().toLowerCase())))
  const grid = 'grid-cols-[1.5rem_minmax(0,2fr)_8rem_7rem_minmax(0,1.2fr)_4.5rem_4.5rem_4.5rem_7rem]'
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><HeartPulse size={20} className="text-indigo-600" /> {t('avail.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('avail.subtitle')}</p>
        </div>
        <button onClick={() => run.mutate()} disabled={run.isPending}
          className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">
          <RefreshCw size={14} className={run.isPending ? 'animate-spin' : ''} /> {t('avail.runNow')}
        </button>
      </div>
      {d && (
        <div className="flex gap-2 flex-wrap items-center">
          {(['down', 'unreachable', 'up'] as const).map(s => (
            <button key={s} onClick={() => setFilter(filter === s ? '' : s)}
              className={cn('bg-white border rounded-xl px-4 py-2 min-w-[8rem] text-left', filter === s ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-200 hover:bg-slate-50')}>
              <div className="text-xs text-slate-500">{t(`avail.state.${s}`)}</div>
              <div className={cn('text-2xl font-bold tabular-nums', d[s] ? (s === 'down' ? 'text-red-600' : s === 'unreachable' ? 'text-amber-600' : 'text-green-600') : 'text-slate-300')}>{d[s]}</div>
            </button>
          ))}
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('soc.filter.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56 ml-auto" />
        </div>
      )}
      {ov.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : items.length === 0 ? <p className="text-sm text-slate-500">{t('avail.empty')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className={cn('grid items-center bg-slate-50 text-xs text-slate-500 py-2', grid)}>
            <div />
            <div className="px-2">{t('avail.col.device')}</div>
            <div className="px-2">{t('avail.col.state')}</div>
            <div className="px-2">{t('avail.col.since')}</div>
            <div className="px-2">{t('avail.col.cause')}</div>
            <div className="px-2 text-right">24 h</div>
            <div className="px-2 text-right">7 d</div>
            <div className="px-2 text-right">30 d</div>
            <div className="px-2">{t('avail.col.watch')}</div>
          </div>
          {items.map(r => (
            <Fragment key={r.id}>
              <div className={cn('grid items-center border-t border-slate-100 cursor-pointer hover:bg-slate-50', grid)} onClick={() => setOpen(open === r.id ? null : r.id)}>
                <div className="px-2 text-slate-400">{open === r.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</div>
                <div className="px-2 py-2 min-w-0" onClick={e => e.stopPropagation()}>
                  <HostLink assetId={r.id} name={r.name} className="truncate block">{r.name}</HostLink>
                  <div className="text-[11px] text-slate-400">{r.ip}</div>
                </div>
                <div className="px-2"><StatePill s={r.state} /></div>
                <div className="px-2 text-xs text-slate-500" title={r.since ? new Date(r.since).toLocaleString() : ''}>{ago(r.since)}</div>
                <div className="px-2 text-xs text-slate-600 truncate" title={r.detail ?? ''}>{r.root ? t('avail.cause', { name: r.root }) : r.state && r.state !== 'up' ? r.detail : ''}</div>
                <div className="px-2 text-right"><Uptime v={r.uptime['24h']} /></div>
                <div className="px-2 text-right"><Uptime v={r.uptime['7d']} /></div>
                <div className="px-2 text-right"><Uptime v={r.uptime['30d']} /></div>
                <div className="px-2" onClick={e => e.stopPropagation()}>
                  <select value={r.mode == null ? 'auto' : String(r.mode)} title={t('avail.watchHint') as string}
                    onChange={e => mode.mutate({ id: r.id, mode: e.target.value === 'auto' ? null : Number(e.target.value) })}
                    className="border border-slate-300 rounded-md px-1.5 py-1 text-xs bg-white w-full">
                    <option value="auto">{t('avail.watch.auto')}</option>
                    <option value="1">{t('avail.watch.on')}</option>
                    <option value="0">{t('avail.watch.off')}</option>
                  </select>
                </div>
              </div>
              {open === r.id && <Outages id={r.id} />}
            </Fragment>
          ))}
        </div>
      )}
      <p className="text-xs text-slate-400">{t('avail.note')}{d?.last?.at ? ` ${t('avail.lastCheck', { when: ago(d.last.at) })}` : ''}</p>
    </div>
  )
}

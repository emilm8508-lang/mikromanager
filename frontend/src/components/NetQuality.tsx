import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Activity, Plus, RefreshCw, Settings2, Trash2 } from 'lucide-react'
import { netQualityApi, NetQualitySettings } from '../lib/api'
import { useAgo } from './SocBits'
import { cn } from '../lib/utils'
import { HostLink } from './HostLink'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

function Num({ v, unit, bad }: { v: number | null | undefined; unit: string; bad?: boolean }) {
  if (v == null) return <span className="text-slate-300">—</span>
  return <span className={cn('tabular-nums', bad ? 'text-red-600 font-medium' : 'text-slate-700')}>{v >= 100 ? Math.round(v) : v.toFixed(1)} {unit}</span>
}

function SettingsForm({ s, onDone }: { s: NetQualitySettings; onDone: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [d, setD] = useState<NetQualitySettings>(s)
  useEffect(() => setD(s), [s])
  const save = useMutation({
    mutationFn: () => netQualityApi.save(d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['net-quality'] }); onDone() },
  })
  const lim = (k: keyof NetQualitySettings['limits'], label: string) => (
    <label className="text-xs text-slate-600">{label}
      <input type="number" min={0} step="any" value={d.limits[k]} onChange={e => setD({ ...d, limits: { ...d.limits, [k]: Number(e.target.value) } })}
        className="block border border-slate-300 rounded-lg px-2 py-1 text-sm w-32 bg-white text-slate-900" />
    </label>
  )
  return (
    <div className="border-t border-slate-100 bg-slate-50 px-4 py-3 space-y-3 text-sm">
      <div className="flex flex-wrap gap-4">
        <label className="flex items-center gap-2 text-xs text-slate-700"><input type="checkbox" checked={d.enabled} onChange={e => setD({ ...d, enabled: e.target.checked })} /> {t('nq.enabled')}</label>
        <label className="flex items-center gap-2 text-xs text-slate-700"><input type="checkbox" checked={d.auto} onChange={e => setD({ ...d, auto: e.target.checked })} /> {t('nq.autoLabel')}</label>
        <label className="flex items-center gap-2 text-xs text-slate-700">{t('nq.count')}
          <input type="number" min={3} max={20} value={d.count} onChange={e => setD({ ...d, count: Number(e.target.value) })} className="border border-slate-300 rounded-lg px-2 py-0.5 w-16 bg-white text-slate-900" />
        </label>
      </div>
      <div>
        <div className="text-xs font-medium text-slate-700 mb-1">{t('nq.targets')}</div>
        <div className="space-y-1">
          {d.targets.map((x, i) => (
            <div key={i} className="flex gap-2 items-center">
              <input value={x.name ?? ''} placeholder={t('nq.name') as string} onChange={e => setD({ ...d, targets: d.targets.map((y, j) => j === i ? { ...y, name: e.target.value } : y) })}
                className="border border-slate-300 rounded-lg px-2 py-1 text-sm w-56 bg-white text-slate-900" />
              <input value={x.ip} placeholder={t('nq.ip') as string} onChange={e => setD({ ...d, targets: d.targets.map((y, j) => j === i ? { ...y, ip: e.target.value } : y) })}
                className="border border-slate-300 rounded-lg px-2 py-1 text-sm w-44 bg-white text-slate-900" />
              <button onClick={() => setD({ ...d, targets: d.targets.filter((_, j) => j !== i) })} title={t('nq.remove') as string} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>
            </div>
          ))}
          <button onClick={() => setD({ ...d, targets: [...d.targets, { name: '', ip: '' }] })} className="flex items-center gap-1 text-xs text-indigo-600 hover:underline"><Plus size={12} /> {t('nq.add')}</button>
        </div>
      </div>
      <div>
        <div className="text-xs font-medium text-slate-700 mb-1">{t('nq.limits')}</div>
        <div className="flex flex-wrap gap-3">
          {lim('loss_pct', t('nq.lossLimit'))}
          {lim('rtt_ms', t('nq.rttLimit'))}
          {lim('rtt_ms_own', t('nq.rttLimitOwn'))}
          {lim('jitter_ms', t('nq.jitterLimit'))}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <button onClick={() => save.mutate()} disabled={save.isPending} className="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-sm disabled:opacity-50">{t('nq.save')}</button>
        {save.isError && <span className="text-xs text-red-600">{errText(save.error)}</span>}
      </div>
    </div>
  )
}

// Latency, jitter and packet loss of the network equipment and of the own targets (services/net_quality.py).
export function NetQuality() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const [edit, setEdit] = useState(false)
  const q = useQuery({ queryKey: ['net-quality'], queryFn: netQualityApi.overview, refetchInterval: 60000 })
  const run = useMutation({ mutationFn: netQualityApi.run, onSuccess: () => qc.invalidateQueries({ queryKey: ['net-quality'] }) })
  const d = q.data
  const grid = 'grid-cols-[minmax(0,2fr)_6rem_6rem_5.5rem_6rem_6rem_7rem_minmax(0,1fr)]'
  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
      <div className="flex items-start gap-3 px-4 py-3">
        <div className="flex-1">
          <h2 className="font-semibold text-slate-900 flex items-center gap-2"><Activity size={16} className="text-indigo-600" /> {t('nq.title')}</h2>
          <p className="text-xs text-slate-500 mt-0.5">{t('nq.subtitle')}</p>
        </div>
        <button onClick={() => setEdit(!edit)} className={cn('flex items-center gap-1.5 text-sm border rounded-lg px-3 py-1.5', edit ? 'border-indigo-500 text-indigo-700 bg-indigo-50' : 'border-slate-300 bg-white hover:bg-slate-50')}>
          <Settings2 size={14} /> {t('nq.settings')}
        </button>
        <button onClick={() => run.mutate()} disabled={run.isPending} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">
          <RefreshCw size={14} className={run.isPending ? 'animate-spin' : ''} /> {t('nq.runNow')}
        </button>
      </div>
      {edit && d && <SettingsForm s={d.settings} onDone={() => setEdit(false)} />}
      {q.isLoading ? <p className="px-4 pb-3 text-sm text-slate-500">{t('common.loading')}</p> : !d || d.items.length === 0 ? <p className="px-4 pb-3 text-sm text-slate-500">{t('nq.empty')}</p> : (
        <div className="text-sm">
          <div className={cn('grid items-center bg-slate-50 text-xs text-slate-500 py-2 border-t border-slate-100', grid)}>
            <div className="px-3">{t('nq.col.target')}</div>
            <div className="px-2 text-right">{t('nq.col.rtt')}</div>
            <div className="px-2 text-right">{t('nq.col.jitter')}</div>
            <div className="px-2 text-right">{t('nq.col.loss')}</div>
            <div className="px-2 text-right">{t('nq.col.p95')}</div>
            <div className="px-2 text-right">{t('nq.col.loss24')}</div>
            <div className="px-2 text-right">{t('nq.col.jmax')}</div>
            <div className="px-2" />
          </div>
          {d.items.map(x => {
            const lim = d.settings.limits
            return (
              <div key={x.ip} className={cn('grid items-center border-t border-slate-100', grid, x.bad.length ? 'bg-red-50/40' : '')}>
                <div className="px-3 py-1.5 min-w-0">
                  {x.asset_id ? <HostLink assetId={x.asset_id} name={x.name} className="truncate block">{x.name}</HostLink> : <span className="truncate block text-slate-800">{x.name}</span>}
                  <div className="text-[11px] text-slate-400">{x.ip} · {x.own ? t('nq.own') : t('nq.auto')}</div>
                </div>
                <div className="px-2 text-right"><Num v={x.rtt} unit="ms" bad={x.bad.includes('latency')} /></div>
                <div className="px-2 text-right"><Num v={x.jitter} unit="ms" bad={x.bad.includes('jitter')} /></div>
                <div className="px-2 text-right"><Num v={x.loss} unit="%" bad={x.bad.includes('loss')} /></div>
                <div className="px-2 text-right"><Num v={x.rtt_p95_24h} unit="ms" bad={x.rtt_p95_24h != null && x.rtt_p95_24h >= (x.own ? lim.rtt_ms_own : lim.rtt_ms)} /></div>
                <div className="px-2 text-right"><Num v={x.loss_avg_24h} unit="%" bad={x.loss_avg_24h != null && x.loss_avg_24h >= lim.loss_pct} /></div>
                <div className="px-2 text-right"><Num v={x.jitter_max_24h} unit="ms" /></div>
                <div className="px-2 text-xs text-red-700 truncate" title={x.error ?? ''}>{x.error ?? x.bad.map(b => t(`nq.bad.${b}`)).join(', ')}</div>
              </div>
            )
          })}
        </div>
      )}
      <p className="px-4 py-2 text-xs text-slate-400 border-t border-slate-100">{t('nq.note')} {t('nq.chart')}{d?.last?.at ? ` ${t('avail.lastCheck', { when: ago(d.last.at) })}` : ''}</p>
    </div>
  )
}

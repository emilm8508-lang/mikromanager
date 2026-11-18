import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { HardDrive, Hourglass, KeyRound, MemoryStick, Binary } from 'lucide-react'
import { forecastsApi, ForecastItem } from '../lib/api'
import { HostLink } from '../components/HostLink'
import { cn } from '../lib/utils'

const ICON = { disk: HardDrive, mem: MemoryStick, dhcp_pool: Binary, certificate: KeyRound } as const

function Days({ d }: { d: number }) {
  const { t } = useTranslation()
  const tone = d <= 0 ? 'bg-red-600 text-white' : d <= 3 ? 'bg-red-100 text-red-800' : d <= 7 ? 'bg-amber-100 text-amber-800' : d <= 30 ? 'bg-yellow-50 text-yellow-800' : 'bg-slate-100 text-slate-700'
  return <span className={cn('inline-block rounded-full px-2 py-0.5 text-xs font-medium tabular-nums', tone)}>{d <= 0 ? t('fc.now') : t('fc.inDays', { n: Math.max(1, Math.round(d)) })}</span>
}

// What will run out and when: disks, memory, DHCP pools growing steadily to full, certificates expiring (services/forecasts.py).
export function Forecasts() {
  const { t } = useTranslation()
  const [horizon, setHorizon] = useState(90)
  const [kind, setKind] = useState('')
  const q = useQuery({ queryKey: ['forecasts', horizon], queryFn: () => forecastsApi.overview(horizon), refetchInterval: 300000 })
  const d = q.data
  const items = (d?.items ?? []).filter(x => !kind || x.kind === kind)
  return (
    <div className="p-6 space-y-4 max-w-[1200px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Hourglass size={20} className="text-indigo-600" /> {t('fc.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('fc.subtitle')}</p>
        </div>
        <div className="flex gap-1 text-xs">
          {[7, 30, 90].map(n => (
            <button key={n} onClick={() => setHorizon(n)} className={cn('px-2.5 py-1 rounded border', horizon === n ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white border-slate-300 text-slate-600')}>{t('fc.horizon', { n })}</button>
          ))}
        </div>
      </div>
      {d && (
        <div className="flex gap-2 flex-wrap">
          {(['disk', 'mem', 'dhcp_pool', 'certificate'] as const).map(k => {
            const Icon = ICON[k]
            return (
              <button key={k} onClick={() => setKind(kind === k ? '' : k)}
                className={cn('bg-white border rounded-xl px-4 py-2 min-w-[9rem] text-left', kind === k ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-200 hover:bg-slate-50')}>
                <div className="text-xs text-slate-500 flex items-center gap-1"><Icon size={12} /> {t(`fc.kind.${k}`)}</div>
                <div className={cn('text-2xl font-bold tabular-nums', d.counts[k] ? 'text-slate-900' : 'text-slate-300')}>{d.counts[k]}</div>
              </button>
            )
          })}
        </div>
      )}
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : items.length === 0 ? <p className="text-sm text-slate-500">{t('fc.empty', { n: horizon })}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
          {items.map((x: ForecastItem) => {
            const Icon = ICON[x.kind]
            return (
              <div key={x.key} className="flex items-center gap-3 px-4 py-2">
                <Icon size={16} className="text-slate-400 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="truncate">
                    {x.asset_id ? <HostLink assetId={x.asset_id} name={x.where} className="font-medium">{x.where}</HostLink> : <span className="font-medium text-slate-900">{x.where}</span>}
                    {x.what ? <span className="text-slate-500"> · {x.what}</span> : null}
                  </div>
                  <div className="text-xs text-slate-500">
                    {x.kind === 'certificate'
                      ? (x.days <= 0 ? t('fc.certExpired') : t('fc.certExpires', { date: new Date(x.date).toLocaleDateString() })) + (x.self_signed ? ` · ${t('fc.selfSigned')}` : '')
                      : t('fc.growth', { value: x.value, per: x.per_day, date: new Date(x.date).toLocaleDateString() })}
                  </div>
                </div>
                <span className="text-xs text-slate-400 w-28 text-right">{t(`fc.kind.${x.kind}`)}</span>
                <Days d={x.days} />
              </div>
            )
          })}
        </div>
      )}
      <p className="text-xs text-slate-400">{t('fc.note')}</p>
    </div>
  )
}

import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Radar } from 'lucide-react'
import { coverageApi } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'

const STYLE: Record<string, string> = {
  ok: 'bg-green-50 text-green-700 border-green-200',
  stale: 'bg-red-50 text-red-700 border-red-200',
  error: 'bg-amber-50 text-amber-800 border-amber-200',
  off: 'bg-slate-50 text-slate-500 border-slate-200',
}
const GROUPS = ['link', 'connectors', 'devices', 'soc']

function every(sec: number | null): string {
  if (!sec) return '—'
  if (sec < 3600) return `${Math.round(sec / 60)} min`
  if (sec < 172800) return `${Math.round(sec / 3600)} h`
  return `${Math.round(sec / 86400)} d`
}

// Which of the agent's sources of information are reporting and which went quiet: silence looks exactly like "nothing is wrong".
export function Coverage() {
  const { t } = useTranslation()
  const ago = useAgo()
  const q = useQuery({ queryKey: ['coverage'], queryFn: coverageApi.report, refetchInterval: 30000 })
  const d = q.data
  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Radar size={20} className="text-indigo-600" /> {t('coverage.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('coverage.subtitle')}</p>
      </div>
      {d && (
        <div className="flex gap-2 flex-wrap">
          {(['stale', 'error', 'ok', 'off'] as const).map(s => (
            <div key={s} className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[7.5rem]">
              <div className="text-xs text-slate-500">{t(`coverage.state.${s}`)}</div>
              <div className={cn('text-2xl font-bold tabular-nums', d.summary[s] ? (s === 'stale' ? 'text-red-600' : s === 'error' ? 'text-amber-600' : s === 'ok' ? 'text-green-600' : 'text-slate-500') : 'text-slate-300')}>{d.summary[s]}</div>
            </div>
          ))}
        </div>
      )}
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : GROUPS.map(g => {
        const rows = (d?.items ?? []).filter(i => i.group === g)
        if (rows.length === 0) return null
        return (
          <div key={g} className="space-y-1">
            <h2 className="text-sm font-semibold text-slate-700">{t(`coverage.group.${g}`)}</h2>
            <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
              {rows.map(i => (
                <div key={i.id} className="grid grid-cols-[minmax(0,2fr)_6rem_7rem_5rem_minmax(0,2.5fr)] gap-2 px-4 py-2 items-start">
                  <div className="font-medium text-slate-900 min-w-0">{t(`coverage.src.${i.id}`, { defaultValue: i.name })}</div>
                  <div><span className={cn('inline-block text-xs border rounded-full px-2 py-0.5', STYLE[i.state])}>{t(`coverage.state.${i.state}`)}</span></div>
                  <div className="text-xs text-slate-500" title={i.last_ok ? new Date(i.last_ok).toLocaleString() : ''}>{i.state === 'off' ? '—' : ago(i.last_ok)}</div>
                  <div className="text-xs text-slate-400">{every(i.expected_s)}</div>
                  <div className="text-xs min-w-0">
                    {i.stale_items.length > 0 && <div className="text-red-700 truncate" title={i.stale_items.join(', ')}>{t('coverage.silentHosts', { n: i.stale_items.length, total: i.total ?? '?' })}: {i.stale_items.join(', ')}</div>}
                    {i.error && <div className="text-amber-800 truncate" title={i.error}>{i.error}</div>}
                    {i.detail && <div className="text-slate-500 truncate">{i.detail}</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })}
      <p className="text-xs text-slate-400">{t('coverage.note')} <Link to="/soc" className="text-indigo-600 hover:underline">{t('nav.socAlerts')}</Link></p>
    </div>
  )
}

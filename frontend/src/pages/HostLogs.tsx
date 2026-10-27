import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ScrollText, RefreshCw } from 'lucide-react'
import { hostLogsApi } from '../lib/api'
import { useAgo } from '../components/SocBits'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

// The Windows Security log and the Linux authentication log of the managed hosts, read over WinRM / SSH: what is read, when, and what went wrong.
export function HostLogs() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['hostlogs'], queryFn: hostLogsApi.status, refetchInterval: 20000 })
  const refresh = () => qc.invalidateQueries({ queryKey: ['hostlogs'] })
  const run = useMutation({ mutationFn: hostLogsApi.run, onSuccess: refresh })
  const save = useMutation({ mutationFn: hostLogsApi.save, onSuccess: refresh })
  const d = q.data
  const [interval, setInterval_] = useState(10)
  useEffect(() => { if (d) setInterval_(d.settings.interval_min) }, [d])
  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><ScrollText size={20} className="text-indigo-600" /> {t('hostlogs.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('hostlogs.subtitle')}</p>
        </div>
        <button onClick={() => run.mutate()} disabled={run.isPending} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">
          <RefreshCw size={14} className={run.isPending ? 'animate-spin' : ''} /> {t('hostlogs.runNow')}
        </button>
      </div>
      {d && (
        <div className="flex items-center gap-4 flex-wrap text-sm text-slate-600">
          <label className="flex items-center gap-2"><input type="checkbox" checked={d.settings.enabled} onChange={e => save.mutate({ enabled: e.target.checked })} /> {t('hostlogs.enabled')}</label>
          <label className="flex items-center gap-2">{t('hostlogs.interval')}
            <select value={interval} onChange={e => { setInterval_(Number(e.target.value)); save.mutate({ interval_min: Number(e.target.value) }) }} className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white">
              {[5, 10, 15, 30, 60].map(m => <option key={m} value={m}>{m} min</option>)}
              {![5, 10, 15, 30, 60].includes(interval) && <option value={interval}>{interval} min</option>}
            </select></label>
        </div>
      )}
      {(run.isError || save.isError) && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{errText(run.error ?? save.error)}</div>}
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : !d || d.hosts.length === 0 ? <p className="text-sm text-slate-500">{t('hostlogs.none')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
          <div className="grid grid-cols-[minmax(0,1.5fr)_6rem_8rem_8rem_5rem_minmax(0,2fr)] px-4 py-2 text-xs text-slate-500 bg-slate-50 rounded-t-xl">
            <div>{t('hostlogs.col.host')}</div><div>{t('hostlogs.col.os')}</div><div>{t('hostlogs.col.lastRun')}</div><div>{t('hostlogs.col.lastOk')}</div><div className="text-right">{t('hostlogs.col.events')}</div><div>{t('hostlogs.col.problem')}</div>
          </div>
          {d.hosts.map(h => (
            <div key={`${h.kind}${h.id}`} className="grid grid-cols-[minmax(0,1.5fr)_6rem_8rem_8rem_5rem_minmax(0,2fr)] px-4 py-2 items-center">
              <div className="min-w-0"><div className="font-medium text-slate-900 truncate">{h.name}</div><div className="text-[11px] text-slate-400">{h.ip}</div></div>
              <div className="text-xs text-slate-600">{h.kind === 'windows' ? 'Windows' : 'Linux'}</div>
              <div className="text-xs text-slate-500">{ago(h.last_run)}</div>
              <div className="text-xs text-slate-500">{ago(h.last_ok)}</div>
              <div className="text-right tabular-nums">{h.events}</div>
              <div className="text-xs text-red-700 truncate" title={h.error ?? ''}>{h.error}</div>
            </div>
          ))}
        </div>
      )}
      <p className="text-xs text-slate-400">{t('hostlogs.note')}</p>
    </div>
  )
}

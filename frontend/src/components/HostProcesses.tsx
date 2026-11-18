import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Cpu, RefreshCw, RotateCw, Square, Play, XCircle } from 'lucide-react'
import { hostProcessesApi, HostProcess, ServicePlatform } from '../lib/api'
import { Button } from './ui/Button'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

type Pending =
  | { kind: 'service'; name: string; action: 'start' | 'stop' | 'restart' }
  | { kind: 'kill'; pid: number; name: string; force: boolean }

// The processes using the most CPU and memory on a managed host (read on demand), and actions on its services and processes - each one
// with a reason, logged (services/host_processes.py).
export function HostProcesses({ platform, hostId }: { platform: ServicePlatform; hostId: number }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [pending, setPending] = useState<Pending | null>(null)
  const [reason, setReason] = useState('')
  const [svcName, setSvcName] = useState('')
  const [sort, setSort] = useState<'cpu' | 'mem_mb'>('cpu')
  const q = useQuery({ queryKey: ['host-procs', platform, hostId], queryFn: () => hostProcessesApi.list(platform, hostId), staleTime: 15000 })
  const hist = useQuery({ queryKey: ['host-procs-hist', platform, hostId], queryFn: () => hostProcessesApi.history(platform, hostId) })
  const act = useMutation({
    mutationFn: (p: Pending) => p.kind === 'service'
      ? hostProcessesApi.service(platform, hostId, p.name, p.action, reason)
      : hostProcessesApi.kill(platform, hostId, p.pid, p.name, reason, p.force),
    onSuccess: () => {
      setPending(null); setReason('')
      qc.invalidateQueries({ queryKey: ['host-procs-hist', platform, hostId] })
      qc.invalidateQueries({ queryKey: ['host-procs', platform, hostId] })
    },
  })
  const d = q.data
  const rows = [...(d?.processes ?? [])].sort((a, b) => b[sort] - a[sort])
  const can = !!d?.can_act
  const ask = (p: Pending) => { setPending(p); setReason(''); act.reset() }
  const svcBtns = (name: string) => can && (
    <span className="inline-flex gap-1 ml-1">
      <button title={t('hproc.restart') as string} onClick={() => ask({ kind: 'service', name, action: 'restart' })} className="text-slate-400 hover:text-indigo-600"><RotateCw size={12} /></button>
      <button title={t('hproc.stop') as string} onClick={() => ask({ kind: 'service', name, action: 'stop' })} className="text-slate-400 hover:text-red-600"><Square size={12} /></button>
    </span>
  )
  const label = (p: Pending) => p.kind === 'service' ? t(`hproc.confirm.${p.action}`, { name: p.name }) : t(p.force ? 'hproc.confirm.killForce' : 'hproc.confirm.kill', { name: p.name, pid: p.pid })
  return (
    <div className="border-t border-slate-100 px-4 py-3 space-y-3 bg-slate-50/50">
      <div className="flex items-center gap-2 flex-wrap">
        <h4 className="text-sm font-semibold text-slate-800 flex items-center gap-1.5"><Cpu size={14} className="text-indigo-600" /> {t('hproc.title')}</h4>
        <span className="text-xs text-slate-500">{d?.at ? t('hproc.readAt', { when: new Date(d.at).toLocaleTimeString() }) : ''}{d?.total ? ` · ${t('hproc.total', { n: d.total })}` : ''}</span>
        <div className="ml-auto flex items-center gap-2">
          {can && (
            <span className="flex items-center gap-1">
              <input value={svcName} onChange={e => setSvcName(e.target.value)} placeholder={t(platform === 'windows' ? 'hproc.svcPlaceholderWin' : 'hproc.svcPlaceholderLinux') as string}
                className="border border-slate-300 rounded px-2 py-1 text-xs w-44 bg-white text-slate-900" />
              {(['start', 'restart', 'stop'] as const).map(a => (
                <Button key={a} size="sm" variant="secondary" disabled={!svcName.trim()} onClick={() => ask({ kind: 'service', name: svcName.trim(), action: a })}>
                  {a === 'start' ? <Play size={12} /> : a === 'restart' ? <RotateCw size={12} /> : <Square size={12} />} {t(`hproc.${a}`)}
                </Button>
              ))}
            </span>
          )}
          <Button size="sm" variant="secondary" onClick={() => q.refetch()} disabled={q.isFetching}><RefreshCw size={12} className={q.isFetching ? 'animate-spin' : ''} /> {t('hproc.refresh')}</Button>
        </div>
      </div>
      {!can && d && !d.error && <p className="text-xs text-amber-700">{t('hproc.readOnly')}</p>}

      {pending && (
        <div className="border border-amber-300 bg-amber-50 rounded-lg px-3 py-2 space-y-2 text-sm">
          <div className="font-medium text-slate-800">{label(pending)}</div>
          <input autoFocus value={reason} onChange={e => setReason(e.target.value)} placeholder={t('hproc.reason') as string} maxLength={500}
            className="w-full border border-slate-300 rounded px-2 py-1 text-sm bg-white text-slate-900" />
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={() => act.mutate(pending)} disabled={!reason.trim() || act.isPending}>{act.isPending ? t('hproc.running') : t('hproc.do')}</Button>
            <Button size="sm" variant="secondary" onClick={() => setPending(null)} disabled={act.isPending}>{t('hproc.cancel')}</Button>
            {act.isError && <span className="text-xs text-red-700">{errText(act.error)}</span>}
          </div>
        </div>
      )}
      {act.data && !pending && (
        <p className={cn('text-xs', act.data.status === 'ok' ? 'text-green-700' : 'text-red-700')}>
          {act.data.status === 'ok' ? t('hproc.done', { state: act.data.state ?? '' }) : t('hproc.failed', { out: act.data.output || act.data.state || '?' })}
        </p>
      )}

      {q.isLoading ? <p className="text-xs text-slate-500">{t('common.loading')}</p> : d?.error ? <p className="text-xs text-red-700">{d.error}</p> : (
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden text-xs max-h-[28rem] overflow-y-auto">
          <table className="w-full">
            <thead className="bg-slate-50 text-slate-500 sticky top-0">
              <tr>
                <th className="text-left px-2 py-1.5 font-normal">PID</th>
                <th className="text-left px-2 py-1.5 font-normal">{t('hproc.col.name')}</th>
                <th className="text-right px-2 py-1.5 font-normal cursor-pointer" onClick={() => setSort('cpu')}>{t('hproc.col.cpu')}{sort === 'cpu' ? ' ▾' : ''}</th>
                <th className="text-right px-2 py-1.5 font-normal cursor-pointer" onClick={() => setSort('mem_mb')}>{t('hproc.col.mem')}{sort === 'mem_mb' ? ' ▾' : ''}</th>
                <th className="text-left px-2 py-1.5 font-normal">{t('hproc.col.services')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((p: HostProcess) => (
                <tr key={p.pid} className="border-t border-slate-100">
                  <td className="px-2 py-1 tabular-nums text-slate-500">{p.pid}</td>
                  <td className="px-2 py-1 text-slate-800 truncate max-w-[16rem]" title={p.name}>{p.name}</td>
                  <td className={cn('px-2 py-1 text-right tabular-nums', p.cpu >= 50 ? 'text-red-600 font-medium' : p.cpu >= 20 ? 'text-amber-600' : 'text-slate-700')}>{p.cpu.toFixed(1)}%</td>
                  <td className="px-2 py-1 text-right tabular-nums text-slate-700">{p.mem_mb >= 1024 ? `${(p.mem_mb / 1024).toFixed(1)} GB` : `${Math.round(p.mem_mb)} MB`}</td>
                  <td className="px-2 py-1 text-slate-600">{p.services.map(s => <span key={s} className="inline-flex items-center mr-2">{s}{svcBtns(s)}</span>)}</td>
                  <td className="px-2 py-1 text-right whitespace-nowrap">
                    {can && (
                      <>
                        <button title={t('hproc.kill') as string} onClick={() => ask({ kind: 'kill', pid: p.pid, name: p.name, force: false })} className="text-slate-400 hover:text-red-600"><XCircle size={13} /></button>
                        {platform === 'linux' && <button title={t('hproc.killForce') as string} onClick={() => ask({ kind: 'kill', pid: p.pid, name: p.name, force: true })} className="ml-1 text-[10px] text-slate-400 hover:text-red-700">-9</button>}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(hist.data?.actions.length ?? 0) > 0 && (
        <div>
          <div className="text-xs font-medium text-slate-700 mb-1">{t('hproc.history')}</div>
          <div className="space-y-0.5 text-xs">
            {hist.data!.actions.slice(0, 15).map(a => (
              <div key={a.id} className="flex gap-2 items-baseline">
                <span className="text-slate-400 w-36 shrink-0">{a.at ? new Date(a.at).toLocaleString() : ''}</span>
                <span className={cn('w-16 shrink-0', a.status === 'ok' ? 'text-green-700' : a.status === 'running' ? 'text-slate-500' : 'text-red-700')}>{t(`hproc.status.${a.status}`)}</span>
                <span className="text-slate-800">{t(`hproc.kind.${a.kind}`)} <b>{a.target}</b></span>
                <span className="text-slate-500 truncate" title={a.output}>· {a.by} · {a.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      <p className="text-[11px] text-slate-400">{t('hproc.note')}</p>
    </div>
  )
}

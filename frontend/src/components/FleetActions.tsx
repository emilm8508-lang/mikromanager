import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { fleetActionsApi, FleetActionKind, FleetDeviceRow, FleetResultStatus, FleetRunDetail } from '../lib/api'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import { Play, ChevronDown, ChevronRight } from 'lucide-react'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const anyE = e as any
  return anyE?.response?.data?.detail || anyE?.message || String(e)
}

const RESULT_VARIANT: Record<FleetResultStatus, 'gray' | 'blue' | 'green' | 'red' | 'yellow'> = {
  queued: 'gray', running: 'blue', ok: 'green', error: 'red', skipped: 'yellow',
}

function RunDetail({ runId }: { runId: number }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState<string | null>(null)
  const { data } = useQuery<FleetRunDetail>({
    queryKey: ['fleet-run', runId],
    queryFn: () => fleetActionsApi.run(runId),
    refetchInterval: q => (q.state.data?.status === 'running' ? 2000 : false),
  })
  if (!data) return <p className="text-sm text-slate-500">{t('common.loading')}</p>
  return (
    <div className="space-y-2">
      {data.script && (
        <details className="text-xs">
          <summary className="cursor-pointer text-slate-600">{t('fleet.actions.scriptUsed')}</summary>
          <pre className="mt-1 bg-slate-50 border border-slate-200 rounded p-2 whitespace-pre-wrap break-all font-mono">{data.script}</pre>
        </details>
      )}
      <div className="border border-slate-200 rounded divide-y divide-slate-100">
        {Object.entries(data.results).map(([id, r]) => (
          <div key={id} className="px-3 py-1.5">
            <div className="flex items-center gap-2 text-sm">
              <button onClick={() => setOpen(open === id ? null : id)} className="text-slate-400">
                {open === id ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              </button>
              <Badge variant={RESULT_VARIANT[r.status]}>{t(`fleet.actions.result.${r.status}`)}</Badge>
              <span className="font-medium text-slate-800">{r.name}</span>
              <span className="text-[11px] font-mono text-slate-400">{r.ip}</span>
              {r.error && <span className="text-xs text-red-700 truncate" title={r.error}>{r.error}</span>}
            </div>
            {open === id && (
              <pre className="mt-1 ml-5 bg-slate-50 border border-slate-200 rounded p-2 text-[11px] font-mono whitespace-pre-wrap break-all max-h-60 overflow-y-auto">
                {r.output || r.error || '—'}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export function FleetActions({ devices }: { devices: FleetDeviceRow[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [q, setQ] = useState('')
  const [action, setAction] = useState<FleetActionKind>('script')
  const [script, setScript] = useState('')
  const [reason, setReason] = useState('')
  const [backup, setBackup] = useState(true)
  const [runId, setRunId] = useState<number | null>(null)

  const { data: runsData } = useQuery({
    queryKey: ['fleet-runs'],
    queryFn: fleetActionsApi.runs,
    refetchInterval: query => (query.state.data?.runs.some(r => r.status === 'running') ? 3000 : 15000),
  })
  const start = useMutation({
    mutationFn: () => fleetActionsApi.start({ action, device_ids: [...selected], reason, script: action === 'script' ? script : undefined, backup }),
    onSuccess: r => { setRunId(r.run_id); qc.invalidateQueries({ queryKey: ['fleet-runs'] }) },
  })

  const targets = devices.filter(d => d.paired)
  const needle = q.trim().toLowerCase()
  const visible = targets.filter(d => !needle || `${d.name} ${d.ip ?? ''} ${d.model ?? ''}`.toLowerCase().includes(needle))
  const toggle = (id: number) => setSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  const kinds: Array<[FleetActionKind, string]> = [['script', 'fleet.actions.kindScript'], ['reboot', 'fleet.actions.kindReboot'], ['upgrade', 'fleet.actions.kindUpgrade']]
  const canRun = selected.size > 0 && reason.trim().length >= 3 && (action !== 'script' || script.trim().length > 0) && !start.isPending
  const enabled = runsData?.enabled !== false

  const submit = () => {
    if (!window.confirm(t('fleet.actions.confirm', { action: t(kinds.find(k => k[0] === action)![1]), count: selected.size }) as string)) return
    start.mutate()
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      <Card>
        <CardHeader><h2 className="text-sm font-semibold text-slate-700">{t('fleet.actions.newTitle')}</h2></CardHeader>
        <CardContent className="space-y-3">
          {!enabled && <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1">{t('fleet.actions.disabled')}</p>}

          <div>
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="text-xs font-medium text-slate-600">{t('fleet.actions.devicesTitle')}</span>
              <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('fleet.actions.filterPlaceholder') as string}
                className="border border-slate-300 rounded px-2 py-1 text-xs flex-1 min-w-[8rem]" />
              <button className="text-xs text-indigo-600 hover:underline" onClick={() => setSelected(new Set([...selected, ...visible.map(d => d.id)]))}>{t('fleet.actions.selectVisible')}</button>
              <button className="text-xs text-indigo-600 hover:underline" onClick={() => setSelected(new Set(targets.filter(d => d.online).map(d => d.id)))}>{t('fleet.actions.onlyOnline')}</button>
              <button className="text-xs text-slate-500 hover:underline" onClick={() => setSelected(new Set())}>{t('fleet.actions.clear')}</button>
            </div>
            <div className="max-h-44 overflow-y-auto border border-slate-200 rounded divide-y divide-slate-100">
              {visible.map(d => (
                <label key={d.id} className="flex items-center gap-2 px-2 py-1 text-xs cursor-pointer hover:bg-slate-50">
                  <input type="checkbox" checked={selected.has(d.id)} onChange={() => toggle(d.id)} />
                  <span className={cn('flex-1 truncate', !d.online && 'text-slate-400')}>{d.name}</span>
                  <span className="font-mono text-[10px] text-slate-400">{d.ip}</span>
                  <Badge variant={d.online ? 'green' : 'red'}>{d.online ? t('common.online') : t('common.offline')}</Badge>
                </label>
              ))}
              {visible.length === 0 && <p className="text-xs text-slate-500 p-2">{t('fleet.noDevices')}</p>}
            </div>
            <p className="text-[11px] text-slate-500 mt-1">{t('fleet.actions.selected', { n: selected.size })}</p>
          </div>

          <div className="flex gap-1 border-b border-slate-200">
            {kinds.map(([k, label]) => (
              <button key={k} onClick={() => setAction(k)}
                className={cn('px-3 py-1.5 text-xs -mb-px border-b-2', action === k ? 'border-indigo-600 text-indigo-700 font-medium' : 'border-transparent text-slate-500 hover:text-slate-800')}>
                {t(label)}
              </button>
            ))}
          </div>

          {action === 'script' && (
            <div>
              <textarea value={script} onChange={e => setScript(e.target.value)} rows={6} spellCheck={false}
                placeholder={'/ip service set telnet disabled=yes\n/system ntp client set enabled=yes'}
                className="w-full border border-slate-300 rounded-lg px-2 py-1.5 text-xs font-mono" />
              <p className="text-[11px] text-slate-500">{t('fleet.actions.scriptHint')}</p>
            </div>
          )}
          {action === 'reboot' && <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1">{t('fleet.actions.rebootHint')}</p>}
          {action === 'upgrade' && (
            <div className="space-y-1">
              <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1">{t('fleet.actions.upgradeHint')}</p>
              <label className="flex items-center gap-2 text-xs text-slate-700">
                <input type="checkbox" checked={backup} onChange={e => setBackup(e.target.checked)} /> {t('fleet.actions.backupLabel')}
              </label>
            </div>
          )}

          <div>
            <label className="text-xs font-medium text-slate-600">{t('fleet.actions.reasonLabel')}</label>
            <input value={reason} onChange={e => setReason(e.target.value)} placeholder={t('fleet.actions.reasonPlaceholder') as string}
              className="w-full border border-slate-300 rounded-lg px-2 py-1.5 text-sm" />
          </div>

          {start.isError && <p className="text-xs text-red-700">{errText(start.error)}</p>}
          <Button variant={action === 'script' ? 'primary' : 'danger'} disabled={!canRun || !enabled} onClick={submit}>
            <Play size={13} /> {t('fleet.actions.run', { n: selected.size })}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><h2 className="text-sm font-semibold text-slate-700">{t('fleet.actions.historyTitle')}</h2></CardHeader>
        <CardContent className="space-y-3">
          {(runsData?.runs ?? []).length === 0 ? <p className="text-sm text-slate-500">{t('fleet.actions.noRuns')}</p> : (
            <div className="max-h-48 overflow-y-auto border border-slate-200 rounded divide-y divide-slate-100">
              {runsData!.runs.map(r => (
                <button key={r.id} onClick={() => setRunId(r.id)}
                  className={cn('w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50', runId === r.id && 'bg-indigo-50')}>
                  <div className="flex items-center gap-2">
                    <Badge variant={r.status === 'running' ? 'blue' : r.status === 'interrupted' ? 'yellow' : 'gray'}>{t(`fleet.actions.status.${r.status}`)}</Badge>
                    <span className="font-medium text-slate-800">{t(`fleet.actions.kind.${r.action}`)}</span>
                    <span className="text-slate-500">· {r.devices}</span>
                    <span className="ml-auto text-slate-400">{r.created_at ? new Date(r.created_at).toLocaleString() : ''}</span>
                  </div>
                  <div className="text-slate-500 truncate">
                    {r.reason} · {t('fleet.actions.counts', { ok: r.counts.ok ?? 0, error: r.counts.error ?? 0, skipped: r.counts.skipped ?? 0 })}
                    {r.created_by ? ` · ${t('fleet.actions.by', { user: r.created_by })}` : ''}
                  </div>
                </button>
              ))}
            </div>
          )}
          {runId != null && <RunDetail runId={runId} />}
        </CardContent>
      </Card>
    </div>
  )
}

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  fleetGroupsApi, FleetDeviceRow, FleetGroup, FleetGroupInput, FleetGroupSummary, FleetChannel, FleetScheduleKind,
} from '../lib/api'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import { RunDetail } from './FleetActions'
import { Plus, Play, Pencil, Trash2, ArrowUp, ArrowDown, X } from 'lucide-react'
import { cn } from '../lib/utils'

const CHANNELS: FleetChannel[] = ['stable', 'long-term', 'testing', 'development']

function errText(e: unknown): string {
  const anyE = e as any
  return anyE?.response?.data?.detail || anyE?.message || String(e)
}

const pad = (n: number) => String(n).padStart(2, '0')

// "every Tuesday 02:30" / "once 2026-10-12 02:00" / "manual only" — shared with Central's read-only card.
export function scheduleText(g: Pick<FleetGroupSummary, 'schedule_kind' | 'weekday' | 'hour' | 'minute' | 'once_at'>,
                             t: (k: string, o?: any) => string): string {
  if (g.schedule_kind === 'weekly' && g.weekday != null && g.hour != null) {
    return t('fleet.groups.schedWeekly', { day: t(`fleet.groups.weekday.${g.weekday}`), time: `${pad(g.hour)}:${pad(g.minute ?? 0)}` })
  }
  if (g.schedule_kind === 'once' && g.once_at) return t('fleet.groups.schedOnce', { time: new Date(g.once_at).toLocaleString() })
  return t('fleet.groups.schedManual')
}

function emptyGroup(): FleetGroupInput {
  return { name: '', device_ids: [], channel: null, schedule_kind: 'manual', weekday: 1, hour: 2, minute: 0, once_at: null,
           enabled: true, stop_on_failure: true, backup: true }
}

function Editor({ initial, devices, onClose, onSave, saving, error }: {
  initial: FleetGroupInput; devices: FleetDeviceRow[]; onClose: () => void; onSave: (g: FleetGroupInput) => void; saving: boolean; error: string | null
}) {
  const { t } = useTranslation()
  const [g, setG] = useState<FleetGroupInput>(initial)
  const byId = new Map(devices.map(d => [d.id, d]))
  const set = <K extends keyof FleetGroupInput>(k: K, v: FleetGroupInput[K]) => setG(prev => ({ ...prev, [k]: v }))
  const toggle = (id: number) => set('device_ids', g.device_ids.includes(id) ? g.device_ids.filter(x => x !== id) : [...g.device_ids, id])
  const move = (i: number, dir: -1 | 1) => {
    const a = [...g.device_ids]; const j = i + dir
    if (j < 0 || j >= a.length) return
    ;[a[i], a[j]] = [a[j], a[i]]
    set('device_ids', a)
  }
  const sel = 'border border-slate-300 rounded px-2 py-1 text-sm bg-white'

  return (
    <div className="border border-indigo-200 bg-indigo-50/40 rounded-lg p-3 space-y-3">
      <input value={g.name} onChange={e => set('name', e.target.value)} placeholder={t('fleet.groups.name') as string}
        className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-sm" />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <div className="text-xs font-medium text-slate-600 mb-1">{t('fleet.groups.pickDevices')}</div>
          <div className="max-h-44 overflow-y-auto border border-slate-200 bg-white rounded divide-y divide-slate-100">
            {devices.filter(d => d.paired).map(d => (
              <label key={d.id} className="flex items-center gap-2 px-2 py-1 text-xs cursor-pointer hover:bg-slate-50">
                <input type="checkbox" checked={g.device_ids.includes(d.id)} onChange={() => toggle(d.id)} />
                <span className="flex-1 truncate">{d.name}</span>
                <span className="text-[10px] font-mono text-slate-400">{d.ros_version}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <div className="text-xs font-medium text-slate-600 mb-1">{t('fleet.groups.order')}</div>
          <div className="max-h-44 overflow-y-auto border border-slate-200 bg-white rounded divide-y divide-slate-100">
            {g.device_ids.length === 0 && <p className="text-xs text-slate-400 p-2">—</p>}
            {g.device_ids.map((id, i) => (
              <div key={id} className="flex items-center gap-1 px-2 py-1 text-xs">
                <span className="w-5 text-slate-400">{i + 1}.</span>
                <span className="flex-1 truncate">{byId.get(id)?.name ?? `#${id}`}</span>
                <button onClick={() => move(i, -1)} className="text-slate-400 hover:text-slate-800" title={t('fleet.groups.moveUp') as string}><ArrowUp size={12} /></button>
                <button onClick={() => move(i, 1)} className="text-slate-400 hover:text-slate-800" title={t('fleet.groups.moveDown') as string}><ArrowDown size={12} /></button>
                <button onClick={() => toggle(id)} className="text-slate-400 hover:text-red-600"><X size={12} /></button>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="flex items-end gap-3 flex-wrap">
        <label className="flex flex-col text-[11px] text-slate-500 gap-0.5">{t('fleet.groups.channel')}
          <select className={sel} value={g.channel ?? ''} onChange={e => set('channel', (e.target.value || null) as FleetChannel | null)}>
            <option value="">{t('fleet.groups.channelKeep')}</option>
            {CHANNELS.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <label className="flex flex-col text-[11px] text-slate-500 gap-0.5">{t('fleet.groups.schedule')}
          <select className={sel} value={g.schedule_kind} onChange={e => set('schedule_kind', e.target.value as FleetScheduleKind)}>
            <option value="manual">{t('fleet.groups.kindManual')}</option>
            <option value="weekly">{t('fleet.groups.kindWeekly')}</option>
            <option value="once">{t('fleet.groups.kindOnce')}</option>
          </select>
        </label>
        {g.schedule_kind === 'weekly' && (
          <>
            <label className="flex flex-col text-[11px] text-slate-500 gap-0.5">{t('fleet.groups.day')}
              <select className={sel} value={g.weekday ?? 1} onChange={e => set('weekday', Number(e.target.value))}>
                {[0, 1, 2, 3, 4, 5, 6].map(d => <option key={d} value={d}>{t(`fleet.groups.weekday.${d}`)}</option>)}
              </select>
            </label>
            <label className="flex flex-col text-[11px] text-slate-500 gap-0.5">{t('fleet.groups.time')}
              <input type="time" className={sel} value={`${pad(g.hour ?? 2)}:${pad(g.minute ?? 0)}`}
                onChange={e => { const [h, m] = e.target.value.split(':').map(Number); setG(p => ({ ...p, hour: h, minute: m })) }} />
            </label>
          </>
        )}
        {g.schedule_kind === 'once' && (
          <label className="flex flex-col text-[11px] text-slate-500 gap-0.5">{t('fleet.groups.onceAt')}
            <input type="datetime-local" className={sel} value={g.once_at ? g.once_at.slice(0, 16) : ''} onChange={e => set('once_at', e.target.value || null)} />
          </label>
        )}
        <label className="flex flex-col text-[11px] text-slate-500 gap-0.5">{t('fleet.groups.onFailure')}
          <select className={sel} value={g.stop_on_failure ? 'stop' : 'continue'} onChange={e => set('stop_on_failure', e.target.value === 'stop')}>
            <option value="stop">{t('fleet.groups.stopOnFailure')}</option>
            <option value="continue">{t('fleet.groups.continueOnFailure')}</option>
          </select>
        </label>
        <label className="flex items-center gap-1 text-xs text-slate-700 pb-1.5"><input type="checkbox" checked={g.backup} onChange={e => set('backup', e.target.checked)} /> {t('fleet.groups.backup')}</label>
        <label className="flex items-center gap-1 text-xs text-slate-700 pb-1.5"><input type="checkbox" checked={g.enabled} onChange={e => set('enabled', e.target.checked)} /> {t('fleet.groups.enabled')}</label>
      </div>
      <p className="text-[11px] text-slate-500">{t('fleet.groups.hint')}</p>
      {error && <p className="text-xs text-red-700">{error}</p>}
      <div className="flex gap-2 justify-end">
        <Button variant="ghost" size="sm" onClick={onClose}>{t('fleet.groups.cancel')}</Button>
        <Button variant="primary" size="sm" disabled={saving || !g.name.trim() || g.device_ids.length === 0} onClick={() => onSave(g)}>{t('fleet.groups.save')}</Button>
      </div>
    </div>
  )
}

export function FleetGroups({ devices }: { devices: FleetDeviceRow[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [editing, setEditing] = useState<{ id: number | null; value: FleetGroupInput } | null>(null)
  const [details, setDetails] = useState<number | null>(null)
  const { data: groups = [] } = useQuery({
    queryKey: ['fleet-groups'],
    queryFn: fleetGroupsApi.list,
    refetchInterval: q => (q.state.data?.some(g => g.last_run?.status === 'running') ? 3000 : 20000),
  })
  const refresh = () => qc.invalidateQueries({ queryKey: ['fleet-groups'] })
  const save = useMutation({
    mutationFn: (g: FleetGroupInput) => editing?.id ? fleetGroupsApi.update(editing.id, g) : fleetGroupsApi.create(g),
    onSuccess: () => { setEditing(null); refresh() },
  })
  const remove = useMutation({ mutationFn: (id: number) => fleetGroupsApi.remove(id), onSuccess: refresh })
  const run = useMutation({ mutationFn: (id: number) => fleetGroupsApi.run(id), onSuccess: r => { refresh(); setDetails(r.run_id); qc.invalidateQueries({ queryKey: ['fleet-runs'] }) } })
  const names = new Map(devices.map(d => [d.id, d.name]))

  const toInput = (g: FleetGroup): FleetGroupInput => ({
    name: g.name, device_ids: g.device_ids, channel: g.channel, schedule_kind: g.schedule_kind, weekday: g.weekday, hour: g.hour,
    minute: g.minute, once_at: g.once_at, enabled: g.enabled, stop_on_failure: g.stop_on_failure, backup: g.backup,
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-700">{t('fleet.groups.title')}</h2>
          <Button size="sm" variant="secondary" onClick={() => setEditing({ id: null, value: emptyGroup() })}><Plus size={13} /> {t('fleet.groups.new')}</Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-slate-500">{t('fleet.groups.intro')}</p>
        {editing && (
          <Editor key={editing.id ?? 'new'} initial={editing.value} devices={devices} onClose={() => { setEditing(null); save.reset() }}
            onSave={g => save.mutate(g)} saving={save.isPending} error={save.isError ? errText(save.error) : null} />
        )}
        {groups.length === 0 && !editing && <p className="text-sm text-slate-500">{t('fleet.groups.empty')}</p>}
        {groups.map(g => (
          <div key={g.id} className="border border-slate-200 rounded-lg p-3 space-y-2">
            <div className="flex items-start justify-between gap-2 flex-wrap">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-slate-900">{g.name}</span>
                  <Badge variant="gray">{t('fleet.groups.devicesCount', { n: g.device_ids.length })}</Badge>
                  <Badge variant="blue">{g.channel ?? t('fleet.groups.channelKeep')}</Badge>
                  {!g.enabled && g.schedule_kind !== 'manual' && <Badge variant="yellow">{t('fleet.groups.paused')}</Badge>}
                </div>
                <div className="text-xs text-slate-500 mt-0.5 truncate" title={g.device_ids.map(i => names.get(i) ?? i).join(' → ')}>
                  {g.device_ids.map(i => names.get(i) ?? `#${i}`).join(' → ')}
                </div>
                <div className="text-xs text-slate-600 mt-1">
                  {scheduleText(g, t as any)}
                  {g.enabled && g.next_run_at && <> · {t('fleet.groups.nextRun')}: <b>{new Date(g.next_run_at).toLocaleString()}</b></>}
                </div>
                <div className="text-xs text-slate-500">
                  {t('fleet.groups.lastRun')}:{' '}
                  {g.last_run ? (
                    <>
                      <Badge variant={g.last_run.status === 'running' ? 'blue' : g.last_run.status === 'interrupted' ? 'yellow' : 'gray'}>{t(`fleet.actions.status.${g.last_run.status}`)}</Badge>{' '}
                      {t('fleet.actions.counts', { ok: g.last_run.counts.ok ?? 0, error: g.last_run.counts.error ?? 0, skipped: g.last_run.counts.skipped ?? 0 })}
                      {g.last_run_at && <> · {new Date(g.last_run_at).toLocaleString()}</>}
                      {' '}<button className="text-indigo-600 hover:underline" onClick={() => setDetails(details === g.last_run!.id ? null : g.last_run!.id)}>{t('fleet.groups.details')}</button>
                    </>
                  ) : t('fleet.groups.never')}
                </div>
                {g.last_note?.startsWith('missed') && <div className="text-xs text-amber-800">{t('fleet.groups.missed')}</div>}
                {g.last_note?.startsWith('error') && <div className="text-xs text-red-700">{g.last_note}</div>}
              </div>
              <div className="flex items-center gap-1">
                <Button size="sm" variant="secondary" disabled={run.isPending || g.last_run?.status === 'running'}
                  onClick={() => { if (window.confirm(t('fleet.groups.runConfirm', { name: g.name, count: g.device_ids.length }) as string)) run.mutate(g.id) }}>
                  <Play size={12} /> {t('fleet.groups.runNow')}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setEditing({ id: g.id, value: toInput(g) })}><Pencil size={12} /></Button>
                <Button size="sm" variant="ghost" onClick={() => { if (window.confirm(t('fleet.groups.deleteConfirm', { name: g.name }) as string)) remove.mutate(g.id) }}><Trash2 size={12} /></Button>
              </div>
            </div>
            {details != null && g.last_run?.id === details && <RunDetail runId={details} />}
          </div>
        ))}
        {run.isError && <p className="text-xs text-red-700">{errText(run.error)}</p>}
        {details != null && !groups.some(g => g.last_run?.id === details) && <RunDetail runId={details} />}
      </CardContent>
    </Card>
  )
}

export function GroupScheduleRow({ g, tenant }: { g: FleetGroupSummary; tenant?: string }) {
  const { t } = useTranslation()
  return (
    <tr className="border-b border-slate-100 align-top">
      <td className="py-1.5 font-medium text-slate-800">{tenant && <span className="text-[10px] px-1.5 py-0.5 mr-1.5 rounded bg-slate-100 text-slate-600 font-normal">{tenant}</span>}{g.name}<div className="text-[10px] text-slate-400">{t('fleet.groups.devicesCount', { n: g.devices })} · {g.channel ?? t('fleet.groups.channelKeep')}</div></td>
      <td className="text-xs text-slate-600">{scheduleText(g, t as any)}{!g.enabled && g.schedule_kind !== 'manual' ? ` (${t('fleet.groups.paused')})` : ''}</td>
      <td className="text-xs text-slate-600">{g.enabled && g.next_run_at ? new Date(g.next_run_at).toLocaleString() : '—'}</td>
      <td className="text-xs text-slate-600">
        {g.last_status ? (
          <>{t(`fleet.actions.status.${g.last_status}`)}{g.last_counts ? ` · ${t('fleet.actions.counts', { ok: g.last_counts.ok ?? 0, error: g.last_counts.error ?? 0, skipped: g.last_counts.skipped ?? 0 })}` : ''}</>
        ) : '—'}
        {g.last_note === 'missed' && <div className="text-amber-800">{t('fleet.groups.missed')}</div>}
      </td>
    </tr>
  )
}

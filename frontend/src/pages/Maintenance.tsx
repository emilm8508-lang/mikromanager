import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { BellOff, Pencil, Plus, Trash2 } from 'lucide-react'
import { assetsApi, maintApi, MaintWindow, MaintBody } from '../lib/api'
import { Modal } from '../components/ui/Modal'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const DAYS = [0, 1, 2, 3, 4, 5, 6]
const SEVS = ['critical', 'high', 'medium', 'low', 'info']

function DevicePicker({ value, onChange }: { value: Set<number>; onChange: (s: Set<number>) => void }) {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const assets = useQuery({ queryKey: ['assets-list'], queryFn: assetsApi.list })
  const rows = (assets.data ?? []).filter(a => value.has(a.id) || (!q.trim() || `${a.name} ${a.ip ?? ''}`.toLowerCase().includes(q.trim().toLowerCase())))
    .sort((a, b) => Number(value.has(b.id)) - Number(value.has(a.id)) || (a.name ?? '').localeCompare(b.name ?? ''))
  const toggle = (id: number) => { const n = new Set(value); if (n.has(id)) n.delete(id); else n.add(id); onChange(n) }
  return (
    <div>
      <div className="flex items-center gap-3 mb-1">
        <span className="text-xs text-slate-400">{t('maint.chosen', { count: value.size })}</span>
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('maint.search') as string} className="ml-auto border border-slate-300 rounded-lg px-2 py-1 text-xs w-56" />
      </div>
      <div className="border border-slate-200 rounded-lg max-h-44 overflow-y-auto divide-y divide-slate-100 bg-white">
        {rows.slice(0, 300).map(a => (
          <label key={a.id} className="flex items-center gap-2 px-3 py-1 hover:bg-slate-50 cursor-pointer text-sm">
            <input type="checkbox" checked={value.has(a.id)} onChange={() => toggle(a.id)} />
            <span className="truncate">{a.name}</span><span className="text-xs text-slate-400">{a.ip}</span>
          </label>
        ))}
      </div>
    </div>
  )
}

const localInput = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16)

function WindowForm({ initial, onClose }: { initial: MaintWindow | null; onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [name, setName] = useState(initial?.name ?? '')
  const [kind, setKind] = useState<'once' | 'weekly'>((initial?.kind as 'once' | 'weekly') ?? 'once')
  const [from, setFrom] = useState(initial?.starts_at ? localInput(new Date(initial.starts_at)) : localInput(new Date()))
  const [to, setTo] = useState(initial?.ends_at ? localInput(new Date(initial.ends_at)) : localInput(new Date(Date.now() + 2 * 3600 * 1000)))
  const [days, setDays] = useState<number[]>(initial?.days ?? [6])
  const [start, setStart] = useState(initial?.start_time ?? '02:00')
  const [dur, setDur] = useState(initial?.duration_min ?? 120)
  const [all, setAll] = useState(initial?.scope_all ?? false)
  const [devs, setDevs] = useState<Set<number>>(new Set(initial?.asset_ids ?? []))
  const save = useMutation({
    mutationFn: (b: MaintBody) => (initial ? maintApi.update(initial.id, b) : maintApi.create(b)),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['maint'] }); onClose() },
  })
  const body = (): MaintBody => ({
    name: name.trim(), kind, scope_all: all, asset_ids: [...devs], enabled: initial?.enabled ?? true,
    ...(kind === 'once' ? { starts_at: new Date(from).toISOString(), ends_at: new Date(to).toISOString() } : { days, start_time: start, duration_min: dur }),
  })
  return (
    <Modal open onClose={onClose} title={t(initial ? 'maint.form.titleEdit' : 'maint.form.titleNew') as string} className="max-w-2xl">
      <div className="space-y-3 text-sm">
        <label className="block"><span className="text-xs text-slate-500">{t('maint.form.name')}</span>
          <input value={name} onChange={e => setName(e.target.value)} maxLength={80} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" /></label>
        <div className="flex gap-4">
          {(['once', 'weekly'] as const).map(k => <label key={k} className="flex items-center gap-1.5"><input type="radio" checked={kind === k} onChange={() => setKind(k)} /> {t(`maint.kind.${k}`)}</label>)}
        </div>
        {kind === 'once' ? (
          <div className="flex gap-3 flex-wrap">
            <label className="text-xs text-slate-500">{t('maint.form.from')}<input type="datetime-local" value={from} onChange={e => setFrom(e.target.value)} className="block mt-0.5 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
            <label className="text-xs text-slate-500">{t('maint.form.to')}<input type="datetime-local" value={to} onChange={e => setTo(e.target.value)} className="block mt-0.5 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="flex gap-2 flex-wrap">
              {DAYS.map(d => (
                <label key={d} className={cn('border rounded-lg px-2.5 py-1 cursor-pointer text-xs', days.includes(d) ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white border-slate-300 text-slate-700')}>
                  <input type="checkbox" className="hidden" checked={days.includes(d)} onChange={() => setDays(days.includes(d) ? days.filter(x => x !== d) : [...days, d])} />{t(`maint.day.${d}`)}
                </label>
              ))}
            </div>
            <div className="flex gap-3 flex-wrap">
              <label className="text-xs text-slate-500">{t('maint.form.startTime')}<input type="time" value={start} onChange={e => setStart(e.target.value)} className="block mt-0.5 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
              <label className="text-xs text-slate-500">{t('maint.form.duration')}<input type="number" min={5} max={1440} value={dur} onChange={e => setDur(Number(e.target.value))} className="block mt-0.5 w-28 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
            </div>
            <p className="text-[11px] text-slate-400">{t('maint.form.localTime')}</p>
          </div>
        )}
        <label className="flex items-center gap-2"><input type="checkbox" checked={all} onChange={e => setAll(e.target.checked)} /> {t('maint.form.all')}</label>
        {!all && <DevicePicker value={devs} onChange={setDevs} />}
        {save.isError && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{errText(save.error)}</div>}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm border border-slate-300 rounded-lg bg-white hover:bg-slate-50">{t('maint.form.cancel')}</button>
          <button disabled={!name.trim() || save.isPending} onClick={() => save.mutate(body())} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('maint.form.save')}</button>
        </div>
      </div>
    </Modal>
  )
}

function QuickMute() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [devs, setDevs] = useState<Set<number>>(new Set())
  const [minutes, setMinutes] = useState(120)
  const [all, setAll] = useState(false)
  const quick = useMutation({ mutationFn: () => maintApi.quick({ asset_ids: [...devs], minutes, scope_all: all }), onSuccess: () => { setDevs(new Set()); setAll(false); void qc.invalidateQueries({ queryKey: ['maint'] }) } })
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-sm">
      <h2 className="font-semibold text-slate-900">{t('maint.quick.title')}</h2>
      <p className="text-xs text-slate-500">{t('maint.quick.intro')}</p>
      <label className="flex items-center gap-2"><input type="checkbox" checked={all} onChange={e => setAll(e.target.checked)} /> {t('maint.form.all')}</label>
      {!all && <DevicePicker value={devs} onChange={setDevs} />}
      <div className="flex items-center gap-3 flex-wrap">
        <select value={minutes} onChange={e => setMinutes(Number(e.target.value))} className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white">
          {[30, 60, 120, 240, 480, 1440].map(m => <option key={m} value={m}>{m >= 60 ? `${m / 60} h` : `${m} min`}</option>)}
        </select>
        <button disabled={(!all && devs.size === 0) || quick.isPending} onClick={() => quick.mutate()} className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"><BellOff size={14} /> {t('maint.quick.go')}</button>
        {quick.isError && <span className="text-xs text-red-700">{errText(quick.error)}</span>}
      </div>
    </div>
  )
}

function Escalation({ s }: { s: { enabled: boolean; levels: Record<string, number[]> } }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [enabled, setEnabled] = useState(s.enabled)
  const [levels, setLevels] = useState<Record<string, string>>({})
  const [dirty, setDirty] = useState(false)
  useEffect(() => { if (!dirty) { setEnabled(s.enabled); setLevels(Object.fromEntries(SEVS.map(k => [k, (s.levels[k] ?? []).join(', ')]))) } }, [s, dirty])
  const save = useMutation({
    mutationFn: () => maintApi.escalation({ enabled, levels: Object.fromEntries(SEVS.map(k => [k, levels[k].split(',').map(x => x.trim()).filter(Boolean).map(Number)])) }),
    onSuccess: () => { setDirty(false); void qc.invalidateQueries({ queryKey: ['maint'] }) },
  })
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-sm">
      <h2 className="font-semibold text-slate-900">{t('maint.esc.title')}</h2>
      <p className="text-xs text-slate-500">{t('maint.esc.intro')}</p>
      <label className="flex items-center gap-2"><input type="checkbox" checked={enabled} onChange={e => { setEnabled(e.target.checked); setDirty(true) }} /> {t('maint.esc.enabled')}</label>
      <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1">
        {SEVS.map(k => (
          <label key={k} className="flex items-center gap-2 text-xs text-slate-600">
            <span className="w-20">{t(`soc.severity.${k}`)}</span>
            <input value={levels[k] ?? ''} onChange={e => { setLevels({ ...levels, [k]: e.target.value }); setDirty(true) }} placeholder="15, 60, 240" className="flex-1 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" />
            <span>min</span>
          </label>
        ))}
      </div>
      <p className="text-[11px] text-slate-400">{t('maint.esc.how')}</p>
      <div className="flex items-center gap-3">
        <button disabled={!dirty || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('maint.form.save')}</button>
        {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
      </div>
    </div>
  )
}

function scheduleText(t: (k: string, o?: Record<string, unknown>) => string, w: MaintWindow): string {
  if (w.kind === 'once') return `${new Date(w.starts_at!).toLocaleString()} → ${new Date(w.ends_at!).toLocaleString()}`
  return `${w.days.map(d => t(`maint.day.${d}`)).join(', ')} ${w.start_time}, ${w.duration_min} min`
}

// Planned work is not an incident: windows in which the alerts of chosen devices are not sent to Central, and the escalation of alerts nobody picked up.
export function Maintenance() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [editing, setEditing] = useState<MaintWindow | 'new' | null>(null)
  const q = useQuery({ queryKey: ['maint'], queryFn: maintApi.overview, refetchInterval: 30000 })
  const del = useMutation({ mutationFn: (id: number) => maintApi.remove(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['maint'] }) })
  const toggle = useMutation({ mutationFn: (w: MaintWindow) => maintApi.update(w.id, { name: w.name, kind: w.kind, starts_at: w.starts_at ?? undefined, ends_at: w.ends_at ?? undefined, days: w.days, start_time: w.start_time ?? undefined, duration_min: w.duration_min ?? undefined, scope_all: w.scope_all, asset_ids: w.asset_ids, enabled: !w.enabled }), onSuccess: () => qc.invalidateQueries({ queryKey: ['maint'] }) })
  const d = q.data
  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><BellOff size={20} className="text-indigo-600" /> {t('maint.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('maint.subtitle')}</p>
        </div>
        <button onClick={() => setEditing('new')} className="flex items-center gap-1.5 text-sm rounded-lg px-3 py-1.5 bg-indigo-600 text-white hover:bg-indigo-700"><Plus size={14} /> {t('maint.new')}</button>
      </div>
      <QuickMute />
      <div className="space-y-2">
        <h2 className="font-semibold text-slate-900 text-sm">{t('maint.windows')}</h2>
        {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : !d || d.windows.length === 0 ? <p className="text-sm text-slate-500">{t('maint.none')}</p> : (
          <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
            {d.windows.map(w => (
              <div key={w.id} className="flex items-center gap-3 px-4 py-2">
                <input type="checkbox" checked={w.enabled} title={t('maint.enabled') as string} onChange={() => toggle.mutate(w)} />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-slate-900 truncate">{w.name} {w.active && <span className="ml-2 text-xs bg-amber-50 text-amber-800 border border-amber-200 rounded-full px-2 py-0.5">{t('maint.active')}</span>}</div>
                  <div className="text-xs text-slate-500">{scheduleText(t as never, w)}</div>
                  <div className="text-[11px] text-slate-400 truncate">{w.scope_all ? t('maint.form.all') : w.assets.join(', ')}</div>
                </div>
                <span className="text-xs text-slate-400 tabular-nums" title={t('maint.suppressedHint') as string}>{t('maint.suppressed', { n: w.suppressed })}</span>
                <button className="p-1 text-slate-400 hover:text-indigo-600" onClick={() => setEditing(w)}><Pencil size={14} /></button>
                <button className="p-1 text-slate-400 hover:text-red-600" onClick={() => { if (confirm(t('maint.deleteConfirm', { name: w.name }) as string)) del.mutate(w.id) }}><Trash2 size={14} /></button>
              </div>
            ))}
          </div>
        )}
      </div>
      {d && <Escalation s={d.escalation} />}
      {editing && <WindowForm initial={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

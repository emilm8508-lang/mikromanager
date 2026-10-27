import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { BatteryCharging, Plus, Trash2, Zap } from 'lucide-react'
import { upsApi, UpsRow, SensorRow } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { Modal } from '../components/ui/Modal'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

function UpsForm({ initial, onClose }: { initial: Partial<UpsRow> | null; onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [name, setName] = useState(initial?.name ?? '')
  const [ip, setIp] = useState(initial?.ip ?? '')
  const [port, setPort] = useState(initial?.port ?? 161)
  const [community, setCommunity] = useState('')
  const test = useMutation({ mutationFn: () => upsApi.test({ ip, port, community: community || null }) })
  const save = useMutation({
    mutationFn: () => (initial?.id ? upsApi.update(initial.id, { name, ip, port, community: community || undefined }) : upsApi.create({ name, ip, port, community: community || undefined })),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['ups'] }); onClose() },
  })
  return (
    <Modal open onClose={onClose} title={t(initial?.id ? 'ups.form.titleEdit' : 'ups.form.titleNew') as string}>
      <div className="space-y-3 text-sm">
        <label className="block"><span className="text-xs text-slate-500">{t('ups.form.name')}</span><input value={name} onChange={e => setName(e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" /></label>
        <div className="flex gap-3">
          <label className="flex-1"><span className="text-xs text-slate-500">IP</span><input value={ip} onChange={e => setIp(e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5 font-mono" /></label>
          <label><span className="text-xs text-slate-500">UDP</span><input type="number" value={port} onChange={e => setPort(Number(e.target.value))} className="mt-0.5 w-24 border border-slate-300 rounded-lg px-2 py-1.5" /></label>
        </div>
        <label className="block"><span className="text-xs text-slate-500">{t('ups.form.community')}</span><input type="password" autoComplete="off" value={community} onChange={e => setCommunity(e.target.value)} placeholder={t('ups.form.communityHint') as string} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5 font-mono" /></label>
        <div className="flex items-center gap-3">
          <button disabled={!ip || test.isPending} onClick={() => test.mutate()} className="px-3 py-1.5 text-sm border border-slate-300 rounded-lg bg-white hover:bg-slate-50 disabled:opacity-50">{t('ups.form.test')}</button>
          {test.data && (test.data.ok ? <span className="text-xs text-green-700">{t('ups.form.testOk', { model: test.data.state?.model ?? '?', charge: test.data.state?.charge ?? '?' })}</span> : <span className="text-xs text-red-700">{t('ups.form.testFail')}</span>)}
        </div>
        {(save.isError || test.isError) && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{errText(save.error ?? test.error)}</div>}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm border border-slate-300 rounded-lg bg-white hover:bg-slate-50">{t('maint.form.cancel')}</button>
          <button disabled={!name.trim() || !ip.trim() || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('maint.form.save')}</button>
        </div>
      </div>
    </Modal>
  )
}

function SensorForm({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [f, setF] = useState({ name: '', ip: '', port: 161, oid: '', scale: 1, unit: '°C', kind: 'temp', community: '' })
  const save = useMutation({ mutationFn: () => upsApi.createSensor({ ...f, community: f.community || undefined }), onSuccess: () => { void qc.invalidateQueries({ queryKey: ['ups'] }); onClose() } })
  const set = (k: string, v: string | number) => setF(p => ({ ...p, [k]: v }))
  return (
    <Modal open onClose={onClose} title={t('ups.sensor.titleNew') as string}>
      <div className="space-y-3 text-sm">
        <label className="block"><span className="text-xs text-slate-500">{t('ups.form.name')}</span><input value={f.name} onChange={e => set('name', e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" /></label>
        <div className="flex gap-3">
          <label className="flex-1"><span className="text-xs text-slate-500">IP</span><input value={f.ip} onChange={e => set('ip', e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5 font-mono" /></label>
          <label><span className="text-xs text-slate-500">UDP</span><input type="number" value={f.port} onChange={e => set('port', Number(e.target.value))} className="mt-0.5 w-24 border border-slate-300 rounded-lg px-2 py-1.5" /></label>
        </div>
        <label className="block"><span className="text-xs text-slate-500">OID</span><input value={f.oid} onChange={e => set('oid', e.target.value)} placeholder="1.3.6.1.4.1…" className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5 font-mono" /></label>
        <div className="flex gap-3">
          <label><span className="text-xs text-slate-500">{t('ups.sensor.scale')}</span><input type="number" step="any" value={f.scale} onChange={e => set('scale', Number(e.target.value))} className="mt-0.5 w-24 border border-slate-300 rounded-lg px-2 py-1.5" /></label>
          <label><span className="text-xs text-slate-500">{t('ups.sensor.unit')}</span><input value={f.unit} onChange={e => set('unit', e.target.value)} className="mt-0.5 w-20 border border-slate-300 rounded-lg px-2 py-1.5" /></label>
          <label><span className="text-xs text-slate-500">{t('metrics.rules.kind')}</span>
            <select value={f.kind} onChange={e => set('kind', e.target.value)} className="mt-0.5 border border-slate-300 rounded-lg px-2 py-1.5 bg-white">{['temp', 'other', 'cpu', 'mem', 'disk'].map(k => <option key={k} value={k}>{t(`metrics.kind.${k}`)}</option>)}</select></label>
          <label className="flex-1"><span className="text-xs text-slate-500">{t('ups.form.community')}</span><input type="password" autoComplete="off" value={f.community} onChange={e => set('community', e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-2 py-1.5 font-mono" /></label>
        </div>
        <p className="text-[11px] text-slate-400">{t('ups.sensor.hint')}</p>
        {save.isError && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{errText(save.error)}</div>}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm border border-slate-300 rounded-lg bg-white hover:bg-slate-50">{t('maint.form.cancel')}</button>
          <button disabled={!f.name.trim() || !f.ip.trim() || !f.oid.trim() || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('maint.form.save')}</button>
        </div>
      </div>
    </Modal>
  )
}

function UpsCard({ u, onDelete }: { u: UpsRow; onDelete: () => void }) {
  const { t } = useTranslation()
  const ago = useAgo()
  const s = u.state
  const src = s?.source ?? 'unknown'
  const tone = u.error ? 'border-red-200 bg-red-50' : src === 'battery' ? 'border-amber-300 bg-amber-50' : 'border-slate-200 bg-white'
  const charge = s?.charge ?? null
  return (
    <div className={cn('border rounded-xl p-4 space-y-2 text-sm', tone)}>
      <div className="flex items-center gap-2">
        <Zap size={16} className={src === 'battery' ? 'text-amber-600' : 'text-green-600'} />
        <div className="flex-1 min-w-0"><div className="font-semibold text-slate-900 truncate">{u.name}</div><div className="text-[11px] text-slate-400">{u.ip}{s?.model ? ` · ${s.model}` : ''}</div></div>
        <span className={cn('text-xs border rounded-full px-2 py-0.5', src === 'battery' ? 'bg-amber-100 text-amber-900 border-amber-300' : src === 'online' ? 'bg-green-50 text-green-700 border-green-200' : 'bg-slate-50 text-slate-500 border-slate-200')}>{t(`ups.source.${src}`)}</span>
        <button className="p-1 text-slate-400 hover:text-red-600" onClick={onDelete}><Trash2 size={14} /></button>
      </div>
      {u.error && <div className="text-xs text-red-700">{t('ups.notAnswering')}</div>}
      {s && (
        <>
          {charge != null && <div><div className="flex justify-between text-xs text-slate-500"><span>{t('ups.charge')}</span><span className="tabular-nums">{charge.toFixed(0)}%</span></div>
            <div className="h-2 bg-slate-200 rounded-full overflow-hidden"><div className={cn('h-full', charge < 30 ? 'bg-red-500' : charge < 60 ? 'bg-amber-400' : 'bg-green-500')} style={{ width: `${Math.max(0, Math.min(100, charge))}%` }} /></div></div>}
          <div className="grid grid-cols-4 gap-2 text-xs">
            {[['runtime', s.minutes, 'min'], ['load', s.load, '%'], ['temp', s.temp, '°C'], ['voltage', s.voltage, 'V']].map(([k, v, unit]) => (
              <div key={k as string}><div className="text-slate-400">{t(`ups.${k}`)}</div><div className="tabular-nums text-slate-800">{v != null ? `${Number(v).toFixed(k === 'voltage' ? 1 : 0)} ${unit}` : '—'}</div></div>
            ))}
          </div>
          {(s.alarms > 0 || s.battery === 'low' || s.battery === 'depleted') && <div className="text-xs text-red-700">{s.battery !== 'ok' && s.battery !== 'unknown' ? t(`ups.battery.${s.battery}`) : ''}{s.alarms > 0 ? ` ${t('ups.alarms', { n: s.alarms })}` : ''}</div>}
        </>
      )}
      <div className="text-[11px] text-slate-400">{t('ups.lastOk')}: {ago(u.last_ok)}</div>
    </div>
  )
}

// The power of the server room: UPS units over SNMP (on battery, battery low, alarms) and any other SNMP value (a temperature probe, a PDU) recorded as a series.
export function Ups() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['ups'], queryFn: upsApi.overview, refetchInterval: 30000 })
  const [form, setForm] = useState<Partial<UpsRow> | null | undefined>(undefined)
  const [sensorForm, setSensorForm] = useState(false)
  const refresh = () => qc.invalidateQueries({ queryKey: ['ups'] })
  const del = useMutation({ mutationFn: (id: number) => upsApi.remove(id), onSuccess: refresh })
  const delS = useMutation({ mutationFn: (id: number) => upsApi.removeSensor(id), onSuccess: refresh })
  const run = useMutation({ mutationFn: upsApi.run, onSuccess: refresh })
  const d = q.data
  return (
    <div className="p-6 space-y-5 max-w-[1100px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><BatteryCharging size={20} className="text-indigo-600" /> {t('ups.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('ups.subtitle')}</p>
        </div>
        <button onClick={() => run.mutate()} disabled={run.isPending} className="text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">{t('ups.runNow')}</button>
        <button onClick={() => setForm(null)} className="flex items-center gap-1.5 text-sm rounded-lg px-3 py-1.5 bg-indigo-600 text-white hover:bg-indigo-700"><Plus size={14} /> {t('ups.add')}</button>
      </div>
      {d && d.suggestions.length > 0 && (
        <div className="bg-sky-50 border border-sky-200 rounded-xl p-3 text-sm space-y-1">
          <div className="font-medium text-sky-900">{t('ups.suggest')}</div>
          <div className="flex flex-wrap gap-2">{d.suggestions.map(s => <button key={s.id} onClick={() => setForm({ name: s.name, ip: s.ip })} className="text-xs border border-sky-300 rounded-full px-3 py-1 bg-white hover:bg-sky-100">{s.name} · {s.ip}</button>)}</div>
        </div>
      )}
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : d && d.ups.length === 0 ? <p className="text-sm text-slate-500">{t('ups.none')}</p> : (
        <div className="grid sm:grid-cols-2 gap-3">{(d?.ups ?? []).map(u => <UpsCard key={u.id} u={u} onDelete={() => { if (confirm(t('ups.deleteConfirm', { name: u.name }) as string)) del.mutate(u.id) }} />)}</div>
      )}
      <div className="space-y-2">
        <div className="flex items-center gap-3"><h2 className="font-semibold text-slate-900 text-sm flex-1">{t('ups.sensors')}</h2>
          <button onClick={() => setSensorForm(true)} className="flex items-center gap-1 text-xs border border-slate-300 rounded-lg px-2.5 py-1 hover:bg-slate-50"><Plus size={12} /> {t('ups.sensor.add')}</button></div>
        {d && d.sensors.length === 0 ? <p className="text-xs text-slate-400">{t('ups.sensor.none')}</p> : (
          <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
            {(d?.sensors ?? []).map((s: SensorRow) => (
              <div key={s.id} className="flex items-center gap-3 px-4 py-2">
                <div className="flex-1 min-w-0"><div className="text-slate-900 truncate">{s.name}</div><div className="text-[11px] text-slate-400 font-mono truncate">{s.ip} · {s.oid}</div></div>
                <div className={cn('tabular-nums', s.error && 'text-red-600')}>{s.error ? t('ups.notAnswering') : s.value != null ? `${s.value.toFixed(1)} ${s.unit ?? ''}` : '—'}</div>
                <div className="text-xs text-slate-400 w-20 text-right">{ago(s.last_check)}</div>
                <button className="p-1 text-slate-400 hover:text-red-600" onClick={() => { if (confirm(t('ups.deleteConfirm', { name: s.name }) as string)) delS.mutate(s.id) }}><Trash2 size={14} /></button>
              </div>
            ))}
          </div>
        )}
      </div>
      <p className="text-xs text-slate-400">{t('ups.note')} <Link to="/metrics" className="text-indigo-600 hover:underline">{t('metrics.title')}</Link></p>
      {form !== undefined && <UpsForm initial={form} onClose={() => setForm(undefined)} />}
      {sensorForm && <SensorForm onClose={() => setSensorForm(false)} />}
    </div>
  )
}

import { useState, Fragment } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight, Layers3, Pencil, Plus, Trash2 } from 'lucide-react'
import { assetsApi, bizApi, BizBody, BizService } from '../lib/api'
import { Modal } from '../components/ui/Modal'
import { StatePill, formatDur } from './Availability'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'

const SVC_STYLE: Record<string, string> = {
  ok: 'bg-green-50 text-green-700 border-green-200',
  degraded: 'bg-amber-50 text-amber-700 border-amber-200',
  down: 'bg-red-50 text-red-700 border-red-200',
  unknown: 'bg-slate-50 text-slate-500 border-slate-200',
}

export function SvcPill({ s }: { s: string }) {
  const { t } = useTranslation()
  return <span className={cn('inline-block text-xs border rounded-full px-2 py-0.5', SVC_STYLE[s] ?? SVC_STYLE.unknown)}>{t(`svc.state.${s}`)}</span>
}

export function modeText(t: (k: string, o?: Record<string, unknown>) => string, mode: string, minUp: number | null) {
  return mode === 'min' ? t('svc.mode.min', { n: minUp ?? '?' }) : t(`svc.mode.${mode}`)
}

export function MonthCell({ m }: { m: { uptime: number | null; target?: number; left_min?: number; met?: boolean } | null }) {
  const { t } = useTranslation()
  if (!m || m.uptime == null) return <span className="text-slate-300">—</span>
  return (
    <div>
      <div className={cn('tabular-nums', m.target != null && !m.met ? 'text-red-600 font-medium' : 'text-slate-700')}>
        {m.target != null ? t('svc.month', { uptime: m.uptime.toFixed(2), target: m.target }) : t('svc.monthNoTarget', { uptime: m.uptime.toFixed(2) })}
      </div>
      {m.target != null && m.left_min != null && (
        <div className="text-[11px] text-slate-400">{m.left_min >= 0 ? t('svc.budgetLeft', { left: Math.round(m.left_min) }) : t('svc.budgetOver', { over: Math.round(-m.left_min) })}</div>
      )}
    </div>
  )
}

function Detail({ id }: { id: number }) {
  const { t } = useTranslation()
  const q = useQuery({ queryKey: ['svc', id], queryFn: () => bizApi.get(id, 30), refetchInterval: 60000 })
  const d = q.data
  if (!d) return <div className="px-4 py-3 text-xs text-slate-500">{t('common.loading')}</div>
  return (
    <div className="px-4 py-3 bg-slate-50 space-y-3 text-xs">
      {d.description && <div className="text-slate-600">{d.description}</div>}
      <div>
        <div className="font-medium text-slate-700 mb-1">{t('svc.members')} ({modeText(t as never, d.mode, d.min_up)})</div>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {d.member_states.map(m => (
            <span key={m.id} className="inline-flex items-center gap-1.5">
              <Link to={`/inventory/${m.id}`} className="text-indigo-600 hover:underline">{m.name}</Link>
              <StatePill s={m.state} />
              {m.root && <span className="text-slate-400">{t('svc.memberCause', { name: m.root })}</span>}
            </span>
          ))}
        </div>
      </div>
      <div>
        <div className="font-medium text-slate-700 mb-1">{t('svc.outages', { days: d.days })}</div>
        {d.outages.length === 0 ? <div className="text-slate-500">{t('svc.outagesNone')}</div> : (
          <div className="space-y-0.5">
            {d.outages.slice(0, 40).map((o, i) => (
              <div key={i} className="flex gap-3 items-baseline">
                <span className="text-slate-500 w-40 shrink-0">{new Date(o.from).toLocaleString()}</span>
                <span className="tabular-nums w-28 shrink-0 text-slate-700">{formatDur(o.seconds)}{o.to == null ? ` (${t('svc.ongoing')})` : ''}</span>
                <span className={o.kind === 'down' ? 'text-red-700' : 'text-amber-700'}>{o.kind === 'down' ? t('svc.outageDown') : t('svc.outageDegraded')}{o.missing ? ` — ${t('svc.missing', { names: o.missing })}` : ''}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function ServiceForm({ initial, onClose }: { initial: BizService | null; onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [mode, setMode] = useState<'all' | 'any' | 'min'>((initial?.mode as 'all' | 'any' | 'min') ?? 'all')
  const [minUp, setMinUp] = useState<number>(initial?.min_up ?? 1)
  const [target, setTarget] = useState<string>(initial?.target != null ? String(initial.target) : '')
  const [members, setMembers] = useState<Set<number>>(new Set(initial?.members ?? []))
  const [q, setQ] = useState('')
  const assets = useQuery({ queryKey: ['assets-list'], queryFn: assetsApi.list })
  const save = useMutation({
    mutationFn: (body: BizBody) => (initial ? bizApi.update(initial.id, body) : bizApi.create(body)),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['svc-list'] }); void qc.invalidateQueries({ queryKey: ['svc'] }); void qc.invalidateQueries({ queryKey: ['avail'] }); onClose() },
  })
  const rows = (assets.data ?? []).filter(a => a.ip && (members.has(a.id) || !q.trim() || `${a.name} ${a.ip}`.toLowerCase().includes(q.trim().toLowerCase())))
    .sort((a, b) => Number(members.has(b.id)) - Number(members.has(a.id)) || (a.name ?? '').localeCompare(b.name ?? ''))
  const err = (save.error as { response?: { data?: { detail?: string } }; message?: string } | null)
  const toggle = (id: number) => setMembers(p => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n })
  return (
    <Modal open onClose={onClose} title={t(initial ? 'svc.form.titleEdit' : 'svc.form.titleNew') as string} className="max-w-2xl">
      <div className="space-y-3 text-sm">
        <label className="block"><span className="text-xs text-slate-500">{t('svc.form.name')}</span>
          <input value={name} onChange={e => setName(e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" maxLength={80} /></label>
        <label className="block"><span className="text-xs text-slate-500">{t('svc.form.description')}</span>
          <input value={description} onChange={e => setDescription(e.target.value)} className="mt-0.5 w-full border border-slate-300 rounded-lg px-3 py-1.5" maxLength={300} /></label>
        <div className="grid grid-cols-[1fr_auto_auto] gap-3 items-end">
          <label className="block"><span className="text-xs text-slate-500">{t('svc.form.mode')}</span>
            <select value={mode} onChange={e => setMode(e.target.value as 'all' | 'any' | 'min')} className="mt-0.5 w-full border border-slate-300 rounded-lg px-2 py-1.5 bg-white">
              <option value="all">{t('svc.form.modeAll')}</option><option value="any">{t('svc.form.modeAny')}</option><option value="min">{t('svc.form.modeMin')}</option>
            </select></label>
          {mode === 'min' ? (
            <label className="block"><span className="text-xs text-slate-500">{t('svc.form.minUp')}</span>
              <input type="number" min={1} max={Math.max(1, members.size)} value={minUp} onChange={e => setMinUp(Number(e.target.value))} className="mt-0.5 w-24 border border-slate-300 rounded-lg px-2 py-1.5" /></label>
          ) : <span />}
          <label className="block"><span className="text-xs text-slate-500">{t('svc.form.target')}</span>
            <input value={target} onChange={e => setTarget(e.target.value)} placeholder="99.9" className="mt-0.5 w-28 border border-slate-300 rounded-lg px-2 py-1.5" /></label>
        </div>
        <div>
          <div className="flex items-center gap-3 mb-1">
            <span className="text-xs text-slate-500">{t('svc.form.members')}</span>
            <span className="text-xs text-slate-400">{t('svc.form.chosen', { count: members.size })}</span>
            <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('svc.form.search') as string} className="ml-auto border border-slate-300 rounded-lg px-2 py-1 text-xs w-56" />
          </div>
          <div className="border border-slate-200 rounded-lg max-h-56 overflow-y-auto divide-y divide-slate-100">
            {rows.slice(0, 300).map(a => (
              <label key={a.id} className="flex items-center gap-2 px-3 py-1 hover:bg-slate-50 cursor-pointer">
                <input type="checkbox" checked={members.has(a.id)} onChange={() => toggle(a.id)} />
                <span className="text-slate-800 truncate">{a.name}</span><span className="text-xs text-slate-400">{a.ip}</span>
              </label>
            ))}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">{t('svc.form.hint')}</p>
        </div>
        {err && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{err.response?.data?.detail ?? err.message}</div>}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm border border-slate-300 rounded-lg bg-white hover:bg-slate-50">{t('svc.form.cancel')}</button>
          <button disabled={!name.trim() || members.size === 0 || save.isPending}
            onClick={() => save.mutate({ name: name.trim(), description: description.trim() || null, mode, min_up: mode === 'min' ? minUp : null,
                                         target: target.trim() ? Number(target.replace(',', '.')) : null, members: [...members] })}
            className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('svc.form.save')}</button>
        </div>
      </div>
    </Modal>
  )
}

// What people use, described as the equipment it needs: the state follows from the availability of that equipment, the SLA from the history.
export function Services() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const [open, setOpen] = useState<number | null>(null)
  const [editing, setEditing] = useState<BizService | 'new' | null>(null)
  const list = useQuery({ queryKey: ['svc-list'], queryFn: bizApi.list, refetchInterval: 30000 })
  const del = useMutation({ mutationFn: bizApi.remove, onSuccess: () => qc.invalidateQueries({ queryKey: ['svc-list'] }) })
  const d = list.data
  const grid = 'grid-cols-[1.5rem_minmax(0,2fr)_7rem_minmax(0,1.3fr)_minmax(0,1.3fr)_minmax(0,1.4fr)_5rem]'
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Layers3 size={20} className="text-indigo-600" /> {t('svc.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('svc.subtitle')}</p>
        </div>
        <button onClick={() => setEditing('new')} className="flex items-center gap-1.5 text-sm rounded-lg px-3 py-1.5 bg-indigo-600 text-white hover:bg-indigo-700"><Plus size={14} /> {t('svc.new')}</button>
      </div>
      {d && d.items.length > 0 && <p className="text-sm text-slate-600">{t('svc.counts', { ok: d.ok, degraded: d.degraded, down: d.down })}</p>}
      {list.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : !d || d.items.length === 0 ? <p className="text-sm text-slate-500">{t('svc.empty')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className={cn('grid items-center bg-slate-50 text-xs text-slate-500 py-2', grid)}>
            <div /><div className="px-2">{t('svc.col.service')}</div><div className="px-2">{t('svc.col.state')}</div><div className="px-2">{t('svc.col.members')}</div>
            <div className="px-2">{t('svc.col.uptime')}</div><div className="px-2">{t('svc.col.sla')}</div><div />
          </div>
          {d.items.map(s => (
            <Fragment key={s.id}>
              <div className={cn('grid items-center border-t border-slate-100 cursor-pointer hover:bg-slate-50', grid)} onClick={() => setOpen(open === s.id ? null : s.id)}>
                <div className="px-2 text-slate-400">{open === s.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</div>
                <div className="px-2 py-2 min-w-0">
                  <div className="font-medium text-slate-900 truncate">{s.name}</div>
                  <div className="text-[11px] text-slate-400">{modeText(t as never, s.mode, s.min_up)}</div>
                </div>
                <div className="px-2"><SvcPill s={s.state} />{s.since && <div className="text-[11px] text-slate-400 mt-0.5">{ago(s.since)}</div>}</div>
                <div className="px-2 text-xs text-slate-600 min-w-0">
                  <div>{t('svc.membersUp', { up: s.up, total: s.total })}</div>
                  {s.missing.length > 0 && <div className="text-red-600 truncate" title={s.missing.join(', ')}>{t('svc.missing', { names: s.missing.join(', ') })}</div>}
                </div>
                <div className="px-2 tabular-nums text-slate-700">{s.uptime['30d'] != null ? `${s.uptime['30d'].toFixed(2)}%` : '—'}</div>
                <div className="px-2"><MonthCell m={s.month} /></div>
                <div className="px-2 flex gap-1 justify-end" onClick={e => e.stopPropagation()}>
                  <button className="p-1 text-slate-400 hover:text-indigo-600" title={t('svc.edit') as string} onClick={() => setEditing(s)}><Pencil size={14} /></button>
                  <button className="p-1 text-slate-400 hover:text-red-600" title={t('svc.delete') as string}
                    onClick={() => { if (confirm(t('svc.deleteConfirm', { name: s.name }) as string)) del.mutate(s.id) }}><Trash2 size={14} /></button>
                </div>
              </div>
              {open === s.id && <Detail id={s.id} />}
            </Fragment>
          ))}
        </div>
      )}
      {editing && <ServiceForm initial={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

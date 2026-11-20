import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, KeySquare, Pencil, Plus, Trash2 } from 'lucide-react'
import { licensesApi, LicenseRow, LicenseStatus } from '../lib/api'
import { useAuth } from './Login'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const KINDS = ['per_device', 'per_user', 'per_server', 'per_core', 'site', 'subscription'] as const
const STATUS_TONE: Record<LicenseStatus, string> = {
  compliant: 'bg-green-50 text-green-700 border-green-200', over: 'bg-red-50 text-red-700 border-red-200', unused: 'bg-sky-50 text-sky-700 border-sky-200',
  expired: 'bg-slate-200 text-slate-600 border-slate-300', expiring: 'bg-amber-50 text-amber-700 border-amber-200', no_installs: 'bg-slate-50 text-slate-500 border-slate-200',
  site: 'bg-indigo-50 text-indigo-700 border-indigo-200',
}
const STATUS_BAR: Record<LicenseStatus, string> = {
  compliant: 'bg-green-500', over: 'bg-red-500', unused: 'bg-sky-400', expired: 'bg-slate-400', expiring: 'bg-amber-400', no_installs: 'bg-slate-200', site: 'bg-indigo-400',
}

type Form = { product: string; vendor: string; kind: string; seats: string; match: string; exclude: string; valid_from: string; valid_until: string; cost: string
  currency: string; supplier: string; reference: string; notes: string; key: string }
const EMPTY: Form = { product: '', vendor: '', kind: 'per_device', seats: '', match: '', exclude: '', valid_from: '', valid_until: '', cost: '', currency: '', supplier: '',
  reference: '', notes: '', key: '' }

function toForm(l: LicenseRow): Form {
  return { product: l.product, vendor: l.vendor ?? '', kind: l.kind, seats: l.seats == null ? '' : String(l.seats), match: l.match.join('; '), exclude: l.exclude.join('; '),
    valid_from: l.valid_from ?? '', valid_until: l.valid_until ?? '', cost: l.cost == null ? '' : String(l.cost), currency: l.currency ?? '', supplier: l.supplier ?? '',
    reference: l.reference ?? '', notes: l.notes ?? '', key: '' }
}

function LicenseForm({ init, id, onDone }: { init: Form; id: number | null; onDone: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [f, setF] = useState<Form>(init)
  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { ...f, seats: f.kind === 'site' || f.seats === '' ? null : Number(f.seats), cost: f.cost || null }
      if (!f.key) delete body.key                         // an empty key field keeps the stored key
      return id ? licensesApi.update(id, body) : licensesApi.create(body)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['licenses'] }); onDone() },
  })
  const inp = 'mt-0.5 block w-full border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white text-slate-900'
  const field = (k: keyof Form, opts: { type?: string; max?: number } = {}) => (
    <label className="block text-xs text-slate-500">{t(`lic.f.${k}`)}
      <input type={opts.type ?? 'text'} value={f[k]} maxLength={opts.max} onChange={e => setF({ ...f, [k]: e.target.value })} className={inp} /></label>
  )
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {field('product', { max: 120 })}
        {field('vendor', { max: 80 })}
        <label className="block text-xs text-slate-500">{t('lic.f.kind')}
          <select value={f.kind} onChange={e => setF({ ...f, kind: e.target.value })} className={inp}>{KINDS.map(k => <option key={k} value={k}>{t(`lic.kind.${k}`)}</option>)}</select></label>
        {f.kind !== 'site' && field('seats', { type: 'number' })}
      </div>
      <div className="grid sm:grid-cols-2 gap-3">
        <label className="block text-xs text-slate-500">{t('lic.f.match')}<input value={f.match} onChange={e => setF({ ...f, match: e.target.value })} placeholder="Office 2021; Microsoft Office Professional Plus 2021" className={inp} /></label>
        <label className="block text-xs text-slate-500">{t('lic.f.exclude')}<input value={f.exclude} onChange={e => setF({ ...f, exclude: e.target.value })} placeholder="Click-to-Run Extensibility" className={inp} /></label>
      </div>
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {field('valid_from', { type: 'date' })}
        {field('valid_until', { type: 'date' })}
        {field('cost')}
        {field('currency', { max: 3 })}
        {field('supplier', { max: 120 })}
        {field('reference', { max: 80 })}
        <label className="block text-xs text-slate-500 lg:col-span-2">{t('lic.f.key')}<input type="password" autoComplete="off" value={f.key} onChange={e => setF({ ...f, key: e.target.value })} placeholder={id ? (t('lic.keyKeep') as string) : ''} className={inp} /></label>
      </div>
      <label className="block text-xs text-slate-500">{t('lic.f.notes')}<textarea value={f.notes} maxLength={1000} rows={2} onChange={e => setF({ ...f, notes: e.target.value })} className={inp} /></label>
      <div className="flex items-center gap-3">
        <button disabled={save.isPending || !f.product.trim() || !f.match.trim()} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50">{t('common.save')}</button>
        <button onClick={onDone} className="px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white">{t('lic.cancel')}</button>
        {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
      </div>
    </div>
  )
}

function Seats({ l }: { l: LicenseRow }) {
  const { t } = useTranslation()
  if (l.seats == null) return <span className="text-xs text-slate-600">{t('lic.usedSite', { used: l.used })}</span>
  const cap = Math.max(l.seats, l.used, 1)
  return (
    <div className="w-44">
      <div className="h-2 bg-slate-100 rounded-full overflow-hidden flex">
        <div className="bg-green-500" style={{ width: `${(Math.min(l.used, l.seats) / cap) * 100}%` }} />
        {l.over > 0 && <div className="bg-red-500" style={{ width: `${(l.over / cap) * 100}%` }} />}
      </div>
      <div className="text-[11px] text-slate-600 tabular-nums mt-0.5">{t('lic.usedOf', { used: l.used, seats: l.seats })}{l.reclaimable ? ` · ${t('lic.reclaim', { n: l.reclaimable })}` : ''}</div>
    </div>
  )
}

function Detail({ id }: { id: number }) {
  const { t } = useTranslation()
  const { role } = useAuth()
  const q = useQuery({ queryKey: ['license', id], queryFn: () => licensesApi.detail(id) })
  const [key, setKey] = useState<string | null>(null)
  const reveal = useMutation({ mutationFn: () => licensesApi.key(id), onSuccess: r => setKey(r.key ?? '—') })
  const d = q.data
  if (!d) return <div className="px-4 py-3 text-xs text-slate-500">{t('common.loading')}</div>
  return (
    <div className="px-4 py-3 bg-slate-50 text-xs space-y-2">
      <div className="text-slate-600">{t('lic.matching')}: <b>{d.match.join('; ')}</b>{d.exclude.length ? ` · ${t('lic.excluding')}: ${d.exclude.join('; ')}` : ''}</div>
      {d.notes && <div className="text-slate-600 whitespace-pre-wrap">{d.notes}</div>}
      {d.has_key && role === 'admin' && (
        <div className="flex items-center gap-2"><KeySquare size={13} className="text-slate-400" />
          {key ? <code className="bg-white border border-slate-200 rounded px-1.5 py-0.5">{key}</code>
            : <button onClick={() => reveal.mutate()} className="text-indigo-600 hover:underline">{t('lic.showKey')}</button>}
          <span className="text-slate-400">{t('lic.keyAudit')}</span>
        </div>
      )}
      {(d.install_list ?? []).length === 0 ? <div className="text-slate-500">{t('lic.noInstalls')}</div> : (
        <table className="w-full">
          <thead className="text-slate-500"><tr><th className="text-left font-normal py-1">{t('lic.col.asset')}</th><th className="text-left font-normal">{t('lic.col.program')}</th><th className="text-left font-normal">{t('lic.col.version')}</th><th className="text-left font-normal">{t('lic.col.counts')}</th></tr></thead>
          <tbody>
            {d.install_list!.map(h => (
              <tr key={h.asset_id} className="border-t border-slate-200">
                <td className="py-1"><Link to={`/inventory/${h.asset_id}`} className="text-indigo-600 hover:underline">{h.asset}</Link></td>
                <td className="text-slate-700">{h.name}</td><td className="text-slate-500">{h.version}</td>
                <td className={h.live ? 'text-green-700' : 'text-amber-700'}>{h.live ? t('lic.inUse') : t('lic.reclaimable')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// Software licenses against the software inventory (services/licenses.py, docs/plan-itam.md stage C).
export function Licenses() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['licenses'], queryFn: licensesApi.overview })
  const [open, setOpen] = useState<number | null>(null)
  const [edit, setEdit] = useState<{ id: number | null; init: Form } | null>(null)
  const del = useMutation({ mutationFn: (id: number) => licensesApi.remove(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['licenses'] }) })
  const d = q.data
  const rows = d?.licenses ?? []
  const counts = rows.reduce<Record<string, number>>((m, l) => ({ ...m, [l.status]: (m[l.status] ?? 0) + 1 }), {})
  const totalSeats = rows.reduce((n, l) => n + (l.seats ?? 0), 0)
  const usedSeats = rows.reduce((n, l) => n + (l.seats != null ? Math.min(l.used, l.seats) : 0), 0)
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><KeySquare size={20} className="text-indigo-600" /> {t('lic.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('lic.subtitle')}</p>
        </div>
        <button onClick={() => setEdit({ id: null, init: EMPTY })} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50"><Plus size={14} /> {t('lic.add')}</button>
      </div>
      {rows.length > 0 && (
        <div className="grid md:grid-cols-2 gap-3">
          <div className="bg-white border border-slate-200 rounded-xl p-4">
            <div className="text-xs text-slate-500 mb-2">{t('lic.chartStatus')}</div>
            <div className="h-4 rounded-full overflow-hidden flex">
              {(Object.keys(STATUS_BAR) as LicenseStatus[]).filter(s => counts[s]).map(s => (
                <div key={s} className={STATUS_BAR[s]} style={{ width: `${(counts[s] / rows.length) * 100}%` }} title={`${t(`lic.status.${s}`)}: ${counts[s]}`} />
              ))}
            </div>
            <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 text-xs">
              {(Object.keys(STATUS_BAR) as LicenseStatus[]).filter(s => counts[s]).map(s => (
                <span key={s} className="flex items-center gap-1"><span className={cn('w-2.5 h-2.5 rounded-sm', STATUS_BAR[s])} />{t(`lic.status.${s}`)} <b>{counts[s]}</b></span>
              ))}
            </div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4">
            <div className="text-xs text-slate-500 mb-2">{t('lic.chartSeats')}</div>
            <div className="h-4 bg-slate-100 rounded-full overflow-hidden"><div className="h-full bg-indigo-500" style={{ width: `${totalSeats ? (usedSeats / totalSeats) * 100 : 0}%` }} /></div>
            <div className="text-xs text-slate-600 mt-2">{t('lic.seatsUse', { used: usedSeats, total: totalSeats, pct: totalSeats ? Math.round((usedSeats / totalSeats) * 100) : 0 })}</div>
          </div>
        </div>
      )}
      {edit && <LicenseForm key={edit.id ?? 'new'} init={edit.init} id={edit.id} onDone={() => setEdit(null)} />}
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : rows.length === 0 ? <p className="text-sm text-slate-500">{t('lic.empty')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          {rows.map(l => (
            <Fragment key={l.id}>
              <div className="flex items-center gap-3 px-4 py-2 border-t border-slate-100 first:border-t-0 cursor-pointer hover:bg-slate-50" onClick={() => setOpen(open === l.id ? null : l.id)}>
                {open === l.id ? <ChevronDown size={14} className="text-slate-400" /> : <ChevronRight size={14} className="text-slate-400" />}
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-slate-900 truncate">{l.product}</div>
                  <div className="text-[11px] text-slate-500">{[l.vendor, t(`lic.kind.${l.kind}`), l.valid_until ? t('lic.until', { date: new Date(l.valid_until).toLocaleDateString() }) : null, l.cost != null ? `${l.cost} ${l.currency ?? ''}` : null].filter(Boolean).join(' · ')}</div>
                </div>
                <Seats l={l} />
                <span className={cn('text-xs border rounded-full px-2 py-0.5 w-28 text-center', STATUS_TONE[l.status])}>{t(`lic.status.${l.status}`)}</span>
                <span className="flex gap-2" onClick={e => e.stopPropagation()}>
                  <button title={t('lic.edit') as string} onClick={() => setEdit({ id: l.id, init: toForm(l) })} className="text-slate-400 hover:text-indigo-600"><Pencil size={14} /></button>
                  <button title={t('lic.remove') as string} onClick={() => { if (window.confirm(`${t('lic.remove')}: ${l.product}?`)) del.mutate(l.id) }} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>
                </span>
              </div>
              {open === l.id && <Detail id={l.id} />}
            </Fragment>
          ))}
        </div>
      )}
      {(d?.suggestions.length ?? 0) > 0 && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 text-sm">
          <div className="font-semibold text-slate-800">{t('lic.suggestTitle')}</div>
          <p className="text-xs text-slate-500 mb-2">{t('lic.suggestHint')}</p>
          <div className="flex flex-wrap gap-1.5">
            {d!.suggestions.map(s => (
              <button key={s.name} onClick={() => setEdit({ id: null, init: { ...EMPTY, product: s.name, match: s.name, seats: String(s.assets) } })}
                className="text-xs border border-slate-200 rounded-full px-2.5 py-0.5 hover:bg-indigo-50 hover:border-indigo-300">{s.name} <b className="text-slate-500">{s.assets}</b></button>
            ))}
          </div>
        </div>
      )}
      <p className="text-xs text-slate-400">{t('lic.note')}</p>
    </div>
  )
}

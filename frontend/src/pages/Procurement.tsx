import { Fragment, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, FileSignature, Pencil, Plus, Trash2 } from 'lucide-react'
import { assetsApi, licensesApi, procurementApi, ContractRow, OrderRow, VendorRow } from '../lib/api'
import { Attachments } from '../components/Attachments'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const KINDS = ['support', 'maintenance', 'warranty', 'lease', 'license', 'sla', 'other'] as const
const ITEM_KINDS = ['asset', 'license', 'service', 'other'] as const
const ASSET_TYPES = ['windows', 'linux', 'network', 'printer', 'virtual', 'server', 'other'] as const
const CSTATUS: Record<string, string> = {
  active: 'bg-green-50 text-green-700 border-green-200', expiring: 'bg-amber-50 text-amber-700 border-amber-200', expired: 'bg-red-50 text-red-700 border-red-200',
  renewing: 'bg-sky-50 text-sky-700 border-sky-200', future: 'bg-slate-50 text-slate-600 border-slate-200',
}
const OSTATUS: Record<string, string> = {
  draft: 'bg-slate-50 text-slate-600 border-slate-200', approved: 'bg-indigo-50 text-indigo-700 border-indigo-200', ordered: 'bg-amber-50 text-amber-700 border-amber-200',
  received: 'bg-green-50 text-green-700 border-green-200', cancelled: 'bg-slate-100 text-slate-400 border-slate-200',
}
const inp = 'mt-0.5 block w-full border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white text-slate-900'
const money = (v: number | null, c: string | null) => v == null ? '' : `${v.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 2 })} ${c ?? ''}`

function Pill({ s, tone }: { s: string; tone: string }) {
  return <span className={cn('text-xs border rounded-full px-2 py-0.5 whitespace-nowrap', tone)}>{s}</span>
}

// ── Contracts ────────────────────────────────────────────────────────────────

type CForm = { title: string; kind: string; number: string; vendor_id: string; start_at: string; end_at: string; notice_days: string; value: string; currency: string
  auto_renew: boolean; owner: string; notes: string; asset_ids: number[]; license_ids: number[] }
const CEMPTY: CForm = { title: '', kind: 'support', number: '', vendor_id: '', start_at: '', end_at: '', notice_days: '30', value: '', currency: '', auto_renew: false, owner: '', notes: '', asset_ids: [], license_ids: [] }

function ContractForm({ init, id, vendors, onDone }: { init: CForm; id: number | null; vendors: VendorRow[]; onDone: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [f, setF] = useState<CForm>(init)
  const assets = useQuery({ queryKey: ['assets'], queryFn: assetsApi.list, staleTime: 60000 })
  const lics = useQuery({ queryKey: ['licenses'], queryFn: licensesApi.overview, staleTime: 60000 })
  const [pick, setPick] = useState('')
  const save = useMutation({
    mutationFn: () => {
      const b = { ...f, vendor_id: f.vendor_id ? Number(f.vendor_id) : null, notice_days: f.notice_days === '' ? null : Number(f.notice_days), value: f.value || null }
      return id ? procurementApi.updateContract(id, b) : procurementApi.createContract(b)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['procurement'] }); onDone() },
  })
  const text = (k: keyof CForm, type = 'text') => (
    <label className="block text-xs text-slate-500">{t(`proc.cf.${k}`)}<input type={type} value={f[k] as string} onChange={e => setF({ ...f, [k]: e.target.value })} className={inp} /></label>
  )
  const anames = new Map((assets.data ?? []).map(a => [a.id, a.name]))
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="lg:col-span-2">{text('title')}</div>
        <label className="block text-xs text-slate-500">{t('proc.cf.kind')}<select value={f.kind} onChange={e => setF({ ...f, kind: e.target.value })} className={inp}>{KINDS.map(k => <option key={k} value={k}>{t(`proc.ckind.${k}`)}</option>)}</select></label>
        {text('number')}
        <label className="block text-xs text-slate-500">{t('proc.cf.vendor')}<select value={f.vendor_id} onChange={e => setF({ ...f, vendor_id: e.target.value })} className={inp}><option value="">—</option>{vendors.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
        {text('start_at', 'date')}
        {text('end_at', 'date')}
        {text('notice_days', 'number')}
        {text('value')}
        {text('currency')}
        {text('owner')}
        <label className="flex items-center gap-2 text-xs text-slate-700 pt-5"><input type="checkbox" checked={f.auto_renew} onChange={e => setF({ ...f, auto_renew: e.target.checked })} /> {t('proc.cf.auto_renew')}</label>
      </div>
      <div className="grid md:grid-cols-2 gap-3">
        <div>
          <div className="text-xs text-slate-500">{t('proc.cf.assets')}</div>
          <div className="flex flex-wrap gap-1 mt-1">
            {f.asset_ids.map(i => <span key={i} className="text-xs bg-white border border-slate-200 rounded-full px-2 py-0.5">{anames.get(i) ?? `#${i}`} <button onClick={() => setF({ ...f, asset_ids: f.asset_ids.filter(x => x !== i) })} className="text-slate-400 hover:text-red-600">×</button></span>)}
          </div>
          <select value={pick} onChange={e => { const v = Number(e.target.value); if (v && !f.asset_ids.includes(v)) setF({ ...f, asset_ids: [...f.asset_ids, v] }); setPick('') }} className={inp}>
            <option value="">{t('proc.addAsset')}</option>{(assets.data ?? []).map(a => <option key={a.id} value={a.id}>{a.name}{a.ip ? ` (${a.ip})` : ''}</option>)}
          </select>
        </div>
        <div>
          <div className="text-xs text-slate-500">{t('proc.cf.licenses')}</div>
          <div className="flex flex-wrap gap-2 mt-1">
            {(lics.data?.licenses ?? []).map(l => <label key={l.id} className="flex items-center gap-1 text-xs"><input type="checkbox" checked={f.license_ids.includes(l.id)} onChange={() => setF({ ...f, license_ids: f.license_ids.includes(l.id) ? f.license_ids.filter(x => x !== l.id) : [...f.license_ids, l.id] })} /> {l.product}</label>)}
          </div>
        </div>
      </div>
      <label className="block text-xs text-slate-500">{t('proc.cf.notes')}<textarea value={f.notes} rows={2} maxLength={2000} onChange={e => setF({ ...f, notes: e.target.value })} className={inp} /></label>
      <div className="flex items-center gap-3">
        <button disabled={!f.title.trim() || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50">{t('common.save')}</button>
        <button onClick={onDone} className="px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white">{t('proc.cancel')}</button>
        {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
      </div>
    </div>
  )
}

function Contracts({ rows, vendors }: { rows: ContractRow[]; vendors: VendorRow[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [open, setOpen] = useState<number | null>(null)
  const [edit, setEdit] = useState<{ id: number | null; init: CForm } | null>(null)
  const del = useMutation({ mutationFn: (id: number) => procurementApi.removeContract(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['procurement'] }) })
  return (
    <div className="space-y-3">
      <button onClick={() => setEdit({ id: null, init: CEMPTY })} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50"><Plus size={14} /> {t('proc.addContract')}</button>
      {edit && <ContractForm key={edit.id ?? 'new'} init={edit.init} id={edit.id} vendors={vendors} onDone={() => setEdit(null)} />}
      {rows.length === 0 ? <p className="text-sm text-slate-500">{t('proc.noContracts')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          {rows.map(c => (
            <Fragment key={c.id}>
              <div className="flex items-center gap-3 px-4 py-2 border-t border-slate-100 first:border-t-0 cursor-pointer hover:bg-slate-50" onClick={() => setOpen(open === c.id ? null : c.id)}>
                {open === c.id ? <ChevronDown size={14} className="text-slate-400" /> : <ChevronRight size={14} className="text-slate-400" />}
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-slate-900 truncate">{c.title}{c.number ? <span className="text-slate-400 font-normal"> · {c.number}</span> : null}</div>
                  <div className="text-[11px] text-slate-500">{[t(`proc.ckind.${c.kind}`), c.vendor, c.start_at && c.end_at ? `${c.start_at} → ${c.end_at}` : c.end_at ? `→ ${c.end_at}` : null, money(c.value, c.currency) || null, c.auto_renew ? t('proc.autoRenew') : null].filter(Boolean).join(' · ')}</div>
                </div>
                <span className="text-xs text-slate-500 w-24 text-right">{c.days_left != null ? (c.days_left < 0 ? t('proc.endedAgo', { n: -c.days_left }) : t('proc.daysLeft', { n: c.days_left })) : ''}</span>
                <Pill s={t(`proc.cstatus.${c.status}`)} tone={CSTATUS[c.status]} />
                <span className="flex gap-2" onClick={e => e.stopPropagation()}>
                  <button title={t('proc.edit') as string} onClick={() => setEdit({ id: c.id, init: { title: c.title, kind: c.kind, number: c.number ?? '', vendor_id: c.vendor_id ? String(c.vendor_id) : '', start_at: c.start_at ?? '', end_at: c.end_at ?? '', notice_days: c.notice_days == null ? '' : String(c.notice_days), value: c.value == null ? '' : String(c.value), currency: c.currency ?? '', auto_renew: c.auto_renew, owner: c.owner ?? '', notes: c.notes ?? '', asset_ids: c.assets.map(a => a.id), license_ids: c.licenses.map(l => l.id) } })} className="text-slate-400 hover:text-indigo-600"><Pencil size={14} /></button>
                  <button title={t('proc.remove') as string} onClick={() => { if (window.confirm(`${t('proc.remove')}: ${c.title}?`)) del.mutate(c.id) }} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>
                </span>
              </div>
              {open === c.id && (
                <div className="px-4 py-3 bg-slate-50 text-xs grid md:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    {c.owner && <div>{t('proc.cf.owner')}: <b>{c.owner}</b></div>}
                    <div>{t('proc.noticeDays', { n: c.notice_days ?? 30 })}</div>
                    {c.assets.length > 0 && <div>{t('proc.cf.assets')}: {c.assets.map((a, i) => <Fragment key={a.id}>{i ? ', ' : ''}<Link to={`/inventory/${a.id}`} className="text-indigo-600 hover:underline">{a.name}</Link></Fragment>)}</div>}
                    {c.licenses.length > 0 && <div>{t('proc.cf.licenses')}: {c.licenses.map(l => l.name).join(', ')}</div>}
                    {c.notes && <div className="whitespace-pre-wrap text-slate-600">{c.notes}</div>}
                  </div>
                  <Attachments kind="contract" id={c.id} />
                </div>
              )}
            </Fragment>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Orders ───────────────────────────────────────────────────────────────────

type Item = { description: string; kind: string; qty: string; unit_price: string; asset_type: string; model: string; license_id: string }
const IEMPTY: Item = { description: '', kind: 'asset', qty: '1', unit_price: '', asset_type: 'other', model: '', license_id: '' }

function OrderForm({ id, init, vendors, onDone }: { id: number | null; init: { number: string; vendor_id: string; currency: string; notes: string; items: Item[] }; vendors: VendorRow[]; onDone: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [f, setF] = useState(init)
  const lics = useQuery({ queryKey: ['licenses'], queryFn: licensesApi.overview, staleTime: 60000 })
  const total = f.items.reduce((n, i) => n + (Number(i.unit_price.replace(',', '.')) || 0) * (Number(i.qty) || 0), 0)
  const save = useMutation({
    mutationFn: () => {
      const b = { number: f.number, vendor_id: f.vendor_id ? Number(f.vendor_id) : null, currency: f.currency, notes: f.notes,
        items: f.items.map(i => ({ description: i.description, kind: i.kind, qty: Number(i.qty) || 1, unit_price: i.unit_price || null, asset_type: i.asset_type, model: i.model, license_id: i.license_id ? Number(i.license_id) : null })) }
      return id ? procurementApi.updateOrder(id, b) : procurementApi.createOrder(b)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['procurement'] }); onDone() },
  })
  const setItem = (n: number, p: Partial<Item>) => setF({ ...f, items: f.items.map((x, i) => (i === n ? { ...x, ...p } : x)) })
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <div className="grid sm:grid-cols-3 gap-3">
        <label className="block text-xs text-slate-500">{t('proc.of.number')}<input value={f.number} maxLength={60} onChange={e => setF({ ...f, number: e.target.value })} className={inp} /></label>
        <label className="block text-xs text-slate-500">{t('proc.cf.vendor')}<select value={f.vendor_id} onChange={e => setF({ ...f, vendor_id: e.target.value })} className={inp}><option value="">—</option>{vendors.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
        <label className="block text-xs text-slate-500">{t('proc.cf.currency')}<input value={f.currency} maxLength={3} onChange={e => setF({ ...f, currency: e.target.value })} className={inp} /></label>
      </div>
      <div className="space-y-2">
        {f.items.map((it, n) => (
          <div key={n} className="flex flex-wrap gap-2 items-end bg-white border border-slate-200 rounded-lg p-2">
            <label className="block text-xs text-slate-500 flex-1 min-w-[12rem]">{t('proc.of.description')}<input value={it.description} maxLength={200} onChange={e => setItem(n, { description: e.target.value })} className={inp} /></label>
            <label className="block text-xs text-slate-500">{t('proc.of.kind')}<select value={it.kind} onChange={e => setItem(n, { kind: e.target.value })} className={inp}>{ITEM_KINDS.map(k => <option key={k} value={k}>{t(`proc.ikind.${k}`)}</option>)}</select></label>
            {it.kind === 'asset' && <label className="block text-xs text-slate-500">{t('proc.of.assetType')}<select value={it.asset_type} onChange={e => setItem(n, { asset_type: e.target.value })} className={inp}>{ASSET_TYPES.map(k => <option key={k} value={k}>{t(`assets.type.${k}`)}</option>)}</select></label>}
            {it.kind === 'asset' && <label className="block text-xs text-slate-500 w-32">{t('proc.of.model')}<input value={it.model} maxLength={80} onChange={e => setItem(n, { model: e.target.value })} className={inp} /></label>}
            {it.kind === 'license' && <label className="block text-xs text-slate-500">{t('proc.of.license')}<select value={it.license_id} onChange={e => setItem(n, { license_id: e.target.value })} className={inp}><option value="">—</option>{(lics.data?.licenses ?? []).map(l => <option key={l.id} value={l.id}>{l.product}</option>)}</select></label>}
            <label className="block text-xs text-slate-500 w-20">{t('proc.of.qty')}<input type="number" min={1} value={it.qty} onChange={e => setItem(n, { qty: e.target.value })} className={inp} /></label>
            <label className="block text-xs text-slate-500 w-28">{t('proc.of.unitPrice')}<input inputMode="decimal" value={it.unit_price} onChange={e => setItem(n, { unit_price: e.target.value })} className={inp} /></label>
            <button onClick={() => setF({ ...f, items: f.items.filter((_, i) => i !== n) })} className="text-slate-400 hover:text-red-600 pb-2"><Trash2 size={14} /></button>
          </div>
        ))}
        <button onClick={() => setF({ ...f, items: [...f.items, { ...IEMPTY }] })} className="flex items-center gap-1 text-xs text-indigo-600 hover:underline"><Plus size={12} /> {t('proc.of.addItem')}</button>
      </div>
      <div className="text-xs text-slate-600">{t('proc.of.total')}: <b>{money(Math.round(total * 100) / 100, f.currency)}</b></div>
      <label className="block text-xs text-slate-500">{t('proc.cf.notes')}<textarea value={f.notes} rows={2} maxLength={2000} onChange={e => setF({ ...f, notes: e.target.value })} className={inp} /></label>
      <div className="flex items-center gap-3">
        <button disabled={!f.number.trim() || f.items.length === 0 || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50">{t('common.save')}</button>
        <button onClick={onDone} className="px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white">{t('proc.cancel')}</button>
        {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
      </div>
    </div>
  )
}

function Orders({ rows, vendors }: { rows: OrderRow[]; vendors: VendorRow[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [open, setOpen] = useState<number | null>(null)
  const [edit, setEdit] = useState<{ id: number | null; init: { number: string; vendor_id: string; currency: string; notes: string; items: Item[] } } | null>(null)
  const [made, setMade] = useState<string | null>(null)
  const move = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) => procurementApi.orderStatus(id, status),
    onSuccess: r => { qc.invalidateQueries({ queryKey: ['procurement'] }); qc.invalidateQueries({ queryKey: ['assets'] }); qc.invalidateQueries({ queryKey: ['licenses'] })
      if (r.assets.length || r.licenses.length) setMade(t('proc.received', { assets: r.assets.length, seats: r.licenses.reduce((n, l) => n + l.added, 0) }) as string) },
  })
  const del = useMutation({ mutationFn: (id: number) => procurementApi.removeOrder(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['procurement'] }) })
  return (
    <div className="space-y-3">
      <button onClick={() => setEdit({ id: null, init: { number: '', vendor_id: '', currency: '', notes: '', items: [{ ...IEMPTY }] } })} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50"><Plus size={14} /> {t('proc.addOrder')}</button>
      {edit && <OrderForm key={edit.id ?? 'new'} id={edit.id} init={edit.init} vendors={vendors} onDone={() => setEdit(null)} />}
      {made && <p className="text-xs text-green-700">{made}</p>}
      {move.isError && <p className="text-xs text-red-700">{errText(move.error)}</p>}
      {rows.length === 0 ? <p className="text-sm text-slate-500">{t('proc.noOrders')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          {rows.map(o => (
            <Fragment key={o.id}>
              <div className="flex items-center gap-3 px-4 py-2 border-t border-slate-100 first:border-t-0 cursor-pointer hover:bg-slate-50" onClick={() => setOpen(open === o.id ? null : o.id)}>
                {open === o.id ? <ChevronDown size={14} className="text-slate-400" /> : <ChevronRight size={14} className="text-slate-400" />}
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-slate-900 truncate">{o.number}{o.vendor ? <span className="text-slate-500 font-normal"> · {o.vendor}</span> : null}</div>
                  <div className="text-[11px] text-slate-500">{t('proc.itemsCount', { n: o.items.length })} · {money(o.total, o.currency)} · {new Date(o.created_at).toLocaleDateString()}{o.created_by ? ` · ${o.created_by}` : ''}</div>
                </div>
                <Pill s={t(`proc.ostatus.${o.status}`)} tone={OSTATUS[o.status]} />
                <span className="flex gap-1.5" onClick={e => e.stopPropagation()}>
                  {o.next.map(s => (
                    <button key={s} disabled={move.isPending} onClick={() => { if (s !== 'received' || window.confirm(t('proc.receiveConfirm') as string)) move.mutate({ id: o.id, status: s }) }}
                      className={cn('text-xs border rounded-lg px-2 py-0.5', s === 'cancelled' ? 'border-slate-300 text-slate-500' : 'border-indigo-300 text-indigo-700 bg-indigo-50 hover:bg-indigo-100')}>{t(`proc.to.${s}`)}</button>
                  ))}
                  {(o.status === 'draft' || o.status === 'approved') && <button title={t('proc.edit') as string} onClick={() => setEdit({ id: o.id, init: { number: o.number, vendor_id: o.vendor_id ? String(o.vendor_id) : '', currency: o.currency ?? '', notes: o.notes ?? '', items: o.items.map(i => ({ description: i.description, kind: i.kind, qty: String(i.qty), unit_price: i.unit_price == null ? '' : String(i.unit_price), asset_type: i.asset_type ?? 'other', model: i.model ?? '', license_id: i.license_id ? String(i.license_id) : '' })) } })} className="text-slate-400 hover:text-indigo-600"><Pencil size={14} /></button>}
                  {(o.status === 'draft' || o.status === 'cancelled') && <button title={t('proc.remove') as string} onClick={() => { if (window.confirm(`${t('proc.remove')}: ${o.number}?`)) del.mutate(o.id) }} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>}
                </span>
              </div>
              {open === o.id && (
                <div className="px-4 py-3 bg-slate-50 text-xs grid md:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <table className="w-full"><tbody>
                      {o.items.map((i, n) => <tr key={n} className="border-b border-slate-200"><td className="py-0.5">{i.description}</td><td className="text-slate-500">{t(`proc.ikind.${i.kind}`)}{i.license ? ` · ${i.license}` : ''}</td><td className="text-right tabular-nums">{i.qty} × {i.unit_price ?? '—'}</td></tr>)}
                    </tbody></table>
                    {o.notes && <div className="whitespace-pre-wrap text-slate-600">{o.notes}</div>}
                    <div className="text-slate-500">{o.history.map((h, n) => <div key={n}>{new Date(h.at).toLocaleString()} · {h.who}: {t(`proc.ostatus.${h.from}`)} → {t(`proc.ostatus.${h.to}`)}</div>)}</div>
                  </div>
                  <Attachments kind="po" id={o.id} />
                </div>
              )}
            </Fragment>
          ))}
        </div>
      )}
      <p className="text-xs text-slate-400">{t('proc.ordersNote')}</p>
    </div>
  )
}

// ── Vendors ──────────────────────────────────────────────────────────────────

function Vendors({ rows }: { rows: VendorRow[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const empty = { name: '', contact: '', email: '', phone: '', website: '', notes: '' }
  const [f, setF] = useState<typeof empty & { id?: number }>(empty)
  const save = useMutation({ mutationFn: () => (f.id ? procurementApi.updateVendor(f.id, f) : procurementApi.createVendor(f)), onSuccess: () => { qc.invalidateQueries({ queryKey: ['procurement'] }); setF(empty) } })
  const del = useMutation({ mutationFn: (id: number) => procurementApi.removeVendor(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['procurement'] }) })
  return (
    <div className="space-y-3">
      <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 grid sm:grid-cols-3 lg:grid-cols-6 gap-3 items-end text-sm">
        {(['name', 'contact', 'email', 'phone', 'website', 'notes'] as const).map(k => (
          <label key={k} className="block text-xs text-slate-500">{t(`proc.vf.${k}`)}<input value={f[k]} onChange={e => setF({ ...f, [k]: e.target.value })} className={inp} /></label>
        ))}
        <div className="flex gap-2 items-center">
          <button disabled={!f.name.trim() || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50">{f.id ? t('common.save') : t('proc.addVendor')}</button>
          {f.id && <button onClick={() => setF(empty)} className="text-xs text-slate-500">{t('proc.cancel')}</button>}
        </div>
        {(save.isError || del.isError) && <span className="text-xs text-red-700 col-span-full">{errText(save.error ?? del.error)}</span>}
      </div>
      {rows.length === 0 ? <p className="text-sm text-slate-500">{t('proc.noVendors')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
          {rows.map(v => (
            <div key={v.id} className="flex items-center gap-3 px-4 py-2">
              <span className="font-medium text-slate-900 w-48 truncate">{v.name}</span>
              <span className="text-xs text-slate-500 flex-1 truncate">{[v.contact, v.email, v.phone, v.website].filter(Boolean).join(' · ')}</span>
              <span className="text-xs text-slate-400">{t('proc.vendorCounts', { c: v.contracts, o: v.orders })}</span>
              <button onClick={() => setF({ id: v.id, name: v.name, contact: v.contact ?? '', email: v.email ?? '', phone: v.phone ?? '', website: v.website ?? '', notes: v.notes ?? '' })} className="text-slate-400 hover:text-indigo-600"><Pencil size={14} /></button>
              <button onClick={() => { if (window.confirm(`${t('proc.remove')}: ${v.name}?`)) del.mutate(v.id) }} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Vendors, contracts and purchase orders (services/procurement.py, docs/plan-itam.md stage D).
export function Procurement() {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as 'contracts' | 'orders' | 'vendors') || 'contracts'
  const c = useQuery({ queryKey: ['procurement', 'contracts'], queryFn: procurementApi.contracts })
  const o = useQuery({ queryKey: ['procurement', 'orders'], queryFn: procurementApi.orders })
  const v = useQuery({ queryKey: ['procurement', 'vendors'], queryFn: procurementApi.vendors })
  const vendors = v.data?.vendors ?? []
  const expiring = (c.data?.contracts ?? []).filter(x => x.status === 'expiring' || x.status === 'expired').length
  const open = (o.data?.orders ?? []).filter(x => ['draft', 'approved', 'ordered'].includes(x.status)).length
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><FileSignature size={20} className="text-indigo-600" /> {t('proc.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('proc.subtitle')}</p>
      </div>
      <div className="flex gap-1 border-b border-slate-200">
        {(['contracts', 'orders', 'vendors'] as const).map(k => (
          <button key={k} onClick={() => setParams({ tab: k })} className={cn('px-4 py-2 text-sm -mb-px border-b-2', tab === k ? 'border-indigo-600 text-indigo-700 font-medium' : 'border-transparent text-slate-600 hover:text-slate-900')}>
            {t(`proc.tab.${k}`)}{k === 'contracts' && expiring ? <span className="ml-1.5 text-[11px] bg-amber-100 text-amber-800 rounded-full px-1.5">{expiring}</span> : null}
            {k === 'orders' && open ? <span className="ml-1.5 text-[11px] bg-slate-100 text-slate-600 rounded-full px-1.5">{open}</span> : null}
          </button>
        ))}
      </div>
      {tab === 'contracts' && <Contracts rows={c.data?.contracts ?? []} vendors={vendors} />}
      {tab === 'orders' && <Orders rows={o.data?.orders ?? []} vendors={vendors} />}
      {tab === 'vendors' && <Vendors rows={vendors} />}
    </div>
  )
}

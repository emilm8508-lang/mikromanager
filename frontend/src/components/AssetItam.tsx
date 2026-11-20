import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Save } from 'lucide-react'
import { assetsApi, AssetItam, ItamStage, licensesApi, procurementApi } from '../lib/api'
import { Attachments } from './Attachments'
import { Link } from 'react-router-dom'
import { Button } from './ui/Button'
import { cn } from '../lib/utils'

export const STAGES: ItamStage[] = ['ordered', 'in_stock', 'deployed', 'in_repair', 'retired', 'disposed']
const DISPOSAL = ['recycled', 'sold', 'donated', 'returned', 'destroyed', 'lost', 'other'] as const

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const STAGE_TONE: Record<ItamStage, string> = {
  ordered: 'bg-sky-50 text-sky-700 border-sky-200', in_stock: 'bg-indigo-50 text-indigo-700 border-indigo-200', deployed: 'bg-green-50 text-green-700 border-green-200',
  in_repair: 'bg-amber-50 text-amber-700 border-amber-200', retired: 'bg-slate-100 text-slate-600 border-slate-200', disposed: 'bg-slate-200 text-slate-500 border-slate-300',
}

export function StagePill({ stage }: { stage: ItamStage }) {
  const { t } = useTranslation()
  return <span className={cn('inline-block text-xs border rounded-full px-2 py-0.5', STAGE_TONE[stage])}>{t(`itam.stage.${stage}`)}</span>
}

export function WarrantyText({ days, until }: { days: number | null; until: string | null }) {
  const { t } = useTranslation()
  if (!until) return <span className="text-slate-300">—</span>
  return <span className={cn(days != null && days < 0 ? 'text-slate-500' : days != null && days <= 30 ? 'text-amber-700 font-medium' : 'text-slate-700')}>
    {new Date(until).toLocaleDateString()}{days != null ? ` (${days < 0 ? t('itam.ended') : t('itam.daysLeft', { n: days })})` : ''}
  </span>
}

// The hardware life of an asset and what it cost (services/asset_itam.py, docs/plan-itam.md stage A): every field is entered by people.
export function AssetItamTab({ id, itam }: { id: number; itam: AssetItam }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const init = (x: AssetItam) => ({ ...x, lifecycle_stage: x.stage_set ? x.lifecycle_stage : '', cost: x.cost == null ? '' : String(x.cost) })
  const [d, setD] = useState(init(itam))
  useEffect(() => setD(init(itam)), [itam])
  const hist = useQuery({ queryKey: ['asset-itam-history', id], queryFn: () => assetsApi.itamHistory(id) })
  const lic = useQuery({ queryKey: ['asset-licenses', id], queryFn: () => licensesApi.forAsset(id) })
  const con = useQuery({ queryKey: ['procurement', 'asset', id], queryFn: () => procurementApi.contractsFor(id) })
  const save = useMutation({
    mutationFn: () => assetsApi.update(id, { itam: {
      lifecycle_stage: d.lifecycle_stage || null, purchased_at: d.purchased_at || null, warranty_until: d.warranty_until || null, replace_at: d.replace_at || null,
      disposed_at: d.disposed_at || null, disposal_method: d.disposal_method || null, cost: d.cost === '' ? null : d.cost, currency: d.currency || null,
      supplier: d.supplier || null, invoice_no: d.invoice_no || null, cost_center: d.cost_center || null, asset_tag: d.asset_tag || null } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['asset', id] }); qc.invalidateQueries({ queryKey: ['assets'] }); qc.invalidateQueries({ queryKey: ['asset-itam-history', id] }) },
  })
  const inp = 'mt-0.5 block w-full border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white text-slate-900'
  const text = (k: 'supplier' | 'invoice_no' | 'cost_center' | 'asset_tag' | 'currency', max: number) => (
    <label className="block text-xs text-slate-500">{t(`itam.f.${k}`)}<input value={d[k] ?? ''} maxLength={max} onChange={e => setD({ ...d, [k]: e.target.value })} className={inp} /></label>
  )
  const dateIn = (k: 'purchased_at' | 'warranty_until' | 'replace_at' | 'disposed_at') => (
    <label className="block text-xs text-slate-500">{t(`itam.f.${k}`)}<input type="date" value={d[k] ?? ''} onChange={e => setD({ ...d, [k]: e.target.value || null })} className={inp} /></label>
  )
  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
        <div className="flex items-center gap-3 flex-wrap">
          <h3 className="font-semibold text-slate-900">{t('itam.title')}</h3>
          <StagePill stage={itam.lifecycle_stage} />
          {itam.age_years != null && <span className="text-xs text-slate-500">{t('itam.age', { n: itam.age_years })}</span>}
        </div>
        <div className="flex flex-wrap gap-1">
          {STAGES.map(s => (
            <button key={s} onClick={() => setD({ ...d, lifecycle_stage: s })}
              className={cn('text-xs border rounded-full px-2.5 py-1', (d.lifecycle_stage || itam.lifecycle_stage) === s ? STAGE_TONE[s] + ' ring-1 ring-offset-1 ring-indigo-400' : 'bg-white border-slate-200 text-slate-500 hover:bg-slate-50')}>
              {t(`itam.stage.${s}`)}
            </button>
          ))}
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {text('asset_tag', 40)}
          {dateIn('purchased_at')}
          {dateIn('warranty_until')}
          {dateIn('replace_at')}
          <label className="block text-xs text-slate-500">{t('itam.f.cost')}<input inputMode="decimal" value={d.cost} onChange={e => setD({ ...d, cost: e.target.value })} className={inp} /></label>
          {text('currency', 3)}
          {text('supplier', 120)}
          {text('invoice_no', 60)}
          {text('cost_center', 60)}
        </div>
        {(d.lifecycle_stage === 'disposed') && (
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-slate-50 border border-slate-200 rounded-lg p-3">
            {dateIn('disposed_at')}
            <label className="block text-xs text-slate-500">{t('itam.f.disposal_method')}
              <select value={d.disposal_method ?? ''} onChange={e => setD({ ...d, disposal_method: e.target.value || null })} className={inp}>
                <option value="">—</option>{DISPOSAL.map(k => <option key={k} value={k}>{t(`itam.disposal.${k}`)}</option>)}
              </select></label>
          </div>
        )}
        <div className="flex items-center gap-3">
          <Button size="sm" variant="primary" disabled={save.isPending} onClick={() => save.mutate()}><Save size={12} /> {t('common.save')}</Button>
          {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
          {save.isSuccess && <span className="text-xs text-green-700">{t('itam.saved')}</span>}
          <a href={`/labels?ids=${id}&size=single`} target="_blank" rel="noreferrer" className="ml-auto text-xs text-indigo-600 hover:underline">{t('lbl.printOne')}</a>
        </div>
        <p className="text-[11px] text-slate-400">{t('itam.note')}</p>
      </div>
      <div className="bg-white border border-slate-200 rounded-xl p-4 text-sm grid md:grid-cols-2 gap-4">
        <div>
          <h3 className="font-semibold text-slate-900 mb-2">{t('proc.onAsset')}</h3>
          {(con.data?.contracts.length ?? 0) === 0 ? <p className="text-xs text-slate-500">{t('proc.noneOnAsset')} <Link to="/procurement" className="text-indigo-600 hover:underline">{t('proc.title')}</Link></p> : (
            <div className="space-y-0.5 text-xs">
              {con.data!.contracts.map(c => (
                <div key={c.id} className="flex gap-3">
                  <Link to="/procurement" className="text-indigo-600 hover:underline flex-1 truncate">{c.title}</Link>
                  <span className="text-slate-500">{c.end_at ?? ''}</span>
                  <span className={cn(c.status === 'expiring' || c.status === 'expired' ? 'text-amber-700' : 'text-slate-500')}>{t(`proc.cstatus.${c.status}`)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <Attachments kind="asset" id={id} />
      </div>
      {(lic.data?.licenses.length ?? 0) > 0 && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 text-sm">
          <h3 className="font-semibold text-slate-900 mb-2">{t('lic.onAsset')}</h3>
          <div className="space-y-0.5 text-xs">
            {lic.data!.licenses.map(l => (
              <div key={l.id} className="flex gap-3">
                <Link to="/licenses" className="text-indigo-600 hover:underline w-56 truncate">{l.product}</Link>
                <span className="text-slate-600 flex-1 truncate">{l.program} {l.version}</span>
                <span className="text-slate-500">{t(`lic.status.${l.status}`)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {(hist.data?.length ?? 0) > 0 && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 text-sm">
          <h3 className="font-semibold text-slate-900 mb-2">{t('itam.history')}</h3>
          <div className="space-y-0.5 text-xs">
            {hist.data!.map((h, i) => (
              <div key={i} className="flex gap-3">
                <span className="text-slate-400 w-36 shrink-0">{new Date(h.at).toLocaleString()}</span>
                <span className="text-slate-700 w-32 shrink-0">{t(`itam.f.${h.field}`, { defaultValue: h.field })}</span>
                <span className="text-slate-500">{h.field === 'lifecycle_stage' ? `${h.old ? t(`itam.stage.${h.old}`) : '—'} → ${h.new ? t(`itam.stage.${h.new}`) : '—'}` : `${h.old ?? '—'} → ${h.new ?? '—'}`}</span>
                <span className="text-slate-400 ml-auto">{h.source.replace(/^itam: /, '')}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

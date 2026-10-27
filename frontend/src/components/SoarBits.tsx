import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ShieldBan } from 'lucide-react'
import { soarApi, type SocAlert } from '../lib/api'

export const TTL_CHOICES = [60, 360, 1440, 4320, 10080]

export function ttlLabel(min: number): string {
  if (min >= 1440) return `${Math.round(min / 1440)} d`
  if (min >= 60) return `${Math.round(min / 60)} h`
  return `${min} min`
}

/** Under an alert (agent): propose blocking one of the addresses it is about on the routers. Nothing happens until someone approves the proposal on the "Reakcje" page. */
export function BlockBox({ alert }: { alert: SocAlert }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const ov = useQuery({ queryKey: ['soar'], queryFn: soarApi.overview })
  const cand = useQuery({ queryKey: ['soar-candidates', alert.id, alert.last_seen], queryFn: () => soarApi.candidates(alert.id), enabled: !!ov.data?.settings.enabled })
  const [open, setOpen] = useState(false)
  const [target, setTarget] = useState('')
  const [ids, setIds] = useState<number[]>([])
  const [ttl, setTtl] = useState(1440)
  const [reason, setReason] = useState('')
  const [done, setDone] = useState(false)
  const m = useMutation({
    mutationFn: () => soarApi.propose({ kind: 'block_ip', target: target || cand.data?.[0], device_ids: ids, ttl_min: ttl, alert_id: alert.id, reason: reason || (alert.title ?? alert.rule) }),
    onSuccess: () => { setDone(true); setOpen(false); void qc.invalidateQueries({ queryKey: ['soar'] }) },
  })
  if (!ov.data?.settings.enabled || !cand.data || cand.data.length === 0) return null
  const routers = ov.data.routers
  const chosen = target || cand.data[0]
  return (
    <div className="border border-slate-200 rounded-lg bg-white p-3 space-y-2">
      <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide inline-flex items-center gap-1.5"><ShieldBan size={13} /> {t('soar.alert.title')}</div>
      {done && <p className="text-xs text-green-700">{t('soar.alert.proposed')} <Link to="/soc/response" className="text-indigo-600 hover:underline">{t('soar.alert.open')}</Link></p>}
      {!open ? (
        <button className="text-xs text-indigo-600 hover:underline" onClick={() => { setOpen(true); setDone(false); setIds(routers.map(r => r.id)) }}>{t('soar.alert.block', { ip: cand.data[0] })}…</button>
      ) : (
        <div className="space-y-2 text-xs">
          <div className="flex flex-wrap gap-2 items-center">
            <select value={chosen} onChange={e => setTarget(e.target.value)} className="border border-slate-300 rounded-md px-1.5 py-1 bg-white">
              {cand.data.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
            <select value={ttl} onChange={e => setTtl(Number(e.target.value))} className="border border-slate-300 rounded-md px-1.5 py-1 bg-white">
              {TTL_CHOICES.map(v => <option key={v} value={v}>{t('soar.for', { time: ttlLabel(v) })}</option>)}
            </select>
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-1">
            {routers.map(r => (
              <label key={r.id} className="inline-flex items-center gap-1.5">
                <input type="checkbox" checked={ids.includes(r.id)} onChange={() => setIds(ids.includes(r.id) ? ids.filter(x => x !== r.id) : [...ids, r.id])} /> {r.name}
              </label>
            ))}
          </div>
          <input value={reason} onChange={e => setReason(e.target.value)} placeholder={(alert.title ?? alert.rule) + ' — ' + t('soar.reason')} className="border border-slate-300 rounded-md px-2 py-1 bg-white w-full" />
          {m.isError && <p className="text-red-600">{((m.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail) ?? (m.error as Error).message}</p>}
          <div className="flex gap-3">
            <button className="px-3 py-1 rounded-md bg-indigo-600 text-white disabled:opacity-40" disabled={ids.length === 0 || m.isPending} onClick={() => m.mutate()}>{t('soar.propose')}</button>
            <button className="text-slate-500 hover:underline" onClick={() => setOpen(false)}>{t('common.cancel')}</button>
          </div>
        </div>
      )}
    </div>
  )
}

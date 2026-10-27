import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ShieldBan } from 'lucide-react'
import { soarApi, type SoarAction } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { TTL_CHOICES, ttlLabel } from '../components/SoarBits'
import { cn } from '../lib/utils'

const errText = (e: unknown) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? ''
const STATUS_STYLE: Record<string, string> = {
  executed: 'bg-green-50 text-green-700 border-green-200', failed: 'bg-red-50 text-red-700 border-red-200', rejected: 'bg-slate-50 text-slate-500 border-slate-200',
  expired: 'bg-slate-50 text-slate-500 border-slate-200', lifted: 'bg-sky-50 text-sky-700 border-sky-200', pending: 'bg-amber-50 text-amber-800 border-amber-200', approved: 'bg-blue-50 text-blue-700 border-blue-200',
}

function ActionLine({ a }: { a: SoarAction }) {
  const { t } = useTranslation()
  return (
    <span>
      <b className="font-medium">{a.kind === 'block_ip' ? t('soar.kind.block', { ip: a.target }) : t('soar.kind.rule')}</b>
      {a.kind === 'block_ip' && <span className="text-slate-500"> · {t('soar.for', { time: ttlLabel(a.ttl_min) })}</span>}
      <span className="text-slate-500"> · {a.devices.map(d => d.name).join(', ')}</span>
    </span>
  )
}

// Response actions with approval: block an address on the routers (a timeout list), nothing runs before a person approves the proposal.
export function SocResponse() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['soar'], queryFn: soarApi.overview, refetchInterval: 15000 })
  const d = q.data
  const refresh = () => void qc.invalidateQueries({ queryKey: ['soar'] })
  const settings = useMutation({ mutationFn: soarApi.settings, onSuccess: refresh })
  const decide = useMutation({ mutationFn: (v: { id: number; approve: boolean }) => soarApi.decide(v.id, v.approve), onSuccess: refresh })
  const unblock = useMutation({ mutationFn: (ip: string) => soarApi.unblock(ip), onSuccess: refresh })

  const [kind, setKind] = useState<'block_ip' | 'install_rule'>('block_ip')
  const [target, setTarget] = useState('')
  const [ids, setIds] = useState<number[]>([])
  const [ttl, setTtl] = useState(1440)
  const [reason, setReason] = useState('')
  const [internal, setInternal] = useState(false)
  const propose = useMutation({
    mutationFn: () => soarApi.propose({ kind, target: kind === 'block_ip' ? target.trim() : undefined, device_ids: ids, ttl_min: ttl, reason, allow_internal: internal }),
    onSuccess: () => { setTarget(''); setReason(''); setInternal(false); refresh() },
  })
  const enabled = !!d?.settings.enabled
  const err = settings.error ?? decide.error ?? unblock.error

  return (
    <div className="p-6 space-y-5 max-w-[1100px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><ShieldBan size={20} className="text-indigo-600" /> {t('soar.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('soar.subtitle')}</p>
      </div>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{errText(err)}</div>}
      {d && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" checked={d.settings.enabled} onChange={e => settings.mutate({ enabled: e.target.checked })} /> <b className="font-medium">{t('soar.enable')}</b></label>
          <label className={cn('flex items-center gap-2', !enabled && 'opacity-40')}>
            <input type="checkbox" disabled={!enabled} checked={d.settings.central_approval} onChange={e => settings.mutate({ central_approval: e.target.checked })} /> {t('soar.centralApproval')}
          </label>
          <p className="text-xs text-slate-500">{t('soar.guard')}</p>
        </div>
      )}

      {enabled && d && (
        <>
          <section className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('soar.pending')}</h2>
            {d.pending.length === 0 ? <p className="text-sm text-slate-400">{t('soar.nonePending')}</p> : (
              <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
                {d.pending.map(a => (
                  <div key={a.id} className="px-4 py-3 flex flex-wrap items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <ActionLine a={a} />
                      {a.internal && <span className="ml-2 text-xs bg-amber-50 text-amber-800 border border-amber-200 rounded px-1.5">{t('soar.internal')}</span>}
                      <div className="text-xs text-slate-500 truncate" title={a.reason}>{a.reason} · {a.proposed_by} · {ago(a.proposed_at)}
                        {a.alert_id && <> · <Link to="/soc" className="text-indigo-600 hover:underline">{t('soar.alertRef', { id: a.alert_id })}</Link></>}</div>
                    </div>
                    <button className="px-3 py-1 rounded-md bg-red-600 text-white text-xs disabled:opacity-40" disabled={decide.isPending} onClick={() => decide.mutate({ id: a.id, approve: true })}>{t('soar.approve')}</button>
                    <button className="px-3 py-1 rounded-md border border-slate-300 text-xs" disabled={decide.isPending} onClick={() => decide.mutate({ id: a.id, approve: false })}>{t('soar.reject')}</button>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('soar.active')}</h2>
            {d.active.length === 0 ? <p className="text-sm text-slate-400">{t('soar.noneActive')}</p> : (
              <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
                {d.active.map(a => (
                  <div key={a.id} className="px-4 py-2 flex flex-wrap items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <ActionLine a={a} />
                      <div className="text-xs text-slate-500">{t('soar.until', { when: a.expires_at ? new Date(a.expires_at).toLocaleString() : '—' })} · {a.decided_by}</div>
                      {a.result.some(r => r.ok && r.rule_present === false) && <div className="text-xs text-amber-800">{t('soar.noRule')}</div>}
                    </div>
                    <button className="text-xs text-indigo-600 hover:underline" disabled={unblock.isPending} onClick={() => a.target && unblock.mutate(a.target)}>{t('soar.unblock')}</button>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('soar.new')}</h2>
            <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-sm">
              <div className="flex flex-wrap gap-2 items-center">
                <select value={kind} onChange={e => setKind(e.target.value as 'block_ip' | 'install_rule')} className="border border-slate-300 rounded-md px-2 py-1 bg-white">
                  <option value="block_ip">{t('soar.kind.blockShort')}</option>
                  <option value="install_rule">{t('soar.kind.rule')}</option>
                </select>
                {kind === 'block_ip' && (
                  <>
                    <input value={target} onChange={e => setTarget(e.target.value)} placeholder="203.0.113.9" className="border border-slate-300 rounded-md px-2 py-1 w-40" />
                    <select value={ttl} onChange={e => setTtl(Number(e.target.value))} className="border border-slate-300 rounded-md px-2 py-1 bg-white">
                      {TTL_CHOICES.map(v => <option key={v} value={v}>{t('soar.for', { time: ttlLabel(v) })}</option>)}
                    </select>
                  </>
                )}
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {d.routers.length === 0 && <span className="text-xs text-slate-400">{t('soar.noRouters')}</span>}
                {d.routers.map(r => (
                  <label key={r.id} className="inline-flex items-center gap-1.5"><input type="checkbox" checked={ids.includes(r.id)} onChange={() => setIds(ids.includes(r.id) ? ids.filter(x => x !== r.id) : [...ids, r.id])} /> {r.name} <span className="text-xs text-slate-400">{r.ip}</span></label>
                ))}
              </div>
              <input value={reason} onChange={e => setReason(e.target.value)} placeholder={t('soar.reason') as string} className="border border-slate-300 rounded-md px-2 py-1 w-full" />
              {kind === 'block_ip' && <label className="flex items-center gap-2 text-xs text-slate-600"><input type="checkbox" checked={internal} onChange={e => setInternal(e.target.checked)} /> {t('soar.allowInternal')}</label>}
              {kind === 'install_rule' && <p className="text-xs text-slate-500">{t('soar.ruleNote')}</p>}
              {propose.isError && <p className="text-xs text-red-600">{errText(propose.error)}</p>}
              <button className="px-3 py-1.5 rounded-md bg-indigo-600 text-white text-sm disabled:opacity-40" disabled={propose.isPending || ids.length === 0 || (kind === 'block_ip' && !target.trim())} onClick={() => propose.mutate()}>{t('soar.propose')}</button>
            </div>
          </section>

          <section className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('soar.history')}</h2>
            {d.history.length === 0 ? <p className="text-sm text-slate-400">—</p> : (
              <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
                {d.history.map(a => (
                  <div key={a.id} className="px-4 py-2 grid grid-cols-[6rem_minmax(0,1fr)_9rem] gap-3 items-start">
                    <span className={cn('inline-block text-xs border rounded-full px-2 py-0.5 text-center', STATUS_STYLE[a.status])}>{t(`soar.status.${a.status}`)}</span>
                    <div className="min-w-0">
                      <ActionLine a={a} />
                      <div className="text-xs text-slate-500 truncate" title={a.reason}>{a.reason} · {a.proposed_by}{a.decided_by ? ` → ${a.decided_by}` : ''}</div>
                      {a.result.filter(r => !r.ok).map((r, i) => <div key={i} className="text-xs text-red-700 truncate" title={r.error}>{r.device}: {r.error}</div>)}
                    </div>
                    <span className="text-xs text-slate-400 text-right">{ago(a.executed_at ?? a.decided_at ?? a.proposed_at)}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  )
}

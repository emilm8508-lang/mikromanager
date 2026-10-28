import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Cable, Check, X } from 'lucide-react'
import { onboardingApi, scannerApi, type OnboardingDiagnosis } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { AccountSnippets } from '../components/AccountSnippets'
import { cn } from '../lib/utils'

const errText = (e: unknown) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? ''
const STATE: Record<string, string> = {
  ok: 'bg-green-50 text-green-700 border-green-200', unverified: 'bg-sky-50 text-sky-700 border-sky-200', snmp: 'bg-amber-50 text-amber-800 border-amber-200', no_credential: 'bg-red-50 text-red-700 border-red-200',
}
const LEVEL: Record<string, string> = { full: 'text-green-700', snmp: 'text-amber-700', none: 'text-red-700' }

function Diagnosis({ d }: { d: OnboardingDiagnosis }) {
  const { t } = useTranslation()
  return (
    <div className="px-6 py-3 bg-slate-50 border-t border-slate-100 text-xs space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <b className={cn('text-sm', LEVEL[d.level])}>{t(`onboarding.level.${d.level}`)}</b>
        {Object.entries(d.channels).map(([k, c]) => (
          <span key={k} className="inline-flex items-center gap-1" title={c.ok ? c.detail : c.message}>
            {c.ok ? <Check size={13} className="text-green-600" /> : <X size={13} className="text-red-500" />} <b className="font-medium">{k.toUpperCase()}</b>
            {!c.ok && <span className="text-slate-500">{t(`onboarding.code.${c.code}`)}</span>}
          </span>
        ))}
      </div>
      {d.best_credential && <p className="text-slate-600">{t('onboarding.bestCredential', { name: d.best_credential })}{d.best_credential_id !== d.own_credential_id ? ` — ${t('onboarding.notAssigned')}` : ''}</p>}
      {d.advice.map(a => <p key={a} className="text-slate-700">• {t(`onboarding.advice.${a}`)}</p>)}
    </div>
  )
}

// Connecting the devices: what works for each one (live test), why not, and fitting stored credentials to many devices at once.
export function Onboarding() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['onboarding'], queryFn: onboardingApi.overview })
  const d = q.data
  const refresh = () => void qc.invalidateQueries({ queryKey: ['onboarding'] })
  const [sel, setSel] = useState<Set<number>>(new Set())
  const [diag, setDiag] = useState<Record<number, OnboardingDiagnosis>>({})
  const [busy, setBusy] = useState<number | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const test = async (id: number) => {
    setBusy(id); setErr(null)
    try { const r = await onboardingApi.test(id); setDiag(x => ({ ...x, [id]: r })) } catch (e) { setErr(errText(e)) } finally { setBusy(null) }
  }
  const assign = useMutation({ mutationFn: () => onboardingApi.assign([...sel]), onSuccess: () => { refresh(); setSel(new Set()) }, onError: e => setErr(errText(e)) })
  const addRange = useMutation({ mutationFn: (cidr: string) => scannerApi.addRange({ cidr }), onSuccess: refresh, onError: e => setErr(errText(e)) })
  const devices = d?.devices ?? []
  const needy = devices.filter(x => x.state === 'no_credential' || x.state === 'snmp').map(x => x.id)
  const toggle = (id: number) => { const n = new Set(sel); n.has(id) ? n.delete(id) : n.add(id); setSel(n) }
  const counts = (s: string) => devices.filter(x => x.state === s).length
  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Cable size={20} className="text-indigo-600" /> {t('onboarding.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('onboarding.subtitle')}</p>
      </div>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {d && d.suggested_ranges.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-sm space-y-2">
          <p className="text-amber-900">{d.ranges.filter(r => r.active).length === 0 ? t('onboarding.noRanges') : t('onboarding.uncoveredRanges')}</p>
          <div className="flex flex-wrap gap-2">
            {d.suggested_ranges.map(r => (
              <button key={r.cidr} disabled={addRange.isPending} onClick={() => addRange.mutate(r.cidr)} className="px-3 py-1 rounded-md bg-white border border-amber-300 text-amber-900 hover:bg-amber-100 text-xs">
                {t('onboarding.addRange', { cidr: r.cidr, hosts: r.hosts })}
              </button>
            ))}
          </div>
        </div>
      )}
      {d && d.ranges.length > 0 && <p className="text-xs text-slate-500">{t('onboarding.ranges')}: {d.ranges.map(r => `${r.cidr}${r.active ? '' : ` (${t('onboarding.off')})`}`).join(' · ')} · <Link to="/scanner" className="text-indigo-600 hover:underline">{t('onboarding.openScanner')}</Link></p>}

      {d && (
        <div className="flex gap-2 flex-wrap items-center">
          {(['no_credential', 'snmp', 'unverified', 'ok'] as const).map(s => (
            <div key={s} className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[8rem]"><div className="text-xs text-slate-500">{t(`onboarding.state.${s}`)}</div><div className="text-2xl font-bold tabular-nums text-slate-800">{counts(s)}</div></div>
          ))}
          <div className="ml-auto flex gap-2">
            <button className="px-3 py-1.5 rounded-md border border-slate-300 text-sm" onClick={() => setSel(new Set(needy))} disabled={needy.length === 0}>{t('onboarding.selectNeedy', { n: needy.length })}</button>
            <button className="px-3 py-1.5 rounded-md bg-indigo-600 text-white text-sm disabled:opacity-40" disabled={sel.size === 0 || assign.isPending} onClick={() => assign.mutate()}>{assign.isPending ? t('onboarding.assigning') : t('onboarding.assign', { n: sel.size })}</button>
          </div>
        </div>
      )}
      {assign.data && (
        <div className="bg-white border border-slate-200 rounded-xl p-3 text-xs space-y-0.5">
          {assign.data.results.map(r => <div key={r.device_id}><b className="font-medium">{r.name}</b>: {r.assigned ? <span className="text-green-700">{t('onboarding.assignedTo', { name: r.assigned })}</span> : <span className="text-slate-500">{t('onboarding.unchanged')} ({t(`onboarding.level.${r.level}`)})</span>}</div>)}
        </div>
      )}

      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : devices.length === 0 ? <p className="text-sm text-slate-400 py-6 text-center">{t('onboarding.empty')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className="grid grid-cols-[2rem_minmax(0,1.6fr)_7rem_minmax(0,1.2fr)_minmax(0,1.4fr)_6rem] gap-2 px-4 py-2 bg-slate-50 text-xs text-slate-500">
            <div /><div>{t('onboarding.col.device')}</div><div>{t('onboarding.col.vendor')}</div><div>{t('onboarding.col.credential')}</div><div>{t('onboarding.col.state')}</div><div />
          </div>
          {devices.map(x => (
            <div key={x.id} className="border-t border-slate-100">
              <div className="grid grid-cols-[2rem_minmax(0,1.6fr)_7rem_minmax(0,1.2fr)_minmax(0,1.4fr)_6rem] gap-2 px-4 py-2 items-center">
                <input type="checkbox" checked={sel.has(x.id)} onChange={() => toggle(x.id)} />
                <div className="min-w-0"><div className="font-medium text-slate-900 truncate">{x.name}</div><div className="text-[11px] text-slate-400">{x.ip}{x.model ? ` · ${x.model}` : ''}</div></div>
                <div className="text-xs text-slate-600">{x.vendor}</div>
                <div className="text-xs text-slate-600 truncate">{x.credential ?? '—'}</div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className={cn('text-[11px] border rounded-full px-2 py-0.5', STATE[x.state])}>{t(`onboarding.state.${x.state}`)}</span>
                  {!x.online && <span className="text-[11px] text-slate-400">{t('onboarding.offline')}</span>}
                  {x.mgmt_ok === false && x.online && <span className="text-[11px] text-amber-700">{t('onboarding.portsBlocked')}</span>}
                  {x.last_read && <span className="text-[11px] text-slate-400" title={new Date(x.last_read).toLocaleString()}>{ago(x.last_read)}</span>}
                </div>
                <button className="text-xs text-indigo-600 hover:underline disabled:text-slate-300" disabled={busy === x.id} onClick={() => void test(x.id)}>{busy === x.id ? t('onboarding.testing') : t('onboarding.test')}</button>
              </div>
              {diag[x.id] && <Diagnosis d={diag[x.id]} />}
            </div>
          ))}
        </div>
      )}
      {d && <AccountSnippets key={d.agent_ip ?? 'none'} agentIp={d.agent_ip} />}
    </div>
  )
}

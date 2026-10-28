import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LockKeyhole, RefreshCw, Trash2 } from 'lucide-react'
import { tlsApi, type TlsRow } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'

const errText = (e: unknown) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? ''
const SEV: Record<string, string> = {
  high: 'bg-red-50 text-red-700 border-red-200', medium: 'bg-amber-50 text-amber-800 border-amber-200', low: 'bg-sky-50 text-sky-700 border-sky-200', info: 'bg-slate-50 text-slate-600 border-slate-200',
}

function daysText(t: (k: string, o?: Record<string, unknown>) => string, d: number | null): string {
  if (d == null) return '—'
  if (d < 0) return t('tls.expiredAgo', { n: Math.max(1, Math.round(-d)) })
  return t('tls.days', { n: Math.floor(d) })
}

function Row({ r, onRemove }: { r: TlsRow; onRemove: (id: number) => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const worst = r.findings.some(f => f.severity === 'high') ? 'text-red-600' : r.findings.some(f => f.severity === 'medium') ? 'text-amber-600' : 'text-slate-700'
  return (
    <div className="border-t border-slate-100">
      <div className="grid grid-cols-[minmax(0,1.6fr)_4rem_minmax(0,1.6fr)_7rem_minmax(0,2fr)_2rem] gap-2 px-4 py-2 items-center cursor-pointer hover:bg-slate-50" onClick={() => setOpen(!open)}>
        <div className="min-w-0"><div className="font-medium text-slate-900 truncate">{r.name}</div><div className="text-[11px] text-slate-400">{r.ip}</div></div>
        <div className="text-slate-600 tabular-nums">{r.port}</div>
        <div className="min-w-0 text-xs text-slate-600 truncate" title={r.subject ?? ''}>{r.subject ?? (r.error ? <span className="text-slate-400">{t('tls.noTls')}</span> : '—')}</div>
        <div className={cn('text-xs font-semibold tabular-nums', worst)}>{daysText(t, r.days)}</div>
        <div className="flex flex-wrap gap-1">
          {r.findings.map(f => <span key={f.code} title={f.message} className={cn('text-[11px] border rounded-full px-2 py-0.5', SEV[f.severity])}>{t(`tls.finding.${f.code}`)}</span>)}
        </div>
        <div onClick={e => e.stopPropagation()}>{r.manual && <button title={t('tls.remove') as string} className="text-slate-400 hover:text-red-600" onClick={() => onRemove(r.id)}><Trash2 size={14} /></button>}</div>
      </div>
      {open && (
        <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-0.5 px-6 py-3 bg-slate-50 border-t border-slate-100 text-xs">
          <dt className="text-slate-500">{t('tls.f.issuer')}</dt><dd>{r.issuer ?? '—'}</dd>
          <dt className="text-slate-500">{t('tls.f.names')}</dt><dd className="break-words">{r.names.join(', ') || '—'}</dd>
          <dt className="text-slate-500">{t('tls.f.valid')}</dt><dd>{r.not_before ? new Date(r.not_before).toLocaleDateString() : '—'} → {r.not_after ? new Date(r.not_after).toLocaleDateString() : '—'}</dd>
          <dt className="text-slate-500">{t('tls.f.key')}</dt><dd>{r.key ?? '—'}{r.sig ? ` · ${r.sig.toUpperCase()}` : ''}</dd>
          <dt className="text-slate-500">{t('tls.f.protocol')}</dt><dd>{r.protocol ?? '—'}{r.cipher ? ` · ${r.cipher}` : ''}</dd>
          <dt className="text-slate-500">{t('tls.f.legacy')}</dt><dd>{r.legacy.length ? r.legacy.join(', ') : t('tls.none')}</dd>
          {r.findings.length > 0 && <><dt className="text-slate-500">{t('tls.f.findings')}</dt><dd>{r.findings.map(f => f.message).join(' · ')}</dd></>}
          {r.error && <><dt className="text-slate-500">{t('tls.f.error')}</dt><dd className="text-amber-800 break-words">{r.error}</dd></>}
        </dl>
      )}
    </div>
  )
}

// The certificates and protocols of the services the vulnerability scan found open: what runs out, what is weak, what still speaks TLS 1.0.
export function Tls() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['tls'], queryFn: tlsApi.overview, refetchInterval: 20000 })
  const d = q.data
  const refresh = () => void qc.invalidateQueries({ queryKey: ['tls'] })
  const run = useMutation({ mutationFn: tlsApi.run, onSuccess: refresh })
  const settings = useMutation({ mutationFn: tlsApi.settings, onSuccess: refresh })
  const add = useMutation({ mutationFn: (v: { ip: string; port: number }) => tlsApi.add(v.ip, v.port), onSuccess: () => { setIp(''); setPort('443'); refresh() } })
  const remove = useMutation({ mutationFn: tlsApi.remove, onSuccess: refresh })
  const [ip, setIp] = useState('')
  const [port, setPort] = useState('443')
  const items = d?.items ?? []
  const cnt = (code: string) => items.filter(i => i.findings.some(f => f.code === code)).length
  const kpis: Array<[string, number, string]> = [
    ['expired', cnt('expired'), 'text-red-600'], ['expiring', cnt('expiring'), 'text-amber-600'],
    ['weak', items.filter(i => i.findings.some(f => ['weak_key', 'weak_signature', 'legacy_protocol'].includes(f.code))).length, 'text-amber-600'], ['selfSigned', cnt('self_signed'), 'text-sky-600'],
  ]
  const intercepted = cnt('intercepted')
  const err = run.error ?? settings.error ?? add.error ?? remove.error
  return (
    <div className="p-6 space-y-4 max-w-[1200px]">
      <div className="flex items-start gap-3 flex-wrap">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><LockKeyhole size={20} className="text-indigo-600" /> {t('tls.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('tls.subtitle')}</p>
        </div>
        <button className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-sm disabled:opacity-40" disabled={run.isPending || d?.running} onClick={() => run.mutate()}>
          <RefreshCw size={14} className={cn((run.isPending || d?.running) && 'animate-spin')} /> {t('tls.scanNow')}
        </button>
      </div>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{errText(err)}</div>}
      {intercepted > 0 && <div className="text-sm bg-amber-50 border border-amber-200 text-amber-900 rounded-xl p-3">{t('tls.intercepted', { n: intercepted })}</div>}
      <div className="flex gap-2 flex-wrap">
        {kpis.map(([k, n, c]) => (
          <div key={k} className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[8rem]"><div className="text-xs text-slate-500">{t(`tls.kpi.${k}`)}</div><div className={cn('text-2xl font-bold tabular-nums', n ? c : 'text-slate-300')}>{n}</div></div>
        ))}
        <div className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[8rem]"><div className="text-xs text-slate-500">{t('tls.kpi.total')}</div><div className="text-2xl font-bold tabular-nums text-slate-700">{items.filter(i => i.days != null).length}</div></div>
      </div>
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : items.length === 0 ? <p className="text-sm text-slate-400 py-6 text-center">{t('tls.empty')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className="grid grid-cols-[minmax(0,1.6fr)_4rem_minmax(0,1.6fr)_7rem_minmax(0,2fr)_2rem] gap-2 px-4 py-2 bg-slate-50 text-xs text-slate-500">
            <div>{t('tls.col.host')}</div><div>{t('tls.col.port')}</div><div>{t('tls.col.subject')}</div><div>{t('tls.col.expires')}</div><div>{t('tls.col.findings')}</div><div />
          </div>
          {items.map(r => <Row key={r.id} r={r} onRemove={id => remove.mutate(id)} />)}
        </div>
      )}
      {d && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
          <div className="flex flex-wrap gap-2 items-center">
            <span className="text-slate-600">{t('tls.addTarget')}</span>
            <input value={ip} onChange={e => setIp(e.target.value)} placeholder="10.0.0.5" className="border border-slate-300 rounded-md px-2 py-1 w-36" />
            <input value={port} onChange={e => setPort(e.target.value)} className="border border-slate-300 rounded-md px-2 py-1 w-20" />
            <button className="px-3 py-1 rounded-md border border-slate-300 disabled:opacity-40" disabled={!ip.trim() || add.isPending} onClick={() => add.mutate({ ip: ip.trim(), port: Number(port) })}>{t('tls.add')}</button>
          </div>
          <div className="flex flex-wrap gap-4 items-center text-xs text-slate-600">
            <label className="inline-flex items-center gap-1.5"><input type="checkbox" checked={d.settings.enabled} onChange={e => settings.mutate({ enabled: e.target.checked })} /> {t('tls.enabled')}</label>
            <label className="inline-flex items-center gap-1.5">{t('tls.warnDays')} <input type="number" defaultValue={d.settings.warn_days} key={`w${d.settings.warn_days}`} className="border border-slate-300 rounded px-1.5 py-0.5 w-16"
              onBlur={e => Number(e.target.value) !== d.settings.warn_days && settings.mutate({ warn_days: Number(e.target.value) })} /></label>
            <label className="inline-flex items-center gap-1.5">{t('tls.critDays')} <input type="number" defaultValue={d.settings.crit_days} key={`c${d.settings.crit_days}`} className="border border-slate-300 rounded px-1.5 py-0.5 w-16"
              onBlur={e => Number(e.target.value) !== d.settings.crit_days && settings.mutate({ crit_days: Number(e.target.value) })} /></label>
            <span className="text-slate-400">{t('tls.lastRun')}: {ago(d.last.at)}{d.last.error ? ` · ${d.last.error}` : ''}</span>
          </div>
        </div>
      )}
    </div>
  )
}

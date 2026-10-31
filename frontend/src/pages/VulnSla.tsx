import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Timer } from 'lucide-react'
import { vulnApi, type VulnSlaRow } from '../lib/api'
import { useAuth } from './Login'
import { cn } from '../lib/utils'

const SEV: Record<string, string> = { CRITICAL: 'text-red-600', HIGH: 'text-orange-600', MEDIUM: 'text-amber-600', LOW: 'text-sky-600' }
const errText = (e: unknown) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? ''

function SlaCell({ row, canEdit, onSave }: { row: VulnSlaRow; canEdit: boolean; onSave: (sev: string, days: number) => void }) {
  const [v, setV] = useState(String(row.sla_days))
  if (!canEdit) return <>{row.sla_days}</>
  return <input type="number" min={1} max={730} value={v} onChange={e => setV(e.target.value)} onBlur={() => { const n = Number(v); if (n && n !== row.sla_days) onSave(row.severity, n); else setV(String(row.sla_days)) }}
                className="w-16 border border-slate-300 rounded px-1.5 py-0.5 text-right text-xs" />
}

// Evidence for an audit (NIS2 art. 21(2)(e), ISO 27001 A.8.8): how fast findings are fixed, what is overdue, and which risks are accepted on purpose, until when and by whom.
export function VulnSla() {
  const { t } = useTranslation()
  const { role } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['vuln-sla'], queryFn: vulnApi.sla, refetchInterval: 60000 })
  const save = useMutation({ mutationFn: (v: { sev: string; days: number }) => vulnApi.slaSettings({ [v.sev.toLowerCase()]: v.days }), onSuccess: () => void qc.invalidateQueries({ queryKey: ['vuln-sla'] }) })
  const d = q.data
  const tile = (label: string, value: React.ReactNode, tone = 'text-slate-800', sub?: string) => (
    <div className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[9rem]"><div className="text-xs text-slate-500">{label}</div><div className={cn('text-2xl font-bold tabular-nums', tone)}>{value}</div>{sub && <div className="text-[11px] text-slate-400">{sub}</div>}</div>
  )
  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Timer size={20} className="text-indigo-600" /> {t('vulnsla.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('vulnsla.subtitle')}</p>
      </div>
      {save.isError && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{errText(save.error)}</div>}
      {q.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : d && (
        <>
          <div className="flex flex-wrap gap-2">
            {tile(t('vulnsla.tile.open') as string, d.totals.open)}
            {tile(t('vulnsla.tile.overdue') as string, d.totals.overdue, d.totals.overdue ? 'text-red-600' : 'text-slate-300')}
            {tile(t('vulnsla.tile.due7') as string, d.totals.due_7d, d.totals.due_7d ? 'text-amber-600' : 'text-slate-300')}
            {tile(t('vulnsla.tile.met') as string, d.totals.met_pct != null ? `${d.totals.met_pct}%` : '—', d.totals.met_pct != null && d.totals.met_pct < 80 ? 'text-amber-600' : 'text-green-600', t('vulnsla.last90', { n: d.totals.resolved_90d }) as string)}
            {tile(t('vulnsla.tile.mttr') as string, d.totals.mttr_days != null ? `${d.totals.mttr_days} ${t('vulnsla.days')}` : '—')}
            {tile(t('vulnsla.tile.exceptions') as string, d.exceptions.length, d.exceptions_expiring_30d ? 'text-amber-600' : 'text-slate-800', d.exceptions_expiring_30d ? t('vulnsla.expiring', { n: d.exceptions_expiring_30d }) as string : undefined)}
          </div>

          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
            <div className="grid grid-cols-[6.5rem_5rem_repeat(6,minmax(0,1fr))] gap-2 px-4 py-2 bg-slate-50 text-xs text-slate-500">
              <div>{t('vulnsla.col.severity')}</div><div className="text-right">{t('vulnsla.col.sla')}</div><div className="text-right">{t('vulnsla.col.open')}</div><div className="text-right">{t('vulnsla.col.overdue')}</div>
              <div className="text-right">{t('vulnsla.col.due7')}</div><div className="text-right">{t('vulnsla.col.fixed90')}</div><div className="text-right">{t('vulnsla.col.met')}</div><div className="text-right">{t('vulnsla.col.mttr')}</div>
            </div>
            {d.by_severity.map(r => (
              <div key={r.severity} className="grid grid-cols-[6.5rem_5rem_repeat(6,minmax(0,1fr))] gap-2 px-4 py-2 border-t border-slate-100 items-center tabular-nums">
                <div className={cn('font-semibold', SEV[r.severity])}>{t(`assets.sev.${r.severity.toLowerCase()}`)}</div>
                <div className="text-right"><SlaCell key={r.sla_days} row={r} canEdit={role === 'admin'} onSave={(sev, days) => save.mutate({ sev, days })} /></div>
                <div className="text-right">{r.open}</div><div className={cn('text-right', r.overdue ? 'text-red-600 font-semibold' : 'text-slate-400')}>{r.overdue}</div>
                <div className="text-right">{r.due_7d}</div><div className="text-right">{r.resolved_90d}</div><div className="text-right">{r.met_pct != null ? `${r.met_pct}%` : '—'}</div><div className="text-right">{r.mttr_days ?? '—'}</div>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-400">{t('vulnsla.note')}</p>

          <section className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('vulnsla.overdueTitle')} <span className="font-normal text-slate-400">{d.overdue.length}</span></h2>
            {d.overdue.length === 0 ? <p className="text-sm text-green-700">{t('vulnsla.noOverdue')}</p> : (
              <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
                {d.overdue.map(o => (
                  <div key={`${o.product}${o.version}${o.cve_id}`} className="px-4 py-2 flex flex-wrap gap-3 items-center">
                    <span className={cn('text-xs font-semibold w-16', SEV[o.severity])}>{t(`assets.sev.${o.severity.toLowerCase()}`)}</span>
                    <span className="font-mono text-slate-900">{o.cve_id}</span><span className="text-slate-600">{o.product} {o.version}</span>
                    <span className="ml-auto text-xs text-red-600">{t('vulnsla.daysOverdue', { n: o.days_overdue })}</span>
                  </div>
                ))}
              </div>
            )}
            <p className="text-xs"><Link to="/vulnerabilities" className="text-indigo-600 hover:underline">{t('nav.vulnerabilities')}</Link></p>
          </section>

          <section className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('vulnsla.exceptionsTitle')} <span className="font-normal text-slate-400">{d.exceptions.length}</span></h2>
            <p className="text-xs text-slate-500">{t('vulnsla.exceptionsNote')}</p>
            {d.exceptions.length === 0 ? <p className="text-sm text-slate-400">—</p> : (
              <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
                {d.exceptions.map(e => (
                  <div key={`${e.product}${e.version}${e.cve_id}`} className="px-4 py-2 grid grid-cols-[minmax(0,2fr)_minmax(0,2fr)_9rem_8rem] gap-3 items-start">
                    <div className="min-w-0"><span className="font-mono text-slate-900">{e.cve_id}</span> <span className="text-xs text-slate-500">{e.product} {e.version}</span></div>
                    <div className="text-xs min-w-0">{e.no_reason ? <span className="text-amber-700">{t('vulnsla.noReason')}</span> : <span className="text-slate-600">{e.reason}</span>}<div className="text-slate-400">{t('vulnsla.approvedBy', { who: e.approved_by ?? '?' })}</div></div>
                    <div className="text-xs text-slate-600">{e.valid_until ? new Date(e.valid_until).toLocaleDateString() : '—'}</div>
                    <div className={cn('text-xs tabular-nums', e.days_left != null && e.days_left <= 30 ? 'text-amber-700 font-semibold' : 'text-slate-500')}>{e.days_left != null ? t('vulnsla.daysLeft', { n: Math.max(0, Math.ceil(e.days_left)) }) : '—'}</div>
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

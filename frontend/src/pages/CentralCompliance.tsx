import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralComplianceFinding } from '../lib/api'
import { ListChecks } from 'lucide-react'

const SEVERITY_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 }
const SEVERITY_STYLE: Record<string, string> = {
  high: 'border-red-300 bg-red-50',
  medium: 'border-amber-300 bg-amber-50',
  low: 'border-slate-300 bg-slate-50',
}
const SEVERITY_BADGE: Record<string, string> = {
  high: 'bg-red-600 text-white',
  medium: 'bg-amber-500 text-white',
  low: 'bg-slate-400 text-white',
}

type Row = { tenant: string; finding: CentralComplianceFinding }

function FindingCard({ row }: { row: Row }) {
  const { finding, tenant } = row
  return (
    <div className={`border-l-4 rounded-lg p-4 ${SEVERITY_STYLE[finding.severity] ?? 'border-slate-300 bg-slate-50'}`}>
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1.5">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">{tenant}</span>
          <span className="text-xs px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-500 uppercase">{finding.target_type}</span>
          <span className="font-mono text-sm text-slate-800">{finding.label}</span>
        </div>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded uppercase ${SEVERITY_BADGE[finding.severity] ?? 'bg-slate-400 text-white'}`}>
          {finding.severity}
        </span>
      </div>
      <p className="text-base font-medium text-slate-900">{finding.title}</p>
      {finding.detail && <p className="text-sm text-slate-700 mt-1.5 leading-relaxed">{finding.detail}</p>}
    </div>
  )
}

export function CentralCompliance() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<Row[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenantFilter, setTenantFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const reload = async () => {
    try {
      const s = await centralApi.complianceStatusAll()
      const flat: Row[] = []
      for (const tRow of s.tenants) {
        for (const finding of tRow.findings) flat.push({ tenant: tRow.tenant, finding })
      }
      flat.sort((a, b) => (SEVERITY_ORDER[a.finding.severity] ?? 9) - (SEVERITY_ORDER[b.finding.severity] ?? 9))
      setRows(flat)
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    reload()
    const iv = setInterval(reload, 30000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!cfg) {
    return (
      <div className="p-6 max-w-5xl">
        <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">
          {t('alerts.needsCentral')}
        </div>
      </div>
    )
  }

  const tenants = [...new Set(rows.map(r => r.tenant))].sort()
  const visible = rows.filter(r =>
    (tenantFilter === 'all' || r.tenant === tenantFilter) &&
    (severityFilter === 'all' || r.finding.severity === severityFilter)
  )
  const counts = { high: 0, medium: 0, low: 0 } as Record<string, number>
  for (const r of rows) counts[r.finding.severity] = (counts[r.finding.severity] ?? 0) + 1

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <ListChecks size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('complianceCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('complianceCentral.intro')}</p>

      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {!loading && rows.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs px-2.5 py-1 rounded bg-red-100 text-red-700 font-medium">{t('complianceCentral.countHigh', { count: counts.high ?? 0 })}</span>
          <span className="text-xs px-2.5 py-1 rounded bg-amber-100 text-amber-700 font-medium">{t('complianceCentral.countMedium', { count: counts.medium ?? 0 })}</span>
          <span className="text-xs px-2.5 py-1 rounded bg-slate-200 text-slate-700 font-medium">{t('complianceCentral.countLow', { count: counts.low ?? 0 })}</span>

          <select value={tenantFilter} onChange={e => setTenantFilter(e.target.value)}
            className="ml-auto text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('alerts.allTenants')}</option>
            {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
          </select>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
            className="text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('complianceCentral.allSeverities')}</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <button onClick={reload} className="text-xs text-indigo-600 hover:underline shrink-0">{t('common.refresh')}</button>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-slate-500">{t('complianceCentral.noFindings')}</p>
      ) : visible.length === 0 ? (
        <p className="text-sm text-slate-500">{t('complianceCentral.noneMatchFilter')}</p>
      ) : (
        <div className="space-y-3">
          {visible.map((row, i) => (
            <FindingCard key={`${row.tenant}:${row.finding.check_id}:${i}`} row={row} />
          ))}
        </div>
      )}
    </div>
  )
}

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralVulnFinding } from '../lib/api'
import { ShieldAlert } from 'lucide-react'

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1 }
const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'border-red-400 bg-red-50',
  HIGH: 'border-amber-400 bg-amber-50',
}
const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-amber-500 text-white',
}

type Row = { tenant: string; ip: string; deviceName: string | null; finding: CentralVulnFinding }

function FindingCard({ row }: { row: Row }) {
  const { finding, tenant, ip, deviceName } = row
  return (
    <div className={`border-l-4 rounded-lg p-4 ${SEVERITY_STYLE[finding.severity] ?? 'border-slate-300 bg-slate-50'}`}>
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1.5">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">{tenant}</span>
          <span className="font-mono text-sm text-slate-800">{deviceName || ip}</span>
          {deviceName && <span className="font-mono text-xs text-slate-400">{ip}</span>}
        </div>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded uppercase ${SEVERITY_BADGE[finding.severity] ?? 'bg-slate-400 text-white'}`}>
          {finding.severity}
        </span>
      </div>
      <p className="text-base font-medium text-slate-900">
        {finding.ref_url ? (
          <a href={finding.ref_url} target="_blank" rel="noopener noreferrer" className="text-indigo-700 hover:underline">
            {finding.cve_id}
          </a>
        ) : finding.cve_id}
        {finding.cvss_score != null && <span className="ml-2 text-sm font-normal text-slate-500">CVSS {finding.cvss_score}</span>}
      </p>
      {finding.summary && <p className="text-sm text-slate-700 mt-1.5 leading-relaxed">{finding.summary}</p>}
    </div>
  )
}

export function CentralVulnerabilities() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<Row[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenantFilter, setTenantFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const reload = async () => {
    try {
      const s = await centralApi.vulnFindingsStatusAll()
      const flat: Row[] = []
      for (const tRow of s.tenants) {
        for (const host of tRow.hosts) {
          for (const finding of host.findings) {
            flat.push({ tenant: tRow.tenant, ip: host.ip, deviceName: host.device_name, finding })
          }
        }
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
    const iv = setInterval(reload, 60000)
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
  const counts = { CRITICAL: 0, HIGH: 0 } as Record<string, number>
  for (const r of rows) counts[r.finding.severity] = (counts[r.finding.severity] ?? 0) + 1

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <ShieldAlert size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('centralVuln.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('centralVuln.intro')}</p>

      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {!loading && rows.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs px-2.5 py-1 rounded bg-red-100 text-red-700 font-medium">{t('centralVuln.countCritical', { count: counts.CRITICAL ?? 0 })}</span>
          <span className="text-xs px-2.5 py-1 rounded bg-amber-100 text-amber-700 font-medium">{t('centralVuln.countHigh', { count: counts.HIGH ?? 0 })}</span>

          <select value={tenantFilter} onChange={e => setTenantFilter(e.target.value)}
            className="ml-auto text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('alerts.allTenants')}</option>
            {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
          </select>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
            className="text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('complianceCentral.allSeverities')}</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
          </select>
          <button onClick={reload} className="text-xs text-indigo-600 hover:underline shrink-0">{t('common.refresh')}</button>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-slate-500">{t('centralVuln.empty')}</p>
      ) : visible.length === 0 ? (
        <p className="text-sm text-slate-500">{t('complianceCentral.noneMatchFilter')}</p>
      ) : (
        <div className="space-y-3">
          {visible.map((row, i) => (
            <FindingCard key={`${row.tenant}:${row.ip}:${row.finding.cve_id}:${i}`} row={row} />
          ))}
        </div>
      )}
    </div>
  )
}

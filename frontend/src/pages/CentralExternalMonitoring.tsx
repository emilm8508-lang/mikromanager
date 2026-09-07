import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralPrtgSensor, type CentralCheckmkService, type CentralCheckmkHost } from '../lib/api'
import { Activity } from 'lucide-react'

type PrtgRow = { tenant: string; sensor: CentralPrtgSensor }
type ServiceRow = { tenant: string; service: CentralCheckmkService }
type HostRow = { tenant: string; host: CentralCheckmkHost }

function ProblemCard({ tenant, title, detail }: { tenant: string; title: string; detail: string }) {
  return (
    <div className="border-l-4 border-red-300 bg-red-50 rounded-lg p-4">
      <div className="flex items-center gap-2 flex-wrap mb-1.5">
        <span className="text-xs font-medium px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">{tenant}</span>
      </div>
      <p className="text-base font-medium text-slate-900">{title}</p>
      <p className="text-sm text-slate-700 mt-1 leading-relaxed">{detail}</p>
    </div>
  )
}

export function CentralExternalMonitoring() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [prtgRows, setPrtgRows] = useState<PrtgRow[]>([])
  const [serviceRows, setServiceRows] = useState<ServiceRow[]>([])
  const [hostRows, setHostRows] = useState<HostRow[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenantFilter, setTenantFilter] = useState<string>('all')

  const reload = async () => {
    try {
      const [prtg, checkmk] = await Promise.all([
        centralApi.prtgStatusAll(),
        centralApi.checkmkStatusAll(),
      ])
      const pRows: PrtgRow[] = []
      for (const tRow of prtg.tenants) {
        for (const sensor of tRow.sensors) pRows.push({ tenant: tRow.tenant, sensor })
      }
      const sRows: ServiceRow[] = []
      const hRows: HostRow[] = []
      for (const tRow of checkmk.tenants) {
        for (const service of tRow.services) sRows.push({ tenant: tRow.tenant, service })
        for (const host of tRow.hosts) hRows.push({ tenant: tRow.tenant, host })
      }
      setPrtgRows(pRows)
      setServiceRows(sRows)
      setHostRows(hRows)
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

  const tenants = [...new Set([
    ...prtgRows.map(r => r.tenant), ...serviceRows.map(r => r.tenant), ...hostRows.map(r => r.tenant),
  ])].sort()
  const visiblePrtg = prtgRows.filter(r => tenantFilter === 'all' || r.tenant === tenantFilter)
  const visibleServices = serviceRows.filter(r => tenantFilter === 'all' || r.tenant === tenantFilter)
  const visibleHosts = hostRows.filter(r => tenantFilter === 'all' || r.tenant === tenantFilter)
  const totalCount = prtgRows.length + serviceRows.length + hostRows.length
  const visibleCount = visiblePrtg.length + visibleServices.length + visibleHosts.length

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <Activity size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('externalMonitoringCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('externalMonitoringCentral.intro')}</p>

      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {!loading && totalCount > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <select value={tenantFilter} onChange={e => setTenantFilter(e.target.value)}
            className="ml-auto text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('alerts.allTenants')}</option>
            {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
          </select>
          <button onClick={reload} className="text-xs text-indigo-600 hover:underline shrink-0">{t('common.refresh')}</button>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : totalCount === 0 ? (
        <p className="text-sm text-slate-500">{t('externalMonitoringCentral.noProblems')}</p>
      ) : visibleCount === 0 ? (
        <p className="text-sm text-slate-500">{t('externalMonitoringCentral.noneMatchFilter')}</p>
      ) : (
        <div className="space-y-5">
          {visiblePrtg.length > 0 && (
            <div className="space-y-2">
              <h2 className="text-sm font-semibold text-slate-700">{t('externalMonitoringCentral.sectionPrtg')}</h2>
              <div className="space-y-3">
                {visiblePrtg.map((row, i) => (
                  <ProblemCard key={`prtg:${row.tenant}:${i}`} tenant={row.tenant}
                    title={`${row.sensor.device_name} — ${row.sensor.sensor_name}`}
                    detail={`${row.sensor.status_name}${row.sensor.message ? ' — ' + row.sensor.message : ''}`} />
                ))}
              </div>
            </div>
          )}
          {visibleServices.length > 0 && (
            <div className="space-y-2">
              <h2 className="text-sm font-semibold text-slate-700">{t('externalMonitoringCentral.sectionCheckmkServices')}</h2>
              <div className="space-y-3">
                {visibleServices.map((row, i) => (
                  <ProblemCard key={`svc:${row.tenant}:${i}`} tenant={row.tenant}
                    title={`${row.service.device_name} — ${row.service.description}`}
                    detail={`${row.service.state_name}${row.service.plugin_output ? ' — ' + row.service.plugin_output : ''}`} />
                ))}
              </div>
            </div>
          )}
          {visibleHosts.length > 0 && (
            <div className="space-y-2">
              <h2 className="text-sm font-semibold text-slate-700">{t('externalMonitoringCentral.sectionCheckmkHosts')}</h2>
              <div className="space-y-3">
                {visibleHosts.map((row, i) => (
                  <ProblemCard key={`host:${row.tenant}:${i}`} tenant={row.tenant}
                    title={row.host.device_name} detail={row.host.state_name} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

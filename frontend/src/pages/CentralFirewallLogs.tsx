import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralFirewallDeviceStatus } from '../lib/api'
import { ScrollText } from 'lucide-react'

type Row = { tenant: string; device: CentralFirewallDeviceStatus }

function DeviceLogCard({ row }: { row: Row }) {
  const { t } = useTranslation()
  const { device, tenant } = row
  return (
    <div className="border border-slate-200 rounded-lg p-4 bg-white space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700">{tenant}</span>
          <span className="font-mono text-sm text-slate-800">{device.device_name}</span>
        </div>
        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-indigo-100 text-indigo-700">
          {t('firewallLogsCentral.entryCount', { count: device.log_count ?? 0 })}
        </span>
      </div>
      {device.log_top_sources.length > 0 && (
        <div className="text-xs text-slate-600">
          <span className="text-slate-500">{t('firewallLogsCentral.topSources')}: </span>
          {device.log_top_sources.map((s, i) => (
            <span key={s.ip} className="font-mono">
              {s.ip} ({s.count}){i < device.log_top_sources.length - 1 ? ', ' : ''}
            </span>
          ))}
        </div>
      )}
      {device.log_recent.length > 0 && (
        <table className="w-full text-xs mt-1">
          <thead>
            <tr className="text-left text-slate-400 border-b">
              <th className="py-1 pr-2">{t('firewallLogsCentral.time')}</th>
              <th className="pr-2">{t('firewallLogsCentral.chain')}</th>
              <th className="pr-2">{t('firewallLogsCentral.proto')}</th>
              <th className="pr-2">{t('firewallLogsCentral.src')}</th>
              <th>{t('firewallLogsCentral.dst')}</th>
            </tr>
          </thead>
          <tbody>
            {device.log_recent.slice().reverse().map((e, i) => (
              <tr key={i} className="border-b border-slate-50 font-mono text-slate-700">
                <td className="py-1 pr-2 text-slate-400">{e.time ?? ''}</td>
                <td className="pr-2">{e.chain ?? ''}</td>
                <td className="pr-2 text-indigo-600">{e.proto ?? ''}</td>
                <td className="pr-2">{e.src ?? ''}{e.src_port ? `:${e.src_port}` : ''}</td>
                <td>{e.dst ?? ''}{e.dst_port ? `:${e.dst_port}` : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export function CentralFirewallLogs() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<Row[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenantFilter, setTenantFilter] = useState<string>('all')

  const reload = async () => {
    try {
      const s = await centralApi.firewallStatusAll()
      const flat: Row[] = []
      for (const tRow of s.tenants) {
        for (const device of tRow.devices) flat.push({ tenant: tRow.tenant, device })
      }
      flat.sort((a, b) => (b.device.log_count ?? 0) - (a.device.log_count ?? 0))
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
  const visible = rows.filter(r => tenantFilter === 'all' || r.tenant === tenantFilter)

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <ScrollText size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('firewallLogsCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('firewallLogsCentral.intro')}</p>

      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {!loading && rows.length > 0 && (
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
      ) : rows.length === 0 ? (
        <p className="text-sm text-slate-500">{t('firewallLogsCentral.noDevices')}</p>
      ) : visible.length === 0 ? (
        <p className="text-sm text-slate-500">{t('complianceCentral.noneMatchFilter')}</p>
      ) : (
        <div className="space-y-3">
          {visible.map((row) => <DeviceLogCard key={`${row.tenant}:${row.device.device_id}`} row={row} />)}
        </div>
      )}
    </div>
  )
}

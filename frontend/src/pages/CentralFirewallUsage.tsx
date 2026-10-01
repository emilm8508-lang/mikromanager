import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralFirewallDeviceStatus } from '../lib/api'
import { ShieldQuestion } from 'lucide-react'

type Row = { tenant: string; device: CentralFirewallDeviceStatus }

function DeviceCard({ row }: { row: Row }) {
  const { t } = useTranslation()
  const { device, tenant } = row
  const unused = device.rules_unused ?? 0
  const hasUnused = unused > 0
  return (
    <div className={`border-l-4 rounded-lg p-4 ${hasUnused ? 'border-amber-300 bg-amber-50' : 'border-slate-300 bg-slate-50'}`}>
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1.5">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">{tenant}</span>
          <span className="font-mono text-sm text-slate-800">{device.device_name}</span>
        </div>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded ${hasUnused ? 'bg-amber-500 text-white' : 'bg-slate-400 text-white'}`}>
          {t('firewallUsageCentral.unusedOfActive', { unused, active: device.rules_active ?? 0 })}
        </span>
      </div>
      {hasUnused && (
        <ul className="text-xs text-slate-700 space-y-0.5 font-mono mt-2">
          {device.unused_rule_labels.map((label, i) => <li key={i}>{label}</li>)}
        </ul>
      )}
    </div>
  )
}

export function CentralFirewallUsage() {
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
      flat.sort((a, b) => (b.device.rules_unused ?? 0) - (a.device.rules_unused ?? 0))
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
        <ShieldQuestion size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('firewallUsageCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('firewallUsageCentral.intro')}</p>

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
        <p className="text-sm text-slate-500">{t('firewallUsageCentral.noDevices')}</p>
      ) : visible.length === 0 ? (
        <p className="text-sm text-slate-500">{t('complianceCentral.noneMatchFilter')}</p>
      ) : (
        <div className="space-y-3">
          {visible.map((row) => <DeviceCard key={`${row.tenant}:${row.device.device_id}`} row={row} />)}
        </div>
      )}
    </div>
  )
}

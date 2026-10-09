import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralFleetGroup, type FleetOverview } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { GroupScheduleRow } from '../components/FleetGroups'
import { CentralFleetGroups } from '../components/CentralFleetGroups'
import { Donut, ResourcesCard, AlertsCard, UpdatesCard, WifiCard, mergeWifi, type AlertRowView } from '../components/FleetWidgets'
import { Router, Download } from 'lucide-react'

type TenantFleet = { tenant: string; lastSeen: string | null; fleet: FleetOverview }

// Same OWASP CSV-formula-injection guard + BOM as the other CSV exports.
function csvSafe(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v)
  return `"${(s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s).replace(/"/g, '""')}"`
}

export function CentralFleet() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<TenantFleet[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenantFilter, setTenantFilter] = useState('all')
  const [centralGroups, setCentralGroups] = useState<CentralFleetGroup[]>([])

  const reload = async () => {
    try {
      const s = await centralApi.fleetStatusAll()
      setRows(s.tenants.filter(x => x.fleet).map(x => ({ tenant: x.tenant, lastSeen: x.last_seen, fleet: x.fleet as FleetOverview })))
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
    // Separate from the status call: an older api.php without the groups actions must not break the page.
    try { setCentralGroups(await centralApi.fleetGroupsList()) } catch { /* keep the last list */ }
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
        <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">{t('alerts.needsCentral')}</div>
      </div>
    )
  }

  const tenants = rows.map(r => r.tenant).sort()
  const vis = rows.filter(r => tenantFilter === 'all' || r.tenant === tenantFilter)
  const devices = vis.flatMap(r => r.fleet.devices.map(d => ({ tenant: r.tenant, device: d })))
  const totals = vis.reduce((a, r) => ({
    devices: a.devices + r.fleet.totals.devices, online: a.online + r.fleet.totals.online, paired: a.paired + r.fleet.totals.paired,
  }), { devices: 0, online: 0, paired: 0 })

  // Alerts of the same kind merged across the visible tenants; Central only has device NAMES, so no links.
  const alertMap = new Map<string, AlertRowView>()
  for (const r of vis) {
    for (const a of r.fleet.alerts) {
      const cur = alertMap.get(a.key) ?? { key: a.key, severity: a.severity, count: 0, total: 0, items: [] }
      cur.count += a.count
      cur.items.push(...(a.devices as string[]).map(n => ({ label: `${r.tenant} / ${n}` })))
      alertMap.set(a.key, cur)
    }
  }
  for (const a of alertMap.values()) a.total = totals.devices
  const alerts = [...alertMap.values()].sort((a, b) => (a.severity === 'high' ? 0 : 1) - (b.severity === 'high' ? 0 : 1) || b.count - a.count)
  const updates = vis.flatMap(r => r.fleet.updates.map(u => ({
    key: `${r.tenant}:${u.id}`, tenant: r.tenant, label: u.name, current: u.current, latest: u.latest, channel: u.channel,
  })))
  const wifi = mergeWifi(vis.map(r => r.fleet.wifi))
  // Groups managed from Central are shown (with their status) in the editable card; this table keeps the agents' own local ones.
  const groups = vis.flatMap(r => (r.fleet.groups ?? []).filter(g => g.central_id == null).map(g => ({ tenant: r.tenant, g })))

  const exportCsv = () => {
    const header = ['tenant', 'name', 'model', 'architecture', 'routeros', 'channel', 'latest_routeros', 'online', 'cpu_pct', 'memory_pct', 'disk_pct', 'uptime_sec', 'packages']
    const lines = [header.map(csvSafe).join(',')]
    for (const { tenant, device: d } of devices) {
      lines.push([tenant, d.name, d.model, d.architecture, d.ros_version, d.ros_channel, d.latest_ros_version, d.online, d.cpu,
                  d.mem == null ? '' : Math.round(d.mem), d.disk == null ? '' : Math.round(d.disk), d.uptime_sec, d.packages_count].map(csvSafe).join(','))
    }
    const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'mikrotik-central.csv'
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <div className="p-6 space-y-4 max-w-6xl">
      <div className="flex items-center gap-2">
        <Router size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('fleetCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('fleetCentral.intro')}</p>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p>
        : rows.length === 0 ? <p className="text-sm text-slate-500">{t('fleetCentral.noData')}</p> : (
        <>
          <div className="flex items-center gap-3 flex-wrap">
            <select value={tenantFilter} onChange={e => setTenantFilter(e.target.value)} className="text-xs border border-slate-300 rounded px-2 py-1">
              <option value="all">{t('alerts.allTenants')}</option>
              {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
            </select>
            <div className="ml-auto flex items-center gap-3">
              <button onClick={exportCsv} className="text-xs text-indigo-600 hover:underline flex items-center gap-1"><Download size={12} /> CSV</button>
              <button onClick={reload} className="text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><h2 className="text-sm font-semibold text-slate-700">{t('fleet.devicesCard')}</h2></CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap gap-8">
                  <Donut value={totals.online} total={totals.devices} label={t('fleet.online') as string} />
                  <Donut value={totals.paired} total={totals.devices} label={t('fleet.paired') as string} />
                </div>
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-slate-500 border-b">
                    <th className="py-1">{t('fleetCentral.colTenant')}</th><th>{t('fleetCentral.colDevices')}</th>
                    <th>{t('fleetCentral.colOnline')}</th><th>{t('fleetCentral.colAlerts')}</th><th>{t('fleetCentral.colLastSeen')}</th>
                  </tr></thead>
                  <tbody>
                    {vis.map(r => (
                      <tr key={r.tenant} className="border-b border-slate-100">
                        <td className="py-1 font-medium text-slate-800">{r.tenant}</td><td>{r.fleet.totals.devices}</td>
                        <td>{r.fleet.totals.online}</td><td>{r.fleet.alerts.reduce((n, a) => n + a.count, 0)}</td>
                        <td className="text-slate-500">{r.lastSeen ? new Date(r.lastSeen.replace(' ', 'T')).toLocaleString() : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
            <ResourcesCard rows={devices.filter(x => x.device.paired).map(x => ({ key: `${x.tenant}:${x.device.id}`, tenant: x.tenant, device: x.device }))} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <AlertsCard alerts={alerts} />
            <UpdatesCard updates={updates} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <WifiCard wifi={wifi} kind="aps" />
            <WifiCard wifi={wifi} kind="stations" />
          </div>
          <CentralFleetGroups rows={rows} tenantFilter={tenantFilter} groups={centralGroups} onChanged={reload} />
          {groups.length > 0 && (
            <Card>
              <CardHeader><h2 className="text-sm font-semibold text-slate-700">{t('fleetCentral.localGroupsCard')}</h2></CardHeader>
              <CardContent className="space-y-2">
                <p className="text-xs text-slate-500">{t('fleetCentral.localGroupsHint')}</p>
                <table className="w-full text-sm">
                  <thead><tr className="text-left text-xs text-slate-500 border-b">
                    <th className="py-1.5">{t('fleetCentral.colGroup')}</th><th>{t('fleetCentral.colSchedule')}</th><th>{t('fleetCentral.colNext')}</th><th>{t('fleetCentral.colLast')}</th>
                  </tr></thead>
                  <tbody>{groups.map(x => <GroupScheduleRow key={`${x.tenant}:${x.g.name}`} g={x.g} tenant={x.tenant} />)}</tbody>
                </table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  )
}

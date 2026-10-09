import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { fleetApi, FleetDeviceRow, FleetOverview } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Donut, ResourcesCard, AlertsCard, UpdatesCard, WifiCard } from '../components/FleetWidgets'
import { Router, RefreshCw, Download, ChevronDown, ChevronRight } from 'lucide-react'
import { cn, formatBytes } from '../lib/utils'

export function formatUptime(sec: number | null | undefined): string {
  if (sec == null) return '—'
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60)
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`
}

// Same OWASP CSV-formula-injection guard + BOM as the other CSV exports in the app.
function csvSafe(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v)
  return `"${(s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s).replace(/"/g, '""')}"`
}

// ── Dashboard ────────────────────────────────────────────────────────────────

function Dashboard({ data }: { data: FleetOverview }) {
  const { t } = useTranslation()
  const { totals } = data
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader><h2 className="text-sm font-semibold text-slate-700">{t('fleet.devicesCard')}</h2></CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-8">
              <Donut value={totals.online} total={totals.devices} label={t('fleet.online') as string} />
              <Donut value={totals.paired} total={totals.devices} label={t('fleet.paired') as string} />
            </div>
          </CardContent>
        </Card>
        <ResourcesCard rows={data.devices.filter(d => d.paired).map(d => ({ key: String(d.id), device: d }))} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <AlertsCard alerts={data.alerts.map(a => ({
          key: a.key, severity: a.severity, count: a.count, total: a.total,
          items: (a.devices as Array<{ id: number; name: string }>).map(d => ({ label: d.name, to: `/devices/${d.id}` })),
        }))} />
        <UpdatesCard updates={data.updates.map(u => ({
          key: String(u.id), label: u.name, current: u.current, latest: u.latest, channel: u.channel, to: `/devices/${u.id}`,
        }))} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <WifiCard wifi={data.wifi} kind="aps" />
        <WifiCard wifi={data.wifi} kind="stations" />
      </div>
    </div>
  )
}

// ── Inventory ────────────────────────────────────────────────────────────────

function Inventory({ data }: { data: FleetOverview }) {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState<'all' | 'offline' | 'updates'>('all')
  const [open, setOpen] = useState<number | null>(null)

  const needle = q.trim().toLowerCase()
  const rows = data.devices.filter(d =>
    (filter === 'all' || (filter === 'offline' ? !d.online : d.update_available))
    && (!needle || [d.name, d.ip, d.model, d.board_name, d.architecture, d.ros_version].some(v => (v ?? '').toLowerCase().includes(needle))))

  const exportCsv = () => {
    const header = ['name', 'ip', 'model', 'board', 'architecture', 'routeros', 'channel', 'latest_routeros', 'routerboard_firmware',
                    'routerboard_firmware_available', 'online', 'paired', 'cpu_pct', 'memory_pct', 'disk_pct', 'uptime_sec', 'packages']
    const lines = [header.map(csvSafe).join(',')]
    for (const d of rows) {
      lines.push([d.name, d.ip, d.model, d.board_name, d.architecture, d.ros_version, d.ros_channel, d.latest_ros_version,
                  d.firmware_current, d.firmware_target, d.online, d.paired, d.cpu, d.mem == null ? '' : Math.round(d.mem), d.disk == null ? '' : Math.round(d.disk),
                  d.uptime_sec, (d.packages ?? []).map(p => `${p.name} ${p.version ?? ''}${p.disabled ? ' (disabled)' : ''}`).join('; ')].map(csvSafe).join(','))
    }
    const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'mikrotik-inventory.csv'
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2 flex-wrap">
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('fleet.searchPlaceholder') as string}
            className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm flex-1 min-w-[12rem]" />
          <select value={filter} onChange={e => setFilter(e.target.value as typeof filter)} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm">
            <option value="all">{t('fleet.filterAll')}</option>
            <option value="offline">{t('fleet.filterOffline')}</option>
            <option value="updates">{t('fleet.filterUpdates')}</option>
          </select>
          <Button size="sm" variant="secondary" onClick={exportCsv}><Download size={13} /> CSV</Button>
          <span className="text-xs text-slate-400">{rows.length} / {data.devices.length}</span>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {rows.length === 0 ? <p className="p-5 text-sm text-slate-500">{t('fleet.noDevices')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-slate-500 border-b">
                <th className="px-4 py-2" /><th>{t('fleet.colName')}</th><th>{t('fleet.colModel')}</th><th>{t('fleet.colArch')}</th>
                <th>{t('fleet.colRos')}</th><th>{t('fleet.colFirmware')}</th><th>{t('fleet.colPackages')}</th>
                <th>{t('fleet.colUptime')}</th><th>CPU / {t('fleet.memory')} / {t('fleet.disk')}</th>
              </tr></thead>
              <tbody>
                {rows.map((d: FleetDeviceRow) => (
                  <Fragment key={d.id}>
                    <tr className="border-b border-slate-100 hover:bg-slate-50 align-top">
                      <td className="px-4 py-2"><Badge variant={d.online ? 'green' : 'red'}>{d.online ? t('common.online') : t('common.offline')}</Badge></td>
                      <td className="py-2 pr-3">
                        <Link to={`/devices/${d.id}`} className="text-indigo-600 hover:underline font-medium">{d.name}</Link>
                        <div className="text-[11px] font-mono text-slate-400">{d.ip}</div>
                      </td>
                      <td className="pr-3 text-slate-700">{d.model ?? '—'}<div className="text-[11px] text-slate-400">{d.board_name ?? ''}</div></td>
                      <td className="pr-3 text-slate-600">{d.architecture ?? '—'}</td>
                      <td className="pr-3 font-mono text-xs">
                        {d.ros_version ?? '—'}
                        {d.ros_channel && <span className="text-slate-400"> · {d.ros_channel}</span>}
                        {d.update_available && <div className="text-amber-700">→ {d.latest_ros_version}</div>}
                      </td>
                      <td className="pr-3 font-mono text-xs">
                        {d.firmware_current ?? '—'}
                        {d.firmware_target && d.firmware_target !== d.firmware_current && <div className="text-amber-700">→ {d.firmware_target}</div>}
                      </td>
                      <td className="pr-3">
                        {d.packages_count > 0 ? (
                          <button onClick={() => setOpen(open === d.id ? null : d.id)} className="text-indigo-600 hover:underline flex items-center gap-0.5 text-xs">
                            {open === d.id ? <ChevronDown size={12} /> : <ChevronRight size={12} />}{d.packages_count}
                          </button>
                        ) : <span className="text-slate-300">—</span>}
                      </td>
                      <td className="pr-3 text-xs text-slate-600">{formatUptime(d.uptime_sec)}</td>
                      <td className="pr-4 text-xs text-slate-600 whitespace-nowrap">
                        {d.cpu ?? '—'}% / {d.mem != null ? Math.round(d.mem) : '—'}% / {d.disk != null ? Math.round(d.disk) : '—'}%
                        {d.mem_total_bytes ? <div className="text-[10px] text-slate-400">{formatBytes(d.mem_total_bytes)}</div> : null}
                      </td>
                    </tr>
                    {open === d.id && (
                      <tr className="bg-slate-50 border-b border-slate-100"><td /><td colSpan={8} className="py-2 text-xs">
                        <div className="flex flex-wrap gap-x-4 gap-y-1">
                          {(d.packages ?? []).map(p => (
                            <span key={p.name} className={cn('font-mono', p.disabled ? 'text-slate-400 line-through' : 'text-slate-700')}>
                              {p.name} <span className="text-slate-400">{p.version}</span>
                            </span>
                          ))}
                        </div>
                      </td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'dashboard' | 'inventory'

export function Mikrotik() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('dashboard')
  const { data, isLoading } = useQuery({ queryKey: ['fleet-overview'], queryFn: fleetApi.overview, refetchInterval: 60_000 })
  const refresh = useMutation({
    mutationFn: fleetApi.refresh,
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['fleet-overview'] }), 8000),
  })

  const tabs: Array<[Tab, string]> = [['dashboard', 'fleet.tabDashboard'], ['inventory', 'fleet.tabInventory']]
  return (
    <div className="p-6 space-y-4 max-w-7xl">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Router size={20} className="text-indigo-600" /> {t('fleet.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('fleet.subtitle')}</p>
        </div>
        <Button size="sm" variant="secondary" onClick={() => refresh.mutate()} disabled={refresh.isPending}>
          <RefreshCw size={13} className={refresh.isPending ? 'animate-spin' : ''} /> {t('fleet.refresh')}
        </Button>
      </div>

      <div className="flex gap-1 border-b border-slate-200">
        {tabs.map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)}
            className={cn('px-4 py-2 text-sm -mb-px border-b-2', tab === k ? 'border-indigo-600 text-indigo-700 font-medium' : 'border-transparent text-slate-500 hover:text-slate-800')}>
            {t(label)}
          </button>
        ))}
      </div>

      {data && data.never_collected > 0 && (
        <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-3 py-1.5">{t('fleet.collecting', { n: data.never_collected })}</p>
      )}

      {isLoading || !data ? <p className="text-sm text-slate-500">{t('common.loading')}</p>
        : data.devices.length === 0 ? <p className="text-sm text-slate-500">{t('fleet.noDevices')}</p>
        : tab === 'dashboard' ? <Dashboard data={data} /> : <Inventory data={data} />}
    </div>
  )
}

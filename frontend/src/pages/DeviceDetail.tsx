import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { devicesApi } from '../lib/api'
import { Card, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { ArrowLeft, Network, Globe, Shield, Wifi, List, Server, Activity, AlertTriangle } from 'lucide-react'
import { cn } from '../lib/utils'
import { useTranslation } from 'react-i18next'
import axios from 'axios'
import { cleanVersion } from '../lib/version'

function errorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail
    if (typeof detail === 'string') return detail
    if (err.code === 'ECONNABORTED') return 'Timeout'
    return err.message
  }
  return err instanceof Error ? err.message : String(err)
}

type Tab = 'interfaces' | 'addresses' | 'routes' | 'firewall' | 'wireless' | 'dhcp' | 'tunnels' | 'resource'

function DataTable({ data, emptyLabel }: { data: Record<string, unknown>[]; emptyLabel: string }) {
  if (!data || data.length === 0) return <p className="text-sm text-slate-500 py-4 text-center">{emptyLabel}</p>

  const keys = Object.keys(data[0]).filter(k => k !== '.id')

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-slate-200">
            {keys.map(k => (
              <th key={k} className="px-3 py-2 text-left text-slate-500 font-medium whitespace-nowrap">{k}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i} className="border-b border-slate-200 hover:bg-slate-50">
              {keys.map(k => (
                <td key={k} className="px-3 py-2 text-slate-700 font-mono whitespace-nowrap">
                  {String(row[k] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TabContent({ deviceId, tab }: { deviceId: number; tab: Tab }) {
  const { t } = useTranslation()
  const queries: Record<Tab, () => Promise<unknown>> = {
    interfaces: () => devicesApi.interfaces(deviceId),
    addresses: () => devicesApi.addresses(deviceId),
    routes: () => devicesApi.routes(deviceId),
    firewall: () => devicesApi.firewall(deviceId),
    wireless: () => devicesApi.wireless(deviceId),
    dhcp: () => devicesApi.dhcpLeases(deviceId),
    tunnels: () => devicesApi.tunnels(deviceId),
    resource: () => devicesApi.resource(deviceId),
  }

  const { data, isLoading, error } = useQuery({
    queryKey: ['device', deviceId, tab],
    queryFn: queries[tab],
    retry: false,
  })

  if (isLoading) return <p className="text-sm text-slate-500 py-8 text-center">{t('common.loadingFromDevice')}</p>
  if (error) return (
    <div className="py-8 px-4 flex flex-col items-center gap-2">
      <AlertTriangle size={22} className="text-red-600" />
      <p className="text-sm text-red-600 font-medium">{t('deviceDetail.connectionError')}</p>
      <p className="text-xs text-slate-600 font-mono text-center max-w-xl break-words">
        {errorMessage(error)}
      </p>
    </div>
  )
  if (!data) return null

  if (tab === 'resource') {
    const r = data as Record<string, unknown>
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 py-2">
        {Object.entries(r).filter(([k]) => k !== '.id').map(([k, v]) => (
          <div key={k} className="bg-slate-100 rounded-lg px-4 py-3">
            <p className="text-xs text-slate-500 mb-1">{k}</p>
            <p className="text-sm text-slate-800 font-mono">{String(v)}</p>
          </div>
        ))}
      </div>
    )
  }

  if (tab === 'firewall') {
    const fw = data as { filter: Record<string, unknown>[]; nat: Record<string, unknown>[] }
    return (
      <div className="space-y-4">
        <div>
          <h3 className="text-xs font-semibold text-slate-600 mb-2">Filter</h3>
          <DataTable data={fw.filter ?? []} emptyLabel={t('common.noData')} />
        </div>
        <div>
          <h3 className="text-xs font-semibold text-slate-600 mb-2">NAT</h3>
          <DataTable data={fw.nat ?? []} emptyLabel={t('common.noData')} />
        </div>
      </div>
    )
  }

  if (tab === 'tunnels') {
    const t2 = data as Record<string, Record<string, unknown>[]>
    return (
      <div className="space-y-4">
        {Object.entries(t2).map(([type, rows]) => (
          <div key={type}>
            <h3 className="text-xs font-semibold text-slate-600 uppercase mb-2">{type}</h3>
            <DataTable data={rows} emptyLabel={t('common.noData')} />
          </div>
        ))}
      </div>
    )
  }

  return <DataTable data={data as Record<string, unknown>[]} emptyLabel={t('common.noData')} />
}

export function DeviceDetail() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const deviceId = Number(id)
  const [activeTab, setActiveTab] = useState<Tab>('resource')

  const { data: device, isLoading } = useQuery({
    queryKey: ['device', deviceId],
    queryFn: () => devicesApi.get(deviceId),
  })

  const tabs: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'resource', label: t('deviceDetail.tabs.resource'), icon: Activity },
    { id: 'interfaces', label: t('deviceDetail.tabs.interfaces'), icon: Network },
    { id: 'addresses', label: t('deviceDetail.tabs.addresses'), icon: Globe },
    { id: 'routes', label: t('deviceDetail.tabs.routes'), icon: List },
    { id: 'firewall', label: t('deviceDetail.tabs.firewall'), icon: Shield },
    { id: 'wireless', label: t('deviceDetail.tabs.wireless'), icon: Wifi },
    { id: 'dhcp', label: t('deviceDetail.tabs.dhcp'), icon: Server },
    { id: 'tunnels', label: t('deviceDetail.tabs.tunnels'), icon: Network },
  ]

  if (isLoading) return <div className="p-6 text-slate-500">{t('common.loading')}</div>
  if (!device) return <div className="p-6 text-red-600">{t('common.notFound')}</div>

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center gap-3">
        <Link to="/devices">
          <Button size="sm" variant="ghost"><ArrowLeft size={16} /></Button>
        </Link>
        <div>
          <h1 className="text-xl font-bold text-slate-900">
            {device.identity || device.name || device.ip}
          </h1>
          <p className="text-sm text-slate-500">{device.ip} · {device.model || t('deviceDetail.unknownModel')} · ROS {cleanVersion(device.ros_version) || '?'}</p>
        </div>
        <Badge variant={device.online ? 'green' : 'red'} className="ml-auto">
          {device.online ? t('common.online') : t('common.offline')}
        </Badge>
      </div>

      {/* Capability badges */}
      <div className="flex gap-2">
        {device.has_api && <Badge variant="blue">API :{device.api_port}</Badge>}
        {device.has_ssh && <Badge variant="gray">SSH :{device.ssh_port}</Badge>}
        {device.has_web && <Badge variant="yellow">Web :{device.web_port}</Badge>}
        {device.has_snmp && <Badge variant="purple">SNMP :{device.snmp_port}</Badge>}
        {!device.credential_id && <Badge variant="red">{t('deviceDetail.noCredsBadge')}</Badge>}
      </div>

      {/* Tabs */}
      <Card>
        <div className="flex border-b border-slate-200 overflow-x-auto">
          {tabs.map(({ id: tid, label, icon: Icon }) => (
            <button
              key={tid}
              onClick={() => setActiveTab(tid)}
              className={cn(
                'flex items-center gap-2 px-4 py-3 text-sm whitespace-nowrap transition-colors border-b-2',
                activeTab === tid
                  ? 'border-indigo-500 text-indigo-700'
                  : 'border-transparent text-slate-500 hover:text-slate-700'
              )}
            >
              <Icon size={14} />
              {label}
            </button>
          ))}
        </div>
        <CardContent>
          {device.credential_id ? (
            <TabContent deviceId={deviceId} tab={activeTab} />
          ) : (
            <p className="text-sm text-amber-600 py-6 text-center">
              {t('deviceDetail.noCredsAssign')}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

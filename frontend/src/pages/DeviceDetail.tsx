import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi } from '../lib/api'
import { Card, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { ArrowLeft, Network, Globe, Shield, Wifi, List, Server, Activity, AlertTriangle, Download, RefreshCw, Gauge, MemoryStick, HardDrive, Cpu } from 'lucide-react'
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

type Tab = 'interfaces' | 'addresses' | 'routes' | 'firewall' | 'wireless' | 'dhcp' | 'tunnels' | 'resource' | 'firmware' | 'network'

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

function FirmwareTab({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [check, setCheck] = useState<any>(null)
  const [checkError, setCheckError] = useState<string | null>(null)
  const [backupBeforeUpgrade, setBackupBeforeUpgrade] = useState(false)

  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['firmware-status', deviceId],
    queryFn: () => devicesApi.firmwareStatus(deviceId),
    refetchInterval: (q) => {
      const s = (q.state.data as any)?.status
      return (s === 'backing_up' || s === 'downloading' || s === 'rebooting' || s === 'starting') ? 5000 : false
    },
  })

  const doCheck = useMutation({
    mutationFn: () => devicesApi.firmwareCheck(deviceId),
    onSuccess: (data: any) => {
      setCheck(data)
      setCheckError(data?.error || null)
    },
    onError: (err: any) => setCheckError(err?.message ?? String(err)),
  })

  const doUpgrade = useMutation({
    mutationFn: () => devicesApi.firmwareUpgrade(deviceId, backupBeforeUpgrade),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firmware-status', deviceId] })
      refetchStatus()
    },
  })

  const doBackup = useMutation({
    mutationFn: () => devicesApi.firmwareBackup(deviceId),
  })

  const inProgress = ['starting', 'backing_up', 'downloading', 'rebooting'].includes(status?.status)

  return (
    <div className="space-y-4 py-2">
      <div className="flex gap-2 flex-wrap">
        <Button variant="secondary" onClick={() => doCheck.mutate()} disabled={doCheck.isPending}>
          <RefreshCw size={13} className={doCheck.isPending ? 'animate-spin' : ''} />
          {t('firmware.check')}
        </Button>
        <Button variant="secondary" onClick={() => doBackup.mutate()} disabled={doBackup.isPending || inProgress}>
          {t('firmware.backup')}
        </Button>
        <Button variant="danger" onClick={() => {
          const msg = backupBeforeUpgrade
            ? t('firmware.upgradeConfirmWithBackup') as string
            : t('firmware.upgradeConfirm') as string
          if (confirm(msg)) doUpgrade.mutate()
        }} disabled={doUpgrade.isPending || inProgress}>
          <Download size={13} />
          {t('firmware.upgrade')}
        </Button>
      </div>

      <label className="inline-flex items-center gap-2 text-sm text-slate-700 cursor-pointer">
        <input
          type="checkbox"
          checked={backupBeforeUpgrade}
          onChange={e => setBackupBeforeUpgrade(e.target.checked)}
          className="rounded"
        />
        {t('firmware.backupBeforeUpgrade')}
      </label>

      {check && !checkError && (
        <div className="bg-slate-100 rounded-lg p-3 text-sm space-y-1">
          <p><span className="text-slate-500">{t('firmware.installed')}:</span> <span className="font-mono">{check.installed ?? '—'}</span></p>
          <p><span className="text-slate-500">{t('firmware.latest')}:</span> <span className="font-mono">{check.latest ?? '—'}</span></p>
          <p><span className="text-slate-500">{t('firmware.channel')}:</span> <span className="font-mono">{check.channel ?? '—'}</span></p>
          <p><span className="text-slate-500">{t('firmware.status')}:</span> <span>{check.status ?? '—'}</span></p>
        </div>
      )}
      {checkError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
          {checkError}
        </div>
      )}
      {doBackup.data && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-sm text-green-800">
          Backup: {(doBackup.data as any).filename ?? '—'}
        </div>
      )}

      {status && status.status !== 'no_job' && (
        <div className="bg-slate-100 rounded-lg p-3 text-sm space-y-1">
          <p className="font-semibold text-slate-800">{t('firmware.jobStatus')}: {status.status}</p>
          {status.old_version && <p className="text-xs">{t('firmware.oldVersion')}: <span className="font-mono">{status.old_version}</span></p>}
          {status.new_version && <p className="text-xs">{t('firmware.newVersion')}: <span className="font-mono">{status.new_version}</span></p>}
          {status.log && status.log.length > 0 && (
            <div className="mt-2 max-h-48 overflow-auto bg-slate-900 text-green-300 p-2 rounded text-[10px] font-mono">
              {status.log.map((l: string, i: number) => <div key={i}>{l}</div>)}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function NetworkMonitoringTab({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation()
  const qc = useQueryClient()

  const { data: device } = useQuery({ queryKey: ['device', deviceId], queryFn: () => devicesApi.get(deviceId) })
  const threshold = device?.iface_mbps_threshold
  const [thresholdInput, setThresholdInput] = useState<string>('')
  const [touched, setTouched] = useState(false)
  const displayValue = touched ? thresholdInput : (threshold != null ? String(threshold) : '')

  const { data: interfaces = [], isLoading } = useQuery({
    queryKey: ['device', deviceId, 'interface-stats'],
    queryFn: () => devicesApi.interfaceStats(deviceId),
    refetchInterval: 30_000,
  })

  const saveThreshold = useMutation({
    mutationFn: (mbps: number | null) => devicesApi.setIfaceThreshold(deviceId, mbps),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['device', deviceId] }); setTouched(false) },
  })

  return (
    <div className="space-y-4 py-2">
      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2">
        <p className="text-xs font-semibold text-slate-700">{t('deviceDetail.ifaceThresholdTitle')}</p>
        <p className="text-xs text-slate-500">{t('deviceDetail.ifaceThresholdHint')}</p>
        <div className="flex items-center gap-2">
          <input
            type="number" min={0} step={1}
            value={displayValue}
            onChange={e => { setTouched(true); setThresholdInput(e.target.value) }}
            placeholder={t('deviceDetail.ifaceThresholdPlaceholder') as string}
            className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm w-40 font-mono"
          />
          <Button
            variant="secondary"
            onClick={() => saveThreshold.mutate(displayValue.trim() === '' ? null : parseFloat(displayValue))}
            disabled={saveThreshold.isPending}
          >
            {t('common.save')}
          </Button>
        </div>
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500 py-4 text-center">{t('common.loading')}</p>
      ) : interfaces.length === 0 ? (
        <p className="text-sm text-slate-500 py-4 text-center">{t('common.noData')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-200">
                <th className="px-3 py-2 text-left text-slate-500 font-medium">{t('deviceDetail.ifaceName')}</th>
                <th className="px-3 py-2 text-left text-slate-500 font-medium">RX Mbps</th>
                <th className="px-3 py-2 text-left text-slate-500 font-medium">TX Mbps</th>
                <th className="px-3 py-2 text-left text-slate-500 font-medium">{t('deviceDetail.ifaceErrors')}</th>
                <th className="px-3 py-2 text-left text-slate-500 font-medium">{t('deviceDetail.ifaceDrops')}</th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map(i => {
                const overThreshold = threshold != null && Math.max(i.rx_mbps ?? 0, i.tx_mbps ?? 0) >= threshold
                const hasErrors = (i.rx_errors ?? 0) > 0 || (i.tx_errors ?? 0) > 0
                return (
                  <tr key={i.iface_name} className="border-b border-slate-200 hover:bg-slate-50">
                    <td className="px-3 py-2 text-slate-700 font-mono">{i.iface_name}</td>
                    <td className={cn('px-3 py-2 font-mono', overThreshold ? 'text-red-600 font-semibold' : 'text-slate-700')}>
                      {i.rx_mbps != null ? i.rx_mbps.toFixed(1) : '—'}
                    </td>
                    <td className={cn('px-3 py-2 font-mono', overThreshold ? 'text-red-600 font-semibold' : 'text-slate-700')}>
                      {i.tx_mbps != null ? i.tx_mbps.toFixed(1) : '—'}
                    </td>
                    <td className={cn('px-3 py-2 font-mono', hasErrors ? 'text-red-600 font-semibold' : 'text-slate-700')}>
                      {(i.rx_errors ?? 0)} / {(i.tx_errors ?? 0)}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-700">{(i.rx_drops ?? 0)} / {(i.tx_drops ?? 0)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function TabContent({ deviceId, tab }: { deviceId: number; tab: Tab }) {
  const { t } = useTranslation()
  if (tab === 'firmware') return <FirmwareTab deviceId={deviceId} />
  if (tab === 'network') return <NetworkMonitoringTab deviceId={deviceId} />
  const queries: Record<Exclude<Tab, 'firmware' | 'network'>, () => Promise<unknown>> = {
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
    queryFn: queries[tab as Exclude<Tab, 'firmware' | 'network'>],
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
    // Every section here is now a nested {peers|interfaces: [...], error?:
    // string} shape (see MikrotikClient.get_wireguard_status/
    // get_ipsec_status/get_simple_tunnel_interfaces) — passing that object
    // straight to DataTable (which expects a flat array) used to crash
    // this section silently, since `data[0]` on a plain object is
    // undefined and Object.keys(undefined) throws.
    const t2 = data as Record<string, unknown>
    return (
      <div className="space-y-4">
        {Object.entries(t2).map(([type, value]) => {
          const v = (value ?? {}) as { peers?: Record<string, unknown>[]; interfaces?: Record<string, unknown>[]; error?: string | null }
          const rows = v.peers ?? v.interfaces ?? []
          return (
            <div key={type}>
              <h3 className="text-xs font-semibold text-slate-600 uppercase mb-2">{type}</h3>
              {v.error && <p className="text-xs text-red-600 mb-2">{v.error}</p>}
              <DataTable data={rows} emptyLabel={t('common.noData')} />
            </div>
          )
        })}
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
    { id: 'network', label: t('deviceDetail.tabs.network'), icon: Gauge },
    { id: 'firmware', label: t('deviceDetail.tabs.firmware'), icon: Download },
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
      <div className="flex gap-2 flex-wrap">
        {device.has_api && <Badge variant="blue">API :{device.api_port}</Badge>}
        {device.has_ssh && <Badge variant="gray">SSH :{device.ssh_port}</Badge>}
        {device.has_web && <Badge variant="yellow">Web :{device.web_port}</Badge>}
        {device.has_snmp && <Badge variant="purple">SNMP :{device.snmp_port}</Badge>}
        {device.mem_used_pct != null && (
          <Badge variant={device.mem_used_pct >= 90 ? 'red' : device.mem_used_pct >= 75 ? 'yellow' : 'green'}>
            <MemoryStick size={12} /> {device.mem_used_pct}%
          </Badge>
        )}
        {device.disk_used_pct != null && (
          <Badge variant={device.disk_used_pct >= 90 ? 'red' : device.disk_used_pct >= 75 ? 'yellow' : 'green'}>
            <HardDrive size={12} /> {device.disk_used_pct}%
          </Badge>
        )}
        {device.cpu_load_pct != null && (
          <Badge variant={device.cpu_load_pct >= 90 ? 'red' : device.cpu_load_pct >= 75 ? 'yellow' : 'gray'}>
            <Cpu size={12} /> {device.cpu_load_pct}%
          </Badge>
        )}
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

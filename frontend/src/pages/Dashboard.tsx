import { useQuery } from '@tanstack/react-query'
import { devicesApi, systemApi, centralApi, centralConfig, type ActivityEntry, type FirmwareComplianceDevice } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Server, Wifi, CheckCircle2, XCircle, AlertOctagon, RefreshCw, Activity, ShieldCheck } from 'lucide-react'
import { formatDate } from '../lib/utils'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'

function ComplianceBar({ label, pct, known, total }: { label: string; pct: number | null; known: number; total: number }) {
  const { t } = useTranslation()
  const color = pct === null ? 'bg-slate-200' : pct >= 90 ? 'bg-green-500' : pct >= 70 ? 'bg-amber-500' : 'bg-red-500'
  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-slate-600">{label}</span>
        <span className="text-slate-500">
          {pct === null ? t('dashboard.complianceNoData') : `${pct}% (${known}/${total})`}
        </span>
      </div>
      <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct ?? 0}%` }} />
      </div>
    </div>
  )
}

function FirmwareComplianceCard() {
  const { t } = useTranslation()
  const { data } = useQuery({
    queryKey: ['firmware-compliance'],
    queryFn: systemApi.firmwareCompliance,
    refetchInterval: 60_000,
  })
  if (!data || data.total_devices === 0) return null

  const nonCompliant: FirmwareComplianceDevice[] = data.devices.filter(
    d => d.ros_status === 'outdated' || d.firmware_status === 'outdated'
  )

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldCheck size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('dashboard.firmwareCompliance')}</h2>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <ComplianceBar
            label={t('dashboard.complianceRos')}
            pct={data.ros_compliant_pct}
            known={data.ros_compliant_count}
            total={data.ros_known_count}
          />
          <ComplianceBar
            label={t('dashboard.complianceFirmware')}
            pct={data.firmware_compliant_pct}
            known={data.firmware_compliant_count}
            total={data.firmware_known_count}
          />
        </div>
        {data.ros_via_global_fallback_count > 0 && (
          <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            {t('dashboard.complianceFallbackWarning', { count: data.ros_via_global_fallback_count })}
            {data.latest_fetch_info.last_error && (
              <> {t('dashboard.complianceFetchError', { error: data.latest_fetch_info.last_error })}</>
            )}
          </p>
        )}
        {nonCompliant.length > 0 && (
          <div className="border-t border-slate-100 pt-3">
            <p className="text-xs text-slate-500 mb-2">{t('dashboard.complianceNonCompliant')}</p>
            <ul className="space-y-1.5">
              {nonCompliant.slice(0, 8).map(d => (
                <li key={d.device_id} className="flex items-center justify-between text-xs">
                  <Link to={`/devices/${d.device_id}`} className="text-indigo-600 hover:underline font-medium">
                    {d.name}
                  </Link>
                  <span className="text-slate-500 font-mono">
                    {d.ros_status === 'outdated' && `RouterOS ${d.ros_version} → ${d.ros_target}`}
                    {d.ros_status === 'outdated' && d.ros_source === 'global_fallback' && ` (${t('dashboard.complianceFallbackTag')})`}
                    {d.ros_status === 'outdated' && d.firmware_status === 'outdated' && ' · '}
                    {d.firmware_status === 'outdated' && `FW ${d.firmware_current} → ${d.firmware_target}`}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function StatCard({ label, value, icon: Icon, color }: { label: string; value: number; icon: React.ElementType; color: string }) {
  return (
    <Card className="flex items-center gap-4 px-5 py-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
        <Icon size={20} />
      </div>
      <div>
        <p className="text-2xl font-bold text-slate-900">{value}</p>
        <p className="text-xs text-slate-500">{label}</p>
      </div>
    </Card>
  )
}

function topicColor(topics?: string) {
  const t = (topics ?? '').toLowerCase()
  if (t.includes('critical')) return 'text-red-700 bg-red-50 border-red-200'
  if (t.includes('error')) return 'text-red-600 bg-red-50 border-red-100'
  return 'text-amber-700 bg-amber-50 border-amber-200'
}

function activityIcon(type: string): string {
  switch (type) {
    case 'firmware_upgraded': return '✅'
    case 'firmware_upgrade_failed': return '❌'
    case 'agent_updated': return '🔄'
    case 'backup_completed': return '💾'
    default: return '•'
  }
}

function ActivityLogCard() {
  const { t } = useTranslation()
  const enabled = !!centralConfig.load()
  const { data, isLoading } = useQuery({
    queryKey: ['central-activity'],
    queryFn: () => centralApi.activityLog(undefined, 30),
    refetchInterval: 30_000,
    enabled,
  })
  if (!enabled) return null
  const items: ActivityEntry[] = data?.activity ?? []
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Activity size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('dashboard.activityLog')}</h2>
          {items.length > 0 && <Badge variant="gray">{items.length}</Badge>}
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading && items.length === 0 ? (
          <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('common.loading')}</p>
        ) : items.length === 0 ? (
          <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('dashboard.noActivity')}</p>
        ) : (
          <ul className="divide-y divide-slate-200">
            {items.map(a => (
              <li key={a.id} className="px-5 py-2.5 flex items-start gap-3 hover:bg-slate-50">
                <span className="text-lg leading-none pt-0.5">{activityIcon(a.event_type)}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-slate-800">{a.message}</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    <span className="font-medium text-indigo-600">{a.tenant}</span>
                    {' · '}
                    <span className="font-mono">{new Date(a.ts).toLocaleString()}</span>
                  </p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

export function Dashboard() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: devices = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })
  const { data: criticalLogs = [], isLoading: logsLoading } = useQuery({
    queryKey: ['critical-logs'],
    queryFn: () => systemApi.criticalLogs(20),
    refetchInterval: 60_000,
  })

  const online = devices.filter(d => d.online).length
  const offline = devices.length - online
  const recent = [...devices].sort((a, b) =>
    new Date(b.last_seen ?? 0).getTime() - new Date(a.last_seen ?? 0).getTime()
  ).slice(0, 8)

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-900">{t('dashboard.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('dashboard.subtitle')}</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label={t('dashboard.totalDevices')} value={devices.length} icon={Server} color="bg-indigo-50 text-indigo-600" />
        <StatCard label={t('common.online')} value={online} icon={CheckCircle2} color="bg-green-50 text-green-600" />
        <StatCard label={t('common.offline')} value={offline} icon={XCircle} color="bg-red-50 text-red-600" />
        <StatCard label={t('dashboard.noCredentials')} value={devices.filter(d => !d.credential_id).length} icon={Wifi} color="bg-amber-50 text-amber-600" />
      </div>

      <ActivityLogCard />
      <FirmwareComplianceCard />

      {/* Critical logs */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertOctagon size={15} className="text-red-600" />
              <h2 className="text-sm font-semibold text-slate-700">{t('dashboard.criticalLogs')}</h2>
              {criticalLogs.length > 0 && (
                <Badge variant="red">{criticalLogs.length}</Badge>
              )}
            </div>
            <button
              onClick={() => qc.invalidateQueries({ queryKey: ['critical-logs'] })}
              className="text-slate-400 hover:text-indigo-600"
              title={t('common.refresh') as string}
            >
              <RefreshCw size={12} className={logsLoading ? 'animate-spin' : ''} />
            </button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {logsLoading && criticalLogs.length === 0 ? (
            <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('common.loading')}</p>
          ) : criticalLogs.length === 0 ? (
            <div className="px-5 py-10 text-center">
              <CheckCircle2 size={28} className="mx-auto text-green-500 mb-2" />
              <p className="text-slate-500 text-sm">{t('dashboard.noCriticalLogs')}</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-xs text-slate-500">
                    <th className="px-5 py-3 text-left">{t('dashboard.criticalCols.device')}</th>
                    <th className="px-5 py-3 text-left">{t('dashboard.criticalCols.time')}</th>
                    <th className="px-5 py-3 text-left">{t('dashboard.criticalCols.topics')}</th>
                    <th className="px-5 py-3 text-left">{t('dashboard.criticalCols.message')}</th>
                  </tr>
                </thead>
                <tbody>
                  {criticalLogs.map((l, i) => (
                    <tr key={i} className="border-b border-slate-200 hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-2.5">
                        <Link to={`/devices/${l.device_id}`}
                          className="text-indigo-600 hover:underline font-medium block">{l.device_label}</Link>
                        <span className="text-[10px] text-slate-400 font-mono">{l.device_ip}</span>
                      </td>
                      <td className="px-5 py-2.5 font-mono text-xs text-slate-600 whitespace-nowrap">{l.time ?? ''}</td>
                      <td className="px-5 py-2.5">
                        <span className={`inline-block px-1.5 py-0.5 rounded border text-[10px] font-mono ${topicColor(l.topics)}`}>
                          {l.topics ?? ''}
                        </span>
                      </td>
                      <td className="px-5 py-2.5 text-slate-700 text-xs break-all">{l.message ?? ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">{t('dashboard.recentlySeen')}</h2>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('common.loading')}</p>
          ) : devices.length === 0 ? (
            <div className="px-5 py-10 text-center">
              <Server size={32} className="mx-auto text-slate-300 mb-3" />
              <p className="text-slate-500 text-sm">{t('dashboard.noDevicesYet')}</p>
              <Link to="/scanner" className="text-indigo-600 text-sm hover:underline mt-1 inline-block">{t('dashboard.goToScanner')}</Link>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs text-slate-500">
                  <th className="px-5 py-3 text-left">{t('dashboard.cols.ip')}</th>
                  <th className="px-5 py-3 text-left">{t('dashboard.cols.identity')}</th>
                  <th className="px-5 py-3 text-left">{t('dashboard.cols.model')}</th>
                  <th className="px-5 py-3 text-left">{t('dashboard.cols.ros')}</th>
                  <th className="px-5 py-3 text-left">{t('dashboard.cols.status')}</th>
                  <th className="px-5 py-3 text-left">{t('dashboard.cols.lastSeen')}</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(d => (
                  <tr key={d.id} className="border-b border-slate-200 hover:bg-slate-50 transition-colors">
                    <td className="px-5 py-3">
                      <Link to={`/devices/${d.id}`} className="text-indigo-600 hover:underline font-mono">{d.ip}</Link>
                    </td>
                    <td className="px-5 py-3 text-slate-700">{d.identity || d.name || '—'}</td>
                    <td className="px-5 py-3 text-slate-600">{d.model || '—'}</td>
                    <td className="px-5 py-3 text-slate-600 font-mono text-xs">{d.ros_version || '—'}</td>
                    <td className="px-5 py-3">
                      <Badge variant={d.online ? 'green' : 'red'}>{d.online ? t('common.online') : t('common.offline')}</Badge>
                    </td>
                    <td className="px-5 py-3 text-slate-500 text-xs">{formatDate(d.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

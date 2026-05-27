import { useQuery } from '@tanstack/react-query'
import { devicesApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Server, Wifi, CheckCircle2, XCircle } from 'lucide-react'
import { formatDate } from '../lib/utils'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

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

export function Dashboard() {
  const { t } = useTranslation()
  const { data: devices = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })

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

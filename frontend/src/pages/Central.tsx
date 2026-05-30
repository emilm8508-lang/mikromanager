import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { systemApi, centralApi, centralConfig, CentralConfig, CentralTenant } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import {
  Cloud, Settings, Send, CheckCircle2, XCircle, AlertTriangle,
  Server, Network, ChevronRight, Wifi, WifiOff, RefreshCw,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

function formatAge(sec: number | null): string {
  if (sec === null || sec === undefined) return '—'
  if (sec < 60) return `${sec}s`
  if (sec < 3600) return `${Math.floor(sec / 60)}m`
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`
  return `${Math.floor(sec / 86400)}d`
}

// ── Agent uplink config panel (used at customer site) ────────────────────────

function UplinkPanel() {
  const { t } = useTranslation()
  const { data: status, refetch } = useQuery({
    queryKey: ['uplink-status'],
    queryFn: systemApi.uplinkStatus,
    refetchInterval: 10_000,
  })

  const [form, setForm] = useState({
    url: '',
    tenant: '',
    api_key: '',
    interval_sec: 120,
  })
  const [editing, setEditing] = useState(false)

  useEffect(() => {
    if (status && !editing) {
      setForm({
        url: status.url || '',
        tenant: status.tenant || '',
        api_key: '',  // never sent back from server
        interval_sec: status.interval_sec || 120,
      })
    }
  }, [status, editing])

  const save = useMutation({
    mutationFn: () => systemApi.uplinkConfigure(form),
    onSuccess: () => { setEditing(false); refetch() },
  })

  const sendNow = useMutation({
    mutationFn: systemApi.uplinkSendNow,
    onSuccess: () => refetch(),
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cloud size={15} className="text-indigo-600" />
            <h2 className="text-sm font-semibold text-slate-700">{t('central.agentUplink')}</h2>
            {status?.enabled ? (
              <Badge variant="green">{t('central.enabled')}</Badge>
            ) : (
              <Badge variant="gray">{t('central.disabled')}</Badge>
            )}
          </div>
          {!editing && (
            <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>
              <Settings size={13} /> {t('common.edit')}
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {editing ? (
          <form onSubmit={e => { e.preventDefault(); save.mutate() }} className="space-y-3">
            <Input label={t('central.serverUrl')} placeholder="https://example.com/mm/ingest.php"
              value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} required />
            <div className="grid grid-cols-2 gap-3">
              <Input label={t('central.tenantId')} placeholder="klient-a"
                value={form.tenant} onChange={e => setForm(f => ({ ...f, tenant: e.target.value }))} required />
              <Input label={t('central.intervalSec')} type="number" min={30}
                value={form.interval_sec}
                onChange={e => setForm(f => ({ ...f, interval_sec: Number(e.target.value) }))} />
            </div>
            <Input label={t('central.apiKey')} type="password"
              placeholder={status?.has_api_key ? t('central.apiKeyKeep') as string : ''}
              value={form.api_key} onChange={e => setForm(f => ({ ...f, api_key: e.target.value }))} />
            <div className="flex gap-2 justify-end pt-1">
              <Button type="button" variant="ghost" onClick={() => setEditing(false)}>{t('common.cancel')}</Button>
              <Button type="submit" variant="primary">{t('common.save')}</Button>
            </div>
          </form>
        ) : (
          <div className="space-y-2 text-sm">
            <div className="grid grid-cols-[120px_1fr] gap-y-1.5">
              <span className="text-slate-500">URL:</span>
              <span className="font-mono text-xs text-slate-800 break-all">{status?.url || '—'}</span>
              <span className="text-slate-500">Tenant:</span>
              <span className="text-slate-800">{status?.tenant || '—'}</span>
              <span className="text-slate-500">{t('central.interval')}:</span>
              <span className="text-slate-800">{status?.interval_sec ?? '—'} s</span>
              <span className="text-slate-500">{t('central.lastSent')}:</span>
              <span className="text-slate-800">{status?.last_sent ?? '—'}</span>
              <span className="text-slate-500">{t('central.totalSent')}:</span>
              <span className="text-slate-800">
                <span className="text-green-700">{status?.total_sent ?? 0}</span>
                {' / '}
                <span className="text-red-700">{status?.total_failed ?? 0} {t('central.failed')}</span>
              </span>
              {status?.buffered_count ? (
                <>
                  <span className="text-slate-500">{t('central.buffered')}:</span>
                  <span className="text-amber-700">{status.buffered_count}</span>
                </>
              ) : null}
              {status?.last_error && (
                <>
                  <span className="text-slate-500">{t('central.lastError')}:</span>
                  <span className="text-red-700 text-xs break-words">{status.last_error}</span>
                </>
              )}
            </div>
            <div className="pt-2 flex gap-2">
              <Button size="sm" variant="secondary" onClick={() => sendNow.mutate()}
                disabled={!status?.enabled || sendNow.isPending}>
                <Send size={13} /> {t('central.sendNow')}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Viewer panel (used on your laptop) ───────────────────────────────────────

function ViewerConfigForm({ onSaved }: { onSaved: () => void }) {
  const { t } = useTranslation()
  const existing = centralConfig.load()
  const [form, setForm] = useState<CentralConfig>({
    apiUrl: existing?.apiUrl || '',
    password: existing?.password || '',
  })

  const save = (e: React.FormEvent) => {
    e.preventDefault()
    centralConfig.save(form)
    onSaved()
  }

  return (
    <form onSubmit={save} className="space-y-3">
      <Input label={t('central.viewerApiUrl')} placeholder="https://example.com/mm/api.php"
        value={form.apiUrl} onChange={e => setForm(f => ({ ...f, apiUrl: e.target.value }))} required />
      <Input label={t('central.viewerPassword')} type="password"
        value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
      <div className="flex gap-2 justify-end">
        <Button type="submit" variant="primary">{t('common.save')}</Button>
      </div>
    </form>
  )
}

function TenantRow({ tenant, threshold, onSelect }: {
  tenant: CentralTenant; threshold: number; onSelect: (t: string) => void
}) {
  const Icon = tenant.online ? Wifi : WifiOff
  return (
    <button
      onClick={() => onSelect(tenant.id)}
      className="w-full flex items-center gap-3 px-5 py-3 hover:bg-slate-50 border-b border-slate-200 text-left transition-colors"
    >
      <Icon size={16} className={tenant.online ? 'text-green-600' : 'text-red-600'} />
      <div className="flex-1 min-w-0">
        <p className="font-medium text-slate-900">{tenant.id}</p>
        <p className="text-xs text-slate-500">
          {tenant.last_seen ?? '—'} · {tenant.last_payload_bytes} B
        </p>
      </div>
      <Badge variant={tenant.online ? 'green' : 'red'}>
        {tenant.age_sec !== null ? formatAge(tenant.age_sec) : '—'}
      </Badge>
      <ChevronRight size={14} className="text-slate-400" />
    </button>
  )
}

function TenantSnapshot({ tenantId }: { tenantId: string }) {
  const { t } = useTranslation()
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['central-snapshot', tenantId],
    queryFn: () => centralApi.snapshot(tenantId),
    refetchInterval: 30_000,
  })

  if (isLoading) return <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('common.loading')}</p>
  if (error) return <p className="px-5 py-8 text-center text-red-600 text-sm">{String(error)}</p>
  if (!data) return <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('central.noSnapshot')}</p>

  const devices = data.devices ?? []
  const critical = data.critical_logs ?? []
  const isStale = !data.online

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 bg-white border border-slate-200 rounded-lg px-4 py-3 text-sm">
        {isStale ? (
          <AlertTriangle size={16} className="text-amber-600" />
        ) : (
          <CheckCircle2 size={16} className="text-green-600" />
        )}
        <div className="flex-1">
          <p className="text-slate-700">
            {t('central.snapshotFrom')}: <span className="font-mono">{data.received_at}</span>
            {' '}({formatAge(data.age_sec)} {t('central.ago')})
          </p>
          {isStale && (
            <p className="text-xs text-amber-700 mt-0.5">{t('central.staleWarning')}</p>
          )}
        </div>
        <button onClick={() => refetch()} className="text-slate-400 hover:text-indigo-600">
          <RefreshCw size={13} />
        </button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
              <Server size={14} /> {t('central.devicesAt', { count: devices.length })}
            </h3>
            <div className="flex gap-2 text-xs">
              <span className="text-green-700">● {data.devices_online ?? 0} {t('common.online')}</span>
              <span className="text-red-700">● {(devices.length - (data.devices_online ?? 0))} {t('common.offline')}</span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs text-slate-500">
                  <th className="px-5 py-2.5 text-left">IP</th>
                  <th className="px-5 py-2.5 text-left">{t('dashboard.cols.identity')}</th>
                  <th className="px-5 py-2.5 text-left">{t('dashboard.cols.model')}</th>
                  <th className="px-5 py-2.5 text-left">ROS</th>
                  <th className="px-5 py-2.5 text-left">{t('dashboard.cols.status')}</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d: any) => (
                  <tr key={d.id} className="border-b border-slate-200">
                    <td className="px-5 py-2 font-mono text-xs text-slate-700">{d.ip}</td>
                    <td className="px-5 py-2 text-slate-700">{d.identity || d.name || '—'}</td>
                    <td className="px-5 py-2 text-slate-600">{d.model || '—'}</td>
                    <td className="px-5 py-2 font-mono text-xs text-slate-600">{d.ros_version || '—'}</td>
                    <td className="px-5 py-2">
                      <Badge variant={d.online ? 'green' : 'red'}>
                        {d.online ? t('common.online') : t('common.offline')}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {critical.length > 0 && (
        <Card>
          <CardHeader>
            <h3 className="text-sm font-semibold text-slate-700">{t('dashboard.criticalLogs')}</h3>
          </CardHeader>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs text-slate-500">
                  <th className="px-5 py-2 text-left">{t('dashboard.criticalCols.device')}</th>
                  <th className="px-5 py-2 text-left">{t('dashboard.criticalCols.time')}</th>
                  <th className="px-5 py-2 text-left">{t('dashboard.criticalCols.message')}</th>
                </tr>
              </thead>
              <tbody>
                {critical.map((l: any, i: number) => (
                  <tr key={i} className="border-b border-slate-200">
                    <td className="px-5 py-1.5 text-slate-700">{l.device_label}</td>
                    <td className="px-5 py-1.5 font-mono text-xs text-slate-500">{l.time}</td>
                    <td className="px-5 py-1.5 text-xs text-slate-700 break-all">{l.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function ViewerPanel() {
  const { t } = useTranslation()
  const [configured, setConfigured] = useState(!!centralConfig.load())
  const [selectedTenant, setSelectedTenant] = useState<string | null>(null)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['central-tenants'],
    queryFn: centralApi.tenants,
    enabled: configured,
    refetchInterval: 30_000,
  })

  if (!configured) {
    return (
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
            <Network size={15} className="text-indigo-600" />
            {t('central.viewerSetup')}
          </h2>
        </CardHeader>
        <CardContent>
          <ViewerConfigForm onSaved={() => setConfigured(true)} />
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
              <Network size={15} className="text-indigo-600" />
              {t('central.tenants')}
              {data && <Badge variant="gray">{data.tenants.length}</Badge>}
            </h2>
            <div className="flex gap-2">
              <button onClick={() => refetch()} className="text-slate-400 hover:text-indigo-600" title={t('common.refresh') as string}>
                <RefreshCw size={13} />
              </button>
              <button
                onClick={() => { centralConfig.clear(); setConfigured(false); setSelectedTenant(null) }}
                className="text-slate-400 hover:text-red-600"
                title={t('central.clearConfig') as string}
              >
                <XCircle size={13} />
              </button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="px-5 py-6 text-center text-slate-500 text-sm">{t('common.loading')}</p>
          ) : error ? (
            <p className="px-5 py-6 text-center text-red-600 text-sm">{String(error)}</p>
          ) : data && data.tenants.length === 0 ? (
            <p className="px-5 py-6 text-center text-slate-500 text-sm">{t('central.noTenants')}</p>
          ) : (
            data?.tenants.map(t => (
              <TenantRow key={t.id} tenant={t}
                threshold={data.offline_threshold_sec}
                onSelect={setSelectedTenant} />
            ))
          )}
        </CardContent>
      </Card>

      {selectedTenant && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <h2 className="text-base font-bold text-slate-900">{selectedTenant}</h2>
            <Badge variant="blue">{t('central.viewing')}</Badge>
          </div>
          <TenantSnapshot tenantId={selectedTenant} />
        </div>
      )}
    </div>
  )
}

// ── Top-level page ───────────────────────────────────────────────────────────

export function Central() {
  const { t } = useTranslation()
  const [tab, setTab] = useState<'agent' | 'viewer'>('viewer')

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-slate-900">{t('central.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('central.subtitle')}</p>
      </div>

      <div className="flex border-b border-slate-200">
        <button onClick={() => setTab('viewer')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            tab === 'viewer' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}>
          {t('central.tabViewer')}
        </button>
        <button onClick={() => setTab('agent')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            tab === 'agent' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}>
          {t('central.tabAgent')}
        </button>
      </div>

      {tab === 'viewer' ? <ViewerPanel /> : <UplinkPanel />}
    </div>
  )
}

import { useState, useEffect, Fragment } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { systemApi, centralApi, centralConfig, CentralConfig, CentralTenant, DeviceLogFetchResult, generateEncKey } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import {
  Cloud, Settings, Send, CheckCircle2, XCircle, AlertTriangle,
  Server, Network, ChevronRight, Wifi, WifiOff, RefreshCw, Shield, ShieldOff, Lock,
  HardDrive, Trash2, GitCommit, Download, FileText, ChevronDown, ChevronUp, Upload,
  DatabaseBackup,
} from 'lucide-react'
import { TenantBadge, tenantColor } from '../components/ui/TenantBadge'
import { useTranslation } from 'react-i18next'
import { AlertsPanel } from './CentralAlerts'
import { UsersPanel } from './CentralUsers'
import { AnydeskPanel } from './CentralAnyDesk'
import { Modal } from '../components/ui/Modal'

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
    enc_key: '',
  })
  const [editing, setEditing] = useState(false)
  const [showGeneratedKey, setShowGeneratedKey] = useState<string | null>(null)

  useEffect(() => {
    if (status && !editing) {
      setForm({
        url: status.url || '',
        tenant: status.tenant || '',
        api_key: '',
        interval_sec: status.interval_sec || 120,
        enc_key: '',
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

            <div className="border-t border-slate-200 pt-3">
              <div className="flex items-center gap-2 mb-2">
                <Lock size={13} className="text-indigo-600" />
                <span className="text-xs font-medium text-slate-700">{t('central.e2eHeader')}</span>
                {status?.has_enc_key && <Badge variant="green">{t('central.e2eActive')}</Badge>}
              </div>
              <Input label={t('central.encKey')} type="password"
                placeholder={status?.has_enc_key ? t('central.encKeyKeep') as string : 'base64 32 bytes'}
                value={form.enc_key} onChange={e => setForm(f => ({ ...f, enc_key: e.target.value }))} />
              <div className="flex items-center justify-between mt-2 gap-2">
                <p className="text-[11px] text-slate-500">{t('central.e2eHint')}</p>
                <div className="flex gap-2 shrink-0 ml-2">
                  {status?.has_enc_key && (
                    <button type="button" onClick={async () => {
                      const k = await systemApi.uplinkGetEncKey()
                      setShowGeneratedKey(k.enc_key)
                    }}
                      className="text-xs text-indigo-600 hover:underline">
                      {t('central.showCurrentKey')}
                    </button>
                  )}
                  <button type="button" onClick={async () => {
                    const k = await systemApi.uplinkGenerateEncKey()
                    setForm(f => ({ ...f, enc_key: k.enc_key }))
                    setShowGeneratedKey(k.enc_key)
                  }}
                    className="text-xs text-indigo-600 hover:underline">
                    {t('central.generateKey')}
                  </button>
                </div>
              </div>
              {showGeneratedKey && (
                <div className="mt-2 p-2 bg-amber-50 border border-amber-200 rounded text-[11px]">
                  <p className="font-semibold text-amber-700 mb-1">{t('central.saveKeyWarn')}</p>
                  <p className="font-mono break-all text-amber-900">{showGeneratedKey}</p>
                </div>
              )}
            </div>

            <div className="flex gap-2 justify-end pt-1">
              <Button type="button" variant="ghost" onClick={() => { setEditing(false); setShowGeneratedKey(null) }}>{t('common.cancel')}</Button>
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
              <span className="text-slate-500">E2E:</span>
              <span className="text-slate-800 flex items-center gap-1">
                {status?.has_enc_key ? (
                  <><Shield size={12} className="text-green-600" /> <span className="text-green-700 font-medium">{t('central.e2eActive')}</span></>
                ) : (
                  <><ShieldOff size={12} className="text-amber-600" /> <span className="text-amber-700">{t('central.e2eOff')}</span></>
                )}
              </span>
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
    tenantKeys: existing?.tenantKeys,
    totpSecret: existing?.totpSecret || '',
  })

  const save = (e: React.FormEvent) => {
    e.preventDefault()
    centralConfig.save({ ...form, totpSecret: form.totpSecret || undefined })
    onSaved()
  }

  return (
    <form onSubmit={save} className="space-y-3">
      <Input label={t('central.viewerApiUrl')} placeholder="https://example.com/mm/api.php"
        value={form.apiUrl} onChange={e => setForm(f => ({ ...f, apiUrl: e.target.value }))} required />
      <Input label={t('central.viewerPassword')} type="password"
        value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
      <Input label={t('central.totpSecretLabel')} type="password" placeholder={t('central.totpSecretPlaceholder') as string}
        value={form.totpSecret || ''} onChange={e => setForm(f => ({ ...f, totpSecret: e.target.value }))} />
      <p className="text-xs text-slate-500">{t('central.totpSecretHint')}</p>
      <div className="flex gap-2 justify-end">
        <Button type="submit" variant="primary">{t('common.save')}</Button>
      </div>
    </form>
  )
}

function TenantRow({ tenant, viewerCommit, viewerCommitTime, pendingUpdate, pendingRestart }: {
  tenant: CentralTenant
  viewerCommit: string | null
  viewerCommitTime: number | null
  pendingUpdate: boolean
  pendingRestart: boolean
}) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const Icon = tenant.online ? Wifi : WifiOff
  const c = tenantColor(tenant.id)

  const trigger = useMutation({
    mutationFn: () => centralApi.requestUpdate(tenant.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['central-pending-updates'] }) },
  })

  const triggerRestart = useMutation({
    mutationFn: () => centralApi.requestRestart(tenant.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['central-pending-restarts'] }) },
  })

  const [showBackups, setShowBackups] = useState(false)

  // Two-click confirm — browser confirm() gets blocked after N dialogs
  // (Firefox "prevent additional dialogs" checkbox), so we do it inline.
  const [confirmMode, setConfirmMode] = useState<'update' | 'restart' | null>(null)
  useEffect(() => {
    if (!confirmMode) return
    const to = setTimeout(() => setConfirmMode(null), 5000)
    return () => clearTimeout(to)
  }, [confirmMode])

  const handleUpdate = () => {
    if (confirmMode === 'update') { trigger.mutate(); setConfirmMode(null) }
    else setConfirmMode('update')
  }
  const handleRestart = () => {
    if (confirmMode === 'restart') { triggerRestart.mutate(); setConfirmMode(null) }
    else setConfirmMode('restart')
  }

  // Determine version status
  let versionBadge: React.ReactNode = null
  if (tenant.agent_commit) {
    if (viewerCommit && tenant.agent_commit === viewerCommit) {
      versionBadge = <Badge variant="green" className="text-[10px]">{t('central.versionCurrent')}</Badge>
    } else if (viewerCommitTime && tenant.agent_commit_time) {
      const behindSec = viewerCommitTime - tenant.agent_commit_time
      if (behindSec > 60) {
        versionBadge = (
          <Badge variant="yellow" className="text-[10px]">
            {t('central.versionOlder', { age: formatAge(behindSec) })}
          </Badge>
        )
      } else if (behindSec < -60) {
        versionBadge = <Badge variant="blue" className="text-[10px]">{t('central.versionNewer')}</Badge>
      } else {
        versionBadge = <Badge variant="gray" className="text-[10px]">≈ {t('central.versionCurrent')}</Badge>
      }
    }
  }

  const canUpdate = tenant.agent_commit && viewerCommit && tenant.agent_commit !== viewerCommit
  const behindTarget = viewerCommitTime && tenant.agent_commit_time && (viewerCommitTime > tenant.agent_commit_time)

  return (
    <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-200">
      <span className={`inline-block w-1 h-10 rounded ${c.bg.replace('-100', '-500')}`} />
      <Icon size={16} className={tenant.online ? 'text-green-600' : 'text-red-600'} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <TenantBadge tenant={tenant.id} />
          {versionBadge}
          {pendingUpdate && (
            <Badge variant="yellow" className="text-[10px] inline-flex items-center gap-1">
              <Download size={9} /> {t('central.updateQueued')}
            </Badge>
          )}
          {pendingRestart && (
            <Badge variant="yellow" className="text-[10px] inline-flex items-center gap-1">
              <RefreshCw size={9} /> {t('central.restartQueued')}
            </Badge>
          )}
        </div>
        <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-3 flex-wrap">
          <span>{tenant.last_seen ?? '—'}</span>
          <span>·</span>
          <span>{(tenant.last_payload_bytes / 1024).toFixed(1)} KB</span>
          {tenant.agent_commit && (
            <>
              <span>·</span>
              <span className="font-mono inline-flex items-center gap-1">
                <GitCommit size={10} />
                {tenant.agent_commit.slice(0, 8)}
              </span>
            </>
          )}
        </div>
      </div>
      <Badge variant={tenant.online ? 'green' : 'red'}>
        {tenant.age_sec !== null ? formatAge(tenant.age_sec) : '—'}
      </Badge>
      {canUpdate && behindTarget && !pendingUpdate && (
        <button
          onClick={handleUpdate}
          disabled={trigger.isPending || !tenant.online}
          className={`text-xs px-2.5 py-1 rounded border disabled:opacity-40 inline-flex items-center gap-1 ${
            confirmMode === 'update'
              ? 'bg-amber-100 hover:bg-amber-200 text-amber-900 border-amber-400 animate-pulse'
              : 'bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border-indigo-200'
          }`}
          title={t('central.updateTooltip') as string}
        >
          <Download size={11} />
          {confirmMode === 'update' ? t('central.confirmClick') : t('central.updateBtn')}
        </button>
      )}
      {!pendingRestart && !pendingUpdate && (
        <button
          onClick={handleRestart}
          disabled={triggerRestart.isPending || !tenant.online}
          className={`text-xs px-2.5 py-1 rounded border disabled:opacity-40 inline-flex items-center gap-1 ${
            confirmMode === 'restart'
              ? 'bg-amber-100 hover:bg-amber-200 text-amber-900 border-amber-400 animate-pulse'
              : 'bg-slate-50 hover:bg-slate-100 text-slate-700 border-slate-200'
          }`}
          title={t('central.restartTooltip') as string}
        >
          <RefreshCw size={11} />
          {confirmMode === 'restart' ? t('central.confirmClick') : t('central.restartBtn')}
        </button>
      )}
      <button
        onClick={() => setShowBackups(true)}
        className="text-xs px-2.5 py-1 rounded border bg-slate-50 hover:bg-slate-100 text-slate-700 border-slate-200 inline-flex items-center gap-1"
        title={t('central.backupsTooltip') as string}
      >
        <DatabaseBackup size={11} />
        {t('central.backupsBtn')}
      </button>
      <BackupsModal tenant={tenant.id} open={showBackups} onClose={() => setShowBackups(false)} />
    </div>
  )
}

// Lists this tenant's encrypted agent-state backups from OVH and lets an
// admin download one — the file it downloads is exactly what
// backend/scripts/restore_backup.py expects as input.
function BackupsModal({ tenant, open, onClose }: { tenant: string; open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const { data, isLoading, error } = useQuery({
    queryKey: ['central-backups', tenant],
    queryFn: () => centralApi.backupList(tenant),
    enabled: open,
  })
  const [downloadingId, setDownloadingId] = useState<number | null>(null)
  const knownKey = centralConfig.load()?.tenantKeys?.[tenant]

  const download = async (id: number) => {
    setDownloadingId(id)
    try {
      const result: any = await centralApi.backupDownload(tenant, id)
      if (knownKey) {
        // Bundled deliberately (user-chosen convenience over strict E2E
        // separation) — the downloaded file alone is now enough to decrypt
        // the backup, so treat it as sensitive as the database itself.
        result.enc_key = knownKey
        result.enc_key_included_warning =
          'This file contains the decryption key — treat it like a plaintext credentials dump.'
      }
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `mikromanager-backup-${tenant}-${id}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setDownloadingId(null)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={t('central.backupsModalTitle', { tenant })}>
      <p className="text-xs text-slate-500 mb-3">{t('central.backupsModalHint')}</p>
      {knownKey ? (
        <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-3 py-2 mb-3">
          {t('central.backupsKeyWillBeIncluded')}
        </p>
      ) : (
        <p className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded px-3 py-2 mb-3">
          {t('central.backupsKeyUnknown')}
        </p>
      )}
      {isLoading ? (
        <p className="text-sm text-slate-500 py-4 text-center">{t('common.loading')}</p>
      ) : error ? (
        <p className="text-sm text-red-600 py-4 text-center">{(error as Error).message}</p>
      ) : !data || data.backups.length === 0 ? (
        <p className="text-sm text-slate-500 py-4 text-center">{t('central.backupsEmpty')}</p>
      ) : (
        <ul className="divide-y divide-slate-100">
          {data.backups.map(b => (
            <li key={b.id} className="py-2 flex items-center justify-between text-sm">
              <div>
                <p className="text-slate-800">{new Date(b.created_at).toLocaleString()}</p>
                <p className="text-xs text-slate-400">{(b.size_bytes / 1024).toFixed(1)} KB</p>
              </div>
              <button
                onClick={() => download(b.id)}
                disabled={downloadingId === b.id}
                className="text-xs px-2.5 py-1 rounded border bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border-indigo-200 disabled:opacity-40 inline-flex items-center gap-1"
              >
                <Download size={11} />
                {downloadingId === b.id ? t('common.loading') : t('central.backupsDownload')}
              </button>
            </li>
          ))}
        </ul>
      )}
    </Modal>
  )
}

function TenantSnapshot({ tenantId }: { tenantId: string }) {
  const { t } = useTranslation()
  const [newKey, setNewKey] = useState('')
  const [keyVersion, setKeyVersion] = useState(0)  // bumps to force refetch after key save
  const [expandedDeviceId, setExpandedDeviceId] = useState<number | null>(null)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['central-snapshot', tenantId, keyVersion],
    queryFn: () => centralApi.snapshot(tenantId),
    refetchInterval: 30_000,
  })

  if (isLoading) return <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('common.loading')}</p>
  if (error) return <p className="px-5 py-8 text-center text-red-600 text-sm">{String(error)}</p>
  if (!data) return <p className="px-5 py-8 text-center text-slate-500 text-sm">{t('central.noSnapshot')}</p>

  // Encrypted snapshot we cannot decrypt → prompt for key
  if (data._encrypted) {
    return (
      <Card>
        <CardContent className="space-y-3 py-5">
          <div className="flex items-center gap-2">
            <Lock size={18} className="text-amber-600" />
            <p className="font-medium text-slate-900">{t('central.snapshotEncrypted')}</p>
          </div>
          <p className="text-xs text-slate-600">
            {data._error === 'missing_key' ? t('central.keyNeeded') : data._error}
          </p>
          <div className="text-xs text-slate-500 space-y-0.5">
            <p>{t('central.snapshotFrom')}: <span className="font-mono">{data.received_at}</span> ({formatAge(data.age_sec)} {t('central.ago')})</p>
            {data.devices_count != null && <p>{t('central.devicesAt', { count: data.devices_count })}</p>}
          </div>
          <form onSubmit={(e) => {
            e.preventDefault()
            if (newKey) {
              centralConfig.setTenantKey(tenantId, newKey)
              setNewKey('')
              setKeyVersion(v => v + 1)
            }
          }} className="space-y-2">
            <Input label={t('central.decryptionKey')} type="password"
              placeholder="base64 32 bytes"
              value={newKey} onChange={e => setNewKey(e.target.value)} />
            <Button type="submit" variant="primary" size="sm" disabled={!newKey}>
              <Lock size={12} /> {t('central.saveKey')}
            </Button>
          </form>
        </CardContent>
      </Card>
    )
  }

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
                  <th className="px-5 py-2.5 text-left">{t('central.logsCol')}</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d: any) => (
                  <Fragment key={d.id}>
                    <tr className="border-b border-slate-200">
                      <td className="px-5 py-2 font-mono text-xs text-slate-700">{d.ip}</td>
                      <td className="px-5 py-2 text-slate-700">{d.identity || d.name || '—'}</td>
                      <td className="px-5 py-2 text-slate-600">{d.model || '—'}</td>
                      <td className="px-5 py-2 font-mono text-xs text-slate-600">{d.ros_version || '—'}</td>
                      <td className="px-5 py-2">
                        <Badge variant={d.online ? 'green' : 'red'}>
                          {d.online ? t('common.online') : t('common.offline')}
                        </Badge>
                      </td>
                      <td className="px-5 py-2">
                        <button
                          onClick={() => setExpandedDeviceId(id => id === d.id ? null : d.id)}
                          className="text-xs text-indigo-600 hover:text-indigo-500 inline-flex items-center gap-1"
                        >
                          <FileText size={12} />
                          {t('central.viewLogs')}
                          {expandedDeviceId === d.id ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                        </button>
                      </td>
                    </tr>
                    {expandedDeviceId === d.id && (
                      <tr className="border-b border-slate-200">
                        <td colSpan={6} className="px-5 py-3 bg-slate-50">
                          <DeviceLogsPanel
                            tenantId={tenantId}
                            deviceId={d.id}
                            deviceLabel={d.identity || d.name || d.ip}
                            result={(data.log_fetch_results ?? []).find((r: any) => r.device_id === d.id)}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
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

function DeviceLogsPanel({ tenantId, deviceId, deviceLabel, result }: {
  tenantId: string
  deviceId: number
  deviceLabel: string
  result?: DeviceLogFetchResult
}) {
  const { t } = useTranslation()
  const [requestedAt, setRequestedAt] = useState<number | null>(null)

  const request = useMutation({
    mutationFn: () => centralApi.requestDeviceLogs(tenantId, deviceId, 100),
    onSuccess: () => setRequestedAt(Date.now()),
  })

  const resultIsFresh = result && (!requestedAt || new Date(result.fetched_at).getTime() >= requestedAt)
  const waiting = requestedAt && !resultIsFresh

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-slate-600">
          {t('central.logsFor', { name: deviceLabel })}
        </p>
        <Button size="sm" variant="secondary" onClick={() => request.mutate()} disabled={request.isPending}>
          <RefreshCw size={12} className={request.isPending ? 'animate-spin' : ''} />
          {resultIsFresh ? t('central.refreshLogs') : t('central.fetchLogs')}
        </Button>
      </div>

      {waiting && (
        <p className="text-xs text-amber-700">{t('central.logsQueued')}</p>
      )}

      {resultIsFresh && result && (
        <div className="space-y-1">
          <p className="text-[11px] text-slate-500">
            {t('central.logsFetchedAt')}: <span className="font-mono">{result.fetched_at}</span>
          </p>
          {result.error ? (
            <p className="text-xs text-red-600">{result.error}</p>
          ) : (
            <div className="max-h-64 overflow-y-auto bg-white border border-slate-200 rounded-lg">
              <table className="w-full text-xs">
                <tbody>
                  {(result.logs ?? []).map((l, i) => (
                    <tr key={i} className="border-b border-slate-100 last:border-0">
                      <td className="px-3 py-1 font-mono text-slate-500 whitespace-nowrap align-top">{l.time}</td>
                      <td className="px-3 py-1 text-slate-400 whitespace-nowrap align-top">{l.topics}</td>
                      <td className="px-3 py-1 text-slate-700 break-all">{l.message}</td>
                    </tr>
                  ))}
                  {(result.logs ?? []).length === 0 && (
                    <tr><td className="px-3 py-2 text-slate-400">{t('central.noLogs')}</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {!resultIsFresh && !waiting && (
        <p className="text-xs text-slate-400">{t('central.logsNotFetchedYet')}</p>
      )}
    </div>
  )
}

function UsageBar() {
  const { t } = useTranslation()
  const { data: usage, refetch } = useQuery({
    queryKey: ['central-usage'],
    queryFn: centralApi.usage,
    refetchInterval: 60_000,
  })
  const [cleaning, setCleaning] = useState(false)

  if (!usage) return null

  const pct = usage.percent_of_cap ?? 0
  const barColor =
    pct >= 90 ? 'bg-red-500' :
    pct >= 70 ? 'bg-amber-500' :
    'bg-green-500'
  const textColor =
    pct >= 90 ? 'text-red-700' :
    pct >= 70 ? 'text-amber-700' :
    'text-slate-700'

  const handleCleanup = async () => {
    if (!confirm(t('central.cleanupConfirm') as string)) return
    setCleaning(true)
    try {
      await centralApi.cleanup(20)
      refetch()
    } finally {
      setCleaning(false)
    }
  }

  return (
    <Card>
      <CardContent className="space-y-2 py-3">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <HardDrive size={14} className={textColor} />
            <span className={`font-medium ${textColor}`}>
              {t('central.dbUsage')}: {usage.total_mb} / {usage.cap_mb} MB ({pct}%)
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-slate-500">{usage.total_count} {t('central.snapshots')}</span>
            <button
              onClick={handleCleanup}
              disabled={cleaning}
              className="text-slate-500 hover:text-red-600 inline-flex items-center gap-1"
              title={t('central.cleanupTooltip') as string}
            >
              <Trash2 size={11} />
              {cleaning ? t('central.cleaning') : t('central.cleanupNow')}
            </button>
          </div>
        </div>
        <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
          <div className={`h-full transition-all ${barColor}`} style={{ width: `${Math.min(pct, 100)}%` }} />
        </div>
        {usage.per_tenant && usage.per_tenant.length > 0 && (
          <div className="pt-1 grid grid-cols-2 md:grid-cols-3 gap-x-3 gap-y-0.5 text-[10px] text-slate-500">
            {usage.per_tenant.map(tn => (
              <div key={tn.tenant} className="flex justify-between">
                <span className="truncate">{tn.tenant}</span>
                <span className="font-mono">{(tn.bytes / 1024).toFixed(0)} KB · {tn.count}</span>
              </div>
            ))}
          </div>
        )}
        {pct >= 90 && (
          <p className="text-[11px] text-red-700">{t('central.quotaWarning')}</p>
        )}
      </CardContent>
    </Card>
  )
}

function KeyBackupPanel() {
  const { t } = useTranslation()
  const [mode, setMode] = useState<'none' | 'export' | 'import'>('none')
  const [importText, setImportText] = useState('')
  const [importResult, setImportResult] = useState<string | null>(null)
  const [importError, setImportError] = useState('')

  const doImport = () => {
    setImportError('')
    setImportResult(null)
    try {
      const count = centralConfig.importTenantKeys(importText)
      setImportResult(t('central.keysImported', { count }))
      setImportText('')
    } catch (e) {
      setImportError((e as Error).message)
    }
  }

  const close = () => {
    setMode('none')
    setImportText('')
    setImportResult(null)
    setImportError('')
  }

  return (
    <div className="flex items-center justify-end gap-2">
      <Button size="sm" variant="ghost" onClick={() => setMode('export')}>
        <Download size={12} /> {t('central.exportKeys')}
      </Button>
      <Button size="sm" variant="ghost" onClick={() => setMode('import')}>
        <Upload size={12} /> {t('central.importKeys')}
      </Button>

      <Modal open={mode === 'export'} onClose={close} title={t('central.exportKeys') as string}>
        <p className="text-xs text-slate-500 mb-2">{t('central.exportKeysHint')}</p>
        <textarea
          readOnly
          value={centralConfig.exportTenantKeys()}
          onClick={e => (e.target as HTMLTextAreaElement).select()}
          className="w-full h-40 font-mono text-xs bg-slate-100 border border-slate-200 rounded-lg p-2"
        />
        <div className="flex justify-end mt-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              // Purely client-side: localStorage -> file. No network call,
              // nothing sent anywhere — the browser's own download, same
              // trust boundary as the "Eksportuj klucze" text already had.
              const blob = new Blob([centralConfig.exportTenantKeys()], { type: 'application/json' })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = `mikromanager-e2e-keys-${new Date().toISOString().slice(0, 10)}.json`
              document.body.appendChild(a)
              a.click()
              document.body.removeChild(a)
              URL.revokeObjectURL(url)
            }}
          >
            <Download size={12} /> {t('central.exportKeysDownload')}
          </Button>
        </div>
      </Modal>

      <Modal open={mode === 'import'} onClose={close} title={t('central.importKeys') as string}>
        <p className="text-xs text-slate-500 mb-2">{t('central.importKeysHint')}</p>
        <textarea
          value={importText}
          onChange={e => setImportText(e.target.value)}
          placeholder={'{"aluplasti": "..."}'}
          className="w-full h-40 font-mono text-xs border border-slate-300 rounded-lg p-2"
        />
        {importError && <p className="text-xs text-red-600 mt-1">{importError}</p>}
        {importResult && <p className="text-xs text-green-700 mt-1">{importResult}</p>}
        <Button variant="primary" size="sm" className="mt-2 w-full justify-center"
          onClick={doImport} disabled={!importText.trim()}>
          {t('central.importKeysBtn')}
        </Button>
      </Modal>
    </div>
  )
}

function EncryptedTenantsPanel() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [keys, setKeys] = useState<Record<string, string>>({})

  // Quick probe: fetch every tenant snapshot, list those that come back encrypted+missing_key
  const { data: encryptedTenants = [] } = useQuery({
    queryKey: ['encrypted-tenants'],
    queryFn: async () => {
      const list = await centralApi.tenants()
      const result: string[] = []
      await Promise.all(list.tenants.map(async (tn) => {
        try {
          const snap = await centralApi.snapshot(tn.id)
          if (snap?._encrypted) result.push(tn.id)
        } catch { /* ignore */ }
      }))
      return result
    },
    refetchInterval: 60_000,
  })

  if (encryptedTenants.length === 0) return null

  const saveKey = (tenant: string) => {
    const k = keys[tenant]?.trim()
    if (!k) return
    centralConfig.setTenantKey(tenant, k)
    setKeys(prev => ({ ...prev, [tenant]: '' }))
    qc.invalidateQueries({ queryKey: ['encrypted-tenants'] })
    qc.invalidateQueries({ queryKey: ['tenant-devices'] })
  }

  return (
    <Card>
      <CardHeader>
        <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
          <Lock size={14} className="text-amber-600" />
          {t('central.keysNeeded', { count: encryptedTenants.length })}
        </h2>
      </CardHeader>
      <CardContent className="space-y-3">
        {encryptedTenants.map(tn => (
          <div key={tn} className="flex items-end gap-2">
            <div className="flex-1">
              <Input label={tn} type="password" placeholder="base64 32 bytes"
                value={keys[tn] ?? ''}
                onChange={e => setKeys(prev => ({ ...prev, [tn]: e.target.value }))} />
            </div>
            <Button size="sm" variant="primary" onClick={() => saveKey(tn)} disabled={!keys[tn]}>
              <Lock size={12} /> {t('central.saveKey')}
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

function ViewerPanel() {
  const { t } = useTranslation()
  const [configured, setConfigured] = useState(!!centralConfig.load())

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['central-tenants'],
    queryFn: centralApi.tenants,
    enabled: configured,
    refetchInterval: 30_000,
  })

  // Viewer's own git commit — for compare
  const { data: selfVer } = useQuery({
    queryKey: ['self-version'],
    queryFn: systemApi.selfVersion,
    refetchInterval: 60_000,
  })

  // Which tenants currently have update queued (yet to be picked up)
  const { data: pendingData } = useQuery({
    queryKey: ['central-pending-updates'],
    queryFn: centralApi.pendingUpdates,
    enabled: configured,
    refetchInterval: 15_000,
  })
  const pendingSet = new Set((pendingData?.pending ?? []).map(p => p.tenant))

  const { data: pendingRestartData } = useQuery({
    queryKey: ['central-pending-restarts'],
    queryFn: centralApi.pendingRestarts,
    enabled: configured,
    refetchInterval: 15_000,
  })
  const pendingRestartSet = new Set((pendingRestartData?.pending ?? []).map(p => p.tenant))

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
      {selfVer?.commit && (
        <div className="flex items-center gap-2 bg-white border border-slate-200 rounded-lg px-4 py-2 text-xs">
          <GitCommit size={13} className="text-indigo-600" />
          <span className="text-slate-600">{t('central.yourVersion')}:</span>
          <span className="font-mono text-slate-900">{selfVer.commit.slice(0, 8)}</span>
          {selfVer.commit_time && (
            <span className="text-slate-500">
              ({formatAge(Math.floor(Date.now() / 1000) - selfVer.commit_time)} {t('central.ago')})
            </span>
          )}
          {selfVer.branch && selfVer.branch !== 'master' && (
            <Badge variant="gray" className="text-[10px]">{selfVer.branch}</Badge>
          )}
        </div>
      )}

      <UsageBar />

      <KeyBackupPanel />

      <EncryptedTenantsPanel />

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
                onClick={() => { centralConfig.clear(); setConfigured(false) }}
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
            data?.tenants.map(tnt => (
              <TenantRow
                key={tnt.id}
                tenant={tnt}
                viewerCommit={selfVer?.commit ?? null}
                viewerCommitTime={selfVer?.commit_time ?? null}
                pendingUpdate={pendingSet.has(tnt.id)}
                pendingRestart={pendingRestartSet.has(tnt.id)}
              />
            ))
          )}
        </CardContent>
      </Card>

      <div className="text-xs text-slate-500 bg-slate-100 border border-slate-200 rounded-lg px-4 py-2.5">
        💡 {t('central.devicesMovedHint')}
      </div>
    </div>
  )
}

// ── Top-level page ───────────────────────────────────────────────────────────

export function Central() {
  const { t } = useTranslation()
  const [tab, setTab] = useState<'agent' | 'viewer' | 'alerts' | 'users' | 'anydesk'>('viewer')
  const isConfigured = !!centralConfig.load()

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
        <button onClick={() => setTab('alerts')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            tab === 'alerts' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}>
          {t('central.tabAlerts')}
        </button>
        {isConfigured && (
          <button onClick={() => setTab('users')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === 'users' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}>
            {t('central.tabUsers')}
          </button>
        )}
        {isConfigured && (
          <button onClick={() => setTab('anydesk')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === 'anydesk' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}>
            {t('central.tabAnydesk')}
          </button>
        )}
      </div>

      {tab === 'viewer' ? <ViewerPanel />
        : tab === 'agent' ? <UplinkPanel />
        : tab === 'alerts' ? <AlertsPanel />
        : tab === 'users' ? <UsersPanel />
        : <AnydeskPanel />}
    </div>
  )
}

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi, credentialsApi, systemApi, getAllTenantDevices, centralConfig } from '../lib/api'
import { pickUpgradeTarget, cleanVersion } from '../lib/version'
import { Card, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { TenantBadge } from '../components/ui/TenantBadge'
import { Modal } from '../components/ui/Modal'
import { Input } from '../components/ui/Input'
import { Server, Trash2, ExternalLink, Plus, ArrowUpCircle, CheckCircle2, RefreshCw, AlertTriangle, Download } from 'lucide-react'
import { Link } from 'react-router-dom'
import { formatDate } from '../lib/utils'
import { useTranslation } from 'react-i18next'

function AddDeviceModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const [form, setForm] = useState({ ip: '', name: '', api_port: 8728, web_port: 80, credential_id: '' })

  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  const create = useMutation({
    mutationFn: () => devicesApi.create({
      ...form,
      api_port: Number(form.api_port),
      web_port: Number(form.web_port),
      credential_id: form.credential_id ? Number(form.credential_id) : undefined,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['devices'] }); onClose() },
  })

  return (
    <form onSubmit={e => { e.preventDefault(); create.mutate() }} className="space-y-4">
      <Input label={t('devices.ipAddress')} value={form.ip} onChange={set('ip')} required placeholder="192.168.1.1" />
      <Input label={t('devices.nameOptional')} value={form.name} onChange={set('name')} placeholder="Main router" />
      <div className="grid grid-cols-2 gap-3">
        <Input label={t('devices.portApi')} type="number" value={form.api_port} onChange={set('api_port')} />
        <Input label={t('devices.portWeb')} type="number" value={form.web_port} onChange={set('web_port')} />
      </div>
      <div>
        <label className="text-xs font-medium text-slate-600 block mb-1">{t('nav.credentials')}</label>
        <select className="w-full bg-slate-100 border border-slate-300 rounded-lg px-3 py-2 text-sm text-slate-900"
          value={form.credential_id} onChange={set('credential_id')}>
          <option value="">{t('devices.noCredsOption')}</option>
          {creds.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>
      <div className="flex gap-2 justify-end pt-2">
        <Button type="button" variant="ghost" onClick={onClose}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary">{t('devices.addDeviceBtn')}</Button>
      </div>
    </form>
  )
}

type RowSource = 'local' | string  // tenant id or 'local'

interface UnifiedDevice {
  source: RowSource         // 'local' | tenant id
  id: number | string       // local: number; remote: "tenant:id"
  raw_id?: number           // original numeric id within its source
  ip: string
  identity?: string
  name?: string
  model?: string
  ros_version?: string
  vendor?: string
  online: boolean
  last_seen?: string
  has_api?: boolean
  has_ssh?: boolean
  has_web?: boolean
  has_snmp?: boolean
  credential_id?: number
}

export function Devices() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: localDevices = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const { data: versionStatus } = useQuery({
    queryKey: ['version-status'],
    queryFn: systemApi.versionStatus,
    refetchInterval: 6 * 3600 * 1000,
  })
  // Aggregated devices from all configured central tenants (decrypted locally).
  const hasCentral = !!centralConfig.load()
  const { data: tenantDevices = [] } = useQuery({
    queryKey: ['tenant-devices'],
    queryFn: getAllTenantDevices,
    enabled: hasCentral,
    refetchInterval: 60_000,
  })

  const [addOpen, setAddOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [tenantFilter, setTenantFilter] = useState<string>('all')  // 'all' | 'local' | tenant id
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkRunning, setBulkRunning] = useState(false)
  const [bulkStatuses, setBulkStatuses] = useState<Record<string, any>>({})

  const remove = useMutation({
    mutationFn: devicesApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['devices'] }),
  })

  const toggleSelect = (id: number) => {
    setSelected(prev => {
      const s = new Set(prev)
      if (s.has(id)) s.delete(id); else s.add(id)
      return s
    })
  }

  const bulkUpgrade = async (backup: boolean) => {
    if (selected.size === 0) return
    const ids = Array.from(selected)
    setBulkRunning(true)
    setBulkStatuses({})
    setBulkOpen(true)
    try {
      await devicesApi.firmwareUpgradeBulk(ids, backup)
      // Poll statuses every 5s until all done/timeout/error
      const poll = setInterval(async () => {
        try {
          const st = await devicesApi.firmwareStatuses(ids)
          setBulkStatuses(st)
          const allDone = ids.every(id => {
            const s = st[String(id)]?.status
            return s === 'done' || s === 'error' || s === 'timeout' || s === 'no_job'
          })
          if (allDone) {
            clearInterval(poll)
            setBulkRunning(false)
            qc.invalidateQueries({ queryKey: ['devices'] })
          }
        } catch { /* keep polling */ }
      }, 5000)
    } catch (e) {
      setBulkRunning(false)
    }
  }

  const credMap = Object.fromEntries(creds.map(c => [c.id, c.name]))

  // Merge local + remote devices into a unified list
  const unified: UnifiedDevice[] = [
    ...localDevices.map((d): UnifiedDevice => ({
      source: 'local',
      id: d.id,
      raw_id: d.id,
      ip: d.ip,
      identity: d.identity,
      name: d.name,
      model: d.model,
      ros_version: d.ros_version,
      vendor: d.vendor,
      online: d.online,
      last_seen: d.last_seen,
      has_api: d.has_api, has_ssh: d.has_ssh, has_web: d.has_web, has_snmp: d.has_snmp,
      credential_id: d.credential_id,
    })),
    ...tenantDevices
      .filter(d => !d.encrypted && d.ip)  // skip undecryptable tenant rows
      .map((d): UnifiedDevice => ({
        source: d.tenant,
        id: `${d.tenant}:${d.id ?? d.ip}`,
        raw_id: d.id,
        ip: d.ip!,
        identity: d.identity,
        name: d.name,
        model: d.model,
        ros_version: d.ros_version,
        vendor: d.vendor,
        online: !!d.online,
        last_seen: d.last_seen,
        has_api: d.has_api, has_ssh: d.has_ssh, has_web: d.has_web, has_snmp: d.has_snmp,
      })),
  ]

  // Build tenant list for filter dropdown
  const allTenants = Array.from(new Set(tenantDevices.map(d => d.tenant))).sort()

  const filtered = unified.filter(d => {
    if (tenantFilter !== 'all' && d.source !== tenantFilter) return false
    const q = search.toLowerCase()
    return !q ||
      d.ip.includes(search) ||
      (d.identity ?? '').toLowerCase().includes(q) ||
      (d.model ?? '').toLowerCase().includes(q) ||
      d.source.toLowerCase().includes(q)
  })

  // Devices in tenant encrypted-but-no-key state — show as warning row at top
  const encryptedTenants = tenantDevices
    .filter(d => d.encrypted)
    .map(d => d.tenant)

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900">{t('devices.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('devices.subtitle', { count: unified.length })}</p>
        </div>
        <div className="flex gap-2">
          {selected.size > 0 && (
            <Button variant="secondary" onClick={() => {
              const withBackup = confirm(t('devices.firmwareUpgradeAskBackup', { count: selected.size }) as string)
              // Second confirmation with big warning
              if (!confirm(t('devices.firmwareUpgradeConfirm', { count: selected.size, backup: withBackup ? '+backup' : '' }) as string)) return
              bulkUpgrade(withBackup)
            }}>
              <Download size={16} /> {t('devices.firmwareUpgradeBtn', { count: selected.size })}
            </Button>
          )}
          <Button variant="primary" onClick={() => setAddOpen(true)}>
            <Plus size={16} /> {t('common.addManual')}
          </Button>
        </div>
      </div>

      {/* Version-check status banner */}
      {versionStatus && (
        <div className="flex items-center gap-3 bg-white border border-slate-200 rounded-lg px-4 py-2.5 text-xs">
          {versionStatus.fetch_status.has_data ? (
            <>
              <CheckCircle2 size={14} className="text-green-600 shrink-0" />
              <span className="text-slate-600">
                {t('devices.versionCheckOk')}:{' '}
                {['6', '7'].map(ch => {
                  const v = versionStatus.latest[ch]
                  if (!v) return null
                  return (
                    <span key={ch} className="font-mono text-slate-800 ml-2">
                      v{ch}={v.version}
                    </span>
                  )
                })}
              </span>
            </>
          ) : (
            <>
              <AlertTriangle size={14} className="text-amber-600 shrink-0" />
              <span className="text-amber-700">
                {t('devices.versionCheckFail')}: {versionStatus.fetch_status.last_error}
              </span>
            </>
          )}
          <button
            onClick={() => systemApi.refreshVersions().then(() => qc.invalidateQueries({ queryKey: ['version-status'] }))}
            className="ml-auto text-slate-500 hover:text-indigo-600"
            title={t('common.refresh') as string}
          >
            <RefreshCw size={12} />
          </button>
        </div>
      )}

      {/* Encrypted-tenant warnings */}
      {encryptedTenants.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-2.5 text-xs text-amber-800">
          {t('devices.encryptedNoKey', { tenants: encryptedTenants.join(', ') })}
        </div>
      )}

      <div className="flex gap-2 items-center">
        <Input placeholder={t('devices.searchPlaceholder')} value={search}
          onChange={e => setSearch(e.target.value)} className="flex-1" />
        {(allTenants.length > 0 || localDevices.length > 0) && (
          <select
            className="bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
            value={tenantFilter}
            onChange={e => setTenantFilter(e.target.value)}
          >
            <option value="all">{t('devices.allSources')}</option>
            <option value="local">{t('devices.localSource')}</option>
            {allTenants.map(tn => (
              <option key={tn} value={tn}>{tn}</option>
            ))}
          </select>
        )}
      </div>

      {isLoading ? (
        <p className="text-slate-500 text-sm text-center py-12">{t('common.loading')}</p>
      ) : filtered.length === 0 ? (
        <Card><CardContent className="py-12 text-center">
          <Server size={32} className="mx-auto text-slate-300 mb-3" />
          <p className="text-slate-500 text-sm">{t('devices.noDevices')}</p>
        </CardContent></Card>
      ) : (
        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500">
                <th className="px-3 py-3 text-left w-8">
                  <input type="checkbox"
                    checked={filtered.length > 0 && filtered.filter(d => d.source === 'local').every(d => selected.has(d.raw_id!))}
                    onChange={e => {
                      const localIds = filtered.filter(d => d.source === 'local').map(d => d.raw_id!)
                      setSelected(prev => {
                        const s = new Set(prev)
                        if (e.target.checked) localIds.forEach(id => s.add(id))
                        else localIds.forEach(id => s.delete(id))
                        return s
                      })
                    }}
                    className="rounded" />
                </th>
                <th className="px-5 py-3 text-left">{t('devices.cols.client')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.ipIdentity')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.model')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.ros')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.capabilities')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.status')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.lastSeen')}</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => {
                const isLocal = d.source === 'local'
                const detailPath = isLocal ? `/devices/${d.raw_id}` : '#'
                return (
                <tr key={d.id} className="border-b border-slate-200 hover:bg-slate-50 transition-colors">
                  <td className="px-3 py-3">
                    {isLocal && d.raw_id != null ? (
                      <input type="checkbox"
                        checked={selected.has(d.raw_id)}
                        onChange={() => toggleSelect(d.raw_id!)}
                        className="rounded" />
                    ) : null}
                  </td>
                  <td className="px-5 py-3">
                    {isLocal ? (
                      <Badge variant="gray" className="text-[10px]">{t('devices.localSource')}</Badge>
                    ) : (
                      <TenantBadge tenant={d.source} withDot />
                    )}
                  </td>
                  <td className="px-5 py-3">
                    {isLocal ? (
                      <Link to={detailPath} className="text-indigo-600 hover:underline font-mono block">{d.ip}</Link>
                    ) : (
                      <span className="text-slate-700 font-mono block">{d.ip}</span>
                    )}
                    {d.identity && <span className="text-xs text-slate-500">{d.identity}</span>}
                    {d.name && <span className="text-xs text-slate-400 block">{d.name}</span>}
                  </td>
                  <td className="px-5 py-3 text-slate-700">
                    <div className="flex items-center gap-1.5">
                      {d.vendor === 'cisco-sb' && (
                        <Badge variant="blue" className="text-[10px]">Cisco</Badge>
                      )}
                      {(d.vendor === 'cisco-generic' || d.vendor === 'generic-snmp') && (
                        <Badge variant="gray" className="text-[10px]">{d.vendor}</Badge>
                      )}
                      <span>{d.model || '—'}</span>
                    </div>
                  </td>
                  <td className="px-5 py-3 font-mono text-xs">
                    {d.ros_version ? (
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-700">{cleanVersion(d.ros_version)}</span>
                        {(() => {
                          // Client-side compare against fetched latest map — works for
                          // both local and remote (tenant) devices.
                          const v = pickUpgradeTarget(d.ros_version, versionStatus?.latest)
                          if (!v) return null
                          if (v.status === 'up_to_date') {
                            return <CheckCircle2 size={12} className="text-green-600" />
                          }
                          if (v.status === 'outdated') {
                            return (
                              <Badge variant="yellow" className="inline-flex items-center gap-1 text-[10px]">
                                <ArrowUpCircle size={10} /> → {v.target}
                              </Badge>
                            )
                          }
                          return null
                        })()}
                      </div>
                    ) : '—'}
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex gap-1 flex-wrap">
                      {d.has_api && <Badge variant="blue">API</Badge>}
                      {d.has_ssh && <Badge variant="gray">SSH</Badge>}
                      {d.has_web && <Badge variant="yellow">Web</Badge>}
                      {d.has_snmp && <Badge variant="purple">SNMP</Badge>}
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <Badge variant={d.online ? 'green' : 'red'}>{d.online ? t('common.online') : t('common.offline')}</Badge>
                  </td>
                  <td className="px-5 py-3 text-slate-500 text-xs">{formatDate(d.last_seen)}</td>
                  <td className="px-5 py-3">
                    {isLocal ? (
                      <div className="flex gap-1">
                        <Link to={detailPath}>
                          <Button size="sm" variant="ghost"><ExternalLink size={13} /></Button>
                        </Link>
                        <Button size="sm" variant="danger" onClick={() => remove.mutate(d.raw_id!)}>
                          <Trash2 size={13} />
                        </Button>
                      </div>
                    ) : (
                      <span className="text-[10px] text-slate-400">{t('devices.readOnly')}</span>
                    )}
                  </td>
                </tr>
              )})}
            </tbody>
          </table>
        </Card>
      )}

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title={t('devices.addTitle')}>
        <AddDeviceModal onClose={() => setAddOpen(false)} />
      </Modal>

      <Modal
        open={bulkOpen}
        onClose={() => { if (!bulkRunning) { setBulkOpen(false); setSelected(new Set()) } }}
        title={t('devices.firmwareBulkTitle')}
      >
        <div className="space-y-2 text-sm">
          {Array.from(selected).map(id => {
            const dev = localDevices.find(d => d.id === id)
            const st = bulkStatuses[String(id)] ?? { status: 'queued' }
            const label = dev ? (dev.identity || dev.name || dev.ip) : `#${id}`
            const badge =
              st.status === 'done' ? <Badge variant="green">{t('devices.fw.done', { v: st.new_version ?? '' })}</Badge> :
              st.status === 'error' || st.status === 'timeout' ? <Badge variant="red">{st.status}</Badge> :
              st.status === 'no_job' ? <Badge variant="gray">—</Badge> :
              <Badge variant="yellow">{st.status}</Badge>
            return (
              <div key={id} className="flex items-center justify-between border-b border-slate-100 pb-1.5">
                <span className="font-mono text-xs text-slate-700">{label}</span>
                <div className="flex items-center gap-2">
                  {badge}
                  {st.log && st.log.length > 0 && (
                    <span className="text-[10px] text-slate-400 max-w-[200px] truncate" title={st.log.join('\n')}>
                      {st.log[st.log.length - 1]}
                    </span>
                  )}
                </div>
              </div>
            )
          })}
          {!bulkRunning && (
            <div className="pt-2 flex justify-end">
              <Button variant="ghost" onClick={() => { setBulkOpen(false); setSelected(new Set()) }}>
                {t('common.cancel')}
              </Button>
            </div>
          )}
        </div>
      </Modal>
    </div>
  )
}

import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { windowsApi, credentialsApi, WindowsHostOut } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { RunScriptModal } from '../components/RunScriptModal'
import { VulnScanStatusPanel } from '../components/VulnScanStatusPanel'
import {
  MonitorSmartphone, RefreshCw, Download, Power, AlertTriangle, CheckCircle2, Terminal,
  ChevronDown, ChevronUp, Trash2, Plus, ShieldAlert, Server, Laptop, HardDrive, MemoryStick,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { formatBytes } from '../lib/utils'

function pctBadgeVariant(pct: number | null | undefined): 'red' | 'yellow' | 'green' | 'gray' {
  if (pct == null) return 'gray'
  if (pct >= 90) return 'red'
  if (pct >= 75) return 'yellow'
  return 'green'
}

interface ScanProgressEvent {
  type: 'phase' | 'progress' | 'done' | 'result' | 'error'
  phase?: string
  completed?: number
  total?: number
  ip?: string
  detail?: string | null
  message?: string
}

function ScanProgressBar({ phase, completed, total, ip }: { phase: string; completed: number; total: number; ip: string | null }) {
  const { t } = useTranslation()
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0
  return (
    <div className="space-y-1.5 bg-slate-50 border border-slate-200 rounded-lg p-3">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-700">{t(`windows.scanPhase.${phase}`, phase)}{ip && <span className="text-slate-500 font-mono"> — {ip}</span>}</span>
        <span className="text-slate-600 font-mono">{completed}/{total} ({pct}%)</span>
      </div>
      <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <div className="h-full bg-indigo-500 transition-all duration-300" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function SettingsPanel() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: settings } = useQuery({ queryKey: ['windows-settings'], queryFn: windowsApi.getSettings })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const [selected, setSelected] = useState<string>('')

  const save = useMutation({
    mutationFn: (credentialId: number | null) => windowsApi.setSettings(credentialId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['windows-settings'] }),
  })

  const toggleEnabled = useMutation({
    mutationFn: (enabled: boolean) => windowsApi.setSettings(settings?.credential_id ?? null, enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['windows-settings'] }),
  })

  const [scanning, setScanning] = useState(false)
  const [scanPhase, setScanPhase] = useState<string | null>(null)
  const [scanProgress, setScanProgress] = useState({ completed: 0, total: 0 })
  const [scanIp, setScanIp] = useState<string | null>(null)
  const [skipNotes, setSkipNotes] = useState<Array<{ ip: string; detail: string }>>([])
  const esRef = useRef<EventSource | null>(null)

  const runDiscoverStream = () => {
    setScanning(true)
    setScanPhase(null)
    setScanProgress({ completed: 0, total: 0 })
    setScanIp(null)
    setSkipNotes([])
    const es = new EventSource('/api/windows/discover-stream')
    esRef.current = es
    es.onmessage = (e) => {
      const ev: ScanProgressEvent = JSON.parse(e.data)
      if (ev.type === 'phase') {
        setScanPhase(ev.phase ?? null)
        setScanProgress({ completed: 0, total: ev.total ?? 0 })
        setScanIp(null)
      } else if (ev.type === 'progress') {
        setScanPhase(ev.phase ?? null)
        setScanProgress({ completed: ev.completed ?? 0, total: ev.total ?? 0 })
        setScanIp(ev.ip ?? null)
        if (ev.phase === 'windows_identify' && ev.detail && ev.ip) {
          setSkipNotes(prev => [...prev, { ip: ev.ip!, detail: ev.detail! }])
        }
      } else if (ev.type === 'result' || ev.type === 'error') {
        es.close()
        esRef.current = null
        setScanning(false)
        qc.invalidateQueries({ queryKey: ['windows-hosts'] })
      }
    }
    es.onerror = () => {
      es.close()
      esRef.current = null
      setScanning(false)
      qc.invalidateQueries({ queryKey: ['windows-hosts'] })
    }
  }

  const current = selected || (settings?.credential_id ? String(settings.credential_id) : '')

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <MonitorSmartphone size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('windows.settingsTitle')}</h2>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-slate-500">{t('windows.settingsHint')}</p>
        {settings && (
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input type="checkbox" checked={settings.enabled} disabled={toggleEnabled.isPending}
              onChange={e => toggleEnabled.mutate(e.target.checked)} />
            {t('windows.manageEnabledToggle')}
          </label>
        )}
        {settings && !settings.enabled && (
          <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-800">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" />
            <span>{t('windows.disabledWarning')}</span>
          </div>
        )}
        <div className="flex items-center gap-2">
          <select
            value={current}
            onChange={e => setSelected(e.target.value)}
            className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm flex-1"
          >
            <option value="">{t('windows.noCredential')}</option>
            {creds.map(c => (
              <option key={c.id} value={c.id}>{c.name} ({c.username}{c.domain ? `@${c.domain}` : ''})</option>
            ))}
          </select>
          <Button
            variant="secondary"
            onClick={() => save.mutate(current ? parseInt(current) : null)}
            disabled={save.isPending}
          >
            {t('common.save')}
          </Button>
        </div>
        {settings?.credential_name && (
          <p className="text-xs text-slate-500">
            {t('windows.currentCredential')}: <span className="font-mono">{settings.credential_name}</span>
          </p>
        )}
        <Button variant="secondary" onClick={runDiscoverStream} disabled={scanning}>
          <RefreshCw size={13} className={scanning ? 'animate-spin' : ''} />
          {t('windows.scanNow')}
        </Button>
        {scanning && (
          <ScanProgressBar phase={scanPhase ?? ''} completed={scanProgress.completed} total={scanProgress.total} ip={scanIp} />
        )}
        {skipNotes.length > 0 && (
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 space-y-1">
            <p className="text-xs font-semibold text-amber-800">{t('windows.skipNotesTitle')}</p>
            {skipNotes.map((n, i) => (
              <p key={i} className="text-xs text-amber-700">
                <span className="font-mono">{n.ip}</span>: {n.detail}
              </p>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function WorkstationPortsPanel() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: ports } = useQuery({ queryKey: ['windows-workstation-ports'], queryFn: windowsApi.getWorkstationPorts })
  const [text, setText] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (list: number[]) => windowsApi.setWorkstationPorts(list),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['windows-workstation-ports'] })
      qc.invalidateQueries({ queryKey: ['windows-hosts'] })
      setText(null)
    },
  })

  const current = text ?? (ports ?? []).join(', ')

  const submit = () => {
    const parsed = current.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n > 0 && n < 65536)
    save.mutate(Array.from(new Set(parsed)))
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldAlert size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('windows.workstationPortsTitle')}</h2>
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs text-slate-500">{t('windows.workstationPortsHint')}</p>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={current}
            onChange={e => setText(e.target.value)}
            className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm flex-1 font-mono"
            placeholder="135, 139, 445, 3389, 5985, 5986"
          />
          <Button variant="secondary" onClick={submit} disabled={save.isPending}>{t('common.save')}</Button>
        </div>
      </CardContent>
    </Card>
  )
}

function ServicesSection({ host }: { host: WindowsHostOut }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: services = [] } = useQuery({
    queryKey: ['windows-services', host.id],
    queryFn: () => windowsApi.listServices(host.id),
  })
  const [newName, setNewName] = useState('')

  const add = useMutation({
    mutationFn: (name: string) => windowsApi.addService(host.id, name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['windows-services', host.id] }); setNewName('') },
  })
  const remove = useMutation({
    mutationFn: (serviceId: number) => windowsApi.removeService(host.id, serviceId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['windows-services', host.id] }),
  })
  const check = useMutation({
    mutationFn: () => windowsApi.checkServices(host.id),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['windows-services', host.id] }), 4000),
  })

  const statusBadge = (status: string | null) => {
    if (!status) return <span className="text-slate-400">—</span>
    if (status === 'not_found') return <Badge variant="gray" className="text-[10px]">{t('windows.serviceNotFound')}</Badge>
    if (status === 'Running') return <Badge variant="green" className="text-[10px]">{status}</Badge>
    return <Badge variant="red" className="text-[10px]">{status}</Badge>
  }

  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-1">
        <p className="text-xs font-semibold text-slate-700">{t('windows.servicesTitle')}</p>
        <div className="flex items-center gap-2">
          {host.last_services_check_at && (
            <span className="text-[10px] text-slate-400">
              {t('windows.lastServicesCheck')}: {new Date(host.last_services_check_at).toLocaleString()}
            </span>
          )}
          <Button size="sm" variant="secondary" onClick={() => check.mutate()} disabled={check.isPending || services.length === 0}>
            <RefreshCw size={11} className={check.isPending ? 'animate-spin' : ''} /> {t('windows.checkServicesNow')}
          </Button>
        </div>
      </div>
      {services.length === 0 ? (
        <p className="text-xs text-slate-400">{t('windows.noServices')}</p>
      ) : (
        <div className="space-y-1">
          {services.map(s => (
            <div key={s.id} className="flex items-center justify-between text-xs bg-white border border-slate-200 rounded px-2 py-1">
              <span className="font-mono text-slate-700">{s.display_name || s.service_name}</span>
              <div className="flex items-center gap-2">
                {statusBadge(s.status)}
                <button onClick={() => remove.mutate(s.id)} className="text-slate-400 hover:text-red-600">
                  <Trash2 size={12} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={newName}
          onChange={e => setNewName(e.target.value)}
          placeholder={t('windows.addServicePlaceholder') as string}
          className="border border-slate-300 rounded-lg px-2 py-1 text-xs flex-1"
          onKeyDown={e => { if (e.key === 'Enter' && newName.trim()) add.mutate(newName.trim()) }}
        />
        <Button size="sm" variant="secondary" onClick={() => newName.trim() && add.mutate(newName.trim())} disabled={add.isPending}>
          <Plus size={11} /> {t('windows.addService')}
        </Button>
      </div>
    </div>
  )
}

function DisksSection({ host }: { host: WindowsHostOut }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: disks = [] } = useQuery({
    queryKey: ['windows-disks', host.id],
    queryFn: () => windowsApi.listDisks(host.id),
  })

  const check = useMutation({
    mutationFn: () => windowsApi.checkResources(host.id),
    onSuccess: () => setTimeout(() => {
      qc.invalidateQueries({ queryKey: ['windows-disks', host.id] })
      qc.invalidateQueries({ queryKey: ['windows-hosts'] })
    }, 5000),
  })

  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-1">
        <p className="text-xs font-semibold text-slate-700">{t('windows.disksTitle')}</p>
        <div className="flex items-center gap-2">
          {host.last_resources_check_at && (
            <span className="text-[10px] text-slate-400">
              {t('windows.lastResourcesCheck')}: {new Date(host.last_resources_check_at).toLocaleString()}
            </span>
          )}
          <Button size="sm" variant="secondary" onClick={() => check.mutate()} disabled={check.isPending}>
            <RefreshCw size={11} className={check.isPending ? 'animate-spin' : ''} /> {t('windows.checkResourcesNow')}
          </Button>
        </div>
      </div>
      {disks.length === 0 ? (
        <p className="text-xs text-slate-400">{t('windows.noDisks')}</p>
      ) : (
        <div className="space-y-1">
          {disks.map(d => (
            <div key={d.id} className="flex items-center justify-between text-xs bg-white border border-slate-200 rounded px-2 py-1">
              <span className="font-mono text-slate-700">{d.drive_letter}</span>
              <div className="flex items-center gap-2 text-slate-500">
                <span>{formatBytes(d.used_bytes)} / {formatBytes(d.total_bytes)}</span>
                <Badge variant={pctBadgeVariant(d.pct)} className="text-[10px]">{d.pct}%</Badge>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function HostCard({ host, selected, onToggleSelect, onRunScript }: {
  host: WindowsHostOut; selected: boolean; onToggleSelect: () => void; onRunScript: () => void
}) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [polling, setPolling] = useState(false)
  const [showServices, setShowServices] = useState(false)
  const [showDisks, setShowDisks] = useState(false)

  const { data: job } = useQuery({
    queryKey: ['windows-job', host.id],
    queryFn: () => windowsApi.status(host.id),
    enabled: polling,
    refetchInterval: (q) => {
      const s = q.state.data?.status
      return (s === 'starting' || s === 'checking' || s === 'updating' || s === 'upgrading' || s === 'restarting' || s === 'running_script') ? 3000 : false
    },
  })

  const setManaged = useMutation({
    mutationFn: (managed: boolean) => windowsApi.setManaged(host.id, managed),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['windows-hosts'] }),
  })

  const setHostType = useMutation({
    mutationFn: (hostType: 'server' | 'workstation') => windowsApi.setHostType(host.id, hostType),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['windows-hosts'] }),
  })

  const runCheck = useMutation({
    mutationFn: () => windowsApi.check(host.id),
    onSuccess: () => { setPolling(true); setTimeout(() => qc.invalidateQueries({ queryKey: ['windows-hosts'] }), 5000) },
  })

  const runUpgrade = useMutation({
    mutationFn: (reason: string) => windowsApi.upgrade(host.id, reason),
    onSuccess: () => setPolling(true),
  })

  const runRestart = useMutation({
    mutationFn: (reason: string) => windowsApi.restart(host.id, reason),
    onSuccess: () => setPolling(true),
  })

  const askReasonAndRun = (mutate: (reason: string) => void, promptKey: string) => {
    const reason = window.prompt(t(promptKey) as string)
    if (reason === null) return
    if (!reason.trim()) { alert(t('windows.reasonRequired') as string); return }
    mutate(reason.trim())
  }

  const inProgress = job && ['starting', 'checking', 'updating', 'upgrading', 'restarting', 'running_script'].includes(job.status)

  return (
    <div className="border border-slate-200 rounded-lg p-3 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <span className="font-mono text-sm text-slate-800">{host.ip}</span>
          {host.hostname && <span className="text-xs text-slate-500 ml-2">{host.hostname}</span>}
          {host.domain && <span className="text-xs text-slate-400 ml-2">({host.domain})</span>}
          {host.source === 'auto' && !host.managed && (
            <Badge variant="gray" className="text-[10px] ml-2">{t('windows.pending')}</Badge>
          )}
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            onClick={() => setHostType.mutate(host.host_type === 'server' ? 'workstation' : 'server')}
            disabled={setHostType.isPending}
            title={t(host.host_type === 'server' ? 'windows.markAsWorkstation' : 'windows.markAsServer') as string}
          >
            <Badge variant={host.host_type === 'server' ? 'purple' : 'gray'} className="text-[10px] cursor-pointer">
              {host.host_type === 'server' ? <Server size={10} /> : <Laptop size={10} />}
              {t(host.host_type === 'server' ? 'windows.hostTypeServer' : 'windows.hostTypeWorkstation')}
            </Badge>
          </button>
          {host.os_name ? (
            <Badge variant="blue" className="text-[10px]">{host.os_name}</Badge>
          ) : (
            <span className="text-xs text-slate-400">—</span>
          )}
          {host.upgradable_count != null && host.upgradable_count > 0 && (
            <Badge variant="yellow" className="text-[10px]">{t('windows.upgradableCount', { count: host.upgradable_count })}</Badge>
          )}
          {host.upgradable_count === 0 && (
            <Badge variant="green" className="text-[10px]"><CheckCircle2 size={10} /> {t('windows.upToDate')}</Badge>
          )}
          {host.reboot_required && (
            <Badge variant="red" className="text-[10px]">{t('windows.rebootRequired')}</Badge>
          )}
          {host.unexpected_ports != null && host.unexpected_ports.length > 0 && (
            <Badge variant="red" className="text-[10px]">
              <ShieldAlert size={10} /> {t('windows.unexpectedPorts', { ports: host.unexpected_ports.join(', ') })}
            </Badge>
          )}
          {host.mem_used_pct != null && (
            <Badge variant={pctBadgeVariant(host.mem_used_pct)} className="text-[10px]">
              <MemoryStick size={10} /> {host.mem_used_pct}%
            </Badge>
          )}
        </div>
      </div>

      {host.host_type === 'workstation' && host.managed && (
        <p className="text-[11px] text-slate-400">{t('windows.workstationOnlyNote')}</p>
      )}

      <div className="flex items-center justify-between flex-wrap gap-2 text-xs text-slate-500">
        <div>
          {host.last_check_at && <span>{t('windows.lastCheck')}: {new Date(host.last_check_at).toLocaleString()}</span>}
          {host.last_upgrade_at && <span className="ml-3">{t('windows.lastUpgrade')}: {new Date(host.last_upgrade_at).toLocaleString()}</span>}
          {host.last_restart_at && <span className="ml-3">{t('windows.lastRestart')}: {new Date(host.last_restart_at).toLocaleString()}</span>}
        </div>
        <div className="flex items-center gap-2">
          {!host.managed ? (
            <Button size="sm" variant="secondary" onClick={() => setManaged.mutate(true)} disabled={setManaged.isPending}>
              {t('windows.enableManagement')}
            </Button>
          ) : (
            <>
              <input type="checkbox" checked={selected} onChange={onToggleSelect}
                title={t('runScript.selectForBulk') as string} />
              <button onClick={() => setManaged.mutate(false)} className="text-xs text-slate-500 hover:underline">
                {t('windows.disableManagement')}
              </button>
              <Button size="sm" variant="secondary" onClick={() => runCheck.mutate()} disabled={!!inProgress}>
                <RefreshCw size={12} className={inProgress ? 'animate-spin' : ''} /> {t('windows.checkUpdates')}
              </Button>
              {host.host_type !== 'workstation' && (
                <>
                  <Button size="sm" variant="danger"
                    onClick={() => askReasonAndRun(reason => {
                      if (confirm(t('windows.upgradeConfirm', { ip: host.ip }) as string)) runUpgrade.mutate(reason)
                    }, 'windows.reasonPromptUpgrade')}
                    disabled={!!inProgress}>
                    <Download size={12} /> {t('windows.upgradeNow')}
                  </Button>
                  <Button size="sm" variant="danger"
                    onClick={() => askReasonAndRun(reason => {
                      if (confirm(t('windows.restartConfirm', { ip: host.ip }) as string)) runRestart.mutate(reason)
                    }, 'windows.reasonPromptRestart')}
                    disabled={!!inProgress}>
                    <Power size={12} /> {t('windows.restartNow')}
                  </Button>
                </>
              )}
              <Button size="sm" variant="secondary" onClick={onRunScript} disabled={!!inProgress}>
                <Terminal size={12} /> {t('runScript.button')}
              </Button>
              <Button size="sm" variant="secondary" onClick={() => setShowServices(s => !s)}>
                {showServices ? <ChevronUp size={12} /> : <ChevronDown size={12} />} {t('windows.servicesToggle')}
              </Button>
              <Button size="sm" variant="secondary" onClick={() => setShowDisks(s => !s)}>
                {showDisks ? <ChevronUp size={12} /> : <ChevronDown size={12} />} <HardDrive size={12} /> {t('windows.disksToggle')}
              </Button>
            </>
          )}
        </div>
      </div>

      {host.managed && showServices && <ServicesSection host={host} />}
      {host.managed && showDisks && <DisksSection host={host} />}

      {job && job.status !== 'no_job' && (
        <div className="bg-slate-100 rounded-lg p-2 text-xs space-y-1">
          <p className="font-semibold text-slate-800">{t('windows.jobStatus')}: {job.status}</p>
          {job.reason && <p className="text-slate-600">{t('windows.reasonLabel')}: {job.reason}</p>}
          {job.error && <p className="text-red-600">{job.error}</p>}
          {job.log && job.log.length > 0 && (
            <div className="mt-1 max-h-40 overflow-auto bg-slate-900 text-green-300 p-2 rounded text-[10px] font-mono whitespace-pre-wrap">
              {job.log.join('\n')}
            </div>
          )}
        </div>
      )}
      {host.last_status === 'error' && host.last_error && !job && (
        <p className="text-xs text-red-600">{host.last_error}</p>
      )}
    </div>
  )
}

export function WindowsHosts() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['windows-hosts'],
    queryFn: windowsApi.hosts,
    refetchInterval: 15_000,
  })

  const upgradeAll = useMutation({
    mutationFn: ({ ids, reason }: { ids: number[]; reason: string }) => windowsApi.upgradeBulk(ids, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['windows-hosts'] }),
  })

  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [scriptTarget, setScriptTarget] = useState<{ hostIds: number[]; label: string } | null>(null)

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const runScriptOn = async ({ script, reason }: { script: string; useSudo: boolean; reason: string }) => {
    if (!scriptTarget) return
    if (scriptTarget.hostIds.length === 1) {
      await windowsApi.runScript(scriptTarget.hostIds[0], script, reason)
    } else {
      await windowsApi.runScriptBulk(scriptTarget.hostIds, script, reason)
    }
    qc.invalidateQueries({ queryKey: ['windows-hosts'] })
  }

  const hosts = data?.hosts ?? []
  const managed = hosts.filter(h => h.managed)

  const upgradeAllClick = () => {
    const reason = window.prompt(t('windows.reasonPromptUpgrade') as string)
    if (reason === null) return
    if (!reason.trim()) { alert(t('windows.reasonRequired') as string); return }
    if (confirm(t('windows.upgradeAllConfirm', { count: managed.length }) as string)) {
      upgradeAll.mutate({ ids: managed.map(h => h.id), reason: reason.trim() })
    }
  }

  return (
    <div className="p-6 space-y-4 max-w-4xl">
      <div className="flex items-center gap-2">
        <MonitorSmartphone size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('nav.windowsHosts')}</h1>
      </div>

      {/* One shared "scan everything" trigger (CVE + Linux/Windows/Dell
          discovery + Mikrotik/Cisco RouterOS refresh), same component as
          Scanner/Vulnerabilities — sits above this page's OWN narrower
          "just Windows, from already-known ports" button below. */}
      <VulnScanStatusPanel hint={t('windows.fullScanHintText') as string} />

      <SettingsPanel />
      <WorkstationPortsPanel />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('windows.hostsTitle')}</h2>
            <div className="flex items-center gap-2">
              {selectedIds.size > 0 && (
                <Button size="sm" variant="secondary"
                  onClick={() => setScriptTarget({ hostIds: [...selectedIds], label: t('runScript.selectedCount', { count: selectedIds.size }) as string })}>
                  <Terminal size={12} /> {t('runScript.buttonBulk', { count: selectedIds.size })}
                </Button>
              )}
              {managed.length > 1 && (
                <Button size="sm" variant="secondary" onClick={upgradeAllClick} disabled={upgradeAll.isPending}>
                  <Download size={12} /> {t('windows.upgradeAll', { count: managed.length })}
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-2">
          {isLoading ? (
            <p className="text-sm text-slate-500">{t('common.loading')}</p>
          ) : hosts.length === 0 ? (
            <p className="text-sm text-slate-500">{t('windows.noHosts')}</p>
          ) : (
            hosts.map(h => (
              <HostCard key={h.id} host={h}
                selected={selectedIds.has(h.id)}
                onToggleSelect={() => toggleSelect(h.id)}
                onRunScript={() => setScriptTarget({ hostIds: [h.id], label: h.hostname || h.ip })}
              />
            ))
          )}
        </CardContent>
      </Card>

      <RunScriptModal
        open={scriptTarget !== null}
        onClose={() => setScriptTarget(null)}
        platform="windows"
        targetLabel={scriptTarget?.label ?? ''}
        onRun={runScriptOn}
      />
    </div>
  )
}

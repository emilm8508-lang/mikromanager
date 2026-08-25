import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { vulnApi, credentialsApi, VulnFindingOut, VulnHostOut, VulnRemediationStatus } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import {
  ShieldAlert, RefreshCw, ExternalLink, Server, ChevronDown, ChevronUp, CheckCircle2, Download, Clock,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useAuth } from './Login'

const STATUSES: VulnRemediationStatus[] = ['open', 'in_progress', 'accepted_risk', 'resolved']

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

function severityBadgeVariant(severity: string | null): 'purple' | 'red' | 'yellow' | 'blue' | 'gray' {
  switch (severity) {
    case 'CRITICAL': return 'purple'
    case 'HIGH': return 'red'
    case 'MEDIUM': return 'yellow'
    case 'LOW': return 'blue'
    default: return 'gray'
  }
}

interface ScanProgressEvent {
  type: 'phase' | 'progress' | 'done' | 'result' | 'error'
  phase?: string
  completed?: number
  total?: number
  ip?: string
  message?: string
}

function ScanProgressBar({ phase, completed, total, ip }: { phase: string; completed: number; total: number; ip: string | null }) {
  const { t } = useTranslation()
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0
  return (
    <div className="space-y-1.5 bg-slate-50 border border-slate-200 rounded-lg p-3">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-700">{t(`vuln.scanPhase.${phase}`, phase)}{ip && <span className="text-slate-500 font-mono"> — {ip}</span>}</span>
        <span className="text-slate-600 font-mono">{completed}/{total} ({pct}%)</span>
      </div>
      <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <div className="h-full bg-indigo-500 transition-all duration-300" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function StatusPanel() {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['vuln-status'],
    queryFn: vulnApi.status,
    refetchInterval: 15_000,
  })

  // Live progress via SSE instead of a fire-and-forget POST — the button
  // previously gave no feedback beyond a spinner for however long the
  // scan takes (which can be a long time across a full network range).
  const [scanning, setScanning] = useState(false)
  const [scanPhase, setScanPhase] = useState<string | null>(null)
  const [scanProgress, setScanProgress] = useState({ completed: 0, total: 0 })
  const [scanIp, setScanIp] = useState<string | null>(null)
  const esRef = useRef<EventSource | null>(null)

  const runScanStream = () => {
    setScanning(true)
    setScanPhase(null)
    setScanProgress({ completed: 0, total: 0 })
    setScanIp(null)
    const es = new EventSource('/api/vuln/scan-stream')
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
      } else if (ev.type === 'result' || ev.type === 'error') {
        es.close()
        esRef.current = null
        setScanning(false)
        qc.invalidateQueries({ queryKey: ['vuln-status'] })
        qc.invalidateQueries({ queryKey: ['vuln-hosts'] })
        qc.invalidateQueries({ queryKey: ['vuln-findings'] })
      }
    }
    es.onerror = () => {
      es.close()
      esRef.current = null
      setScanning(false)
      qc.invalidateQueries({ queryKey: ['vuln-status'] })
      qc.invalidateQueries({ queryKey: ['vuln-hosts'] })
      qc.invalidateQueries({ queryKey: ['vuln-findings'] })
    }
  }

  if (!data) return null

  const lastRun = data.last_run ? new Date(data.last_run) : null
  const nextRun = new Date(data.next_run_estimated * 1000)
  const nextRunStr = nextRun.toLocaleString(i18n.language, {
    weekday: 'long', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
            <ShieldAlert size={15} className="text-indigo-600" />
            {t('vuln.statusTitle')}
          </h2>
          <Button size="sm" variant="primary" onClick={runScanStream} disabled={data.in_progress || scanning}>
            <RefreshCw size={13} className={(data.in_progress || scanning) ? 'animate-spin' : ''} />
            {(data.in_progress || scanning) ? t('vuln.scanning') : t('vuln.scanNow')}
          </Button>
        </div>
      </CardHeader>
      {scanning && (
        <div className="px-4 pt-2">
          <ScanProgressBar phase={scanPhase ?? ''} completed={scanProgress.completed} total={scanProgress.total} ip={scanIp} />
        </div>
      )}
      <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <div>
          <p className="text-xs text-slate-500">{t('vuln.lastScan')}</p>
          <p className="text-slate-900">{lastRun ? lastRun.toLocaleString(i18n.language) : t('vuln.never')}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500">{t('vuln.nextScan')}</p>
          <p className="text-slate-900">{nextRunStr}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500">{t('vuln.hostsScanned')}</p>
          <p className="text-slate-900">{data.hosts_scanned_last}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500">{t('vuln.findingsCount')}</p>
          <p className="text-slate-900">{data.findings_count_last}</p>
        </div>
      </CardContent>
    </Card>
  )
}

function statusBadgeVariant(status: VulnRemediationStatus): 'red' | 'yellow' | 'blue' | 'green' | 'gray' {
  switch (status) {
    case 'open': return 'red'
    case 'in_progress': return 'yellow'
    case 'accepted_risk': return 'blue'
    case 'resolved': return 'green'
    default: return 'gray'
  }
}

function FindingRow({ finding }: { finding: VulnFindingOut }) {
  const { t } = useTranslation()
  const { role } = useAuth()
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [note, setNote] = useState(finding.note ?? '')

  const setRemediation = useMutation({
    mutationFn: (data: { status: VulnRemediationStatus; note?: string }) =>
      vulnApi.setRemediation({
        product: finding.product, version: finding.version, cve_id: finding.cve_id,
        status: data.status, note: data.note,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vuln-findings'] }),
  })

  return (
    <div className="border-b border-slate-100 last:border-0">
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-slate-50"
      >
        <Badge variant={severityBadgeVariant(finding.severity)}>{finding.severity ?? '—'}</Badge>
        <Badge variant={statusBadgeVariant(finding.status)} className="text-[10px]">
          {t(`vuln.status.${finding.status}`)}
        </Badge>
        {finding.overdue && (
          <Badge variant="red" className="text-[10px] inline-flex items-center gap-1">
            <Clock size={9} /> {t('vuln.overdue')}
          </Badge>
        )}
        <span className="font-mono text-xs text-slate-700 shrink-0">{finding.cve_id}</span>
        <span className="text-sm text-slate-600 truncate flex-1">
          {finding.product} {finding.version}
        </span>
        {finding.cvss_score != null && (
          <span className="text-xs text-slate-500 shrink-0">CVSS {finding.cvss_score.toFixed(1)}</span>
        )}
        {expanded ? <ChevronUp size={14} className="text-slate-400 shrink-0" /> : <ChevronDown size={14} className="text-slate-400 shrink-0" />}
      </button>
      {expanded && (
        <div className="px-4 pb-3 space-y-2 text-sm">
          {finding.summary && <p className="text-slate-700 text-xs">{finding.summary}</p>}
          {finding.recommendation && (
            <p className="text-xs text-indigo-700 bg-indigo-50 border border-indigo-100 rounded p-2">
              {finding.recommendation}
            </p>
          )}
          {finding.ref_url && (
            <a href={finding.ref_url} target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-1 text-indigo-600 hover:text-indigo-500 text-xs">
              <ExternalLink size={12} /> {t('vuln.viewCve')}
            </a>
          )}
          {finding.due_date && (
            <p className="text-xs text-slate-500">
              {t('vuln.dueDate')}: {new Date(finding.due_date).toLocaleDateString()}
            </p>
          )}
          {finding.updated_by && (
            <p className="text-xs text-slate-400">
              {t('vuln.lastUpdatedBy', { username: finding.updated_by })}
              {finding.updated_at ? ` · ${new Date(finding.updated_at).toLocaleString()}` : ''}
            </p>
          )}
          {role === 'admin' && (
            <div className="flex items-center gap-2 pt-1">
              <select
                value={finding.status}
                onChange={e => setRemediation.mutate({ status: e.target.value as VulnRemediationStatus, note })}
                className="text-xs border border-slate-300 rounded px-1.5 py-1"
              >
                {STATUSES.map(s => <option key={s} value={s}>{t(`vuln.status.${s}`)}</option>)}
              </select>
              <input
                value={note}
                onChange={e => setNote(e.target.value)}
                onBlur={() => { if (note !== (finding.note ?? '')) setRemediation.mutate({ status: finding.status, note }) }}
                placeholder={t('vuln.notePlaceholder') as string}
                className="flex-1 text-xs border border-slate-300 rounded px-2 py-1"
              />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// One card per host — IP/device name up top, its findings listed below,
// a per-host "check again" button (patched something? verify right away
// instead of waiting for the weekly scan), and optional credential
// assignment for a deeper SSH-based identity check next time.
function HostCard({ host, findings, credentials }: {
  host: VulnHostOut
  findings: VulnFindingOut[]
  credentials: Array<{ id: number; name: string }>
}) {
  const { t } = useTranslation()
  const qc = useQueryClient()

  const rescan = useMutation({
    mutationFn: () => vulnApi.rescanHost(host.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vuln-hosts'] })
      qc.invalidateQueries({ queryKey: ['vuln-findings'] })
    },
  })

  const assign = useMutation({
    mutationFn: (credentialId: number | null) => vulnApi.setHostCredential(host.id, credentialId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vuln-hosts'] }),
  })

  const sorted = [...findings].sort((a, b) =>
    ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 } as any)[a.severity ?? ''] -
    ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 } as any)[b.severity ?? ''])

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Server size={14} className="text-slate-400 shrink-0" />
            <span className="font-mono text-sm text-slate-900">{host.ip}</span>
            {host.device_name && <Badge variant="gray">{host.device_name}</Badge>}
            {findings.length === 0 ? (
              <Badge variant="green"><CheckCircle2 size={11} className="mr-1 inline" />{t('vuln.clean')}</Badge>
            ) : (
              <Badge variant="red">{t('vuln.findingsN', { count: findings.length })}</Badge>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <select
              className="bg-white border border-slate-300 rounded px-2 py-1 text-xs"
              value={host.credential_id ?? ''}
              onChange={e => assign.mutate(e.target.value ? Number(e.target.value) : null)}
              title={t('vuln.credentialHint') as string}
            >
              <option value="">{t('vuln.noCredential')}</option>
              {credentials.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <Button size="sm" variant="secondary" onClick={() => rescan.mutate()} disabled={rescan.isPending}>
              <RefreshCw size={12} className={rescan.isPending ? 'animate-spin' : ''} />
              {t('vuln.rescanHost')}
            </Button>
          </div>
        </div>
        {host.services.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {host.services.map(s => (
              <span key={s.port} className="text-[11px] bg-slate-100 border border-slate-200 rounded px-1.5 py-0.5 text-slate-600">
                :{s.port} {s.product ? `${s.product} ${s.version ?? ''}` : (s.service_name ?? '')}
              </span>
            ))}
          </div>
        )}
      </CardHeader>
      {findings.length > 0 && (
        <CardContent className="p-0">
          {sorted.map(f => <FindingRow key={f.id} finding={f} />)}
        </CardContent>
      )}
    </Card>
  )
}

export function Vulnerabilities() {
  const { t } = useTranslation()
  const [severity, setSeverity] = useState<string | undefined>(undefined)

  const { data: hosts = [] } = useQuery({
    queryKey: ['vuln-hosts'],
    queryFn: vulnApi.hosts,
    refetchInterval: 30_000,
  })
  const { data: findings = [] } = useQuery({
    queryKey: ['vuln-findings', severity],
    queryFn: () => vulnApi.findings(severity),
    refetchInterval: 30_000,
  })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })

  // Invert findings.affected[] into ip -> findings[], so the report can be
  // grouped by host/device the way it reads on screen (device, then its
  // vulnerabilities, then the next device).
  const findingsByIp: Record<string, VulnFindingOut[]> = {}
  for (const f of findings) {
    for (const a of f.affected) {
      if (!findingsByIp[a.ip]) findingsByIp[a.ip] = []
      if (!findingsByIp[a.ip].some(existing => existing.id === f.id)) {
        findingsByIp[a.ip].push(f)
      }
    }
  }

  const visibleHosts = severity
    ? hosts.filter(h => (findingsByIp[h.ip] ?? []).length > 0)
    : hosts

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900">{t('vuln.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('vuln.subtitle')}</p>
          <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mt-2">
            {t('vuln.disclaimer')}
          </p>
        </div>
        <a
          href={vulnApi.exportUrl(severity)}
          className="shrink-0 inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-slate-200 text-slate-600 hover:text-indigo-600 hover:border-indigo-200 bg-white"
        >
          <Download size={13} /> {t('vuln.exportCsv')}
        </a>
      </div>

      <StatusPanel />

      <div className="flex items-center gap-1.5">
        <button
          onClick={() => setSeverity(undefined)}
          className={`text-xs px-2.5 py-1 rounded border ${!severity ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'border-slate-200 text-slate-500 bg-white'}`}
        >
          {t('vuln.all')}
        </button>
        {SEVERITIES.map(s => (
          <button
            key={s}
            onClick={() => setSeverity(s)}
            className={`text-xs px-2.5 py-1 rounded border ${severity === s ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'border-slate-200 text-slate-500 bg-white'}`}
          >
            {s}
          </button>
        ))}
      </div>

      {visibleHosts.length === 0 ? (
        <p className="text-sm text-slate-500 text-center py-10">{t('vuln.noHosts')}</p>
      ) : (
        <div className="space-y-3">
          {visibleHosts.map(h => (
            <HostCard key={h.id} host={h} findings={findingsByIp[h.ip] ?? []} credentials={creds} />
          ))}
        </div>
      )}
    </div>
  )
}

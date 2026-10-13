import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { vulnApi, credentialsApi, VulnFindingOut, VulnHostOut, VulnRemediationStatus } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { VulnScanStatusPanel } from '../components/VulnScanStatusPanel'
import { VulnOverview, VulnCveList, RemediationPanel, STATUSES } from '../components/VulnViews'
import { cn } from '../lib/utils'
import {
  RefreshCw, Server, ChevronDown, ChevronUp, CheckCircle2, Download, Clock,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

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
  const [expanded, setExpanded] = useState(false)

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
      {expanded && <div className="px-4 pb-3"><RemediationPanel finding={finding} /></div>}
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
  const [params, setParams] = useSearchParams()
  const tab = (['overview', 'cves', 'hosts'] as const).find(x => x === params.get('tab')) ?? 'overview'
  const setTab = (k: string) => setParams(k === 'overview' ? {} : { tab: k }, { replace: true })

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

      <VulnScanStatusPanel />

      <div className="flex gap-1 border-b border-slate-200 overflow-x-auto">
        {(['overview', 'cves', 'hosts'] as const).map(k => (
          <button key={k} onClick={() => setTab(k)} className={cn('px-4 py-2 text-sm -mb-px border-b-2 whitespace-nowrap', tab === k ? 'border-blue-600 text-blue-700 font-medium' : 'border-transparent text-slate-600 hover:text-slate-900')}>
            {t(`vulnDash.tab_${k}`)}
          </button>
        ))}
      </div>

      {tab === 'overview' && <VulnOverview onOpen={(k, f) => setParams({ tab: k, ...(f ?? {}) })} />}
      {tab === 'cves' && <VulnCveList />}

      {tab === 'hosts' && <>
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
      </>}
    </div>
  )
}

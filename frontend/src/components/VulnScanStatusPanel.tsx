import { useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { vulnApi } from '../lib/api'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { ShieldAlert, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

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

// Single trigger for the full network pass: CVE lookup (banners + known
// device versions, refreshed right before reading them) + Linux/Windows/
// Dell host discovery all run from this ONE scan — see services/
// vuln_scan.py's run_scan() docstring. Shown on the Vulnerabilities,
// Scanner, Linux, Windows, and Dell pages so wherever the operator is,
// there's a "scan everything" option right next to that page's own
// narrower, page-specific scan button — not a replacement for it, both
// stay available (confirmed with the user: several separate scan buttons
// were confusing without a consolidated "scan all" option alongside them).
// scanner.py's own device-discovery CIDR scan runs on its own separate,
// manual-only schedule regardless.
export function VulnScanStatusPanel({ hint }: { hint?: string }) {
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
        qc.invalidateQueries({ queryKey: ['linux-hosts'] })
        qc.invalidateQueries({ queryKey: ['windows-hosts'] })
        qc.invalidateQueries({ queryKey: ['dell-servers'] })
        qc.invalidateQueries({ queryKey: ['devices'] })
      }
    }
    es.onerror = () => {
      es.close()
      esRef.current = null
      setScanning(false)
      qc.invalidateQueries({ queryKey: ['vuln-status'] })
      qc.invalidateQueries({ queryKey: ['vuln-hosts'] })
      qc.invalidateQueries({ queryKey: ['vuln-findings'] })
      qc.invalidateQueries({ queryKey: ['dell-servers'] })
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
      {hint && <p className="px-4 -mt-1 pb-2 text-xs text-slate-500">{hint}</p>}
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

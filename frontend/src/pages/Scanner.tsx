import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scannerApi, credentialsApi, type ScannerProbeResult } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { VulnScanStatusPanel } from '../components/VulnScanStatusPanel'
import { Search, Plus, Trash2, CheckCircle2, AlertCircle, KeyRound, Activity, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

interface ScanEvent {
  type: 'info' | 'cidr_start' | 'progress' | 'found' | 'cidr_done' | 'done'
  cidr?: string
  ip?: string
  total?: number
  total_all?: number
  skipped_known?: number
  completed?: number
  device?: Record<string, unknown>
  message_key?: string
  count?: number
  known_count?: number
  full_scan?: boolean
  total_found?: number
  found?: number
}

interface FoundLine {
  ip: string
  identity?: string
  model?: string
  has_snmp?: boolean
  matched_credential?: string
}

const DAY_KEYS = ['scanner.dayMon', 'scanner.dayTue', 'scanner.dayWed', 'scanner.dayThu', 'scanner.dayFri', 'scanner.daySat', 'scanner.daySun']

function RangeScheduleEditor({ range, onSave, saving }: {
  range: { scan_day?: number | null; scan_hour?: number | null }
  onSave: (args: { scan_day?: number; scan_hour?: number; clear_schedule?: boolean }) => void
  saving: boolean
}) {
  const { t } = useTranslation()
  const hasCustom = range.scan_day != null && range.scan_hour != null
  const [day, setDay] = useState<string>(hasCustom ? String(range.scan_day) : '')
  const [hour, setHour] = useState<number>(hasCustom ? range.scan_hour! : 2)

  return (
    <div className="flex items-center gap-1.5">
      <select value={day} onChange={e => setDay(e.target.value)}
        className="border border-slate-300 rounded px-1.5 py-1 text-xs">
        <option value="">{t('scanner.scheduleGlobal')}</option>
        {DAY_KEYS.map((key, i) => <option key={i} value={i}>{t(key)}</option>)}
      </select>
      {day !== '' && (
        <select value={hour} onChange={e => setHour(parseInt(e.target.value))}
          className="border border-slate-300 rounded px-1.5 py-1 text-xs">
          {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{h}:00</option>)}
        </select>
      )}
      <button
        onClick={() => day === '' ? onSave({ clear_schedule: true }) : onSave({ scan_day: parseInt(day), scan_hour: hour })}
        disabled={saving}
        className="text-xs text-indigo-600 hover:underline disabled:opacity-50"
      >
        {t('common.save')}
      </button>
    </div>
  )
}

export function Scanner() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: ranges = [] } = useQuery({ queryKey: ['ranges'], queryFn: scannerApi.listRanges })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })

  const [newCidr, setNewCidr] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [scanning, setScanning] = useState(false)
  const [fullScan, setFullScan] = useState(false)
  const [foundList, setFoundList] = useState<FoundLine[]>([])
  const [currentCidr, setCurrentCidr] = useState<string | null>(null)
  const [currentIp, setCurrentIp] = useState<string | null>(null)
  const [progress, setProgress] = useState({ completed: 0, total: 0 })
  const [skippedKnown, setSkippedKnown] = useState(0)
  const [totalFound, setTotalFound] = useState<number | null>(null)
  const esRef = useRef<EventSource | null>(null)

  // Single-IP diagnostic probe — bypasses the mass-scan's concurrency
  // entirely, so it reflects exactly what a single manual connection
  // attempt sees. Added specifically to diagnose a device the full-range
  // scan can't seem to find: shows port-by-port liveness, not just a
  // found/dead verdict.
  const [probeIp, setProbeIp] = useState('')
  const [probeCredId, setProbeCredId] = useState<string>('')
  const [probeTimeout, setProbeTimeout] = useState('2')
  const [probeResult, setProbeResult] = useState<ScannerProbeResult | null>(null)
  const [probeError, setProbeError] = useState<string | null>(null)

  const probeMutation = useMutation({
    mutationFn: () => scannerApi.probe(probeIp, {
      credentialId: probeCredId ? Number(probeCredId) : undefined,
      timeout: probeTimeout ? Number(probeTimeout) : undefined,
    }),
    onSuccess: (data) => { setProbeResult(data); setProbeError(null) },
    onError: (e: Error) => { setProbeError(e.message); setProbeResult(null) },
  })

  const addRange = useMutation({
    mutationFn: () => scannerApi.addRange({ cidr: newCidr, label: newLabel || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ranges'] }); setNewCidr(''); setNewLabel('') },
  })

  const deleteRange = useMutation({
    mutationFn: scannerApi.deleteRange,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ranges'] }),
  })

  const updateRangeSchedule = useMutation({
    mutationFn: (args: { id: number; scan_day?: number; scan_hour?: number; clear_schedule?: boolean }) =>
      scannerApi.updateRange(args.id, args),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ranges'] }),
  })

  const runScan = () => {
    setFoundList([])
    setCurrentCidr(null)
    setCurrentIp(null)
    setProgress({ completed: 0, total: 0 })
    setSkippedKnown(0)
    setTotalFound(null)
    setScanning(true)

    const url = fullScan ? '/api/scanner/run?full=true' : '/api/scanner/run'
    const es = new EventSource(url)
    esRef.current = es
    es.onmessage = (e) => {
      const ev: ScanEvent = JSON.parse(e.data)

      switch (ev.type) {
        case 'cidr_start':
          setCurrentCidr(ev.cidr ?? null)
          setProgress({ completed: 0, total: 0 })
          break
        case 'progress':
          setCurrentIp(ev.ip ?? null)
          setProgress({ completed: ev.completed ?? 0, total: ev.total ?? 0 })
          break
        case 'cidr_done':
          if (ev.skipped_known) setSkippedKnown(s => s + (ev.skipped_known ?? 0))
          break
        case 'found':
          setCurrentIp(ev.ip ?? null)
          setProgress({ completed: ev.completed ?? 0, total: ev.total ?? 0 })
          if (ev.device) {
            setFoundList(prev => [...prev, {
              ip: String(ev.device!.ip),
              identity: ev.device!.identity as string | undefined,
              model: ev.device!.model as string | undefined,
              has_snmp: ev.device!.has_snmp as boolean | undefined,
              matched_credential: ev.device!.matched_credential as string | undefined,
            }])
          }
          break
        case 'done':
          setTotalFound(ev.total_found ?? null)
          setCurrentIp(null)
          es.close()
          esRef.current = null
          setScanning(false)
          qc.invalidateQueries({ queryKey: ['devices'] })
          break
      }
    }
    es.onerror = () => {
      es.close()
      esRef.current = null
      setScanning(false)
    }
  }

  const stopScan = () => {
    esRef.current?.close()
    esRef.current = null
    setScanning(false)
    setCurrentIp(null)
  }

  const pct = progress.total > 0 ? Math.round((progress.completed / progress.total) * 100) : 0

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-900">{t('scanner.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('scanner.subtitle')}</p>
      </div>

      {/* Full scan (CVE + Linux + Windows discovery + device version refresh) —
          consolidated here so every scanner is triggerable from one page,
          even though it and the device-discovery scan below run on their
          own separate schedules. */}
      <VulnScanStatusPanel hint={t('scanner.fullScanHintText') as string} />

      {/* Ranges */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">{t('scanner.rangesTitle')}</h2>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input placeholder={t('scanner.cidrPlaceholder') as string} value={newCidr} onChange={e => setNewCidr(e.target.value)}
              className="flex-1" />
            <Input placeholder={t('scanner.labelPlaceholder') as string} value={newLabel} onChange={e => setNewLabel(e.target.value)}
              className="flex-1" />
            <Button variant="primary" onClick={() => addRange.mutate()} disabled={!newCidr}>
              <Plus size={16} /> {t('common.add')}
            </Button>
          </div>

          {ranges.length === 0 ? (
            <p className="text-sm text-slate-500 text-center py-4">{t('scanner.noRanges')}</p>
          ) : (
            <div className="space-y-2">
              {ranges.map(r => (
                <div key={r.id} className="flex items-center gap-3 bg-slate-100 rounded-lg px-4 py-2.5 flex-wrap">
                  <span className="font-mono text-sm text-slate-800">{r.cidr}</span>
                  {r.label && <span className="text-xs text-slate-500">{r.label}</span>}
                  <Badge variant={r.active ? 'green' : 'gray'}>{r.active ? t('scanner.active') : t('scanner.inactive')}</Badge>
                  <RangeScheduleEditor range={r}
                    saving={updateRangeSchedule.isPending}
                    onSave={args => updateRangeSchedule.mutate({ id: r.id, ...args })} />
                  <Button size="sm" variant="danger" className="ml-auto" onClick={() => deleteRange.mutate(r.id)}>
                    <Trash2 size={13} />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Run scan */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">{t('scanner.runTitle')}</h2>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-sm text-slate-600">
              <KeyRound size={15} className="text-indigo-600" />
              <span>
                {t('scanner.credsInfo')} (<span className="text-slate-800 font-medium">{creds.length}</span>)
                {creds.length > 0 && ' ' + t('scanner.credsInfoSuffix')}
              </span>
            </div>
            {!scanning ? (
              <Button variant="primary" onClick={runScan} disabled={ranges.length === 0}>
                <Search size={16} />
                {t('scanner.scanNow')}
              </Button>
            ) : (
              <Button variant="danger" onClick={stopScan}>
                {t('logs.stopStream')}
              </Button>
            )}
          </div>

          <div className="flex items-start gap-2 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2.5 text-xs">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={fullScan}
                onChange={e => setFullScan(e.target.checked)}
                disabled={scanning}
                className="rounded border-slate-300 bg-white text-indigo-600 focus:ring-indigo-500 focus:ring-offset-0"
              />
              <span className="text-slate-700">{t('scanner.fullScanLabel')}</span>
            </label>
            <span className="text-slate-500 ml-auto flex items-center gap-1.5">
              <RefreshCw size={11} />
              {fullScan ? t('scanner.fullScanHint') : t('scanner.incrementalHint')}
            </span>
          </div>

          {creds.length === 0 && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-2.5 text-xs text-amber-700 flex items-center gap-2">
              <AlertCircle size={14} />
              {t('scanner.noCredsWarn')}
            </div>
          )}

          {/* Progress bar */}
          {(scanning || progress.total > 0) && (
            <div className="space-y-2 bg-slate-50 border border-slate-200 rounded-lg p-4">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <Activity size={13} className={scanning ? 'text-indigo-600 animate-pulse' : 'text-slate-500'} />
                  {currentCidr && (
                    <span className="font-mono text-slate-700">{currentCidr}</span>
                  )}
                  {currentIp && scanning && (
                    <span className="text-slate-500">â†’ <span className="text-slate-700 font-mono">{currentIp}</span></span>
                  )}
                </div>
                <span className="text-slate-600 font-mono">
                  {progress.completed}/{progress.total} ({pct}%)
                </span>
              </div>
              <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-indigo-500 transition-all duration-300"
                  style={{ width: `${pct}%` }}
                />
              </div>
              {totalFound !== null && (
                <p className="text-xs text-indigo-700 font-medium pt-1">
                  âś“ {t('scanner.scanDone', { found: totalFound })}
                  {skippedKnown > 0 && (
                    <span className="text-slate-500 font-normal"> · {t('scanner.skippedKnown', { count: skippedKnown })}</span>
                  )}
                </p>
              )}
            </div>
          )}

          {/* Found devices list */}
          {foundList.length > 0 && (
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 max-h-80 overflow-y-auto scrollbar-thin space-y-1.5">
              <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">
                {t('scanner.foundDevices', { count: foundList.length, defaultValue: 'Znalezione urzÄ…dzenia ({{count}})' })}
              </p>
              {foundList.map((d, i) => (
                <div key={i} className="flex items-center gap-2 text-sm">
                  <CheckCircle2 size={14} className="text-green-600 shrink-0" />
                  <span className="text-green-700 font-mono">{d.ip}</span>
                  {d.identity && <span className="text-slate-700">— {d.identity}</span>}
                  {d.model && <Badge variant="blue" className="ml-1">{d.model}</Badge>}
                  {d.has_snmp && <Badge variant="purple" className="ml-1">SNMP</Badge>}
                  {d.matched_credential && (
                    <Badge variant="green" className="ml-1 inline-flex items-center gap-1">
                      <KeyRound size={10} />
                      {d.matched_credential}
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Single-address diagnostic probe */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">{t('scanner.probeTitle')}</h2>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-slate-500">{t('scanner.probeHint')}</p>
          <div className="flex flex-wrap gap-2 items-end">
            <div className="flex-1 min-w-[160px]">
              <label className="block text-xs text-slate-500 mb-1">{t('scanner.probeIpLabel')}</label>
              <Input placeholder="192.168.1.1" value={probeIp} onChange={e => setProbeIp(e.target.value)} />
            </div>
            <div className="min-w-[160px]">
              <label className="block text-xs text-slate-500 mb-1">{t('scanner.probeCredLabel')}</label>
              <select
                value={probeCredId}
                onChange={e => setProbeCredId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-700 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              >
                <option value="">{t('scanner.probeCredNone')}</option>
                {creds.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
            </div>
            <div className="w-24">
              <label className="block text-xs text-slate-500 mb-1">{t('scanner.probeTimeoutLabel')}</label>
              <Input type="number" step="0.5" min="0.5" value={probeTimeout} onChange={e => setProbeTimeout(e.target.value)} />
            </div>
            <Button variant="primary" onClick={() => probeMutation.mutate()} disabled={!probeIp || probeMutation.isPending}>
              <Search size={16} />
              {t('scanner.probeButton')}
            </Button>
          </div>

          {probeError && (
            <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-2.5 text-xs text-red-700">
              {probeError}
            </div>
          )}

          {probeResult && (
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-3 text-sm">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-1.5">{t('scanner.probePorts')}</p>
                <p className="text-xs text-slate-500 mb-2">{t('scanner.probePortsHint')}</p>
                <div className="overflow-x-auto">
                  <table className="text-xs w-full">
                    <thead>
                      <tr className="text-left text-slate-500 border-b border-slate-200">
                        <th className="py-1 pr-3">{t('scanner.probeColPort')}</th>
                        <th className="pr-3">asyncio</th>
                        <th className="pr-3">socket</th>
                        <th>{t('scanner.probeColNote')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(probeResult.ports).map(([port, asyncioOk]) => {
                        const sock = probeResult.ports_socket[port]
                        const mismatch = sock && sock.open !== asyncioOk
                        return (
                          <tr key={port} className={`border-b border-slate-100 ${mismatch ? 'bg-amber-50' : ''}`}>
                            <td className="py-1 pr-3 font-mono">{port}</td>
                            <td className="pr-3">
                              <Badge variant={asyncioOk ? 'green' : 'gray'}>{asyncioOk ? t('scanner.probeOpen') : t('scanner.probeClosed')}</Badge>
                            </td>
                            <td className="pr-3">
                              {sock && (
                                <Badge variant={sock.open ? 'green' : 'gray'}>{sock.open ? t('scanner.probeOpen') : t('scanner.probeClosed')}</Badge>
                              )}
                            </td>
                            <td className="text-slate-500">
                              {mismatch && (
                                <span className="text-amber-700 font-medium">{t('scanner.probeMismatch')}</span>
                              )}
                              {sock?.error && !sock.open && (
                                <span className="ml-1 font-mono text-slate-400">{sock.error}</span>
                              )}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  <Badge variant={probeResult.snmp_public ? 'green' : 'gray'}>SNMP (public): {probeResult.snmp_public ? t('scanner.probeOpen') : t('scanner.probeClosed')}</Badge>
                </div>
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-1.5">{t('scanner.probeDiscovery')}</p>
                {probeResult.found ? (
                  <pre className="text-xs bg-white border border-slate-200 rounded p-2 overflow-x-auto">{JSON.stringify(probeResult.found, null, 2)}</pre>
                ) : (
                  <p className="text-xs text-red-600">{t('scanner.probeNotFound')}</p>
                )}
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-1.5">{t('scanner.probeScanRanges')}</p>
                <div className="flex flex-wrap gap-1.5">
                  {probeResult.scan_range_membership.map((r, i) => (
                    <Badge key={i} variant={r.contains_ip ? 'green' : 'gray'}>
                      {r.cidr}{r.label ? ` (${r.label})` : ''}: {r.contains_ip ? t('scanner.probeInRange') : t('scanner.probeOutOfRange')}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-1.5">{t('scanner.probeVulnScan')}</p>
                {Object.keys(probeResult.vuln_scan_probe).length > 0 ? (
                  <pre className="text-xs bg-white border border-slate-200 rounded p-2 overflow-x-auto">{JSON.stringify(probeResult.vuln_scan_probe, null, 2)}</pre>
                ) : (
                  <p className="text-xs text-red-600">{t('scanner.probeVulnScanEmpty')}</p>
                )}
              </div>
              {probeResult.enrich && (
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-1.5">{t('scanner.probeEnrich')}</p>
                  {probeResult.enrich.ok ? (
                    <pre className="text-xs bg-white border border-slate-200 rounded p-2 overflow-x-auto">{JSON.stringify(probeResult.enrich.data, null, 2)}</pre>
                  ) : (
                    <p className="text-xs text-red-600 font-mono">{probeResult.enrich.error}</p>
                  )}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

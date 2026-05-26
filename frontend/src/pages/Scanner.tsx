import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scannerApi, credentialsApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Search, Plus, Trash2, CheckCircle2, AlertCircle, Info, KeyRound, Activity } from 'lucide-react'
import { useTranslation } from 'react-i18next'

interface ScanEvent {
  type: 'info' | 'cidr_start' | 'progress' | 'found' | 'cidr_done' | 'done'
  cidr?: string
  ip?: string
  total?: number
  completed?: number
  device?: Record<string, unknown>
  message_key?: string
  count?: number
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

export function Scanner() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: ranges = [] } = useQuery({ queryKey: ['ranges'], queryFn: scannerApi.listRanges })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })

  const [newCidr, setNewCidr] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [scanning, setScanning] = useState(false)
  const [foundList, setFoundList] = useState<FoundLine[]>([])
  const [currentCidr, setCurrentCidr] = useState<string | null>(null)
  const [currentIp, setCurrentIp] = useState<string | null>(null)
  const [progress, setProgress] = useState({ completed: 0, total: 0 })
  const [totalFound, setTotalFound] = useState<number | null>(null)
  const esRef = useRef<EventSource | null>(null)

  const addRange = useMutation({
    mutationFn: () => scannerApi.addRange({ cidr: newCidr, label: newLabel || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ranges'] }); setNewCidr(''); setNewLabel('') },
  })

  const deleteRange = useMutation({
    mutationFn: scannerApi.deleteRange,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ranges'] }),
  })

  const runScan = () => {
    setFoundList([])
    setCurrentCidr(null)
    setCurrentIp(null)
    setProgress({ completed: 0, total: 0 })
    setTotalFound(null)
    setScanning(true)

    const es = new EventSource('/api/scanner/run')
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
        case 'cidr_done':
          // keep state
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
        <h1 className="text-xl font-bold text-gray-100">{t('scanner.title')}</h1>
        <p className="text-sm text-gray-500 mt-0.5">{t('scanner.subtitle')}</p>
      </div>

      {/* Ranges */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-gray-300">{t('scanner.rangesTitle')}</h2>
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
            <p className="text-sm text-gray-500 text-center py-4">{t('scanner.noRanges')}</p>
          ) : (
            <div className="space-y-2">
              {ranges.map(r => (
                <div key={r.id} className="flex items-center gap-3 bg-gray-800 rounded-lg px-4 py-2.5">
                  <span className="font-mono text-sm text-gray-200">{r.cidr}</span>
                  {r.label && <span className="text-xs text-gray-500">{r.label}</span>}
                  <Badge variant={r.active ? 'green' : 'gray'}>{r.active ? t('scanner.active') : t('scanner.inactive')}</Badge>
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
          <h2 className="text-sm font-semibold text-gray-300">{t('scanner.runTitle')}</h2>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <KeyRound size={15} className="text-indigo-400" />
              <span>
                {t('scanner.credsInfo')} (<span className="text-gray-200 font-medium">{creds.length}</span>)
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

          {creds.length === 0 && (
            <div className="bg-amber-950/30 border border-amber-900/50 rounded-lg px-4 py-2.5 text-xs text-amber-300 flex items-center gap-2">
              <AlertCircle size={14} />
              {t('scanner.noCredsWarn')}
            </div>
          )}

          {/* Progress bar */}
          {(scanning || progress.total > 0) && (
            <div className="space-y-2 bg-gray-950 border border-gray-800 rounded-lg p-4">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <Activity size={13} className={scanning ? 'text-indigo-400 animate-pulse' : 'text-gray-500'} />
                  {currentCidr && (
                    <span className="font-mono text-gray-300">{currentCidr}</span>
                  )}
                  {currentIp && scanning && (
                    <span className="text-gray-500">→ <span className="text-gray-300 font-mono">{currentIp}</span></span>
                  )}
                </div>
                <span className="text-gray-400 font-mono">
                  {progress.completed}/{progress.total} ({pct}%)
                </span>
              </div>
              <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-indigo-500 transition-all duration-300"
                  style={{ width: `${pct}%` }}
                />
              </div>
              {totalFound !== null && (
                <p className="text-xs text-indigo-300 font-medium pt-1">
                  ✓ {t('scanner.scanDone', { found: totalFound })}
                </p>
              )}
            </div>
          )}

          {/* Found devices list */}
          {foundList.length > 0 && (
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 max-h-80 overflow-y-auto scrollbar-thin space-y-1.5">
              <p className="text-xs text-gray-500 uppercase tracking-wider font-semibold mb-2">
                {t('scanner.foundDevices', { count: foundList.length, defaultValue: 'Znalezione urządzenia ({{count}})' })}
              </p>
              {foundList.map((d, i) => (
                <div key={i} className="flex items-center gap-2 text-sm">
                  <CheckCircle2 size={14} className="text-green-400 shrink-0" />
                  <span className="text-green-300 font-mono">{d.ip}</span>
                  {d.identity && <span className="text-gray-300">— {d.identity}</span>}
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
    </div>
  )
}

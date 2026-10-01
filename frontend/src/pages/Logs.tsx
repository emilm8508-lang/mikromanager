import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { devicesApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { ScrollText, Play, Square, Trash2 } from 'lucide-react'
import { cn } from '../lib/utils'
import { useTranslation } from 'react-i18next'

interface LogEntry {
  '.id'?: string
  time?: string
  topics?: string
  message?: string
  [k: string]: unknown
}

const topicColor = (topics?: string) => {
  if (!topics) return 'text-slate-600'
  if (topics.includes('error') || topics.includes('critical')) return 'text-red-600'
  if (topics.includes('warning')) return 'text-amber-600'
  if (topics.includes('info')) return 'text-blue-600'
  if (topics.includes('firewall')) return 'text-orange-400'
  return 'text-slate-600'
}

const isFirewallLog = (l: LogEntry) => (l.topics ?? '').toLowerCase().includes('firewall')

// RouterOS firewall rule log message format (confirmed against real
// output, e.g. "forward: in:ether1 out:bridge, proto TCP (SYN),
// 192.168.1.5:54321->8.8.8.8:443, len 60") - best-effort, a message that
// doesn't match this shape (an older RouterOS build, or a rule with a
// custom log-prefix in front) just falls back to the raw text below,
// never hidden.
const FW_LOG_RE = /^(\w+):\s*(?:in:([^\s,]+)\s*)?(?:out:([^\s,]+)\s*)?,?\s*proto (\S+)[^,]*,\s*([\d.]+)(?::(\d+))?->([\d.]+)(?::(\d+))?/

interface ParsedFwLog {
  chain: string; inIface?: string; outIface?: string; proto: string
  srcIp: string; srcPort?: string; dstIp: string; dstPort?: string
}

function parseFirewallLog(message?: string): ParsedFwLog | null {
  if (!message) return null
  const m = FW_LOG_RE.exec(message)
  if (!m) return null
  return {
    chain: m[1], inIface: m[2], outIface: m[3], proto: m[4],
    srcIp: m[5], srcPort: m[6], dstIp: m[7], dstPort: m[8],
  }
}

export function Logs() {
  const { t } = useTranslation()
  const { data: devices = [] } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [streaming, setStreaming] = useState(false)
  const [filter, setFilter] = useState('')
  const [firewallOnly, setFirewallOnly] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  const devicesWithCreds = devices.filter(d => d.credential_id)

  const fetchOnce = async () => {
    if (!selectedId) return
    try {
      const res = await fetch(`/api/logs/${selectedId}`)
      const json = await res.json()
      setLogs(json)
    } catch {
      setLogs([{ message: t('deviceDetail.connectionError'), topics: 'error' }])
    }
  }

  const startStream = () => {
    if (!selectedId || esRef.current) return
    setStreaming(true)
    setLogs([])
    const es = new EventSource(`/api/logs/${selectedId}/stream`)
    esRef.current = es
    es.onmessage = (e) => {
      const entry: LogEntry = JSON.parse(e.data)
      setLogs(prev => [...prev.slice(-500), entry])
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
    es.onerror = () => { stopStream() }
  }

  const stopStream = () => {
    esRef.current?.close()
    esRef.current = null
    setStreaming(false)
  }

  useEffect(() => () => esRef.current?.close(), [])

  useEffect(() => {
    if (selectedId && !streaming) fetchOnce()
  }, [selectedId])

  const filtered = logs.filter(l =>
    (!firewallOnly || isFirewallLog(l)) &&
    (!filter ||
      (l.message ?? '').toLowerCase().includes(filter.toLowerCase()) ||
      (l.topics ?? '').toLowerCase().includes(filter.toLowerCase()))
  )

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-slate-900">{t('logs.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('logs.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-3 flex-wrap">
            <select
              className="bg-slate-100 border border-slate-300 rounded-lg px-3 py-2 text-sm text-slate-900"
              value={selectedId ?? ''}
              onChange={e => { stopStream(); setSelectedId(Number(e.target.value) || null); setLogs([]) }}
            >
              <option value="">{t('logs.selectDevice')}</option>
              {devicesWithCreds.map(d => (
                <option key={d.id} value={d.id}>
                  {d.identity || d.ip} {d.model ? `(${d.model})` : ''}
                </option>
              ))}
            </select>

            <input
              className="bg-slate-100 border border-slate-300 rounded-lg px-3 py-2 text-sm text-slate-900 flex-1 min-w-40"
              placeholder={t('logs.searchPlaceholder')}
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />

            <label className="flex items-center gap-1.5 text-sm text-slate-600 whitespace-nowrap">
              <input type="checkbox" checked={firewallOnly} onChange={e => setFirewallOnly(e.target.checked)} />
              {t('logs.firewallOnly')}
            </label>

            {!streaming ? (
              <Button variant="primary" size="sm" disabled={!selectedId} onClick={startStream}>
                <Play size={14} /> {t('logs.startStream')}
              </Button>
            ) : (
              <Button variant="danger" size="sm" onClick={stopStream}>
                <Square size={14} /> {t('logs.stopStream')}
              </Button>
            )}

            <Button variant="ghost" size="sm" onClick={() => setLogs([])}>
              <Trash2 size={14} />
            </Button>

            {streaming && <Badge variant="green" className="animate-pulse">â—Ź {t('logs.live')}</Badge>}
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {!selectedId ? (
            <div className="py-14 text-center">
              <ScrollText size={32} className="mx-auto text-slate-300 mb-3" />
              <p className="text-slate-500 text-sm">{t('logs.selectDevice')}</p>
              {devicesWithCreds.length === 0 && (
                <p className="text-amber-600 text-xs mt-2">{t('deviceDetail.noCredsBadge')}</p>
              )}
            </div>
          ) : (
            <div className="bg-slate-50 font-mono text-xs h-[500px] overflow-y-auto p-4 space-y-0.5 scrollbar-thin">
              {filtered.length === 0 && (
                <p className="text-slate-400 text-center py-8">{t('logs.noLogs')}</p>
              )}
              {filtered.map((l, i) => {
                const fw = isFirewallLog(l) ? parseFirewallLog(l.message) : null
                return (
                  <div key={l['.id'] ?? i} className="flex gap-3 hover:bg-white/60 px-1 py-0.5 rounded">
                    <span className="text-slate-400 shrink-0 w-20">{l.time ?? ''}</span>
                    <span className={cn('shrink-0 w-28 truncate', topicColor(l.topics))}>{l.topics ?? ''}</span>
                    {fw ? (
                      <span className="text-slate-700 break-all">
                        <span className="text-slate-500">{fw.chain}</span>{' '}
                        <span className="text-indigo-600">{fw.proto}</span>{' '}
                        <span className="font-semibold">{fw.srcIp}{fw.srcPort ? `:${fw.srcPort}` : ''}</span>
                        {' → '}
                        <span className="font-semibold">{fw.dstIp}{fw.dstPort ? `:${fw.dstPort}` : ''}</span>
                        {fw.inIface && <span className="text-slate-400"> (in:{fw.inIface}{fw.outIface ? ` out:${fw.outIface}` : ''})</span>}
                      </span>
                    ) : (
                      <span className="text-slate-700 break-all">{l.message ?? JSON.stringify(l)}</span>
                    )}
                  </div>
                )
              })}
              <div ref={bottomRef} />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

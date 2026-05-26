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
  if (!topics) return 'text-gray-400'
  if (topics.includes('error') || topics.includes('critical')) return 'text-red-400'
  if (topics.includes('warning')) return 'text-yellow-400'
  if (topics.includes('info')) return 'text-blue-400'
  if (topics.includes('firewall')) return 'text-orange-400'
  return 'text-gray-400'
}

export function Logs() {
  const { t } = useTranslation()
  const { data: devices = [] } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [streaming, setStreaming] = useState(false)
  const [filter, setFilter] = useState('')
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
    !filter ||
    (l.message ?? '').toLowerCase().includes(filter.toLowerCase()) ||
    (l.topics ?? '').toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-gray-100">{t('logs.title')}</h1>
        <p className="text-sm text-gray-500 mt-0.5">{t('logs.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-3 flex-wrap">
            <select
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100"
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
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 flex-1 min-w-40"
              placeholder={t('common.search')}
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />

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

            {streaming && <Badge variant="green" className="animate-pulse">● {t('logs.live')}</Badge>}
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {!selectedId ? (
            <div className="py-14 text-center">
              <ScrollText size={32} className="mx-auto text-gray-700 mb-3" />
              <p className="text-gray-500 text-sm">{t('logs.selectDevice')}</p>
              {devicesWithCreds.length === 0 && (
                <p className="text-yellow-500 text-xs mt-2">{t('deviceDetail.noCredsBadge')}</p>
              )}
            </div>
          ) : (
            <div className="bg-gray-950 font-mono text-xs h-[500px] overflow-y-auto p-4 space-y-0.5 scrollbar-thin">
              {filtered.length === 0 && (
                <p className="text-gray-600 text-center py-8">{t('logs.noLogs')}</p>
              )}
              {filtered.map((l, i) => (
                <div key={l['.id'] ?? i} className="flex gap-3 hover:bg-gray-900/50 px-1 py-0.5 rounded">
                  <span className="text-gray-600 shrink-0 w-20">{l.time ?? ''}</span>
                  <span className={cn('shrink-0 w-28 truncate', topicColor(l.topics))}>{l.topics ?? ''}</span>
                  <span className="text-gray-300 break-all">{l.message ?? JSON.stringify(l)}</span>
                </div>
              ))}
              <div ref={bottomRef} />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

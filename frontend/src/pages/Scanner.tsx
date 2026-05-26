import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scannerApi, credentialsApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Search, Plus, Trash2, CheckCircle2, AlertCircle, Info, KeyRound } from 'lucide-react'
import { useTranslation } from 'react-i18next'

interface ScanEvent {
  status: 'scanning' | 'found' | 'done' | 'info'
  cidr?: string
  device?: Record<string, unknown>
  message?: string
}

export function Scanner() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: ranges = [] } = useQuery({ queryKey: ['ranges'], queryFn: scannerApi.listRanges })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })

  const [newCidr, setNewCidr] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [scanning, setScanning] = useState(false)
  const [events, setEvents] = useState<ScanEvent[]>([])

  const addRange = useMutation({
    mutationFn: () => scannerApi.addRange({ cidr: newCidr, label: newLabel || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ranges'] }); setNewCidr(''); setNewLabel('') },
  })

  const deleteRange = useMutation({
    mutationFn: scannerApi.deleteRange,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ranges'] }),
  })

  const runScan = () => {
    setEvents([])
    setScanning(true)
    const es = new EventSource('/api/scanner/run')
    es.onmessage = (e) => {
      const data: ScanEvent = JSON.parse(e.data)
      setEvents(prev => [...prev, data])
      if (data.status === 'done') {
        es.close()
        setScanning(false)
        qc.invalidateQueries({ queryKey: ['devices'] })
      }
    }
    es.onerror = () => { es.close(); setScanning(false) }
  }

  const found = events.filter(e => e.status === 'found')
  const matchedCount = found.filter(e => e.device?.matched_credential).length

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
            <Button variant="primary" onClick={runScan} disabled={scanning || ranges.length === 0}>
              <Search size={16} />
              {scanning ? t('scanner.scanning') : t('scanner.scanNow')}
            </Button>
          </div>

          {creds.length === 0 && (
            <div className="bg-amber-950/30 border border-amber-900/50 rounded-lg px-4 py-2.5 text-xs text-amber-300 flex items-center gap-2">
              <AlertCircle size={14} />
              {t('scanner.noCredsWarn')}
            </div>
          )}

          {/* Events */}
          {events.length > 0 && (
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 max-h-96 overflow-y-auto scrollbar-thin space-y-1.5">
              {events.map((ev, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  {ev.status === 'info' && (
                    <>
                      <Info size={14} className="text-gray-400 mt-0.5 shrink-0" />
                      <span className="text-gray-400">{ev.message}</span>
                    </>
                  )}
                  {ev.status === 'scanning' && (
                    <>
                      <Search size={14} className="text-blue-400 mt-0.5 shrink-0" />
                      <span className="text-blue-400">{t('scanner.scanningCidr', { cidr: ev.cidr })}</span>
                    </>
                  )}
                  {ev.status === 'found' && ev.device && (
                    <>
                      <CheckCircle2 size={14} className="text-green-400 mt-0.5 shrink-0" />
                      <span className="text-green-300 font-mono">{String(ev.device.ip)}</span>
                      {ev.device.identity != null && <span className="text-gray-300">— {String(ev.device.identity)}</span>}
                      {ev.device.model != null && <Badge variant="blue" className="ml-1">{String(ev.device.model)}</Badge>}
                      {ev.device.has_snmp ? <Badge variant="purple" className="ml-1">SNMP</Badge> : null}
                      {ev.device.matched_credential != null && (
                        <Badge variant="green" className="ml-1 inline-flex items-center gap-1">
                          <KeyRound size={10} />
                          {String(ev.device.matched_credential)}
                        </Badge>
                      )}
                    </>
                  )}
                  {ev.status === 'done' && (
                    <>
                      <AlertCircle size={14} className="text-indigo-400 mt-0.5 shrink-0" />
                      <span className="text-indigo-300 font-medium">
                        {t('scanner.scanDone', { found: found.length })}
                        {creds.length > 0 && ' ' + t('scanner.scanDoneMatched', { matched: matchedCount })}.
                      </span>
                    </>
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

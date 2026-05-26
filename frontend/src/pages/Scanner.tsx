import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scannerApi, credentialsApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Search, Plus, Trash2, Wifi, CheckCircle2, AlertCircle } from 'lucide-react'

interface ScanEvent {
  status: 'scanning' | 'found' | 'done'
  cidr?: string
  device?: Record<string, unknown>
}

export function Scanner() {
  const qc = useQueryClient()
  const { data: ranges = [] } = useQuery({ queryKey: ['ranges'], queryFn: scannerApi.listRanges })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })

  const [newCidr, setNewCidr] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [scanning, setScanning] = useState(false)
  const [selectedCred, setSelectedCred] = useState<string>('')
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
    const url = `/api/scanner/run${selectedCred ? `?credential_id=${selectedCred}` : ''}`
    const es = new EventSource(url)
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

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Skaner sieci</h1>
        <p className="text-sm text-gray-500 mt-0.5">Wykryj urządzenia Mikrotik w podanych zakresach IP</p>
      </div>

      {/* Ranges */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-gray-300">Zakresy skanowania</h2>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input placeholder="192.168.1.0/24" value={newCidr} onChange={e => setNewCidr(e.target.value)}
              className="flex-1" />
            <Input placeholder="Etykieta (opcjonalnie)" value={newLabel} onChange={e => setNewLabel(e.target.value)}
              className="flex-1" />
            <Button variant="primary" onClick={() => addRange.mutate()} disabled={!newCidr}>
              <Plus size={16} /> Dodaj
            </Button>
          </div>

          {ranges.length === 0 ? (
            <p className="text-sm text-gray-500 text-center py-4">Brak zakresów. Dodaj zakres CIDR powyżej.</p>
          ) : (
            <div className="space-y-2">
              {ranges.map(r => (
                <div key={r.id} className="flex items-center gap-3 bg-gray-800 rounded-lg px-4 py-2.5">
                  <span className="font-mono text-sm text-gray-200">{r.cidr}</span>
                  {r.label && <span className="text-xs text-gray-500">{r.label}</span>}
                  <Badge variant={r.active ? 'green' : 'gray'}>{r.active ? 'Aktywny' : 'Nieaktywny'}</Badge>
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
          <h2 className="text-sm font-semibold text-gray-300">Uruchom skan</h2>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3 items-end">
            <div className="flex-1">
              <label className="text-xs font-medium text-gray-400 block mb-1">Poświadczenia do wzbogacania (opcjonalnie)</label>
              <select
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100"
                value={selectedCred}
                onChange={e => setSelectedCred(e.target.value)}
              >
                <option value="">— tylko wykrycie portów —</option>
                {creds.map(c => (
                  <option key={c.id} value={c.id}>{c.name} ({c.username})</option>
                ))}
              </select>
            </div>
            <Button variant="primary" onClick={runScan} disabled={scanning || ranges.length === 0}>
              <Search size={16} />
              {scanning ? 'Skanowanie...' : 'Skanuj teraz'}
            </Button>
          </div>

          {/* Events */}
          {events.length > 0 && (
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 max-h-80 overflow-y-auto scrollbar-thin space-y-1.5">
              {events.map((ev, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  {ev.status === 'scanning' && (
                    <>
                      <Search size={14} className="text-blue-400 mt-0.5 shrink-0" />
                      <span className="text-blue-400">Skanuję {ev.cidr}...</span>
                    </>
                  )}
                  {ev.status === 'found' && ev.device && (
                    <>
                      <CheckCircle2 size={14} className="text-green-400 mt-0.5 shrink-0" />
                      <span className="text-green-300 font-mono">{String(ev.device.ip)}</span>
                      {ev.device.identity && <span className="text-gray-400">— {String(ev.device.identity)}</span>}
                      {ev.device.model && <Badge variant="blue" className="ml-1">{String(ev.device.model)}</Badge>}
                    </>
                  )}
                  {ev.status === 'done' && (
                    <>
                      <AlertCircle size={14} className="text-indigo-400 mt-0.5 shrink-0" />
                      <span className="text-indigo-300 font-medium">Skan zakończony. Znaleziono: {found.length} urządzeń.</span>
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

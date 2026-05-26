import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi, credentialsApi, Device } from '../lib/api'
import { Card, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Modal } from '../components/ui/Modal'
import { Input } from '../components/ui/Input'
import { Server, Pencil, Trash2, ExternalLink, Plus } from 'lucide-react'
import { Link } from 'react-router-dom'
import { formatDate } from '../lib/utils'

function AddDeviceModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const [form, setForm] = useState({ ip: '', name: '', api_port: 8728, web_port: 80, credential_id: '' })

  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  const create = useMutation({
    mutationFn: () => devicesApi.create({
      ...form,
      api_port: Number(form.api_port),
      web_port: Number(form.web_port),
      credential_id: form.credential_id ? Number(form.credential_id) : undefined,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['devices'] }); onClose() },
  })

  return (
    <form onSubmit={e => { e.preventDefault(); create.mutate() }} className="space-y-4">
      <Input label="Adres IP" value={form.ip} onChange={set('ip')} required placeholder="192.168.1.1" />
      <Input label="Nazwa (opcjonalnie)" value={form.name} onChange={set('name')} placeholder="Router główny" />
      <div className="grid grid-cols-2 gap-3">
        <Input label="Port API" type="number" value={form.api_port} onChange={set('api_port')} />
        <Input label="Port Web" type="number" value={form.web_port} onChange={set('web_port')} />
      </div>
      <div>
        <label className="text-xs font-medium text-gray-400 block mb-1">Poświadczenia</label>
        <select className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100"
          value={form.credential_id} onChange={set('credential_id')}>
          <option value="">— brak —</option>
          {creds.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>
      <div className="flex gap-2 justify-end pt-2">
        <Button type="button" variant="ghost" onClick={onClose}>Anuluj</Button>
        <Button type="submit" variant="primary">Dodaj urządzenie</Button>
      </div>
    </form>
  )
}

export function Devices() {
  const qc = useQueryClient()
  const { data: devices = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const [addOpen, setAddOpen] = useState(false)
  const [search, setSearch] = useState('')

  const remove = useMutation({
    mutationFn: devicesApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['devices'] }),
  })

  const credMap = Object.fromEntries(creds.map(c => [c.id, c.name]))

  const filtered = devices.filter(d =>
    !search || d.ip.includes(search) ||
    (d.identity ?? '').toLowerCase().includes(search.toLowerCase()) ||
    (d.model ?? '').toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Urządzenia</h1>
          <p className="text-sm text-gray-500 mt-0.5">{devices.length} zarejestrowanych urządzeń</p>
        </div>
        <Button variant="primary" onClick={() => setAddOpen(true)}>
          <Plus size={16} /> Dodaj ręcznie
        </Button>
      </div>

      <Input placeholder="Szukaj po IP, nazwie, modelu..." value={search}
        onChange={e => setSearch(e.target.value)} />

      {isLoading ? (
        <p className="text-gray-500 text-sm text-center py-12">Ładowanie...</p>
      ) : filtered.length === 0 ? (
        <Card><CardContent className="py-12 text-center">
          <Server size={32} className="mx-auto text-gray-700 mb-3" />
          <p className="text-gray-500 text-sm">Brak urządzeń. Uruchom skaner lub dodaj ręcznie.</p>
        </CardContent></Card>
      ) : (
        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500">
                <th className="px-5 py-3 text-left">IP / Tożsamość</th>
                <th className="px-5 py-3 text-left">Model</th>
                <th className="px-5 py-3 text-left">ROS</th>
                <th className="px-5 py-3 text-left">Możliwości</th>
                <th className="px-5 py-3 text-left">Poświadczenia</th>
                <th className="px-5 py-3 text-left">Status</th>
                <th className="px-5 py-3 text-left">Ostatnio widziano</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => (
                <tr key={d.id} className="border-b border-gray-800/50 hover:bg-gray-800/20 transition-colors">
                  <td className="px-5 py-3">
                    <Link to={`/devices/${d.id}`} className="text-indigo-400 hover:underline font-mono block">{d.ip}</Link>
                    {d.identity && <span className="text-xs text-gray-500">{d.identity}</span>}
                    {d.name && <span className="text-xs text-gray-600 block">{d.name}</span>}
                  </td>
                  <td className="px-5 py-3 text-gray-300">{d.model || '—'}</td>
                  <td className="px-5 py-3 text-gray-400 font-mono text-xs">{d.ros_version || '—'}</td>
                  <td className="px-5 py-3">
                    <div className="flex gap-1 flex-wrap">
                      {d.has_api && <Badge variant="blue">API</Badge>}
                      {d.has_ssh && <Badge variant="gray">SSH</Badge>}
                      {d.has_web && <Badge variant="yellow">Web</Badge>}
                    </div>
                  </td>
                  <td className="px-5 py-3 text-gray-400 text-xs">
                    {d.credential_id ? credMap[d.credential_id] || '—' : <span className="text-red-400">brak</span>}
                  </td>
                  <td className="px-5 py-3">
                    <Badge variant={d.online ? 'green' : 'red'}>{d.online ? 'Online' : 'Offline'}</Badge>
                  </td>
                  <td className="px-5 py-3 text-gray-500 text-xs">{formatDate(d.last_seen)}</td>
                  <td className="px-5 py-3">
                    <div className="flex gap-1">
                      <Link to={`/devices/${d.id}`}>
                        <Button size="sm" variant="ghost"><ExternalLink size={13} /></Button>
                      </Link>
                      <Button size="sm" variant="danger" onClick={() => remove.mutate(d.id)}>
                        <Trash2 size={13} />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Dodaj urządzenie">
        <AddDeviceModal onClose={() => setAddOpen(false)} />
      </Modal>
    </div>
  )
}

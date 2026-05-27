import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi, credentialsApi, systemApi } from '../lib/api'
import { Card, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Modal } from '../components/ui/Modal'
import { Input } from '../components/ui/Input'
import { Server, Trash2, ExternalLink, Plus, ArrowUpCircle, CheckCircle2 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { formatDate } from '../lib/utils'
import { useTranslation } from 'react-i18next'

function AddDeviceModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
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
      <Input label={t('devices.ipAddress')} value={form.ip} onChange={set('ip')} required placeholder="192.168.1.1" />
      <Input label={t('devices.nameOptional')} value={form.name} onChange={set('name')} placeholder="Main router" />
      <div className="grid grid-cols-2 gap-3">
        <Input label={t('devices.portApi')} type="number" value={form.api_port} onChange={set('api_port')} />
        <Input label={t('devices.portWeb')} type="number" value={form.web_port} onChange={set('web_port')} />
      </div>
      <div>
        <label className="text-xs font-medium text-slate-600 block mb-1">{t('nav.credentials')}</label>
        <select className="w-full bg-slate-100 border border-slate-300 rounded-lg px-3 py-2 text-sm text-slate-900"
          value={form.credential_id} onChange={set('credential_id')}>
          <option value="">{t('devices.noCredsOption')}</option>
          {creds.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>
      <div className="flex gap-2 justify-end pt-2">
        <Button type="button" variant="ghost" onClick={onClose}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary">{t('devices.addDeviceBtn')}</Button>
      </div>
    </form>
  )
}

export function Devices() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: devices = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const { data: versionStatus } = useQuery({
    queryKey: ['version-status'],
    queryFn: systemApi.versionStatus,
    refetchInterval: 6 * 3600 * 1000,
  })
  const [addOpen, setAddOpen] = useState(false)
  const [search, setSearch] = useState('')

  const versionMap = new Map(
    (versionStatus?.devices ?? []).map(v => [v.id, v.target])
  )

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
          <h1 className="text-xl font-bold text-slate-900">{t('devices.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('devices.subtitle', { count: devices.length })}</p>
        </div>
        <Button variant="primary" onClick={() => setAddOpen(true)}>
          <Plus size={16} /> {t('common.addManual')}
        </Button>
      </div>

      <Input placeholder={t('devices.searchPlaceholder')} value={search}
        onChange={e => setSearch(e.target.value)} />

      {isLoading ? (
        <p className="text-slate-500 text-sm text-center py-12">{t('common.loading')}</p>
      ) : filtered.length === 0 ? (
        <Card><CardContent className="py-12 text-center">
          <Server size={32} className="mx-auto text-slate-300 mb-3" />
          <p className="text-slate-500 text-sm">{t('devices.noDevices')}</p>
        </CardContent></Card>
      ) : (
        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500">
                <th className="px-5 py-3 text-left">{t('devices.cols.ipIdentity')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.model')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.ros')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.capabilities')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.credentials')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.status')}</th>
                <th className="px-5 py-3 text-left">{t('devices.cols.lastSeen')}</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => (
                <tr key={d.id} className="border-b border-slate-200 hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3">
                    <Link to={`/devices/${d.id}`} className="text-indigo-600 hover:underline font-mono block">{d.ip}</Link>
                    {d.identity && <span className="text-xs text-slate-500">{d.identity}</span>}
                    {d.name && <span className="text-xs text-slate-400 block">{d.name}</span>}
                  </td>
                  <td className="px-5 py-3 text-slate-700">{d.model || '—'}</td>
                  <td className="px-5 py-3 font-mono text-xs">
                    {d.ros_version ? (
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-700">{d.ros_version}</span>
                        {(() => {
                          const v = versionMap.get(d.id)
                          if (!v) return null
                          if (v.status === 'up_to_date') {
                            return <CheckCircle2 size={12} className="text-green-600" />
                          }
                          if (v.status === 'outdated') {
                            return (
                              <Badge variant="yellow" className="inline-flex items-center gap-1 text-[10px]">
                                <ArrowUpCircle size={10} /> → {v.target}
                              </Badge>
                            )
                          }
                          return null
                        })()}
                      </div>
                    ) : '—'}
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex gap-1 flex-wrap">
                      {d.has_api && <Badge variant="blue">API</Badge>}
                      {d.has_ssh && <Badge variant="gray">SSH</Badge>}
                      {d.has_web && <Badge variant="yellow">Web</Badge>}
                      {d.has_snmp && <Badge variant="purple">SNMP</Badge>}
                    </div>
                  </td>
                  <td className="px-5 py-3 text-slate-600 text-xs">
                    {d.credential_id ? credMap[d.credential_id] || '—' : <span className="text-red-600">{t('devices.noCredsBadge')}</span>}
                  </td>
                  <td className="px-5 py-3">
                    <Badge variant={d.online ? 'green' : 'red'}>{d.online ? t('common.online') : t('common.offline')}</Badge>
                  </td>
                  <td className="px-5 py-3 text-slate-500 text-xs">{formatDate(d.last_seen)}</td>
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

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title={t('devices.addTitle')}>
        <AddDeviceModal onClose={() => setAddOpen(false)} />
      </Modal>
    </div>
  )
}

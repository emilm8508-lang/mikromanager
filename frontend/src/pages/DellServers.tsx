import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { dellApi, windowsApi, credentialsApi, DellServerOut, DellHealth, DellServerInput } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Modal } from '../components/ui/Modal'
import { Input } from '../components/ui/Input'
import { Server, Plus, Trash2, RefreshCw, ChevronDown, ChevronUp, KeyRound, Pencil } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function healthBadgeVariant(h: DellHealth): 'red' | 'yellow' | 'green' | 'gray' {
  if (h === 'Critical') return 'red'
  if (h === 'Warning') return 'yellow'
  if (h === 'OK') return 'green'
  return 'gray'
}

function ServerForm({ initial, onSave, onCancel }: {
  initial?: DellServerOut
  onSave: (data: DellServerInput) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: windowsHostsData } = useQuery({ queryKey: ['windows-hosts'], queryFn: windowsApi.hosts })
  const windowsHosts = windowsHostsData?.hosts ?? []
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })

  const [form, setForm] = useState({
    name: initial?.name ?? '',
    idrac_ip: initial?.idrac_ip ?? '',
    idrac_port: initial?.idrac_port ?? 443,
    windows_host_id: initial?.windows_host_id != null ? String(initial.windows_host_id) : '',
    credential_id: initial?.credential_id != null ? String(initial.credential_id) : '',
  })

  const quickAddCred = useMutation({
    mutationFn: () => credentialsApi.create({
      name: 'iDRAC (domyślne root/calvin)', username: 'root', password: 'calvin',
    }),
    onSuccess: (cred) => {
      qc.invalidateQueries({ queryKey: ['credentials'] })
      setForm(f => ({ ...f, credential_id: String(cred.id) }))
    },
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave({
      name: form.name || undefined,
      idrac_ip: form.idrac_ip || undefined,
      idrac_port: form.idrac_port,
      windows_host_id: form.windows_host_id ? parseInt(form.windows_host_id) : null,
      credential_id: form.credential_id ? parseInt(form.credential_id) : null,
    })
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <Input label={t('dell.nameLabel')} value={form.name}
        onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
        placeholder={t('dell.namePlaceholder') as string} />

      <div className="grid grid-cols-2 gap-3">
        <Input label={t('dell.idracIpLabel')} value={form.idrac_ip}
          onChange={e => setForm(f => ({ ...f, idrac_ip: e.target.value }))}
          placeholder="192.168.1.50" />
        <Input label={t('dell.idracPortLabel')} type="number" value={form.idrac_port}
          onChange={e => setForm(f => ({ ...f, idrac_port: parseInt(e.target.value) || 443 }))} />
      </div>
      <p className="text-[11px] text-slate-500 -mt-2">{t('dell.idracIpHint')}</p>

      <div>
        <label className="block text-xs font-medium text-slate-600 mb-1">{t('dell.windowsHostLabel')}</label>
        <select
          value={form.windows_host_id}
          onChange={e => setForm(f => ({ ...f, windows_host_id: e.target.value }))}
          className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-700 bg-white"
        >
          <option value="">{t('dell.windowsHostNone')}</option>
          {windowsHosts.map(h => (
            <option key={h.id} value={h.id}>{h.hostname || h.ip}</option>
          ))}
        </select>
        <p className="text-[11px] text-slate-500 mt-1">{t('dell.windowsHostHint')}</p>
      </div>

      <div>
        <label className="block text-xs font-medium text-slate-600 mb-1">{t('dell.credentialLabel')}</label>
        <div className="flex items-center gap-2">
          <select
            value={form.credential_id}
            onChange={e => setForm(f => ({ ...f, credential_id: e.target.value }))}
            className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-700 bg-white"
          >
            <option value="">{t('dell.credentialDefault')}</option>
            {creds.map(c => <option key={c.id} value={c.id}>{c.name} ({c.username})</option>)}
          </select>
          <Button type="button" variant="secondary" size="sm" onClick={() => quickAddCred.mutate()} disabled={quickAddCred.isPending}>
            <KeyRound size={12} /> root/calvin
          </Button>
        </div>
        <p className="text-[11px] text-slate-500 mt-1">{t('dell.credentialHint')}</p>
      </div>

      <div className="flex gap-2 justify-end pt-2">
        <Button type="button" variant="ghost" onClick={onCancel}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary">{t('common.save')}</Button>
      </div>
    </form>
  )
}

function SelLogSection({ serverId }: { serverId: number }) {
  const { t } = useTranslation()
  const { data: entries = [] } = useQuery({
    queryKey: ['dell-sel', serverId],
    queryFn: () => dellApi.sel(serverId),
  })

  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2">
      <p className="text-xs font-semibold text-slate-700">{t('dell.selTitle')}</p>
      {entries.length === 0 ? (
        <p className="text-xs text-slate-400">{t('dell.noSelEntries')}</p>
      ) : (
        <div className="space-y-1 max-h-64 overflow-y-auto">
          {entries.map(e => (
            <div key={e.id} className="flex items-start gap-2 text-xs bg-white border border-slate-200 rounded px-2 py-1.5">
              <Badge variant={healthBadgeVariant(e.severity as DellHealth)} className="text-[10px] shrink-0">
                {e.severity || '—'}
              </Badge>
              <span className="text-slate-700 flex-1">{e.message}</span>
              {e.logged_at && <span className="text-slate-400 font-mono shrink-0">{new Date(e.logged_at).toLocaleString()}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ServerCard({ server, onEdit }: { server: DellServerOut; onEdit: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [showSel, setShowSel] = useState(false)

  const check = useMutation({
    mutationFn: () => dellApi.check(server.id),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['dell-servers'] }), 8000),
  })

  const remove = useMutation({
    mutationFn: () => dellApi.delete(server.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dell-servers'] }),
  })

  const components = server.components || {}

  return (
    <div className="border border-slate-200 rounded-lg p-3 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <span className="font-mono text-sm text-slate-800">{server.name || server.service_tag || server.idrac_ip}</span>
          {server.model && <span className="text-xs text-slate-500 ml-2">{server.model}</span>}
          {server.access_method && (
            <Badge variant="blue" className="text-[10px] ml-2">{t(`dell.accessMethod.${server.access_method}`)}</Badge>
          )}
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          {server.health_rollup && (
            <Badge variant={healthBadgeVariant(server.health_rollup)} className="text-[10px]">
              {t('dell.overallHealth')}: {server.health_rollup}
            </Badge>
          )}
          {(['cpu', 'memory', 'power', 'fans_temperature', 'storage'] as const).map(k => (
            components[k] ? (
              <Badge key={k} variant={healthBadgeVariant(components[k] as DellHealth)} className="text-[10px]">
                {t(`dell.component.${k}`)}: {components[k]}
              </Badge>
            ) : null
          ))}
        </div>
      </div>

      <div className="flex items-center justify-between flex-wrap gap-2 text-xs text-slate-500">
        <div>
          {server.last_check_at && <span>{t('dell.lastCheck')}: {new Date(server.last_check_at).toLocaleString()}</span>}
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={() => check.mutate()} disabled={check.isPending}>
            <RefreshCw size={12} className={check.isPending ? 'animate-spin' : ''} /> {t('dell.checkNow')}
          </Button>
          <Button size="sm" variant="secondary" onClick={onEdit}><Pencil size={12} /></Button>
          <Button size="sm" variant="secondary" onClick={() => setShowSel(s => !s)}>
            {showSel ? <ChevronUp size={12} /> : <ChevronDown size={12} />} {t('dell.selToggle')}
          </Button>
          <Button size="sm" variant="danger" onClick={() => { if (confirm(t('dell.deleteConfirm') as string)) remove.mutate() }}>
            <Trash2 size={12} />
          </Button>
        </div>
      </div>

      {showSel && <SelLogSection serverId={server.id} />}

      {server.last_status === 'error' && server.last_error && (
        <p className="text-xs text-red-600">{server.last_error}</p>
      )}
    </div>
  )
}

export function DellServers() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: servers = [], isLoading } = useQuery({
    queryKey: ['dell-servers'],
    queryFn: dellApi.servers,
    refetchInterval: 30_000,
  })

  const [modal, setModal] = useState<'add' | 'edit' | null>(null)
  const [editing, setEditing] = useState<DellServerOut | null>(null)

  const add = useMutation({
    mutationFn: dellApi.add,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['dell-servers'] }); setModal(null) },
  })

  const update = useMutation({
    mutationFn: ({ id, data }: { id: number; data: DellServerInput }) => dellApi.update(id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['dell-servers'] }); setModal(null) },
  })

  return (
    <div className="p-6 space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Server size={20} className="text-indigo-600" />
          <h1 className="text-lg font-semibold text-slate-900">{t('nav.dellServers')}</h1>
        </div>
        <Button variant="primary" onClick={() => setModal('add')}>
          <Plus size={16} /> {t('common.add')}
        </Button>
      </div>
      <p className="text-sm text-slate-500 -mt-2">{t('dell.subtitle')}</p>

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">{t('dell.serversTitle')}</h2>
        </CardHeader>
        <CardContent className="space-y-2">
          {isLoading ? (
            <p className="text-sm text-slate-500">{t('common.loading')}</p>
          ) : servers.length === 0 ? (
            <p className="text-sm text-slate-500">{t('dell.noServers')}</p>
          ) : (
            servers.map(s => (
              <ServerCard key={s.id} server={s} onEdit={() => { setEditing(s); setModal('edit') }} />
            ))
          )}
        </CardContent>
      </Card>

      <Modal open={modal === 'add'} onClose={() => setModal(null)} title={t('dell.addTitle')}>
        <ServerForm onSave={data => add.mutate(data)} onCancel={() => setModal(null)} />
      </Modal>

      <Modal open={modal === 'edit'} onClose={() => setModal(null)} title={t('dell.editTitle')}>
        {editing && (
          <ServerForm initial={editing}
            onSave={data => update.mutate({ id: editing.id, data })}
            onCancel={() => setModal(null)} />
        )}
      </Modal>
    </div>
  )
}

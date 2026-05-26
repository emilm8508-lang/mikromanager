import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { credentialsApi, Credential } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { Input } from '../components/ui/Input'
import { Plus, Pencil, Trash2, Key } from 'lucide-react'

function CredentialForm({ initial, onSave, onCancel }: {
  initial?: Credential
  onSave: (data: { name: string; username: string; password: string; description?: string }) => void
  onCancel: () => void
}) {
  const [form, setForm] = useState({
    name: initial?.name ?? '',
    username: initial?.username ?? '',
    password: '',
    description: initial?.description ?? '',
  })

  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  return (
    <form onSubmit={e => { e.preventDefault(); onSave(form) }} className="space-y-4">
      <Input label="Nazwa" value={form.name} onChange={set('name')} required placeholder="np. Admin główny" />
      <Input label="Login" value={form.username} onChange={set('username')} required placeholder="admin" />
      <Input label="Hasło" type="password" value={form.password} onChange={set('password')}
        required={!initial} placeholder={initial ? '(zostaw puste = bez zmian)' : ''} />
      <Input label="Opis (opcjonalny)" value={form.description} onChange={set('description')} />
      <div className="flex gap-2 justify-end pt-2">
        <Button type="button" variant="ghost" onClick={onCancel}>Anuluj</Button>
        <Button type="submit" variant="primary">Zapisz</Button>
      </div>
    </form>
  )
}

export function Credentials() {
  const qc = useQueryClient()
  const { data: creds = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })

  const [modal, setModal] = useState<'create' | 'edit' | null>(null)
  const [editing, setEditing] = useState<Credential | null>(null)

  const create = useMutation({
    mutationFn: credentialsApi.create,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['credentials'] }); setModal(null) },
  })

  const update = useMutation({
    mutationFn: ({ id, data }: { id: number; data: any }) => credentialsApi.update(id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['credentials'] }); setModal(null) },
  })

  const remove = useMutation({
    mutationFn: credentialsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  })

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Poświadczenia</h1>
          <p className="text-sm text-gray-500 mt-0.5">Zarządzaj loginami do urządzeń</p>
        </div>
        <Button variant="primary" onClick={() => setModal('create')}>
          <Plus size={16} /> Dodaj
        </Button>
      </div>

      <div className="grid gap-3">
        {creds.length === 0 && (
          <Card>
            <CardContent className="py-12 text-center">
              <Key size={32} className="mx-auto text-gray-700 mb-3" />
              <p className="text-gray-500 text-sm">Brak poświadczeń. Dodaj pierwsze.</p>
            </CardContent>
          </Card>
        )}
        {creds.map(c => (
          <Card key={c.id} className="flex items-center gap-4 px-5 py-4">
            <div className="w-9 h-9 bg-indigo-600/20 rounded-lg flex items-center justify-center">
              <Key size={16} className="text-indigo-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-medium text-gray-200">{c.name}</p>
              <p className="text-sm text-gray-500">Login: <span className="text-gray-300 font-mono">{c.username}</span></p>
              {c.description && <p className="text-xs text-gray-600 mt-0.5">{c.description}</p>}
            </div>
            <div className="flex gap-2">
              <Button size="sm" variant="ghost" onClick={() => { setEditing(c); setModal('edit') }}>
                <Pencil size={14} />
              </Button>
              <Button size="sm" variant="danger" onClick={() => remove.mutate(c.id)}>
                <Trash2 size={14} />
              </Button>
            </div>
          </Card>
        ))}
      </div>

      <Modal open={modal === 'create'} onClose={() => setModal(null)} title="Nowe poświadczenia">
        <CredentialForm onSave={data => create.mutate(data)} onCancel={() => setModal(null)} />
      </Modal>

      <Modal open={modal === 'edit'} onClose={() => setModal(null)} title="Edytuj poświadczenia">
        {editing && (
          <CredentialForm
            initial={editing}
            onSave={data => update.mutate({ id: editing.id, data })}
            onCancel={() => setModal(null)}
          />
        )}
      </Modal>
    </div>
  )
}

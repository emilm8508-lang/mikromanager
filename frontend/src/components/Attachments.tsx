import { useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Paperclip, Trash2, Upload } from 'lucide-react'
import { procurementApi } from '../lib/api'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

function size(n: number) {
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} kB`
}

// Files on a contract, an order or an asset (services/procurement.py, 3.92): uploaded here, always downloaded (never shown as a page).
export function Attachments({ kind, id, compact }: { kind: 'contract' | 'po' | 'asset'; id: number; compact?: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const input = useRef<HTMLInputElement>(null)
  const q = useQuery({ queryKey: ['attachments', kind, id], queryFn: () => procurementApi.attachments(kind, id) })
  const inv = () => { qc.invalidateQueries({ queryKey: ['attachments', kind, id] }); qc.invalidateQueries({ queryKey: ['procurement'] }) }
  const up = useMutation({ mutationFn: (f: File) => procurementApi.upload(kind, id, f), onSuccess: inv })
  const del = useMutation({ mutationFn: (aid: number) => procurementApi.removeAttachment(aid), onSuccess: inv })
  const list = q.data ?? []
  return (
    <div className="space-y-1 text-xs">
      {!compact && <div className="font-medium text-slate-700 flex items-center gap-1"><Paperclip size={12} /> {t('proc.attachments')}</div>}
      {list.map(a => (
        <div key={a.id} className="flex items-center gap-2">
          <a href={procurementApi.downloadUrl(a.id)} className="text-indigo-600 hover:underline truncate">{a.filename}</a>
          <span className="text-slate-400">{size(a.size)} · {new Date(a.at).toLocaleDateString()}{a.by ? ` · ${a.by}` : ''}</span>
          <button onClick={() => { if (window.confirm(`${t('proc.removeFile')}: ${a.filename}?`)) del.mutate(a.id) }} className="text-slate-400 hover:text-red-600"><Trash2 size={12} /></button>
        </div>
      ))}
      <input ref={input} type="file" className="hidden" accept=".pdf,.png,.jpg,.jpeg,.gif,.webp,.txt,.csv,.doc,.docx,.xls,.xlsx,.odt,.ods,.msg,.eml"
        onChange={e => { const f = e.target.files?.[0]; if (f) up.mutate(f); e.target.value = '' }} />
      <button onClick={() => input.current?.click()} disabled={up.isPending} className="flex items-center gap-1 text-indigo-600 hover:underline disabled:opacity-50">
        <Upload size={12} /> {up.isPending ? t('proc.uploading') : t('proc.addFile')}
      </button>
      {up.isError && <div className="text-red-700">{errText(up.error)}</div>}
    </div>
  )
}

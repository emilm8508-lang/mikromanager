import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Plug, ClipboardCopy, Check, ChevronDown, ChevronRight, Trash2 } from 'lucide-react'
import { centralApi } from '../lib/api'

// Central's AI connector (ovh/mcp.php + oauth.php): the person adds Central to their own Claude / ChatGPT as a custom connector and
// signs in with their Central account; the model of their subscription then reads Central through read-only tools. This card gives
// the address, the steps, and the list of connected apps with a way to take the access back.

export function McpConnector() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const q = useQuery({ queryKey: ['mcp-connections'], queryFn: centralApi.mcpConnections, enabled: open, retry: false })
  const revoke = useMutation({
    mutationFn: (id: string) => centralApi.mcpRevoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mcp-connections'] }),
  })
  const url = q.data?.url
  const copy = () => {
    if (!url) return
    void navigator.clipboard.writeText(url).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
  }
  const when = (s: string | null) => (s ? new Date(s).toLocaleString() : '—')
  return (
    <div className="bg-white border border-slate-200 rounded-xl">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center gap-2 px-4 py-3 text-left">
        {open ? <ChevronDown size={16} className="text-slate-400" /> : <ChevronRight size={16} className="text-slate-400" />}
        <Plug size={16} className="text-indigo-600" />
        <span className="font-semibold text-sm text-slate-800">{t('mcp.title')}</span>
        <span className="text-xs text-slate-500 ml-2 hidden sm:inline">{t('mcp.short')}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-4 text-sm text-slate-700">
          <p>{t('mcp.intro')}</p>
          {q.isLoading && <div className="text-slate-500">…</div>}
          {q.error && <div className="text-red-700 bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-xs">{t('mcp.loadError')}: {(q.error as Error).message}</div>}
          {q.data && !q.data.enabled && <div className="text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 text-xs">{t('mcp.disabled')}</div>}
          {q.data && !q.data.per_user_account && <div className="text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 text-xs">{t('mcp.needUser')}</div>}
          {url && (
            <div>
              <div className="text-xs font-medium text-slate-500 mb-1">{t('mcp.urlLabel')}</div>
              <div className="flex gap-2">
                <code className="flex-1 min-w-0 truncate bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs">{url}</code>
                <button onClick={copy} className="flex items-center gap-1 text-xs border border-slate-300 rounded-lg px-3 hover:bg-slate-50">
                  {copied ? <Check size={14} className="text-emerald-600" /> : <ClipboardCopy size={14} />} {t('mcp.copy')}
                </button>
              </div>
            </div>
          )}
          <div className="grid sm:grid-cols-2 gap-3">
            <div className="border border-slate-200 rounded-lg p-3">
              <div className="font-semibold text-slate-800 mb-1">Claude</div>
              <ol className="list-decimal pl-4 space-y-0.5 text-xs">
                <li>{t('mcp.claude1')}</li><li>{t('mcp.claude2')}</li><li>{t('mcp.claude3')}</li><li>{t('mcp.claude4')}</li>
              </ol>
            </div>
            <div className="border border-slate-200 rounded-lg p-3">
              <div className="font-semibold text-slate-800 mb-1">ChatGPT</div>
              <ol className="list-decimal pl-4 space-y-0.5 text-xs">
                <li>{t('mcp.gpt1')}</li><li>{t('mcp.gpt2')}</li><li>{t('mcp.gpt3')}</li><li>{t('mcp.gpt4')}</li>
              </ol>
            </div>
          </div>
          <p className="text-xs text-slate-500">{t('mcp.menusNote')}</p>
          <div className="text-xs text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">{t('mcp.dataNote')}</div>
          <div>
            <div className="font-semibold text-slate-800 mb-1">{t('mcp.connections')}</div>
            {q.data && q.data.connections.length === 0 && <div className="text-xs text-slate-500">{t('mcp.none')}</div>}
            {q.data && q.data.connections.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-slate-500 border-b border-slate-200">
                    <th className="py-1.5 pr-3">{t('mcp.colApp')}</th><th className="pr-3">{t('mcp.colUser')}</th><th className="pr-3">{t('mcp.colSince')}</th>
                    <th className="pr-3">{t('mcp.colLast')}</th><th className="pr-3">{t('mcp.colUntil')}</th><th />
                  </tr></thead>
                  <tbody>
                    {q.data.connections.map(c => (
                      <tr key={c.id} className="border-b border-slate-100">
                        <td className="py-1.5 pr-3"><div className="font-medium">{c.client || t('mcp.unnamed')}</div><div className="text-slate-400">{c.host}</div></td>
                        <td className="pr-3">{c.user}</td><td className="pr-3">{when(c.since)}</td><td className="pr-3">{when(c.last_used)}</td><td className="pr-3">{when(c.until)}</td>
                        <td className="text-right">
                          <button disabled={revoke.isPending} onClick={() => { if (confirm(t('mcp.revokeConfirm') as string)) revoke.mutate(c.id) }}
                            className="inline-flex items-center gap-1 text-red-700 border border-red-200 rounded px-2 py-1 hover:bg-red-50 disabled:opacity-50">
                            <Trash2 size={12} /> {t('mcp.revoke')}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

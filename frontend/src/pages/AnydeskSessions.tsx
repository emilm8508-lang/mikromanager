import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { anydeskApi, AnydeskSessionOut } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { History, RefreshCw, Search, AlertTriangle, Tag } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function formatDuration(sec: number | null): string {
  if (sec == null) return '—'
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

function LabelCell({ session }: { session: AnydeskSessionOut }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(session.label ?? '')

  const save = useMutation({
    mutationFn: () => anydeskApi.setLabel(session.cid, value.trim()),
    onSuccess: () => {
      setEditing(false)
      qc.invalidateQueries({ queryKey: ['anydesk-sessions'] })
      qc.invalidateQueries({ queryKey: ['anydesk-labels'] })
    },
  })

  if (editing) {
    return (
      <div className="flex items-center gap-1">
        <input
          autoFocus
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') save.mutate(); if (e.key === 'Escape') setEditing(false) }}
          onBlur={() => save.mutate()}
          className="border border-slate-300 rounded px-1.5 py-0.5 text-xs w-36"
          placeholder={t('anydesk.labelPlaceholder') as string}
        />
      </div>
    )
  }

  return (
    <button
      onClick={() => { setValue(session.label ?? ''); setEditing(true) }}
      className="flex items-center gap-1 text-left hover:underline"
      title={t('anydesk.editLabel') as string}
    >
      {session.label ? (
        <span className="text-slate-800">{session.label}</span>
      ) : (
        <span className="text-slate-400 flex items-center gap-1"><Tag size={11} /> {t('anydesk.addLabel')}</span>
      )}
    </button>
  )
}

export function AnydeskSessions() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query.trim()), 300)
    return () => clearTimeout(timer)
  }, [query])

  const { data: status } = useQuery({ queryKey: ['anydesk-status'], queryFn: anydeskApi.status })

  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['anydesk-sessions', debouncedQuery],
    queryFn: () => anydeskApi.sessions(debouncedQuery ? { q: debouncedQuery } : undefined),
  })

  const sync = useMutation({
    mutationFn: anydeskApi.sync,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['anydesk-sessions'] })
      qc.invalidateQueries({ queryKey: ['anydesk-status'] })
    },
  })

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <History size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('nav.anydeskSessions')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('anydesk.subtitle')}</p>

      {status && !status.connection_trace_found && (
        <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-800">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" />
          <span>{t('anydesk.noTraceFile')}: <span className="font-mono">{status.connection_trace_path}</span></span>
        </div>
      )}

      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={t('anydesk.searchPlaceholder') as string}
            className="w-full border border-slate-300 rounded-lg pl-8 pr-3 py-1.5 text-sm"
          />
        </div>
        <Button variant="secondary" onClick={() => sync.mutate()} disabled={sync.isPending || !status?.connection_trace_found}>
          <RefreshCw size={13} className={sync.isPending ? 'animate-spin' : ''} />
          {t('anydesk.syncNow')}
        </Button>
      </div>

      {sync.data && (
        <p className="text-xs text-slate-500">
          {t('anydesk.syncResult', { inserted: sync.data.inserted, updated: sync.data.updated })}
          {!sync.data.service_trace_found && <span className="ml-2 text-amber-700">{t('anydesk.noServiceTrace')}</span>}
        </p>
      )}

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">
            {t('anydesk.sessionsTitle')} {!isLoading && `(${sessions.length})`}
          </h2>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-slate-500">{t('common.loading')}</p>
          ) : sessions.length === 0 ? (
            <p className="text-sm text-slate-500">{t('anydesk.empty')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b">
                    <th className="py-1 pr-3">{t('anydesk.colStarted')}</th>
                    <th className="pr-3">{t('anydesk.colCid')}</th>
                    <th className="pr-3">{t('anydesk.colLabel')}</th>
                    <th className="pr-3">{t('anydesk.colDuration')}</th>
                    <th className="pr-3">{t('anydesk.colMethod')}</th>
                    <th>{t('anydesk.colStatus')}</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map(s => (
                    <tr key={s.id} className="border-b border-slate-100">
                      <td className="py-2 text-xs text-slate-600 whitespace-nowrap">{new Date(s.started_at).toLocaleString()}</td>
                      <td className="font-mono text-xs">{s.cid}</td>
                      <td><LabelCell session={s} /></td>
                      <td className="text-xs">
                        {formatDuration(s.duration_sec)}
                        {s.duration_sec == null && !s.rejected && (
                          <span className="text-slate-400 ml-1" title={t('anydesk.durationUnknownHint') as string}>*</span>
                        )}
                      </td>
                      <td className="text-xs text-slate-500">{s.auth_method ?? '—'}</td>
                      <td>
                        {s.rejected ? (
                          <Badge variant="red" className="text-[10px]">{t('anydesk.rejected')}</Badge>
                        ) : (
                          <Badge variant="green" className="text-[10px]">{t('anydesk.connected')}</Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="text-[11px] text-slate-400 mt-2">* {t('anydesk.durationUnknownFootnote')}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

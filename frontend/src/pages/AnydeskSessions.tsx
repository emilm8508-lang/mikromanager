import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { anydeskApi, AnydeskSessionOut, AnydeskCategory } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { History, RefreshCw, Search, AlertTriangle, Tag, FileDown } from 'lucide-react'
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

function formatMinutes(min: number): string {
  const h = Math.floor(min / 60)
  const m = min % 60
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

function csvSafe(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value)
  if (s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0])) return "'" + s
  return s
}

function downloadCsv(filename: string, header: string[], rows: unknown[]) {
  const lines = [header.join(',')]
  for (const r of rows) lines.push(header.map(k => csvSafe((r as Record<string, unknown>)[k])).join(','))
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
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
      <input
        autoFocus
        value={value}
        onChange={e => setValue(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') save.mutate(); if (e.key === 'Escape') setEditing(false) }}
        onBlur={() => save.mutate()}
        className="border border-slate-300 rounded px-1.5 py-0.5 text-xs w-32"
        placeholder={t('anydesk.labelPlaceholder') as string}
      />
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

function ClassifyCell({ session }: { session: AnydeskSessionOut }) {
  const qc = useQueryClient()
  const [note, setNote] = useState(session.note ?? '')

  const setCategory = useMutation({
    mutationFn: (category: AnydeskCategory | null) => anydeskApi.classify(session.id, category, session.note ?? undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['anydesk-sessions'] }),
  })
  const saveNote = useMutation({
    mutationFn: () => anydeskApi.classify(session.id, session.category, note),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['anydesk-sessions'] }),
  })

  return (
    <div className="flex items-center gap-1.5">
      <select
        value={session.category ?? ''}
        onChange={e => setCategory.mutate((e.target.value || null) as AnydeskCategory | null)}
        className="text-xs border border-slate-300 rounded px-1 py-0.5"
      >
        <option value="">—</option>
        <option value="billable">billable</option>
        <option value="training">training</option>
        <option value="internal">internal</option>
      </select>
      <input
        value={note}
        onChange={e => setNote(e.target.value)}
        onBlur={() => saveNote.mutate()}
        className="text-xs border border-slate-300 rounded px-1.5 py-0.5 w-28"
      />
    </div>
  )
}

function SessionsTab({ query, setQuery }: { query: string; setQuery: (v: string) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
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

  const exportCsv = () => downloadCsv(
    `anydesk_sessions_${new Date().toISOString().slice(0, 10)}.csv`,
    ['started_at', 'ended_at', 'duration_sec', 'cid', 'label', 'auth_method', 'rejected', 'category', 'note'],
    sessions,
  )

  return (
    <div className="space-y-4">
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
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={exportCsv} disabled={sessions.length === 0}>
            <FileDown size={13} /> {t('anydesk.exportCsv')}
          </Button>
          <Button variant="secondary" onClick={() => sync.mutate()} disabled={sync.isPending || !status?.connection_trace_found}>
            <RefreshCw size={13} className={sync.isPending ? 'animate-spin' : ''} />
            {t('anydesk.syncNow')}
          </Button>
        </div>
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
                    <th className="pr-3">{t('anydesk.colStatus')}</th>
                    <th>{t('anydesk.colCategory')}</th>
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
                      <td>{!s.rejected && <ClassifyCell session={s} />}</td>
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

function SummaryTab() {
  const { t } = useTranslation()
  const { data: rows = [], isLoading } = useQuery({ queryKey: ['anydesk-summary'], queryFn: () => anydeskApi.summary() })

  const exportCsv = () => downloadCsv(
    `anydesk_summary_${new Date().toISOString().slice(0, 10)}.csv`,
    ['client', 'month', 'billable_minutes', 'training_minutes', 'internal_minutes', 'unclassified_minutes', 'session_count'],
    rows,
  )

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">{t('anydesk.summaryTitle')}</h2>
          <Button variant="secondary" onClick={exportCsv} disabled={rows.length === 0}>
            <FileDown size={13} /> {t('anydesk.exportCsv')}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <p className="text-sm text-slate-500">{t('common.loading')}</p>
        ) : rows.length === 0 ? (
          <p className="text-sm text-slate-500">{t('anydesk.noSummary')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b">
                  <th className="py-1 pr-3">{t('anydesk.colLabel')}</th>
                  <th className="pr-3">{t('anydesk.colMonth')}</th>
                  <th className="pr-3">billable</th>
                  <th className="pr-3">training</th>
                  <th className="pr-3">internal</th>
                  <th className="pr-3 text-slate-400">unclassified</th>
                  <th>{t('anydesk.colSessions')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i} className="border-b border-slate-100">
                    <td className="py-2">{r.client}</td>
                    <td className="font-mono text-xs">{r.month}</td>
                    <td>{formatMinutes(r.billable_minutes)}</td>
                    <td>{formatMinutes(r.training_minutes)}</td>
                    <td>{formatMinutes(r.internal_minutes)}</td>
                    <td className="text-slate-400">{formatMinutes(r.unclassified_minutes)}</td>
                    <td className="text-xs text-slate-500">{r.session_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function AnydeskSessions() {
  const { t } = useTranslation()
  const [tab, setTab] = useState<'sessions' | 'summary'>('sessions')
  const [query, setQuery] = useState('')

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <History size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('nav.anydeskSessions')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('anydesk.subtitle')}</p>

      <div className="flex gap-1 border-b border-slate-200 text-sm">
        <button onClick={() => setTab('sessions')}
          className={`px-3 py-1.5 border-b-2 -mb-px ${tab === 'sessions' ? 'border-indigo-600 text-indigo-600 font-medium' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>
          {t('anydesk.tabSessions')}
        </button>
        <button onClick={() => setTab('summary')}
          className={`px-3 py-1.5 border-b-2 -mb-px ${tab === 'summary' ? 'border-indigo-600 text-indigo-600 font-medium' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>
          {t('anydesk.tabSummary')}
        </button>
      </div>

      {tab === 'sessions' ? <SessionsTab query={query} setQuery={setQuery} /> : <SummaryTab />}
    </div>
  )
}

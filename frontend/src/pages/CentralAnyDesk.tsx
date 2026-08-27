import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  centralAnydeskApi, centralApi, centralSession,
  type AnydeskSession, type AnydeskClientMap, type CentralAnydeskSummaryRow, type CentralAnydeskStatus, type AnydeskCategory, type AnydeskUnassignedRow,
} from '../lib/api'
import { UsersLoginForm } from './CentralUsers'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Modal } from '../components/ui/Modal'
import { RefreshCw, FileDown, Upload, Trash2, Clock, UserCheck } from 'lucide-react'

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function formatMinutes(min: number | null): string {
  if (min === null) return '—'
  const h = Math.floor(min / 60)
  const m = min % 60
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

function csvSafe(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value)
  if (s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0])) return "'" + s
  return s
}

// ── AnyDesk time-tracking panel — reuses the same OVH per-user login as
// CentralUsers.tsx (global-admin only, this is internal billing data).

export function AnydeskPanel() {
  const { t } = useTranslation()
  const [session, setSessionState] = useState(centralSession.load())

  if (!session) {
    return <UsersLoginForm onLoggedIn={s => setSessionState(s)} />
  }
  if (session.role !== 'admin' || (session.allowedTenants !== null && session.allowedTenants !== undefined)) {
    return (
      <div className="bg-white rounded-lg border border-slate-200 p-4 text-sm text-slate-600">
        <p>{t('centralUsers.notGlobalAdmin')}</p>
        <button
          onClick={() => { centralSession.clear(); setSessionState(null) }}
          className="mt-2 text-xs text-indigo-600 hover:text-indigo-500"
        >
          {t('centralUsers.switchAccount')}
        </button>
      </div>
    )
  }
  return <AnydeskManagePanel />
}

type SubTab = 'sessions' | 'mapping' | 'summary'

function AnydeskManagePanel() {
  const { t } = useTranslation()
  const [tab, setTab] = useState<SubTab>('sessions')

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Clock size={16} className="text-indigo-600" />
        <h3 className="font-semibold text-slate-900">{t('central.anydesk.title')}</h3>
      </div>
      <div className="flex gap-1 border-b border-slate-200 text-sm">
        {(['sessions', 'mapping', 'summary'] as SubTab[]).map(x => (
          <button key={x} onClick={() => setTab(x)}
            className={`px-3 py-1.5 border-b-2 -mb-px ${tab === x ? 'border-indigo-600 text-indigo-600 font-medium' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>
            {t(`central.anydesk.tab.${x}`)}
          </button>
        ))}
      </div>
      {tab === 'sessions' && <SessionsTab />}
      {tab === 'mapping' && <MappingTab />}
      {tab === 'summary' && <SummaryTab />}
    </div>
  )
}

function StatusBar({ status, onSync, syncing }: { status: CentralAnydeskStatus | null; onSync: () => void; syncing: boolean }) {
  const { t } = useTranslation()
  if (!status) return null
  return (
    <div className="flex items-center justify-between text-xs bg-slate-50 border border-slate-200 rounded px-3 py-2">
      <div className="text-slate-600">
        {!status.configured && <span className="text-amber-700 mr-2">{t('central.anydesk.notConfigured')}</span>}
        {status.configured && (
          <>
            {t('central.anydesk.lastSync')}: <span className="font-mono">{formatDate(status.last_sync_at)}</span>
            {status.last_error && <span className="text-red-600 ml-2">({status.last_error})</span>}
          </>
        )}
        <span className="ml-2 text-slate-400">
          {t('central.anydesk.totalUnclassified', { total: status.sessions_total, unclassified: status.sessions_unclassified })}
        </span>
      </div>
      <button onClick={onSync} disabled={syncing || !status.configured}
        className="text-indigo-600 hover:text-indigo-800 disabled:opacity-40 inline-flex items-center gap-1">
        <RefreshCw size={12} className={syncing ? 'animate-spin' : ''} /> {t('central.anydesk.syncNow')}
      </button>
    </div>
  )
}

function SessionsTab() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<CentralAnydeskStatus | null>(null)
  const [sessions, setSessions] = useState<AnydeskSession[]>([])
  const [tenants, setTenants] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [importing, setImporting] = useState(false)
  const [tenantFilter, setTenantFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [showUnassigned, setShowUnassigned] = useState(false)

  const reload = async () => {
    setLoading(true)
    try {
      const [st, s, tn, mp] = await Promise.all([
        centralAnydeskApi.status(),
        centralAnydeskApi.sessions({
          tenant: tenantFilter || undefined,
          category: (categoryFilter || undefined) as any,
        }),
        centralApi.tenants(),
        centralAnydeskApi.mappingList(),
      ])
      setStatus(st)
      setSessions(s.sessions ?? [])
      // Includes AnyDesk-only clients (no agent), not just agent tenants —
      // time tracking isn't limited to clients with a MikroManager agent.
      const agentTenants = (tn.tenants ?? []).map(x => x.id)
      const anydeskTenants = (mp.mappings ?? []).map(x => x.tenant)
      setTenants(Array.from(new Set([...agentTenants, ...anydeskTenants])).sort())
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { reload() }, [tenantFilter, categoryFilter])

  const sync = async () => {
    setSyncing(true)
    try { await centralAnydeskApi.syncNow(); await reload() }
    catch (e) { alert((e as Error).message) }
    finally { setSyncing(false) }
  }

  const importCsvFile = async (file: File) => {
    setImporting(true)
    try {
      const text = await file.text()
      const r = await centralAnydeskApi.importCsv(text)
      alert(t('central.anydesk.importResult', { imported: r.imported, skipped: r.skipped }) as string)
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setImporting(false)
    }
  }

  const classify = async (s: AnydeskSession, category: AnydeskCategory | null) => {
    try {
      await centralAnydeskApi.classify(s.id, category, s.note ?? undefined)
      setSessions(prev => prev.map(x => x.id === s.id ? { ...x, category } : x))
    } catch (e) { alert((e as Error).message) }
  }

  const saveNote = async (s: AnydeskSession, note: string) => {
    try { await centralAnydeskApi.classify(s.id, s.category, note) }
    catch (e) { alert((e as Error).message) }
  }

  const exportCsv = () => {
    const header = ['start_time', 'end_time', 'tenant', 'from_alias', 'from_cid', 'to_alias', 'to_cid', 'duration_sec', 'billed_minutes', 'active', 'state', 'category', 'note']
    const lines = [header.join(',')]
    for (const s of sessions) {
      lines.push(header.map(k => csvSafe((s as any)[k])).join(','))
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `anydesk_sessions_${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-3">
      <StatusBar status={status} onSync={sync} syncing={syncing} />
      <div className="flex gap-2 flex-wrap">
        <select value={tenantFilter} onChange={e => setTenantFilter(e.target.value)}
          className="text-xs border border-slate-300 rounded px-2 py-1.5">
          <option value="">{t('central.anydesk.allTenants')}</option>
          {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
        </select>
        <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
          className="text-xs border border-slate-300 rounded px-2 py-1.5">
          <option value="">{t('central.anydesk.allCategories')}</option>
          <option value="unclassified">{t('central.anydesk.category.unclassified')}</option>
          <option value="billable">{t('central.anydesk.category.billable')}</option>
          <option value="training">{t('central.anydesk.category.training')}</option>
          <option value="internal">{t('central.anydesk.category.internal')}</option>
        </select>
        <label className="ml-auto">
          <input type="file" accept=".csv,text/csv" className="hidden" disabled={importing}
            onChange={e => { const f = e.target.files?.[0]; if (f) importCsvFile(f); e.target.value = '' }} />
          <span className={`inline-flex items-center gap-2 rounded-lg font-medium text-sm px-3 py-1.5 cursor-pointer bg-slate-200 hover:bg-slate-300 text-slate-800 ${importing ? 'opacity-50 pointer-events-none' : ''}`}>
            <Upload size={14} /> {importing ? t('common.loading') : t('central.anydesk.importCsv')}
          </span>
        </label>
        <Button variant="secondary" onClick={exportCsv} disabled={sessions.length === 0}>
          <FileDown size={14} /> {t('central.anydesk.exportCsv')}
        </Button>
      </div>
      <p className="text-[11px] text-slate-400">{t('central.anydesk.importCsvHint')}</p>
      {!!status?.sessions_unassigned && (
        <Button variant="secondary" onClick={() => setShowUnassigned(true)}>
          <UserCheck size={14} /> {t('central.anydesk.assignUnassigned', { count: status.sessions_unassigned })}
        </Button>
      )}
      <Modal open={showUnassigned} onClose={() => { setShowUnassigned(false); reload() }} title={t('central.anydesk.assignUnassignedTitle') as string}>
        <UnassignedModalBody tenants={tenants} onClose={() => setShowUnassigned(false)} />
      </Modal>
      {loading ? (
        <p className="text-sm text-slate-500 py-4">{t('common.loading')}</p>
      ) : sessions.length === 0 ? (
        <p className="text-sm text-slate-500 py-4">{t('central.anydesk.noSessions')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-slate-500 border-b border-slate-200">
                <th className="py-1.5 pr-3">{t('central.anydesk.cols.date')}</th>
                <th className="py-1.5 pr-3">{t('central.anydesk.cols.tenant')}</th>
                <th className="py-1.5 pr-3">{t('central.anydesk.cols.remote')}</th>
                <th className="py-1.5 pr-3">{t('central.anydesk.cols.duration')}</th>
                <th className="py-1.5 pr-3">{t('central.anydesk.cols.billed')}</th>
                <th className="py-1.5 pr-3">{t('central.anydesk.cols.category')}</th>
                <th className="py-1.5 pr-3">{t('central.anydesk.cols.note')}</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map(s => (
                <tr key={s.id} className="border-b border-slate-100">
                  <td className="py-1.5 pr-3 whitespace-nowrap">{formatDate(s.start_time)}</td>
                  <td className="py-1.5 pr-3">
                    {s.tenant ? <Badge variant="blue" className="text-[10px]">{s.tenant}</Badge> : <span className="text-slate-400">{t('central.anydesk.unassigned')}</span>}
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-slate-500">{s.to_alias || s.to_cid}</td>
                  <td className="py-1.5 pr-3">{s.active ? <Badge variant="yellow" className="text-[10px]">{t('central.anydesk.active')}</Badge> : formatMinutes(s.duration_sec !== null ? Math.round(s.duration_sec / 60) : null)}</td>
                  <td className="py-1.5 pr-3">{formatMinutes(s.billed_minutes)}</td>
                  <td className="py-1.5 pr-3">
                    <select value={s.category ?? ''} onChange={e => classify(s, (e.target.value || null) as AnydeskCategory | null)}
                      className="text-xs border border-slate-300 rounded px-1 py-0.5">
                      <option value="">{t('central.anydesk.category.unclassified')}</option>
                      <option value="billable">{t('central.anydesk.category.billable')}</option>
                      <option value="training">{t('central.anydesk.category.training')}</option>
                      <option value="internal">{t('central.anydesk.category.internal')}</option>
                    </select>
                  </td>
                  <td className="py-1.5 pr-3">
                    <input defaultValue={s.note ?? ''} onBlur={e => saveNote(s, e.target.value)}
                      className="text-xs border border-slate-300 rounded px-1.5 py-0.5 w-32" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// Focused review queue for assigning a tenant to distinct unmapped AnyDesk
// clients (grouped, not one row per session) — the "przypisz nieprzypisane"
// flow requested to replace hunting for the right cid in the full session
// list. Assigning here reuses mappingAdd(), whose backend retroactively
// fixes every already-imported session with that cid, not just future ones.
function UnassignedModalBody({ tenants, onClose }: { tenants: string[]; onClose: () => void }) {
  const { t } = useTranslation()
  const [rows, setRows] = useState<AnydeskUnassignedRow[] | null>(null)
  const [tenantInputs, setTenantInputs] = useState<Record<string, string>>({})
  const [assigning, setAssigning] = useState<string | null>(null)

  useEffect(() => {
    centralAnydeskApi.unassigned().then(r => setRows(r.unassigned ?? [])).catch(e => alert((e as Error).message))
  }, [])

  const assign = async (row: AnydeskUnassignedRow) => {
    const tenant = (tenantInputs[row.cid] ?? '').trim()
    if (!tenant) return
    setAssigning(row.cid)
    try {
      await centralAnydeskApi.mappingAdd({ tenant, anydesk_cid: row.cid, label: row.alias ?? undefined })
      setRows(prev => (prev ?? []).filter(r => r.cid !== row.cid))
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setAssigning(null)
    }
  }

  if (rows === null) return <p className="text-sm text-slate-500 py-4">{t('common.loading')}</p>
  if (rows.length === 0) {
    return (
      <div className="py-4 text-center space-y-3">
        <p className="text-sm text-green-700">{t('central.anydesk.allAssigned')}</p>
        <Button variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">{t('central.anydesk.unassignedRemaining', { count: rows.length })}</p>
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {rows.map(row => (
          <div key={row.cid} className="border border-slate-200 rounded p-2.5 flex items-center gap-2">
            <div className="flex-1 min-w-0">
              <p className="text-sm font-mono text-slate-800">{row.alias || row.cid}</p>
              <p className="text-[11px] text-slate-400">
                {t('central.anydesk.unassignedRowHint', { count: row.session_count, date: formatDate(row.last_seen) })}
              </p>
            </div>
            <Input list="anydesk-tenant-suggestions" placeholder={t('central.anydesk.tenantPlaceholder') as string}
              value={tenantInputs[row.cid] ?? ''}
              onChange={e => setTenantInputs(prev => ({ ...prev, [row.cid]: e.target.value }))}
              className="w-40 shrink-0" />
            <datalist id="anydesk-tenant-suggestions">
              {tenants.map(tn => <option key={tn} value={tn} />)}
            </datalist>
            <Button size="sm" variant="primary" onClick={() => assign(row)}
              disabled={assigning === row.cid || !(tenantInputs[row.cid] ?? '').trim()}>
              {t('central.anydesk.assign')}
            </Button>
          </div>
        ))}
      </div>
    </div>
  )
}

function MappingTab() {
  const { t } = useTranslation()
  const [mappings, setMappings] = useState<AnydeskClientMap[]>([])
  const [tenants, setTenants] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [newTenant, setNewTenant] = useState('')
  const [newCid, setNewCid] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const reload = async () => {
    setLoading(true)
    try {
      const [m, tn] = await Promise.all([centralAnydeskApi.mappingList(), centralApi.tenants()])
      const mapped = m.mappings ?? []
      setMappings(mapped)
      // Suggestions only — combines agent tenants with clients already used
      // for AnyDesk mapping (which may have no agent at all). The field
      // itself stays free text, so any client name can be added.
      const agentTenants = (tn.tenants ?? []).map(x => x.id)
      const anydeskTenants = mapped.map(x => x.tenant)
      setTenants(Array.from(new Set([...agentTenants, ...anydeskTenants])).sort())
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { reload() }, [])

  const add = async () => {
    setSubmitting(true)
    try {
      await centralAnydeskApi.mappingAdd({ tenant: newTenant, anydesk_cid: newCid, label: newLabel || undefined })
      setNewTenant(''); setNewCid(''); setNewLabel('')
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  const del = async (m: AnydeskClientMap) => {
    if (!confirm(t('central.anydesk.confirmDeleteMapping', { cid: m.anydesk_cid }) as string)) return
    try { await centralAnydeskApi.mappingDelete(m.id); await reload() }
    catch (e) { alert((e as Error).message) }
  }

  return (
    <div className="space-y-3">
      <div className="border border-slate-200 rounded p-3 bg-slate-50 space-y-2">
        <div className="grid grid-cols-3 gap-2">
          <div>
            <Input list="anydesk-tenant-suggestions" placeholder={t('central.anydesk.tenantPlaceholder') as string}
              value={newTenant} onChange={e => setNewTenant(e.target.value)} />
            <datalist id="anydesk-tenant-suggestions">
              {tenants.map(tn => <option key={tn} value={tn} />)}
            </datalist>
          </div>
          <Input placeholder={t('central.anydesk.cidPlaceholder') as string} value={newCid}
            onChange={e => setNewCid(e.target.value.replace(/\D/g, ''))} />
          <Input placeholder={t('central.anydesk.labelPlaceholder') as string} value={newLabel}
            onChange={e => setNewLabel(e.target.value)} />
        </div>
        <div className="flex justify-end">
          <Button onClick={add} variant="primary" disabled={submitting || !newTenant || !newCid}>
            {t('central.anydesk.addMapping')}
          </Button>
        </div>
      </div>
      {loading ? (
        <p className="text-sm text-slate-500 py-4">{t('common.loading')}</p>
      ) : mappings.length === 0 ? (
        <p className="text-sm text-slate-500 py-4">{t('central.anydesk.noMappings')}</p>
      ) : (
        <div className="divide-y divide-slate-100">
          {mappings.map(m => (
            <div key={m.id} className="py-2 flex items-center justify-between text-sm">
              <div>
                <Badge variant="blue" className="text-[10px] mr-2">{m.tenant}</Badge>
                <span className="font-mono text-slate-700">{m.anydesk_cid}</span>
                {m.label && <span className="text-xs text-slate-400 ml-2">{m.label}</span>}
              </div>
              <button onClick={() => del(m)} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function SummaryTab() {
  const { t } = useTranslation()
  const [rows, setRows] = useState<CentralAnydeskSummaryRow[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    centralAnydeskApi.summary().then(r => setRows(r.summary ?? [])).catch(e => alert((e as Error).message)).finally(() => setLoading(false))
  }, [])

  const exportCsv = () => {
    const header = ['tenant', 'month', 'billable_minutes', 'training_minutes', 'internal_minutes', 'unclassified_minutes', 'session_count']
    const lines = [header.join(',')]
    for (const r of rows) {
      lines.push(header.map(k => csvSafe((r as any)[k])).join(','))
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `anydesk_summary_${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Button variant="secondary" onClick={exportCsv} disabled={rows.length === 0}>
          <FileDown size={14} /> {t('central.anydesk.exportCsv')}
        </Button>
      </div>
      {loading ? (
        <p className="text-sm text-slate-500 py-4">{t('common.loading')}</p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-slate-500 py-4">{t('central.anydesk.noSummary')}</p>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-slate-500 border-b border-slate-200">
              <th className="py-1.5 pr-3">{t('central.anydesk.cols.tenant')}</th>
              <th className="py-1.5 pr-3">{t('central.anydesk.cols.month')}</th>
              <th className="py-1.5 pr-3">{t('central.anydesk.category.billable')}</th>
              <th className="py-1.5 pr-3">{t('central.anydesk.category.training')}</th>
              <th className="py-1.5 pr-3">{t('central.anydesk.category.internal')}</th>
              <th className="py-1.5 pr-3">{t('central.anydesk.category.unclassified')}</th>
              <th className="py-1.5 pr-3">{t('central.anydesk.cols.sessions')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-b border-slate-100">
                <td className="py-1.5 pr-3"><Badge variant="blue" className="text-[10px]">{r.tenant}</Badge></td>
                <td className="py-1.5 pr-3 font-mono">{r.month}</td>
                <td className="py-1.5 pr-3">{formatMinutes(r.billable_minutes)}</td>
                <td className="py-1.5 pr-3">{formatMinutes(r.training_minutes)}</td>
                <td className="py-1.5 pr-3">{formatMinutes(r.internal_minutes)}</td>
                <td className="py-1.5 pr-3 text-slate-400">{formatMinutes(r.unclassified_minutes)}</td>
                <td className="py-1.5 pr-3">{r.session_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralHostmonHostStatus, type HostEventOut } from '../lib/api'
import { Radar, ChevronDown, ChevronUp, Download } from 'lucide-react'
import { formatDuration, formatTs, eventText } from './HostMonitor'

type Row = { tenant: string; lastSeen: string | null; host: CentralHostmonHostStatus }

// The per-host details (IP, MAC, switch port, recent log lines) ride only in
// the E2E-encrypted snapshot, so they are fetched per tenant on expand and
// only readable when that tenant's key was imported (same as inventory).
type Details = { ip: string | null; mac: string | null; ports: string[]; events: (HostEventOut & { cause: string | null })[] }
type DetailState =
  | { status: 'loading' }
  | { status: 'nokey' }
  | { status: 'none' }
  | { status: 'ok'; data: Details }

// Same OWASP CSV-formula-injection guard + BOM as CentralVulnerabilities.tsx.
function csvSafe(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value)
  const escaped = s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s
  return `"${escaped.replace(/"/g, '""')}"`
}

function download(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function HostCard({ row, expanded, onToggle, detail }: {
  row: Row; expanded: boolean; onToggle: () => void; detail?: DetailState
}) {
  const { t } = useTranslation()
  const { host, tenant } = row
  const down = host.state === 'down'
  const hasOutages = host.outages_24h > 0
  const tone = down ? 'border-red-400 bg-red-50' : hasOutages ? 'border-amber-300 bg-amber-50' : 'border-slate-300 bg-slate-50'

  return (
    <div className={`border-l-4 rounded-lg p-4 ${tone}`}>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">{tenant}</span>
          <span className="text-sm font-medium text-slate-900">{host.name}</span>
          <span className={`text-xs font-semibold px-2 py-0.5 rounded text-white ${down ? 'bg-red-600' : host.state === 'up' ? 'bg-green-600' : 'bg-slate-400'}`}>
            {host.state === 'up' ? t('hostmon.up') : down ? t('hostmon.down') : t('hostmon.unknown')}
          </span>
          {down && host.state_since && (
            <span className="text-xs text-red-700">{t('hostmon.downSince', { time: formatTs(host.state_since) })}</span>
          )}
        </div>
        <button onClick={onToggle} className="text-xs text-indigo-600 hover:underline flex items-center gap-1">
          {t('hostmonCentral.details')} {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
      </div>

      <div className="text-xs text-slate-600 mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5">
        <span>{t('hostmon.outages24h')}: <b>{host.outages_24h}</b>{host.downtime_24h_sec > 0 && ` (${formatDuration(host.downtime_24h_sec)})`}</span>
        <span>{t('hostmonCentral.outages7d')}: <b>{host.outages_7d}</b></span>
        {host.main_cause && (
          <span>{t('hostmonCentral.mainCause')}: <b>{t(`hostmon.cause.${host.main_cause}`)}</b></span>
        )}
      </div>
      {host.periodic_sec != null && (
        <p className="text-xs text-amber-800 mt-1">{t('hostmon.periodic', { interval: formatDuration(host.periodic_sec) })}</p>
      )}

      {expanded && (
        <div className="mt-3 space-y-3 border-t border-slate-200 pt-3">
          {host.recent_outages.length > 0 ? (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 border-b"><th className="py-1">{t('hostmon.colStart')}</th><th>{t('hostmon.colDuration')}</th><th>{t('hostmon.colCause')}</th></tr>
              </thead>
              <tbody>
                {host.recent_outages.map(o => (
                  <tr key={o.start} className="border-b border-slate-100">
                    <td className="py-1">{formatTs(o.start)}</td>
                    <td>{o.end ? formatDuration(o.duration_sec) : t('hostmon.ongoing')}</td>
                    <td>{t(`hostmon.cause.${o.code}`)}{o.confidence ? ` (${t(`hostmon.confidence.${o.confidence}`)})` : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-xs text-slate-500">{t('hostmon.noOutages')}</p>
          )}

          {(!detail || detail.status === 'loading') && <p className="text-xs text-slate-500">{t('common.loading')}</p>}
          {detail?.status === 'nokey' && <p className="text-xs text-amber-800">{t('hostmonCentral.noKey')}</p>}
          {detail?.status === 'none' && <p className="text-xs text-slate-500">{t('hostmonCentral.noDetails')}</p>}
          {detail?.status === 'ok' && (
            <div className="space-y-2">
              <div className="text-xs font-mono text-slate-700">
                {detail.data.ip || '—'} · {detail.data.mac || '—'}
                {detail.data.ports.length > 0 && <span className="text-slate-500"> · {detail.data.ports.join(', ')}</span>}
              </div>
              <div className="text-xs font-semibold text-slate-700">{t('hostmonCentral.recentEvents')}</div>
              {detail.data.events.length === 0 ? (
                <p className="text-xs text-slate-500">{t('hostmon.noEvents')}</p>
              ) : (
                <div className="max-h-72 overflow-y-auto border border-slate-200 rounded bg-white">
                  <table className="w-full text-xs">
                    <tbody>
                      {detail.data.events.map((e, i) => (
                        <tr key={i} className="border-b border-slate-100 align-top">
                          <td className="py-1 px-2 whitespace-nowrap text-slate-500">{formatTs(e.ts)}</td>
                          <td className="px-1 whitespace-nowrap text-slate-500">{t(`hostmon.source.${e.source}`)}{e.device ? ` · ${e.device}` : ''}</td>
                          <td className={`px-1 font-mono break-all ${e.severity === 'error' ? 'text-red-700' : e.severity === 'warn' ? 'text-amber-700' : 'text-slate-700'}`}>
                            {eventText(e as HostEventOut, t as any)}
                          </td>
                          <td className="px-1 whitespace-nowrap text-slate-500">{e.cause ? t(`hostmon.cause.${e.cause}`) : ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function CentralHostMonitor() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<Row[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenantFilter, setTenantFilter] = useState('all')
  const [stateFilter, setStateFilter] = useState<'all' | 'down' | 'outages'>('all')
  const [openKey, setOpenKey] = useState<string | null>(null)
  const [details, setDetails] = useState<Record<string, DetailState>>({})   // key: "tenant:hostId"

  const reload = async () => {
    try {
      const s = await centralApi.hostmonStatusAll()
      const flat: Row[] = []
      for (const tRow of s.tenants) {
        for (const host of tRow.hosts) flat.push({ tenant: tRow.tenant, lastSeen: tRow.last_seen, host })
      }
      flat.sort((a, b) =>
        Number(b.host.state === 'down') - Number(a.host.state === 'down')
        || b.host.outages_24h - a.host.outages_24h
        || a.host.name.localeCompare(b.host.name))
      setRows(flat)
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    reload()
    const iv = setInterval(reload, 30000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggle = async (row: Row) => {
    const key = `${row.tenant}:${row.host.id}`
    if (openKey === key) { setOpenKey(null); return }
    setOpenKey(key)
    setDetails(d => ({ ...d, [key]: { status: 'loading' } }))
    try {
      const snap = await centralApi.snapshot(row.tenant)
      const mine = snap?.hostmon_details?.[String(row.host.id)]
      const state: DetailState = !snap || snap._encrypted ? { status: 'nokey' }
        : mine ? { status: 'ok', data: mine as Details } : { status: 'none' }
      setDetails(d => ({ ...d, [key]: state }))
    } catch {
      setDetails(d => ({ ...d, [key]: { status: 'none' } }))
    }
  }

  if (!cfg) {
    return (
      <div className="p-6 max-w-5xl">
        <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">
          {t('alerts.needsCentral')}
        </div>
      </div>
    )
  }

  const tenants = [...new Set(rows.map(r => r.tenant))].sort()
  const visible = rows.filter(r =>
    (tenantFilter === 'all' || r.tenant === tenantFilter)
    && (stateFilter === 'all' || (stateFilter === 'down' ? r.host.state === 'down' : r.host.outages_24h > 0)))

  const exportCsv = () => {
    const header = ['tenant', 'host', 'state', 'state_since', 'outages_24h', 'downtime_24h_sec', 'outages_7d', 'main_cause',
                    'outage_start', 'outage_end', 'outage_duration_sec', 'outage_cause', 'outage_confidence']
    const lines = [header.map(csvSafe).join(',')]
    for (const r of visible) {
      const h = r.host
      const base = [r.tenant, h.name, h.state ?? '', h.state_since ?? '', h.outages_24h, h.downtime_24h_sec, h.outages_7d, h.main_cause ?? '']
      const outs = h.recent_outages.length ? h.recent_outages : [null]
      for (const o of outs) {
        lines.push([...base, o?.start ?? '', o?.end ?? '', o?.duration_sec ?? '', o?.code ?? '', o?.confidence ?? ''].map(csvSafe).join(','))
      }
    }
    download('hostmon-central.csv', '﻿' + lines.join('\r\n'), 'text/csv;charset=utf-8')
  }
  const exportJson = () =>
    download('hostmon-central.json', JSON.stringify(visible.map(r => ({ tenant: r.tenant, last_seen: r.lastSeen, ...r.host })), null, 2), 'application/json')

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <Radar size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('hostmonCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('hostmonCentral.intro')}</p>

      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {!loading && rows.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <select value={stateFilter} onChange={e => setStateFilter(e.target.value as typeof stateFilter)}
            className="text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('hostmonCentral.filterAll')}</option>
            <option value="down">{t('hostmonCentral.filterDown')}</option>
            <option value="outages">{t('hostmonCentral.filterOutages')}</option>
          </select>
          <select value={tenantFilter} onChange={e => setTenantFilter(e.target.value)}
            className="text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('alerts.allTenants')}</option>
            {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
          </select>
          <div className="ml-auto flex items-center gap-3">
            <button onClick={exportCsv} className="text-xs text-indigo-600 hover:underline flex items-center gap-1"><Download size={12} /> CSV</button>
            <button onClick={exportJson} className="text-xs text-indigo-600 hover:underline flex items-center gap-1"><Download size={12} /> JSON</button>
            <button onClick={reload} className="text-xs text-indigo-600 hover:underline shrink-0">{t('common.refresh')}</button>
          </div>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-slate-500">{t('hostmonCentral.noHosts')}</p>
      ) : visible.length === 0 ? (
        <p className="text-sm text-slate-500">{t('complianceCentral.noneMatchFilter')}</p>
      ) : (
        <div className="space-y-3">
          {visible.map(row => {
            const key = `${row.tenant}:${row.host.id}`
            return <HostCard key={key} row={row} expanded={openKey === key} onToggle={() => toggle(row)} detail={details[key]} />
          })}
        </div>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { hostMonApi, WatchedHostOut, HostEventOut, HostFindingOut, HostMonSearchResult } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Radar, Search, RefreshCw, Trash2, Plus, ChevronDown, ChevronUp, Lightbulb, Network } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const anyE = e as any
  return anyE?.response?.data?.detail || anyE?.message || String(e)
}

function formatDuration(sec: number | null | undefined): string {
  if (sec == null) return '—'
  if (sec < 60) return `${sec} s`
  const m = Math.floor(sec / 60)
  if (m < 60) return `${m} min ${sec % 60} s`
  const h = Math.floor(m / 60)
  return h < 24 ? `${h} h ${m % 60} min` : `${Math.floor(h / 24)} d ${h % 24} h`
}

function formatTs(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : '—'
}

const SEVERITY_ROW: Record<string, string> = {
  error: 'text-red-700',
  warn: 'text-amber-700',
  info: 'text-slate-700',
}

const CONFIDENCE_VARIANT: Record<string, 'green' | 'yellow' | 'gray'> = {
  high: 'green', medium: 'yellow', low: 'gray',
}

// ── Search + add ─────────────────────────────────────────────────────────────

function AddPanel() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [input, setInput] = useState('')
  const [q, setQ] = useState('')
  const [manual, setManual] = useState(false)
  const [form, setForm] = useState({ name: '', ip: '', mac: '', port: '' })

  useEffect(() => {
    const id = setTimeout(() => setQ(input.trim()), 400)
    return () => clearTimeout(id)
  }, [input])

  const { data, isFetching, refetch } = useQuery({
    queryKey: ['hostmon-search', q],
    queryFn: () => hostMonApi.search(q),
    enabled: q.length >= 2,
  })

  const add = useMutation({
    mutationFn: (v: { name: string; ip?: string | null; mac?: string | null; probe_port?: number | null }) =>
      hostMonApi.create(v),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hostmon-hosts'] })
      qc.invalidateQueries({ queryKey: ['hostmon-search'] })
      setManual(false)
      setForm({ name: '', ip: '', mac: '', port: '' })
    },
  })

  const results: HostMonSearchResult[] = data?.results ?? []

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search size={15} className="text-indigo-600" />
            <h2 className="text-sm font-semibold text-slate-700">{t('hostmon.searchTitle')}</h2>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setManual(m => !m)}>
            <Plus size={13} /> {t('hostmon.addManual')}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex gap-2">
          <div className="flex-1">
            <Input placeholder={t('hostmon.searchPlaceholder') as string} value={input}
              onChange={e => setInput(e.target.value)} />
          </div>
          <Button variant="secondary" onClick={() => hostMonApi.search(q, true).then(() => refetch())}
            disabled={q.length < 2 || isFetching} title={t('hostmon.refreshList') as string}>
            <RefreshCw size={13} className={cn(isFetching && 'animate-spin')} />
          </Button>
        </div>
        {q.length < 2 && <p className="text-xs text-slate-500">{t('hostmon.searchHint')}</p>}

        {manual && (
          <form className="grid grid-cols-1 md:grid-cols-5 gap-2 items-end border border-slate-200 rounded-lg p-3 bg-slate-50"
            onSubmit={e => {
              e.preventDefault()
              add.mutate({ name: form.name, ip: form.ip || null, mac: form.mac || null,
                           probe_port: form.port ? Number(form.port) : null })
            }}>
            <Input label={t('hostmon.manualName') as string} value={form.name} required
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            <Input label="IP" value={form.ip} placeholder="192.168.1.50"
              onChange={e => setForm(f => ({ ...f, ip: e.target.value }))} />
            <Input label="MAC" value={form.mac} placeholder="AA:BB:CC:DD:EE:FF"
              onChange={e => setForm(f => ({ ...f, mac: e.target.value }))} />
            <Input label={t('hostmon.manualPort') as string} value={form.port} placeholder={t('hostmon.manualPortHint') as string}
              onChange={e => setForm(f => ({ ...f, port: e.target.value.replace(/\D/g, '') }))} />
            <Button type="submit" variant="primary" disabled={add.isPending}>{t('hostmon.add')}</Button>
          </form>
        )}
        {add.isError && <p className="text-xs text-red-700">{errText(add.error)}</p>}

        {q.length >= 2 && (
          results.length === 0 ? (
            <p className="text-sm text-slate-500">{isFetching ? t('hostmon.searching') : t('hostmon.noResults')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b">
                    <th className="py-1">{t('hostmon.colName')}</th>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>{t('hostmon.colSeen')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={`${r.ip}-${r.mac}-${i}`} className="border-b border-slate-100">
                      <td className="py-1.5 font-medium text-slate-800">{r.name || r.comment || '—'}</td>
                      <td className="font-mono text-xs">{r.ip || '—'}</td>
                      <td className="font-mono text-xs">{r.mac || '—'}</td>
                      <td className="text-xs text-slate-500">{r.devices.length ? r.devices.join(', ') : r.sources.join(', ')}</td>
                      <td className="text-right">
                        {r.watched ? (
                          <Badge variant="green">{t('hostmon.monitored')}</Badge>
                        ) : (
                          <Button size="sm" variant="secondary" disabled={add.isPending}
                            onClick={() => add.mutate({ name: r.name || r.ip || r.mac || '?', ip: r.ip, mac: r.mac })}>
                            <Radar size={13} /> {t('hostmon.monitor')}
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {data && data.total != null && data.total > results.length && (
                <p className="text-xs text-slate-500 mt-1">{results.length} / {data.total}</p>
              )}
            </div>
          )
        )}
      </CardContent>
    </Card>
  )
}

// ── Host detail ──────────────────────────────────────────────────────────────

function eventText(e: HostEventOut, t: (k: string, o?: any) => string): string {
  const d = e.data || {}
  switch (e.kind) {
    case 'probe_down': return t('hostmon.kind.probe_down', { target: d.target })
    case 'probe_up': return t('hostmon.kind.probe_up', { target: d.target, duration: formatDuration(d.duration_sec) })
    case 'ip_changed': return t('hostmon.kind.ip_changed', { old: d.old, new: d.new })
    case 'mac_changed': return t('hostmon.kind.mac_changed', { old: d.old, new: d.new })
    case 'port_changed': return t('hostmon.kind.port_changed', { old: (d.old || []).join(', '), new: (d.new || []).join(', ') })
    default: return e.message || ''
  }
}

function CauseText({ code, finding }: { code: string; finding?: HostFindingOut }) {
  const { t } = useTranslation()
  return (
    <div>
      <span className="font-medium text-slate-900">{t(`hostmon.cause.${code}`)}</span>
      {finding?.confidence && (
        <Badge variant={CONFIDENCE_VARIANT[finding.confidence]} className="ml-2">{t(`hostmon.confidence.${finding.confidence}`)}</Badge>
      )}
    </div>
  )
}

function HostDetail({ host }: { host: WatchedHostOut }) {
  const { t } = useTranslation()
  const [hours, setHours] = useState(72)
  const [source, setSource] = useState('all')
  const [text, setText] = useState('')

  const { data: report, isLoading } = useQuery({
    queryKey: ['hostmon-report', host.id, hours],
    queryFn: () => hostMonApi.report(host.id, hours),
    refetchInterval: 30_000,
  })

  if (isLoading || !report) return <div className="p-4 text-sm text-slate-500">…</div>

  const evidence = new Set<number>(report.findings.flatMap(f => f.evidence))
  const events = report.events.filter(e =>
    (source === 'all' || e.source === source) &&
    (!text || `${eventText(e, t as any)} ${e.device ?? ''} ${e.topics ?? ''}`.toLowerCase().includes(text.toLowerCase())))
  const summary = report.summary
  const sources = Array.from(new Set(report.events.map(e => e.source)))
  const findingByStart = new Map(report.findings.map(f => [f.start, f]))

  return (
    <div className="space-y-4 p-4 border-t border-slate-100 bg-slate-50/50">
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-500">{t('hostmon.range')}:</span>
        {[24, 72, 168, 720].map(h => (
          <Button key={h} size="sm" variant={hours === h ? 'primary' : 'ghost'} onClick={() => setHours(h)}>
            {h < 168 ? `${h} h` : `${h / 24} d`}
          </Button>
        ))}
      </div>

      {/* Probable cause */}
      <div className="rounded-lg border border-indigo-200 bg-indigo-50 p-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-indigo-900">
          <Lightbulb size={15} /> {t('hostmon.causeTitle')}
        </div>
        {!summary ? (
          <p className="text-sm text-slate-600 mt-1">
            {t('hostmon.noOutages')}
            {report.indicators.length > 0 && ` ${t('hostmon.indicatorsInstead')}`}
          </p>
        ) : (
          <div className="mt-1 space-y-1">
            <CauseText code={summary.code} />
            <p className="text-xs text-slate-600">{t(`hostmon.causeHint.${summary.code}`)}</p>
            <p className="text-xs text-slate-500">
              {t('hostmon.causeCount', { n: summary.outages_with_cause, total: summary.outages })}
            </p>
            {summary.periodic_sec != null && (
              <p className="text-xs text-amber-800">{t('hostmon.periodic', { interval: formatDuration(summary.periodic_sec) })}</p>
            )}
          </div>
        )}
        {report.indicators.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {report.indicators.map(i => (
              <span key={i.code} title={t(`hostmon.causeHint.${i.code}`) as string}
                className="text-xs px-2 py-0.5 rounded bg-white border border-indigo-200 text-slate-700">
                {t(`hostmon.cause.${i.code}`)} ×{i.count}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Presence */}
      <div>
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-700 mb-1">
          <Network size={14} /> {t('hostmon.presenceTitle')}
        </div>
        {!report.presence || report.presence.entries.length === 0 ? (
          <p className="text-xs text-slate-500">{t('hostmon.presenceNone')}</p>
        ) : (
          <ul className="text-xs text-slate-700 space-y-0.5">
            {report.presence.entries.map((p, i) => (
              <li key={i} className="font-mono">
                <span className="text-slate-400">[{p.device}]</span>{' '}
                {p.type === 'port' && <>port <b>{p.interface}</b>{p.vid ? ` (vlan ${p.vid})` : ''}{p.uplink ? ` — ${t('hostmon.uplink')}` : ''}</>}
                {p.type === 'dhcp' && <>DHCP {p.address} {p.host_name ? `(${p.host_name})` : ''} {p.status ?? ''} {p.server ? `@${p.server}` : ''}</>}
                {p.type === 'arp' && <>ARP {p.address} → {p.mac} {p.interface ? `(${p.interface})` : ''} {p.status ?? ''}</>}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Outages */}
      <div>
        <div className="text-sm font-semibold text-slate-700 mb-1">{t('hostmon.outagesTitle')}</div>
        {report.findings.length === 0 ? (
          <p className="text-xs text-slate-500">{t('hostmon.noOutages')}</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500 border-b text-xs">
                <th className="py-1">{t('hostmon.colStart')}</th>
                <th>{t('hostmon.colDuration')}</th>
                <th>{t('hostmon.colCause')}</th>
              </tr>
            </thead>
            <tbody>
              {[...report.findings].reverse().map(f => (
                <tr key={f.start} className="border-b border-slate-100">
                  <td className="py-1.5 text-xs">{formatTs(f.start)}</td>
                  <td className="text-xs">{f.end ? formatDuration(f.duration_sec) : <Badge variant="red">{t('hostmon.ongoing')}</Badge>}</td>
                  <td className="text-xs">
                    <CauseText code={f.code} finding={findingByStart.get(f.start)} />
                    {f.also.length > 0 && (
                      <span className="text-slate-500">{t('hostmon.also')}: {f.also.map(c => t(`hostmon.cause.${c}`)).join('; ')}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* PRTG / Check_MK context */}
      {(report.external.prtg.length > 0 || report.external.checkmk.length > 0) && (
        <div>
          <div className="text-sm font-semibold text-slate-700 mb-1">{t('hostmon.externalTitle')}</div>
          <ul className="text-xs space-y-0.5">
            {report.external.prtg.map((s, i) => (
              <li key={`p${i}`} className={s.problem ? 'text-red-700' : 'text-slate-600'}>PRTG · {s.sensor}: {s.status} {s.message ? `— ${s.message}` : ''}</li>
            ))}
            {report.external.checkmk.map((s, i) => (
              <li key={`c${i}`} className={s.problem ? 'text-red-700' : 'text-slate-600'}>Check_MK · {s.name}: {s.state} {s.output ? `— ${s.output}` : ''}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Timeline */}
      <div>
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <div className="text-sm font-semibold text-slate-700">{t('hostmon.timelineTitle')}</div>
          <select value={source} onChange={e => setSource(e.target.value)}
            className="border border-slate-300 rounded px-2 py-1 text-xs">
            <option value="all">{t('hostmon.allSources')}</option>
            {sources.map(s => <option key={s} value={s}>{t(`hostmon.source.${s}`)}</option>)}
          </select>
          <input value={text} onChange={e => setText(e.target.value)} placeholder={t('hostmon.filterText') as string}
            className="border border-slate-300 rounded px-2 py-1 text-xs w-48" />
          <span className="text-xs text-slate-400">{events.length}</span>
        </div>
        {events.length === 0 ? (
          <p className="text-xs text-slate-500">{t('hostmon.noEvents')}</p>
        ) : (
          <div className="max-h-[28rem] overflow-y-auto border border-slate-200 rounded bg-white">
            <table className="w-full text-xs">
              <tbody>
                {events.map(e => (
                  <tr key={e.id} className={cn('border-b border-slate-100 align-top', evidence.has(e.id) && 'bg-amber-50')}>
                    <td className="py-1 px-2 whitespace-nowrap text-slate-500">{formatTs(e.ts)}</td>
                    <td className="px-1 whitespace-nowrap"><Badge variant={e.source === 'probe' ? 'blue' : e.source === 'wazuh' ? 'purple' : 'gray'}>{t(`hostmon.source.${e.source}`)}</Badge></td>
                    <td className="px-1 whitespace-nowrap text-slate-500">{e.device ?? ''}</td>
                    <td className={cn('px-1 font-mono break-all', SEVERITY_ROW[e.severity])}>
                      {eventText(e, t as any)}
                      {e.kind?.startsWith('probe') && e.message ? <span className="text-slate-400"> · {e.message}</span> : null}
                      {e.topics && !e.kind ? <span className="text-slate-400"> [{e.topics}]</span> : null}
                    </td>
                    <td className="px-1 whitespace-nowrap">{e.matched_on && <Badge>{t(`hostmon.matched.${e.matched_on}`)}</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

function HostRow({ host, expanded, onToggle }: { host: WatchedHostOut; expanded: boolean; onToggle: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()

  const refresh = useMutation({
    mutationFn: () => hostMonApi.refresh(host.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hostmon-hosts'] })
      qc.invalidateQueries({ queryKey: ['hostmon-report', host.id] })
    },
  })
  const remove = useMutation({
    mutationFn: () => hostMonApi.remove(host.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hostmon-hosts'] }),
  })

  const stateBadge = host.probe_state === 'up' ? <Badge variant="green">{t('hostmon.up')}</Badge>
    : host.probe_state === 'down' ? <Badge variant="red">{t('hostmon.down')}</Badge>
    : <Badge variant="gray">{t('hostmon.unknown')}</Badge>

  return (
    <div className="border border-slate-200 rounded-lg bg-white overflow-hidden">
      <div className="flex items-center gap-3 p-3 flex-wrap">
        {stateBadge}
        <div className="min-w-[10rem]">
          <div className="font-medium text-slate-900">{host.name}</div>
          <div className="text-xs font-mono text-slate-500">
            {host.resolved_ip || host.ip || '—'} · {host.resolved_mac || host.mac || '—'}
          </div>
        </div>
        <div className="text-xs text-slate-500 flex-1 min-w-[12rem]">
          {host.probe_state === 'down' && host.probe_state_since && <div className="text-red-700">{t('hostmon.downSince', { time: formatTs(host.probe_state_since) })}</div>}
          <div>{t('hostmon.outages24h')}: <b>{host.outages_24h ?? 0}</b> · {t('hostmon.events24h')}: <b>{host.events_24h ?? 0}</b></div>
          {host.last_error && <div className="text-amber-700 truncate" title={host.last_error}>{host.last_error}</div>}
        </div>
        <div className="flex items-center gap-1">
          <Button size="sm" variant="ghost" onClick={() => refresh.mutate()} disabled={refresh.isPending} title={t('hostmon.refresh') as string}>
            <RefreshCw size={13} className={cn(refresh.isPending && 'animate-spin')} />
          </Button>
          <Button size="sm" variant="ghost" onClick={() => { if (window.confirm(t('hostmon.removeConfirm', { name: host.name }) as string)) remove.mutate() }}>
            <Trash2 size={13} />
          </Button>
          <Button size="sm" variant="secondary" onClick={onToggle}>
            {t('hostmon.details')} {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </Button>
        </div>
      </div>
      {expanded && <HostDetail host={host} />}
    </div>
  )
}

export function HostMonitor() {
  const { t } = useTranslation()
  const [openId, setOpenId] = useState<number | null>(null)
  const { data: hosts = [] } = useQuery({
    queryKey: ['hostmon-hosts'],
    queryFn: hostMonApi.hosts,
    refetchInterval: 15_000,
  })

  return (
    <div className="p-6 space-y-4 max-w-6xl">
      <div>
        <h1 className="text-xl font-semibold text-slate-900 flex items-center gap-2"><Radar size={20} /> {t('hostmon.title')}</h1>
        <p className="text-sm text-slate-500 mt-1">{t('hostmon.intro')}</p>
      </div>

      <AddPanel />

      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-slate-700">{t('hostmon.watchedTitle')} ({hosts.length})</h2>
        {hosts.length === 0 && <p className="text-sm text-slate-500">{t('hostmon.noWatched')}</p>}
        {hosts.map(h => (
          <HostRow key={h.id} host={h} expanded={openId === h.id} onToggle={() => setOpenId(openId === h.id ? null : h.id)} />
        ))}
      </div>
    </div>
  )
}

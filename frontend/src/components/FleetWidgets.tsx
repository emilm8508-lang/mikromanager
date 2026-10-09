import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Badge } from './ui/Badge'
import { FleetDeviceRow, FleetWifi } from '../lib/api'
import { cn } from '../lib/utils'
import { ChevronDown, ChevronRight } from 'lucide-react'

// Presentational pieces of the Mikrotik dashboard — shared by the agent's
// "Mikrotik" tab and Central's page, which feed them differently-shaped but
// equivalent rows (Central has names only, merged over several tenants).

export function pctColor(pct: number): string {
  return pct >= 90 ? 'bg-red-500' : pct >= 75 ? 'bg-amber-500' : 'bg-indigo-500'
}

export function Bar({ pct }: { pct: number | null | undefined }) {
  if (pct == null) return <span className="text-slate-300 text-xs">—</span>
  return (
    <div className="flex items-center gap-2">
      <div className="w-14 h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', pctColor(pct))} style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
      </div>
      <span className="text-xs tabular-nums text-slate-700 w-9 text-right">{Math.round(pct)}%</span>
    </div>
  )
}

export function Donut({ value, total, label, sub }: { value: number; total: number; label: string; sub?: string }) {
  const r = 22
  const c = 2 * Math.PI * r
  const frac = total > 0 ? value / total : 0
  return (
    <div className="flex items-center gap-3">
      <svg width="56" height="56" viewBox="0 0 56 56" className="shrink-0">
        <circle cx="28" cy="28" r={r} fill="none" stroke="#e2e8f0" strokeWidth="7" />
        <circle cx="28" cy="28" r={r} fill="none" stroke="#4f46e5" strokeWidth="7" strokeLinecap="butt"
          strokeDasharray={`${c * frac} ${c}`} transform="rotate(-90 28 28)" />
        <text x="28" y="32" textAnchor="middle" className="fill-slate-800" style={{ fontSize: 13, fontWeight: 600 }}>{value}</text>
      </svg>
      <div>
        <div className="text-sm font-medium text-slate-800">{label}</div>
        <div className="text-xs text-slate-500">{value} / {total}{sub ? ` · ${sub}` : ''}</div>
      </div>
    </div>
  )
}

function Header({ title, right }: { title: string; right?: React.ReactNode }) {
  return (
    <CardHeader>
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-700">{title}</h2>
        {right}
      </div>
    </CardHeader>
  )
}

// ── Resources ────────────────────────────────────────────────────────────────

export type ResourceRow = { key: string; tenant?: string; device: FleetDeviceRow }

export function ResourcesCard({ rows }: { rows: ResourceRow[] }) {
  const { t } = useTranslation()
  const [sort, setSort] = useState<'name' | 'cpu' | 'mem' | 'disk'>('name')
  const val = (r: ResourceRow) => sort === 'cpu' ? r.device.cpu : sort === 'mem' ? r.device.mem : r.device.disk
  const sorted = [...rows].sort((a, b) => sort === 'name'
    ? a.device.name.localeCompare(b.device.name)
    : (val(b) ?? -1) - (val(a) ?? -1))
  const th = (k: typeof sort, label: string) => (
    <th className={cn('py-1.5 cursor-pointer select-none', sort === k && 'text-indigo-600')} onClick={() => setSort(k)}>{label}{sort === k ? ' ▾' : ''}</th>
  )
  return (
    <Card>
      <Header title={t('fleet.resourcesCard')} />
      <CardContent>
        {rows.length === 0 ? <p className="text-sm text-slate-500">{t('fleet.noData')}</p> : (
          <div className="max-h-80 overflow-y-auto overflow-x-hidden">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-slate-500 border-b">
                {th('name', t('fleet.colDevice') as string)}{th('cpu', 'CPU')}{th('mem', t('fleet.memory') as string)}{th('disk', t('fleet.disk') as string)}
              </tr></thead>
              <tbody>
                {sorted.map(r => (
                  <tr key={r.key} className="border-b border-slate-100">
                    <td className="py-1.5 pr-2">
                      {r.tenant && <span className="text-[10px] px-1.5 py-0.5 mr-1.5 rounded bg-slate-100 text-slate-600">{r.tenant}</span>}
                      <span className={cn('text-slate-800 inline-block max-w-[9rem] truncate align-bottom', !r.device.online && 'text-slate-400')} title={r.device.name}>{r.device.name}</span>
                    </td>
                    <td><Bar pct={r.device.cpu} /></td><td><Bar pct={r.device.mem} /></td><td><Bar pct={r.device.disk} /></td>
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

// ── Alerts ───────────────────────────────────────────────────────────────────

export type AlertItem = { label: string; to?: string }
export type AlertRowView = { key: string; severity: 'high' | 'medium' | 'low'; count: number; total: number; items: AlertItem[] }

export function AlertsCard({ alerts }: { alerts: AlertRowView[] }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState<string | null>(null)
  return (
    <Card>
      <Header title={t('fleet.alertsCard')} right={<span className="text-xs text-slate-400">{alerts.length}</span>} />
      <CardContent>
        {alerts.length === 0 ? <p className="text-sm text-green-700">{t('fleet.noAlerts')}</p> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-slate-500 border-b">
              <th className="py-1.5">{t('fleet.colAlert')}</th><th>{t('fleet.colDevices')}</th><th>{t('fleet.colSeverity')}</th>
            </tr></thead>
            <tbody>
              {alerts.map(a => (
                <Fragment key={a.key}>
                  <tr className="border-b border-slate-100 cursor-pointer hover:bg-slate-50" onClick={() => setOpen(open === a.key ? null : a.key)}>
                    <td className="py-1.5 flex items-center gap-1 text-slate-800">
                      {open === a.key ? <ChevronDown size={12} /> : <ChevronRight size={12} />}{t(`fleet.alert.${a.key}`)}
                    </td>
                    <td className="tabular-nums text-slate-600">{a.count}/{a.total}</td>
                    <td><Badge variant={a.severity === 'high' ? 'red' : a.severity === 'medium' ? 'yellow' : 'gray'}>{t(`fleet.severity.${a.severity}`)}</Badge></td>
                  </tr>
                  {open === a.key && (
                    <tr><td colSpan={3} className="pb-2 pl-5 text-xs text-slate-600">
                      {a.items.map((it, i) => (
                        <span key={i} className="inline-block mr-3">
                          {it.to ? <Link to={it.to} className="text-indigo-600 hover:underline">{it.label}</Link> : it.label}
                        </span>
                      ))}
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  )
}

// ── Available updates ────────────────────────────────────────────────────────

export type UpdateRowView = { key: string; label: string; tenant?: string; current: string | null; latest: string | null; channel: string | null; to?: string }

export function UpdatesCard({ updates, footer }: { updates: UpdateRowView[]; footer?: React.ReactNode }) {
  const { t } = useTranslation()
  return (
    <Card>
      <Header title={t('fleet.updatesCard')} right={<span className="text-xs text-slate-400">{updates.length}</span>} />
      <CardContent>
        {updates.length === 0 ? <p className="text-sm text-green-700">{t('fleet.noUpdates')}</p> : (
          <div className="max-h-64 overflow-y-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-slate-500 border-b">
                <th className="py-1.5">{t('fleet.colDevice')}</th><th>{t('fleet.colCurrent')}</th><th>{t('fleet.colAvailable')}</th><th>{t('fleet.colChannel')}</th>
              </tr></thead>
              <tbody>
                {updates.map(u => (
                  <tr key={u.key} className="border-b border-slate-100">
                    <td className="py-1.5">
                      {u.tenant && <span className="text-[10px] px-1.5 py-0.5 mr-1.5 rounded bg-slate-100 text-slate-600">{u.tenant}</span>}
                      {u.to ? <Link to={u.to} className="text-indigo-600 hover:underline">{u.label}</Link> : u.label}
                    </td>
                    <td className="font-mono text-xs text-slate-600">{u.current ?? '—'}</td>
                    <td className="font-mono text-xs text-slate-800">{u.latest ?? '—'}</td>
                    <td className="text-xs text-slate-500">{u.channel ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {footer}
      </CardContent>
    </Card>
  )
}

// ── Wi-Fi (access points / stations by band and channel) ─────────────────────

const BANDS: Array<{ key: string; label: string }> = [
  { key: '2.4', label: '2.4 GHz' }, { key: '5', label: '5 GHz' }, { key: '6', label: '6 GHz' },
]
const CHANNELS_24 = [2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472]

export function mergeWifi(list: FleetWifi[]): FleetWifi {
  const out: FleetWifi = { aps_total: 0, stations_total: 0, by_band: {}, by_channel: {} }
  for (const w of list) {
    out.aps_total += w.aps_total
    out.stations_total += w.stations_total
    for (const [b, v] of Object.entries(w.by_band)) {
      const o = (out.by_band[b] ??= { aps: 0, stations: 0 })
      o.aps += v.aps; o.stations += v.stations
    }
    for (const [b, chans] of Object.entries(w.by_channel)) {
      const m = (out.by_channel[b] ??= [])
      for (const c of chans) {
        const ex = m.find(x => x.freq === c.freq)
        if (ex) { ex.aps += c.aps; ex.stations += c.stations } else m.push({ ...c })
      }
      m.sort((x, y) => x.freq - y.freq)
    }
  }
  return out
}

export function WifiCard({ wifi, kind }: { wifi: FleetWifi; kind: 'aps' | 'stations' }) {
  const { t } = useTranslation()
  const [band, setBand] = useState('2.4')
  const total = kind === 'aps' ? wifi.aps_total : wifi.stations_total
  const bandTotal = wifi.by_band[band]?.[kind] ?? 0
  const present = wifi.by_channel[band] ?? []
  const freqs = band === '2.4'
    ? CHANNELS_24
    : [...new Set(present.map(c => c.freq))].sort((a, b) => a - b)
  const countAt = (f: number) => present.find(c => c.freq === f)?.[kind] ?? 0
  const known = freqs.reduce((n, f) => n + countAt(f), 0)
  const max = Math.max(1, ...freqs.map(countAt))
  const noWifi = wifi.aps_total === 0 && wifi.stations_total === 0

  return (
    <Card>
      <Header title={t(kind === 'aps' ? 'fleet.apCard' : 'fleet.stationsCard')} right={<span className="text-xs text-slate-500">{t('fleet.total')}: <b>{total}</b></span>} />
      <CardContent>
        {noWifi ? <p className="text-sm text-slate-500">{t('fleet.noWifi')}</p> : (
          <div className="space-y-3">
            <div className="flex items-center gap-3 text-sm">
              {BANDS.map(b => (
                <label key={b.key} className="flex items-center gap-1 cursor-pointer text-slate-700">
                  <input type="radio" checked={band === b.key} onChange={() => setBand(b.key)} />
                  {b.label} <span className="text-xs text-slate-400">({wifi.by_band[b.key]?.[kind] ?? 0})</span>
                </label>
              ))}
            </div>
            {freqs.length === 0 ? (
              <p className="text-xs text-slate-500">{t('fleet.noChannelData')} — {bandTotal}</p>
            ) : (
              <div className="flex items-end gap-1 h-24">
                {freqs.map(f => {
                  const n = countAt(f)
                  return (
                    <div key={f} className="flex-1 flex flex-col items-center justify-end h-full min-w-0">
                      <span className="text-[10px] text-slate-600">{n}</span>
                      <div className={cn('w-full rounded-t', n ? 'bg-indigo-400' : 'bg-slate-100')} style={{ height: `${n ? Math.max(8, (n / max) * 100) : 6}%` }} />
                      <span className="text-[9px] text-slate-400 mt-0.5">{f}</span>
                    </div>
                  )
                })}
              </div>
            )}
            {bandTotal > known && <p className="text-[11px] text-slate-400">{t('fleet.unknownChannel', { n: bandTotal - known })}</p>}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

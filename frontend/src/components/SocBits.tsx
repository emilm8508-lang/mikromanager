import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import { socApi, SOC_SEVERITIES, SOC_STATUSES, type AssetType, type SocAlert, type SocRiskFactor, type SocRiskItem, type SocSeverity, type SocStats, type SocStatus } from '../lib/api'
import { Pill, TypeIcon } from './AssetBits'
import { cn } from '../lib/utils'

// The pieces of the SOC pages shared by the agent (triage: acknowledge, take, close) and Central (the same queue, read-only).

export const SOC_CATEGORIES = ['auth', 'detection', 'availability', 'network', 'hardware', 'resource', 'vulnerability', 'system', 'other']
export const SOC_SOURCES = ['agent', 'wazuh', 'checkmk', 'prtg', 'rules', 'syslog']

const SEV_CLASS: Record<SocSeverity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-amber-300 text-amber-950',
  low: 'bg-sky-100 text-sky-800',
  info: 'bg-slate-100 text-slate-600',
}
const STATUS_TONE: Record<SocStatus, 'blue' | 'amber' | 'orange' | 'gray' | 'green'> = { new: 'blue', ack: 'amber', in_progress: 'orange', false_positive: 'gray', closed: 'green' }

export function SevBadge({ s }: { s: SocSeverity }) {
  const { t } = useTranslation()
  return <span className={cn('inline-block min-w-[4.5rem] text-center px-2 py-0.5 rounded-md text-xs font-semibold', SEV_CLASS[s] ?? SEV_CLASS.info)}>{t(`soc.severity.${s}`)}</span>
}

export function StatusPill({ s }: { s: SocStatus }) {
  const { t } = useTranslation()
  return <Pill tone={STATUS_TONE[s] ?? 'gray'}>{t(`soc.status.${s}`)}</Pill>
}

/** "5 minutes ago" in the language of the page. */
export function useAgo() {
  const { i18n } = useTranslation()
  const rtf = new Intl.RelativeTimeFormat(i18n.language, { numeric: 'auto' })
  return (iso?: string | null) => {
    if (!iso) return '—'
    const s = Math.round((new Date(iso).getTime() - Date.now()) / 1000)
    const a = Math.abs(s)
    if (a < 60) return rtf.format(Math.round(s), 'second')
    if (a < 3600) return rtf.format(Math.round(s / 60), 'minute')
    if (a < 86400) return rtf.format(Math.round(s / 3600), 'hour')
    return rtf.format(Math.round(s / 86400), 'day')
  }
}

export function alertTitle(t: (k: string, o?: Record<string, unknown>) => string, a: Pick<SocAlert, 'rule' | 'title'>): string {
  return t(`soc.rule.${a.rule}`, { defaultValue: a.title || a.rule })
}

/** One line of what the alert is about: the fields an analyst reads first. */
export function evidenceLine(a: SocAlert): string {
  const d = a.detail || {}
  const parts: string[] = []
  const list = (v: unknown) => Array.isArray(v) ? v.join(', ') : String(v)
  if (d.rule_description) parts.push(String(d.rule_description))
  if (d.sources?.length) parts.push(`← ${list(d.sources)}`)
  if (d.users?.length) parts.push(list(d.users))
  for (const k of ['service', 'tunnel_name', 'iface', 'sensor_name', 'description']) if (d[k]) parts.push(String(d[k]))
  if (d.plugin_output) parts.push(String(d.plugin_output))
  else if (d.message) parts.push(String(d.message))
  return Array.from(new Set(parts)).join(' · ')
}

export function SocKpis({ stats }: { stats: SocStats }) {
  const { t } = useTranslation()
  const tile = (label: string, value: string | number, tone = 'text-slate-900', hint?: string) => (
    <div className="bg-white border border-slate-200 rounded-xl px-4 py-3 min-w-[8.5rem]" title={hint}>
      <div className="text-xs text-slate-500">{label}</div>
      <div className={cn('text-2xl font-bold tabular-nums', tone)}>{value}</div>
    </div>
  )
  const ch = (stats.by_severity?.critical ?? 0) + (stats.by_severity?.high ?? 0)
  const max = Math.max(1, ...stats.opened_daily.map(d => d.n))
  return (
    <div className="flex gap-3 flex-wrap items-stretch">
      {tile(t('soc.kpi.open') as string, stats.open)}
      {tile(t('soc.kpi.new') as string, stats.new, stats.new ? 'text-blue-600' : 'text-slate-900', stats.oldest_new_hours ? t('soc.kpi.oldestHint', { h: stats.oldest_new_hours }) as string : undefined)}
      {tile(t('soc.kpi.critHigh') as string, ch, ch ? 'text-red-600' : 'text-slate-900')}
      {tile(t('soc.kpi.opened24') as string, stats.opened_24h)}
      {tile(t('soc.kpi.closed24') as string, stats.closed_24h)}
      {tile(t('soc.kpi.mttr') as string, stats.mttr_hours == null ? '—' : `${stats.mttr_hours} h`, 'text-slate-900', t('soc.kpi.mttrHint') as string)}
      <div className="bg-white border border-slate-200 rounded-xl px-4 py-3 min-w-[11rem]">
        <div className="text-xs text-slate-500">{t('soc.kpi.week')}</div>
        <div className="flex items-end gap-1 h-9 mt-1">
          {stats.opened_daily.map(d => (
            <div key={d.t} className="flex-1 bg-indigo-500 rounded-sm min-h-[2px]" style={{ height: `${Math.max(6, (d.n / max) * 100)}%`, opacity: d.n ? 1 : 0.25 }}
              title={`${new Date(d.t).toLocaleDateString()}: ${d.n}`} />
          ))}
        </div>
      </div>
    </div>
  )
}

export type SocFilterState = { tab: string; severity: string; category: string; source: string; q: string }
export const SOC_FILTER_DEFAULT: SocFilterState = { tab: 'open', severity: '', category: '', source: '', q: '' }

export function SocFilters({ f, set, tabs }: { f: SocFilterState; set: (f: SocFilterState) => void; tabs: string[] }) {
  const { t } = useTranslation()
  const sel = 'border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white'
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <div className="inline-flex rounded-lg border border-slate-300 overflow-hidden text-sm">
        {tabs.map(k => (
          <button key={k} onClick={() => set({ ...f, tab: k })} className={cn('px-3 py-1.5', f.tab === k ? 'bg-indigo-600 text-white' : 'bg-white text-slate-600 hover:bg-slate-50')}>{t(`soc.tab.${k}`)}</button>
        ))}
      </div>
      <select value={f.severity} onChange={e => set({ ...f, severity: e.target.value })} className={sel}>
        <option value="">{t('soc.filter.allSeverities')}</option>
        {SOC_SEVERITIES.map(s => <option key={s} value={s}>{t(`soc.severity.${s}`)}</option>)}
      </select>
      <select value={f.category} onChange={e => set({ ...f, category: e.target.value })} className={sel}>
        <option value="">{t('soc.filter.allCategories')}</option>
        {SOC_CATEGORIES.map(s => <option key={s} value={s}>{t(`soc.category.${s}`)}</option>)}
      </select>
      <select value={f.source} onChange={e => set({ ...f, source: e.target.value })} className={sel}>
        <option value="">{t('soc.filter.allSources')}</option>
        {SOC_SOURCES.map(s => <option key={s} value={s}>{t(`soc.source.${s}`)}</option>)}
      </select>
      <input value={f.q} onChange={e => set({ ...f, q: e.target.value })} placeholder={t('soc.filter.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56" />
    </div>
  )
}

/** The facts of one alert, its trail and (agent only) the triage controls. */
function AlertDetail({ a, readOnly, onUpdate }: { a: SocAlert; readOnly: boolean; onUpdate?: (ids: number[], patch: Record<string, unknown>) => void }) {
  const { t } = useTranslation()
  const full = useQuery({ queryKey: ['soc-alert', a.id, a.last_seen, a.status], queryFn: () => socApi.alert(a.id), enabled: !readOnly })
  const cur = full.data ?? a
  const [owner, setOwner] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)
  const ago = useAgo()
  const facts = Object.entries(cur.detail || {}).filter(([k]) => k !== 'mitre')
  const fmt = (v: unknown) => Array.isArray(v) ? v.join(', ') : String(v)
  return (
    <div className="grid gap-4 md:grid-cols-2 px-4 py-3 bg-slate-50 border-t border-slate-200 text-sm">
      <div className="space-y-3 min-w-0">
        <div>
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">{t('soc.detail.evidence')}</div>
          {facts.length === 0 ? <p className="text-slate-400">—</p> : (
            <dl className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-0.5">
              {facts.map(([k, v]) => (<div key={k} className="contents"><dt className="text-slate-500">{t(`soc.field.${k}`, { defaultValue: k })}</dt><dd className="text-slate-800 break-words">{fmt(v)}</dd></div>))}
            </dl>
          )}
        </div>
        <div className="flex flex-wrap gap-2 text-xs text-slate-500">
          <span>{t('soc.detail.first')}: {new Date(cur.first_seen).toLocaleString()}</span>
          <span>{t('soc.detail.last')}: {new Date(cur.last_seen).toLocaleString()}</span>
          {cur.closed_at && <span>{t('soc.detail.closed')}: {new Date(cur.closed_at).toLocaleString()} ({cur.closed_by})</span>}
        </div>
        {cur.mitre && (
          <div className="flex flex-wrap gap-1.5 items-center text-xs">
            <span className="text-slate-500">{t('soc.detail.mitre')}:</span>
            {cur.mitre.split(',').map(m => m.trim()).filter(Boolean).map(m => (
              <a key={m} href={`https://attack.mitre.org/techniques/${m.replace('.', '/')}/`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-indigo-600 hover:underline">{m}<ExternalLink size={11} /></a>
            ))}
          </div>
        )}
      </div>
      <div className="space-y-3 min-w-0">
        {!readOnly && onUpdate && (
          <div className="space-y-2">
            <div className="flex gap-2">
              <input value={owner ?? cur.owner ?? ''} onChange={e => setOwner(e.target.value)} placeholder={t('soc.detail.owner') as string} className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white w-40" />
              <button className="text-xs text-indigo-600 hover:underline disabled:text-slate-300" disabled={owner == null} onClick={() => { onUpdate([cur.id], { owner, set_owner: true }); setOwner(null) }}>{t('soc.detail.save')}</button>
            </div>
            <textarea value={note ?? cur.note ?? ''} onChange={e => setNote(e.target.value)} rows={2} placeholder={t('soc.detail.note') as string} className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white w-full" />
            <button className="text-xs text-indigo-600 hover:underline disabled:text-slate-300" disabled={note == null} onClick={() => { onUpdate([cur.id], { note, set_note: true }); setNote(null) }}>{t('soc.detail.saveNote')}</button>
          </div>
        )}
        {readOnly && (cur.owner || cur.note) && <p className="text-slate-600">{cur.owner ? `${t('soc.detail.owner')}: ${cur.owner}` : ''}{cur.note ? ` · ${cur.note}` : ''}</p>}
        {!readOnly && (
          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">{t('soc.detail.trail')}</div>
            <ul className="space-y-0.5 text-xs text-slate-600 max-h-40 overflow-y-auto">
              {[...(cur.log ?? [])].reverse().map((l, i) => (
                <li key={i}><span className="text-slate-400">{ago(l.t)}</span> · <b className="font-medium">{l.who}</b> · {t(`soc.trail.${l.a}`, { defaultValue: l.a })}{l.v != null && l.v !== '' ? `: ${typeof l.v === 'string' ? t(`soc.status.${l.v}`, { defaultValue: t(`soc.severity.${l.v}`, { defaultValue: String(l.v) }) }) : String(l.v)}` : ''}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

/** The queue. Agent: `readOnly` false with a status control per row and checkboxes for the bulk bar; Central: the same rows without controls. */
export function SocTable({ alerts, readOnly, selected, setSelected, onUpdate, onOpenAsset, empty }: {
  alerts: SocAlert[]; readOnly: boolean; selected?: Set<number>; setSelected?: (s: Set<number>) => void
  onUpdate?: (ids: number[], patch: Record<string, unknown>) => void
  onOpenAsset?: (assetId: number) => void          // Central: opens the device's drawer (details and commands) instead of a link to the agent's page
  empty: string
}) {
  const { t } = useTranslation()
  const ago = useAgo()
  const [open, setOpen] = useState<number | null>(null)
  const allOn = !!selected && alerts.length > 0 && alerts.every(a => selected.has(a.id))
  const toggle = (id: number) => { if (!selected || !setSelected) return; const n = new Set(selected); n.has(id) ? n.delete(id) : n.add(id); setSelected(n) }
  if (alerts.length === 0) return <p className="text-sm text-slate-400 py-8 text-center">{empty}</p>
  const grid = readOnly ? 'grid-cols-[2rem,5.5rem,minmax(0,3fr),minmax(0,1.4fr),4rem,7rem,8rem]' : 'grid-cols-[2.25rem,2rem,5.5rem,minmax(0,3fr),minmax(0,1.4fr),4rem,7rem,8rem]'
  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
      <div className={cn('grid items-center bg-slate-50 text-xs text-slate-500 py-2', grid)}>
        {!readOnly && <div className="px-3"><input type="checkbox" checked={allOn} onChange={() => setSelected?.(allOn ? new Set() : new Set(alerts.map(a => a.id)))} /></div>}
        <div />
        <div className="px-2">{t('soc.col.severity')}</div>
        <div className="px-2">{t('soc.col.alert')}</div>
        <div className="px-2">{t('soc.col.device')}</div>
        <div className="px-2 text-right">{t('soc.col.count')}</div>
        <div className="px-2">{t('soc.col.last')}</div>
        <div className="px-2">{t('soc.col.status')}</div>
      </div>
      {alerts.map(a => {
        const isOpen = open === a.id
        const line = evidenceLine(a)
        return (
          <div key={a.id} className="border-t border-slate-100">
            <div className={cn('grid items-center cursor-pointer hover:bg-slate-50', grid)} onClick={() => setOpen(isOpen ? null : a.id)}>
              {!readOnly && <div className="px-3 py-2" onClick={e => e.stopPropagation()}><input type="checkbox" checked={!!selected?.has(a.id)} onChange={() => toggle(a.id)} /></div>}
              <div className="text-slate-400 px-2">{isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</div>
              <div className="px-2 py-2"><SevBadge s={a.severity} /></div>
              <div className="px-2 py-2 min-w-0">
                <div className="font-medium text-slate-900 truncate">{alertTitle(t as never, a)}{a.mitre && <span className="ml-2 text-[10px] font-normal text-slate-500 border border-slate-200 rounded px-1">{a.mitre}</span>}</div>
                {a.root_name && <div className="text-xs text-amber-700 truncate">{t('soc.field.correlated', { name: a.root_name })}</div>}
                {a.maintenance && <div className="text-xs text-sky-700 truncate">{t('soc.field.maintenance', { name: a.maintenance })}</div>}
                {(a.esc_level ?? 0) > 0 && <div className="text-xs text-red-700 truncate">{t('soc.field.escalated', { n: a.esc_level })}</div>}
                {line && <div className="text-xs text-slate-500 truncate" title={line}>{line}</div>}
              </div>
              <div className="px-2 py-2 min-w-0 truncate" onClick={e => e.stopPropagation()}>
                {a.device_name ? (a.asset_id && !readOnly ? <Link to={`/inventory/${a.asset_id}`} className="text-indigo-600 hover:underline">{a.device_name}</Link>
                  : a.asset_id && onOpenAsset ? <button className="text-indigo-600 hover:underline" onClick={() => onOpenAsset(a.asset_id!)}>{a.device_name}</button> : a.device_name) : '—'}
                <div className="text-[11px] text-slate-400 truncate">{t(`soc.source.${a.source}`, { defaultValue: a.source })} · {t(`soc.category.${a.category}`, { defaultValue: a.category })}</div>
              </div>
              <div className="px-2 py-2 text-right tabular-nums text-slate-600">{a.count}</div>
              <div className="px-2 py-2 text-xs text-slate-500" title={new Date(a.last_seen).toLocaleString()}>{ago(a.last_seen)}</div>
              <div className="px-2 py-2" onClick={e => e.stopPropagation()}>
                {readOnly || !onUpdate ? <StatusPill s={a.status} /> : (
                  <select value={a.status} onChange={e => onUpdate([a.id], { status: e.target.value })} className="border border-slate-300 rounded-md px-1.5 py-1 text-xs bg-white w-full">
                    {SOC_STATUSES.map(s => <option key={s} value={s}>{t(`soc.status.${s}`)}</option>)}
                  </select>
                )}
                {a.owner && <div className="text-[11px] text-slate-400 truncate">{a.owner}</div>}
              </div>
            </div>
            {isOpen && <AlertDetail a={a} readOnly={readOnly} onUpdate={onUpdate} />}
          </div>
        )
      })}
    </div>
  )
}

export const RISK_LEVELS = [
  { key: 'critical', bar: 'bg-red-500', text: 'text-red-600' },
  { key: 'high', bar: 'bg-orange-500', text: 'text-orange-600' },
  { key: 'medium', bar: 'bg-amber-400', text: 'text-amber-600' },
  { key: 'low', bar: 'bg-slate-400', text: 'text-slate-600' },
]

export interface RiskRowView {
  id: number; name: string; type: string; score: number; level: string; factors: SocRiskFactor[]
  ip?: string | null; loc?: string | null; tenant?: string; services?: string[] | null; href?: string; onOpen?: () => void
}

function RiskItem({ factor, item }: { factor: string; item: SocRiskItem }) {
  const { t } = useTranslation()
  if (typeof item !== 'string') return <span className="inline-flex items-center gap-1.5"><SevBadge s={item.s as SocSeverity} /><span>{alertTitle(t as never, { rule: item.r, title: item.t })}</span></span>
  if (factor === 'hints') return <span>{t(`assets.hint.${item}`, { defaultValue: item })}</span>
  if (factor === 'patches' && item === 'reboot') return <span>{t('assets.act.rebootRequired')}</span>
  if (item.startsWith('CVE-')) return <a href={`https://nvd.nist.gov/vuln/detail/${item.split(' ')[0]}`} target="_blank" rel="noreferrer" className="font-mono text-indigo-600 hover:underline">{item}</a>
  return <span className="font-mono">{item}</span>
}

/** Everything behind a device's score: each factor with its points and what it is made of (which services, checks, CVEs, alerts), then its open ports. */
export function RiskDetail({ factors, services }: { factors: SocRiskFactor[]; services?: string[] | null }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2">
      {factors.map(f => (
        <div key={f.k} className="border border-slate-200 rounded-lg bg-white">
          <div className="flex items-center gap-2 px-3 py-1.5 text-sm">
            <b className="font-medium text-slate-900">{t(`soc.risk.factor.${f.k}`, { n: f.n ?? 0 })}</b>
            <span className="ml-auto text-xs text-slate-400">+{Math.round(f.pts)}</span>
          </div>
          {f.items && f.items.length > 0 && (
            <ul className="px-3 pb-2 text-xs text-slate-600 space-y-0.5">
              {f.items.map((it, i) => <li key={i}><RiskItem factor={f.k} item={it} /></li>)}
              {typeof f.n === 'number' && f.n > f.items.length && <li className="text-slate-400">… {t('soc.risk.more', { count: f.n - f.items.length })}</li>}
            </ul>
          )}
        </div>
      ))}
      {services && services.length > 0 && (
        <div className="border border-slate-200 rounded-lg bg-white">
          <div className="px-3 py-1.5 text-sm font-medium text-slate-900">{t('soc.risk.ports')} ({services.length})</div>
          <ul className="px-3 pb-2 text-xs text-slate-600 font-mono space-y-0.5 max-h-48 overflow-y-auto">{services.map((x, i) => <li key={i}>{x}</li>)}</ul>
        </div>
      )}
    </div>
  )
}

/** Devices with their score and the reasons behind it. A row opens into the detail of every factor (the chips only say how many). */
export function RiskTable({ rows, empty }: { rows: RiskRowView[]; empty: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState<number | null>(null)
  if (rows.length === 0) return <p className="text-sm text-slate-400 py-8 text-center">{empty}</p>
  const cols = 'grid-cols-[1.25rem,minmax(0,1.3fr),9rem,minmax(0,3fr)]'
  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
      <div className={cn('grid bg-slate-50 text-xs text-slate-500 px-4 py-2 gap-x-3', cols)}>
        <div /><div>{t('soc.risk.col.asset')}</div><div>{t('soc.risk.col.score')}</div><div>{t('soc.risk.col.why')}</div>
      </div>
      {rows.map(r => {
        const lv = RISK_LEVELS.find(l => l.key === r.level) ?? RISK_LEVELS[3]
        const isOpen = open === r.id
        return (
          <div key={r.id} className="border-t border-slate-100">
            <div className={cn('grid items-center px-4 py-2 gap-x-3 cursor-pointer hover:bg-slate-50', cols)} onClick={() => setOpen(isOpen ? null : r.id)}>
              <div className="text-slate-400">{isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</div>
              <div className="flex items-center gap-2 min-w-0" onClick={e => e.stopPropagation()}>
                <TypeIcon type={(r.type as AssetType) ?? 'other'} size={15} />
                <div className="min-w-0">
                  {r.href ? <Link to={r.href} className="text-indigo-600 hover:underline truncate block">{r.name}</Link>
                    : r.onOpen ? <button onClick={r.onOpen} className="text-indigo-600 hover:underline truncate block max-w-full text-left">{r.name}</button>
                    : <span className="truncate block text-slate-900">{r.name}</span>}
                  {(r.ip || r.loc || r.tenant) && <div className="text-[11px] text-slate-400 truncate">{[r.ip, r.loc, r.tenant].filter(Boolean).join(' · ')}</div>}
                </div>
              </div>
              <div className="flex items-center gap-2" title={t(`soc.risk.level.${r.level}`) as string}>
                <div className="w-16 h-2 bg-slate-100 rounded-full overflow-hidden"><div className={cn('h-full rounded-full', lv.bar)} style={{ width: `${Math.min(100, r.score)}%` }} /></div>
                <span className={cn('font-semibold tabular-nums', lv.text)}>{Math.round(r.score)}</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {r.factors.map(f => {
                  // which services is the one thing worth saying in the chip itself
                  const names = f.k === 'exposure' && f.items ? (f.items as string[]).slice(0, 4).map(x => x.split(' ').slice(1).join(' ') || x).join(', ') : ''
                  return <Pill key={f.k} tone="gray">{t(`soc.risk.factor.${f.k}`, { n: f.n ?? 0 })}{names ? ` (${names}${(f.n ?? 0) > 4 ? ', …' : ''})` : ''} <span className="text-slate-400">+{Math.round(f.pts)}</span></Pill>
                })}
              </div>
            </div>
            {isOpen && <div className="px-4 pb-3 pl-10 bg-slate-50 border-t border-slate-100"><div className="pt-3"><RiskDetail factors={r.factors} services={r.services} /></div></div>}
          </div>
        )
      })}
    </div>
  )
}

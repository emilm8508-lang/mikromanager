import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { HeartPulse, Layers3, FileClock, Radio } from 'lucide-react'
import { centralApi, centralConfig, type CentralSoc } from '../lib/api'
import { TenantBadge } from '../components/ui/TenantBadge'
import { SvcPill, modeText, MonthCell } from './Services'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'

type Part = { tenant: string; lastSeen: string | null; soc: CentralSoc }

// The agents report these sections inside their compact SOC status; these pages show them for all clients at once.
function useParts() {
  const cfg = centralConfig.load()
  const [parts, setParts] = useState<Part[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    const load = async () => {
      try {
        const r = await centralApi.socStatusAll()
        setParts(r.tenants.filter(x => x.soc).map(x => ({ tenant: x.tenant, lastSeen: x.last_seen, soc: x.soc! })))
        setErr(null)
      } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
    }
    void load()
    const iv = setInterval(() => void load(), 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  return { parts, loading, err, configured: !!cfg }
}

function Shell({ icon, title, subtitle, children, state }: { icon: React.ReactNode; title: string; subtitle: string; children: React.ReactNode; state: ReturnType<typeof useParts> }) {
  const { t } = useTranslation()
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">{icon} {title}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{subtitle}</p>
      </div>
      {state.err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{state.err}</div>}
      {state.loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : state.parts.length === 0 ? <p className="text-sm text-slate-500">{t('soc.centralNoData')}</p> : children}
    </div>
  )
}

const GRID_SVC = 'grid-cols-[minmax(0,1.2fr)_minmax(0,1.6fr)_7rem_minmax(0,2fr)_6rem_minmax(0,1.5fr)]'

export function CentralServicesPage() {
  const { t } = useTranslation()
  const ago = useAgo()
  const state = useParts()
  const rows = useMemo(() => {
    const order = { down: 0, degraded: 1, unknown: 2, ok: 3 } as Record<string, number>
    return state.parts.flatMap(p => (p.soc.services?.items ?? []).map(s => ({ tenant: p.tenant, s }))).sort((a, b) => (order[a.s.s] ?? 3) - (order[b.s.s] ?? 3) || a.tenant.localeCompare(b.tenant) || a.s.n.localeCompare(b.s.n))
  }, [state.parts])
  const counts = { down: rows.filter(r => r.s.s === 'down').length, degraded: rows.filter(r => r.s.s === 'degraded').length, ok: rows.filter(r => r.s.s === 'ok').length }
  return (
    <Shell state={state} icon={<Layers3 size={20} className="text-indigo-600" />} title={t('svc.title')} subtitle={t('svc.subtitle')}>
      {rows.length === 0 ? <p className="text-sm text-slate-500">{t('svc.central.none')}</p> : (
        <>
          <p className="text-sm text-slate-600">{t('svc.counts', { ok: counts.ok, degraded: counts.degraded, down: counts.down })}</p>
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
            <div className={cn('grid bg-slate-50 text-xs text-slate-500 px-4 py-2', GRID_SVC)}>
              <div>{t('soc.central.client')}</div><div>{t('svc.col.service')}</div><div>{t('svc.col.state')}</div><div>{t('svc.col.members')}</div><div>{t('svc.col.uptime')}</div><div>{t('svc.col.sla')}</div>
            </div>
            {rows.map(({ tenant, s }) => (
              <div key={tenant + s.n} className={cn('grid px-4 py-2 border-t border-slate-100 items-start', GRID_SVC)}>
                <div><TenantBadge tenant={tenant} /></div>
                <div className="min-w-0"><div className="font-medium text-slate-900 truncate">{s.n}</div><div className="text-[11px] text-slate-400">{modeText(t as never, s.mode, s.min ?? null)}</div></div>
                <div><SvcPill s={s.s} />{s.since && <div className="text-[11px] text-slate-400 mt-0.5">{ago(s.since)}</div>}</div>
                <div className="text-xs text-slate-600 min-w-0">
                  <div>{t('svc.membersUp', { up: s.up, total: s.total })}</div>
                  {s.missing.length > 0 && <div className="text-red-600 truncate" title={s.missing.join(', ')}>{t('svc.missing', { names: s.missing.join(', ') })}</div>}
                </div>
                <div className="tabular-nums text-slate-700">{s.u30 != null ? `${s.u30.toFixed(2)}%` : '—'}</div>
                <div><MonthCell m={s.month} /></div>
              </div>
            ))}
          </div>
        </>
      )}
    </Shell>
  )
}

export function CentralAvailabilityPage() {
  const { t } = useTranslation()
  const ago = useAgo()
  const state = useParts()
  const withData = state.parts.filter(p => p.soc.availability)
  const bad = withData.flatMap(p => p.soc.availability!.bad.map(b => ({ tenant: p.tenant, b })))
  const total = withData.reduce((n, p) => ({ up: n.up + p.soc.availability!.up, down: n.down + p.soc.availability!.down, unreachable: n.unreachable + p.soc.availability!.unreachable }), { up: 0, down: 0, unreachable: 0 })
  return (
    <Shell state={state} icon={<HeartPulse size={20} className="text-indigo-600" />} title={t('avail.title')} subtitle={t('avail.subtitle')}>
      {withData.length === 0 ? <p className="text-sm text-slate-500">{t('svc.central.none')}</p> : (
        <>
          <div className="flex gap-2 flex-wrap">
            {(['down', 'unreachable', 'up'] as const).map(s => (
              <div key={s} className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[8rem]">
                <div className="text-xs text-slate-500">{t(`avail.state.${s}`)}</div>
                <div className={cn('text-2xl font-bold tabular-nums', total[s] ? (s === 'down' ? 'text-red-600' : s === 'unreachable' ? 'text-amber-600' : 'text-green-600') : 'text-slate-300')}>{total[s]}</div>
              </div>
            ))}
          </div>
          {bad.length === 0 ? <p className="text-sm text-slate-500">{t('svc.central.availNone', { up: total.up })}</p> : (
            <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
              {bad.map(({ tenant, b }, i) => (
                <div key={i} className="flex items-center gap-3 px-4 py-2">
                  <span className="w-40 shrink-0"><TenantBadge tenant={tenant} /></span>
                  <span className="font-medium text-slate-900 flex-1 truncate">{b.n}</span>
                  <span className={b.s === 'down' ? 'text-red-600 text-xs' : 'text-amber-600 text-xs'}>{t(`avail.state.${b.s}`)}{b.root ? ` · ${t('svc.central.behind', { name: b.root })}` : ''}</span>
                  <span className="text-xs text-slate-400 w-24 text-right">{ago(b.since)}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </Shell>
  )
}

export function CentralConfigsPage() {
  const { t } = useTranslation()
  const ago = useAgo()
  const state = useParts()
  const withData = state.parts.filter(p => p.soc.configs)
  const changed = withData.flatMap(p => p.soc.configs!.changed_24h.map(c => ({ tenant: p.tenant, c }))).sort((a, b) => b.c.at.localeCompare(a.c.at))
  return (
    <Shell state={state} icon={<FileClock size={20} className="text-indigo-600" />} title={t('cfg.title')} subtitle={t('cfg.subtitle')}>
      {withData.length === 0 ? <p className="text-sm text-slate-500">{t('svc.central.none')}</p> : (
        <>
          <p className="text-sm text-slate-600">{withData.map(p => `${p.tenant}: ${p.soc.configs!.tracked}`).join(' · ')}</p>
          <h2 className="text-sm font-medium text-slate-700">{t('cfg.central.changed')}</h2>
          {changed.length === 0 ? <p className="text-sm text-slate-500">{t('avail.outagesNone')}</p> : (
            <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
              {changed.map(({ tenant, c }, i) => (
                <div key={i} className="flex items-center gap-3 px-4 py-2">
                  <span className="w-40 shrink-0"><TenantBadge tenant={tenant} /></span>
                  <span className="font-medium text-slate-900 w-48 truncate">{c.n}</span>
                  <span className="text-xs text-slate-500 flex-1 truncate" title={c.sections.join(', ')}>{c.added != null && <><span className="text-green-700">+{c.added}</span> <span className="text-red-700">−{c.removed}</span> </>}{c.sections.join(', ')}</span>
                  <span className="text-xs text-slate-400 w-24 text-right">{ago(c.at)}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </Shell>
  )
}

export function CentralSyslogPage() {
  const { t } = useTranslation()
  const state = useParts()
  const withData = state.parts.filter(p => p.soc.syslog)
  return (
    <Shell state={state} icon={<Radio size={20} className="text-indigo-600" />} title={t('syslog.title')} subtitle={t('syslog.subtitle')}>
      {withData.length === 0 ? <p className="text-sm text-slate-500">{t('svc.central.none')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className="grid grid-cols-[minmax(0,1.5fr)_6rem_minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,2fr)] bg-slate-50 text-xs text-slate-500 px-4 py-2">
            <div>{t('soc.central.client')}</div><div>{t('syslog.central.state')}</div><div>{t('syslog.settings.title')}</div><div className="text-right">{t('syslog.central.events')}</div><div className="text-right">{t('syslog.central.devices')}</div><div />
          </div>
          {withData.map(p => {
            const s = p.soc.syslog!
            return (
              <div key={p.tenant} className="grid grid-cols-[minmax(0,1.5fr)_6rem_minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,2fr)] px-4 py-2 border-t border-slate-100 items-center">
                <div><TenantBadge tenant={p.tenant} /></div>
                <div className={s.on ? 'text-green-700' : 'text-slate-400'}>{t(s.on ? 'syslog.central.on' : 'syslog.central.off')}</div>
                <div className="text-xs text-slate-500">syslog: {s.listening.syslog ? '✓' : '—'} · trap: {s.listening.trap ? '✓' : '—'}</div>
                <div className="text-right tabular-nums">{s.stored_24h}</div>
                <div className="text-right tabular-nums">{s.sources}</div>
                <div className="text-xs text-red-600 truncate pl-3" title={s.errors.join(' · ')}>{s.errors.join(' · ')}</div>
              </div>
            )
          })}
        </div>
      )}
    </Shell>
  )
}

import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Siren } from 'lucide-react'
import { centralApi, centralConfig, socFromCentral, type CentralSoc as CentralSocData } from '../lib/api'
import { SocFilters, SocKpis, SocTable, SOC_FILTER_DEFAULT, useAgo, type SocFilterState } from '../components/SocBits'
import { cn } from '../lib/utils'

type Part = { tenant: string; lastSeen: string | null; soc: CentralSocData }

// The alerts of the clients: every agent detects and triages on its own side, Central shows the results - an overview of all clients on top,
// the open queue of the chosen one below (read-only; the analyst works the alerts on the agent).
export function CentralSoc() {
  const { t } = useTranslation()
  const ago = useAgo()
  const cfg = centralConfig.load()
  const [parts, setParts] = useState<Part[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenant, setTenant] = useState('')
  const [f, setF] = useState<SocFilterState>(SOC_FILTER_DEFAULT)

  const reload = async () => {
    try {
      const r = await centralApi.socStatusAll()
      setParts(r.tenants.filter(x => x.soc && x.soc.stats).map(x => ({ tenant: x.tenant, lastSeen: x.last_seen, soc: x.soc! })))
      setErr(null)
    } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }
  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    void reload()
    const iv = setInterval(() => void reload(), 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  useEffect(() => { if (parts.length && !parts.some(p => p.tenant === tenant)) setTenant(parts[0].tenant) }, [parts, tenant])

  const ranked = useMemo(() => [...parts].sort((a, b) => {
    const w = (p: Part) => (p.soc.stats!.by_severity.critical ?? 0) * 1000 + (p.soc.stats!.by_severity.high ?? 0) * 10 + p.soc.stats!.open
    return w(b) - w(a)
  }), [parts])
  const part = parts.find(p => p.tenant === tenant)
  const alerts = useMemo(() => {
    if (!part) return []
    const q = f.q.trim().toLowerCase()
    return socFromCentral(part.soc).filter(a =>
      (!f.severity || a.severity === f.severity) && (!f.category || a.category === f.category) && (!f.source || a.source === f.source)
      && (f.tab === 'open' || (f.tab === 'new' && a.status === 'new'))
      && (!q || [a.device_name, a.rule, a.title, JSON.stringify(a.detail)].some(x => String(x ?? '').toLowerCase().includes(q))))
  }, [part, f])
  const stale = part?.soc.at ? Date.now() - new Date(part.soc.at).getTime() > 20 * 60 * 1000 : false

  return (
    <div className="p-6 space-y-4 max-w-[1500px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Siren size={20} className="text-indigo-600" /> {t('soc.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('soc.centralIntro')}</p>
      </div>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}
      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : parts.length === 0 ? <p className="text-sm text-slate-500">{t('soc.centralNoData')}</p> : (
        <>
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
            <div className="grid grid-cols-[minmax(0,2fr),repeat(5,minmax(0,1fr)),minmax(0,1.2fr)] bg-slate-50 text-xs text-slate-500 px-4 py-2">
              <div>{t('soc.central.client')}</div><div className="text-right">{t('soc.kpi.open')}</div><div className="text-right">{t('soc.severity.critical')}</div>
              <div className="text-right">{t('soc.severity.high')}</div><div className="text-right">{t('soc.kpi.new')}</div><div className="text-right">{t('soc.kpi.closed24')}</div>
              <div className="text-right">{t('soc.central.lastReport')}</div>
            </div>
            {ranked.map(p => {
              const s = p.soc.stats!
              return (
                <button key={p.tenant} onClick={() => setTenant(p.tenant)}
                  className={cn('grid w-full text-left grid-cols-[minmax(0,2fr),repeat(5,minmax(0,1fr)),minmax(0,1.2fr)] px-4 py-2 border-t border-slate-100 hover:bg-slate-50 tabular-nums', p.tenant === tenant && 'bg-indigo-50')}>
                  <div className="font-medium text-slate-900 truncate">{p.tenant}</div>
                  <div className="text-right">{s.open}</div>
                  <div className={cn('text-right', s.by_severity.critical ? 'text-red-600 font-semibold' : 'text-slate-400')}>{s.by_severity.critical}</div>
                  <div className={cn('text-right', s.by_severity.high ? 'text-orange-600 font-semibold' : 'text-slate-400')}>{s.by_severity.high}</div>
                  <div className="text-right">{s.new}</div>
                  <div className="text-right text-slate-500">{s.closed_24h}</div>
                  <div className="text-right text-xs text-slate-500">{ago(p.soc.at)}</div>
                </button>
              )
            })}
          </div>
          {part && (
            <>
              <div className="flex items-center gap-3 flex-wrap">
                <h2 className="text-base font-semibold text-slate-900">{part.tenant}</h2>
                {stale && <span className="text-xs bg-amber-50 border border-amber-200 text-amber-900 rounded px-2 py-0.5">{t('soc.central.stale', { when: ago(part.soc.at) })}</span>}
              </div>
              <SocKpis stats={part.soc.stats!} />
              <SocFilters f={f} set={setF} tabs={['open', 'new']} />
              <SocTable alerts={alerts} readOnly empty={t('soc.empty') as string} />
              {part.soc.alerts.length >= 80 && <p className="text-xs text-slate-400">{t('soc.central.cut')}</p>}
            </>
          )}
        </>
      )}
    </div>
  )
}

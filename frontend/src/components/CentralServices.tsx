import { useTranslation } from 'react-i18next'
import { CentralSoc } from '../lib/api'
import { SvcPill, modeText, MonthCell } from '../pages/Services'
import { useAgo } from './SocBits'

// What the agent of a client reports about its business services and the devices that do not answer (compact; no addresses).
export function CentralServices({ soc }: { soc: CentralSoc }) {
  const { t } = useTranslation()
  const ago = useAgo()
  const svc = soc.services
  const av = soc.availability
  if (!svc && !av && !soc.syslog && !soc.configs) return null
  return (
    <div className="space-y-3 pt-2">
      <h2 className="text-base font-semibold text-slate-900">{t('svc.central.title')}</h2>
      {soc.syslog && (
        <p className="text-xs text-slate-500">
          {t('syslog.central.line', { state: t(soc.syslog.on ? 'syslog.central.on' : 'syslog.central.off'), n: soc.syslog.stored_24h, sources: soc.syslog.sources })}
          {soc.syslog.errors.length > 0 && <span className="text-red-600"> · {soc.syslog.errors.join(' · ')}</span>}
        </p>
      )}
      {svc && (
        svc.items.length === 0 ? <p className="text-sm text-slate-500">{t('svc.central.none')}</p> : (
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
            <div className="grid grid-cols-[minmax(0,2fr)_7rem_minmax(0,2fr)_6rem_minmax(0,1.5fr)] bg-slate-50 text-xs text-slate-500 px-4 py-2">
              <div>{t('svc.col.service')}</div><div>{t('svc.col.state')}</div><div>{t('svc.col.members')}</div><div>{t('svc.col.uptime')}</div><div>{t('svc.col.sla')}</div>
            </div>
            {svc.items.map(s => (
              <div key={s.n} className="grid grid-cols-[minmax(0,2fr)_7rem_minmax(0,2fr)_6rem_minmax(0,1.5fr)] px-4 py-2 border-t border-slate-100 items-start">
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
        )
      )}
      {soc.configs && soc.configs.changed_24h.length > 0 && (
        <div className="space-y-1">
          <h3 className="text-sm font-medium text-slate-700">{t('cfg.central.changed')}</h3>
          <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
            {soc.configs.changed_24h.map((c, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-1.5">
                <span className="font-medium text-slate-900 w-48 truncate">{c.n}</span>
                <span className="text-xs text-slate-500 flex-1 truncate">{c.added != null && <><span className="text-green-700">+{c.added}</span> <span className="text-red-700">−{c.removed}</span> </>}{c.sections.join(', ')}</span>
                <span className="text-xs text-slate-400 w-20 text-right">{ago(c.at)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {av && (
        <div className="space-y-1">
          <h3 className="text-sm font-medium text-slate-700">{t('svc.central.availability')}</h3>
          {av.bad.length === 0 ? <p className="text-sm text-slate-500">{t('svc.central.availNone', { up: av.up })}</p> : (
            <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
              {av.bad.map((b, i) => (
                <div key={i} className="flex items-center gap-3 px-4 py-1.5">
                  <span className="font-medium text-slate-900 flex-1 truncate">{b.n}</span>
                  <span className={b.s === 'down' ? 'text-red-600 text-xs' : 'text-amber-600 text-xs'}>{t(`avail.state.${b.s}`)}{b.root ? ` · ${t('svc.central.behind', { name: b.root })}` : ''}</span>
                  <span className="text-xs text-slate-400 w-20 text-right">{ago(b.since)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

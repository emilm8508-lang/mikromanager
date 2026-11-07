import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { BrainCircuit } from 'lucide-react'
import { centralApi, centralConfig, CentralSoc } from '../lib/api'
import { AnomalyItems, scoreTone } from '../components/AnomalyParts'
import { cn } from '../lib/utils'

// Central: the anomalies every agent found (services/anomaly.py, inside the SOC part of the snapshot). The detection runs on each
// agent against its own hosts' history; Central shows the results side by side. A false alarm is labelled by marking its SOC alert
// a false positive (Central's SOC page) or on the agent.

export function CentralAnomalies() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<Array<{ tenant: string; a: NonNullable<CentralSoc['anomalies']> | null; nf: NonNullable<CentralSoc['netflow']> | null }>>([])
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!cfg) return
    const load = async () => {
      try {
        const r = await centralApi.socStatusAll()
        setRows(r.tenants.map(x => ({ tenant: x.tenant, a: x.soc?.anomalies ?? null, nf: x.soc?.netflow ?? null })))
        setErr(null)
      } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
    }
    load()
    const iv = setInterval(load, 60_000)
    return () => clearInterval(iv)
  }, [])

  if (!cfg) return <div className="p-6"><div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">{t('alerts.needsCentral')}</div></div>

  const withData = rows.filter(r => r.a)
  const openAll = withData.flatMap(r => r.a!.open.map(o => ({ tenant: r.tenant, o }))).sort((x, y) => y.o.z - x.o.z)
  const sum = (f: (a: NonNullable<CentralSoc['anomalies']>) => number) => withData.reduce((s, r) => s + f(r.a!), 0)
  const tt = sum(a => a.true), ff = sum(a => a.false)

  return (
    <div className="p-6 space-y-4 max-w-6xl">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><BrainCircuit size={20} className="text-indigo-600" /> {t('anomaly.centralTitle')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('anomaly.centralIntro')}</p>
      </div>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}
      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[[t('anomaly.stat.open'), String(openAll.length)], [t('anomaly.stat.judged'), String(sum(a => a.series - a.learning))],
              [t('anomaly.stat.events30'), String(sum(a => a.events_30d))],
              [t('anomaly.stat.precision'), tt + ff ? `${Math.round((tt / (tt + ff)) * 100)} %` : '—']].map(([l, v]) => (
              <div key={l} className="bg-white border border-slate-200 rounded-xl px-4 py-3"><div className="text-xs text-slate-500">{l}</div><div className="text-2xl font-bold text-slate-900 tabular-nums">{v}</div></div>
            ))}
          </div>

          <div className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('anomaly.openTitle')}</h2>
            {openAll.length === 0 ? <p className="text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2">{t('anomaly.noneOpen')}</p>
              : openAll.map(({ tenant, o }, i) => (
                <div key={i} className={cn('bg-white border rounded-xl p-3 space-y-2', o.sev === 'high' ? 'border-red-300' : 'border-amber-300')}>
                  <div className="flex items-center gap-2 flex-wrap text-sm">
                    <span className="text-xs text-slate-500">{tenant}</span>
                    <span className="font-semibold text-slate-900">{o.h || '—'}</span>
                    <span className="text-xs text-slate-500">{t(`anomaly.cat.${o.c}`)}</span>
                    <span className={cn('text-[11px] rounded px-1.5 py-0.5 font-semibold', scoreTone(o.z))}>{t('anomaly.peak')} {o.z.toFixed(1)}</span>
                    <span className="text-xs text-slate-500 ml-auto">{t('anomaly.sinceShort', { at: new Date(o.since).toLocaleString() })}</span>
                  </div>
                  <AnomalyItems items={o.items} />
                </div>
              ))}
            <p className="text-[11px] text-slate-400">{t('anomaly.centralLabelHint')}</p>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-3 space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('netflow.centralTitle')}</h2>
            {rows.filter(r => r.nf?.on).length === 0 ? <p className="text-xs text-slate-400">{t('netflow.centralNone')}</p> : (
              <table className="w-full text-xs">
                <thead><tr className="text-left text-slate-400 border-b border-slate-200">
                  <th className="font-medium px-2 py-1.5">{t('anomaly.col.tenant')}</th><th className="font-medium px-2 py-1.5">{t('netflow.col.state')}</th>
                  <th className="font-medium px-2 py-1.5 text-right">{t('netflow.col.hosts')}</th><th className="font-medium px-2 py-1.5">{t('netflow.col.busiest')}</th>
                  <th className="font-medium px-2 py-1.5">{t('netflow.detTitle')} (24 h)</th>
                </tr></thead>
                <tbody>
                  {rows.filter(r => r.nf?.on).map(r => (
                    <tr key={r.tenant} className="border-t border-slate-100 align-top">
                      <td className="px-2 py-1.5 font-medium text-slate-800">{r.tenant}</td>
                      <td className={cn('px-2 py-1.5', r.nf!.listening ? 'text-emerald-700' : 'text-red-600')}>{r.nf!.listening ? t('netflow.centralOk', { n: r.nf!.exporters }) : (r.nf!.error || t('netflow.notListening'))}</td>
                      <td className="px-2 py-1.5 text-right font-mono">{r.nf!.hosts}</td>
                      <td className="px-2 py-1.5 text-slate-600">{r.nf!.top.slice(0, 3).map(x => `${x.n} ${(x.out / 1e6).toFixed(0)}/${(x.in / 1e6).toFixed(0)} MB`).join(' · ') || '—'}</td>
                      <td className="px-2 py-1.5">
                        {Object.keys(r.nf!.detections_24h).length === 0 ? <span className="text-slate-400">—</span>
                          : Object.entries(r.nf!.detections_24h).map(([k, n]) => <span key={k} className="mr-2 rounded px-1.5 py-0.5 bg-red-100 text-red-700 font-semibold">{t(`netflow.rule.${k.replace('net.', '')}`)} {n}</span>)}
                        {r.nf!.recent.slice(0, 3).map((x, i) => <div key={i} className="text-slate-500 mt-1">{x.msg}</div>)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-3">
            <h2 className="text-sm font-semibold text-slate-700 mb-2">{t('anomaly.perTenant')}</h2>
            <table className="w-full text-xs">
              <thead><tr className="text-left text-slate-400 border-b border-slate-200">
                <th className="font-medium px-2 py-1.5">{t('anomaly.col.tenant')}</th><th className="font-medium px-2 py-1.5 text-right">{t('anomaly.stat.judged')}</th>
                <th className="font-medium px-2 py-1.5 text-right">{t('anomaly.stat.learning')}</th><th className="font-medium px-2 py-1.5 text-right">{t('anomaly.stat.open')}</th>
                <th className="font-medium px-2 py-1.5 text-right">{t('anomaly.stat.events30')}</th><th className="font-medium px-2 py-1.5 text-right">{t('anomaly.stat.precision')}</th>
              </tr></thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.tenant} className="border-t border-slate-100">
                    <td className="px-2 py-1.5 font-medium text-slate-800">{r.tenant}</td>
                    {r.a ? <>
                      <td className="px-2 py-1.5 text-right font-mono">{r.a.series - r.a.learning}</td>
                      <td className="px-2 py-1.5 text-right font-mono">{r.a.learning}</td>
                      <td className="px-2 py-1.5 text-right font-mono">{r.a.open.length}</td>
                      <td className="px-2 py-1.5 text-right font-mono">{r.a.events_30d}</td>
                      <td className="px-2 py-1.5 text-right font-mono">{r.a.precision == null ? '—' : `${Math.round(r.a.precision * 100)} % (${r.a.true}/${r.a.true + r.a.false})`}</td>
                    </> : <td colSpan={5} className="px-2 py-1.5 text-slate-400">{t('anomaly.noAgentData')}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

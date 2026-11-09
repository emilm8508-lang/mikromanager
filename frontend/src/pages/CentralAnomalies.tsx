import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { BrainCircuit, ClipboardCopy } from 'lucide-react'
import { centralApi, centralConfig, CentralSoc } from '../lib/api'
import { AnomalyItems, scoreTone } from '../components/AnomalyParts'
import { cn } from '../lib/utils'

// Central: the anomalies every agent found (services/anomaly.py, inside the SOC part of the snapshot). The detection runs on each
// agent against its own hosts' history; Central shows the results side by side. A false alarm is labelled by marking its SOC alert
// a false positive (Central's SOC page) or on the agent.

export function CentralAnomalies() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<Array<{ tenant: string; a: NonNullable<CentralSoc['anomalies']> | null; nf: NonNullable<CentralSoc['netflow']> | null; ind: NonNullable<CentralSoc['indicators']> | null }>>([])
  const [allIps, setAllIps] = useState(false)
  const [copied, setCopied] = useState(false)
  // labels set here, shown until the agent's next report carries them (the command reaches the agent within ~2 minutes)
  const [queued, setQueued] = useState<Record<string, 'true' | 'false' | null>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [err2, setErr2] = useState<string | null>(null)
  const setVerdict = async (tenant: string, id: number, verdict: 'true' | 'false' | 'clear') => {
    const key = `${tenant}:${id}`
    setBusy(key)
    try {
      await centralApi.requestAnomalyVerdict(tenant, id, verdict)
      setQueued(q => ({ ...q, [key]: verdict === 'clear' ? null : verdict }))
      setErr2(null)
    } catch (e) { setErr2((e as Error).message) } finally { setBusy(null) }
  }
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!cfg) return
    const load = async () => {
      try {
        const r = await centralApi.socStatusAll()
        setRows(r.tenants.map(x => ({ tenant: x.tenant, a: x.soc?.anomalies ?? null, nf: x.soc?.netflow ?? null, ind: x.soc?.indicators ?? null })))
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
  // outside addresses across clients: one that probes several clients is a campaign (services/indicators.py on each agent)
  const merged: Record<string, { tenants: Set<string>; kinds: Set<string>; n: number; last: string | null }> = {}
  for (const r of rows) for (const x of r.ind?.ips ?? []) {
    const m = (merged[x.ip] ??= { tenants: new Set(), kinds: new Set(), n: 0, last: null })
    m.tenants.add(r.tenant); x.k.forEach(k => m.kinds.add(k)); m.n += x.n
    if (x.last && (!m.last || x.last > m.last)) m.last = x.last
  }
  const shared = Object.entries(merged).filter(([, m]) => allIps || m.tenants.size >= 2)
    .sort((a, b) => b[1].tenants.size - a[1].tenants.size || b[1].n - a[1].n).slice(0, 200)
  const multiTenant = Object.values(merged).filter(m => m.tenants.size >= 2).length
  const ros = shared.map(([ip, m]) => `/ip firewall address-list add list=mm-shared-attackers address=${ip} timeout=7d comment="${[...m.tenants].length} clients: ${[...m.kinds].join(',')}"`).join('\n')
  const copyRos = async () => { try { await navigator.clipboard.writeText(ros); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* selectable */ } }

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
                    {o.if != null && <span className="text-[11px] rounded px-1.5 py-0.5 font-mono bg-slate-100 text-slate-600" title={t('anomaly.multiHelp') as string}>IF {o.if.toFixed(2)}</span>}
                    <span className="text-xs text-slate-500 ml-auto">{t('anomaly.sinceShort', { at: new Date(o.since).toLocaleString() })}</span>
                  </div>
                  <AnomalyItems items={o.items} />
                </div>
              ))}
            <p className="text-[11px] text-slate-400">{t('anomaly.centralLabelHint')}</p>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-3 space-y-2">
            <h2 className="text-sm font-semibold text-slate-700">{t('anomaly.centralEventsTitle')}</h2>
            <p className="text-xs text-slate-500">{t('anomaly.centralEventsIntro')}</p>
            {rows.every(r => !(r.a?.events?.length)) ? <p className="text-xs text-slate-400">{t('anomaly.noHistory')}</p> : (
              <div className="overflow-x-auto max-h-[28rem]">
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-slate-400 border-b border-slate-200">
                    <th className="font-medium px-2 py-1.5">{t('anomaly.col.tenant')}</th><th className="font-medium px-2 py-1.5">{t('anomaly.col.host')}</th>
                    <th className="font-medium px-2 py-1.5">{t('anomaly.col.start')}</th><th className="font-medium px-2 py-1.5 text-right">{t('anomaly.col.peak')}</th>
                    <th className="font-medium px-2 py-1.5 text-right">IF</th><th className="font-medium px-2 py-1.5">{t('anomaly.col.what')}</th>
                    <th className="font-medium px-2 py-1.5">{t('anomaly.col.verdict')}</th>
                  </tr></thead>
                  <tbody>
                    {rows.flatMap(r => (r.a?.events ?? []).map(e => ({ tenant: r.tenant, e }))).sort((x, y) => y.e.since.localeCompare(x.e.since)).map(({ tenant, e }) => {
                      const key = `${tenant}:${e.id}`
                      const v = key in queued ? queued[key] : e.v
                      const btn = (val: 'true' | 'false', label: string, on: string) => (
                        <button disabled={busy === key} onClick={() => setVerdict(tenant, e.id, v === val ? 'clear' : val)}
                          className={cn('rounded border px-1.5 py-0.5 text-[11px]', v === val ? on : 'border-slate-300 text-slate-500 hover:bg-slate-50')}>{label}</button>
                      )
                      return (
                        <tr key={key} className="border-t border-slate-100">
                          <td className="px-2 py-1.5 text-slate-600">{tenant}</td>
                          <td className="px-2 py-1.5 font-medium text-slate-800">{e.h || '—'}{!e.end && <span className="ml-1 text-[10px] text-red-600">●</span>}</td>
                          <td className="px-2 py-1.5 text-slate-600 whitespace-nowrap">{new Date(e.since).toLocaleString()} · {e.min} min</td>
                          <td className="px-2 py-1.5 text-right"><span className={cn('rounded px-1.5 py-0.5 font-mono', scoreTone(e.z))}>{e.z.toFixed(1)}</span></td>
                          <td className="px-2 py-1.5 text-right font-mono text-slate-500">{e.if != null ? e.if.toFixed(2) : '—'}</td>
                          <td className="px-2 py-1.5 text-slate-600">{e.top.join(' · ')}</td>
                          <td className="px-2 py-1.5 whitespace-nowrap">
                            <span className="inline-flex gap-1">{btn('true', t('anomaly.verdict.true'), 'bg-green-100 border-green-300 text-green-800')}{btn('false', t('anomaly.verdict.false'), 'bg-slate-200 border-slate-300 text-slate-700')}</span>
                            {key in queued && <span className="ml-1 text-[10px] text-amber-700">{t('anomaly.queued')}</span>}
                            {!(key in queued) && e.vsoc && <span className="ml-1 text-[10px] text-slate-400" title={t('anomaly.verdict.fromSoc') as string}>SOC</span>}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {err2 && <p className="text-xs text-red-600">{err2}</p>}
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-3 space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-sm font-semibold text-slate-700">{t('anomaly.sharedTitle')}</h2>
              <span className="text-xs text-slate-500">{t('anomaly.sharedCount', { n: multiTenant, total: Object.keys(merged).length })}</span>
              <label className="ml-auto flex items-center gap-1.5 text-xs text-slate-600"><input type="checkbox" checked={allIps} onChange={e => setAllIps(e.target.checked)} /> {t('anomaly.sharedAll')}</label>
              {shared.length > 0 && <button onClick={copyRos} className="flex items-center gap-1 text-xs border border-slate-300 rounded-md px-2 py-1 hover:bg-slate-50"><ClipboardCopy size={12} /> {copied ? t('netflow.copied') : t('anomaly.sharedCopy')}</button>}
            </div>
            <p className="text-xs text-slate-500">{t('anomaly.sharedIntro')}</p>
            {shared.length === 0 ? <p className="text-xs text-slate-400">{t('anomaly.sharedNone')}</p> : (
              <div className="overflow-x-auto max-h-96">
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-slate-400 border-b border-slate-200">
                    <th className="font-medium px-2 py-1.5">{t('anomaly.col.address')}</th><th className="font-medium px-2 py-1.5">{t('anomaly.col.clients')}</th>
                    <th className="font-medium px-2 py-1.5">{t('anomaly.col.kinds')}</th><th className="font-medium px-2 py-1.5 text-right">{t('anomaly.col.count')}</th>
                    <th className="font-medium px-2 py-1.5">{t('anomaly.col.last')}</th>
                  </tr></thead>
                  <tbody>
                    {shared.map(([ip, m]) => (
                      <tr key={ip} className="border-t border-slate-100">
                        <td className="px-2 py-1.5 font-mono text-slate-800">{ip}</td>
                        <td className="px-2 py-1.5"><span className={cn('rounded px-1.5 py-0.5 font-semibold mr-1', m.tenants.size >= 2 ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-600')}>{m.tenants.size}</span>{[...m.tenants].join(', ')}</td>
                        <td className="px-2 py-1.5 text-slate-600">{[...m.kinds].map(k => t(`anomaly.kind.${k}`, { defaultValue: k })).join(', ')}</td>
                        <td className="px-2 py-1.5 text-right font-mono">{m.n}</td>
                        <td className="px-2 py-1.5 text-slate-500">{m.last ? new Date(m.last).toLocaleString() : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
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

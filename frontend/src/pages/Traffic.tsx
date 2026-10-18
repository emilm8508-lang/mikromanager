import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { Activity, Play, Square, Download } from 'lucide-react'
import { trafficApi, type TrafficFlow, type TrafficSample } from '../lib/api'
import { Button } from '../components/ui/Button'
import { cn } from '../lib/utils'

// Who talks to whom through a router, right now: the flows RouterOS Torch reports for an interface, asked again every few seconds.
// The rows are filterable and coloured by protocol; a double click on a device that is in the inventory opens its tools (ping / port scan).

const PROTO_COLOR: Record<string, string> = { tcp: '#2a78d6', udp: '#1baf7a', icmp: '#eda100', gre: '#8b5cf6', esp: '#8b5cf6' }
const fmtBps = (v: number) => v >= 1e9 ? `${(v / 1e9).toFixed(2)} Gb/s` : v >= 1e6 ? `${(v / 1e6).toFixed(2)} Mb/s` : v >= 1e3 ? `${(v / 1e3).toFixed(1)} kb/s` : `${Math.round(v)} b/s`
const csvq = (v: unknown) => { const s = v == null ? '' : String(v); return `"${(s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s).replace(/"/g, '""')}"` }

export function Traffic() {
  const { t } = useTranslation()
  const nav = useNavigate()
  const devices = useQuery({ queryKey: ['traffic-devices'], queryFn: trafficApi.devices })
  const [dev, setDev] = useState<number | null>(null)
  const [iface, setIface] = useState('')
  const [secs, setSecs] = useState(3)
  const [running, setRunning] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [last, setLast] = useState<TrafficSample | null>(null)
  const [history, setHistory] = useState<number[]>([])
  const [q, setQ] = useState('')
  const [proto, setProto] = useState('all')
  const live = useRef(false)
  const ifaces = useQuery({ queryKey: ['traffic-ifaces', dev], queryFn: () => trafficApi.interfaces(dev!), enabled: dev != null, retry: false })

  useEffect(() => { if (dev == null && devices.data?.length) setDev(devices.data[0].id) }, [devices.data, dev])
  useEffect(() => { if (ifaces.data?.length && !ifaces.data.includes(iface)) setIface(ifaces.data[0]) }, [ifaces.data, iface])
  useEffect(() => () => { live.current = false }, [])

  const loop = async (d: number, i: string, s: number) => {
    live.current = true; setRunning(true); setErr(null)
    while (live.current) {
      try {
        const r = await trafficApi.sample(d, i, s)
        if (!live.current) break
        setLast(r)
        setHistory(h => [...h.slice(-59), r.flows.reduce((n, f) => n + f.tx + f.rx, 0)])
      } catch (e: any) { setErr(e?.response?.data?.detail ?? e?.message ?? String(e)); break }
    }
    live.current = false; setRunning(false)
  }
  const stop = () => { live.current = false }

  const flows = useMemo(() => (last?.flows ?? []).filter(f =>
    (proto === 'all' || f.proto === proto)
    && (!q.trim() || [f.src, f.dst, f.proto, f.service, f.sport, f.dport, last?.agg.devices.find(d => d.ip === f.src)?.name, last?.agg.devices.find(d => d.ip === f.dst)?.name].some(x => String(x ?? '').toLowerCase().includes(q.trim().toLowerCase())))), [last, q, proto])
  const nameOf = (ip: string) => last?.agg.devices.find(d => d.ip === ip)
  const max = Math.max(1, ...(last?.agg.devices.slice(0, 12).map(d => d.up + d.down) ?? [1]))
  const protoTotal = Math.max(1, ...(last?.agg.protocols.map(p => p[1]) ?? [1]))
  const hMax = Math.max(1, ...history)
  const exportCsv = () => {
    const lines = ['src,dst,protocol,src_port,dst_port,service,tx_bps,rx_bps', ...flows.map((f: TrafficFlow) => [f.src, f.dst, f.proto, f.sport, f.dport, f.service, f.tx, f.rx].map(csvq).join(','))]
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' })); a.download = 'traffic.csv'; a.click(); URL.revokeObjectURL(a.href)
  }
  const sel = 'border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white'
  const protos = ['all', ...Array.from(new Set((last?.flows ?? []).map(f => f.proto)))]
  const openAsset = (ip: string) => { const d = nameOf(ip); if (d?.asset_id) nav(`/inventory/${d.asset_id}`) }

  return (
    <div className="p-6 space-y-4 max-w-[1500px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Activity size={20} className="text-indigo-600" /> {t('traffic.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('traffic.subtitle')}</p>
      </div>
      {devices.data && devices.data.length === 0 && <div className="text-sm bg-amber-50 border border-amber-200 text-amber-900 rounded-lg px-4 py-2">{t('traffic.noRouters')} <Link to="/credentials" className="underline">{t('traffic.goCredentials')}</Link></div>}
      <div className="flex items-center gap-2 flex-wrap">
        <select value={dev ?? ''} onChange={e => { stop(); setDev(Number(e.target.value)); setIface('') }} className={sel}>{(devices.data ?? []).map(d => <option key={d.id} value={d.id}>{d.name} ({d.ip})</option>)}</select>
        <select value={iface} onChange={e => setIface(e.target.value)} className={sel} disabled={!ifaces.data?.length}>{(ifaces.data ?? []).map(i => <option key={i} value={i}>{i}</option>)}</select>
        <select value={secs} onChange={e => setSecs(Number(e.target.value))} className={sel}>{[1, 2, 3, 5].map(s => <option key={s} value={s}>{t('traffic.window', { s })}</option>)}</select>
        {running ? <Button size="sm" variant="secondary" onClick={stop}><Square size={13} /> {t('traffic.stop')}</Button>
          : <Button size="sm" variant="primary" disabled={dev == null || !iface} onClick={() => void loop(dev!, iface, secs)}><Play size={13} /> {t('traffic.start')}</Button>}
        <span className="flex-1" />
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('traffic.filter') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56" />
        <select value={proto} onChange={e => setProto(e.target.value)} className={sel}>{protos.map(p => <option key={p} value={p}>{p === 'all' ? t('traffic.allProtocols') : p}</option>)}</select>
        <Button size="sm" variant="secondary" disabled={!flows.length} onClick={exportCsv}><Download size={13} /> CSV</Button>
      </div>
      {err && <div className="text-sm bg-red-50 border border-red-200 text-red-800 rounded-lg px-4 py-2">{err}</div>}
      {ifaces.isError && <div className="text-sm bg-amber-50 border border-amber-200 text-amber-900 rounded-lg px-4 py-2">{t('traffic.ifacesFailed')}</div>}

      {last && (
        <div className="grid grid-cols-1 xl:grid-cols-[22rem_1fr] gap-4 items-start">
          <div className="space-y-4">
            <section className="bg-white border border-slate-200 rounded-xl p-3">
              <h3 className="text-sm font-semibold text-slate-800 mb-1">{t('traffic.total')} <span className="text-xs font-normal text-slate-400">{running ? '· live' : ''}</span></h3>
              <p className="text-lg font-bold text-slate-900">{fmtBps(history[history.length - 1] ?? 0)}</p>
              <svg viewBox="0 0 240 40" className="w-full h-10" preserveAspectRatio="none"><polyline fill="none" stroke="#2a78d6" strokeWidth="1.5" points={history.map((v, i) => `${(i / Math.max(1, history.length - 1)) * 240},${38 - (v / hMax) * 36}`).join(' ')} /></svg>
            </section>
            <section className="bg-white border border-slate-200 rounded-xl p-3">
              <h3 className="text-sm font-semibold text-slate-800 mb-2">{t('traffic.topTalkers')}</h3>
              <ul className="space-y-1.5">
                {last.agg.devices.slice(0, 12).map(d => (
                  <li key={d.ip} className="text-xs" onDoubleClick={() => openAsset(d.ip)} title={d.asset_id ? t('traffic.dblHint') as string : undefined}>
                    <div className="flex justify-between gap-2"><span className={cn('truncate', d.asset_id && 'text-indigo-700 cursor-pointer')}>{d.name ?? d.ip}{d.name && <span className="text-slate-400"> {d.ip}</span>}</span><span className="text-slate-500 shrink-0">↑{fmtBps(d.up)} ↓{fmtBps(d.down)}</span></div>
                    <div className="h-1.5 bg-slate-100 rounded mt-0.5 flex overflow-hidden"><div style={{ width: `${(d.up / max) * 100}%`, background: '#eb6834' }} /><div style={{ width: `${(d.down / max) * 100}%`, background: '#2a78d6' }} /></div>
                  </li>))}
              </ul>
              <p className="text-[10px] text-slate-400 mt-2">{t('traffic.legend')}</p>
            </section>
            <section className="bg-white border border-slate-200 rounded-xl p-3">
              <h3 className="text-sm font-semibold text-slate-800 mb-2">{t('traffic.protocols')}</h3>
              <ul className="space-y-1">{last.agg.protocols.map(([p, v]) => (
                <li key={p} className="text-xs flex items-center gap-2"><span className="w-12" style={{ color: PROTO_COLOR[p] ?? '#64748b' }}>{p}</span><div className="flex-1 h-1.5 bg-slate-100 rounded overflow-hidden"><div style={{ width: `${(v / protoTotal) * 100}%`, background: PROTO_COLOR[p] ?? '#94a3b8', height: '100%' }} /></div><span className="text-slate-500 w-20 text-right">{fmtBps(v)}</span></li>))}</ul>
              <h3 className="text-sm font-semibold text-slate-800 mt-3 mb-1">{t('traffic.services')}</h3>
              <div className="flex flex-wrap gap-1">{last.agg.services.slice(0, 12).map(([s, v]) => <span key={s} className="text-[11px] bg-slate-100 rounded px-1.5 py-0.5" title={fmtBps(v)}>{s}</span>)}</div>
            </section>
          </div>
          <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="max-h-[38rem] overflow-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-slate-50"><tr className="text-left text-slate-500"><th className="px-3 py-2 font-normal">{t('traffic.src')}</th><th className="font-normal">{t('traffic.dst')}</th><th className="font-normal">{t('traffic.proto')}</th><th className="font-normal">{t('traffic.port')}</th><th className="font-normal text-right">↑</th><th className="font-normal text-right pr-3">↓</th></tr></thead>
                <tbody>{flows.slice(0, 200).map((f, i) => (
                  <tr key={i} className="border-t border-slate-100 hover:bg-slate-50" onDoubleClick={() => openAsset(nameOf(f.src)?.asset_id ? f.src : f.dst)}>
                    <td className="px-3 py-1.5"><span className="text-slate-800">{nameOf(f.src)?.name ?? f.src}</span>{f.sport ? <span className="text-slate-400">:{f.sport}</span> : null}</td>
                    <td><span className="text-slate-800">{nameOf(f.dst)?.name ?? f.dst}</span>{f.dport ? <span className="text-slate-400">:{f.dport}</span> : null}</td>
                    <td style={{ color: PROTO_COLOR[f.proto] ?? '#64748b' }}>{f.proto}</td><td className="text-slate-500">{f.service ?? ''}</td>
                    <td className="text-right text-slate-600">{fmtBps(f.tx)}</td><td className="text-right pr-3 text-slate-600">{fmtBps(f.rx)}</td>
                  </tr>))}</tbody>
              </table>
              {flows.length === 0 && <p className="p-6 text-center text-sm text-slate-400">{t('traffic.none')}</p>}
            </div>
            <p className="text-[11px] text-slate-400 px-3 py-2 border-t border-slate-100">{t('traffic.counts', { shown: Math.min(flows.length, 200), total: last.flows.length })} · {new Date(last.at).toLocaleTimeString()}</p>
          </section>
        </div>
      )}
    </div>
  )
}

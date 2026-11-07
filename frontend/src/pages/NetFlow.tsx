import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Waves, ClipboardCopy, ShieldAlert } from 'lucide-react'
import { netflowApi, NetflowSettings } from '../lib/api'
import { AnomalyBandChart } from '../components/AnomalyParts'
import { cn } from '../lib/utils'

// NetFlow / IPFIX from the routers (services/netflow.py): the collector's state and how to set a router up, the busiest hosts of the
// last 10 minutes with their learned traffic range, the conversations, and what the network detectors raised. Stage 2 of the ML work.

type Target = 'ros7' | 'ros6' | 'firewall'

export function netflowSnippet(target: Target, agentIp: string, port: number): string {
  const ip = agentIp || '<ADRES-AGENTA>'
  if (target === 'ros7') {
    return [
      `/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m inactive-flow-timeout=15s`,
      `/ip traffic-flow target add dst-address=${ip} port=${port} version=ipfix`,
    ].join('\n')
  }
  if (target === 'ros6') {
    return [
      `/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m inactive-flow-timeout=15s`,
      `/ip traffic-flow target add address=${ip}:${port} version=9`,
    ].join('\n')
  }
  return [
    `# on the computer of the agent (PowerShell as administrator): let the routers' flows in`,
    `New-NetFirewallRule -DisplayName "MikroManager NetFlow" -Direction Inbound -Protocol UDP -LocalPort ${port} -Action Allow -RemoteAddress <ADRESY-ROUTEROW>`,
  ].join('\n')
}

const mb = (b: number) => b >= 1e9 ? `${(b / 1e9).toFixed(2)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.round(b / 1e3)} kB`
const PROTO: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP' }

function Settings({ s }: { s: NetflowSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [f, setF] = useState({ ...s, nets: s.local_nets.join('\n') })
  useEffect(() => setF({ ...s, nets: s.local_nets.join('\n') }), [s])
  const save = useMutation({
    mutationFn: () => netflowApi.save({ port: f.port, accept_unknown: f.accept_unknown, local_nets: f.nets.split(/[\s,]+/).filter(Boolean), scan_ports: f.scan_ports,
      scan_hosts: f.scan_hosts, lateral_hosts: f.lateral_hosts, beacon: f.beacon, external_scans: f.external_scans, max_hosts: f.max_hosts }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['netflow'] }),
  })
  const num = (k: 'port' | 'scan_ports' | 'scan_hosts' | 'lateral_hosts' | 'max_hosts') => (
    <label className="text-xs text-slate-600 space-y-1 block">{t(`netflow.set.${k}`)}
      <input type="number" value={f[k]} onChange={e => setF(x => ({ ...x, [k]: parseInt(e.target.value) || 0 }))} className="w-full border border-slate-300 rounded px-2 py-1 bg-white" />
    </label>
  )
  const chk = (k: 'accept_unknown' | 'beacon' | 'external_scans') => (
    <label className="flex items-center gap-2 text-xs text-slate-700"><input type="checkbox" checked={f[k]} onChange={e => setF(x => ({ ...x, [k]: e.target.checked }))} /> {t(`netflow.set.${k}`)}</label>
  )
  return (
    <details className="bg-white border border-slate-200 rounded-xl p-3 text-sm">
      <summary className="cursor-pointer font-semibold text-slate-700">{t('netflow.set.title')}</summary>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-3">{num('port')}{num('scan_ports')}{num('scan_hosts')}{num('lateral_hosts')}{num('max_hosts')}</div>
      <div className="grid md:grid-cols-2 gap-3 mt-3">
        <label className="text-xs text-slate-600 space-y-1 block">{t('netflow.set.local_nets')}
          <textarea rows={4} value={f.nets} onChange={e => setF(x => ({ ...x, nets: e.target.value }))} className="w-full border border-slate-300 rounded px-2 py-1 font-mono bg-white" />
        </label>
        <div className="space-y-2 pt-5">{chk('beacon')}{chk('external_scans')}{chk('accept_unknown')}</div>
      </div>
      {save.isError && <p className="text-xs text-red-600 mt-2">{String((save.error as any)?.response?.data?.detail ?? save.error)}</p>}
      <button onClick={() => save.mutate()} disabled={save.isPending} className="mt-3 text-xs px-3 py-1.5 rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('common.save')}</button>
    </details>
  )
}

export function NetFlow() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['netflow'], queryFn: netflowApi.status, refetchInterval: 20_000 })
  const enable = useMutation({ mutationFn: (on: boolean) => netflowApi.save({ enabled: on }), onSuccess: () => qc.invalidateQueries({ queryKey: ['netflow'] }) })
  const [target, setTarget] = useState<Target>('ros7')
  const [picked, setPicked] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const d = q.data
  if (!d) return <div className="p-6 text-sm text-slate-500">{t('common.loading')}</div>
  const text = netflowSnippet(target, d.agent_ip ?? '', d.settings.port)
  const copy = async () => { try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* selectable anyway */ } }
  const w = d.window

  return (
    <div className="p-6 space-y-4 max-w-[1100px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Waves size={20} className="text-indigo-600" /> {t('netflow.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('netflow.subtitle')}</p>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-3 flex items-center gap-3 flex-wrap text-sm">
        <span className={cn('inline-block w-2.5 h-2.5 rounded-full', d.listening ? 'bg-emerald-500' : d.settings.enabled ? 'bg-red-500' : 'bg-slate-300')} />
        <span className="font-medium text-slate-800">
          {d.listening ? t('netflow.listening', { port: d.settings.port }) : d.settings.enabled ? t('netflow.notListening') : t('netflow.off')}
        </span>
        {d.error && <span className="text-xs text-red-600">{d.error}</span>}
        {d.listening && <span className="text-xs text-slate-500">{t('netflow.counts', { flows: d.stats.flows.toLocaleString(), packets: d.stats.packets.toLocaleString(), hosts: d.tracked })}</span>}
        <button onClick={() => enable.mutate(!d.settings.enabled)} disabled={enable.isPending}
          className={cn('ml-auto text-xs px-3 py-1.5 rounded-lg', d.settings.enabled ? 'border border-slate-300 text-slate-700 hover:bg-slate-50' : 'bg-indigo-600 text-white hover:bg-indigo-700')}>
          {d.settings.enabled ? t('netflow.disable') : t('netflow.enable')}
        </button>
      </div>
      <p className="text-xs text-slate-500">
        {d.wazuh.configured ? t('netflow.wazuhOn', { agents: d.wazuh.agents }) : t('netflow.wazuhOff')}
        {d.wazuh.error && <span className="text-red-600"> · {d.wazuh.error}</span>}
      </p>

      <section className="bg-white border border-slate-200 rounded-xl p-3 space-y-2 text-sm">
        <h2 className="font-semibold text-slate-700">{t('netflow.setupTitle')}</h2>
        <p className="text-xs text-slate-500">{t('netflow.setupIntro')}</p>
        <div className="flex gap-1.5 flex-wrap">
          {(['ros7', 'ros6', 'firewall'] as Target[]).map(x => (
            <button key={x} onClick={() => setTarget(x)} className={cn('px-3 py-1.5 text-xs rounded-md border', target === x ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50')}>{t(`netflow.target.${x}`)}</button>
          ))}
          <button onClick={copy} className="ml-auto flex items-center gap-1 text-xs border border-slate-300 rounded-md px-2.5 py-1.5 hover:bg-slate-50"><ClipboardCopy size={12} /> {copied ? t('netflow.copied') : t('netflow.copy')}</button>
        </div>
        <pre className="bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-x-auto whitespace-pre">{text}</pre>
        <p className="text-[11px] text-slate-400">{t('netflow.setupNote')}</p>
        {(d.exporters.length > 0 || d.unknown.length > 0) && (
          <div className="text-xs space-y-1">
            {d.exporters.map(e => <div key={e.ip} className="text-slate-600"><span className="font-medium text-slate-800">{e.name}</span> <span className="font-mono">{e.ip}</span> · {e.version === 10 ? 'IPFIX' : `NetFlow v${e.version}`} · {t('netflow.flowsN', { n: e.flows.toLocaleString() })}{e.last ? ` · ${new Date(e.last).toLocaleTimeString()}` : ''}</div>)}
            {d.unknown.length > 0 && <div className="text-amber-700">{t('netflow.unknown')}: {d.unknown.map(u => `${u.ip} (${u.n})`).join(', ')}</div>}
          </div>
        )}
      </section>

      <Settings s={d.settings} />

      <section className="bg-white border border-slate-200 rounded-xl p-3 space-y-2">
        <div className="flex items-center gap-2"><ShieldAlert size={15} className="text-indigo-500" /><h2 className="text-sm font-semibold text-slate-700">{t('netflow.detTitle')}</h2>
          <span className="text-xs text-slate-500">{t('netflow.det24', { n: d.detections_24h })}</span>
          <Link to="/soc" className="ml-auto text-xs text-indigo-600 hover:underline">{t('netflow.toSoc')}</Link></div>
        <p className="text-xs text-slate-500">{t('netflow.detIntro', { ports: d.settings.scan_ports, hosts: d.settings.scan_hosts, lateral: d.settings.lateral_hosts })}</p>
        {d.detections.length === 0 ? <p className="text-xs text-slate-400">{t('netflow.noDet')}</p> : (
          <ul className="text-xs divide-y divide-slate-100">
            {d.detections.slice(0, 30).map((x, i) => (
              <li key={i} className="py-1.5 flex gap-2 items-start">
                <span className={cn('rounded px-1.5 py-0.5 font-semibold shrink-0', x.severity === 'high' ? 'bg-red-100 text-red-700' : x.severity === 'medium' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600')}>{t(`netflow.rule.${x.rule.replace('net.', '')}`)}</span>
                <span className="text-slate-700 flex-1">{x.message}</span>
                <span className="font-mono text-slate-400 shrink-0">{x.mitre}</span>
                <span className="text-slate-400 shrink-0">{new Date(x.at).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="bg-white border border-slate-200 rounded-xl p-3 space-y-2">
        <h2 className="text-sm font-semibold text-slate-700">{t('netflow.topTitle')}{w ? ` · ${new Date(w.start).toLocaleTimeString()}` : ''}</h2>
        <p className="text-xs text-slate-500">{t('netflow.topIntro')}</p>
        {!w ? <p className="text-xs text-slate-400">{t('netflow.noWindow')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-slate-400 border-b border-slate-200">
                <th className="font-medium px-2 py-1.5">{t('netflow.col.host')}</th><th className="font-medium px-2 py-1.5 text-right">{t('netflow.col.out')}</th>
                <th className="font-medium px-2 py-1.5 text-right">{t('netflow.col.in')}</th><th className="font-medium px-2 py-1.5 text-right">{t('netflow.col.peers')}</th>
                <th className="font-medium px-2 py-1.5 text-right">{t('netflow.col.ports')}</th><th className="font-medium px-2 py-1.5 text-right">{t('netflow.col.unanswered')}</th>
              </tr></thead>
              <tbody>
                {w.top.map(h => (
                  <tr key={h.ip} onClick={() => setPicked(p => p === h.ip ? null : h.ip)} className={cn('border-t border-slate-100 cursor-pointer hover:bg-slate-50', picked === h.ip && 'bg-indigo-50')}>
                    <td className="px-2 py-1.5"><span className="font-medium text-slate-800">{h.name || h.ip}</span>{h.name && <span className="font-mono text-slate-400 ml-1.5">{h.ip}</span>}</td>
                    <td className="px-2 py-1.5 text-right font-mono">{mb(h.out)}</td><td className="px-2 py-1.5 text-right font-mono">{mb(h.in)}</td>
                    <td className="px-2 py-1.5 text-right font-mono">{h.peers}</td><td className="px-2 py-1.5 text-right font-mono">{h.ports}</td>
                    <td className={cn('px-2 py-1.5 text-right font-mono', h.unanswered > 20 && 'text-red-600 font-semibold')}>{h.unanswered}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {picked && (
          <div className="grid md:grid-cols-2 gap-3 pt-2">
            <AnomalyBandChart seriesKey={`net:${picked}:out_mb`} />
            <AnomalyBandChart seriesKey={`net:${picked}:peers`} />
          </div>
        )}
      </section>

      {w && w.conv.length > 0 && (
        <section className="bg-white border border-slate-200 rounded-xl p-3 space-y-2">
          <h2 className="text-sm font-semibold text-slate-700">{t('netflow.convTitle')}</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-slate-400 border-b border-slate-200">
                <th className="font-medium px-2 py-1.5">{t('netflow.col.src')}</th><th className="font-medium px-2 py-1.5">{t('netflow.col.dst')}</th>
                <th className="font-medium px-2 py-1.5">{t('netflow.col.proto')}</th><th className="font-medium px-2 py-1.5 text-right">{t('netflow.col.bytes')}</th>
              </tr></thead>
              <tbody>
                {w.conv.map((c, i) => (
                  <tr key={i} className="border-t border-slate-100">
                    <td className="px-2 py-1.5 font-mono">{c.src_name ? `${c.src_name} ` : ''}<span className="text-slate-500">{c.src}</span></td>
                    <td className="px-2 py-1.5 font-mono">{c.dst_name ? `${c.dst_name} ` : ''}<span className="text-slate-500">{c.dst}</span></td>
                    <td className="px-2 py-1.5">{PROTO[c.proto] ?? c.proto}{c.dport ? ` / ${c.dport}` : ''}</td>
                    <td className="px-2 py-1.5 text-right font-mono">{mb(c.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}

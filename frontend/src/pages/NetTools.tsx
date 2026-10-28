import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Wrench } from 'lucide-react'
import { netkitApi, type NetkitHost } from '../lib/api'
import { cn } from '../lib/utils'

const TABS = ['wol', 'snmp', 'rdap', 'path'] as const
type Tab = typeof TABS[number]
const errText = (e: unknown) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? ''
const input = 'border border-slate-300 rounded-md px-2 py-1 text-sm bg-white'
const btn = 'px-3 py-1.5 rounded-md bg-indigo-600 text-white text-sm disabled:opacity-40'

function Wol({ hosts }: { hosts: NetkitHost[] }) {
  const { t } = useTranslation()
  const [mac, setMac] = useState('')
  const m = useMutation({ mutationFn: () => netkitApi.wol(mac.trim()) })
  const withMac = hosts.filter(h => h.mac)
  return (
    <div className="space-y-3 text-sm">
      <p className="text-slate-500">{t('nettools.wol.intro')}</p>
      <div className="flex flex-wrap gap-2 items-center">
        <select className={input} value="" onChange={e => setMac(e.target.value)}>
          <option value="">{t('nettools.pickHost')}</option>
          {withMac.map(h => <option key={h.ip} value={h.mac!}>{h.name} · {h.mac}</option>)}
        </select>
        <input className={cn(input, 'w-44')} placeholder="aa:bb:cc:dd:ee:ff" value={mac} onChange={e => setMac(e.target.value)} />
        <button className={btn} disabled={!mac.trim() || m.isPending} onClick={() => m.mutate()}>{t('nettools.wol.send')}</button>
      </div>
      {m.isError && <p className="text-red-600">{errText(m.error)}</p>}
      {m.data && <p className="text-green-700">{t('nettools.wol.sent', { mac: m.data.mac, to: m.data.sent_to.join(', ') })}</p>}
      <p className="text-xs text-slate-400">{t('nettools.wol.note')}</p>
    </div>
  )
}

function Snmp({ hosts }: { hosts: NetkitHost[] }) {
  const { t } = useTranslation()
  const [ip, setIp] = useState('')
  const [oid, setOid] = useState('1.3.6.1.2.1.1')
  const [op, setOp] = useState<'get' | 'walk'>('walk')
  const [community, setCommunity] = useState('')
  const m = useMutation({ mutationFn: () => netkitApi.snmp({ ip: ip.trim(), op, oid: oid.trim(), community: community || undefined }) })
  const stored = hosts.find(h => h.ip === ip.trim())?.snmp
  return (
    <div className="space-y-3 text-sm">
      <p className="text-slate-500">{t('nettools.snmp.intro')}</p>
      <div className="flex flex-wrap gap-2 items-center">
        <select className={input} value={ip} onChange={e => setIp(e.target.value)}>
          <option value="">{t('nettools.pickHost')}</option>
          {hosts.map(h => <option key={h.ip} value={h.ip}>{h.name} · {h.ip}{h.snmp ? ' ✓' : ''}</option>)}
        </select>
        <select className={input} value={op} onChange={e => setOp(e.target.value as 'get' | 'walk')}><option value="walk">WALK</option><option value="get">GET</option></select>
        <input className={cn(input, 'w-64')} value={oid} onChange={e => setOid(e.target.value)} placeholder="1.3.6.1.2.1.1.1.0" />
        <input className={cn(input, 'w-36')} type="password" value={community} onChange={e => setCommunity(e.target.value)} placeholder={(stored ? t('nettools.snmp.stored') : t('nettools.snmp.community')) as string} autoComplete="off" />
        <button className={btn} disabled={!ip || !oid.trim() || m.isPending} onClick={() => m.mutate()}>{t('nettools.run')}</button>
      </div>
      {m.isError && <p className="text-red-600">{errText(m.error)}</p>}
      {m.data && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          {m.data.rows.length === 0 ? <p className="p-3 text-slate-400">{t('nettools.snmp.none')}</p> : m.data.rows.map(r => (
            <div key={r.oid} className="grid grid-cols-[minmax(0,2fr)_minmax(0,3fr)] gap-3 px-3 py-1 border-t first:border-t-0 border-slate-100 text-xs">
              <div className="font-mono text-slate-600 break-all">{r.oid}{r.name && <span className="ml-2 text-indigo-600">{r.name}</span>}</div>
              <div className="text-slate-900 break-words">{r.value}</div>
            </div>
          ))}
          {m.data.truncated && <p className="px-3 py-1 text-xs text-amber-700 border-t border-slate-100">{t('nettools.snmp.cut')}</p>}
        </div>
      )}
    </div>
  )
}

function Rdap() {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const m = useMutation({ mutationFn: () => netkitApi.rdap(q.trim()) })
  const d = m.data
  return (
    <div className="space-y-3 text-sm">
      <p className="text-slate-500">{t('nettools.rdap.intro')}</p>
      <div className="flex gap-2 items-center">
        <input className={cn(input, 'w-72')} value={q} onChange={e => setQ(e.target.value)} placeholder="example.com · 8.8.8.8 · AS15169" onKeyDown={e => { if (e.key === 'Enter' && q.trim()) m.mutate() }} />
        <button className={btn} disabled={!q.trim() || m.isPending} onClick={() => m.mutate()}>{t('nettools.run')}</button>
      </div>
      {m.isError && <p className="text-red-600">{errText(m.error)}</p>}
      {d && (
        <dl className="bg-white border border-slate-200 rounded-xl p-4 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-xs">
          <dt className="text-slate-500">{t('nettools.rdap.name')}</dt><dd className="font-medium">{d.name ?? '—'} {d.handle && <span className="text-slate-400">({d.handle})</span>}</dd>
          {d.range && <><dt className="text-slate-500">{t('nettools.rdap.range')}</dt><dd>{d.range}{d.cidr?.length ? ` · ${d.cidr.join(', ')}` : ''}</dd></>}
          {d.country && <><dt className="text-slate-500">{t('nettools.rdap.country')}</dt><dd>{d.country}</dd></>}
          {d.status.length > 0 && <><dt className="text-slate-500">{t('nettools.rdap.status')}</dt><dd>{d.status.join(', ')}</dd></>}
          {d.nameservers && d.nameservers.length > 0 && <><dt className="text-slate-500">{t('nettools.rdap.ns')}</dt><dd>{d.nameservers.join(', ')}</dd></>}
          {d.events.length > 0 && <><dt className="text-slate-500">{t('nettools.rdap.events')}</dt><dd>{d.events.map(e => `${e.action}: ${e.date ? new Date(e.date).toLocaleDateString() : '—'}`).join(' · ')}</dd></>}
          {d.entities.length > 0 && <><dt className="text-slate-500">{t('nettools.rdap.entities')}</dt><dd>{d.entities.map(e => `${e.name ?? e.handle ?? '?'} (${e.roles.join('/')})`).join(' · ')}</dd></>}
        </dl>
      )}
      <p className="text-xs text-slate-400">{t('nettools.rdap.note')}</p>
    </div>
  )
}

function Path() {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const m = useMutation({ mutationFn: () => netkitApi.path(q.trim()) })
  const hops = m.data?.hops ?? []
  const max = Math.max(1, ...hops.map(h => h.ms ?? 0))
  return (
    <div className="space-y-3 text-sm">
      <p className="text-slate-500">{t('nettools.path.intro')}</p>
      <div className="flex gap-2 items-center">
        <input className={cn(input, 'w-64')} value={q} onChange={e => setQ(e.target.value)} placeholder="8.8.8.8 · example.com" onKeyDown={e => { if (e.key === 'Enter' && q.trim()) m.mutate() }} />
        <button className={btn} disabled={!q.trim() || m.isPending} onClick={() => m.mutate()}>{m.isPending ? t('nettools.path.running') : t('nettools.run')}</button>
      </div>
      {m.isError && <p className="text-red-600">{errText(m.error)}</p>}
      {m.data?.error && <p className="text-amber-800">{m.data.error}</p>}
      {m.data && hops.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <p className="text-xs text-slate-500 mb-2">{m.data.target}{m.data.target !== m.data.ip ? ` (${m.data.ip})` : ''} · {m.data.reached ? t('nettools.path.reached') : t('nettools.path.notReached')}</p>
          <ol className="space-y-1">
            {hops.map(h => (
              <li key={h.n} className="grid grid-cols-[1.5rem_minmax(0,1.4fr)_minmax(0,3fr)_9rem] gap-2 items-center text-xs">
                <span className="text-slate-400 tabular-nums">{h.n}</span>
                <span className="min-w-0 truncate">{h.ip ? <><b className="font-medium text-slate-900">{h.name ?? h.ip}</b>{h.name && <span className="text-slate-400"> {h.ip}</span>}</> : <span className="text-slate-300">* * *</span>}</span>
                <span className="h-3 bg-slate-100 rounded relative overflow-hidden">
                  {h.ms != null && <span className={cn('absolute inset-y-0 left-0 rounded', h.delta != null && h.delta > 40 ? 'bg-amber-400' : h.scope === 'public' ? 'bg-indigo-400' : 'bg-emerald-400')} style={{ width: `${Math.max(2, (h.ms / max) * 100)}%` }} />}
                </span>
                <span className="tabular-nums text-slate-600 text-right">{h.ms != null ? `${h.ms} ms` : '—'}{h.delta != null && h.delta > 0 && h.n > 1 ? <span className="text-slate-400"> (+{h.delta})</span> : null}</span>
              </li>
            ))}
          </ol>
          <p className="text-[11px] text-slate-400 mt-2">{t('nettools.path.legend')}</p>
        </div>
      )}
    </div>
  )
}

// The small tools of a network administrator in one place: Wake on LAN, an SNMP browser, RDAP lookups and the path to a host.
export function NetTools() {
  const { t } = useTranslation()
  const [tab, setTab] = useState<Tab>('wol')
  const hosts = useQuery({ queryKey: ['netkit-hosts'], queryFn: netkitApi.hosts })
  const list = hosts.data ?? []
  return (
    <div className="p-6 space-y-4 max-w-[1000px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Wrench size={20} className="text-indigo-600" /> {t('nettools.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('nettools.subtitle')}</p>
      </div>
      <div className="flex gap-1 border-b border-slate-200">
        {TABS.map(k => (
          <button key={k} onClick={() => setTab(k)} className={cn('px-4 py-2 text-sm -mb-px border-b-2', tab === k ? 'border-indigo-600 text-indigo-700 font-medium' : 'border-transparent text-slate-500 hover:text-slate-800')}>{t(`nettools.tab.${k}`)}</button>
        ))}
      </div>
      {tab === 'wol' && <Wol hosts={list} />}
      {tab === 'snmp' && <Snmp hosts={list} />}
      {tab === 'rdap' && <Rdap />}
      {tab === 'path' && <Path />}
    </div>
  )
}

import { useEffect, useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Copy, Check, Cable, Server, Share2, ArrowLeft, RefreshCw, Search } from 'lucide-react'
import { onsiteApi, onsiteKey, type OnsiteHost, type OnsiteMapState } from '../lib/api'
import { SUPPORTED_LANGS } from '../i18n'
import { TypeIcon, AttachCell, ago } from '../components/AssetBits'
import { Button } from '../components/ui/Button'
import { cn } from '../lib/utils'

// The view for the person standing next to the equipment: what is connected where. Standalone (no menu of the application), read-only, opened by a
// logged-in user or by a link with a key that the administrator creates under "Udostępnij". Phone-friendly: rows stack on a narrow screen.

function CopyText({ text, className, children }: { text: string; className?: string; children?: React.ReactNode }) {
  const { t } = useTranslation()
  const [done, setDone] = useState(false)
  return (
    <button type="button" title={t('onsite.copy') as string} className={cn('inline-flex items-center gap-1 hover:text-indigo-600', className)}
      onClick={() => { void navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200) }).catch(() => undefined) }}>
      {children ?? text}{done ? <Check size={12} className="text-emerald-600" /> : <Copy size={11} className="text-slate-300" />}
    </button>
  )
}

function MapNote({ map }: { map?: OnsiteMapState }) {
  const { t } = useTranslation()
  if (!map) return null
  return (
    <p className="text-xs text-slate-500">
      {map.at ? t('onsite.mapAsOf', { when: ago(map.at) }) : t('onsite.mapNone')}{map.building ? ` · ${t('onsite.mapBuilding')}` : ''} · {t('onsite.mapHint')}
    </p>
  )
}

function ShareBox() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const share = useQuery({ queryKey: ['onsite-share'], queryFn: onsiteApi.shareGet, retry: false })
  const set = useMutation({ mutationFn: onsiteApi.shareSet, onSuccess: d => qc.setQueryData(['onsite-share'], d) })
  const [open, setOpen] = useState(false)
  if (!share.data?.admin) return null
  const link = share.data.key ? `${window.location.origin}/onsite#k=${share.data.key}` : ''
  return (
    <div className="bg-white border border-slate-200 rounded-xl">
      <button className="w-full flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-slate-800" onClick={() => setOpen(!open)}>
        <Share2 size={15} className="text-indigo-600" /> {t('onsite.share.title')}
        <span className={cn('ml-2 text-xs px-2 py-0.5 rounded-full', share.data.enabled ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-500')}>{share.data.enabled ? t('onsite.share.on') : t('onsite.share.off')}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 text-sm border-t border-slate-100 pt-3">
          <p className="text-slate-600">{t('onsite.share.intro')}</p>
          <div className="flex gap-2 flex-wrap">
            {share.data.enabled
              ? <Button size="sm" variant="secondary" disabled={set.isPending} onClick={() => set.mutate({ enabled: false })}>{t('onsite.share.disable')}</Button>
              : <Button size="sm" variant="primary" disabled={set.isPending} onClick={() => set.mutate({ enabled: true })}>{t('onsite.share.enable')}</Button>}
            {share.data.enabled && <Button size="sm" variant="secondary" disabled={set.isPending} onClick={() => { if (confirm(t('onsite.share.regenerateConfirm') as string)) set.mutate({ regenerate: true }) }}><RefreshCw size={13} /> {t('onsite.share.regenerate')}</Button>}
          </div>
          {link && (
            <div className="space-y-1">
              <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 font-mono text-xs break-all"><CopyText text={link} className="text-left">{link}</CopyText></div>
              <p className="text-xs text-amber-700">{t('onsite.share.warning')}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Devices({ hosts, map }: { hosts: OnsiteHost[]; map?: OnsiteMapState }) {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const [sw, setSw] = useState('')
  const [type, setType] = useState('')
  const [all, setAll] = useState(false)
  const switches = useMemo(() => [...new Set(hosts.map(h => h.attach?.to).filter((x): x is string => !!x))].sort(), [hosts])
  const types = useMemo(() => [...new Set(hosts.map(h => h.type))].sort(), [hosts])
  const needle = q.trim().toLowerCase()
  const rows = useMemo(() => hosts.filter(h =>
    (all || h.active) && (!sw || h.attach?.to === sw) && (!type || h.type === type)
    && (!needle || [h.name, h.ip, h.mac, h.place, h.location, h.manufacturer, h.model, h.attach?.to, h.attach?.port].some(v => (v ?? '').toLowerCase().includes(needle)))
  ).sort((a, b) => (a.attach?.to ?? '~').localeCompare(b.attach?.to ?? '~') || a.name.localeCompare(b.name)), [hosts, needle, sw, type, all])
  const sel = 'border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white'
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[14rem] max-w-md">
          <Search size={14} className="absolute left-3 top-2.5 text-slate-400" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('onsite.search') as string} autoFocus className="w-full border border-slate-300 rounded-lg pl-9 pr-3 py-1.5 text-sm bg-white" />
        </div>
        <select value={sw} onChange={e => setSw(e.target.value)} className={sel}><option value="">{t('onsite.allSwitches')}</option>{switches.map(s => <option key={s} value={s}>{s}</option>)}</select>
        <select value={type} onChange={e => setType(e.target.value)} className={sel}><option value="">{t('onsite.allTypes')}</option>{types.map(x => <option key={x} value={x}>{t(`assets.type.${x}`, { defaultValue: x })}</option>)}</select>
        <label className="text-xs text-slate-600 inline-flex items-center gap-1.5"><input type="checkbox" checked={all} onChange={e => setAll(e.target.checked)} />{t('onsite.showInactive')}</label>
        <span className="text-xs text-slate-400 ml-auto">{t('onsite.count', { count: rows.length })}</span>
      </div>
      <MapNote map={map} />
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
        <div className="hidden md:grid grid-cols-[minmax(0,1.6fr),7.5rem,9.5rem,minmax(0,1.8fr),minmax(0,1.4fr),5.5rem] bg-slate-50 text-xs text-slate-500 px-4 py-2 gap-x-3">
          <div>{t('onsite.col.name')}</div><div>{t('onsite.col.ip')}</div><div>{t('onsite.col.mac')}</div><div>{t('onsite.col.attached')}</div><div>{t('onsite.col.place')}</div><div>{t('onsite.col.seen')}</div>
        </div>
        {rows.length === 0 && <p className="p-6 text-center text-slate-400">{t('onsite.none')}</p>}
        {rows.map(h => (
          <div key={h.id} className={cn('grid md:grid-cols-[minmax(0,1.6fr),7.5rem,9.5rem,minmax(0,1.8fr),minmax(0,1.4fr),5.5rem] gap-x-3 gap-y-0.5 px-4 py-2.5 border-t border-slate-100 items-center', !h.active && 'opacity-60')}>
            <div className="flex items-center gap-2 min-w-0">
              <TypeIcon type={h.type} size={16} />
              <div className="min-w-0"><div className="font-medium text-slate-900 truncate">{h.name}</div>{(h.manufacturer || h.model) && <div className="text-[11px] text-slate-400 truncate">{[h.manufacturer, h.model].filter(Boolean).join(' · ')}</div>}</div>
            </div>
            <div className="font-mono text-xs text-slate-700">{h.ip ? <CopyText text={h.ip} /> : '—'}</div>
            <div className="font-mono text-[11px] text-slate-500">{h.mac ? <CopyText text={h.mac} /> : '—'}</div>
            <div><AttachCell at={h.attach} />{h.attach && !h.attach.port && <div className="text-[10px] text-slate-400">{t('onsite.noPort')}</div>}</div>
            <div className="text-xs text-slate-700 break-words">{h.place ?? <span className="text-slate-300">—</span>}{h.location && <div className="text-[11px] text-slate-400">{h.location}</div>}</div>
            <div className="text-xs text-slate-500 whitespace-nowrap">{ago(h.last_seen_at)}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function Switches() {
  const { t } = useTranslation()
  const list = useQuery({ queryKey: ['onsite-switches'], queryFn: onsiteApi.switches, refetchInterval: 120_000 })
  const [pick, setPick] = useState<number | null>(null)
  const [q, setQ] = useState('')
  useEffect(() => { if (pick == null && list.data?.items.length) setPick(list.data.items[0].id) }, [list.data, pick])
  const ports = useQuery({ queryKey: ['onsite-switch', pick], queryFn: () => onsiteApi.switchPorts(pick!), enabled: pick != null })
  const needle = q.trim().toLowerCase()
  const rows = (ports.data?.ports ?? []).filter(p => !needle || p.port.toLowerCase().includes(needle) || p.devices.some(d => [d.name, d.ip, d.mac, d.place].some(v => (v ?? '').toLowerCase().includes(needle))))
  if (list.isLoading) return <p className="text-sm text-slate-500">{t('common.loading')}</p>
  if (!list.data?.items.length) return <div className="space-y-2"><MapNote map={list.data?.map} /><p className="text-sm text-slate-500">{t('onsite.switchesNone')}</p></div>
  return (
    <div className="space-y-3">
      <div className="flex gap-2 flex-wrap items-center">
        {list.data.items.map(s => (
          <button key={s.id} onClick={() => setPick(s.id)} className={cn('text-left border rounded-xl px-3 py-2 bg-white min-w-[10rem]', pick === s.id ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-200 hover:bg-slate-50')}>
            <div className="flex items-center gap-1.5 font-medium text-slate-900 text-sm"><Server size={13} className="text-emerald-600" />{s.name}</div>
            <div className="text-[11px] text-slate-500">{s.ip ?? ''} · {t('onsite.switchStats', { ports: s.ports, hosts: s.hosts })}</div>
            {s.place && <div className="text-[11px] text-slate-400">{s.place}</div>}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search size={14} className="absolute left-3 top-2.5 text-slate-400" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('onsite.searchPort') as string} className="w-full border border-slate-300 rounded-lg pl-9 pr-3 py-1.5 text-sm bg-white" />
        </div>
      </div>
      <MapNote map={ports.data?.map ?? list.data.map} />
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
        <div className="hidden md:grid grid-cols-[7rem,5rem,minmax(0,1fr)] bg-slate-50 text-xs text-slate-500 px-4 py-2 gap-x-3"><div>{t('onsite.col.port')}</div><div>VLAN</div><div>{t('onsite.col.devices')}</div></div>
        {rows.length === 0 && <p className="p-6 text-center text-slate-400">{t('onsite.none')}</p>}
        {rows.map(p => (
          <div key={p.port} className="grid md:grid-cols-[7rem,5rem,minmax(0,1fr)] gap-x-3 px-4 py-2.5 border-t border-slate-100 items-start">
            <div className="font-semibold text-slate-900 inline-flex items-center gap-1.5"><Cable size={13} className="text-slate-400" />{p.port}</div>
            <div className="text-slate-500 text-xs pt-0.5">{p.vlan ?? ''}</div>
            <div className="space-y-1.5 min-w-0">
              {p.devices.map(d => (
                <div key={d.id} className="flex items-center gap-2 flex-wrap">
                  <TypeIcon type={d.type} size={14} /><span className="font-medium text-slate-900">{d.name}</span>
                  <span className="font-mono text-xs text-slate-600">{d.ip ? <CopyText text={d.ip} /> : null}</span>
                  <span className="font-mono text-[11px] text-slate-400">{d.mac ? <CopyText text={d.mac} /> : null}</span>
                  {d.place && <span className="text-xs text-slate-600">· {d.place}</span>}
                </div>
              ))}
              {p.devices.length > 1 && <div className="text-[11px] text-amber-700">{t('onsite.manyOnPort', { count: p.devices.length })}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export function OnSite() {
  const { t, i18n } = useTranslation()
  const [tab, setTab] = useState<'devices' | 'switches'>('devices')
  useMemo(() => { onsiteKey.takeFromHash() }, [])             // before the first request: the key of a shared link has to be in place
  const hosts = useQuery({ queryKey: ['onsite-hosts'], queryFn: () => onsiteApi.hosts(true), refetchInterval: 120_000, retry: false })
  const session = useQuery({ queryKey: ['onsite-share'], queryFn: onsiteApi.shareGet, retry: false })
  const denied = hosts.isError
  const status = (hosts.error as { response?: { status?: number } } | null)?.response?.status
  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-[1400px] mx-auto px-4 py-3 flex items-center gap-3 flex-wrap">
          <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center"><Cable size={16} className="text-white" /></div>
          <div className="min-w-0"><h1 className="text-base font-bold text-slate-900 leading-tight">{t('onsite.title')}</h1><p className="text-xs text-slate-500">{t('onsite.subtitle')}</p></div>
          <div className="ml-auto flex items-center gap-3">
            <select value={i18n.language?.slice(0, 2)} onChange={e => { void i18n.changeLanguage(e.target.value) }} className="border border-slate-300 rounded-lg px-2 py-1 text-xs bg-white" aria-label="language">
              {SUPPORTED_LANGS.map(l => <option key={l.code} value={l.code}>{l.flag} {l.name}</option>)}
            </select>
            {session.data && <Link to="/inventory/list" className="text-xs text-indigo-600 hover:underline inline-flex items-center gap-1"><ArrowLeft size={12} />{t('onsite.back')}</Link>}
          </div>
        </div>
      </header>
      <main className="max-w-[1400px] mx-auto px-4 py-4 space-y-4">
        {denied && <div className="text-sm bg-amber-50 border border-amber-200 text-amber-900 rounded-lg px-4 py-3">{status === 429 ? t('onsite.tooMany') : t('onsite.noAccess')}</div>}
        {!denied && (
          <>
            <ShareBox />
            <div className="flex gap-1 border-b border-slate-200">
              {(['devices', 'switches'] as const).map(k => (
                <button key={k} onClick={() => setTab(k)} className={cn('px-4 py-2 text-sm -mb-px border-b-2', tab === k ? 'border-indigo-600 text-indigo-700 font-medium' : 'border-transparent text-slate-600 hover:text-slate-900')}>{t(`onsite.tab.${k}`)}</button>
              ))}
            </div>
            {hosts.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : tab === 'devices' ? <Devices hosts={hosts.data?.items ?? []} map={hosts.data?.map} /> : <Switches />}
          </>
        )}
      </main>
    </div>
  )
}

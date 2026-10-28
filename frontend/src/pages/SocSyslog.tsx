import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Radio, Plus, Trash2 } from 'lucide-react'
import { syslogApi, SyslogRule } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'
import { HostLink } from '../components/HostLink'

const SEV_STYLE = ['bg-red-100 text-red-800', 'bg-red-100 text-red-800', 'bg-red-50 text-red-700', 'bg-orange-50 text-orange-700', 'bg-amber-50 text-amber-700',
                   'bg-sky-50 text-sky-700', 'bg-slate-100 text-slate-600', 'bg-slate-50 text-slate-400']

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

function Settings() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const st = useQuery({ queryKey: ['syslog-status'], queryFn: syslogApi.status, refetchInterval: 10000 })
  const s = st.data?.settings
  const [form, setForm] = useState({ enabled: false, syslog_port: 514, trap_port: 162, accept_unknown: false, store_info: false, communities: '' })
  const [dirty, setDirty] = useState(false)
  useEffect(() => { if (s && !dirty) setForm({ enabled: s.enabled, syslog_port: s.syslog_port, trap_port: s.trap_port, accept_unknown: s.accept_unknown, store_info: s.store_info, communities: '' }) }, [s, dirty])
  const save = useMutation({
    mutationFn: () => syslogApi.save({ enabled: form.enabled, syslog_port: Number(form.syslog_port), trap_port: Number(form.trap_port), accept_unknown: form.accept_unknown, store_info: form.store_info,
                                       ...(form.communities.trim() ? { communities: form.communities.split(',').map(x => x.trim()).filter(Boolean) } : {}) }),
    onSuccess: () => { setDirty(false); void qc.invalidateQueries({ queryKey: ['syslog-status'] }) },
  })
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => { setForm(f => ({ ...f, [k]: v })); setDirty(true) }
  const d = st.data
  const host = window.location.hostname
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <div className="flex items-center gap-3 flex-wrap">
        <h2 className="font-semibold text-slate-900">{t('syslog.settings.title')}</h2>
        {d && (['syslog', 'trap'] as const).map(k => (
          <span key={k} className={cn('text-xs border rounded-full px-2 py-0.5', d.listening[k] ? 'bg-green-50 text-green-700 border-green-200' : 'bg-slate-50 text-slate-500 border-slate-200')}>
            {k === 'syslog' ? 'syslog' : 'trap'}: {d.listening[k] ? `${t('syslog.status.listening')} · ${t('syslog.status.port', { port: k === 'syslog' ? d.settings.syslog_port : d.settings.trap_port })}` : t('syslog.status.off')}
          </span>
        ))}
      </div>
      {d && (d.errors.syslog || d.errors.trap) && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{d.errors.syslog}{d.errors.syslog && d.errors.trap ? ' · ' : ''}{d.errors.trap}</div>}
      <label className="flex items-center gap-2"><input type="checkbox" checked={form.enabled} onChange={e => set('enabled', e.target.checked)} /> {t('syslog.settings.enabled')}</label>
      <div className="flex gap-4 flex-wrap">
        <label className="text-xs text-slate-500">{t('syslog.settings.syslogPort')}
          <input type="number" value={form.syslog_port} onChange={e => set('syslog_port', Number(e.target.value))} className="block mt-0.5 w-28 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
        <label className="text-xs text-slate-500">{t('syslog.settings.trapPort')}
          <input type="number" value={form.trap_port} onChange={e => set('trap_port', Number(e.target.value))} className="block mt-0.5 w-28 border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
        <label className="text-xs text-slate-500 flex-1 min-w-[16rem]">{t('syslog.settings.communities', { count: s?.communities ?? 0 })}
          <input value={form.communities} placeholder={t('syslog.settings.communitiesPlaceholder') as string} onChange={e => set('communities', e.target.value)}
            className="block mt-0.5 w-full border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900" /></label>
      </div>
      <p className="text-[11px] text-slate-400">{t('syslog.settings.portHint')}</p>
      <label className="flex items-center gap-2"><input type="checkbox" checked={form.accept_unknown} onChange={e => set('accept_unknown', e.target.checked)} /> {t('syslog.settings.acceptUnknown')}</label>
      <label className="flex items-center gap-2"><input type="checkbox" checked={form.store_info} onChange={e => set('store_info', e.target.checked)} /> {t('syslog.settings.storeInfo')}</label>
      <div className="flex items-center gap-3">
        <button disabled={!dirty || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('syslog.settings.save')}</button>
        {save.isSuccess && !dirty && <span className="text-xs text-green-700">{t('syslog.settings.saved')}</span>}
        {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
      </div>
      {d && (
        <div className="text-xs text-slate-500 space-y-0.5 pt-1 border-t border-slate-100">
          <div>{t('syslog.status.counts', { received: d.stats.received, stored: d.stored_24h, traps: d.stats.traps })}</div>
          <div>{t('syslog.status.dropped', { unknown: d.stats.unknown, rate: d.stats.rate_dropped, community: d.stats.bad_community, v3: d.stats.v3, bad: d.stats.bad })}</div>
        </div>
      )}
      <details className="text-xs text-slate-600">
        <summary className="cursor-pointer font-medium text-slate-700">{t('syslog.how.title')}</summary>
        <div className="mt-1 space-y-1">
          <p>{t('syslog.how.intro', { host })}</p>
          <p className="font-mono break-words">{t('syslog.how.mikrotik', { host, port: form.syslog_port })}</p>
          <p className="font-mono break-words">{t('syslog.how.linux', { host, port: form.syslog_port })}</p>
          <p className="font-mono break-words">{t('syslog.how.cisco', { host })}</p>
          <p className="font-mono break-words">{t('syslog.how.snmp', { host, trapPort: form.trap_port })}</p>
        </div>
      </details>
    </div>
  )
}

const blankRule = (): Omit<SyslogRule, 'id'> => ({ name: '', pattern: '', severity: 'medium', source: 'any', threshold: 1, window_sec: 300, enabled: true })

function Rules() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const st = useQuery({ queryKey: ['syslog-status'], queryFn: syslogApi.status })
  const [draft, setDraft] = useState<Omit<SyslogRule, 'id'> | null>(null)
  const rules = st.data?.rules ?? []
  const custom = rules.filter(r => !r.builtin)
  const disabled = rules.filter(r => r.builtin && !r.enabled).map(r => r.id)
  const save = useMutation({
    mutationFn: (body: { rules?: Array<Omit<SyslogRule, 'id'>>; disabled?: string[] }) => syslogApi.save(body),
    onSuccess: () => { setDraft(null); void qc.invalidateQueries({ queryKey: ['syslog-status'] }) },
  })
  const customBody = (list: SyslogRule[]) => list.map(({ id: _id, builtin: _b, ...r }) => r)
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-sm">
      <div className="flex items-center gap-3">
        <h2 className="font-semibold text-slate-900 flex-1">{t('syslog.rules.title')}</h2>
        <button onClick={() => setDraft(blankRule())} className="flex items-center gap-1 text-xs border border-slate-300 rounded-lg px-2.5 py-1 hover:bg-slate-50"><Plus size={12} /> {t('syslog.rules.addCustom')}</button>
      </div>
      <div className="divide-y divide-slate-100">
        {rules.map(r => (
          <div key={r.id} className="flex items-start gap-3 py-1.5">
            <input type="checkbox" className="mt-1" checked={r.enabled}
              onChange={e => r.builtin
                ? save.mutate({ disabled: e.target.checked ? disabled.filter(x => x !== r.id) : [...disabled, r.id] })
                : save.mutate({ rules: customBody(custom.map(c => c.id === r.id ? { ...c, enabled: e.target.checked } : c)) })} />
            <div className="flex-1 min-w-0">
              <div className="text-slate-900">{r.builtin ? t(`syslog.rule.${r.id}.name`, { defaultValue: r.name }) : r.name} <span className="text-[10px] text-slate-400 border border-slate-200 rounded px-1">{r.builtin ? t('syslog.rules.builtin') : t('syslog.rules.custom')}</span>
                <span className="text-[11px] text-slate-400 ml-2">{t(`syslog.sev.${r.severity}`)}{r.window_sec ? ` · ${t('syslog.rules.threshold', { n: r.threshold, sec: r.window_sec })}` : ''}</span></div>
              <div className="text-xs text-slate-500 break-words">{r.builtin ? t(`syslog.rule.${r.id}.desc`, { defaultValue: r.description ?? '' }) : <span className="font-mono">{r.pattern}</span>}</div>
            </div>
            {!r.builtin && <button className="p-1 text-slate-400 hover:text-red-600" title={t('syslog.rules.remove') as string} onClick={() => save.mutate({ rules: customBody(custom.filter(c => c.id !== r.id)) })}><Trash2 size={14} /></button>}
          </div>
        ))}
      </div>
      {draft && (
        <div className="border border-slate-200 rounded-lg p-3 space-y-2 bg-slate-50">
          <div className="flex gap-2 flex-wrap">
            <input placeholder={t('syslog.rules.name') as string} value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} className="border border-slate-300 rounded-lg px-2 py-1 text-sm w-56" />
            <input placeholder={t('syslog.rules.pattern') as string} value={draft.pattern} onChange={e => setDraft({ ...draft, pattern: e.target.value })} className="border border-slate-300 rounded-lg px-2 py-1 text-sm flex-1 min-w-[14rem] font-mono" />
          </div>
          <div className="flex gap-3 flex-wrap items-end text-xs text-slate-500">
            <label>{t('syslog.rules.severity')}<select value={draft.severity} onChange={e => setDraft({ ...draft, severity: e.target.value })} className="block border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900">
              {['low', 'medium', 'high', 'critical'].map(v => <option key={v} value={v}>{t(`syslog.sev.${v}`)}</option>)}</select></label>
            <label>{t('syslog.rules.source')}<select value={draft.source} onChange={e => setDraft({ ...draft, source: e.target.value })} className="block border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900">
              <option value="any">{t('syslog.rules.sourceAny')}</option><option value="syslog">{t('syslog.rules.sourceSyslog')}</option><option value="trap">{t('syslog.rules.sourceTrap')}</option></select></label>
            <label>{t('syslog.rules.thresholdLabel')}<input type="number" min={1} value={draft.threshold} onChange={e => setDraft({ ...draft, threshold: Number(e.target.value) })} className="block border border-slate-300 rounded-lg px-2 py-1 text-sm w-20 text-slate-900" /></label>
            <label>{t('syslog.rules.window')}<input type="number" min={10} value={draft.window_sec} onChange={e => setDraft({ ...draft, window_sec: Number(e.target.value) })} className="block border border-slate-300 rounded-lg px-2 py-1 text-sm w-24 text-slate-900" /></label>
            <button disabled={!draft.name.trim() || !draft.pattern.trim() || save.isPending} onClick={() => save.mutate({ rules: [...customBody(custom), draft] })}
              className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('syslog.settings.save')}</button>
          </div>
        </div>
      )}
      {save.isError && <div className="text-xs text-red-700">{errText(save.error)}</div>}
      <p className="text-[11px] text-slate-400">{t('syslog.rules.hint')}</p>
    </div>
  )
}

function Unknown() {
  const { t } = useTranslation()
  const st = useQuery({ queryKey: ['syslog-status'], queryFn: syslogApi.status })
  const u = st.data?.unknown ?? []
  if (!u.length) return null
  return (
    <div className="bg-amber-50 border border-amber-200 rounded-xl p-3 text-sm space-y-1">
      <div className="font-medium text-amber-900">{t('syslog.unknown.title')}</div>
      <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-amber-900">{u.map(x => <span key={x.ip} className="font-mono">{x.ip} ({x.n})</span>)}</div>
      <div className="text-[11px] text-amber-800">{t('syslog.unknown.hint')}</div>
    </div>
  )
}

function Events() {
  const { t } = useTranslation()
  const ago = useAgo()
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  const [maxSev, setMaxSev] = useState('')
  const ev = useQuery({ queryKey: ['syslog-events', kind, q, maxSev], queryFn: () => syslogApi.events({ kind: kind || undefined, q: q.trim() || undefined, max_severity: maxSev === '' ? undefined : Number(maxSev), limit: 200 }), refetchInterval: 10000 })
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <h2 className="font-semibold text-slate-900 flex-1 text-sm">{t('syslog.events.title')} {ev.data ? <span className="text-xs font-normal text-slate-400">({ev.data.total})</span> : null}</h2>
        <select value={kind} onChange={e => setKind(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1 text-xs bg-white">
          <option value="">{t('syslog.events.allKinds')}</option><option value="syslog">{t('syslog.events.kindSyslog')}</option><option value="trap">{t('syslog.events.kindTrap')}</option></select>
        <select value={maxSev} onChange={e => setMaxSev(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1 text-xs bg-white" title={t('syslog.events.minSeverity') as string}>
          <option value="">{t('syslog.events.minSeverity')}…</option>{[2, 3, 4, 5, 6].map(n => <option key={n} value={n}>{t(`syslog.sev.${n}`)}</option>)}</select>
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('syslog.events.search') as string} className="border border-slate-300 rounded-lg px-2 py-1 text-xs w-48" />
      </div>
      {ev.data && ev.data.items.length === 0 ? <p className="text-sm text-slate-500">{t('syslog.events.none')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-xs">
          <div className="grid grid-cols-[7rem_minmax(0,1.2fr)_5.5rem_minmax(0,1fr)_minmax(0,3fr)] bg-slate-50 text-slate-500 py-1.5">
            <div className="px-2">{t('syslog.events.col.time')}</div><div className="px-2">{t('syslog.events.col.device')}</div><div className="px-2">{t('syslog.events.col.severity')}</div>
            <div className="px-2">{t('syslog.events.col.source')}</div><div className="px-2">{t('syslog.events.col.message')}</div>
          </div>
          {(ev.data?.items ?? []).map(e => (
            <div key={e.id} className="grid grid-cols-[7rem_minmax(0,1.2fr)_5.5rem_minmax(0,1fr)_minmax(0,3fr)] border-t border-slate-100 items-start">
              <div className="px-2 py-1 text-slate-500" title={new Date(e.at).toLocaleString()}>{ago(e.at)}</div>
              <div className="px-2 py-1 min-w-0 truncate"><HostLink ip={e.ip} assetId={e.asset_id} name={e.name}>{e.name ?? e.ip}</HostLink><div className="text-[10px] text-slate-400">{e.ip}</div></div>
              <div className="px-2 py-1"><span className={cn('inline-block rounded px-1.5 py-0.5', SEV_STYLE[e.severity] ?? SEV_STYLE[6])}>{t(`syslog.sev.${e.severity}`)}</span></div>
              <div className="px-2 py-1 text-slate-500 truncate" title={e.app ?? ''}>{e.kind === 'trap' ? 'SNMP' : 'syslog'}{e.app ? ` · ${e.app}` : ''}</div>
              <div className="px-2 py-1 text-slate-800 break-words">{e.message}{e.raised.length > 0 && <span className="ml-2 text-[10px] bg-red-50 text-red-700 border border-red-200 rounded px-1">{t('syslog.events.raised')}</span>}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Syslog and SNMP traps of the devices that cannot run an agent: what is received, what it raised, and how to switch it on.
export function SocSyslog() {
  const { t } = useTranslation()
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Radio size={20} className="text-indigo-600" /> {t('syslog.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('syslog.subtitle')}</p>
      </div>
      <Settings />
      <Unknown />
      <Rules />
      <Events />
    </div>
  )
}

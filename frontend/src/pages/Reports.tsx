import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Download, FileBarChart, Mail, Play, Save, Send, Trash2 } from 'lucide-react'
import { reportsApi, ReportData, SavedReport } from '../lib/api'
import { useAuth } from './Login'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const STAGES = ['ordered', 'in_stock', 'deployed', 'in_repair', 'retired', 'disposed']
const TYPES = ['windows', 'linux', 'network', 'printer', 'virtual', 'server', 'other']
const FORMATS = ['xlsx', 'csv', 'docx'] as const
const inp = 'mt-0.5 block w-full border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white text-slate-900'

// the column headings: the translations the pages already have, a few of their own (rep.col)
const LABEL_KEY: Record<string, string> = {
  name: 'assets.colName', ip: 'assets.colIp', type: 'assets.colType', role: 'assets.roleLabel', ci_class: 'cmdb.classLabel', stage: 'itam.stageLabel',
  asset_tag: 'itam.f.asset_tag', manufacturer: 'assets.manufacturer', model: 'assets.model', serial: 'assets.serial', os: 'assets.os', location: 'assets.location',
  place: 'assets.place', owner: 'assets.owner', criticality: 'assets.criticality', purchased_at: 'itam.f.purchased_at', warranty_until: 'itam.f.warranty_until',
  replace_at: 'itam.f.replace_at', disposed_at: 'itam.f.disposed_at', disposal_method: 'itam.f.disposal_method', cost: 'itam.f.cost', currency: 'itam.f.currency',
  supplier: 'itam.f.supplier', invoice_no: 'itam.f.invoice_no', cost_center: 'itam.f.cost_center', state: 'assets.state.label', last_seen: 'assets.colLastSeen',
  product: 'lic.f.product', vendor: 'lic.f.vendor', kind: 'lic.f.kind', seats: 'lic.f.seats', status: 'lic.statusLabel', valid_from: 'lic.f.valid_from',
  valid_until: 'lic.f.valid_until', reference: 'lic.f.reference', title: 'proc.cf.title', number: 'proc.cf.number', start_at: 'proc.cf.start_at', end_at: 'proc.cf.end_at',
  value: 'proc.cf.value', auto_renew: 'proc.cf.auto_renew',
}

function useLabels() {
  const { t } = useTranslation()
  return (c: string) => (LABEL_KEY[c] ? t(LABEL_KEY[c]) : t(`rep.col.${c}`, { defaultValue: c })) as string
}

function Preview({ data }: { data: ReportData }) {
  const { t } = useTranslation()
  const label = useLabels()
  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-auto max-h-[28rem] text-xs">
      <div className="px-3 py-2 text-slate-500 border-b border-slate-100">{t('rep.rows', { n: data.total })}{data.total > data.rows.length ? ` · ${t('rep.previewCut', { n: data.rows.length })}` : ''}</div>
      <table className="w-full">
        <thead className="bg-slate-50 sticky top-0"><tr>{data.columns.map(c => <th key={c} className="text-left font-normal text-slate-500 px-2 py-1.5 whitespace-nowrap">{label(c)}</th>)}</tr></thead>
        <tbody>{data.rows.map((r, i) => <tr key={i} className="border-t border-slate-100">{data.columns.map(c => <td key={c} className="px-2 py-1 whitespace-nowrap">{r[c] == null ? '' : typeof r[c] === 'boolean' ? (r[c] ? '✓' : '') : String(r[c])}</td>)}</tr>)}</tbody>
      </table>
    </div>
  )
}

function SaveBox({ builtin, params, title, onSaved }: { builtin: string | null; params: Record<string, unknown> | null; title: string; onSaved: () => void }) {
  const { t } = useTranslation()
  const [f, setF] = useState({ name: title, schedule: 'none', format: 'xlsx', hour: '7', weekday: '0', day: '1', recipients: '' })
  const save = useMutation({ mutationFn: () => reportsApi.save({ ...f, builtin, params, hour: Number(f.hour), weekday: Number(f.weekday), day: Number(f.day) }), onSuccess: onSaved })
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 grid sm:grid-cols-3 lg:grid-cols-7 gap-2 items-end text-sm">
      <label className="block text-xs text-slate-500 lg:col-span-2">{t('rep.name')}<input value={f.name} onChange={e => setF({ ...f, name: e.target.value })} className={inp} /></label>
      <label className="block text-xs text-slate-500">{t('rep.schedule')}<select value={f.schedule} onChange={e => setF({ ...f, schedule: e.target.value })} className={inp}>{['none', 'daily', 'weekly', 'monthly'].map(s => <option key={s} value={s}>{t(`rep.sched.${s}`)}</option>)}</select></label>
      {f.schedule === 'weekly' && <label className="block text-xs text-slate-500">{t('rep.weekday')}<select value={f.weekday} onChange={e => setF({ ...f, weekday: e.target.value })} className={inp}>{[0, 1, 2, 3, 4, 5, 6].map(d => <option key={d} value={d}>{t(`rep.day.${d}`)}</option>)}</select></label>}
      {f.schedule === 'monthly' && <label className="block text-xs text-slate-500">{t('rep.dayOfMonth')}<input type="number" min={1} max={28} value={f.day} onChange={e => setF({ ...f, day: e.target.value })} className={inp} /></label>}
      {f.schedule !== 'none' && <label className="block text-xs text-slate-500">{t('rep.hour')}<input type="number" min={0} max={23} value={f.hour} onChange={e => setF({ ...f, hour: e.target.value })} className={inp} /></label>}
      <label className="block text-xs text-slate-500">{t('rep.format')}<select value={f.format} onChange={e => setF({ ...f, format: e.target.value })} className={inp}>{FORMATS.map(x => <option key={x} value={x}>{x.toUpperCase()}</option>)}</select></label>
      {f.schedule !== 'none' && <label className="block text-xs text-slate-500 lg:col-span-2">{t('rep.recipients')}<input value={f.recipients} onChange={e => setF({ ...f, recipients: e.target.value })} placeholder="it@firma.pl, szef@firma.pl" className={inp} /></label>}
      <button disabled={!f.name.trim() || save.isPending} onClick={() => save.mutate()} className="flex items-center gap-1 justify-center px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50"><Save size={13} /> {t('rep.save')}</button>
      {save.isError && <span className="text-xs text-red-700 col-span-full">{errText(save.error)}</span>}
    </div>
  )
}

function Custom({ columns, onSaved }: { columns: Record<string, string[]>; onSaved: () => void }) {
  const { t } = useTranslation()
  const label = useLabels()
  const [scope, setScope] = useState<'assets' | 'licenses' | 'contracts'>('assets')
  const [cols, setCols] = useState<string[]>(['name', 'type', 'stage', 'model', 'serial', 'location', 'warranty_until', 'cost', 'currency'])
  const [flt, setFlt] = useState<Record<string, string | string[]>>({})
  const params = { scope, columns: cols, filters: flt }
  const run = useMutation({ mutationFn: () => reportsApi.preview({ params }) })
  const set = (k: string, v: string | string[]) => setFlt(v === '' || (Array.isArray(v) && v.length === 0) ? Object.fromEntries(Object.entries(flt).filter(([x]) => x !== k)) : { ...flt, [k]: v })
  const multi = (k: string, opts: string[], tk: string) => (
    <div className="text-xs"><span className="text-slate-500">{t(`rep.f.${k}`)}:</span>
      <span className="flex flex-wrap gap-x-2">{opts.map(o => <label key={o} className="flex items-center gap-1"><input type="checkbox" checked={((flt[k] as string[]) ?? []).includes(o)} onChange={e => set(k, e.target.checked ? [...((flt[k] as string[]) ?? []), o] : ((flt[k] as string[]) ?? []).filter(x => x !== o))} /> {t(`${tk}.${o}`)}</label>)}</span>
    </div>
  )
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <h2 className="font-semibold text-slate-900">{t('rep.customTitle')}</h2>
      <div className="flex gap-2">
        {(['assets', 'licenses', 'contracts'] as const).map(s => <button key={s} onClick={() => { setScope(s); setCols(columns[s].slice(0, 8)); setFlt({}) }} className={cn('text-xs border rounded-full px-3 py-1', scope === s ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white border-slate-300')}>{t(`rep.scope.${s}`)}</button>)}
      </div>
      <div>
        <div className="text-xs text-slate-500 mb-1">{t('rep.columns')}</div>
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs">{columns[scope].map(c => <label key={c} className="flex items-center gap-1"><input type="checkbox" checked={cols.includes(c)} onChange={e => setCols(e.target.checked ? [...cols, c] : cols.filter(x => x !== c))} /> {label(c)}</label>)}</div>
      </div>
      <div className="space-y-2">
        <div className="text-xs text-slate-500">{t('rep.filters')}</div>
        {scope === 'assets' && <>
          {multi('stage', STAGES, 'itam.stage')}
          {multi('type', TYPES, 'assets.type')}
          <div className="grid sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {(['location', 'owner', 'cost_center', 'supplier'] as const).map(k => <label key={k} className="block text-xs text-slate-500">{t(`rep.f.${k}`)}<input value={(flt[k] as string) ?? ''} onChange={e => set(k, e.target.value)} className={inp} /></label>)}
            {(['purchased_from', 'purchased_to', 'warranty_before'] as const).map(k => <label key={k} className="block text-xs text-slate-500">{t(`rep.f.${k}`)}<input type="date" value={(flt[k] as string) ?? ''} onChange={e => set(k, e.target.value)} className={inp} /></label>)}
          </div>
        </>}
        {scope === 'licenses' && multi('status', ['compliant', 'over', 'unused', 'expired', 'expiring', 'no_installs', 'site'], 'lic.status')}
        {scope === 'contracts' && <>
          {multi('status', ['active', 'expiring', 'expired', 'renewing', 'future'], 'proc.cstatus')}
          <label className="block text-xs text-slate-500 w-48">{t('rep.f.end_before')}<input type="date" value={(flt.end_before as string) ?? ''} onChange={e => set('end_before', e.target.value)} className={inp} /></label>
        </>}
        <label className="block text-xs text-slate-500 w-64">{t('rep.f.text')}<input value={(flt.text as string) ?? ''} onChange={e => set('text', e.target.value)} className={inp} /></label>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => run.mutate()} disabled={cols.length === 0 || run.isPending} className="flex items-center gap-1 px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50"><Play size={13} /> {t('rep.run')}</button>
        {FORMATS.map(f => <DownloadButton key={f} fmt={f} body={{ params }} title={t('rep.customTitle') as string} />)}
        {run.isError && <span className="text-xs text-red-700">{errText(run.error)}</span>}
      </div>
      {run.data && <Preview data={run.data} />}
      {run.data && <SaveBox builtin={null} params={params} title={t('rep.customTitle') as string} onSaved={onSaved} />}
    </div>
  )
}

function DownloadButton({ fmt, body, title }: { fmt: string; body: { builtin?: string | null; params?: Record<string, unknown> | null }; title: string }) {
  const { t } = useTranslation()
  const label = useLabels()
  const [err, setErr] = useState<string | null>(null)
  const go = async () => {
    setErr(null)
    try {
      const cols = new Set<string>(Object.keys(LABEL_KEY).concat(['mac', 'first_seen', 'used', 'reclaimable', 'over', 'unused', 'days_left', 'assets_covered', 'year', 'assets', 'total', 'program', 'installs', 'versions', 'items', 'created_at', 'created_by']))
      const labels = Object.fromEntries([...cols].map(c => [c, label(c)]))
      const { blob, name } = await reportsApi.download({ ...body, format: fmt, title, labels })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = name; a.click()
      setTimeout(() => URL.revokeObjectURL(url), 2000)
    } catch (e) { setErr(errText(e)) }
  }
  return <><button onClick={go} className="flex items-center gap-1 px-2.5 py-1.5 text-xs rounded-lg border border-slate-300 bg-white hover:bg-slate-50"><Download size={12} /> {fmt.toUpperCase()}</button>{err && <span className="text-xs text-red-700">{err}</span>}</>
}

function Smtp() {
  const { t } = useTranslation()
  const { role } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['smtp'], queryFn: reportsApi.smtp })
  const [f, setF] = useState<Record<string, string> | null>(null)
  const [to, setTo] = useState('')
  const cur = f ?? (q.data ? { host: q.data.host ?? '', port: q.data.port ? String(q.data.port) : '', security: q.data.security, username: q.data.username ?? '', password: '', from_addr: q.data.from_addr ?? '', from_name: q.data.from_name ?? '' } : null)
  const save = useMutation({
    mutationFn: () => { const b: Record<string, unknown> = { ...cur!, port: cur!.port ? Number(cur!.port) : null }; if (!cur!.password) delete b.password; return reportsApi.saveSmtp(b) },
    onSuccess: () => { setF(null); qc.invalidateQueries({ queryKey: ['smtp'] }); qc.invalidateQueries({ queryKey: ['reports'] }) },
  })
  const test = useMutation({ mutationFn: () => reportsApi.testSmtp(to) })
  if (!cur) return null
  const admin = role === 'admin'
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <h2 className="font-semibold text-slate-900 flex items-center gap-2"><Mail size={15} className="text-indigo-600" /> {t('rep.smtpTitle')} {q.data?.configured ? <span className="text-xs text-green-700 font-normal">{t('rep.smtpOn')}</span> : <span className="text-xs text-amber-700 font-normal">{t('rep.smtpOff')}</span>}</h2>
      <div className="grid sm:grid-cols-3 lg:grid-cols-7 gap-2 items-end">
        {(['host', 'port', 'username', 'password', 'from_addr', 'from_name'] as const).map(k => (
          <label key={k} className="block text-xs text-slate-500">{t(`rep.smtp.${k}`)}
            <input type={k === 'password' ? 'password' : 'text'} autoComplete="off" disabled={!admin} value={cur[k]} placeholder={k === 'password' && q.data?.password_set ? (t('rep.smtp.passwordSet') as string) : ''}
              onChange={e => setF({ ...cur, [k]: e.target.value })} className={inp} /></label>
        ))}
        <label className="block text-xs text-slate-500">{t('rep.smtp.security')}<select disabled={!admin} value={cur.security} onChange={e => setF({ ...cur, security: e.target.value })} className={inp}>{['starttls', 'ssl', 'none'].map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}</select></label>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {admin && <button disabled={!f || save.isPending} onClick={() => save.mutate()} className="px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50">{t('common.save')}</button>}
        <input value={to} onChange={e => setTo(e.target.value)} placeholder={t('rep.smtp.testTo') as string} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm w-56" />
        <button disabled={!to || test.isPending || !q.data?.configured} onClick={() => test.mutate()} className="flex items-center gap-1 px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white disabled:opacity-50"><Send size={13} /> {t('rep.smtp.test')}</button>
        {test.data && <span className={cn('text-xs', test.data.ok ? 'text-green-700' : 'text-red-700')}>{test.data.ok ? t('rep.smtp.testOk') : test.data.error}</span>}
        {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
      </div>
      {!admin && <p className="text-xs text-slate-500">{t('rep.smtp.adminOnly')}</p>}
    </div>
  )
}

function Saved({ rows }: { rows: SavedReport[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const send = useMutation({ mutationFn: (id: number) => reportsApi.sendNow(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['reports'] }) })
  const del = useMutation({ mutationFn: (id: number) => reportsApi.remove(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['reports'] }) })
  if (rows.length === 0) return null
  const when = (r: SavedReport) => r.schedule === 'none' ? t('rep.sched.none') : r.schedule === 'daily' ? t('rep.whenDaily', { h: r.hour }) : r.schedule === 'weekly' ? t('rep.whenWeekly', { d: t(`rep.day.${r.weekday}`), h: r.hour }) : t('rep.whenMonthly', { d: r.day, h: r.hour })
  return (
    <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
      <div className="px-4 py-2 font-semibold text-slate-900">{t('rep.savedTitle')}</div>
      {rows.map(r => (
        <div key={r.id} className="px-4 py-2 space-y-1">
          <div className="flex items-center gap-3">
            <span className="font-medium text-slate-900 flex-1 truncate">{r.name}</span>
            <span className="text-xs text-slate-500">{r.builtin ? t(`rep.builtin.${r.builtin}`) : t(`rep.scope.${r.params?.scope ?? 'assets'}`)} · {r.format.toUpperCase()} · {when(r)}</span>
            <span className="text-xs text-slate-500 truncate max-w-[16rem]" title={r.recipients.join(', ')}>{r.recipients.join(', ')}</span>
            {r.builtin
              ? <DownloadButton fmt={r.format} body={{ builtin: r.builtin }} title={r.name} />
              : <DownloadButton fmt={r.format} body={{ params: r.params }} title={r.name} />}
            {r.recipients.length > 0 && <button disabled={send.isPending} onClick={() => send.mutate(r.id)} title={t('rep.sendNow') as string} className="text-slate-400 hover:text-indigo-600"><Send size={14} /></button>}
            <button onClick={() => { if (window.confirm(`${t('rep.remove')}: ${r.name}?`)) del.mutate(r.id) }} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>
          </div>
          {r.runs.length > 0 && <div className="text-[11px] text-slate-500">{r.runs.slice(0, 3).map((x, i) => <span key={i} className={cn('mr-3', x.status === 'ok' ? '' : 'text-red-700')}>{new Date(x.at).toLocaleString()} · {x.status === 'ok' ? t('rep.sentRows', { n: x.rows }) : x.error}</span>)}</div>}
        </div>
      ))}
      {send.isError && <div className="px-4 py-2 text-xs text-red-700">{errText(send.error)}</div>}
    </div>
  )
}

// Ready-made and your own reports of the assets, licenses and contracts; files and scheduled e-mail (services/reports.py, plan stage E).
export function Reports() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['reports'], queryFn: reportsApi.overview })
  const [sel, setSel] = useState<string | null>(null)
  const prev = useMutation({ mutationFn: (b: string) => reportsApi.preview({ builtin: b }) })
  const d = q.data
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><FileBarChart size={20} className="text-indigo-600" /> {t('rep.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('rep.subtitle')}</p>
      </div>
      {d && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
          <h2 className="font-semibold text-slate-900 text-sm">{t('rep.builtinTitle')}</h2>
          <div className="flex flex-wrap gap-1.5">
            {d.builtin.map(b => <button key={b} onClick={() => { setSel(b); prev.mutate(b) }} className={cn('text-xs border rounded-full px-3 py-1', sel === b ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white border-slate-300 hover:bg-slate-50')}>{t(`rep.builtin.${b}`)}</button>)}
          </div>
          {sel && (
            <>
              <p className="text-xs text-slate-500">{t(`rep.builtinHint.${sel}`)}</p>
              <div className="flex flex-wrap gap-2">{FORMATS.map(f => <DownloadButton key={f} fmt={f} body={{ builtin: sel }} title={t(`rep.builtin.${sel}`) as string} />)}</div>
              {prev.isError && <p className="text-xs text-red-700">{errText(prev.error)}</p>}
              {prev.data && <Preview data={prev.data} />}
              <SaveBox key={sel} builtin={sel} params={null} title={t(`rep.builtin.${sel}`) as string} onSaved={() => qc.invalidateQueries({ queryKey: ['reports'] })} />
            </>
          )}
        </div>
      )}
      {d && <Saved rows={d.saved} />}
      {d && <Custom columns={d.columns} onSaved={() => qc.invalidateQueries({ queryKey: ['reports'] })} />}
      <Smtp />
      <p className="text-xs text-slate-400">{t('rep.note')}</p>
    </div>
  )
}

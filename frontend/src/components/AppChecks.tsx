import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { AppWindow, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { appChecksApi, AppCheck, AppCheckItem } from '../lib/api'
import { useAgo } from './SocBits'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const EMPTY: AppCheck = { kind: 'http', name: '', target: '', enabled: true, interval_min: 2, timeout_s: 10, slow_ms: null, expect_status: null, contains: null, insecure: false, dns_server: null, expect_ip: null }

// strips the overview's result fields: what is saved is the check itself
function bare(x: AppCheckItem | AppCheck): AppCheck {
  const { id, name, kind, target, enabled, interval_min, timeout_s, slow_ms, expect_status, contains, insecure, dns_server, expect_ip } = x
  return { id, name, kind, target, enabled, interval_min, timeout_s, slow_ms, expect_status, contains, insecure, dns_server, expect_ip }
}

function Form({ init, onSave, onCancel, saving, error }: { init: AppCheck; onSave: (c: AppCheck) => void; onCancel: () => void; saving: boolean; error: string | null }) {
  const { t } = useTranslation()
  const [c, setC] = useState<AppCheck>(init)
  const test = useMutation({ mutationFn: () => appChecksApi.test(c) })
  const inp = 'block border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white text-slate-900'
  const set = (p: Partial<AppCheck>) => setC({ ...c, ...p })
  const txt = (v: string) => (v.trim() === '' ? null : v)
  return (
    <div className="border-t border-slate-100 bg-slate-50 px-4 py-3 space-y-3 text-sm">
      <div className="flex flex-wrap gap-3 items-end">
        <label className="text-xs text-slate-600">{t('appc.f.kind')}
          <select value={c.kind} onChange={e => set({ kind: e.target.value as AppCheck['kind'] })} className={inp}>
            {(['http', 'tcp', 'dns'] as const).map(k => <option key={k} value={k}>{t(`appc.kind.${k}`)}</option>)}
          </select>
        </label>
        <label className="text-xs text-slate-600">{t('appc.f.name')}<input value={c.name ?? ''} onChange={e => set({ name: e.target.value })} className={cn(inp, 'w-48')} /></label>
        <label className="text-xs text-slate-600 flex-1 min-w-[16rem]">{t('appc.f.target')}
          <input value={c.target} onChange={e => set({ target: e.target.value.trim() })} placeholder={t(c.kind === 'http' ? 'appc.f.targetHttp' : c.kind === 'tcp' ? 'appc.f.targetTcp' : 'appc.f.targetDns') as string} className={cn(inp, 'w-full')} />
        </label>
      </div>
      <div className="flex flex-wrap gap-3 items-end">
        <label className="text-xs text-slate-600">{t('appc.f.interval')}<input type="number" min={1} max={60} value={c.interval_min} onChange={e => set({ interval_min: Number(e.target.value) })} className={cn(inp, 'w-24')} /></label>
        <label className="text-xs text-slate-600">{t('appc.f.timeout')}<input type="number" min={1} max={30} value={c.timeout_s} onChange={e => set({ timeout_s: Number(e.target.value) })} className={cn(inp, 'w-24')} /></label>
        <label className="text-xs text-slate-600">{t('appc.f.slow')}<input type="number" min={1} value={c.slow_ms ?? ''} onChange={e => set({ slow_ms: e.target.value === '' ? null : Number(e.target.value) })} className={cn(inp, 'w-28')} /></label>
        {c.kind === 'http' && <label className="text-xs text-slate-600">{t('appc.f.status')}<input value={c.expect_status ?? ''} onChange={e => set({ expect_status: txt(e.target.value) })} placeholder="200-399" className={cn(inp, 'w-40')} /></label>}
        {c.kind !== 'dns' && <label className="text-xs text-slate-600">{t(c.kind === 'tcp' ? 'appc.f.containsTcp' : 'appc.f.contains')}<input value={c.contains ?? ''} onChange={e => set({ contains: txt(e.target.value) })} className={cn(inp, 'w-56')} /></label>}
        {c.kind === 'dns' && <>
          <label className="text-xs text-slate-600">{t('appc.f.dnsServer')}<input value={c.dns_server ?? ''} onChange={e => set({ dns_server: txt(e.target.value) })} className={cn(inp, 'w-40')} /></label>
          <label className="text-xs text-slate-600">{t('appc.f.expectIp')}<input value={c.expect_ip ?? ''} onChange={e => set({ expect_ip: txt(e.target.value) })} className={cn(inp, 'w-40')} /></label>
        </>}
      </div>
      <div className="flex flex-wrap gap-4">
        <label className="flex items-center gap-2 text-xs text-slate-700"><input type="checkbox" checked={c.enabled} onChange={e => set({ enabled: e.target.checked })} /> {t('appc.f.enabled')}</label>
        {c.kind === 'http' && <label className="flex items-center gap-2 text-xs text-slate-700"><input type="checkbox" checked={c.insecure} onChange={e => set({ insecure: e.target.checked })} /> {t('appc.f.insecure')}</label>}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={() => onSave(c)} disabled={saving || !c.target} className="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-sm disabled:opacity-50">{t('appc.save')}</button>
        <button onClick={onCancel} className="border border-slate-300 bg-white rounded-lg px-3 py-1.5 text-sm">{t('appc.cancel')}</button>
        <button onClick={() => test.mutate()} disabled={test.isPending || !c.target} className="border border-slate-300 bg-white rounded-lg px-3 py-1.5 text-sm disabled:opacity-50">{t('appc.test')}</button>
        {test.data && <span className={cn('text-xs', test.data.ok ? 'text-green-700' : 'text-red-700')}>{test.data.ok ? t('appc.testOk', { ms: test.data.ms }) : t('appc.testFail', { err: test.data.error })}{test.data.code ? ` · HTTP ${test.data.code}` : ''}{test.data.addrs?.length ? ` · ${test.data.addrs.join(', ')}` : ''}</span>}
        {test.isError && <span className="text-xs text-red-700">{errText(test.error)}</span>}
        {error && <span className="text-xs text-red-700">{error}</span>}
      </div>
    </div>
  )
}

function Pct({ v }: { v: number | null }) {
  if (v == null) return <span className="text-slate-300">—</span>
  return <span className={cn('tabular-nums', v >= 99.9 ? 'text-green-700' : v >= 99 ? 'text-slate-700' : v >= 95 ? 'text-amber-600' : 'text-red-600')}>{v.toFixed(v >= 99.9 ? 2 : 1)}%</span>
}

// Application checks: HTTP(S), TCP and DNS checks of your own (services/app_checks.py).
export function AppChecks() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const [editing, setEditing] = useState<string | 'new' | null>(null)
  const q = useQuery({ queryKey: ['app-checks'], queryFn: appChecksApi.overview, refetchInterval: 30000 })
  const items = q.data?.items ?? []
  const save = useMutation({
    mutationFn: (list: AppCheck[]) => appChecksApi.save(list),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['app-checks'] }); setEditing(null) },
  })
  const run = useMutation({ mutationFn: appChecksApi.run, onSuccess: () => qc.invalidateQueries({ queryKey: ['app-checks'] }) })
  const all = items.map(bare)
  const put = (c: AppCheck) => save.mutate(editing === 'new' ? [...all, c] : all.map(x => (x.id === c.id ? c : x)))
  const del = (id: string, name: string) => { if (window.confirm(`${t('appc.remove')}: ${name}?`)) save.mutate(all.filter(x => x.id !== id)) }
  const grid = 'grid-cols-[minmax(0,2fr)_6rem_6rem_6rem_4.5rem_4.5rem_6rem_minmax(0,1.4fr)_4rem]'
  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
      <div className="flex items-start gap-3 px-4 py-3">
        <div className="flex-1">
          <h2 className="font-semibold text-slate-900 flex items-center gap-2"><AppWindow size={16} className="text-indigo-600" /> {t('appc.title')}</h2>
          <p className="text-xs text-slate-500 mt-0.5">{t('appc.subtitle')}</p>
        </div>
        <button onClick={() => setEditing('new')} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50"><Plus size={14} /> {t('appc.add')}</button>
        {items.length > 0 && (
          <button onClick={() => run.mutate()} disabled={run.isPending} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">
            <RefreshCw size={14} className={run.isPending ? 'animate-spin' : ''} /> {t('appc.runNow')}
          </button>
        )}
      </div>
      {editing === 'new' && <Form init={EMPTY} onSave={put} onCancel={() => setEditing(null)} saving={save.isPending} error={save.isError ? errText(save.error) : null} />}
      {q.isLoading ? <p className="px-4 pb-3 text-sm text-slate-500">{t('common.loading')}</p> : items.length === 0 ? (editing ? null : <p className="px-4 pb-3 text-sm text-slate-500">{t('appc.empty')}</p>) : (
        <div className="text-sm">
          <div className={cn('grid items-center bg-slate-50 text-xs text-slate-500 py-2 border-t border-slate-100', grid)}>
            <div className="px-3">{t('appc.col.check')}</div>
            <div className="px-2">{t('appc.col.state')}</div>
            <div className="px-2 text-right">{t('appc.col.resp')}</div>
            <div className="px-2 text-right">{t('appc.col.p95')}</div>
            <div className="px-2 text-right">{t('appc.col.up24')}</div>
            <div className="px-2 text-right">{t('appc.col.up7')}</div>
            <div className="px-2 text-right">{t('appc.col.cert')}</div>
            <div className="px-2">{t('appc.col.detail')}</div>
            <div />
          </div>
          {items.map(x => (
            <div key={x.id}>
              <div className={cn('grid items-center border-t border-slate-100', grid, x.ok === false ? 'bg-red-50/40' : '')}>
                <div className="px-3 py-1.5 min-w-0">
                  <div className="truncate text-slate-800">{x.name}</div>
                  <div className="text-[11px] text-slate-400 truncate" title={x.target}>{t(`appc.kind.${x.kind}`)} · {x.target}</div>
                </div>
                <div className="px-2 text-xs">
                  {!x.enabled ? <span className="text-slate-400">{t('appc.disabled')}</span>
                    : x.ok == null ? <span className="text-slate-400">{t('appc.pending')}</span>
                    : <span className={cn('inline-block border rounded-full px-2 py-0.5', x.ok ? 'bg-green-50 text-green-700 border-green-200' : 'bg-red-50 text-red-700 border-red-200')} title={x.since ? new Date(x.since).toLocaleString() : ''}>{x.ok ? t('appc.ok') : t('appc.fail')}</span>}
                </div>
                <div className={cn('px-2 text-right tabular-nums', x.slow_ms && x.ms != null && x.ms >= x.slow_ms ? 'text-amber-600 font-medium' : 'text-slate-700')}>{x.ms != null ? `${Math.round(x.ms)} ms` : '—'}</div>
                <div className="px-2 text-right tabular-nums text-slate-600">{x.p95_24h != null ? `${Math.round(x.p95_24h)} ms` : '—'}</div>
                <div className="px-2 text-right"><Pct v={x.up_24h} /></div>
                <div className="px-2 text-right"><Pct v={x.up_7d} /></div>
                <div className={cn('px-2 text-right text-xs tabular-nums', x.cert_days == null ? 'text-slate-300' : x.cert_days < 0 ? 'text-red-700 font-medium' : x.cert_days <= 14 ? 'text-amber-600 font-medium' : 'text-slate-600')}>
                  {x.cert_days == null ? '—' : x.cert_days < 0 ? t('appc.expired') : t('appc.days', { n: Math.floor(x.cert_days) })}
                </div>
                <div className="px-2 text-xs text-slate-600 truncate" title={x.error ?? ''}>
                  {x.error ? <span className="text-red-700">{x.error}</span> : x.code ? `HTTP ${x.code}` : x.addrs?.length ? x.addrs.join(', ') : ''}
                  {x.at ? <span className="text-slate-400"> · {ago(x.at)}</span> : null}
                </div>
                <div className="px-2 flex gap-2 justify-end">
                  <button onClick={() => setEditing(editing === x.id ? null : x.id)} title={t('appc.edit') as string} className="text-slate-400 hover:text-indigo-600"><Pencil size={14} /></button>
                  <button onClick={() => del(x.id, x.name)} title={t('appc.remove') as string} className="text-slate-400 hover:text-red-600"><Trash2 size={14} /></button>
                </div>
              </div>
              {editing === x.id && <Form init={bare(x)} onSave={put} onCancel={() => setEditing(null)} saving={save.isPending} error={save.isError ? errText(save.error) : null} />}
            </div>
          ))}
        </div>
      )}
      <p className="px-4 py-2 text-xs text-slate-400 border-t border-slate-100">{t('appc.note')}</p>
    </div>
  )
}

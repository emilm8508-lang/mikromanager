import { useEffect, useState, Fragment } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, FileClock, RefreshCw, Trash2, Download } from 'lucide-react'
import { cfgApi, CfgDiff } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

function Diff({ d }: { d: CfgDiff }) {
  const { t } = useTranslation()
  if (d.hunks.length === 0) return <div className="text-xs text-slate-500">{t('cfg.noDiff')}</div>
  return (
    <div className="font-mono text-[11px] leading-snug border border-slate-200 rounded-lg overflow-hidden bg-white">
      {d.hunks.map((h, i) => (
        <div key={i} className="border-b border-slate-100 last:border-0">
          <div className="bg-slate-100 text-slate-600 px-2 py-0.5">{h.section || '/'}</div>
          {h.lines.map(([sign, text], j) => (
            <div key={j} className={cn('px-2 whitespace-pre-wrap break-all', sign === '+' ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800')}>{sign} {text}</div>
          ))}
        </div>
      ))}
    </div>
  )
}

function Versions({ id }: { id: number }) {
  const { t } = useTranslation()
  const ago = useAgo()
  const vq = useQuery({ queryKey: ['cfg-versions', id], queryFn: () => cfgApi.versions(id) })
  const versions = vq.data?.versions ?? []
  const [a, setA] = useState<number | null>(null)
  const [b, setB] = useState<number | null>(null)
  useEffect(() => {
    if (versions.length >= 2 && a == null && b == null) { setB(versions[0].id); setA(versions[1].id) }
  }, [versions, a, b])
  const dq = useQuery({ queryKey: ['cfg-diff', id, a, b], queryFn: () => cfgApi.diff(id, a!, b!), enabled: a != null && b != null && a !== b })
  if (vq.isLoading) return <div className="px-4 py-3 text-xs text-slate-500">{t('common.loading')}</div>
  return (
    <div className="px-4 py-3 bg-slate-50 space-y-3 text-xs">
      <div className="grid gap-x-4 gap-y-0.5 grid-cols-[auto_auto_auto_auto_1fr_auto] items-center">
        <div className="text-slate-400">{t('cfg.from')}</div><div className="text-slate-400">{t('cfg.to')}</div><div className="text-slate-400">{t('cfg.version')}</div>
        <div className="text-slate-400 text-right">+/−</div><div className="text-slate-400">{t('cfg.sections')}</div><div />
        {versions.map(v => (
          <Fragment key={v.id}>
            <div><input type="radio" name={`a-${id}`} checked={a === v.id} onChange={() => setA(v.id)} /></div>
            <div><input type="radio" name={`b-${id}`} checked={b === v.id} onChange={() => setB(v.id)} /></div>
            <div className="text-slate-700" title={new Date(v.at).toLocaleString()}>{new Date(v.at).toLocaleString()} <span className="text-slate-400">({ago(v.at)})</span></div>
            <div className="text-right tabular-nums">{v.added == null ? <span className="text-slate-400">{t('cfg.first')}</span> : <><span className="text-green-700">+{v.added}</span> <span className="text-red-700">−{v.removed}</span></>}</div>
            <div className="text-slate-500 truncate" title={v.sections.join(', ')}>{v.sections.join(', ')}</div>
            <a className="text-indigo-600 hover:underline inline-flex items-center gap-1" href={`/api/config-history/${id}/version/${v.id}`} target="_blank" rel="noreferrer"><Download size={11} /> {t('cfg.text')}</a>
          </Fragment>
        ))}
      </div>
      {versions.length < 2 ? <div className="text-slate-500">{t('cfg.oneVersion')}</div> : a === b ? null : dq.isLoading ? <div className="text-slate-500">{t('common.loading')}</div> : dq.data ? (
        <div className="space-y-1">
          <div className="text-slate-700">{t('cfg.diffSummary', { added: dq.data.added, removed: dq.data.removed })}{dq.data.sensitive ? <span className="ml-2 text-red-700 font-medium">{t('cfg.sensitive')}</span> : null}</div>
          <Diff d={dq.data} />
        </div>
      ) : null}
    </div>
  )
}

// What was changed on a router, when, and what it was before: the history of the configuration of every MikroTik with the diff of any two versions.
export function ConfigHistory() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const [open, setOpen] = useState<number | null>(null)
  const ov = useQuery({ queryKey: ['cfg'], queryFn: cfgApi.overview, refetchInterval: 60000 })
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['cfg'] }); void qc.invalidateQueries({ queryKey: ['cfg-versions'] }); void qc.invalidateQueries({ queryKey: ['cfg-diff'] }) }
  const one = useMutation({ mutationFn: (id: number) => cfgApi.snapshot(id), onSuccess: refresh })
  const all = useMutation({ mutationFn: cfgApi.run, onSuccess: refresh })
  const del = useMutation({ mutationFn: (id: number) => cfgApi.remove(id), onSuccess: refresh })
  const sets = useMutation({ mutationFn: (b: { enabled?: boolean; interval_hours?: number }) => cfgApi.settings(b), onSuccess: refresh })
  const d = ov.data
  const grid = 'grid-cols-[1.5rem_minmax(0,1.6fr)_4rem_minmax(0,1.1fr)_minmax(0,1.1fr)_minmax(0,2fr)_6.5rem]'
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><FileClock size={20} className="text-indigo-600" /> {t('cfg.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('cfg.subtitle')}</p>
        </div>
        <button onClick={() => all.mutate()} disabled={all.isPending} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">
          <RefreshCw size={14} className={all.isPending ? 'animate-spin' : ''} /> {t('cfg.runAll')}
        </button>
      </div>
      {d && (
        <div className="flex items-center gap-4 flex-wrap text-sm text-slate-600">
          <label className="flex items-center gap-2"><input type="checkbox" checked={d.settings.enabled} onChange={e => sets.mutate({ enabled: e.target.checked })} /> {t('cfg.enabled')}</label>
          <label className="flex items-center gap-2">{t('cfg.interval')}
            <select value={d.settings.interval_hours} onChange={e => sets.mutate({ interval_hours: Number(e.target.value) })} className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white">
              {[1, 3, 6, 12, 24, 72].map(h => <option key={h} value={h}>{h} h</option>)}
              {![1, 3, 6, 12, 24, 72].includes(d.settings.interval_hours) && <option value={d.settings.interval_hours}>{d.settings.interval_hours} h</option>}
            </select></label>
        </div>
      )}
      {(all.isError || one.isError || sets.isError) && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">{errText(all.error ?? one.error ?? sets.error)}</div>}
      {ov.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : !d || d.items.length === 0 ? <p className="text-sm text-slate-500">{t('cfg.empty')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className={cn('grid items-center bg-slate-50 text-xs text-slate-500 py-2', grid)}>
            <div /><div className="px-2">{t('cfg.col.device')}</div><div className="px-2 text-right">{t('cfg.col.versions')}</div><div className="px-2">{t('cfg.col.lastCheck')}</div>
            <div className="px-2">{t('cfg.col.lastChange')}</div><div className="px-2">{t('cfg.col.what')}</div><div />
          </div>
          {d.items.map(r => (
            <Fragment key={r.id}>
              <div className={cn('grid items-center border-t border-slate-100 cursor-pointer hover:bg-slate-50', grid)} onClick={() => setOpen(open === r.id ? null : r.id)}>
                <div className="px-2 text-slate-400">{open === r.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</div>
                <div className="px-2 py-2 min-w-0"><div className="font-medium text-slate-900 truncate">{r.name}{r.vendor === 'cisco-sb' && <span className="ml-2 text-[10px] font-normal text-slate-500 border border-slate-200 rounded px-1">Cisco</span>}</div><div className="text-[11px] text-slate-400">{r.ip}</div></div>
                <div className="px-2 text-right tabular-nums text-slate-700">{r.versions}</div>
                <div className="px-2 text-xs">{r.last_error ? <span className="text-red-600" title={r.last_error}>{t('cfg.error')}</span> : <span className="text-slate-500">{ago(r.last_check)}</span>}</div>
                <div className="px-2 text-xs text-slate-600">{r.last_change ? ago(r.last_change) : <span className="text-slate-400">—</span>}</div>
                <div className="px-2 text-xs text-slate-500 truncate" title={r.last_sections.join(', ')}>
                  {r.last_added != null && <span className="mr-2"><span className="text-green-700">+{r.last_added}</span> <span className="text-red-700">−{r.last_removed}</span></span>}{r.last_sections.join(', ')}
                </div>
                <div className="px-2 flex gap-1 justify-end" onClick={e => e.stopPropagation()}>
                  <button className="p-1 text-slate-400 hover:text-indigo-600 disabled:opacity-40" title={t('cfg.snapshotNow') as string} disabled={one.isPending} onClick={() => one.mutate(r.id)}><RefreshCw size={14} /></button>
                  <button className="p-1 text-slate-400 hover:text-red-600" title={t('cfg.deleteHistory') as string} onClick={() => { if (confirm(t('cfg.deleteConfirm', { name: r.name }) as string)) del.mutate(r.id) }}><Trash2 size={14} /></button>
                </div>
              </div>
              {r.last_error && open === r.id && <div className="px-4 py-2 text-xs text-red-700 bg-red-50 break-words">{r.last_error}</div>}
              {open === r.id && <Versions id={r.id} />}
            </Fragment>
          ))}
        </div>
      )}
      <p className="text-xs text-slate-400">{t('cfg.note')}</p>
    </div>
  )
}

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Merge } from 'lucide-react'
import { assetsApi, type AssetDuplicateGroup } from '../lib/api'
import { useAgo } from './SocBits'
import { cn } from '../lib/utils'

const errText = (e: unknown) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? ''

/** Entries of the inventory that look like one machine (the same managed object, MAC address or name): choose which stays and join them. */
export function AssetDuplicates() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['asset-duplicates'], queryFn: assetsApi.duplicates, refetchInterval: 120000 })
  const [keep, setKeep] = useState<Record<string, number>>({})
  const [err, setErr] = useState<string | null>(null)
  const done = () => { void qc.invalidateQueries({ queryKey: ['asset-duplicates'] }); void qc.invalidateQueries({ queryKey: ['assets'] }); void qc.invalidateQueries({ queryKey: ['asset-summary'] }) }
  const merge = useMutation({ mutationFn: (v: { keep: number; drop: number[] }) => assetsApi.merge(v.keep, v.drop), onSuccess: () => { setErr(null); done() }, onError: e => setErr(errText(e)) })
  const remove = useMutation({ mutationFn: (id: number) => assetsApi.bulkDelete([id]), onSuccess: () => { setErr(null); done() }, onError: e => setErr(errText(e)) })
  const groups = (q.data ?? []).filter(g => g.assets.length > 1)
  if (groups.length === 0) return null
  const keyOf = (g: AssetDuplicateGroup) => g.ids.join(',')
  return (
    <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 space-y-3 text-sm">
      <div className="flex items-center gap-2 text-amber-900 font-semibold"><Merge size={15} /> {t('assetmerge.title', { count: groups.length })}</div>
      <p className="text-xs text-amber-900/80">{t('assetmerge.intro')}</p>
      {err && <p className="text-xs text-red-600">{err}</p>}
      {groups.map(g => {
        const k = keep[keyOf(g)] ?? g.keep
        return (
          <div key={keyOf(g)} className="bg-white border border-amber-200 rounded-lg p-3 space-y-2">
            <div className="text-xs text-slate-500">{g.reasons.map(r => t(`assetmerge.reason.${r}`)).join(' · ')}{g.auto ? ` · ${t('assetmerge.auto')}` : ''}</div>
            <ul className="space-y-1">
              {g.assets.map(a => (
                <li key={a.id} className="flex flex-wrap items-center gap-3">
                  <label className="inline-flex items-center gap-2 min-w-[14rem]"><input type="radio" name={keyOf(g)} checked={k === a.id} onChange={() => setKeep(x => ({ ...x, [keyOf(g)]: a.id }))} />
                    <span className="font-medium text-slate-900">{a.name}</span></label>
                  <span className="font-mono text-xs text-slate-500">{a.ip ?? '—'}</span>
                  <span className={cn('text-xs', a.alive ? 'text-green-700' : 'text-slate-400')}>{a.alive ? t('assetmerge.alive') : `${t('assetmerge.silent')} ${ago(a.last_seen_at)}`}</span>
                  {a.managed.length > 0 && <span className="text-[11px] border border-slate-200 rounded px-1.5 text-slate-500">{t('assetmerge.managed')}</span>}
                  {a.has_notes && <span className="text-[11px] border border-slate-200 rounded px-1.5 text-slate-500">{t('assetmerge.hasNotes')}</span>}
                  <button className="ml-auto text-xs text-red-600 hover:underline disabled:opacity-40" disabled={remove.isPending || k === a.id}
                    onClick={() => { if (confirm(t('assets.removeConfirm') as string)) remove.mutate(a.id) }}>{t('assetmerge.remove')}</button>
                </li>
              ))}
            </ul>
            <button className="px-3 py-1 rounded-md bg-indigo-600 text-white text-xs disabled:opacity-40" disabled={merge.isPending}
              onClick={() => { const keepName = g.assets.find(a => a.id === k)?.name; if (confirm(t('assetmerge.confirm', { name: keepName, count: g.assets.length - 1 }) as string)) merge.mutate({ keep: k, drop: g.ids.filter(i => i !== k) }) }}>
              {t('assetmerge.merge')}
            </button>
          </div>
        )
      })}
    </div>
  )
}

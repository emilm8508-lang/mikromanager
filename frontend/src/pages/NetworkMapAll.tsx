import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Waypoints, RefreshCw, Loader2 } from 'lucide-react'
import { assetsApi, netmapApi } from '../lib/api'
import { NetworkGraph } from '../components/NetworkGraph'
import { Button } from '../components/ui/Button'

// The map of the whole network of this agent: what the routers and switches report (LLDP, MAC tables), with the computers hanging off their ports.
export function NetworkMapAll() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [every, setEvery] = useState<number>(() => { try { return Number(localStorage.getItem('netmap-refresh')) || 0 } catch { return 0 } })
  // asks again every few seconds while the first full map is still being built, then at the chosen interval (or not at all)
  const { data, isLoading, isFetching } = useQuery({ queryKey: ['netmap'], queryFn: netmapApi.get, refetchInterval: q => every > 0 ? every * 1000 : (q.state.data?.building || q.state.data?.partial) ? 8000 : false })
  const rebuild = useMutation({ mutationFn: netmapApi.refresh, onSuccess: r => qc.setQueryData(['netmap'], r) })
  const rename = useMutation({ mutationFn: ({ id, name }: { id: number; name: string }) => assetsApi.update(id, { name }), onSuccess: () => { void qc.invalidateQueries({ queryKey: ['netmap'] }); void qc.invalidateQueries({ queryKey: ['assets'] }) } })
  const setEveryAndSave = (v: number) => { setEvery(v); try { localStorage.setItem('netmap-refresh', String(v)) } catch { /* storage unavailable */ } }
  return (
    <div className="p-6 space-y-4 max-w-[1700px]">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Waypoints size={20} className="text-indigo-600" /> {t('netmap.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('netmap.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-slate-500 inline-flex items-center gap-1.5">{t('netmap.auto')}
            <select value={every} onChange={e => setEveryAndSave(Number(e.target.value))} className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white">
              <option value={0}>{t('netmap.autoOff')}</option>{[30, 60, 120].map(s => <option key={s} value={s}>{s} s</option>)}
            </select>
          </label>
          <Button size="sm" variant="secondary" disabled={rebuild.isPending} onClick={() => rebuild.mutate()}>{rebuild.isPending || isFetching ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />} {t('netmap.rebuild')}</Button>
        </div>
      </div>
      {data?.partial && <div className="text-sm bg-amber-50 border border-amber-200 text-amber-900 rounded-lg px-4 py-2">{t('netmap.partial')}</div>}
      {isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : (
        <>
          <p className="text-xs text-slate-400">{t('netmap.counts', { nodes: data?.nodes.length ?? 0, edges: data?.edges.length ?? 0, subnets: data?.subnets.length ?? 0 })}{data?.at ? ` · ${new Date(data.at).toLocaleTimeString()}` : ''}</p>
          <NetworkGraph nodes={data?.nodes ?? []} edges={data?.edges ?? []} assetHref={id => `/inventory/${id}`} onRename={(id, name) => rename.mutate({ id, name })} />
        </>
      )}
    </div>
  )
}

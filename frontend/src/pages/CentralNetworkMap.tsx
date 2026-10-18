import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Waypoints } from 'lucide-react'
import { centralApi, centralConfig, netmapFromCentral, type CentralNetMap } from '../lib/api'
import { NetworkGraph } from '../components/NetworkGraph'

// The network map of one client, as its agent last reported it (read-only; the agent page can rename devices).
export function CentralNetworkMap() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [parts, setParts] = useState<Array<{ tenant: string; lastSeen: string | null; map: CentralNetMap }>>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenant, setTenant] = useState('')

  const reload = async () => {
    try {
      const r = await centralApi.topologyStatusAll()
      setParts(r.tenants.filter(x => x.map && Array.isArray(x.map.n) && x.map.n.length > 0).map(x => ({ tenant: x.tenant, lastSeen: x.last_seen, map: x.map! })))
      setErr(null)
    } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }
  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    void reload()
    const iv = setInterval(() => void reload(), 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  useEffect(() => { if (parts.length && !parts.some(p => p.tenant === tenant)) setTenant(parts[0].tenant) }, [parts, tenant])
  const part = parts.find(p => p.tenant === tenant)
  const g = useMemo(() => part ? netmapFromCentral(part.map) : null, [part])
  return (
    <div className="p-6 space-y-4 max-w-[1700px]">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Waypoints size={20} className="text-indigo-600" /> {t('netmap.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('netmap.centralIntro')}</p>
        </div>
        {parts.length > 0 && (
          <select value={tenant} onChange={e => setTenant(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white">
            {parts.map(p => p.tenant).sort().map(tn => <option key={tn} value={tn}>{tn}</option>)}
          </select>
        )}
      </div>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}
      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : !g ? <p className="text-sm text-slate-500">{t('netmap.centralNoData')}</p> : (
        <>
          <p className="text-xs text-slate-400">{t('netmap.counts', { nodes: g.nodes.length, edges: g.edges.length, subnets: new Set(g.nodes.map(n => n.sub).filter(Boolean)).size })} · {new Date(part!.map.at).toLocaleString()}</p>
          <NetworkGraph nodes={g.nodes} edges={g.edges} persistKey="netmap-central" />
        </>
      )}
    </div>
  )
}

import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { racksApi, rackFromAgent, type RackView } from '../lib/api'
import { RackWorkspace, type RackOps } from '../components/RackWorkspace'
import { Button } from '../components/ui/Button'
import { RefreshCw, Loader2 } from 'lucide-react'

// The agent's rack page: the data comes straight from the agent (placement from its database, ports / neighbours read live from the routers).
export function Racks() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['racks'], queryFn: racksApi.list })
  const [rackId, setRackId] = useState<number | null>(null)
  useEffect(() => {
    const racks = list.data ?? []
    if (racks.length && (rackId == null || !racks.some(r => r.id === rackId))) setRackId(racks[0].id)
    if (!racks.length && rackId != null) setRackId(null)
  }, [list.data, rackId])

  const detail = useQuery({ queryKey: ['rack', rackId], queryFn: () => racksApi.get(rackId!), enabled: rackId != null })
  const live = useQuery({ queryKey: ['rack-live', rackId], queryFn: () => racksApi.live(rackId!), enabled: rackId != null, refetchInterval: 30_000, retry: false })
  const palette = useQuery({ queryKey: ['rack-palette', rackId], queryFn: () => racksApi.palette(rackId ?? undefined), enabled: rackId != null })
  const rack: RackView | null = useMemo(() => detail.data ? rackFromAgent(detail.data, live.data) : null, [detail.data, live.data])

  const changed = () => { for (const k of ['racks', 'rack', 'rack-live', 'rack-palette']) void qc.invalidateQueries({ queryKey: [k] }) }
  const after = async (p: Promise<unknown>) => { await p; changed() }
  const ops: RackOps = {
    createRack: async b => { const r = await racksApi.create(b); setRackId(r.id); changed() },
    updateRack: (id, b) => after(racksApi.update(id, b)),
    removeRack: (id) => after(racksApi.remove(id)),
    addSuggested: async id => { const r = await racksApi.addSuggested(id); changed(); return t('racks.suggestedAdded', { count: r.placed }) as string },
    addItem: (rid, b) => after(racksApi.addItem(rid, b)),
    updateItem: (id, b) => after(racksApi.updateItem(id, b)),
    removeItem: (id) => after(racksApi.removeItem(id)),
    addLink: (rid, b) => after(racksApi.addLink(rid, b)),
    removeLink: (id) => after(racksApi.removeLink(id)),
  }
  return (
    <RackWorkspace
      racks={list.data ?? []} rackId={rackId} onRackId={setRackId} rack={rack} palette={palette.data ?? []} paletteLoading={palette.isLoading} loading={list.isLoading}
      ops={ops} assetHref={id => `/inventory/${id}`}
      toolbar={rackId != null && <Button size="sm" variant="ghost" onClick={changed}>{live.isFetching ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />} {t('racks.refresh')}</Button>}
    />
  )
}

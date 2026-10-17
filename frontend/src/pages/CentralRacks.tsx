import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, rackFromCentral, type AssetType, type CentralRack, type CentralRackOp, type RackPaletteAsset, type RackSummary, type RackView } from '../lib/api'
import { RackWorkspace, type RackOps } from '../components/RackWorkspace'
import { Rows3 } from 'lucide-react'

type Part = { tenant: string; lastSeen: string | null; racks: CentralRack[]; ops: CentralRackOp[]; assets: Array<{ id: number; n: string; t: string; r: string | null; ip: string | null; md: string | null; loc: string | null; seen: number | null }> }

const WEEK = 7 * 86400

type Pending = { op: Record<string, any>; at: number }

// What the agent will show once it has applied the queued changes, drawn right away so that Central does not look as if nothing happened.
// Dropped as soon as the agent has reported a result (its operation log is newer than the request) - the real data takes over.
function withPending(view: RackView, pending: Pending[], assets: Part['assets']): RackView {
  let v = view
  let temp = 0
  for (const { op } of pending) {
    if (op.op === 'item_add' && op.rack_id === v.id) {
      const a = op.asset_id != null ? assets.find(x => x.id === op.asset_id) : undefined
      v = { ...v, items: [...v.items, { id: -(1000 + temp++), kind: op.kind ?? 'asset', label: op.label ?? a?.n ?? '', u: op.u, height: op.height ?? 1, portCount: op.port_count ?? null, pending: true,
        asset: a ? { id: a.id, type: a.t as AssetType, role: a.r, ip: a.ip, model: a.md, online: null } : null, ports: [], nics: [] }] }
    } else if (op.op === 'item_update' && v.items.some(i => i.id === op.id)) {
      v = { ...v, items: v.items.map(i => i.id === op.id ? { ...i, u: op.u ?? i.u, height: op.height ?? i.height, label: op.label ?? i.label, pending: true } : i) }
    } else if (op.op === 'item_delete') {
      v = { ...v, items: v.items.filter(i => i.id !== op.id), links: v.links.filter(l => l.a !== op.id && l.b !== op.id) }
    } else if (op.op === 'link_add' && op.rack_id === v.id) {
      v = { ...v, links: [...v.links, { id: null, a: op.item_a_id, aPort: op.port_a ?? null, b: op.item_b_id ?? null, bPort: op.port_b ?? null, remote: op.remote_text ?? null, label: op.label ?? null, cable: op.cable ?? null, kind: 'manual' }] }
    } else if (op.op === 'link_delete') {
      v = { ...v, links: v.links.filter(l => l.id !== op.id) }
    }
  }
  return v
}

// The racks of one client, as its agent last reported them (placement, ports, what is plugged into what) - and the place to arrange them:
// every change is queued at Central as a command and the agent applies it on its next synchronisation (max ~2 min); the view then
// updates from the agent's next report. Pick the client at the top, then one of its racks.
export function CentralRacks() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [parts, setParts] = useState<Part[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenant, setTenant] = useState('')
  const [rackId, setRackId] = useState<number | null>(null)
  const [queued, setQueued] = useState(0)
  const [pending, setPending] = useState<Pending[]>([])

  const reload = async () => {
    try {
      const [r, a] = await Promise.all([centralApi.racksStatusAll(), centralApi.assetsStatusAll().catch(() => null)])
      const assets = new Map((a?.tenants ?? []).map(x => [x.tenant, (x.assets?.rows ?? []).filter(row => row.id != null) as unknown as Part['assets']]))
      setParts(r.tenants.filter(x => x.racks).map(x => ({ tenant: x.tenant, lastSeen: x.last_seen, racks: x.racks!.racks ?? [], ops: x.racks!.ops ?? [], assets: assets.get(x.tenant) ?? [] })))
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    reload()
    const iv = setInterval(reload, queued > 0 ? 15000 : 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queued > 0])

  useEffect(() => {
    if (!parts.length) return
    const p = parts.find(x => x.tenant === tenant) ?? parts[0]
    if (p.tenant !== tenant) setTenant(p.tenant)
    if (rackId != null && rackId < 0) return                        // a rack still on its way: keep it selected until the agent reports it
    if (!p.racks.some(r => r.id === rackId)) setRackId(p.racks[0]?.id ?? null)
  }, [parts, tenant, rackId])

  const part = parts.find(p => p.tenant === tenant)
  // racks asked for but not yet reported by the agent are drawn at once (empty, ids below zero) so that devices can be put into them right away
  const virtualRacks = useMemo(() => {
    const known = new Set((part?.racks ?? []).map(r => r.n))
    return pending.filter(p => p.op.op === 'rack_create' && !known.has(String(p.op.name))).map((p, i) => ({ id: -(i + 1), name: String(p.op.name), location: (p.op.location as string | null) ?? null, units: Number(p.op.units) || 42 }))
  }, [pending, part])
  const virtual = rackId != null && rackId < 0 ? virtualRacks.find(v => v.id === rackId) : undefined
  const raw = part?.racks.find(r => r.id === rackId)
  // a queued change stays drawn until the agent's log shows a result newer than the request
  useEffect(() => {
    const done = Math.max(0, ...(part?.ops ?? []).map(o => o.at))
    setPending(p => { const keep = p.filter(x => x.at > done); return keep.length === p.length ? p : keep })
  }, [part])
  // the rack the agent has reported under the name of the one that was waiting: switch to it
  useEffect(() => {
    if (rackId != null && rackId < 0 && !virtual) setRackId(null)
  }, [rackId, virtual])
  const rack = useMemo(() => {
    const base = raw ? rackFromCentral(raw) : virtual ? { id: virtual.id, name: virtual.name, location: virtual.location, units: virtual.units, items: [], links: [] } as RackView : null
    return base ? withPending(base, pending, part?.assets ?? []) : null
  }, [raw, virtual, pending, part])
  const summaries: RackSummary[] = useMemo(() => [
    ...(part?.racks ?? []).map(r => ({ id: r.id, name: r.n, location: r.loc, units: r.u, notes: r.nt ?? null, items: r.items.length, used_u: r.items.reduce((n, i) => n + i.h, 0) })),
    ...virtualRacks.map(v => ({ id: v.id, name: `${v.name} ⏳`, location: v.location, units: v.units, notes: null, items: 0, used_u: pending.filter(p => p.op.op === 'item_add' && p.op.rack_id === v.id).reduce((n, p) => n + (Number(p.op.height) || 1), 0) })),
  ], [part, virtualRacks, pending])

  // what can still be put into a rack: the client's devices (as the inventory reports them) that no rack of that client holds yet
  const palette: RackPaletteAsset[] = useMemo(() => {
    if (!part) return []
    const placed = new Set(part.racks.flatMap(r => r.items.map(i => i.a?.id)).filter((x): x is number => x != null))
    const loc = (raw?.loc ?? virtual?.location)?.trim().toLowerCase()
    const now = Date.now() / 1000
    const byId = new Map(part.assets.map(a => [a.id, a]))
    return part.assets.filter(a => !placed.has(a.id) && ['network', 'server', 'windows', 'linux', 'printer', 'other'].includes(a.t)).map(a => {
      const infra = a.t === 'network' || a.t === 'server' || a.r === 'server'
      return { id: a.id, name: a.n, type: a.t as RackPaletteAsset['type'], role: a.r, ip: a.ip, model: a.md, location: a.loc, infra, suggested: !!loc && !!a.loc && a.loc.trim().toLowerCase() === loc }
    }).filter(a => a.infra || !byId.get(a.id)?.seen || now - byId.get(a.id)!.seen! < WEEK).sort((x, y) => Number(y.suggested) - Number(x.suggested) || Number(y.infra) - Number(x.infra) || x.name.localeCompare(y.name))
  }, [part, raw, virtual])

  const send = async (op: Record<string, unknown>) => {
    await centralApi.requestRackOp(tenant, JSON.stringify(op))
    setQueued(n => n + 1)
    setPending(p => [...p, { op, at: Math.floor(Date.now() / 1000) - 5 }])
  }
  const waiting = () => { throw new Error(t('racks.waitingForAgent') as string) }
  const ops: RackOps = {
    createRack: async b => {
      await send({ op: 'rack_create', name: b.name, location: b.location ?? null, units: b.units, notes: b.notes ?? null })
      setRackId(-(virtualRacks.length + 1))                         // open the new rack at once (it is drawn while it waits for the agent)
    },
    updateRack: (id, b) => id < 0 ? waiting() : send({ op: 'rack_update', id, name: b.name, location: b.location ?? null, units: b.units, notes: b.notes ?? null }),
    removeRack: id => id < 0 ? waiting() : send({ op: 'rack_delete', id }),
    addSuggested: id => send({ op: 'rack_suggested', id, ...(id < 0 ? { rack_name: virtualRacks.find(v => v.id === id)?.name } : {}) }),
    addItem: (rid, b) => send({ op: 'item_add', rack_id: rid, ...(rid < 0 ? { rack_name: virtualRacks.find(v => v.id === rid)?.name } : {}), ...b }),
    updateItem: (id, b) => id < 0 ? waiting() : send({ op: 'item_update', id, ...b }),
    removeItem: id => id < 0 ? waiting() : send({ op: 'item_delete', id }),
    addLink: (rid, b) => (rid < 0 || b.item_a_id < 0 || (b.item_b_id ?? 0) < 0) ? waiting() : send({ op: 'link_add', rack_id: rid, ...b }),
    removeLink: id => send({ op: 'link_delete', id }),
  }

  const lastOps = (part?.ops ?? []).slice(-3).reverse()
  // changes queued a while ago with no result from the agent since: it has not answered (too old, not restarted, offline)
  const silent = pending.some(p => Date.now() / 1000 - p.at > 360)
  const sel = 'text-sm border border-slate-300 rounded-lg px-2 py-1.5 bg-white'
  if (loading) return <div className="p-6"><p className="text-sm text-slate-500">{t('common.loading')}</p></div>
  return (
    <div className="space-y-0">
      {err && <div className="mx-6 mt-6 text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}
      {parts.length === 0 ? (
        <div className="p-6"><h1 className="text-lg font-semibold text-slate-900 flex items-center gap-2"><Rows3 size={20} className="text-indigo-600" /> {t('racks.title')}</h1><p className="text-sm text-slate-500 mt-2">{t('racks.centralNoData')}</p></div>
      ) : (
        <RackWorkspace
          racks={summaries} rackId={rackId} onRackId={setRackId} rack={rack} palette={palette} loading={false} ops={ops}
          subtitle={t('racks.centralIntro') as string} queuedNote={t('racks.queued') as string}
          leading={
            <select value={tenant} onChange={e => { setTenant(e.target.value); setRackId(null) }} className={sel} aria-label={t('assetsCentral.client') as string}>
              {parts.map(p => p.tenant).sort().map(tn => <option key={tn} value={tn}>{tn}</option>)}
            </select>}
          toolbar={<button onClick={reload} className="text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>}
          notice={(queued > 0 || lastOps.length > 0 || silent) && (
            <div className="text-xs bg-slate-50 border border-slate-200 rounded-lg px-4 py-2 space-y-1">
              {silent && <p className="text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1">{t('racks.agentSilent')}</p>}
              {queued > 0 && <p className="text-slate-700">{t('racks.centralQueued', { count: queued })}</p>}
              {part?.lastSeen && <p className="text-slate-400">{t('racks.centralSeen', { when: new Date(part.lastSeen.replace(' ', 'T') + (part.lastSeen.includes('Z') ? '' : 'Z')).toLocaleString() })}</p>}
              {lastOps.map((o, i) => <p key={i} className={o.ok ? 'text-slate-500' : 'text-red-700'}>{new Date(o.at * 1000).toLocaleTimeString()} · {o.op} · {o.ok ? 'OK' : o.error}</p>)}
            </div>
          )}
        />
      )}
    </div>
  )
}

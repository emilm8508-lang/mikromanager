import { useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Cable, BatteryCharging, Plug, Network, Square, Rows3 } from 'lucide-react'
import type { AssetType, RackItemView, RackLinkView, RackPort, RackView } from '../lib/api'
import { TypeIcon, TYPE_COLOR } from './AssetBits'
import { cn } from '../lib/utils'

// The rack diagram and the panel of one device - shared by the agent page (editable) and Central (read-only).
// A rack is drawn from the top: the highest unit first. `u` of an item is its lowest unit (1 = bottom).

export const UH = 26                                    // px per rack unit
const RULER = 26
const GUTTER = 64                                       // room on the right for the cables

export const KIND_COLOR: Record<string, string> = {
  patch_panel: '#7a8ca3', switch: '#1baf7a', ups: '#c58b00', pdu: '#c58b00', cable_manager: '#9aa5b1', shelf: '#9aa5b1', blank: '#cbd5e1', other: '#898781',
}
const KIND_ICON: Record<string, typeof Cable> = { patch_panel: Cable, ups: BatteryCharging, pdu: Plug, switch: Network, cable_manager: Rows3, shelf: Square, blank: Square, other: Square }
export const LINK_COLOR: Record<string, string> = { lldp: '#2a78d6', mac: '#1baf7a', manual: '#eb6834' }

export function itemColor(i: RackItemView): string {
  return i.asset ? TYPE_COLOR[i.asset.type as AssetType] ?? '#898781' : KIND_COLOR[i.kind] ?? '#898781'
}

// what is being dragged right now (dragover cannot read dataTransfer, so the height is kept here)
let dragHeight = 1
export function startRackDrag(e: React.DragEvent, type: 'asset' | 'kind' | 'item', value: string | number, height: number) {
  dragHeight = height
  e.dataTransfer.setData(`application/x-rack-${type}`, String(value))
  e.dataTransfer.effectAllowed = 'move'
}

export interface RackEditHooks {
  onDropAsset: (u: number, assetId: number) => void
  onDropKind: (u: number, kind: string) => void
  onMove: (itemId: number, u: number) => void
}

const portColor = (p: RackPort) => p.disabled ? '#e5a3a3' : p.up === true ? '#1baf7a' : p.up === false ? '#cbd5e1' : '#ffffff'

export function itemTitle(i: RackItemView): string {
  return i.label || i.asset?.ip || ''
}

export function RackDiagram({ rack, selectedId, selectedPort, onSelect, edit }: {
  rack: RackView; selectedId: number | null; selectedPort: string | null
  onSelect: (id: number | null, port?: string | null) => void; edit?: RackEditHooks
}) {
  const { t } = useTranslation()
  const body = useRef<HTMLDivElement>(null)
  const [ghost, setGhost] = useState<{ u: number; h: number } | null>(null)
  const height = rack.units * UH
  const byId = useMemo(() => new Map(rack.items.map(i => [i.id, i])), [rack.items])
  const top = (i: RackItemView) => (rack.units - (i.u + i.height - 1)) * UH
  const mid = (i: RackItemView) => top(i) + (i.height * UH) / 2

  const related = useMemo(() => {
    const s = new Set<number>()
    if (selectedId == null) return s
    for (const l of rack.links) {
      if (l.a === selectedId && l.b != null) s.add(l.b)
      if (l.b === selectedId) s.add(l.a)
    }
    return s
  }, [rack.links, selectedId])

  // the unit under the pointer -> the lowest unit of a thing of `h` units that has its top there
  const slot = (e: React.DragEvent): { u: number; h: number } | null => {
    const el = body.current
    if (!el) return null
    const row = Math.floor((e.clientY - el.getBoundingClientRect().top) / UH)
    const h = dragHeight
    const u = Math.max(1, Math.min(rack.units - h + 1, rack.units - row - h + 1))
    return { u, h }
  }
  const drop = (e: React.DragEvent) => {
    e.preventDefault()
    const s = slot(e)
    setGhost(null)
    if (!s || !edit) return
    const a = e.dataTransfer.getData('application/x-rack-asset')
    const k = e.dataTransfer.getData('application/x-rack-kind')
    const m = e.dataTransfer.getData('application/x-rack-item')
    if (a) edit.onDropAsset(s.u, Number(a))
    else if (k) edit.onDropKind(s.u, k)
    else if (m) edit.onMove(Number(m), s.u)
  }

  const arcs = rack.links.flatMap((l, idx) => {
    const a = byId.get(l.a), b = l.b != null ? byId.get(l.b) : undefined
    if (!a || !b) return []
    const y1 = mid(a), y2 = mid(b)
    const bulge = 8 + Math.min(44, Math.abs(y2 - y1) / 7) + (idx % 3) * 4
    const on = selectedId != null && (l.a === selectedId || l.b === selectedId)
    const dim = selectedId != null && !on
    return [{ l, d: `M0,${y1} C${bulge},${y1} ${bulge},${y2} 0,${y2}`, on, dim }]
  })

  return (
    <div className="inline-block">
      <div className="flex" style={{ paddingRight: GUTTER }}>
        <div style={{ width: RULER }} className="shrink-0 select-none">
          {Array.from({ length: rack.units }, (_, r) => rack.units - r).map(u => (
            <div key={u} style={{ height: UH }} className="text-[10px] leading-none text-slate-400 text-right pr-1.5 flex items-center justify-end">{u}</div>
          ))}
        </div>
        <div className="relative">
          <div ref={body} className="relative w-[34rem] max-w-full rounded-sm border-2 border-slate-400 bg-slate-100"
            style={{ height, backgroundImage: `repeating-linear-gradient(to bottom, transparent 0, transparent ${UH - 1}px, #dbe2ea ${UH - 1}px, #dbe2ea ${UH}px)` }}
            onClick={() => onSelect(null)}
            onDragOver={e => { if (edit) { e.preventDefault(); setGhost(slot(e)) } }}
            onDragLeave={() => setGhost(null)}
            onDrop={drop}>
            {ghost && <div className="absolute left-0 right-0 bg-indigo-300/40 border border-dashed border-indigo-500 pointer-events-none" style={{ top: (rack.units - (ghost.u + ghost.h - 1)) * UH, height: ghost.h * UH }} />}
            {rack.items.map(i => <ItemBlock key={i.id} item={i} byId={byId} top={top(i)} selected={selectedId === i.id} related={related.has(i.id)}
              selectedPort={selectedId === i.id ? selectedPort : null} onSelect={onSelect} draggable={!!edit} />)}
          </div>
          <svg className="absolute top-0 pointer-events-none" style={{ left: '100%', width: GUTTER, height }} aria-hidden>
            {arcs.map(({ l, d, on, dim }, i) => (
              <path key={i} d={d} fill="none" stroke={LINK_COLOR[l.kind] ?? '#898781'} strokeWidth={on ? 2.4 : 1.4} opacity={dim ? 0.18 : on ? 1 : 0.6} strokeDasharray={l.kind === 'manual' ? '5 3' : undefined} />
            ))}
          </svg>
        </div>
      </div>
      <div className="flex items-center gap-3 flex-wrap text-[11px] text-slate-500 mt-2" style={{ paddingLeft: RULER }}>
        <Legend color="#1baf7a" label={t('racks.legend.up') as string} /><Legend color="#cbd5e1" label={t('racks.legend.down') as string} /><Legend color="#e5a3a3" label={t('racks.legend.disabled') as string} />
        <span className="mx-1 text-slate-300">|</span>
        {(['lldp', 'mac', 'manual'] as const).map(k => <span key={k} className="inline-flex items-center gap-1"><span className="inline-block w-4 border-t-2" style={{ borderColor: LINK_COLOR[k], borderStyle: k === 'manual' ? 'dashed' : 'solid' }} />{t(`racks.link.${k}`)}</span>)}
      </div>
    </div>
  )
}

function Legend({ color, label }: { color: string; label: string }) {
  return <span className="inline-flex items-center gap-1"><span className="inline-block w-2.5 h-2.5 rounded-[2px] border border-slate-300" style={{ background: color }} />{label}</span>
}

function ItemBlock({ item, byId, top, selected, related, selectedPort, onSelect, draggable }: {
  item: RackItemView; byId: Map<number, RackItemView>; top: number; selected: boolean; related: boolean; selectedPort: string | null
  onSelect: (id: number | null, port?: string | null) => void; draggable: boolean
}) {
  const color = itemColor(item)
  const Icon = KIND_ICON[item.kind]
  const ports = item.ports
  const box = item.height >= 2 ? 11 : 8
  const nicLink = item.nics.find(n => n.connected)
  const online = item.asset?.online
  return (
    <div
      draggable={draggable}
      onDragStart={e => { e.stopPropagation(); startRackDrag(e, 'item', item.id, item.height) }}
      onClick={e => { e.stopPropagation(); onSelect(item.id) }}
      className={cn('absolute left-0 right-0 flex items-center gap-2 pl-2 pr-1.5 overflow-hidden bg-white border border-slate-300 rounded-[3px] cursor-pointer hover:border-slate-500',
        selected && 'ring-2 ring-indigo-500 z-10', !selected && related && 'ring-2 ring-amber-400 z-10', draggable && 'active:opacity-70', item.pending && 'opacity-60 border-dashed')}
      style={{ top: top + 1, height: item.height * UH - 2, borderLeft: `5px solid ${color}` }}
      title={[item.label, item.asset?.ip, item.asset?.model].filter(Boolean).join(' · ')}
    >
      <span className="shrink-0 text-slate-600">{item.asset ? <TypeIcon type={item.asset.type as AssetType} size={14} /> : Icon ? <Icon size={14} /> : null}</span>
      <span className="min-w-0 w-40 shrink-0">
        <span className="flex items-center gap-1.5 text-[12px] leading-tight font-medium text-slate-800 truncate">
          {online != null && <span className={cn('inline-block w-1.5 h-1.5 rounded-full shrink-0', online ? 'bg-emerald-500' : 'bg-red-500')} />}
          <span className="truncate">{itemTitle(item)}</span>
        </span>
        {item.height >= 2 && <span className="block text-[10px] leading-tight text-slate-400 truncate">{[item.asset?.ip, item.asset?.model].filter(Boolean).join(' · ')}</span>}
      </span>
      <span className="flex flex-wrap gap-[2px] justify-end content-center flex-1 min-w-0 self-center">
        {ports.map(p => (
          <button key={p.name} type="button" onClick={e => { e.stopPropagation(); onSelect(item.id, p.name) }}
            title={[p.name, p.speed, p.poe?.on ? 'PoE' + (p.poe.watts != null ? ` ${p.poe.watts} W` : '') : null, p.remote?.name].filter(Boolean).join(' · ')}
            className={cn('rounded-[2px] border', selectedPort === p.name ? 'border-indigo-600 ring-1 ring-indigo-500' : p.poe?.on ? 'border-amber-500 border-2' : p.remote ? 'border-slate-700' : 'border-slate-400')}
            style={{ width: box, height: box, background: portColor(p) }} />
        ))}
        {ports.length === 0 && item.portCount ? Array.from({ length: Math.min(item.portCount, 96) }, (_, n) => (
          <span key={n} className="rounded-[2px] border border-slate-400 bg-white" style={{ width: box, height: box }} />)) : null}
        {ports.length === 0 && !item.portCount && nicLink?.connected && (
          <span className="text-[10px] text-slate-500 truncate">→ {byId.get(nicLink.connected.item_id)?.label}:{nicLink.connected.port}</span>
        )}
      </span>
    </div>
  )
}

const hasPoe = (ports: RackPort[]) => ports.some(p => p.poe)
function PoeCell({ p }: { p: RackPort }) {
  const { t } = useTranslation()
  const o = p.poe
  if (!o) return <span className="text-slate-300">—</span>
  if (o.off) return <span className="text-slate-400">{t('racks.poe.off')}</span>
  if (o.on) return <span className="text-amber-700 font-medium whitespace-nowrap">⚡ {o.watts != null ? `${o.watts} W` : t('racks.poe.on')}</span>
  if (o.status === 'fault') return <span className="text-red-600">{t('racks.poe.fault')}</span>
  return <span className="text-slate-500">{t('racks.poe.idle')}</span>
}
const fmtMbps = (v: number | null | undefined) => v == null ? '' : v < 1 ? `${Math.round(v * 1000)} kb/s` : `${v.toFixed(1)} Mb/s`

export function RackItemPanel({ rack, item, selectedPort, onSelect, assetHref, children }: {
  rack: RackView; item: RackItemView; selectedPort: string | null
  onSelect: (id: number | null, port?: string | null) => void; assetHref?: (assetId: number) => string | null; children?: React.ReactNode
}) {
  const { t } = useTranslation()
  const [onlyBusy, setOnlyBusy] = useState(true)
  const byAsset = useMemo(() => new Map(rack.items.filter(i => i.asset).map(i => [i.asset!.id, i])), [rack.items])
  const byId = useMemo(() => new Map(rack.items.map(i => [i.id, i])), [rack.items])
  const links = rack.links.filter(l => l.a === item.id || l.b === item.id)
  const many = item.ports.length > 16
  const poe = hasPoe(item.ports)
  const rows = item.ports.filter(p => !(many && onlyBusy) || p.remote || p.up)
  const color = itemColor(item)
  const href = item.asset && assetHref ? assetHref(item.asset.id) : null
  const jump = (assetId?: number | null) => { const t2 = assetId != null ? byAsset.get(assetId) : undefined; if (t2) onSelect(t2.id) }
  const other = (l: RackLinkView) => {
    const mine = l.a === item.id
    const oid = mine ? l.b : l.a
    return { item: oid != null ? byId.get(oid) : undefined, myPort: mine ? l.aPort : l.bPort, port: mine ? l.bPort : l.aPort }
  }
  return (
    <div className="space-y-3">
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden" style={{ borderTop: `3px solid ${color}` }}>
        <div className="px-4 py-3 flex items-center gap-2">
          {item.asset ? <TypeIcon type={item.asset.type as AssetType} size={20} /> : null}
          <div className="min-w-0 flex-1">
            <h3 className="text-base font-semibold text-slate-900 truncate">{itemTitle(item)}</h3>
            <p className="text-xs text-slate-500">U{item.u}{item.height > 1 ? `–U${item.u + item.height - 1}` : ''} · {item.asset ? t(`assets.type.${item.asset.type}`) : t(`racks.kind.${item.kind}`)}</p>
          </div>
          {item.asset?.online != null && <span className={cn('text-xs px-2 py-0.5 rounded-full', item.asset.online ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700')}>{item.asset.online ? t('racks.online') : t('racks.offline')}</span>}
        </div>
        {item.asset && (
          <dl className="px-4 pb-3 text-sm grid grid-cols-[6rem_1fr] gap-y-1">
            {item.asset.ip && <><dt className="text-slate-400">IP</dt><dd className="font-mono text-slate-700">{item.asset.ip}</dd></>}
            {(item.asset.manufacturer || item.asset.model) && <><dt className="text-slate-400">{t('assets.model')}</dt><dd className="text-slate-700">{[item.asset.manufacturer, item.asset.model].filter(Boolean).join(' · ')}</dd></>}
          </dl>
        )}
        {href && <div className="px-4 pb-3"><a href={href} className="text-xs text-indigo-600 hover:underline">{t('racks.openAsset')}</a></div>}
      </div>

      {item.error && <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">{t('racks.noLive')}: {item.error}</p>}

      {item.ports.length > 0 && (
        <section className="bg-white border border-slate-200 rounded-xl">
          <div className="px-4 py-2.5 border-b border-slate-100 flex items-center gap-3">
            <h4 className="text-sm font-semibold text-slate-800">{t('racks.ports')} ({item.ports.length})</h4>
            {item.poeTotal && <span className="text-xs text-amber-700">{t('racks.poe.budget', { used: item.poeTotal.used_w, total: item.poeTotal.budget_w })}</span>}
            {many && <label className="text-xs text-slate-500 inline-flex items-center gap-1 ml-auto"><input type="checkbox" checked={onlyBusy} onChange={e => setOnlyBusy(e.target.checked)} />{t('racks.onlyBusy')}</label>}
          </div>
          <div className="max-h-[26rem] overflow-y-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-[11px] text-slate-400 border-b border-slate-100"><th className="pl-4 py-1.5 font-normal">{t('racks.port')}</th><th className="font-normal">{t('racks.speed')}</th><th className="font-normal">VLAN</th><th className="font-normal">{t('racks.traffic')}</th>{poe && <th className="font-normal">PoE</th>}<th className="font-normal pr-4">{t('racks.connectedTo')}</th></tr></thead>
              <tbody>
                {rows.map(p => {
                  const r = p.remote
                  const tgt = r?.assetId != null ? byAsset.get(r.assetId) : undefined
                  return (
                    <tr key={p.name} onClick={() => onSelect(item.id, p.name)} className={cn('border-b border-slate-50 cursor-pointer align-top', selectedPort === p.name ? 'bg-indigo-50' : 'hover:bg-slate-50')}>
                      <td className="pl-4 py-1.5 whitespace-nowrap"><span className="inline-block w-2.5 h-2.5 rounded-[2px] border border-slate-400 mr-1.5 align-middle" style={{ background: portColor(p) }} />{p.name}{p.comment && <span className="block text-[10px] text-slate-400 pl-4">{p.comment}</span>}</td>
                      <td className="text-xs text-slate-600 whitespace-nowrap">{p.speed ?? '—'}</td>
                      <td className="text-xs text-slate-600">{p.vlan ?? '—'}</td>
                      <td className="text-[11px] text-slate-500 whitespace-nowrap">{p.rx != null || p.tx != null ? <>↓{fmtMbps(p.rx)}<br />↑{fmtMbps(p.tx)}</> : '—'}</td>
                      {poe && <td className="text-xs"><PoeCell p={p} /></td>}
                      <td className="pr-4 text-xs">
                        {!r ? <span className="text-slate-300">—</span> : r.kind === 'multi' ? (
                          <span title={(r.hosts ?? []).map(h => `${h.name}${h.ip ? ` (${h.ip})` : ''}`).join('\n')} className="text-slate-600">{t('racks.multi', { count: r.count })}</span>
                        ) : (
                          <span>
                            {tgt ? <button className="text-indigo-600 hover:underline" onClick={e => { e.stopPropagation(); jump(r.assetId) }}>{r.name}</button> : <span className="text-slate-800">{r.name}</span>}
                            {r.port && <span className="text-slate-400"> · {r.port}</span>}
                            {r.ip && <span className="block font-mono text-[10px] text-slate-400">{r.ip}</span>}
                            <span className="inline-block ml-1 text-[9px] px-1 rounded text-white align-middle" style={{ background: LINK_COLOR[r.kind] }}>{t(`racks.link.${r.kind}`)}</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {item.nics.length > 0 && (
        <section className="bg-white border border-slate-200 rounded-xl">
          <h4 className="px-4 py-2.5 text-sm font-semibold text-slate-800 border-b border-slate-100">{t('racks.nics')}</h4>
          <ul className="divide-y divide-slate-100 text-sm">
            {item.nics.map((n, i) => {
              const sw = n.connected ? byId.get(n.connected.item_id) : undefined
              return (
                <li key={i} className="px-4 py-2 flex items-center gap-2">
                  <span className="min-w-0 flex-1"><span className="text-slate-800">{n.name ?? '—'}</span><span className="block font-mono text-[10px] text-slate-400">{n.ips.join(', ')}</span></span>
                  {sw && n.connected ? <button className="text-xs text-indigo-600 hover:underline" onClick={() => onSelect(sw.id, n.connected!.port)}>→ {sw.label} · {n.connected.port}{n.connected.vlan ? ` (VLAN ${n.connected.vlan})` : ''}</button> : <span className="text-xs text-slate-300">{t('racks.notFound')}</span>}
                </li>
              )
            })}
          </ul>
        </section>
      )}

      <section className="bg-white border border-slate-200 rounded-xl">
        <h4 className="px-4 py-2.5 text-sm font-semibold text-slate-800 border-b border-slate-100">{t('racks.connections')} ({links.length})</h4>
        {links.length === 0 ? <p className="px-4 py-3 text-sm text-slate-400">{t('racks.noConnections')}</p> : (
          <ul className="divide-y divide-slate-100 text-sm">
            {links.map((l, i) => {
              const o = other(l)
              return (
                <li key={`${l.id}:${i}`} className="px-4 py-2 flex items-center gap-2">
                  <span className="inline-block w-3 border-t-2 shrink-0" style={{ borderColor: LINK_COLOR[l.kind], borderStyle: l.kind === 'manual' ? 'dashed' : 'solid' }} />
                  <span className="min-w-0 flex-1">
                    <span className="text-slate-500">{o.myPort ?? '—'} ↔ </span>
                    {o.item ? <button className="text-indigo-600 hover:underline" onClick={() => onSelect(o.item!.id, o.port)}>{itemTitle(o.item)}</button> : <span className="text-slate-800">{l.remote ?? '—'}</span>}
                    {o.port && <span className="text-slate-500"> · {o.port}</span>}
                    {(l.label || l.cable) && <span className="block text-[11px] text-slate-400">{[l.label, l.cable ? t(`racks.cable.${l.cable}`) : null].filter(Boolean).join(' · ')}</span>}
                  </span>
                </li>
              )
            })}
          </ul>
        )}
      </section>
      {children}
    </div>
  )
}

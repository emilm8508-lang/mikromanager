import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { DataSet, Network } from 'vis-network/standalone'
import { Download, Maximize2, Image as ImageIcon } from 'lucide-react'
import type { AssetType } from '../lib/api'
import { TYPE_COLOR, TYPE_ORDER } from './AssetBits'
import { Button } from './ui/Button'
import { cn } from '../lib/utils'

// The map of the whole network: nodes are the assets, edges what the devices report (LLDP, the port a MAC was learned on, the subnet).
// Shared by the agent page and Central. Layouts: hierarchical (the levels come from the server: Internet, routers, switches, clients)
// and Force Atlas; dashed boxes mark the subnets; hovering shows the device, a double click renames it (agent page only).

export type MapNodeType = AssetType | 'subnet' | 'internet'
export interface MapNode { id: number | string; name: string; type: MapNodeType; role?: string | null; ip?: string | null; mf?: string | null; md?: string | null; v: number; vn?: number; sub: string | null; lvl: number | null }
export interface MapEdge { a: number | string; b: number | string; k: 'backbone' | 'uplink' | 'client' | 'l3' | 'vm'; l: string }

const SEV_COLOR = ['', '#2a78d6', '#c58b00', '#eb6834', '#d1342f']
export const EDGE_STYLE: Record<MapEdge['k'], { color: string; width: number; dashes: boolean | number[] }> = {
  backbone: { color: '#2a78d6', width: 3.5, dashes: false },
  uplink: { color: '#475569', width: 2.5, dashes: false },
  client: { color: '#94a3b8', width: 1.3, dashes: false },
  l3: { color: '#b6bfcc', width: 1.2, dashes: [5, 5] },
  vm: { color: '#8b5cf6', width: 1.4, dashes: [2, 4] },
}
const INFRA: MapNodeType[] = ['network', 'internet']

const nodeColor = (t: MapNodeType) => t === 'internet' ? '#0f172a' : t === 'subnet' ? '#cbd5e1' : TYPE_COLOR[t as AssetType] ?? '#898781'

function tooltip(n: MapNode, kind: string, edges: string[]): HTMLElement {
  const el = document.createElement('div')
  el.style.cssText = 'font:12px/1.4 system-ui;padding:6px 8px;max-width:260px'
  const row = (a: string, b?: string | null) => { if (!b) return; const d = document.createElement('div'); const s = document.createElement('b'); s.textContent = a + ' '; d.appendChild(s); d.appendChild(document.createTextNode(b)); el.appendChild(d) }
  const h = document.createElement('div'); h.style.fontWeight = '600'; h.textContent = n.name; el.appendChild(h)
  row('', [kind, n.ip].filter(Boolean).join(' · '))
  row('', [n.mf, n.md].filter(Boolean).join(' '))
  if (n.sub && n.type !== 'subnet') row('Subnet:', n.sub)
  if (n.v) row('Vulnerabilities:', `${n.vn ?? ''} (max ${['', 'low', 'medium', 'high', 'critical'][n.v]})`)
  edges.slice(0, 6).forEach(e => row('•', e))
  return el
}

export function mapToCsv(nodes: MapNode[], edges: MapEdge[]): string {
  const q = (v: unknown) => { const s = v == null ? '' : String(v); return `"${(s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s).replace(/"/g, '""')}"` }
  const byId = new Map(nodes.map(n => [String(n.id), n]))
  const lines = ['kind,id,name,type,ip,vendor,model,subnet,max_vulnerability,from,to,edge_type,port']
  nodes.forEach(n => lines.push(['node', n.id, n.name, n.type, n.ip, n.mf, n.md, n.sub, n.v, '', '', '', ''].map(q).join(',')))
  edges.forEach(e => lines.push(['edge', '', '', '', '', '', '', '', '', byId.get(String(e.a))?.name ?? e.a, byId.get(String(e.b))?.name ?? e.b, e.k, e.l].map(q).join(',')))
  return '﻿' + lines.join('\r\n')
}

export function NetworkGraph({ nodes, edges, assetHref, onRename, height = '70vh', persistKey = 'netmap' }: {
  nodes: MapNode[]; edges: MapEdge[]; assetHref?: (id: number) => string | null; onRename?: (id: number, name: string) => void; height?: string; persistKey?: string
}) {
  const { t } = useTranslation()
  const box = useRef<HTMLDivElement>(null)
  const net = useRef<Network | null>(null)
  const boxesOn = useRef(true)
  const [layout, setLayout] = useState<'hier' | 'force'>(() => { try { return (localStorage.getItem(`${persistKey}-layout`) as 'hier' | 'force') || 'hier' } catch { return 'hier' } })
  const [boxes, setBoxes] = useState(true)
  const [q, setQ] = useState('')
  const [onlyVuln, setOnlyVuln] = useState(false)
  const [types, setTypes] = useState<Set<string>>(new Set())
  const [picked, setPicked] = useState<MapNode | null>(null)
  boxesOn.current = boxes

  const typesPresent = useMemo(() => TYPE_ORDER.filter(k => nodes.some(n => n.type === k)), [nodes])
  const needle = q.trim().toLowerCase()
  const matches = (n: MapNode) =>
    (types.size === 0 || types.has(n.type) || INFRA.includes(n.type) || n.type === 'subnet')
    && (!onlyVuln || n.v > 0 || INFRA.includes(n.type))
    && (!needle || [n.name, n.ip, n.mf, n.md, n.sub].some(x => (x ?? '').toLowerCase().includes(needle)))

  const edgeText = useMemo(() => {
    const names = new Map(nodes.map(n => [String(n.id), n.name]))
    const m = new Map<string, string[]>()
    edges.forEach(e => {
      const kind = t(`netmap.edge.${e.k}`) as string
      m.set(String(e.a), [...(m.get(String(e.a)) ?? []), `${kind}: ${names.get(String(e.b)) ?? e.b}${e.l ? ` (${e.l})` : ''}`])
      m.set(String(e.b), [...(m.get(String(e.b)) ?? []), `${kind}: ${names.get(String(e.a)) ?? e.a}${e.l ? ` (${e.l})` : ''}`])
    })
    return m
  }, [nodes, edges, t])

  useEffect(() => {
    if (!box.current) return
    const data = {
      nodes: new DataSet(nodes.map(n => {
        const ok = matches(n)
        const infra = INFRA.includes(n.type)
        const sev = SEV_COLOR[n.v] || ''
        return {
          id: n.id, label: n.name.length > 22 ? n.name.slice(0, 21) + '…' : n.name, level: layout === 'hier' ? (n.lvl ?? 0) : undefined,
          shape: n.type === 'internet' ? 'star' : n.type === 'subnet' ? 'ellipse' : infra || n.type === 'network' ? 'square' : n.type === 'server' ? 'diamond' : 'dot',
          size: n.type === 'internet' ? 24 : n.type === 'network' ? 20 : n.type === 'subnet' ? 10 : 13,
          color: { background: nodeColor(n.type), border: sev || nodeColor(n.type), highlight: { background: nodeColor(n.type), border: '#111827' } },
          borderWidth: sev ? 4 : 1.5, font: { size: n.type === 'subnet' ? 10 : 12, color: '#1e293b', strokeWidth: 3, strokeColor: '#ffffff' },
          opacity: ok ? 1 : 0.12, title: tooltip(n, n.type === 'subnet' ? 'subnet' : n.type === 'internet' ? 'Internet' : (t(`assets.type.${n.type}`) as string), edgeText.get(String(n.id)) ?? []),
        }
      })),
      edges: new DataSet(edges.map((e, i) => {
        const st = EDGE_STYLE[e.k]
        return { id: i, from: e.a, to: e.b, color: { color: st.color, opacity: 0.9 }, width: st.width, dashes: st.dashes, smooth: layout === 'hier' ? { enabled: true, type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 } : { enabled: false }, title: `${t(`netmap.edge.${e.k}`)}${e.l ? ` · ${e.l}` : ''}` }
      })),
    }
    const options = layout === 'hier'
      ? { layout: { hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed', levelSeparation: 130, nodeSpacing: 110, treeSpacing: 150, shakeTowards: 'roots' } }, physics: { enabled: false } }
      : { layout: { hierarchical: { enabled: false } }, physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -60, springLength: 90 }, stabilization: { iterations: 200 } } }
    const network = new Network(box.current, data as never, { ...options, interaction: { hover: true, tooltipDelay: 150, navigationButtons: false }, edges: { arrows: { to: false } } } as never)
    net.current = network
    network.on('beforeDrawing', (ctx: CanvasRenderingContext2D) => {
      if (!boxesOn.current) return
      const groups = new Map<string, Array<number | string>>()
      nodes.forEach(n => { if (n.sub && n.type !== 'subnet' && n.type !== 'internet') groups.set(n.sub, [...(groups.get(n.sub) ?? []), n.id]) })
      groups.forEach((ids, cidr) => {
        const pos = network.getPositions(ids as never)
        const pts = Object.values(pos)
        if (pts.length < 2) return
        const xs = pts.map(p => p.x), ys = pts.map(p => p.y)
        const pad = 38, x0 = Math.min(...xs) - pad, y0 = Math.min(...ys) - pad, w = Math.max(...xs) - Math.min(...xs) + pad * 2, h = Math.max(...ys) - Math.min(...ys) + pad * 2
        ctx.save(); ctx.setLineDash([8, 6]); ctx.strokeStyle = '#94a3b8'; ctx.fillStyle = 'rgba(148,163,184,0.07)'; ctx.lineWidth = 1.5
        ctx.beginPath(); ctx.roundRect(x0, y0, w, h, 14); ctx.fill(); ctx.stroke()
        ctx.setLineDash([]); ctx.fillStyle = '#64748b'; ctx.font = '12px system-ui'; ctx.fillText(cidr, x0 + 10, y0 + 16); ctx.restore()
      })
    })
    network.on('click', params => { const id = params.nodes?.[0]; setPicked(id == null ? null : nodes.find(n => String(n.id) === String(id)) ?? null) })
    network.on('doubleClick', params => {
      const id = params.nodes?.[0]
      const n = nodes.find(x => String(x.id) === String(id))
      if (n && onRename && typeof n.id === 'number' && n.type !== 'subnet') {
        const name = window.prompt(t('netmap.rename') as string, n.name)
        if (name && name.trim() && name !== n.name) onRename(n.id, name.trim())
      }
    })
    return () => { network.destroy(); net.current = null }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, layout, q, onlyVuln, types, boxes, edgeText])

  const exportPng = () => {
    const canvas = box.current?.querySelector('canvas')
    if (!canvas) return
    const out = document.createElement('canvas')
    out.width = canvas.width; out.height = canvas.height
    const ctx = out.getContext('2d')!
    ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, out.width, out.height); ctx.drawImage(canvas, 0, 0)
    const a = document.createElement('a'); a.href = out.toDataURL('image/png'); a.download = 'network-map.png'; a.click()
  }
  const exportCsv = () => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([mapToCsv(nodes, edges)], { type: 'text/csv;charset=utf-8' }))
    a.download = 'network-map.csv'; a.click(); URL.revokeObjectURL(a.href)
  }
  const chip = (on: boolean) => cn('text-xs px-2 py-1 rounded-full border', on ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-300 hover:border-slate-400')
  const href = picked && typeof picked.id === 'number' ? assetHref?.(picked.id) : null

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('netmap.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56" />
        <div className="inline-flex rounded-lg border border-slate-300 overflow-hidden text-xs">
          {(['hier', 'force'] as const).map(l => (
            <button key={l} onClick={() => { setLayout(l); try { localStorage.setItem(`${persistKey}-layout`, l) } catch { /* storage unavailable */ } }}
              className={cn('px-3 py-1.5', layout === l ? 'bg-indigo-600 text-white' : 'bg-white text-slate-600 hover:bg-slate-50')}>{t(`netmap.layout.${l}`)}</button>
          ))}
        </div>
        <label className="text-xs text-slate-600 inline-flex items-center gap-1.5"><input type="checkbox" checked={boxes} onChange={e => setBoxes(e.target.checked)} />{t('netmap.subnets')}</label>
        <label className="text-xs text-slate-600 inline-flex items-center gap-1.5"><input type="checkbox" checked={onlyVuln} onChange={e => setOnlyVuln(e.target.checked)} />{t('netmap.onlyVuln')}</label>
        <span className="flex-1" />
        <Button size="sm" variant="ghost" onClick={() => net.current?.fit({ animation: true })}><Maximize2 size={13} /> {t('netmap.fit')}</Button>
        <Button size="sm" variant="secondary" onClick={exportPng}><ImageIcon size={13} /> PNG</Button>
        <Button size="sm" variant="secondary" onClick={exportCsv}><Download size={13} /> CSV</Button>
      </div>
      <div className="flex items-center gap-1.5 flex-wrap">
        {typesPresent.map(k => <button key={k} className={chip(types.has(k))} onClick={() => setTypes(p => { const n = new Set(p); n.has(k) ? n.delete(k) : n.add(k); return n })}>{t(`assets.type.${k}`)}</button>)}
        {types.size > 0 && <button className="text-xs text-indigo-600 hover:underline ml-1" onClick={() => setTypes(new Set())}>{t('netmap.clearFilter')}</button>}
      </div>
      <div className="relative bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div ref={box} style={{ height }} className="w-full" />
        {nodes.length === 0 && <p className="absolute inset-0 flex items-center justify-center text-sm text-slate-400">{t('netmap.empty')}</p>}
        {picked && (
          <div className="absolute top-3 right-3 w-64 bg-white/95 border border-slate-200 rounded-lg shadow p-3 text-sm space-y-1">
            <div className="font-semibold text-slate-900 truncate">{picked.name}</div>
            <div className="text-xs text-slate-500">{[picked.type === 'subnet' ? 'subnet' : picked.type === 'internet' ? 'Internet' : t(`assets.type.${picked.type}`), picked.ip].filter(Boolean).join(' · ')}</div>
            {(picked.mf || picked.md) && <div className="text-xs text-slate-500">{[picked.mf, picked.md].filter(Boolean).join(' ')}</div>}
            {(edgeText.get(String(picked.id)) ?? []).slice(0, 8).map((x, i) => <div key={i} className="text-[11px] text-slate-600">• {x}</div>)}
            {href && <a href={href} className="inline-block text-xs text-indigo-600 hover:underline pt-1">{t('netmap.openAsset')}</a>}
          </div>
        )}
      </div>
      <div className="flex items-center gap-4 flex-wrap text-[11px] text-slate-500">
        {(Object.keys(EDGE_STYLE) as Array<MapEdge['k']>).map(k => (
          <span key={k} className="inline-flex items-center gap-1.5"><svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke={EDGE_STYLE[k].color} strokeWidth={Math.min(3, EDGE_STYLE[k].width)} strokeDasharray={Array.isArray(EDGE_STYLE[k].dashes) ? (EDGE_STYLE[k].dashes as number[]).join(' ') : undefined} /></svg>{t(`netmap.edge.${k}`)}</span>
        ))}
        <span className="text-slate-300">|</span>
        {[1, 2, 3, 4].map(s => <span key={s} className="inline-flex items-center gap-1"><span className="inline-block w-2.5 h-2.5 rounded-full border-2" style={{ borderColor: SEV_COLOR[s] }} />{t(`netmap.sev.${s}`)}</span>)}
        {onRename && <span className="text-slate-400">{t('netmap.renameHint')}</span>}
      </div>
    </div>
  )
}

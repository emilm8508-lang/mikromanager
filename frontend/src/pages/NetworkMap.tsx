import { useState, useRef, useMemo, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi, systemApi, TopologyNode, TopologyLink } from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { Network, Server, Move, RefreshCw, Link2 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

const NODE_W = 170
const NODE_H = 76

const linkTypeColor: Record<string, string> = {
  lldp: '#6366f1',   // indigo
  cdp: '#8b5cf6',    // violet
  mndp: '#22c55e',   // green
  eoip: '#f59e0b',   // amber
  gre: '#ef4444',    // red
  vxlan: '#06b6d4',  // cyan
  ipip: '#ec4899',   // pink
}

function nodeCenter(node: TopologyNode) {
  return { cx: node.x_pos + NODE_W / 2, cy: node.y_pos + NODE_H / 2 }
}

function DeviceNode({ node, onDragEnd, onlineLabel, offlineLabel }: {
  node: TopologyNode
  onDragEnd: (id: number, x: number, y: number) => void
  onlineLabel: string
  offlineLabel: string
}) {
  const dragRef = useRef<{ startX: number; startY: number; nodeX: number; nodeY: number } | null>(null)

  const onMouseDown = (e: React.MouseEvent) => {
    e.preventDefault()
    dragRef.current = { startX: e.clientX, startY: e.clientY, nodeX: node.x_pos, nodeY: node.y_pos }

    const onMove = (me: MouseEvent) => {
      if (!dragRef.current) return
      const dx = me.clientX - dragRef.current.startX
      const dy = me.clientY - dragRef.current.startY
      const el = document.getElementById(`node-${node.id}`)
      if (el) {
        el.style.transform = `translate(${dragRef.current.nodeX + dx}px, ${dragRef.current.nodeY + dy}px)`
      }
      // Dispatch a custom event so SVG layer redraws
      window.dispatchEvent(new CustomEvent('node-moved', {
        detail: { id: node.id, x: dragRef.current.nodeX + dx, y: dragRef.current.nodeY + dy }
      }))
    }

    const onUp = (ue: MouseEvent) => {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      if (!dragRef.current) return
      const dx = ue.clientX - dragRef.current.startX
      const dy = ue.clientY - dragRef.current.startY
      onDragEnd(node.id, dragRef.current.nodeX + dx, dragRef.current.nodeY + dy)
      dragRef.current = null
    }

    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }

  return (
    <div
      id={`node-${node.id}`}
      className="absolute select-none z-10"
      style={{ transform: `translate(${node.x_pos}px, ${node.y_pos}px)`, width: NODE_W }}
    >
      <div className={`bg-gray-900 border rounded-xl p-3 shadow-lg cursor-move transition-shadow hover:shadow-indigo-500/20 ${node.online ? 'border-gray-700' : 'border-red-900/50'}`}>
        <div className="flex items-center gap-2 mb-1" onMouseDown={onMouseDown}>
          <div className={`w-6 h-6 rounded flex items-center justify-center ${node.online ? 'bg-indigo-600/20' : 'bg-red-600/20'}`}>
            <Server size={13} className={node.online ? 'text-indigo-400' : 'text-red-400'} />
          </div>
          <Link to={`/devices/${node.id}`}
            onMouseDown={e => e.stopPropagation()}
            className="text-xs font-medium text-gray-200 hover:text-indigo-300 truncate">
            {node.identity || node.name || node.ip}
          </Link>
        </div>
        <p className="text-[10px] font-mono text-gray-500 mb-1.5">{node.ip}</p>
        <div className="flex gap-1 flex-wrap">
          <Badge variant={node.online ? 'green' : 'red'} className="text-[10px] py-0">{node.online ? onlineLabel : offlineLabel}</Badge>
          {node.model && <Badge variant="gray" className="text-[10px] py-0">{node.model}</Badge>}
        </div>
      </div>
    </div>
  )
}

interface RenderedLink {
  link: TopologyLink
  x1: number; y1: number
  x2: number; y2: number
}

function LinksSvg({ nodes, links, version }: {
  nodes: TopologyNode[]
  links: TopologyLink[]
  version: number  // bumped on drag to force recompute
}) {
  const rendered = useMemo<RenderedLink[]>(() => {
    const byId = new Map(nodes.map(n => [n.id, n]))
    return links.flatMap(l => {
      const a = byId.get(l.a)
      const b = byId.get(l.b)
      if (!a || !b) return []
      const { cx: x1, cy: y1 } = nodeCenter(a)
      const { cx: x2, cy: y2 } = nodeCenter(b)
      return [{ link: l, x1, y1, x2, y2 }]
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, links, version])

  return (
    <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ overflow: 'visible' }}>
      <defs>
        {Object.entries(linkTypeColor).map(([key, color]) => (
          <marker key={key} id={`arrow-${key}`} viewBox="0 0 8 8" refX="6" refY="4"
            markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 8 4 L 0 8 z" fill={color} opacity="0.7" />
          </marker>
        ))}
      </defs>
      {rendered.map(({ link, x1, y1, x2, y2 }) => {
        const color = linkTypeColor[link.type] ?? '#6b7280'
        const midX = (x1 + x2) / 2
        const midY = (y1 + y2) / 2
        const isTunnel = ['eoip', 'gre', 'vxlan', 'ipip'].includes(link.type)

        // Position port labels closer to each endpoint (25% along the line)
        const labelAX = x1 + (x2 - x1) * 0.22
        const labelAY = y1 + (y2 - y1) * 0.22
        const labelBX = x1 + (x2 - x1) * 0.78
        const labelBY = y1 + (y2 - y1) * 0.78

        return (
          <g key={link.id}>
            <line
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke={color}
              strokeWidth={2}
              strokeOpacity={0.55}
              strokeDasharray={isTunnel ? '6 3' : undefined}
            />
            {/* Link type badge in middle */}
            <g transform={`translate(${midX}, ${midY})`}>
              <rect x={-22} y={-9} width={44} height={18} rx={4}
                fill="#0a0a0a" stroke={color} strokeWidth={1} fillOpacity={0.9} />
              <text x={0} y={3} textAnchor="middle" fontSize="10" fontFamily="ui-monospace, monospace"
                fill={color} fontWeight="600">
                {link.type.toUpperCase()}
              </text>
            </g>
            {/* Port label A */}
            {link.iface_a && (
              <g transform={`translate(${labelAX}, ${labelAY})`}>
                <rect x={-(link.iface_a.length * 3.2 + 4)} y={-7} width={link.iface_a.length * 6.4 + 8} height={14} rx={3}
                  fill="#111827" stroke="#374151" strokeWidth={0.5} />
                <text x={0} y={3} textAnchor="middle" fontSize="9" fontFamily="ui-monospace, monospace" fill="#d1d5db">
                  {link.iface_a}
                </text>
              </g>
            )}
            {/* Port label B */}
            {link.iface_b && (
              <g transform={`translate(${labelBX}, ${labelBY})`}>
                <rect x={-(link.iface_b.length * 3.2 + 4)} y={-7} width={link.iface_b.length * 6.4 + 8} height={14} rx={3}
                  fill="#111827" stroke="#374151" strokeWidth={0.5} />
                <text x={0} y={3} textAnchor="middle" fontSize="9" fontFamily="ui-monospace, monospace" fill="#d1d5db">
                  {link.iface_b}
                </text>
              </g>
            )}
          </g>
        )
      })}
    </svg>
  )
}

export function NetworkMap() {
  const { t } = useTranslation()
  const qc = useQueryClient()

  const { data: topology, isLoading } = useQuery({
    queryKey: ['topology'],
    queryFn: systemApi.topology,
    refetchInterval: 30_000,
  })

  // Track positions locally so dragging updates the line layer in realtime
  const [posOverride, setPosOverride] = useState<Record<number, { x: number; y: number }>>({})
  const [version, setVersion] = useState(0)

  // Listen for drag events to bump version → SVG recomputes positions in realtime
  useEffect(() => {
    const handler = (e: Event) => {
      const ce = e as CustomEvent
      setPosOverride(prev => ({ ...prev, [ce.detail.id]: { x: ce.detail.x, y: ce.detail.y } }))
      setVersion(v => v + 1)
    }
    window.addEventListener('node-moved', handler)
    return () => window.removeEventListener('node-moved', handler)
  }, [])

  const updatePos = useMutation({
    mutationFn: ({ id, x, y }: { id: number; x: number; y: number }) =>
      devicesApi.update(id, { x_pos: x, y_pos: y }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['topology'] }),
  })

  const rediscover = useMutation({
    mutationFn: systemApi.discoverTopology,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['topology'] }),
  })

  const nodes = useMemo(() => {
    if (!topology) return []
    return topology.nodes.map(n => ({
      ...n,
      x_pos: posOverride[n.id]?.x ?? n.x_pos,
      y_pos: posOverride[n.id]?.y ?? n.y_pos,
    }))
  }, [topology, posOverride])

  const links = topology?.links ?? []

  const autoLayout = () => {
    const cols = Math.ceil(Math.sqrt(nodes.length))
    nodes.forEach((d, i) => {
      const col = i % cols
      const row = Math.floor(i / cols)
      const x = 40 + col * (NODE_W + 80)
      const y = 40 + row * (NODE_H + 100)
      updatePos.mutate({ id: d.id, x, y })
      setPosOverride(prev => ({ ...prev, [d.id]: { x, y } }))
    })
    setVersion(v => v + 1)
  }

  // Build legend of link types actually present
  const linkTypesPresent = Array.from(new Set(links.map(l => l.type)))

  return (
    <div className="p-6 space-y-4 h-full flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">{t('map.title')}</h1>
          <p className="text-sm text-gray-500 mt-0.5">{t('map.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => rediscover.mutate()}
            disabled={rediscover.isPending}
            className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <RefreshCw size={13} className={rediscover.isPending ? 'animate-spin' : ''} />
            {t('map.rediscover')}
          </button>
          <button
            onClick={autoLayout}
            className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5"
          >
            <Move size={13} /> {t('map.resetLayout')}
          </button>
        </div>
      </div>

      {/* Legend */}
      {linkTypesPresent.length > 0 && (
        <div className="flex items-center gap-3 text-xs flex-wrap">
          <Link2 size={13} className="text-gray-500" />
          <span className="text-gray-500">{t('map.linkTypes')}:</span>
          {linkTypesPresent.map(type => (
            <span key={type} className="flex items-center gap-1.5">
              <span className="inline-block w-4 h-0.5" style={{
                background: linkTypeColor[type] ?? '#6b7280',
                borderStyle: ['eoip', 'gre', 'vxlan', 'ipip'].includes(type) ? 'dashed' : 'solid'
              }} />
              <span className="text-gray-400 font-mono uppercase">{type}</span>
            </span>
          ))}
          <span className="text-gray-600 ml-3">· {nodes.length} {t('map.nodes')} · {links.length} {t('map.links')}</span>
        </div>
      )}

      <div className="flex-1 relative bg-gray-950 border border-gray-800 rounded-xl overflow-hidden min-h-[500px]">
        {/* Grid pattern */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgb(31 41 55)" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>

        {/* Link layer */}
        <LinksSvg nodes={nodes} links={links} version={version} />

        {isLoading && (
          <p className="absolute inset-0 flex items-center justify-center text-gray-500 text-sm">{t('common.loading')}</p>
        )}

        {!isLoading && nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3">
            <Network size={40} className="text-gray-700" />
            <p className="text-gray-500 text-sm">{t('map.noDevices')}</p>
          </div>
        )}

        {!isLoading && nodes.length > 0 && links.length === 0 && (
          <div className="absolute top-3 left-1/2 -translate-x-1/2 z-20 bg-amber-950/40 border border-amber-900/50 rounded-lg px-3 py-1.5 text-xs text-amber-300">
            {t('map.noLinksYet')}
          </div>
        )}

        {nodes.map(n => (
          <DeviceNode
            key={n.id}
            node={n}
            onDragEnd={(id, x, y) => {
              setPosOverride(prev => ({ ...prev, [id]: { x, y } }))
              updatePos.mutate({ id, x, y })
            }}
            onlineLabel={t('common.online')}
            offlineLabel={t('common.offline')}
          />
        ))}
      </div>
    </div>
  )
}

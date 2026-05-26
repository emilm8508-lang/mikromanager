import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi, Device } from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { Network, Server, Move } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

const NODE_W = 160
const NODE_H = 72

function DeviceNode({ device, onDragEnd, onlineLabel, offlineLabel }: {
  device: Device
  onDragEnd: (id: number, x: number, y: number) => void
  onlineLabel: string
  offlineLabel: string
}) {
  const dragRef = useRef<{ startX: number; startY: number; nodeX: number; nodeY: number } | null>(null)

  const onMouseDown = (e: React.MouseEvent) => {
    e.preventDefault()
    dragRef.current = { startX: e.clientX, startY: e.clientY, nodeX: device.x_pos, nodeY: device.y_pos }

    const onMove = (me: MouseEvent) => {
      if (!dragRef.current) return
      const dx = me.clientX - dragRef.current.startX
      const dy = me.clientY - dragRef.current.startY
      const el = document.getElementById(`node-${device.id}`)
      if (el) {
        el.style.transform = `translate(${dragRef.current.nodeX + dx}px, ${dragRef.current.nodeY + dy}px)`
      }
    }

    const onUp = (ue: MouseEvent) => {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      if (!dragRef.current) return
      const dx = ue.clientX - dragRef.current.startX
      const dy = ue.clientY - dragRef.current.startY
      onDragEnd(device.id, dragRef.current.nodeX + dx, dragRef.current.nodeY + dy)
      dragRef.current = null
    }

    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }

  return (
    <div
      id={`node-${device.id}`}
      className="absolute select-none"
      style={{ transform: `translate(${device.x_pos}px, ${device.y_pos}px)`, width: NODE_W }}
    >
      <div className={`bg-gray-900 border rounded-xl p-3 shadow-lg cursor-move transition-shadow hover:shadow-indigo-500/20 ${device.online ? 'border-gray-700' : 'border-red-900/50'}`}>
        <div className="flex items-center gap-2 mb-1">
          <div className={`w-6 h-6 rounded flex items-center justify-center ${device.online ? 'bg-indigo-600/20' : 'bg-red-600/20'}`}
            onMouseDown={onMouseDown}>
            <Server size={13} className={device.online ? 'text-indigo-400' : 'text-red-400'} />
          </div>
          <Link to={`/devices/${device.id}`} className="text-xs font-medium text-gray-200 hover:text-indigo-300 truncate">
            {device.identity || device.name || device.ip}
          </Link>
        </div>
        <p className="text-[10px] font-mono text-gray-500 mb-1.5">{device.ip}</p>
        <div className="flex gap-1 flex-wrap">
          <Badge variant={device.online ? 'green' : 'red'} className="text-[10px] py-0">{device.online ? onlineLabel : offlineLabel}</Badge>
          {device.model && <Badge variant="gray" className="text-[10px] py-0">{device.model}</Badge>}
        </div>
      </div>
    </div>
  )
}

export function NetworkMap() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: devices = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: devicesApi.list })
  const [hint, setHint] = useState(true)

  const updatePos = useMutation({
    mutationFn: ({ id, x, y }: { id: number; x: number; y: number }) =>
      devicesApi.update(id, { x_pos: x, y_pos: y }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['devices'] }),
  })

  const autoLayout = () => {
    const cols = Math.ceil(Math.sqrt(devices.length))
    devices.forEach((d, i) => {
      const col = i % cols
      const row = Math.floor(i / cols)
      updatePos.mutate({ id: d.id, x: 40 + col * (NODE_W + 40), y: 40 + row * (NODE_H + 40) })
    })
  }

  return (
    <div className="p-6 space-y-4 h-full flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">{t('map.title')}</h1>
          <p className="text-sm text-gray-500 mt-0.5">{t('map.subtitle')}</p>
        </div>
        <button
          onClick={autoLayout}
          className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5"
        >
          <Move size={13} /> {t('map.resetLayout')}
        </button>
      </div>

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

        {isLoading && (
          <p className="absolute inset-0 flex items-center justify-center text-gray-500 text-sm">{t('common.loading')}</p>
        )}

        {!isLoading && devices.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3">
            <Network size={40} className="text-gray-700" />
            <p className="text-gray-500 text-sm">{t('map.noDevices')}</p>
          </div>
        )}

        {devices.map(d => (
          <DeviceNode
            key={d.id}
            device={d}
            onDragEnd={(id, x, y) => updatePos.mutate({ id, x, y })}
            onlineLabel={t('common.online')}
            offlineLabel={t('common.offline')}
          />
        ))}

        {hint && devices.length > 0 && (
          <button
            onClick={() => setHint(false)}
            className="absolute bottom-3 right-3 text-xs text-gray-600 hover:text-gray-400 bg-gray-900/80 px-3 py-1.5 rounded-lg border border-gray-800"
          >
            {t('map.subtitle')}
          </button>
        )}
      </div>
    </div>
  )
}

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { hypervApi, HypervHostOut, HypervVmOut } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Layers, RefreshCw, ChevronDown, ChevronUp, Cpu, MemoryStick, HeartPulse } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { formatBytes } from '../lib/utils'

function stateBadgeVariant(state: string | null): 'green' | 'gray' | 'yellow' | 'red' {
  if (state === 'Running') return 'green'
  if (state === 'Off') return 'gray'
  if (state === 'Saved' || state === 'Paused') return 'yellow'
  return 'red'
}

function formatUptime(sec: number | null): string {
  if (sec == null || sec <= 0) return '—'
  const days = Math.floor(sec / 86400)
  const hours = Math.floor((sec % 86400) / 3600)
  const mins = Math.floor((sec % 3600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${mins}m`
  return `${mins}m`
}

function VmTable({ vms }: { vms: HypervVmOut[] }) {
  const { t } = useTranslation()
  if (vms.length === 0) {
    return <div className="text-sm text-slate-500 py-2">{t('hyperv.noVms')}</div>
  }
  return (
    <table className="w-full text-sm mt-2">
      <thead>
        <tr className="text-left text-slate-500 border-b">
          <th className="py-1">{t('hyperv.vmName')}</th>
          <th>{t('hyperv.state')}</th>
          <th>{t('hyperv.cpu')}</th>
          <th>{t('hyperv.memoryAssigned')}</th>
          <th>{t('hyperv.memoryDemand')}</th>
          <th>{t('hyperv.heartbeat')}</th>
          <th>{t('hyperv.uptime')}</th>
        </tr>
      </thead>
      <tbody>
        {vms.map(v => (
          <tr key={v.id} className="border-b border-slate-100">
            <td className="py-1.5 font-medium text-slate-800">{v.name}</td>
            <td><Badge variant={stateBadgeVariant(v.state)}>{v.state ?? '—'}</Badge></td>
            <td className="text-xs text-slate-600">{v.cpu_usage_pct != null ? `${v.cpu_usage_pct}%` : '—'}</td>
            <td className="text-xs text-slate-600">{formatBytes(v.memory_assigned_bytes)}</td>
            <td className="text-xs text-slate-600">{formatBytes(v.memory_demand_bytes)}</td>
            <td className="text-xs text-slate-600">{v.heartbeat ?? '—'}</td>
            <td className="text-xs text-slate-600">{formatUptime(v.uptime_sec)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function HostCard({ host }: { host: HypervHostOut }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)

  const { data: vms = [] } = useQuery({
    queryKey: ['hyperv-vms', host.id],
    queryFn: () => hypervApi.vms(host.id),
    enabled: expanded,
  })

  const refresh = useMutation({
    mutationFn: () => hypervApi.refresh(host.windows_host_id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hyperv-hosts'] })
      qc.invalidateQueries({ queryKey: ['hyperv-vms', host.id] })
    },
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers size={15} className="text-indigo-600" />
            <h3 className="text-sm font-semibold text-slate-700">{host.hostname || host.ip}</h3>
            <span className="text-xs text-slate-400 font-mono">{host.ip}</span>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={host.last_status === 'ok' ? 'green' : 'red'}>
              {host.vm_count_running ?? 0}/{host.vm_count_total ?? 0} {t('hyperv.running')}
            </Badge>
            <Button size="sm" variant="ghost" onClick={() => refresh.mutate()} disabled={refresh.isPending}>
              <RefreshCw size={13} className={refresh.isPending ? 'animate-spin' : ''} />
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setExpanded(v => !v)}>
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4 text-xs text-slate-500">
          <span className="flex items-center gap-1"><Cpu size={12} /> {host.logical_processor_count ?? '—'} {t('hyperv.logicalCpus')}</span>
          <span className="flex items-center gap-1"><MemoryStick size={12} /> {formatBytes(host.memory_capacity_bytes)}</span>
          {host.last_error && (
            <span className="flex items-center gap-1 text-red-600"><HeartPulse size={12} /> {host.last_error}</span>
          )}
        </div>
        {expanded && <VmTable vms={vms} />}
      </CardContent>
    </Card>
  )
}

export function HyperV() {
  const { t } = useTranslation()
  const { data: hosts = [], isLoading } = useQuery({ queryKey: ['hyperv-hosts'], queryFn: hypervApi.hosts })

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-900">{t('nav.hyperv')}</h1>
        <p className="text-sm text-slate-500 mt-1">{t('hyperv.intro')}</p>
      </div>
      {isLoading ? (
        <div className="text-sm text-slate-500">{t('common.loading')}</div>
      ) : hosts.length === 0 ? (
        <div className="text-sm text-slate-500">{t('hyperv.noHosts')}</div>
      ) : (
        <div className="space-y-3">
          {hosts.map(h => <HostCard key={h.id} host={h} />)}
        </div>
      )}
    </div>
  )
}

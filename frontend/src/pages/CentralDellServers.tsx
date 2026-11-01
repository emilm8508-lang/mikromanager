import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { LayoutDashboard, Boxes, Server } from 'lucide-react'
import { centralApi, centralConfig } from '../lib/api'
import { PhysicalServersPanel } from './CentralAlerts'
import { DellFleetOverview, DellFleetInventory, type FleetRow } from '../components/DellFleetOverview'
import { DellServerDetail } from '../components/DellServerDetail'
import { Modal } from '../components/ui/Modal'
import { cn } from '../lib/utils'

// Standalone left-sidebar page (Central mode) for Dell/iDRAC hardware
// health specifically — deliberately NOT combined with Linux/Windows
// (see CentralHosts.tsx): "Serwery fizyczne" is about physical hardware
// health (power/fans/RAID/etc.), a different concern from Linux/Windows
// OS patch status, which can run on hardware OR a VM either way.
// Three tabs: the fleet overview, the inventory table, and the per-server
// health list (PhysicalServersPanel, with its "check now" buttons).
type Tab = 'overview' | 'inventory' | 'servers'

export function CentralDellServers() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [tab, setTab] = useState<Tab>('overview')
  const [rows, setRows] = useState<FleetRow[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [detail, setDetail] = useState<FleetRow | null>(null)

  useEffect(() => {
    if (!cfg) return
    const load = async () => {
      try {
        const s = await centralApi.dellServersStatusAll()
        setRows(s.tenants.flatMap(tr => tr.dell_servers.map(server => ({ tenant: tr.tenant, server }))))
        setErr(null)
      } catch (e) {
        setErr((e as Error).message)
      } finally {
        setLoading(false)
      }
    }
    load()
    const iv = setInterval(load, 5 * 60_000)    // the agents refresh these every ~30 min
    return () => clearInterval(iv)
  }, [])

  if (!cfg) {
    return (
      <div className="p-6 max-w-5xl">
        <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">
          {t('alerts.needsCentral')}
        </div>
      </div>
    )
  }

  const tabs: Array<[Tab, string, React.ComponentType<any>]> = [
    ['overview', t('dellFleet.tab.overview'), LayoutDashboard],
    ['inventory', t('dellFleet.tab.inventory'), Boxes],
    ['servers', t('dellFleet.tab.servers'), Server],
  ]

  return (
    <div className="p-6 max-w-7xl space-y-4">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">{t('dellFleet.kicker')}</p>
        <h1 className="text-lg font-semibold text-slate-900">{t('dellFleet.title', { hosts: rows.length, tenants: new Set(rows.map(r => r.tenant)).size })}</h1>
      </div>
      <div className="flex flex-wrap gap-1 border-b border-slate-200">
        {tabs.map(([k, label, Icon]) => (
          <button key={k} onClick={() => setTab(k)}
            className={cn('flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px', tab === k ? 'border-indigo-600 text-indigo-700 font-medium' : 'border-transparent text-slate-500 hover:text-slate-700')}>
            <Icon size={14} />{label}
          </button>
        ))}
      </div>

      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}
      {tab === 'servers' ? <PhysicalServersPanel />
        : loading ? <div className="text-sm text-slate-500">{t('common.loading')}</div>
        : rows.length === 0 ? <div className="text-sm text-slate-500">{t('dellCentral.noServers')}</div>
        : tab === 'overview' ? <DellFleetOverview rows={rows} onOpen={setDetail} />
        : <DellFleetInventory rows={rows} onOpen={setDetail} />}

      <Modal open={detail !== null} onClose={() => setDetail(null)} className="max-w-6xl"
        title={detail ? `${detail.tenant} · ${detail.server.name || '—'}${detail.server.model ? ` — ${detail.server.model}` : ''}` : ''}>
        <div className="max-h-[78vh] overflow-y-auto pr-1">
          {detail && <DellServerDetail details={detail.server.details} history={detail.server.history ?? {}} />}
        </div>
      </Modal>
    </div>
  )
}

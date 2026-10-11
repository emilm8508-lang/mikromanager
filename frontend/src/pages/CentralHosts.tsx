import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralConfig } from '../lib/api'
import { LinuxCentralPanel, WindowsCentralPanel } from './CentralAlerts'
import { CentralServerBoard } from '../components/CentralServerBoard'
import { TerminalSquare, MonitorSmartphone } from 'lucide-react'

// Standalone left-sidebar page (Central mode) for Linux/Windows OS patch
// status — deliberately separate from "Serwery fizyczne" (CentralDellServers.tsx):
// this is about OS-level update status, not hardware health, and these
// hosts may not even be physical (VMs are equally in scope).
// The graphical boards (same look as the agent's pages) come first; the classic tables, with the scan
// buttons and the Windows-management switch per client, stay underneath.
export function CentralHosts() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [tenant, setTenant] = useState('all')
  const [linuxTenants, setLinuxTenants] = useState<string[]>([])
  const [windowsTenants, setWindowsTenants] = useState<string[]>([])
  const tenants = [...new Set([...linuxTenants, ...windowsTenants])].sort()

  if (!cfg) {
    return (
      <div className="p-6 max-w-5xl">
        <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">
          {t('alerts.needsCentral')}
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-4 max-w-6xl">
      <div className="flex items-center gap-2">
        <TerminalSquare size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('centralHosts.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('centralHosts.intro')}</p>

      <div className="flex items-center gap-3">
        <select value={tenant} onChange={e => setTenant(e.target.value)} className="text-xs border border-slate-300 rounded px-2 py-1.5">
          <option value="all">{t('alerts.allTenants')}</option>
          {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
        </select>
      </div>

      <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2"><TerminalSquare size={15} className="text-indigo-600" /> Linux</h2>
      <CentralServerBoard platform="linux" tenantFilter={tenant} onTenants={setLinuxTenants} />
      <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2 pt-2"><MonitorSmartphone size={15} className="text-indigo-600" /> Windows</h2>
      <CentralServerBoard platform="windows" tenantFilter={tenant} onTenants={setWindowsTenants} />

      <details className="group pt-2">
        <summary className="cursor-pointer text-sm text-indigo-600 hover:underline select-none">{t('centralHosts.classic')}</summary>
        <div className="space-y-4 mt-3">
          <LinuxCentralPanel />
          <WindowsCentralPanel />
        </div>
      </details>
    </div>
  )
}

import { useTranslation } from 'react-i18next'
import { centralConfig } from '../lib/api'
import { LinuxCentralPanel, WindowsCentralPanel } from './CentralAlerts'
import { TerminalSquare } from 'lucide-react'

// Standalone left-sidebar page (Central mode) for Linux/Windows OS patch
// status — deliberately separate from "Serwery fizyczne" (CentralDellServers.tsx):
// this is about OS-level update status, not hardware health, and these
// hosts may not even be physical (VMs are equally in scope).
export function CentralHosts() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()

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
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <TerminalSquare size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('centralHosts.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('centralHosts.intro')}</p>
      <LinuxCentralPanel />
      <WindowsCentralPanel />
    </div>
  )
}

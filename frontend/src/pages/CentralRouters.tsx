import { useTranslation } from 'react-i18next'
import { centralConfig } from '../lib/api'
import { RoutersCentralPanel } from './CentralAlerts'

// Standalone left-sidebar page (Central mode) for Mikrotik router resource
// health (CPU/RAM/disk) — deliberately routers only, not switches (an
// explicit ask: switches stay on the plain display for now, see
// services/resource_monitor.py's routers_public_summary()/_is_router()).
export function CentralRouters() {
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
    <div className="p-6 max-w-5xl">
      <RoutersCentralPanel />
    </div>
  )
}

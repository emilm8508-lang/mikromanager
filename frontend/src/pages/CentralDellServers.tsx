import { useTranslation } from 'react-i18next'
import { centralConfig } from '../lib/api'
import { PhysicalServersPanel } from './CentralAlerts'

// Standalone left-sidebar page (Central mode) for Dell/iDRAC hardware
// health specifically — deliberately NOT combined with Linux/Windows
// (see CentralHosts.tsx): "Serwery fizyczne" is about physical hardware
// health (power/fans/RAID/etc.), a different concern from Linux/Windows
// OS patch status, which can run on hardware OR a VM either way.
export function CentralDellServers() {
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
      <PhysicalServersPanel />
    </div>
  )
}

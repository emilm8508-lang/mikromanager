import { useQuery } from '@tanstack/react-query'
import { inventoryApi, InventoryHostEntry, InventoryNetworkEntry } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Boxes, Server, MonitorSmartphone, TerminalSquare, HelpCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'

function FindingsBadge({ count }: { count: number }) {
  const { t } = useTranslation()
  if (count === 0) return <span className="text-xs text-slate-400">—</span>
  return <Badge variant="red" className="text-[10px]">{t('inventory.findingsCount', { count })}</Badge>
}

function NetworkGroup({ entries }: { entries: InventoryNetworkEntry[] }) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
          <Server size={15} className="text-indigo-600" />
          {t('inventory.groupNetwork')} ({entries.length})
        </h2>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-sm text-slate-500">{t('inventory.empty')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b">
                  <th className="py-1 pr-3">IP</th>
                  <th className="pr-3">{t('inventory.colName')}</th>
                  <th className="pr-3">{t('inventory.colModel')}</th>
                  <th className="pr-3">{t('inventory.colVendor')}</th>
                  <th>{t('inventory.colFindings')}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(e => (
                  <tr key={e.ip} className="border-b border-slate-100">
                    <td className="py-2 font-mono">{e.ip}</td>
                    <td>{e.name || '—'}</td>
                    <td className="text-slate-500">{e.model || '—'}</td>
                    <td className="text-slate-500">{e.vendor || '—'}</td>
                    <td><FindingsBadge count={e.findings_count} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function HostGroup({ title, icon: Icon, entries }: { title: string; icon: typeof Server; entries: InventoryHostEntry[] }) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
          <Icon size={15} className="text-indigo-600" />
          {title} ({entries.length})
        </h2>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-sm text-slate-500">{t('inventory.empty')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b">
                  <th className="py-1 pr-3">IP</th>
                  <th className="pr-3">{t('inventory.colHostname')}</th>
                  <th className="pr-3">{t('inventory.colOs')}</th>
                  <th className="pr-3">{t('inventory.colPorts')}</th>
                  <th>{t('inventory.colFindings')}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(e => (
                  <tr key={e.ip} className="border-b border-slate-100">
                    <td className="py-2 font-mono">{e.ip}</td>
                    <td>{e.hostname || '—'}</td>
                    <td className="text-slate-500">{e.os || '—'}</td>
                    <td className="text-slate-500 font-mono text-xs">{e.ports.join(', ')}</td>
                    <td><FindingsBadge count={e.findings_count} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function Inventory() {
  const { t } = useTranslation()
  const { data, isLoading } = useQuery({ queryKey: ['inventory'], queryFn: inventoryApi.get, refetchInterval: 30_000 })

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <Boxes size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('nav.inventory')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('inventory.subtitle')}</p>

      {isLoading || !data ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : (
        <>
          <NetworkGroup entries={data.network} />
          <HostGroup title={t('inventory.groupWindows')} icon={MonitorSmartphone} entries={data.windows} />
          <HostGroup title={t('inventory.groupLinux')} icon={TerminalSquare} entries={data.linux} />
          <HostGroup title={t('inventory.groupOther')} icon={HelpCircle} entries={data.other} />
        </>
      )}
    </div>
  )
}

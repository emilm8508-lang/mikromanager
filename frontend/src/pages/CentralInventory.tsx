import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, getAllTenantInventory, type TenantInventoryEntry } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Boxes, Server, MonitorSmartphone, TerminalSquare, HelpCircle } from 'lucide-react'
import { FindingsBadge } from './Inventory'

function NetworkGroupCentral({ entries }: { entries: TenantInventoryEntry[] }) {
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
                  <th className="py-1 pr-3">{t('inventoryCentral.colTenant')}</th>
                  <th className="pr-3">IP</th>
                  <th className="pr-3">{t('inventory.colName')}</th>
                  <th className="pr-3">{t('inventory.colModel')}</th>
                  <th className="pr-3">{t('inventory.colVendor')}</th>
                  <th>{t('inventory.colFindings')}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e, i) => (
                  <tr key={`${e.tenant}:${e.ip}:${i}`} className="border-b border-slate-100">
                    <td className="py-2 text-xs text-slate-500">{e.tenant}</td>
                    <td className="font-mono">{e.ip}</td>
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

function HostGroupCentral({ title, icon: Icon, entries }: { title: string; icon: typeof Server; entries: TenantInventoryEntry[] }) {
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
                  <th className="py-1 pr-3">{t('inventoryCentral.colTenant')}</th>
                  <th className="pr-3">IP</th>
                  <th className="pr-3">{t('inventory.colHostname')}</th>
                  <th className="pr-3">{t('inventory.colOs')}</th>
                  <th className="pr-3">{t('inventory.colPorts')}</th>
                  <th>{t('inventory.colFindings')}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e, i) => (
                  <tr key={`${e.tenant}:${e.ip}:${i}`} className="border-b border-slate-100">
                    <td className="py-2 text-xs text-slate-500">{e.tenant}</td>
                    <td className="font-mono">{e.ip}</td>
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

export function CentralInventory() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [rows, setRows] = useState<TenantInventoryEntry[]>([])
  const [pendingScans, setPendingScans] = useState<Array<{ tenant: string; queued_at: string }>>([])
  const [tenants, setTenants] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [busyScan, setBusyScan] = useState(false)

  const reload = async () => {
    try {
      const [inv, ps] = await Promise.all([
        getAllTenantInventory(),
        centralApi.pendingLinuxScans(),
      ])
      setRows(inv)
      setTenants([...new Set(inv.map(r => r.tenant))])
      setPendingScans(ps.pending ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    reload()
    const iv = setInterval(reload, 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  const scanPendingSet = new Set(pendingScans.map(p => p.tenant))
  const scanAll = async () => {
    const targets = tenants.filter(tn => !scanPendingSet.has(tn))
    if (targets.length === 0) return
    setBusyScan(true)
    try {
      await Promise.all(targets.map(tn => centralApi.requestLinuxScan(tn)))
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setBusyScan(false)
    }
  }

  const byGroup = (g: TenantInventoryEntry['group']) => rows.filter(r => r.group === g)

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center gap-2">
        <Boxes size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('inventoryCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('inventoryCentral.intro')}</p>

      {err && <div className="text-sm text-red-600">{err}</div>}

      {tenants.length > 0 && (
        <button onClick={scanAll} disabled={busyScan}
          className="text-xs px-2.5 py-1.5 rounded bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">
          {t('inventoryCentral.scanAll', { count: tenants.length })}
        </button>
      )}

      {loading ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-slate-500">{t('inventoryCentral.empty')}</p>
      ) : (
        <>
          <NetworkGroupCentral entries={byGroup('network')} />
          <HostGroupCentral title={t('inventory.groupWindows')} icon={MonitorSmartphone} entries={byGroup('windows')} />
          <HostGroupCentral title={t('inventory.groupLinux')} icon={TerminalSquare} entries={byGroup('linux')} />
          <HostGroupCentral title={t('inventory.groupOther')} icon={HelpCircle} entries={byGroup('other')} />
        </>
      )}
    </div>
  )
}

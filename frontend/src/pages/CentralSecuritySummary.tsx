import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig } from '../lib/api'
import { buildSec, type SecPart } from '../lib/securityData'
import { SecurityDashboard } from '../components/SecurityDashboard'
import { ShieldCheck } from 'lucide-react'

// Security Summary across all clients (one call: the latest snapshot's plaintext sections of every client).
export function CentralSecuritySummary() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [parts, setParts] = useState<SecPart[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenant, setTenant] = useState('all')

  const reload = async () => {
    try {
      const s = await centralApi.securityStatusAll()
      // PHP renders an empty data object as []
      setParts(s.tenants.map(x => ({ tenant: x.tenant, lastSeen: x.last_seen, data: Array.isArray(x.data) ? {} : x.data })))
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

  const vis = useMemo(() => parts.filter(p => tenant === 'all' || p.tenant === tenant), [parts, tenant])
  const sec = useMemo(() => buildSec(vis), [vis])

  if (!cfg) {
    return <div className="p-6 max-w-5xl"><div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">{t('alerts.needsCentral')}</div></div>
  }
  return (
    <div className="p-6 space-y-4 max-w-[1500px]">
      <div className="flex items-center gap-2">
        <ShieldCheck size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('secDash.centralTitle')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('secDash.centralIntro')}</p>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}
      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : parts.length === 0 ? <p className="text-sm text-slate-500">{t('secDash.centralNoData')}</p> : (
        <>
          <div className="flex items-center gap-3">
            <select value={tenant} onChange={e => setTenant(e.target.value)} className="text-xs border border-slate-300 rounded px-2 py-1.5">
              <option value="all">{t('alerts.allTenants')}</option>
              {parts.map(p => p.tenant).sort().map(tn => <option key={tn} value={tn}>{tn}</option>)}
            </select>
            <button onClick={reload} className="ml-auto text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>
          </div>
          <SecurityDashboard data={sec} central />
        </>
      )}
    </div>
  )
}

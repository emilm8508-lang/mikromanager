import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { securityApi } from '../lib/api'
import { buildSec } from '../lib/securityData'
import { SecurityDashboard } from '../components/SecurityDashboard'
import { Button } from '../components/ui/Button'
import { ShieldCheck, RefreshCw } from 'lucide-react'

// Security Summary of this agent's own network.
export function SecuritySummary() {
  const { t } = useTranslation()
  const { data, isLoading, isFetching, refetch } = useQuery({ queryKey: ['security-summary'], queryFn: securityApi.summary, refetchInterval: 60_000 })
  const sec = useMemo(() => (data ? buildSec([{ tenant: 'local', lastSeen: null, data }]) : null), [data])
  return (
    <div className="p-6 space-y-4 max-w-[1500px]">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><ShieldCheck size={20} className="text-indigo-600" /> {t('secDash.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('secDash.subtitle')}</p>
        </div>
        <Button size="sm" variant="secondary" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} /> {t('secDash.refresh')}
        </Button>
      </div>
      <div className={isFetching && sec ? 'opacity-70 transition-opacity' : 'transition-opacity'}>
        {isLoading || !sec ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : <SecurityDashboard data={sec} central={false} />}
      </div>
    </div>
  )
}

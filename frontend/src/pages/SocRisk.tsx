import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Gauge } from 'lucide-react'
import { socApi } from '../lib/api'
import { RiskTable, RISK_LEVELS } from '../components/SocBits'
import { cn } from '../lib/utils'

// Which devices are worst off and why: the open alerts, vulnerabilities, patches, failed checks ... of each device put together into one score.
export function SocRisk() {
  const { t } = useTranslation()
  const [level, setLevel] = useState('')
  const [q, setQ] = useState('')
  const risk = useQuery({ queryKey: ['soc-risk'], queryFn: () => socApi.risk(500), refetchInterval: 60000 })
  const items = (risk.data?.items ?? []).filter(r => (!level || r.level === level) && (!q.trim() || `${r.name} ${r.ip ?? ''}`.toLowerCase().includes(q.trim().toLowerCase())))
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Gauge size={20} className="text-indigo-600" /> {t('soc.risk.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('soc.risk.subtitle')}</p>
      </div>
      {risk.data && (
        <div className="flex gap-2 flex-wrap items-center">
          {RISK_LEVELS.map(l => (
            <button key={l.key} onClick={() => setLevel(level === l.key ? '' : l.key)}
              className={cn('bg-white border rounded-xl px-4 py-2 min-w-[7.5rem] text-left', level === l.key ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-200 hover:bg-slate-50')}>
              <div className="text-xs text-slate-500">{t(`soc.risk.level.${l.key}`)}</div>
              <div className={cn('text-2xl font-bold tabular-nums', risk.data.levels[l.key] ? l.text : 'text-slate-300')}>{risk.data.levels[l.key] ?? 0}</div>
            </button>
          ))}
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('soc.filter.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56 ml-auto" />
        </div>
      )}
      {risk.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : <RiskTable rows={items.map(r => ({ id: r.id, name: r.name, type: r.type, score: r.score, level: r.level, factors: r.factors, ip: r.ip, loc: r.loc, href: `/inventory/${r.id}` }))} empty={t('soc.risk.empty') as string} />}
    </div>
  )
}

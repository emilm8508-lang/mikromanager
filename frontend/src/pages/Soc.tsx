import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Siren } from 'lucide-react'
import { socApi, type SocStatus } from '../lib/api'
import { SocFilters, SocKpis, SocTable, SOC_FILTER_DEFAULT, type SocFilterState } from '../components/SocBits'
import { Button } from '../components/ui/Button'

// The alert queue of this agent: everything the detectors and the connected systems (Wazuh, Checkmk, PRTG, the monitors) reported, merged into
// one alert per thing, with a status the analyst moves forward. Central shows the same queue of every client, read-only.
export function Soc() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [f, setF] = useState<SocFilterState>(SOC_FILTER_DEFAULT)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const status = f.tab === 'open' ? 'open' : f.tab === 'closed' ? 'closed' : 'all'
  const list = useQuery({
    queryKey: ['soc', status, f.severity, f.category, f.source, f.q],
    queryFn: () => socApi.alerts({ status, severity: f.severity || undefined, category: f.category || undefined, source: f.source || undefined, q: f.q || undefined, limit: 500 }),
    refetchInterval: 30000,
  })
  const stats = useQuery({ queryKey: ['soc-stats'], queryFn: socApi.stats, refetchInterval: 30000 })
  const update = useMutation({
    mutationFn: ({ ids, patch }: { ids: number[]; patch: Record<string, unknown> }) => socApi.update({ ids, ...patch }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['soc'] }); void qc.invalidateQueries({ queryKey: ['soc-stats'] }); void qc.invalidateQueries({ queryKey: ['soc-alert'] }) },
  })
  const onUpdate = (ids: number[], patch: Record<string, unknown>) => update.mutate({ ids, patch })
  const bulk = (st: SocStatus) => { onUpdate(Array.from(selected), { status: st }); setSelected(new Set()) }
  const items = list.data?.items ?? []

  return (
    <div className="p-6 space-y-4 max-w-[1500px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Siren size={20} className="text-indigo-600" /> {t('soc.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('soc.subtitle')}</p>
      </div>
      {stats.data && <SocKpis stats={stats.data} />}
      <SocFilters f={f} set={nf => { setF(nf); setSelected(new Set()) }} tabs={['open', 'closed', 'all']} />
      {selected.size > 0 && (
        <div className="flex items-center gap-2 flex-wrap bg-indigo-50 border border-indigo-200 rounded-lg px-3 py-2 text-sm">
          <b>{t('soc.bulk.selected', { count: selected.size })}</b>
          <Button size="sm" variant="secondary" onClick={() => bulk('ack')}>{t('soc.bulk.ack')}</Button>
          <Button size="sm" variant="secondary" onClick={() => bulk('in_progress')}>{t('soc.bulk.take')}</Button>
          <Button size="sm" variant="secondary" onClick={() => bulk('closed')}>{t('soc.bulk.close')}</Button>
          <Button size="sm" variant="secondary" onClick={() => bulk('false_positive')}>{t('soc.bulk.falsePositive')}</Button>
          <Button size="sm" variant="ghost" onClick={() => bulk('new')}>{t('soc.bulk.reopen')}</Button>
          <button className="text-xs text-slate-500 hover:underline ml-auto" onClick={() => setSelected(new Set())}>{t('soc.bulk.clear')}</button>
        </div>
      )}
      {update.isError && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{(update.error as Error).message}</div>}
      {list.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : (
        <>
          <SocTable alerts={items} readOnly={false} selected={selected} setSelected={setSelected} onUpdate={onUpdate} empty={t('soc.empty') as string} />
          {list.data && list.data.total > items.length && <p className="text-xs text-slate-400">{t('soc.shown', { shown: items.length, total: list.data.total })}</p>}
        </>
      )}
    </div>
  )
}

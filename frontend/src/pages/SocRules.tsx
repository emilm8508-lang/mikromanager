import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ListChecks, Play } from 'lucide-react'
import { socApi, type SocRule } from '../lib/api'
import { SevBadge, useAgo } from '../components/SocBits'
import { Button } from '../components/ui/Button'
import { cn } from '../lib/utils'

// What the agent detects by itself, rule by rule: switch a rule off, run it now, see when it last ran and how many things it already knows.
export function SocRules() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const ago = useAgo()
  const rules = useQuery({ queryKey: ['soc-rules'], queryFn: socApi.rules, refetchInterval: 30000 })
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['soc-rules'] }); void qc.invalidateQueries({ queryKey: ['soc'] }); void qc.invalidateQueries({ queryKey: ['soc-stats'] }) }
  const toggle = useMutation({ mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => socApi.ruleToggle(id, enabled), onSuccess: refresh })
  const run = useMutation({ mutationFn: (id: string) => socApi.ruleRun(id), onSuccess: refresh })
  const minutes = (r: SocRule) => Math.round(r.interval_sec / 60)
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><ListChecks size={20} className="text-indigo-600" /> {t('soc.rules.title')}</h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('soc.rules.subtitle')}</p>
      </div>
      {(toggle.isError || run.isError) && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{((toggle.error ?? run.error) as Error).message}</div>}
      {rules.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          {(rules.data ?? []).map(r => (
            <div key={r.id} className={cn('flex gap-4 items-start px-4 py-3 border-t border-slate-100 first:border-t-0', !r.enabled && 'opacity-60')}>
              <label className="pt-0.5 shrink-0" title={t('soc.rules.col.enabled') as string}>
                <input type="checkbox" checked={r.enabled} disabled={toggle.isPending} onChange={e => toggle.mutate({ id: r.id, enabled: e.target.checked })} />
              </label>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-slate-900">{t(`soc.rule.rule.${r.id}`, { defaultValue: r.title })}</span>
                  <SevBadge s={r.severity as never} />
                  {r.mitre && <span className="text-[10px] text-slate-500 border border-slate-200 rounded px-1">{r.mitre}</span>}
                  <span className="text-[11px] text-slate-400">{t(`soc.category.${r.category}`, { defaultValue: r.category })}</span>
                </div>
                <p className="text-slate-600 mt-0.5">{t(`soc.ruledesc.${r.id}`, { defaultValue: r.description })}</p>
                <p className="text-xs text-slate-400 mt-1">
                  {t('soc.rules.every', { min: minutes(r) })} · {r.last_run ? `${t('soc.rules.col.last')}: ${ago(r.last_run)}` : t('soc.rules.never')}
                  {r.baselined && ` · ${t('soc.rules.known', { n: r.known })}`}
                  {r.baselined && r.last_new != null && ` · ${t('soc.rules.lastNew', { n: r.last_new })}`}
                </p>
                {!r.baselined && <p className="text-xs text-amber-700 mt-0.5">{t('soc.rules.baseline')}</p>}
                {r.last_error && <p className="text-xs text-red-600 mt-0.5 break-words">{r.last_error}</p>}
              </div>
              <Button size="sm" variant="secondary" disabled={run.isPending} onClick={() => run.mutate(r.id)}><Play size={13} /> {t('soc.rules.runNow')}</Button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

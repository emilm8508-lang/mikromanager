import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { complianceApi, ComplianceTargetType } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { ListChecks, ChevronDown, ChevronUp, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const TARGET_LABELS: Record<ComplianceTargetType, string> = {
  linux: 'compliance.targetLinux',
  windows: 'compliance.targetWindows',
  mikrotik: 'compliance.targetMikrotik',
}

function TargetRow({ targetType, targetId, label, passed, failed, unknown, total }: {
  targetType: ComplianceTargetType; targetId: number; label: string
  passed: number; failed: number; unknown: number; total: number
}) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)

  const { data: details } = useQuery({
    queryKey: ['compliance-details', targetType, targetId],
    queryFn: () => complianceApi.results(targetType, targetId),
    enabled: expanded,
  })

  const runNow = useMutation({
    mutationFn: () => complianceApi.run(targetType, targetId),
    onSuccess: () => {
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ['compliance-summary'] })
        qc.invalidateQueries({ queryKey: ['compliance-details', targetType, targetId] })
      }, 8000)
    },
  })

  return (
    <div className="border border-slate-200 rounded-lg">
      <button
        className="w-full flex items-center justify-between gap-2 px-4 py-2.5 hover:bg-slate-50"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-center gap-2 min-w-0">
          <Badge variant="gray" className="text-[10px] shrink-0">{t(TARGET_LABELS[targetType])}</Badge>
          <span className="font-mono text-sm text-slate-800 truncate">{label}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {failed > 0 && <Badge variant="red" className="text-[10px]">{t('compliance.failedCount', { count: failed })}</Badge>}
          {passed > 0 && <Badge variant="green" className="text-[10px]">{t('compliance.passedCount', { count: passed })}</Badge>}
          {unknown > 0 && <Badge variant="gray" className="text-[10px]">{t('compliance.unknownCount', { count: unknown })}</Badge>}
          <span className="text-xs text-slate-400">{passed}/{total}</span>
          {expanded ? <ChevronUp size={14} className="text-slate-400" /> : <ChevronDown size={14} className="text-slate-400" />}
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-3 space-y-2 border-t border-slate-100 pt-2">
          <Button size="sm" variant="secondary" onClick={() => runNow.mutate()} disabled={runNow.isPending}>
            <RefreshCw size={12} className={runNow.isPending ? 'animate-spin' : ''} /> {t('compliance.runNow')}
          </Button>
          {!details ? (
            <p className="text-xs text-slate-500">{t('common.loading')}</p>
          ) : (
            <div className="space-y-1.5">
              {details.map(d => (
                <div key={d.check_id} className="flex items-start gap-2 text-xs">
                  <Badge variant={d.passed === true ? 'green' : d.passed === false ? 'red' : 'gray'} className="text-[10px] shrink-0 mt-0.5">
                    {d.passed === true ? t('compliance.pass') : d.passed === false ? t('compliance.fail') : t('compliance.unknown')}
                  </Badge>
                  <div className="min-w-0">
                    <p className="text-slate-700">{d.title}</p>
                    {d.detail && <p className="text-slate-400 font-mono truncate">{d.detail}</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function Compliance() {
  const { t } = useTranslation()
  const { data, isLoading } = useQuery({
    queryKey: ['compliance-summary'],
    queryFn: complianceApi.summary,
    refetchInterval: 30_000,
  })

  const rows = data ?? []

  return (
    <div className="p-6 space-y-4 max-w-4xl">
      <div className="flex items-center gap-2">
        <ListChecks size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('nav.compliance')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('compliance.subtitle')}</p>

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-700">{t('compliance.targetsTitle')}</h2>
        </CardHeader>
        <CardContent className="space-y-2">
          {isLoading ? (
            <p className="text-sm text-slate-500">{t('common.loading')}</p>
          ) : rows.length === 0 ? (
            <p className="text-sm text-slate-500">{t('compliance.empty')}</p>
          ) : (
            rows.map(r => (
              <TargetRow key={`${r.target_type}:${r.target_id}`}
                targetType={r.target_type} targetId={r.target_id} label={r.label}
                passed={r.passed} failed={r.failed} unknown={r.unknown} total={r.total} />
            ))
          )}
        </CardContent>
      </Card>
    </div>
  )
}

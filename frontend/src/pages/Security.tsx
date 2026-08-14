import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { systemApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { KeyRound, ShieldCheck, AlertTriangle, DatabaseBackup, PackageSearch } from 'lucide-react'
import { useAuth } from './Login'

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function formatBytes(n: number | null): string {
  if (n === null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

const WEEKDAYS_KEYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

function BackupSection() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['backup-status'], queryFn: systemApi.backupStatus, refetchInterval: 30_000 })

  const runBackup = useMutation({
    mutationFn: systemApi.backupRun,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backup-status'] }),
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <DatabaseBackup size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('security.backupTitle')}</h2>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-slate-500">{t('security.backupExplanation')}</p>

        {data && !data.enc_key_configured && (
          <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-3 py-2">
            {t('security.backupNoEncKey')}
          </p>
        )}

        {data && (
          <div className="text-sm space-y-1">
            <p>
              <span className="text-slate-500">{t('security.backupLastAt')}: </span>
              <span className="font-mono">{formatDate(data.last_backup_at)}</span>
              {data.last_size_bytes !== null && (
                <span className="text-slate-400"> ({formatBytes(data.last_size_bytes)})</span>
              )}
            </p>
            <p>
              <span className="text-slate-500">{t('security.backupSchedule')}: </span>
              <span className="font-mono">
                {t(`security.weekday.${WEEKDAYS_KEYS[data.backup_day]}`)} {String(data.backup_hour).padStart(2, '0')}:00
              </span>
            </p>
            {data.last_error && (
              <p className="text-red-600 text-xs">{t('security.backupLastError', { error: data.last_error })}</p>
            )}
          </div>
        )}

        {runBackup.data && (
          <p className={`text-xs rounded px-3 py-2 border ${runBackup.data.ok
            ? 'text-green-700 bg-green-50 border-green-200'
            : 'text-red-700 bg-red-50 border-red-200'}`}>
            {runBackup.data.ok
              ? t('security.backupRunSuccess', { size: formatBytes(runBackup.data.size_bytes) })
              : t('security.backupRunFailed', { error: runBackup.data.error })}
          </p>
        )}

        <Button
          variant="secondary"
          onClick={() => runBackup.mutate()}
          disabled={runBackup.isPending || data?.in_progress}
        >
          {runBackup.isPending || data?.in_progress ? t('security.backupRunning') : t('security.backupRunButton')}
        </Button>

        <p className="text-[11px] text-slate-400 pt-1">{t('security.backupRestoreHint')}</p>
      </CardContent>
    </Card>
  )
}

const NPM_SEVERITY_BADGE: Record<string, 'gray' | 'blue' | 'yellow' | 'red'> = {
  info: 'gray', low: 'gray', moderate: 'blue', high: 'yellow', critical: 'red',
}

function SupplyChainSection() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['supply-chain-status'], queryFn: systemApi.supplyChainStatus, refetchInterval: 30_000 })

  const run = useMutation({
    mutationFn: systemApi.supplyChainRun,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['supply-chain-status'] }),
  })

  const npmSummary = data?.npm?.summary
  const pipCount = data?.pip?.findings?.length ?? 0

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <PackageSearch size={15} className="text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-700">{t('security.supplyChainTitle')}</h2>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-slate-500">{t('security.supplyChainExplanation')}</p>

        {data && (
          <div className="text-sm space-y-1">
            <p>
              <span className="text-slate-500">{t('security.supplyChainLastRun')}: </span>
              <span className="font-mono">{formatDate(data.last_run)}</span>
            </p>
            <p>
              <span className="text-slate-500">{t('security.backupSchedule')}: </span>
              <span className="font-mono">
                {t(`security.weekday.${WEEKDAYS_KEYS[data.scan_day]}`)} {String(data.scan_hour).padStart(2, '0')}:00
              </span>
            </p>
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div className="border border-slate-200 rounded-lg p-3">
            <p className="text-xs font-medium text-slate-600 mb-1.5">{t('security.supplyChainNpm')}</p>
            {data?.npm?.ok === false ? (
              <p className="text-xs text-red-600">{data.npm.error}</p>
            ) : npmSummary ? (
              <div className="flex gap-1.5 flex-wrap">
                {(['critical', 'high', 'moderate', 'low'] as const).map(sev => (
                  npmSummary[sev] > 0 && (
                    <Badge key={sev} variant={NPM_SEVERITY_BADGE[sev]} className="text-[10px]">
                      {npmSummary[sev]} {t(`security.severity.${sev}`)}
                    </Badge>
                  )
                ))}
                {npmSummary.total === 0 && <span className="text-xs text-green-700">{t('security.supplyChainClean')}</span>}
              </div>
            ) : (
              <span className="text-xs text-slate-400">—</span>
            )}
          </div>
          <div className="border border-slate-200 rounded-lg p-3">
            <p className="text-xs font-medium text-slate-600 mb-1.5">{t('security.supplyChainPip')}</p>
            {data?.pip?.ok === false ? (
              <p className="text-xs text-red-600">{data.pip.error}</p>
            ) : data?.pip ? (
              pipCount === 0 ? (
                <span className="text-xs text-green-700">{t('security.supplyChainClean')}</span>
              ) : (
                <Badge variant="red" className="text-[10px]">{t('security.supplyChainFindings', { count: pipCount })}</Badge>
              )
            ) : (
              <span className="text-xs text-slate-400">—</span>
            )}
          </div>
        </div>

        <Button
          variant="secondary"
          onClick={() => run.mutate()}
          disabled={run.isPending || data?.in_progress}
        >
          {run.isPending || data?.in_progress ? t('security.supplyChainRunning') : t('security.supplyChainRunButton')}
        </Button>
      </CardContent>
    </Card>
  )
}

export function Security() {
  const { t } = useTranslation()
  const { role } = useAuth()
  const qc = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const [result, setResult] = useState<{ rotated_fields: number } | null>(null)

  const { data } = useQuery({ queryKey: ['crypto-status'], queryFn: systemApi.cryptoStatus })

  const rotate = useMutation({
    mutationFn: systemApi.rotateKey,
    onSuccess: (r) => {
      setResult({ rotated_fields: r.rotated_fields })
      setConfirming(false)
      qc.invalidateQueries({ queryKey: ['crypto-status'] })
    },
  })

  if (role !== 'admin') {
    return (
      <div className="p-6">
        <Card><CardContent className="text-sm text-slate-500 py-8 text-center">
          {t('security.adminOnly')}
        </CardContent></Card>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">
          <ShieldCheck size={20} className="text-indigo-600" />
          {t('security.title')}
        </h1>
        <p className="text-sm text-slate-500 mt-0.5">{t('security.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <KeyRound size={15} className="text-indigo-600" />
            <h2 className="text-sm font-semibold text-slate-700">{t('security.keyTitle')}</h2>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-slate-500">{t('security.keyExplanation')}</p>
          <div className="text-sm space-y-1">
            <p>
              <span className="text-slate-500">{t('security.keyCreatedAt')}: </span>
              <span className="font-mono">{formatDate(data?.key_created_at ?? null)}</span>
            </p>
            <p>
              <span className="text-slate-500">{t('security.protectedFields')}: </span>
              <span className="font-mono">{data?.encrypted_field_count ?? '—'}</span>
            </p>
          </div>

          {result && (
            <p className="text-xs text-green-700 bg-green-50 border border-green-200 rounded px-3 py-2">
              {t('security.rotateSuccess', { count: result.rotated_fields })}
            </p>
          )}
          {rotate.isError && (
            <p className="text-xs text-red-600">{t('security.rotateFailed')}</p>
          )}

          {!confirming ? (
            <Button variant="secondary" onClick={() => setConfirming(true)}>
              {t('security.rotateButton')}
            </Button>
          ) : (
            <div className="border border-amber-200 bg-amber-50 rounded-lg p-3 space-y-2">
              <p className="text-xs text-amber-800 flex items-start gap-1.5">
                <AlertTriangle size={13} className="shrink-0 mt-0.5" />
                {t('security.rotateConfirm')}
              </p>
              <div className="flex gap-2">
                <Button variant="primary" onClick={() => rotate.mutate()} disabled={rotate.isPending}>
                  {rotate.isPending ? t('security.rotating') : t('security.rotateConfirmButton')}
                </Button>
                <Button variant="secondary" onClick={() => setConfirming(false)} disabled={rotate.isPending}>
                  {t('common.cancel')}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <BackupSection />
      <SupplyChainSection />
    </div>
  )
}

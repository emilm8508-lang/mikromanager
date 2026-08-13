import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { systemApi } from '../lib/api'
import { Card, CardHeader, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { KeyRound, ShieldCheck, AlertTriangle } from 'lucide-react'
import { useAuth } from './Login'

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString() } catch { return iso }
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
    </div>
  )
}

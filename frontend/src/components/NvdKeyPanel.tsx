import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ExternalLink, KeyRound } from 'lucide-react'
import { centralApi, centralConfig } from '../lib/api'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Pill } from './AssetBits'

// The organisation's NVD API key lives in Central (the OVH database) and nowhere else: this is the only place it is entered. The agents ask Central for their NVD
// lookups, so they use the key without holding it; the key cannot be read back from here - only replaced or removed.
export function NvdKeyPanel() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const configured = !!centralConfig.load()
  const [key, setKey] = useState('')
  const q = useQuery({ queryKey: ['central-nvd'], queryFn: centralApi.nvdStatus, enabled: configured, retry: false, refetchInterval: 60_000 })
  const done = () => { setKey(''); void qc.invalidateQueries({ queryKey: ['central-nvd'] }) }
  const save = useMutation({ mutationFn: (k: string) => centralApi.nvdKeySet(k), onSuccess: done })
  const clear = useMutation({ mutationFn: () => centralApi.nvdKeyClear(), onSuccess: done })
  if (!configured) return null
  const s = q.data
  const err = (save.error ?? clear.error ?? q.error) as Error | null
  const total = (s?.usage ?? []).reduce((n, u) => n + u.requests, 0)
  const upstream = (s?.usage ?? []).reduce((n, u) => n + u.upstream, 0)
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2"><KeyRound size={15} className="text-indigo-600" /> {t('central.nvd.title')}</h2>
          {s && <Pill tone={s.configured ? 'green' : 'amber'}>{s.configured ? t('central.nvd.set') : t('central.nvd.notSet')}</Pill>}
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-slate-600">{t('central.nvd.intro')}</p>
        {s?.configured && (
          <p className="text-xs text-slate-500">{t('central.nvd.meta', { by: s.updated_by ?? '?', when: s.updated_at ?? '?' })}</p>
        )}
        <div className="flex gap-2 flex-wrap items-center">
          <input type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} placeholder={t('central.nvd.placeholder') as string}
            className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-80 font-mono" />
          <Button size="sm" variant="primary" disabled={!key.trim() || save.isPending} onClick={() => save.mutate(key.trim())}>{save.isPending ? t('central.nvd.checking') : t('central.nvd.save')}</Button>
          {s?.configured && <Button size="sm" variant="secondary" disabled={clear.isPending} onClick={() => { if (confirm(t('central.nvd.clearConfirm') as string)) clear.mutate() }}>{t('central.nvd.clear')}</Button>}
          <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noreferrer noopener" className="text-xs text-indigo-600 hover:underline inline-flex items-center gap-1">{t('central.nvd.getKey')} <ExternalLink size={11} /></a>
        </div>
        {err && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2 break-words">{err.message}</div>}
        {s && s.usage.length > 0 && (
          <div>
            <div className="text-xs font-medium text-slate-600 mb-1">{t('central.nvd.usage', { total, upstream, cached: total ? Math.round(100 * (1 - upstream / total)) : 0 })}</div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
              {s.usage.map(u => <span key={u.tenant}>{u.tenant}: <b className="text-slate-700">{u.requests}</b> ({u.upstream} → NVD)</span>)}
            </div>
          </div>
        )}
        <p className="text-[11px] text-slate-400">{t('central.nvd.note')}</p>
      </CardContent>
    </Card>
  )
}

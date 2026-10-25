import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, ExternalLink, KeyRound } from 'lucide-react'
import { vulnApi } from '../lib/api'
import { Button } from './ui/Button'
import { Pill } from './AssetBits'
import { useAgo } from './SocBits'

// Where the vulnerability data comes from and how well it is going: the NVD key (entered here instead of an environment variable of the agent)
// and whether the questions to NVD reach it - a scan that cannot reach NVD finds nothing, and used to say nothing about it.
export function VulnSources() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const ago = useAgo()
  const q = useQuery({ queryKey: ['vuln-settings'], queryFn: vulnApi.settings, refetchInterval: 30_000 })
  const [open, setOpen] = useState(false)
  const [key, setKey] = useState('')
  const save = useMutation({ mutationFn: (body: { nvd_key?: string; clear_nvd_key?: boolean }) => vulnApi.saveSettings(body), onSuccess: () => { setKey(''); void qc.invalidateQueries({ queryKey: ['vuln-settings'] }) } })
  const refresh = useMutation({ mutationFn: vulnApi.refreshExploit, onSuccess: () => { void qc.invalidateQueries({ queryKey: ['vuln-settings'] }); void qc.invalidateQueries({ queryKey: ['vuln-findings'] }) } })
  const nvd = q.data?.nvd
  const ex = q.data?.exploit
  const h = nvd?.health
  const failing = !!h && h.errors > 0 && !!h.last_error_at && (!h.last_ok_at || h.last_error_at > h.last_ok_at)
  const err = save.isError ? ((save.error as { response?: { data?: { detail?: string } }; message: string }).response?.data?.detail ?? (save.error as Error).message) : null
  return (
    <div className="bg-white border border-slate-200 rounded-xl">
      <button className="w-full flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-slate-800 text-left" onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}<KeyRound size={14} className="text-indigo-600" /> {t('vuln.sources.title')}
        {nvd && <Pill tone={nvd.configured ? 'green' : 'amber'}>{nvd.configured ? t('vuln.sources.keyOk') : t('vuln.sources.keyNone')}</Pill>}
        {failing && <Pill tone="red">{t('vuln.sources.failing')}</Pill>}
      </button>
      {(open || failing) && nvd && (
        <div className="px-4 pb-4 pt-1 space-y-3 text-sm border-t border-slate-100">
          {failing && (
            <div className="text-xs bg-red-50 border border-red-200 text-red-800 rounded-lg px-3 py-2">
              <b>{t('vuln.sources.failingTitle')}</b> {t('vuln.sources.failingBody')}
              <div className="font-mono mt-1 break-words">{h!.last_error}</div>
              <div className="mt-1 text-red-700">{t('vuln.sources.lastError', { when: ago(h!.last_error_at) })}{h!.last_ok_at ? ` · ${t('vuln.sources.lastOk', { when: ago(h!.last_ok_at) })}` : ''}</div>
            </div>
          )}
          <p className="text-slate-600">{t('vuln.sources.intro')}</p>
          <p className="text-xs text-slate-500">{t('vuln.sources.state', { source: nvd.source ? t(`vuln.sources.src_${nvd.source}`) : t('vuln.sources.src_none'), sec: nvd.interval_sec })}</p>
          <div className="flex gap-2 flex-wrap items-center">
            <input type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} placeholder={t('vuln.sources.placeholder') as string}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-80 font-mono" />
            <Button size="sm" variant="primary" disabled={!key.trim() || save.isPending} onClick={() => save.mutate({ nvd_key: key.trim() })}>{save.isPending ? t('vuln.sources.checking') : t('vuln.sources.save')}</Button>
            {nvd.source === 'app' && <Button size="sm" variant="secondary" disabled={save.isPending} onClick={() => save.mutate({ clear_nvd_key: true })}>{t('vuln.sources.remove')}</Button>}
            <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noreferrer noopener" className="text-xs text-indigo-600 hover:underline inline-flex items-center gap-1">{t('vuln.sources.getKey')} <ExternalLink size={11} /></a>
          </div>
          {err && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2 break-words">{err}</div>}
          <p className="text-[11px] text-slate-400">{t('vuln.sources.note')}</p>
          {ex && (
            <div className="border-t border-slate-100 pt-3 space-y-1.5">
              <div className="font-medium text-slate-800">{t('vuln.sources.exploitTitle')}</div>
              <p className="text-xs text-slate-500">{t('vuln.sources.exploitIntro')}</p>
              <div className="flex items-center gap-3 flex-wrap text-xs text-slate-600">
                <span>{ex.kev_at ? t('vuln.sources.exploitState', { count: ex.kev_count, when: ago(ex.kev_at), epss: ex.epss_count }) : t('vuln.sources.exploitNever')}</span>
                <Button size="sm" variant="secondary" disabled={refresh.isPending} onClick={() => refresh.mutate()}>{refresh.isPending ? t('vuln.sources.refreshing') : t('vuln.sources.refresh')}</Button>
              </div>
              {ex.error && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2 break-words">{t('vuln.sources.exploitFailing', { error: ex.error })}</div>}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

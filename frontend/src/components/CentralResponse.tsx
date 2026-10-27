import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldBan } from 'lucide-react'
import { centralApi, type CentralSoc } from '../lib/api'
import { useAgo } from './SocBits'
import { ttlLabel } from './SoarBits'

/** The response actions a client's agent proposed and is waiting to have approved. The decision travels as a signed command; the agent carries it out only if it allows approval from Central. */
export function CentralResponse({ tenant, soc }: { tenant: string; soc: CentralSoc }) {
  const { t } = useTranslation()
  const ago = useAgo()
  const [sent, setSent] = useState<Record<number, string>>({})
  const [err, setErr] = useState<string | null>(null)
  const s = soc.soar
  if (!s || !s.enabled || (s.pending.length === 0 && s.active === 0)) return null
  const decide = async (id: number, decision: 'approve' | 'reject') => {
    try {
      await centralApi.requestSoarDecision(tenant, id, decision)
      setSent(x => ({ ...x, [id]: decision }))
      setErr(null)
    } catch (e) { setErr((e as Error).message) }
  }
  return (
    <div className="space-y-2 pt-2">
      <h2 className="text-base font-semibold text-slate-900 inline-flex items-center gap-2"><ShieldBan size={16} className="text-indigo-600" /> {t('soar.central.title')}</h2>
      <p className="text-xs text-slate-500">{t('soar.central.line', { n: s.pending.length, active: s.active })} {!s.central_approval && s.pending.length > 0 && <span className="text-amber-700">{t('soar.central.off')}</span>}</p>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-2">{err}</div>}
      {s.pending.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 text-sm">
          {s.pending.map(p => (
            <div key={p.id} className="px-4 py-2 flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <b className="font-medium">{p.kind === 'block_ip' ? t('soar.kind.block', { ip: p.target ?? t('soar.internalHidden') }) : t('soar.kind.rule')}</b>
                {p.kind === 'block_ip' && <span className="text-slate-500"> · {t('soar.for', { time: ttlLabel(p.ttl_min) })}</span>}
                <span className="text-slate-500"> · {p.devices.join(', ')}</span>
                <div className="text-xs text-slate-500 truncate" title={p.reason}>{p.reason} · {p.by} · {ago(p.at)}</div>
              </div>
              {sent[p.id] ? <span className="text-xs text-green-700">{t(`soar.central.sent_${sent[p.id]}`)}</span> : (
                <>
                  <button className="px-3 py-1 rounded-md bg-red-600 text-white text-xs disabled:opacity-40" disabled={!s.central_approval} onClick={() => void decide(p.id, 'approve')}>{t('soar.approve')}</button>
                  <button className="px-3 py-1 rounded-md border border-slate-300 text-xs" onClick={() => void decide(p.id, 'reject')}>{t('soar.reject')}</button>
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { cardApi } from '../lib/api'
import { cn } from '../lib/utils'

/** The path of a host's card: by its address, or `a<id>` for an asset without one. */
export function hostPath(ip?: string | null, assetId?: number | null): string | null {
  if (ip) return `/host/${encodeURIComponent(ip)}`
  if (assetId != null) return `/host/a${assetId}`
  return null
}

/** A host's name or address that opens its card (everything the agent knows about it, from every module). Knowing the address or the asset id is enough; with only a name the inventory is asked
 *  when it is clicked. A host the inventory does not know falls back to `fallback` (the page of the module that found it) or says so. */
export function HostLink({ ip, assetId, name, children, className, fallback }: { ip?: string | null; assetId?: number | null; name?: string | null; children?: React.ReactNode; className?: string; fallback?: string }) {
  const { t } = useTranslation()
  const nav = useNavigate()
  const [busy, setBusy] = useState(false)
  const [missing, setMissing] = useState(false)
  const label = children ?? name ?? ip
  if (!ip && assetId == null && !name) return <>{label ?? '—'}</>
  const direct = hostPath(ip, assetId)
  const go = async (e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation()
    setBusy(true)
    try {
      let to = assetId != null ? direct : null
      if (!to) {                                   // not sure the inventory knows it: ask, so that the fallback can take over
        const id = await cardApi.resolve(ip, name)
        to = id != null ? hostPath(ip, id) : null
      }
      if (to) { nav(to); return }
      if (fallback) { nav(fallback); return }
      setMissing(true); setTimeout(() => setMissing(false), 2500)
    } catch { if (direct) nav(direct); else if (fallback) nav(fallback) } finally { setBusy(false) }
  }
  return (
    <a href={direct ?? '#'} onClick={e => void go(e)} title={(missing ? t('card.notInInventory') : t('card.open')) as string}
       className={cn('text-indigo-600 hover:underline cursor-pointer', busy && 'opacity-60', missing && 'text-amber-600', className)}>{missing ? t('card.notInInventory') : label}</a>
  )
}

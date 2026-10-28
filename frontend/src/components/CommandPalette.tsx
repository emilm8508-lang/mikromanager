import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Search, CornerDownLeft } from 'lucide-react'
import { assetsApi } from '../lib/api'
import { buildNav, PALETTE_EVENT, type NavEntry, type NavItem } from './Sidebar'
import { useAuth } from '../pages/Login'
import { cn } from '../lib/utils'
import { hostPath } from './HostLink'

type Hit = { key: string; label: string; hint: string; to: string; kind: 'page' | 'central' | 'asset'; Icon?: NavItem['icon'] }

const fold = (s: string) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/ł/g, 'l').toLowerCase()

function flatten(entries: NavEntry[], central: boolean): Hit[] {
  const out: Hit[] = []
  for (const e of entries) {
    if ('items' in e) for (const i of e.items) out.push({ key: `${central ? 'c' : 'a'}:${i.to}`, label: i.label, hint: e.label, to: i.to, kind: central ? 'central' : 'page', Icon: i.icon })
    else out.push({ key: `${central ? 'c' : 'a'}:${e.to}`, label: e.label, hint: '', to: e.to, kind: central ? 'central' : 'page', Icon: e.icon })
  }
  return out
}

/** Ctrl+K (or the button in the menu): jump to any page of the agent or of Central, or to an asset of the inventory, by typing a part of its name or address. */
export function CommandPalette() {
  const { t } = useTranslation()
  const nav = useNavigate()
  const { role } = useAuth()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen(o => !o) }
    }
    const onOpen = () => setOpen(true)
    window.addEventListener('keydown', onKey)
    window.addEventListener(PALETTE_EVENT, onOpen)
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener(PALETTE_EVENT, onOpen) }
  }, [])
  useEffect(() => { if (open) { setQ(''); setSel(0); setTimeout(() => input.current?.focus(), 0) } }, [open])

  const assets = useQuery({ queryKey: ['palette-assets'], queryFn: assetsApi.list, enabled: open, staleTime: 60000, retry: false })
  const pages = useMemo(() => {
    const { agentNav, centralNav } = buildNav(t as never, role === 'admin')
    return [...flatten(agentNav, false), ...flatten(centralNav, true)]
  }, [t, role])
  const hits = useMemo(() => {
    const all: Hit[] = [...pages, ...(assets.data ?? []).filter(a => a.id != null).map((a): Hit => ({ key: `s:${a.id}`, label: a.name || a.ip || `#${a.id}`, hint: [a.ip, a.type].filter(Boolean).join(' · '), to: hostPath(a.ip, a.id) ?? `/inventory/${a.id}`, kind: 'asset' }))]
    const tokens = fold(q).split(/\s+/).filter(Boolean)
    if (tokens.length === 0) return pages.filter(p => p.kind === 'page').slice(0, 12)
    const scored: Array<[number, Hit]> = []
    for (const h of all) {
      const hay = fold(`${h.label} ${h.hint}`)
      if (!tokens.every(tk => hay.includes(tk))) continue
      const label = fold(h.label)
      scored.push([(label.startsWith(tokens[0]) ? 0 : label.includes(tokens[0]) ? 1 : 2) + (h.kind === 'asset' ? 0.5 : h.kind === 'central' ? 0.3 : 0), h])
    }
    return scored.sort((a, b) => a[0] - b[0]).slice(0, 14).map(x => x[1])
  }, [q, pages, assets.data])
  useEffect(() => { setSel(0) }, [q])

  if (!open) return null
  const go = (h: Hit) => { setOpen(false); nav(h.to) }
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') setOpen(false)
    else if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(hits.length - 1, s + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSel(s => Math.max(0, s - 1)) }
    else if (e.key === 'Enter' && hits[sel]) { e.preventDefault(); go(hits[sel]) }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] bg-slate-900/40" onMouseDown={() => setOpen(false)}>
      <div className="w-full max-w-xl mx-4 bg-white rounded-xl shadow-2xl border border-slate-200 overflow-hidden" onMouseDown={e => e.stopPropagation()} onKeyDown={onKey}>
        <div className="flex items-center gap-2 px-4 border-b border-slate-200">
          <Search size={16} className="text-slate-400" />
          <input ref={input} value={q} onChange={e => setQ(e.target.value)} placeholder={t('palette.placeholder') as string} className="flex-1 py-3 text-sm outline-none bg-transparent" />
          <kbd className="text-[10px] text-slate-400 border border-slate-200 rounded px-1">Esc</kbd>
        </div>
        <ul className="max-h-[50vh] overflow-y-auto py-1">
          {hits.length === 0 && <li className="px-4 py-6 text-center text-sm text-slate-400">{t('palette.none')}</li>}
          {hits.map((h, i) => (
            <li key={h.key}>
              <button onMouseEnter={() => setSel(i)} onClick={() => go(h)} className={cn('w-full flex items-center gap-3 px-4 py-2 text-left text-sm', i === sel ? 'bg-indigo-50' : 'hover:bg-slate-50')}>
                <span className="w-5 shrink-0 text-slate-400">{h.Icon ? <h.Icon size={15} /> : <Search size={15} />}</span>
                <span className="flex-1 min-w-0 truncate text-slate-900">{h.label}</span>
                {h.kind === 'central' && <span className="text-[10px] uppercase tracking-wide text-indigo-600 border border-indigo-200 rounded px-1">{t('palette.central')}</span>}
                {h.kind === 'asset' && <span className="text-[10px] uppercase tracking-wide text-emerald-700 border border-emerald-200 rounded px-1">{t('palette.asset')}</span>}
                <span className="text-xs text-slate-400 truncate max-w-[10rem]">{h.hint}</span>
                {i === sel && <CornerDownLeft size={13} className="text-slate-400" />}
              </button>
            </li>
          ))}
        </ul>
        <div className="px-4 py-1.5 border-t border-slate-100 text-[11px] text-slate-400">{t('palette.hint')}</div>
      </div>
    </div>
  )
}

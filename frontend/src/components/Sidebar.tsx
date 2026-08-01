import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Server, Key, Search, ScrollText, Network, Globe, RefreshCw, Cloud, GitCommit, Download } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { cn } from '../lib/utils'
import { SUPPORTED_LANGS } from '../i18n'
import { systemApi } from '../lib/api'
import axios from 'axios'

function RefresherStatus() {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['refresh-status'],
    queryFn: systemApi.refreshStatus,
    refetchInterval: 10_000,
  })

  const trigger = useMutation({
    mutationFn: systemApi.runRefresh,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['refresh-status'] }),
  })

  if (!data) return null

  const lastRun = data.last_run ? new Date(data.last_run) : null
  const minsAgo = lastRun ? Math.round((Date.now() - lastRun.getTime()) / 60000) : null
  const nextInMin = data.next_run_estimated
    ? Math.max(0, Math.round((data.next_run_estimated * 1000 - Date.now()) / 60000))
    : null

  const whenStr = lastRun
    ? lastRun.toLocaleTimeString(i18n.language, { hour: '2-digit', minute: '2-digit' }) +
      (minsAgo !== null && minsAgo < 60 ? ` (${minsAgo}m)` : '')
    : t('refresher.neverRun')

  return (
    <div className="px-4 py-3 border-t border-slate-200 space-y-2 text-[10.5px]">
      <div className="flex items-center justify-between">
        <span className="text-slate-500 uppercase tracking-wider font-semibold">{t('refresher.label')}</span>
        <button
          onClick={() => trigger.mutate()}
          disabled={data.in_progress || trigger.isPending}
          title={t('refresher.runManual') as string}
          className="text-slate-500 hover:text-indigo-600 disabled:opacity-40"
        >
          <RefreshCw size={11} className={data.in_progress ? 'animate-spin' : ''} />
        </button>
      </div>
      {data.in_progress ? (
        <p className="text-indigo-600">{t('refresher.running')}</p>
      ) : (
        <>
          <p className="text-slate-600 truncate">{t('refresher.lastRun', { when: whenStr })}</p>
          {nextInMin !== null && (
            <p className="text-slate-400">{t('refresher.nextRun', { min: nextInMin })}</p>
          )}
        </>
      )}
      <p className="text-slate-400">{t('refresher.intervalEvery', { min: data.interval_min })}</p>
    </div>
  )
}

function LanguageSwitcher() {
  const { i18n } = useTranslation()
  const [open, setOpen] = useState(false)

  const current = SUPPORTED_LANGS.find(l => l.code === i18n.language) ?? SUPPORTED_LANGS[0]

  return (
    <div className="relative px-3 py-2">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors"
      >
        <Globe size={13} />
        <span>{current.flag} {current.name}</span>
      </button>
      {open && (
        <div className="absolute bottom-full left-3 right-3 mb-1 bg-white border border-slate-200 rounded-lg shadow-lg overflow-hidden">
          {SUPPORTED_LANGS.map(lang => (
            <button
              key={lang.code}
              onClick={() => { i18n.changeLanguage(lang.code); setOpen(false) }}
              className={cn(
                'w-full text-left px-3 py-2 text-xs hover:bg-slate-100 transition-colors',
                i18n.language === lang.code ? 'text-indigo-600 bg-indigo-50 font-medium' : 'text-slate-700'
              )}
            >
              {lang.flag} {lang.name}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export function Sidebar() {
  const { t } = useTranslation()

  const nav = [
    { to: '/', label: t('nav.dashboard'), icon: LayoutDashboard },
    { to: '/devices', label: t('nav.devices'), icon: Server },
    { to: '/map', label: t('nav.map'), icon: Network },
    { to: '/scanner', label: t('nav.scanner'), icon: Search },
    { to: '/credentials', label: t('nav.credentials'), icon: Key },
    { to: '/logs', label: t('nav.logs'), icon: ScrollText },
    { to: '/central', label: t('nav.central'), icon: Cloud },
  ]

  return (
    <aside className="w-56 shrink-0 bg-white border-r border-slate-200 flex flex-col">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-slate-200">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 bg-indigo-600 rounded-lg flex items-center justify-center">
            <Network size={15} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-slate-900 leading-none">MikroManager</p>
            <p className="text-[10px] text-slate-500 mt-0.5">RouterOS v6 / v7</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {nav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 font-medium'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      <RefresherStatus />
      <SelfUpdatePanel />
      <LanguageSwitcher />

      <div className="px-5 py-3 border-t border-slate-200">
        <p className="text-[10px] text-slate-400">MikroManager v1.3</p>
      </div>
    </aside>
  )
}

function SelfUpdatePanel() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: self } = useQuery({
    queryKey: ['self-version'],
    queryFn: systemApi.selfVersion,
    refetchInterval: 60_000,
  })
  const { data: updaterStatus } = useQuery({
    queryKey: ['updater-status'],
    queryFn: () => axios.get('/api/system/updater/status').then(r => r.data),
    refetchInterval: 5_000,
  })

  const trigger = useMutation({
    mutationFn: () => axios.post('/api/system/updater/run').then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['updater-status'] }),
  })

  if (!self) return null

  const inProgress = updaterStatus?.in_progress === true

  const handleClick = () => {
    if (inProgress) return
    if (!confirm(t('sidebar.updateConfirm') as string)) return
    trigger.mutate()
  }

  return (
    <div className="px-4 py-3 border-t border-slate-200 text-[10.5px] space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-slate-500 uppercase tracking-wider font-semibold flex items-center gap-1">
          <GitCommit size={10} /> {t('sidebar.versionLabel')}
        </span>
        <button
          onClick={handleClick}
          disabled={inProgress || trigger.isPending}
          title={t('sidebar.updateAppTooltip') as string}
          className="text-slate-500 hover:text-indigo-600 disabled:opacity-40 inline-flex items-center gap-1"
        >
          {inProgress
            ? <RefreshCw size={11} className="animate-spin" />
            : <Download size={11} />}
        </button>
      </div>
      <p className="font-mono text-slate-700 truncate">{self.commit?.slice(0, 10) ?? '—'}</p>
      {inProgress && (
        <p className="text-indigo-600 italic">{t('sidebar.updating')}</p>
      )}
    </div>
  )
}

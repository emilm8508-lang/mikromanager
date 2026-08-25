import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Server, Key, Search, ScrollText, Network, Globe, RefreshCw, Cloud, GitCommit, Download, LogOut, KeyRound, ShieldAlert, ClipboardList, ShieldCheck, TerminalSquare, Boxes, MonitorSmartphone } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, useEffect } from 'react'
import { cn } from '../lib/utils'
import { SUPPORTED_LANGS } from '../i18n'
import { api, systemApi, authApi, MfaSetupInfo, uiMode, UiMode } from '../lib/api'
import { useAuth } from '../pages/Login'
import { Modal } from './ui/Modal'
import { Input } from './ui/Input'

function formatMinutes(min: number): string {
  if (min < 60) return `${min} min`
  if (min < 1440) return `${Math.round(min / 60)} h`
  return `${Math.round(min / 1440)} d`
}

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
            <p className="text-slate-400">{t('refresher.nextRun', { min: formatMinutes(nextInMin) })}</p>
          )}
        </>
      )}
      <p className="text-slate-400">{t('refresher.intervalEvery', { min: formatMinutes(data.interval_min) })}</p>
      {data.ping_interval_min != null && (
        <p className="text-slate-400">{t('refresher.pingEvery', { min: formatMinutes(data.ping_interval_min) })}</p>
      )}
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

function ShowSecretModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const [info, setInfo] = useState<MfaSetupInfo | null>(null)
  const [error, setError] = useState('')
  const [justRegenerated, setJustRegenerated] = useState(false)
  const [showRetype, setShowRetype] = useState(false)
  const [retypeSecret, setRetypeSecret] = useState('')

  const fetchSecret = useMutation({
    mutationFn: authApi.totpSecret,
    onSuccess: setInfo,
    onError: () => setError(t('auth.genericError') as string),
  })

  const regenerate = useMutation({
    mutationFn: () => authApi.totpSecretRegenerate(retypeSecret || undefined),
    onSuccess: (data) => { setInfo(data); setJustRegenerated(true); setShowRetype(false); setRetypeSecret('') },
    onError: () => setError(t('auth.genericError') as string),
  })

  useEffect(() => {
    if (open && !info && !error) fetchSecret.mutate()
  }, [open])

  return (
    <Modal open={open} onClose={() => { onClose(); setInfo(null); setError(''); setJustRegenerated(false); setShowRetype(false); setRetypeSecret('') }} title={t('auth.reuseSecretLabel') as string}>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {!info && !error && <p className="text-sm text-slate-500">{t('common.loading')}</p>}
      {info && (
        <div className="space-y-3">
          <p className="text-xs text-slate-500">
            {justRegenerated ? t('auth.mfaRegeneratedHint') : t('auth.mfaSecretExportHint')}
          </p>
          <div className="flex justify-center bg-white border border-slate-200 rounded-lg p-3">
            <img src={info.qr_svg_data_uri} alt="TOTP QR code" className="w-40 h-40" />
          </div>
          <p className="font-mono text-xs text-slate-700 break-all bg-slate-100 rounded px-2 py-1">
            {info.secret}
          </p>
          {!showRetype ? (
            <button
              type="button"
              onClick={() => setShowRetype(true)}
              className="text-xs text-red-600 hover:underline"
            >
              {t('auth.mfaRegenerateButton')}
            </button>
          ) : (
            <div className="space-y-1">
              <Input label={t('auth.reuseSecretLabel') as string} value={retypeSecret}
                onChange={e => setRetypeSecret(e.target.value)}
                placeholder="RC63HTOZD75QBACER6JWVUPFFANYUXFJ" />
              <p className="text-[11px] text-slate-500">{t('auth.resumeRetypeHint')}</p>
              <div className="flex gap-2 justify-end pt-1">
                <button type="button" onClick={() => { setShowRetype(false); setRetypeSecret('') }}
                  className="text-xs text-slate-500 hover:underline">
                  {t('common.cancel')}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    if (confirm(t('auth.mfaRegenerateConfirm') as string)) regenerate.mutate()
                  }}
                  disabled={regenerate.isPending}
                  className="text-xs text-red-600 hover:underline"
                >
                  {t('auth.mfaRegenerateButton')}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </Modal>
  )
}

function AccountPanel() {
  const { t } = useTranslation()
  const { username, role, source, logout } = useAuth()
  const [showSecret, setShowSecret] = useState(false)
  return (
    <div className="border-t border-slate-200">
      {source === 'local' && (
        <div
          className="px-4 py-1.5 flex items-center gap-1.5 bg-amber-50 text-amber-700 text-[10px] font-medium"
          title={t('auth.loginLocalBanner') as string}
        >
          <ShieldAlert size={12} className="shrink-0" />
          <span className="truncate">{t('auth.loginLocalBanner')}</span>
        </div>
      )}
      <div className="px-4 py-3 flex items-center justify-between">
        <span className="text-xs text-slate-600 truncate" title={`${username} · ${t(`auth.role${role === 'admin' ? 'Admin' : 'Viewer'}`)}`}>
          {username}
        </span>
        <div className="flex items-center gap-2 shrink-0">
          {source === 'local' && (
            <button
              onClick={() => setShowSecret(true)}
              title={t('auth.reuseSecretLabel') as string}
              className="text-slate-500 hover:text-indigo-600"
            >
              <KeyRound size={14} />
            </button>
          )}
          <button
            onClick={logout}
            title={t('auth.logout') as string}
            className="text-slate-500 hover:text-red-600"
          >
            <LogOut size={14} />
          </button>
        </div>
        <ShowSecretModal open={showSecret} onClose={() => setShowSecret(false)} />
      </div>
    </div>
  )
}

export function Sidebar() {
  const { t } = useTranslation()
  const { role } = useAuth()
  const [mode, setMode] = useState<UiMode>(uiMode.load())

  const setModeAndSave = (m: UiMode) => {
    uiMode.save(m)
    setMode(m)
  }

  const agentNav = [
    { to: '/', label: t('nav.dashboard'), icon: LayoutDashboard },
    { to: '/devices', label: t('nav.devices'), icon: Server },
    { to: '/map', label: t('nav.map'), icon: Network },
    { to: '/scanner', label: t('nav.scanner'), icon: Search },
    { to: '/credentials', label: t('nav.credentials'), icon: Key },
    { to: '/logs', label: t('nav.logs'), icon: ScrollText },
    { to: '/vulnerabilities', label: t('nav.vulnerabilities'), icon: ShieldAlert },
    { to: '/linux', label: t('nav.linuxHosts'), icon: TerminalSquare },
    { to: '/windows', label: t('nav.windowsHosts'), icon: MonitorSmartphone },
    { to: '/inventory', label: t('nav.inventory'), icon: Boxes },
    // Read-only accounts can't act on any admin-action trail meaningfully
    // (the endpoint itself is admin-only too — this just avoids a dead
    // link + surprise 403 in the nav).
    ...(role === 'admin' ? [{ to: '/audit', label: t('nav.audit'), icon: ClipboardList }] : []),
    ...(role === 'admin' ? [{ to: '/security', label: t('nav.security'), icon: ShieldCheck }] : []),
  ]
  const centralNavItem = { to: '/central', label: t('nav.central'), icon: Cloud }
  const centralInventoryNavItem = { to: '/central/inventory', label: t('nav.inventory'), icon: Boxes }
  // 'central' mode is a purely local display preference — hides agent-only
  // tabs for a computer that's only ever used to view Central. Every local
  // backend service (uplink, scanner, vuln_scan...) keeps running regardless;
  // this doesn't touch anything server-side.
  const nav = mode === 'central' ? [centralNavItem, centralInventoryNavItem] : [...agentNav, centralNavItem]

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

      {/* Agent/Central UI mode toggle */}
      <div className="px-3 pt-3">
        <div className="flex rounded-lg border border-slate-200 p-0.5 bg-slate-50 text-xs">
          <button
            onClick={() => setModeAndSave('agent')}
            className={cn(
              'flex-1 py-1 rounded-md transition-colors',
              mode === 'agent' ? 'bg-white text-slate-900 font-medium shadow-sm' : 'text-slate-500 hover:text-slate-700'
            )}
          >
            {t('nav.modeAgent')}
          </button>
          <button
            onClick={() => setModeAndSave('central')}
            className={cn(
              'flex-1 py-1 rounded-md transition-colors',
              mode === 'central' ? 'bg-white text-slate-900 font-medium shadow-sm' : 'text-slate-500 hover:text-slate-700'
            )}
          >
            {t('nav.modeCentral')}
          </button>
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
      <AccountPanel />

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
    queryFn: () => api.get('/system/updater/status').then(r => r.data),
    refetchInterval: 5_000,
  })

  const trigger = useMutation({
    mutationFn: () => api.post('/system/updater/run').then(r => r.data),
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
      {!inProgress && updaterStatus?.last_error && (
        <p
          className="text-red-600"
          title={Array.isArray(updaterStatus.last_log_tail) ? updaterStatus.last_log_tail.join('\n') : undefined}
        >
          {t('sidebar.updateError')}: {updaterStatus.last_error}
        </p>
      )}
    </div>
  )
}

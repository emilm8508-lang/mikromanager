import { NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, Server, Key, Search, ScrollText, Network, Globe, RefreshCw, Cloud, GitCommit, Download, LogOut, KeyRound, ShieldAlert, ClipboardList, ShieldCheck, TerminalSquare, Boxes, MonitorSmartphone, Package, ListChecks, History, ServerCog, Activity, Router, Layers, ShieldQuestion, Radar, PieChart, ChevronDown, Settings, Rows3, Waypoints, Sun, Moon, MonitorCog, Siren, Gauge, MapPin, HeartPulse, Layers3, Radio, FileClock, Sparkles, BellOff, LineChart, BatteryCharging } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, useEffect } from 'react'
import { loadTheme, saveTheme, type ThemeMode } from '../lib/theme'
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

// light -> dark -> follow the system; the palette itself is src/theme.css (the class "dark" on <html>)
function ThemeSwitcher() {
  const { t } = useTranslation()
  const [mode, setMode] = useState<ThemeMode>(loadTheme())
  const next = () => { const n: ThemeMode = mode === 'light' ? 'dark' : mode === 'dark' ? 'auto' : 'light'; saveTheme(n); setMode(n) }
  const Icon = mode === 'dark' ? Moon : mode === 'auto' ? MonitorCog : Sun
  return (
    <div className="px-3 pt-1">
      <button onClick={next} title={t('nav.theme.label') as string} className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors">
        <Icon size={13} /><span>{t(`nav.theme.${mode}`)}</span>
      </button>
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

type NavItem = { to: string; label: string; icon: typeof Server }
type NavGroup = { key: string; label: string; icon: typeof Server; items: NavItem[] }
type NavEntry = NavItem | NavGroup
const NAV_OPEN_KEY = 'mikromanager_nav_open'

export function Sidebar() {
  const { t } = useTranslation()
  const { role } = useAuth()
  const [mode, setMode] = useState<UiMode>(uiMode.load())

  const setModeAndSave = (m: UiMode) => {
    uiMode.save(m)
    setMode(m)
  }

  // The menu is grouped: a few always-visible entries on top, then collapsible groups. A group opens by itself when
  // the page you are on belongs to it, and what you open or close is remembered.
  const admin = role === 'admin'
  const item = (to: string, label: string, icon: NavItem['icon']): NavItem => ({ to, label, icon })

  const agentNav: NavEntry[] = [
    item('/', t('nav.dashboard') as string, LayoutDashboard),
    item('/security-summary', t('nav.securitySummary') as string, PieChart),
    item('/assistant', t('nav.ai') as string, Sparkles),
    { key: 'soc', label: t('nav.groupSoc') as string, icon: Siren, items: [
      item('/soc', t('nav.socAlerts') as string, Siren),
      item('/soc/risk', t('nav.socRisk') as string, Gauge),
      item('/soc/rules', t('nav.socRules') as string, ListChecks),
      item('/soc/syslog', t('nav.syslog') as string, Radio),
      item('/soc/hostlogs', t('nav.hostlogs') as string, ScrollText),
    ] },
    { key: 'systems', label: t('nav.groupSystems') as string, icon: Server, items: [
      item('/mikrotik', t('nav.mikrotik') as string, Router),
      item('/config-history', t('nav.cfg') as string, FileClock),
      item('/linux', t('nav.linuxHosts') as string, TerminalSquare),
      item('/windows', t('nav.windowsHosts') as string, MonitorSmartphone),
      item('/hyperv', t('nav.hyperv') as string, Layers),
      item('/dell-servers', t('nav.dellServers') as string, ServerCog),
      item('/ups', t('nav.ups') as string, BatteryCharging),
      item('/hostmon', t('nav.hostMonitor') as string, Radar),
    ] },
    { key: 'network', label: t('nav.groupNetwork') as string, icon: Network, items: [
      item('/devices', t('nav.devices') as string, Server),
      item('/map', t('nav.map') as string, Network),
      item('/netmap', t('nav.netmap') as string, Waypoints),
      item('/availability', t('nav.avail') as string, HeartPulse),
      item('/services', t('nav.svc') as string, Layers3),
      item('/maintenance', t('nav.maint') as string, BellOff),
      item('/metrics', t('nav.metrics') as string, LineChart),
      item('/traffic', t('nav.traffic') as string, Activity),
      item('/scanner', t('nav.scanner') as string, Search),
      item('/logs', t('nav.logs') as string, ScrollText),
    ] },
    { key: 'compliance', label: t('nav.groupCompliance') as string, icon: ShieldCheck, items: [
      item('/vulnerabilities', t('nav.vulnerabilities') as string, ShieldAlert),
      item('/compliance', t('nav.compliance') as string, ListChecks),
      // Read-only accounts can't act on any admin-action trail meaningfully (the endpoints are admin-only too — this
      // just avoids a dead link + surprise 403 in the nav).
      ...(admin ? [item('/security', t('nav.security') as string, ShieldCheck), item('/audit', t('nav.audit') as string, ClipboardList)] : []),
    ] },
    { key: 'assets', label: t('nav.groupAssets') as string, icon: Boxes, items: [
      item('/inventory', t('nav.assetsOverview') as string, PieChart),
      item('/inventory/list', t('nav.assetsList') as string, Boxes),
      item('/racks', t('nav.racks') as string, Rows3),
      item('/onsite', t('nav.onsite') as string, MapPin),
      item('/software', t('nav.software') as string, Package),
    ] },
    { key: 'admin', label: t('nav.groupAdmin') as string, icon: Settings, items: [
      item('/credentials', t('nav.credentials') as string, Key),
      // Personal tool for the one control machine used to connect to clients via AnyDesk — admin-only like audit/security.
      ...(admin ? [item('/anydesk', t('nav.anydeskSessions') as string, History)] : []),
    ] },
    item('/central', t('nav.central') as string, Cloud),
  ]

  // Central mode: a purely local display preference — hides agent-only tabs for a computer that's only ever used to
  // view Central. Every local backend service (uplink, scanner, vuln_scan...) keeps running regardless.
  // Dell/iDRAC hardware health and Linux/Windows OS patch status are deliberately separate entries (different concern).
  const centralNav: NavEntry[] = [
    item('/central', t('nav.central') as string, Cloud),
    item('/central/security', t('nav.securitySummary') as string, PieChart),
    item('/central/soc', t('nav.soc') as string, Siren),
    { key: 'c-systems', label: t('nav.groupSystems') as string, icon: Server, items: [
      item('/central/fleet', t('fleetCentral.navLabel') as string, Router),
      item('/central/hosts', t('centralHosts.navLabel') as string, TerminalSquare),
      item('/central/hyperv', t('hypervCentral.navLabel') as string, Layers),
      item('/central/servers', t('central.tabServers') as string, ServerCog),
      item('/central/routers', t('routersCentral.navLabel') as string, Router),
    ] },
    { key: 'c-netsvc', label: t('nav.groupNetSvc') as string, icon: HeartPulse, items: [
      item('/central/services', t('nav.svc') as string, Layers3),
      item('/central/availability', t('nav.avail') as string, HeartPulse),
      item('/central/configs', t('nav.cfg') as string, FileClock),
      item('/central/syslog', t('nav.syslog') as string, Radio),
    ] },
    { key: 'c-monitoring', label: t('nav.groupMonitoring') as string, icon: Activity, items: [
      item('/central/external-monitoring', t('externalMonitoringCentral.navLabel') as string, Activity),
      item('/central/hostmon', t('hostmonCentral.navLabel') as string, Radar),
    ] },
    { key: 'c-compliance', label: t('nav.groupCompliance') as string, icon: ShieldCheck, items: [
      item('/central/vulnerabilities', t('nav.vulnerabilities') as string, ShieldAlert),
      item('/central/compliance', t('nav.compliance') as string, ListChecks),
      item('/central/firewall-usage', t('firewallUsageCentral.navLabel') as string, ShieldQuestion),
      item('/central/firewall-logs', t('firewallLogsCentral.navLabel') as string, ScrollText),
    ] },
    { key: 'c-assets', label: t('nav.groupAssets') as string, icon: Boxes, items: [
      item('/central/assets', t('nav.assetsOverview') as string, PieChart),
      item('/central/inventory', t('nav.inventory') as string, Boxes),
      item('/central/racks', t('nav.racks') as string, Rows3),
      item('/central/netmap', t('nav.netmap') as string, Waypoints),
    ] },
  ]
  const nav = mode === 'central' ? centralNav : agentNav

  // which groups are open: remembered, and the group of the current page is always open
  const { pathname } = useLocation()
  const [open, setOpen] = useState<Record<string, boolean>>(() => {
    try { return JSON.parse(localStorage.getItem(NAV_OPEN_KEY) || '{}') } catch { return {} }
  })
  const isActive = (to: string) => (to === '/' ? pathname === '/' : pathname === to || pathname.startsWith(`${to}/`))
  const activeGroup = nav.find((e): e is NavGroup => 'items' in e && e.items.some(i => isActive(i.to)))?.key
  const save = (next: Record<string, boolean>) => {
    setOpen(next)
    try { localStorage.setItem(NAV_OPEN_KEY, JSON.stringify(next)) } catch { /* storage unavailable */ }
  }
  useEffect(() => {
    if (activeGroup && !open[activeGroup]) save({ ...open, [activeGroup]: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeGroup])
  const toggle = (key: string) => save({ ...open, [key]: !open[key] })

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
      <nav className="flex-1 min-h-0 overflow-y-auto px-3 py-3 space-y-0.5">
        {nav.map(entry => 'items' in entry ? (
          <div key={entry.key} className="pt-1">
            <button
              onClick={() => toggle(entry.key)}
              aria-expanded={!!open[entry.key]}
              className={cn(
                'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                activeGroup === entry.key ? 'text-indigo-700 font-medium' : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100'
              )}
            >
              <entry.icon size={16} />
              <span className="flex-1 text-left">{entry.label}</span>
              {activeGroup === entry.key && !open[entry.key] && <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />}
              <ChevronDown size={14} className={cn('text-slate-400 transition-transform', open[entry.key] ? 'rotate-0' : '-rotate-90')} />
            </button>
            {open[entry.key] && (
              <div className="ml-4 pl-2 border-l border-slate-200 space-y-0.5 mt-0.5">
                {entry.items.map(({ to, label, icon: Icon }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === '/inventory' || to === '/soc'}
                    className={({ isActive: a }) =>
                      cn(
                        'flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-[13px] transition-colors',
                        a
                          ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 font-medium'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                      )
                    }
                  >
                    <Icon size={14} />
                    {label}
                  </NavLink>
                ))}
              </div>
            )}
          </div>
        ) : (
          <NavLink
            key={entry.to}
            to={entry.to}
            end={entry.to === '/'}
            className={({ isActive: a }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                a
                  ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 font-medium'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              )
            }
          >
            <entry.icon size={16} />
            {entry.label}
          </NavLink>
        ))}
      </nav>

      <RefresherStatus />
      <SelfUpdatePanel />
      <LanguageSwitcher />
      <ThemeSwitcher />
      <AccountPanel />

      <VersionFooter />
    </aside>
  )
}

function ChangelogModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const { data, isLoading } = useQuery({
    queryKey: ['changelog'],
    queryFn: systemApi.changelog,
    enabled: open,
  })

  return (
    <Modal open={open} onClose={onClose} title={t('sidebar.changelogTitle')}>
      <div className="max-h-[60vh] overflow-y-auto space-y-4 pr-1">
        {isLoading ? (
          <p className="text-sm text-slate-500">{t('common.loading')}</p>
        ) : (
          data?.entries.map(entry => (
            <div key={entry.version}>
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-sm font-semibold text-slate-900">{entry.version}</span>
                <span className="text-xs text-slate-400">{entry.date}</span>
              </div>
              <ul className="mt-1 list-disc list-inside text-xs text-slate-600 space-y-0.5">
                {entry.changes.map((c, i) => <li key={i}>{c}</li>)}
              </ul>
            </div>
          ))
        )}
      </div>
    </Modal>
  )
}

function VersionFooter() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const { data } = useQuery({
    queryKey: ['changelog-current'],
    queryFn: systemApi.changelog,
    staleTime: 5 * 60_000,
  })

  return (
    <div className="px-5 py-3 border-t border-slate-200">
      <button
        onClick={() => setOpen(true)}
        className="text-[10px] text-slate-400 hover:text-indigo-600 flex items-center gap-1"
      >
        <History size={10} />
        MikroManager v{data?.current_version ?? '…'} — {t('sidebar.changelogLink')}
      </button>
      <ChangelogModal open={open} onClose={() => setOpen(false)} />
    </div>
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

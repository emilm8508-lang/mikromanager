import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { hostServicesApi, HostServiceOut, HostServiceParams, DiscoveredService, ServicePlatform } from '../lib/api'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import { RefreshCw, Trash2, Plus, ListChecks, History, ChevronDown, ChevronUp } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/utils'

const INTERVALS = [1, 2, 5, 10, 15, 30, 60]
const ALERT_AFTER = [1, 2, 3, 5, 10]

function errText(e: unknown): string {
  const anyE = e as any
  return anyE?.response?.data?.detail || anyE?.message || String(e)
}

function formatDuration(sec: number | null | undefined): string {
  if (sec == null) return '—'
  if (sec < 60) return `${sec} s`
  const m = Math.floor(sec / 60)
  if (m < 60) return `${m} min`
  const h = Math.floor(m / 60)
  return h < 24 ? `${h} h ${m % 60} min` : `${Math.floor(h / 24)} d ${h % 24} h`
}

function Select<T extends string | number>({ value, options, onChange, label, render }: {
  value: T; options: T[]; onChange: (v: T) => void; label: string; render: (v: T) => string
}) {
  return (
    <label className="flex flex-col text-[10px] text-slate-500 gap-0.5">
      {label}
      <select value={value} onChange={e => onChange((typeof value === 'number' ? Number(e.target.value) : e.target.value) as T)}
        className="border border-slate-300 rounded px-1.5 py-1 text-xs text-slate-800 bg-white">
        {options.map(o => <option key={String(o)} value={o}>{render(o)}</option>)}
      </select>
    </label>
  )
}

function ServiceRow({ s, platform, hostId }: { s: HostServiceOut; platform: ServicePlatform; hostId: number }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const refresh = () => qc.invalidateQueries({ queryKey: ['host-services', platform, hostId] })
  const update = useMutation({
    mutationFn: (params: HostServiceParams) => hostServicesApi.update(platform, s.id, params),
    onSuccess: refresh,
  })
  const remove = useMutation({ mutationFn: () => hostServicesApi.remove(platform, s.id), onSuccess: refresh })

  const badge = !s.enabled ? <Badge variant="gray">{t('hostServices.statusPaused')}</Badge>
    : s.ok === true ? <Badge variant="green">{t('hostServices.statusOk')}</Badge>
    : s.ok === false ? <Badge variant="red">{t('hostServices.statusProblem')}</Badge>
    : <Badge variant="gray">{t('hostServices.statusUnknown')}</Badge>

  return (
    <div className={cn('bg-white border rounded-lg px-3 py-2 space-y-2', s.ok === false && s.enabled ? 'border-red-300' : 'border-slate-200')}>
      <div className="flex items-start justify-between gap-2 flex-wrap">
        <div className="flex items-start gap-2 min-w-0">
          {badge}
          <div className="min-w-0">
            <div className="text-sm font-medium text-slate-900 break-all">{s.display_name || s.service_name}</div>
            <div className="text-[11px] text-slate-500 font-mono break-all">
              {s.service_name}
              {s.state && <> · {t(`hostServices.state.${s.state}`)}{s.status && s.status.toLowerCase() !== s.state ? ` (${s.status})` : ''}</>}
              {s.status_since && <> · {t('hostServices.since', { time: new Date(s.status_since).toLocaleString() })}</>}
              {s.startup && <> · {t('hostServices.startup')}: {s.startup}</>}
            </div>
            {s.enabled && s.fail_streak > 0 && (
              <div className="text-[11px] text-amber-700">
                {t('hostServices.failStreak', { n: s.fail_streak, max: s.alert_after_fails })}
                {s.incident_open && <b> · {t('hostServices.incidentOpen')}</b>}
              </div>
            )}
          </div>
        </div>
        <button onClick={() => remove.mutate()} className="text-slate-400 hover:text-red-600" title={t('hostServices.remove') as string}>
          <Trash2 size={13} />
        </button>
      </div>
      <div className="flex items-end gap-3 flex-wrap">
        <Select label={t('hostServices.expectedLabel') as string} value={s.expected_state} options={['running', 'stopped'] as ('running' | 'stopped')[]}
          render={v => t(v === 'running' ? 'hostServices.expectedRunning' : 'hostServices.expectedStopped') as string}
          onChange={v => update.mutate({ expected_state: v })} />
        <Select label={t('hostServices.intervalLabel') as string} value={s.interval_min}
          options={INTERVALS.includes(s.interval_min) ? INTERVALS : [...INTERVALS, s.interval_min].sort((a, b) => a - b)}
          render={v => t('hostServices.intervalOpt', { n: v }) as string} onChange={v => update.mutate({ interval_min: v })} />
        <Select label={t('hostServices.alertAfterLabel') as string} value={s.alert_after_fails}
          options={ALERT_AFTER.includes(s.alert_after_fails) ? ALERT_AFTER : [...ALERT_AFTER, s.alert_after_fails].sort((a, b) => a - b)}
          render={v => t('hostServices.alertAfterOpt', { n: v }) as string} onChange={v => update.mutate({ alert_after_fails: v })} />
        <label className="flex items-center gap-1 text-xs text-slate-700 pb-1.5">
          <input type="checkbox" checked={s.alert_enabled} onChange={e => update.mutate({ alert_enabled: e.target.checked })} />
          {t('hostServices.alertLabel')}
        </label>
        <label className="flex items-center gap-1 text-xs text-slate-700 pb-1.5">
          <input type="checkbox" checked={s.enabled} onChange={e => update.mutate({ enabled: e.target.checked })} />
          {t('hostServices.activeLabel')}
        </label>
      </div>
      {update.isError && <p className="text-xs text-red-700">{errText(update.error)}</p>}
    </div>
  )
}

function DiscoverPanel({ platform, hostId, onDone }: { platform: ServicePlatform; hostId: number; onDone: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [filter, setFilter] = useState('')
  const [stateFilter, setStateFilter] = useState<'all' | 'running' | 'stopped'>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [interval, setIntervalMin] = useState(5)
  const [alertAfter, setAlertAfter] = useState(2)

  const { data: found, isFetching, error } = useQuery({
    queryKey: ['host-services-discover', platform, hostId],
    queryFn: () => hostServicesApi.discover(platform, hostId),
    staleTime: 0, gcTime: 0, retry: false,
  })
  const add = useMutation({
    mutationFn: () => hostServicesApi.add(platform, hostId, (found ?? []).filter(s => selected.has(s.name)).map(s => ({
      name: s.name, display_name: s.display_name, startup: s.startup, interval_min: interval, alert_after_fails: alertAfter,
    }))),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['host-services', platform, hostId] }); onDone() },
  })

  const q = filter.trim().toLowerCase()
  const visible = (found ?? []).filter((s: DiscoveredService) =>
    (stateFilter === 'all' || (stateFilter === 'running' ? s.state === 'running' : s.state !== 'running'))
    && (!q || s.name.toLowerCase().includes(q) || (s.display_name ?? '').toLowerCase().includes(q)))

  const toggle = (name: string) => setSelected(prev => {
    const next = new Set(prev)
    next.has(name) ? next.delete(name) : next.add(name)
    return next
  })

  return (
    <div className="border border-indigo-200 bg-indigo-50/40 rounded-lg p-3 space-y-2">
      <div className="text-xs font-semibold text-slate-700">{t('hostServices.discoverTitle')}</div>
      <p className="text-[11px] text-slate-500">{t('hostServices.discoverHint')}</p>
      {isFetching && <p className="text-xs text-slate-500">{t('hostServices.discovering')}</p>}
      {error && <p className="text-xs text-red-700">{errText(error)}</p>}
      {found && (
        <>
          <div className="flex items-center gap-2 flex-wrap">
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder={t('hostServices.filterPlaceholder') as string}
              className="border border-slate-300 rounded px-2 py-1 text-xs flex-1 min-w-[10rem] bg-white" />
            <select value={stateFilter} onChange={e => setStateFilter(e.target.value as typeof stateFilter)}
              className="border border-slate-300 rounded px-2 py-1 text-xs bg-white">
              <option value="all">{t('hostServices.filterAll')}</option>
              <option value="running">{t('hostServices.filterRunning')}</option>
              <option value="stopped">{t('hostServices.filterNotRunning')}</option>
            </select>
            <span className="text-[11px] text-slate-500">{visible.length} / {found.length}</span>
          </div>
          <div className="max-h-64 overflow-y-auto bg-white border border-slate-200 rounded divide-y divide-slate-100">
            {visible.length === 0 && <p className="text-xs text-slate-500 p-2">{t('hostServices.noneFound')}</p>}
            {visible.map(s => (
              <label key={s.name} className={cn('flex items-center gap-2 px-2 py-1 text-xs cursor-pointer hover:bg-slate-50', s.monitored && 'opacity-60 cursor-default')}>
                <input type="checkbox" disabled={s.monitored} checked={s.monitored || selected.has(s.name)} onChange={() => toggle(s.name)} />
                <span className="flex-1 min-w-0">
                  <span className="text-slate-900 break-all">{s.display_name || s.name}</span>
                  <span className="text-slate-400 font-mono ml-1 break-all">{s.display_name ? s.name : ''}</span>
                </span>
                {s.startup && <span className="text-[10px] text-slate-400">{s.startup}</span>}
                <Badge variant={s.state === 'running' ? 'green' : s.state === 'failed' ? 'red' : 'gray'}>{s.state ? t(`hostServices.state.${s.state}`) : '—'}</Badge>
                {s.monitored && <Badge variant="blue">{t('hostServices.alreadyMonitored')}</Badge>}
              </label>
            ))}
          </div>
          <div className="flex items-end gap-3 flex-wrap">
            <Select label={t('hostServices.intervalLabel') as string} value={interval} options={INTERVALS}
              render={v => t('hostServices.intervalOpt', { n: v }) as string} onChange={setIntervalMin} />
            <Select label={t('hostServices.alertAfterLabel') as string} value={alertAfter} options={ALERT_AFTER}
              render={v => t('hostServices.alertAfterOpt', { n: v }) as string} onChange={setAlertAfter} />
            <Button size="sm" variant="primary" disabled={selected.size === 0 || add.isPending} onClick={() => add.mutate()}>
              <Plus size={12} /> {t('hostServices.addSelected', { count: selected.size })}
            </Button>
          </div>
          {add.isError && <p className="text-xs text-red-700">{errText(add.error)}</p>}
        </>
      )}
    </div>
  )
}

function HistoryPanel({ platform, hostId }: { platform: ServicePlatform; hostId: number }) {
  const { t } = useTranslation()
  const { data: events = [] } = useQuery({
    queryKey: ['host-services-events', platform, hostId],
    queryFn: () => hostServicesApi.events(platform, hostId),
    refetchInterval: 30_000,
  })
  if (events.length === 0) return <p className="text-xs text-slate-500">{t('hostServices.historyEmpty')}</p>
  return (
    <ul className="text-xs space-y-0.5">
      {events.map(e => (
        <li key={e.id} className={e.kind === 'down' ? 'text-red-700' : 'text-green-700'}>
          <span className="text-slate-500">{new Date(e.ts).toLocaleString()}</span>{' '}
          {e.kind === 'down'
            ? t('hostServices.eventDown', {
                service: e.display_name || e.service_name,
                expected: t(e.expected === 'stopped' ? 'hostServices.expectedStopped' : 'hostServices.expectedRunning'),
                state: e.state ? t(`hostServices.state.${e.state}`) : '—',
              })
            : t('hostServices.eventUp', { service: e.display_name || e.service_name, duration: formatDuration(e.duration_sec) })}
        </li>
      ))}
    </ul>
  )
}

export function HostServices({ platform, hostId }: { platform: ServicePlatform; hostId: number }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [showDiscover, setShowDiscover] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [manual, setManual] = useState('')

  const { data } = useQuery({
    queryKey: ['host-services', platform, hostId],
    queryFn: () => hostServicesApi.list(platform, hostId),
    refetchInterval: 15_000,
  })
  const services = data?.services ?? []
  const refresh = () => qc.invalidateQueries({ queryKey: ['host-services', platform, hostId] })

  const check = useMutation({ mutationFn: () => hostServicesApi.checkNow(platform, hostId), onSuccess: refresh, onError: refresh })
  const addManual = useMutation({
    mutationFn: (name: string) => hostServicesApi.add(platform, hostId, [{ name }]),
    onSuccess: () => { refresh(); setManual('') },
  })
  const lastChecked = services.map(s => s.last_checked_at).filter(Boolean).sort().pop()

  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <p className="text-xs font-semibold text-slate-700">{t('hostServices.title')} ({services.length})</p>
        <div className="flex items-center gap-2 flex-wrap">
          {lastChecked && <span className="text-[10px] text-slate-400">{t('hostServices.lastCheck')}: {new Date(lastChecked).toLocaleString()}</span>}
          <Button size="sm" variant="secondary" onClick={() => setShowDiscover(s => !s)}>
            <ListChecks size={12} /> {t('hostServices.discover')}
          </Button>
          <Button size="sm" variant="secondary" onClick={() => check.mutate()} disabled={check.isPending || services.length === 0}>
            <RefreshCw size={12} className={check.isPending ? 'animate-spin' : ''} /> {t('hostServices.checkNow')}
          </Button>
        </div>
      </div>

      {check.isError && <p className="text-xs text-red-700">{errText(check.error)}</p>}
      {data?.check_error && (
        <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1">
          {t('hostServices.checkError', { error: data.check_error })}
        </p>
      )}

      {showDiscover && <DiscoverPanel platform={platform} hostId={hostId} onDone={() => setShowDiscover(false)} />}

      {services.length === 0 ? (
        <p className="text-xs text-slate-400">{t('hostServices.none')}</p>
      ) : (
        <div className="space-y-2">
          {services.map(s => <ServiceRow key={s.id} s={s} platform={platform} hostId={hostId} />)}
        </div>
      )}

      <div className="flex items-center gap-2">
        <input type="text" value={manual} onChange={e => setManual(e.target.value)}
          placeholder={t(platform === 'windows' ? 'hostServices.manualPlaceholderWindows' : 'hostServices.manualPlaceholderLinux') as string}
          className="border border-slate-300 rounded-lg px-2 py-1 text-xs flex-1"
          onKeyDown={e => { if (e.key === 'Enter' && manual.trim()) addManual.mutate(manual.trim()) }} />
        <Button size="sm" variant="secondary" disabled={!manual.trim() || addManual.isPending} onClick={() => addManual.mutate(manual.trim())}>
          <Plus size={12} /> {t('hostServices.add')}
        </Button>
      </div>
      {addManual.isError && <p className="text-xs text-red-700">{errText(addManual.error)}</p>}

      <div>
        <button onClick={() => setShowHistory(s => !s)} className="text-xs text-indigo-600 hover:underline flex items-center gap-1">
          <History size={12} /> {t('hostServices.historyToggle')} {showHistory ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
        {showHistory && <div className="mt-1"><HistoryPanel platform={platform} hostId={hostId} /></div>}
      </div>
    </div>
  )
}

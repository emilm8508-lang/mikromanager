import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig } from '../lib/api'
import { Card, CardContent } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { fromCentral, HostBoard, SummaryStrip, ProblemsCard, HeatModeSwitch, ago, type HeatMode, type HvHost, type HvVm, type ProblemRow } from '../components/HypervWidgets'
import { Layers, X } from 'lucide-react'
import { formatBytes } from '../lib/utils'

type Filter = 'all' | 'problems' | 'down'

export function CentralHyperV() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [hosts, setHosts] = useState<HvHost[]>([])
  const [oldAgents, setOldAgents] = useState(0)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenant, setTenant] = useState('all')
  const [filter, setFilter] = useState<Filter>('all')
  const [mode, setMode] = useState<HeatMode>('state')
  const [sel, setSel] = useState<{ host: HvHost; vm: HvVm } | null>(null)

  const reload = async () => {
    try {
      const s = await centralApi.hypervHostsStatusAll()
      const all: HvHost[] = []
      let old = 0
      for (const tn of s.tenants) {
        for (const h of tn.hosts ?? []) {
          if (!h.vms) old++
          all.push(fromCentral(h, tn.tenant))
        }
      }
      setHosts(all); setOldAgents(old); setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    reload()
    const iv = setInterval(reload, 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const tenants = useMemo(() => [...new Set(hosts.map(h => h.tenant!))].sort(), [hosts])
  const vis = useMemo(() => hosts
    .filter(h => tenant === 'all' || h.tenant === tenant)
    .filter(h => filter === 'all' || (filter === 'down' ? h.down : h.problems.length > 0 || h.down))
    .sort((a, b) => Number(b.down) - Number(a.down) || b.problems.length - a.problems.length || (a.tenant! + a.name).localeCompare(b.tenant! + b.name)), [hosts, tenant, filter])
  const problems: ProblemRow[] = vis.flatMap(h => h.problems.map(p => ({ ...p, host: h.name, tenant: h.tenant, hostKey: h.key })))

  if (!cfg) {
    return (
      <div className="p-6 max-w-5xl">
        <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">{t('alerts.needsCentral')}</div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-4 max-w-7xl">
      <div className="flex items-center gap-2">
        <Layers size={20} className="text-indigo-600" />
        <h1 className="text-lg font-semibold text-slate-900">{t('hypervCentral.title')}</h1>
      </div>
      <p className="text-sm text-slate-500">{t('hypervCentral.intro')}</p>
      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p>
        : hosts.length === 0 ? <p className="text-sm text-slate-500">{t('hypervCentral.noData')}</p> : (
        <>
          {oldAgents > 0 && <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-3 py-1.5">{t('hypervCentral.oldAgent')}</p>}
          <div className="flex items-center gap-3 flex-wrap">
            <select value={tenant} onChange={e => setTenant(e.target.value)} className="text-xs border border-slate-300 rounded px-2 py-1.5">
              <option value="all">{t('alerts.allTenants')}</option>
              {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
            </select>
            <select value={filter} onChange={e => setFilter(e.target.value as Filter)} className="text-xs border border-slate-300 rounded px-2 py-1.5">
              <option value="all">{t('hyperv.filterAll')}</option>
              <option value="problems">{t('hyperv.filterProblems')}</option>
              <option value="down">{t('hyperv.hostDown')}</option>
            </select>
            <HeatModeSwitch mode={mode} onChange={setMode} />
            <span className="text-xs text-slate-400">{t('hypervCentral.clickTile')}</span>
            <button onClick={reload} className="ml-auto text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>
          </div>

          <SummaryStrip hosts={vis} />

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 items-start">
            <div className="xl:col-span-2 space-y-3">
              {vis.length === 0 ? <p className="text-sm text-slate-500">{t('hyperv.noProblems')}</p> : vis.map(h => (
                <HostBoard key={h.key} host={h} mode={mode} staleMin={20} selectedVm={sel?.host.key === h.key ? sel.vm.key : null}
                  onVm={v => setSel({ host: h, vm: v })} />
              ))}
            </div>
            <div className="space-y-4">
              {sel && (
                <Card><CardContent className="space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-slate-900 truncate">{sel.vm.name}</div>
                      <div className="text-xs text-slate-500 truncate"><span className="px-1 mr-1 rounded bg-slate-100">{sel.host.tenant}</span>{sel.host.name}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={sel.vm.tile === 'ok' ? 'green' : sel.vm.tile === 'crit' ? 'red' : sel.vm.tile === 'warn' ? 'yellow' : 'gray'}>{sel.vm.state ?? '—'}</Badge>
                      <button onClick={() => setSel(null)} className="text-slate-400 hover:text-slate-800"><X size={15} /></button>
                    </div>
                  </div>
                  <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
                    <dt className="text-slate-400">vCPU</dt><dd>{sel.vm.vcpu ?? '—'}</dd>
                    <dt className="text-slate-400">CPU</dt><dd>{sel.vm.cpu != null ? `${sel.vm.cpu}%` : '—'}</dd>
                    <dt className="text-slate-400">{t('hyperv.memory')}</dt><dd>{formatBytes(sel.vm.memDemand)} / {formatBytes(sel.vm.memAssigned)}</dd>
                    <dt className="text-slate-400">{t('hyperv.heartbeat')}</dt><dd>{sel.vm.heartbeat ?? '—'}</dd>
                    <dt className="text-slate-400">{t('hyperv.uptime')}</dt><dd>{sel.vm.uptime ? ago(new Date(Date.now() - sel.vm.uptime * 1000).toISOString()) : '—'}</dd>
                    <dt className="text-slate-400">{t('hyperv.checkpoints')}</dt><dd>{sel.vm.snapshots ?? '—'}</dd>
                    <dt className="text-slate-400">{t('hyperv.replication')}</dt><dd>{sel.vm.replication ?? t('hyperv.replOff')}</dd>
                  </dl>
                  {sel.vm.flags.length > 0 && <ul className="text-xs text-amber-800 space-y-0.5">{sel.vm.flags.map(f => <li key={f}>⚠ {t(`hyperv.problem.${f}`)}</li>)}</ul>}
                </CardContent></Card>
              )}
              <ProblemsCard rows={problems} />
            </div>
          </div>
        </>
      )}
    </div>
  )
}

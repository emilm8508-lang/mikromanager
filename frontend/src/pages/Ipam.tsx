import { useState, Fragment } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Binary, ChevronDown, ChevronRight, RefreshCw } from 'lucide-react'
import { ipamApi, IpamSubnet } from '../lib/api'
import { useAgo } from '../components/SocBits'
import { cn } from '../lib/utils'

function Bar({ pct }: { pct: number | null }) {
  if (pct == null) return <span className="text-slate-300 text-xs">—</span>
  const tone = pct >= 98 ? 'bg-red-500' : pct >= 90 ? 'bg-amber-500' : pct >= 75 ? 'bg-yellow-400' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-2 bg-slate-100 rounded-full overflow-hidden"><div className={cn('h-full', tone)} style={{ width: `${Math.min(100, pct)}%` }} /></div>
      <span className={cn('text-xs tabular-nums', pct >= 90 ? 'text-red-700 font-medium' : 'text-slate-600')}>{pct.toFixed(pct >= 99 ? 1 : 0)}%</span>
    </div>
  )
}

function SubnetDetail({ s }: { s: IpamSubnet }) {
  const { t } = useTranslation()
  return (
    <div className="px-4 py-3 bg-slate-50 text-xs space-y-2">
      <div>
        <span className="font-medium text-slate-700">{t('ipam.freeFirst', { n: s.free_list.length })}: </span>
        {s.free_list.length ? <span className="font-mono text-slate-600">{s.free_list.join(', ')}</span> : <span className="text-slate-500">{t('ipam.noneFree')}</span>}
      </div>
      {s.static_in_pool.length > 0 && (
        <div>
          <div className="font-medium text-amber-800">{t('ipam.staticInPool', { n: s.static_in_pool.length })}</div>
          <div className="font-mono text-slate-600">{s.static_in_pool.map(x => `${x.ip} (${x.pool})`).join(', ')}</div>
          <div className="text-slate-500">{t('ipam.staticHint')}</div>
        </div>
      )}
    </div>
  )
}

// IP address management from the routers' tables: subnets, DHCP pools, address conflicts (services/ipam.py).
export function Ipam() {
  const { t } = useTranslation()
  const ago = useAgo()
  const qc = useQueryClient()
  const [open, setOpen] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const ov = useQuery({ queryKey: ['ipam'], queryFn: ipamApi.overview, refetchInterval: 120000 })
  const run = useMutation({ mutationFn: ipamApi.run, onSuccess: () => qc.invalidateQueries({ queryKey: ['ipam'] }) })
  const d = ov.data
  const subnets = (d?.subnets ?? []).filter(s => !q.trim() || `${s.network} ${s.router} ${s.interface ?? ''}`.toLowerCase().includes(q.trim().toLowerCase()))
  const grid = 'grid-cols-[1.5rem_minmax(0,1.3fr)_minmax(0,1fr)_6rem_6rem_6rem_9rem_minmax(0,1fr)]'
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Binary size={20} className="text-indigo-600" /> {t('ipam.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('ipam.subtitle')}</p>
        </div>
        <button onClick={() => run.mutate()} disabled={run.isPending} className="flex items-center gap-1.5 text-sm border border-slate-300 rounded-lg px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50">
          <RefreshCw size={14} className={run.isPending ? 'animate-spin' : ''} /> {t('ipam.runNow')}
        </button>
      </div>

      {d && (
        <div className="flex gap-2 flex-wrap">
          {([['subnets', d.subnets.length, 'text-slate-800'], ['pools', d.pools.filter(p => p.served).length, 'text-slate-800'],
             ['conflicts', d.conflicts.length, d.conflicts.length ? 'text-red-600' : 'text-slate-300'],
             ['static', d.subnets.reduce((n, s) => n + s.static_in_pool.length, 0), 'text-amber-600']] as const).map(([k, v, c]) => (
            <div key={k} className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[9rem]">
              <div className="text-xs text-slate-500">{t(`ipam.count.${k}`)}</div>
              <div className={cn('text-2xl font-bold tabular-nums', v ? c : 'text-slate-300')}>{v}</div>
            </div>
          ))}
        </div>
      )}
      {(d?.last.errors?.length ?? 0) > 0 && (
        <p className="text-xs text-amber-700">{t('ipam.readErrors')}: {d!.last.errors.map(e => `${e.router} (${e.error})`).join(' · ')}</p>
      )}

      {d && d.conflicts.length > 0 && (
        <div className="bg-white border border-red-200 rounded-xl overflow-hidden text-sm">
          <div className="px-4 py-2 bg-red-50 text-red-800 font-medium">{t('ipam.conflicts')}</div>
          {d.conflicts.map(c => (
            <div key={c.ip} className="flex items-center gap-3 px-4 py-1.5 border-t border-red-100">
              <span className="font-mono w-36">{c.ip}</span>
              <span className="font-mono text-xs text-slate-700 flex-1">{c.macs.join(' · ')}</span>
              <span className="text-xs text-slate-500">{c.routers.join(', ')}</span>
            </div>
          ))}
          <p className="px-4 py-2 text-xs text-slate-500 border-t border-red-100">{t('ipam.conflictHint')}</p>
        </div>
      )}

      {d && d.pools.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
          <div className="px-4 py-2 bg-slate-50 text-xs text-slate-500 font-medium">{t('ipam.pools')}</div>
          {d.pools.map(p => (
            <div key={p.key} className={cn('flex items-center gap-3 px-4 py-1.5 border-t border-slate-100', !p.served && 'opacity-60')}>
              <span className="w-48 truncate font-medium text-slate-800" title={p.ranges}>{p.name}</span>
              <span className="w-40 truncate text-xs text-slate-500">{p.router}{p.interface ? ` · ${p.interface}` : ''}</span>
              <span className="w-56 truncate font-mono text-xs text-slate-500" title={p.ranges}>{p.ranges}</span>
              <span className="w-28 text-xs tabular-nums text-slate-700">{t('ipam.leased', { bound: p.bound, size: p.size })}</span>
              <Bar pct={p.pct} />
              <span className="text-xs text-slate-500 ml-auto">{!p.served ? t('ipam.notServed') : p.days_to_full != null ? t('ipam.fullIn', { n: Math.max(0, Math.round(p.days_to_full)) }) : ''}</span>
            </div>
          ))}
        </div>
      )}

      {ov.isLoading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : !d || d.subnets.length === 0 ? <p className="text-sm text-slate-500">{t('ipam.empty')}</p> : (
        <div className="space-y-2">
          <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('soc.filter.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm w-56" />
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden text-sm">
            <div className={cn('grid items-center bg-slate-50 text-xs text-slate-500 py-2', grid)}>
              <div />
              <div className="px-2">{t('ipam.col.network')}</div>
              <div className="px-2">{t('ipam.col.router')}</div>
              <div className="px-2 text-right">{t('ipam.col.size')}</div>
              <div className="px-2 text-right">{t('ipam.col.used')}</div>
              <div className="px-2 text-right">{t('ipam.col.free')}</div>
              <div className="px-2">{t('ipam.col.usage')}</div>
              <div className="px-2">{t('ipam.col.pools')}</div>
            </div>
            {subnets.map(s => (
              <Fragment key={s.network}>
                <div className={cn('grid items-center border-t border-slate-100 cursor-pointer hover:bg-slate-50', grid)} onClick={() => setOpen(open === s.network ? null : s.network)}>
                  <div className="px-2 text-slate-400">{open === s.network ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</div>
                  <div className="px-2 py-1.5"><span className="font-mono text-slate-900">{s.network}</span> <span className="text-[11px] text-slate-400">gw {s.gateway}</span></div>
                  <div className="px-2 text-xs text-slate-600 truncate">{s.router}{s.interface ? ` · ${s.interface}` : ''}</div>
                  <div className="px-2 text-right tabular-nums text-slate-600">{s.size}</div>
                  <div className="px-2 text-right tabular-nums text-slate-700">{s.used ?? '—'}</div>
                  <div className="px-2 text-right tabular-nums text-slate-700">{s.free ?? '—'}</div>
                  <div className="px-2"><Bar pct={s.pct} /></div>
                  <div className="px-2 text-xs text-slate-500 truncate">{s.pools.join(', ')}{s.static_in_pool.length ? <span className="text-amber-700"> · {t('ipam.staticShort', { n: s.static_in_pool.length })}</span> : null}</div>
                </div>
                {open === s.network && <SubnetDetail s={s} />}
              </Fragment>
            ))}
          </div>
        </div>
      )}
      <p className="text-xs text-slate-400">{t('ipam.note')}{d?.at ? ` ${t('avail.lastCheck', { when: ago(d.at) })}` : ''}</p>
    </div>
  )
}

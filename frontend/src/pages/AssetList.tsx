import { useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { assetsApi, type AssetRow, type AssetType } from '../lib/api'
import { TypeIcon, TYPE_ORDER, TypePill, VulnPill, LifecyclePill, ScanLevelPill, ago } from '../components/AssetBits'
import { AssetBulkBar, partition } from '../components/AssetActions'
import { Button } from '../components/ui/Button'
import { Boxes, Download, ChevronUp, ChevronDown } from 'lucide-react'
import { cn } from '../lib/utils'

// Same OWASP CSV-formula-injection guard + BOM as the other exports in the app.
function csvSafe(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v)
  return `"${(s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s).replace(/"/g, '""')}"`
}

type SortKey = 'name' | 'type' | 'vulns' | 'lifecycle' | 'ip' | 'location' | 'seen'
const LC_ORDER: Record<string, number> = { eol: 0, ending: 1, supported: 2, unknown: 3 }
const ipKey = (ip: string | null) => (ip ? ip.split('.').map(p => p.padStart(3, '0')).join('.') : '~')

export function AssetList() {
  const { t } = useTranslation()
  const nav = useNavigate()
  const { data = [], isLoading } = useQuery({ queryKey: ['assets'], queryFn: assetsApi.list, refetchInterval: 60_000 })
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState('')
  const [type, setType] = useState(params.get('type') ?? 'all')
  const [location, setLocation] = useState(params.get('location') ?? 'all')
  const [lifecycle, setLifecycle] = useState(params.get('lifecycle') ?? 'all')
  const [vuln, setVuln] = useState(params.get('vuln') ?? 'all')
  const [level, setLevel] = useState(params.get('level') ?? 'all')
  const [group, setGroup] = useState(params.get('group') ?? 'all')
  const [inactive, setInactive] = useState(params.get('inactive') === '1')
  const [onlyNew, setOnlyNew] = useState(params.get('new') === '1')
  const [picked, setPicked] = useState<Set<number>>(new Set())
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'vulns', dir: 1 })
  const [page, setPage] = useState(0)
  const [size, setSize] = useState(25)

  const locations = useMemo(() => [...new Set(data.map(a => a.location).filter((x): x is string => !!x))].sort(), [data])
  const groups = useMemo(() => [...new Set(data.flatMap(a => a.groups))].sort(), [data])
  const needle = q.trim().toLowerCase()

  const rows = useMemo(() => {
    const f = data.filter(a =>
      (inactive || a.active)
      && (!onlyNew || (a.first_seen_at != null && Date.now() - new Date(a.first_seen_at).getTime() < 7 * 86_400_000))
      && (type === 'all' || a.type === type)
      && (location === 'all' || (location === '_none' ? !a.location : a.location === location))
      && (lifecycle === 'all' || a.lifecycle === lifecycle)
      && (vuln === 'all' || (vuln === 'any' ? a.vulns.total > 0 : vuln === 'none' ? a.vulns.total === 0 : a.vulns[vuln as 'critical' | 'high'] > 0))
      && (level === 'all' || a.scan_level === level)
      && (group === 'all' || a.groups.includes(group))
      && (!needle || [a.name, a.ip, a.mac, a.manufacturer, a.model, a.serial, a.os_name, a.location].some(v => (v ?? '').toLowerCase().includes(needle))))
    const val = (a: AssetRow): string | number => {
      switch (sort.key) {
        case 'name': return a.name.toLowerCase()
        case 'type': return TYPE_ORDER.indexOf(a.type)
        case 'vulns': return -a.risk
        case 'lifecycle': return LC_ORDER[a.lifecycle]
        case 'ip': return ipKey(a.ip)
        case 'location': return (a.location ?? '~').toLowerCase()
        case 'seen': return -(a.last_seen_at ? new Date(a.last_seen_at).getTime() : 0)
      }
    }
    return [...f].sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * sort.dir })
  }, [data, inactive, onlyNew, type, location, lifecycle, vuln, level, group, needle, sort])

  const selectedRows = useMemo(() => data.filter(a => picked.has(a.id)), [data, picked])
  const pages = Math.max(1, Math.ceil(rows.length / size))
  const cur = Math.min(page, pages - 1)
  const shown = rows.slice(cur * size, cur * size + size)

  const th = (key: SortKey, label: string, cls = '') => (
    <th className={cn('py-2.5 font-normal cursor-pointer select-none', cls, sort.key === key && 'text-indigo-600')} onClick={() => { setSort(s => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : 1 })); setPage(0) }}>
      <span className="inline-flex items-center gap-0.5">{label}{sort.key === key && (sort.dir === 1 ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}</span>
    </th>
  )

  const exportCsv = () => {
    const head = ['name', 'type', 'role', 'ip', 'mac', 'manufacturer', 'model', 'serial', 'os', 'os_version', 'location', 'lifecycle', 'eol', 'vuln_critical', 'vuln_high', 'vuln_medium', 'vuln_low', 'scan_level', 'groups', 'first_seen', 'last_seen']
    const lines = [head.map(csvSafe).join(',')]
    for (const a of rows) lines.push([a.name, a.type, a.role, a.ip, a.mac, a.manufacturer, a.model, a.serial, a.os_name, a.os_version, a.location, a.lifecycle, a.eol,
      a.vulns.critical, a.vulns.high, a.vulns.medium, a.vulns.low, a.scan_level, a.groups.join('; '), a.first_seen_at, a.last_seen_at].map(csvSafe).join(','))
    const el = document.createElement('a')
    el.href = URL.createObjectURL(new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }))
    el.download = 'assets.csv'; el.click(); URL.revokeObjectURL(el.href)
  }

  const sel = 'border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white'
  const reset = (fn: (v: string) => void) => (e: React.ChangeEvent<HTMLSelectElement>) => { fn(e.target.value); setPage(0) }

  return (
    <div className="p-6 space-y-4 max-w-[1400px]">
      {onlyNew && (
        <div className="text-sm bg-indigo-50 border border-indigo-100 rounded-lg px-4 py-2 text-indigo-900 flex items-center gap-3">
          {t('assets.onlyNew')}
          <button className="text-xs text-indigo-600 hover:underline" onClick={() => { setOnlyNew(false); setParams({}, { replace: true }) }}>{t('assets.clearFilter')}</button>
        </div>
      )}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Boxes size={20} className="text-indigo-600" /> {t('assets.listTitle')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{t('assets.listSubtitle')}</p>
        </div>
        <div className="flex items-center gap-3">
          <Link to="/inventory" className="text-sm text-indigo-600 hover:underline">{t('assets.openOverview')}</Link>
          <Button size="sm" variant="secondary" onClick={exportCsv}><Download size={13} /> CSV</Button>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <input value={q} onChange={e => { setQ(e.target.value); setPage(0) }} placeholder={t('assets.search') as string} className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm flex-1 min-w-[14rem]" />
        <select value={type} onChange={reset(setType)} className={sel}>
          <option value="all">{t('assets.allTypes')}</option>
          {TYPE_ORDER.map(k => <option key={k} value={k}>{t(`assets.type.${k}`)}</option>)}
        </select>
        <select value={location} onChange={reset(setLocation)} className={sel}>
          <option value="all">{t('assets.allLocations')}</option>
          {locations.map(l => <option key={l} value={l}>{l}</option>)}
          <option value="_none">{t('assets.noLocation')}</option>
        </select>
        <select value={lifecycle} onChange={reset(setLifecycle)} className={sel}>
          <option value="all">{t('assets.allLifecycle')}</option>
          {(['eol', 'ending', 'supported', 'unknown'] as const).map(k => <option key={k} value={k}>{t(`assets.lifecycle.${k}`)}</option>)}
        </select>
        <select value={vuln} onChange={reset(setVuln)} className={sel}>
          <option value="all">{t('assets.allVulns')}</option>
          <option value="any">{t('assets.withVulns')}</option>
          <option value="critical">{t('assets.sev.critical')}</option>
          <option value="high">{t('assets.sev.high')}</option>
          <option value="none">{t('assets.noVulns')}</option>
        </select>
        <select value={level} onChange={reset(setLevel)} className={sel}>
          <option value="all">{t('assets.allScanLevels')}</option>
          {(['credentialed', 'snmp', 'passive'] as const).map(k => <option key={k} value={k}>{t(`assets.scanLevel.${k}`)}</option>)}
        </select>
        <select value={group} onChange={reset(setGroup)} className={sel}>
          <option value="all">{t('assets.allGroups')}</option>
          {groups.map(g => <option key={g} value={g}>{t(`assets.group.${g}`, { defaultValue: g })}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-xs text-slate-600"><input type="checkbox" checked={inactive} onChange={e => { setInactive(e.target.checked); setPage(0) }} />{t('assets.showInactive')}</label>
      </div>

      {selectedRows.length > 0 && <AssetBulkBar rows={selectedRows} onClear={() => setPicked(new Set())} />}

      <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
        {isLoading ? <p className="p-5 text-sm text-slate-500">{t('common.loading')}</p> : shown.length === 0 ? <p className="p-5 text-sm text-slate-500">{t('assets.none')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                <th className="pl-4 w-8"><input type="checkbox" aria-label={t('assets.bulk.selectPage') as string} title={t('assets.bulk.selectPage') as string}
                  checked={shown.length > 0 && shown.filter(a => partition([a]).skipped === 0).every(a => picked.has(a.id)) && shown.some(a => partition([a]).skipped === 0)}
                  onChange={e => setPicked(prev => { const n = new Set(prev); shown.filter(a => partition([a]).skipped === 0).forEach(a => e.target.checked ? n.add(a.id) : n.delete(a.id)); return n })} /></th>
                {th('name', t('assets.colName') as string, 'px-4')}{th('type', t('assets.colType') as string)}{th('vulns', t('assets.colVulns') as string)}
                {th('lifecycle', t('assets.colLifecycle') as string)}{th('ip', t('assets.colIp') as string)}{th('location', t('assets.colLocation') as string)}
                <th className="font-normal">{t('assets.colScan')}</th>{th('seen', t('assets.colLastSeen') as string, 'pr-4')}
              </tr></thead>
              <tbody>
                {shown.map(a => (
                  <tr key={a.id} onClick={() => nav(`/inventory/${a.id}`)} className={cn('border-b border-slate-100 hover:bg-slate-50 cursor-pointer', !a.active && 'opacity-60')}>
                    <td className="pl-4 w-8" onClick={e => e.stopPropagation()}>
                      {partition([a]).skipped === 0 && <input type="checkbox" checked={picked.has(a.id)} onChange={e => setPicked(prev => { const n = new Set(prev); e.target.checked ? n.add(a.id) : n.delete(a.id); return n })} />}
                    </td>
                    <td className="px-2 py-2.5">
                      <span className="inline-flex items-center gap-2.5 min-w-0"><TypeIcon type={a.type as AssetType} size={18} />
                        <span className="min-w-0"><span className="block text-slate-900 font-medium truncate max-w-[16rem]">{a.name}</span>
                          {(a.manufacturer || a.model) && <span className="block text-[11px] text-slate-400 truncate max-w-[16rem]">{[a.manufacturer, a.model].filter(Boolean).join(' · ')}</span>}</span></span>
                    </td>
                    <td><TypePill type={a.type} role={a.role} /></td>
                    <td><VulnPill v={a.vulns} /></td>
                    <td><LifecyclePill status={a.lifecycle} /></td>
                    <td className="font-mono text-xs text-slate-600">{a.ip ?? '—'}</td>
                    <td className="text-xs text-slate-600">{a.location ?? '—'}</td>
                    <td><ScanLevelPill level={a.scan_level} /></td>
                    <td className="pr-4 text-xs text-slate-500 whitespace-nowrap">{ago(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="px-4 py-2.5 border-t border-slate-200 flex items-center justify-between gap-3 flex-wrap text-xs text-slate-500">
          <span>{t('assets.showing', { from: rows.length ? cur * size + 1 : 0, to: Math.min(rows.length, cur * size + size), total: rows.length })}</span>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1">{t('assets.perPage')}
              <select value={size} onChange={e => { setSize(Number(e.target.value)); setPage(0) }} className="border border-slate-300 rounded px-1 py-0.5 bg-white">{[25, 50, 100, 250].map(n => <option key={n} value={n}>{n}</option>)}</select></label>
            <button disabled={cur === 0} onClick={() => setPage(cur - 1)} className="px-2 py-1 rounded border border-slate-300 disabled:opacity-40">‹</button>
            <span>{cur + 1} / {pages}</span>
            <button disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)} className="px-2 py-1 rounded border border-slate-300 disabled:opacity-40">›</button>
          </div>
        </div>
      </div>
    </div>
  )
}

import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Activity, Cpu, MemoryStick, HardDrive, AlertTriangle, Zap, Building2, Search } from 'lucide-react'
import type { CentralDellServerStatus, DellHealth } from '../lib/api'
import { cn } from '../lib/utils'

// Central's fleet view of the physical servers of every client: a health
// score, fleet totals, the clients, capacity per host, and an inventory
// table. Everything is computed from the snapshot each agent already sends
// (dell_monitor.public_summary: health + the details of 3.41) — no extra data.

export type FleetRow = { tenant: string; server: CentralDellServerStatus }

type Host = {
  key: string; tenant: string; row: FleetRow; name: string; model: string | null; tag: string | null
  health: NonNullable<DellHealth> | 'none'; cores: number; threads: number; sockets: number; cpuModel: string | null
  memGb: number | null; dimms: number; dimmSlots: number | null; dimmType: string | null
  diskGb: number; ssd: number; hdd: number; disks: number; drivesBad: number; psusBad: number
  bios: string | null; biosBehind: boolean; idrac: string | null; powerW: number | null; inletC: number | null
}

const HEALTH_SCORE: Record<string, number> = { OK: 100, Warning: 50, Critical: 0 }

function cmpVersion(a: string, b: string) {
  const pa = a.split(/[.\-]/).map(x => parseInt(x, 10) || 0), pb = b.split(/[.\-]/).map(x => parseInt(x, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0)
  return 0
}

const mostCommon = (xs: Array<string | null | undefined>) => {
  const c: Record<string, number> = {}
  for (const x of xs) if (x) c[x] = (c[x] ?? 0) + 1
  return Object.entries(c).sort((a, b) => b[1] - a[1])[0]?.[0] ?? null
}

export function buildHosts(rows: FleetRow[]): Host[] {
  const hosts: Host[] = rows.map(row => {
    const s = row.server, d = s.details ?? {}, sys = d.system ?? {}, sum = d.summary ?? {}
    const cpus = d.cpus ?? [], dimms = d.dimms ?? [], drives = d.storage?.drives ?? []
    const health: Host['health'] = s.last_status === 'error' && !s.health_rollup ? 'none' : (s.health_rollup ?? 'none')
    return {
      key: `${row.tenant}:${s.id}`, tenant: row.tenant, row, name: s.name || sys.service_tag || `#${s.id}`,
      model: s.model ?? sys.model ?? null, tag: sys.service_tag ?? null, health,
      cores: cpus.reduce((a, c) => a + (c.cores ?? 0), 0), threads: cpus.reduce((a, c) => a + (c.threads ?? 0), 0),
      sockets: cpus.length, cpuModel: mostCommon(cpus.map(c => c.model)),
      memGb: sum.mem_gb ?? sys.mem_gb ?? null, dimms: dimms.length, dimmSlots: sys.dimm_slots ?? null, dimmType: mostCommon(dimms.map(x => x.type)),
      diskGb: drives.reduce((a, x) => a + (x.gb ?? 0), 0), disks: drives.length,
      ssd: drives.filter(x => (x.media ?? '').toUpperCase().includes('SSD')).length,
      hdd: drives.filter(x => (x.media ?? '').toUpperCase().includes('HDD')).length,
      drivesBad: sum.drives_bad ?? 0, psusBad: sum.psus_bad ?? 0,
      bios: sys.bios ?? null, biosBehind: false, idrac: sys.idrac_fw ?? null, powerW: sum.power_w ?? null, inletC: sum.inlet_c ?? null,
    }
  })
  // BIOS drift: behind the newest BIOS seen on the same model anywhere in the fleet
  const newest: Record<string, string> = {}
  for (const h of hosts) if (h.model && h.bios && (!newest[h.model] || cmpVersion(h.bios, newest[h.model]) > 0)) newest[h.model] = h.bios
  for (const h of hosts) h.biosBehind = !!(h.model && h.bios && cmpVersion(h.bios, newest[h.model]) < 0)
  return hosts
}

const fmtGb = (gb: number) => gb >= 1000 ? `${(gb / 1000).toLocaleString(undefined, { maximumFractionDigits: 1 })} TB` : `${Math.round(gb)} GB`
const fmtMem = (gb: number) => gb >= 1024 ? `${(gb / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} TB` : `${Math.round(gb)} GB`

function Card({ title, Icon, children, className, extra }: { title: string; Icon: React.ComponentType<any>; children: React.ReactNode; className?: string; extra?: React.ReactNode }) {
  return (
    <div className={cn('bg-white border border-slate-200 rounded-xl p-4', className)}>
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-700"><Icon size={15} className="text-indigo-500" />{title}</div>
        {extra}
      </div>
      {children}
    </div>
  )
}

function Big({ value, unit, sub }: { value: string; unit?: string; sub?: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-baseline gap-1.5"><span className="text-3xl font-bold text-slate-900 tabular-nums">{value}</span>{unit && <span className="text-sm text-slate-500">{unit}</span>}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </div>
  )
}

function ScoreRing({ score }: { score: number | null }) {
  const r = 52, c = 2 * Math.PI * r, pct = score == null ? 0 : score / 100
  const color = score == null ? '#cbd5e1' : score >= 90 ? '#22c55e' : score >= 60 ? '#f59e0b' : '#ef4444'
  return (
    <svg viewBox="0 0 128 128" className="w-36 h-36">
      <circle cx="64" cy="64" r={r} fill="none" className="stroke-slate-100" strokeWidth="12" />
      <circle cx="64" cy="64" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
        strokeDasharray={`${c * pct} ${c}`} transform="rotate(-90 64 64)" />
      <text x="64" y="70" textAnchor="middle" className="fill-slate-900" fontSize="30" fontWeight="700">{score ?? '—'}</text>
    </svg>
  )
}

function Bars({ hosts, value, label, fmt, color, onOpen }: {
  hosts: Host[]; value: (h: Host) => number; label: (h: Host) => string; fmt: (v: number) => string; color: string; onOpen: (r: FleetRow) => void
}) {
  const list = hosts.filter(h => value(h) > 0).sort((a, b) => value(b) - value(a))
  const max = Math.max(1, ...list.map(value))
  if (list.length === 0) return <p className="text-xs text-slate-400">—</p>
  return (
    <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
      {list.map(h => (
        <div key={h.key} className="grid grid-cols-[7rem_1fr_4.5rem] items-center gap-2 text-xs">
          <button onClick={() => onOpen(h.row)} className="truncate text-left font-mono text-slate-700 hover:text-indigo-600" title={`${h.tenant} · ${h.name}`}>{h.name}</button>
          {/* light bar with the label over the whole track, so a short bar keeps a readable label */}
          <div className="relative h-5 bg-slate-100 rounded overflow-hidden">
            <div className={cn('absolute inset-y-0 left-0 rounded', color)} style={{ width: `${Math.max(3, (value(h) / max) * 100)}%` }} />
            <span className="relative px-1.5 leading-5 text-[10px] font-medium text-slate-800 whitespace-nowrap">{label(h)}</span>
          </div>
          <span className="text-right font-mono text-slate-700">{fmt(value(h))}</span>
        </div>
      ))}
    </div>
  )
}

export function DellFleetOverview({ rows, onOpen }: { rows: FleetRow[]; onOpen: (r: FleetRow) => void }) {
  const { t } = useTranslation()
  const hosts = useMemo(() => buildHosts(rows), [rows])
  const known = hosts.filter(h => h.health in HEALTH_SCORE)
  const score = known.length ? Math.round(known.reduce((a, h) => a + HEALTH_SCORE[h.health as string], 0) / known.length) : null
  const count = (x: Host['health']) => hosts.filter(h => h.health === x).length
  const sum = (f: (h: Host) => number) => hosts.reduce((a, h) => a + f(h), 0)
  const memGb = sum(h => h.memGb ?? 0), slotsFree = sum(h => h.dimmSlots != null ? Math.max(0, h.dimmSlots - h.dimms) : 0)
  const diskGb = sum(h => h.diskGb), withPower = hosts.filter(h => h.powerW != null)
  const hottest = hosts.filter(h => h.inletC != null).sort((a, b) => (b.inletC ?? 0) - (a.inletC ?? 0))[0]
  const notOk = hosts.filter(h => h.health === 'Warning' || h.health === 'Critical')
  const tenants = Array.from(new Set(hosts.map(h => h.tenant)))

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <Card title={t('dellFleet.score')} Icon={Activity} className="xl:row-span-2" extra={<span className="text-[10px] text-slate-400" title={t('dellFleet.scoreHow') as string}>{t('dellFleet.scoreHowShort')}</span>}>
          <div className="flex flex-col items-center">
            <ScoreRing score={score} />
            <div className="grid grid-cols-4 gap-3 mt-3 text-center w-full">
              {([['OK', 'text-green-600'], ['Warning', 'text-amber-600'], ['Critical', 'text-red-600'], ['none', 'text-slate-400']] as const).map(([k, cls]) => (
                <div key={k}><div className={cn('text-xl font-bold', cls)}>{count(k)}</div><div className="text-[10px] uppercase tracking-wide text-slate-500">{t(`dellFleet.h.${k}`)}</div></div>
              ))}
            </div>
            <p className="text-[11px] text-slate-400 mt-3 text-center">{t('dellFleet.scoreHow')}</p>
          </div>
        </Card>

        <Card title={t('dellFleet.cpu')} Icon={Cpu}>
          <Big value={sum(h => h.cores).toLocaleString()} unit={`/ ${sum(h => h.threads).toLocaleString()} ${t('dellFleet.threadsShort')}`}
            sub={t('dellFleet.sockets', { n: sum(h => h.sockets), hosts: hosts.length })} />
        </Card>
        <Card title={t('dellFleet.memory')} Icon={MemoryStick}>
          <Big value={fmtMem(memGb).split(' ')[0]} unit={fmtMem(memGb).split(' ')[1]} sub={slotsFree ? t('dellFleet.slotsFree', { n: slotsFree }) : undefined} />
        </Card>
        <Card title={t('dellFleet.storage')} Icon={HardDrive}>
          <Big value={fmtGb(diskGb).split(' ')[0]} unit={`${fmtGb(diskGb).split(' ')[1]} · ${sum(h => h.disks)} ${t('dellFleet.disks')}`}
            sub={<>{sum(h => h.ssd)} SSD · {sum(h => h.hdd)} HDD{sum(h => h.drivesBad) > 0 && <span className="text-red-600 font-semibold"> · {t('dellFleet.drivesBad', { n: sum(h => h.drivesBad) })}</span>}</>} />
        </Card>
        <Card title={t('dellFleet.warnings')} Icon={AlertTriangle}>
          <Big value={String(notOk.length)} unit={t('dellFleet.hostsUnit')} sub={
            <span className="flex flex-col gap-0.5">
              {sum(h => h.psusBad) > 0 && <span className="text-red-600">{t('dellFleet.psuIssues', { n: hosts.filter(h => h.psusBad > 0).length })}</span>}
              {hosts.some(h => h.biosBehind) && <span className="text-amber-700">{t('dellFleet.biosDrift', { n: hosts.filter(h => h.biosBehind).length })}</span>}
              {count('none') > 0 && <span>{t('dellFleet.noData', { n: count('none') })}</span>}
            </span>} />
        </Card>
        <Card title={t('dellFleet.power')} Icon={Zap}>
          <Big value={withPower.length ? Math.round(sum(h => h.powerW ?? 0)).toLocaleString() : '—'} unit="W"
            sub={<>{t('dellFleet.powerHosts', { n: withPower.length })}{hottest && <> · {t('dellFleet.hottest', { name: hottest.name, c: hottest.inletC })}</>}</>} />
        </Card>
        <Card title={t('dellFleet.tenants')} Icon={Building2} className="md:col-span-2 xl:col-span-1">
          <div className="space-y-1.5 max-h-44 overflow-y-auto">
            {tenants.map(tn => {
              const hs = hosts.filter(h => h.tenant === tn)
              return (
                <div key={tn} className="flex items-center gap-2 text-xs">
                  <span className="flex-1 truncate font-medium text-slate-700">{tn}</span>
                  <span className="text-slate-500">{t('dellFleet.hostsN', { n: hs.length })}</span>
                  {(['OK', 'Warning', 'Critical'] as const).map(k => {
                    const n = hs.filter(h => h.health === k).length
                    return n ? <span key={k} className={cn('rounded px-1.5 py-0.5 font-semibold', k === 'OK' ? 'bg-green-100 text-green-700' : k === 'Warning' ? 'bg-amber-100 text-amber-800' : 'bg-red-100 text-red-700')}>{n}</span> : null
                  })}
                </div>
              )
            })}
          </div>
        </Card>
      </div>

      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">{t('dellFleet.capacityKicker')}</p>
        <h3 className="text-base font-semibold text-slate-900 mb-2">{t('dellFleet.capacityTitle')}</h3>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <Card title={t('dellFleet.ramPerHost')} Icon={MemoryStick} extra={<span className="text-[10px] text-slate-400">{t('dellFleet.hostsN', { n: hosts.filter(h => h.memGb).length })}</span>}>
            <Bars hosts={hosts} value={h => h.memGb ?? 0} onOpen={onOpen} color="bg-sky-300" fmt={fmtMem}
              label={h => h.dimms ? `${h.dimms}× ${h.dimmType ?? 'DIMM'}` : ''} />
          </Card>
          <Card title={t('dellFleet.storagePerHost')} Icon={HardDrive} extra={<span className="text-[10px] text-slate-400">{t('dellFleet.hostsN', { n: hosts.filter(h => h.diskGb).length })}</span>}>
            <Bars hosts={hosts} value={h => h.diskGb} onOpen={onOpen} color="bg-fuchsia-300" fmt={fmtGb}
              label={h => [h.ssd ? `${h.ssd} × SSD` : '', h.hdd ? `${h.hdd} × HDD` : ''].filter(Boolean).join(' + ') || `${h.disks}`} />
          </Card>
          <Card title={t('dellFleet.coresPerHost')} Icon={Cpu} extra={<span className="text-[10px] text-slate-400">{t('dellFleet.coresLegend')}</span>}>
            <Bars hosts={hosts} value={h => h.cores} onOpen={onOpen} color="bg-indigo-300" fmt={v => `${v}`}
              label={h => `${h.sockets} × ${(h.cpuModel ?? 'CPU').replace(/Intel\(R\)|Xeon\(R\)|CPU|@.*$/g, '').replace(/\s+/g, ' ').trim()} · ${h.threads} ${t('dellFleet.threadsShort')}`} />
          </Card>
        </div>
      </div>
    </div>
  )
}

type SortKey = 'tenant' | 'name' | 'model' | 'cores' | 'memGb' | 'diskGb' | 'bios' | 'powerW' | 'inletC' | 'health'

export function DellFleetInventory({ rows, onOpen }: { rows: FleetRow[]; onOpen: (r: FleetRow) => void }) {
  const { t } = useTranslation()
  const hosts = useMemo(() => buildHosts(rows), [rows])
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<{ k: SortKey; desc: boolean }>({ k: 'tenant', desc: false })
  const order: Record<string, number> = { Critical: 0, Warning: 1, OK: 2, none: 3 }
  const needle = q.trim().toLowerCase()
  const list = hosts
    .filter(h => !needle || [h.tenant, h.name, h.model, h.tag, h.cpuModel, h.bios].some(x => (x ?? '').toLowerCase().includes(needle)))
    .sort((a, b) => {
      const va = sort.k === 'health' ? order[a.health as string] : a[sort.k], vb = sort.k === 'health' ? order[b.health as string] : b[sort.k]
      const r = typeof va === 'number' || typeof vb === 'number' ? ((va as number) ?? -1) - ((vb as number) ?? -1)
        : sort.k === 'bios' ? cmpVersion(String(va ?? ''), String(vb ?? '')) : String(va ?? '').localeCompare(String(vb ?? ''))
      return sort.desc ? -r : r
    })
  const H = ({ k, label }: { k: SortKey; label: string }) => (
    <th className="font-medium px-2 py-1.5 whitespace-nowrap cursor-pointer select-none hover:text-slate-700" onClick={() => setSort(s => ({ k, desc: s.k === k ? !s.desc : false }))}>
      {label}{sort.k === k ? (sort.desc ? ' ▾' : ' ▴') : ''}
    </th>
  )
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
      <div className="relative max-w-sm">
        <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('dellFleet.search') as string}
          className="w-full rounded-lg border border-slate-300 pl-8 pr-3 py-1.5 text-sm bg-white text-slate-700" />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead><tr className="text-left text-slate-400 border-b border-slate-200">
            <H k="tenant" label={t('dellFleet.col.tenant')} /><H k="name" label={t('dellFleet.col.server')} /><H k="model" label={t('dellFleet.col.model')} />
            <th className="font-medium px-2 py-1.5">Service Tag</th><H k="cores" label={t('dellFleet.col.cpu')} /><H k="memGb" label="RAM" />
            <H k="diskGb" label={t('dellFleet.col.storage')} /><H k="bios" label="BIOS" /><th className="font-medium px-2 py-1.5">iDRAC</th>
            <H k="powerW" label="W" /><H k="inletC" label={t('dellFleet.col.inlet')} /><H k="health" label={t('dellFleet.col.health')} />
          </tr></thead>
          <tbody>
            {list.map(h => (
              <tr key={h.key} className="border-t border-slate-100 hover:bg-slate-50 cursor-pointer" onClick={() => onOpen(h.row)}>
                <td className="px-2 py-1.5 text-slate-600 whitespace-nowrap">{h.tenant}</td>
                <td className="px-2 py-1.5 font-mono text-slate-800 whitespace-nowrap">{h.name}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{h.model ?? '—'}</td>
                <td className="px-2 py-1.5 font-mono whitespace-nowrap">{h.tag ?? '—'}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{h.cores ? `${h.sockets} × · ${h.cores}c / ${h.threads}t` : '—'}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{h.memGb ? fmtMem(h.memGb) : '—'}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{h.diskGb ? `${fmtGb(h.diskGb)} · ${h.disks}` : '—'}{h.drivesBad > 0 && <span className="text-red-600 font-semibold"> !</span>}</td>
                <td className={cn('px-2 py-1.5 whitespace-nowrap', h.biosBehind && 'text-amber-700 font-semibold')} title={h.biosBehind ? t('dellFleet.biosBehind') as string : undefined}>{h.bios ?? '—'}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{h.idrac ?? '—'}</td>
                <td className="px-2 py-1.5 text-right font-mono">{h.powerW != null ? Math.round(h.powerW) : '—'}</td>
                <td className="px-2 py-1.5 text-right font-mono">{h.inletC != null ? `${h.inletC} °C` : '—'}</td>
                <td className="px-2 py-1.5">
                  <span className={cn('rounded px-1.5 py-0.5 font-semibold text-[10px]', h.health === 'Critical' ? 'bg-red-100 text-red-700' : h.health === 'Warning' ? 'bg-amber-100 text-amber-800' : h.health === 'OK' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500')}>
                    {t(`dellFleet.h.${h.health}`)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {list.length === 0 && <p className="text-sm text-slate-500 py-3">{t('dellFleet.nothing')}</p>}
      </div>
    </div>
  )
}

import { useMemo } from 'react'
import { useQueries } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Zap, Thermometer, Cpu, Fan, MemoryStick, HardDrive, PlugZap } from 'lucide-react'
import { metricsApi, DellDetails, DellHealth, DellHistory } from '../lib/api'
import { cn } from '../lib/utils'

// The detailed iDRAC / BMC view (services/bmc_details.py), shared by the
// agent's DellServers page and Central's physical-servers panel: a row of
// key numbers under each server, and the full detail in a modal on click.

type Pt = { t: string; v: number }
const SERIES = ['power_w', 'inlet_c', 'cpu_c', 'fan_rpm'] as const
const UNITS: Record<string, string> = { power_w: 'W', inlet_c: '°C', cpu_c: '°C', exhaust_c: '°C', fan_rpm: 'RPM' }

const fmt = (v: number | null | undefined, digits = 0) => v == null ? '—' : v.toLocaleString(undefined, { maximumFractionDigits: digits })
const gb = (v: number | null | undefined) => v == null ? '—' : v >= 1000 ? `${(v / 1000).toLocaleString(undefined, { maximumFractionDigits: 2 })} TB` : `${fmt(v, 1)} GB`

function Health({ h }: { h: DellHealth | undefined }) {
  const { t } = useTranslation()
  if (!h) return <span className="text-slate-400">—</span>
  return (
    <span className={cn('inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold',
      h === 'Critical' ? 'bg-red-100 text-red-700' : h === 'Warning' ? 'bg-amber-100 text-amber-800' : 'bg-green-100 text-green-700')}>
      {t(`bmc.value.${h}`, { defaultValue: h })}
    </span>
  )
}

function tone(h: DellHealth | undefined | 'bad') {
  return h === 'Critical' || h === 'bad' ? 'border-red-300 bg-red-50 text-red-800'
    : h === 'Warning' ? 'border-amber-300 bg-amber-50 text-amber-900' : 'border-slate-200 bg-white text-slate-800'
}

// ── Summary row under each server ────────────────────────────────────────────

export function DellSummaryStats({ details }: { details: DellDetails | null | undefined }) {
  const { t } = useTranslation()
  const s = details?.summary
  if (!s) return null
  const items: Array<{ Icon: React.ComponentType<any>; label: string; value: string; bad?: boolean }> = []
  if (s.power_w != null) items.push({ Icon: Zap, label: t('dellDetail.power'), value: `${fmt(s.power_w)} W` })
  if (s.inlet_c != null) items.push({ Icon: Thermometer, label: t('dellDetail.inlet'), value: `${fmt(s.inlet_c)} °C` })
  if (s.cpu_c != null) items.push({ Icon: Cpu, label: t('dellDetail.cpuTemp'), value: `${fmt(s.cpu_c)} °C` })
  if (s.exhaust_c != null) items.push({ Icon: Thermometer, label: t('dellDetail.exhaust'), value: `${fmt(s.exhaust_c)} °C` })
  if (s.fan_rpm != null) items.push({ Icon: Fan, label: t('dellDetail.fans'), value: `${fmt(s.fan_rpm)} RPM` })
  if (s.mem_gb != null) items.push({ Icon: MemoryStick, label: t('dellDetail.memory'), value: `${fmt(s.mem_gb)} GB` })
  if (s.cpus != null) items.push({ Icon: Cpu, label: t('dellDetail.cpus'), value: s.cores ? `${s.cpus} · ${s.cores} ${t('dellDetail.coresShort')}` : `${s.cpus}` })
  if (s.drives != null) items.push({ Icon: HardDrive, label: t('dellDetail.drives'), value: s.drives_bad ? `${s.drives_bad}/${s.drives} !` : `${s.drives} OK`, bad: !!s.drives_bad })
  if (s.psus != null) items.push({ Icon: PlugZap, label: t('dellDetail.psus'), value: s.psus_bad ? `${s.psus_bad}/${s.psus} !` : `${s.psus} OK`, bad: !!s.psus_bad })
  if (items.length === 0) return null
  return (
    <div className="flex flex-wrap gap-2">
      {items.map(({ Icon, label, value, bad }, i) => (
        <div key={i} className={cn('flex items-center gap-1.5 border rounded-lg px-2 py-1 text-xs', tone(bad ? 'bad' : undefined))}>
          <Icon size={13} className={bad ? 'text-red-600' : 'text-slate-400'} />
          <span className="text-slate-500">{label}</span>
          <span className="font-semibold font-mono">{value}</span>
        </div>
      ))}
    </div>
  )
}

// ── Charts ───────────────────────────────────────────────────────────────────

function MiniChart({ label, unit, points, now }: { label: string; unit: string; points: Pt[]; now: number | null | undefined }) {
  const { t } = useTranslation()
  const W = 300, H = 90, P = 4
  const geo = useMemo(() => {
    if (points.length < 2) return null
    const xs = points.map(p => new Date(p.t).getTime()), ys = points.map(p => p.v)
    const x0 = xs[0], x1 = xs[xs.length - 1]
    let lo = Math.min(...ys), hi = Math.max(...ys)
    if (hi - lo < 1) { hi += 0.5; lo -= 0.5 }
    const X = (x: number) => P + ((x - x0) / Math.max(1, x1 - x0)) * (W - 2 * P)
    const Y = (y: number) => P + (1 - (y - lo) / (hi - lo)) * (H - 2 * P)
    const line = points.map((p, i) => `${i ? 'L' : 'M'}${X(xs[i]).toFixed(1)},${Y(p.v).toFixed(1)}`).join(' ')
    return { line, area: `${line} L${X(x1).toFixed(1)},${H - P} L${X(x0).toFixed(1)},${H - P} Z`, lo, hi }
  }, [points])
  return (
    <div className="border border-slate-200 rounded-lg p-2 bg-white">
      <div className="flex items-baseline justify-between text-xs">
        <span className="text-slate-500">{label}</span>
        <span className="font-semibold font-mono text-slate-800">{fmt(now ?? points[points.length - 1]?.v)} {unit}</span>
      </div>
      {geo ? (
        <>
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-20 mt-1">
            <path d={geo.area} className="fill-indigo-100" />
            <path d={geo.line} fill="none" stroke="#4f46e5" strokeWidth="1.5" />
          </svg>
          <div className="flex justify-between text-[10px] text-slate-400 font-mono">
            <span>min {fmt(Math.min(...points.map(p => p.v)))}</span><span>max {fmt(Math.max(...points.map(p => p.v)))}</span>
          </div>
        </>
      ) : <div className="h-20 flex items-center justify-center text-[11px] text-slate-400">{t('dellDetail.noHistory')}</div>}
    </div>
  )
}

function Charts({ serverId, history, summary }: { serverId?: number; history?: DellHistory; summary: NonNullable<DellDetails['summary']> }) {
  const { t } = useTranslation()
  const live = history === undefined && serverId != null
  const qs = useQueries({
    queries: SERIES.map(k => ({
      queryKey: ['metric-series', `bmc:${serverId}:${k}`, 7],
      queryFn: () => metricsApi.series(`bmc:${serverId}:${k}`, 7),
      enabled: live,
    })),
  })
  const shown = SERIES.filter(k => summary[k] != null)
  if (shown.length === 0) return null
  return (
    <div>
      <p className="text-xs text-slate-500 mb-1">{live ? t('dellDetail.history7d') : t('dellDetail.history24h')}</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
        {shown.map(k => {
          const pts: Pt[] = live ? (qs[SERIES.indexOf(k)].data?.points ?? []) : (history?.[k] ?? []).map(([at, v]) => ({ t: at, v }))
          return <MiniChart key={k} label={t(`dellDetail.series.${k}`)} unit={UNITS[k]} points={pts} now={summary[k]} />
        })}
      </div>
    </div>
  )
}

// ── Detail sections ─────────────────────────────────────────────────────────

function Section({ title, extra, children }: { title: string; extra?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="border border-slate-200 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between gap-2 bg-slate-50 px-3 py-1.5 border-b border-slate-200">
        <span className="text-xs font-semibold text-slate-700">{title}</span>
        {extra}
      </div>
      <div className="p-2 overflow-x-auto">{children}</div>
    </div>
  )
}

function Table({ head, rows }: { head: string[]; rows: Array<Array<React.ReactNode>> }) {
  return (
    <table className="w-full text-xs">
      <thead><tr className="text-left text-slate-400">{head.map(h => <th key={h} className="font-medium px-1.5 py-1 whitespace-nowrap">{h}</th>)}</tr></thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-t border-slate-100">
            {r.map((c, j) => <td key={j} className="px-1.5 py-1 text-slate-700 whitespace-nowrap">{c ?? '—'}</td>)}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function KV({ items }: { items: Array<[string, React.ReactNode]> }) {
  return (
    <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1.5 text-xs">
      {items.filter(([, v]) => v != null && v !== '').map(([k, v]) => (
        <div key={k}><dt className="text-slate-400">{k}</dt><dd className="text-slate-800 font-medium break-words">{v}</dd></div>
      ))}
    </dl>
  )
}

export function DellServerDetail({ details, serverId, history }: {
  details: DellDetails | null | undefined
  serverId?: number        // agent: charts read the metric series of this server
  history?: DellHistory    // Central: charts from the snapshot's last day
}) {
  const { t } = useTranslation()
  if (!details) return <p className="text-sm text-slate-500">{t('dellDetail.none')}</p>
  const sys = details.system ?? {}
  const st = details.storage ?? {}
  const pw = details.power ?? {}
  const yes = t('common.yes'), no = t('common.no')

  return (
    <div className="space-y-3">
      {details.error && <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded p-2">{t('dellDetail.partial')}: {details.error}</p>}

      <Section title={t('dellDetail.system')} extra={<span className="text-[10px] text-slate-400">{t('dellDetail.source')}: {details.source === 'racadm' ? 'RACADM' : 'Redfish'}</span>}>
        <KV items={[
          [t('dellDetail.model'), sys.model], [t('dellDetail.serviceTag'), sys.service_tag], [t('dellDetail.hostname'), sys.hostname],
          [t('dellDetail.powerState'), sys.power_state], ['BIOS', sys.bios], ['iDRAC', sys.idrac_fw],
          [t('dellDetail.generation'), sys.generation],
          [t('dellDetail.airflow'), sys.airflow_cfm != null ? `${fmt(sys.airflow_cfm)} CFM` : null],
          [t('dellDetail.intrusion'), details.intrusion],
        ]} />
        {sys.rollups && Object.keys(sys.rollups).length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {Object.entries(sys.rollups).map(([k, v]) => (
              <span key={k} className={cn('border rounded px-1.5 py-0.5 text-[10px]', tone(v))}>{t(`dellDetail.rollup.${k}`, { defaultValue: k })}: {v}</span>
            ))}
          </div>
        )}
      </Section>

      {details.summary && <Charts serverId={serverId} history={history} summary={details.summary} />}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {(details.temps?.length ?? 0) > 0 && (
          <Section title={t('dellDetail.temps')}>
            <Table head={[t('dellDetail.sensor'), '°C', t('dellDetail.warn'), t('dellDetail.crit'), t('dellDetail.state')]}
              rows={details.temps!.map(x => [x.name, <span className="font-mono font-semibold">{fmt(x.c, 1)}</span>, fmt(x.warn), fmt(x.crit), <Health h={x.health} />])} />
          </Section>
        )}
        {(details.fans?.length ?? 0) > 0 && (
          <Section title={t('dellDetail.fansTitle')} extra={details.fan_redundancy ? <span className="text-[10px] text-slate-500">{t('dellDetail.redundancy')}: <Health h={details.fan_redundancy} /></span> : null}>
            <Table head={[t('dellDetail.sensor'), 'RPM', 'PWM', t('dellDetail.state')]}
              rows={details.fans!.map(x => [x.name, <span className="font-mono font-semibold">{fmt(x.rpm)}</span>, x.pwm != null ? `${fmt(x.pwm)} %` : '—', <Health h={x.health} />])} />
          </Section>
        )}
      </div>

      {(pw.watts != null || (pw.psus?.length ?? 0) > 0) && (
        <Section title={t('dellDetail.powerTitle')} extra={pw.redundancy ? <span className="text-[10px] text-slate-500">{t('dellDetail.redundancy')}: <Health h={pw.redundancy} /></span> : null}>
          <KV items={[
            [t('dellDetail.powerNow'), pw.watts != null ? `${fmt(pw.watts)} W` : null],
            [t('dellDetail.powerMinAvgMax'), pw.avg_w != null ? `${fmt(pw.min_w)} / ${fmt(pw.avg_w)} / ${fmt(pw.max_w)} W` : null],
            [t('dellDetail.powerCapacity'), pw.capacity_w != null ? `${fmt(pw.capacity_w)} W` : null],
          ]} />
          {(pw.psus?.length ?? 0) > 0 && (
            <div className="mt-2">
              <Table head={[t('dellDetail.psu'), t('dellDetail.model'), t('dellDetail.capacity'), t('dellDetail.output'), t('dellDetail.inputV'), 'FW', t('dellDetail.detailState'), t('dellDetail.state')]}
                rows={pw.psus!.map(p => [p.name, p.model, p.capacity_w != null ? `${p.capacity_w} W` : null, p.output_w != null ? `${p.output_w} W` : null,
                  p.input_v != null ? `${fmt(p.input_v)} V` : null, p.firmware, p.state?.replace(/\|/g, ', '), <Health h={p.health} />])} />
            </div>
          )}
        </Section>
      )}

      {(details.cpus?.length ?? 0) > 0 && (
        <Section title={t('dellDetail.cpusTitle')}>
          <Table head={[t('dellDetail.socket'), t('dellDetail.model'), t('dellDetail.cores'), t('dellDetail.threads'), 'MHz', t('dellDetail.state')]}
            rows={details.cpus!.map(c => [c.name, c.model, c.cores, c.threads, c.max_mhz && c.max_mhz !== c.mhz ? `${fmt(c.mhz)} (max ${fmt(c.max_mhz)})` : fmt(c.mhz), <Health h={c.health} />])} />
        </Section>
      )}

      {(details.dimms?.length ?? 0) > 0 && (
        <Section title={t('dellDetail.memoryTitle')} extra={<span className="text-[10px] text-slate-500">
          {fmt(sys.mem_gb ?? details.summary?.mem_gb)} GB{sys.dimm_slots ? ` · ${t('dellDetail.slots', { used: sys.dimm_populated ?? details.dimms!.length, total: sys.dimm_slots })}` : ''}
        </span>}>
          <Table head={[t('dellDetail.slot'), 'GB', t('dellDetail.type'), 'MHz', t('dellDetail.vendor'), t('dellDetail.part'), t('dellDetail.ranks'), t('dellDetail.state')]}
            rows={details.dimms!.map(d => [d.slot, fmt(d.gb), d.type, d.mhz, d.vendor, d.part, d.ranks, <Health h={d.health} />])} />
        </Section>
      )}

      {((st.drives?.length ?? 0) > 0 || (st.volumes?.length ?? 0) > 0) && (
        <Section title={t('dellDetail.storageTitle')}>
          {(st.controllers?.length ?? 0) > 0 && (
            <Table head={[t('dellDetail.controller'), 'FW', t('dellDetail.cache'), t('dellDetail.state')]}
              rows={st.controllers!.map(c => [c.name, c.firmware, c.cache_mb ? `${c.cache_mb} MB` : null, <Health h={c.health} />])} />
          )}
          {(st.volumes?.length ?? 0) > 0 && (
            <div className="mt-2">
              <Table head={[t('dellDetail.volume'), 'RAID', t('dellDetail.capacity'), t('dellDetail.detailState'), t('dellDetail.state')]}
                rows={st.volumes!.map(v => [v.name, v.raid, gb(v.gb), v.state, <Health h={v.health} />])} />
            </div>
          )}
          {(st.drives?.length ?? 0) > 0 && (
            <div className="mt-2">
              <Table head={[t('dellDetail.drive'), t('dellDetail.model'), t('dellDetail.type'), t('dellDetail.capacity'), t('dellDetail.lifeLeft'), t('dellDetail.predicted'), 'FW', t('dellDetail.serial'), t('dellDetail.state')]}
                rows={st.drives!.map(d => [d.name, d.model, [d.media, d.protocol].filter(Boolean).join(' · ') || null, gb(d.gb),
                  d.life_left_pct != null ? `${fmt(d.life_left_pct)} %` : null,
                  d.failure_predicted == null ? null : d.failure_predicted ? <span className="text-red-700 font-semibold">{yes}</span> : no,
                  d.firmware, d.serial, <Health h={d.health} />])} />
            </div>
          )}
          {(details.batteries?.length ?? 0) > 0 && (
            <p className="text-xs text-slate-600 mt-2">{t('dellDetail.battery')}: {details.batteries!.map((b, i) => <span key={i} className="mr-2">{b.name} <Health h={b.health} /></span>)}</p>
          )}
        </Section>
      )}

      {(details.nics?.length ?? 0) > 0 && (
        <Section title={t('dellDetail.nicsTitle')}>
          <Table head={[t('dellDetail.port'), t('dellDetail.model'), t('dellDetail.link'), t('dellDetail.speed'), ...(details.nics!.some(n => n.mac) ? ['MAC'] : []), t('dellDetail.state')]}
            rows={details.nics!.map(n => [n.name, n.model, n.link === 'LinkUp' ? t('dellDetail.up') : n.link === 'LinkDown' ? t('dellDetail.down') : n.link,
              n.speed_mbps ? `${n.speed_mbps} Mb/s` : null, ...(details.nics!.some(x => x.mac) ? [<span className="font-mono">{n.mac}</span>] : []), <Health h={n.health} />])} />
        </Section>
      )}
    </div>
  )
}

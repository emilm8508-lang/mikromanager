import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { SecData } from '../lib/securityData'
import { eventCategory } from '../lib/securityData'
import { ago } from './HypervWidgets'
import {
  Widget, Empty, Donut, HBars, VBars, StackRows, AreaChart, NumberTiles, RiskGauge, SEV_COLOR, CAT, OTHER, INK, fmt, type Seg,
} from './SecCharts'
import { CheckCircle2, AlertTriangle, XCircle, ExternalLink } from 'lucide-react'
import { cn } from '../lib/utils'

// The Security Summary dashboard: one grid of widgets over a SecData (see lib/securityData.ts). The agent's page and
// Central's page both render this; the page decides where the data comes from and which filters sit above it.

const pascal = (s: string) => s.split('_').map(p => p.charAt(0).toUpperCase() + p.slice(1)).join('')
const humanize = (s: string) => s.replace(/_/g, ' ')

function useEventLabel() {
  const { t } = useTranslation()
  return (type: string) => t(`alerts.event${pascal(type)}`, { defaultValue: humanize(type) }) as string
}

/** top `n` as separate slices, the rest folded into one grey "other" slice — categorical colours are never cycled */
function foldSegs(items: Array<{ key: string; label: string; value: number }>, n: number, otherLabel: string): Seg[] {
  const top = items.slice(0, n).map((s, i) => ({ ...s, color: CAT[i] }))
  const rest = items.slice(n).reduce((a, s) => a + s.value, 0)
  return rest > 0 ? [...top, { key: '_other', label: otherLabel, value: rest, color: OTHER }] : top
}

const CATEGORY_ICON = { ok: CheckCircle2, warn: AlertTriangle, bad: XCircle }

export function SecurityDashboard({ data, central }: { data: SecData; central: boolean }) {
  const { t } = useTranslation()
  const eventLabel = useEventLabel()
  const [range, setRange] = useState<'24h' | '7d'>('24h')
  const v = data.vuln, c = data.compliance, e = data.events, p = data.patch
  const none = t('secDash.noData') as string

  // ── nodes ──
  const staleMin = central ? [5, 15] : [120, 1440]
  const nodes = [...data.nodes].sort((a, b) => (a.ts ? new Date(a.ts).getTime() : 0) - (b.ts ? new Date(b.ts).getTime() : 0))
  const nodeState = (ts: string | null) => {
    const min = ts ? (Date.now() - new Date(ts).getTime()) / 60000 : Infinity
    return min > staleMin[1] ? 'bad' : min > staleMin[0] ? 'warn' : 'ok'
  }

  // ── events ──
  const series = range === '24h' ? e.hourly : e.daily
  const tickLabel = (iso: string) => range === '24h'
    ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : new Date(iso).toLocaleDateString([], { day: '2-digit', month: '2-digit' })
  const byType = range === '24h' ? e.byType24h : e.byType7d
  const typeSegs = foldSegs(byType.map(x => ({ key: x.key, label: eventLabel(x.key), value: x.n })), 5, t('secDash.other') as string)
  const catTotals = byType.reduce((m, x) => { const k = eventCategory(x.key); m[k] = (m[k] ?? 0) + x.n; return m }, {} as Record<string, number>)

  // ── vulnerabilities ──
  const sevSegs: Seg[] = (['critical', 'high', 'medium', 'low'] as const).map(k => ({ key: k, label: t(`secDash.sev.${k}`) as string, value: v.findingsBySev[k], color: SEV_COLOR[k] }))
  const openFindings = sevSegs.reduce((a, s) => a + s.value, 0)

  // ── compliance ──
  const compSegs: Seg[] = [
    { key: 'passed', label: t('secDash.passed') as string, value: c.passed, color: '#0ca30c' },
    { key: 'failed', label: t('secDash.failed') as string, value: c.failed, color: SEV_COLOR.critical },
    { key: 'unknown', label: t('secDash.unknownChecks') as string, value: c.unknown, color: OTHER },
  ]

  // ── patches ──
  const patchSegs: Seg[] = [
    { key: 'current', label: t('secDash.upToDate') as string, value: p.current, color: '#0ca30c' },
    { key: 'need', label: t('secDash.needUpdates') as string, value: p.needUpdates, color: SEV_COLOR.medium },
    { key: 'unknown', label: t('secDash.unknown') as string, value: p.unknown, color: OTHER },
  ]

  // ── infrastructure ──
  const infraState = (r: { bad: number; warn?: number }) => (r.bad > 0 ? 'bad' : (r.warn ?? 0) > 0 ? 'warn' : 'ok')

  return (
    <div className="space-y-4">
      {data.partialClients > 0 && (
        <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-3 py-1.5">{t('secDash.partialNote')}</p>
      )}

      {/* Row 1 — node health, events over time, events by type */}
      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <Widget className="xl:col-span-4 lg:col-span-3" title={t(central ? 'secDash.clientHealth' : 'secDash.nodeHealth') as string} subtitle={t(central ? 'secDash.clientHealthSub' : 'secDash.nodeHealthSub') as string}>
          {nodes.length === 0 ? <Empty text={none} /> : (
            <div className="max-h-[230px] overflow-y-auto -mx-1">
              <table className="w-full text-xs">
                <thead><tr className="text-left text-slate-400 border-b border-slate-200"><th className="py-1 px-1 font-normal">{t('secDash.colName')}</th><th className="font-normal">{t('secDash.colLastContact')}</th></tr></thead>
                <tbody>
                  {nodes.map(n => {
                    const st = nodeState(n.ts) as 'ok' | 'warn' | 'bad'
                    const I = CATEGORY_ICON[st]
                    return (
                      <tr key={`${n.group}:${n.name}`} className="border-b border-slate-100">
                        <td className="py-1.5 px-1 text-slate-800 truncate max-w-[160px]" title={n.name}>{n.name}<span className="text-[10px] text-slate-400 ml-1.5">{t(`secDash.group.${n.group}`)}</span></td>
                        <td className={cn('whitespace-nowrap', st === 'bad' ? 'text-red-600 font-medium' : st === 'warn' ? 'text-amber-700' : 'text-slate-600')}><I size={11} className="inline mr-1 -mt-0.5" />{ago(n.ts)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Widget>

        <Widget className="xl:col-span-5 lg:col-span-3" title={t('secDash.eventsOverTime') as string} subtitle={t('secDash.eventsSub') as string}
          right={
            <div className="inline-flex rounded-md border border-slate-300 overflow-hidden text-[11px] shrink-0">
              {(['24h', '7d'] as const).map(r => <button key={r} onClick={() => setRange(r)} className={cn('px-2 py-0.5', range === r ? 'bg-indigo-600 text-white' : 'bg-white text-slate-600 hover:bg-slate-50')}>{r === '24h' ? '24 h' : '7 d'}</button>)}
            </div>
          }>
          {!e.available ? <Empty text={t('secDash.eventsNone') as string} /> : (
            <AreaChart points={series} label={t('secDash.eventsOverTime') as string} tickLabel={tickLabel} tickEvery={range === '24h' ? 4 : 1} />
          )}
        </Widget>

        <Widget className="xl:col-span-3 lg:col-span-6" title={t('secDash.eventsByType') as string} subtitle={range === '24h' ? '24 h' : '7 d'}>
          {typeSegs.length === 0 ? <Empty text={t('secDash.eventsNone') as string} /> : (
            <>
              <Donut segs={typeSegs} size={132} centerLabel={t('secDash.eventsCenter') as string} />
              <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-3 text-[11px] text-slate-500">
                {Object.entries(catTotals).map(([k, n]) => <span key={k}>{t(`secDash.cat.${k}`)}: <b className="text-slate-800">{fmt(n)}</b></span>)}
              </div>
            </>
          )}
        </Widget>
      </div>

      {/* Row 2 — vulnerabilities at a glance */}
      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <Widget className="xl:col-span-4 lg:col-span-3" title={t('secDash.hostsByVuln') as string} subtitle={t('secDash.hostsByVulnSub') as string}>
          <NumberTiles tiles={[
            { label: t('secDash.vulnerableHosts', { total: v.hostsTotal }) as string, value: v.hostsVulnerable },
            { label: t('secDash.sev.critical') as string, value: v.hostsBySev.critical, tone: 'critical' },
            { label: t('secDash.sev.high') as string, value: v.hostsBySev.high, tone: 'high' },
          ]} />
        </Widget>
        <Widget className="xl:col-span-5 lg:col-span-3" title={t('secDash.vulnBySeverity') as string} subtitle={v.accepted ? t('secDash.acceptedNote', { count: v.accepted }) as string : undefined}>
          {openFindings === 0 ? <Empty text={t('secDash.noVulns') as string} /> : <Donut segs={sevSegs} size={146} centerLabel={t('secDash.openFindings') as string} />}
        </Widget>
        <Widget className="xl:col-span-3 lg:col-span-6" title={t('secDash.riskScore') as string} subtitle={t('secDash.riskSub') as string}>
          <RiskGauge score={v.risk} caption={t('secDash.riskCaption') as string} scale={[t('secDash.riskLow') as string, t('secDash.riskHigh') as string]} />
        </Widget>
      </div>

      {/* Row 3 — top vulnerabilities, by host class */}
      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <Widget className="xl:col-span-7 lg:col-span-4" title={t('secDash.topVulns') as string} subtitle={t('secDash.topVulnsSub') as string}>
          {v.topCves.length === 0 ? <Empty text={t('secDash.noVulns') as string} /> : (
            <table className="w-full text-xs">
              <thead><tr className="text-left text-slate-400 border-b border-slate-200"><th className="py-1 font-normal">{t('secDash.colSeverity')}</th><th className="font-normal">CVE</th><th className="font-normal text-right">{t('secDash.colHosts')}</th><th className="font-normal text-right">CVSS</th></tr></thead>
              <tbody>
                {v.topCves.map(x => (
                  <tr key={x.cve} className="border-b border-slate-100">
                    <td className="py-1.5"><span className="inline-flex items-center gap-1.5 text-slate-700"><i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: SEV_COLOR[x.sev] }} />{t(`secDash.sev.${x.sev}`)}</span></td>
                    <td><a href={`https://nvd.nist.gov/vuln/detail/${x.cve}`} target="_blank" rel="noreferrer" className="text-indigo-600 hover:underline inline-flex items-center gap-1 font-mono">{x.cve}<ExternalLink size={10} /></a></td>
                    <td className="text-right tabular-nums text-slate-900">{x.hosts}</td>
                    <td className="text-right tabular-nums text-slate-600">{x.cvss ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Widget>
        <Widget className="xl:col-span-5 lg:col-span-2" title={t('secDash.vulnByClass') as string} subtitle={t('secDash.openFindings') as string}>
          {v.byClass.length === 0 ? <Empty text={t('secDash.noVulns') as string} /> : (
            <VBars bars={v.byClass.map((x, i) => ({ key: x.key, label: t(`secDash.class.${x.key}`, { defaultValue: x.key }) as string, value: x.n, color: CAT[i % CAT.length] }))} />
          )}
        </Widget>
      </div>

      {/* Row 4 — compliance and patches */}
      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <Widget className="xl:col-span-4 lg:col-span-3" title={t('secDash.compliance') as string} subtitle={c.score != null ? t('secDash.complianceScore', { score: c.score }) as string : undefined}>
          {c.passed + c.failed + c.unknown === 0 && !c.partial ? <Empty text={t('secDash.noChecks') as string} /> : (
            c.partial ? <Donut segs={[{ key: 'failed', label: t('secDash.failed') as string, value: c.failed, color: SEV_COLOR.critical }]} size={132} centerLabel={t('secDash.failed') as string} />
              : <Donut segs={compSegs} size={132} center={c.score != null ? `${c.score}%` : undefined} centerLabel={t('secDash.passed') as string} />
          )}
        </Widget>
        <Widget className="xl:col-span-4 lg:col-span-3" title={t('secDash.complianceFailed') as string} subtitle={t('secDash.complianceFailedSub') as string}>
          {c.failed === 0 ? <Empty text={t('secDash.noFailed') as string} /> : (
            <div className="space-y-4">
              <HBars bars={(['high', 'medium', 'low'] as const).map(k => ({ key: k, label: t(`secDash.sev.${k === 'low' ? 'low' : k}`) as string, value: c.failedBySev[k], color: SEV_COLOR[k === 'high' ? 'critical' : k === 'medium' ? 'high' : 'medium'] }))} />
              {!c.partial && <StackRows rows={c.byPlatform.map(x => ({ key: x.key, label: t(`secDash.class.${x.key}`, { defaultValue: x.key }) as string, a: x.passed, b: x.failed }))}
                a={{ label: t('secDash.passed') as string, color: '#0ca30c' }} b={{ label: t('secDash.failed') as string, color: SEV_COLOR.critical }} />}
            </div>
          )}
        </Widget>
        <Widget className="xl:col-span-4 lg:col-span-6" title={t('secDash.patch') as string} subtitle={t('secDash.patchSub', { count: p.hosts }) as string}>
          {p.hosts === 0 && p.rosDevices === 0 ? <Empty text={none} /> : (
            <div className="space-y-3">
              {p.hosts > 0 && <Donut segs={patchSegs} size={120} centerLabel={t('secDash.servers') as string} />}
              <ul className="text-xs text-slate-600 space-y-0.5">
                {p.packages > 0 && <li>{t('secDash.pkgs', { count: p.packages })}</li>}
                {p.reboot > 0 && <li className="text-red-700 font-medium" title={p.rebootNames.join(', ')}>{t('secDash.restartNeeded', { count: p.reboot })}: <span className="font-normal text-slate-500">{p.rebootNames.slice(0, 4).join(', ')}{p.rebootNames.length > 4 ? '…' : ''}</span></li>}
                {p.rosOutdated > 0 && <li>{t('secDash.rosOutdated', { count: p.rosOutdated })}</li>}
                {p.firmwareOutdated > 0 && <li>{t('secDash.fwOutdated', { count: p.firmwareOutdated })}</li>}
              </ul>
            </div>
          )}
        </Widget>
      </div>

      {/* Row 5 — Wazuh and firewall */}
      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <Widget className="xl:col-span-4 lg:col-span-2" title={t('secDash.wazuh') as string} subtitle={t('secDash.wazuhSub') as string}>
          {data.wazuh.total === 0 ? <Empty text={t('secDash.wazuhNone') as string} /> : (
            <div className="space-y-3">
              <Donut size={110} segs={[
                { key: 'critical', label: t('secDash.band.critical') as string, value: data.wazuh.byBand.critical, color: SEV_COLOR.critical },
                { key: 'important', label: t('secDash.band.important') as string, value: data.wazuh.byBand.important, color: SEV_COLOR.high },
                { key: 'info', label: t('secDash.band.info') as string, value: data.wazuh.byBand.info, color: SEV_COLOR.low },
              ]} />
              <HBars bars={data.wazuh.topRules.map(r => ({ key: r.name, label: r.name, value: r.n }))} color={CAT[1]} />
            </div>
          )}
        </Widget>
        <Widget className="xl:col-span-4 lg:col-span-2" title={t('secDash.fwSources') as string} subtitle={data.firewall.devices ? t('secDash.fwSub', { devices: data.firewall.devices, logs: data.firewall.logs }) as string : undefined}>
          {data.firewall.topSources.length === 0 ? <Empty text={t('secDash.fwNone') as string} /> : <HBars bars={data.firewall.topSources.map(s => ({ key: s.ip, label: s.ip, value: s.n }))} color={CAT[0]} />}
        </Widget>
        <Widget className="xl:col-span-4 lg:col-span-2" title={t('secDash.fwPorts') as string} subtitle={t('secDash.fwPortsSub') as string}>
          {data.firewall.topPorts.length === 0 ? <Empty text={t('secDash.fwNone') as string} /> : <VBars bars={data.firewall.topPorts.map(s => ({ key: s.port, label: s.port, value: s.n }))} color={CAT[2]} />}
        </Widget>
      </div>

      {/* Row 6 — events by device and the state of the infrastructure */}
      <div className="grid grid-cols-1 lg:grid-cols-6 xl:grid-cols-12 gap-4">
        <Widget className="xl:col-span-4 lg:col-span-3" title={t('secDash.eventsByDevice') as string} subtitle="24 h">
          {e.topDevices.length === 0 ? <Empty text={t('secDash.eventsNone') as string} /> : <HBars bars={e.topDevices.map(d => ({ key: d.name, label: d.name, value: d.n }))} color={CAT[3]} />}
        </Widget>
        <Widget className="xl:col-span-8 lg:col-span-3" title={t('secDash.infra') as string} subtitle={t('secDash.infraSub') as string}>
          {data.infra.length === 0 ? <Empty text={none} /> : (
            <table className="w-full text-xs">
              <thead><tr className="text-left text-slate-400 border-b border-slate-200"><th className="py-1 font-normal">{t('secDash.colSource')}</th><th className="font-normal">{t('secDash.colStatus')}</th><th className="font-normal text-right">{t('secDash.colProblems')}</th><th className="font-normal text-right">{t('secDash.colTotal')}</th></tr></thead>
              <tbody>
                {data.infra.map(r => {
                  const st = infraState(r) as 'ok' | 'warn' | 'bad'
                  const I = CATEGORY_ICON[st]
                  return (
                    <tr key={r.key} className="border-b border-slate-100">
                      <td className="py-1.5 text-slate-800">{t(`secDash.infraRow.${r.key}`)}</td>
                      <td><span className={cn('inline-flex items-center gap-1', st === 'bad' ? 'text-red-700' : st === 'warn' ? 'text-amber-700' : 'text-emerald-700')}><I size={12} />{t(`secDash.state.${st}`)}</span></td>
                      <td className="text-right tabular-nums text-slate-900">{r.bad + (r.warn ?? 0)}</td>
                      <td className="text-right tabular-nums text-slate-500">{r.total}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </Widget>
      </div>
      <p className="text-[10px] text-slate-400" style={{ color: INK.muted }}>{t('secDash.footer')}</p>
    </div>
  )
}

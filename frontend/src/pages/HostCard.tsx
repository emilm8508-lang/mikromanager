import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, FileDown, Pencil, Cable, Wrench } from 'lucide-react'
import { assetsApi, hostCardApi, type HostCard as Card } from '../lib/api'
import { useAgo, SevBadge } from '../components/SocBits'
import { HostLink } from '../components/HostLink'
import { cn } from '../lib/utils'

const HEALTH: Record<string, string> = { ok: 'bg-green-50 text-green-700 border-green-300', warn: 'bg-amber-50 text-amber-800 border-amber-300', crit: 'bg-red-50 text-red-700 border-red-300' }
const AVAIL: Record<string, string> = { up: 'text-green-600', down: 'text-red-600', unreachable: 'text-amber-600' }

function Section({ title, count, children, wide }: { title: string; count?: number | string; children: React.ReactNode; wide?: boolean }) {
  return (
    <section className={cn('bg-white border border-slate-200 rounded-xl overflow-hidden', wide && 'lg:col-span-2')}>
      <div className="px-4 py-2 border-b border-slate-100 flex items-center gap-2"><h2 className="text-sm font-semibold text-slate-800">{title}</h2>{count != null && <span className="text-xs text-slate-400">{count}</span>}</div>
      <div className="p-4 text-sm">{children}</div>
    </section>
  )
}

function Kv({ rows }: { rows: Array<[string, React.ReactNode]> }) {
  const shown = rows.filter(([, v]) => v != null && v !== '' && v !== false)
  if (shown.length === 0) return <p className="text-slate-400">—</p>
  return <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-xs">{shown.map(([k, v]) => <div key={k} className="contents"><dt className="text-slate-500">{k}</dt><dd className="text-slate-800 break-words">{v}</dd></div>)}</dl>
}

const dur = (s: number) => (s >= 86400 ? `${Math.round(s / 86400)} d` : s >= 3600 ? `${Math.round(s / 3600)} h` : `${Math.max(1, Math.round(s / 60))} min`)

// One host, everything the application knows about it (a configuration item): identity, health, alerts, vulnerabilities, TLS, services, updates, resources,
// configuration history, syslog, what it hangs on and what hangs on it, response actions, access and the timeline.
export function HostCard() {
  const { t, i18n } = useTranslation()
  const ago = useAgo()
  const { ref = '' } = useParams()
  const q = useQuery({ queryKey: ['hostcard', ref], queryFn: () => hostCardApi.get(ref), refetchInterval: 60000, retry: false })
  const [pbErr, setPbErr] = useState<string | null>(null)
  const c: Card | undefined = q.data
  const playbook = async () => {
    if (!c) return
    try {
      const r = await assetsApi.playbook(c.asset_id, i18n.language.startsWith('pl') ? 'pl' : 'en')
      const url = URL.createObjectURL(new Blob([r.markdown], { type: 'text/markdown;charset=utf-8' }))
      const a = document.createElement('a'); a.href = url; a.download = r.filename; a.click(); URL.revokeObjectURL(url); setPbErr(null)
    } catch (e) { setPbErr((e as Error).message) }
  }
  if (q.isLoading) return <div className="p-6 text-sm text-slate-500">{t('common.loading')}</div>
  if (q.isError || !c) return <div className="p-6 space-y-2"><p className="text-sm text-red-600">{t('hostcard.notFound')}</p><Link to="/inventory/list" className="text-sm text-indigo-600 hover:underline">{t('assets.listTitle')}</Link></div>
  const ci = c.ci
  const av = c.status.availability
  const health = c.status.health
  const reason = (code: string) => code.startsWith('alert:') ? t(`soc.rule.${code.slice(6)}`, { defaultValue: code.slice(6) }) : code.startsWith('bmc_') ? t(`bmc.reason.${code.slice(4)}`) : t(`hostcard.reason.${code}`, { defaultValue: code })
  const vc = c.vulnerabilities?.counts
  const tlsBad = c.tls.filter(x => x.findings.length > 0).length
  const upd = c.updates
  const pending = (upd?.windows?.upgradable ?? 0) + (upd?.linux?.upgradable ?? 0)
  const src = (k: string) => c.sources.find(s => s.kind === k)
  const rel = c.relationships
  const tile = (label: string, value: React.ReactNode, tone = 'text-slate-800', sub?: React.ReactNode) => (
    <div className="bg-white border border-slate-200 rounded-xl px-4 py-2 min-w-[8.5rem]"><div className="text-xs text-slate-500">{label}</div><div className={cn('text-xl font-bold tabular-nums', tone)}>{value}</div>{sub && <div className="text-[11px] text-slate-400">{sub}</div>}</div>
  )
  return (
    <div className="p-6 space-y-4 max-w-[1300px]">
      <Link to="/inventory/list" className="text-sm text-slate-500 hover:text-indigo-600 inline-flex items-center gap-1"><ArrowLeft size={14} /> {t('assets.listTitle')}</Link>
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2 flex-wrap">{c.name}
            <span className={cn('text-xs font-medium border rounded-full px-2.5 py-0.5', HEALTH[health.level])}>{t(`hostcard.health.${health.level}`)}</span>
          </h1>
          <p className="text-sm text-slate-500 mt-0.5 font-mono">{c.ip ?? '—'}{ci.mac ? ` · ${ci.mac}` : ''}
            <span className="ml-3 font-sans text-xs border border-slate-200 rounded px-1.5 py-0.5 text-slate-600">{t(`hostcard.class.${ci.class}`, { defaultValue: ci.class })}</span>
            <span className={cn('ml-2 font-sans text-xs', ci.ci_status === 'operational' ? 'text-green-700' : 'text-slate-400')}>{t(`hostcard.ciStatus.${ci.ci_status}`)}</span>
          </p>
          {(health.critical.length > 0 || health.warnings.length > 0) && (
            <p className="text-xs mt-1.5 flex flex-wrap gap-1.5">
              {health.critical.map(x => <span key={x} className="bg-red-50 text-red-700 border border-red-200 rounded px-1.5 py-0.5">{reason(x)}</span>)}
              {health.warnings.map(x => <span key={x} className="bg-amber-50 text-amber-800 border border-amber-200 rounded px-1.5 py-0.5">{reason(x)}</span>)}
            </p>
          )}
          {c.status.maintenance.length > 0 && <p className="text-xs mt-1 text-sky-700">{t('hostcard.inMaintenance', { name: c.status.maintenance.map(m => m.name).join(', ') })}</p>}
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <Link to={`/inventory/${c.asset_id}`} className="inline-flex items-center gap-1.5 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50"><Pencil size={13} /> {t('hostcard.editAsset')}</Link>
          {src('device') && <Link to={src('device')!.path} className="inline-flex items-center gap-1.5 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50">{t('hostcard.deviceDetails')}</Link>}
          {c.access && <Link to="/onboarding" className="inline-flex items-center gap-1.5 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50"><Cable size={13} /> {t('hostcard.testAccess')}</Link>}
          <Link to="/tools" className="inline-flex items-center gap-1.5 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50"><Wrench size={13} /> {t('nav.nettools')}</Link>
          <button onClick={() => void playbook()} className="inline-flex items-center gap-1.5 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 hover:bg-slate-50"><FileDown size={13} /> {t('playbook.button')}</button>
        </div>
      </div>
      {pbErr && <p className="text-xs text-red-600">{pbErr}</p>}
      {c.errors.length > 0 && <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded p-2">{t('hostcard.partial')}: {c.errors.join(' · ')}</p>}

      <div className="flex flex-wrap gap-2">
        {tile(t('hostcard.tile.availability') as string, av ? t(`hostcard.avail.${av.state}`) : '—', av ? AVAIL[av.state] : 'text-slate-400', av ? (av.uptime != null ? `${t('hostcard.uptime30')}: ${av.uptime}%` : undefined) : undefined)}
        {tile(t('hostcard.tile.alerts') as string, c.alerts.open_count, c.alerts.open_count ? 'text-red-600' : 'text-slate-300', c.alerts.closed_30d ? t('hostcard.closed30', { n: c.alerts.closed_30d }) : undefined)}
        {tile(t('hostcard.tile.vulns') as string, c.vulnerabilities?.total ?? 0, (vc?.critical ?? 0) ? 'text-red-600' : (vc?.high ?? 0) ? 'text-orange-600' : 'text-slate-800', c.vulnerabilities?.kev ? `KEV: ${c.vulnerabilities.kev}` : undefined)}
        {tile(t('hostcard.tile.tls') as string, tlsBad, tlsBad ? 'text-amber-600' : 'text-slate-300', c.tls.length ? t('hostcard.tlsChecked', { n: c.tls.length }) : undefined)}
        {tile(t('hostcard.tile.updates') as string, pending || (upd?.device?.latest && upd.device.latest !== upd.device.version ? 1 : 0), pending ? 'text-amber-600' : 'text-slate-300', (upd?.windows?.reboot_required || upd?.linux?.reboot_required) ? t('hostcard.reboot') : undefined)}
        {tile(t('hostcard.tile.lastBoot') as string, c.last_boot?.boot ? ago(c.last_boot.boot.at) : '—', c.last_boot?.boot ? 'text-slate-800' : 'text-slate-300', c.last_boot?.boot
          ? <span title={`${new Date(c.last_boot.boot.at).toLocaleString()} · ${t('hostcard.lastBoot.asOf', { when: ago(c.last_boot.boot.as_of) })}`}>{t(`hostcard.lastBoot.source.${c.last_boot.boot.source}`)}{c.last_boot.boot.approx ? ` · ${t('hostcard.lastBoot.approx')}` : ''}{c.last_boot.restarts.length > 0 ? ` · ${t('hostcard.lastBoot.noticed', { n: c.last_boot.restarts.length })}` : ''}</span>
          : t('hostcard.lastBoot.unknown'))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title={t('hostcard.sec.ci') as string}>
          <Kv rows={[
            [t('hostcard.f.type') as string, `${t(`hostcard.class.${ci.class}`, { defaultValue: ci.class })}${ci.role && ci.role !== ci.class ? ` · ${ci.role}` : ''}`],
            [t('hostcard.f.vendor') as string, [ci.manufacturer, ci.model].filter(Boolean).join(' ')], [t('hostcard.f.serial') as string, ci.serial],
            [t('hostcard.f.os') as string, [ci.os, ci.os_version].filter(Boolean).join(' ')],
            [t('hostcard.f.support') as string, ci.lifecycle && ci.lifecycle.status !== 'unknown' ? `${ci.lifecycle.product ?? ''} — ${t(`assets.lifecycle.${ci.lifecycle.status}`, { defaultValue: ci.lifecycle.status })}${ci.lifecycle.eol ? ` (${ci.lifecycle.eol})` : ''}` : null],
            [t('hostcard.f.owner') as string, ci.owner], [t('hostcard.f.criticality') as string, ci.criticality], [t('hostcard.f.place') as string, ci.place], [t('hostcard.f.location') as string, ci.location],
            [t('hostcard.f.tags') as string, ci.tags.join(', ')], [t('hostcard.f.firstSeen') as string, ci.first_seen ? new Date(ci.first_seen).toLocaleDateString() : null], [t('hostcard.f.lastSeen') as string, ci.last_seen ? ago(ci.last_seen) : null],
            [t('hostcard.f.scan') as string, ci.scan ? `${ci.scan.level}${ci.scan.last_scan_at ? ` · ${ago(ci.scan.last_scan_at)}` : ''}${ci.scan.status === 'error' ? ' · ' + t('hostcard.scanError') : ''}` : null],
            [t('hostcard.f.notes') as string, ci.notes], [t('hostcard.f.software') as string, c.software_count ? String(c.software_count) : null],
          ]} />
        </Section>

        <Section title={t('hostcard.sec.status') as string}>
          {av ? (
            <div className="space-y-2">
              <p><b className={cn('font-semibold', AVAIL[av.state])}>{t(`hostcard.avail.${av.state}`)}</b> <span className="text-xs text-slate-500">{t('hostcard.since', { when: ago(av.since) })}{av.uptime != null ? ` · ${t('hostcard.uptime30')}: ${av.uptime}%` : ''}</span></p>
              {av.outages.length > 0 && <ul className="text-xs text-slate-600 space-y-0.5">{av.outages.map((o, i) => <li key={i}>{new Date(o.from).toLocaleString()} · {dur(o.seconds)} · {o.kind}{o.cause ? ` (${o.cause})` : ''}</li>)}</ul>}
              {av.affects.length > 0 && <p className="text-xs text-amber-700">{t('hostcard.affects')}: {av.affects.map(a => <HostLink key={a.id} ip={a.ip} name={a.name}>{a.name}</HostLink>).reduce<React.ReactNode[]>((acc, x, i) => (i ? [...acc, ', ', x] : [x]), [])}</p>}
            </div>
          ) : <p className="text-slate-400">{t('hostcard.notMonitored')}</p>}
          {c.access && <div className="mt-3"><Kv rows={[
            [t('hostcard.f.credential') as string, c.access.credential ?? t('hostcard.noCredential')], [t('hostcard.f.online') as string, c.access.online ? t('common.online') : t('common.offline')],
            [t('hostcard.f.mgmt') as string, c.access.mgmt_ok === false ? t('common.mgmtBlocked') : null],
            [t('hostcard.f.channels') as string, Object.entries(c.access.ports).filter(([, v]) => v).map(([k]) => k.toUpperCase()).join(' · ')]]} /></div>}
        </Section>

        <Section title={t('hostcard.sec.alerts') as string} count={c.alerts.open_count} wide={c.alerts.open_count > 3}>
          {c.alerts.open.length === 0 ? <p className="text-green-700">{t('hostcard.noAlerts')}</p> : (
            <ul className="divide-y divide-slate-100 -my-1">
              {c.alerts.open.map(a => (
                <li key={a.id} className="py-1.5 flex items-start gap-2"><SevBadge s={a.severity} /><div className="min-w-0 flex-1"><div className="text-slate-900 truncate">{t(`soc.rule.${a.rule}`, { defaultValue: a.title || a.rule })}</div>
                  <div className="text-xs text-slate-500 truncate">{a.message}</div></div><span className="text-xs text-slate-400 whitespace-nowrap">{ago(a.last_seen)}</span></li>
              ))}
            </ul>
          )}
          <p className="text-xs mt-2"><Link to="/soc" className="text-indigo-600 hover:underline">{t('nav.socAlerts')}</Link></p>
        </Section>

        <Section title={t('hostcard.sec.vulns') as string} count={c.vulnerabilities?.total ?? 0}>
          {!c.vulnerabilities || c.vulnerabilities.total === 0 ? <p className="text-green-700">{t('assets.noVulnsHere')}</p> : (
            <div className="space-y-2">
              <p className="text-xs text-slate-600">{(['critical', 'high', 'medium', 'low'] as const).map(k => `${t(`assets.sev.${k}`)}: ${vc?.[k] ?? 0}`).join(' · ')}{c.vulnerabilities.kev ? ` · KEV: ${c.vulnerabilities.kev}` : ''}{c.vulnerabilities.accepted ? ` · ${t('hostcard.accepted', { n: c.vulnerabilities.accepted })}` : ''}</p>
              <ul className="divide-y divide-slate-100 text-xs">
                {c.vulnerabilities.top.map(v => (
                  <li key={v.cve_id} className="py-1 flex gap-2 items-start"><span className="font-mono text-slate-900 whitespace-nowrap">{v.url ? <a href={v.url} target="_blank" rel="noreferrer" className="text-indigo-600 hover:underline">{v.cve_id}</a> : v.cve_id}</span>
                    <span className="tabular-nums text-slate-500">{v.cvss ?? '—'}</span>{v.kev && <span className="text-[10px] bg-red-600 text-white rounded px-1">KEV</span>}<span className="text-slate-600 truncate">{v.product} {v.version}</span></li>
                ))}
              </ul>
            </div>
          )}
        </Section>

        {c.tls.length > 0 && (
          <Section title={t('hostcard.sec.tls') as string} count={c.tls.length}>
            <ul className="divide-y divide-slate-100 text-xs">{c.tls.map(x => (
              <li key={x.port} className="py-1 flex flex-wrap gap-x-3 gap-y-0.5 items-center"><b className="tabular-nums">{x.port}</b><span className="text-slate-600 truncate">{x.subject ?? (x.error ? t('tls.noTls') : '—')}</span>
                <span className={cn('tabular-nums', x.days != null && x.days < 30 ? 'text-amber-700 font-semibold' : 'text-slate-500')}>{x.days != null ? (x.days < 0 ? t('tls.expiredAgo', { n: Math.max(1, Math.round(-x.days)) }) : t('tls.days', { n: Math.floor(x.days) })) : ''}</span>
                {x.findings.map(f => <span key={f.code} className="border border-amber-200 bg-amber-50 text-amber-800 rounded-full px-1.5">{t(`tls.finding.${f.code}`)}</span>)}</li>
            ))}</ul>
          </Section>
        )}

        {c.services.length > 0 && (
          <Section title={t('hostcard.sec.services') as string} count={c.services.length}>
            <div className="flex flex-wrap gap-1.5 text-xs">{c.services.map(s => <span key={`${s.port}/${s.proto}`} className="border border-slate-200 rounded px-1.5 py-0.5 bg-slate-50" title={[s.product, s.version].filter(Boolean).join(' ')}><b className="tabular-nums">{s.port}</b> {s.service ?? ''}{s.product ? ` · ${s.product}${s.version ? ' ' + s.version : ''}` : ''}</span>)}</div>
          </Section>
        )}

        {upd && (
          <Section title={t('hostcard.sec.updates') as string}>
            <Kv rows={[
              [t('hostcard.f.windowsUpdates') as string, upd.windows ? `${upd.windows.upgradable ?? '?'} ${t('hostcard.pending')}${upd.windows.reboot_required ? ' · ' + t('hostcard.reboot') : ''}${upd.windows.last_check ? ' · ' + ago(upd.windows.last_check) : ''}` : null],
              [t('hostcard.f.linuxUpdates') as string, upd.linux ? `${upd.linux.upgradable ?? '?'} ${t('hostcard.pending')}${upd.linux.reboot_required ? ' · ' + t('hostcard.reboot') : ''}${upd.linux.last_check ? ' · ' + ago(upd.linux.last_check) : ''}` : null],
              [t('hostcard.f.routeros') as string, upd.device ? `${upd.device.version ?? '?'}${upd.device.latest && upd.device.latest !== upd.device.version ? ` → ${upd.device.latest}` : ''}` : null],
              [t('hostcard.f.firmware') as string, upd.device?.firmware ? `${upd.device.firmware}${upd.device.upgrade_firmware && upd.device.upgrade_firmware !== upd.device.firmware ? ` → ${upd.device.upgrade_firmware}` : ''}` : null],
              [t('hostcard.f.titles') as string, upd.windows?.titles?.length ? upd.windows.titles.join('; ') : null]]} />
          </Section>
        )}

        {c.bmc && c.bmc.map(b => (
          <Section key={b.id} title={`${t('bmc.title')}${b.name ? ` — ${b.name}` : ''}`} wide={b.sel.length > 0}>
            <Kv rows={[
              [t('bmc.model') as string, [b.vendor ? b.vendor.toUpperCase() : null, b.model].filter(Boolean).join(' ')], [t('bmc.tag') as string, b.service_tag], [t('bmc.bios') as string, b.bios],
              [t('bmc.power') as string, b.power], [t('bmc.access') as string, b.access],
              [t('bmc.lastCheck') as string, b.last_check ? `${ago(b.last_check)}${b.status === 'error' ? ' · ' + t('bmc.checkError') : ''}` : null],
              ['BMC', b.bmc_ref ? <HostLink ip={b.bmc_ref}>{b.idrac_ip}</HostLink> : b.idrac_ip]]} />
            {b.status === 'error' && b.error && <p className="text-xs text-amber-800 mt-1 break-words">{b.error}</p>}
            <div className="flex flex-wrap gap-1.5 mt-3 text-xs">
              <span className={cn('border rounded-full px-2 py-0.5 font-medium', b.health === 'Critical' ? 'bg-red-50 text-red-700 border-red-200' : b.health === 'Warning' ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-green-50 text-green-700 border-green-200')}>{t('bmc.health')}: {b.health ? t(`bmc.value.${b.health}`) : '—'}</span>
              {Object.entries(b.components).map(([k, v]) => <span key={k} className={cn('border rounded px-1.5 py-0.5', v === 'Critical' ? 'border-red-200 text-red-700 bg-red-50' : v === 'Warning' ? 'border-amber-200 text-amber-800 bg-amber-50' : 'border-slate-200 text-slate-600')}>{t(`bmc.comp.${k}`, { defaultValue: k })}{v && v !== 'OK' ? `: ${t(`bmc.value.${v}`)}` : ''}</span>)}
            </div>
            {b.sel.length > 0 && <div className="mt-3"><div className="text-xs font-semibold text-slate-500 mb-1">{t('bmc.sel')}</div><ul className="text-xs space-y-0.5">{b.sel.map((e, i) => <li key={i} className={cn('truncate', e.severity === 'Critical' && 'text-red-700')}><span className="text-slate-400">{ago(e.at)}</span> {e.message}</li>)}</ul></div>}
            <p className="text-xs mt-2"><Link to="/dell-servers" className="text-indigo-600 hover:underline">{t('nav.dellServers')}</Link></p>
          </Section>
        ))}

        {c.resources && (
          <Section title={t('hostcard.sec.resources') as string}>
            {c.resources.now && <p className="text-xs text-slate-700 mb-2">{[['CPU', c.resources.now.cpu], ['RAM', c.resources.now.mem], ['Disk', c.resources.now.disk]].filter(([, v]) => v != null).map(([k, v]) => `${k} ${v}%`).join(' · ')}{c.resources.now.temp != null ? ` · ${c.resources.now.temp}°C` : ''} <span className="text-slate-400">{ago(c.resources.now.at)}</span></p>}
            {c.resources.series.length > 0 && <ul className="text-xs text-slate-600 space-y-0.5">{c.resources.series.map(s => <li key={s.key}>{s.name}: <b className="tabular-nums">{s.value ?? '—'}{s.unit ?? ''}</b></li>)}</ul>}
            <p className="text-xs mt-2"><Link to="/metrics" className="text-indigo-600 hover:underline">{t('metrics.title')}</Link></p>
          </Section>
        )}

        {c.config && (
          <Section title={t('hostcard.sec.config') as string} count={c.config.versions}>
            <p className="text-xs text-slate-600 mb-1">{c.config.last_change ? t('hostcard.lastChange', { when: ago(c.config.last_change) }) : t('hostcard.noChange')}{c.config.error ? ` · ${c.config.error}` : ''}</p>
            <ul className="text-xs text-slate-600 space-y-0.5">{c.config.recent.map(r => <li key={r.id}>{new Date(r.at).toLocaleString()} · +{r.added ?? 0} / −{r.removed ?? 0}{r.sections.length ? ` · ${r.sections.join(', ')}` : ''}</li>)}</ul>
            <p className="text-xs mt-2"><Link to="/config-history" className="text-indigo-600 hover:underline">{t('nav.cfg')}</Link></p>
          </Section>
        )}

        {c.syslog && (
          <Section title={t('hostcard.sec.syslog') as string} count={t('hostcard.in24h', { n: c.syslog.count_24h }) as string}>
            <ul className="text-xs space-y-0.5">{c.syslog.recent.map((e, i) => <li key={i} className="truncate"><span className="text-slate-400">{ago(e.at)}</span> <span className="text-slate-500">{e.app ?? e.kind}</span> {e.message}</li>)}</ul>
          </Section>
        )}

        <Section title={t('hostcard.sec.relations') as string}>
          <div className="space-y-2 text-xs">
            <div><span className="text-slate-500">{t('hostcard.dependsOn')}: </span>{rel.depends_on?.length ? rel.depends_on.map((d, i) => <span key={i}><HostLink ip={d.ip} name={d.name}>{d.name ?? d.ip}</HostLink>{d.via ? ` (${d.via})` : ''} </span>) : <span className="text-slate-400">—</span>}</div>
            <div><span className="text-slate-500">{t('hostcard.supports')}: </span>{rel.supports?.length ? rel.supports.slice(0, 25).map(s => <span key={s.id} className="mr-1.5"><HostLink name={s.name}>{s.name}</HostLink>{s.via ? <span className="text-slate-400"> ({s.via})</span> : null}</span>) : <span className="text-slate-400">—</span>}{rel.supports?.length > 25 ? <span className="text-slate-400"> +{rel.supports.length - 25}</span> : null}</div>
            <div><span className="text-slate-500">{t('hostcard.bizServices')}: </span>{rel.business_services?.length ? rel.business_services.map(b => <Link key={b.id} to="/services" className="text-indigo-600 hover:underline mr-1.5">{b.name}</Link>) : <span className="text-slate-400">—</span>}</div>
            {rel.hosted_on?.name && <div><span className="text-slate-500">{t('hostcard.hostedOn')}: </span>{rel.hosted_on.name}</div>}
            {rel.hosts?.length > 0 && <div><span className="text-slate-500">{t('hostcard.vms')}: </span>{rel.hosts.map(h => h.name).join(', ')}</div>}
            {rel.peripherals?.length > 0 && <div><span className="text-slate-500">{t('hostcard.peripherals')}: </span>{rel.peripherals.map(p => p.name ?? p.kind).join(', ')}</div>}
          </div>
        </Section>

        {c.response.length > 0 && (
          <Section title={t('hostcard.sec.response') as string}>
            <ul className="text-xs space-y-0.5">{c.response.map(r => <li key={r.id}>{t(`soar.status.${r.status}`, { defaultValue: r.status })} · {r.kind} · {r.reason}{r.until ? ` · ${t('soar.until', { when: new Date(r.until).toLocaleString() })}` : ''}</li>)}</ul>
            <p className="text-xs mt-2"><Link to="/soc/response" className="text-indigo-600 hover:underline">{t('nav.soar')}</Link></p>
          </Section>
        )}

        <Section title={t('hostcard.sec.sources') as string}>
          <div className="flex flex-wrap gap-1.5 text-xs">{c.sources.map(s => <Link key={`${s.kind}${s.id}`} to={s.path} className="border border-slate-200 rounded px-2 py-0.5 bg-slate-50 text-indigo-700 hover:bg-indigo-50">{t(`hostcard.source.${s.kind}`, { defaultValue: s.kind })}</Link>)}</div>
          <p className="text-[11px] text-slate-400 mt-2">{t('hostcard.sourcesNote')}</p>
        </Section>

        <Section title={t('hostcard.sec.timeline') as string} count={c.timeline.length} wide>
          {c.timeline.length === 0 ? <p className="text-slate-400">—</p> : (
            <ul className="divide-y divide-slate-100 text-xs max-h-96 overflow-y-auto -my-1">
              {c.timeline.map((e, i) => (
                <li key={i} className="py-1 flex gap-3 items-start"><span className="w-36 shrink-0 text-slate-400" title={new Date(e.at).toLocaleString()}>{ago(e.at)}</span><span className="w-28 shrink-0 text-slate-500">{e.kind === 'bmc' ? t('bmc.tl') : t(`hostcard.tl.${e.kind}`, { defaultValue: e.kind })}</span>
                  <span className={cn('min-w-0 break-words', e.severity === 'high' || e.severity === 'critical' ? 'text-red-700' : 'text-slate-800')}>{e.kind.startsWith('alert') ? t(`soc.rule.${e.text}`, { defaultValue: e.text }) : e.text}</span></li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </div>
  )
}

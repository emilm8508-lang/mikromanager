// Data layer of the Security Summary dashboard. The agent's own page and Central's page show the same widgets:
// both feed `buildSec` the same shape — one part per client, holding the sections of that client's snapshot
// (the agent's page has a single part, "local"; Central has one per client and can filter).
//
// Everything here is plain data in / plain numbers out, so the page code only draws.

export type Sev = 'critical' | 'high' | 'medium' | 'low'
export const SEVS: Sev[] = ['critical', 'high', 'medium', 'low']

export interface SecPart {
  tenant: string
  lastSeen: string | null
  data: Record<string, any>
}

export interface SecEventPoint { t: string; n: number }

export interface SecInfraRow {
  key: string                  // i18n key suffix
  total: number
  bad: number                  // how many of `total` are in a problem state
  warn?: number
}

export interface SecNode { name: string; ts: string | null; group: string }

export interface SecData {
  clients: number
  partialClients: number       // clients whose agent predates the dashboard (no security_stats)
  vuln: {
    hostsTotal: number
    hostsVulnerable: number
    hostsBySev: Record<Sev, number>
    findingsBySev: Record<Sev, number>
    byClass: Array<{ key: string; n: number }>
    topCves: Array<{ cve: string; sev: Sev; cvss: number | null; hosts: number }>
    accepted: number
    risk: number | null
    partial: boolean           // an older agent: only critical / high findings are known
  }
  compliance: {
    passed: number
    failed: number
    unknown: number
    failedBySev: Record<'high' | 'medium' | 'low', number>
    byPlatform: Array<{ key: string; passed: number; failed: number }>
    score: number | null
    partial: boolean
  }
  events: {
    hourly: SecEventPoint[]
    daily: SecEventPoint[]
    byType24h: Array<{ key: string; n: number }>
    byType7d: Array<{ key: string; n: number }>
    topDevices: Array<{ name: string; n: number }>
    total24h: number
    total7d: number
    available: boolean
  }
  patch: {
    hosts: number                // managed Linux + Windows servers
    current: number
    needUpdates: number
    unknown: number
    packages: number
    reboot: number
    rebootNames: string[]
    rosOutdated: number
    firmwareOutdated: number
    rosDevices: number
  }
  wazuh: { total: number; byBand: { critical: number; important: number; info: number }; topRules: Array<{ name: string; n: number }> }
  firewall: {
    devices: number
    logs: number
    topSources: Array<{ ip: string; n: number }>
    topPorts: Array<{ port: string; n: number }>
    rulesUnused: number
  }
  infra: SecInfraRow[]
  nodes: SecNode[]
}

const num = (x: unknown): number => (typeof x === 'number' && isFinite(x) ? x : 0)
const arr = (x: unknown): any[] => (Array.isArray(x) ? x : [])
// PHP renders an empty map as [] — Object.entries([]) is fine, but a typed read needs this
const obj = (x: unknown): Record<string, any> => (x && typeof x === 'object' && !Array.isArray(x) ? (x as Record<string, any>) : {})
const sevOf = (s: unknown): Sev => {
  const v = String(s ?? '').toLowerCase()
  return v === 'critical' || v === 'high' || v === 'medium' ? (v as Sev) : 'low'
}
const WEIGHT: Record<Sev, number> = { critical: 5, high: 3, medium: 1, low: 0.5 }

function addMap(into: Map<string, number>, m: Record<string, any>) {
  for (const [k, v] of Object.entries(m)) into.set(k, (into.get(k) ?? 0) + num(v))
}
const sortedMap = (m: Map<string, number>) => [...m.entries()].map(([key, n]) => ({ key, n })).sort((a, b) => b.n - a.n)

export function buildSec(parts: SecPart[]): SecData {
  const multi = parts.length > 1

  // ── vulnerabilities ──
  const hostsBySev: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  const findingsBySev: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  const byClass = new Map<string, number>()
  const cves = new Map<string, { cve: string; sev: Sev; cvss: number | null; hosts: number }>()
  let hostsTotal = 0, hostsVulnerable = 0, accepted = 0, riskWeighted = 0, riskHosts = 0, vulnPartial = false
  for (const p of parts) {
    const v = p.data.security_stats?.vuln
    if (v) {
      const hs = obj(v.hosts_by_severity), fs = obj(v.findings_by_severity)
      for (const s of SEVS) { hostsBySev[s] += num(hs[s.toUpperCase()]); findingsBySev[s] += num(fs[s.toUpperCase()]) }
      addMap(byClass, obj(v.findings_by_class))
      for (const c of arr(v.top_cves)) {
        const cur = cves.get(c.cve_id) ?? { cve: c.cve_id, sev: sevOf(c.severity), cvss: c.cvss ?? null, hosts: 0 }
        cur.hosts += num(c.hosts); cves.set(c.cve_id, cur)
      }
      hostsTotal += num(v.hosts_total); hostsVulnerable += num(v.hosts_vulnerable); accepted += num(v.accepted)
      riskWeighted += num(v.risk_score) * Math.max(1, num(v.hosts_total)); riskHosts += Math.max(1, num(v.hosts_total))
    } else if (p.data.vuln_findings_status !== undefined) {
      // an agent from before the dashboard: only the critical / high cut is known, and no host total
      vulnPartial = true
      for (const h of arr(p.data.vuln_findings_status)) {
        const open = arr(h.findings).filter((f: any) => (f.status ?? 'open') === 'open' || f.status === 'in_progress')
        if (!open.length) continue
        hostsVulnerable++
        const worst = open.map((f: any) => sevOf(f.severity)).sort((a: Sev, b: Sev) => WEIGHT[b] - WEIGHT[a])[0]
        hostsBySev[worst]++
        for (const f of open) {
          const s = sevOf(f.severity)
          findingsBySev[s]++
          const cur = cves.get(f.cve_id) ?? { cve: f.cve_id, sev: s, cvss: f.cvss_score ?? null, hosts: 0 }
          cur.hosts++; cves.set(f.cve_id, cur)
        }
      }
    }
  }
  const vuln: SecData['vuln'] = {
    hostsTotal: hostsTotal || hostsVulnerable, hostsVulnerable, hostsBySev, findingsBySev, byClass: sortedMap(byClass),
    topCves: [...cves.values()].sort((a, b) => WEIGHT[b.sev] - WEIGHT[a.sev] || (b.cvss ?? 0) - (a.cvss ?? 0) || b.hosts - a.hosts).slice(0, 10),
    accepted, risk: riskHosts ? Math.round((riskWeighted / riskHosts) * 10) / 10 : null, partial: vulnPartial && !riskHosts,
  }

  // ── compliance ──
  let passed = 0, failed = 0, unknown = 0, compPartial = false
  const hasFullCompliance = parts.some(p => p.data.security_stats?.compliance)
  const failedBySev = { high: 0, medium: 0, low: 0 }
  const platforms = new Map<string, { passed: number; failed: number }>()
  for (const p of parts) {
    const c = p.data.security_stats?.compliance
    if (c) {
      passed += num(c.passed); failed += num(c.failed); unknown += num(c.unknown)
      const fb = obj(c.failed_by_severity)
      for (const k of ['high', 'medium', 'low'] as const) failedBySev[k] += num(fb[k])
      for (const [k, v] of Object.entries(obj(c.by_platform))) {
        const cur = platforms.get(k) ?? { passed: 0, failed: 0 }
        cur.passed += num(v.passed); cur.failed += num(v.failed); platforms.set(k, cur)
      }
    } else if (Array.isArray(p.data.compliance_status)) {
      compPartial = true
      for (const f of p.data.compliance_status) {
        failed++
        const k = (String(f.severity ?? 'low').toLowerCase() as 'high' | 'medium' | 'low')
        failedBySev[k in failedBySev ? k : 'low']++
        const cur = platforms.get(f.target_type) ?? { passed: 0, failed: 0 }
        cur.failed++; platforms.set(f.target_type, cur)
      }
    }
  }
  const compliance: SecData['compliance'] = {
    passed, failed, unknown, failedBySev, byPlatform: [...platforms.entries()].map(([key, v]) => ({ key, ...v })).sort((a, b) => b.failed - a.failed),
    score: passed + failed > 0 ? Math.round((passed / (passed + failed)) * 1000) / 10 : null, partial: compPartial && !hasFullCompliance,
  }

  // ── events over time ──
  const hourly = new Map<string, number>(), daily = new Map<string, number>()
  const t24 = new Map<string, number>(), t7 = new Map<string, number>(), devices = new Map<string, number>()
  let eventsAvailable = false
  for (const p of parts) {
    const e = p.data.security_stats?.events
    if (!e) continue
    eventsAvailable = true
    for (const h of arr(e.hourly)) hourly.set(h.t, (hourly.get(h.t) ?? 0) + num(h.n))
    for (const d of arr(e.daily)) daily.set(d.t, (daily.get(d.t) ?? 0) + num(d.n))
    addMap(t24, obj(e.by_type_24h)); addMap(t7, obj(e.by_type_7d))
    for (const d of arr(e.top_devices)) {
      const k = multi ? `${p.tenant} / ${d.name}` : d.name
      devices.set(k, (devices.get(k) ?? 0) + num(d.n))
    }
  }
  const series = (m: Map<string, number>): SecEventPoint[] => [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([t, n]) => ({ t, n }))
  const events: SecData['events'] = {
    hourly: series(hourly), daily: series(daily), byType24h: sortedMap(t24), byType7d: sortedMap(t7),
    topDevices: [...devices.entries()].map(([name, n]) => ({ name, n })).sort((a, b) => b.n - a.n).slice(0, 8),
    total24h: [...t24.values()].reduce((a, b) => a + b, 0), total7d: [...t7.values()].reduce((a, b) => a + b, 0), available: eventsAvailable,
  }

  // ── patch status ──
  const patch: SecData['patch'] = { hosts: 0, current: 0, needUpdates: 0, unknown: 0, packages: 0, reboot: 0, rebootNames: [], rosOutdated: 0, firmwareOutdated: 0, rosDevices: 0 }
  for (const p of parts) {
    for (const h of [...arr(p.data.linux_hosts_status), ...arr(p.data.windows_hosts_status)]) {
      patch.hosts++
      const n = h.upgradable_count
      if (n == null) patch.unknown++
      else if (n > 0) { patch.needUpdates++; patch.packages += n } else patch.current++
      if (h.reboot_required) { patch.reboot++; patch.rebootNames.push(multi ? `${p.tenant} / ${h.hostname || h.ip}` : h.hostname || h.ip) }
    }
    const fw = p.data.firmware_status
    if (fw) { patch.rosOutdated += num(fw.outdated_count); patch.firmwareOutdated += num(fw.firmware_outdated_count) }
    patch.rosDevices += num(p.data.mikrotik_fleet?.totals?.paired)
  }

  // ── Wazuh ──
  const wz = { total: 0, byBand: { critical: 0, important: 0, info: 0 }, rules: new Map<string, number>() }
  for (const p of parts) {
    for (const a of arr(p.data.wazuh_status)) {
      wz.total++
      const l = num(a.rule_level)
      wz.byBand[l >= 12 ? 'critical' : l >= 8 ? 'important' : 'info']++
      const r = String(a.rule_description ?? '—').slice(0, 60)
      wz.rules.set(r, (wz.rules.get(r) ?? 0) + 1)
    }
  }

  // ── firewall ──
  const fwSrc = new Map<string, number>(), fwPorts = new Map<string, number>()
  let fwDevices = 0, fwLogs = 0, unused = 0
  for (const p of parts) {
    for (const d of arr(p.data.firewall_status)) {
      fwDevices++; fwLogs += num(d.log_count); unused += num(d.rules_unused)
      for (const s of arr(d.log_top_sources)) fwSrc.set(s.ip, (fwSrc.get(s.ip) ?? 0) + num(s.count))
      for (const l of arr(d.log_recent)) if (l.dst_port) fwPorts.set(String(l.dst_port), (fwPorts.get(String(l.dst_port)) ?? 0) + 1)
    }
  }

  // ── other sources: one row each ──
  const infra: SecInfraRow[] = []
  const row = (key: string, total: number, bad: number, warn = 0) => { if (total > 0) infra.push({ key, total, bad, warn }) }
  let tun = 0, tunBad = 0, wan = 0, wanBad = 0, hvHosts = 0, hvDown = 0, vms = 0, vmsBad = 0, dell = 0, dellBad = 0, dellWarn = 0
  let prtgBad = 0, cmkBad = 0, hmTotal = 0, hmDown = 0, devTotal = 0, devOff = 0, scTotal = 0, scBad = 0
  for (const p of parts) {
    for (const t of arr(p.data.tunnel_status)) { tun++; if (t.status !== 'up') tunBad++ }
    for (const w of arr(p.data.wan_link_status)) { wan++; if (w.status !== 'up') wanBad++ }
    for (const h of arr(p.data.hyperv_status)) {
      hvHosts++; if (h.status === 'error') hvDown++
      for (const v of arr(h.vms)) { vms++; if (v.tile === 'crit') vmsBad++ }
      if (!arr(h.vms).length) { vms += num(h.vm_count_total); vmsBad += arr(h.vms_not_running).length }
    }
    for (const d of arr(p.data.dell_servers_status)) { dell++; if (d.health_rollup === 'Critical') dellBad++; else if (d.health_rollup === 'Warning') dellWarn++ }
    prtgBad += arr(p.data.prtg_status).length
    cmkBad += arr(obj(p.data.checkmk_status).services).length + arr(obj(p.data.checkmk_status).hosts).length
    for (const h of arr(p.data.hostmon_status)) { hmTotal++; if (h.state === 'down') hmDown++ }
    devTotal += num(p.data.devices_count); devOff += Math.max(0, num(p.data.devices_count) - num(p.data.devices_online))
    const sc = p.data.supply_chain_status
    if (sc) for (const k of ['pip', 'npm', 'bandit', 'eslint', 'php']) { const t = sc[k]; if (t && t.ok !== null) { scTotal++; if (num(t.count) > 0 || t.ok === false) scBad++ } }
  }
  row('devices', devTotal, devOff); row('tunnels', tun, tunBad); row('wan', wan, wanBad); row('hypervHosts', hvHosts, hvDown)
  row('hypervVms', vms, vmsBad); row('dell', dell, dellBad, dellWarn); row('hostmon', hmTotal, hmDown); row('supplyChain', scTotal, scBad)
  if (prtgBad) infra.push({ key: 'prtg', total: prtgBad, bad: prtgBad })
  if (cmkBad) infra.push({ key: 'checkmk', total: cmkBad, bad: cmkBad })

  // ── node health: Central lists the clients (last contact); the agent lists what it watches ──
  const nodes: SecNode[] = multi || parts[0]?.tenant !== 'local'
    ? parts.map(p => ({ name: p.tenant, ts: p.lastSeen ? `${p.lastSeen.replace(' ', 'T')}Z` : null, group: 'client' }))
    : [
      ...arr(parts[0]?.data.linux_hosts_status).map((h: any) => ({ name: h.hostname || h.ip, ts: h.last_check_at ? `${h.last_check_at}Z` : null, group: 'linux' })),
      ...arr(parts[0]?.data.windows_hosts_status).map((h: any) => ({ name: h.hostname || h.ip, ts: h.last_check_at ? `${h.last_check_at}Z` : null, group: 'windows' })),
      ...arr(parts[0]?.data.hyperv_status).map((h: any) => ({ name: h.hostname || h.ip, ts: h.last_check_at ? `${h.last_check_at}Z` : null, group: 'hyperv' })),
      ...arr(parts[0]?.data.routers_status).map((r: any) => ({ name: r.name || '—', ts: r.last_check_at ? `${r.last_check_at}` : null, group: 'router' })),
    ]

  return {
    clients: parts.length, partialClients: parts.filter(p => !p.data.security_stats).length, vuln, compliance, events, patch,
    wazuh: { total: wz.total, byBand: wz.byBand, topRules: sortedMap(wz.rules).map(r => ({ name: r.key, n: r.n })).slice(0, 6) },
    firewall: {
      devices: fwDevices, logs: fwLogs, rulesUnused: unused,
      topSources: sortedMap(fwSrc).map(r => ({ ip: r.key, n: r.n })).slice(0, 6),
      topPorts: sortedMap(fwPorts).map(r => ({ port: r.key, n: r.n })).slice(0, 8),
    },
    infra, nodes,
  }
}

/** The classes an alert event type belongs to — the dashboard colours and groups the event tally by them. */
export function eventCategory(type: string): 'security' | 'availability' | 'maintenance' | 'resource' {
  if (/^(failed_logins|wazuh|device_log_critical|vuln|checkmk_service|prtg|hyperv_vm_no_heartbeat|hyperv_replication)/.test(type)) return 'security'
  if (/(_down|_offline|unreachable|rebooted)/.test(type)) return 'availability'
  if (/(firmware|snapshot|update|upgrade)/.test(type)) return 'maintenance'
  return 'resource'
}

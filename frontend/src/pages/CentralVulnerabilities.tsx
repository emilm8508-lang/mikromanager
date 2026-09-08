import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type CentralVulnFinding } from '../lib/api'
import { ShieldAlert, FileDown } from 'lucide-react'

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1 }
const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-amber-500 text-white',
}
const STATUSES = ['open', 'in_progress', 'accepted_risk', 'resolved']
const STATUS_BADGE: Record<string, string> = {
  open: 'bg-red-100 text-red-700',
  in_progress: 'bg-amber-100 text-amber-700',
  accepted_risk: 'bg-blue-100 text-blue-700',
  resolved: 'bg-green-100 text-green-700',
}

type DeviceGroup = {
  tenant: string
  ip: string
  deviceName: string | null
  findings: CentralVulnFinding[]
}

// Same OWASP CSV-formula-injection mitigation used elsewhere in this app
// (AnydeskSessions.tsx's csvSafe) — plus proper quoting/escaping, which
// that helper doesn't do, needed here since CVE summaries are free-text
// prose that routinely contains commas and quotes. A UTF-8 BOM is added
// so Excel (not just any CSV reader) renders Polish diacritics correctly
// instead of mojibake.
function csvSafe(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value)
  const escaped = s && ['=', '+', '-', '@', '\t', '\r'].includes(s[0]) ? "'" + s : s
  return `"${escaped.replace(/"/g, '""')}"`
}

function downloadCsv(filename: string, header: string[], rows: unknown[][]) {
  const lines = [header.map(csvSafe).join(','), ...rows.map(r => r.map(csvSafe).join(','))]
  const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

type RemediationSubmit = (tenant: string, finding: CentralVulnFinding, status: string, note: string) => void

function FindingRow({ tenant, finding, pending, onSubmit }: {
  tenant: string; finding: CentralVulnFinding; pending: boolean; onSubmit: RemediationSubmit
}) {
  const { t } = useTranslation()
  const [note, setNote] = useState(finding.note ?? '')

  return (
    <div className="py-2 border-t border-slate-100 first:border-t-0 first:pt-0">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <p className="text-sm font-medium text-slate-900">
          {finding.ref_url ? (
            <a href={finding.ref_url} target="_blank" rel="noopener noreferrer" className="text-indigo-700 hover:underline">
              {finding.cve_id}
            </a>
          ) : finding.cve_id}
          {finding.cvss_score != null && <span className="ml-2 text-xs font-normal text-slate-500">CVSS {finding.cvss_score}</span>}
        </p>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded uppercase ${SEVERITY_BADGE[finding.severity] ?? 'bg-slate-400 text-white'}`}>
          {finding.severity}
        </span>
      </div>
      {finding.summary && <p className="text-sm text-slate-600 mt-1 leading-relaxed">{finding.summary}</p>}
      <div className="flex items-center gap-2 flex-wrap mt-2">
        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded uppercase ${STATUS_BADGE[finding.status] ?? 'bg-slate-200 text-slate-700'}`}>
          {t(`vuln.status.${finding.status}`)}
        </span>
        {pending ? (
          <span className="text-xs text-slate-500">{t('centralVuln.queued')}</span>
        ) : (
          <>
            <select
              value={finding.status}
              onChange={e => onSubmit(tenant, finding, e.target.value, note)}
              className="text-xs border border-slate-300 rounded px-1.5 py-1"
            >
              {STATUSES.map(s => <option key={s} value={s}>{t(`vuln.status.${s}`)}</option>)}
            </select>
            <input
              value={note}
              onChange={e => setNote(e.target.value)}
              onBlur={() => { if (note !== (finding.note ?? '')) onSubmit(tenant, finding, finding.status, note) }}
              placeholder={t('vuln.notePlaceholder') as string}
              className="flex-1 min-w-[10rem] text-xs border border-slate-300 rounded px-2 py-1"
            />
          </>
        )}
      </div>
    </div>
  )
}

function DeviceCard({ group, pendingSet, onSubmit }: {
  group: DeviceGroup; pendingSet: Set<string>; onSubmit: RemediationSubmit
}) {
  const worst = group.findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH'
  const borderClass = worst === 'CRITICAL' ? 'border-red-400' : 'border-amber-400'
  return (
    <div className={`border-l-4 ${borderClass} bg-white border border-slate-200 rounded-lg p-4`}>
      <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700">{group.tenant}</span>
          <span className="font-mono text-sm text-slate-800">{group.deviceName || group.ip}</span>
          {group.deviceName && <span className="font-mono text-xs text-slate-400">{group.ip}</span>}
        </div>
        <span className="text-xs text-slate-500">{group.findings.length}</span>
      </div>
      <div>
        {group.findings.map((f, i) => (
          <FindingRow key={`${f.cve_id}:${i}`} tenant={group.tenant} finding={f}
            pending={pendingSet.has(`${group.tenant}:${f.product}:${f.version}:${f.cve_id}`)}
            onSubmit={onSubmit} />
        ))}
      </div>
    </div>
  )
}

export function CentralVulnerabilities() {
  const { t } = useTranslation()
  const cfg = centralConfig.load()
  const [groups, setGroups] = useState<DeviceGroup[]>([])
  const [pendingSet, setPendingSet] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [tenantFilter, setTenantFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const reload = async () => {
    try {
      const [s, p] = await Promise.all([centralApi.vulnFindingsStatusAll(), centralApi.pendingVulnRemediations()])
      const flat: DeviceGroup[] = []
      for (const tRow of s.tenants) {
        for (const host of tRow.hosts) {
          if (host.findings.length === 0) continue
          flat.push({ tenant: tRow.tenant, ip: host.ip, deviceName: host.device_name, findings: host.findings })
        }
      }
      flat.sort((a, b) => {
        const aWorst = Math.min(...a.findings.map(f => SEVERITY_ORDER[f.severity] ?? 9))
        const bWorst = Math.min(...b.findings.map(f => SEVERITY_ORDER[f.severity] ?? 9))
        return aWorst - bWorst
      })
      setGroups(flat)
      setPendingSet(new Set(p.pending.map(x => `${x.tenant}:${x.product}:${x.version}:${x.cve_id}`)))
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  const submitRemediation: RemediationSubmit = async (tenant, finding, status, note) => {
    try {
      await centralApi.requestVulnRemediation(tenant, finding.product, finding.version, finding.cve_id, status, note)
      await reload()
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  useEffect(() => {
    if (!cfg) { setLoading(false); return }
    reload()
    const iv = setInterval(reload, 60000)
    return () => clearInterval(iv)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!cfg) {
    return (
      <div className="p-6 max-w-5xl">
        <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">
          {t('alerts.needsCentral')}
        </div>
      </div>
    )
  }

  const tenants = [...new Set(groups.map(g => g.tenant))].sort()

  // Severity filter narrows the findings WITHIN each device (not just
  // which devices show) — a device with e.g. one CRITICAL and one HIGH
  // finding should still appear, showing only the CRITICAL one, when the
  // filter is set to CRITICAL.
  const visible = groups
    .filter(g => tenantFilter === 'all' || g.tenant === tenantFilter)
    .map(g => ({
      ...g,
      findings: severityFilter === 'all' ? g.findings : g.findings.filter(f => f.severity === severityFilter),
    }))
    .filter(g => g.findings.length > 0)

  const counts = { CRITICAL: 0, HIGH: 0 } as Record<string, number>
  for (const g of groups) for (const f of g.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1

  const exportCsv = () => {
    const rows = visible.flatMap(g =>
      g.findings.map(f => [g.tenant, g.deviceName || '', g.ip, f.cve_id, f.severity, f.cvss_score ?? '', f.summary ?? '', f.ref_url ?? ''])
    )
    downloadCsv(
      `podatnosci_${new Date().toISOString().slice(0, 10)}.csv`,
      ['Tenant', 'Urzadzenie', 'IP', 'CVE', 'Waga', 'CVSS', 'Opis', 'Link'],
      rows,
    )
  }

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert size={20} className="text-indigo-600" />
          <h1 className="text-lg font-semibold text-slate-900">{t('centralVuln.title')}</h1>
        </div>
        {!loading && visible.length > 0 && (
          <button onClick={exportCsv}
            className="text-xs px-2.5 py-1.5 rounded bg-indigo-600 text-white hover:bg-indigo-700 flex items-center gap-1.5">
            <FileDown size={13} /> {t('centralVuln.exportCsv')}
          </button>
        )}
      </div>
      <p className="text-sm text-slate-500">{t('centralVuln.intro')}</p>

      {err && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">{err}</div>}

      {!loading && groups.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs px-2.5 py-1 rounded bg-red-100 text-red-700 font-medium">{t('centralVuln.countCritical', { count: counts.CRITICAL ?? 0 })}</span>
          <span className="text-xs px-2.5 py-1 rounded bg-amber-100 text-amber-700 font-medium">{t('centralVuln.countHigh', { count: counts.HIGH ?? 0 })}</span>

          <select value={tenantFilter} onChange={e => setTenantFilter(e.target.value)}
            className="ml-auto text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('alerts.allTenants')}</option>
            {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
          </select>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
            className="text-xs border border-slate-300 rounded px-2 py-1">
            <option value="all">{t('complianceCentral.allSeverities')}</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
          </select>
          <button onClick={reload} className="text-xs text-indigo-600 hover:underline shrink-0">{t('common.refresh')}</button>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-slate-500">{t('common.loading')}</p>
      ) : groups.length === 0 ? (
        <p className="text-sm text-slate-500">{t('centralVuln.empty')}</p>
      ) : visible.length === 0 ? (
        <p className="text-sm text-slate-500">{t('complianceCentral.noneMatchFilter')}</p>
      ) : (
        <div className="space-y-3">
          {visible.map((g, i) => (
            <DeviceCard key={`${g.tenant}:${g.ip}:${i}`} group={g} pendingSet={pendingSet} onSubmit={submitRemediation} />
          ))}
        </div>
      )}
    </div>
  )
}

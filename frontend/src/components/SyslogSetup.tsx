import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ClipboardCopy, Radio } from 'lucide-react'
import { syslogApi } from '../lib/api'
import { cn } from '../lib/utils'

type Target = 'ros' | 'cisco' | 'swos' | 'firewall'
const TARGETS: Target[] = ['ros', 'cisco', 'swos', 'firewall']

/** What to paste on a device so that it sends its log to the agent's syslog receiver (and, for the agent's own computer, the firewall rule that lets it in). Templates. */
export function syslogSnippet(target: Target, agentIp: string, port: number): string {
  const ip = agentIp || '<ADRES-AGENTA>'
  if (target === 'ros') {
    return [
      `/system logging action add name=mikromanager target=remote remote=${ip} remote-port=${port}`,
      `/system logging add topics=critical action=mikromanager`,
      `/system logging add topics=error action=mikromanager`,
      `/system logging add topics=warning action=mikromanager`,
      `# logins and failed logins`,
      `/system logging add topics=account action=mikromanager`,
      `# configuration changes, restarts`,
      `/system logging add topics=system,info action=mikromanager`,
      `# links up / down`,
      `/system logging add topics=interface,info action=mikromanager`,
    ].join('\n')
  }
  if (target === 'cisco') {
    return [`logging on`, `logging host ${ip} port ${port} severity informational`].join('\n')
  }
  if (target === 'swos') {
    return `SwOS Lite has no syslog setting (it is configured only from its web page and offers SNMP).\nUse the SNMP tab of the switch and the accounts panel above; availability, ports and traffic come from SNMP.`
  }
  return [
    `# on the computer of the agent (PowerShell as administrator): let the devices' syslog in`,
    `New-NetFirewallRule -DisplayName "MikroManager syslog" -Direction Inbound -Protocol UDP -LocalPort ${port} -Action Allow -RemoteAddress <ADRESY-URZADZEN>`,
  ].join('\n')
}

export function SyslogSetup({ agentIp }: { agentIp: string | null }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const st = useQuery({ queryKey: ['syslog-status'], queryFn: syslogApi.status, refetchInterval: 20000 })
  const enable = useMutation({ mutationFn: () => syslogApi.save({ enabled: true }), onSuccess: () => void qc.invalidateQueries({ queryKey: ['syslog-status'] }) })
  const [target, setTarget] = useState<Target>('ros')
  const [ip, setIp] = useState(agentIp ?? '')
  const [copied, setCopied] = useState(false)
  const d = st.data
  const port = d?.settings.syslog_port ?? 514
  const text = syslogSnippet(target, ip, port)
  const copy = async () => { try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* selectable anyway */ } }
  const tab = (active: boolean) => cn('px-3 py-1.5 text-xs rounded-md border', active ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50')
  return (
    <section className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <div>
        <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2"><Radio size={16} className="text-indigo-600" /> {t('onboarding.syslog.title')}</h2>
        <p className="text-xs text-slate-500 mt-0.5">{t('onboarding.syslog.intro')}</p>
      </div>
      {d && (
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <span className={cn('border rounded-full px-2.5 py-0.5', d.settings.enabled && d.listening.syslog ? 'bg-green-50 text-green-700 border-green-200' : 'bg-amber-50 text-amber-800 border-amber-200')}>
            {d.settings.enabled ? (d.listening.syslog ? t('onboarding.syslog.listening', { port }) : t('onboarding.syslog.notListening')) : t('onboarding.syslog.off')}
          </span>
          {!d.settings.enabled && <button className="px-2.5 py-1 rounded-md bg-indigo-600 text-white disabled:opacity-40" disabled={enable.isPending} onClick={() => enable.mutate()}>{t('onboarding.syslog.enable')}</button>}
          {d.settings.enabled && <span className="text-slate-500">{t('onboarding.syslog.received', { n: d.stored_24h })}</span>}
          {d.errors.syslog && <span className="text-red-600">{d.errors.syslog}</span>}
          <Link to="/soc/syslog" className="text-indigo-600 hover:underline">{t('nav.syslog')}</Link>
        </div>
      )}
      {d && d.unknown.length > 0 && <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded p-2">{t('onboarding.syslog.unknown', { ips: d.unknown.slice(0, 6).map(u => u.ip).join(', ') })}</p>}
      <div className="flex flex-wrap gap-1.5">{TARGETS.map(k => <button key={k} className={tab(target === k)} onClick={() => setTarget(k)}>{t(`onboarding.syslog.target.${k}`)}</button>)}</div>
      <label className="inline-flex items-center gap-1.5 text-xs">{t('onboarding.acc.agentIp')} <input value={ip} onChange={e => setIp(e.target.value)} className="border border-slate-300 rounded px-2 py-1 w-36" /></label>
      <div className="relative">
        <pre className="bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-x-auto whitespace-pre">{text}</pre>
        <button onClick={() => void copy()} className="absolute top-2 right-2 inline-flex items-center gap-1 text-[11px] bg-slate-700 text-slate-100 rounded px-2 py-1 hover:bg-slate-600"><ClipboardCopy size={12} /> {copied ? t('onboarding.acc.copied') : t('onboarding.acc.copy')}</button>
      </div>
      <ul className="text-xs text-slate-500 space-y-1 list-disc pl-4">
        <li>{t('onboarding.syslog.noteKnown')}</li>
        {target === 'ros' && <li>{t('onboarding.syslog.noteRos')}</li>}
        {target === 'cisco' && <li>{t('onboarding.syslog.noteCisco')}</li>}
        <li>{t('onboarding.syslog.noteCheck')}</li>
      </ul>
    </section>
  )
}

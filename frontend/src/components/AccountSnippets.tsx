import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ClipboardCopy, KeyRound } from 'lucide-react'
import { cn } from '../lib/utils'

type Target = 'ros7' | 'ros6' | 'cisco' | 'swos'
type Profile = 'ro' | 'ctl'
const TARGETS: Target[] = ['ros7', 'ros6', 'cisco', 'swos']

function randomPassword(n = 20): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const buf = new Uint32Array(n)
  crypto.getRandomValues(buf)
  return Array.from(buf, v => chars[v % chars.length]).join('')
}

/** The commands to paste on a device so that the agent gets a dedicated account with only the rights it needs. Templates: check them against the device's firmware. */
export function snippet(target: Target, profile: Profile, agentIp: string, pass: string, community: string): string {
  const ip = agentIp || '<ADRES-AGENTA>'
  const pw = pass || '<HASLO>'
  const comm = community || '<COMMUNITY>'
  if (target === 'ros7' || target === 'ros6') {
    const v7 = target === 'ros7'
    const api = v7 ? 'api,rest-api' : 'api'
    const policy = profile === 'ro' ? `read,${api},ssh,test` : `read,write,reboot,ftp,test,${api},ssh`
    const group = profile === 'ro' ? 'mikromanager-ro' : 'mikromanager-ctl'
    return [
      `/user group add name=${group} policy=${policy}`,
      `/user add name=mikromanager group=${group} password="${pw}" comment="MikroManager"`,
      `/user set mikromanager address=${ip}/32`,
      '',
      `# services the agent uses, reachable from the agent only`,
      `/ip service set api disabled=no address=${ip}/32`,
      ...(v7 ? [`# REST is served by the www service`, `/ip service set www disabled=no address=${ip}/32`] : []),
      `/ip service set ssh disabled=no address=${ip}/32`,
    ].join('\n')
  }
  if (target === 'cisco') {
    return [
      `! SSH and a dedicated account (privilege 15 is needed to read the running configuration)`,
      `ip ssh server`,
      `crypto key generate rsa`,
      `username mikromanager password ${pw} privilege 15`,
      '',
      `! read-only SNMP (a community of your own, not "public")`,
      `snmp-server community ${comm} ro`,
    ].join('\n')
  }
  return [
    `SwOS Lite has no accounts, SSH or API: only the web page and SNMP.`,
    `1. SNMP tab: Enable SNMP, Community = ${comm} (not "public"), Save.`,
    `2. System tab: Allow From IP = ${ip}/32 (limits who may manage the switch; leave your own admin address allowed too).`,
    `3. Change the default admin password (System tab).`,
  ].join('\n')
}

export function AccountSnippets({ agentIp }: { agentIp: string | null }) {
  const { t } = useTranslation()
  const [target, setTarget] = useState<Target>('ros7')
  const [profile, setProfile] = useState<Profile>('ro')
  const [pass, setPass] = useState('')
  const [community, setCommunity] = useState('')
  const [copied, setCopied] = useState(false)
  const [ip, setIp] = useState(agentIp ?? '')
  const text = snippet(target, profile, ip, pass, community)
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* the text is selectable anyway */ }
  }
  const tab = (active: boolean) => cn('px-3 py-1.5 text-xs rounded-md border', active ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50')
  return (
    <section className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <div>
        <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2"><KeyRound size={16} className="text-indigo-600" /> {t('onboarding.acc.title')}</h2>
        <p className="text-xs text-slate-500 mt-0.5">{t('onboarding.acc.intro')}</p>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {TARGETS.map(k => <button key={k} className={tab(target === k)} onClick={() => setTarget(k)}>{t(`onboarding.acc.target.${k}`)}</button>)}
      </div>
      {(target === 'ros7' || target === 'ros6') && (
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-xs text-slate-500">{t('onboarding.acc.profile')}:</span>
          {(['ro', 'ctl'] as Profile[]).map(k => <button key={k} className={tab(profile === k)} onClick={() => setProfile(k)}>{t(`onboarding.acc.profiles.${k}`)}</button>)}
        </div>
      )}
      {(target === 'ros7' || target === 'ros6') && <p className="text-xs text-slate-600">{t(`onboarding.acc.profileNote.${profile}`)}</p>}
      <div className="flex flex-wrap gap-2 items-center text-xs">
        <label className="inline-flex items-center gap-1.5">{t('onboarding.acc.agentIp')} <input value={ip} onChange={e => setIp(e.target.value)} className="border border-slate-300 rounded px-2 py-1 w-36" /></label>
        <label className="inline-flex items-center gap-1.5">{t('onboarding.acc.password')} <input value={pass} onChange={e => setPass(e.target.value)} className="border border-slate-300 rounded px-2 py-1 w-52 font-mono" /></label>
        {(target === 'cisco' || target === 'swos') && <label className="inline-flex items-center gap-1.5">{t('onboarding.acc.community')} <input value={community} onChange={e => setCommunity(e.target.value)} className="border border-slate-300 rounded px-2 py-1 w-40 font-mono" /></label>}
        <button className="px-2.5 py-1 rounded-md border border-slate-300 hover:bg-slate-50" onClick={() => { setPass(randomPassword()); setCommunity(randomPassword(14)) }}>{t('onboarding.acc.generate')}</button>
      </div>
      <div className="relative">
        <pre className="bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-x-auto whitespace-pre">{text}</pre>
        <button onClick={() => void copy()} className="absolute top-2 right-2 inline-flex items-center gap-1 text-[11px] bg-slate-700 text-slate-100 rounded px-2 py-1 hover:bg-slate-600"><ClipboardCopy size={12} /> {copied ? t('onboarding.acc.copied') : t('onboarding.acc.copy')}</button>
      </div>
      <ul className="text-xs text-slate-500 space-y-1 list-disc pl-4">
        <li>{t('onboarding.acc.noteStore')} <Link to="/credentials" className="text-indigo-600 hover:underline">{t('nav.credentials')}</Link></li>
        {(target === 'ros7' || target === 'ros6') && <li>{t('onboarding.acc.noteAddress')}</li>}
        {target === 'cisco' && <li>{t('onboarding.acc.noteCisco')}</li>}
        <li>{t('onboarding.acc.noteCheck')}</li>
      </ul>
    </section>
  )
}

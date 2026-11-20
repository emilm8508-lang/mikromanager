import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ArrowDownRight, ArrowUpRight, EyeOff, Plus, Trash2 } from 'lucide-react'
import { assetsApi, cmdbApi, CiRelation } from '../lib/api'
import { cn } from '../lib/utils'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const MANUAL = ['runs_on', 'depends_on', 'connected_to', 'backs_up'] as const

// The same classes as services/cmdb.py CLASSES (for Central, which has no agent to ask)
export const CI_CLASSES: Record<string, string[]> = {
  hardware: ['server_physical', 'server_virtual', 'hypervisor', 'workstation', 'laptop', 'thin_client', 'tablet', 'phone_mobile', 'monitor', 'printer', 'mfp', 'scanner',
             'ups', 'pdu', 'nas', 'storage_array', 'tape_library', 'bmc', 'kvm', 'camera_ip', 'phone_ip', 'access_control', 'iot_device'],
  network: ['router', 'switch', 'access_point', 'wlan_controller', 'firewall', 'load_balancer', 'vpn_gateway', 'modem'],
  server_role: ['domain_controller', 'database_server', 'web_server', 'mail_server', 'file_server', 'print_server', 'backup_server', 'application_server',
                'dns_dhcp_server', 'monitoring_server', 'remote_desktop_server'],
  logical: ['application', 'business_service', 'cluster', 'other'],
}

function AssetName({ id, name }: { id: number | null; name: string | null }) {
  if (id == null) return <span className="text-slate-700">{name ?? '—'}</span>
  return <Link to={`/inventory/${id}`} className="text-indigo-600 hover:underline">{name ?? `#${id}`}</Link>
}

// The class of a CI with a select to set another one (3.90, services/cmdb.py).
export function CiClassSelect({ id, ci, classes }: { id: number; ci: { class: string; set: boolean; suggested: string; why: string }; classes: Record<string, string[]> }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const save = useMutation({
    mutationFn: (v: string) => assetsApi.update(id, { ci_class: v }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['asset', id] }); qc.invalidateQueries({ queryKey: ['cmdb'] }) },
  })
  return (
    <span className="inline-flex flex-col gap-0.5">
      <select value={ci.set ? ci.class : ''} onChange={e => save.mutate(e.target.value)} className="border border-slate-300 rounded-md px-1.5 py-0.5 text-xs bg-white max-w-[13rem]">
        <option value="">{t('cmdb.suggested', { cls: t(`cmdb.class.${ci.suggested}`) })}</option>
        {Object.entries(classes).map(([g, cs]) => (
          <optgroup key={g} label={t(`cmdb.group.${g}`) as string}>{cs.map(c => <option key={c} value={c}>{t(`cmdb.class.${c}`)}</option>)}</optgroup>
        ))}
      </select>
      {!ci.set && <span className="text-[10px] text-slate-400">{t('cmdb.why', { why: ci.why })}</span>}
    </span>
  )
}

function relText(t: (k: string, o?: Record<string, unknown>) => string, r: CiRelation, self: number) {
  return r.src === self ? t(`cmdb.rel.${r.kind}`) : t(`cmdb.relIn.${r.kind}`)
}

// The relations of one asset, what is affected when it fails and what it needs (asset page tab).
export function AssetRelations({ id }: { id: number }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['cmdb-asset', id], queryFn: () => cmdbApi.forAsset(id) })
  const all = useQuery({ queryKey: ['cmdb'], queryFn: cmdbApi.overview, staleTime: 60000 })
  const [kind, setKind] = useState<string>('depends_on')
  const [dir, setDir] = useState<'out' | 'in'>('out')
  const [other, setOther] = useState('')
  const [note, setNote] = useState('')
  const inv = () => { qc.invalidateQueries({ queryKey: ['cmdb-asset', id] }); qc.invalidateQueries({ queryKey: ['cmdb'] }) }
  const add = useMutation({
    mutationFn: () => {
      const o = Number(other)
      return cmdbApi.add(dir === 'out' ? { src: id, dst: o, kind, note } : { src: o, dst: id, kind, note })
    },
    onSuccess: () => { setOther(''); setNote(''); inv() },
  })
  const del = useMutation({ mutationFn: (rid: number) => cmdbApi.remove(rid), onSuccess: inv })
  const hide = useMutation({ mutationFn: (r: CiRelation) => cmdbApi.hide({ src: r.src, dst: r.dst, kind: r.kind, service_id: r.service_id ?? null }), onSuccess: inv })
  const d = q.data
  const options = (all.data?.items ?? []).filter(x => x.id !== id)
  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-xl p-4 text-sm space-y-2">
        <h3 className="font-semibold text-slate-900">{t('cmdb.relations')}</h3>
        {!d ? <p className="text-xs text-slate-500">{t('common.loading')}</p> : d.relations.length === 0 ? <p className="text-xs text-slate-500">{t('cmdb.noRelations')}</p> : (
          <div className="divide-y divide-slate-100">
            {d.relations.map((r, i) => (
              <div key={r.id ?? `a${i}`} className="flex items-center gap-2 py-1.5">
                <span className="text-xs text-slate-500 w-40 shrink-0">{relText(t, r, id)}</span>
                <span className="flex-1 min-w-0 truncate">{r.src === id ? <AssetName id={r.dst} name={r.dst_name} /> : <AssetName id={r.src} name={r.src_name} />}</span>
                <span className={cn('text-[11px] rounded-full px-2 py-0.5', r.auto ? 'bg-slate-100 text-slate-500' : 'bg-indigo-50 text-indigo-700')}>{r.auto ? `${t('cmdb.auto')}${r.how ? ` · ${r.how}` : ''}` : t('cmdb.manual')}</span>
                {r.note && <span className="text-xs text-slate-500 truncate max-w-[12rem]" title={r.note}>{r.note}</span>}
                {r.auto
                  ? <button title={t('cmdb.hide') as string} onClick={() => hide.mutate(r)} className="text-slate-400 hover:text-slate-700"><EyeOff size={13} /></button>
                  : <button title={t('cmdb.remove') as string} onClick={() => r.id && del.mutate(r.id)} className="text-slate-400 hover:text-red-600"><Trash2 size={13} /></button>}
              </div>
            ))}
          </div>
        )}
        <div className="flex flex-wrap items-end gap-2 pt-2 border-t border-slate-100">
          <select value={dir} onChange={e => setDir(e.target.value as 'out' | 'in')} className="border border-slate-300 rounded-lg px-2 py-1 text-xs bg-white">
            <option value="out">{t('cmdb.thisOne')}</option><option value="in">{t('cmdb.otherOne')}</option>
          </select>
          <select value={kind} onChange={e => setKind(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1 text-xs bg-white">
            {MANUAL.map(k => <option key={k} value={k}>{t(`cmdb.rel.${k}`)}</option>)}
          </select>
          <select value={other} onChange={e => setOther(e.target.value)} className="border border-slate-300 rounded-lg px-2 py-1 text-xs bg-white max-w-[16rem]">
            <option value="">{dir === 'out' ? t('cmdb.pickTarget') : t('cmdb.pickSource')}</option>
            {options.map(o => <option key={o.id} value={o.id}>{o.name}{o.ip ? ` (${o.ip})` : ''}</option>)}
          </select>
          <input value={note} onChange={e => setNote(e.target.value)} maxLength={200} placeholder={t('cmdb.note') as string} className="border border-slate-300 rounded-lg px-2 py-1 text-xs w-40" />
          <button disabled={!other || add.isPending} onClick={() => add.mutate()} className="flex items-center gap-1 text-xs text-white bg-indigo-600 rounded-lg px-2.5 py-1 disabled:opacity-50"><Plus size={12} /> {t('cmdb.add')}</button>
          {add.isError && <span className="text-xs text-red-700">{errText(add.error)}</span>}
        </div>
        <p className="text-[11px] text-slate-400">{t('cmdb.relNote')}</p>
      </div>
      {d && <ImpactBox impact={d.impact} deps={d.dependencies} />}
    </div>
  )
}

export function ImpactBox({ impact, deps, compact }: { impact: { assets: Array<{ id: number; name: string | null; depth: number; kind: string; via: string | null }>; services: Array<{ name: string }> }
  deps: Array<{ id: number; name: string | null; depth: number; kind: string; from: string | null }>; compact?: boolean }) {
  const { t } = useTranslation()
  if (compact && impact.assets.length === 0 && impact.services.length === 0 && deps.length === 0) return null
  return (
    <div className={cn('grid gap-3', compact ? 'text-xs' : 'md:grid-cols-2 text-sm')}>
      <div className={cn(!compact && 'bg-white border border-slate-200 rounded-xl p-4')}>
        <div className="font-semibold text-slate-800 flex items-center gap-1.5 mb-1"><ArrowDownRight size={14} className="text-red-500" /> {t('cmdb.impact')}</div>
        {impact.assets.length === 0 && impact.services.length === 0 ? <p className="text-slate-500 text-xs">{t('cmdb.impactNone')}</p> : (
          <ul className="space-y-0.5">
            {impact.services.map(s => <li key={s.name} className="text-red-700">{t('cmdb.service', { name: s.name })}</li>)}
            {impact.assets.slice(0, compact ? 8 : 100).map(x => (
              <li key={x.id} style={{ paddingLeft: (x.depth - 1) * 12 }}><AssetName id={x.id} name={x.name} /> <span className="text-slate-400">· {t(`cmdb.rel.${x.kind}`)} {x.via}</span></li>
            ))}
            {compact && impact.assets.length > 8 && <li className="text-slate-400">+{impact.assets.length - 8}</li>}
          </ul>
        )}
      </div>
      <div className={cn(!compact && 'bg-white border border-slate-200 rounded-xl p-4')}>
        <div className="font-semibold text-slate-800 flex items-center gap-1.5 mb-1"><ArrowUpRight size={14} className="text-indigo-500" /> {t('cmdb.dependsOn')}</div>
        {deps.length === 0 ? <p className="text-slate-500 text-xs">{t('cmdb.depsNone')}</p> : (
          <ul className="space-y-0.5">
            {deps.slice(0, compact ? 8 : 100).map(x => (
              <li key={x.id} style={{ paddingLeft: (x.depth - 1) * 12 }}><AssetName id={x.id} name={x.name} /> <span className="text-slate-400">· {x.from} {t(`cmdb.rel.${x.kind}`)}</span></li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

// For a SOC alert about an asset: what else it affects and what it may come from (3.90).
export function AlertImpact({ assetId }: { assetId: number }) {
  const { t } = useTranslation()
  const q = useQuery({ queryKey: ['cmdb-asset', assetId], queryFn: () => cmdbApi.forAsset(assetId), staleTime: 60000 })
  if (!q.data) return null
  if (q.data.impact.assets.length === 0 && q.data.impact.services.length === 0 && q.data.dependencies.length === 0) return null
  return (
    <div>
      <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">{t('cmdb.alertTitle')}</div>
      <ImpactBox impact={q.data.impact} deps={q.data.dependencies} compact />
    </div>
  )
}

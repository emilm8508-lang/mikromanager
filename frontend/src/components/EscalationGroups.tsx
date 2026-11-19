import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2 } from 'lucide-react'
import { maintApi, EscalationGroup } from '../lib/api'

function errText(e: unknown): string {
  const x = e as { response?: { data?: { detail?: string } }; message?: string }
  return x?.response?.data?.detail ?? x?.message ?? String(e)
}

const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const
const TYPES = ['windows', 'linux', 'network', 'printer', 'virtual', 'server', 'other'] as const
const CRIT = ['critical', 'important', 'normal', 'ignore'] as const      // the asset criticality levels

type Draft = { name: string; route: string; groups: string; types: string[]; criticality: string[]; nameMatch: string; levels: Record<string, string>; exclusive: boolean }

function toDraft(g: EscalationGroup): Draft {
  return { name: g.name, route: g.route, groups: g.match.groups.join(', '), types: g.match.types, criticality: g.match.criticality, nameMatch: g.match.name ?? '',
           levels: Object.fromEntries(SEVS.map(k => [k, g.levels[k] ? g.levels[k].join(', ') : ''])), exclusive: g.exclusive }
}

function fromDraft(d: Draft): EscalationGroup {
  const levels: Record<string, number[]> = {}
  for (const k of SEVS) {
    const v = (d.levels[k] ?? '').trim()
    if (v) levels[k] = v.split(',').map(x => x.trim()).filter(Boolean).map(Number)
  }
  return { name: d.name, route: d.route.trim().toLowerCase(), exclusive: d.exclusive, levels,
           match: { groups: d.groups.split(',').map(x => x.trim()).filter(Boolean), types: d.types, criticality: d.criticality, name: d.nameMatch.trim() || null } }
}

const EMPTY: Draft = { name: '', route: '', groups: '', types: [], criticality: [], nameMatch: '', levels: {}, exclusive: true }

// Escalation groups (services/escalation.py, 3.88): alerts of some equipment escalate on their own times, to their own Central rule
// (event type soc_escalated.<route>).
export function EscalationGroups({ groups }: { groups: EscalationGroup[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [list, setList] = useState<Draft[]>(groups.map(toDraft))
  const [dirty, setDirty] = useState(false)
  useEffect(() => { if (!dirty) setList(groups.map(toDraft)) }, [groups, dirty])
  const save = useMutation({
    mutationFn: () => maintApi.escalation({ groups: list.map(fromDraft) }),
    onSuccess: () => { setDirty(false); void qc.invalidateQueries({ queryKey: ['maint'] }) },
  })
  const set = (i: number, p: Partial<Draft>) => { setList(list.map((d, j) => (j === i ? { ...d, ...p } : d))); setDirty(true) }
  const toggle = (arr: string[], v: string) => (arr.includes(v) ? arr.filter(x => x !== v) : [...arr, v])
  const inp = 'border border-slate-300 rounded-lg px-2 py-1 text-sm text-slate-900 bg-white'
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3 text-sm">
      <h2 className="font-semibold text-slate-900">{t('escg.title')}</h2>
      <p className="text-xs text-slate-500">{t('escg.intro')}</p>
      {list.map((d, i) => (
        <div key={i} className="border border-slate-200 rounded-lg p-3 space-y-2 bg-slate-50">
          <div className="flex flex-wrap gap-3 items-end">
            <label className="text-xs text-slate-600">{t('escg.name')}<input value={d.name} onChange={e => set(i, { name: e.target.value })} className={`block w-48 ${inp}`} /></label>
            <label className="text-xs text-slate-600">{t('escg.route')}<input value={d.route} onChange={e => set(i, { route: e.target.value })} placeholder="network-team" className={`block w-44 font-mono ${inp}`} /></label>
            <span className="text-[11px] text-slate-500 pb-1.5">{t('escg.eventType')}: <code className="bg-white border border-slate-200 rounded px-1">soc_escalated.{d.route.trim().toLowerCase() || '…'}</code></span>
            <button onClick={() => { setList(list.filter((_, j) => j !== i)); setDirty(true) }} title={t('escg.remove') as string} className="ml-auto text-slate-400 hover:text-red-600 pb-1.5"><Trash2 size={14} /></button>
          </div>
          <div className="text-xs font-medium text-slate-700">{t('escg.when')}</div>
          <div className="flex flex-wrap gap-3 items-end">
            <label className="text-xs text-slate-600">{t('escg.assetGroups')}<input value={d.groups} onChange={e => set(i, { groups: e.target.value })} placeholder="servers, network" className={`block w-56 ${inp}`} /></label>
            <label className="text-xs text-slate-600">{t('escg.nameMatch')}<input value={d.nameMatch} onChange={e => set(i, { nameMatch: e.target.value })} placeholder="SRV-" className={`block w-40 ${inp}`} /></label>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-700">
            <span className="text-slate-500">{t('escg.types')}:</span>
            {TYPES.map(k => <label key={k} className="flex items-center gap-1"><input type="checkbox" checked={d.types.includes(k)} onChange={() => set(i, { types: toggle(d.types, k) })} /> {t(`escg.type.${k}`)}</label>)}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-700">
            <span className="text-slate-500">{t('escg.criticality')}:</span>
            {CRIT.map(k => <label key={k} className="flex items-center gap-1"><input type="checkbox" checked={d.criticality.includes(k)} onChange={() => set(i, { criticality: toggle(d.criticality, k) })} /> {t(`assets.crit.${k}`)}</label>)}
          </div>
          <div className="text-xs font-medium text-slate-700">{t('escg.times')}</div>
          <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1">
            {SEVS.map(k => (
              <label key={k} className="flex items-center gap-2 text-xs text-slate-600">
                <span className="w-20">{t(`soc.severity.${k}`)}</span>
                <input value={d.levels[k] ?? ''} onChange={e => set(i, { levels: { ...d.levels, [k]: e.target.value } })} placeholder={t('escg.general') as string} className={`flex-1 ${inp}`} />
                <span>min</span>
              </label>
            ))}
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-700"><input type="checkbox" checked={d.exclusive} onChange={e => set(i, { exclusive: e.target.checked })} /> {t('escg.exclusive')}</label>
        </div>
      ))}
      <div className="flex items-center gap-3">
        <button onClick={() => { setList([...list, { ...EMPTY }]); setDirty(true) }} className="flex items-center gap-1 text-xs text-indigo-600 hover:underline"><Plus size={12} /> {t('escg.add')}</button>
        <button disabled={!dirty || save.isPending} onClick={() => save.mutate()} className="ml-auto px-3 py-1.5 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">{t('maint.form.save')}</button>
        {save.isError && <span className="text-xs text-red-700">{errText(save.error)}</span>}
      </div>
      <p className="text-[11px] text-slate-400">{t('escg.how')}</p>
    </div>
  )
}

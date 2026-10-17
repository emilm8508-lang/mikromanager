import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { AssetType, RackItemView, RackPaletteAsset, RackSummary, RackView } from '../lib/api'
import { RackDiagram, RackItemPanel, startRackDrag, KIND_COLOR } from './RackView'
import { TypeIcon } from './AssetBits'
import { Button } from './ui/Button'
import { Rows3, Plus, Pencil, Trash2, GripVertical, Sparkles, X } from 'lucide-react'
import { cn } from '../lib/utils'

const DEFAULT_H: Partial<Record<AssetType, number>> = { network: 1, server: 2, printer: 2 }
const MANUAL: Array<{ kind: string; h: number }> = [
  { kind: 'patch_panel', h: 1 }, { kind: 'switch', h: 1 }, { kind: 'ups', h: 2 }, { kind: 'pdu', h: 1 }, { kind: 'cable_manager', h: 1 }, { kind: 'shelf', h: 1 }, { kind: 'blank', h: 1 },
]
const CABLES = ['cat6', 'fibre', 'dac', 'power', 'other']
const inp = 'border border-slate-300 rounded-lg px-2.5 py-1.5 text-sm bg-white w-full'

const errText = (e: any) => e?.response?.data?.detail ?? e?.message ?? String(e)

export interface RackBody { name: string; location?: string | null; units: number; notes?: string | null }
export interface RackOps {
  createRack: (b: RackBody) => Promise<void>
  updateRack: (id: number, b: RackBody) => Promise<void>
  removeRack: (id: number) => Promise<void>
  addSuggested: (id: number) => Promise<string | void>
  addItem: (rackId: number, b: { u: number; height?: number; asset_id?: number; kind?: string; label?: string; port_count?: number }) => Promise<void>
  updateItem: (id: number, b: { u?: number; height?: number; label?: string; notes?: string; port_count?: number }) => Promise<void>
  removeItem: (id: number) => Promise<void>
  addLink: (rackId: number, b: { item_a_id: number; port_a?: string; item_b_id?: number | null; port_b?: string; remote_text?: string; label?: string; cable?: string }) => Promise<void>
  removeLink: (id: number) => Promise<void>
}

// The rack screen shared by the agent and Central: choose a rack, drag devices into it, click a device for its ports and connections, cable by hand.
// What it changes goes through `ops` - straight to the agent's API there, as a queued command to the agent here (Central).
export function RackWorkspace({ racks, rackId, onRackId, rack, palette, paletteLoading, loading, ops, assetHref, toolbar, leading, subtitle, queuedNote, notice }: {
  racks: RackSummary[]; rackId: number | null; onRackId: (id: number | null) => void; rack: RackView | null
  palette: RackPaletteAsset[]; paletteLoading?: boolean; loading?: boolean; ops: RackOps; assetHref?: (assetId: number) => string | null
  toolbar?: React.ReactNode; leading?: React.ReactNode; subtitle?: string; queuedNote?: string; notice?: React.ReactNode
}) {
  const { t } = useTranslation()
  const [selected, setSelected] = useState<{ id: number | null; port: string | null }>({ id: null, port: null })
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [form, setForm] = useState<{ id: number | null; name: string; location: string; units: string; notes: string } | null>(null)
  const [q, setQ] = useState('')
  const [onlyInfra, setOnlyInfra] = useState(true)
  const item = rack?.items.find(i => i.id === selected.id) ?? null
  useEffect(() => { if (selected.id != null && rack && !item) setSelected({ id: null, port: null }) }, [rack, item, selected.id])
  useEffect(() => { setSelected({ id: null, port: null }) }, [rackId])

  const run = async (fn: () => Promise<unknown>) => {
    setMsg(null)
    try { const r = await fn(); if (typeof r === 'string' && r) setMsg({ ok: true, text: r }); else if (queuedNote) setMsg({ ok: true, text: queuedNote }) }
    catch (e) { setMsg({ ok: false, text: errText(e) }) }
  }

  // the first free place from the top where `h` units fit (what a click on "+" uses instead of a drop)
  const firstFree = (h: number): number | null => {
    if (!rack) return null
    for (let u = rack.units - h + 1; u >= 1; u--) if (rack.items.every(i => u + h - 1 < i.u || u > i.u + i.height - 1)) return u
    return null
  }
  const addAsset = (a: RackPaletteAsset, u?: number) => {
    const h = DEFAULT_H[a.type] ?? 1
    const at = u ?? firstFree(h)
    if (at == null) { setMsg({ ok: false, text: t('racks.noSpace') as string }); return }
    void run(() => ops.addItem(rackId!, { u: at, height: h, asset_id: a.id }))
  }
  const addKind = (kind: string, h: number, u?: number) => {
    const at = u ?? firstFree(h)
    if (at == null) { setMsg({ ok: false, text: t('racks.noSpace') as string }); return }
    void run(() => ops.addItem(rackId!, { u: at, height: h, kind, label: t(`racks.kind.${kind}`) as string }))
  }

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return palette.filter(a => (!onlyInfra || a.infra || a.suggested) && (!needle || [a.name, a.ip, a.model, a.location].some(v => (v ?? '').toLowerCase().includes(needle))))
  }, [palette, q, onlyInfra])
  const suggested = shown.filter(a => a.suggested)
  const rest = shown.filter(a => !a.suggested).slice(0, 80)

  const saveForm = async () => {
    if (!form) return
    const body = { name: form.name, location: form.location || null, units: Number(form.units) || 42, notes: form.notes || null }
    await run(async () => { if (form.id) await ops.updateRack(form.id, body); else await ops.createRack(body); setForm(null) })
  }

  const cur = racks.find(r => r.id === rackId)
  return (
    <div className="p-6 space-y-4 max-w-[1700px]">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2"><Rows3 size={20} className="text-indigo-600" /> {t('racks.title')}</h1>
          <p className="text-sm text-slate-500 mt-0.5">{subtitle ?? t('racks.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {leading}
          {racks.length > 0 && (
            <select value={rackId ?? ''} onChange={e => onRackId(Number(e.target.value))} className="border border-slate-300 rounded-lg px-2 py-1.5 text-sm bg-white">
              {racks.map(r => <option key={r.id} value={r.id}>{r.name}{r.location ? ` · ${r.location}` : ''} ({r.used_u}/{r.units} U)</option>)}
            </select>
          )}
          <Button size="sm" variant="secondary" onClick={() => setForm({ id: null, name: '', location: '', units: '42', notes: '' })}><Plus size={13} /> {t('racks.newRack')}</Button>
          {cur && <Button size="sm" variant="ghost" onClick={() => setForm({ id: cur.id, name: cur.name, location: cur.location ?? '', units: String(cur.units), notes: cur.notes ?? '' })}><Pencil size={13} /> {t('racks.editRack')}</Button>}
          {cur && <Button size="sm" variant="ghost" onClick={() => { if (confirm(t('racks.deleteRackConfirm', { name: cur.name }) as string)) void run(() => ops.removeRack(cur.id)) }}><Trash2 size={13} /> {t('racks.deleteRack')}</Button>}
          {toolbar}
        </div>
      </div>

      {notice}
      {msg && <div className={cn('text-sm border rounded-lg px-4 py-2 flex items-center gap-3', msg.ok ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-red-50 border-red-200 text-red-800')}>{msg.text}<button className="ml-auto" onClick={() => setMsg(null)}><X size={14} /></button></div>}

      {form && (
        <div className="bg-white border border-slate-200 rounded-xl p-4 grid grid-cols-1 md:grid-cols-[1fr_1fr_6rem_2fr_auto] gap-3 items-end">
          <label className="text-xs text-slate-500">{t('racks.name')}<input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className={inp} autoFocus /></label>
          <label className="text-xs text-slate-500">{t('racks.location')}<input value={form.location} onChange={e => setForm({ ...form, location: e.target.value })} className={inp} placeholder={t('racks.locationHint') as string} /></label>
          <label className="text-xs text-slate-500">{t('racks.units')}<input type="number" min={1} max={60} value={form.units} onChange={e => setForm({ ...form, units: e.target.value })} className={inp} /></label>
          <label className="text-xs text-slate-500">{t('racks.notes')}<input value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} className={inp} /></label>
          <div className="flex gap-2"><Button size="sm" variant="primary" disabled={!form.name.trim()} onClick={saveForm}>{t('common.save')}</Button><Button size="sm" variant="ghost" onClick={() => setForm(null)}>{t('common.cancel')}</Button></div>
        </div>
      )}

      {loading ? <p className="text-sm text-slate-500">{t('common.loading')}</p> : !rack ? (
        <div className="bg-white border border-dashed border-slate-300 rounded-xl p-10 text-center text-sm text-slate-500">{t('racks.empty')}</div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[17rem_auto_minmax(22rem,1fr)] gap-5 items-start">
          <aside className="bg-white border border-slate-200 rounded-xl p-3 space-y-3 xl:sticky xl:top-4 max-h-[calc(100vh-7rem)] overflow-y-auto">
            <p className="text-xs text-slate-500">{t('racks.dragHint')}</p>
            <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('racks.search') as string} className={inp} />
            <label className="text-xs text-slate-500 inline-flex items-center gap-1.5"><input type="checkbox" checked={onlyInfra} onChange={e => setOnlyInfra(e.target.checked)} />{t('racks.onlyInfra')}</label>
            {suggested.length > 0 && (
              <section>
                <div className="flex items-center gap-2 mb-1"><h4 className="text-xs font-semibold text-slate-700 flex-1">{t('racks.suggested')} ({suggested.length})</h4>
                  <Button size="sm" variant="secondary" onClick={() => run(async () => ops.addSuggested(rackId!))}><Sparkles size={12} /> {t('racks.addAll')}</Button></div>
                <PaletteList rows={suggested} onAdd={addAsset} />
              </section>
            )}
            <section>
              <h4 className="text-xs font-semibold text-slate-700 mb-1">{t('racks.assets')}</h4>
              {paletteLoading ? <p className="text-xs text-slate-400">{t('common.loading')}</p> : rest.length === 0 ? <p className="text-xs text-slate-400">{t('racks.noAssets')}</p> : <PaletteList rows={rest} onAdd={addAsset} />}
            </section>
            <section>
              <h4 className="text-xs font-semibold text-slate-700 mb-1">{t('racks.manual')}</h4>
              <ul className="space-y-1">
                {MANUAL.map(m => (
                  <li key={m.kind} draggable onDragStart={e => startRackDrag(e, 'kind', m.kind, m.h)} className="flex items-center gap-2 text-sm border border-slate-200 rounded-lg px-2 py-1.5 cursor-grab bg-white hover:bg-slate-50">
                    <GripVertical size={12} className="text-slate-300 shrink-0" /><span className="inline-block w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: KIND_COLOR[m.kind] }} />
                    <span className="flex-1 truncate">{t(`racks.kind.${m.kind}`)}</span><span className="text-[10px] text-slate-400">{m.h}U</span>
                    <button className="text-slate-400 hover:text-indigo-600" title={t('racks.addFirstFree') as string} onClick={() => addKind(m.kind, m.h)}><Plus size={13} /></button>
                  </li>
                ))}
              </ul>
            </section>
          </aside>

          <div className="overflow-x-auto">
            <RackDiagram rack={rack} selectedId={selected.id} selectedPort={selected.port} onSelect={(id, port) => setSelected({ id, port: port ?? null })}
              edit={{
                onDropAsset: (u, assetId) => { const a = palette.find(x => x.id === assetId); if (a) addAsset(a, u) },
                onDropKind: (u, kind) => addKind(kind, MANUAL.find(m => m.kind === kind)?.h ?? 1, u),
                onMove: (id, u) => { void run(() => ops.updateItem(id, { u })) },
              }} />
          </div>

          <div className="min-w-0">
            {item ? (
              <RackItemPanel rack={rack} item={item} selectedPort={selected.port} onSelect={(id, port) => setSelected({ id, port: port ?? null })} assetHref={id => `/inventory/${id}`}>
                <ItemEditor rack={rack} item={item} ops={ops} run={run} onGone={() => setSelected({ id: null, port: null })} />
              </RackItemPanel>
            ) : (
              <div className="bg-white border border-dashed border-slate-300 rounded-xl p-8 text-center text-sm text-slate-500">{t('racks.pick')}</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function PaletteList({ rows, onAdd }: { rows: RackPaletteAsset[]; onAdd: (a: RackPaletteAsset) => void }) {
  const { t } = useTranslation()
  return (
    <ul className="space-y-1">
      {rows.map(a => (
        <li key={a.id} draggable onDragStart={e => startRackDrag(e, 'asset', a.id, DEFAULT_H[a.type] ?? 1)} className={cn('flex items-center gap-2 text-sm border rounded-lg px-2 py-1.5 cursor-grab bg-white hover:bg-slate-50', a.suggested ? 'border-indigo-200' : 'border-slate-200')}>
          <GripVertical size={12} className="text-slate-300 shrink-0" /><TypeIcon type={a.type} size={14} />
          <span className="min-w-0 flex-1"><span className="block truncate text-slate-800">{a.name}</span><span className="block truncate text-[10px] text-slate-400">{[a.ip, a.model].filter(Boolean).join(' · ')}</span></span>
          <button className="text-slate-400 hover:text-indigo-600" title={t('racks.addFirstFree') as string} onClick={() => onAdd(a)}><Plus size={13} /></button>
        </li>
      ))}
    </ul>
  )
}

// what only the editor does: rename, height, remove from the rack, and the cables drawn by hand
function ItemEditor({ rack, item, ops, run, onGone }: { rack: RackView; item: RackItemView; ops: RackOps; run: (fn: () => Promise<unknown>) => Promise<void>; onGone: () => void }) {
  const { t } = useTranslation()
  const [label, setLabel] = useState(item.label)
  const [link, setLink] = useState({ port: '', target: '', port_b: '', remote: '', cable: 'cat6', label: '' })
  useEffect(() => { setLabel(item.label); setLink(l => ({ ...l, port: '' })) }, [item.id, item.label])
  const manualLinks = rack.links.filter(l => l.kind === 'manual' && l.id != null && (l.a === item.id || l.b === item.id))
  const others = rack.items.filter(i => i.id !== item.id)
  const maxH = Math.min(8, rack.units)
  const addLink = () => run(() => ops.addLink(rack.id, {
    item_a_id: item.id, port_a: link.port || undefined, item_b_id: link.target ? Number(link.target) : null, port_b: link.port_b || undefined,
    remote_text: link.target ? undefined : link.remote, cable: link.cable, label: link.label || undefined,
  })).then(() => setLink({ ...link, port: '', port_b: '', remote: '', label: '' }))
  return (
    <>
      <section className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
        <h4 className="text-sm font-semibold text-slate-800">{t('racks.edit')}</h4>
        <div className="grid grid-cols-[1fr_5.5rem] gap-2">
          <label className="text-xs text-slate-500">{t('racks.label')}<input value={label} onChange={e => setLabel(e.target.value)} onBlur={() => { if (label.trim() && label !== item.label) void run(() => ops.updateItem(item.id, { label })) }} className={inp} /></label>
          <label className="text-xs text-slate-500">{t('racks.height')}
            <select value={item.height} onChange={e => void run(() => ops.updateItem(item.id, { height: Number(e.target.value) }))} className={inp}>
              {Array.from({ length: maxH }, (_, n) => n + 1).map(n => <option key={n} value={n}>{n} U</option>)}
            </select></label>
        </div>
        {!item.asset && (
          <label className="text-xs text-slate-500 block">{t('racks.portCount')}
            <input type="number" min={0} max={96} defaultValue={item.portCount ?? 0} onBlur={e => void run(() => ops.updateItem(item.id, { port_count: Number(e.target.value) || 0 }))} className={inp} /></label>
        )}
        <Button size="sm" variant="ghost" onClick={() => { if (confirm(t('racks.removeItemConfirm') as string)) void run(async () => { await ops.removeItem(item.id); onGone() }) }}><Trash2 size={13} /> {t('racks.removeItem')}</Button>
      </section>

      <section className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
        <h4 className="text-sm font-semibold text-slate-800">{t('racks.manualLinks')}</h4>
        <p className="text-xs text-slate-500">{t('racks.manualHint')}</p>
        {manualLinks.length > 0 && (
          <ul className="divide-y divide-slate-100 text-sm">
            {manualLinks.map(l => {
              const mine = l.a === item.id
              const o = rack.items.find(i => i.id === (mine ? l.b : l.a))
              return (
                <li key={l.id} className="py-1.5 flex items-center gap-2">
                  <span className="flex-1 min-w-0 truncate">{(mine ? l.aPort : l.bPort) ?? '—'} ↔ {o ? o.label : l.remote} {(mine ? l.bPort : l.aPort) ? `· ${mine ? l.bPort : l.aPort}` : ''}{l.cable ? <span className="text-slate-400"> · {t(`racks.cable.${l.cable}`)}</span> : null}</span>
                  <button className="text-slate-400 hover:text-red-600" onClick={() => void run(() => ops.removeLink(l.id!))}><Trash2 size={13} /></button>
                </li>
              )
            })}
          </ul>
        )}
        <div className="grid grid-cols-2 gap-2">
          <label className="text-xs text-slate-500">{t('racks.thisPort')}
            {item.ports.length > 0 ? (
              <select value={link.port} onChange={e => setLink({ ...link, port: e.target.value })} className={inp}><option value="">—</option>{item.ports.map(p => <option key={p.name} value={p.name}>{p.name}</option>)}</select>
            ) : <input value={link.port} onChange={e => setLink({ ...link, port: e.target.value })} className={inp} />}
          </label>
          <label className="text-xs text-slate-500">{t('racks.otherEnd')}
            <select value={link.target} onChange={e => setLink({ ...link, target: e.target.value })} className={inp}><option value="">{t('racks.elsewhere')}</option>{others.map(i => <option key={i.id} value={i.id}>{i.label}</option>)}</select></label>
          {link.target ? <label className="text-xs text-slate-500">{t('racks.otherPort')}<input value={link.port_b} onChange={e => setLink({ ...link, port_b: e.target.value })} className={inp} /></label>
            : <label className="text-xs text-slate-500">{t('racks.otherName')}<input value={link.remote} onChange={e => setLink({ ...link, remote: e.target.value })} className={inp} placeholder={t('racks.otherNameHint') as string} /></label>}
          <label className="text-xs text-slate-500">{t('racks.cableType')}<select value={link.cable} onChange={e => setLink({ ...link, cable: e.target.value })} className={inp}>{CABLES.map(c => <option key={c} value={c}>{t(`racks.cable.${c}`)}</option>)}</select></label>
          <label className="text-xs text-slate-500 col-span-2">{t('racks.cableLabel')}<input value={link.label} onChange={e => setLink({ ...link, label: e.target.value })} className={inp} /></label>
        </div>
        <Button size="sm" variant="secondary" disabled={!link.target && !link.remote.trim()} onClick={addLink}><Plus size={13} /> {t('racks.addLink')}</Button>
      </section>
    </>
  )
}

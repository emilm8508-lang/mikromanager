import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, type CentralFleetGroup, type FleetGroupInput, type FleetGroupSummary, type FleetOverview } from '../lib/api'
import { Card, CardHeader, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import { Editor, emptyGroup, scheduleText } from './FleetGroups'
import { Plus, Play, Pencil, Trash2 } from 'lucide-react'

type TenantFleet = { tenant: string; lastSeen: string | null; fleet: FleetOverview }

function errText(e: unknown): string {
  return (e as Error)?.message || String(e)
}

// Upgrade groups defined in Central: stored on OVH, mirrored read-only by each tenant's agent
// (which runs them on schedule and reports the outcome back in its summary, joined here by central_id).
export function CentralFleetGroups({ rows, tenantFilter, groups, onChanged }: {
  rows: TenantFleet[]; tenantFilter: string; groups: CentralFleetGroup[]; onChanged: () => void
}) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState<{ tenant: string; id: number | null; value: FleetGroupInput } | null>(null)
  const [pickTenant, setPickTenant] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const fleetOf = (tenant: string) => rows.find(r => r.tenant === tenant)?.fleet
  const nameOf = (tenant: string, id: number) => fleetOf(tenant)?.devices.find(d => d.id === id)?.name ?? `#${id}`
  const statusOf = (tenant: string, id: number): FleetGroupSummary | undefined =>
    (fleetOf(tenant)?.groups ?? []).find(g => g.central_id === id)
  const vis = groups.filter(g => tenantFilter === 'all' || g.tenant === tenantFilter)
  const tenants = rows.map(r => r.tenant).sort()
  const newTenant = tenantFilter !== 'all' ? tenantFilter : pickTenant

  const act = async (fn: () => Promise<unknown>, okMsg?: string) => {
    setError(null); setNotice(null)
    try { await fn(); if (okMsg) setNotice(okMsg); onChanged() } catch (e) { setError(errText(e)) }
  }

  const save = async (g: FleetGroupInput) => {
    if (!editing) return
    setSaving(true); setError(null)
    try {
      await centralApi.fleetGroupSave(editing.tenant, g, editing.id ?? undefined)
      setEditing(null); setNotice(t('fleetCentral.groupSaved') as string); onChanged()
    } catch (e) {
      setError(errText(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-slate-700">{t('fleetCentral.groupsCard')}</h2>
          <div className="flex items-center gap-2">
            {tenantFilter === 'all' && (
              <select value={pickTenant} onChange={e => setPickTenant(e.target.value)} className="text-xs border border-slate-300 rounded px-2 py-1">
                <option value="">{t('fleetCentral.pickTenant')}</option>
                {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
              </select>
            )}
            <Button size="sm" variant="secondary" disabled={!newTenant || !!editing}
              onClick={() => { setError(null); setEditing({ tenant: newTenant, id: null, value: emptyGroup() }) }}>
              <Plus size={13} /> {t('fleet.groups.new')}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-slate-500">{t('fleetCentral.groupsIntro')}</p>
        {notice && <p className="text-xs text-emerald-700">{notice}</p>}
        {error && !editing && <p className="text-xs text-red-700">{error}</p>}

        {editing && (
          <div className="space-y-1">
            <div className="text-xs text-slate-600">{t('fleetCentral.groupFor')}: <b>{editing.tenant}</b></div>
            <Editor key={`${editing.tenant}:${editing.id ?? 'new'}`} initial={editing.value} devices={fleetOf(editing.tenant)?.devices ?? []}
              onClose={() => { setEditing(null); setError(null) }} onSave={save} saving={saving} error={error} />
          </div>
        )}

        {vis.length === 0 && !editing && <p className="text-sm text-slate-500">{t('fleetCentral.groupsEmpty')}</p>}
        {vis.map(cg => {
          const d = cg.definition
          const st = statusOf(cg.tenant, cg.id)
          const input: FleetGroupInput = { name: cg.name, ...d }
          return (
            <div key={cg.id} className="border border-slate-200 rounded-lg p-3 flex items-start justify-between gap-2 flex-wrap">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">{cg.tenant}</span>
                  <span className="font-medium text-slate-900">{cg.name}</span>
                  <Badge variant="gray">{t('fleet.groups.devicesCount', { n: d.device_ids.length })}</Badge>
                  <Badge variant="blue">{d.channel ?? t('fleet.groups.channelKeep')}</Badge>
                  {!d.enabled && d.schedule_kind !== 'manual' && <Badge variant="yellow">{t('fleet.groups.paused')}</Badge>}
                  {!st && <Badge variant="yellow">{t('fleetCentral.waitingForAgent')}</Badge>}
                </div>
                <div className="text-xs text-slate-500 mt-0.5 truncate" title={d.device_ids.map(i => nameOf(cg.tenant, i)).join(' → ')}>
                  {d.device_ids.map(i => nameOf(cg.tenant, i)).join(' → ')}
                </div>
                <div className="text-xs text-slate-600 mt-1">
                  {scheduleText(d, t as any)}
                  {st && d.enabled && st.next_run_at && <> · {t('fleet.groups.nextRun')}: <b>{new Date(st.next_run_at).toLocaleString()}</b></>}
                </div>
                {st && (
                  <div className="text-xs text-slate-500">
                    {t('fleet.groups.lastRun')}:{' '}
                    {st.last_status ? (
                      <>
                        {t(`fleet.actions.status.${st.last_status}`)}
                        {st.last_counts && ` · ${t('fleet.actions.counts', { ok: st.last_counts.ok ?? 0, error: st.last_counts.error ?? 0, skipped: st.last_counts.skipped ?? 0 })}`}
                        {st.last_run_at && <> · {new Date(st.last_run_at).toLocaleString()}</>}
                      </>
                    ) : t('fleet.groups.never')}
                    {st.last_note?.startsWith('missed') && <div className="text-amber-800">{t('fleet.groups.missed')}</div>}
                    {st.last_note?.startsWith('error') && <div className="text-red-700">{st.last_note}</div>}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1">
                <Button size="sm" variant="secondary"
                  onClick={() => {
                    if (window.confirm(t('fleet.groups.runConfirm', { name: cg.name, count: d.device_ids.length }) as string)) {
                      act(() => centralApi.fleetGroupRun(cg.id), t('fleetCentral.runQueued') as string)
                    }
                  }}>
                  <Play size={12} /> {t('fleet.groups.runNow')}
                </Button>
                <Button size="sm" variant="ghost" disabled={!!editing}
                  onClick={() => { setError(null); setNotice(null); setEditing({ tenant: cg.tenant, id: cg.id, value: input }) }}><Pencil size={12} /></Button>
                <Button size="sm" variant="ghost"
                  onClick={() => { if (window.confirm(t('fleet.groups.deleteConfirm', { name: cg.name }) as string)) act(() => centralApi.fleetGroupDelete(cg.id), t('fleetCentral.groupDeleted') as string) }}>
                  <Trash2 size={12} />
                </Button>
              </div>
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { centralApi, centralConfig, type AlertChannel, type AlertRule, type AlertHistoryEntry, type EdgeDevice, type EdgeEvent, type CentralSupplyChainStatus, type CentralSupplyChainToolSummary, type CentralLinuxHostStatus } from '../lib/api'

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function ChannelsPanel({ onChange }: { onChange: () => void }) {
  const { t } = useTranslation()
  const [channels, setChannels] = useState<AlertChannel[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [testing, setTesting] = useState<number | null>(null)
  const [testResult, setTestResult] = useState<{ id: number; ok: boolean; msg: string } | null>(null)

  // Form state
  const [name, setName] = useState('')
  const [type, setType] = useState<'telegram' | 'webhook'>('telegram')
  const [botToken, setBotToken] = useState('')
  const [chatId, setChatId] = useState('')
  const [url, setUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const reload = async () => {
    setLoading(true)
    try {
      const r = await centralApi.alertChannels()
      setChannels(r.channels ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { reload() }, [])

  const submit = async () => {
    setSubmitting(true)
    try {
      const config = type === 'telegram'
        ? { bot_token: botToken.trim(), chat_id: chatId.trim() }
        : { url: url.trim() }
      await centralApi.alertChannelAdd({ name: name.trim(), type, config })
      setShowForm(false)
      setName(''); setBotToken(''); setChatId(''); setUrl('')
      await reload()
      onChange()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  const test = async (id: number) => {
    setTesting(id)
    setTestResult(null)
    try {
      const r = await centralApi.alertChannelTest(id)
      setTestResult({
        id,
        ok: r.result.ok,
        msg: r.result.ok ? t('alerts.testOk') : (r.result.error ?? t('alerts.testFailed')),
      })
    } catch (e) {
      setTestResult({ id, ok: false, msg: (e as Error).message })
    } finally {
      setTesting(null)
    }
  }

  const del = async (id: number, name: string) => {
    if (!confirm(t('alerts.confirmDeleteChannel', { name }) as string)) return
    try {
      await centralApi.alertChannelDelete(id)
      await reload()
      onChange()
    } catch (e) {
      alert((e as Error).message)
    }
  }

  const toggle = async (id: number) => {
    try {
      await centralApi.alertChannelToggle(id)
      await reload()
    } catch (e) {
      alert((e as Error).message)
    }
  }

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-slate-900">{t('alerts.channelsTitle')}</h3>
        <button onClick={() => setShowForm(v => !v)}
          className="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700">
          {showForm ? t('common.cancel') : `+ ${t('alerts.addChannel')}`}
        </button>
      </div>

      {showForm && (
        <div className="border border-slate-200 rounded p-3 space-y-2 bg-slate-50">
          <div className="grid grid-cols-2 gap-2">
            <label className="text-sm">
              <span className="text-slate-600">{t('alerts.channelName')}</span>
              <input value={name} onChange={e => setName(e.target.value)}
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1" />
            </label>
            <label className="text-sm">
              <span className="text-slate-600">{t('alerts.channelType')}</span>
              <select value={type} onChange={e => setType(e.target.value as any)}
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1">
                <option value="telegram">Telegram</option>
                <option value="webhook">Webhook</option>
              </select>
            </label>
          </div>
          {type === 'telegram' ? (
            <div className="grid grid-cols-2 gap-2">
              <label className="text-sm">
                <span className="text-slate-600">Bot token</span>
                <input value={botToken} onChange={e => setBotToken(e.target.value)}
                  placeholder="123456:ABC-..."
                  className="w-full mt-1 border border-slate-300 rounded px-2 py-1 font-mono text-xs" />
              </label>
              <label className="text-sm">
                <span className="text-slate-600">Chat ID</span>
                <input value={chatId} onChange={e => setChatId(e.target.value)}
                  placeholder="-1001234567890"
                  className="w-full mt-1 border border-slate-300 rounded px-2 py-1 font-mono text-xs" />
              </label>
            </div>
          ) : (
            <label className="text-sm block">
              <span className="text-slate-600">URL</span>
              <input value={url} onChange={e => setUrl(e.target.value)}
                placeholder="https://hooks.example.com/..."
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1 font-mono text-xs" />
            </label>
          )}
          <div className="text-xs text-slate-500">
            {type === 'telegram' ? t('alerts.telegramHint') : t('alerts.webhookHint')}
          </div>
          <button onClick={submit} disabled={submitting || !name.trim()}
            className="px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">
            {submitting ? '...' : t('common.save')}
          </button>
        </div>
      )}

      {err && <div className="text-sm text-red-600">{err}</div>}
      {loading ? (
        <div className="text-sm text-slate-500">{t('common.loading')}</div>
      ) : channels.length === 0 ? (
        <div className="text-sm text-slate-500">{t('alerts.noChannels')}</div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-slate-500 border-b">
              <th className="py-1">{t('alerts.channelName')}</th>
              <th>{t('alerts.channelType')}</th>
              <th>{t('alerts.channelDetail')}</th>
              <th>{t('alerts.channelStatus')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {channels.map(c => (
              <tr key={c.id} className="border-b border-slate-100">
                <td className="py-2">{c.name}</td>
                <td className="capitalize">{c.type}</td>
                <td className="font-mono text-xs">
                  {c.type === 'telegram'
                    ? `chat ${c.config.chat_id ?? '?'} · token ${c.config.bot_token_suffix ?? ''}`
                    : c.config.url_host ?? ''}
                </td>
                <td>
                  <button onClick={() => toggle(c.id)}
                    className={`text-xs px-2 py-0.5 rounded ${c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}`}>
                    {c.enabled ? t('alerts.enabled') : t('alerts.disabled')}
                  </button>
                </td>
                <td className="text-right space-x-2">
                  <button onClick={() => test(c.id)} disabled={testing === c.id}
                    className="text-xs text-indigo-600 hover:underline disabled:opacity-50">
                    {testing === c.id ? '...' : t('alerts.test')}
                  </button>
                  <button onClick={() => del(c.id, c.name)}
                    className="text-xs text-red-600 hover:underline">
                    {t('common.delete')}
                  </button>
                  {testResult?.id === c.id && (
                    <span className={`text-xs ml-2 ${testResult.ok ? 'text-green-600' : 'text-red-600'}`}>
                      {testResult.msg}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}


function RulesPanel({ channels, tenants }: { channels: AlertChannel[]; tenants: string[] }) {
  const { t } = useTranslation()
  const [rules, setRules] = useState<AlertRule[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)

  const [name, setName] = useState('')
  const [tenant, setTenant] = useState('')
  const [eventType, setEventType] = useState('failed_logins')
  const [minCount, setMinCount] = useState(5)
  const [cooldownMin, setCooldownMin] = useState(60)
  const [selectedChannels, setSelectedChannels] = useState<number[]>([])
  const [submitting, setSubmitting] = useState(false)

  const reload = async () => {
    setLoading(true)
    try {
      const r = await centralApi.alertRules()
      setRules(r.rules ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { reload() }, [])

  const submit = async () => {
    if (selectedChannels.length === 0) { alert(t('alerts.selectChannel')); return }
    setSubmitting(true)
    try {
      await centralApi.alertRuleAdd({
        name: name.trim() || undefined,
        tenant: tenant || undefined,
        event_type: eventType,
        min_count: minCount,
        cooldown_sec: cooldownMin * 60,
        channel_ids: selectedChannels,
      })
      setShowForm(false)
      setName(''); setTenant(''); setMinCount(5); setCooldownMin(60); setSelectedChannels([])
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  const del = async (id: number) => {
    if (!confirm(t('alerts.confirmDeleteRule') as string)) return
    try { await centralApi.alertRuleDelete(id); await reload() }
    catch (e) { alert((e as Error).message) }
  }

  const toggle = async (id: number) => {
    try { await centralApi.alertRuleToggle(id); await reload() }
    catch (e) { alert((e as Error).message) }
  }

  const toggleChannel = (id: number) => {
    setSelectedChannels(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id])
  }

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-slate-900">{t('alerts.rulesTitle')}</h3>
        <button onClick={() => setShowForm(v => !v)} disabled={channels.length === 0}
          className="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50">
          {showForm ? t('common.cancel') : `+ ${t('alerts.addRule')}`}
        </button>
      </div>
      {channels.length === 0 && (
        <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded p-2">
          {t('alerts.needChannelFirst')}
        </div>
      )}

      {showForm && (
        <div className="border border-slate-200 rounded p-3 space-y-2 bg-slate-50">
          <div className="grid grid-cols-2 gap-2">
            <label className="text-sm">
              <span className="text-slate-600">{t('alerts.ruleName')}</span>
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder={t('alerts.ruleNamePlaceholder') as string}
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1" />
            </label>
            <label className="text-sm">
              <span className="text-slate-600">Tenant</span>
              <select value={tenant} onChange={e => setTenant(e.target.value)}
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1">
                <option value="">{t('alerts.allTenants')}</option>
                {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="text-slate-600">{t('alerts.eventType')}</span>
              <select value={eventType} onChange={e => setEventType(e.target.value)}
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1">
                <option value="failed_logins">{t('alerts.eventFailedLogins')}</option>
                <option value="firmware_available">{t('alerts.eventFirmwareAvailable')}</option>
                <option value="board_firmware_available">{t('alerts.eventBoardFirmwareAvailable')}</option>
                <option value="device_rebooted">{t('alerts.eventDeviceRebooted')}</option>
                <option value="wan_ip_changed">{t('alerts.eventWanIpChanged')}</option>
                <option value="vuln_overdue">{t('alerts.eventVulnOverdue')}</option>
                <option value="tunnel_down">{t('alerts.eventTunnelDown')}</option>
                <option value="tunnel_up">{t('alerts.eventTunnelUp')}</option>
              </select>
            </label>
            <label className="text-sm">
              <span className="text-slate-600">{t('alerts.minCount')}</span>
              <input type="number" min={1} value={minCount} onChange={e => setMinCount(parseInt(e.target.value) || 1)}
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1" />
            </label>
            <label className="text-sm">
              <span className="text-slate-600">{t('alerts.cooldownMin')}</span>
              <input type="number" min={0} value={cooldownMin} onChange={e => setCooldownMin(parseInt(e.target.value) || 0)}
                className="w-full mt-1 border border-slate-300 rounded px-2 py-1" />
            </label>
          </div>
          <div>
            <div className="text-sm text-slate-600 mb-1">{t('alerts.notifyVia')}</div>
            <div className="flex flex-wrap gap-2">
              {channels.filter(c => c.enabled).map(c => (
                <label key={c.id} className="text-sm flex items-center gap-1 px-2 py-1 border border-slate-300 rounded bg-white">
                  <input type="checkbox" checked={selectedChannels.includes(c.id)}
                    onChange={() => toggleChannel(c.id)} />
                  {c.name} <span className="text-xs text-slate-500">({c.type})</span>
                </label>
              ))}
            </div>
          </div>
          <button onClick={submit} disabled={submitting}
            className="px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">
            {submitting ? '...' : t('common.save')}
          </button>
        </div>
      )}

      {err && <div className="text-sm text-red-600">{err}</div>}
      {loading ? (
        <div className="text-sm text-slate-500">{t('common.loading')}</div>
      ) : rules.length === 0 ? (
        <div className="text-sm text-slate-500">{t('alerts.noRules')}</div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-slate-500 border-b">
              <th className="py-1">{t('alerts.ruleName')}</th>
              <th>Tenant</th>
              <th>{t('alerts.eventType')}</th>
              <th>{t('alerts.threshold')}</th>
              <th>{t('alerts.cooldown')}</th>
              <th>{t('alerts.notifyVia')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rules.map(r => (
              <tr key={r.id} className="border-b border-slate-100">
                <td className="py-2">{r.name || <em className="text-slate-400">bez nazwy</em>}</td>
                <td>{r.tenant || <span className="text-slate-400">{t('alerts.allTenants')}</span>}</td>
                <td>{r.event_type}</td>
                <td>≥ {r.min_count}</td>
                <td>{Math.round(r.cooldown_sec / 60)} min</td>
                <td className="text-xs">
                  {r.channel_ids.map(cid => {
                    const ch = channels.find(c => c.id === cid)
                    return ch?.name ?? `#${cid}`
                  }).join(', ')}
                </td>
                <td className="text-right space-x-2">
                  <button onClick={() => toggle(r.id)}
                    className={`text-xs px-2 py-0.5 rounded ${r.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}`}>
                    {r.enabled ? t('alerts.enabled') : t('alerts.disabled')}
                  </button>
                  <button onClick={() => del(r.id)} className="text-xs text-red-600 hover:underline">
                    {t('common.delete')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}


function HistoryPanel() {
  const { t } = useTranslation()
  const [history, setHistory] = useState<AlertHistoryEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)

  const reload = async () => {
    setLoading(true)
    try {
      const r = await centralApi.alertHistory(undefined, 100)
      setHistory(r.history ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    reload()
    const iv = setInterval(reload, 30000)
    return () => clearInterval(iv)
  }, [])

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-slate-900">{t('alerts.historyTitle')}</h3>
        <button onClick={reload} className="text-xs text-indigo-600 hover:underline">
          {t('common.refresh')}
        </button>
      </div>
      {err && <div className="text-sm text-red-600">{err}</div>}
      {loading && history.length === 0 ? (
        <div className="text-sm text-slate-500">{t('common.loading')}</div>
      ) : history.length === 0 ? (
        <div className="text-sm text-slate-500">{t('alerts.noHistory')}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500 border-b">
                <th className="py-1">{t('alerts.time')}</th>
                <th>Tenant</th>
                <th>{t('alerts.eventType')}</th>
                <th>{t('alerts.device')}</th>
                <th>{t('alerts.details')}</th>
                <th>{t('alerts.deliveryStatus')}</th>
              </tr>
            </thead>
            <tbody>
              {history.map(h => {
                const ev = h.event_data
                const okCount = Object.values(h.notifications_result ?? {}).filter(r => r.ok).length
                const total = Object.keys(h.notifications_result ?? {}).length
                return (
                  <tr key={h.id} className="border-b border-slate-100 align-top">
                    <td className="py-2 whitespace-nowrap text-xs">{formatDate(h.triggered_at)}</td>
                    <td>{h.tenant}</td>
                    <td>{h.event_type}</td>
                    <td className="text-xs">{ev.device_name ?? ev.device_ip ?? '?'}</td>
                    <td className="text-xs text-slate-600">
                      {ev.count !== undefined && <>× {ev.count}</>}
                      {ev.sources && ev.sources.length > 0 && (
                        <div className="font-mono">{ev.sources.slice(0, 3).join(', ')}</div>
                      )}
                    </td>
                    <td className="text-xs">
                      <span className={okCount === total ? 'text-green-600' : okCount > 0 ? 'text-amber-600' : 'text-red-600'}>
                        {okCount}/{total}
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}


function formatDuration(sec: number | null): string {
  if (sec === null) return '—'
  if (sec < 60) return `${sec}s`
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  return `${h}h ${m}m`
}


function EdgeMonitoringPanel({ channels, tenants }: { channels: AlertChannel[]; tenants: string[] }) {
  const { t } = useTranslation()
  const [devices, setDevices] = useState<EdgeDevice[]>([])
  const [events, setEvents] = useState<EdgeEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState<number | null>(null)
  const [editing, setEditing] = useState<Record<number, { port: string; interval: string; channels: number[] }>>({})

  const [showAddForm, setShowAddForm] = useState(false)
  const [newTenant, setNewTenant] = useState('')
  const [newName, setNewName] = useState('')
  const [newIp, setNewIp] = useState('')
  const [newPort, setNewPort] = useState('')
  const [newInterval, setNewInterval] = useState(15)
  const [newChannels, setNewChannels] = useState<number[]>([])
  const [adding, setAdding] = useState(false)

  const reload = async () => {
    try {
      const [d, e] = await Promise.all([centralApi.edgeDevices(), centralApi.edgeEvents(undefined, 100)])
      setDevices(d.devices ?? [])
      setEvents(e.events ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    reload()
    const iv = setInterval(reload, 30000)
    return () => clearInterval(iv)
  }, [])

  const beginEdit = (d: EdgeDevice) => {
    setEditing(prev => ({
      ...prev,
      [d.id]: {
        port: d.check_port !== null ? String(d.check_port) : '',
        interval: String(Math.round(d.interval_sec / 60)),
        channels: [...d.channel_ids],
      },
    }))
  }

  const saveEdit = async (d: EdgeDevice) => {
    const e = editing[d.id]; if (!e) return
    setBusy(d.id)
    try {
      await centralApi.edgeDeviceUpdate({
        id: d.id,
        check_port: e.port.trim() === '' ? null : parseInt(e.port),
        interval_sec: Math.max(60, parseInt(e.interval) * 60),
        channel_ids: e.channels,
      })
      setEditing(prev => { const c = { ...prev }; delete c[d.id]; return c })
      await reload()
    } catch (err) {
      alert((err as Error).message)
    } finally {
      setBusy(null)
    }
  }

  const toggle = async (d: EdgeDevice) => {
    if (!d.enabled && d.channel_ids.length === 0) {
      alert(t('edge.needChannelBeforeEnable'))
      return
    }
    setBusy(d.id)
    try { await centralApi.edgeDeviceToggle(d.id); await reload() }
    catch (e) { alert((e as Error).message) }
    finally { setBusy(null) }
  }

  const checkNow = async (d: EdgeDevice) => {
    setBusy(d.id)
    try {
      const r = await centralApi.edgeDeviceCheckNow(d.id)
      await reload()
      const ok = r.result.ok
      const label = ok ? t('edge.checkOk') : t('edge.checkFail')
      alert(`${label}\n\n${r.result.detail}`)
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  const del = async (d: EdgeDevice) => {
    if (!confirm(t('edge.confirmDelete', { name: d.name }) as string)) return
    try { await centralApi.edgeDeviceDelete(d.id); await reload() }
    catch (e) { alert((e as Error).message) }
  }

  const toggleNewChannel = (id: number) => {
    setNewChannels(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id])
  }

  const addManual = async () => {
    if (!newTenant || !newName.trim() || !newIp.trim()) return
    if (newChannels.length === 0) { alert(t('edge.needChannelBeforeEnable')); return }
    setAdding(true)
    try {
      await centralApi.edgeDeviceAdd({
        tenant: newTenant,
        name: newName.trim(),
        ip: newIp.trim(),
        check_port: newPort.trim() === '' ? null : parseInt(newPort),
        interval_sec: Math.max(60, newInterval * 60),
        channel_ids: newChannels,
      })
      setShowAddForm(false)
      setNewTenant(''); setNewName(''); setNewIp(''); setNewPort(''); setNewInterval(15); setNewChannels([])
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setAdding(false)
    }
  }

  const statusBadge = (s: string) => {
    const cls = s === 'online' ? 'bg-green-100 text-green-700'
              : s === 'offline' ? 'bg-red-100 text-red-700'
              : 'bg-slate-100 text-slate-500'
    return <span className={`text-xs px-2 py-0.5 rounded ${cls}`}>{s}</span>
  }

  return (
    <>
      <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-slate-900">{t('edge.title')}</h3>
          <div className="flex items-center gap-3">
            <button onClick={() => setShowAddForm(v => !v)} disabled={channels.length === 0}
              className="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50">
              {showAddForm ? t('common.cancel') : `+ ${t('edge.addManual')}`}
            </button>
            <button onClick={reload} className="text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>
          </div>
        </div>
        <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded p-2">
          {t('edge.intro')}
        </div>
        {channels.length === 0 && (
          <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded p-2">
            {t('alerts.needChannelFirst')}
          </div>
        )}

        {showAddForm && (
          <div className="border border-slate-200 rounded p-3 space-y-2 bg-slate-50">
            <p className="text-xs text-slate-500">{t('edge.addManualHint')}</p>
            <div className="grid grid-cols-2 gap-2">
              <label className="text-sm">
                <span className="text-slate-600">Tenant</span>
                <select value={newTenant} onChange={e => setNewTenant(e.target.value)}
                  className="w-full mt-1 border border-slate-300 rounded px-2 py-1">
                  <option value="">{t('edge.selectTenant')}</option>
                  {tenants.map(tn => <option key={tn} value={tn}>{tn}</option>)}
                </select>
              </label>
              <label className="text-sm">
                <span className="text-slate-600">{t('edge.deviceName')}</span>
                <input value={newName} onChange={e => setNewName(e.target.value)}
                  placeholder={t('edge.deviceNamePlaceholder') as string}
                  className="w-full mt-1 border border-slate-300 rounded px-2 py-1" />
              </label>
              <label className="text-sm">
                <span className="text-slate-600">IP</span>
                <input value={newIp} onChange={e => setNewIp(e.target.value)}
                  placeholder="203.0.113.5"
                  className="w-full mt-1 border border-slate-300 rounded px-2 py-1 font-mono" />
              </label>
              <label className="text-sm">
                <span className="text-slate-600">{t('edge.port')} ({t('common.optional')})</span>
                <input value={newPort} onChange={e => setNewPort(e.target.value.replace(/\D/g, ''))}
                  placeholder="80"
                  className="w-full mt-1 border border-slate-300 rounded px-2 py-1" />
              </label>
              <label className="text-sm">
                <span className="text-slate-600">{t('edge.interval')} (min)</span>
                <input type="number" min={1} value={newInterval} onChange={e => setNewInterval(parseInt(e.target.value) || 1)}
                  className="w-full mt-1 border border-slate-300 rounded px-2 py-1" />
              </label>
            </div>
            <div>
              <div className="text-sm text-slate-600 mb-1">{t('alerts.notifyVia')}</div>
              <div className="flex flex-wrap gap-2">
                {channels.filter(c => c.enabled).map(c => (
                  <label key={c.id} className="text-sm flex items-center gap-1 px-2 py-1 border border-slate-300 rounded bg-white">
                    <input type="checkbox" checked={newChannels.includes(c.id)}
                      onChange={() => toggleNewChannel(c.id)} />
                    {c.name} <span className="text-xs text-slate-500">({c.type})</span>
                  </label>
                ))}
              </div>
            </div>
            <button onClick={addManual} disabled={adding || !newTenant || !newName.trim() || !newIp.trim()}
              className="px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">
              {adding ? '...' : t('common.save')}
            </button>
          </div>
        )}
        {err && <div className="text-sm text-red-600">{err}</div>}
        {loading ? (
          <div className="text-sm text-slate-500">{t('common.loading')}</div>
        ) : devices.length === 0 ? (
          <div className="text-sm text-slate-500">{t('edge.noDevices')}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b">
                  <th className="py-1">Tenant</th>
                  <th>{t('edge.deviceName')}</th>
                  <th>IP</th>
                  <th>WAN</th>
                  <th>{t('edge.status')}</th>
                  <th>{t('edge.lastCheck')}</th>
                  <th>{t('edge.interval')}</th>
                  <th>{t('edge.port')}</th>
                  <th>{t('alerts.notifyVia')}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {devices.map(d => {
                  const e = editing[d.id]
                  return (
                    <tr key={d.id} className="border-b border-slate-100 align-top">
                      <td className="py-2">{d.tenant}</td>
                      <td>
                        {d.name}
                        {d.source === 'manual' && (
                          <span className="ml-1 text-[10px] text-purple-600">(manual)</span>
                        )}
                      </td>
                      <td className="font-mono text-xs">{d.ip}</td>
                      <td className="text-xs text-slate-500">
                        {d.source_device_name && <div>{d.source_device_name}</div>}
                        {d.source_iface && <div className="font-mono">{d.source_iface}</div>}
                      </td>
                      <td>
                        {statusBadge(d.last_status)}
                        {d.last_check_detail && (
                          <div className="text-[10px] text-slate-400 mt-0.5 max-w-[220px]" title={d.last_check_detail}>
                            {d.last_check_detail}
                          </div>
                        )}
                      </td>
                      <td className="text-xs text-slate-500">{d.last_check ? new Date(d.last_check).toLocaleString() : '—'}</td>
                      <td>
                        {e ? (
                          <input type="number" min={1} value={e.interval}
                            onChange={ev => setEditing(p => ({...p, [d.id]: {...e, interval: ev.target.value}}))}
                            className="w-14 border border-slate-300 rounded px-1 py-0.5 text-xs" />
                        ) : (
                          <span className="text-xs">{Math.round(d.interval_sec / 60)} min</span>
                        )}
                      </td>
                      <td>
                        {e ? (
                          <input type="number" placeholder="ICMP" value={e.port}
                            onChange={ev => setEditing(p => ({...p, [d.id]: {...e, port: ev.target.value}}))}
                            className="w-16 border border-slate-300 rounded px-1 py-0.5 text-xs" />
                        ) : (
                          <span className="text-xs">{d.check_port ?? 'ICMP'}</span>
                        )}
                      </td>
                      <td className="text-xs">
                        {e ? (
                          <div className="flex flex-wrap gap-1">
                            {channels.filter(c => c.enabled).map(c => (
                              <label key={c.id} className="flex items-center gap-0.5 px-1 border rounded">
                                <input type="checkbox" checked={e.channels.includes(c.id)}
                                  onChange={() => setEditing(p => ({
                                    ...p, [d.id]: {
                                      ...e,
                                      channels: e.channels.includes(c.id) ? e.channels.filter(x=>x!==c.id) : [...e.channels, c.id]
                                    }
                                  }))} />
                                {c.name}
                              </label>
                            ))}
                          </div>
                        ) : (
                          d.channel_ids.map(cid => channels.find(c=>c.id===cid)?.name ?? `#${cid}`).join(', ') || <em className="text-slate-400">—</em>
                        )}
                      </td>
                      <td className="text-right space-x-1 whitespace-nowrap">
                        {e ? (
                          <>
                            <button onClick={() => saveEdit(d)} disabled={busy === d.id}
                              className="text-xs text-green-600 hover:underline">{t('common.save')}</button>
                            <button onClick={() => setEditing(p => { const c={...p}; delete c[d.id]; return c })}
                              className="text-xs text-slate-500 hover:underline">{t('common.cancel')}</button>
                          </>
                        ) : (
                          <>
                            <button onClick={() => toggle(d)} disabled={busy === d.id}
                              className={`text-xs px-2 py-0.5 rounded ${d.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}`}>
                              {d.enabled ? t('alerts.enabled') : t('alerts.disabled')}
                            </button>
                            <button onClick={() => beginEdit(d)} className="text-xs text-indigo-600 hover:underline">{t('common.edit')}</button>
                            <button onClick={() => checkNow(d)} disabled={busy === d.id}
                              className="text-xs text-indigo-600 hover:underline">{t('edge.checkNow')}</button>
                            {d.source === 'manual' && (
                              <button onClick={() => del(d)} className="text-xs text-red-600 hover:underline">{t('common.delete')}</button>
                            )}
                          </>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
        <h3 className="font-semibold text-slate-900">{t('edge.eventsTitle')}</h3>
        {events.length === 0 ? (
          <div className="text-sm text-slate-500">{t('edge.noEvents')}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b">
                  <th className="py-1">{t('alerts.time')}</th>
                  <th>Tenant</th>
                  <th>{t('edge.deviceName')}</th>
                  <th>IP</th>
                  <th>{t('edge.event')}</th>
                  <th>{t('edge.duration')}</th>
                </tr>
              </thead>
              <tbody>
                {events.map(ev => (
                  <tr key={ev.id} className="border-b border-slate-100">
                    <td className="py-1 text-xs whitespace-nowrap">{new Date(ev.ts).toLocaleString()}</td>
                    <td>{ev.tenant}</td>
                    <td>{ev.device_name}</td>
                    <td className="font-mono text-xs">{ev.device_ip}</td>
                    <td>{statusBadge(ev.event_type)}</td>
                    <td className="text-xs">{formatDuration(ev.duration_sec)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}


function ToolBadge({ label, res }: { label: string; res: CentralSupplyChainToolSummary | undefined | null }) {
  if (!res) return <span className="text-xs text-slate-400">—</span>
  if (res.ok === false) {
    return <span className="text-xs px-1.5 py-0.5 rounded bg-red-100 text-red-700" title={res.error ?? ''}>{label}: {'×'}</span>
  }
  const cls = res.count > 0 ? 'bg-amber-100 text-amber-700' : 'bg-green-100 text-green-700'
  return <span className={`text-xs px-1.5 py-0.5 rounded ${cls}`}>{label}: {res.count}</span>
}

// PHP (Centrala's own ovh/*.php code) is intentionally only scanned on
// whichever agent happens to have a PHP CLI installed — most agents won't,
// and that's expected, not an error. A red "×" there would look like every
// other tenant is broken; render that specific case as a neutral "n/a"
// instead, matching the local Security page's same distinction.
function PhpToolBadge({ res }: { res: CentralSupplyChainToolSummary | undefined | null }) {
  if (!res) return <span className="text-xs text-slate-400">—</span>
  if (res.ok === false) {
    const notInstalled = (res.error ?? '').includes('not found on PATH')
    if (notInstalled) {
      return <span className="text-xs text-slate-400" title={res.error ?? ''}>{'n/a'}</span>
    }
    return <span className="text-xs px-1.5 py-0.5 rounded bg-red-100 text-red-700" title={res.error ?? ''}>{'PHP: ×'}</span>
  }
  const cls = res.count > 0 ? 'bg-amber-100 text-amber-700' : 'bg-green-100 text-green-700'
  return <span className={`text-xs px-1.5 py-0.5 rounded ${cls}`}>{'PHP'}: {res.count}</span>
}

function SupplyChainCentralPanel() {
  const { t } = useTranslation()
  const [rows, setRows] = useState<Array<{ tenant: string; last_seen: string | null; age_sec: number | null; supply_chain_status: CentralSupplyChainStatus | null }>>([])
  const [pending, setPending] = useState<Array<{ tenant: string; queued_at: string }>>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const reload = async () => {
    try {
      const [s, p] = await Promise.all([centralApi.supplyChainStatusAll(), centralApi.pendingSupplyChainScans()])
      setRows(s.tenants ?? [])
      setPending(p.pending ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    reload()
    const iv = setInterval(reload, 30000)
    return () => clearInterval(iv)
  }, [])

  const pendingSet = new Set(pending.map(p => p.tenant))

  const scanNow = async (tenant: string) => {
    setBusy(tenant)
    try {
      await centralApi.requestSupplyChainScan(tenant)
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-slate-900">{t('supplyChainCentral.title')}</h3>
        <button onClick={reload} className="text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>
      </div>
      <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded p-2">
        {t('supplyChainCentral.intro')}
      </div>
      {err && <div className="text-sm text-red-600">{err}</div>}
      {loading ? (
        <div className="text-sm text-slate-500">{t('common.loading')}</div>
      ) : rows.length === 0 ? (
        <div className="text-sm text-slate-500">{t('supplyChainCentral.noTenants')}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500 border-b">
                <th className="py-1">Tenant</th>
                <th>{t('supplyChainCentral.lastScan')}</th>
                <th>pip</th>
                <th>npm</th>
                <th>Bandit</th>
                <th>ESLint</th>
                <th title={t('supplyChainCentral.phpHint') as string}>{t('supplyChainCentral.phpColumn')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => {
                const sc = r.supply_chain_status
                const queued = pendingSet.has(r.tenant)
                return (
                  <tr key={r.tenant} className="border-b border-slate-100">
                    <td className="py-2">{r.tenant}</td>
                    <td className="text-xs text-slate-500">
                      {sc?.last_run ? new Date(sc.last_run).toLocaleString() : t('supplyChainCentral.neverScanned')}
                    </td>
                    <td><ToolBadge label="pip" res={sc?.pip} /></td>
                    <td><ToolBadge label="npm" res={sc?.npm} /></td>
                    <td><ToolBadge label="Bandit" res={sc?.bandit} /></td>
                    <td><ToolBadge label="ESLint" res={sc?.eslint} /></td>
                    <td><PhpToolBadge res={sc?.php} /></td>
                    <td className="text-right">
                      {queued ? (
                        <span className="text-xs px-2 py-0.5 rounded bg-amber-100 text-amber-700">{t('supplyChainCentral.queued')}</span>
                      ) : (
                        <button onClick={() => scanNow(r.tenant)} disabled={busy === r.tenant}
                          className="text-xs text-indigo-600 hover:underline">
                          {t('supplyChainCentral.scanNow')}
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}


function LinuxCentralPanel() {
  const { t } = useTranslation()
  const [rows, setRows] = useState<Array<{ tenant: string; host: CentralLinuxHostStatus }>>([])
  const [pendingScans, setPendingScans] = useState<Array<{ tenant: string; queued_at: string }>>([])
  const [pendingUpgrades, setPendingUpgrades] = useState<Array<{ tenant: string; host_id: number; queued_at: string }>>([])
  const [tenants, setTenants] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [busyScan, setBusyScan] = useState<string | null>(null)
  const [busyUpgrade, setBusyUpgrade] = useState<string | null>(null)

  const reload = async () => {
    try {
      const [s, ps, pu] = await Promise.all([
        centralApi.linuxHostsStatusAll(),
        centralApi.pendingLinuxScans(),
        centralApi.pendingLinuxAptUpgrades(),
      ])
      const flat: Array<{ tenant: string; host: CentralLinuxHostStatus }> = []
      for (const tRow of s.tenants) {
        for (const h of tRow.linux_hosts) flat.push({ tenant: tRow.tenant, host: h })
      }
      setRows(flat)
      setTenants(s.tenants.map(tRow => tRow.tenant))
      setPendingScans(ps.pending ?? [])
      setPendingUpgrades(pu.pending ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    reload()
    const iv = setInterval(reload, 30000)
    return () => clearInterval(iv)
  }, [])

  const scanPendingSet = new Set(pendingScans.map(p => p.tenant))
  const upgradePendingSet = new Set(pendingUpgrades.map(p => `${p.tenant}:${p.host_id}`))

  const scanNow = async (tenant: string) => {
    setBusyScan(tenant)
    try { await centralApi.requestLinuxScan(tenant); await reload() }
    catch (e) { alert((e as Error).message) }
    finally { setBusyScan(null) }
  }

  const scanAll = async () => {
    const targets = tenants.filter(tn => !scanPendingSet.has(tn))
    if (targets.length === 0) return
    setBusyScan('__all__')
    try {
      // Fan out to every connected tenant's agent — each just writes an
      // OVH-side marker file, so firing them concurrently is safe (no
      // shared state between tenants to race on).
      await Promise.all(targets.map(tn => centralApi.requestLinuxScan(tn)))
      await reload()
    } catch (e) {
      alert((e as Error).message)
    } finally {
      setBusyScan(null)
    }
  }

  const upgradeNow = async (tenant: string, hostId: number) => {
    const key = `${tenant}:${hostId}`
    setBusyUpgrade(key)
    try { await centralApi.requestLinuxAptUpgrade(tenant, hostId); await reload() }
    catch (e) { alert((e as Error).message) }
    finally { setBusyUpgrade(null) }
  }

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-slate-900">{t('linuxCentral.title')}</h3>
        <button onClick={reload} className="text-xs text-indigo-600 hover:underline">{t('common.refresh')}</button>
      </div>
      <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded p-2">
        {t('linuxCentral.intro')}
      </div>
      {err && <div className="text-sm text-red-600">{err}</div>}

      {tenants.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={scanAll} disabled={busyScan !== null}
            className="text-xs px-2.5 py-1 rounded bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">
            {t('linuxCentral.scanAll', { count: tenants.length })}
          </button>
          <span className="text-slate-300">|</span>
          {tenants.map(tn => {
            const queued = scanPendingSet.has(tn)
            return (
              <button key={tn} onClick={() => scanNow(tn)} disabled={busyScan === tn || busyScan === '__all__' || queued}
                className={`text-xs px-2 py-1 rounded border ${queued ? 'bg-amber-100 text-amber-700 border-amber-200' : 'border-slate-300 text-indigo-600 hover:bg-indigo-50'}`}>
                {queued ? t('linuxCentral.scanQueued', { tenant: tn }) : t('linuxCentral.scanTenant', { tenant: tn })}
              </button>
            )
          })}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-slate-500">{t('common.loading')}</div>
      ) : rows.length === 0 ? (
        <div className="text-sm text-slate-500">{t('linuxCentral.noHosts')}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500 border-b">
                <th className="py-1">Tenant</th>
                <th>Host</th>
                <th>{t('linuxCentral.distro')}</th>
                <th>{t('linuxCentral.pending')}</th>
                <th>{t('linuxCentral.lastUpgrade')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ tenant, host }) => {
                const queued = upgradePendingSet.has(`${tenant}:${host.id}`)
                return (
                  <tr key={`${tenant}:${host.id}`} className="border-b border-slate-100">
                    <td className="py-2">{tenant}</td>
                    <td className="font-mono text-xs">{host.hostname || host.ip}</td>
                    <td className="text-xs text-slate-500">{host.distro_pretty ?? '—'}</td>
                    <td>
                      {host.upgradable_count != null ? (
                        <span className={`text-xs px-1.5 py-0.5 rounded ${host.upgradable_count > 0 ? 'bg-amber-100 text-amber-700' : 'bg-green-100 text-green-700'}`}>
                          {host.upgradable_count}
                        </span>
                      ) : <span className="text-xs text-slate-400">—</span>}
                      {host.reboot_required && (
                        <span className="ml-1 text-xs px-1.5 py-0.5 rounded bg-red-100 text-red-700">{t('linuxCentral.rebootRequired')}</span>
                      )}
                    </td>
                    <td className="text-xs text-slate-500">{host.last_upgrade_at ? new Date(host.last_upgrade_at).toLocaleString() : '—'}</td>
                    <td className="text-right">
                      {queued ? (
                        <span className="text-xs px-2 py-0.5 rounded bg-amber-100 text-amber-700">{t('linuxCentral.queued')}</span>
                      ) : (
                        <button onClick={() => upgradeNow(tenant, host.id)} disabled={busyUpgrade === `${tenant}:${host.id}`}
                          className="text-xs text-indigo-600 hover:underline">
                          {t('linuxCentral.upgradeNow')}
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}


export function AlertsPanel() {
  const { t } = useTranslation()
  const [channels, setChannels] = useState<AlertChannel[]>([])
  const [tenants, setTenants] = useState<string[]>([])
  const [err, setErr] = useState<string | null>(null)
  const cfg = centralConfig.load()

  const loadShared = async () => {
    try {
      const [chRes, tRes] = await Promise.all([
        centralApi.alertChannels(),
        centralApi.tenants(),
      ])
      setChannels(chRes.channels ?? [])
      setTenants((tRes.tenants ?? []).map(x => x.id))
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  useEffect(() => {
    if (cfg) loadShared()
  }, [])

  if (!cfg) {
    return (
      <div className="bg-amber-50 border border-amber-200 rounded p-4 text-sm text-amber-800">
        {t('alerts.needsCentral')}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {err && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-700">{err}</div>
      )}
      <div className="text-sm text-slate-600 bg-slate-50 border border-slate-200 rounded p-3">
        {t('alerts.intro')}
      </div>
      <ChannelsPanel onChange={loadShared} />
      <RulesPanel channels={channels} tenants={tenants} />
      <EdgeMonitoringPanel channels={channels} tenants={tenants} />
      <SupplyChainCentralPanel />
      <LinuxCentralPanel />
      <HistoryPanel />
    </div>
  )
}

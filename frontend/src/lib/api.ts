import axios from 'axios'

export const api = axios.create({ baseURL: '/api', withCredentials: true })

api.interceptors.response.use(
  r => r,
  err => {
    if (err?.response?.status === 401 && !err.config?.url?.startsWith('/auth/')) {
      window.location.reload()
    }
    return Promise.reject(err)
  },
)

// ── Auth types ───────────────────────────────────────────────────────────────

export interface AuthStatus {
  configured: boolean
  mfa_setup_pending: boolean
}

export interface MfaSetupInfo {
  secret: string
  otpauth_uri: string
  qr_svg_data_uri: string
}

export const authApi = {
  status: () => api.get<AuthStatus>('/auth/status').then(r => r.data),
  setup: (username: string, password: string, totpSecret?: string) =>
    api.post<MfaSetupInfo>('/auth/setup', { username, password, totp_secret: totpSecret || undefined }).then(r => r.data),
  setupResume: (username: string, password: string) =>
    api.post<MfaSetupInfo>('/auth/setup/resume', { username, password }).then(r => r.data),
  mfaConfirm: (code: string) => api.post('/auth/mfa/confirm', { code }).then(r => r.data),
  login: (username: string, password: string, totp_code: string) =>
    api.post('/auth/login', { username, password, totp_code }).then(r => r.data),
  logout: () => api.post('/auth/logout').then(r => r.data),
  me: () => api.get<{ username: string }>('/auth/me').then(r => r.data),
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface Credential {
  id: number
  name: string
  username: string
  description?: string
  has_snmp: boolean
}

export interface Device {
  id: number
  ip: string
  name?: string
  mac?: string
  model?: string
  ros_version?: string
  board_name?: string
  identity?: string
  api_port: number
  ssh_port: number
  web_port: number
  has_api: boolean
  has_ssh: boolean
  has_web: boolean
  has_snmp: boolean
  snmp_port: number
  vendor?: string  // 'mikrotik' | 'cisco-sb' | 'generic-snmp' | 'cisco-generic'
  credential_id?: number
  last_seen?: string
  online: boolean
  notes?: string
  x_pos: number
  y_pos: number
}

export interface ScanRange {
  id: number
  cidr: string
  label?: string
  active: boolean
}

// ── Credentials ──────────────────────────────────────────────────────────────

export interface CredentialInput {
  name: string
  username: string
  password: string
  snmp_community?: string
  description?: string
}

export const credentialsApi = {
  list: () => api.get<Credential[]>('/credentials').then(r => r.data),
  create: (data: CredentialInput) => api.post<Credential>('/credentials', data).then(r => r.data),
  update: (id: number, data: CredentialInput) =>
    api.put<Credential>(`/credentials/${id}`, data).then(r => r.data),
  delete: (id: number) => api.delete(`/credentials/${id}`),
}

// ── Devices ──────────────────────────────────────────────────────────────────

export const devicesApi = {
  list: () => api.get<Device[]>('/devices').then(r => r.data),
  get: (id: number) => api.get<Device>(`/devices/${id}`).then(r => r.data),
  create: (data: Partial<Device>) => api.post<Device>('/devices', data).then(r => r.data),
  update: (id: number, data: Partial<Device>) => api.put<Device>(`/devices/${id}`, data).then(r => r.data),
  delete: (id: number) => api.delete(`/devices/${id}`),
  interfaces: (id: number) => api.get(`/devices/${id}/interfaces`).then(r => r.data),
  addresses: (id: number) => api.get(`/devices/${id}/addresses`).then(r => r.data),
  routes: (id: number) => api.get(`/devices/${id}/routes`).then(r => r.data),
  neighbors: (id: number) => api.get(`/devices/${id}/neighbors`).then(r => r.data),
  firewall: (id: number) => api.get(`/devices/${id}/firewall`).then(r => r.data),
  wireless: (id: number) => api.get(`/devices/${id}/wireless`).then(r => r.data),
  dhcpLeases: (id: number) => api.get(`/devices/${id}/dhcp-leases`).then(r => r.data),
  tunnels: (id: number) => api.get(`/devices/${id}/tunnels`).then(r => r.data),
  resource: (id: number) => api.get(`/devices/${id}/resource`).then(r => r.data),
  // Firmware
  firmwareCheck: (id: number) => api.post(`/devices/${id}/firmware/check`).then(r => r.data),
  firmwareUpgrade: (id: number, backup: boolean = false) =>
    api.post(`/devices/${id}/firmware/upgrade`, null, { params: { backup } }).then(r => r.data),
  firmwareStatus: (id: number) => api.get(`/devices/${id}/firmware/status`).then(r => r.data),
  firmwareBackup: (id: number) => api.post(`/devices/${id}/firmware/backup`).then(r => r.data),
  firmwareUpgradeBulk: (ids: number[], backup: boolean = false) =>
    api.post('/devices/firmware/upgrade-bulk', { ids, backup }).then(r => r.data),
  firmwareStatuses: (ids: number[]) =>
    api.get(`/devices/firmware/statuses`, { params: { ids: ids.join(',') } }).then(r => r.data),
  backups: (id: number) => api.get(`/devices/${id}/backups`).then(r => r.data),
}

// ── Scanner ──────────────────────────────────────────────────────────────────

export const scannerApi = {
  listRanges: () => api.get<ScanRange[]>('/scanner/ranges').then(r => r.data),
  addRange: (data: { cidr: string; label?: string }) =>
    api.post<ScanRange>('/scanner/ranges', data).then(r => r.data),
  deleteRange: (id: number) => api.delete(`/scanner/ranges/${id}`),
}

// ── System (refresher) ───────────────────────────────────────────────────────

export interface RefreshStatus {
  interval_min: number
  in_progress: boolean
  last_run: string | null
  last_duration_sec: number | null
  devices_checked_last: number
  devices_updated_last: number
  next_run_estimated: number | null  // epoch seconds
}

export interface TopologyNode {
  id: number
  ip: string
  name?: string
  identity?: string
  model?: string
  online: boolean
  x_pos: number
  y_pos: number
  has_api: boolean
  has_web: boolean
  has_ssh: boolean
  has_snmp: boolean
}

export interface TopologyLink {
  id: number
  a: number
  b: number
  iface_a?: string
  iface_b?: string
  type: string  // 'lldp'|'cdp'|'mndp'|'eoip'|'gre'|'vxlan'|'ipip'
  last_seen?: string
}

export interface Topology {
  nodes: TopologyNode[]
  links: TopologyLink[]
}

export interface VersionTarget {
  status: 'up_to_date' | 'outdated'
  current: string
  target: string
  channel: string
  released_at?: number | null
}

export interface DeviceVersionInfo {
  id: number
  ip: string
  name?: string
  identity?: string
  current?: string
  target: VersionTarget | null
}

export interface VersionFetchStatus {
  fetched_at: number
  age_sec: number | null
  last_error: string | null
  has_data: boolean
}

export interface VersionStatus {
  latest: Record<string, { channel: string; version: string; released_at?: number | null }>
  devices: DeviceVersionInfo[]
  fetch_status: VersionFetchStatus
}

export interface CriticalLogEntry {
  device_id: number
  device_ip: string
  device_label: string
  time?: string
  topics?: string
  message?: string
}

export interface UplinkStatus {
  enabled: boolean
  url: string
  tenant: string
  interval_sec: number
  has_api_key: boolean
  has_enc_key: boolean
  last_sent: string | null
  last_attempt: string | null
  last_error: string | null
  buffered_count: number
  total_sent: number
  total_failed: number
}

export interface SelfVersion {
  commit: string | null
  commit_time: number | null
  branch: string | null
}

export const systemApi = {
  refreshStatus: () => api.get<RefreshStatus>('/system/refresh/status').then(r => r.data),
  runRefresh: () => api.post('/system/refresh/run').then(r => r.data),
  topology: () => api.get<Topology>('/system/topology').then(r => r.data),
  discoverTopology: () => api.post('/system/topology/discover').then(r => r.data),
  versionStatus: () => api.get<VersionStatus>('/system/versions/status').then(r => r.data),
  refreshVersions: () => api.post<{ latest: VersionStatus['latest']; fetch_status: VersionFetchStatus }>('/system/versions/refresh').then(r => r.data),
  criticalLogs: (limit = 20) => api.get<CriticalLogEntry[]>('/system/critical-logs', { params: { limit } }).then(r => r.data),
  selfVersion: () => api.get<SelfVersion>('/system/self-version').then(r => r.data),
  uplinkStatus: () => api.get<UplinkStatus>('/system/uplink/status').then(r => r.data),
  uplinkConfigure: (data: { url: string; tenant: string; api_key: string; interval_sec: number; enc_key?: string }) =>
    api.post<UplinkStatus>('/system/uplink/config', data).then(r => r.data),
  uplinkSendNow: () => api.post<{ success: boolean; status: UplinkStatus }>('/system/uplink/send-now').then(r => r.data),
  uplinkGenerateEncKey: () => api.post<{ enc_key: string }>('/system/uplink/generate-enc-key').then(r => r.data),
}

// ── Central (viewer querying OVH directly) ───────────────────────────────────

export interface CentralTenant {
  id: string
  first_seen: string | null
  last_seen: string | null
  age_sec: number | null
  last_payload_bytes: number
  online: boolean
  notes?: string | null
  agent_commit?: string | null
  agent_commit_time?: number | null
}

export interface CentralTenantList {
  tenants: CentralTenant[]
  offline_threshold_sec: number
  server_time: string
}

// Central calls bypass our backend — they go directly to the OVH PHP API.
// Config is stored in localStorage.
const CENTRAL_LS = 'mikromanager_central'

export interface CentralConfig {
  apiUrl: string
  password: string
  // Per-tenant E2E decryption keys (base64). Map tenant id → key.
  // The server never has these. Without it, encrypted snapshots cannot be read.
  tenantKeys?: Record<string, string>
}

export const centralConfig = {
  load(): CentralConfig | null {
    try {
      const raw = localStorage.getItem(CENTRAL_LS)
      return raw ? JSON.parse(raw) : null
    } catch { return null }
  },
  save(cfg: CentralConfig) {
    localStorage.setItem(CENTRAL_LS, JSON.stringify(cfg))
  },
  setTenantKey(tenant: string, key: string) {
    const cfg = centralConfig.load()
    if (!cfg) return
    cfg.tenantKeys = { ...(cfg.tenantKeys ?? {}), [tenant]: key }
    centralConfig.save(cfg)
  },
  clear() {
    localStorage.removeItem(CENTRAL_LS)
  },
}

async function centralRequest<T>(
  action: string,
  params: Record<string, string> = {},
  opts: { method?: 'GET' | 'POST' | 'DELETE'; body?: any } = {},
): Promise<T> {
  const cfg = centralConfig.load()
  if (!cfg) throw new Error('Central not configured')

  const url = new URL('/api/system/central-proxy', window.location.origin)
  url.searchParams.set('upstream', cfg.apiUrl)
  url.searchParams.set('action', action)
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)

  const method = opts.method ?? 'GET'
  const headers: Record<string, string> = { Authorization: `Bearer ${cfg.password}` }
  let body: string | undefined
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }

  const resp = await fetch(url.toString(), { method, headers, body })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${await resp.text()}`)
  return resp.json()
}

// ── Alert + edge types ─────────────────────────────────────────────────────

export interface AlertChannel {
  id: number
  name: string
  type: 'telegram' | 'webhook'
  config: {
    chat_id?: string
    bot_token_set?: boolean
    bot_token_suffix?: string
    url_set?: boolean
    url_host?: string
  }
  enabled: number
  created_at: string
}

export interface AlertChannelInput {
  name: string
  type: 'telegram' | 'webhook'
  config: { bot_token?: string; chat_id?: string; url?: string }
}

export interface AlertRule {
  id: number
  name: string | null
  tenant: string | null
  event_type: string
  min_count: number
  cooldown_sec: number
  channel_ids: number[]
  enabled: number
  created_at: string
}

export interface AlertRuleInput {
  name?: string
  tenant?: string
  event_type: string
  min_count: number
  cooldown_sec: number
  channel_ids: number[]
}

export interface AlertHistoryEntry {
  id: number
  triggered_at: string
  tenant: string
  event_type: string
  event_data: {
    type?: string
    device_name?: string
    device_ip?: string
    count?: number
    sources?: string[]
    users?: string[]
    window_sec?: number
    threshold?: number
    detected_at?: string
  }
  matched_rule_id: number | null
  notifications_result: Record<string, { ok: boolean; error?: string; status?: number }>
}

export interface EdgeDevice {
  id: number
  tenant: string
  name: string
  ip: string
  check_port: number | null
  interval_sec: number
  channel_ids: number[]
  enabled: number
  source: 'auto' | 'manual'
  source_device_id: number | null
  source_device_name: string | null
  source_iface: string | null
  last_seen_from_agent: string | null
  last_check: string | null
  last_status: 'unknown' | 'online' | 'offline'
  last_state_change: string | null
  consecutive_fails: number
  created_at: string
}

export interface EdgeDeviceUpdate {
  id: number
  name?: string
  check_port?: number | null
  interval_sec?: number
  channel_ids?: number[]
}

export interface EdgeDeviceManualInput {
  tenant: string
  name: string
  ip: string
  check_port?: number | null
  interval_sec: number
  channel_ids: number[]
}

export interface ActivityEntry {
  id: number
  ts: string
  tenant: string
  event_type: string
  message: string
  details: any
}

export interface DeviceLogFetchResult {
  device_id: number
  device_label?: string
  requested_limit: number
  logs?: Array<{ time?: string; topics?: string; message?: string }>
  error?: string
  fetched_at: string
}

export interface EdgeEvent {
  id: number
  edge_id: number
  ts: string
  event_type: 'offline' | 'online'
  duration_sec: number | null
  notifications_result: Record<string, { ok: boolean; error?: string; status?: number }>
  device_name: string
  device_ip: string
  tenant: string
}

// ── E2E decryption (Web Crypto API, runs in-browser only) ────────────────────

function b64ToBuffer(s: string): ArrayBuffer {
  const bin = atob(s)
  const buf = new ArrayBuffer(bin.length)
  const view = new Uint8Array(buf)
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i)
  return buf
}

async function decryptEnvelope(envelope: any, keyB64: string): Promise<any> {
  if (envelope?.v !== 2 || envelope?.alg !== 'aes-256-gcm') {
    throw new Error(`unsupported envelope: v=${envelope?.v} alg=${envelope?.alg}`)
  }
  const rawKey = b64ToBuffer(keyB64)
  if (rawKey.byteLength !== 32) throw new Error('decryption key must be 32 bytes')
  const nonce = b64ToBuffer(envelope.nonce)
  const ct = b64ToBuffer(envelope.ciphertext)
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct)
  const text = new TextDecoder().decode(pt)
  return JSON.parse(text)
}

export interface CentralUsageTenant {
  tenant: string
  bytes: number
  count: number
  oldest: string
  newest: string
}

export interface CentralUsage {
  total_bytes: number
  total_mb: number
  total_count: number
  cap_mb: number
  percent_of_cap: number | null
  per_tenant_limit: number
  per_tenant: CentralUsageTenant[]
}

export const centralApi = {
  tenants: () => centralRequest<CentralTenantList>('tenants'),
  history: (tenant: string) =>
    centralRequest<Array<{ id: number; received_at: string; bytes: number }>>('history', { tenant }),
  usage: () => centralRequest<CentralUsage>('usage'),
  cleanup: (keep: number = 20) =>
    centralRequest<{ deleted: number; kept_per_tenant: number }>('cleanup', { keep: String(keep) }),
  requestUpdate: (tenant: string) =>
    centralRequest<{ ok: boolean; tenant: string; queued_at: string; note: string }>('request_update', { tenant }),
  pendingUpdates: () =>
    centralRequest<{ pending: Array<{ tenant: string; queued_at: string }> }>('pending_updates'),
  requestRestart: (tenant: string) =>
    centralRequest<{ ok: boolean; tenant: string; queued_at: string; note: string }>('request_restart', { tenant }),
  pendingRestarts: () =>
    centralRequest<{ pending: Array<{ tenant: string; queued_at: string }> }>('pending_restarts'),
  requestFirmwareUpgrade: (tenant: string, deviceId: number, backup: boolean) =>
    centralRequest<{ ok: boolean; tenant: string; device_id: number; backup: boolean; queued_at: string }>(
      'request_firmware_upgrade',
      { tenant, device_id: String(deviceId), backup: String(backup) },
    ),
  pendingFirmwareUpgrades: () =>
    centralRequest<{ pending: Array<{ tenant: string; device_id: number; backup: boolean; queued_at: string }> }>('pending_firmware_upgrades'),
  requestDeviceLogs: (tenant: string, deviceId: number, limit: number = 100) =>
    centralRequest<{ ok: boolean; tenant: string; device_id: number; limit: number; queued_at: string; note: string }>(
      'request_device_logs',
      { tenant, device_id: String(deviceId), limit: String(limit) },
    ),
  pendingDeviceLogRequests: () =>
    centralRequest<{ pending: Array<{ tenant: string; device_id: number; limit: number; queued_at: string }> }>('pending_device_log_requests'),

  // Alerts
  alertChannels: () => centralRequest<{ channels: AlertChannel[] }>('alert_channels'),
  alertChannelAdd: (data: AlertChannelInput) =>
    centralRequest<{ ok: boolean; id: number }>('alert_channel_add', {}, { method: 'POST', body: data }),
  alertChannelDelete: (id: number) =>
    centralRequest<{ ok: boolean; deleted: number }>('alert_channel_delete', { id: String(id) }, { method: 'DELETE' }),
  alertChannelToggle: (id: number) =>
    centralRequest<{ ok: boolean }>('alert_channel_toggle', { id: String(id) }, { method: 'POST' }),
  alertChannelTest: (id: number) =>
    centralRequest<{ result: { ok: boolean; error?: string; status?: number } }>('alert_channel_test', { id: String(id) }, { method: 'POST' }),
  alertRules: () => centralRequest<{ rules: AlertRule[] }>('alert_rules'),
  alertRuleAdd: (data: AlertRuleInput) =>
    centralRequest<{ ok: boolean; id: number }>('alert_rule_add', {}, { method: 'POST', body: data }),
  alertRuleDelete: (id: number) =>
    centralRequest<{ ok: boolean; deleted: number }>('alert_rule_delete', { id: String(id) }, { method: 'DELETE' }),
  alertRuleToggle: (id: number) =>
    centralRequest<{ ok: boolean }>('alert_rule_toggle', { id: String(id) }, { method: 'POST' }),
  alertHistory: (tenant?: string, limit: number = 50) =>
    centralRequest<{ history: AlertHistoryEntry[] }>(
      'alert_history',
      tenant ? { tenant, limit: String(limit) } : { limit: String(limit) },
    ),

  // Edge monitoring
  edgeDevices: () => centralRequest<{ devices: EdgeDevice[] }>('edge_devices'),
  edgeDeviceUpdate: (data: EdgeDeviceUpdate) =>
    centralRequest<{ ok: boolean }>('edge_device_update', {}, { method: 'POST', body: data }),
  edgeDeviceAdd: (data: EdgeDeviceManualInput) =>
    centralRequest<{ ok: boolean; id: number }>('edge_device_add', {}, { method: 'POST', body: data }),
  edgeDeviceDelete: (id: number) =>
    centralRequest<{ ok: boolean; deleted: number }>('edge_device_delete', { id: String(id) }, { method: 'DELETE' }),
  edgeDeviceToggle: (id: number) =>
    centralRequest<{ ok: boolean }>('edge_device_toggle', { id: String(id) }, { method: 'POST' }),
  edgeDeviceCheckNow: (id: number) =>
    centralRequest<{ ok: boolean; result: { ok: boolean; state_changed: boolean; new_status: string } }>(
      'edge_device_check_now', { id: String(id) }, { method: 'POST' },
    ),
  edgeEvents: (edgeId?: number, limit: number = 100) =>
    centralRequest<{ events: EdgeEvent[] }>(
      'edge_events',
      edgeId ? { edge_id: String(edgeId), limit: String(limit) } : { limit: String(limit) },
    ),

  // Activity log (dashboard timeline)
  activityLog: (tenant?: string, limit: number = 50) =>
    centralRequest<{ activity: ActivityEntry[] }>(
      'activity_log',
      tenant ? { tenant, limit: String(limit) } : { limit: String(limit) },
    ),

  async snapshot(tenant: string): Promise<any> {
    const data = await centralRequest<any>('snapshot', { tenant })
    if (!data) return null
    // Check if data is an encrypted envelope (has v + ciphertext fields)
    if (data.v === 2 && data.ciphertext) {
      const cfg = centralConfig.load()
      const key = cfg?.tenantKeys?.[tenant]
      if (!key) {
        return {
          _encrypted: true,
          _error: 'missing_key',
          tenant,
          sent_at: data.sent_at,
          devices_count: data.devices_count,
          devices_online: data.devices_online,
          received_at: data.received_at,
          age_sec: data.age_sec,
          online: data.online,
        }
      }
      try {
        const decrypted = await decryptEnvelope(data, key)
        return {
          ...decrypted,
          received_at: data.received_at,
          age_sec: data.age_sec,
          online: data.online,
          _decrypted: true,
        }
      } catch (e) {
        return {
          _encrypted: true,
          _error: `decrypt_failed: ${(e as Error).message}`,
          tenant,
          received_at: data.received_at,
          age_sec: data.age_sec,
          online: data.online,
        }
      }
    }
    // Plaintext snapshot
    return data
  },
}

// ── Aggregated fetchers (used by Devices/Dashboard/Logs to merge local+central)

export interface TenantDeviceRow {
  tenant: string                 // 'sanmed', 'klient-b', etc.
  online_at_source?: boolean     // tenant's heartbeat status
  age_sec?: number               // snapshot age
  encrypted?: boolean            // true if we couldn't decrypt
  // Device fields (same shape as local Device when decrypted)
  id?: number
  ip?: string
  name?: string
  identity?: string
  model?: string
  ros_version?: string
  vendor?: string
  online?: boolean
  last_seen?: string
  has_api?: boolean
  has_ssh?: boolean
  has_web?: boolean
  has_snmp?: boolean
}

export interface TenantCriticalLog {
  tenant: string
  device_id?: number
  device_ip?: string
  device_label?: string
  time?: string
  topics?: string
  message?: string
}

/** Fetch every tenant's latest snapshot, decrypt if possible, return flat
 *  device list tagged with tenant id. */
export async function getAllTenantDevices(): Promise<TenantDeviceRow[]> {
  if (!centralConfig.load()) return []
  let tenantsList: CentralTenantList
  try {
    tenantsList = await centralApi.tenants()
  } catch {
    return []
  }
  const results: TenantDeviceRow[] = []
  await Promise.all(tenantsList.tenants.map(async (t) => {
    try {
      const snap = await centralApi.snapshot(t.id)
      if (!snap) return
      if (snap._encrypted) {
        results.push({ tenant: t.id, encrypted: true, online_at_source: t.online })
        return
      }
      const devs: any[] = Array.isArray(snap.devices) ? snap.devices : []
      for (const d of devs) {
        results.push({
          tenant: t.id,
          online_at_source: t.online,
          age_sec: snap.age_sec,
          id: d.id, ip: d.ip, name: d.name, identity: d.identity,
          model: d.model, ros_version: d.ros_version,
          vendor: d.vendor,
          online: d.online, last_seen: d.last_seen,
          has_api: d.has_api, has_ssh: d.has_ssh,
          has_web: d.has_web, has_snmp: d.has_snmp,
        })
      }
    } catch { /* ignore one bad tenant */ }
  }))
  return results
}

/** Fetch critical logs from every tenant's latest snapshot. */
export async function getAllTenantCriticalLogs(): Promise<TenantCriticalLog[]> {
  if (!centralConfig.load()) return []
  let tenantsList: CentralTenantList
  try { tenantsList = await centralApi.tenants() } catch { return [] }

  const all: TenantCriticalLog[] = []
  await Promise.all(tenantsList.tenants.map(async (t) => {
    try {
      const snap = await centralApi.snapshot(t.id)
      if (!snap || snap._encrypted) return
      const logs: any[] = Array.isArray(snap.critical_logs) ? snap.critical_logs : []
      for (const l of logs) {
        all.push({
          tenant: t.id,
          device_id: l.device_id, device_ip: l.device_ip, device_label: l.device_label,
          time: l.time, topics: l.topics, message: l.message,
        })
      }
    } catch { /* ignore */ }
  }))
  return all.sort((a, b) => (b.time ?? '').localeCompare(a.time ?? ''))
}

// Helper to generate a fresh 32-byte key in browser (base64)
export function generateEncKey(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

import axios from 'axios'

export const api = axios.create({ baseURL: '/api' })

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

export const systemApi = {
  refreshStatus: () => api.get<RefreshStatus>('/system/refresh/status').then(r => r.data),
  runRefresh: () => api.post('/system/refresh/run').then(r => r.data),
  topology: () => api.get<Topology>('/system/topology').then(r => r.data),
  discoverTopology: () => api.post('/system/topology/discover').then(r => r.data),
  versionStatus: () => api.get<VersionStatus>('/system/versions/status').then(r => r.data),
  refreshVersions: () => api.post<{ latest: VersionStatus['latest']; fetch_status: VersionFetchStatus }>('/system/versions/refresh').then(r => r.data),
  criticalLogs: (limit = 20) => api.get<CriticalLogEntry[]>('/system/critical-logs', { params: { limit } }).then(r => r.data),
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

async function centralRequest<T>(action: string, params: Record<string, string> = {}): Promise<T> {
  const cfg = centralConfig.load()
  if (!cfg) throw new Error('Central not configured')
  const url = new URL(cfg.apiUrl)
  url.searchParams.set('action', action)
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)
  const resp = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${cfg.password}` },
  })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${await resp.text()}`)
  return resp.json()
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

// Helper to generate a fresh 32-byte key in browser (base64)
export function generateEncKey(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

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

export const systemApi = {
  refreshStatus: () => api.get<RefreshStatus>('/system/refresh/status').then(r => r.data),
  runRefresh: () => api.post('/system/refresh/run').then(r => r.data),
  topology: () => api.get<Topology>('/system/topology').then(r => r.data),
  discoverTopology: () => api.post('/system/topology/discover').then(r => r.data),
  versionStatus: () => api.get<VersionStatus>('/system/versions/status').then(r => r.data),
  refreshVersions: () => api.post<{ latest: VersionStatus['latest']; fetch_status: VersionFetchStatus }>('/system/versions/refresh').then(r => r.data),
}

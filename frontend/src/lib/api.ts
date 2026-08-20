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

export type AuthSource = 'ovh' | 'local'
export type AuthRole = 'admin' | 'viewer'

export interface LoginResult {
  ok: boolean
  source: AuthSource
  username: string
  role: AuthRole
  allowed_tenants?: string[] | null
}

export interface MeResult {
  username: string
  role: AuthRole
  source: AuthSource
}

export const authApi = {
  status: () => api.get<AuthStatus>('/auth/status').then(r => r.data),
  setup: (username: string, password: string, totpSecret?: string) =>
    api.post<MfaSetupInfo>('/auth/setup', { username, password, totp_secret: totpSecret || undefined }).then(r => r.data),
  setupResume: (username: string, password: string) =>
    api.post<MfaSetupInfo>('/auth/setup/resume', { username, password }).then(r => r.data),
  setupRegenerate: (username: string, password: string, totpSecret?: string) =>
    api.post<MfaSetupInfo>('/auth/setup/regenerate', { username, password, totp_secret: totpSecret || undefined }).then(r => r.data),
  mfaConfirm: (code: string) => api.post('/auth/mfa/confirm', { code }).then(r => r.data),
  // OVH-primary: tries the central account first, silently falls back to the
  // local emergency account only when OVH is unreachable/not provisioned.
  login: (username: string, password: string, totp_code: string) =>
    api.post<LoginResult>('/auth/login', { username, password, totp_code }).then(r => r.data),
  // Deliberate, explicit use of the local emergency account (bypasses OVH
  // on purpose — e.g. the operator's central account was deactivated).
  loginLocal: (username: string, password: string, totp_code: string) =>
    api.post<LoginResult>('/auth/login/local', { username, password, totp_code }).then(r => r.data),
  logout: () => api.post('/auth/logout').then(r => r.data),
  me: () => api.get<MeResult>('/auth/me').then(r => r.data),
  totpSecret: () => api.get<MfaSetupInfo>('/auth/totp-secret').then(r => r.data),
  totpSecretRegenerate: (totpSecret?: string) =>
    api.post<MfaSetupInfo>('/auth/totp-secret/regenerate', { totp_secret: totpSecret || undefined }).then(r => r.data),
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface Credential {
  id: number
  name: string
  username: string
  domain?: string | null
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
  owner?: string | null
  criticality?: string | null  // 'low' | 'medium' | 'high' | 'critical'
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
  domain?: string
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
  exportCsv: () => api.get('/devices/export', { responseType: 'blob' }).then(r => r.data as Blob),
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
  ping_interval_min?: number
  last_ping?: string | null
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
  uplinkGetEncKey: () => api.get<{ enc_key: string }>('/system/uplink/enc-key').then(r => r.data),
  firmwareCompliance: () => api.get<FirmwareComplianceReport>('/system/firmware-compliance').then(r => r.data),
  cryptoStatus: () => api.get<CryptoStatus>('/system/crypto/status').then(r => r.data),
  rotateKey: () => api.post<{ ok: boolean; rotated_fields: number }>('/system/crypto/rotate-key').then(r => r.data),
  backupStatus: () => api.get<AgentBackupStatus>('/system/backup/status').then(r => r.data),
  backupRun: () => api.post<{ ok: boolean; error: string | null; size_bytes: number | null }>('/system/backup/run').then(r => r.data),
  backupRestore: (file: File, encKey: string) => {
    const form = new FormData()
    form.append('file', file)
    form.append('enc_key', encKey)
    form.append('confirm', 'true')
    return api.post<{ ok: boolean; staged: boolean; restarting: boolean }>('/system/backup/restore', form).then(r => r.data)
  },
  supplyChainStatus: () => api.get<SupplyChainStatus>('/system/supply-chain/status').then(r => r.data),
  supplyChainRun: () => api.post<{ ok: boolean; pip?: SupplyChainPipResult; npm?: SupplyChainNpmResult; bandit?: SupplyChainBanditResult; eslint?: SupplyChainEslintResult; php?: SupplyChainPhpResult; error?: string }>('/system/supply-chain/run').then(r => r.data),
}

export interface SupplyChainPipFinding {
  package: string
  version: string
  id: string
  aliases: string[]
  fix_versions: string[]
}

export interface SupplyChainPipResult {
  ok: boolean
  error: string | null
  findings: SupplyChainPipFinding[]
  skipped: { name: string; reason: string }[]
}

export interface SupplyChainNpmFinding {
  package: string
  severity: string | null
  title: string | null
  url: string | null
  range: string | null
  is_direct: boolean | null
  fix_available: boolean
}

export interface SupplyChainNpmResult {
  ok: boolean
  error: string | null
  findings: SupplyChainNpmFinding[]
  summary: { info: number; low: number; moderate: number; high: number; critical: number; total: number } | null
}

export interface SupplyChainBanditFinding {
  file: string
  line: number
  severity: string
  confidence: string
  test_id: string
  test_name: string
  issue_text: string
  cwe_id: number | null
  more_info: string
}

export interface SupplyChainBanditResult {
  ok: boolean
  error: string | null
  findings: SupplyChainBanditFinding[]
  counts: { high?: number; medium?: number; low?: number }
}

export interface SupplyChainEslintFinding {
  file: string
  line: number
  rule_id: string | null
  severity: 'error' | 'warning'
  message: string
}

export interface SupplyChainEslintResult {
  ok: boolean
  error: string | null
  findings: SupplyChainEslintFinding[]
  counts: { error?: number; warning?: number }
}

export interface SupplyChainPhpFinding {
  file: string
  line: number
  function: string
  severity: 'high' | 'medium'
}

export interface SupplyChainPhpResult {
  ok: boolean
  error: string | null
  findings: SupplyChainPhpFinding[]
  counts: { high?: number; medium?: number }
}

export interface SupplyChainStatus {
  last_run: string | null
  last_error: string | null
  in_progress: boolean
  pip: SupplyChainPipResult
  npm: SupplyChainNpmResult
  bandit: SupplyChainBanditResult
  eslint: SupplyChainEslintResult
  php: SupplyChainPhpResult
  scan_day: number
  scan_hour: number
  next_run_estimated: number
}

// Redacted, capped summary sent by each agent in its snapshot envelope —
// distinct from SupplyChainStatus above (that's the full local result with
// every finding, only ever fetched from THIS agent's own /system/supply-
// chain/status). This is what Central sees for every tenant at once.
export interface CentralSupplyChainToolSummary {
  ok: boolean | null
  error: string | null
  count: number
  counts?: Record<string, number>
  summary?: { info: number; low: number; moderate: number; high: number; critical: number; total: number } | null
  top: Array<Record<string, string | null>>
}

export interface CentralSupplyChainStatus {
  last_run: string | null
  last_error: string | null
  pip: CentralSupplyChainToolSummary
  npm: CentralSupplyChainToolSummary
  bandit: CentralSupplyChainToolSummary
  eslint: CentralSupplyChainToolSummary
  php: CentralSupplyChainToolSummary
}

export interface AgentBackupStatus {
  last_backup_at: string | null
  last_error: string | null
  last_size_bytes: number | null
  in_progress: boolean
  backup_day: number
  backup_hour: number
  next_run_estimated: number
  enc_key_configured: boolean
}

export interface CryptoStatus {
  key_created_at: string | null
  encrypted_field_count: number
}

export interface FirmwareComplianceDevice {
  device_id: number
  name: string
  ip: string
  model: string | null
  vendor: string | null
  ros_version: string | null
  ros_target: string | null
  ros_status: 'compliant' | 'outdated' | 'unknown'
  ros_source: 'device_check' | 'global_fallback' | 'none'
  firmware_current: string | null
  firmware_target: string | null
  firmware_status: 'compliant' | 'outdated' | 'unknown'
  last_seen: string | null
}

export interface VersionFetchInfo {
  fetched_at: number | null
  age_sec: number | null
  last_error: string | null
  has_data: boolean
}

export interface FirmwareComplianceReport {
  latest_stable: string
  latest_fetch_info: VersionFetchInfo
  total_devices: number
  ros_known_count: number
  ros_compliant_count: number
  ros_compliant_pct: number | null
  ros_via_device_check_count: number
  ros_via_global_fallback_count: number
  firmware_known_count: number
  firmware_compliant_count: number
  firmware_compliant_pct: number | null
  devices: FirmwareComplianceDevice[]
}

// ── Passive vulnerability scanner ─────────────────────────────────────────────

export interface VulnStatus {
  in_progress: boolean
  last_run: string | null
  last_duration_sec: number | null
  hosts_scanned_last: number
  findings_count_last: number
  scan_day: number    // 0=Mon..6=Sun
  scan_hour: number
  next_run_estimated: number  // epoch seconds
}

export interface VulnHostService {
  port: number
  service_name: string | null
  product: string | null
  version: string | null
  banner_raw: string | null
  last_seen: string | null
}

export interface VulnHostOut {
  id: number
  ip: string
  device_id: number | null
  device_name: string | null
  credential_id: number | null
  credential_name: string | null
  last_scan_at: string | null
  services: VulnHostService[]
}

export interface VulnFindingAffected {
  kind: 'host' | 'device'
  ip: string
  port: number | null
  device_id?: number
  device_name?: string | null
}

export type VulnRemediationStatus = 'open' | 'in_progress' | 'accepted_risk' | 'resolved'

export interface VulnFindingOut {
  id: number
  product: string
  version: string
  cve_id: string
  cvss_score: number | null
  severity: string | null
  summary: string | null
  published: string | null
  ref_url: string | null
  affected: VulnFindingAffected[]
  status: VulnRemediationStatus
  note: string | null
  updated_by: string | null
  updated_at: string | null
  first_seen_at: string | null
  due_date: string | null
  overdue: boolean
}

export const vulnApi = {
  status: () => api.get<VulnStatus>('/vuln/status').then(r => r.data),
  run: () => api.post('/vuln/run').then(r => r.data),
  hosts: () => api.get<VulnHostOut[]>('/vuln/hosts').then(r => r.data),
  setRemediation: (data: { product: string; version: string; cve_id: string; status: VulnRemediationStatus; note?: string }) =>
    api.put('/vuln/remediation', data).then(r => r.data),
  exportUrl: (severity?: string) =>
    '/api/vuln/findings/export' + (severity ? `?severity=${encodeURIComponent(severity)}` : ''),
  findings: (severity?: string) =>
    api.get<VulnFindingOut[]>('/vuln/findings', { params: severity ? { severity } : {} }).then(r => r.data),
  setHostCredential: (hostId: number, credentialId: number | null) =>
    api.put(`/vuln/hosts/${hostId}/credential`, { credential_id: credentialId }).then(r => r.data),
  rescanHost: (hostId: number) =>
    api.post<{ ip: string; alive: boolean; unique_versions: number; findings_count: number }>(
      `/vuln/hosts/${hostId}/rescan`,
    ).then(r => r.data),
}

// ── Audit log ────────────────────────────────────────────────────────────────

export interface AuditEntry {
  id: number
  ts: string
  username: string
  role: AuthRole
  source: AuthSource
  method: string
  path: string
  status_code: number
  ip: string | null
}

export const auditApi = {
  list: (params?: { limit?: number; offset?: number; username?: string }) =>
    api.get<AuditEntry[]>('/audit', { params }).then(r => r.data),
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

// UI display mode — a purely local browser preference for Sidebar nav.
// 'central' hides agent-only tabs (Devices/Scanner/Vulnerabilities/etc) on
// a computer used only to view Central. The backend is NOT affected either
// way — uplink/scanner/vuln_scan/supply_chain keep running regardless of
// this setting, it's cosmetic navigation only.
const UI_MODE_LS = 'mikromanager_ui_mode'
export type UiMode = 'agent' | 'central'
export const uiMode = {
  load(): UiMode {
    return localStorage.getItem(UI_MODE_LS) === 'central' ? 'central' : 'agent'
  },
  save(mode: UiMode) {
    localStorage.setItem(UI_MODE_LS, mode)
  },
}

// Central calls bypass our backend — they go directly to the OVH PHP API.
// Config is stored in localStorage.
const CENTRAL_LS = 'mikromanager_central'

export interface CentralConfig {
  apiUrl: string
  // Legacy shared viewer password — kept optional now that per-user account
  // login (centralSession below) is the recommended path; still supported
  // so existing configs and the phone-viewer PWA keep working unchanged.
  password?: string
  // Per-tenant E2E decryption keys (base64). Map tenant id → key.
  // The server never has these. Without it, encrypted snapshots cannot be read.
  tenantKeys?: Record<string, string>
  // Optional second factor for the LEGACY shared viewer login (ovh/totp.php
  // on the server side) — ONE secret for the whole central server, unlike
  // tenantKeys which are per-tenant. Base32, same format pyotp uses locally.
  // Not used by per-user account login, which has its own per-user TOTP.
  totpSecret?: string
}

// Per-user OVH account session (recommended path) — kept in sessionStorage,
// not localStorage: it's a short-lived bearer credential, not long-term
// config, so it shouldn't outlive the browser tab/session by default.
const CENTRAL_SESSION_KEY = 'mikromanager_central_session'

export interface CentralSession {
  token: string
  username: string
  role: AuthRole
  allowedTenants?: string[] | null
  expiresAt: string
}

export const centralSession = {
  load(): CentralSession | null {
    try {
      const raw = sessionStorage.getItem(CENTRAL_SESSION_KEY)
      return raw ? JSON.parse(raw) : null
    } catch { return null }
  },
  save(s: CentralSession) {
    sessionStorage.setItem(CENTRAL_SESSION_KEY, JSON.stringify(s))
  },
  clear() {
    sessionStorage.removeItem(CENTRAL_SESSION_KEY)
  },
}

// TOTP code generation (RFC 6238) via native WebCrypto — mirrors
// ovh/totp.php's algorithm exactly (SHA1, 6 digits, 30s step) so a code
// computed here verifies against that PHP implementation.
function base32Decode(b32: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = b32.toUpperCase().replace(/[^A-Z2-7]/g, '')
  let bits = ''
  for (const ch of clean) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0')
  const bytes = new Uint8Array(Math.floor(bits.length / 8))
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2)
  return bytes
}

export async function totpCode(secretB32: string, atMs: number = Date.now()): Promise<string> {
  const step = Math.floor(atMs / 1000 / 30)
  const keyBytes = base32Decode(secretB32)
  const counter = new ArrayBuffer(8)
  new DataView(counter).setUint32(4, step) // low 32 bits; high 32 bits stay 0
  const key = await crypto.subtle.importKey(
    'raw', keyBytes as BufferSource, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter))
  const offset = sig[sig.length - 1] & 0x0f
  const code = (
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff)
  ) % 1000000
  return String(code).padStart(6, '0')
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
  // Decryption keys never leave the browser except via this deliberate,
  // user-initiated copy/paste — there is no server-side transfer. Keeps the
  // E2E model intact (OVH never has the keys) while letting you move to a
  // different browser/device without retyping every 32-byte key by hand.
  exportTenantKeys(): string {
    const cfg = centralConfig.load()
    return JSON.stringify(cfg?.tenantKeys ?? {}, null, 2)
  },
  importTenantKeys(json: string): number {
    const cfg = centralConfig.load()
    if (!cfg) throw new Error('viewer not configured yet — set up API URL/password first')
    let parsed: unknown
    try {
      parsed = JSON.parse(json)
    } catch {
      throw new Error('invalid JSON')
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('expected a JSON object of {tenant: key}')
    }
    const entries = Object.entries(parsed as Record<string, unknown>)
      .filter((e): e is [string, string] => typeof e[1] === 'string')
    cfg.tenantKeys = { ...(cfg.tenantKeys ?? {}), ...Object.fromEntries(entries) }
    centralConfig.save(cfg)
    return entries.length
  },
  // Full config transfer (apiUrl + password + totpSecret + tenantKeys) as
  // ONE blob — for setting up "Centralny" on a second computer in one paste
  // instead of retyping the API URL/password and re-importing keys
  // separately. Unlike exportTenantKeys(), this includes the shared viewer
  // password (and TOTP secret, if set) in PLAIN TEXT — same "convenience
  // over defense in depth" tradeoff already accepted for E2E-key-bundled
  // backup downloads elsewhere in this app. Whoever holds this blob can log
  // into Central as you; treat it like a password, never paste it anywhere
  // untrusted.
  exportFullConfig(): string {
    const cfg = centralConfig.load()
    return JSON.stringify(cfg ?? {}, null, 2)
  },
  importFullConfig(json: string): CentralConfig {
    let parsed: unknown
    try {
      parsed = JSON.parse(json)
    } catch {
      throw new Error('invalid JSON')
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('expected a JSON object')
    }
    const obj = parsed as Record<string, unknown>
    if (typeof obj.apiUrl !== 'string' || !obj.apiUrl) {
      throw new Error('missing apiUrl')
    }
    const tenantKeysRaw = obj.tenantKeys
    const tenantKeys = (typeof tenantKeysRaw === 'object' && tenantKeysRaw !== null && !Array.isArray(tenantKeysRaw))
      ? Object.fromEntries(
          Object.entries(tenantKeysRaw as Record<string, unknown>)
            .filter((e): e is [string, string] => typeof e[1] === 'string'),
        )
      : undefined
    const cfg: CentralConfig = {
      apiUrl: obj.apiUrl,
      password: typeof obj.password === 'string' ? obj.password : undefined,
      totpSecret: typeof obj.totpSecret === 'string' ? obj.totpSecret : undefined,
      tenantKeys,
    }
    centralConfig.save(cfg)
    return cfg
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
  // URLSearchParams.set(k, undefined) stringifies to the literal "undefined"
  // rather than omitting the param — callers routinely pass `x || undefined`
  // for "no filter", so this must be skipped explicitly or every such filter
  // silently becomes `?field=undefined` and matches nothing server-side.
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, v)
  }

  const method = opts.method ?? 'GET'
  const headers: Record<string, string> = {}
  // Prefer a per-user account session token (recommended path) over the
  // legacy shared password — `login`/logged-out state doesn't have one yet,
  // so this falls back to the legacy password if that's all that's configured.
  const session = centralSession.load()
  if (session) {
    headers.Authorization = `Bearer ${session.token}`
  } else if (cfg.password) {
    headers.Authorization = `Bearer ${cfg.password}`
    if (cfg.totpSecret) headers['X-Totp'] = await totpCode(cfg.totpSecret)
  }
  let body: string | undefined
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }

  const resp = await fetch(url.toString(), { method, headers, body })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${await resp.text()}`)
  return resp.json()
}

// ── Per-user OVH account login (Central) ────────────────────────────────────
// Uses the same central-proxy relay as everything else in this file, just
// with the new `login`/`me`/`users_*` actions on ovh/api.php, which are
// unauthenticated (login) or authenticated via the token this returns
// (everything else) rather than the legacy shared password.

export interface CentralUser {
  id: number
  username: string
  role: AuthRole
  allowed_tenants: string[] | null
  totp_enabled: number
  is_active: number
  created_at: string
  last_login_at: string | null
}

export const centralAuthApi = {
  login: (username: string, password: string, totp_code?: string) =>
    centralRequest<{ token: string; username: string; role: AuthRole; allowed_tenants: string[] | null; expires_at: string }>(
      'login', {}, { method: 'POST', body: { username, password, totp_code } }),
  logout: () => centralRequest<{ ok: boolean }>('logout', {}, { method: 'POST' }),
  me: () => centralRequest<{ id: number; username: string; role: AuthRole; allowed_tenants: string[] | null }>('me'),
  totpConfirm: (code: string) => centralRequest<{ ok: boolean }>('me_totp_confirm', {}, { method: 'POST', body: { code } }),
}

export const centralUsersApi = {
  list: () => centralRequest<{ users: CentralUser[] }>('users_list'),
  add: (data: { username: string; password: string; role: AuthRole; allowed_tenants?: string[] | null }) =>
    centralRequest<{ ok: boolean; id: number }>('user_add', {}, { method: 'POST', body: data }),
  update: (data: { id: number; role?: AuthRole; allowed_tenants?: string[] | null; is_active?: boolean; password?: string }) =>
    centralRequest<{ ok: boolean }>('user_update', {}, { method: 'POST', body: data }),
  delete: (id: number) => centralRequest<{ ok: boolean; deleted: number }>('user_delete', { id: String(id) }, { method: 'DELETE' }),
  totpReset: (id: number) => centralRequest<{ secret: string; otpauth_uri: string }>('user_totp_reset', { id: String(id) }, { method: 'POST' }),
}

// ── AnyDesk time tracking (Centrala, global-admin only) ─────────────────────
// Session data comes from AnyDesk's own REST API, synced server-side by
// ovh/anydesk.php — this app never talks to AnyDesk directly, only to the
// usual central-proxy relay.

export type AnydeskCategory = 'billable' | 'training' | 'internal'

export interface AnydeskSession {
  id: number
  anydesk_sid: string
  tenant: string | null
  from_cid: string
  from_alias: string | null
  to_cid: string
  to_alias: string | null
  start_time: string
  end_time: string | null
  duration_sec: number | null
  billed_minutes: number | null
  active: number
  state: string | null
  category: AnydeskCategory | null
  note: string | null
  classified_by: string | null
  classified_at: string | null
  synced_at: string
}

export interface AnydeskClientMap {
  id: number
  tenant: string
  anydesk_cid: string
  label: string | null
  created_at: string
}

export interface AnydeskSummaryRow {
  tenant: string
  month: string
  billable_minutes: number
  training_minutes: number
  internal_minutes: number
  unclassified_minutes: number
  session_count: number
}

export interface AnydeskStatus {
  configured: boolean
  last_sync_at: string | null
  last_error: string | null
  sessions_total: number
  sessions_unclassified: number
  sessions_unassigned: number
}

export interface AnydeskUnassignedRow {
  cid: string
  alias: string | null
  session_count: number
  last_seen: string
}

export const centralAnydeskApi = {
  status: () => centralRequest<AnydeskStatus>('anydesk_status'),
  syncNow: () => centralRequest<{ ok: boolean; error: string | null; synced: number; skipped?: number }>('anydesk_sync_now', {}, { method: 'POST' }),
  importCsv: (csv: string) => centralRequest<{ ok: boolean; imported: number; skipped: number }>('anydesk_import_csv', {}, { method: 'POST', body: { csv } }),
  mappingList: () => centralRequest<{ mappings: AnydeskClientMap[] }>('anydesk_client_map_list'),
  mappingAdd: (data: { tenant: string; anydesk_cid: string; label?: string }) =>
    centralRequest<{ ok: boolean; id: number; retroactively_assigned: number }>('anydesk_client_map_add', {}, { method: 'POST', body: data }),
  mappingDelete: (id: number) => centralRequest<{ ok: boolean; deleted: number }>('anydesk_client_map_delete', { id: String(id) }, { method: 'DELETE' }),
  sessions: (filters: { tenant?: string; category?: AnydeskCategory | 'unclassified'; from?: string; to?: string } = {}) =>
    centralRequest<{ sessions: AnydeskSession[] }>('anydesk_sessions', filters as Record<string, string>),
  classify: (id: number, category: AnydeskCategory | null, note?: string) =>
    centralRequest<{ ok: boolean }>('anydesk_session_classify', {}, { method: 'POST', body: { id, category, note } }),
  summary: (filters: { from?: string; to?: string } = {}) =>
    centralRequest<{ summary: AnydeskSummaryRow[] }>('anydesk_summary', filters as Record<string, string>),
  unassigned: () => centralRequest<{ unassigned: AnydeskUnassignedRow[] }>('anydesk_unassigned'),
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
  last_check_detail: string | null
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
  requestSupplyChainScan: (tenant: string) =>
    centralRequest<{ ok: boolean; tenant: string; queued_at: string; note: string }>('request_supply_chain_scan', { tenant }),
  pendingSupplyChainScans: () =>
    centralRequest<{ pending: Array<{ tenant: string; queued_at: string }> }>('pending_supply_chain_scans'),
  supplyChainStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; age_sec: number | null; supply_chain_status: CentralSupplyChainStatus | null }> }>('supply_chain_status_all'),

  // Agent self-backup (BCP) — admin-only on the OVH side regardless of role
  // checks here; the server enforces it independently.
  backupList: (tenant: string) =>
    centralRequest<{ backups: Array<{ id: number; created_at: string; size_bytes: number }> }>('backup_list', { tenant }),
  backupDownload: (tenant: string, id: number) =>
    centralRequest<{ created_at: string; size_bytes: number; envelope: Record<string, unknown> }>(
      'backup_download', { tenant, id: String(id) },
    ),

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
    centralRequest<{ ok: boolean; result: { ok: boolean; state_changed: boolean; new_status: string; method: string; detail: string } }>(
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

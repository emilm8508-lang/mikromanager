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
  asset_scan?: string[]
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
  mgmt_ok?: boolean | null  // false while online: it answers ping / SNMP but no management port answers from this agent
  notes?: string
  x_pos: number
  y_pos: number
  owner?: string | null
  criticality?: string | null  // 'low' | 'medium' | 'high' | 'critical'
  mem_used_pct?: number | null
  disk_used_pct?: number | null
  cpu_load_pct?: number | null
  last_resources_check_at?: string | null
  iface_mbps_threshold?: number | null
  wan_status?: 'up' | 'down' | null
  wan_iface?: string | null
  drp_exclude?: boolean | null
}

export interface DeviceInterfaceStat {
  iface_name: string
  rx_mbps: number | null
  tx_mbps: number | null
  rx_errors: number | null
  tx_errors: number | null
  rx_drops: number | null
  tx_drops: number | null
  last_sample_at: string | null
}

export interface ScanRange {
  id: number
  cidr: string
  label?: string
  active: boolean
  scan_day?: number | null    // 0=Mon..6=Sun, null = use the global schedule
  scan_hour?: number | null   // 0-23
}

// ── Credentials ──────────────────────────────────────────────────────────────

export interface CredentialInput {
  name: string
  username: string
  password: string
  domain?: string
  snmp_community?: string
  description?: string
  asset_scan?: string[]
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
  backups: (id: number) => api.get<Array<{
    id: number; device_id: number; created_at: string | null; filename: string | null
    trigger: string | null; size_bytes: number | null; downloaded_locally: boolean
  }>>(`/devices/${id}/backups`).then(r => r.data),
  interfaceStats: (id: number) =>
    api.get<{ interfaces: DeviceInterfaceStat[] }>(`/devices/${id}/interface-stats`).then(r => r.data.interfaces),
  setIfaceThreshold: (id: number, mbps: number | null) =>
    api.put<{ iface_mbps_threshold: number | null }>(`/devices/${id}/iface-threshold`, { mbps }).then(r => r.data),
}

// ── Scanner ──────────────────────────────────────────────────────────────────

export interface ScannerProbeResult {
  ip: string
  ports: Record<string, boolean>
  ports_socket: Record<string, { open: boolean; error: string | null }>
  api_ssl_8729: boolean
  snmp_public: boolean
  found: Record<string, unknown> | null
  scan_range_membership: Array<{ cidr: string; label: string | null; contains_ip: boolean }>
  vuln_scan_probe: Record<string, { service: string; product: string | null; version: string | null }>
  enrich?: { ok: boolean; data?: Record<string, unknown>; error?: string }
}

export const scannerApi = {
  listRanges: () => api.get<ScanRange[]>('/scanner/ranges').then(r => r.data),
  addRange: (data: { cidr: string; label?: string }) =>
    api.post<ScanRange>('/scanner/ranges', data).then(r => r.data),
  deleteRange: (id: number) => api.delete(`/scanner/ranges/${id}`),
  updateRange: (id: number, data: { label?: string; active?: boolean; scan_day?: number; scan_hour?: number; clear_schedule?: boolean }) =>
    api.put<ScanRange>(`/scanner/ranges/${id}`, data).then(r => r.data),
  probe: (ip: string, opts?: { credentialId?: number; timeout?: number }) =>
    api.get<ScannerProbeResult>('/scanner/probe', {
      params: {
        ip,
        credential_id: opts?.credentialId,
        timeout: opts?.timeout,
      },
    }).then(r => r.data),
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
  buffered_count: number          // events waiting in the on-disk spool because Central could not take them
  failing_since?: string | null   // Central unreachable since then
  spool?: { alerts: number; activity: number; since: string | null; dropped: number }
  total_sent: number
  total_failed: number
}

export interface PrtgStatus {
  enabled: boolean
  url: string
  has_api_token: boolean
  verify_ssl: boolean
}

export interface CheckmkStatus {
  enabled: boolean
  url: string
  site: string
  username: string
  has_secret: boolean
  verify_ssl: boolean
}

export interface ConnectorTestResult {
  ok: boolean
  error?: string
  sample_count?: number
}

export interface WazuhStatus {
  enabled: boolean
  indexer_url: string
  indexer_username: string
  has_password: boolean
  verify_ssl: boolean
}

export interface EndpointCentralStatus {
  enabled: boolean
  url: string
  username: string
  has_password: boolean
  has_totp: boolean
  auth_type: 'local_authentication' | 'ad_authentication'
  domain: string
  verify_ssl: boolean
}

export interface EndpointCentralSample {
  ok: boolean
  status?: number
  body?: string
  truncated?: boolean
  error?: string
}

export interface ServicedeskRule { enabled: boolean; delay_min: number }
export interface ServicedeskRules { wan: ServicedeskRule; service: ServicedeskRule; idrac: ServicedeskRule }
export interface ServicedeskTicketFields { request_type: string; priority: string; urgency: string; category: string; closure_code: string; requester: string; extra: string }
export interface ServicedeskStatus {
  enabled: boolean
  url: string
  has_authtoken: boolean
  verify_ssl: boolean
  rules: ServicedeskRules
  ticket: ServicedeskTicketFields
  close_on_recovery: boolean
}
export interface ServicedeskTicketRow {
  id: number; rule: 'wan' | 'service' | 'idrac'; state: 'pending' | 'open' | 'recovering' | 'closed' | 'cancelled'
  what: string | null; subject: string | null; down_at: string; up_at: string | null; closed_at: string | null
  sdp_display_id: string | null; attempts: number; last_error: string | null; note: string | null
}
export interface ServicedeskTestTicket { ok: boolean; stage?: string; created?: string | number; closed?: boolean; error?: string | null; steps?: Array<{ step: string; ok: boolean; error?: string | null }> }

export interface SelfVersion {
  commit: string | null
  commit_time: number | null
  branch: string | null
}

export interface ChangelogEntry {
  version: string
  date: string
  changes: string[]
}

export interface Changelog {
  current_version: string
  entries: ChangelogEntry[]
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
  changelog: () => api.get<Changelog>('/system/changelog').then(r => r.data),
  uplinkStatus: () => api.get<UplinkStatus>('/system/uplink/status').then(r => r.data),
  uplinkConfigure: (data: { url: string; tenant: string; api_key: string; interval_sec: number; enc_key?: string }) =>
    api.post<UplinkStatus>('/system/uplink/config', data).then(r => r.data),
  uplinkSendNow: () => api.post<{ success: boolean; status: UplinkStatus }>('/system/uplink/send-now').then(r => r.data),
  uplinkGenerateEncKey: () => api.post<{ enc_key: string }>('/system/uplink/generate-enc-key').then(r => r.data),
  uplinkGetEncKey: () => api.get<{ enc_key: string }>('/system/uplink/enc-key').then(r => r.data),

  prtgStatus: () => api.get<PrtgStatus>('/system/prtg/status').then(r => r.data),
  prtgConfigure: (data: { url: string; api_token: string; verify_ssl: boolean }) =>
    api.post<PrtgStatus>('/system/prtg/config', data).then(r => r.data),
  prtgTest: () => api.post<ConnectorTestResult>('/system/prtg/test').then(r => r.data),

  checkmkStatus: () => api.get<CheckmkStatus>('/system/checkmk/status').then(r => r.data),
  checkmkConfigure: (data: { url: string; site: string; username: string; secret: string; verify_ssl: boolean }) =>
    api.post<CheckmkStatus>('/system/checkmk/config', data).then(r => r.data),
  checkmkTest: () => api.post<ConnectorTestResult>('/system/checkmk/test').then(r => r.data),

  wazuhStatus: () => api.get<WazuhStatus>('/system/wazuh/status').then(r => r.data),
  wazuhConfigure: (data: { indexer_url: string; indexer_username: string; indexer_password: string; verify_ssl: boolean }) =>
    api.post<WazuhStatus>('/system/wazuh/config', data).then(r => r.data),
  wazuhTest: () => api.post<ConnectorTestResult>('/system/wazuh/test').then(r => r.data),

  servicedeskStatus: () => api.get<ServicedeskStatus>('/system/servicedesk/status').then(r => r.data),
  servicedeskConfigure: (data: { url: string; authtoken: string; verify_ssl: boolean; rules?: ServicedeskRules; ticket?: ServicedeskTicketFields; close_on_recovery?: boolean }) =>
    api.post<ServicedeskStatus>('/system/servicedesk/config', data).then(r => r.data),
  servicedeskTickets: () => api.get<{ tickets: ServicedeskTicketRow[] }>('/system/servicedesk/tickets').then(r => r.data.tickets),
  servicedeskTestTicket: () => api.post<ServicedeskTestTicket>('/system/servicedesk/test-ticket').then(r => r.data),
  servicedeskTest: () => api.post<ConnectorTestResult>('/system/servicedesk/test').then(r => r.data),

  endpointcentralStatus: () => api.get<EndpointCentralStatus>('/system/endpointcentral/status').then(r => r.data),
  endpointcentralConfigure: (data: { url: string; username: string; password: string; auth_type: string; domain: string; verify_ssl: boolean; totp_secret: string }) =>
    api.post<EndpointCentralStatus>('/system/endpointcentral/config', data).then(r => r.data),
  endpointcentralTest: () =>
    api.post<ConnectorTestResult & { api_version?: string }>('/system/endpointcentral/test').then(r => r.data),
  endpointcentralSample: (path: string) =>
    api.post<EndpointCentralSample>('/system/endpointcentral/sample', { path }).then(r => r.data),
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

// Redacted per-host summary an agent includes in its snapshot envelope —
// only ever hosts the local operator has already opted into management
// (managed=True in LinuxHost), never the full auto-discovered list, and
// never raw command output (see linux_manage.public_summary()).
export interface CentralHostDiskStatus {
  // 'mount_point' for Linux hosts, 'drive_letter' for Windows hosts —
  // whichever the host type sends; the tile renderer just picks a label.
  mount_point?: string
  drive_letter?: string
  pct: number | null
  total_bytes: number | null
  used_bytes: number | null
}

export interface CentralLinuxHostStatus {
  id: number
  ip: string
  hostname: string | null
  distro_pretty: string | null
  distro_id?: string | null        // 2.54+: lets Central arrange hosts like the agent does
  package_manager?: string | null
  group?: string | null            // name of the agent's own group, if any
  upgradable_count: number | null
  reboot_required: boolean
  last_upgrade_at: string | null
  last_check_at: string | null
  last_status: string | null
  mem_used_pct: number | null
  mem_total_bytes: number | null
  cpu_used_pct: number | null
  disks: CentralHostDiskStatus[]
}

// Mirror of CentralLinuxHostStatus for windows_manage.public_summary().
export interface CentralWindowsHostStatus {
  id: number
  ip: string
  hostname: string | null
  os_name: string | null
  domain?: string | null
  host_type?: 'server' | 'workstation'
  group?: string | null
  upgradable_count: number | null
  reboot_required: boolean
  last_upgrade_at: string | null
  last_check_at: string | null
  last_status: string | null
  mem_used_pct: number | null
  mem_total_bytes: number | null
  cpu_used_pct: number | null
  disks: CentralHostDiskStatus[]
}

// Redacted per-server iDRAC health an agent includes in its snapshot
// envelope (see services/dell_monitor.py's public_summary()) — never the
// iDRAC IP or credential, just what's needed for the at-a-glance rollup
// the user asked for in Central (CPU/power/disk load, alerts).
export interface CentralDellServerStatus {
  id: number
  name: string | null
  vendor: DellVendor
  model: string | null
  health_rollup: 'OK' | 'Warning' | 'Critical' | null
  power_state: string | null
  components: {
    system?: string | null; cpu?: string | null; memory?: string | null; power?: string | null
    fans_temperature?: string | null; storage?: string | null
  }
  last_check_at: string | null
  last_status: string | null
}

// Redacted CPU/RAM/disk/temperature summary for a Mikrotik device an agent
// includes in its snapshot envelope (see services/resource_monitor.py's
// routers_public_summary()) — EVERY polled Mikrotik device, not just
// router-classified ones, so Central can show "other devices" too and let
// the operator correct is_router when the automatic WAN-interface-list
// detection gets it wrong. Same "general resource health view in Central"
// concept as CentralDellServerStatus, extended to routers.
export interface CentralRouterStatus {
  id: number
  name: string | null
  board_name: string | null
  is_router: boolean
  is_override: boolean
  cpu_used_pct: number | null
  mem_used_pct: number | null
  mem_total_bytes: number | null
  disk_used_pct: number | null
  disk_total_bytes: number | null
  temperature_c: number | null
  last_check_at: string | null
}

// Redacted per-tunnel status an agent includes in its snapshot envelope
// (see services/tunnel_monitor.py's public_summary()) — current up/down
// state only, same data already visible locally on the agent's own
// Tunele tab.
export interface CentralTunnelStatus {
  device_name: string
  tunnel_type: string
  tunnel_name: string
  status: string
  detail: string | null
}

// Redacted Hyper-V host+VM summary an agent includes in its snapshot
// envelope (see services/hyperv_manage.py's public_summary()) — only
// managed=True Windows hosts confirmed to actually run Hyper-V, and only
// the VM NAMES currently not running (never the full healthy VM list,
// nothing an operator needs a remote glance at).
export interface CentralHypervVm {
  name: string
  state: string | null
  cpu: number | null
  vcpu: number | null
  mem_assigned: number | null
  mem_demand: number | null
  uptime_sec: number | null
  heartbeat: string | null
  snapshots: number | null
  replication: string | null
  flags: string[]
  tile: HypervTile
}

export interface CentralHypervHostStatus {
  id: number
  ip: string
  hostname: string | null
  logical_processor_count: number | null
  memory_capacity_bytes: number | null
  vm_count_total: number | null
  vm_count_running: number | null
  vms_not_running: string[]
  last_check_at: string | null
  // Added with the Hyper-V dashboard — absent when the agent is older.
  status?: 'ok' | 'error'
  cluster_name?: string | null
  os_name?: string | null
  cpu_used_pct?: number | null
  mem_used_pct?: number | null
  storage_free_bytes?: number | null
  storage_total_bytes?: number | null
  vcpu_assigned?: number
  memory_assigned_bytes?: number
  vms?: CentralHypervVm[]
  problems?: Array<{ kind: string; severity: HypervSeverity; vm: string | null }>
}

// Redacted per-device firewall rule-usage + firewall-log activity summary
// an agent includes in its snapshot envelope (see services/
// firewall_analysis.py's public_summary()) — capped lists only, never
// the full raw rule set or full log text.
export interface CentralFirewallDeviceStatus {
  device_id: number
  device_name: string
  checked_at: string | null
  rules_active: number | null
  rules_unused: number | null
  unused_rule_labels: string[]
  log_count: number | null
  log_top_sources: Array<{ ip: string; count: number }>
  log_recent: Array<{ time?: string; chain?: string; proto?: string; src?: string; src_port?: string; dst?: string; dst_port?: string }>
}

// Host-monitoring summary an agent includes in its plaintext snapshot envelope
// (services/host_monitor.py's public_summary()): names, state, outage counts
// and causes only - IP/MAC and log lines stay in the encrypted snapshot.
export interface CentralHostmonHostStatus {
  id: number
  name: string
  state: 'up' | 'down' | null
  state_since: string | null
  last_probe_at: string | null
  outages_24h: number
  outages_7d: number
  downtime_24h_sec: number
  main_cause: string | null
  periodic_sec: number | null
  recent_outages: Array<{ start: string; end: string | null; duration_sec: number; code: string; confidence: 'high' | 'medium' | 'low' | null }>
}

// Redacted per-WAN-interface status an agent includes in its snapshot
// envelope (see services/edge_discovery.py's public_summary()) — checked
// locally by the agent from the router's own RouterOS "WAN" interface-list
// and its own running-state, not by an external ping (unlike edge_devices).
export interface CentralWanLinkStatus {
  device_name: string
  iface: string
  status: string
}

// Redacted compliance/hardening recommendations an agent includes in its
// snapshot envelope (see services/compliance.py's public_summary()) —
// FAILED checks only, i.e. actual recommendations to act on, not a full
// pass/fail report card.
export interface CentralComplianceFinding {
  target_type: 'linux' | 'windows' | 'mikrotik'
  label: string
  check_id: string
  title: string
  severity: string
  detail: string | null
  checked_at: string | null
}

// Redacted PRTG/Check_MK problem summaries an agent includes in its
// snapshot envelope (see services/prtg_monitor.py / checkmk_monitor.py's
// public_summary()) — only sensors/services/hosts currently in a problem
// state, not a full inventory.
export interface CentralPrtgSensor {
  device_name: string
  sensor_name: string
  status_name: string
  message: string | null
}

export interface CentralCheckmkService {
  device_name: string
  description: string
  state_name: string
  plugin_output: string | null
}

export interface CentralCheckmkHost {
  device_name: string
  state_name: string
}

export interface CentralWazuhAlert {
  device_name: string
  agent_name: string | null
  rule_level: number | null
  rule_description: string | null
}

// CRITICAL/HIGH-only CVE findings an agent includes in its plaintext
// snapshot envelope (see services/vuln_scan.py's public_summary()) — a
// deliberately narrower cut than the full vuln_findings_summary (which
// stays E2E-encrypted-only, CRITICAL/HIGH/MEDIUM); an explicit, informed
// tradeoff for Central visibility without requiring the tenant's key.
export interface CentralVulnFinding {
  cve_id: string
  severity: string
  cvss_score: number | null
  summary: string | null
  ref_url: string | null
  // Identify which VulnRemediation row a status change applies to
  // (product+version+cve_id, its real key) and the current status/note.
  product: string
  version: string
  status: string
  note: string | null
  kev?: boolean
  epss?: number | null
}

export interface CentralVulnHostFindings {
  ip: string
  device_name: string | null
  findings: CentralVulnFinding[]
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
  recommendation: string
  status: VulnRemediationStatus
  note: string | null
  updated_by: string | null
  updated_at: string | null
  first_seen_at: string | null
  due_date: string | null
  overdue: boolean
  kev?: boolean                     // exploited in attacks now (CISA KEV)
  kev_due?: string | null
  ransomware?: boolean
  epss?: number | null              // probability (0-1) of exploitation in the next 30 days (FIRST EPSS)
}

export interface VulnPackageOut {
  host_id: number
  ip: string
  hostname: string | null
  name: string
  version: string
  last_seen: string | null
}

// the organisation's NVD key kept in Central (ovh/nvd.php): whether it is set, who set it, and the use of it in the last 24 hours per client
export interface CentralNvdStatus {
  configured: boolean; updated_at: string | null; updated_by: string | null; cache_entries: number
  usage: Array<{ tenant: string; requests: number; upstream: number }>
}

export interface VulnSettings {
  nvd: { configured: boolean; source: 'app' | 'env' | null; interval_sec: number; mode: 'local' | 'central' | 'keyless'
         central: { url_set: boolean; available: boolean; no_key: boolean; down: boolean; last_error: string | null; last_error_at: string | null; last_ok_at: string | null
                    via_central: number; cache_hits: number; fallbacks: number }
         health?: { ok: number; errors: number; last_error: string | null; last_error_at: string | null; last_ok_at: string | null } }
  exploit?: { kev_count: number; kev_at: string | null; epss_count: number; error: string | null; error_at: string | null }
}
export const vulnApi = {
  status: () => api.get<VulnStatus>('/vuln/status').then(r => r.data),
  settings: () => api.get<VulnSettings>('/vuln/settings').then(r => r.data),
  saveSettings: (body: { nvd_key?: string; clear_nvd_key?: boolean }) => api.put<VulnSettings>('/vuln/settings', body).then(r => r.data),
  refreshExploit: () => api.post<NonNullable<VulnSettings['exploit']>>('/vuln/exploit-intel/refresh').then(r => r.data),
  packages: (params?: { host_id?: number; q?: string }) =>
    api.get<VulnPackageOut[]>('/vuln/packages', { params }).then(r => r.data),
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

// ── Compliance (configuration-hardening checks, not CVE-based) ────────────────

export type ComplianceTargetType = 'linux' | 'windows' | 'mikrotik'

export interface ComplianceResult {
  id: number
  target_type: ComplianceTargetType
  target_id: number
  check_id: string
  title: string
  severity: 'high' | 'medium' | 'low'
  passed: boolean | null
  detail: string | null
  checked_at: string | null
}

export interface ComplianceSummaryRow {
  target_type: ComplianceTargetType
  target_id: number
  label: string
  passed: number
  failed: number
  unknown: number
  total: number
}

export const complianceApi = {
  summary: () => api.get<ComplianceSummaryRow[]>('/compliance/summary').then(r => r.data),
  results: (targetType?: ComplianceTargetType, targetId?: number) =>
    api.get<ComplianceResult[]>('/compliance/results', {
      params: { target_type: targetType, target_id: targetId },
    }).then(r => r.data),
  run: (targetType: ComplianceTargetType, targetId: number) =>
    api.post<{ queued: boolean }>(`/compliance/run/${targetType}/${targetId}`).then(r => r.data),
}

// ── Inventory (grouped view of everything the scanner found) ─────────────────

export interface InventoryNetworkEntry {
  ip: string
  name: string | null
  model: string | null
  vendor: string | null
  version: string | null
  findings_count: number
}

export interface InventoryHostEntry {
  ip: string
  hostname: string | null
  os: string | null
  ports: number[]
  findings_count: number
}

export interface InventoryOut {
  network: InventoryNetworkEntry[]
  windows: InventoryHostEntry[]
  linux: InventoryHostEntry[]
  other: InventoryHostEntry[]
}

// ── Asset inventory (services/assets.py) ──────────────────────────────────────

export type AssetType = 'windows' | 'linux' | 'network' | 'printer' | 'virtual' | 'server' | 'camera' | 'mobile' | 'monitor' | 'other'
export type AssetLifecycle = 'supported' | 'ending' | 'eol' | 'unknown'
export type AssetScanLevel = 'credentialed' | 'snmp' | 'passive'

export interface AssetVulnCounts { critical: number; high: number; medium: number; low: number; total: number }

// where an asset is plugged in, from the last map of the network: the port of a switch (its MAC was learned there), or - without a port - the router /
// Hyper-V host it hangs under
export interface AssetAttach {
  to: string; to_id: number; to_ip?: string | null; kind: 'client' | 'uplink' | 'l3' | 'vm' | 'wifi'; port: string | null; vlan: number | null
  iface?: string | null; ssid?: string | null; signal?: number | null     // "wifi": the interface of the access point, the network and the signal (dBm) it hears the device with
  shared: number | null              // other MACs learned on the same port: something (a switch, an access point) is behind it
  how: string | null                 // for "l3": ARP/DHCP | traceroute | subnet
}

export interface AssetRow {
  id: number
  name: string
  ip: string | null
  mac: string | null
  type: AssetType
  role: 'server' | 'workstation' | null
  dclass?: string | null            // gateway / router / switch / ap / apple / raspberry / vm
  hints?: string[]                  // embedded device kinds often left on a factory password (ilo, printer, camera ...)
  via?: string | null               // the gateway of a host in a routed range (the last hop of a traceroute)
  hops?: number | null
  manufacturer: string | null
  model: string | null
  serial: string | null
  os_name: string | null
  os_version: string | null
  location: string | null
  place?: string | null              // where it physically is (room, desk, socket), as written by the operator
  attach?: AssetAttach | null
  groups: string[]
  scan_level: AssetScanLevel
  lifecycle: AssetLifecycle
  lifecycle_product: string | null
  eol: string | null
  vulns: AssetVulnCounts
  risk: number
  first_seen_at: string | null
  last_seen_at: string | null
  last_scan_at: string | null
  active: boolean
  refs?: Record<string, number>
}

export interface AssetSummary {
  total: number
  total_7d_ago: number
  new_7d: number
  new_by_day: Array<{ day: string; n: number }>
  by_type: Array<{ key: AssetType; n: number }>
  by_location: Array<{ name: string; n: number }>
  by_lifecycle: Record<AssetLifecycle, number>
  by_scan_level: Record<AssetScanLevel, number>
  inactive: number
  vulnerable: { assets: number; critical: number; high: number; medium: number; low: number }
  top_risk: AssetRow[]
  last_refresh: string | null
}

// What an agent sends to Central about its assets: numbers and compact rows, never serial numbers or MAC addresses
export interface AssetsPublicRow {
  id?: number; n: string; ip: string | null; t: AssetType; r: 'server' | 'workstation' | null; mf: string | null; md: string | null; os: string | null
  pl?: string | null                                           // physical place, as written by the operator
  at?: [string, string | null, number | null, number | null, string]   // attached to: [device, port, VLAN, other MACs on the port, how it is known]
  lc: AssetLifecycle; v: [number, number, number, number]; loc: string | null; sl: AssetScanLevel; seen: number | null
  // what Central may ask the agent to do with the device (ids and flags only)
  x?: { k: 'linux' | 'windows' | 'device' | 'vm'; id: number; m?: boolean; u?: number | null; rb?: boolean; ws?: boolean; st?: string | null }
}
export interface AssetsPublic {
  summary: Pick<AssetSummary, 'total' | 'total_7d_ago' | 'new_7d' | 'new_by_day' | 'by_type' | 'by_location' | 'by_lifecycle' | 'by_scan_level' | 'inactive' | 'vulnerable'>
  rows: AssetsPublicRow[]
  truncated: boolean
}

export interface AssetPeripheralOut {
  id: number
  kind: 'monitor' | 'printer' | 'usb' | 'other'
  name: string | null
  manufacturer: string | null
  model: string | null
  serial: string | null
  details: Record<string, any>
  last_seen_at: string | null
}

export interface AssetDetail extends AssetRow {
  notes: string | null
  manual_groups: string[]
  location_override: string | null
  lifecycle_detail: { product: string | null; status: AssetLifecycle; eol: string | null; days_left: number | null }
  refs: Record<string, number>
  override: { type?: string; role?: string }
  parent: string | null
  installed_on?: Array<{ id: number; name: string; queue: string | null }>
  hardware: Record<string, any>
  peripherals: AssetPeripheralOut[]
  services: Array<{ port: number; proto: string | null; service: string | null; product: string | null; version: string | null }>
  software_count: number
  scan: { level: AssetScanLevel; last_scan_at: string | null; status: string | null; error: string | null; running: boolean; available: boolean }
}

export interface AssetFinding {
  cve_id: string
  severity: string
  cvss_score: number | null
  summary: string | null
  ref_url: string | null
  product: string
  version: string
  status: string
  note: string | null
}

export interface AssetDuplicateGroup {
  ids: number[]; reasons: Array<'ref' | 'mac' | 'name'>; auto: boolean; keep: number
  assets: Array<{ id: number; name: string; ip: string | null; mac: string | null; type: string; last_seen_at: string | null; alive: boolean; managed: string[]; has_notes: boolean }>
}
export const assetsApi = {
  summary: () => api.get<AssetSummary>('/assets/summary').then(r => r.data),
  list: () => api.get<{ assets: AssetRow[] }>('/assets').then(r => r.data.assets),
  get: (id: number) => api.get<AssetDetail>(`/assets/${id}`).then(r => r.data),
  vulnerabilities: (id: number) => api.get<{ findings: AssetFinding[] }>(`/assets/${id}/vulnerabilities`).then(r => r.data.findings),
  playbook: (id: number, lang: string) => api.get<{ filename: string; markdown: string }>(`/assets/${id}/playbook`, { params: { lang } }).then(r => r.data),
  software: (id: number) => api.get<{ software: Array<{ name: string; version: string | null; last_seen: string | null }> }>(`/assets/${id}/software`).then(r => r.data.software),
  refresh: () => api.post('/assets/refresh').then(r => r.data),
  scanSettings: () => api.get<{ computers_hours: number; devices_hours: number }>('/assets/scan-settings').then(r => r.data),
  setScanSettings: (body: { computers_hours?: number; devices_hours?: number }) => api.put<{ computers_hours: number; devices_hours: number }>('/assets/scan-settings', body).then(r => r.data),
  discover: () => api.post<{ sweep: { alive: number; ranges: Array<{ cidr: string; label?: string | null; probed?: number; alive?: number; skipped?: string }> }; inventory: { created?: number; total?: number } }>('/assets/discover').then(r => r.data),
  vulnHistory: (days = 90) => api.get<{ points: Array<{ day: string; assets: number; critical: number; high: number; medium: number; low: number }> }>('/assets/vuln-history', { params: { days } }).then(r => r.data),
  scan: (id: number) => api.post<{ started: boolean }>(`/assets/${id}/scan`).then(r => r.data),
  scanAll: () => api.post<{ started: number }>('/assets/scan-all').then(r => r.data),
  update: (id: number, body: { asset_type?: string; role?: string; name?: string; location_override?: string | null; place?: string | null; notes?: string | null; manual_groups?: string[] }) =>
    api.put(`/assets/${id}`, body).then(r => r.data),
  remove: (id: number) => api.delete(`/assets/${id}`).then(r => r.data),
  tool: (id: number, tool: 'ping' | 'traceroute' | 'portscan', ports?: string) => api.post<{ job: string }>(`/assets/${id}/tools`, { tool, ports }).then(r => r.data),
  toolOutput: (job: string, since = 0) => api.get<{ kind: string; ip: string; lines: string[]; next: number; done: boolean }>(`/assets/tools/${job}`, { params: { since } }).then(r => r.data),
  duplicates: () => api.get<{ groups: AssetDuplicateGroup[] }>('/assets/duplicates').then(r => r.data.groups),
  merge: (keepId: number, dropIds: number[]) => api.post<{ merged: number }>('/assets/merge', { keep_id: keepId, drop_ids: dropIds }).then(r => r.data),
  bulkDelete: (ids: number[]) => api.post<{ deleted: number; managed: number }>('/assets/bulk', { ids, action: 'delete' }).then(r => r.data),
  bulkType: (ids: number[], asset_type: string) => api.post<{ changed: number }>('/assets/bulk', { ids, action: 'type', asset_type }).then(r => r.data),
}

// ── Server racks ──────────────────────────────────────────────────────────────

export interface RackRemote { kind: 'lldp' | 'mac' | 'multi'; name: string; ip?: string | null; port?: string | null; assetId?: number | null; count?: number; hosts?: Array<{ name: string; ip?: string | null }> }
export interface RackPoe { mode?: string | null; on?: boolean | null; status?: string | null; watts?: number | null; off?: boolean }
export interface RackPort { name: string; up: boolean | null; disabled?: boolean; speed?: string | null; vlan?: string | null; comment?: string | null; rx?: number | null; tx?: number | null; remote?: RackRemote | null; poe?: RackPoe | null }
export interface RackNic { name: string | null; ips: string[]; connected?: { item_id: number; port: string; vlan?: string | null } | null }
export interface RackItemView {
  id: number; kind: string; label: string; u: number; height: number; portCount: number | null; notes?: string | null
  asset: { id: number; type: AssetType; role?: string | null; ip?: string | null; model?: string | null; manufacturer?: string | null; online: boolean | null; managed?: boolean } | null
  ports: RackPort[]; nics: RackNic[]; error?: string | null; poeTotal?: { budget_w: number; used_w: number } | null
  pending?: boolean                                  // placed in Central but not yet applied by the agent
}
export interface RackLinkView { id: number | null; a: number; aPort: string | null; b: number | null; bPort: string | null; remote?: string | null; label?: string | null; cable?: string | null; kind: 'lldp' | 'mac' | 'manual' }
export interface RackView { id: number; name: string; location: string | null; units: number; notes?: string | null; items: RackItemView[]; links: RackLinkView[] }

export interface RackSummary { id: number; name: string; location: string | null; units: number; notes: string | null; items: number; used_u: number }
export interface RackPaletteAsset { id: number; name: string; type: AssetType; role: string | null; ip: string | null; model: string | null; location: string | null; infra: boolean; suggested: boolean }
export interface RackDetailRaw {
  id: number; name: string; location: string | null; units: number; notes: string | null
  items: Array<{ id: number; kind: string; label: string; u: number; height: number; port_count: number | null; notes: string | null
    asset: { id: number; name: string; type: AssetType; role: string | null; ip: string | null; model: string | null; manufacturer: string | null; online: boolean | null; managed: boolean } | null }>
  links: Array<{ id: number; a: number; a_port: string | null; b: number | null; b_port: string | null; remote: string | null; label: string | null; cable: string | null; kind: 'manual' }>
}
export interface RackLiveRaw {
  items: Record<string, { online: boolean | null; ports: Array<{ name: string; up: boolean | null; disabled?: boolean; speed?: string | null; vlan?: string | null; comment?: string | null; rx_mbps?: number | null; tx_mbps?: number | null; poe?: RackPoe | null
    remote?: { kind: 'lldp' | 'mac' | 'multi'; name: string; ip?: string | null; port?: string | null; asset_id?: number | null; count?: number; hosts?: Array<{ name: string; ip?: string | null }> } | null }> | null
    nics: RackNic[]; error: string | null; poe_total?: { budget_w: number; used_w: number } | null }>
  links: Array<{ id: number | null; a: number; a_port: string | null; b: number | null; b_port: string | null; remote: string | null; label: string | null; cable: string | null; kind: 'lldp' | 'mac' | 'manual' }>
  at: string
}

/** the rack as the diagram draws it: the stored placement plus (when it has arrived) what the devices report live */
export function rackFromAgent(r: RackDetailRaw, live?: RackLiveRaw | null): RackView {
  return {
    id: r.id, name: r.name, location: r.location, units: r.units, notes: r.notes,
    items: r.items.map(i => {
      const l = live?.items[String(i.id)]
      return {
        id: i.id, kind: i.kind, label: i.label, u: i.u, height: i.height, portCount: i.port_count, notes: i.notes,
        asset: i.asset ? { id: i.asset.id, type: i.asset.type, role: i.asset.role, ip: i.asset.ip, model: i.asset.model, manufacturer: i.asset.manufacturer, online: l?.online ?? i.asset.online, managed: i.asset.managed } : null,
        ports: (l?.ports ?? []).map(p => ({ name: p.name, up: p.up, disabled: p.disabled, speed: p.speed, vlan: p.vlan, comment: p.comment, rx: p.rx_mbps, tx: p.tx_mbps, poe: p.poe,
          remote: p.remote ? { kind: p.remote.kind, name: p.remote.name, ip: p.remote.ip, port: p.remote.port, assetId: p.remote.asset_id, count: p.remote.count, hosts: p.remote.hosts } : null })),
        nics: l?.nics ?? [], error: l?.error ?? null, poeTotal: l?.poe_total ?? null,
      }
    }),
    links: (live?.links ?? r.links).map(l => ({ id: l.id, a: l.a, aPort: l.a_port, b: l.b, bPort: l.b_port, remote: l.remote, label: l.label, cable: l.cable, kind: l.kind })),
  }
}

// what Central receives (compact keys, see services/racks.py public_summary)
export interface CentralRack {
  id: number; n: string; loc: string | null; u: number; nt?: string | null
  items: Array<{ id: number; k: string; l: string; u: number; h: number; pc: number | null
    a: { id: number; t: AssetType; r: string | null; ip: string | null; md: string | null; mf: string | null; on: boolean | null } | null
    pt?: { budget_w: number; used_w: number } | null
    p: Array<{ n: string; up: boolean | null; sp: string | null; v: string | null; c: string | null; rx: number | null; tx: number | null; po?: { m?: string; on?: boolean; st?: string; w?: number; off?: boolean } | null; rm: { k: 'lldp' | 'mac' | 'multi'; n: string; ip?: string; p?: string; aid?: number; c?: number; hs?: Array<{ n: string; ip?: string | null }> } | null }>
    nic: Array<{ n: string | null; ip: string[]; c: { item_id: number; port: string; vlan?: string | null } | null }> }>
  links: Array<{ a: number; ap: string | null; b: number | null; bp: string | null; rm: string | null; lb: string | null; cb: string | null; k: 'lldp' | 'mac' | 'manual' }>
}
export interface CentralRackOp { at: number; op: string; ok: boolean; error: string | null }
export function rackFromCentral(r: CentralRack): RackView {
  return {
    id: r.id, name: r.n, location: r.loc, units: r.u,
    items: r.items.map(i => ({
      id: i.id, kind: i.k, label: i.l, u: i.u, height: i.h, portCount: i.pc,
      asset: i.a ? { id: i.a.id, type: i.a.t, role: i.a.r, ip: i.a.ip, model: i.a.md, manufacturer: i.a.mf, online: i.a.on } : null,
      poeTotal: i.pt ?? null,
      ports: i.p.map(p => ({ name: p.n, up: p.up, speed: p.sp, vlan: p.v, comment: p.c, rx: p.rx, tx: p.tx, poe: p.po ? { mode: p.po.m, on: p.po.on, status: p.po.st, watts: p.po.w, off: p.po.off } : null,
        remote: p.rm ? { kind: p.rm.k, name: p.rm.n, ip: p.rm.ip, port: p.rm.p, assetId: p.rm.aid, count: p.rm.c, hosts: p.rm.hs?.map(h => ({ name: h.n, ip: h.ip })) } : null })),
      nics: i.nic.map(n => ({ name: n.n, ips: n.ip ?? [], connected: n.c })),
    })),
    links: r.links.map(l => ({ id: null, a: l.a, aPort: l.ap, b: l.b, bPort: l.bp, remote: l.rm, label: l.lb, cable: l.cb, kind: l.k })),
  }
}

export const racksApi = {
  list: () => api.get<{ racks: RackSummary[] }>('/racks').then(r => r.data.racks),
  get: (id: number) => api.get<RackDetailRaw>(`/racks/${id}`).then(r => r.data),
  live: (id: number) => api.get<RackLiveRaw>(`/racks/${id}/live`).then(r => r.data),
  palette: (rackId?: number) => api.get<{ assets: RackPaletteAsset[] }>('/racks/palette', { params: { rack_id: rackId } }).then(r => r.data.assets),
  create: (body: { name: string; location?: string | null; units: number; notes?: string | null }) => api.post<RackSummary>('/racks', body).then(r => r.data),
  update: (id: number, body: { name: string; location?: string | null; units: number; notes?: string | null }) => api.put<RackSummary>(`/racks/${id}`, body).then(r => r.data),
  remove: (id: number) => api.delete(`/racks/${id}`).then(r => r.data),
  addSuggested: (id: number) => api.post<{ placed: number }>(`/racks/${id}/suggested`).then(r => r.data),
  addItem: (rackId: number, body: { u: number; height?: number; asset_id?: number; kind?: string; label?: string; port_count?: number }) => api.post(`/racks/${rackId}/items`, body).then(r => r.data),
  updateItem: (id: number, body: { u?: number; height?: number; label?: string; notes?: string; port_count?: number; rack_id?: number }) => api.put(`/racks/items/${id}`, body).then(r => r.data),
  removeItem: (id: number) => api.delete(`/racks/items/${id}`).then(r => r.data),
  addLink: (rackId: number, body: { item_a_id: number; port_a?: string; item_b_id?: number | null; port_b?: string; remote_text?: string; label?: string; cable?: string }) => api.post(`/racks/${rackId}/links`, body).then(r => r.data),
  removeLink: (id: number) => api.delete(`/racks/links/${id}`).then(r => r.data),
}

// ── Network map ───────────────────────────────────────────────────────────────

export interface NetMap {
  nodes: Array<{ id: number | string; name: string; type: AssetType | 'subnet' | 'internet'; role?: string | null; cls?: string | null; ip?: string | null; mf?: string | null; md?: string | null; v: number; vn?: number; sub: string | null; lvl: number | null }>
  edges: Array<{ a: number | string; b: number | string; k: 'backbone' | 'uplink' | 'client' | 'l3' | 'vm' | 'wifi'; l: string }>
  subnets: Array<{ cidr: string; n: number }>
  at: string; partial: boolean; building?: boolean
}
export const netmapApi = {
  get: () => api.get<NetMap>('/netmap').then(r => r.data),
  refresh: () => api.post<NetMap>('/netmap/refresh').then(r => r.data),
}
// what Central receives: nodes [id, name, type, ip, vulnerability, subnet, level], edges [a, b, kind, label]
export interface CentralNetMap { n: Array<[number | string, string, NetMap['nodes'][number]['type'], string | null, number, string | null, number | null, (string | null)?]>; e: Array<[number | string, number | string, NetMap['edges'][number]['k'], string]>; at: string }
export function netmapFromCentral(m: CentralNetMap): Pick<NetMap, 'nodes' | 'edges'> {
  return {
    nodes: m.n.map(([id, name, type, ip, v, sub, lvl, cls]) => ({ id, name, type, ip, v, sub, lvl, cls })),
    edges: m.e.map(([a, b, k, l]) => ({ a, b, k, l })),
  }
}

// ── On-site view ──────────────────────────────────────────────────────────────

// Its own client without the "401 -> reload the page" of `api`: the page is also opened by a visitor with a key, and must say "no access" instead of reloading.
const onsiteHttp = axios.create({ baseURL: '/api', withCredentials: true })
const ONSITE_KEY = 'mm_onsite_key'
export const onsiteKey = {
  get: (): string | null => { try { return sessionStorage.getItem(ONSITE_KEY) } catch { return null } },
  /** The key of a shared link is in its # part (never sent to a server, never in a log): kept for this tab. */
  takeFromHash: () => {
    const m = /[#&]k=([^&]+)/.exec(window.location.hash)
    if (m) { try { sessionStorage.setItem(ONSITE_KEY, decodeURIComponent(m[1])) } catch { /* storage unavailable */ } }
  },
}
onsiteHttp.interceptors.request.use(cfg => { const k = onsiteKey.get(); if (k) cfg.headers.set('X-Onsite-Key', k); return cfg })

export interface OnsiteMapState { at: string | null; building: boolean }
export interface OnsiteHost {
  id: number; name: string; ip: string | null; mac: string | null; type: AssetType; dclass?: string | null; manufacturer: string | null; model: string | null
  location: string | null; place: string | null; last_seen_at: string | null; active: boolean
  attach: { to: string; to_id: number; port: string | null; vlan: number | null; shared: number | null; kind: 'client' | 'uplink' | 'l3' | 'vm' | 'wifi'; how: string | null
            iface?: string | null; ssid?: string | null; signal?: number | null } | null
}
export interface OnsiteShare { enabled: boolean; key: string | null; admin: boolean }
export const onsiteApi = {
  hosts: (all = false) => onsiteHttp.get<{ items: OnsiteHost[]; map: OnsiteMapState }>('/onsite/hosts', { params: { all } }).then(r => r.data),
  switches: () => onsiteHttp.get<{ items: Array<{ id: number; name: string; ip: string | null; ports: number; hosts: number; wifi: number; place: string | null }>; map: OnsiteMapState }>('/onsite/switches').then(r => r.data),
  switchPorts: (id: number) => onsiteHttp.get<{ switch: { id: number; name: string; ip: string | null; place: string | null }; ports: Array<{ port: string; vlan: number | null; devices: OnsiteHost[] }>
    wifi: Array<{ ssid: string | null; iface: string | null; devices: Array<OnsiteHost & { signal: number | null }> }>; map: OnsiteMapState }>(`/onsite/switch/${id}`).then(r => r.data),
  shareGet: () => onsiteHttp.get<OnsiteShare>('/onsite/share').then(r => r.data),
  shareSet: (body: { enabled?: boolean; regenerate?: boolean }) => onsiteHttp.post<OnsiteShare>('/onsite/share', body).then(r => r.data),
}

// ── SOC ───────────────────────────────────────────────────────────────────────

export type SocSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type SocStatus = 'new' | 'ack' | 'in_progress' | 'false_positive' | 'closed'
export const SOC_SEVERITIES: SocSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
export const SOC_STATUSES: SocStatus[] = ['new', 'ack', 'in_progress', 'false_positive', 'closed']
export interface SocAlert {
  esc_level?: number; maintenance?: string | null              // escalated for staying unacknowledged; the maintenance window that mutes its device now
  root_asset_id?: number | null; root_name?: string | null      // availability alerts: the device that is down above this one (this one is a consequence)
  id: number; rule: string; source: string; category: string; severity: SocSeverity; title: string | null
  device_name: string | null; ip?: string | null; asset_id?: number | null; status: SocStatus; owner: string | null; count: number; mitre: string | null
  first_seen: string; last_seen: string; closed_at?: string | null; closed_by?: string | null
  detail: Record<string, any>; note?: string | null; log?: Array<{ t: string; who: string; a: string; v?: unknown }>
}
// availability (services/availability.py): state of the watched devices, uptime and outages
export interface AvailItem {
  id: number; name: string; ip: string | null; type: string | null; watched: boolean; mode: number | null
  state: 'up' | 'down' | 'unreachable' | null; since: string | null; uptime: Record<string, number | null>
  root: string | null; root_id?: number | null; detail: string | null; last_check: string | null
}
export interface AvailOverview {
  items: AvailItem[]; up: number; down: number; unreachable: number; interval_sec: number; last: { at: string | null; checked: number; duration_sec: number | null; error: string | null }
}
export interface AvailOutages {
  outages: Array<{ from: string; to: string | null; seconds: number; kind: 'down' | 'unreachable'; cause: string | null }>
  uptime: number | null; state: string | null; since?: string | null; days: number; affected: Array<{ id: number; name: string; ip: string | null }>
}
export const availApi = {
  overview: () => api.get<AvailOverview>('/availability').then(r => r.data),
  run: () => api.post('/availability/run').then(r => r.data),
  outages: (id: number, days = 30) => api.get<AvailOutages>(`/availability/${id}`, { params: { days } }).then(r => r.data),
  setMonitor: (id: number, mode: number | null) => api.put<{ ok: boolean }>(`/availability/${id}/monitor`, { mode }).then(r => r.data),
}
// coverage: which sources of the agent report (services/coverage.py)
export interface CoverageItem { id: string; group: string; name: string; state: 'ok' | 'stale' | 'error' | 'off'; last_ok: string | null; expected_s: number | null; error: string | null; detail: string | null; stale_items: string[]; total: number | null }
export const coverageApi = { report: () => api.get<{ items: CoverageItem[]; summary: Record<'ok' | 'stale' | 'error' | 'off', number>; uptime_s: number; at: string }>('/coverage').then(r => r.data) }
// Response actions with approval (services/soar.py)
export interface SoarResult { device: string; ok: boolean; error?: string; rule_present?: boolean; position?: string }
export interface SoarAction {
  id: number; kind: 'block_ip' | 'install_rule'; target: string | null; devices: Array<{ id: number; name: string }>; ttl_min: number; reason: string; alert_id: number | null
  status: 'pending' | 'approved' | 'rejected' | 'executed' | 'failed' | 'expired' | 'lifted'; proposed_by: string | null; proposed_at: string | null; decided_by: string | null; decided_at: string | null
  executed_at: string | null; expires_at: string | null; result: SoarResult[]; internal: boolean
}
export interface SoarOverview {
  settings: { enabled: boolean; central_approval: boolean }; pending: SoarAction[]; active: SoarAction[]; history: SoarAction[]
  routers: Array<{ id: number; name: string; ip: string; online: boolean; mgmt_ok: boolean | null }>
}
export interface SoarProposal { kind: 'block_ip' | 'install_rule'; target?: string; device_ids: number[]; ttl_min?: number; reason: string; alert_id?: number | null; allow_internal?: boolean }
export const soarApi = {
  overview: () => api.get<SoarOverview>('/soar').then(r => r.data),
  settings: (body: { enabled?: boolean; central_approval?: boolean }) => api.put('/soar/settings', body).then(r => r.data),
  candidates: (alertId: number) => api.get<{ addresses: string[] }>(`/soar/candidates/${alertId}`).then(r => r.data.addresses),
  propose: (body: SoarProposal) => api.post<{ id: number }>('/soar/propose', body).then(r => r.data),
  decide: (id: number, approve: boolean) => api.post<SoarAction>(`/soar/${id}/decide`, { approve }).then(r => r.data),
  unblock: (target: string) => api.post('/soar/unblock', { target }).then(r => r.data),
}
// The card of one host (services/hostcard.py)
export interface HostCardAlert { id: number; rule: string; title: string | null; severity: SocSeverity; status: string; source: string; category: string; count: number; first_seen: string | null; last_seen: string | null; message: string }
export interface HostCard {
  ref: string; asset_id: number; name: string; ip: string | null
  ci: { class: string; type: string; role: string | null; manufacturer: string | null; model: string | null; serial: string | null; os: string | null; os_version: string | null
        lifecycle: { product: string | null; status: string; eol: string | null; days_left: number | null } | null; owner: string | null; criticality: string | null; place: string | null; location: string | null
        tags: string[]; groups: string[]; notes: string | null; first_seen: string | null; last_seen: string | null; ci_status: 'operational' | 'inactive' | 'unknown'; mac: string | null
        scan: { level: string; last_scan_at: string | null; status: string | null; error: string | null } | null }
  status: { availability: { state: string; since: string | null; uptime: number | null; outages: Array<{ from: string; to: string | null; seconds: number; kind: string; cause: string | null }>; affects: Array<{ id: number; name: string; ip: string | null }> } | null
            maintenance: Array<{ id: number; name: string; until: string | null; weekly?: boolean }>; health: { level: 'ok' | 'warn' | 'crit'; critical: string[]; warnings: string[] } }
  sources: Array<{ kind: string; label?: string; id: number | null; path: string }>
  alerts: { open: HostCardAlert[]; open_count: number; closed_30d: number; recent_closed: HostCardAlert[] }
  vulnerabilities: { counts: Record<string, number>; total: number; kev: number; accepted: number; top: Array<{ cve_id: string; severity: string | null; cvss: number | null; kev: boolean; epss: number | null; product: string | null; version: string | null; summary: string; url: string | null }> } | null
  tls: Array<{ port: number; subject: string | null; issuer: string | null; days: number | null; protocol: string | null; findings: Array<{ code: string; severity: string; message: string }>; error: string | null }>
  services: Array<{ port: number; proto: string; service: string | null; product: string | null; version: string | null; seen: string | null }>
  updates: { windows?: { id: number; upgradable: number | null; reboot_required: boolean; last_check: string | null; last_upgrade: string | null; titles: string[]; status: string | null; error: string | null; managed: boolean }
            linux?: { id: number; upgradable: number | null; reboot_required: boolean; last_check: string | null; last_upgrade: string | null; packages: unknown[]; status: string | null; error: string | null; managed: boolean; distro: string | null }
            device?: { id: number; version: string | null; latest: string | null; update_status: string | null; firmware: string | null; upgrade_firmware: string | null } } | null
  resources: { now: { cpu: number | null; mem: number | null; disk: number | null; temp: number | null; at: string; source: string } | null; series: Array<{ key: string; name: string; kind: string; unit: string | null; value: number | null; at: string | null }> } | null
  config: { device_id: number; last_check: string | null; last_change: string | null; error: string | null; versions: number; recent: Array<{ id: number; at: string; added: number | null; removed: number | null; sections: string[] }> } | null
  syslog: { count_24h: number; recent: Array<{ at: string; severity: string | null; kind: string | null; app: string | null; message: string }> } | null
  network: { attached_to: { id: number | null; name: string | null; ip: string | null; port: string | null; vlan: number | null; kind: string | null } | null; children: Array<{ id: number; name: string | null; port: string | null; vlan: number | null; kind: string | null }> } | null
  relationships: { depends_on: Array<{ id: number | null; name: string | null; ip: string | null; via: string | null }>; supports: Array<{ id: number; name: string | null; via: string | null }>; business_services: Array<{ id: number; name: string; mode: string }>
                   hosted_on: { name?: string } | null; hosts: Array<{ name: string; state: string | null }>; peripherals: Array<{ kind: string; name: string | null }> }
  response: Array<{ id: number; kind: string; status: string; reason: string; at: string | null; until: string | null }>
  access: { device_id: number; vendor: string | null; credential: string | null; online: boolean; mgmt_ok: boolean | null; last_seen: string | null; ports: { api: boolean; ssh: boolean; web: boolean; snmp: boolean } } | null
  bmc: Array<{ id: number; name: string | null; vendor: string | null; idrac_ip: string | null; bmc_ref: string | null; model: string | null; service_tag: string | null; bios: string | null; power: string | null
               health: 'OK' | 'Warning' | 'Critical' | null; access: string | null; last_check: string | null; status: 'ok' | 'error' | null; error: string | null; components: Record<string, 'OK' | 'Warning' | 'Critical' | null>
               sel: Array<{ severity: string | null; message: string; at: string | null }> }> | null
  software_count: number | null
  last_boot: { boot: { at: string; source: 'hardware_scan' | 'snmp' | 'routeros' | 'hyperv'; as_of: string; uptime_sec: number | null; approx: boolean; age_sec: number | null } | null; restarts: Array<{ at: string; count: number }> } | null
  timeline: Array<{ at: string; kind: string; severity: string; text: string; ref: number | null }>
  errors: string[]
}
export const hostCardApi = { get: (ref: string) => api.get<HostCard>(`/hostcard/${encodeURIComponent(ref)}`).then(r => r.data) }
// Which inventory asset an address or a name belongs to (services/last_boot.py), for links that only know a name
export const cardApi = {
  resolve: (ip?: string | null, name?: string | null) => api.get<{ asset_id: number | null }>('/card/resolve', { params: { ip: ip || undefined, name: name || undefined } }).then(r => r.data.asset_id),
}
// Connecting the devices (services/onboarding.py)
export interface OnboardingDevice {
  id: number; name: string; ip: string; vendor: string; model: string | null; online: boolean; mgmt_ok: boolean | null; credential: string | null; has_login: boolean; has_snmp_community: boolean
  state: 'no_credential' | 'snmp' | 'unverified' | 'ok'; last_read: string | null; ports: { api: boolean; ssh: boolean; web: boolean; snmp: boolean }
}
export interface OnboardingChannel { ok: boolean; detail?: string; code?: 'auth' | 'closed' | 'timeout' | 'other'; message?: string }
export interface OnboardingDiagnosis {
  device_id: number; name: string; ip: string; vendor: string; level: 'full' | 'snmp' | 'none'; channels: Record<string, OnboardingChannel>; best_credential: string | null
  best_credential_id: number | null; own_credential_id: number | null; tried: number; advice: string[]; results: Array<{ credential_id: number; credential: string; own: boolean; level: string }>
}
export const onboardingApi = {
  overview: () => api.get<{ devices: OnboardingDevice[]; ranges: Array<{ id: number; cidr: string; label: string | null; active: boolean }>; credentials: number; suggested_ranges: Array<{ cidr: string; hosts: number }>; agent_ip: string | null }>('/onboarding').then(r => r.data),
  test: (id: number) => api.post<OnboardingDiagnosis>(`/onboarding/test/${id}`, undefined, { timeout: 120000 }).then(r => r.data),
  assign: (ids: number[]) => api.post<{ results: Array<{ device_id: number; name: string; level: string; assigned: string | null; advice: string[] }> }>('/onboarding/assign', { device_ids: ids }, { timeout: 300000 }).then(r => r.data),
}
// Small network tools (services/netkit.py): Wake on LAN, SNMP browser, RDAP, path to a host
export interface NetkitHost { name: string; ip: string; mac: string | null; snmp: boolean; type: string }
export interface RdapResult { kind: string; handle: string | null; name: string | null; status: string[]; events: Array<{ action: string; date: string | null }>
                              entities: Array<{ roles: string[]; handle: string | null; name: string | null }>; country: string | null; type: string | null; range?: string | null; cidr?: string[]; nameservers?: string[] }
export interface PathHop { n: number; ip: string | null; ms: number | null; delta: number | null; name: string | null; scope: 'private' | 'public' | null }
export const netkitApi = {
  hosts: () => api.get<{ hosts: NetkitHost[] }>('/netkit/hosts').then(r => r.data.hosts),
  wol: (mac: string) => api.post<{ mac: string; sent_to: string[]; errors: string[] }>('/netkit/wol', { mac }).then(r => r.data),
  snmp: (body: { ip: string; op: 'get' | 'walk'; oid: string; community?: string }) =>
    api.post<{ rows: Array<{ oid: string; name: string | null; value: string }>; truncated: boolean }>('/netkit/snmp', body).then(r => r.data),
  rdap: (query: string) => api.post<RdapResult>('/netkit/rdap', { query }).then(r => r.data),
  path: (query: string) => api.post<{ target: string; ip: string; hops: PathHop[]; reached: boolean; error: string | null }>('/netkit/path', { query }, { timeout: 90000 }).then(r => r.data),
}
// TLS certificates and protocols (services/tls_scan.py)
export interface TlsFinding { code: string; severity: 'high' | 'medium' | 'low' | 'info'; message: string }
export interface TlsRow {
  id: number; ip: string; name: string; port: number; manual: boolean; subject: string | null; issuer: string | null; names: string[]; not_before: string | null; not_after: string | null
  days: number | null; key: string | null; sig: string | null; self_signed: boolean; protocol: string | null; cipher: string | null; legacy: string[]; findings: TlsFinding[]; last_check_at: string | null; error: string | null
}
export interface TlsOverview { settings: { enabled: boolean; warn_days: number; crit_days: number }; running: boolean; last: { at: string | null; error: string | null }; items: TlsRow[] }
export const tlsApi = {
  overview: () => api.get<TlsOverview>('/tls').then(r => r.data),
  settings: (body: { enabled?: boolean; warn_days?: number; crit_days?: number }) => api.put('/tls/settings', body).then(r => r.data),
  run: () => api.post<{ ok: boolean; checked: number }>('/tls/run').then(r => r.data),
  add: (ip: string, port: number) => api.post<{ id: number }>('/tls/targets', { ip, port }).then(r => r.data),
  remove: (id: number) => api.delete(`/tls/targets/${id}`).then(r => r.data),
}
// UPS units and SNMP sensors (services/ups_monitor.py)
export interface UpsState { source: string; battery: string; charge: number | null; minutes: number | null; load: number | null; temp: number | null; voltage: number | null; alarms: number; model: string | null; on_battery_s: number }
export interface UpsRow { id: number; name: string; ip: string; port: number; enabled: boolean; has_community: boolean; state: UpsState | null; last_check: string | null; last_ok: string | null; error: string | null }
export interface SensorRow { id: number; name: string; ip: string; port: number; oid: string; scale: number; unit: string | null; kind: string; enabled: boolean; has_community: boolean; value: number | null; last_check: string | null; error: string | null }
export const upsApi = {
  overview: () => api.get<{ ups: UpsRow[]; sensors: SensorRow[]; suggestions: Array<{ id: number; name: string; ip: string; model: string | null; manufacturer: string | null }> }>('/ups').then(r => r.data),
  test: (b: { ip: string; port: number; community: string | null }) => api.post<{ ok: boolean; state: UpsState | null }>('/ups/test', b).then(r => r.data),
  create: (b: { name: string; ip: string; port: number; community?: string }) => api.post<{ id: number }>('/ups', b).then(r => r.data),
  update: (id: number, b: { name: string; ip: string; port: number; community?: string }) => api.put<{ id: number }>(`/ups/${id}`, b).then(r => r.data),
  remove: (id: number) => api.delete(`/ups/${id}`).then(r => r.data),
  createSensor: (b: { name: string; ip: string; port: number; oid: string; scale: number; unit: string; kind: string; community?: string }) => api.post<{ id: number }>('/ups/sensors', b).then(r => r.data),
  removeSensor: (id: number) => api.delete(`/ups/sensors/${id}`).then(r => r.data),
  run: () => api.post('/ups/run').then(r => r.data),
}
// metrics with history, forecast and thresholds that last (services/metrics.py)
export interface MetricSeriesRow { key: string; name: string; kind: string; unit: string; asset_id: number | null; value: number | null; at: string | null; slope: number | null; r2: number | null; days_to_full: number | null; samples: number; stale: boolean }
export interface MetricRule { id?: string; name: string; kind: string; op: string; threshold: number; minutes: number; severity: string; match?: string | null; enabled: boolean }
export const metricsApi = {
  overview: () => api.get<{ series: MetricSeriesRow[]; rules: MetricRule[]; status: { at: string | null; series: number; error: string | null } }>('/metrics').then(r => r.data),
  series: (key: string, days: number) => api.get<{ key: string; points: Array<{ t: string; v: number }>; trend: { slope: number | null; r2: number | null; current: number | null; days_to_limit: number | null; span_days: number } }>('/metrics/series', { params: { key, days } }).then(r => r.data),
  saveRules: (rules: MetricRule[]) => api.put<{ rules: MetricRule[] }>('/metrics/rules', { rules }).then(r => r.data),
}
// security events of the managed hosts (services/host_logs.py)
export const hostLogsApi = {
  status: () => api.get<{ settings: { enabled: boolean; interval_min: number }; running: boolean
                          hosts: Array<{ kind: 'windows' | 'linux'; id: number; name: string; ip: string; last_run: string | null; last_ok: string | null; error: string | null; events: number }> }>('/host-logs').then(r => r.data),
  save: (b: { enabled?: boolean; interval_min?: number }) => api.put('/host-logs/settings', b).then(r => r.data),
  run: () => api.post('/host-logs/run').then(r => r.data),
}
// maintenance windows and escalation (services/maintenance.py, services/escalation.py)
export interface MaintWindow {
  id: number; name: string; kind: 'once' | 'weekly'; scope_all: boolean; asset_ids: number[]; assets: string[]; starts_at: string | null; ends_at: string | null
  days: number[]; start_time: string | null; duration_min: number | null; enabled: boolean; active: boolean; suppressed: number; created_by: string | null
}
export interface MaintBody {
  name: string; kind: 'once' | 'weekly'; starts_at?: string; ends_at?: string; days?: number[]; start_time?: string; duration_min?: number; scope_all: boolean; asset_ids: number[]; enabled: boolean
}
export const maintApi = {
  overview: () => api.get<{ windows: MaintWindow[]; escalation: { enabled: boolean; levels: Record<string, number[]> } }>('/maintenance').then(r => r.data),
  create: (b: MaintBody) => api.post<{ id: number }>('/maintenance', b).then(r => r.data),
  update: (id: number, b: MaintBody) => api.put<{ id: number }>(`/maintenance/${id}`, b).then(r => r.data),
  remove: (id: number) => api.delete(`/maintenance/${id}`).then(r => r.data),
  quick: (b: { asset_ids: number[]; minutes: number; scope_all: boolean }) => api.post<{ id: number }>('/maintenance/quick', b).then(r => r.data),
  escalation: (b: { enabled: boolean; levels: Record<string, number[]> }) => api.put('/maintenance/escalation', b).then(r => r.data),
}
// the AI assistant (services/ai_assistant.py)
export type AiScope = 'alerts' | 'assets' | 'vulnerabilities' | 'availability' | 'configs' | 'syslog'
export interface AiStatus {
  settings: { enabled: boolean; has_key: boolean; model: string; effort: string; scopes: Record<AiScope, boolean>; consent_at: string | null; consent_by: string | null; daily_limit: number
              models: string[]; efforts: string[]; ready: boolean; not_ready: string | null }
  queries: Array<{ at: string; user: string; question: string; tools: string[]; in: number; out: number; model: string; error: string | null }>
  today: number; tokens_30d: { in: number; out: number }
}
export const aiApi = {
  status: () => api.get<AiStatus>('/assistant/status').then(r => r.data),
  save: (body: Record<string, unknown>) => api.put('/assistant/settings', body).then(r => r.data),
  chat: (message: string, session_id: string | null) =>
    api.post<{ session_id: string; answer: string; tools: Array<{ name: string; input: unknown }>; usage: { in: number; out: number }; model: string }>('/assistant/chat', { message, session_id }, { timeout: 240000 }).then(r => r.data),
  endSession: (id: string) => api.delete(`/assistant/session/${id}`).then(r => r.data),
}
// configuration history of the MikroTik devices (services/config_history.py)
export interface CfgItem {
  vendor?: string
  id: number; name: string; ip: string; versions: number; last_check: string | null; last_error: string | null; last_change: string | null; last_version: string | null
  last_added: number | null; last_removed: number | null; last_sections: string[]
}
export interface CfgVersion { id: number; at: string; size: number; lines: number; added: number | null; removed: number | null; sections: string[] }
export interface CfgDiff { added: number; removed: number; sections: Record<string, { added: number; removed: number }>; hunks: Array<{ section: string; lines: Array<[string, string]> }>; a: number; b: number; sensitive: boolean }
export const cfgApi = {
  overview: () => api.get<{ items: CfgItem[]; settings: { enabled: boolean; interval_hours: number } }>('/config-history').then(r => r.data),
  versions: (id: number) => api.get<{ versions: CfgVersion[] }>(`/config-history/${id}`).then(r => r.data),
  diff: (id: number, a: number, b: number) => api.get<CfgDiff>(`/config-history/${id}/diff`, { params: { a, b } }).then(r => r.data),
  snapshot: (id: number) => api.post(`/config-history/${id}/snapshot`).then(r => r.data),
  run: () => api.post('/config-history/run').then(r => r.data),
  remove: (id: number) => api.delete(`/config-history/${id}`).then(r => r.data),
  settings: (body: { enabled?: boolean; interval_hours?: number }) => api.put('/config-history/settings', body).then(r => r.data),
}
// syslog and SNMP traps (services/syslog_receiver.py)
export interface SyslogRule {
  id: string; name: string; pattern: string; severity: string; source: string; threshold: number; window_sec: number; enabled: boolean
  builtin?: boolean; description?: string | null
}
export interface SyslogStatus {
  settings: { enabled: boolean; syslog_port: number; trap_port: number; accept_unknown: boolean; store_info: boolean; communities: number; rules: SyslogRule[]; disabled: string[] }
  listening: { syslog: boolean; trap: boolean }; errors: { syslog: string | null; trap: string | null }
  stats: { received: number; stored: number; unknown: number; rate_dropped: number; bad: number; traps: number; v3: number; bad_community: number; since: string | null }
  stored_24h: number; top_sources: Array<{ ip: string; n: number; name: string | null }>; unknown: Array<{ ip: string; n: number }>; rules: SyslogRule[]
}
export interface SyslogEventRow { id: number; at: string; ip: string; name: string | null; asset_id: number | null; host: string | null; app: string | null; severity: number; kind: string; message: string; raised: string[] }
export const syslogApi = {
  status: () => api.get<SyslogStatus>('/syslog/status').then(r => r.data),
  save: (body: Record<string, unknown>) => api.put('/syslog/settings', body).then(r => r.data),
  events: (p: { kind?: string; q?: string; max_severity?: number; ip?: string; limit?: number }) => api.get<{ total: number; items: SyslogEventRow[] }>('/syslog/events', { params: p }).then(r => r.data),
}
// business services (services/business_services.py)
export interface BizBody { name: string; description: string | null; mode: 'all' | 'any' | 'min'; min_up: number | null; target: number | null; members: number[] }
export interface BizMonth { uptime: number | null; down_min: number; target?: number; allowed_min?: number; left_min?: number; met?: boolean }
export interface BizService {
  id: number; name: string; description: string | null; mode: string; min_up: number | null; target: number | null; members: number[]; member_names: string[]
  state: 'ok' | 'degraded' | 'down' | 'unknown'; since: string | null; up: number; total: number; missing: string[]; uptime: Record<string, number | null>; month: BizMonth | null
}
export interface BizDetail extends BizService {
  days: number; outages: Array<{ from: string; to: string | null; seconds: number; kind: 'down' | 'degraded'; missing: string | null }>
  member_states: Array<{ id: number; name: string; state: 'up' | 'down' | 'unreachable' | null; root: string | null }>
}
export const bizApi = {
  list: () => api.get<{ items: BizService[]; ok: number; degraded: number; down: number }>('/services').then(r => r.data),
  get: (id: number, days = 30) => api.get<BizDetail>(`/services/${id}`, { params: { days } }).then(r => r.data),
  create: (body: BizBody) => api.post<{ id: number }>('/services', body).then(r => r.data),
  update: (id: number, body: BizBody) => api.put<{ id: number }>(`/services/${id}`, body).then(r => r.data),
  remove: (id: number) => api.delete(`/services/${id}`).then(r => r.data),
}
export interface SocStats {
  open: number; new: number; in_progress: number; by_severity: Record<SocSeverity, number>; by_category: Record<string, number>
  top_devices?: Array<{ name: string; n: number }>; opened_24h: number; closed_24h: number; false_positive_7d: number; mttr_hours: number | null
  opened_daily: Array<{ t: string; n: number }>; oldest_new_hours: number | null
}
export interface SocQuery { status?: string; severity?: string; category?: string; source?: string; q?: string; limit?: number; offset?: number }
// what a risk factor is made of: strings (a service "3389 RDP", a check, a CVE, a hint key) or - for alerts - {s: severity, r: rule, t: title}
export type SocRiskItem = string | { s: string; r: string; t: string | null }
export interface SocRiskFactor { k: string; pts: number; n?: number | null; items?: SocRiskItem[] | null }
export interface SocRiskRow {
  id: number; name: string; ip: string | null; loc?: string | null; type: string; dclass: string | null; score: number; level: 'critical' | 'high' | 'medium' | 'low'
  factors: SocRiskFactor[]; services?: string[]
}
export interface CentralRiskDevice {
  id: number; name: string; ip?: string | null; loc?: string | null; type: string; score: number; level: string
  factors: Array<[string, number, number | null, SocRiskItem[] | null]>; services?: string[]
}
export interface SocRisk { levels: Record<string, number>; total: number; items: SocRiskRow[] }
export interface SocRule {
  id: string; title: string; description: string; category: string; severity: string; mitre: string | null; interval_sec: number
  enabled: boolean; baselined: boolean; last_run: string | null; last_error: string | null; last_new: number | null; known: number
}
export const socApi = {
  risk: (limit = 300) => api.get<SocRisk>('/soc/risk', { params: { limit } }).then(r => r.data),
  rules: () => api.get<SocRule[]>('/soc/rules').then(r => r.data),
  ruleToggle: (id: string, enabled: boolean) => api.post<{ ok: boolean }>(`/soc/rules/${id}`, { enabled }).then(r => r.data),
  ruleRun: (id: string) => api.post<Record<string, { findings?: number; new?: number; raised?: number; baseline?: boolean; error?: string }>>(`/soc/rules/${id}/run`).then(r => r.data),
  alerts: (p: SocQuery) => api.get<{ total: number; items: SocAlert[] }>('/soc/alerts', { params: p }).then(r => r.data),
  alert: (id: number) => api.get<SocAlert>(`/soc/alerts/${id}`).then(r => r.data),
  update: (body: { ids: number[]; status?: SocStatus; owner?: string | null; note?: string | null; set_owner?: boolean; set_note?: boolean }) =>
    api.post<{ changed: number }>('/soc/alerts/update', body).then(r => r.data),
  stats: () => api.get<SocStats>('/soc/stats').then(r => r.data),
}
// what Central receives (compact; no internal addresses): the numbers and the open alerts, worst first
export interface CentralSoc {
  at: string | null; stats: SocStats | null
  risk?: { levels: Record<string, number>; scored: number; top: CentralRiskDevice[] }
  availability?: { up: number; down: number; unreachable: number; bad: Array<{ n: string; s: 'down' | 'unreachable'; since: string | null; root: string | null }>; at: string }
  coverage?: { summary: Record<string, number>; silent: Array<{ n: string; s: string; items: string[] }> }
  tls?: { total: number; expired: number; expiring: number; weak: number; intercepted: number; worst: Array<{ n: string; p: number; d: number | null; f: string[] }> }
  soar?: { enabled: boolean; central_approval: boolean; active: number
           pending: Array<{ id: number; kind: 'block_ip' | 'install_rule'; target: string | null; devices: string[]; ttl_min: number; reason: string; by: string | null; at: string | null; internal: boolean }> }
  configs?: { tracked: number; changed_24h: Array<{ n: string; at: string; added: number | null; removed: number | null; sections: string[] }> }
  syslog?: { on: boolean; listening: { syslog: boolean; trap: boolean }; stored_24h: number; sources: number; unknown: number; errors: string[] }
  services?: { ok: number; degraded: number; down: number
               items: Array<{ n: string; s: 'ok' | 'degraded' | 'down' | 'unknown'; since: string | null; up: number; total: number; missing: string[]; mode: string; min?: number | null; u30: number | null; month: BizMonth | null }> }
  alerts: Array<{ id: number; rule: string; source: string; category: string; severity: SocSeverity; title: string | null; device: string | null; asset?: number | null; status: SocStatus
                  owner: string | null; count: number; first: string; last: string; mitre: string | null; detail: Record<string, any>; root?: string | null }>
}
export function socFromCentral(s: CentralSoc): SocAlert[] {
  return s.alerts.map(a => ({ id: a.id, rule: a.rule, source: a.source, category: a.category, severity: a.severity, title: a.title, device_name: a.device, asset_id: a.asset ?? null,
                              status: a.status, owner: a.owner, count: a.count, mitre: a.mitre, first_seen: a.first, last_seen: a.last, detail: a.detail, root_name: a.root ?? null }))
}

// ── Traffic analyzer (RouterOS Torch) ───────────────────────────────────────

export interface TrafficFlow { src: string; dst: string; proto: string; sport: number | null; dport: number | null; service: string | null; tx: number; rx: number }
export interface TrafficDevice { ip: string; up: number; down: number; flows: number; name: string | null; asset_id: number | null; type: string | null; local: boolean }
export interface TrafficSample { flows: TrafficFlow[]; agg: { devices: TrafficDevice[]; protocols: Array<[string, number]>; services: Array<[string, number]> }; at: string; interface: string; seconds: number }
export const trafficApi = {
  devices: () => api.get<{ devices: Array<{ id: number; name: string; ip: string }> }>('/traffic/devices').then(r => r.data.devices),
  interfaces: (id: number) => api.get<{ interfaces: string[] }>(`/traffic/interfaces/${id}`).then(r => r.data.interfaces),
  sample: (device_id: number, iface: string, seconds = 3) => api.post<TrafficSample>('/traffic/sample', { device_id, interface: iface, seconds }).then(r => r.data),
}

export const inventoryApi = {
  get: () => api.get<InventoryOut>('/inventory').then(r => r.data),
}

// ── Linux host management (apt update/upgrade) ────────────────────────────────

// What the server boards show of a host's current / last job (status, reason, error — never the log)
export interface HostJobView {
  status: string | null
  reason: string | null
  error: string | null
}

// An operator-defined group of servers of one platform (services/host_groups.py)
export interface HostGroupOut {
  id: number
  name: string
  hosts: number
}

export interface RestartBulkBody {
  ids: number[]
  reason: string
  stagger_sec: number
}

export interface LinuxHostOut {
  id: number
  ip: string
  hostname: string | null
  distro_id: string | null
  distro_pretty: string | null
  distro_version: string | null
  package_manager: string | null
  managed: boolean
  source: 'auto' | 'manual'
  first_seen_at: string | null
  last_seen_at: string | null
  last_check_at: string | null
  last_upgrade_at: string | null
  upgradable_count: number | null
  reboot_required: boolean
  last_status: 'ok' | 'error' | 'timeout' | null
  last_error: string | null
  mem_used_pct: number | null
  mem_total_bytes: number | null
  last_resources_check_at: string | null
  last_restart_at: string | null
  last_restart_reason: string | null
  group_id: number | null
  cpu_used_pct: number | null
  disk_max_pct: number | null
  job: HostJobView | null
}

export interface HostDisk {
  id: number
  total_bytes: number | null
  used_bytes: number | null
  pct: number | null
  last_seen_at: string | null
  mount_point?: string    // Linux
  drive_letter?: string   // Windows
}

export interface LinuxJobStatus {
  status: 'no_job' | 'starting' | 'checking' | 'updating' | 'upgrading' | 'running_script' | 'done' | 'error' | 'timeout'
  started_at?: string
  finished_at?: string
  ip?: string
  identity?: string
  reason?: string
  log?: string[]
  error?: string
  upgradable_count?: number
  reboot_required?: boolean
}

export interface LinuxSettings {
  credential_id: number | null
  credential_name: string | null
  enabled: boolean
}

export const linuxApi = {
  restartBulk: (body: RestartBulkBody) =>
    api.post<{ queued: number }>('/linux/hosts/restart-bulk', body).then(r => r.data),
  groups: () => api.get<{ groups: HostGroupOut[] }>('/linux/groups').then(r => r.data.groups),
  createGroup: (name: string) => api.post<HostGroupOut>('/linux/groups', { name }).then(r => r.data),
  renameGroup: (id: number, name: string) => api.put<HostGroupOut>(`/linux/groups/${id}`, { name }).then(r => r.data),
  deleteGroup: (id: number) => api.delete<{ ok: boolean }>(`/linux/groups/${id}`).then(r => r.data),
  setHostGroup: (hostId: number, groupId: number | null) =>
    api.put<{ ok: boolean }>(`/linux/hosts/${hostId}/group`, { group_id: groupId }).then(r => r.data),
  hosts: () => api.get<{ hosts: LinuxHostOut[]; enabled: boolean }>('/linux/hosts').then(r => r.data),
  setManaged: (hostId: number, managed: boolean) =>
    api.post<LinuxHostOut>(`/linux/hosts/${hostId}/managed`, { managed }).then(r => r.data),
  check: (hostId: number) =>
    api.post<{ queued: boolean }>(`/linux/hosts/${hostId}/check`).then(r => r.data),
  upgrade: (hostId: number) =>
    api.post<{ queued: boolean }>(`/linux/hosts/${hostId}/upgrade`).then(r => r.data),
  restart: (hostId: number, reason: string) =>
    api.post<{ queued: boolean }>(`/linux/hosts/${hostId}/restart`, { reason }).then(r => r.data),
  status: (hostId: number) =>
    api.get<LinuxJobStatus>(`/linux/hosts/${hostId}/status`).then(r => r.data),
  upgradeBulk: (ids: number[]) =>
    api.post<{ queued: number }>('/linux/hosts/upgrade-bulk', { ids }).then(r => r.data),
  runScript: (hostId: number, script: string, useSudo: boolean, reason: string) =>
    api.post<{ queued: boolean }>(`/linux/hosts/${hostId}/run-script`, { script, use_sudo: useSudo, reason }).then(r => r.data),
  runScriptBulk: (ids: number[], script: string, useSudo: boolean, reason: string) =>
    api.post<{ queued: number }>('/linux/hosts/run-script-bulk', { ids, script, use_sudo: useSudo, reason }).then(r => r.data),
  getSettings: () => api.get<LinuxSettings>('/linux/settings').then(r => r.data),
  setSettings: (credentialId: number | null) =>
    api.put<LinuxSettings>('/linux/settings', { credential_id: credentialId }).then(r => r.data),
  listDisks: (hostId: number) =>
    api.get<{ disks: HostDisk[] }>(`/linux/hosts/${hostId}/disks`).then(r => r.data.disks),
  checkResources: (hostId: number) =>
    api.post<{ queued: boolean }>(`/linux/hosts/${hostId}/resources/check`).then(r => r.data),
}

// ── AnyDesk local connection history (connection_trace.txt + ad_svc.trace) ────

export type AnydeskCategory = 'billable' | 'training' | 'internal'

export interface AnydeskSessionOut {
  id: number
  cid: string
  label: string | null
  started_at: string
  ended_at: string | null
  duration_sec: number | null
  auth_method: string | null
  rejected: boolean
  source: 'connection_trace' | 'ad_svc_trace' | 'merged'
  category: AnydeskCategory | null
  note: string | null
}

export interface AnydeskSummaryRow {
  client: string
  month: string
  billable_minutes: number
  training_minutes: number
  internal_minutes: number
  unclassified_minutes: number
  session_count: number
}

export interface AnydeskStatus {
  connection_trace_path: string
  connection_trace_found: boolean
  service_trace_path: string | null
  service_trace_found: boolean
}

export interface AnydeskSyncResult extends AnydeskStatus {
  inserted: number
  updated: number
  skipped: number
  connection_trace_lines: number
  service_trace_pairs: number
}

export interface AnydeskLabel {
  cid: string
  label: string
}

export const anydeskApi = {
  status: () => api.get<AnydeskStatus>('/anydesk/status').then(r => r.data),
  sync: () => api.post<AnydeskSyncResult>('/anydesk/sync').then(r => r.data),
  sessions: (params?: { cid?: string; q?: string; from_date?: string; to_date?: string }) =>
    api.get<{ sessions: AnydeskSessionOut[] }>('/anydesk/sessions', { params }).then(r => r.data.sessions),
  labels: () => api.get<{ labels: AnydeskLabel[] }>('/anydesk/labels').then(r => r.data.labels),
  setLabel: (cid: string, label: string) =>
    api.put<AnydeskLabel>('/anydesk/labels', { cid, label }).then(r => r.data),
  deleteLabel: (cid: string) =>
    api.delete<{ deleted: string }>(`/anydesk/labels/${cid}`).then(r => r.data),
  classify: (sessionId: number, category: AnydeskCategory | null, note?: string) =>
    api.put<AnydeskSessionOut>(`/anydesk/sessions/${sessionId}/classify`, { category, note }).then(r => r.data),
  summary: (params?: { from_date?: string; to_date?: string }) =>
    api.get<{ summary: AnydeskSummaryRow[] }>('/anydesk/summary', { params }).then(r => r.data.summary),
  import: (sessions: Record<string, unknown>[], labels: Record<string, unknown>[]) =>
    api.post<{ sessions_inserted: number; sessions_updated: number; sessions_skipped: number; labels_applied: number }>(
      '/anydesk/import', { sessions, labels }).then(r => r.data),
}

// ── Windows host management (Windows Update install/restart) ──────────────────

export interface WindowsHostOut {
  id: number
  ip: string
  hostname: string | null
  os_name: string | null
  os_version: string | null
  winrm_port: number | null
  managed: boolean
  source: 'auto' | 'manual'
  credential_id: number | null
  domain: string | null
  host_type: 'server' | 'workstation'
  first_seen_at: string | null
  last_seen_at: string | null
  last_check_at: string | null
  last_upgrade_at: string | null
  upgradable_count: number | null
  reboot_required: boolean
  last_status: 'ok' | 'error' | 'timeout' | null
  last_error: string | null
  last_restart_at: string | null
  last_restart_reason: string | null
  last_services_check_at: string | null
  unexpected_ports: number[] | null
  mem_used_pct: number | null
  mem_total_bytes: number | null
  last_resources_check_at: string | null
  group_id: number | null
  cpu_used_pct: number | null
  disk_max_pct: number | null
  job: HostJobView | null
}

export interface WindowsHostService {
  id: number
  host_id: number
  service_name: string
  display_name: string | null
  status: string | null
  last_checked_at: string | null
}

export interface WindowsJobStatus {
  status: 'no_job' | 'starting' | 'checking' | 'updating' | 'upgrading' | 'restarting' | 'running_script' | 'done' | 'error' | 'timeout'
  started_at?: string
  finished_at?: string
  ip?: string
  identity?: string
  reason?: string
  log?: string[]
  error?: string
  upgradable_count?: number
  reboot_required?: boolean
}

export interface WindowsSettings {
  credential_id: number | null
  credential_name: string | null
  enabled: boolean
}

export const windowsApi = {
  restartBulk: (body: RestartBulkBody) =>
    api.post<{ queued: number }>('/windows/hosts/restart-bulk', body).then(r => r.data),
  groups: () => api.get<{ groups: HostGroupOut[] }>('/windows/groups').then(r => r.data.groups),
  createGroup: (name: string) => api.post<HostGroupOut>('/windows/groups', { name }).then(r => r.data),
  renameGroup: (id: number, name: string) => api.put<HostGroupOut>(`/windows/groups/${id}`, { name }).then(r => r.data),
  deleteGroup: (id: number) => api.delete<{ ok: boolean }>(`/windows/groups/${id}`).then(r => r.data),
  setHostGroup: (hostId: number, groupId: number | null) =>
    api.put<{ ok: boolean }>(`/windows/hosts/${hostId}/group`, { group_id: groupId }).then(r => r.data),
  hosts: () => api.get<{ hosts: WindowsHostOut[]; enabled: boolean }>('/windows/hosts').then(r => r.data),
  setManaged: (hostId: number, managed: boolean) =>
    api.post<WindowsHostOut>(`/windows/hosts/${hostId}/managed`, { managed }).then(r => r.data),
  setHostCredential: (hostId: number, credentialId: number | null) =>
    api.post<WindowsHostOut>(`/windows/hosts/${hostId}/credential`, { credential_id: credentialId }).then(r => r.data),
  check: (hostId: number) =>
    api.post<{ queued: boolean }>(`/windows/hosts/${hostId}/check`).then(r => r.data),
  upgrade: (hostId: number, reason: string) =>
    api.post<{ queued: boolean }>(`/windows/hosts/${hostId}/upgrade`, { reason }).then(r => r.data),
  restart: (hostId: number, reason: string) =>
    api.post<{ queued: boolean }>(`/windows/hosts/${hostId}/restart`, { reason }).then(r => r.data),
  status: (hostId: number) =>
    api.get<WindowsJobStatus>(`/windows/hosts/${hostId}/status`).then(r => r.data),
  upgradeBulk: (ids: number[], reason: string) =>
    api.post<{ queued: number }>('/windows/hosts/upgrade-bulk', { ids, reason }).then(r => r.data),
  runScript: (hostId: number, script: string, reason: string) =>
    api.post<{ queued: boolean }>(`/windows/hosts/${hostId}/run-script`, { script, reason }).then(r => r.data),
  runScriptBulk: (ids: number[], script: string, reason: string) =>
    api.post<{ queued: number }>('/windows/hosts/run-script-bulk', { ids, script, reason }).then(r => r.data),
  getSettings: () => api.get<WindowsSettings>('/windows/settings').then(r => r.data),
  setSettings: (credentialId: number | null, manageEnabled?: boolean) =>
    api.put<WindowsSettings>('/windows/settings', { credential_id: credentialId, manage_enabled: manageEnabled }).then(r => r.data),
  setHostType: (hostId: number, hostType: 'server' | 'workstation') =>
    api.post<WindowsHostOut>(`/windows/hosts/${hostId}/host-type`, { host_type: hostType }).then(r => r.data),
  listServices: (hostId: number) =>
    api.get<{ services: WindowsHostService[] }>(`/windows/hosts/${hostId}/services`).then(r => r.data.services),
  addService: (hostId: number, serviceName: string) =>
    api.post<WindowsHostService>(`/windows/hosts/${hostId}/services`, { service_name: serviceName }).then(r => r.data),
  removeService: (hostId: number, serviceId: number) =>
    api.delete<{ ok: boolean }>(`/windows/hosts/${hostId}/services/${serviceId}`).then(r => r.data),
  checkServices: (hostId: number) =>
    api.post<{ queued: boolean }>(`/windows/hosts/${hostId}/services/check`).then(r => r.data),
  getWorkstationPorts: () =>
    api.get<{ ports: number[] }>('/windows/settings/workstation-ports').then(r => r.data.ports),
  setWorkstationPorts: (ports: number[]) =>
    api.put<{ ports: number[] }>('/windows/settings/workstation-ports', { ports }).then(r => r.data.ports),
  listDisks: (hostId: number) =>
    api.get<{ disks: HostDisk[] }>(`/windows/hosts/${hostId}/disks`).then(r => r.data.disks),
  checkResources: (hostId: number) =>
    api.post<{ queued: boolean }>(`/windows/hosts/${hostId}/resources/check`).then(r => r.data),
}

// ── Hyper-V host/VM inventory (local agent) ───────────────────────────────────

export type HypervTile = 'ok' | 'warn' | 'crit' | 'off'
export type HypervSeverity = 'high' | 'medium' | 'low'

export interface HypervHostOut {
  id: number
  windows_host_id: number
  ip: string
  hostname: string | null
  os_name: string | null
  logical_processor_count: number | null
  memory_capacity_bytes: number | null
  vm_count_total: number | null
  vm_count_running: number | null
  cpu_used_pct: number | null
  mem_used_pct: number | null
  storage_path: string | null
  storage_free_bytes: number | null
  storage_total_bytes: number | null
  switch_count: number | null
  cluster_name: string | null
  last_check_at: string | null
  last_ok_at: string | null
  last_status: 'ok' | 'error' | 'not_hyperv' | null
  last_error: string | null
  fail_streak: number
}

export interface HypervVmOut {
  id: number
  hyperv_host_id: number
  name: string
  state: string | null
  status: string | null
  cpu_usage_pct: number | null
  memory_assigned_bytes: number | null
  memory_demand_bytes: number | null
  memory_startup_bytes: number | null
  memory_min_bytes: number | null
  memory_max_bytes: number | null
  dynamic_memory: boolean | null
  uptime_sec: number | null
  heartbeat: string | null
  vcpu_count: number | null
  generation: number | null
  checkpoint_type: string | null
  replication_state: string | null
  replication_health: string | null
  snapshot_count: number | null
  oldest_snapshot_at: string | null
  disk_count: number | null
  disk_file_bytes: number | null
  disk_max_bytes: number | null
  ips: string[]
  switches: string[]
  state_since: string | null
  last_seen_at: string | null
}

export interface HypervVmDetail extends HypervVmOut {
  vm_guid: string | null
  disks: Array<{ file: string | null; type: string | null; file_bytes: number | null; max_bytes: number | null }>
  snapshots: Array<{ name: string | null; created: string | null }>
}

export interface HypervInsight {
  key: string
  kind: string
  severity: HypervSeverity
  hyperv_host_id: number
  windows_host_id: number
  host: string
  vm: string | null
  text: string
  params: Record<string, string | number | null>
}

export interface HypervTrendPoint { t: string; cpu: number | null; mem: number | null }

export interface HypervOverviewHost extends HypervHostOut {
  vcpu_assigned: number
  memory_assigned_bytes: number
  down: boolean
  vms: Array<HypervVmOut & { tile: HypervTile; flags: string[] }>
  trend: HypervTrendPoint[]
}

export interface HypervOverview {
  generated_at: string
  poll_sec: number
  actions_enabled: boolean
  totals: {
    hosts: number; hosts_ok: number; hosts_down: number; vms: number; running: number; off: number; other: number
    tiles: Record<HypervTile, number>; vcpu: number; lp: number; mem_assigned: number; mem_capacity: number
    problems: Record<HypervSeverity, number>
  }
  hosts: HypervOverviewHost[]
  insights: HypervInsight[]
}

export type HypervActionKind = 'start' | 'shutdown' | 'poweroff' | 'restart' | 'checkpoint'

export interface HypervActionLogEntry {
  id: number
  windows_host_id: number
  host_name: string | null
  vm_name: string
  action: HypervActionKind
  reason: string
  created_by: string | null
  status: 'running' | 'ok' | 'error'
  output: string | null
  created_at: string | null
  finished_at: string | null
}

// Security Summary dashboard (services/security_summary.py): the sections of a snapshot plus the aggregated stats
export const securityApi = {
  summary: () => api.get<Record<string, any>>('/security-summary').then(r => r.data),
}

export const hypervApi = {
  overview: () => api.get<HypervOverview>('/hyperv/overview').then(r => r.data),
  hosts: () => api.get<{ hosts: HypervHostOut[] }>('/hyperv/hosts').then(r => r.data.hosts),
  vms: (hypervHostId: number) =>
    api.get<{ vms: HypervVmOut[] }>(`/hyperv/hosts/${hypervHostId}/vms`).then(r => r.data.vms),
  vm: (vmId: number) => api.get<HypervVmDetail>(`/hyperv/vms/${vmId}`).then(r => r.data),
  history: (kind: 'host' | 'vm', id: number, hours = 24) =>
    api.get<{ points: HypervTrendPoint[] }>('/hyperv/history', { params: { kind, id, hours } }).then(r => r.data.points),
  refresh: (windowsHostId: number) =>
    api.post<{ ok?: boolean; error?: string; not_hyperv?: boolean }>(`/hyperv/hosts/${windowsHostId}/refresh`).then(r => r.data),
  refreshAll: () => api.post<{ started: boolean }>('/hyperv/refresh').then(r => r.data),
  action: (vmId: number, body: { action: HypervActionKind; reason: string; snapshot_name?: string }) =>
    api.post<{ action_id: number }>(`/hyperv/vms/${vmId}/actions`, body).then(r => r.data),
  actions: (limit = 50) =>
    api.get<{ actions: HypervActionLogEntry[]; enabled: boolean }>('/hyperv/actions', { params: { limit } }).then(r => r.data),
}

// ── Host monitoring ("Monitoring hostów") ─────────────────────────────────────

export interface HostMonSearchResult {
  name: string | null
  ip: string | null
  mac: string | null
  sources: string[]
  devices: string[]
  comment: string | null
  watched: boolean
}

export interface WatchedHostOut {
  id: number
  name: string
  ip: string | null
  mac: string | null
  note: string | null
  enabled: boolean
  probe_port: number | null
  resolved_ip: string | null
  resolved_mac: string | null
  probe_state: 'up' | 'down' | null
  probe_state_since: string | null
  last_probe_at: string | null
  last_collect_at: string | null
  last_error: string | null
  events_24h?: number
  outages_24h?: number
}

export interface HostEventOut {
  id: number
  ts: string
  source: string
  kind: string | null
  device: string | null
  topics: string | null
  message: string | null
  matched_on: string | null
  severity: 'info' | 'warn' | 'error'
  data: Record<string, any> | null
}

export interface HostFindingOut {
  start: string
  end: string | null
  duration_sec: number
  code: string
  confidence: 'high' | 'medium' | 'low' | null
  evidence: number[]
  also: string[]
}

export interface HostReport {
  host: WatchedHostOut
  presence: { updated: string; entries: Record<string, any>[]; ports: string[] } | null
  hours: number
  events: HostEventOut[]
  outages: { start: string; end: string | null; duration_sec: number }[]
  findings: HostFindingOut[]
  indicators: { code: string; count: number; last_ts: string }[]
  summary: { code: string; outages_with_cause: number; outages: number; periodic_sec?: number } | null
  external: {
    prtg: { sensor: string; status: string; message: string | null; problem: boolean }[]
    checkmk: { kind: string; name: string; state: string; output: string | null; problem: boolean }[]
  }
}

export interface HostMonInput {
  name: string
  ip?: string | null
  mac?: string | null
  note?: string | null
  probe_port?: number | null
  enabled?: boolean
}

export const hostMonApi = {
  search: (q: string, refresh = false) =>
    api.get<{ results: HostMonSearchResult[]; total?: number }>('/hostmon/search', { params: { q, refresh } }).then(r => r.data),
  hosts: () => api.get<{ hosts: WatchedHostOut[] }>('/hostmon/hosts').then(r => r.data.hosts),
  create: (data: HostMonInput) => api.post<{ id: number }>('/hostmon/hosts', data).then(r => r.data),
  update: (id: number, data: HostMonInput) => api.put(`/hostmon/hosts/${id}`, data).then(r => r.data),
  remove: (id: number) => api.delete(`/hostmon/hosts/${id}`).then(r => r.data),
  refresh: (id: number) => api.post(`/hostmon/hosts/${id}/refresh`).then(r => r.data),
  report: (id: number, hours: number) =>
    api.get<HostReport>(`/hostmon/hosts/${id}/report`, { params: { hours } }).then(r => r.data),
  // The labels are the UI's own hostmon.* texts, so the file comes out in the user's language.
  exportReport: (data: { format: 'docx' | 'csv' | 'json'; hours: number; host_ids: number[] | null; labels: Record<string, string> }) =>
    api.post('/hostmon/export', data, { responseType: 'blob' }).then(r => r.data as Blob),
}
// ── Service monitoring on hosts (Windows services / Linux systemd units) ─────

export type ServicePlatform = 'windows' | 'linux'
export type ServiceState = 'running' | 'stopped' | 'failed' | 'other' | 'not_found'

export interface HostServiceParams {
  expected_state?: 'running' | 'stopped'
  interval_min?: number
  alert_after_fails?: number
  alert_enabled?: boolean
  enabled?: boolean
}

export interface HostServiceOut extends Required<HostServiceParams> {
  id: number
  platform: ServicePlatform
  host_id: number
  service_name: string
  display_name: string | null
  status: string | null
  state: ServiceState | null
  startup: string | null
  fail_streak: number
  incident_open: boolean
  ok: boolean | null
  status_since: string | null
  last_checked_at: string | null
}

export interface DiscoveredService {
  name: string
  display_name: string | null
  raw: string | null
  state: ServiceState | null
  startup: string | null
  monitored: boolean
}

export interface HostServiceEventOut {
  id: number
  ts: string
  kind: 'down' | 'up'
  service_name: string
  display_name: string | null
  state: string | null
  expected: string | null
  duration_sec: number | null
}

export const hostServicesApi = {
  list: (platform: ServicePlatform, hostId: number) =>
    api.get<{ services: HostServiceOut[]; check_error: string | null; check_error_at: string | null }>(
      `/services/${platform}/hosts/${hostId}`).then(r => r.data),
  add: (platform: ServicePlatform, hostId: number,
        services: Array<{ name: string; display_name?: string | null; startup?: string | null } & HostServiceParams>) =>
    api.post<{ added: HostServiceOut[]; skipped: string[] }>(`/services/${platform}/hosts/${hostId}`, { services }).then(r => r.data),
  update: (platform: ServicePlatform, serviceId: number, params: HostServiceParams) =>
    api.put<HostServiceOut>(`/services/${platform}/services/${serviceId}`, params).then(r => r.data),
  remove: (platform: ServicePlatform, serviceId: number) =>
    api.delete(`/services/${platform}/services/${serviceId}`).then(r => r.data),
  checkNow: (platform: ServicePlatform, hostId: number) =>
    api.post<{ ok: boolean; checked: number }>(`/services/${platform}/hosts/${hostId}/check`).then(r => r.data),
  discover: (platform: ServicePlatform, hostId: number) =>
    api.get<{ services: DiscoveredService[] }>(`/services/${platform}/hosts/${hostId}/discover`).then(r => r.data.services),
  events: (platform: ServicePlatform, hostId: number, limit = 30) =>
    api.get<{ events: HostServiceEventOut[] }>(`/services/${platform}/hosts/${hostId}/events`, { params: { limit } }).then(r => r.data.events),
}
// ── Mikrotik fleet view (services/fleet.py) ──────────────────────────────────

export interface FleetAlertRow {
  key: string
  severity: 'high' | 'medium' | 'low'
  count: number
  total: number
  devices: Array<{ id: number; name: string }> | string[]   // names only in Central's redacted copy
}

export interface FleetDeviceRow {
  mgmt_ok?: boolean | null                                 // false while online: answers ping / SNMP, but no management port answers from the agent
  id: number
  ip?: string                                              // absent in Central's redacted copy
  name: string
  model: string | null
  board_name: string | null
  architecture: string | null
  ros_version: string | null
  ros_channel: string | null
  latest_ros_version: string | null
  update_available: boolean
  firmware_current: string | null
  firmware_target: string | null
  online: boolean
  paired: boolean
  cpu: number | null
  mem: number | null
  mem_total_bytes: number | null
  disk: number | null
  disk_total_bytes: number | null
  temperature: number | null
  uptime_sec: number | null
  packages_count: number
  packages?: Array<{ name: string; version: string | null; disabled: boolean }>
  last_seen: string | null
  resources_checked_at: string | null
  fleet_checked_at: string | null
  alerts: string[]
  wifi: { aps: unknown[] | number; stations: unknown[] | number }
}

export interface FleetWifi {
  aps_total: number
  stations_total: number
  by_band: Record<string, { aps: number; stations: number }>
  by_channel: Record<string, Array<{ freq: number; aps: number; stations: number }>>
}

export interface FleetOverview {
  generated_at: string
  totals: { devices: number; online: number; paired: number }
  devices: FleetDeviceRow[]
  alerts: FleetAlertRow[]
  updates: Array<{ id: number; name: string; current: string | null; latest: string | null; channel: string | null }>
  wifi: FleetWifi
  never_collected: number
  groups?: FleetGroupSummary[]                          // Central's redacted copy only
}

export const fleetApi = {
  overview: () => api.get<FleetOverview>('/fleet/overview').then(r => r.data),
  refresh: () => api.post<{ started: boolean }>('/fleet/refresh').then(r => r.data),
}

// Bulk actions (services/fleet_actions.py)
export type FleetActionKind = 'script' | 'reboot' | 'upgrade'
export type FleetResultStatus = 'queued' | 'running' | 'ok' | 'error' | 'skipped'

export interface FleetRunSummary {
  id: number
  action: FleetActionKind
  reason: string
  created_by: string | null
  status: 'running' | 'done' | 'interrupted'
  created_at: string | null
  finished_at: string | null
  devices: number
  counts: Partial<Record<FleetResultStatus, number>>
}

export interface FleetRunDeviceResult {
  name: string
  ip: string
  status: FleetResultStatus
  output?: string
  error?: string | null
  started_at?: string
  finished_at?: string
}

export interface FleetRunDetail extends FleetRunSummary {
  script: string | null
  options: { backup?: boolean } | null
  results: Record<string, FleetRunDeviceResult>
}

// Upgrade groups (services/fleet_schedule.py)
export type FleetChannel = 'stable' | 'long-term' | 'testing' | 'development'
export type FleetScheduleKind = 'manual' | 'weekly' | 'once'

export interface FleetGroupInput {
  name: string
  device_ids: number[]                    // the order is the upgrade order
  channel: FleetChannel | null
  schedule_kind: FleetScheduleKind
  weekday: number | null                  // 0 = Monday .. 6 = Sunday
  hour: number | null
  minute: number
  once_at: string | null                  // ISO local datetime
  enabled: boolean
  stop_on_failure: boolean
  backup: boolean
}

export interface FleetGroup extends FleetGroupInput {
  id: number
  source: 'local' | 'central'             // 'central' = defined in Central, read-only on the agent
  central_id: number | null
  next_run_at: string | null
  last_run_at: string | null
  last_note: string | null
  last_run: { id: number; status: 'running' | 'done' | 'interrupted'; counts: Partial<Record<FleetResultStatus, number>>; devices: number } | null
}

// Redacted copy of a group in Central's summary (no device ids)
export interface FleetGroupSummary {
  central_id: number | null               // set when the group is managed from Central
  name: string
  devices: number
  channel: FleetChannel | null
  enabled: boolean
  schedule_kind: FleetScheduleKind
  weekday: number | null
  hour: number | null
  minute: number
  once_at: string | null
  next_run_at: string | null
  last_run_at: string | null
  last_status: 'running' | 'done' | 'interrupted' | null
  last_counts: Partial<Record<FleetResultStatus, number>> | null
  last_note: string | null
}

export const fleetGroupsApi = {
  list: () => api.get<{ groups: FleetGroup[] }>('/fleet/groups').then(r => r.data.groups),
  create: (g: FleetGroupInput) => api.post<FleetGroup>('/fleet/groups', g).then(r => r.data),
  update: (id: number, g: FleetGroupInput) => api.put<FleetGroup>(`/fleet/groups/${id}`, g).then(r => r.data),
  remove: (id: number) => api.delete(`/fleet/groups/${id}`).then(r => r.data),
  run: (id: number, reason?: string) => api.post<{ run_id: number }>(`/fleet/groups/${id}/run`, { reason }).then(r => r.data),
}
// A group definition kept on Central (ovh/api.php fleet_groups); the tenant's agent mirrors it read-only.
export interface CentralFleetGroup {
  id: number
  tenant: string
  name: string
  definition: Omit<FleetGroupInput, 'name'>
  rev: number
  updated_at: string | null
}

export const fleetActionsApi = {
  start: (body: { action: FleetActionKind; device_ids: number[]; reason: string; script?: string; backup?: boolean }) =>
    api.post<{ run_id: number }>('/fleet/actions/run', body).then(r => r.data),
  runs: () => api.get<{ runs: FleetRunSummary[]; enabled: boolean }>('/fleet/actions/runs').then(r => r.data),
  run: (id: number) => api.get<FleetRunDetail>(`/fleet/actions/runs/${id}`).then(r => r.data),
}
// ── Dell servers (iDRAC health monitoring) ────────────────────────────────────

export type DellHealth = 'OK' | 'Warning' | 'Critical' | null
export type DellVendor = 'dell' | 'hp' | 'fujitsu' | 'lenovo' | null

export interface DellServerOut {
  id: number
  name: string | null
  vendor: DellVendor
  idrac_ip: string | null
  idrac_port: number
  windows_host_id: number | null
  credential_id: number | null
  access_method: 'redfish' | 'local_ism' | 'local_racadm' | 'local_omsa' | null
  last_check_at: string | null
  last_status: 'ok' | 'error' | null
  last_error: string | null
  health_rollup: DellHealth
  service_tag: string | null
  model: string | null
  bios_version: string | null
  power_state: string | null
  components: {
    system?: DellHealth; cpu?: DellHealth; memory?: DellHealth; power?: DellHealth
    fans_temperature?: DellHealth; storage?: DellHealth
  }
}

export interface DellSelEntry {
  id: number
  severity: string | null
  message: string
  logged_at: string | null
}

export interface DellServerInput {
  name?: string
  vendor?: DellVendor
  idrac_ip?: string
  idrac_port?: number
  windows_host_id?: number | null
  credential_id?: number | null
}

export const dellApi = {
  servers: () => api.get<{ servers: DellServerOut[] }>('/dell/servers').then(r => r.data.servers),
  add: (data: DellServerInput) => api.post<DellServerOut>('/dell/servers', data).then(r => r.data),
  update: (id: number, data: Partial<DellServerInput>) =>
    api.put<DellServerOut>(`/dell/servers/${id}`, data).then(r => r.data),
  delete: (id: number) => api.delete(`/dell/servers/${id}`),
  check: (id: number) => api.post<{ queued: boolean }>(`/dell/servers/${id}/check`).then(r => r.data),
  sel: (id: number, limit = 50) =>
    api.get<{ entries: DellSelEntry[] }>(`/dell/servers/${id}/sel`, { params: { limit } }).then(r => r.data.entries),
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
  opts: { method?: 'GET' | 'POST' | 'DELETE'; body?: any; file?: string } = {},
): Promise<T> {
  const cfg = centralConfig.load()
  if (!cfg) throw new Error('Central not configured')

  const url = new URL('/api/system/central-proxy', window.location.origin)
  // `file`: another script of the same Central (e.g. nvd.php) next to the API one
  url.searchParams.set('upstream', opts.file ? cfg.apiUrl.replace(/\/[^/]*$/, `/${opts.file}`) : cfg.apiUrl)
  url.searchParams.set('action', action)
  // URLSearchParams.set(k, undefined) stringifies to the literal "undefined"
  // rather than omitting the param — callers routinely pass `x || undefined`
  // for "no filter", so this must be skipped explicitly or every such filter
  // silently becomes `?field=undefined` and matches nothing server-side.
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, v)
  }

  const method = opts.method ?? 'GET'
  const baseHeaders: Record<string, string> = {}
  let body: string | undefined
  if (opts.body !== undefined) {
    baseHeaders['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }
  const doFetch = (authHeaders: Record<string, string>) =>
    fetch(url.toString(), { method, headers: { ...baseHeaders, ...authHeaders }, body })

  // Prefer a per-user account session token (recommended path) over the
  // legacy shared password — `login`/logged-out state doesn't have one yet,
  // so this falls back to the legacy password if that's all that's configured.
  const session = centralSession.load()
  let resp: Response
  if (session) {
    resp = await doFetch({ Authorization: `Bearer ${session.token}` })
    // The token in sessionStorage can go stale independently of anything
    // the browser knows (server-side expiry, e.g. after
    // user_session_ttl_sec, or a revoked session) — confirmed in practice:
    // a one-click action like AnyDesk's "Importuj z Centrali" would
    // otherwise just fail with a raw 401 until the user manually re-logs
    // into the "Użytkownicy" tab. Self-heal instead: drop the dead session
    // and retry once with the legacy shared password (counts as global
    // admin server-side, same as every other already-established fallback
    // in this app) if one is configured.
    if (resp.status === 401 && cfg.password) {
      centralSession.clear()
      const fallbackHeaders: Record<string, string> = { Authorization: `Bearer ${cfg.password}` }
      if (cfg.totpSecret) fallbackHeaders['X-Totp'] = await totpCode(cfg.totpSecret)
      resp = await doFetch(fallbackHeaders)
    }
  } else if (cfg.password) {
    const headers: Record<string, string> = { Authorization: `Bearer ${cfg.password}` }
    if (cfg.totpSecret) headers['X-Totp'] = await totpCode(cfg.totpSecret)
    resp = await doFetch(headers)
  } else {
    resp = await doFetch({})
  }

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
  me: () => centralRequest<{
    id: number; username: string; role: AuthRole; allowed_tenants: string[] | null
    totp_enabled: boolean; totp_secret_set: boolean
  }>('me'),
  totpConfirm: (code: string) => centralRequest<{ ok: boolean }>('me_totp_confirm', {}, { method: 'POST', body: { code } }),
}

export const centralUsersApi = {
  list: () => centralRequest<{ users: CentralUser[] }>('users_list'),
  add: (data: { username: string; password: string; role: AuthRole; allowed_tenants?: string[] | null }) =>
    centralRequest<{ ok: boolean; id: number }>('user_add', {}, { method: 'POST', body: data }),
  update: (data: { id: number; role?: AuthRole; allowed_tenants?: string[] | null; is_active?: boolean; password?: string; totp_enabled?: boolean }) =>
    centralRequest<{ ok: boolean }>('user_update', {}, { method: 'POST', body: data }),
  delete: (id: number) => centralRequest<{ ok: boolean; deleted: number }>('user_delete', { id: String(id) }, { method: 'DELETE' }),
  totpReset: (id: number) => centralRequest<{ secret: string; otpauth_uri: string }>('user_totp_reset', { id: String(id) }, { method: 'POST' }),
}

// ── AnyDesk on OVH (read-only, used only for the one-time/repeatable
// "Importuj z Centrali" pull into the local AnyDesk tab below) ─────────────
// This used to be a whole standalone Central panel (classification,
// mapping CRUD, CSV import, monthly summary) with its own OVH per-user
// login on top of the local agent's — removed because the local
// trace-file feature covers all of that with richer data and no extra
// login. What's kept here is the minimum needed to pull the user's
// EXISTING OVH data (client-ID mappings + already-classified sessions,
// e.g. from earlier manual CSV imports) down into the local table once —
// see anydeskApi.import() below, which is where the actual merge happens.

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

export const centralAnydeskApi = {
  mappingList: () => centralRequest<{ mappings: AnydeskClientMap[] }>('anydesk_client_map_list'),
  sessions: (filters: { tenant?: string; category?: AnydeskCategory | 'unclassified'; from?: string; to?: string; limit?: number; offset?: number } = {}) => {
    const params: Record<string, string> = {}
    for (const [k, v] of Object.entries(filters)) {
      if (v !== undefined) params[k] = String(v)
    }
    return centralRequest<{ sessions: AnydeskSession[] }>('anydesk_sessions', params)
  },
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
  verify_pending: number
  verify_direction: 'down' | 'up' | null
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

export interface CentralRecentAction {
  tenant: string
  label: string
  target: string | number | null
  status: 'queued' | 'delivered' | 'done' | 'failed'
  at: string
  detail?: string          // the message of the latest event of this command (e.g. why it failed)
  id?: number              // failed commands only: the event to accept or reject (they stay listed until then)
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

// Sibling of decryptEnvelope() above for envelopes whose plaintext is raw
// BINARY content (a generated .docx, an agent-backup archive) rather than
// JSON text — services/agent_backup.py's/drp_docs.py's envelope shape
// (v:1, no plaintext metadata alongside the ciphertext, unlike the
// snapshot envelope's v:2). Returns the decrypted bytes directly instead
// of decoding+JSON.parse-ing them, which would corrupt binary data.
export async function decryptEnvelopeToBytes(envelope: any, keyB64: string): Promise<ArrayBuffer> {
  if (envelope?.v !== 1 || envelope?.alg !== 'aes-256-gcm') {
    throw new Error(`unsupported envelope: v=${envelope?.v} alg=${envelope?.alg}`)
  }
  const rawKey = b64ToBuffer(keyB64)
  if (rawKey.byteLength !== 32) throw new Error('decryption key must be 32 bytes')
  const nonce = b64ToBuffer(envelope.nonce)
  const ct = b64ToBuffer(envelope.ciphertext)
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct)
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
  requestLinuxScan: (tenant: string) =>
    centralRequest<{ ok: boolean; tenant: string; queued_at: string; note: string }>('request_linux_scan', { tenant }),
  pendingLinuxScans: () =>
    centralRequest<{ pending: Array<{ tenant: string; queued_at: string }> }>('pending_linux_scans'),
  requestLinuxAptUpgrade: (tenant: string, hostId: number) =>
    centralRequest<{ ok: boolean; tenant: string; host_id: number; queued_at: string; note: string }>(
      'request_linux_apt_upgrade', { tenant, host_id: String(hostId) },
    ),
  pendingLinuxAptUpgrades: () =>
    centralRequest<{ pending: Array<{ tenant: string; host_id: number; queued_at: string }> }>('pending_linux_apt_upgrades'),
  requestLinuxRestart: (tenant: string, hostId: number, reason: string) =>
    centralRequest<{ ok: boolean; tenant: string; host_id: number; queued_at: string; note: string }>(
      'request_linux_restart', { tenant, host_id: String(hostId), reason },
    ),
  requestHypervVmAction: (tenant: string, vmId: number, action: HypervActionKind, reason: string) =>
    centralRequest<{ ok: boolean; tenant: string; vm_id: number; vm_action: string; queued_at: string }>(
      'request_hyperv_vm_action', { tenant, vm_id: String(vmId), vm_action: action, reason },
    ),
  requestSoarDecision: (tenant: string, actionId: number, decision: 'approve' | 'reject') =>
    centralRequest<{ ok: boolean; queued_at: string }>('request_soar_decision', { tenant, action_id: String(actionId), decision }),
  requestSocUpdate: (tenant: string, alertId: number, status: string) =>
    centralRequest<{ ok: boolean; queued_at: string }>('request_soc_update', { tenant, alert_id: String(alertId), status }),
  requestDeviceReboot: (tenant: string, deviceId: number, reason: string) =>
    centralRequest<{ ok: boolean; tenant: string; device_id: number; queued_at: string }>(
      'request_device_reboot', { tenant, device_id: String(deviceId), reason },
    ),
  pendingLinuxRestarts: () =>
    centralRequest<{ pending: Array<{ tenant: string; host_id: number; queued_at: string }> }>('pending_linux_restarts'),
  linuxHostsStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; linux_hosts: CentralLinuxHostStatus[] }> }>('linux_hosts_status_all'),
  requestWindowsUpdate: (tenant: string, hostId: number, reason: string) =>
    centralRequest<{ ok: boolean; tenant: string; host_id: number; queued_at: string; note: string }>(
      'request_windows_update', { tenant, host_id: String(hostId), reason },
    ),
  pendingWindowsUpdates: () =>
    centralRequest<{ pending: Array<{ tenant: string; host_id: number; queued_at: string }> }>('pending_windows_updates'),
  requestWindowsRestart: (tenant: string, hostId: number, reason: string) =>
    centralRequest<{ ok: boolean; tenant: string; host_id: number; queued_at: string; note: string }>(
      'request_windows_restart', { tenant, host_id: String(hostId), reason },
    ),
  pendingWindowsRestarts: () =>
    centralRequest<{ pending: Array<{ tenant: string; host_id: number; queued_at: string }> }>('pending_windows_restarts'),
  windowsHostsStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; windows_hosts: CentralWindowsHostStatus[]; manage_enabled: boolean }> }>('windows_hosts_status_all'),
  requestWindowsScan: (tenant: string) =>
    centralRequest<{ ok: boolean; tenant: string; queued_at: string; note: string }>('request_windows_scan', { tenant }),
  pendingWindowsScans: () =>
    centralRequest<{ pending: Array<{ tenant: string; queued_at: string }> }>('pending_windows_scans'),
  requestWindowsManageToggle: (tenant: string, enabled: boolean) =>
    centralRequest<{ ok: boolean; tenant: string; enabled: boolean; queued_at: string; note: string }>(
      'request_windows_manage_toggle', { tenant, enabled: String(enabled) },
    ),
  pendingWindowsManageToggles: () =>
    centralRequest<{ pending: Array<{ tenant: string; enabled: boolean; queued_at: string }> }>('pending_windows_manage_toggles'),
  tunnelStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; tunnels: CentralTunnelStatus[] }> }>('tunnel_status_all'),
  hypervHostsStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; hosts: CentralHypervHostStatus[] }> }>('hyperv_hosts_status_all'),
  firewallStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; devices: CentralFirewallDeviceStatus[] }> }>('firewall_status_all'),
  topologyStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; map: CentralNetMap | null }> }>('topology_status_all'),
  nvdStatus: () => centralRequest<CentralNvdStatus>('status', {}, { file: 'nvd.php' }),
  nvdKeySet: (key: string) => centralRequest<CentralNvdStatus>('key_set', {}, { method: 'POST', body: { key }, file: 'nvd.php' }),
  nvdKeyClear: () => centralRequest<CentralNvdStatus>('key_clear', {}, { method: 'POST', file: 'nvd.php' }),
  socStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; soc: CentralSoc | null }> }>('soc_status_all'),
  racksStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; racks: { racks: CentralRack[]; ops: CentralRackOp[] } | null }> }>('racks_status_all'),
  requestRackOp: (tenant: string, op: string) =>
    centralRequest<{ ok: boolean; tenant: string; queued_at: string }>('request_rack_op', { tenant, op }),
  assetsStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; assets: AssetsPublic | null }> }>('assets_status_all'),
  securityStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; data: Record<string, any> }> }>('security_status_all'),
  fleetStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; fleet: FleetOverview | null }> }>('fleet_status_all'),
  fleetGroupsList: () =>
    centralRequest<{ groups: CentralFleetGroup[] }>('fleet_groups_list').then(r => r.groups),
  fleetGroupSave: (tenant: string, g: FleetGroupInput, id?: number) => {
    const { name, ...definition } = g
    return centralRequest<{ ok: boolean; id: number }>('fleet_group_save', {}, { method: 'POST', body: { id, tenant, name, definition } })
  },
  fleetGroupDelete: (id: number) =>
    centralRequest<{ ok: boolean }>('fleet_group_delete', { id: String(id) }, { method: 'DELETE' }),
  fleetGroupRun: (id: number) =>
    centralRequest<{ ok: boolean; queued_at: string; note: string }>('fleet_group_run', { id: String(id) }, { method: 'POST' }),
  hostmonStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; hosts: CentralHostmonHostStatus[] }> }>('hostmon_status_all'),
  wanLinksStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; links: CentralWanLinkStatus[] }> }>('wan_links_status_all'),
  complianceStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; findings: CentralComplianceFinding[] }> }>('compliance_status_all'),

  prtgStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; sensors: CentralPrtgSensor[] }> }>('prtg_status_all'),

  checkmkStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; services: CentralCheckmkService[]; hosts: CentralCheckmkHost[] }> }>('checkmk_status_all'),
  wazuhStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; alerts: CentralWazuhAlert[] }> }>('wazuh_status_all'),
  vulnFindingsStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; hosts: CentralVulnHostFindings[] }> }>('vuln_findings_status_all'),
  requestVulnRemediation: (tenant: string, product: string, version: string, cveId: string, status: string, note: string) =>
    centralRequest<{ ok: boolean; tenant: string; product: string; version: string; cve_id: string; queued_at: string; note: string }>(
      'request_vuln_remediation', { tenant, product, version, cve_id: cveId, status, note },
    ),
  pendingVulnRemediations: () =>
    centralRequest<{ pending: Array<{ tenant: string; product: string; version: string; cve_id: string; queued_at: string }> }>('pending_vuln_remediations'),
  dellServersStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; dell_servers: CentralDellServerStatus[] }> }>('dell_servers_status_all'),
  routersStatusAll: () =>
    centralRequest<{ tenants: Array<{ tenant: string; last_seen: string | null; routers: CentralRouterStatus[] }> }>('routers_status_all'),
  requestDeviceRouterOverride: (tenant: string, deviceId: number, isRouter: boolean | null) =>
    centralRequest<{ ok: boolean; tenant: string; device_id: number; is_router: string; queued_at: string; note: string }>(
      'request_device_router_override', { tenant, device_id: String(deviceId), is_router: isRouter === null ? 'null' : String(isRouter) },
    ),
  pendingDeviceRouterOverrides: () =>
    centralRequest<{ pending: Array<{ tenant: string; device_id: number; queued_at: string }> }>('pending_device_router_overrides'),
  requestDellCheck: (tenant: string, serverId: number) =>
    centralRequest<{ ok: boolean; tenant: string; server_id: number; queued_at: string; note: string }>(
      'request_dell_check', { tenant, server_id: String(serverId) },
    ),
  pendingDellChecks: () =>
    centralRequest<{ pending: Array<{ tenant: string; server_id: number; queued_at: string }> }>('pending_dell_checks'),

  // Agent self-backup (BCP) — admin-only on the OVH side regardless of role
  // checks here; the server enforces it independently.
  backupList: (tenant: string) =>
    centralRequest<{ backups: Array<{ id: number; created_at: string; size_bytes: number }> }>('backup_list', { tenant }),
  backupDownload: (tenant: string, id: number) =>
    centralRequest<{ created_at: string; size_bytes: number; envelope: Record<string, unknown> }>(
      'backup_download', { tenant, id: String(id) },
    ),

  // Mikrotik DRP (disaster-recovery) documents — generated on the agent
  // (services/drp_docs.py) on request, admin-only on the OVH side same as
  // backups above.
  requestDrpDocGenerate: (tenant: string) =>
    centralRequest<{ ok: boolean; tenant: string; queued_at: string; note: string }>('request_drp_doc_generate', { tenant }),
  pendingDrpDocGenerates: () =>
    centralRequest<{ pending: Array<{ tenant: string; queued_at: string }> }>('pending_drp_doc_generates'),
  drpDocList: (tenant: string) =>
    centralRequest<{ documents: Array<{ id: number; created_at: string; size_bytes: number }> }>('drp_doc_list', { tenant }),
  drpDocDownload: (tenant: string, id: number) =>
    centralRequest<{ created_at: string; size_bytes: number; envelope: Record<string, unknown> }>(
      'drp_doc_download', { tenant, id: String(id) },
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
  alertRuleUpdate: (id: number, data: AlertRuleInput) =>
    centralRequest<{ ok: boolean }>('alert_rule_update', { id: String(id) }, { method: 'POST', body: data }),
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

  // Unified "recently requested actions" view (agent update/restart,
  // firmware upgrade, Linux/Windows apt-upgrade/restart, DRP doc
  // generation, Dell checks, ...) — see ovh/api.php's recent_actions.
  recentActions: (limit: number = 50) =>
    centralRequest<{ actions: CentralRecentAction[]; pending_errors?: number }>('recent_actions', { limit: String(limit) }),
  // accept or reject failed commands: only then do they leave the recent-actions list
  ackActions: (ids: number[], decision: 'accepted' | 'rejected') =>
    centralRequest<{ ok: boolean; acked: number }>('action_ack', {}, { method: 'POST', body: { ids, decision } }),

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

export interface TenantInventoryEntry {
  tenant: string
  group: 'network' | 'windows' | 'linux' | 'other'
  ip: string
  name: string | null       // network group only
  hostname: string | null   // windows/linux/other groups only
  os: string | null
  model: string | null
  vendor: string | null
  ports: number[]
  findings_count: number
}

/** Fetch every tenant's latest snapshot, decrypt if possible, return a flat
 *  inventory row list tagged with tenant id — same shape as
 *  services/inventory.py's build_inventory(), just flattened across
 *  tenants. inventory_summary rides inside the E2E-encrypted snapshot body
 *  only (see uplink.py) — a tenant whose key hasn't been imported here
 *  contributes nothing, same as getAllTenantDevices() for that case. */
export async function getAllTenantInventory(): Promise<TenantInventoryEntry[]> {
  if (!centralConfig.load()) return []
  let tenantsList: CentralTenantList
  try { tenantsList = await centralApi.tenants() } catch { return [] }

  const all: TenantInventoryEntry[] = []
  await Promise.all(tenantsList.tenants.map(async (t) => {
    try {
      const snap = await centralApi.snapshot(t.id)
      if (!snap || snap._encrypted || !snap.inventory_summary) return
      const inv = snap.inventory_summary
      for (const n of (inv.network ?? [])) {
        all.push({
          tenant: t.id, group: 'network', ip: n.ip, name: n.name, hostname: null,
          os: null, model: n.model, vendor: n.vendor, ports: [],
          findings_count: n.findings_count ?? 0,
        })
      }
      for (const group of ['windows', 'linux', 'other'] as const) {
        for (const h of (inv[group] ?? [])) {
          all.push({
            tenant: t.id, group, ip: h.ip, name: null, hostname: h.hostname,
            os: h.os, model: null, vendor: null, ports: h.ports ?? [],
            findings_count: h.findings_count ?? 0,
          })
        }
      }
    } catch { /* ignore one bad tenant */ }
  }))
  return all
}

// Helper to generate a fresh 32-byte key in browser (base64)
export function generateEncKey(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float,
    UniqueConstraint, create_engine, inspect, text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mikrotik.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)
    ip = Column(String, unique=True, nullable=False, index=True)
    mac = Column(String, nullable=True)
    model = Column(String, nullable=True)
    ros_version = Column(String, nullable=True)
    board_name = Column(String, nullable=True)
    identity = Column(String, nullable=True)
    # RouterBOARD firmware (RouterBOOT bootloader) — a SEPARATE thing from
    # ros_version above. Only actionable if upgrade_firmware differs from
    # current_firmware; applying it requires an explicit /system/routerboard
    # upgrade + reboot, RouterOS never does this automatically.
    current_firmware = Column(String, nullable=True)
    upgrade_firmware = Column(String, nullable=True)
    # Per-device, model/architecture/channel-aware update check (from the
    # device's own /system/package/update, not a single global "latest"
    # guessed from a static file) — the authoritative answer to "does THIS
    # specific model actually have a newer RouterOS available to it".
    latest_ros_version = Column(String, nullable=True)
    ros_update_status = Column(String, nullable=True)
    api_port = Column(Integer, default=8728)
    ssh_port = Column(Integer, default=22)
    web_port = Column(Integer, default=80)
    snmp_port = Column(Integer, default=161)
    has_api = Column(Boolean, default=False)
    has_ssh = Column(Boolean, default=False)
    has_web = Column(Boolean, default=False)
    has_snmp = Column(Boolean, default=False)
    # Vendor / device type. 'mikrotik' (default) | 'cisco-sb' | 'generic-snmp' | 'unknown'
    vendor = Column(String, default="mikrotik")
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    online = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    # topology
    x_pos = Column(Float, default=0.0)
    y_pos = Column(Float, default=0.0)
    # Asset inventory (ISO 27001 A.5.9 — inventory of assets): free-text
    # owner/responsible person, and a business-impact rating independent of
    # any technical severity computed elsewhere in the app.
    owner = Column(String, nullable=True)
    criticality = Column(String, nullable=True)  # 'low' | 'medium' | 'high' | 'critical', free-text (no DB-level enum)

    # Resource monitoring (services/resource_monitor.py) — from RouterOS's
    # own /system/resource, already fetched elsewhere in the app but never
    # persisted until now.
    mem_used_pct = Column(Float, nullable=True)
    disk_used_pct = Column(Float, nullable=True)
    cpu_load_pct = Column(Integer, nullable=True)
    last_resources_check_at = Column(DateTime, nullable=True)
    # Per-device, manually-set bandwidth ceiling (Mbps) for the
    # interface_overload alert — NULL (default) means "don't check
    # bandwidth on this device", only error/drop counters are watched.
    # Deliberately per-device rather than a single global default: link
    # capacity varies wildly between a WAN uplink and a switch trunk.
    iface_mbps_threshold = Column(Float, nullable=True)

    credential = relationship("Credential", back_populates="devices")


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password_enc = Column(Text, nullable=False)
    snmp_community_enc = Column(Text, nullable=True)  # encrypted; v2c community string
    description = Column(String, nullable=True)
    # Windows domain (NetBIOS name, e.g. "CORP") for domain accounts used by
    # the vuln scanner's WinRM identity check. Leave blank for a local
    # Windows account or for Linux/Mikrotik credentials — unused there.
    domain = Column(String, nullable=True)

    devices = relationship("Device", back_populates="credential")


class DeviceInterfaceStats(Base):
    """Latest per-interface sample from services/resource_monitor.py's
    Mikrotik polling — both the "previous sample" used to compute the next
    delta (rate/error-count changes), and what the UI reads to show current
    throughput/error counts per port. One row per (device, interface),
    overwritten on every poll (no history kept, same as LinuxHostDisk)."""
    __tablename__ = "device_interface_stats"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    iface_name = Column(String, nullable=False)
    rx_bytes = Column(Integer, nullable=True)
    tx_bytes = Column(Integer, nullable=True)
    rx_errors = Column(Integer, nullable=True)
    tx_errors = Column(Integer, nullable=True)
    rx_drops = Column(Integer, nullable=True)
    tx_drops = Column(Integer, nullable=True)
    rx_mbps = Column(Float, nullable=True)
    tx_mbps = Column(Float, nullable=True)
    last_sample_at = Column(DateTime, nullable=True)

    __table_args__ = (UniqueConstraint("device_id", "iface_name", name="uq_device_iface_stats"),)


class ScanRange(Base):
    __tablename__ = "scan_ranges"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String, nullable=False, unique=True)
    label = Column(String, nullable=True)
    active = Column(Boolean, default=True)
    # Optional per-range schedule override for services/vuln_scan.py's
    # weekly scan — NULL (both) = use the global MIKROTIK_VULN_SCAN_DAY/
    # MIKROTIK_VULN_SCAN_HOUR default, same as every range today.
    scan_day = Column(Integer, nullable=True)    # 0=Mon..6=Sun
    scan_hour = Column(Integer, nullable=True)   # 0-23


class DeviceBackup(Base):
    """Record of a backup taken on a Mikrotik device.
    Content is empty initially — v1 only records that backup exists on device.
    Later can be filled by downloading via FTP/SFTP."""
    __tablename__ = "device_backups"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    filename = Column(String, nullable=False)
    trigger = Column(String, default="manual")   # 'manual' | 'pre-upgrade'
    size_bytes = Column(Integer, default=0)
    content_b64 = Column(Text, nullable=True)    # base64 of file (filled by future FTP downloader)


class DeviceLink(Base):
    """An edge between two devices in the topology — discovered via
    /ip/neighbor (LLDP/CDP/MNDP) or via L2 tunnels (EOIP/GRE/VXLAN).

    Pair is stored canonically: device_a_id < device_b_id, so each link
    appears exactly once regardless of which side reported it.
    """
    __tablename__ = "device_links"

    id = Column(Integer, primary_key=True, index=True)
    device_a_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    device_b_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    interface_a = Column(String, nullable=True)   # port on device A
    interface_b = Column(String, nullable=True)   # port on device B
    link_type = Column(String, nullable=True)     # 'lldp' | 'cdp' | 'mndp' | 'eoip' | 'gre' | 'vxlan' | 'ipip'
    last_seen = Column(DateTime, default=datetime.utcnow)


class AppAccount(Base):
    """The single local admin account for this MikroManager instance.
    Password + mandatory TOTP MFA, both verified entirely locally — login
    keeps working even if the OVH central server/DB is unreachable, since
    it never depends on them."""
    __tablename__ = "app_account"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    totp_secret_enc = Column(Text, nullable=True)  # encrypted; set at setup time
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Who did what — one row per mutating (non-GET) API request that
    reached a handler, written by services/audit.py. Insert-only: no code
    path anywhere updates or deletes a row here. Each entry is also queued
    via services/activity.py, which the next uplink cycle forwards into
    OVH's existing activity_log table — a copy that has already left this
    machine before anyone here could tamper with it."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String, nullable=False)
    role = Column(String, nullable=False)      # admin | viewer
    source = Column(String, nullable=False)    # local | ovh
    method = Column(String, nullable=False)
    path = Column(String, nullable=False)
    status_code = Column(Integer, nullable=False)
    ip = Column(String, nullable=True)


class VulnHost(Base):
    """A host discovered by the passive vulnerability scanner (services/vuln_scan.py).
    May or may not correspond to a known Device — the vuln scanner covers the
    whole network (Windows/Linux servers included), not just Mikrotik/Cisco gear."""
    __tablename__ = "vuln_hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, nullable=False, unique=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    # Optional: attach existing credentials (same Credential model used for
    # Mikrotik devices) to enable a deeper, authenticated SSH identity check
    # (os-release/uname) for this specific host on top of the passive banner
    # grab. Opt-in per host — most hosts have none and stay purely passive.
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    last_scan_at = Column(DateTime, default=datetime.utcnow)
    # Separate, longer-cadence TTL from last_scan_at — a full installed-
    # package audit (services/vuln_scan.py's _package_audit) can submit
    # thousands of packages in one vulners.com call, so it only runs once
    # per MIKROTIK_VULN_PACKAGE_AUDIT_DAYS, not on every weekly scan.
    last_package_audit_at = Column(DateTime, nullable=True)


class VulnService(Base):
    """One open, fingerprinted service on a VulnHost (e.g. port 22 -> OpenSSH 8.2)."""
    __tablename__ = "vuln_services"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("vuln_hosts.id"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    proto = Column(String, default="tcp")
    service_name = Column(String, nullable=True)   # "ssh", "http", "smb", ...
    product = Column(String, nullable=True)         # parsed product, e.g. "OpenSSH"
    version = Column(String, nullable=True)         # parsed version, e.g. "8.2"
    banner_raw = Column(Text, nullable=True)
    last_seen = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("host_id", "port", name="uq_vuln_service_host_port"),)


class VulnPackage(Base):
    """One installed package/software entry on a VulnHost, from a full
    credentialed audit (dpkg/rpm listing over SSH, or KB+installed-software
    over WinRM) — as opposed to VulnService, which is network-exposed ports,
    this is the host's local software inventory. Only populated for hosts
    where credentials already work (see _package_audit in vuln_scan.py)."""
    __tablename__ = "vuln_packages"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("vuln_hosts.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("host_id", "name", name="uq_vuln_package_host_name"),)


class VulnFinding(Base):
    """A CVE match for a (product, version) pair, cached from NVD so a weekly
    re-scan doesn't re-query the same version repeatedly (see queried_at TTL
    check in services/vuln_scan.py)."""
    __tablename__ = "vuln_findings"

    id = Column(Integer, primary_key=True, index=True)
    product = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False)
    cve_id = Column(String, nullable=False)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)  # CRITICAL | HIGH | MEDIUM | LOW
    summary = Column(Text, nullable=True)
    published = Column(String, nullable=True)
    ref_url = Column(String, nullable=True)
    queried_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("product", "version", "cve_id", name="uq_vuln_finding"),)


class VulnRemediation(Base):
    """Remediation status for a specific finding — deliberately a SEPARATE
    table from VulnFinding, not new columns on it: VulnFinding rows are a
    re-fetched CVE cache that services/vuln_scan.py's _get_findings_for
    DELETEs and recreates every NVD_CACHE_DAYS, which would silently wipe
    any status stored directly on that table. Keyed by the same (product,
    version, cve_id) identity, so status survives the cache refresh and
    re-attaches automatically when the same CVE reappears.

    severity is snapshotted here at first-seen time (not read live from
    VulnFinding) so SLA due-date computation still works even between
    cache refreshes — CVSS/severity for a published CVE essentially never
    changes anyway."""
    __tablename__ = "vuln_remediation"

    id = Column(Integer, primary_key=True, index=True)
    product = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False)
    cve_id = Column(String, nullable=False)
    severity = Column(String, nullable=True)
    status = Column(String, nullable=False, default="open")  # open | in_progress | accepted_risk | resolved
    note = Column(Text, nullable=True)
    updated_by = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
    first_seen_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("product", "version", "cve_id", name="uq_vuln_remediation"),)


class LinuxHost(Base):
    """A Linux server the operator has opted into centralized apt-based patch
    management (services/linux_manage.py). Discovered from services/
    vuln_scan.py's own weekly scan (any host with an open port 22) — but
    deliberately a SEPARATE table from VulnHost, not new columns on it:
    VulnHost rows get deleted the moment one weekly CVE scan doesn't see
    them (_prune_dead_hosts in vuln_scan.py), which would silently drop a
    host from a curated, opted-in management list just because it was
    briefly offline. VulnHost also has no persisted distro/package-manager
    identity — this table is the first to need that.

    managed=False until an operator explicitly opts in (mirrors
    edge_devices.enabled in ovh/schema.sql — auto-discovered rows start
    disabled) — apt upgrade must never run on a host nobody reviewed."""
    __tablename__ = "linux_hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, nullable=False, unique=True, index=True)
    hostname = Column(String, nullable=True)
    distro_id = Column(String, nullable=True)          # /etc/os-release ID, e.g. "ubuntu"
    distro_pretty = Column(String, nullable=True)       # PRETTY_NAME, e.g. "Ubuntu 22.04.3 LTS"
    distro_version = Column(String, nullable=True)      # VERSION_ID
    package_manager = Column(String, nullable=True)     # "apt" — only actionable value in v1
    managed = Column(Boolean, nullable=False, default=False)
    source = Column(String, nullable=False, default="auto")   # "auto" | "manual"
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    last_check_at = Column(DateTime, nullable=True)
    last_upgrade_at = Column(DateTime, nullable=True)
    upgradable_count = Column(Integer, nullable=True)
    upgradable_packages = Column(Text, nullable=True)   # JSON list, capped
    reboot_required = Column(Boolean, nullable=False, default=False)
    last_status = Column(String, nullable=True)          # "ok" | "error" | "timeout"
    last_error = Column(Text, nullable=True)
    last_compliance_check_at = Column(DateTime, nullable=True)
    mem_used_pct = Column(Float, nullable=True)
    mem_total_bytes = Column(Integer, nullable=True)
    last_resources_check_at = Column(DateTime, nullable=True)


class LinuxHostDisk(Base):
    """One mounted filesystem's usage on a managed Linux host — a host can
    have several real mounts, hence a separate table rather than columns on
    LinuxHost (mirrors WindowsHostService's "per-host list" shape). One row
    per (host, mount), overwritten on every resource check."""
    __tablename__ = "linux_host_disks"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("linux_hosts.id"), nullable=False)
    mount_point = Column(String, nullable=False)
    total_bytes = Column(Integer, nullable=True)
    used_bytes = Column(Integer, nullable=True)
    pct = Column(Float, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)

    __table_args__ = (UniqueConstraint("host_id", "mount_point", name="uq_linux_host_disk"),)


class LinuxManageSettings(Base):
    """Single-row (id always 1) global config: the ONE shared Credential used
    for every managed Linux host. No per-host credential picker here (unlike
    VulnHost.credential_id) — the feature was explicitly requested as "same
    credential for all of them", so _auth_augment-style per-host credential
    guessing (services/vuln_scan.py) is deliberately NOT used for discovery
    or SSH exec here."""
    __tablename__ = "linux_manage_settings"

    id = Column(Integer, primary_key=True, default=1)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class WindowsHost(Base):
    """A Windows server the operator has opted into centralized Windows
    Update management (services/windows_manage.py) — direct analog of
    LinuxHost above, same reasoning for being a separate table from
    VulnHost (pruning safety, persisted identity). Discovered from
    services/vuln_scan.py's own weekly pass (any host with an open WinRM
    port 5985/5986 — see vuln_scan.py's WINRM_PORTS)."""
    __tablename__ = "windows_hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, nullable=False, unique=True, index=True)
    hostname = Column(String, nullable=True)            # "Host Name:" from systeminfo
    os_name = Column(String, nullable=True)              # e.g. "Microsoft Windows Server 2019 Standard"
    os_version = Column(String, nullable=True)
    winrm_port = Column(Integer, nullable=True)          # 5985 or 5986
    managed = Column(Boolean, nullable=False, default=False)
    source = Column(String, nullable=False, default="auto")   # "auto" | "manual"
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    last_check_at = Column(DateTime, nullable=True)
    last_upgrade_at = Column(DateTime, nullable=True)
    upgradable_count = Column(Integer, nullable=True)
    upgradable_titles = Column(Text, nullable=True)      # JSON list of update titles, capped
    reboot_required = Column(Boolean, nullable=False, default=False)
    last_status = Column(String, nullable=True)           # "ok" | "error" | "timeout"
    last_error = Column(Text, nullable=True)
    last_restart_at = Column(DateTime, nullable=True)
    last_restart_reason = Column(Text, nullable=True)
    last_compliance_check_at = Column(DateTime, nullable=True)
    domain = Column(String, nullable=True)               # "WORKGROUP" or AD domain, from systeminfo
    host_type = Column(String, nullable=False, default="server")  # "server" | "workstation" — auto-detected, overridable
    last_services_check_at = Column(DateTime, nullable=True)
    mem_used_pct = Column(Float, nullable=True)
    mem_total_bytes = Column(Integer, nullable=True)
    last_resources_check_at = Column(DateTime, nullable=True)
    # "System Model:" from systeminfo — e.g. "Virtual Machine" for a
    # Hyper-V guest, "PowerEdge R640" for real Dell hardware. Lets
    # services/dell_monitor.py's discover_local_servers() skip VMs
    # entirely instead of wasting a WinRM+iSM/RACADM round trip (and a
    # confusing "not found" note) on a host that can never have its own
    # physical iDRAC — confirmed live: several Windows hosts at one site
    # turned out to be Hyper-V guests, not the physical hypervisor itself.
    system_model = Column(String, nullable=True)
    # Per-host credential override — falls back to WindowsManageSettings'
    # shared credential when unset. Confirmed necessary live: a real
    # environment can have BOTH domain-joined and workgroup-only Windows
    # hosts needing genuinely different accounts, which a single shared
    # credential can never cover for both at once. Mirrors DellServer's
    # own credential_id exactly (services/dell_monitor.py).
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)


class WindowsHostDisk(Base):
    """One local fixed drive's usage on a managed Windows host — mirrors
    LinuxHostDisk. One row per (host, drive letter), overwritten on every
    resource check."""
    __tablename__ = "windows_host_disks"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("windows_hosts.id"), nullable=False)
    drive_letter = Column(String, nullable=False)
    total_bytes = Column(Integer, nullable=True)
    used_bytes = Column(Integer, nullable=True)
    pct = Column(Float, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)

    __table_args__ = (UniqueConstraint("host_id", "drive_letter", name="uq_windows_host_disk"),)


class WindowsHostService(Base):
    """One Windows service the operator wants watched on a specific host —
    per-host list (not global), per the user's explicit choice. Status is
    refreshed alongside the rest of discover_windows_hosts()'s per-host
    pass; shown in the UI only — no Telegram alert, per the user's choice."""
    __tablename__ = "windows_host_services"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("windows_hosts.id"), nullable=False)
    service_name = Column(String, nullable=False)    # Win32_Service/Get-Service "Name" (short key, not display name)
    display_name = Column(String, nullable=True)
    status = Column(String, nullable=True)             # "Running" | "Stopped" | ... | None = not yet checked
    last_checked_at = Column(DateTime, nullable=True)

    __table_args__ = (UniqueConstraint("host_id", "service_name", name="uq_windows_host_service"),)


class WindowsManageSettings(Base):
    """Single-row (id always 1) global config: the ONE shared Credential used
    for every managed Windows host — same "one credential for all" model as
    LinuxManageSettings, per the user's explicit request to mirror Linux.

    manage_enabled: NULL = fall back to the MIKROTIK_WINDOWS_MANAGE_ENABLED
    env var (the original, OS-level-only toggle) — nullable rather than a
    plain default so an operator who never touches this setting keeps
    exactly today's behavior. A non-NULL value here overrides the env var,
    letting the toggle be flipped from this agent's own UI (or remotely
    from Central) without editing the OS process environment and
    restarting the service on every single agent."""
    __tablename__ = "windows_manage_settings"

    id = Column(Integer, primary_key=True, default=1)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    manage_enabled = Column(Boolean, nullable=True)
    # JSON list of ints — the "normal" ports a workstation is allowed to have
    # open; anything else found open (via the existing weekly vuln-scan port
    # data) is flagged as unexpected. NULL = use the built-in default list.
    workstation_allowed_ports = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class ComplianceCheckResult(Base):
    """Result of one configuration-hardening check (services/compliance.py)
    against one managed target — read-only pass/fail, not a vulnerability
    (no CVE involved). One row per (target_type, target_id, check_id),
    overwritten on every run — history isn't needed yet, checked_at says
    "as of when"."""
    __tablename__ = "compliance_check_results"

    id = Column(Integer, primary_key=True, index=True)
    target_type = Column(String, nullable=False)   # "linux" | "windows" | "mikrotik"
    target_id = Column(Integer, nullable=False)     # LinuxHost.id / WindowsHost.id / Device.id
    check_id = Column(String, nullable=False)        # e.g. "linux.ssh_root_login_disabled"
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)         # "high" | "medium" | "low"
    passed = Column(Boolean, nullable=True)             # None = couldn't be determined
    detail = Column(Text, nullable=True)                 # what was actually found
    checked_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("target_type", "target_id", "check_id",
                                        name="uq_compliance_check"),)


class AnydeskSession(Base):
    """One AnyDesk outgoing connection, reconstructed from LOCAL trace files
    on the control machine — not the AnyDesk REST API (that requires a
    Standard-or-above license; this user's account is Solo/Lite, confirmed
    with them directly, so the API is not an option). Two different local
    log files feed this table, merged by (cid, minute-truncated start):

    - connection_trace.txt: one line per connection attempt, minute
      precision, no end time, but retains MONTHS of history (confirmed on
      this user's machine: ~8 months in a 135 KB file) — the durable
      long-term record, source of `auth_method`/`rejected`.
    - ad.trace/ad_svc.trace: verbose service log with exact (ms-precision)
      "Received outgoing connection request"/"Stop monitoring" pairs, but
      rotates out after only a few days on this machine — the source of
      `ended_at`/`duration_sec` when it's still available at sync time.

    A session synced from connection_trace.txt alone (the common case for
    anything older than a few days) has ended_at/duration_sec = NULL —
    there is no way to know how long it lasted once the trace log has
    rotated past it. started_at is upgraded from minute- to ms-precision
    the moment a matching ad_svc.trace pair is found for it.

    cid is the numeric AnyDesk Client-ID of the OTHER party (the machine
    connected to) — a human label is looked up separately via
    AnydeskCidLabel, not stored redundantly here."""
    __tablename__ = "anydesk_sessions"

    id = Column(Integer, primary_key=True, index=True)
    cid = Column(String, nullable=False, index=True)
    started_at = Column(DateTime, nullable=False, index=True)
    ended_at = Column(DateTime, nullable=True)
    duration_sec = Column(Integer, nullable=True)
    auth_method = Column(String, nullable=True)    # "User" | "Passwd" | "Token" | None (ad_svc-only row)
    rejected = Column(Boolean, nullable=False, default=False)
    source = Column(String, nullable=False, default="connection_trace")  # "connection_trace" | "ad_svc_trace" | "merged"
    # Billing/time-tracking classification — added so this ONE local table
    # covers both "which sessions happened" and "which of them are billable
    # work", instead of a separate OVH panel (removed) that needed its own
    # login on top of the local agent's. NULL = not yet classified.
    category = Column(String, nullable=True)        # "billable" | "training" | "internal" | None
    note = Column(Text, nullable=True)
    synced_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("cid", "started_at", name="uq_anydesk_session"),)


class AnydeskCidLabel(Base):
    """Operator-entered label for an AnyDesk numeric Client-ID, e.g.
    "1268917895" -> "sanmed - R3". Purely local, purely cosmetic — never
    sent anywhere, just makes AnydeskSession.cid readable in the UI."""
    __tablename__ = "anydesk_cid_labels"

    cid = Column(String, primary_key=True)
    label = Column(String, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow)


class DellServer(Base):
    """One physical server's out-of-band BMC (Redfish — health monitoring:
    CPU, memory, power, fans, storage/RAID, hardware event log). Despite
    the table/model name (kept for backward compatibility — this table
    predates multi-vendor support), NOT Dell-only: the `vendor` column
    tells which one (Dell iDRAC / HP iLO / Fujitsu iRMC — confirmed by
    the user to exist in their infrastructure alongside Dell), since
    services/idrac_client.py's Redfish client was always vendor-generic
    (standard DMTF Systems/Chassis/Managers discovery, no Dell-specific
    resource paths) — only the DEFAULT credential and the local-fallback
    tools (see below) are vendor-specific. NULL vendor = legacy rows from
    before this column existed, always Dell in practice (migration
    backfills them to "dell").

    Reachable one of two ways depending on how the site's network is
    set up (confirmed with the user: not every server has its BMC on its
    own routable IP):

      - idrac_ip set: talked to directly over the network via Redfish
        (services/idrac_client.py) — clean, no dependency on what's
        installed on the server's own OS.
      - idrac_ip NULL, windows_host_id set: iDRAC has no routable address
        (the common case when only "Shared LOM"/the internal USB NIC is
        configured) — reached instead by WinRM-ing into the companion
        Windows Server host itself and running a LOCAL query there
        (services/dell_local.py tries iDRAC Service Module's WMI provider,
        then RACADM CLI — "different servers have different things
        installed" per the user, so both are tried rather than requiring
        one specific tool).

    Both fields may be set (some sites might want the local path to also
    confirm what the network path reports) but at least one must be for
    this row to be checkable at all — enforced in the service layer, not
    the schema, so a row can be added before either is configured yet."""
    __tablename__ = "dell_servers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)
    # "dell" | "hp" | "fujitsu" | None (legacy row, treated as Dell).
    vendor = Column(String, nullable=True)
    idrac_ip = Column(String, nullable=True, unique=True)
    idrac_port = Column(Integer, nullable=False, default=443)
    windows_host_id = Column(Integer, ForeignKey("windows_hosts.id"), nullable=True)
    # iDRAC has its own local account, separate from the Windows/domain
    # credential used for the WinRM local-fallback path — reuses the same
    # Credential model/encryption as everything else, just a different row.
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    # Which path last actually worked — "redfish" | "local_ism" |
    # "local_racadm" — shown in the UI so an operator can tell which of
    # the two-or-three methods this server is actually using, not just
    # that a health check ran.
    access_method = Column(String, nullable=True)
    last_check_at = Column(DateTime, nullable=True)
    last_status = Column(String, nullable=True)          # "ok" | "error"
    last_error = Column(Text, nullable=True)
    health_rollup = Column(String, nullable=True)          # "OK" | "Warning" | "Critical"
    service_tag = Column(String, nullable=True)
    model = Column(String, nullable=True)
    bios_version = Column(String, nullable=True)
    power_state = Column(String, nullable=True)             # "On" | "Off"
    # {"cpu": "OK", "memory": "OK", "storage": "Warning", "power": "OK",
    #  "fans": "OK", "temperature": "OK"} — one JSON blob rather than a
    # column per component: Redfish/racadm/iSM don't all expose exactly
    # the same component set, and this avoids a schema change every time
    # coverage grows.
    components_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    credential = relationship("Credential")


class DellServerSelEntry(Base):
    """One System Event Log (hardware event log) entry — the server's own
    record of things like a failed PSU, a DIMM ECC error, a degraded RAID
    disk. Deduped by (server, message + logged_at) so re-checking the same
    server doesn't re-insert entries the device already reported before;
    kept (not pruned) so the log view has real history, unlike the
    live-only health fields above."""
    __tablename__ = "dell_server_sel_entries"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("dell_servers.id"), nullable=False)
    severity = Column(String, nullable=True)         # "OK" | "Warning" | "Critical"
    message = Column(Text, nullable=False)
    logged_at = Column(DateTime, nullable=True)
    seen_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("server_id", "message", "logged_at", name="uq_dell_sel_entry"),)


def _migrate_add_columns():
    """Add new columns to existing tables without dropping data.
    SQLite ALTER TABLE ADD COLUMN is safe and idempotent (we check first)."""
    inspector = inspect(engine)

    if "credentials" in inspector.get_table_names():
        cred_cols = {c["name"] for c in inspector.get_columns("credentials")}
        with engine.begin() as conn:
            if "snmp_community_enc" not in cred_cols:
                conn.execute(text("ALTER TABLE credentials ADD COLUMN snmp_community_enc TEXT"))
            if "domain" not in cred_cols:
                conn.execute(text("ALTER TABLE credentials ADD COLUMN domain TEXT"))

    if "devices" in inspector.get_table_names():
        dev_cols = {c["name"] for c in inspector.get_columns("devices")}
        with engine.begin() as conn:
            if "has_snmp" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN has_snmp BOOLEAN DEFAULT 0"))
            if "snmp_port" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN snmp_port INTEGER DEFAULT 161"))
            if "vendor" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN vendor VARCHAR(32) DEFAULT 'mikrotik'"))
            if "current_firmware" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN current_firmware TEXT"))
            if "upgrade_firmware" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN upgrade_firmware TEXT"))
            if "latest_ros_version" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN latest_ros_version TEXT"))
            if "ros_update_status" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN ros_update_status TEXT"))
            if "owner" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN owner TEXT"))
            if "criticality" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN criticality VARCHAR(32)"))
            if "mem_used_pct" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN mem_used_pct FLOAT"))
            if "disk_used_pct" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN disk_used_pct FLOAT"))
            if "cpu_load_pct" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN cpu_load_pct INTEGER"))
            if "last_resources_check_at" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN last_resources_check_at DATETIME"))
            if "iface_mbps_threshold" not in dev_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN iface_mbps_threshold FLOAT"))

    if "vuln_hosts" in inspector.get_table_names():
        vh_cols = {c["name"] for c in inspector.get_columns("vuln_hosts")}
        with engine.begin() as conn:
            if "last_package_audit_at" not in vh_cols:
                conn.execute(text("ALTER TABLE vuln_hosts ADD COLUMN last_package_audit_at DATETIME"))

    if "scan_ranges" in inspector.get_table_names():
        sr_cols = {c["name"] for c in inspector.get_columns("scan_ranges")}
        with engine.begin() as conn:
            if "scan_day" not in sr_cols:
                conn.execute(text("ALTER TABLE scan_ranges ADD COLUMN scan_day INTEGER"))
            if "scan_hour" not in sr_cols:
                conn.execute(text("ALTER TABLE scan_ranges ADD COLUMN scan_hour INTEGER"))

    if "linux_hosts" in inspector.get_table_names():
        lh_cols = {c["name"] for c in inspector.get_columns("linux_hosts")}
        with engine.begin() as conn:
            if "last_compliance_check_at" not in lh_cols:
                conn.execute(text("ALTER TABLE linux_hosts ADD COLUMN last_compliance_check_at DATETIME"))
            if "mem_used_pct" not in lh_cols:
                conn.execute(text("ALTER TABLE linux_hosts ADD COLUMN mem_used_pct FLOAT"))
            if "mem_total_bytes" not in lh_cols:
                conn.execute(text("ALTER TABLE linux_hosts ADD COLUMN mem_total_bytes INTEGER"))
            if "last_resources_check_at" not in lh_cols:
                conn.execute(text("ALTER TABLE linux_hosts ADD COLUMN last_resources_check_at DATETIME"))

    if "dell_servers" in inspector.get_table_names():
        ds_cols = {c["name"] for c in inspector.get_columns("dell_servers")}
        with engine.begin() as conn:
            if "vendor" not in ds_cols:
                conn.execute(text("ALTER TABLE dell_servers ADD COLUMN vendor VARCHAR(32)"))
                # Every row that existed before this column did so ONLY
                # through Dell-specific discovery/add flows — safe to
                # backfill them all as "dell" rather than leave NULL.
                conn.execute(text("UPDATE dell_servers SET vendor = 'dell' WHERE vendor IS NULL"))

    if "windows_hosts" in inspector.get_table_names():
        wh_cols = {c["name"] for c in inspector.get_columns("windows_hosts")}
        with engine.begin() as conn:
            if "last_compliance_check_at" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN last_compliance_check_at DATETIME"))
            if "domain" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN domain TEXT"))
            if "host_type" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN host_type VARCHAR DEFAULT 'server'"))
            if "last_services_check_at" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN last_services_check_at DATETIME"))
            if "mem_used_pct" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN mem_used_pct FLOAT"))
            if "mem_total_bytes" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN mem_total_bytes INTEGER"))
            if "last_resources_check_at" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN last_resources_check_at DATETIME"))
            if "system_model" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN system_model TEXT"))
            if "credential_id" not in wh_cols:
                conn.execute(text("ALTER TABLE windows_hosts ADD COLUMN credential_id INTEGER"))

    if "windows_manage_settings" in inspector.get_table_names():
        wms_cols = {c["name"] for c in inspector.get_columns("windows_manage_settings")}
        with engine.begin() as conn:
            if "manage_enabled" not in wms_cols:
                conn.execute(text("ALTER TABLE windows_manage_settings ADD COLUMN manage_enabled BOOLEAN"))
            if "workstation_allowed_ports" not in wms_cols:
                conn.execute(text("ALTER TABLE windows_manage_settings ADD COLUMN workstation_allowed_ports TEXT"))

    if "anydesk_sessions" in inspector.get_table_names():
        as_cols = {c["name"] for c in inspector.get_columns("anydesk_sessions")}
        with engine.begin() as conn:
            if "category" not in as_cols:
                conn.execute(text("ALTER TABLE anydesk_sessions ADD COLUMN category VARCHAR"))
            if "note" not in as_cols:
                conn.execute(text("ALTER TABLE anydesk_sessions ADD COLUMN note TEXT"))


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

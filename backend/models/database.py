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


class ScanRange(Base):
    __tablename__ = "scan_ranges"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String, nullable=False, unique=True)
    label = Column(String, nullable=True)
    active = Column(Boolean, default=True)


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

    if "vuln_hosts" in inspector.get_table_names():
        vh_cols = {c["name"] for c in inspector.get_columns("vuln_hosts")}
        with engine.begin() as conn:
            if "last_package_audit_at" not in vh_cols:
                conn.execute(text("ALTER TABLE vuln_hosts ADD COLUMN last_package_audit_at DATETIME"))


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

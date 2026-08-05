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


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

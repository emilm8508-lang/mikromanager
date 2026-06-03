from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float,
    create_engine, inspect, text,
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

    devices = relationship("Device", back_populates="credential")


class ScanRange(Base):
    __tablename__ = "scan_ranges"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String, nullable=False, unique=True)
    label = Column(String, nullable=True)
    active = Column(Boolean, default=True)


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


def _migrate_add_columns():
    """Add new columns to existing tables without dropping data.
    SQLite ALTER TABLE ADD COLUMN is safe and idempotent (we check first)."""
    inspector = inspect(engine)

    if "credentials" in inspector.get_table_names():
        cred_cols = {c["name"] for c in inspector.get_columns("credentials")}
        with engine.begin() as conn:
            if "snmp_community_enc" not in cred_cols:
                conn.execute(text("ALTER TABLE credentials ADD COLUMN snmp_community_enc TEXT"))

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

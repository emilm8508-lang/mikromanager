from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mikrotik.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Sync engine — avoids greenlet/aiosqlite (which lack stable wheels on newer Pythons).
# SQLite calls are microsecond-fast, so doing them sync inside async FastAPI endpoints
# is fine for this single-user admin tool.
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
    has_api = Column(Boolean, default=False)
    has_ssh = Column(Boolean, default=False)
    has_web = Column(Boolean, default=False)
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
    description = Column(String, nullable=True)

    devices = relationship("Device", back_populates="credential")


class ScanRange(Base):
    __tablename__ = "scan_ranges"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String, nullable=False, unique=True)
    label = Column(String, nullable=True)
    active = Column(Boolean, default=True)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

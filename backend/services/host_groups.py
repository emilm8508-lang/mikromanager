"""
Operator-defined groups of Linux / Windows servers — the unit the "update the whole group" and
"restart the whole group" buttons work on. Purely local bookkeeping: a group is a name and a list
of hosts of ONE platform (HostGroup.platform); nothing here talks to a host. A host belongs to at
most one group (LinuxHost.group_id / WindowsHost.group_id); deleting a group only un-assigns its
hosts. Servers without a group are arranged automatically by the UI (Windows: by domain, Linux: by
distribution).
"""
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.exc import IntegrityError

from models.database import SessionLocal, HostGroup, LinuxHost, WindowsHost

_HOST_MODEL = {"linux": LinuxHost, "windows": WindowsHost}
MAX_NAME = 64


def _model(platform: str):
    if platform not in _HOST_MODEL:
        raise ValueError("unknown platform")
    return _HOST_MODEL[platform]


def _clean_name(name: Optional[str]) -> str:
    name = " ".join((name or "").split())
    if not name:
        raise ValueError("a group name is required")
    if len(name) > MAX_NAME:
        raise ValueError(f"the name is too long (max {MAX_NAME} characters)")
    return name


def list_groups(platform: str) -> list:
    host = _model(platform)
    with SessionLocal() as db:
        counts = dict(db.execute(select(host.group_id, func.count()).where(host.group_id.is_not(None)).group_by(host.group_id)).all())
        rows = db.execute(select(HostGroup).where(HostGroup.platform == platform).order_by(HostGroup.name)).scalars().all()
        return [{"id": g.id, "name": g.name, "hosts": counts.get(g.id, 0)} for g in rows]


def create_group(platform: str, name: str) -> dict:
    _model(platform)
    name = _clean_name(name)
    with SessionLocal() as db:
        g = HostGroup(platform=platform, name=name)
        db.add(g)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise ValueError("a group with this name already exists")
        return {"id": g.id, "name": g.name, "hosts": 0}


def rename_group(platform: str, group_id: int, name: str) -> dict:
    name = _clean_name(name)
    with SessionLocal() as db:
        g = db.get(HostGroup, group_id)
        if not g or g.platform != platform:
            raise LookupError("group not found")
        g.name = name
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise ValueError("a group with this name already exists")
        return {"id": g.id, "name": g.name}


def delete_group(platform: str, group_id: int) -> dict:
    host = _model(platform)
    with SessionLocal() as db:
        g = db.get(HostGroup, group_id)
        if not g or g.platform != platform:
            raise LookupError("group not found")
        db.execute(update(host).where(host.group_id == group_id).values(group_id=None))
        db.delete(g)
        db.commit()
    return {"ok": True}


def set_host_group(platform: str, host_id: int, group_id: Optional[int]) -> dict:
    """Puts a host into a group of its own platform, or takes it out (group_id None)."""
    host = _model(platform)
    with SessionLocal() as db:
        row = db.get(host, host_id)
        if not row:
            raise LookupError("host not found")
        if group_id is not None:
            g = db.get(HostGroup, group_id)
            if not g or g.platform != platform:
                raise ValueError("group not found")
        row.group_id = group_id
        db.commit()
    return {"ok": True, "host_id": host_id, "group_id": group_id}

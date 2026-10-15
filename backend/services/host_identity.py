"""One machine, one entry - also when its address changes.

Hosts are found by address (a WinRM / SSH / API port open at an IP), so a computer that gets another DHCP lease used to show up as a
second entry next to the old one, which then sat there with its last job failed. Here a host is recognised by its NAME: when the
address-less identity (host name) of a newly found address matches an entry whose old address is no longer seen, that entry just gets
the new address - keeping its "managed" flag, credential, group, watched services and history. `merge_duplicates` does the same for
the pairs that already exist from before. Two live machines that really share a name are left alone."""
import json
from datetime import datetime
from typing import Optional, Set

from sqlalchemy import select, delete, update

from models.database import (SessionLocal, VulnHost, VulnService, Asset, DellServer, HypervActionLog, HypervHost, LinuxHost, LinuxHostDisk, LinuxHostService,
                             WindowsHost, WindowsHostDisk, WindowsHostService, Device)


def _norm(h: Optional[str]) -> str:
    return (h or "").strip().casefold()


def adopt_moved(model, hostname: Optional[str], new_ip: str, seen_ips: Set[str], **fresh) -> bool:
    """True if an existing entry of `model` (LinuxHost / WindowsHost) with this host name was given the address `new_ip` (and the
    `fresh` columns): its old address is not among `seen_ips` (what the current pass found alive) and no other candidate is either."""
    name = _norm(hostname)
    if not name:
        return False
    with SessionLocal() as db:
        cands = [h for h in db.execute(select(model).where(model.ip != new_ip)).scalars().all() if _norm(h.hostname) == name and h.ip not in seen_ips]
        if len(cands) != 1:
            return False
        h = cands[0]
        if db.execute(select(model.id).where(model.ip == new_ip)).first():
            return False
        h.ip = new_ip
        h.last_seen_at = datetime.utcnow()
        for k, v in fresh.items():
            if v is not None and hasattr(h, k):
                setattr(h, k, v)
        db.commit()
        print(f"[host_identity] {model.__tablename__}: '{hostname}' moved to {new_ip}")
        return True


def _score(h) -> tuple:
    return (bool(h.managed), bool(getattr(h, "credential_id", None)), bool(getattr(h, "group_id", None)), h.last_upgrade_at or datetime.min, h.last_seen_at or datetime.min)


def merge_duplicates(platform: str, seen_ips: Set[str]) -> int:
    """Merges the entries that share a host name when at most one of them is alive now (in `seen_ips`); returns how many entries it
    removed. The entry with the most history (managed, credential, group) stays and takes the live address."""
    model = WindowsHost if platform == "windows" else LinuxHost
    removed = 0
    with SessionLocal() as db:
        groups = {}
        for h in db.execute(select(model)).scalars().all():
            if _norm(h.hostname):
                groups.setdefault(_norm(h.hostname), []).append(h)
        for name, rows in groups.items():
            if len(rows) < 2:
                continue
            live = [h for h in rows if h.ip in seen_ips]
            if len(live) > 1:
                continue                                  # two machines that are up at the same time: really two
            keep = max(rows, key=_score)
            target = live[0] if live else max(rows, key=lambda h: h.last_seen_at or datetime.min)
            drops = [h for h in rows if h is not keep]
            if platform == "windows":
                keep_hv = db.execute(select(HypervHost).where(HypervHost.windows_host_id == keep.id)).scalar_one_or_none()
                if sum(1 for d in drops if db.execute(select(HypervHost.id).where(HypervHost.windows_host_id == d.id)).first()) + (1 if keep_hv else 0) > 1:
                    continue                              # more than one of them is a Hyper-V host with its own machines: leave to a human
            new_ip, new_port = target.ip, getattr(target, "winrm_port", None)
            fresh = {c: getattr(target, c, None) for c in ("os_name", "os_version", "domain", "system_model", "distro_id", "distro_pretty", "distro_version", "package_manager")}
            for d in drops:
                dead_assets = [a for a in db.execute(select(Asset)).scalars().all()
                               if (json.loads(a.refs or "{}").get("windows_host_id" if platform == "windows" else "linux_host_id") == d.id)]
                if platform == "windows":
                    mine = {s.service_name for s in db.execute(select(WindowsHostService).where(WindowsHostService.host_id == keep.id)).scalars().all()}
                    for s in db.execute(select(WindowsHostService).where(WindowsHostService.host_id == d.id)).scalars().all():
                        if s.service_name in mine:
                            db.delete(s)
                        else:
                            s.host_id = keep.id               # the services somebody chose to watch stay
                    db.execute(delete(WindowsHostDisk).where(WindowsHostDisk.host_id == d.id))
                    if not db.execute(select(HypervHost.id).where(HypervHost.windows_host_id == keep.id)).first():
                        db.execute(update(HypervHost).where(HypervHost.windows_host_id == d.id).values(windows_host_id=keep.id))
                    db.execute(update(DellServer).where(DellServer.windows_host_id == d.id).values(windows_host_id=keep.id))
                    db.execute(update(HypervActionLog).where(HypervActionLog.windows_host_id == d.id).values(windows_host_id=keep.id))
                else:
                    mine = {s.service_name for s in db.execute(select(LinuxHostService).where(LinuxHostService.host_id == keep.id)).scalars().all()}
                    for s in db.execute(select(LinuxHostService).where(LinuxHostService.host_id == d.id)).scalars().all():
                        if s.service_name in mine:
                            db.delete(s)
                        else:
                            s.host_id = keep.id
                    db.execute(delete(LinuxHostDisk).where(LinuxHostDisk.host_id == d.id))
                for a in dead_assets:
                    db.delete(a)                              # its asset is re-keyed to the surviving host by the next inventory rebuild
                db.delete(d)
                removed += 1
            db.flush()
            if keep.ip != new_ip:
                keep.ip = new_ip
                if new_port:
                    keep.winrm_port = new_port
            for k, v in fresh.items():
                if v is not None and hasattr(keep, k):
                    setattr(keep, k, v)
            keep.last_seen_at = max([h.last_seen_at for h in rows if h.last_seen_at] or [datetime.utcnow()])
            print(f"[host_identity] {platform}: merged {len(drops)} duplicate(s) of '{name}' into one entry at {new_ip}")
        db.commit()
    return removed


def adopt_moved_device(identity: Optional[str], vendor: Optional[str], new_ip: str) -> Optional[int]:
    """A router / switch found at a new address that has the identity (and vendor) of exactly one known device which is offline now:
    the same device, new address - returns its id after changing the address, else None."""
    name = _norm(identity)
    if not name:
        return None
    with SessionLocal() as db:
        if db.execute(select(Device.id).where(Device.ip == new_ip)).first():
            return None
        cands = [d for d in db.execute(select(Device)).scalars().all()
                 if _norm(d.identity) == name and (not vendor or not d.vendor or d.vendor == vendor) and not d.online]
        if len(cands) != 1:
            return None
        cands[0].ip = new_ip
        db.commit()
        print(f"[host_identity] device '{identity}' moved to {new_ip}")
        return cands[0].id


def startup_merge() -> None:
    """At start: fold the duplicates that already exist, judging "alive" by what the vulnerability scan last saw open (WinRM / SSH)."""
    try:
        with SessionLocal() as db:
            def seen(ports):
                return {ip for ip, in db.execute(select(VulnHost.ip).join(VulnService, VulnService.host_id == VulnHost.id).where(VulnService.port.in_(ports))).all()}
            win, lin = seen((5985, 5986)), seen((22,))
        if win:
            merge_duplicates("windows", win)
        if lin:
            merge_duplicates("linux", lin)
    except Exception as e:
        print(f"[host_identity] startup merge skipped: {e}")

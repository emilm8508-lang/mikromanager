"""
When a host or device was last restarted - and the restarts the agent noticed - for the host card.

Never guessed: the last boot is the time of a reading minus the uptime read at that moment - RouterOS /system/resource (read by the fleet refresh), SNMP sysUpTime (the
inventory scan), the Windows boot time (WMI / WinRM hardware scan), the uptime of a Linux host (/proc/uptime in its hardware scan), the uptime of a Hyper-V VM - and the reading
with the newest timestamp wins (at the same age the boot time itself beats a computed one). The source and the age of the reading come with it, because an uptime read a day ago
places the restart only as accurately as that. When the agent itself saw the uptime fall (the "device restarted" event, kept 30 days) that moment is listed as a detected restart.
Nothing here queries the network.
"""
import json
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, Device, HypervVM, SecurityEvent


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _jload(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default


def _parse(v) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v.replace("Z", "").split("+")[0])
        except ValueError:
            return None
    return None


# ── Last restart ─────────────────────────────────────────────────────────────

def boot_candidates(asset: Asset, device: Optional[Device], vm: Optional[HypervVM]) -> List[dict]:
    """Every way the last boot can be told, as {at, source, as_of, uptime_sec, approx}."""
    out: List[dict] = []
    det = _jload(asset.details, {})
    system = det.get("system") or {}
    if system.get("last_boot"):                                  # Windows (WMI / WinRM) and Linux (/proc/uptime) hardware scans: the boot time itself
        at = _parse(system["last_boot"])
        if at:
            out.append({"at": at, "source": "hardware_scan", "as_of": asset.last_scan_at, "uptime_sec": None, "approx": False})
    snmp = det.get("snmp") or det.get("network") or {}
    up = snmp.get("uptime_sec") if isinstance(snmp, dict) else None
    if up is None:
        up = det.get("uptime_sec")
    if up and asset.last_scan_at:
        out.append({"at": asset.last_scan_at - timedelta(seconds=int(up)), "source": "snmp", "as_of": asset.last_scan_at, "uptime_sec": int(up), "approx": True})
    if device is not None and device.uptime_sec is not None and device.fleet_checked_at:
        out.append({"at": device.fleet_checked_at - timedelta(seconds=int(device.uptime_sec)), "source": "routeros", "as_of": device.fleet_checked_at,
                    "uptime_sec": int(device.uptime_sec), "approx": True})
    if vm is not None and vm.uptime_sec is not None and vm.last_seen_at:
        out.append({"at": vm.last_seen_at - timedelta(seconds=int(vm.uptime_sec)), "source": "hyperv", "as_of": vm.last_seen_at, "uptime_sec": int(vm.uptime_sec), "approx": True})
    return out


def best_boot(cands: List[dict]) -> Optional[dict]:
    """The reading with the newest `as_of` (the freshest uptime says the most), the boot time itself preferred over a computed one at the same age."""
    if not cands:
        return None
    best = max(cands, key=lambda c: (c["as_of"] or datetime.min, not c["approx"]))
    return {"at": _iso(best["at"]), "source": best["source"], "as_of": _iso(best["as_of"]), "uptime_sec": best["uptime_sec"], "approx": best["approx"],
            "age_sec": int((datetime.utcnow() - best["at"]).total_seconds()) if best["at"] else None}


def detected_restarts(db, names: List[str], days: int = 30) -> List[dict]:
    """The restarts the agent noticed (the uptime of the device fell between two readings), newest first."""
    names = [n for n in names if n]
    if not names:
        return []
    since = datetime.utcnow() - timedelta(days=days)
    rows = db.execute(select(SecurityEvent).where(SecurityEvent.type == "device_rebooted", SecurityEvent.device_name.in_(names), SecurityEvent.ts >= since)
                      .order_by(SecurityEvent.ts.desc()).limit(10)).scalars().all()
    return [{"at": _iso(r.ts), "count": r.count} for r in rows]


# ── Resolving ────────────────────────────────────────────────────────────────

def resolve(ip: Optional[str] = None, name: Optional[str] = None) -> Optional[int]:
    """The inventory asset an address or a name belongs to (the address first, then the name, case-insensitive; a "host: vm" name is cut at the colon)."""
    with SessionLocal() as db:
        if ip:
            a = db.execute(select(Asset).where(Asset.ip == ip.strip()).limit(1)).scalars().first()
            if a:
                return a.id
        if name:
            n = name.split(":")[0].strip().lower()
            if n:
                for a in db.execute(select(Asset)).scalars().all():
                    if (a.name or "").lower() == n or (a.ip or "") == n:
                        return a.id
    return None


def for_asset(asset_id: int) -> Optional[dict]:
    """{"boot": the best reading | None, "restarts": [the restarts the agent noticed]} for an inventory asset; None when it does not exist."""
    with SessionLocal() as db:
        asset = db.get(Asset, asset_id)
        if asset is None:
            return None
        refs = _jload(asset.refs, {})
        device = db.get(Device, refs["device_id"]) if refs.get("device_id") else None
        vm = db.get(HypervVM, refs["hyperv_vm_id"]) if refs.get("hyperv_vm_id") else None
        names = [n for n in {asset.name, device.name if device else None, device.identity if device else None} if n]
        return {"boot": best_boot(boot_candidates(asset, device, vm)), "restarts": detected_restarts(db, names)}

"""
The detailed readings of a server's BMC (iDRAC / iLO / iRMC) — what the
detail view and the central server show beyond the per-component health.

idrac_client.collect_details() (Redfish) and dell_local._racadm_details()
(RACADM) both return the same shape: system, cpus, dimms, storage
{controllers, drives, volumes}, temps, fans, fan_redundancy, power {watts,
psus, redundancy, ...}, nics, intrusion, batteries. This module derives the
one-line summary from it, records the readings worth a history (power draw,
inlet / CPU / exhaust temperature, fan speed) as metric series, and makes
the copy that goes to the central server (no MAC addresses).
"""
from typing import List, Optional

from services import metrics

# metric key suffix -> (label, kind, unit)
SERIES = {
    "power_w": ("Pobór mocy", "other", "W"),
    "inlet_c": ("Temperatura wlotu", "temp", "°C"),
    "cpu_c": ("Temperatura CPU", "temp", "°C"),
    "exhaust_c": ("Temperatura wylotu", "temp", "°C"),
    "fan_rpm": ("Wentylatory (średnio)", "other", "RPM"),
}


def series_key(server_id: int, suffix: str) -> str:
    return f"bmc:{server_id}:{suffix}"


def _num(v) -> Optional[float]:
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def summarize(d: dict) -> dict:
    """The numbers shown on the server's row: power draw, temperatures,
    average fan speed, memory, CPUs, drives and power supplies (with how
    many of them are not OK)."""
    if not d:
        return {}
    temps = d.get("temps") or []
    named = lambda word: [_num(t.get("c")) for t in temps if word in (t.get("name") or "").lower() and _num(t.get("c")) is not None]
    inlet, cpu, exhaust = named("inlet"), named("cpu"), named("exhaust")
    rpms = [_num(f.get("rpm")) for f in d.get("fans") or [] if _num(f.get("rpm"))]
    system = d.get("system") or {}
    dimms = d.get("dimms") or []
    storage = d.get("storage") or {}
    drives = storage.get("drives") or []
    psus = (d.get("power") or {}).get("psus") or []
    cpus = d.get("cpus") or []
    bad = lambda items: sum(1 for x in items if x.get("health") in ("Warning", "Critical") or x.get("failure_predicted") is True)
    mem = _num(system.get("mem_gb")) or (sum(_num(x.get("gb")) or 0 for x in dimms) or None)
    return {
        "power_w": _num((d.get("power") or {}).get("watts")),
        "inlet_c": max(inlet) if inlet else None,
        "cpu_c": max(cpu) if cpu else None,
        "exhaust_c": max(exhaust) if exhaust else _num(system.get("exhaust_c")),
        "fan_rpm": round(sum(rpms) / len(rpms)) if rpms else None,
        "mem_gb": mem,
        "cpus": len(cpus) or None,
        "cores": sum(c.get("cores") or 0 for c in cpus) or None,
        "drives": len(drives) or None, "drives_bad": bad(drives),
        "volumes": len(storage.get("volumes") or []) or None,
        "psus": len(psus) or None, "psus_bad": bad(psus),
    }


def record_metrics(server_id: int, name: str, summary: dict, now=None) -> None:
    for suffix, (label, kind, unit) in SERIES.items():
        metrics.record(series_key(server_id, suffix), summary.get(suffix), name=f"{name} · {label}", kind=kind, unit=unit, now=now)


def history(server_id: int, days: float = 1, max_points: int = 24) -> dict:
    """The last day of each recorded series, for the central server's charts."""
    out = {}
    for suffix in SERIES:
        pts = metrics.points(series_key(server_id, suffix), days=days, max_points=max_points)
        if pts:
            out[suffix] = [[a.isoformat(), round(v, 1)] for a, v in pts]
    return out


def public(d: Optional[dict]) -> Optional[dict]:
    """The copy for the central server: everything except MAC addresses."""
    if not d:
        return d
    out = dict(d)
    out["nics"] = [{k: v for k, v in n.items() if k != "mac"} for n in d.get("nics") or []]
    return out

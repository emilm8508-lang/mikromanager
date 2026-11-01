"""
Out-of-band server health monitoring over Redfish — the DMTF-standard REST
API present on iDRAC7+ (Dell, ~2013 onward). Used only when a DellServer
row has its own routable idrac_ip — see services/dell_local.py for the
WinRM-into-the-host fallback used when iDRAC only has an internal,
non-routable address.

Deliberately vendor-generic: every resource path is DISCOVERED at request
time via the standard Redfish collection endpoints (/redfish/v1/Systems,
/Chassis, /Managers), never hardcoded to Dell's own fixed member names
("System.Embedded.1", "iDRAC.Embedded.1") — those are Dell-specific IDs
that HP iLO and Lenovo XCC name differently, but the /redfish/v1/*
collections themselves and the {"Status": {"Health": ...}} shape used
throughout are the actual DMTF standard both of those also implement.
Planned next step (per the user): reuse this same module for HP iLO and
Lenovo XCC servers once Dell/iDRAC is working — the discovery-based
design here means that should mostly need a new BMC "kind" label and a
credential, not a rewrite of the health-collection logic itself.

Every call is a fresh aiohttp.ClientSession (async with — always closed,
same pattern as mikrotik_client.py's REST path) with basic auth and TLS
verification disabled: BMC web UIs almost universally ship a self-signed
cert that's rarely replaced.

Never verified against live hardware from this environment (no real
Dell/HP/Lenovo server reachable here) — every call is defensive: a
missing/differently-shaped resource is skipped, never raised, and the
caller always gets back whatever partial data it could read.
"""
import asyncio
import contextvars
import ssl
from typing import Optional

import aiohttp

REQUEST_TIMEOUT_SEC = 10

# Host header override for every _get() of one collect_health() run — set
# there, read in _get(), so the per-component helpers keep their
# signatures. See DellServer.redfish_host_header for why it exists.
_host_header: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("_host_header", default=None)


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _get(base_url: str, path: str, username: str, password: str) -> Optional[dict]:
    """GET one Redfish resource. None on any failure (auth, timeout, 404 —
    a resource genuinely not present on this BMC/firmware is a normal,
    expected outcome here, not an error worth surfacing per-call —
    collect_health() below reports the overall failure if EVERYTHING
    fails)."""
    url = f"{base_url.rstrip('/')}{path}"
    headers = {"Accept": "application/json"}
    if _host_header.get():
        headers["Host"] = _host_header.get()
    try:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SEC)
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, auth=aiohttp.BasicAuth(username, password),
                ssl=_ssl_context(), timeout=timeout,
                headers=headers,
            ) as resp:
                if resp.status != 200:
                    return None
                return await resp.json(content_type=None)
    except Exception:
        return None


# Canonical vendor keys this app knows how to act on (drives which
# default credential, if any, dell_monitor.check_server() safely tries) —
# maps several observed Redfish ServiceRoot "Oem" key spellings to one
# name each (HP has used both "Hp" and "Hpe" across firmware versions;
# Fujitsu's has been seen as both "Fujitsu" and "Ts_Fujitsu"). Confirmed
# by the user: their infrastructure includes Dell, HP, and Fujitsu
# servers. Lenovo included too since idrac_client's Redfish handling is
# already vendor-generic — costs nothing to recognize it even though the
# user hasn't confirmed having any.
_VENDOR_OEM_MAP = {
    "dell": "dell",
    "hp": "hp", "hpe": "hp",
    "fujitsu": "fujitsu", "ts_fujitsu": "fujitsu",
    "lenovo": "lenovo",
}


def normalize_vendor(oem_key: Optional[str]) -> Optional[str]:
    """Maps a raw Redfish ServiceRoot Oem key (e.g. "Hpe", "Ts_Fujitsu")
    to the canonical vendor string this app understands, or None if
    absent/unrecognized — see probe_redfish_root's docstring for why an
    unrecognized vendor is its own bucket, not silently dropped."""
    if not oem_key:
        return None
    return _VENDOR_OEM_MAP.get(oem_key.strip().lower())


async def probe_redfish_root(ip: str, port: int = 443) -> dict:
    """Used only by dell_monitor.discover_network_servers() to decide
    whether a host with an open port 443 is actually a Redfish-speaking
    BMC before registering it as a DellServer — NOT just "port 443 open",
    which is far too common a signal on its own (any HTTPS server,
    RouterOS's own WebFig included, would match that). The Redfish service
    root (/redfish/v1/) is a standard, typically UNAUTHENTICATED resource
    on every conformant implementation (Dell/HP/Lenovo/Fujitsu alike) and
    always carries a "RedfishVersion" key — that key's presence is the
    actual signal, not just a 200 status (some servers 200 an arbitrary
    page for any path).

    Also returns a best-effort vendor hint, read from the SAME
    unauthenticated response's "Oem" key (e.g. Dell's ServiceRoot nests
    Dell-specific extensions under Oem.Dell, HPE's under Oem.Hpe, Lenovo's
    under Oem.Lenovo) — the infrastructure this app monitors is confirmed
    to include non-Dell servers too (HP/Fujitsu/Lenovo), and this module
    only knows how to talk to Dell's iDRAC (Dell-specific default
    credential, Dell-specific local WinRM tools). Deliberately does NOT
    attempt an authenticated call to confirm the vendor — that would mean
    trying a credential (even just Dell's root/calvin default) against a
    BMC we don't yet know is Dell, risking tripping that OTHER vendor's
    account-lockout policy for nothing. Absent/unrecognized Oem data
    means "unknown", not "not Dell" — some Dell firmware versions may not
    expose this, so an unknown vendor still gets registered as before
    rather than silently dropped, to avoid a regression."""
    url = f"https://{ip}:{port}/redfish/v1/"
    try:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SEC)
        async with aiohttp.ClientSession() as session:
            async with session.get(url, ssl=_ssl_context(), timeout=timeout,
                                    headers={"Accept": "application/json"}) as resp:
                if resp.status != 200:
                    return {"is_redfish": False, "vendor_hint": None}
                data = await resp.json(content_type=None)
                if not isinstance(data, dict) or not data.get("RedfishVersion"):
                    return {"is_redfish": False, "vendor_hint": None}
                oem = data.get("Oem")
                vendor_hint = next(iter(oem.keys())) if isinstance(oem, dict) and oem else None
                return {"is_redfish": True, "vendor_hint": vendor_hint}
    except Exception:
        return {"is_redfish": False, "vendor_hint": None}


async def _first_member(base_url: str, collection_path: str, username: str, password: str) -> Optional[str]:
    """Standard Redfish pattern: a collection resource ({"Members": [{"@odata.id":
    "..."}]}) at a well-known path, whose first (and on nearly every real
    server, only) member is the thing we actually want — the server's own
    System/Chassis/Manager resource, whatever that vendor happens to name
    it. Returns the member's @odata.id path, or None if the collection is
    missing/empty (auth failure, or this BMC doesn't implement it)."""
    data = await _get(base_url, collection_path, username, password)
    if not data:
        return None
    members = data.get("Members") or []
    if not members or not isinstance(members[0], dict):
        return None
    return members[0].get("@odata.id")


def _health(status_obj) -> Optional[str]:
    """Redfish's ubiquitous {"Status": {"Health": "OK"|"Warning"|"Critical",
    "HealthRollup": "OK"|..., "State": "Enabled"|...}} shape. Prefers
    HealthRollup over Health when both are present — Health is this one
    resource's own state, HealthRollup is the aggregate across everything
    IT manages (sub-components a caller may not separately enumerate:
    network adapters, PCIe devices, batteries, etc.). Confirmed as the
    right read on a real server: a PowerEdge showed overall "Warning" with
    every one of this module's own tracked components (CPU/memory/power/
    fans/storage) reading "OK" — the discrepancy was exactly this field,
    previously not read at all, so the UI had no way to explain the
    mismatch."""
    if not isinstance(status_obj, dict):
        return None
    status = status_obj.get("Status")
    if not isinstance(status, dict):
        return None
    return status.get("HealthRollup") or status.get("Health")


def _worst(*healths: Optional[str]) -> Optional[str]:
    """Redfish health values, worst-first. None (unknown) never overrides
    a real reading — only used to roll up several component healths into
    one, never to replace a single missing one with "unknown is worse"."""
    order = {"Critical": 0, "Warning": 1, "OK": 2}
    known = [h for h in healths if h in order]
    if not known:
        return None
    return min(known, key=lambda h: order[h])


async def get_system_summary(base_url: str, username: str, password: str) -> dict:
    """Core identity + top-level health from the server's own /Systems
    member — service tag, model, BIOS version, power state, CPU/memory
    health. Also returns the discovered system_path/chassis path isn't
    needed here (System and Chassis are separate collections), just the
    system resource's own data."""
    system_path = await _first_member(base_url, "/redfish/v1/Systems", username, password)
    if not system_path:
        return {}
    data = await _get(base_url, system_path, username, password)
    if not data:
        return {}
    return {
        "service_tag": data.get("SerialNumber"),
        "model": data.get("Model"),
        "bios_version": data.get("BiosVersion"),
        "power_state": data.get("PowerState"),
        "overall_health": _health(data),
        "cpu_health": _health(data.get("ProcessorSummary")),
        "memory_health": _health(data.get("MemorySummary")),
        "storage_collection": (data.get("Storage") or {}).get("@odata.id"),
    }


async def get_thermal_health(base_url: str, username: str, password: str) -> Optional[str]:
    """Rolled-up worst health across all fans + temperature sensors from
    the discovered Chassis member's /Thermal sub-resource."""
    chassis_path = await _first_member(base_url, "/redfish/v1/Chassis", username, password)
    if not chassis_path:
        return None
    data = await _get(base_url, f"{chassis_path}/Thermal", username, password)
    if not data:
        return None
    healths = [_health(f) for f in (data.get("Fans") or []) if isinstance(f, dict)]
    healths += [_health(t) for t in (data.get("Temperatures") or []) if isinstance(t, dict)]
    return _worst(*healths)


async def get_power_health(base_url: str, username: str, password: str) -> Optional[str]:
    """Rolled-up worst health across power supplies from the discovered
    Chassis member's /Power sub-resource."""
    chassis_path = await _first_member(base_url, "/redfish/v1/Chassis", username, password)
    if not chassis_path:
        return None
    data = await _get(base_url, f"{chassis_path}/Power", username, password)
    if not data:
        return None
    healths = [_health(p) for p in (data.get("PowerSupplies") or []) if isinstance(p, dict)]
    return _worst(*healths)


async def get_storage_health(base_url: str, storage_collection_path: Optional[str],
                             username: str, password: str) -> Optional[str]:
    """Rolled-up worst health across every storage controller AND every
    physical drive under it — a degraded/predicted-failure disk is
    exactly the kind of thing this whole feature exists to catch, so this
    goes one level deeper than the other component checks. Takes the
    System resource's own Storage collection path (from
    get_system_summary) rather than re-discovering it, since Storage
    hangs off the System resource, not a top-level collection."""
    if not storage_collection_path:
        return None
    collection = await _get(base_url, storage_collection_path, username, password)
    if not collection:
        return None
    healths = []
    for m in collection.get("Members") or []:
        if not isinstance(m, dict):
            continue
        odata_id = m.get("@odata.id")
        if not odata_id:
            continue
        controller = await _get(base_url, odata_id, username, password)
        if not controller:
            continue
        healths.append(_health(controller))
        for d in controller.get("Drives") or []:
            if not isinstance(d, dict):
                continue
            drive_id = d.get("@odata.id")
            if not drive_id:
                continue
            drive = await _get(base_url, drive_id, username, password)
            if drive:
                healths.append(_health(drive))
    return _worst(*healths)


async def get_sel_entries(base_url: str, username: str, password: str, limit: int = 20) -> list:
    """Most recent hardware/system event log entries — Dell calls this the
    SEL, other vendors call it the "System Log"/"IML" (Lenovo), but all
    Redfish implementations expose it the same way: a LogServices entry
    under the discovered Manager resource, with a standard Entries
    collection. Returns newest-first, capped at `limit`."""
    manager_path = await _first_member(base_url, "/redfish/v1/Managers", username, password)
    if not manager_path:
        return []
    log_services = await _get(base_url, f"{manager_path}/LogServices", username, password)
    if not log_services:
        return []
    log_members = log_services.get("Members") or []
    if not log_members or not isinstance(log_members[0], dict):
        return []
    log_path = log_members[0].get("@odata.id")
    if not log_path:
        return []
    data = await _get(base_url, f"{log_path}/Entries", username, password)
    if not data:
        return []
    members = data.get("Members") or []
    out = []
    for m in members:
        if not isinstance(m, dict):
            continue
        out.append({
            "severity": m.get("Severity"),
            "message": m.get("Message") or m.get("MessageId") or "",
            "logged_at": m.get("Created"),
        })
    # Redfish doesn't guarantee ordering — sort newest-first by Created
    # when present, defensively falling back to insertion order otherwise.
    out.sort(key=lambda e: e["logged_at"] or "", reverse=True)
    return out[:limit]


# ── Detailed readings (the per-server detail view) ──────────────────────────

def _h(obj) -> Optional[str]:
    """One element's own health (not the rollup), None for an absent slot."""
    st = obj.get("Status") if isinstance(obj, dict) else None
    if not isinstance(st, dict) or st.get("State") == "Absent":
        return None
    return st.get("Health") or st.get("HealthRollup")


def _absent(obj) -> bool:
    st = obj.get("Status") if isinstance(obj, dict) else None
    return isinstance(st, dict) and st.get("State") in ("Absent", "Disabled") and not st.get("Health")


def _gb(n, div) -> Optional[float]:
    try:
        return round(float(n) / div, 1) if n is not None else None
    except (TypeError, ValueError):
        return None


async def _members(base_url: str, path: Optional[str], username: str, password: str, cap: int = 64) -> list:
    """Every member of a collection, expanded. iDRAC9 answers $expand in one
    request; older firmware (or another vendor) that refuses it gets the
    members fetched one by one, a few at a time."""
    if not path:
        return []
    data = await _get(base_url, f"{path}?$expand=*($levels=1)", username, password)
    members = (data or {}).get("Members") or []
    if members and all(isinstance(m, dict) and len(m) > 1 for m in members):
        return members[:cap]
    if not data:
        data = await _get(base_url, path, username, password)
    ids = [m.get("@odata.id") for m in ((data or {}).get("Members") or []) if isinstance(m, dict) and m.get("@odata.id")][:cap]
    sem = asyncio.Semaphore(6)

    async def one(p):
        async with sem:
            return await _get(base_url, p, username, password)
    got = await asyncio.gather(*(one(p) for p in ids))
    return [g for g in got if g]


async def collect_details(base_url: str, username: str, password: str) -> dict:
    """Everything the detail view shows: CPUs, DIMMs, controllers / drives /
    volumes, every temperature and fan reading, power draw and the power
    supplies, NICs, intrusion. Field names are the DMTF ones iDRAC9 uses;
    each part is best-effort and simply missing when the BMC lacks it."""
    out: dict = {"source": "redfish"}
    system_path = await _first_member(base_url, "/redfish/v1/Systems", username, password)
    chassis_path = await _first_member(base_url, "/redfish/v1/Chassis", username, password)
    manager_path = await _first_member(base_url, "/redfish/v1/Managers", username, password)
    sys_ = await _get(base_url, system_path, username, password) if system_path else None
    sys_ = sys_ or {}
    dell = ((sys_.get("Oem") or {}).get("Dell") or {}).get("DellSystem") or {}
    manager = await _get(base_url, manager_path, username, password) if manager_path else None

    out["system"] = {
        "model": sys_.get("Model"), "service_tag": sys_.get("SKU") or sys_.get("SerialNumber"),
        "bios": sys_.get("BiosVersion"), "hostname": sys_.get("HostName"),
        "power_state": sys_.get("PowerState"), "idrac_fw": (manager or {}).get("FirmwareVersion"),
        "generation": dell.get("SystemGeneration"),
        "exhaust_c": dell.get("EstimatedExhaustTemperatureCelsius"),
        "airflow_cfm": dell.get("EstimatedSystemAirflowCFM"),
        "dimm_slots": dell.get("MaxDIMMSlots"), "dimm_populated": dell.get("PopulatedDIMMSlots"),
        "mem_gb": (sys_.get("MemorySummary") or {}).get("TotalSystemMemoryGiB"),
        "health": _health(sys_),
    }

    cpus = await _members(base_url, (sys_.get("Processors") or {}).get("@odata.id"), username, password)
    out["cpus"] = [{
        "name": c.get("Name") or c.get("Id"), "model": c.get("Model"),
        "cores": c.get("TotalCores"), "threads": c.get("TotalThreads"),
        "mhz": c.get("OperatingSpeedMHz") or c.get("MaxSpeedMHz"), "max_mhz": c.get("MaxSpeedMHz"),
        "health": _h(c),
    } for c in cpus if not _absent(c) and (c.get("ProcessorType") in (None, "CPU"))]

    dimms = await _members(base_url, (sys_.get("Memory") or {}).get("@odata.id"), username, password)
    out["dimms"] = [{
        "slot": d.get("DeviceLocator") or d.get("Name") or d.get("Id"),
        "gb": _gb(d.get("CapacityMiB"), 1024), "type": d.get("MemoryDeviceType"),
        "mhz": d.get("OperatingSpeedMhz"), "vendor": d.get("Manufacturer"),
        "part": (d.get("PartNumber") or "").strip() or None, "ranks": d.get("RankCount"),
        "health": _h(d),
    } for d in dimms if not _absent(d) and d.get("CapacityMiB")]

    controllers, drives, volumes = [], [], []
    for ctl in await _members(base_url, (sys_.get("Storage") or {}).get("@odata.id"), username, password, cap=16):
        sc = (ctl.get("StorageControllers") or [{}])[0] if isinstance(ctl.get("StorageControllers"), list) else {}
        drive_refs = [d.get("@odata.id") for d in (ctl.get("Drives") or []) if isinstance(d, dict)]
        if not drive_refs and not ctl.get("Volumes"):
            continue                                  # an empty embedded AHCI port — nothing to show
        controllers.append({
            "name": sc.get("Name") or ctl.get("Name") or ctl.get("Id"), "firmware": sc.get("FirmwareVersion"),
            "cache_mb": (sc.get("CacheSummary") or {}).get("TotalCacheSizeMiB"), "health": _h(ctl),
        })
        got = await asyncio.gather(*(_get(base_url, p, username, password) for p in drive_refs if p))
        for d in got:
            if not d:
                continue
            drives.append({
                "name": d.get("Name") or d.get("Id"), "model": d.get("Model"), "media": d.get("MediaType"),
                "protocol": d.get("Protocol"), "gb": _gb(d.get("CapacityBytes"), 1e9),
                "failure_predicted": d.get("FailurePredicted"), "life_left_pct": d.get("PredictedMediaLifeLeftPercent"),
                "firmware": d.get("Revision"), "serial": d.get("SerialNumber"), "health": _h(d),
            })
        for v in await _members(base_url, (ctl.get("Volumes") or {}).get("@odata.id"), username, password, cap=32):
            volumes.append({
                "name": v.get("Name") or v.get("Id"), "raid": v.get("RAIDType") or v.get("VolumeType"),
                "gb": _gb(v.get("CapacityBytes"), 1e9), "health": _h(v),
            })
    out["storage"] = {"controllers": controllers, "drives": drives, "volumes": volumes}

    if chassis_path:
        thermal, power, chassis = await asyncio.gather(
            _get(base_url, f"{chassis_path}/Thermal", username, password),
            _get(base_url, f"{chassis_path}/Power", username, password),
            _get(base_url, chassis_path, username, password),
        )
        thermal, power, chassis = thermal or {}, power or {}, chassis or {}
        out["temps"] = [{
            "name": t.get("Name"), "c": t.get("ReadingCelsius"),
            "warn": t.get("UpperThresholdNonCritical"), "crit": t.get("UpperThresholdCritical"), "health": _h(t),
        } for t in thermal.get("Temperatures") or [] if isinstance(t, dict) and t.get("ReadingCelsius") is not None]
        out["fans"] = [{
            "name": f.get("Name") or f.get("FanName"), "rpm": f.get("Reading") if (f.get("ReadingUnits") or "RPM") == "RPM" else None,
            "pwm": f.get("Reading") if f.get("ReadingUnits") == "Percent" else None, "health": _h(f),
        } for f in thermal.get("Fans") or [] if isinstance(f, dict) and not _absent(f)]
        out["fan_redundancy"] = _worst(*(_h(r) for r in thermal.get("Redundancy") or [] if isinstance(r, dict)))
        pc = (power.get("PowerControl") or [{}])[0] if isinstance(power.get("PowerControl"), list) and power.get("PowerControl") else {}
        pm = pc.get("PowerMetrics") or {}
        out["power"] = {
            "watts": pc.get("PowerConsumedWatts"), "capacity_w": pc.get("PowerCapacityWatts"),
            "min_w": pm.get("MinConsumedWatts"), "avg_w": pm.get("AverageConsumedWatts"), "max_w": pm.get("MaxConsumedWatts"),
            "redundancy": _worst(*(_h(r) for r in power.get("Redundancy") or [] if isinstance(r, dict))),
            "psus": [{
                "name": p.get("Name") or p.get("MemberId"), "model": p.get("Model"),
                "capacity_w": p.get("PowerCapacityWatts"), "output_w": p.get("LastPowerOutputWatts"),
                "input_v": p.get("LineInputVoltage"), "firmware": p.get("FirmwareVersion"), "health": _h(p),
            } for p in power.get("PowerSupplies") or [] if isinstance(p, dict) and not _absent(p)],
        }
        out["intrusion"] = (chassis.get("PhysicalSecurity") or {}).get("IntrusionSensor")

    if system_path:
        nics = await _members(base_url, f"{system_path}/EthernetInterfaces", username, password, cap=32)
        out["nics"] = [{
            "name": n.get("Id") or n.get("Name"), "mac": n.get("MACAddress") or n.get("PermanentMACAddress"),
            "speed_mbps": n.get("SpeedMbps"), "link": n.get("LinkStatus"), "health": _h(n),
        } for n in nics]
    return out


async def collect_health(base_url: str, username: str, password: str,
                         host_header: Optional[str] = None) -> dict:
    """One health snapshot combining every component check above. Never
    raises — a total connection failure (wrong credential, BMC
    unreachable, TLS handshake failure) surfaces as {"ok": False, "error":
    ...}; a partial failure (e.g. a resource missing on a given
    vendor/firmware) just leaves that one component's health as None
    rather than failing the whole check."""
    _host_header.set(host_header or None)
    try:
        summary = await asyncio.wait_for(get_system_summary(base_url, username, password), timeout=15)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    if not summary:
        return {"ok": False, "error": "could not reach Redfish /redfish/v1/Systems "
                                       "(wrong credential, BMC unreachable, or not Redfish-capable)"}

    try:
        thermal = await asyncio.wait_for(get_thermal_health(base_url, username, password), timeout=15)
    except Exception:
        thermal = None
    try:
        power = await asyncio.wait_for(get_power_health(base_url, username, password), timeout=15)
    except Exception:
        power = None
    try:
        storage = await asyncio.wait_for(
            get_storage_health(base_url, summary.get("storage_collection"), username, password), timeout=20)
    except Exception:
        storage = None
    try:
        sel = await asyncio.wait_for(get_sel_entries(base_url, username, password), timeout=15)
    except Exception:
        sel = []
    try:
        details = await asyncio.wait_for(collect_details(base_url, username, password), timeout=60)
    except Exception as e:
        details = {"source": "redfish", "error": f"{type(e).__name__}: {e}"[:300]}

    components = {
        # "system" makes the System resource's own aggregate visible on its
        # own — confirmed necessary on a real server: health_rollup showed
        # "Warning" while every OTHER tracked component read "OK", with no
        # way to tell why. HealthRollup (see _health()) aggregates things
        # this module doesn't separately enumerate (network adapters,
        # PCIe, batteries, etc.), so a mismatch here is the visible clue
        # that something outside the other 5 components needs attention —
        # check iDRAC's own web UI for specifics in that case.
        "system": summary.get("overall_health"),
        "cpu": summary.get("cpu_health"),
        "memory": summary.get("memory_health"),
        "power": power,
        "fans_temperature": thermal,
        "storage": storage,
    }
    rollup = _worst(*components.values())

    return {
        "ok": True,
        "service_tag": summary.get("service_tag"),
        "model": summary.get("model"),
        "bios_version": summary.get("bios_version"),
        "power_state": summary.get("power_state"),
        "health_rollup": rollup,
        "components": components,
        "sel_entries": sel,
        "details": details,
    }

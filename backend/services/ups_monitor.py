"""
UPS units and SNMP sensors: the power and the environment of the server room.

The commonest outage in a small server room is not a server - it is the power: the mains fail, the UPS runs the equipment on its battery for twenty minutes, and
nobody knows until the servers go down. A UPS with a network card answers SNMP, the agent asks it every couple of minutes (read-only) and raises:

  * "UPS is running on battery" (high) as soon as the output comes from the battery, closed when the mains are back;
  * "UPS battery low" (critical) when the battery reports low / depleted, or the charge or the runtime left drops under a limit while it is on battery;
  * alarms present, battery temperature too high, overload (medium); and "UPS not answering" (medium) after three failed reads.

The standard UPS-MIB (RFC 1628) is read first; APC units with only their own PowerNet-MIB are read through the few equivalent OIDs of it. Every reading - charge, minutes
of runtime left, load, temperature, battery voltage - is also recorded as a series (services/metrics.py), so it has a chart, can have thresholds of its own ("charge below
40%") and is visible in Central's numbers. Alongside the UPS: any other SNMP value you name (an OID, a scale, a unit - a temperature probe, a humidity sensor, a PDU
current) is read the same way and recorded as a series.

The community is the one entered for the unit, else the communities the agent already knows for that address (the asset's credential, the saved ones, "public").
"""
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, UpsTarget, SnmpSensor, Asset
from services.crypto import encrypt, decrypt

INTERVAL_SEC = 120
FAILS_BEFORE_ALERT = 3
CHARGE_LOW = 30           # % while on battery
RUNTIME_LOW = 10          # minutes left while on battery
TEMP_HIGH = 40            # battery temperature, deg C
LOAD_HIGH = 85            # output load, %

_UPS = "1.3.6.1.2.1.33.1"
OIDS = {
    "manufacturer": f"{_UPS}.1.1.0", "model": f"{_UPS}.1.2.0",
    "battery_status": f"{_UPS}.2.1.0", "seconds_on_battery": f"{_UPS}.2.2.0", "minutes_remaining": f"{_UPS}.2.3.0", "charge": f"{_UPS}.2.4.0",
    "voltage": f"{_UPS}.2.5.0", "temperature": f"{_UPS}.2.7.0", "output_source": f"{_UPS}.4.1.0", "load": f"{_UPS}.4.4.1.5.1", "alarms": f"{_UPS}.6.1.0",
}
APC = {                                      # PowerNet-MIB, for units that do not answer UPS-MIB
    "model": "1.3.6.1.4.1.318.1.1.1.1.1.1.0", "battery_status": "1.3.6.1.4.1.318.1.1.1.2.1.1.0", "charge": "1.3.6.1.4.1.318.1.1.1.2.2.1.0",
    "temperature": "1.3.6.1.4.1.318.1.1.1.2.2.2.0", "runtime_ticks": "1.3.6.1.4.1.318.1.1.1.2.2.3.0", "output_status": "1.3.6.1.4.1.318.1.1.1.4.1.1.0", "load": "1.3.6.1.4.1.318.1.1.1.4.2.3.0",
}
_fails: Dict[int, int] = {}
_task: Optional[asyncio.Task] = None
_snmp_get = None                             # tests put a fake here: async (ip, community, port, oids) -> {oid: value}


# ── SNMP ─────────────────────────────────────────────────────────────────────

def _num(v) -> Optional[float]:
    try:
        if isinstance(v, (bytes, bytearray)):
            v = v.decode("ascii", errors="ignore").strip()
        return float(v)
    except (TypeError, ValueError):
        return None


def _text(v) -> Optional[str]:
    if v is None:
        return None
    s = v.decode("utf-8", errors="ignore") if isinstance(v, (bytes, bytearray)) else str(v)
    s = s.replace("\x00", "").strip()
    return s or None


def candidates(ip: str, stored: Optional[str]) -> List[str]:
    """The communities to try for an address: the one entered, else those the agent already knows for it, then "public"."""
    out: List[str] = []
    if stored:
        try:
            out.append(decrypt(stored))
        except Exception:
            pass
    if not out:
        try:
            from services import asset_scan
            with SessionLocal() as db:
                a = db.execute(select(Asset).where(Asset.ip == ip).limit(1)).scalars().first()
            out = list(asset_scan._communities(a)) if a is not None else ["public"]
        except Exception:
            out = ["public"]
    return list(dict.fromkeys(out))[:4]


async def _get_many(ip: str, community: str, port: int, oids: List[str]) -> Dict[str, object]:
    if _snmp_get is not None:
        return await _snmp_get(ip, community, port, oids)
    from services.snmp_client import SnmpClient
    cl = SnmpClient(ip, community, port=port, timeout=2.5)
    out: Dict[str, object] = {}
    for oid in oids:
        try:
            out[oid] = await cl._get(oid)
        except Exception:
            out[oid] = None
    return out


async def _read_with(ip: str, port: int, stored: Optional[str], oids: List[str]) -> Optional[Dict[str, object]]:
    """The values of the OIDs from the first community that gets any answer; None when the device does not answer at all."""
    for c in candidates(ip, stored):
        vals = await _get_many(ip, c, port, oids)
        if any(v is not None for v in vals.values()):
            return vals
    return None


# ── UPS ──────────────────────────────────────────────────────────────────────

def interpret(ups_mib: Dict[str, Optional[object]], apc: Optional[Dict[str, Optional[object]]] = None) -> dict:
    """The readings of a UPS as one state: {source: online | battery | bypass | off | unknown, battery: ok | low | depleted | unknown, charge, minutes, load, temp, voltage, alarms,
    on_battery_s, model}."""
    g = lambda k: ups_mib.get(OIDS[k])
    src_code = _num(g("output_source"))
    bat_code = _num(g("battery_status"))
    secs = _num(g("seconds_on_battery"))
    st = {"model": _text(g("model")), "manufacturer": _text(g("manufacturer")), "charge": _num(g("charge")), "minutes": _num(g("minutes_remaining")), "load": _num(g("load")),
          "temp": _num(g("temperature")), "voltage": (_num(g("voltage")) / 10.0) if _num(g("voltage")) is not None else None, "alarms": int(_num(g("alarms")) or 0),
          "on_battery_s": int(secs) if secs else 0}
    st["source"] = {1: "unknown", 2: "off", 3: "online", 4: "bypass", 5: "battery", 6: "online", 7: "online"}.get(int(src_code), "unknown") if src_code is not None else "unknown"
    st["battery"] = {2: "ok", 3: "low", 4: "depleted"}.get(int(bat_code), "unknown") if bat_code is not None else "unknown"
    if st["source"] == "unknown" and apc:
        out = _num(apc.get(APC["output_status"]))
        st["source"] = {2: "online", 3: "battery", 4: "online", 5: "bypass", 6: "bypass", 7: "bypass", 8: "off", 9: "bypass"}.get(int(out), "unknown") if out is not None else "unknown"
        b = _num(apc.get(APC["battery_status"]))
        st["battery"] = {2: "ok", 3: "low"}.get(int(b), "unknown") if b is not None else st["battery"]
        ticks = _num(apc.get(APC["runtime_ticks"]))
        st.update(model=st["model"] or _text(apc.get(APC["model"])), charge=_num(apc.get(APC["charge"])), temp=_num(apc.get(APC["temperature"])), load=_num(apc.get(APC["load"])),
                  minutes=round(ticks / 6000.0, 1) if ticks is not None else None)
    return st


async def read_ups(ip: str, port: int, stored: Optional[str]) -> Optional[dict]:
    """One reading of a UPS (UPS-MIB, else APC's own), or None when it does not answer."""
    vals = await _read_with(ip, port, stored, list(OIDS.values()))
    if vals is None:
        return None
    apc = None
    if _num(vals.get(OIDS["output_source"])) is None:
        apc = await _read_with(ip, port, stored, list(APC.values()))
        if apc is None and all(v is None for k, v in vals.items() if k != OIDS["model"]):
            return None
    return interpret(vals, apc)


def _alerts(name: str, ip: str, st: dict, now: datetime) -> None:
    from services import soc
    kw = dict(device=name, ip=ip, source="rules", now=now)

    def raise_(rule, title, sev, msg, key=""):
        soc.raise_alert(rule=f"ups.{rule}", title=title, severity=sev, category="hardware", fp_detail=key, detail={"message": msg}, **kw)

    def clear(rule, key=""):
        soc.resolve(rule=f"ups.{rule}", device=name, fp_detail=key)

    bits = ", ".join(x for x in (f"charge {st['charge']:.0f}%" if st.get("charge") is not None else None, f"{st['minutes']:.0f} min left" if st.get("minutes") is not None else None,
                                 f"load {st['load']:.0f}%" if st.get("load") is not None else None) if x)
    on_batt = st["source"] == "battery"
    if on_batt:
        raise_("on_battery", "UPS is running on battery", "high", f"{name}: the mains failed; " + (bits or "on battery"))
    else:
        clear("on_battery")
    low = st["battery"] in ("low", "depleted") or (on_batt and ((st.get("charge") is not None and st["charge"] < CHARGE_LOW) or (st.get("minutes") is not None and st["minutes"] < RUNTIME_LOW)))
    if low:
        raise_("battery_low", "UPS battery low", "critical", f"{name}: battery {st['battery']}; " + (bits or ""))
    else:
        clear("battery_low")
    if st.get("alarms"):
        raise_("alarm", "UPS reports alarms", "medium", f"{name}: {st['alarms']} alarm(s) present")
    else:
        clear("alarm")
    if st.get("temp") is not None and st["temp"] > TEMP_HIGH:
        raise_("temperature", "UPS battery temperature high", "medium", f"{name}: {st['temp']:.0f} °C")
    else:
        clear("temperature")
    if st.get("load") is not None and st["load"] > LOAD_HIGH:
        raise_("overload", "UPS load high", "medium", f"{name}: output load {st['load']:.0f}%")
    else:
        clear("overload")


def _record_metrics(target_id: int, name: str, st: dict, now: datetime) -> None:
    from services import metrics
    for suffix, kind, label, unit, val in (("charge", "ups_charge", "charge", "%", st.get("charge")), ("load", "ups_load", "load", "%", st.get("load")),
                                           ("runtime", "ups_runtime", "runtime left", "min", st.get("minutes")), ("temp", "ups_temp", "temperature", "°C", st.get("temp")),
                                           ("voltage", "other", "battery voltage", "V", st.get("voltage"))):
        metrics.record(f"ups:{target_id}:{suffix}", val, name=f"{name} · {label}", kind=kind, unit=unit, now=now)


async def check_ups(target_id: int, now: Optional[datetime] = None) -> dict:
    now = now or datetime.utcnow()
    with SessionLocal() as db:
        t = db.get(UpsTarget, target_id)
        if t is None:
            return {"error": "not found"}
        ip, port, stored, name = t.ip, t.port or 161, t.community_enc, t.name
    st = await read_ups(ip, port, stored)
    with SessionLocal() as db:
        t = db.get(UpsTarget, target_id)
        if t is None:
            return {"error": "not found"}
        t.last_check = now
        if st is None:
            _fails[target_id] = _fails.get(target_id, 0) + 1
            t.last_error = "no answer to SNMP"
            fails = _fails[target_id]
        else:
            _fails[target_id] = 0
            t.last_error = None
            t.state = json.dumps(st)
            t.last_ok = now
            fails = 0
        db.commit()
    if st:
        _record_metrics(target_id, name, st, now)
    from services import soc
    if st is None:
        if fails >= FAILS_BEFORE_ALERT:
            soc.raise_alert(rule="ups.unreachable", device=name, title="UPS not answering", severity="medium", category="hardware", ip=ip, detail={"message": f"{name} does not answer SNMP"}, source="rules", now=now)
        return {"error": "no answer"}
    soc.resolve(rule="ups.unreachable", device=name)
    _alerts(name, ip, st, now)
    return {"ok": True, "state": st}


# ── Other SNMP sensors ───────────────────────────────────────────────────────

async def check_sensor(sensor_id: int, now: Optional[datetime] = None) -> dict:
    from services import metrics
    now = now or datetime.utcnow()
    with SessionLocal() as db:
        s = db.get(SnmpSensor, sensor_id)
        if s is None:
            return {"error": "not found"}
        ip, port, stored, oid, scale, name, unit, kind = s.ip, s.port or 161, s.community_enc, s.oid, s.scale or 1.0, s.name, s.unit or "", s.kind or "other"
    vals = await _read_with(ip, port, stored, [oid])
    v = _num(vals.get(oid)) if vals else None
    with SessionLocal() as db:
        s = db.get(SnmpSensor, sensor_id)
        if s is None:
            return {"error": "not found"}
        s.last_check = now
        s.last_error = None if v is not None else ("no answer to SNMP" if vals is None else "the OID returned no number")
        if v is not None:
            s.last_value, s.last_ok = v * scale, now
        db.commit()
    if v is None:
        return {"error": "no value"}
    metrics.record(f"snmp:{sensor_id}", v * scale, name=f"{name} · {unit or 'value'}" if " · " not in name else name, kind=kind, unit=unit or "", now=now)
    return {"ok": True, "value": v * scale}


# ── The loop ─────────────────────────────────────────────────────────────────

async def run_cycle() -> dict:
    with SessionLocal() as db:
        ups = [u.id for u in db.execute(select(UpsTarget).where(UpsTarget.enabled.is_(True))).scalars().all()]
        sens = [s.id for s in db.execute(select(SnmpSensor).where(SnmpSensor.enabled.is_(True))).scalars().all()]
    sem = asyncio.Semaphore(4)
    out = {"ups": len(ups), "sensors": len(sens), "errors": 0}

    async def one(fn, i):
        async with sem:
            try:
                r = await fn(i)
                out["errors"] += "error" in r
            except Exception as e:
                out["errors"] += 1
                print(f"[ups_monitor] {fn.__name__} {i}: {type(e).__name__}: {e}")
    await asyncio.gather(*[one(check_ups, i) for i in ups], *[one(check_sensor, i) for i in sens])
    return out


async def _loop():
    await asyncio.sleep(75)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            print(f"[ups_monitor] cycle error: {type(e).__name__}: {e}")
        await asyncio.sleep(INTERVAL_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None


# ── Managing and reading ─────────────────────────────────────────────────────

def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _clean_target(body: dict) -> dict:
    name = str(body.get("name") or "").strip()
    ip = str(body.get("ip") or "").strip()
    if not name or len(name) > 80:
        raise ValueError("name required (80 characters at most)")
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("a valid IP address is required")
    port = int(161 if body.get("port") is None else body["port"])
    if not (1 <= port <= 65535):
        raise ValueError("bad port")
    return {"name": name, "ip": ip, "port": port, "enabled": bool(body.get("enabled", True))}


def save_ups(uid: Optional[int], body: dict) -> int:
    f = _clean_target(body)
    comm = body.get("community")
    with SessionLocal() as db:
        t = db.get(UpsTarget, uid) if uid else None
        if uid and t is None:
            raise LookupError("not found")
        if t is None:
            t = UpsTarget(**f)
            db.add(t)
        else:
            for k, v in f.items():
                setattr(t, k, v)
        if comm is not None:
            t.community_enc = encrypt(str(comm)) if str(comm).strip() else None
        db.commit()
        return t.id


def delete_ups(uid: int) -> bool:
    with SessionLocal() as db:
        t = db.get(UpsTarget, uid)
        if t is None:
            return False
        name = t.name
        db.delete(t)
        db.commit()
    try:
        from services import soc
        for rule in ("on_battery", "battery_low", "alarm", "temperature", "overload", "unreachable"):
            soc.resolve(rule=f"ups.{rule}", device=name)
    except Exception:
        pass
    return True


def save_sensor(sid: Optional[int], body: dict) -> int:
    f = _clean_target(body)
    oid = str(body.get("oid") or "").strip().lstrip(".")
    if not oid or not all(p.isdigit() for p in oid.split(".")) or len(oid.split(".")) < 3:
        raise ValueError("the OID is dotted numbers, e.g. 1.3.6.1.4.1.318.1.1.10.2.3.2.1.4.1")
    try:
        scale = float(body.get("scale") or 1.0)
    except (TypeError, ValueError):
        raise ValueError("scale is a number (0.1 turns tenths into units)")
    kind = str(body.get("kind") or "other")
    if kind not in ("temp", "other", "cpu", "mem", "disk"):
        raise ValueError("unknown kind")
    comm = body.get("community")
    with SessionLocal() as db:
        s = db.get(SnmpSensor, sid) if sid else None
        if sid and s is None:
            raise LookupError("not found")
        if s is None:
            s = SnmpSensor(**f, oid=oid, scale=scale, unit=str(body.get("unit") or "")[:12], kind=kind)
            db.add(s)
        else:
            for k, v in f.items():
                setattr(s, k, v)
            s.oid, s.scale, s.unit, s.kind = oid, scale, str(body.get("unit") or "")[:12], kind
        if comm is not None:
            s.community_enc = encrypt(str(comm)) if str(comm).strip() else None
        db.commit()
        return s.id


def delete_sensor(sid: int) -> bool:
    with SessionLocal() as db:
        s = db.get(SnmpSensor, sid)
        if s is None:
            return False
        db.delete(s)
        db.commit()
        return True


def overview() -> dict:
    with SessionLocal() as db:
        ups = []
        for t in db.execute(select(UpsTarget).order_by(UpsTarget.name)).scalars().all():
            try:
                st = json.loads(t.state) if t.state else None
            except Exception:
                st = None
            ups.append({"id": t.id, "name": t.name, "ip": t.ip, "port": t.port, "enabled": bool(t.enabled), "has_community": bool(t.community_enc), "state": st,
                        "last_check": _iso(t.last_check), "last_ok": _iso(t.last_ok), "error": t.last_error})
        sensors = [{"id": s.id, "name": s.name, "ip": s.ip, "port": s.port, "oid": s.oid, "scale": s.scale, "unit": s.unit, "kind": s.kind, "enabled": bool(s.enabled),
                    "has_community": bool(s.community_enc), "value": s.last_value, "last_check": _iso(s.last_check), "error": s.last_error} for s in db.execute(select(SnmpSensor).order_by(SnmpSensor.name)).scalars().all()]
        known = {u["ip"] for u in ups}
        import re
        sug = [{"id": a.id, "name": a.name or a.ip, "ip": a.ip, "model": a.model, "manufacturer": a.manufacturer} for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all()
               if a.ip not in known and re.search(r"\bups\b|smart-?ups|apc\b|eaton|powerware|riello|socomec|ippon|mge\b|apc ", f"{a.name} {a.model} {a.manufacturer}", re.I)]
    return {"ups": ups, "sensors": sensors, "suggestions": sug[:20]}


async def test_reading(ip: str, port: int = 161, community: Optional[str] = None) -> dict:
    """One reading of an address as a UPS, without saving anything (the "test" of the form)."""
    stored = encrypt(community) if community else None
    st = await read_ups(ip, port or 161, stored)
    return {"ok": st is not None, "state": st}

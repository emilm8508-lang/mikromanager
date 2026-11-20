"""
Software licenses and their compliance (docs/plan-itam.md, stage C): what was bought against what is installed.

A license is entered by a person: the product, the vendor, which installed programs it covers (parts of the names in the software inventory -
"Microsoft Office Professional Plus 2021", "Office 2021"; and parts to leave out), the kind (per device, per user, per server, per core, site,
subscription), the number of seats, the dates, the cost and supplier, and the key. The key is encrypted (services/crypto.py) and shown only to an
admin, and the reading is recorded in the audit log; it never goes to Central.

Compliance, from the software the scans found on the hosts (VulnPackage, one row per host and program):
  installs     the assets with a matching program
  in use       of those, the ones alive and in use (not decommissioned / probably removed / ignored, seen in the last RECLAIM_DAYS)
  reclaimable  installed on assets that are gone or retired - the seat can be freed (uninstall, or the asset is really gone)
  over         in use above the seats: not compliant
  unused       seats above what is in use: bought and not used
  status       compliant | over | unused | expired | expiring | no_installs | site (a site license has no seat count)
A per-user license is counted by devices too (the agent does not know who uses a program) - shown as such.

Alerts: license.over (medium) when in use exceeds the seats; license.expiring (low) within EXPIRY_WARN_DAYS of the end. Checked every hour.
"""
import re
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, SoftwareLicense, VulnHost, VulnPackage

KINDS = ("per_device", "per_user", "per_server", "per_core", "site", "subscription")
RECLAIM_DAYS = 30
EXPIRY_WARN_DAYS = 30
MAX_PATTERNS = 10


def _now() -> datetime:
    return datetime.utcnow()


def _patterns(v) -> List[str]:
    if isinstance(v, str):
        v = re.split(r"[;\n]", v)
    return [" ".join(str(x).split()).lower() for x in (v or []) if str(x).strip()][:MAX_PATTERNS]


def _d(v) -> Optional[datetime]:
    if v in (None, ""):
        return None
    try:
        d = date.fromisoformat(str(v).strip()[:10])
    except ValueError:
        raise ValueError(f"not a date (YYYY-MM-DD): {v!r}")
    return datetime(d.year, d.month, d.day)


def clean(body: Dict) -> Dict:
    """A license from a form, validated. Raises ValueError with what is wrong."""
    product = " ".join(str(body.get("product") or "").split())[:120]
    if not product:
        raise ValueError("a license needs a product name")
    kind = str(body.get("kind") or "per_device")
    if kind not in KINDS:
        raise ValueError(f"kind: one of {', '.join(KINDS)}")
    match = _patterns(body.get("match"))
    if not match:
        raise ValueError("a license needs at least one part of a program name to match")
    seats = body.get("seats")
    if kind == "site":
        seats = None
    elif seats in (None, ""):
        raise ValueError("the number of seats is needed (or the kind \"site\")")
    else:
        try:
            seats = int(seats)
        except (TypeError, ValueError):
            raise ValueError("seats: a whole number")
        if seats < 0 or seats > 1_000_000:
            raise ValueError("seats: 0 or more")
    cost = body.get("cost")
    if cost not in (None, ""):
        try:
            cost = round(float(str(cost).replace(",", ".").replace(" ", "")), 2)
        except ValueError:
            raise ValueError("cost: a number")
    else:
        cost = None
    cur = str(body.get("currency") or "").strip().upper() or None
    if cur and not re.fullmatch(r"[A-Z]{3}", cur):
        raise ValueError("currency: a 3-letter code")
    vf, vu = _d(body.get("valid_from")), _d(body.get("valid_until"))
    if vf and vu and vu < vf:
        raise ValueError("the license cannot end before it starts")
    return {"product": product, "vendor": (" ".join(str(body.get("vendor") or "").split())[:80] or None), "kind": kind, "seats": seats,
            "match": match, "exclude": _patterns(body.get("exclude")), "valid_from": vf, "valid_until": vu, "cost": cost, "currency": cur,
            "supplier": (" ".join(str(body.get("supplier") or "").split())[:120] or None),
            "reference": (" ".join(str(body.get("reference") or "").split())[:80] or None), "notes": (str(body.get("notes") or "").strip()[:1000] or None)}


def _apply(row: SoftwareLicense, v: Dict) -> None:
    import json
    for k in ("product", "vendor", "kind", "seats", "valid_from", "valid_until", "cost", "currency", "supplier", "reference", "notes"):
        setattr(row, k, v[k])
    row.match = json.dumps(v["match"], ensure_ascii=False)
    row.exclude = json.dumps(v["exclude"], ensure_ascii=False)


def save(body: Dict, lic_id: Optional[int] = None, who: str = "operator") -> int:
    from services import crypto
    v = clean(body)
    with SessionLocal() as db:
        row = db.get(SoftwareLicense, lic_id) if lic_id else SoftwareLicense(created_at=_now(), created_by=(who or "")[:64])
        if lic_id and not row:
            raise ValueError("license not found")
        _apply(row, v)
        if "key" in body:                                    # "" clears it; absent keeps it
            k = str(body.get("key") or "").strip()
            row.key_enc = crypto.encrypt(k[:500]) if k else None
        row.updated_at = _now()
        if not lic_id:
            db.add(row)
        db.commit()
        return row.id


def delete(lic_id: int) -> bool:
    with SessionLocal() as db:
        row = db.get(SoftwareLicense, lic_id)
        if not row:
            return False
        db.delete(row)
        db.commit()
        return True


def read_key(lic_id: int) -> Optional[str]:
    from services import crypto
    with SessionLocal() as db:
        row = db.get(SoftwareLicense, lic_id)
        if not row:
            raise ValueError("license not found")
        return crypto.decrypt(row.key_enc) if row.key_enc else None


# ── Compliance ───────────────────────────────────────────────────────────────

def matches(name: str, match: List[str], exclude: List[str]) -> bool:
    n = " ".join((name or "").split()).lower()
    return any(m in n for m in match) and not any(x in n for x in exclude)


def _installed(db) -> List[Dict]:
    """Every program on every asset: {asset_id, asset, name, version, seen, live, server}."""
    import json
    now = _now()
    assets_by_vh: Dict[int, Asset] = {}
    by_ip: Dict[str, Asset] = {}
    for a in db.execute(select(Asset)).scalars().all():
        try:
            vh = (json.loads(a.refs or "{}") or {}).get("vuln_host_id")
        except ValueError:
            vh = None
        if isinstance(vh, int):
            assets_by_vh[vh] = a
        if a.ip:
            by_ip.setdefault(a.ip, a)
    hosts = {h.id: h.ip for h in db.execute(select(VulnHost)).scalars().all()}
    out = []
    for p in db.execute(select(VulnPackage)).scalars().all():
        a = assets_by_vh.get(p.host_id) or by_ip.get(hosts.get(p.host_id) or "")
        if a is None:
            continue
        from services import asset_itam
        stage = asset_itam.stage_of(a)
        alive = a.last_seen_at is None or now - a.last_seen_at <= timedelta(days=RECLAIM_DAYS)
        live = alive and not a.state and stage not in ("retired", "disposed")
        out.append({"asset_id": a.id, "asset": a.name or a.ip or a.key, "name": p.name, "version": p.version, "seen": p.last_seen.isoformat() + "Z" if p.last_seen else None,
                    "live": live, "server": a.role == "server" or a.asset_type in ("server", "virtual")})
    return out


def _status(lic: SoftwareLicense, used: int, now: datetime) -> str:
    if lic.valid_until and lic.valid_until < now:
        return "expired"
    if lic.seats is not None and used > lic.seats:
        return "over"
    if lic.valid_until and (lic.valid_until - now).days <= EXPIRY_WARN_DAYS:
        return "expiring"
    if lic.kind == "site":
        return "site" if used else "no_installs"
    if used == 0:
        return "no_installs"
    if lic.seats is not None and used < lic.seats:
        return "unused"
    return "compliant"


def compliance(now: Optional[datetime] = None, with_installs: bool = False) -> List[Dict]:
    import json
    now = now or _now()
    with SessionLocal() as db:
        inst = _installed(db)
        lics = db.execute(select(SoftwareLicense).order_by(SoftwareLicense.product)).scalars().all()
        out = []
        for l in lics:
            m, x = json.loads(l.match or "[]"), json.loads(l.exclude or "[]")
            hits = [i for i in inst if matches(i["name"], m, x) and (l.kind != "per_server" or i["server"])]
            per_asset: Dict[int, Dict] = {}
            for h in hits:
                per_asset.setdefault(h["asset_id"], h)
            used = sum(1 for h in per_asset.values() if h["live"])
            reclaim = sum(1 for h in per_asset.values() if not h["live"])
            row = {"id": l.id, "product": l.product, "vendor": l.vendor, "kind": l.kind, "seats": l.seats, "match": m, "exclude": x,
                   "valid_from": l.valid_from.date().isoformat() if l.valid_from else None, "valid_until": l.valid_until.date().isoformat() if l.valid_until else None,
                   "days_left": (l.valid_until - now).days if l.valid_until else None, "cost": l.cost, "currency": l.currency, "supplier": l.supplier,
                   "reference": l.reference, "notes": l.notes, "has_key": bool(l.key_enc),
                   "installs": len(per_asset), "used": used, "reclaimable": reclaim,
                   "over": max(0, used - l.seats) if l.seats is not None else 0, "unused": max(0, l.seats - used) if l.seats is not None else None,
                   "status": _status(l, used, now)}
            if with_installs:
                row["install_list"] = sorted(per_asset.values(), key=lambda h: (not h["live"], (h["asset"] or "").lower()))
            out.append(row)
        return out


def suggestions(limit: int = 40) -> List[Dict]:
    """The programs installed on the most assets that no license covers yet - a start for entering licenses. Updates and runtimes are skipped."""
    import json
    skip = ("update", "redistributable", "runtime", "hotfix", "security intelligence", "driver", "kb", "language pack", "lib", "python3-", "-common", "-dev")
    with SessionLocal() as db:
        inst = _installed(db)
        lics = [(json.loads(l.match or "[]"), json.loads(l.exclude or "[]")) for l in db.execute(select(SoftwareLicense)).scalars().all()]
    counts: Dict[str, set] = {}
    for i in inst:
        n = " ".join(i["name"].split())
        nl = n.lower()
        if any(s in nl for s in skip) or any(matches(n, m, x) for m, x in lics):
            continue
        counts.setdefault(n, set()).add(i["asset_id"])
    rows = sorted(((n, len(a)) for n, a in counts.items()), key=lambda r: (-r[1], r[0].lower()))
    return [{"name": n, "assets": c} for n, c in rows[:limit]]


def for_asset(asset_id: int) -> List[Dict]:
    """The licenses that cover programs on one asset."""
    out = []
    for l in compliance(with_installs=True):
        for h in l["install_list"]:
            if h["asset_id"] == asset_id:
                out.append({"id": l["id"], "product": l["product"], "kind": l["kind"], "program": h["name"], "version": h["version"], "status": l["status"]})
                break
    return out


def check(now: Optional[datetime] = None) -> Dict[str, int]:
    from services import soc
    now = now or _now()
    counts = {"over": 0, "expiring": 0}
    for l in compliance(now):
        name, k = l["product"], str(l["id"])
        if l["over"] > 0:
            soc.raise_alert(rule="license.over", device=name, title="License not compliant", severity="medium", category="compliance", fp_detail=k,
                            detail={"message": f"{name}: {l['used']} installations in use, {l['seats']} seats ({l['over']} over)", "description": "software license"},
                            count=0, source="rules", now=now)
            counts["over"] += 1
        else:
            soc.resolve(rule="license.over", device=name, fp_detail=k, now=now)
        if l["days_left"] is not None and 0 <= l["days_left"] <= EXPIRY_WARN_DAYS:
            soc.raise_alert(rule="license.expiring", device=name, title="License expiring", severity="low", category="compliance", fp_detail=k,
                            detail={"message": f"{name}: the license ends on {l['valid_until']} (in {l['days_left']} days)", "description": "software license"},
                            count=0, source="rules", now=now)
            counts["expiring"] += 1
        else:
            soc.resolve(rule="license.expiring", device=name, fp_detail=k, now=now)
    return counts


def forecast_items(now: Optional[datetime] = None, horizon: int = 90) -> List[Dict]:
    now = now or _now()
    out = []
    for l in compliance(now):
        if l["valid_until"] and l["days_left"] is not None and -30 <= l["days_left"] <= horizon:
            out.append({"kind": "license", "key": f"license:{l['id']}", "name": l["product"], "where": l["product"], "what": l["vendor"], "asset_id": None,
                        "unit": None, "value": None, "per_day": None, "days": float(l["days_left"]), "date": l["valid_until"] + "T00:00:00Z"})
    return out


def public_summary() -> Dict:
    """For Central / MCP: per license the counts and the status - no keys, no notes."""
    rows = compliance()
    return {"licenses": [{"p": l["product"], "v": l["vendor"], "k": l["kind"], "s": l["seats"], "u": l["used"], "r": l["reclaimable"], "o": l["over"],
                          "until": l["valid_until"], "st": l["status"], "c": l["cost"], "cu": l["currency"]} for l in rows][:200],
            "counts": {st: sum(1 for l in rows if l["status"] == st) for st in ("compliant", "over", "unused", "expired", "expiring", "no_installs", "site")}}

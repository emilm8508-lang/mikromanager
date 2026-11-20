"""
Vendors, contracts and purchase orders (docs/plan-itam.md, stage D).

  vendors          who we buy from / who supports us: name, contact person, e-mail, phone, web site, notes
  contracts        support / maintenance / warranty / lease / license / SLA / other: number, title, vendor, dates, value, automatic renewal,
                   how many days before the end to be told (notice_days), the person responsible, the assets and licenses it covers, notes,
                   attachments. Status: future / active / expiring (within notice_days of the end) / expired / renewing (auto-renew past its end).
  purchase orders  number, vendor, items (description, quantity, unit price, kind asset / license / service / other), total, a simple flow
                   draft -> approved -> ordered -> received, or cancelled from any but received; every change with who and when. Receiving
                   an order creates its asset items in the inventory in the stage "in stock" (with the cost, supplier, order number and the
                   date) and adds license items' quantities to the seats of the license they name.
  attachments      a PDF, image or office document (MAX_FILE bytes) on a contract, an order or an asset, kept in data/attachments/ under a
                   random name and only ever sent back as a download (never run, never shown inline as HTML).

Alerts: contract.expiring (low; medium within 7 days) from notice_days before the end, unless it renews by itself; and an event
`contract_expiring` to Central (once per contract and end date) so a Central alert rule can send it to a channel. Checked every hour.
"""
import json
import os
import re
import secrets
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, Vendor, Contract, PurchaseOrder, Attachment, SoftwareLicense

CONTRACT_KINDS = ("support", "maintenance", "warranty", "lease", "license", "sla", "other")
PO_STATUSES = ("draft", "approved", "ordered", "received", "cancelled")
_FLOW = {"draft": ("approved", "cancelled"), "approved": ("ordered", "cancelled", "draft"), "ordered": ("received", "cancelled"), "received": (), "cancelled": ("draft",)}
ITEM_KINDS = ("asset", "license", "service", "other")
ASSET_TYPES = ("windows", "linux", "network", "printer", "virtual", "server", "other")
MAX_ITEMS = 50
MAX_FILE = 10 * 1024 * 1024
ALLOWED_EXT = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
               ".txt": "text/plain", ".csv": "text/csv", ".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
               ".xls": "application/vnd.ms-excel", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".odt": "application/vnd.oasis.opendocument.text",
               ".ods": "application/vnd.oasis.opendocument.spreadsheet", ".msg": "application/vnd.ms-outlook", ".eml": "message/rfc822"}
_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "attachments")
_pending: List[dict] = []
_SENT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "contract_notices.json")


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.date().isoformat() if d else None


def _txt(v, n: int) -> Optional[str]:
    return " ".join(str(v or "").split())[:n] or None


def _d(v) -> Optional[datetime]:
    if v in (None, ""):
        return None
    try:
        d = date.fromisoformat(str(v).strip()[:10])
    except ValueError:
        raise ValueError(f"not a date (YYYY-MM-DD): {v!r}")
    return datetime(d.year, d.month, d.day)


def _money(v) -> Optional[float]:
    if v in (None, ""):
        return None
    try:
        x = round(float(str(v).replace(",", ".").replace(" ", "")), 2)
    except ValueError:
        raise ValueError("an amount: a number")
    if x < 0:
        raise ValueError("an amount: 0 or more")
    return x


def _cur(v) -> Optional[str]:
    c = str(v or "").strip().upper() or None
    if c and not re.fullmatch(r"[A-Z]{3}", c):
        raise ValueError("currency: a 3-letter code")
    return c


def _ids(v) -> List[int]:
    return sorted({int(x) for x in (v or []) if str(x).isdigit()})[:500]


# ── Vendors ──────────────────────────────────────────────────────────────────

def save_vendor(body: Dict, vid: Optional[int] = None) -> int:
    name = _txt(body.get("name"), 120)
    if not name:
        raise ValueError("a vendor needs a name")
    email = _txt(body.get("email"), 120)
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("not an e-mail address")
    with SessionLocal() as db:
        dup = db.execute(select(Vendor).where(Vendor.name == name)).scalars().first()
        if dup and dup.id != vid:
            raise ValueError("a vendor of that name exists")
        v = db.get(Vendor, vid) if vid else Vendor(created_at=_now())
        if vid and not v:
            raise ValueError("vendor not found")
        v.name, v.contact, v.email, v.phone = name, _txt(body.get("contact"), 120), email, _txt(body.get("phone"), 40)
        v.website, v.notes = _txt(body.get("website"), 200), (str(body.get("notes") or "").strip()[:1000] or None)
        if not vid:
            db.add(v)
        db.commit()
        return v.id


def vendors() -> List[Dict]:
    with SessionLocal() as db:
        cn = {}
        for c in db.execute(select(Contract)).scalars().all():
            cn[c.vendor_id] = cn.get(c.vendor_id, 0) + 1
        po = {}
        for p in db.execute(select(PurchaseOrder)).scalars().all():
            po[p.vendor_id] = po.get(p.vendor_id, 0) + 1
        return [{"id": v.id, "name": v.name, "contact": v.contact, "email": v.email, "phone": v.phone, "website": v.website, "notes": v.notes,
                 "contracts": cn.get(v.id, 0), "orders": po.get(v.id, 0)} for v in db.execute(select(Vendor).order_by(Vendor.name)).scalars().all()]


def delete_vendor(vid: int) -> bool:
    with SessionLocal() as db:
        v = db.get(Vendor, vid)
        if not v:
            return False
        if db.execute(select(Contract.id).where(Contract.vendor_id == vid)).first() or db.execute(select(PurchaseOrder.id).where(PurchaseOrder.vendor_id == vid)).first():
            raise ValueError("the vendor has contracts or orders")
        db.delete(v)
        db.commit()
        return True


# ── Contracts ────────────────────────────────────────────────────────────────

def contract_status(c: Contract, now: Optional[datetime] = None) -> str:
    now = now or _now()
    if c.start_at and c.start_at > now:
        return "future"
    if c.end_at and c.end_at < now:
        return "renewing" if c.auto_renew else "expired"
    if c.end_at and (c.end_at - now).days <= (c.notice_days if c.notice_days is not None else 30):
        return "renewing" if c.auto_renew else "expiring"
    return "active"


def save_contract(body: Dict, cid: Optional[int] = None, who: str = "operator") -> int:
    title = _txt(body.get("title"), 160)
    if not title:
        raise ValueError("a contract needs a title")
    kind = str(body.get("kind") or "support")
    if kind not in CONTRACT_KINDS:
        raise ValueError(f"kind: one of {', '.join(CONTRACT_KINDS)}")
    start, end = _d(body.get("start_at")), _d(body.get("end_at"))
    if start and end and end < start:
        raise ValueError("the contract cannot end before it starts")
    notice = body.get("notice_days")
    notice = 30 if notice in (None, "") else int(notice)
    if not 0 <= notice <= 365:
        raise ValueError("notice_days: 0 to 365")
    with SessionLocal() as db:
        vid = body.get("vendor_id")
        if vid not in (None, "") and not db.get(Vendor, int(vid)):
            raise ValueError("vendor not found")
        c = db.get(Contract, cid) if cid else Contract(created_at=_now(), created_by=(who or "")[:64])
        if cid and not c:
            raise ValueError("contract not found")
        c.title, c.kind, c.number = title, kind, _txt(body.get("number"), 80)
        c.vendor_id = int(vid) if vid not in (None, "") else None
        c.start_at, c.end_at, c.notice_days = start, end, notice
        c.value, c.currency, c.auto_renew = _money(body.get("value")), _cur(body.get("currency")), bool(body.get("auto_renew"))
        c.owner, c.notes = _txt(body.get("owner"), 120), (str(body.get("notes") or "").strip()[:2000] or None)
        c.asset_ids = json.dumps(_ids(body.get("asset_ids")))
        c.license_ids = json.dumps(_ids(body.get("license_ids")))
        c.updated_at = _now()
        if not cid:
            db.add(c)
        db.commit()
        return c.id


def _contract_dict(c: Contract, vnames: Dict[int, str], anames: Dict[int, str], lnames: Dict[int, str], atts: Dict, now: datetime) -> Dict:
    aids, lids = json.loads(c.asset_ids or "[]"), json.loads(c.license_ids or "[]")
    return {"id": c.id, "title": c.title, "kind": c.kind, "number": c.number, "vendor_id": c.vendor_id, "vendor": vnames.get(c.vendor_id),
            "start_at": _iso(c.start_at), "end_at": _iso(c.end_at), "days_left": (c.end_at - now).days if c.end_at else None,
            "notice_days": c.notice_days, "value": c.value, "currency": c.currency, "auto_renew": bool(c.auto_renew), "owner": c.owner, "notes": c.notes,
            "assets": [{"id": i, "name": anames.get(i)} for i in aids if i in anames], "licenses": [{"id": i, "name": lnames.get(i)} for i in lids if i in lnames],
            "status": contract_status(c, now), "attachments": atts.get(("contract", c.id), [])}


def _names(db):
    return ({v.id: v.name for v in db.execute(select(Vendor)).scalars().all()}, {a.id: a.name or a.ip or a.key for a in db.execute(select(Asset)).scalars().all()},
            {l.id: l.product for l in db.execute(select(SoftwareLicense)).scalars().all()}, _attachments_by_owner(db))


def contracts(now: Optional[datetime] = None) -> List[Dict]:
    now = now or _now()
    with SessionLocal() as db:
        vn, an, ln, at = _names(db)
        rows = [_contract_dict(c, vn, an, ln, at, now) for c in db.execute(select(Contract)).scalars().all()]
    order = {"expired": 0, "expiring": 1, "renewing": 2, "active": 3, "future": 4}
    return sorted(rows, key=lambda r: (order.get(r["status"], 9), r["days_left"] if r["days_left"] is not None else 99999, r["title"].lower()))


def contracts_for_asset(asset_id: int) -> List[Dict]:
    return [c for c in contracts() if any(a["id"] == asset_id for a in c["assets"])]


def delete_contract(cid: int) -> bool:
    with SessionLocal() as db:
        c = db.get(Contract, cid)
        if not c:
            return False
        for a in db.execute(select(Attachment).where(Attachment.owner_kind == "contract", Attachment.owner_id == cid)).scalars().all():
            _unlink(a)
            db.delete(a)
        db.delete(c)
        db.commit()
        return True


# ── Purchase orders ──────────────────────────────────────────────────────────

def _items(v) -> List[Dict]:
    out = []
    for it in (v or [])[:MAX_ITEMS]:
        desc = _txt((it or {}).get("description"), 200)
        if not desc:
            raise ValueError("every item needs a description")
        kind = str(it.get("kind") or "asset")
        if kind not in ITEM_KINDS:
            raise ValueError(f"item kind: one of {', '.join(ITEM_KINDS)}")
        try:
            qty = int(it.get("qty") or 1)
        except (TypeError, ValueError):
            raise ValueError("quantity: a whole number")
        if not 1 <= qty <= 1000:
            raise ValueError("quantity: 1 to 1000")
        row = {"description": desc, "kind": kind, "qty": qty, "unit_price": _money(it.get("unit_price"))}
        if kind == "asset":
            at = str(it.get("asset_type") or "other")
            row["asset_type"] = at if at in ASSET_TYPES else "other"
            row["model"] = _txt(it.get("model"), 80)
        if kind == "license" and str(it.get("license_id") or "").isdigit():
            row["license_id"] = int(it["license_id"])
        out.append(row)
    if not out:
        raise ValueError("an order needs at least one item")
    return out


def save_order(body: Dict, oid: Optional[int] = None, who: str = "operator") -> int:
    number = _txt(body.get("number"), 60)
    if not number:
        raise ValueError("an order needs a number")
    items = _items(body.get("items"))
    total = round(sum((i["unit_price"] or 0) * i["qty"] for i in items), 2)
    with SessionLocal() as db:
        dup = db.execute(select(PurchaseOrder).where(PurchaseOrder.number == number)).scalars().first()
        if dup and dup.id != oid:
            raise ValueError("an order with that number exists")
        vid = body.get("vendor_id")
        if vid not in (None, "") and not db.get(Vendor, int(vid)):
            raise ValueError("vendor not found")
        o = db.get(PurchaseOrder, oid) if oid else PurchaseOrder(created_at=_now(), created_by=(who or "")[:64], status="draft", history=json.dumps([]))
        if oid and not o:
            raise ValueError("order not found")
        if oid and o.status in ("received", "cancelled"):
            raise ValueError(f"a {o.status} order cannot be changed")
        o.number, o.vendor_id = number, int(vid) if vid not in (None, "") else None
        o.items, o.total, o.currency = json.dumps(items, ensure_ascii=False), total, _cur(body.get("currency"))
        o.notes = str(body.get("notes") or "").strip()[:2000] or None
        o.updated_at = _now()
        if not oid:
            db.add(o)
        db.commit()
        return o.id


def set_order_status(oid: int, status: str, who: str, received_at: Optional[str] = None) -> Dict:
    """Moves an order along the flow; receiving it creates its assets and adds its license seats. Returns what receiving made."""
    if status not in PO_STATUSES:
        raise ValueError("unknown status")
    made = {"assets": [], "licenses": []}
    with SessionLocal() as db:
        o = db.get(PurchaseOrder, oid)
        if not o:
            raise ValueError("order not found")
        if status not in _FLOW.get(o.status, ()):
            raise ValueError(f"an order cannot go from {o.status} to {status}")
        now = _now()
        hist = json.loads(o.history or "[]")
        hist.append({"at": now.isoformat() + "Z", "who": (who or "?")[:64], "from": o.status, "to": status})
        o.history, o.status, o.updated_at = json.dumps(hist), status, now
        if status == "ordered":
            o.ordered_at = now
        if status == "received":
            o.received_at = _d(received_at) or datetime(now.year, now.month, now.day)
            vname = db.get(Vendor, o.vendor_id).name if o.vendor_id and db.get(Vendor, o.vendor_id) else None
            from services import identity
            for n, it in enumerate(json.loads(o.items or "[]")):
                if it["kind"] == "asset":
                    for k in range(it["qty"]):
                        a = Asset(key=f"po:{o.id}:{n}:{k}", name=it["description"][:120] if it["qty"] == 1 else f"{it['description'][:110]} #{k + 1}",
                                  asset_type=it.get("asset_type") or "other", model=it.get("model"), scan_level="passive", first_seen_at=now,
                                  lifecycle_stage="in_stock", purchased_at=o.received_at, cost=it.get("unit_price"), currency=o.currency, supplier=vname,
                                  invoice_no=o.number, notes=f"from purchase order {o.number}")
                        db.add(a)
                        db.flush()
                        identity.history(db, a.id, "lifecycle_stage", None, "in_stock", f"po {o.number}: {who}"[:80], now)
                        made["assets"].append(a.id)
                elif it["kind"] == "license" and it.get("license_id"):
                    lic = db.get(SoftwareLicense, it["license_id"])
                    if lic and lic.seats is not None:
                        lic.seats += it["qty"]
                        lic.updated_at = now
                        made["licenses"].append({"id": lic.id, "added": it["qty"]})
        db.commit()
    return made


def orders() -> List[Dict]:
    with SessionLocal() as db:
        vn, _an, ln, at = _names(db)
        out = []
        for o in db.execute(select(PurchaseOrder)).scalars().all():
            items = json.loads(o.items or "[]")
            for it in items:
                if it.get("license_id"):
                    it["license"] = ln.get(it["license_id"])
            out.append({"id": o.id, "number": o.number, "vendor_id": o.vendor_id, "vendor": vn.get(o.vendor_id), "status": o.status, "items": items,
                        "total": o.total, "currency": o.currency, "notes": o.notes, "created_by": o.created_by, "created_at": o.created_at.isoformat() + "Z",
                        "ordered_at": _iso(o.ordered_at), "received_at": _iso(o.received_at), "history": json.loads(o.history or "[]"),
                        "next": list(_FLOW.get(o.status, ())), "attachments": at.get(("po", o.id), [])})
    order = {"draft": 0, "approved": 1, "ordered": 2, "received": 3, "cancelled": 4}
    return sorted(out, key=lambda r: (order.get(r["status"], 9), r["created_at"]), reverse=False)


def delete_order(oid: int) -> bool:
    with SessionLocal() as db:
        o = db.get(PurchaseOrder, oid)
        if not o:
            return False
        if o.status not in ("draft", "cancelled"):
            raise ValueError("only a draft or a cancelled order can be deleted")
        for a in db.execute(select(Attachment).where(Attachment.owner_kind == "po", Attachment.owner_id == oid)).scalars().all():
            _unlink(a)
            db.delete(a)
        db.delete(o)
        db.commit()
        return True


# ── Attachments ──────────────────────────────────────────────────────────────

def _attachments_by_owner(db) -> Dict:
    out: Dict = {}
    for a in db.execute(select(Attachment).order_by(Attachment.id)).scalars().all():
        out.setdefault((a.owner_kind, a.owner_id), []).append({"id": a.id, "filename": a.filename, "size": a.size, "at": a.uploaded_at.isoformat() + "Z", "by": a.uploaded_by})
    return out


def _safe_name(name: str) -> str:
    base = os.path.basename(str(name or "").replace("\\", "/"))
    base = re.sub(r"[^\w.\- ()]", "_", base).strip(" .")[:120]
    return base or "file"


def add_attachment(owner_kind: str, owner_id: int, filename: str, data: bytes, who: str) -> int:
    if owner_kind not in ("contract", "po", "asset"):
        raise ValueError("unknown owner")
    name = _safe_name(filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        raise ValueError(f"only {', '.join(sorted(ALLOWED_EXT))} files")
    if not data:
        raise ValueError("an empty file")
    if len(data) > MAX_FILE:
        raise ValueError(f"a file up to {MAX_FILE // (1024 * 1024)} MB")
    if ext == ".pdf" and not data.startswith(b"%PDF"):
        raise ValueError("not a PDF file")
    with SessionLocal() as db:
        model = {"contract": Contract, "po": PurchaseOrder, "asset": Asset}[owner_kind]
        if not db.get(model, owner_id):
            raise ValueError("not found")
        os.makedirs(_FILES, exist_ok=True)
        stored = secrets.token_hex(16) + ext
        with open(os.path.join(_FILES, stored), "wb") as f:
            f.write(data)
        a = Attachment(owner_kind=owner_kind, owner_id=owner_id, filename=name, stored=stored, content_type=ALLOWED_EXT[ext], size=len(data),
                       uploaded_by=(who or "")[:64], uploaded_at=_now())
        db.add(a)
        db.commit()
        return a.id


def attachment(att_id: int) -> Optional[Dict]:
    with SessionLocal() as db:
        a = db.get(Attachment, att_id)
        if not a:
            return None
        path = os.path.join(_FILES, a.stored)
        if not re.fullmatch(r"[0-9a-f]{32}\.[a-z]{2,5}", a.stored or "") or not os.path.isfile(path):
            return None
        return {"path": path, "filename": a.filename, "content_type": a.content_type}


def attachments_of(owner_kind: str, owner_id: int) -> List[Dict]:
    with SessionLocal() as db:
        return _attachments_by_owner(db).get((owner_kind, owner_id), [])


def _unlink(a: Attachment) -> None:
    try:
        if re.fullmatch(r"[0-9a-f]{32}\.[a-z]{2,5}", a.stored or ""):
            os.remove(os.path.join(_FILES, a.stored))
    except OSError:
        pass


def delete_attachment(att_id: int) -> bool:
    with SessionLocal() as db:
        a = db.get(Attachment, att_id)
        if not a:
            return False
        _unlink(a)
        db.delete(a)
        db.commit()
        return True


# ── Notices ──────────────────────────────────────────────────────────────────

def _sent() -> Dict[str, str]:
    try:
        with open(_SENT_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def check(now: Optional[datetime] = None) -> int:
    """Raises / closes contract.expiring and queues a contract_expiring event for Central once per contract and end date."""
    from services import soc
    now = now or _now()
    sent = _sent()
    n = 0
    for c in contracts(now):
        name = c["title"] + (f" ({c['vendor']})" if c["vendor"] else "")
        key = str(c["id"])
        if c["status"] in ("expiring", "expired"):
            days = c["days_left"]
            sev = "medium" if days is not None and days <= 7 else "low"
            soc.raise_alert(rule="contract.expiring", device=name[:120], title="Contract ending", severity=sev, category="compliance", fp_detail=key,
                            detail={"message": f"{name}: {'ended' if (days or 0) < 0 else 'ends'} on {c['end_at']}" + (f" (in {days} days)" if (days or 0) >= 0 else ""),
                                    "description": f"{c['kind']} contract"}, count=0, source="rules", now=now)
            n += 1
            mark = f"{c['id']}:{c['end_at']}"
            if sent.get(key) != mark:
                _pending.append({"type": "contract_expiring", "count": 1, "device_name": name[:120], "title": c["title"], "kind": c["kind"], "vendor": c["vendor"],
                                 "end_at": c["end_at"], "days_left": days, "detected_at": now.isoformat()})
                sent[key] = mark
        else:
            soc.resolve(rule="contract.expiring", device=name[:120], fp_detail=key, now=now)
    try:
        os.makedirs(os.path.dirname(_SENT_PATH), exist_ok=True)
        with open(_SENT_PATH, "w", encoding="utf-8") as f:
            json.dump(sent, f)
    except OSError as e:
        print(f"[procurement] could not keep the notices: {e}")
    return n


def collect_alert_events() -> List[Dict]:
    out = list(_pending)
    _pending.clear()
    return out


def forecast_items(now: Optional[datetime] = None, horizon: int = 90) -> List[Dict]:
    now = now or _now()
    return [{"kind": "contract", "key": f"contract:{c['id']}", "name": c["title"], "where": c["title"], "what": c["vendor"], "asset_id": None, "unit": None,
             "value": None, "per_day": None, "days": float(c["days_left"]), "date": c["end_at"] + "T00:00:00Z"}
            for c in contracts(now) if c["end_at"] and c["days_left"] is not None and -30 <= c["days_left"] <= horizon and not c["auto_renew"]]


def public_summary() -> Dict:
    """For Central / MCP: contracts ending within 60 days, open orders, counts - no notes, no attachments, no person responsible."""
    cs, os_ = contracts(), orders()
    return {"contracts": [{"t": c["title"], "k": c["kind"], "v": c["vendor"], "end": c["end_at"], "d": c["days_left"], "st": c["status"], "val": c["value"],
                           "cu": c["currency"], "ar": c["auto_renew"], "n": len(c["assets"])} for c in cs if c["status"] != "active" or (c["days_left"] or 999) <= 60][:100],
            "orders": [{"no": o["number"], "v": o["vendor"], "st": o["status"], "tot": o["total"], "cu": o["currency"], "items": len(o["items"])}
                       for o in os_ if o["status"] in ("draft", "approved", "ordered")][:100],
            "counts": {"contracts": len(cs), "expiring": sum(1 for c in cs if c["status"] in ("expiring", "expired")), "vendors": len(vendors()),
                       "orders_open": sum(1 for o in os_ if o["status"] in ("draft", "approved", "ordered"))}}

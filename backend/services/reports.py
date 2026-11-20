"""
Reports of the assets, licenses and contracts, ready-made or of your own, downloaded or sent by e-mail on a schedule (docs/plan-itam.md, stage E).

Ready-made reports (BUILTIN): the asset register, warranties ending, assets to replace, costs per cost centre and year, license compliance,
contracts ending, open purchase orders, disposed assets, software by product. A report of your own picks a scope (assets / licenses /
contracts), filters and columns, and can be saved. A saved report can have a schedule (daily / weekly on a day / monthly on a day, at an hour)
and recipients: it is then built and sent as an attachment (CSV, XLSX or Word) through the agent's own SMTP server settings (services/mailer.py).
Every sending is kept in the history (when, to whom, how many rows, ok / the error).

Formats: CSV with ";" and a BOM (opens right in a Polish Excel), XLSX written here without any extra library (one sheet, text and numbers),
Word through python-docx (a table, landscape).
"""
import asyncio
import csv
import io
import json
import re
import zipfile
from datetime import date, datetime, timedelta
from typing import Callable, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape

from sqlalchemy import select

from models.database import SessionLocal, Asset, ReportDef, ReportRun

FORMATS = ("csv", "xlsx", "docx")
SCHEDULES = ("none", "daily", "weekly", "monthly")
SCOPES = ("assets", "licenses", "contracts")
MAX_ROWS = 20000
TICK_SEC = 600
_task: Optional[asyncio.Task] = None

# the columns of each scope: key -> how to read it from a row
ASSET_COLUMNS = ("name", "ip", "mac", "type", "role", "ci_class", "stage", "asset_tag", "manufacturer", "model", "serial", "os", "location", "place", "owner",
                 "criticality", "purchased_at", "warranty_until", "replace_at", "disposed_at", "disposal_method", "cost", "currency", "supplier", "invoice_no",
                 "cost_center", "state", "first_seen", "last_seen")
LICENSE_COLUMNS = ("product", "vendor", "kind", "seats", "used", "reclaimable", "over", "unused", "status", "valid_from", "valid_until", "cost", "currency", "supplier", "reference")
CONTRACT_COLUMNS = ("title", "kind", "number", "vendor", "start_at", "end_at", "days_left", "status", "value", "currency", "auto_renew", "assets_covered", "owner")
COLUMNS = {"assets": ASSET_COLUMNS, "licenses": LICENSE_COLUMNS, "contracts": CONTRACT_COLUMNS}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d) -> Optional[str]:
    return d.date().isoformat() if isinstance(d, datetime) else (d.isoformat() if isinstance(d, date) else d)


# ── Data ─────────────────────────────────────────────────────────────────────

def asset_rows() -> List[Dict]:
    from services import asset_itam, cmdb
    with SessionLocal() as db:
        ports, hv = cmdb._ports(db), cmdb._hyperv_hosts(db)
        out = []
        for a in db.execute(select(Asset)).scalars().all():
            if a.state == "ignore":
                continue
            out.append({"id": a.id, "name": a.name or a.ip or a.key, "ip": a.ip, "mac": a.mac, "type": a.asset_type, "role": a.role,
                        "ci_class": cmdb.class_of(a, ports, hv)["class"], "stage": asset_itam.stage_of(a), "asset_tag": a.asset_tag, "manufacturer": a.manufacturer,
                        "model": a.model, "serial": a.serial, "os": " ".join(x for x in (a.os_name, a.os_version) if x) or None,
                        "location": a.location_override, "place": a.place, "owner": a.owner, "criticality": a.criticality,
                        "purchased_at": _iso(a.purchased_at), "warranty_until": _iso(a.warranty_until), "replace_at": _iso(a.replace_at), "disposed_at": _iso(a.disposed_at),
                        "disposal_method": a.disposal_method, "cost": a.cost, "currency": a.currency, "supplier": a.supplier, "invoice_no": a.invoice_no,
                        "cost_center": a.cost_center, "state": a.state or "in_use", "first_seen": _iso(a.first_seen_at), "last_seen": _iso(a.last_seen_at)})
    return sorted(out, key=lambda r: (r["name"] or "").lower())


def license_rows() -> List[Dict]:
    from services import licenses
    return licenses.compliance()


def contract_rows() -> List[Dict]:
    from services import procurement
    return [{**c, "assets_covered": len(c["assets"])} for c in procurement.contracts()]


_SOURCES: Dict[str, Callable[[], List[Dict]]] = {"assets": asset_rows, "licenses": license_rows, "contracts": contract_rows}


# ── Filters (a report of your own) ───────────────────────────────────────────

def clean_params(p: Dict) -> Dict:
    scope = p.get("scope") or "assets"
    if scope not in SCOPES:
        raise ValueError(f"scope: one of {', '.join(SCOPES)}")
    cols = [c for c in (p.get("columns") or []) if c in COLUMNS[scope]] or list(COLUMNS[scope][:10])
    f = p.get("filters") or {}
    out = {}
    for k in ("type", "ci_class", "stage", "state", "status", "kind"):
        v = f.get(k)
        if v:
            out[k] = [str(x) for x in (v if isinstance(v, list) else [v])][:20]
    for k in ("location", "owner", "cost_center", "supplier", "text"):
        if f.get(k):
            out[k] = str(f[k]).strip()[:80]
    for k in ("purchased_from", "purchased_to", "warranty_before", "end_before"):
        if f.get(k):
            try:
                out[k] = date.fromisoformat(str(f[k])[:10]).isoformat()
            except ValueError:
                raise ValueError(f"{k}: a date (YYYY-MM-DD)")
    sort = p.get("sort") if p.get("sort") in COLUMNS[scope] else None
    return {"scope": scope, "columns": cols, "filters": out, "sort": sort, "desc": bool(p.get("desc"))}


def _apply_filters(rows: List[Dict], f: Dict) -> List[Dict]:
    def keep(r):
        for k in ("type", "ci_class", "stage", "state", "status", "kind"):
            if k in f and str(r.get(k)) not in f[k]:
                return False
        for k in ("location", "owner", "cost_center", "supplier"):
            if k in f and f[k].lower() not in str(r.get(k) or "").lower():
                return False
        if "text" in f and f["text"].lower() not in " ".join(str(v) for v in r.values() if v is not None).lower():
            return False
        if "purchased_from" in f and not (r.get("purchased_at") and r["purchased_at"] >= f["purchased_from"]):
            return False
        if "purchased_to" in f and not (r.get("purchased_at") and r["purchased_at"] <= f["purchased_to"]):
            return False
        if "warranty_before" in f and not (r.get("warranty_until") and r["warranty_until"] <= f["warranty_before"]):
            return False
        if "end_before" in f and not (r.get("end_at") and r["end_at"] <= f["end_before"]):
            return False
        return True
    return [r for r in rows if keep(r)]


# ── Ready-made reports ───────────────────────────────────────────────────────

def _within(days: int) -> str:
    return (_now().date() + timedelta(days=days)).isoformat()


def _costs(_p=None) -> Tuple[List[str], List[Dict]]:
    sums: Dict[Tuple[str, str, str], Dict] = {}
    for r in asset_rows():
        if r["cost"] is None:
            continue
        key = (r["cost_center"] or "—", (r["purchased_at"] or "")[:4] or "—", r["currency"] or "—")
        s = sums.setdefault(key, {"cost_center": key[0], "year": key[1], "currency": key[2], "assets": 0, "total": 0.0})
        s["assets"] += 1
        s["total"] = round(s["total"] + r["cost"], 2)
    return ["cost_center", "year", "assets", "total", "currency"], sorted(sums.values(), key=lambda s: (s["cost_center"], s["year"], s["currency"]))


def _software(_p=None) -> Tuple[List[str], List[Dict]]:
    from services import licenses
    with SessionLocal() as db:
        inst = licenses._installed(db)
    per: Dict[str, Dict] = {}
    for i in inst:
        n = " ".join(i["name"].split())
        r = per.setdefault(n, {"program": n, "assets": set(), "versions": set()})
        r["assets"].add(i["asset_id"])
        if i["version"]:
            r["versions"].add(i["version"])
    rows = [{"program": r["program"], "installs": len(r["assets"]), "versions": ", ".join(sorted(r["versions"])[:5])} for r in per.values()]
    return ["program", "installs", "versions"], sorted(rows, key=lambda r: (-r["installs"], r["program"].lower()))


def _orders(_p=None) -> Tuple[List[str], List[Dict]]:
    from services import procurement
    rows = [{"number": o["number"], "vendor": o["vendor"], "status": o["status"], "items": len(o["items"]), "total": o["total"], "currency": o["currency"],
             "created_at": o["created_at"][:10], "created_by": o["created_by"]} for o in procurement.orders() if o["status"] in ("draft", "approved", "ordered")]
    return ["number", "vendor", "status", "items", "total", "currency", "created_at", "created_by"], rows


BUILTIN: Dict[str, Dict] = {
    "asset_register": {"scope": "assets", "columns": ["asset_tag", "name", "type", "ci_class", "stage", "manufacturer", "model", "serial", "location", "owner",
                                                      "purchased_at", "warranty_until", "cost", "currency", "supplier", "cost_center"], "filters": {"stage": ["ordered", "in_stock", "deployed", "in_repair"]}},
    "warranty_ending": {"scope": "assets", "columns": ["name", "asset_tag", "model", "serial", "warranty_until", "supplier", "location"],
                        "filters": {"warranty_before": None, "stage": ["in_stock", "deployed", "in_repair"]}, "sort": "warranty_until", "dyn": {"warranty_before": 90}},
    "replace_due": {"scope": "assets", "columns": ["name", "asset_tag", "model", "purchased_at", "replace_at", "cost", "currency", "location"],
                    "filters": {"stage": ["deployed", "in_repair"]}, "sort": "replace_at", "only": "replace_at", "dyn_replace": 90},
    "costs_by_center": {"fn": _costs},
    "license_compliance": {"scope": "licenses", "columns": ["product", "vendor", "kind", "seats", "used", "reclaimable", "over", "unused", "status", "valid_until", "cost", "currency"],
                           "filters": {}},
    "contracts_ending": {"scope": "contracts", "columns": ["title", "kind", "vendor", "number", "end_at", "days_left", "status", "value", "currency", "auto_renew", "assets_covered"],
                         "filters": {}, "sort": "end_at", "dyn": {"end_before": 60}},
    "open_orders": {"fn": _orders},
    "disposed_assets": {"scope": "assets", "columns": ["name", "asset_tag", "model", "serial", "disposed_at", "disposal_method", "cost", "currency"],
                        "filters": {"stage": ["disposed"]}, "sort": "disposed_at"},
    "software_by_product": {"fn": _software},
}


def build(builtin: Optional[str] = None, params: Optional[Dict] = None) -> Dict:
    """{"columns", "rows", "title_key", "total"} of a ready-made report or of the given parameters."""
    if builtin:
        b = BUILTIN.get(builtin)
        if not b:
            raise ValueError("unknown report")
        if "fn" in b:
            cols, rows = b["fn"]()
            return {"columns": cols, "rows": rows[:MAX_ROWS], "total": len(rows), "builtin": builtin}
        p = {k: v for k, v in b.items() if k in ("scope", "columns", "sort")}
        f = {k: v for k, v in b["filters"].items() if v is not None}
        for k, days in (b.get("dyn") or {}).items():
            f[k] = _within(days)
        p["filters"] = f
        p = clean_params(p)
        rows = _apply_filters(_SOURCES[p["scope"]](), p["filters"])
        if b.get("only"):
            lim = _within(b.get("dyn_replace", 90))
            rows = [r for r in rows if r.get(b["only"]) and r[b["only"]] <= lim]
    else:
        p = clean_params(params or {})
        rows = _apply_filters(_SOURCES[p["scope"]](), p["filters"])
    if p.get("sort"):
        rows.sort(key=lambda r: (r.get(p["sort"]) is None, r.get(p["sort"]) if r.get(p["sort"]) is not None else ""), reverse=bool(p.get("desc")))
    cols = p["columns"]
    return {"columns": cols, "rows": [{c: r.get(c) for c in cols} for r in rows[:MAX_ROWS]], "total": len(rows), "builtin": builtin, "scope": p["scope"]}


# ── Files ────────────────────────────────────────────────────────────────────

def _cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (list, tuple, set)):
        return ", ".join(str(x) for x in v)
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") and not re.fullmatch(r"-?\d+(\.\d+)?", s) else s     # no formulas in a spreadsheet from device data


def to_csv(columns: List[str], labels: Dict[str, str], rows: List[Dict]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow([labels.get(c, c) for c in columns])
    for r in rows:
        w.writerow([_cell(r.get(c)) for c in columns])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def _col(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def to_xlsx(columns: List[str], labels: Dict[str, str], rows: List[Dict], sheet: str = "Report") -> bytes:
    """One sheet: the header in bold, numbers as numbers, everything else as inline text."""
    def cell(ci, ri, v, bold=False):
        ref = f"{_col(ci)}{ri}"
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return f'<c r="{ref}"><v>{v}</v></c>'
        style = ' s="1"' if bold else ""
        return f'<c r="{ref}" t="inlineStr"{style}><is><t xml:space="preserve">{escape(_cell(v))}</t></is></c>'
    data = ['<row r="1">' + "".join(cell(i, 1, labels.get(c, c), True) for i, c in enumerate(columns)) + "</row>"]
    for ri, r in enumerate(rows, start=2):
        data.append(f'<row r="{ri}">' + "".join(cell(i, ri, r.get(c)) for i, c in enumerate(columns)) + "</row>")
    widths = "".join(f'<col min="{i + 1}" max="{i + 1}" width="{min(50, max(10, len(labels.get(c, c)) + 4))}" customWidth="1"/>' for i, c in enumerate(columns))
    ws = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
          f'<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
          f'<cols>{widths}</cols><sheetData>{"".join(data)}</sheetData></worksheet>')
    files = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                               '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                               '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                               '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                               '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                           'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                           f'<sheet name="{escape(sheet[:31])}" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                                      '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                                      '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>',
        "xl/styles.xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                         '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
                         '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
                         '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                         '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                         '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
                         '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
                         '</styleSheet>',
        "xl/worksheets/sheet1.xml": ws,
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in files.items():
            z.writestr(name, body)
    return out.getvalue()


def to_docx(title: str, columns: List[str], labels: Dict[str, str], rows: List[Dict]) -> bytes:
    from docx import Document
    from docx.enum.section import WD_ORIENT
    from docx.shared import Pt
    d = Document()
    sec = d.sections[0]
    sec.orientation = WD_ORIENT.LANDSCAPE
    sec.page_width, sec.page_height = sec.page_height, sec.page_width
    d.add_heading(title, level=1)
    d.add_paragraph(f"{_now().strftime('%Y-%m-%d %H:%M')} UTC · {len(rows)}")
    t = d.add_table(rows=1, cols=len(columns))
    t.style = "Table Grid"
    for i, c in enumerate(columns):
        t.rows[0].cells[i].text = labels.get(c, c)
    for r in rows[:5000]:
        cells = t.add_row().cells
        for i, c in enumerate(columns):
            cells[i].text = _cell(r.get(c))
    for row in t.rows:
        for c in row.cells:
            for p in c.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(8)
    out = io.BytesIO()
    d.save(out)
    return out.getvalue()


def render(fmt: str, title: str, data: Dict, labels: Optional[Dict[str, str]] = None) -> Tuple[bytes, str, str]:
    """(bytes, content type, file name)."""
    if fmt not in FORMATS:
        raise ValueError(f"format: one of {', '.join(FORMATS)}")
    labels = labels or {}
    safe = re.sub(r"[^\w\-]+", "_", title, flags=re.UNICODE).strip("_")[:60] or "report"
    stamp = _now().strftime("%Y-%m-%d")
    if fmt == "csv":
        return to_csv(data["columns"], labels, data["rows"]), "text/csv", f"{safe}_{stamp}.csv"
    if fmt == "xlsx":
        return to_xlsx(data["columns"], labels, data["rows"], title), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", f"{safe}_{stamp}.xlsx"
    return to_docx(title, data["columns"], labels, data["rows"]), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", f"{safe}_{stamp}.docx"


# ── Saved reports and the schedule ───────────────────────────────────────────

_EMAIL = re.compile(r"[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+")


def clean_def(body: Dict) -> Dict:
    name = " ".join(str(body.get("name") or "").split())[:100]
    if not name:
        raise ValueError("a report needs a name")
    builtin = body.get("builtin") or None
    if builtin and builtin not in BUILTIN:
        raise ValueError("unknown ready-made report")
    params = None if builtin else clean_params(body.get("params") or {})
    sched = body.get("schedule") or "none"
    if sched not in SCHEDULES:
        raise ValueError(f"schedule: one of {', '.join(SCHEDULES)}")
    fmt = body.get("format") or "xlsx"
    if fmt not in FORMATS:
        raise ValueError(f"format: one of {', '.join(FORMATS)}")
    hour = int(body.get("hour") if body.get("hour") not in (None, "") else 7)
    weekday = int(body.get("weekday") if body.get("weekday") not in (None, "") else 0)
    day = int(body.get("day") if body.get("day") not in (None, "") else 1)
    if not 0 <= hour <= 23 or not 0 <= weekday <= 6 or not 1 <= day <= 28:
        raise ValueError("hour 0-23, weekday 0 (Monday) - 6, day of the month 1-28")
    rec = body.get("recipients") or []
    if isinstance(rec, str):
        rec = re.split(r"[,;\s]+", rec)
    rec = [r.strip() for r in rec if r and r.strip()]
    for r in rec:
        if not _EMAIL.fullmatch(r):
            raise ValueError(f"not an e-mail address: {r}")
    if sched != "none" and not rec:
        raise ValueError("a scheduled report needs at least one recipient")
    return {"name": name, "builtin": builtin, "params": params, "schedule": sched, "format": fmt, "hour": hour, "weekday": weekday, "day": day, "recipients": rec[:20]}


def save_def(body: Dict, rid: Optional[int], who: str) -> int:
    v = clean_def(body)
    with SessionLocal() as db:
        r = db.get(ReportDef, rid) if rid else ReportDef(created_at=_now(), created_by=(who or "")[:64])
        if rid and not r:
            raise ValueError("report not found")
        r.name, r.builtin, r.params = v["name"], v["builtin"], json.dumps(v["params"]) if v["params"] else None
        r.schedule, r.format, r.hour, r.weekday, r.day = v["schedule"], v["format"], v["hour"], v["weekday"], v["day"]
        r.recipients = json.dumps(v["recipients"])
        if not rid:
            db.add(r)
        db.commit()
        return r.id


def delete_def(rid: int) -> bool:
    with SessionLocal() as db:
        r = db.get(ReportDef, rid)
        if not r:
            return False
        db.delete(r)
        db.commit()
        return True


def defs() -> List[Dict]:
    with SessionLocal() as db:
        runs: Dict[int, List[Dict]] = {}
        for x in db.execute(select(ReportRun).order_by(ReportRun.id.desc()).limit(300)).scalars().all():
            runs.setdefault(x.report_id, []).append({"at": x.at.isoformat() + "Z", "status": x.status, "error": x.error, "rows": x.rows, "to": json.loads(x.recipients or "[]")})
        return [{"id": r.id, "name": r.name, "builtin": r.builtin, "params": json.loads(r.params) if r.params else None, "schedule": r.schedule, "format": r.format,
                 "hour": r.hour, "weekday": r.weekday, "day": r.day, "recipients": json.loads(r.recipients or "[]"), "created_by": r.created_by,
                 "last_sent_at": r.last_sent_at.isoformat() + "Z" if r.last_sent_at else None, "runs": runs.get(r.id, [])[:10]}
                for r in db.execute(select(ReportDef).order_by(ReportDef.name)).scalars().all()]


def due(r: ReportDef, now: datetime) -> bool:
    """Whether a scheduled report should be sent now (local hour of the agent's clock in UTC; once per period)."""
    if r.schedule == "none":
        return False
    if now.hour < (r.hour or 0):
        return False
    last = r.last_sent_at
    if r.schedule == "daily":
        return not last or last.date() < now.date()
    if r.schedule == "weekly":
        return now.weekday() == (r.weekday or 0) and (not last or (now.date() - last.date()).days >= 1)
    if r.schedule == "monthly":
        return now.day == (r.day or 1) and (not last or (last.year, last.month) != (now.year, now.month))
    return False


def labels_for(lang: str = "en") -> Dict[str, str]:
    """Column headings for files sent by e-mail (the page sends its own translations for downloads)."""
    pl = lang == "pl"
    base = {"name": "Nazwa" if pl else "Name", "ip": "IP", "mac": "MAC", "type": "Typ" if pl else "Type", "role": "Rola" if pl else "Role",
            "ci_class": "Klasa CI" if pl else "CI class", "stage": "Etap" if pl else "Stage", "asset_tag": "Nr inwentarzowy" if pl else "Asset tag",
            "manufacturer": "Producent" if pl else "Manufacturer", "model": "Model", "serial": "Nr seryjny" if pl else "Serial", "os": "System" if pl else "OS",
            "location": "Lokalizacja" if pl else "Location", "place": "Miejsce" if pl else "Place", "owner": "Właściciel" if pl else "Owner",
            "criticality": "Krytyczność" if pl else "Criticality", "purchased_at": "Data zakupu" if pl else "Purchased", "warranty_until": "Gwarancja do" if pl else "Warranty until",
            "replace_at": "Planowana wymiana" if pl else "Replace at", "disposed_at": "Data utylizacji" if pl else "Disposed", "disposal_method": "Sposób utylizacji" if pl else "Disposal",
            "cost": "Koszt" if pl else "Cost", "currency": "Waluta" if pl else "Currency", "supplier": "Dostawca" if pl else "Supplier",
            "invoice_no": "Nr faktury" if pl else "Invoice", "cost_center": "MPK" if pl else "Cost centre", "state": "Stan" if pl else "State",
            "first_seen": "Pierwszy raz" if pl else "First seen", "last_seen": "Ostatnio" if pl else "Last seen",
            "product": "Produkt" if pl else "Product", "vendor": "Producent / dostawca" if pl else "Vendor", "kind": "Rodzaj" if pl else "Kind",
            "seats": "Stanowiska" if pl else "Seats", "used": "W użyciu" if pl else "In use", "reclaimable": "Do odzyskania" if pl else "To reclaim",
            "over": "Ponad limit" if pl else "Over", "unused": "Niewykorzystane" if pl else "Unused", "status": "Stan" if pl else "Status",
            "valid_from": "Od" if pl else "From", "valid_until": "Do" if pl else "Until", "reference": "Nr dokumentu" if pl else "Reference",
            "title": "Tytuł" if pl else "Title", "number": "Numer" if pl else "Number", "start_at": "Od" if pl else "From", "end_at": "Do" if pl else "Until",
            "days_left": "Dni do końca" if pl else "Days left", "value": "Wartość" if pl else "Value", "auto_renew": "Auto-odnowienie" if pl else "Auto-renew",
            "assets_covered": "Zasobów" if pl else "Assets", "year": "Rok" if pl else "Year", "assets": "Zasobów" if pl else "Assets",
            "total": "Razem" if pl else "Total", "program": "Program", "installs": "Instalacje" if pl else "Installs", "versions": "Wersje" if pl else "Versions",
            "items": "Pozycji" if pl else "Items", "created_at": "Utworzono" if pl else "Created", "created_by": "Kto" if pl else "By"}
    return base


async def send(rid: int, now: Optional[datetime] = None, lang: str = "pl") -> Dict:
    """Builds a saved report and sends it to its recipients. Records the run."""
    from services import mailer
    now = now or _now()
    with SessionLocal() as db:
        r = db.get(ReportDef, rid)
        if not r:
            raise ValueError("report not found")
        name, builtin, params, fmt, rec = r.name, r.builtin, json.loads(r.params) if r.params else None, r.format, json.loads(r.recipients or "[]")
    status, error, n = "error", None, 0
    try:
        if not rec:
            raise ValueError("no recipients")
        data = build(builtin, params)
        n = data["total"]
        body, ctype, fname = render(fmt, name, data, labels_for(lang))
        text = (f"{name}\n{now.strftime('%Y-%m-%d %H:%M')} UTC\n{'Wierszy' if lang == 'pl' else 'Rows'}: {n}\n\n"
                f"{'Raport z MikroManagera w załączniku.' if lang == 'pl' else 'The MikroManager report is attached.'}")
        await mailer.send(rec, f"[MikroManager] {name}", text, [(fname, ctype, body)])
        status = "ok"
    except Exception as e:
        error = f"{type(e).__name__}: {e}"[:300]
    with SessionLocal() as db:
        db.add(ReportRun(report_id=rid, at=now, status=status, error=error, rows=n, recipients=json.dumps(rec)))
        r = db.get(ReportDef, rid)
        if r and status == "ok":
            r.last_sent_at = now
        db.commit()
    return {"status": status, "error": error, "rows": n}


async def run_due(now: Optional[datetime] = None) -> int:
    from services import mailer
    if not mailer.configured():
        return 0
    now = now or _now()
    with SessionLocal() as db:
        ids = [r.id for r in db.execute(select(ReportDef)).scalars().all() if due(r, now)]
    for i in ids:
        r = await send(i, now)
        if r["status"] != "ok":                  # a failed run is not retried until the next period (no mail storm) - the error is in the history
            with SessionLocal() as db:
                d = db.get(ReportDef, i)
                if d:
                    d.last_sent_at = now
                    db.commit()
    return len(ids)


async def _loop():
    await asyncio.sleep(300)
    while True:
        try:
            await run_due()
        except Exception as e:
            print(f"[reports] schedule error: {type(e).__name__}: {e}")
        await asyncio.sleep(TICK_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None

"""
Asset labels with a QR code, and finding an asset by what a phone scanned (docs/plan-itam.md, stage F).

A label carries the asset's name, its asset tag (stage A), the model and serial, and a QR code of the address of the asset's mobile page on this
agent: <base>/m/a/<id>. The base is the address the browser printing the labels uses (the agent does not know under which name people reach it),
checked to be a plain http(s) origin. A scan on the phone gives either that address or - from a label made elsewhere, or a barcode - the asset tag
or the serial; find() resolves all three.
"""
import base64
import io
import re
from typing import Dict, List, Optional

from sqlalchemy import func, select

from models.database import SessionLocal, Asset

_BASE = re.compile(r"https?://[A-Za-z0-9.\-]{1,253}(:\d{1,5})?")
_ASSET_URL = re.compile(r"/m/a/(\d{1,9})(?:[/?#]|$)")
MAX_LABELS = 200


def clean_base(base: Optional[str]) -> str:
    b = (base or "").strip().rstrip("/")
    if not _BASE.fullmatch(b):
        raise ValueError("base: an address like https://agent.example:8000")
    return b


def qr_svg(text: str) -> str:
    """The QR code of `text` as an SVG data URI (the same library as the two-factor setup)."""
    import qrcode
    import qrcode.image.svg
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, border=1)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


def labels(ids: List[int], base: str) -> List[Dict]:
    base = clean_base(base)
    ids = [int(i) for i in ids][:MAX_LABELS]
    if not ids:
        raise ValueError("no assets given")
    with SessionLocal() as db:
        rows = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_(ids))).scalars().all()}
    out = []
    for i in ids:
        a = rows.get(i)
        if not a:
            continue
        url = f"{base}/m/a/{a.id}"
        out.append({"id": a.id, "name": a.name or a.ip or a.key, "asset_tag": a.asset_tag, "model": a.model, "serial": a.serial,
                    "manufacturer": a.manufacturer, "location": a.location_override or a.place, "url": url, "qr": qr_svg(url)})
    return out


def find(code: str) -> Optional[int]:
    """The asset a scanned code points at: the address of its mobile page, its asset tag, or its serial number."""
    code = (code or "").strip()
    if not code or len(code) > 500:
        return None
    m = _ASSET_URL.search(code)
    with SessionLocal() as db:
        if m:
            a = db.get(Asset, int(m.group(1)))
            return a.id if a else None
        for col in (Asset.asset_tag, Asset.serial):
            a = db.execute(select(Asset).where(func.lower(col) == code.lower())).scalars().first()
            if a:
                return a.id
    return None


def search(q: str, limit: int = 30) -> List[Dict]:
    """Assets whose name, address, asset tag, serial or model contain `q` - for the phone page."""
    q = (q or "").strip().lower()
    if len(q) < 2:
        return []
    out = []
    with SessionLocal() as db:
        for a in db.execute(select(Asset)).scalars().all():
            hay = " ".join(str(x) for x in (a.name, a.ip, a.asset_tag, a.serial, a.model, a.mac) if x).lower()
            if q in hay:
                out.append({"id": a.id, "name": a.name or a.ip or a.key, "ip": a.ip, "asset_tag": a.asset_tag, "type": a.asset_type, "model": a.model})
                if len(out) >= limit:
                    break
    return out

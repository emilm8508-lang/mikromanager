from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import racks

router = APIRouter(prefix="/api/racks", tags=["racks"])


def _guard(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except racks.RackError as e:
        raise HTTPException(400, str(e))


class RackIn(BaseModel):
    name: str
    location: Optional[str] = None
    units: int = 42
    notes: Optional[str] = None


class ItemIn(BaseModel):
    u: int
    height: Optional[int] = None
    asset_id: Optional[int] = None
    kind: Optional[str] = None
    label: Optional[str] = None
    port_count: Optional[int] = None


class ItemEdit(BaseModel):
    u: Optional[int] = None
    height: Optional[int] = None
    label: Optional[str] = None
    notes: Optional[str] = None
    port_count: Optional[int] = None
    rack_id: Optional[int] = None


class LinkIn(BaseModel):
    item_a_id: int
    port_a: Optional[str] = None
    item_b_id: Optional[int] = None
    port_b: Optional[str] = None
    remote_text: Optional[str] = None
    label: Optional[str] = None
    cable: Optional[str] = None


@router.get("")
async def list_racks():
    return {"racks": racks.list_racks()}


@router.post("")
async def create_rack(body: RackIn):
    return _guard(racks.save_rack, None, body.name, body.location, body.units, body.notes)


@router.get("/palette")
async def palette(rack_id: Optional[int] = None):
    return {"assets": racks.palette(rack_id)}


@router.get("/{rack_id}")
async def get_rack(rack_id: int):
    r = racks.get_rack(rack_id)
    if r is None:
        raise HTTPException(404, "rack not found")
    return r


@router.put("/{rack_id}")
async def update_rack(rack_id: int, body: RackIn):
    return _guard(racks.save_rack, rack_id, body.name, body.location, body.units, body.notes)


@router.delete("/{rack_id}")
async def delete_rack(rack_id: int):
    if not racks.delete_rack(rack_id):
        raise HTTPException(404, "rack not found")
    return {"ok": True}


@router.get("/{rack_id}/live")
async def live(rack_id: int):
    r = await racks.live(rack_id)
    if r is None:
        raise HTTPException(404, "rack not found")
    return r


@router.post("/{rack_id}/suggested")
async def add_suggested(rack_id: int):
    return _guard(racks.add_suggested, rack_id)


@router.post("/{rack_id}/items")
async def add_item(rack_id: int, body: ItemIn):
    return _guard(racks.add_item, rack_id, body.u, body.height, body.asset_id, body.kind, body.label, body.port_count)


@router.put("/items/{item_id}")
async def update_item(item_id: int, body: ItemEdit):
    return _guard(racks.update_item, item_id, body.model_dump(exclude_unset=True, exclude_none=True))


@router.delete("/items/{item_id}")
async def delete_item(item_id: int):
    if not racks.delete_item(item_id):
        raise HTTPException(404, "item not found")
    return {"ok": True}


@router.post("/{rack_id}/links")
async def add_link(rack_id: int, body: LinkIn):
    return _guard(racks.add_link, rack_id, body.item_a_id, body.port_a, body.item_b_id, body.port_b, body.remote_text, body.label, body.cable)


@router.delete("/links/{link_id}")
async def delete_link(link_id: int):
    if not racks.delete_link(link_id):
        raise HTTPException(404, "link not found")
    return {"ok": True}

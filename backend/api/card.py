from typing import Optional

from fastapi import APIRouter

from services import last_boot

router = APIRouter(prefix="/api/card", tags=["card"])


@router.get("/resolve")
def resolve(ip: Optional[str] = None, name: Optional[str] = None):
    """The inventory asset an address or a name belongs to: {"asset_id": id | null} (for links that only know a name)."""
    return {"asset_id": last_boot.resolve(ip, name)}

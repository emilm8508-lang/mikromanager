from fastapi import APIRouter

from services import inventory

router = APIRouter(prefix="/api/inventory", tags=["inventory"])


@router.get("")
async def get_inventory():
    return inventory.build_inventory()

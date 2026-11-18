from fastapi import APIRouter, Depends

from api.auth import require_login
from services import ipam

router = APIRouter(prefix="/api/ipam", tags=["ipam"])


@router.get("")
def overview():
    """Subnets (size, used, free, the first free addresses, fixed addresses inside DHCP ranges), DHCP pools (usage, days to full) and
    address conflicts - from the last pass over the routers' tables."""
    return ipam.overview()


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await ipam.run_cycle()

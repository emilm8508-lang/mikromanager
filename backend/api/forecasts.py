from fastapi import APIRouter

from services import forecasts

router = APIRouter(prefix="/api/forecasts", tags=["forecasts"])


@router.get("")
def overview(horizon: int = 90):
    """What will run out within `horizon` days: disks, memory, DHCP pools growing steadily to full, and certificates expiring - nearest first."""
    return forecasts.overview(horizon)

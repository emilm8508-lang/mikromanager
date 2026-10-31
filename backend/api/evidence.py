from fastapi import APIRouter

from services import compliance_map

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


@router.get("")
async def evidence():
    """NIS2 art. 21(2) and ISO 27001:2022 requirements mapped onto what the application measures, with the status of every check."""
    return await compliance_map.build()

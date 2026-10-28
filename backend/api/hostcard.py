from fastapi import APIRouter, HTTPException

from services import hostcard

router = APIRouter(prefix="/api/hostcard", tags=["hostcard"])


@router.get("/{ref}")
async def card(ref: str):
    """Everything the agent knows about one host, by its address (or `a<id>` for an asset without one), put together."""
    c = await hostcard.build(ref)
    if c is None:
        raise HTTPException(404, "the application does not know this host")
    return c

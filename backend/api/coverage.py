from fastapi import APIRouter

from services import coverage

router = APIRouter(prefix="/api/coverage", tags=["coverage"])


@router.get("")
def report():
    """Every source of information of the agent with when it last worked, how often it should and its state (ok / stale / error / off)."""
    return coverage.report()

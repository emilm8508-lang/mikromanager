from fastapi import APIRouter

from services import security_summary

router = APIRouter(prefix="/api/security-summary", tags=["security-summary"])


@router.get("")
async def get_summary():
    """Everything the Security Summary dashboard shows for this agent, from the database only."""
    return await security_summary.agent_bundle()

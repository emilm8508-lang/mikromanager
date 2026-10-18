from fastapi import APIRouter

from services import topology_map

router = APIRouter(prefix="/api/netmap", tags=["netmap"])


@router.get("")
async def network_map():
    """The map of the whole network (nodes, edges, subnets). Never waits for the devices: the last map, rebuilt in the background."""
    return await topology_map.get_map()


@router.post("/refresh")
async def refresh():
    return await topology_map.get_map(force=True)

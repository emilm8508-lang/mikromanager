from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import ups_monitor

router = APIRouter(prefix="/api/ups", tags=["ups"])


class TargetBody(BaseModel):
    name: str
    ip: str
    port: int = 161
    community: Optional[str] = None          # "" removes it; never returned by any endpoint
    enabled: bool = True


class SensorBody(TargetBody):
    oid: str
    scale: float = 1.0
    unit: Optional[str] = None
    kind: str = "other"


class TestBody(BaseModel):
    ip: str
    port: int = 161
    community: Optional[str] = None


@router.get("")
def overview():
    """The UPS units with their last reading, the SNMP sensors with their last value, and the devices that look like a UPS and are not yet monitored."""
    return ups_monitor.overview()


@router.post("/test")
async def test(body: TestBody, user: dict = Depends(require_login)):
    return await ups_monitor.test_reading(body.ip, body.port, body.community)


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await ups_monitor.run_cycle()


@router.post("")
def create(body: TargetBody, user: dict = Depends(require_login)):
    try:
        return {"id": ups_monitor.save_ups(None, body.model_dump(exclude_unset=True))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/{ups_id}")
def update(ups_id: int, body: TargetBody, user: dict = Depends(require_login)):
    try:
        return {"id": ups_monitor.save_ups(ups_id, body.model_dump(exclude_unset=True))}
    except LookupError:
        raise HTTPException(404, "not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{ups_id}")
def delete(ups_id: int, user: dict = Depends(require_login)):
    if not ups_monitor.delete_ups(ups_id):
        raise HTTPException(404, "not found")
    return {"ok": True}


@router.post("/sensors")
def create_sensor(body: SensorBody, user: dict = Depends(require_login)):
    try:
        return {"id": ups_monitor.save_sensor(None, body.model_dump(exclude_unset=True))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/sensors/{sensor_id}")
def update_sensor(sensor_id: int, body: SensorBody, user: dict = Depends(require_login)):
    try:
        return {"id": ups_monitor.save_sensor(sensor_id, body.model_dump(exclude_unset=True))}
    except LookupError:
        raise HTTPException(404, "not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/sensors/{sensor_id}")
def delete_sensor(sensor_id: int, user: dict = Depends(require_login)):
    if not ups_monitor.delete_sensor(sensor_id):
        raise HTTPException(404, "not found")
    return {"ok": True}

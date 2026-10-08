from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import host_services

router = APIRouter(prefix="/api/services", tags=["host-services"])


class ServiceParams(BaseModel):
    expected_state: Optional[str] = None      # running | stopped
    interval_min: Optional[int] = None        # 1..1440
    alert_after_fails: Optional[int] = None   # 1..20 consecutive failed checks
    alert_enabled: Optional[bool] = None
    enabled: Optional[bool] = None


class ServiceItem(ServiceParams):
    name: str
    display_name: Optional[str] = None
    startup: Optional[str] = None


class AddServicesIn(BaseModel):
    services: List[ServiceItem]


def _platform(platform: str) -> str:
    if platform not in ("windows", "linux"):
        raise HTTPException(404, "unknown platform")
    return platform


def _bad(e: Exception) -> HTTPException:
    return HTTPException(404 if isinstance(e, LookupError) else 400, str(e))


@router.get("/{platform}/hosts/{host_id}")
async def list_services(platform: str, host_id: int):
    return host_services.list_services(_platform(platform), host_id)


@router.post("/{platform}/hosts/{host_id}")
async def add_services(platform: str, host_id: int, body: AddServicesIn):
    try:
        return host_services.add_services(
            _platform(platform), host_id, [s.model_dump(exclude_unset=True) for s in body.services])
    except (ValueError, LookupError) as e:
        raise _bad(e)


@router.put("/{platform}/services/{service_id}")
async def update_service(platform: str, service_id: int, body: ServiceParams):
    try:
        return host_services.update_service(_platform(platform), service_id, body.model_dump(exclude_unset=True))
    except (ValueError, LookupError) as e:
        raise _bad(e)


@router.delete("/{platform}/services/{service_id}")
async def remove_service(platform: str, service_id: int):
    try:
        return host_services.remove_service(_platform(platform), service_id)
    except LookupError as e:
        raise _bad(e)


@router.post("/{platform}/hosts/{host_id}/check")
async def check_now(platform: str, host_id: int):
    """Checks every enabled service of the host right now and returns once done."""
    res = await host_services.check_host(_platform(platform), host_id, force=True)
    if res.get("error"):
        raise HTTPException(502, res["error"])
    return res


@router.get("/{platform}/hosts/{host_id}/discover")
async def discover(platform: str, host_id: int):
    """Live read of every service on the host (read-only) — to pick from."""
    res = await host_services.discover(_platform(platform), host_id)
    if res.get("error"):
        raise HTTPException(502, res["error"])
    return res


@router.get("/{platform}/hosts/{host_id}/events")
async def events(platform: str, host_id: int, limit: int = 50):
    return {"events": host_services.list_events(_platform(platform), host_id, limit)}

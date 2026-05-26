from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from pydantic import BaseModel
from typing import Optional, List, Callable, Awaitable
from datetime import datetime
import asyncio
import aiohttp
from models.database import Device, Credential, get_db
from services.crypto import decrypt

router = APIRouter(prefix="/api/devices", tags=["devices"])


class DeviceCreate(BaseModel):
    ip: str
    name: Optional[str] = None
    api_port: int = 8728
    ssh_port: int = 22
    web_port: int = 80
    credential_id: Optional[int] = None
    notes: Optional[str] = None


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    credential_id: Optional[int] = None
    notes: Optional[str] = None
    x_pos: Optional[float] = None
    y_pos: Optional[float] = None


class DeviceOut(BaseModel):
    id: int
    ip: str
    name: Optional[str]
    mac: Optional[str]
    model: Optional[str]
    ros_version: Optional[str]
    board_name: Optional[str]
    identity: Optional[str]
    api_port: int
    ssh_port: int
    web_port: int
    has_api: bool
    has_ssh: bool
    has_web: bool
    credential_id: Optional[int]
    last_seen: Optional[datetime]
    online: bool
    notes: Optional[str]
    x_pos: float
    y_pos: float

    class Config:
        from_attributes = True


@router.get("", response_model=List[DeviceOut])
async def list_devices(db: Session = Depends(get_db)):
    return db.execute(select(Device)).scalars().all()


@router.post("", response_model=DeviceOut)
async def add_device(data: DeviceCreate, db: Session = Depends(get_db)):
    device = Device(**data.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(device_id: int, db: Session = Depends(get_db)):
    device = db.execute(select(Device).where(Device.id == device_id)).scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Not found")
    return device


@router.put("/{device_id}", response_model=DeviceOut)
async def update_device(device_id: int, data: DeviceUpdate, db: Session = Depends(get_db)):
    device = db.execute(select(Device).where(Device.id == device_id)).scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(device, field, value)
    db.commit()
    db.refresh(device)
    return device


@router.delete("/{device_id}")
async def delete_device(device_id: int, db: Session = Depends(get_db)):
    db.execute(delete(Device).where(Device.id == device_id))
    db.commit()
    return {"ok": True}


def _get_client(device_id: int, db: Session):
    from services.mikrotik_client import MikrotikClient
    row = db.execute(
        select(Device, Credential)
        .join(Credential, Device.credential_id == Credential.id)
        .where(Device.id == device_id)
    ).one_or_none()
    if not row:
        dev = db.execute(select(Device).where(Device.id == device_id)).scalar_one_or_none()
        if dev and not dev.credential_id:
            raise HTTPException(412, "Urządzenie nie ma przypisanych poświadczeń")
        raise HTTPException(404, "Urządzenie lub poświadczenia nie znalezione")
    device, cred = row
    password = decrypt(cred.password_enc)
    community = decrypt(cred.snmp_community_enc) if cred.snmp_community_enc else None
    return MikrotikClient(
        device.ip, cred.username, password,
        api_port=device.api_port, web_port=device.web_port,
        snmp_community=community, snmp_port=device.snmp_port or 161,
    ), device


async def _safe_call(coro_fn: Callable[[], Awaitable]):
    """Execute a Mikrotik client call and translate errors to user-friendly messages."""
    try:
        return await coro_fn()
    except aiohttp.ClientResponseError as e:
        if e.status == 401:
            raise HTTPException(401, "Nieprawidłowe poświadczenia (401)")
        if e.status == 403:
            raise HTTPException(403, "Brak uprawnień użytkownika do tego zasobu (403)")
        if e.status == 404:
            raise HTTPException(404, "Endpoint REST API nie istnieje — RouterOS może być starszy niż v7 lub usługa www jest wyłączona")
        raise HTTPException(502, f"HTTP {e.status} z urządzenia: {e.message}")
    except aiohttp.ClientConnectorError as e:
        raise HTTPException(503, f"Nie można połączyć się z urządzeniem ({e.os_error if hasattr(e, 'os_error') else e})")
    except aiohttp.ServerDisconnectedError:
        raise HTTPException(503, "Urządzenie zamknęło połączenie")
    except asyncio.TimeoutError:
        raise HTTPException(504, "Timeout — urządzenie nie odpowiedziało w ciągu 8s")
    except aiohttp.ClientSSLError as e:
        raise HTTPException(502, f"Błąd SSL: {e}")
    except aiohttp.ClientError as e:
        raise HTTPException(502, f"Błąd HTTP: {type(e).__name__}: {e}")
    except OSError as e:
        raise HTTPException(503, f"Błąd sieciowy: {e}")
    except Exception as e:
        raise HTTPException(500, f"{type(e).__name__}: {e}")


@router.get("/{device_id}/interfaces")
async def get_interfaces(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_interfaces)


@router.get("/{device_id}/addresses")
async def get_addresses(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_ip_addresses)


@router.get("/{device_id}/routes")
async def get_routes(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_routes)


@router.get("/{device_id}/neighbors")
async def get_neighbors(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_neighbors)


@router.get("/{device_id}/firewall")
async def get_firewall(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_firewall_rules)


@router.get("/{device_id}/wireless")
async def get_wireless(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_wireless)


@router.get("/{device_id}/dhcp-leases")
async def get_dhcp_leases(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_dhcp_leases)


@router.get("/{device_id}/tunnels")
async def get_tunnels(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_vpn_tunnels)


@router.get("/{device_id}/resource")
async def get_resource(device_id: int, db: Session = Depends(get_db)):
    client, _ = _get_client(device_id, db)
    return await _safe_call(client.get_resource)

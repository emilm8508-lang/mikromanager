from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from pydantic import BaseModel
from typing import Optional, List
from models.database import Credential, get_db
from services.crypto import encrypt

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


class CredentialCreate(BaseModel):
    name: str
    username: str
    password: str = ""  # empty allowed — RouterOS default 'admin' has no password
    snmp_community: Optional[str] = None
    description: Optional[str] = None


class CredentialOut(BaseModel):
    id: int
    name: str
    username: str
    description: Optional[str]
    has_snmp: bool  # whether community is set (we don't expose actual value)

    class Config:
        from_attributes = True


def _to_out(cred: Credential) -> dict:
    return {
        "id": cred.id,
        "name": cred.name,
        "username": cred.username,
        "description": cred.description,
        "has_snmp": bool(cred.snmp_community_enc),
    }


@router.get("", response_model=List[CredentialOut])
async def list_credentials(db: Session = Depends(get_db)):
    rows = db.execute(select(Credential)).scalars().all()
    return [_to_out(c) for c in rows]


@router.post("", response_model=CredentialOut)
async def create_credential(data: CredentialCreate, db: Session = Depends(get_db)):
    # Empty password is intentional (default Mikrotik 'admin' has none).
    # Always encrypt — even "" — so downstream code can always decrypt.
    cred = Credential(
        name=data.name,
        username=data.username,
        password_enc=encrypt(data.password or ""),
        snmp_community_enc=encrypt(data.snmp_community) if data.snmp_community else None,
        description=data.description,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return _to_out(cred)


@router.put("/{cred_id}", response_model=CredentialOut)
async def update_credential(cred_id: int, data: CredentialCreate, db: Session = Depends(get_db)):
    cred = db.execute(select(Credential).where(Credential.id == cred_id)).scalar_one_or_none()
    if not cred:
        raise HTTPException(404, "Not found")
    cred.name = data.name
    cred.username = data.username
    # For edits: empty password = "keep existing" (so user doesn't have to retype).
    # To intentionally set EMPTY password use the explicit checkbox 'allow_empty_password'
    # (sent as password="<empty>" sentinel from UI).
    if data.password == "<empty>":
        cred.password_enc = encrypt("")
    elif data.password:
        cred.password_enc = encrypt(data.password)
    # snmp_community: explicit None = clear, '' = clear, set value = update
    if data.snmp_community is None or data.snmp_community == "":
        cred.snmp_community_enc = None
    else:
        cred.snmp_community_enc = encrypt(data.snmp_community)
    cred.description = data.description
    db.commit()
    db.refresh(cred)
    return _to_out(cred)


@router.delete("/{cred_id}")
async def delete_credential(cred_id: int, db: Session = Depends(get_db)):
    db.execute(delete(Credential).where(Credential.id == cred_id))
    db.commit()
    return {"ok": True}

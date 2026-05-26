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
    password: str
    description: Optional[str] = None


class CredentialOut(BaseModel):
    id: int
    name: str
    username: str
    description: Optional[str]

    class Config:
        from_attributes = True


@router.get("", response_model=List[CredentialOut])
async def list_credentials(db: Session = Depends(get_db)):
    return db.execute(select(Credential)).scalars().all()


@router.post("", response_model=CredentialOut)
async def create_credential(data: CredentialCreate, db: Session = Depends(get_db)):
    cred = Credential(
        name=data.name,
        username=data.username,
        password_enc=encrypt(data.password),
        description=data.description,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred


@router.put("/{cred_id}", response_model=CredentialOut)
async def update_credential(cred_id: int, data: CredentialCreate, db: Session = Depends(get_db)):
    cred = db.execute(select(Credential).where(Credential.id == cred_id)).scalar_one_or_none()
    if not cred:
        raise HTTPException(404, "Not found")
    cred.name = data.name
    cred.username = data.username
    cred.password_enc = encrypt(data.password)
    cred.description = data.description
    db.commit()
    db.refresh(cred)
    return cred


@router.delete("/{cred_id}")
async def delete_credential(cred_id: int, db: Session = Depends(get_db)):
    db.execute(delete(Credential).where(Credential.id == cred_id))
    db.commit()
    return {"ok": True}

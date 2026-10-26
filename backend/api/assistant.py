from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import ai_assistant

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


class ChatBody(BaseModel):
    message: str
    session_id: Optional[str] = None


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    api_key: Optional[str] = None            # "" removes the key; never returned by any endpoint
    model: Optional[str] = None
    effort: Optional[str] = None
    scopes: Optional[Dict[str, bool]] = None
    daily_limit: Optional[int] = None
    consent: Optional[bool] = None


@router.get("/status")
def status():
    """The settings (without the key), whether the assistant is ready and, if not, why; the questions asked lately and the tokens used."""
    return {"settings": ai_assistant.public_settings(), **ai_assistant.recent_queries(30)}


@router.put("/settings")
def settings(body: SettingsBody, user: dict = Depends(require_login)):
    try:
        return ai_assistant.update_settings(body.model_dump(exclude_unset=True), str(user.get("username") or "?"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/chat")
async def chat(body: ChatBody, user: dict = Depends(require_login)):
    try:
        return await ai_assistant.chat(body.session_id, body.message, str(user.get("username") or "?"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(502, str(e))


@router.delete("/session/{session_id}")
def end_session(session_id: str, user: dict = Depends(require_login)):
    ai_assistant.reset_session(session_id)
    return {"ok": True}

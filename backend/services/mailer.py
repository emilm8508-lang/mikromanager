"""
The agent's own e-mail sending (docs/plan-itam.md, stage E): the SMTP server of the client, set on the Reports page.

Settings in data/smtp.json: host, port, security (starttls | ssl | none), user name, the password encrypted (services/crypto.py; never sent back to
the page, only "set"), the sender address and name. A test message checks them. Sending runs in a worker thread with a timeout, so a slow or
unreachable server never blocks the agent. Used by the scheduled reports (services/reports.py).
"""
import asyncio
import json
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Dict, List, Optional, Tuple

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "smtp.json")
TIMEOUT_SEC = 30
SECURITY = ("starttls", "ssl", "none")
_EMAIL = re.compile(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+")


def _load() -> Dict:
    try:
        with open(_PATH, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def settings() -> Dict:
    """For the page: everything but the password (only whether one is set)."""
    d = _load()
    return {"host": d.get("host"), "port": d.get("port"), "security": d.get("security") or "starttls", "username": d.get("username"),
            "password_set": bool(d.get("password_enc")), "from_addr": d.get("from_addr"), "from_name": d.get("from_name"), "configured": configured()}


def configured() -> bool:
    d = _load()
    return bool(d.get("host") and d.get("from_addr"))


def save(body: Dict) -> Dict:
    from services import crypto
    d = _load()
    host = str(body.get("host") or "").strip()
    if host and not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
        raise ValueError("host: a server name or address")
    port = int(body.get("port") or (465 if body.get("security") == "ssl" else 587))
    if not 1 <= port <= 65535:
        raise ValueError("port: 1-65535")
    sec = body.get("security") or "starttls"
    if sec not in SECURITY:
        raise ValueError(f"security: one of {', '.join(SECURITY)}")
    frm = str(body.get("from_addr") or "").strip()
    if frm and not _EMAIL.fullmatch(frm):
        raise ValueError("the sender is not an e-mail address")
    d.update(host=host or None, port=port, security=sec, username=(str(body.get("username") or "").strip()[:120] or None), from_addr=frm or None,
             from_name=(" ".join(str(body.get("from_name") or "").split())[:80] or None))
    if "password" in body and body["password"] is not None:          # absent / None keeps the stored one, "" clears it
        pw = str(body["password"])
        d["password_enc"] = crypto.encrypt(pw) if pw else None
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(d, f)
    return settings()


def build_message(d: Dict, to: List[str], subject: str, text: str, files: List[Tuple[str, str, bytes]]) -> EmailMessage:
    m = EmailMessage()
    m["From"] = formataddr((d.get("from_name") or "MikroManager", d["from_addr"]))
    m["To"] = ", ".join(to)
    m["Subject"] = subject.replace("\r", " ").replace("\n", " ")[:200]
    m["Message-ID"] = make_msgid(domain=d["from_addr"].split("@")[-1])
    m.set_content(text)
    for name, ctype, data in files:
        main, _, sub = (ctype or "application/octet-stream").partition("/")
        m.add_attachment(data, maintype=main, subtype=sub or "octet-stream", filename=name)
    return m


def _send_sync(to: List[str], subject: str, text: str, files: List[Tuple[str, str, bytes]]) -> None:
    from services import crypto
    d = _load()
    if not (d.get("host") and d.get("from_addr")):
        raise RuntimeError("SMTP is not set up")
    to = [t for t in to if _EMAIL.fullmatch(t)]
    if not to:
        raise ValueError("no valid recipient")
    msg = build_message(d, to, subject, text, files)
    pw = crypto.decrypt(d["password_enc"]) if d.get("password_enc") else None
    ctx = ssl.create_default_context()
    if d.get("security") == "ssl":
        s = smtplib.SMTP_SSL(d["host"], int(d.get("port") or 465), timeout=TIMEOUT_SEC, context=ctx)
    else:
        s = smtplib.SMTP(d["host"], int(d.get("port") or 587), timeout=TIMEOUT_SEC)
    try:
        s.ehlo()
        if d.get("security") == "starttls":
            s.starttls(context=ctx)
            s.ehlo()
        if d.get("username") and pw:
            s.login(d["username"], pw)
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except Exception:
            pass


async def send(to: List[str], subject: str, text: str, files: Optional[List[Tuple[str, str, bytes]]] = None) -> None:
    loop = asyncio.get_event_loop()
    await asyncio.wait_for(loop.run_in_executor(None, _send_sync, to, subject, text, files or []), timeout=TIMEOUT_SEC * 3)


async def test(to: str) -> Dict:
    try:
        await send([to], "[MikroManager] test", "This is a test message from MikroManager: the SMTP settings work.\nTo jest wiadomość testowa z MikroManagera: ustawienia SMTP działają.")
        return {"ok": True, "error": None}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}

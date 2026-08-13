import os
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", ".key")


def _get_or_create_key() -> bytes:
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


_fernet = None


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_get_or_create_key())
    return _fernet


def encrypt(plaintext: str) -> str:
    return get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    return get_fernet().decrypt(ciphertext.encode()).decode()


def key_status() -> dict:
    """When the current key was created/last rotated — the key file's own
    mtime, no separate metadata file needed — and how many fields it
    currently protects, for the "Bezpieczeństwo" page and as evidence of a
    documented key lifecycle (ISO 27001 A.8.24)."""
    from sqlalchemy import select
    from models.database import SessionLocal, Credential, AppAccount

    created_at = None
    if os.path.exists(KEY_FILE):
        created_at = datetime.utcfromtimestamp(os.path.getmtime(KEY_FILE)).isoformat()

    count = 0
    with SessionLocal() as db:
        for c in db.execute(select(Credential)).scalars().all():
            if c.password_enc:
                count += 1
            if c.snmp_community_enc:
                count += 1
        for a in db.execute(select(AppAccount)).scalars().all():
            if a.totp_secret_enc:
                count += 1

    return {"key_created_at": created_at, "encrypted_field_count": count}


def rotate_key() -> dict:
    """Generate a new Fernet key, re-encrypt every _enc field with it, and
    only swap the key file in after every row is safely committed under the
    new key — ISO 27001's "documented key lifecycle" as an actual operation,
    not just a policy doc. The old key is never archived: once rotation
    succeeds, the old key/ciphertext pairing no longer exists anywhere, so a
    leaked old key file can't be used against a backup of this database.

    All-or-nothing at the DB layer (one session, one commit) — if anything
    fails before the commit, nothing is written and the old key is still
    fully valid, safe to just retry. The one unavoidable, very small window
    is between that commit and the key-file rename (a single os.replace
    call) — a crash in exactly that instant would need a retry of the
    rename with the already-rotated ciphertext, not a full re-rotation;
    considered acceptable for a rare, manually-triggered admin action."""
    from sqlalchemy import select
    from models.database import SessionLocal, Credential, AppAccount

    old_fernet = get_fernet()
    new_key = Fernet.generate_key()
    new_fernet = Fernet(new_key)

    rotated = 0
    with SessionLocal() as db:
        for c in db.execute(select(Credential)).scalars().all():
            if c.password_enc:
                c.password_enc = new_fernet.encrypt(old_fernet.decrypt(c.password_enc.encode())).decode()
                rotated += 1
            if c.snmp_community_enc:
                c.snmp_community_enc = new_fernet.encrypt(old_fernet.decrypt(c.snmp_community_enc.encode())).decode()
                rotated += 1
        for a in db.execute(select(AppAccount)).scalars().all():
            if a.totp_secret_enc:
                a.totp_secret_enc = new_fernet.encrypt(old_fernet.decrypt(a.totp_secret_enc.encode())).decode()
                rotated += 1
        db.commit()

    tmp_path = KEY_FILE + ".new"
    with open(tmp_path, "wb") as f:
        f.write(new_key)
    os.replace(tmp_path, KEY_FILE)  # atomic on both POSIX and NTFS

    global _fernet
    _fernet = new_fernet

    return {"rotated_fields": rotated}

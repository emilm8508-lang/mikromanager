"""
Restore an agent's own state (SQLite DB + encryption key + session secret +
uplink config) from an encrypted backup downloaded from OVH.

Where the backup comes from: OVH's ovh/api.php `backup_download` action
(via the desktop "Centralny" viewer, admin role required) returns
{"created_at", "size_bytes", "envelope": {...}} — save that JSON response
to a file, or just the "envelope" object on its own; this script accepts
either shape.

What you need to run this: the downloaded backup file, and the SAME
enc_key that was configured on the agent that made the backup (Centralny
→ Agent (uplink) → E2E encryption key). Without that exact key, the
backup cannot be decrypted — there is no other way to recover it, by
design (OVH never has it either).

Usage:
    python backend/scripts/restore_backup.py <backup.json> <enc_key_b64> [--force]

Safety: this NEVER deletes anything. If backend/data/ already has content,
it's moved aside to backend/data.bak.<timestamp>/ before the restored
files are written — --force is required to proceed at all when data/
already exists, so this can't be run by accident against a live agent.
"""
import argparse
import json
import os
import shutil
import sys
import tarfile
import io
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.agent_backup import decrypt_archive, BACKUP_FILES  # noqa: E402

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_envelope(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "envelope" in data:
        return data["envelope"]
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("backup_file", help="Downloaded backup JSON (full API response or just the envelope)")
    parser.add_argument("enc_key", help="Base64 E2E encryption key (same one the agent used to create the backup)")
    parser.add_argument("--force", action="store_true", help="Required if backend/data/ already has content")
    args = parser.parse_args()

    envelope = load_envelope(args.backup_file)
    print(f"Loaded envelope: v={envelope.get('v')}, alg={envelope.get('alg')}, created_at={envelope.get('created_at')}")

    try:
        archive_bytes = decrypt_archive(envelope, args.enc_key)
    except Exception as e:
        print(f"ERROR: could not decrypt backup — wrong enc_key, or a corrupted/wrong file? ({e})")
        return 1
    print(f"Decrypted OK — {len(archive_bytes)} bytes of archive data.")

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        members = tar.getnames()
        print(f"Archive contains: {', '.join(members)}")
        if "mikrotik.db" not in members:
            print("ERROR: archive does not contain mikrotik.db — refusing to restore, this doesn't look like a valid backup.")
            return 1

        existing_files = [f for f in BACKUP_FILES if os.path.exists(os.path.join(DATA_DIR, f))]
        if existing_files and not args.force:
            print(f"backend/data/ already has: {', '.join(existing_files)}")
            print("Re-run with --force to proceed (the existing data/ will be moved aside first, never deleted).")
            return 1

        if os.path.isdir(DATA_DIR) and os.listdir(DATA_DIR):
            backup_aside = f"{DATA_DIR}.bak.{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}"
            shutil.move(DATA_DIR, backup_aside)
            print(f"Existing backend/data/ moved aside to: {backup_aside}")

        os.makedirs(DATA_DIR, exist_ok=True)
        # 'data' filter (Python 3.12+, PEP 706): rejects absolute paths,
        # path traversal, and metadata that could affect files outside
        # DATA_DIR — defense in depth even though the archive already
        # passed AES-GCM authentication (i.e. it's a real backup, not a
        # tampered one). TypeError on Python <3.12 (no filter param yet).
        try:
            tar.extractall(DATA_DIR, filter="data")
        except TypeError:
            tar.extractall(DATA_DIR)  # pre-3.12: no filter support

    print(f"\nRestored {len(members)} file(s) into {DATA_DIR}.")
    print("Next steps: restart the agent process. It will pick up the restored")
    print("database, encryption key, and uplink config exactly as they were")
    print("at backup time — including any credentials created since the backup")
    print("will be GONE (this restores to the backup's point in time, nothing newer).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

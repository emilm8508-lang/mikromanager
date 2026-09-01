"""
Uplink service — sends periodic snapshots of local agent state to a central
HTTPS endpoint (e.g. PHP+MySQL on OVH shared hosting).

Snapshot includes: device list, online/offline, model, ROS version, topology
links, recent critical logs. Sent every UPLINK_INTERVAL seconds (default 120).

On send failure, snapshots are buffered locally (up to 50) and retried.
Configuration via environment variables OR via /api/system/uplink/config.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime
from typing import Optional
import aiohttp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from models.database import SessionLocal, Device, DeviceLink, Credential
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient
from services.device_client import build_client
from services import updater
from services import alerts
from services import edge_discovery
from services import firmware_status
from services import activity
from services import changelog


# Config — can be overridden via UI/env vars
_config = {
    "url": os.environ.get("MIKROTIK_UPLINK_URL", ""),
    "tenant": os.environ.get("MIKROTIK_UPLINK_TENANT", ""),
    "api_key": os.environ.get("MIKROTIK_UPLINK_KEY", ""),
    # End-to-end encryption key (base64). If set, payload is AES-256-GCM
    # encrypted before POST. Server stores only ciphertext. Viewer needs
    # the same key to decrypt.
    "enc_key": os.environ.get("MIKROTIK_UPLINK_ENC_KEY", ""),
    "interval_sec": int(os.environ.get("MIKROTIK_UPLINK_INTERVAL", "120")),
}

_state = {
    "last_sent": None,
    "last_attempt": None,
    "last_error": None,
    "buffered_count": 0,
    "total_sent": 0,
    "total_failed": 0,
}
_buffer = []
_task: Optional[asyncio.Task] = None
_log_fetch_results: list = []


def is_configured() -> bool:
    return bool(_config["url"] and _config["tenant"] and _config["api_key"])


def api_url() -> str:
    """URL of ovh/api.php, derived from the configured ingest.php URL — both
    files are always deployed side by side (see ovh/README.md). Used for the
    per-user OVH login (services/ovh_auth.py), which is a completely
    different endpoint/credential space than the snapshot uplink itself."""
    url = _config["url"]
    if not url:
        return ""
    if "ingest.php" in url:
        return url.replace("ingest.php", "api.php")
    return url.rstrip("/") + "/api.php"


def backup_url() -> str:
    """URL of ovh/backup.php, same side-by-side deployment convention as
    api_url() above. Used by services/agent_backup.py."""
    url = _config["url"]
    if not url:
        return ""
    if "ingest.php" in url:
        return url.replace("ingest.php", "backup.php")
    return url.rstrip("/") + "/backup.php"


def status() -> dict:
    return {
        "enabled": is_configured(),
        "url": _config["url"],
        "tenant": _config["tenant"],
        "interval_sec": _config["interval_sec"],
        "has_api_key": bool(_config["api_key"]),
        "has_enc_key": bool(_config["enc_key"]),  # E2E encryption active
        **_state,
    }


def configure(url: str, tenant: str, api_key: str, interval_sec: int = 120,
              enc_key: str = "") -> dict:
    """Update uplink configuration at runtime. Persists to a small JSON file.

    Empty api_key/enc_key fields mean 'keep existing' (so user can change
    other fields without retyping secrets)."""
    _config["url"] = url
    _config["tenant"] = tenant
    if api_key:  # only overwrite if a non-empty value was provided
        _config["api_key"] = api_key
    if enc_key:
        # Validate it's base64 of 32 bytes (AES-256 key)
        try:
            raw = base64.b64decode(enc_key)
            if len(raw) != 32:
                raise ValueError(f"enc_key must be 32 bytes (got {len(raw)})")
            _config["enc_key"] = enc_key
        except Exception as e:
            raise ValueError(f"invalid enc_key: {e}")
    elif enc_key == "":
        # Empty string explicitly = keep existing
        pass
    _config["interval_sec"] = max(30, interval_sec)
    _persist()
    stop()
    start()
    return status()


def generate_enc_key() -> str:
    """Generate a fresh 32-byte AES-256-GCM key, return base64-encoded."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def get_enc_key() -> str:
    """The agent always holds its own enc_key in plaintext (it has to, to
    encrypt outgoing snapshots) — this just exposes it back to an already-
    authenticated admin who forgot to save it when it was generated. OVH
    itself never gets this value; that zero-knowledge property is unaffected."""
    return _config["enc_key"]


_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "uplink.json")


def _persist():
    import json
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    # Don't write api_key in plaintext if we encrypt — but for simplicity here we do.
    # The file is in backend/data which is .gitignored.
    with open(_CONFIG_PATH, "w") as f:
        json.dump(_config, f, indent=2)


def _load():
    import json
    if not os.path.exists(_CONFIG_PATH):
        return
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
        for k in ("url", "tenant", "api_key", "interval_sec", "enc_key"):
            if k in saved:
                _config[k] = saved[k]
    except Exception as e:
        print(f"[uplink] config load error: {e}")


async def _build_snapshot() -> dict:
    """Build current snapshot from local database + fresh log scan."""
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        links = db.execute(select(DeviceLink)).scalars().all()
        dev_list = [{
            "id": d.id,
            "ip": d.ip,
            "identity": d.identity,
            "name": d.name,
            "model": d.model,
            "ros_version": d.ros_version,
            "board_name": d.board_name,
            "vendor": d.vendor or "mikrotik",
            "online": d.online,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "has_api": d.has_api,
            "has_ssh": d.has_ssh,
            "has_web": d.has_web,
            "has_snmp": d.has_snmp,
            "api_port": d.api_port,
            "web_port": d.web_port,
        } for d in devices]
        link_list = [{
            "a": l.device_a_id,
            "b": l.device_b_id,
            "type": l.link_type,
            "iface_a": l.interface_a,
            "iface_b": l.interface_b,
        } for l in links]

    # Get critical logs (cached or fresh)
    try:
        from api import system as sys_api
        crit_logs = await sys_api.get_critical_logs(limit=30)
        if hasattr(crit_logs, "body"):  # if it's a Response object
            crit_logs = []
    except Exception:
        crit_logs = []

    git_info = updater.read_git_info()

    try:
        alert_events = await alerts.collect_alert_events()
    except Exception as e:
        print(f"[uplink] alert detection error: {e}")
        alert_events = []

    try:
        from services import vuln_scan as vuln_scan_svc
        alert_events += await vuln_scan_svc.collect_overdue_alert_events()
    except Exception as e:
        print(f"[uplink] vuln overdue alert detection error: {e}")

    try:
        alert_events += await edge_discovery.collect_wan_change_events()
    except Exception as e:
        print(f"[uplink] WAN change detection error: {e}")

    try:
        from services import tunnel_monitor
        alert_events += await tunnel_monitor.collect_tunnel_events()
    except Exception as e:
        print(f"[uplink] tunnel monitor error: {e}")

    try:
        from services import resource_monitor
        alert_events += await resource_monitor.collect_resource_events()
    except Exception as e:
        print(f"[uplink] resource monitor error: {e}")

    try:
        edge_ips = await edge_discovery.collect_public_ips()
    except Exception as e:
        print(f"[uplink] edge discovery error: {e}")
        edge_ips = []

    try:
        fw_status = await firmware_status.collect_firmware_status()
    except Exception as e:
        print(f"[uplink] firmware status error: {e}")
        fw_status = None

    # Drain any queued activity events (firmware upgrades, backups, etc.)
    try:
        activity_events = activity.drain()
    except Exception as e:
        print(f"[uplink] activity drain error: {e}")
        activity_events = []

    global _log_fetch_results
    log_fetch_results, _log_fetch_results = _log_fetch_results, []

    try:
        from services import supply_chain
        supply_chain_status = supply_chain.public_summary()
    except Exception as e:
        print(f"[uplink] supply chain summary error: {e}")
        supply_chain_status = None

    try:
        from services import vuln_scan
        # Only CRITICAL/HIGH/MEDIUM leave the agent — LOW-severity findings
        # stay purely local (still fully visible in the agent's own
        # Vulnerabilities page, which reads straight from the DB and
        # doesn't go through this function at all).
        vuln_findings_summary = await vuln_scan.hosts_with_findings(
            severities=frozenset({"CRITICAL", "HIGH", "MEDIUM"}))
    except Exception as e:
        print(f"[uplink] vuln findings summary error: {e}")
        vuln_findings_summary = []

    try:
        from services import linux_manage
        linux_hosts_status = linux_manage.public_summary()
    except Exception as e:
        print(f"[uplink] linux hosts summary error: {e}")
        linux_hosts_status = []

    try:
        from services import windows_manage
        windows_hosts_status = windows_manage.public_summary()
        windows_manage_enabled = windows_manage._manage_enabled()
    except Exception as e:
        print(f"[uplink] windows hosts summary error: {e}")
        windows_hosts_status = []
        windows_manage_enabled = False

    try:
        from services import tunnel_monitor as tunnel_monitor_svc
        tunnel_status = tunnel_monitor_svc.public_summary()
    except Exception as e:
        print(f"[uplink] tunnel status summary error: {e}")
        tunnel_status = []

    try:
        from services import dell_monitor
        dell_servers_status = dell_monitor.public_summary()
    except Exception as e:
        print(f"[uplink] dell servers summary error: {e}")
        dell_servers_status = []

    try:
        from services import inventory
        # Deliberately NOT added to _build_request_body()'s plaintext
        # envelope fields (unlike linux_hosts_status/tunnel_status/
        # supply_chain_status) — same reasoning as vuln_findings_summary
        # just above: this reveals the full internal network map (every
        # scanned host's IP, OS, open ports) plus which ones are
        # vulnerable, the single most sensitive thing this agent sends.
        # Stays inside the E2E-encrypted snapshot body only.
        inventory_summary = inventory.build_inventory()
    except Exception as e:
        print(f"[uplink] inventory summary error: {e}")
        inventory_summary = None

    return {
        "tenant": _config["tenant"],
        "sent_at": int(time.time()),
        "sent_at_iso": datetime.utcnow().isoformat(),
        "agent_version": changelog.current_version(),
        "agent_commit": git_info.get("commit"),
        "agent_commit_time": git_info.get("commit_time"),
        "agent_branch": git_info.get("branch"),
        "devices_count": len(dev_list),
        "devices_online": sum(1 for d in dev_list if d["online"]),
        "devices": dev_list,
        "links": link_list,
        "critical_logs": crit_logs,
        "alert_events": alert_events,
        "edge_ips": edge_ips,
        "firmware_status": fw_status,
        "activity_events": activity_events,
        "log_fetch_results": log_fetch_results,
        "vuln_findings_summary": vuln_findings_summary,
        "supply_chain_status": supply_chain_status,
        "linux_hosts_status": linux_hosts_status,
        "windows_hosts_status": windows_hosts_status,
        "windows_manage_enabled": windows_manage_enabled,
        "tunnel_status": tunnel_status,
        "dell_servers_status": dell_servers_status,
        "inventory_summary": inventory_summary,
    }


def _build_request_body(snapshot: dict) -> tuple:
    """Build the request body (encrypted if enc_key configured) and HMAC headers.
    Returns (body_bytes, headers_dict)."""
    plaintext = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")

    if _config["enc_key"]:
        # E2E encryption: AES-256-GCM with random 12-byte nonce.
        # Result envelope: { v: 2, alg: "aes-256-gcm", nonce: b64, ciphertext: b64 }
        # Server stores this opaquely. Only client with enc_key can decrypt.
        key = base64.b64decode(_config["enc_key"])
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        envelope = {
            "v": 2,
            "alg": "aes-256-gcm",
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            # These fields are PUBLIC metadata that server + viewer's tenant list
            # can use WITHOUT decryption. Reveal only summary + version identifiers.
            "tenant": _config["tenant"],
            "sent_at": snapshot.get("sent_at"),
            "devices_count": snapshot.get("devices_count"),
            "devices_online": snapshot.get("devices_online"),
            "agent_commit": snapshot.get("agent_commit"),
            "agent_commit_time": snapshot.get("agent_commit_time"),
            "alert_events": snapshot.get("alert_events", []),
            "edge_ips": snapshot.get("edge_ips", []),
            "firmware_status": snapshot.get("firmware_status"),
            "activity_events": snapshot.get("activity_events", []),
            "supply_chain_status": snapshot.get("supply_chain_status"),
            "linux_hosts_status": snapshot.get("linux_hosts_status", []),
            "windows_hosts_status": snapshot.get("windows_hosts_status", []),
            "windows_manage_enabled": snapshot.get("windows_manage_enabled", False),
            "tunnel_status": snapshot.get("tunnel_status", []),
            "dell_servers_status": snapshot.get("dell_servers_status", []),
        }
        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    else:
        body = plaintext

    # HMAC-SHA256 over: timestamp || body. Prevents tamper + replay.
    ts = str(int(time.time()))
    sig = hmac.new(
        _config["api_key"].encode(), (ts + "|").encode() + body,
        hashlib.sha256
    ).hexdigest()

    headers = {
        "Authorization": f"Bearer {_config['api_key']}",
        "X-Tenant": _config["tenant"],
        "X-Timestamp": ts,
        "X-Signature": sig,
        "X-Encrypted": "1" if _config["enc_key"] else "0",
        "Content-Type": "application/json",
        "User-Agent": "MikroManager-Agent/1.2",
    }
    return body, headers


async def _send_one(snapshot: dict) -> bool:
    if not is_configured():
        return False
    body, headers = _build_request_body(snapshot)
    timeout = aiohttp.ClientTimeout(total=20)
    _state["last_attempt"] = datetime.utcnow().isoformat()
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(_config["url"], data=body, headers=headers) as resp:
                if 200 <= resp.status < 300:
                    _state["last_sent"] = datetime.utcnow().isoformat()
                    _state["last_error"] = None
                    _state["total_sent"] += 1

                    # Server may include commands for us to run
                    try:
                        resp_json = await resp.json(content_type=None)
                        if _verify_commands_signature(resp_json):
                            await _handle_commands(resp_json.get("commands") or [])
                        elif resp_json.get("commands"):
                            print("[uplink] REJECTED commands: invalid/missing signature")
                    except Exception:
                        pass
                    return True
                resp_body = await resp.text()
                _state["last_error"] = f"HTTP {resp.status}: {resp_body[:200]}"
                _state["total_failed"] += 1
                return False
    except asyncio.TimeoutError:
        _state["last_error"] = "timeout"
        _state["total_failed"] += 1
        return False
    except Exception as e:
        _state["last_error"] = f"{type(e).__name__}: {e}"
        _state["total_failed"] += 1
        return False


def _canonical_commands(commands: list) -> str:
    """Must match ovh/ingest.php's canonical_commands() exactly, token for token."""
    parts = []
    for c in commands:
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, dict) and c.get("type") == "firmware_upgrade":
            device_id = int(c.get("device_id") or 0)
            backup = "1" if c.get("backup") else "0"
            parts.append(f"firmware_upgrade:{device_id}:{backup}")
        elif isinstance(c, dict) and c.get("type") == "fetch_logs":
            device_id = int(c.get("device_id") or 0)
            limit = int(c.get("limit") or 0)
            parts.append(f"fetch_logs:{device_id}:{limit}")
        elif isinstance(c, dict) and c.get("type") == "linux_apt_upgrade":
            host_id = int(c.get("host_id") or 0)
            parts.append(f"linux_apt_upgrade:{host_id}")
        elif isinstance(c, dict) and c.get("type") == "windows_update":
            host_id = int(c.get("host_id") or 0)
            parts.append(f"windows_update:{host_id}")
        elif isinstance(c, dict) and c.get("type") == "windows_restart":
            host_id = int(c.get("host_id") or 0)
            parts.append(f"windows_restart:{host_id}")
        elif isinstance(c, dict) and c.get("type") == "windows_manage_toggle":
            parts.append(f"windows_manage_toggle:{'1' if c.get('enabled') else '0'}")
        elif isinstance(c, dict) and c.get("type") == "dell_check":
            server_id = int(c.get("server_id") or 0)
            parts.append(f"dell_check:{server_id}")
        else:
            parts.append("unknown")
    return ",".join(parts)


def _verify_commands_signature(resp_json: dict) -> bool:
    """Verify central signed the commands list with our api_key. Empty/absent
    commands need no signature (nothing to execute)."""
    commands = resp_json.get("commands") or []
    if not commands:
        return True
    ts = resp_json.get("commands_ts")
    sig = resp_json.get("commands_sig")
    if not ts or not sig:
        return False
    expected = hmac.new(
        _config["api_key"].encode(), f"{ts}|{_canonical_commands(commands)}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


async def _fetch_device_logs(device_id: int, limit: int) -> None:
    """Fetch the last `limit` log lines from one device and queue the result
    to ride along on the NEXT snapshot."""
    entry = {
        "device_id": device_id,
        "requested_limit": limit,
        "fetched_at": datetime.utcnow().isoformat(),
    }
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
    if not row:
        entry["error"] = "device or credential not found"
        _log_fetch_results.append(entry)
        return

    device, cred = row
    entry["device_label"] = device.identity or device.name or device.ip
    try:
        client = build_client(device, cred)
        logs = await asyncio.wait_for(client.get_logs(limit=limit), timeout=10)
        entry["logs"] = logs[-limit:] if isinstance(logs, list) else []
    except Exception as e:
        entry["error"] = f"{type(e).__name__}: {e}"
    _log_fetch_results.append(entry)


async def _perform_restart() -> None:
    """Requested by central. Record activity event, flush one snapshot so the
    event reaches OVH, then exit cleanly — supervisor (NSSM/systemd) restarts us."""
    try:
        activity.record("agent_restart", reason="remote_request")
        snap = await _build_snapshot()
        await _send_one(snap)
    except Exception as e:
        print(f"[uplink] restart pre-flush error: {e}")
    await asyncio.sleep(1)
    print("[uplink] exiting for supervisor restart")
    os._exit(0)


async def _handle_commands(commands: list) -> None:
    """Execute commands returned by the central server in the ingest response.

    Supported commands (mixed types in one list):
      - "update"                                          — self-update the app
      - "supply_chain_scan"                                — run pip-audit/npm
        audit/Bandit/eslint-security now; result rides the next snapshot
      - "linux_scan"                                        — discover new
        Linux hosts + refresh pending-update counts for managed ones now;
        NOT gated on MIKROTIK_LINUX_MANAGE_ENABLED (read-only SSH identity/
        check-for-updates probes, no privileged command — see
        linux_apt_upgrade below for the one that is gated)
      - {"type":"firmware_upgrade","device_id":N,
         "backup":bool}                                   — upgrade Mikrotik firmware
      - {"type":"fetch_logs","device_id":N,"limit":N}      — fetch last N log
        lines from a device, delivered in the next snapshot
      - {"type":"linux_apt_upgrade","host_id":N}            — apt/dnf
        update+upgrade a managed Linux host. Respects
        MIKROTIK_LINUX_MANAGE_ENABLED locally (services/linux_manage.py,
        defaults on but can be set to "0" to opt out): a correctly signed
        command from central is NOT sufficient by itself to run privileged
        sudo commands on a client's servers if
        this agent's own operator never opted in.
      - {"type":"windows_update","host_id":N,"reason":str}   — install
        pending Windows Update on a managed Windows host. Respects
        MIKROTIK_WINDOWS_MANAGE_ENABLED locally (services/windows_manage.py,
        defaults OFF — opt-in, unlike Linux's default-on).
      - {"type":"windows_restart","host_id":N,"reason":str}  — restart a
        managed Windows host. Same MIKROTIK_WINDOWS_MANAGE_ENABLED gate.
      - {"type":"windows_manage_toggle","enabled":bool}      — flips
        WindowsManageSettings.manage_enabled locally (services/
        windows_manage.py's DB-backed override of the env var) — lets
        Central turn Windows management on/off for a tenant without
        touching that agent's OS. Deliberately NOT gated on
        _manage_enabled() itself (see below).
      - {"type":"dell_check","server_id":N}                 — re-run an
        iDRAC health check for one DellServer now (Redfish GET or a local
        WinRM iSM/RACADM query — never a write to the server), so Central
        can force a fresh read instead of waiting up to
        MIKROTIK_DELL_CHECK_MIN (default 30 min). Read-only, so unlike
        linux_apt_upgrade/windows_update there is no MANAGE_ENABLED gate.
    """
    for cmd in commands:
        if cmd == "update":
            print("[uplink] received UPDATE command from central — starting")
            asyncio.create_task(updater.perform_update(restart_supervisor=True))
        elif cmd == "restart":
            print("[uplink] received RESTART command from central — restarting")
            asyncio.create_task(_perform_restart())
        elif cmd == "supply_chain_scan":
            print("[uplink] received SUPPLY_CHAIN_SCAN command from central — starting")
            from services import supply_chain
            asyncio.create_task(supply_chain.run_scan())
        elif cmd == "linux_scan":
            print("[uplink] received LINUX_SCAN command from central — starting")
            from services import linux_manage
            asyncio.create_task(linux_manage.discover_linux_hosts())
        elif isinstance(cmd, dict):
            cmd_type = cmd.get("type")
            if cmd_type == "firmware_upgrade":
                device_id = cmd.get("device_id")
                backup = bool(cmd.get("backup", False))
                if device_id:
                    print(f"[uplink] received FIRMWARE_UPGRADE for device {device_id} (backup={backup})")
                    from services import firmware
                    asyncio.create_task(firmware.upgrade_device(int(device_id), do_backup=backup))
                else:
                    print(f"[uplink] firmware_upgrade command missing device_id: {cmd}")
            elif cmd_type == "fetch_logs":
                device_id = cmd.get("device_id")
                limit = min(int(cmd.get("limit") or 100), 500)
                if device_id:
                    print(f"[uplink] received FETCH_LOGS for device {device_id} (limit={limit})")
                    asyncio.create_task(_fetch_device_logs(int(device_id), limit))
                else:
                    print(f"[uplink] fetch_logs command missing device_id: {cmd}")
            elif cmd_type == "linux_apt_upgrade":
                host_id = cmd.get("host_id")
                from services import linux_manage
                if not linux_manage.MANAGE_ENABLED:
                    print(f"[uplink] linux_apt_upgrade received but MIKROTIK_LINUX_MANAGE_ENABLED "
                          f"is not set locally — ignoring (host_id={host_id})")
                elif host_id:
                    print(f"[uplink] received LINUX_APT_UPGRADE for host {host_id}")
                    asyncio.create_task(linux_manage.upgrade_host(int(host_id)))
                else:
                    print(f"[uplink] linux_apt_upgrade command missing host_id: {cmd}")
            elif cmd_type == "windows_update":
                host_id = cmd.get("host_id")
                reason = cmd.get("reason") or ""
                from services import windows_manage
                if not windows_manage._manage_enabled():
                    print(f"[uplink] windows_update received but Windows management "
                          f"is not enabled locally — ignoring (host_id={host_id})")
                elif host_id:
                    print(f"[uplink] received WINDOWS_UPDATE for host {host_id}")
                    asyncio.create_task(windows_manage.upgrade_host(int(host_id), reason))
                else:
                    print(f"[uplink] windows_update command missing host_id: {cmd}")
            elif cmd_type == "windows_restart":
                host_id = cmd.get("host_id")
                reason = cmd.get("reason") or ""
                from services import windows_manage
                if not windows_manage._manage_enabled():
                    print(f"[uplink] windows_restart received but Windows management "
                          f"is not enabled locally — ignoring (host_id={host_id})")
                elif host_id:
                    print(f"[uplink] received WINDOWS_RESTART for host {host_id}")
                    asyncio.create_task(windows_manage.restart_host(int(host_id), reason))
                else:
                    print(f"[uplink] windows_restart command missing host_id: {cmd}")
            elif cmd_type == "windows_manage_toggle":
                # Sets the DB-backed toggle itself — deliberately NOT gated
                # on _manage_enabled() (that would make the one command
                # that turns it ON only work when it's already on). Still
                # tenant-scoped and HMAC-signed like every other command.
                enabled = bool(cmd.get("enabled"))
                from services import windows_manage
                current = windows_manage.get_settings()
                windows_manage.set_settings(current["credential_id"], enabled)
                print(f"[uplink] received WINDOWS_MANAGE_TOGGLE — set to {enabled}")
            elif cmd_type == "dell_check":
                server_id = cmd.get("server_id")
                if server_id:
                    print(f"[uplink] received DELL_CHECK for server {server_id}")
                    from services import dell_monitor
                    asyncio.create_task(dell_monitor.check_server(int(server_id)))
                else:
                    print(f"[uplink] dell_check command missing server_id: {cmd}")
            else:
                print(f"[uplink] unknown command type: {cmd_type}")
        else:
            print(f"[uplink] unknown command: {cmd!r}")


async def send_now() -> dict:
    """Manually trigger one send. Returns result + status."""
    snapshot = await _build_snapshot()
    success = await _send_one(snapshot)
    if not success:
        _buffer.append(snapshot)
        _state["buffered_count"] = len(_buffer)
    return {"success": success, "status": status()}


async def _loop():
    global _buffer
    # Wait one interval before first try
    while True:
        try:
            await asyncio.sleep(_config["interval_sec"])
            if not is_configured():
                continue

            snapshot = await _build_snapshot()
            _buffer.append(snapshot)

            # Try to drain buffer oldest-first
            while _buffer:
                head = _buffer[0]
                if await _send_one(head):
                    _buffer.pop(0)
                else:
                    break  # keep buffered, retry next cycle

            # Cap buffer
            if len(_buffer) > 50:
                _buffer = _buffer[-50:]
            _state["buffered_count"] = len(_buffer)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[uplink] loop error: {e}")


def start():
    global _task
    _load()
    if _task is None or _task.done():
        loop = asyncio.get_event_loop()
        _task = loop.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
        _task = None

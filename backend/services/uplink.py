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
from services import uplink_spool
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
    "buffered_count": 0,         # events waiting in the spool (services/uplink_spool.py) because Central could not take them
    "failing_since": None,       # the first failed attempt of the current run of failures - Central unreachable since then
    "total_sent": 0,
    "total_failed": 0,
    "last_status": None,         # HTTP status of the last attempt that got an answer (413 = the report was too large)
    "building_since": None,      # a report is being put together (the sections are awaited one by one) - set while it lasts
    "last_build_sec": None,      # how long the last report took to build
}
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


def drp_url() -> str:
    """URL of ovh/drp.php, same side-by-side deployment convention as
    api_url()/backup_url() above. Used by services/drp_docs.py."""
    url = _config["url"]
    if not url:
        return ""
    if "ingest.php" in url:
        return url.replace("ingest.php", "drp.php")
    return url.rstrip("/") + "/drp.php"


def status() -> dict:
    return {
        "enabled": is_configured(),
        "url": _config["url"],
        "tenant": _config["tenant"],
        "interval_sec": _config["interval_sec"],
        "has_api_key": bool(_config["api_key"]),
        "has_enc_key": bool(_config["enc_key"]),  # E2E encryption active
        **_state,
        "spool": uplink_spool.stats(),
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


# One section of the snapshot (a router that does not answer, a Hyper-V host that hangs ...) must not hold back everything else: the snapshot is
# built section by section, each awaited on the network, and used to be unbounded - a handful of unreachable devices made one build last
# minutes and the agent looked silent (its status showed no attempt at all). Now:
#   - each section gets SECTION_TIMEOUT_SEC, and the whole build BUILD_BUDGET_SEC (what is left is skipped for this report);
#   - a section that runs out is NOT cancelled - it goes on in the background, so a slow shared scan (the WAN scan of all routers) still
#     finishes and fills its cache; the next report takes its result (events included, nothing is lost) instead of starting it again.
SECTION_TIMEOUT_SEC = max(15, int(os.environ.get("MIKROTIK_UPLINK_SECTION_TIMEOUT", "90")))
BUILD_BUDGET_SEC = max(60, int(os.environ.get("MIKROTIK_UPLINK_BUILD_BUDGET", "300")))
_section_tasks: dict = {}
_build_started = [0.0]


async def _bounded(coro):
    name = getattr(coro, "__qualname__", None) or getattr(getattr(coro, "cr_code", None), "co_name", "section")
    prev = _section_tasks.get(name)
    if prev is not None:
        if not prev.done():
            coro.close()
            raise TimeoutError(f"{name} is still running from an earlier report - skipped for this one")
        del _section_tasks[name]
        coro.close()
        return prev.result()                                  # finished after its report was sent: its result (events ...) is not lost
    left = BUILD_BUDGET_SEC - (time.time() - _build_started[0])
    if left <= 0:
        coro.close()
        raise TimeoutError(f"{name} skipped: the report has used its {BUILD_BUDGET_SEC}s")
    task = asyncio.ensure_future(coro)
    try:
        return await asyncio.wait_for(asyncio.shield(task), min(SECTION_TIMEOUT_SEC, left))
    except asyncio.TimeoutError:
        _section_tasks[name] = task                           # keeps running; collected by the next report
        raise TimeoutError(f"{name} took longer than {SECTION_TIMEOUT_SEC}s - continuing in the background, skipped for this report") from None


async def _build_snapshot() -> dict:
    """Build current snapshot from local database + fresh log scan."""
    _build_started[0] = time.time()
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
        crit_logs = await _bounded(sys_api.get_critical_logs(limit=30))
        if hasattr(crit_logs, "body"):  # if it's a Response object
            crit_logs = []
    except Exception:
        crit_logs = []

    git_info = updater.read_git_info()

    try:
        alert_events = await _bounded(alerts.collect_alert_events())
    except Exception as e:
        print(f"[uplink] alert detection error: {e}")
        alert_events = []

    try:
        from services import vuln_scan as vuln_scan_svc
        alert_events += await _bounded(vuln_scan_svc.collect_overdue_alert_events())
    except Exception as e:
        print(f"[uplink] vuln overdue alert detection error: {e}")

    try:
        alert_events += await _bounded(edge_discovery.collect_wan_change_events())
    except Exception as e:
        print(f"[uplink] WAN change detection error: {e}")

    try:
        alert_events += await _bounded(edge_discovery.collect_wan_link_events())
    except Exception as e:
        print(f"[uplink] WAN link status detection error: {e}")

    try:
        from services import tunnel_monitor
        alert_events += await _bounded(tunnel_monitor.collect_tunnel_events())
    except Exception as e:
        print(f"[uplink] tunnel monitor error: {e}")

    try:
        from services import hyperv_manage
        alert_events += await _bounded(hyperv_manage.collect_hyperv_events())
    except Exception as e:
        print(f"[uplink] hyperv monitor error: {e}")

    try:
        from services import host_monitor
        alert_events += await _bounded(host_monitor.collect_alert_events())
    except Exception as e:
        print(f"[uplink] host monitor alert events error: {e}")

    try:
        from services import host_services
        alert_events += await _bounded(host_services.collect_alert_events())
    except Exception as e:
        print(f"[uplink] host services alert events error: {e}")

    try:
        from services import availability
        alert_events += availability.collect_alert_events()          # devices that stopped answering (topology-aware), see services/availability.py
        from services import business_services
        alert_events += business_services.collect_alert_events()     # business services that are down or degraded
    except Exception as e:
        print(f"[uplink] availability alert events error: {e}")

    try:
        from services import resource_monitor
        alert_events += await _bounded(resource_monitor.collect_resource_events())
    except Exception as e:
        print(f"[uplink] resource monitor error: {e}")

    try:
        from services import dell_monitor
        alert_events += await _bounded(dell_monitor.collect_dell_events())
    except Exception as e:
        print(f"[uplink] dell monitor error: {e}")

    try:
        from services import prtg_monitor
        alert_events += await _bounded(prtg_monitor.collect_prtg_events())
    except Exception as e:
        print(f"[uplink] PRTG monitor error: {e}")

    try:
        from services import checkmk_monitor
        alert_events += await _bounded(checkmk_monitor.collect_checkmk_events())
    except Exception as e:
        print(f"[uplink] Check_MK monitor error: {e}")

    soc_extra: list = []      # what only the SOC layer gets (all the Wazuh alerts, also the low-level ones, with the log line)
    try:
        from services import wazuh_monitor
        alert_events += await _bounded(wazuh_monitor.collect_wazuh_events())
        soc_extra = wazuh_monitor.take_soc_events()
    except Exception as e:
        print(f"[uplink] Wazuh monitor error: {e}")

    try:
        from services import prtg_monitor
        await _bounded(prtg_monitor.collect_activity())
    except Exception as e:
        print(f"[uplink] PRTG activity error: {e}")

    try:
        edge_ips = await _bounded(edge_discovery.collect_public_ips())
    except Exception as e:
        print(f"[uplink] edge discovery error: {e}")
        edge_ips = []

    try:
        from services import edge_selfcheck
        edge_check_results = await _bounded(edge_selfcheck.check_all())
    except Exception as e:
        print(f"[uplink] edge selfcheck error: {e}")
        edge_check_results = []

    try:
        from services import edge_selfcheck
        edge_verify_results = await _bounded(edge_selfcheck.check_verify_targets())
    except Exception as e:
        print(f"[uplink] edge cross-verify error: {e}")
        edge_verify_results = []

    try:
        fw_status = await _bounded(firmware_status.collect_firmware_status())
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
        vuln_findings_summary = await _bounded(vuln_scan.hosts_with_findings(
            severities=frozenset({"CRITICAL", "HIGH", "MEDIUM"})))
    except Exception as e:
        print(f"[uplink] vuln findings summary error: {e}")
        vuln_findings_summary = []

    try:
        # Narrower (CRITICAL/HIGH only) and, unlike vuln_findings_summary
        # above, deliberately placed in the plaintext envelope below — an
        # explicit, informed tradeoff the user chose (Central visibility
        # without requiring the E2E key on every viewer), not a default.
        # See vuln_scan.public_summary()'s own comment for the full reasoning.
        vuln_findings_status = await _bounded(vuln_scan.public_summary())
    except Exception as e:
        print(f"[uplink] public vuln findings summary error: {e}")
        vuln_findings_status = []

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
        from services import hyperv_manage
        hyperv_status = hyperv_manage.public_summary()
    except Exception as e:
        print(f"[uplink] hyperv status summary error: {e}")
        hyperv_status = []

    try:
        from services import firewall_analysis
        firewall_status = firewall_analysis.public_summary()
    except Exception as e:
        print(f"[uplink] firewall analysis summary error: {e}")
        firewall_status = []

    try:
        from services import fleet
        mikrotik_fleet = fleet.public_summary()
    except Exception as e:
        print(f"[uplink] fleet summary error: {e}")
        mikrotik_fleet = None

    # Host monitoring: the name/state/outage summary goes in the plaintext
    # envelope (see _build_request_body), but the per-host details (IP, MAC,
    # switch port, recent log lines - which carry other devices' addresses)
    # stay inside the E2E-encrypted snapshot body only, like inventory_summary.
    try:
        from services import host_monitor
        hostmon_status = host_monitor.public_summary()
        hostmon_details = host_monitor.encrypted_details()
    except Exception as e:
        print(f"[uplink] host monitor summary error: {e}")
        hostmon_status, hostmon_details = [], {}

    try:
        from services import dell_monitor
        dell_servers_status = dell_monitor.public_summary()
    except Exception as e:
        print(f"[uplink] dell servers summary error: {e}")
        dell_servers_status = []

    try:
        from services import resource_monitor
        routers_status = resource_monitor.routers_public_summary()
    except Exception as e:
        print(f"[uplink] routers summary error: {e}")
        routers_status = []

    try:
        wan_link_status = edge_discovery.public_summary()
    except Exception as e:
        print(f"[uplink] wan link summary error: {e}")
        wan_link_status = []

    try:
        from services import compliance
        compliance_status = compliance.public_summary()
    except Exception as e:
        print(f"[uplink] compliance summary error: {e}")
        compliance_status = []

    try:
        from services import prtg_monitor
        prtg_status = prtg_monitor.public_summary()
    except Exception as e:
        print(f"[uplink] PRTG status summary error: {e}")
        prtg_status = []

    try:
        from services import checkmk_monitor
        checkmk_status = checkmk_monitor.public_summary()
    except Exception as e:
        print(f"[uplink] Check_MK status summary error: {e}")
        checkmk_status = {"services": [], "hosts": []}

    try:
        from services import wazuh_monitor
        wazuh_status = wazuh_monitor.public_summary()
    except Exception as e:
        print(f"[uplink] Wazuh status summary error: {e}")
        wazuh_status = []

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

    # Keep a local record of every alert event (type, device, count) for the Security Summary dashboard, and
    # summarise it - together with the all-severity vulnerability counts and the compliance totals - for Central.
    try:
        from services import security_summary
        security_summary.record_events(alert_events)
        security_stats = await _bounded(security_summary.compute())
    except Exception as e:
        print(f"[uplink] security summary error: {e}")
        security_stats = None

    # The SOC layer: every alert event becomes an alert with a life of its own (merged while it repeats, closed by its recovery event) - see
    # services/soc.py; Central gets the numbers and the open alerts in the plaintext metadata.
    try:
        from services import soc
        soc.ingest([e for e in alert_events if e.get("type") != "wazuh_alert"] + soc_extra)
        try:
            from services import soc_rules
            await _bounded(soc_rules.run_due())                  # the agent's own detection rules (each at its own interval)
        except Exception as e:
            print(f"[uplink] soc rules error: {e}")
        soc_status = soc.public_summary()
        try:
            from services import soc_risk
            soc_status["risk"] = await _bounded(soc_risk.public_summary())          # the worst devices and why, for Central's top list
        except Exception as e:
            print(f"[uplink] soc risk error: {e}")
        try:
            from services import availability, business_services
            soc_status["availability"] = availability.public_summary()          # what is down / unreachable, for Central
            soc_status["services"] = business_services.public_summary()         # the business services and their SLA
            from services import syslog_receiver
            soc_status["syslog"] = syslog_receiver.public_summary()             # whether devices' syslog / traps are received
            from services import coverage
            cov = coverage.report()
            soc_status["coverage"] = {"summary": cov["summary"], "silent": [{"n": i["name"], "s": i["state"], "items": i["stale_items"][:5]} for i in cov["items"] if i["state"] in ("stale", "error")][:20]}
            from services import config_history
            soc_status["configs"] = config_history.public_summary()             # routers whose configuration changed lately
            from services import soar
            soc_status["soar"] = soar.public_summary()                          # response actions waiting for approval
        except Exception as e:
            print(f"[uplink] availability summary error: {e}")
    except Exception as e:
        print(f"[uplink] soc error: {e}")
        soc_status = None

    # What goes to Central as alert events beyond the collectors': the alerts the agent's own detectors opened (syslog, configuration changes, the rules ...), the
    # escalations of alerts nobody has picked up - and then everything that concerns devices in planned maintenance is left out (services/maintenance.py).
    try:
        from services import soc as _soc, escalation, maintenance
        alert_events = list(alert_events) + _soc.take_new_alert_events() + escalation.collect_events()
        alert_events = maintenance.filter_events(alert_events)
    except Exception as e:
        print(f"[uplink] maintenance / escalation error: {e}")

    # Outages that should open (and, when they end, close) a ServiceDesk Plus ticket - see services/servicedesk_tickets.py
    try:
        from services import servicedesk_tickets
        servicedesk_tickets.process_events(alert_events, _config["tenant"])
    except Exception as e:
        print(f"[uplink] servicedesk tickets error: {e}")

    # The asset inventory, cut down for Central: numbers plus compact rows, no serial numbers / MAC addresses.
    try:
        from services import assets as assets_svc
        assets_status = await _bounded(assets_svc.public_summary())
    except Exception as e:
        print(f"[uplink] asset summary error: {e}")
        assets_status = None

    # The racks (placement, ports, what is plugged into what) for Central's rack view - sanitised, see racks.public_summary.
    try:
        from services import racks as racks_svc
        racks_status = await _bounded(racks_svc.public_summary())
    except Exception as e:
        print(f"[uplink] racks summary error: {e}")
        racks_status = None

    # The map of the whole network (nodes, edges) for Central's map: the last one built; asking for it also starts a rebuild in the background.
    try:
        from services import topology_map
        await topology_map.get_map()
        topology_status = topology_map.public_summary()
    except Exception as e:
        print(f"[uplink] network map error: {e}")
        topology_status = None

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
        "edge_check_results": edge_check_results,
        "edge_verify_results": edge_verify_results,
        "firmware_status": fw_status,
        "activity_events": activity_events,
        "log_fetch_results": log_fetch_results,
        "vuln_findings_summary": vuln_findings_summary,
        "vuln_findings_status": vuln_findings_status,
        "supply_chain_status": supply_chain_status,
        "linux_hosts_status": linux_hosts_status,
        "windows_hosts_status": windows_hosts_status,
        "windows_manage_enabled": windows_manage_enabled,
        "tunnel_status": tunnel_status,
        "hyperv_status": hyperv_status,
        "firewall_status": firewall_status,
        "hostmon_status": hostmon_status,
        "hostmon_details": hostmon_details,
        "mikrotik_fleet": mikrotik_fleet,
        "security_stats": security_stats,
        "assets_status": assets_status,
        "racks_status": racks_status,
        "topology_status": topology_status,
        "soc_status": soc_status,
        "dell_servers_status": dell_servers_status,
        "routers_status": routers_status,
        "wan_link_status": wan_link_status,
        "compliance_status": compliance_status,
        "prtg_status": prtg_status,
        "checkmk_status": checkmk_status,
        "wazuh_status": wazuh_status,
        "inventory_summary": inventory_summary,
    }


# Sections that Central reads only from the plaintext metadata of the envelope (never from the decrypted snapshot). With end-to-end
# encryption they used to travel twice - once in the metadata and once, base64-encoded (x 1.33), inside the ciphertext: a few hundred KB of
# racks made a big client's report cross the relay's 2 MB limit (HTTP 413 "payload too large", every report refused).
_META_ONLY = ("racks_status", "assets_status", "topology_status", "soc_status")
MAX_BODY_BYTES = int(os.environ.get("MIKROTIK_UPLINK_MAX_BYTES", str(1_900_000)))      # the relay refuses more than 2 MB
# What may be cut down, in this order (least important first), when a report is still too big: the lists inside are halved, then dropped.
_TRIM_ORDER = ("topology_status", "racks_status", "assets_status", "soc_status", "hostmon_details", "vuln_findings_status", "hostmon_status", "security_stats", "prtg_status", "wazuh_status")


def _halve(v):
    """A smaller copy of a section: lists are cut to half their length, dicts are cut inside."""
    if isinstance(v, list):
        return v[:len(v) // 2]
    if isinstance(v, dict):
        return {k: _halve(x) if isinstance(x, (list, dict)) else x for k, x in v.items()}
    return v


def _fit(snapshot: dict) -> dict:
    """The snapshot cut down until its request body fits MAX_BODY_BYTES (unchanged when it already does)."""
    body, _h = _build_request_body_raw(snapshot)
    if len(body) <= MAX_BODY_BYTES:
        return snapshot
    snap = dict(snapshot)
    trimmed = []
    for key in _TRIM_ORDER:
        for _ in range(4):
            if len(body) <= MAX_BODY_BYTES:
                break
            if snap.get(key) in (None, [], {}):
                break
            snap[key] = _halve(snap[key])
            trimmed.append(key)
            body, _h = _build_request_body_raw(snap)
        if len(body) <= MAX_BODY_BYTES:
            break
    print(f"[uplink] report was {len(_build_request_body_raw(snapshot)[0]) // 1024} KB, over the {MAX_BODY_BYTES // 1024} KB the relay accepts: "
          f"cut down to {len(body) // 1024} KB ({', '.join(dict.fromkeys(trimmed)) or 'nothing left to cut'})")
    return snap


def _build_request_body(snapshot: dict) -> tuple:
    return _build_request_body_raw(_fit(snapshot))


def _build_request_body_raw(snapshot: dict) -> tuple:
    """Build the request body (encrypted if enc_key configured) and HMAC headers.
    Returns (body_bytes, headers_dict)."""
    inner = {k: v for k, v in snapshot.items() if k not in _META_ONLY} if _config["enc_key"] else snapshot
    plaintext = json.dumps(inner, separators=(",", ":")).encode("utf-8")

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
            "edge_check_results": snapshot.get("edge_check_results", []),
            "edge_verify_results": snapshot.get("edge_verify_results", []),
            "firmware_status": snapshot.get("firmware_status"),
            "activity_events": snapshot.get("activity_events", []),
            "supply_chain_status": snapshot.get("supply_chain_status"),
            "linux_hosts_status": snapshot.get("linux_hosts_status", []),
            "windows_hosts_status": snapshot.get("windows_hosts_status", []),
            "windows_manage_enabled": snapshot.get("windows_manage_enabled", False),
            "tunnel_status": snapshot.get("tunnel_status", []),
            "hyperv_status": snapshot.get("hyperv_status", []),
            "firewall_status": snapshot.get("firewall_status", []),
            "hostmon_status": snapshot.get("hostmon_status", []),
            "mikrotik_fleet": snapshot.get("mikrotik_fleet"),
            "security_stats": snapshot.get("security_stats"),
            "assets_status": snapshot.get("assets_status"),
            "racks_status": snapshot.get("racks_status"),
            "topology_status": snapshot.get("topology_status"),
            "soc_status": snapshot.get("soc_status"),
            "dell_servers_status": snapshot.get("dell_servers_status", []),
            "routers_status": snapshot.get("routers_status", []),
            "wan_link_status": snapshot.get("wan_link_status", []),
            "compliance_status": snapshot.get("compliance_status", []),
            "prtg_status": snapshot.get("prtg_status", []),
            "checkmk_status": snapshot.get("checkmk_status", {"services": [], "hosts": []}),
            "wazuh_status": snapshot.get("wazuh_status", []),
            # Deliberately narrower than vuln_findings_summary (which stays
            # encrypted-only, CRITICAL/HIGH/MEDIUM) — CRITICAL/HIGH only,
            # an explicit user-approved tradeoff to make Central visibility
            # possible without the E2E key. See vuln_scan.public_summary().
            "vuln_findings_status": snapshot.get("vuln_findings_status", []),
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
    _state["last_status"] = None
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
                _state["last_status"] = resp.status
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


def _fleet_group_token(g: dict) -> str:
    """One Central-defined upgrade group in the signed command string. Must
    match ovh/ingest.php's fleet_group_token() exactly. Only structured values
    (ids, numbers, enums) - the free-text name is deliberately left out, same
    rule as every other free-text field in these commands."""
    import re as _re

    def num(v):
        return "-" if v is None else str(int(v))
    ids = ".".join(str(int(i)) for i in (g.get("device_ids") or []))
    once = _re.sub(r"\D", "", str(g.get("once_at") or ""))
    return ":".join([
        str(int(g.get("id") or 0)), str(int(g.get("rev") or 0)), ids or "-", g.get("channel") or "-",
        g.get("schedule_kind") or "manual", num(g.get("weekday")), num(g.get("hour")), str(int(g.get("minute") or 0)),
        once or "-", "1" if g.get("enabled") else "0", "1" if g.get("stop_on_failure") else "0", "1" if g.get("backup") else "0",
    ])


async def _soar_decide(soar, action_id: int, approve: bool) -> None:
    try:
        await soar.decide(action_id, approve, "Centrala", via="Centrala")
    except (LookupError, ValueError) as e:
        print(f"[uplink] soar_decision {action_id} not applied: {e}")
        activity.record("soar_decision_refused", action_id=action_id, error=str(e)[:120])


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
        elif isinstance(c, dict) and c.get("type") == "linux_restart":
            host_id = int(c.get("host_id") or 0)
            parts.append(f"linux_restart:{host_id}")
        elif isinstance(c, dict) and c.get("type") == "windows_update":
            host_id = int(c.get("host_id") or 0)
            parts.append(f"windows_update:{host_id}")
        elif isinstance(c, dict) and c.get("type") == "windows_restart":
            host_id = int(c.get("host_id") or 0)
            parts.append(f"windows_restart:{host_id}")
        elif isinstance(c, dict) and c.get("type") == "hyperv_vm_action":
            parts.append(f"hyperv_vm_action:{int(c.get('vm_id') or 0)}:{c.get('action') or ''}")
        elif isinstance(c, dict) and c.get("type") == "device_reboot":
            parts.append(f"device_reboot:{int(c.get('device_id') or 0)}")
        elif isinstance(c, dict) and c.get("type") == "soar_decision":
            parts.append(f"soar_decision:{int(c.get('action_id') or 0)}:{'approve' if c.get('approve') else 'reject'}")
        elif isinstance(c, dict) and c.get("type") == "soc_update":
            parts.append(f"soc_update:{int(c.get('alert_id') or 0)}:{c.get('status') or ''}")
        elif isinstance(c, dict) and c.get("type") == "rack_op":
            # the operation travels as an opaque JSON string; its SHA-256 is what is signed
            parts.append("rack_op:" + hashlib.sha256(str(c.get("op") or "").encode("utf-8")).hexdigest())
        elif isinstance(c, dict) and c.get("type") == "windows_manage_toggle":
            parts.append(f"windows_manage_toggle:{'1' if c.get('enabled') else '0'}")
        elif isinstance(c, dict) and c.get("type") == "dell_check":
            server_id = int(c.get("server_id") or 0)
            parts.append(f"dell_check:{server_id}")
        elif isinstance(c, dict) and c.get("type") == "vuln_remediation":
            product = c.get("product") or ""
            version = c.get("version") or ""
            cve_id = c.get("cve_id") or ""
            status = c.get("status") or ""
            parts.append(f"vuln_remediation:{product}|{version}|{cve_id}|{status}")
        elif isinstance(c, dict) and c.get("type") == "edge_check_targets":
            enc = ",".join(f"{t.get('ip') or ''}/{int(t.get('check_port') or 0)}" for t in (c.get("targets") or []))
            parts.append(f"edge_check_targets:{enc}")
        elif isinstance(c, dict) and c.get("type") == "edge_verify_targets":
            enc = ",".join(
                f"{int(t.get('verification_id') or 0)}:{t.get('ip') or ''}/{int(t.get('check_port') or 0)}"
                for t in (c.get("targets") or [])
            )
            parts.append(f"edge_verify_targets:{enc}")
        elif isinstance(c, dict) and c.get("type") == "fleet_groups_sync":
            parts.append("fleet_groups_sync:" + ",".join(_fleet_group_token(g) for g in (c.get("groups") or [])))
        elif isinstance(c, dict) and c.get("type") == "fleet_group_run":
            parts.append(f"fleet_group_run:{int(c.get('group_id') or 0)}")
        elif isinstance(c, dict) and c.get("type") == "device_router_override":
            device_id = int(c.get("device_id") or 0)
            # "null"/"true"/"false" as literal strings - is_router is a
            # tri-state (None clears the override back to auto-detection),
            # which a bare 0/1 int couldn't represent unambiguously.
            value = c.get("is_router")
            value_str = "null" if value is None else ("1" if value else "0")
            parts.append(f"device_router_override:{device_id}:{value_str}")
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
      - "restart"                                          — restart the agent
        process now (supervisor in run.py brings it back up)
      - "supply_chain_scan"                                — run pip-audit/npm
        audit/Bandit/eslint-security now; result rides the next snapshot
      - "linux_scan"                                        — refresh
        pending-update counts for already-managed Linux hosts now.
        Deliberately does NOT probe/try credentials against new/unknown
        IPs (that used to be discover_linux_hosts()'s behavior here, and
        showed up as a wall of SSH AuthenticationException log noise
        against unrelated devices — e.g. Mikrotik routers also listen on
        port 22 — every time Central queued this). New-host discovery
        stays agent-local only: the weekly automatic vuln_scan pass, or
        this agent's own "Skanuj sieć teraz" button. NOT gated on
        MIKROTIK_LINUX_MANAGE_ENABLED (read-only check-for-updates probes,
        no privileged command — see linux_apt_upgrade below for the one
        that is gated)
      - "windows_scan"                                       — Windows
        mirror of "linux_scan" above (refresh_managed_hosts_updates() for
        already-managed Windows hosts only). NOT gated on
        MIKROTIK_WINDOWS_MANAGE_ENABLED — same reasoning as discovery
        itself being ungated (see windows_manage.discover_windows_hosts()'s
        docstring): this is a read-only Search()/systeminfo probe, not the
        install/restart action that flag actually protects.
      - "drp_doc_generate"                                    — build the
        Mikrotik disaster-recovery Word document (services/drp_docs.py:
        one /export per non-excluded Mikrotik device) and upload it
        encrypted to Central. Read-only against every device (/export is
        a query, never a write) — no MANAGE_ENABLED gate, same reasoning
        as dell_check below.
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
      - {"type":"linux_restart","host_id":N,"reason":str}    — restart a
        managed Linux host (`shutdown -r +1`). Same
        MIKROTIK_LINUX_MANAGE_ENABLED gate as linux_apt_upgrade above.
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
      - {"type":"vuln_remediation","product":str,"version":str,
         "cve_id":str,"status":str,"note":str}               — set a
        vulnerability finding's remediation status (open/in_progress/
        accepted_risk/resolved) from Central, so a finding that's a known,
        accepted risk (e.g. "SSH needs to stay open for login") doesn't
        need every tenant's own agent UI opened just to mark it. A write
        to this agent's own VulnRemediation table only — never touches any
        host/service — so no MANAGE_ENABLED gate, same reasoning as
        windows_manage_toggle above.
      - {"type":"edge_check_targets","targets":[{"ip":str,
         "check_port":int|None}, ...]}                        — the
        tenant's current list of edge-device addresses to self-check
        (services/edge_selfcheck.py) — resent fresh every heartbeat, not a
        one-off action, so just stored for the next snapshot cycle's
        check_all() to use. No MANAGE_ENABLED gate: outbound ping/TCP
        connect to addresses OVH already tracks for this same tenant.
      - {"type":"edge_verify_targets","targets":[{"verification_id":int,
         "ip":str,"check_port":int|None}, ...]}                — addresses
        owned by OTHER tenants that OVH picked this agent (at random) to
        independently ping/TCP-check, before declaring that other
        tenant's WAN link offline (cross-tenant false-positive guard —
        see services/edge_selfcheck.py's module docstring). Same
        resent-wholesale shape as edge_check_targets. No MANAGE_ENABLED
        gate: same outbound-only ping/TCP, just to an address this agent
        doesn't otherwise know anything about beyond the bare IP/port.
      - {"type":"device_router_override","device_id":N,
         "is_router":bool|None}                                 — manually
        confirm/correct whether a device counts as a "router" for
        Central's resource-tile view (services/resource_monitor.py's
        routers_public_summary()), for when the automatic WAN-interface-
        list signal gets it wrong. None clears the override back to
        auto-detection. A write to this agent's own Device row only —
        no MANAGE_ENABLED gate, same reasoning as vuln_remediation above.
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
            asyncio.create_task(linux_manage.refresh_managed_hosts_updates())
        elif cmd == "windows_scan":
            print("[uplink] received WINDOWS_SCAN command from central — starting")
            from services import windows_manage
            asyncio.create_task(windows_manage.refresh_managed_hosts_updates())
        elif cmd == "drp_doc_generate":
            print("[uplink] received DRP_DOC_GENERATE command from central — starting")
            from services import drp_docs
            asyncio.create_task(drp_docs.generate_document())
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
            elif cmd_type == "linux_restart":
                host_id = cmd.get("host_id")
                reason = cmd.get("reason") or ""
                from services import linux_manage
                if not linux_manage.MANAGE_ENABLED:
                    print(f"[uplink] linux_restart received but MIKROTIK_LINUX_MANAGE_ENABLED "
                          f"is not set locally — ignoring (host_id={host_id})")
                elif host_id:
                    print(f"[uplink] received LINUX_RESTART for host {host_id}")
                    asyncio.create_task(linux_manage.restart_host(int(host_id), reason))
                else:
                    print(f"[uplink] linux_restart command missing host_id: {cmd}")
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
            elif cmd_type == "hyperv_vm_action":
                vm_id = cmd.get("vm_id")
                action = str(cmd.get("action") or "")
                reason = cmd.get("reason") or ""
                from services import hyperv_actions
                try:
                    if not vm_id or not action:
                        raise ValueError("vm_id and action required")
                    log_id = hyperv_actions.start_action(int(vm_id), action, reason, "Centrala")
                    print(f"[uplink] received HYPERV_VM_ACTION {action} for VM {vm_id} (action log {log_id})")
                except (PermissionError, ValueError) as e:
                    print(f"[uplink] hyperv_vm_action rejected: {e}")
            elif cmd_type == "device_reboot":
                device_id = cmd.get("device_id")
                reason = cmd.get("reason") or ""
                from services import fleet_actions
                try:
                    if not fleet_actions.ENABLED:
                        raise PermissionError("bulk device actions are switched off on this agent")
                    if not device_id:
                        raise ValueError("device_id required")
                    run_id = fleet_actions.start_run("reboot", [int(device_id)], reason, None, False, "Centrala")
                    print(f"[uplink] received DEVICE_REBOOT for device {device_id} (run {run_id})")
                except (PermissionError, ValueError) as e:
                    print(f"[uplink] device_reboot rejected: {e}")
            elif cmd_type == "soar_decision":
                from services import soar
                try:
                    action_id = int(cmd.get("action_id") or 0)
                    approve = bool(cmd.get("approve"))
                    if not action_id:
                        raise ValueError("action_id required")
                    asyncio.create_task(_soar_decide(soar, action_id, approve))
                    print(f"[uplink] received SOAR_DECISION {action_id}: {'approve' if approve else 'reject'}")
                except (PermissionError, ValueError) as e:
                    print(f"[uplink] soar_decision rejected: {e}")
            elif cmd_type == "soc_update":
                from services import soc as _soc
                try:
                    alert_id = int(cmd.get("alert_id") or 0)
                    status = str(cmd.get("status") or "")
                    if not alert_id or status not in ("ack", "in_progress", "closed", "false_positive"):
                        raise ValueError("alert_id and a status required")
                    n = _soc.update([alert_id], status=status, who="Centrala")
                    print(f"[uplink] received SOC_UPDATE alert {alert_id} -> {status} ({n} changed)")
                except (PermissionError, ValueError) as e:
                    print(f"[uplink] soc_update rejected: {e}")
            elif cmd_type == "rack_op":
                from services import racks as racks_svc
                try:
                    op = json.loads(str(cmd.get("op") or ""))
                    if not isinstance(op, dict):
                        raise ValueError("not an object")
                except ValueError as e:
                    print(f"[uplink] rack_op rejected: {e}")
                else:
                    r = racks_svc.apply_op(op)
                    print(f"[uplink] received RACK_OP {op.get('op')}: {'ok' if r['ok'] else r['error']}")
                    activity.record("rack_op_done" if r["ok"] else "rack_op_failed", op=str(op.get("op") or ""), error=r["error"])
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
            elif cmd_type == "vuln_remediation":
                product = cmd.get("product")
                version = cmd.get("version")
                cve_id = cmd.get("cve_id")
                status = cmd.get("status")
                note = cmd.get("note") or None
                if product and version and cve_id and status:
                    print(f"[uplink] received VULN_REMEDIATION for {cve_id} ({product} {version}) -> {status}")
                    from services import vuln_scan
                    try:
                        vuln_scan.set_remediation_status(product, version, cve_id, status, note,
                                                          updated_by="Centrala")
                    except ValueError as e:
                        print(f"[uplink] vuln_remediation rejected: {e}")
                else:
                    print(f"[uplink] vuln_remediation command missing required fields: {cmd}")
            elif cmd_type == "edge_check_targets":
                from services import edge_selfcheck
                targets = cmd.get("targets") or []
                edge_selfcheck.set_targets(targets)
            elif cmd_type == "edge_verify_targets":
                from services import edge_selfcheck
                targets = cmd.get("targets") or []
                edge_selfcheck.set_verify_targets(targets)
            elif cmd_type == "fleet_groups_sync":
                # Upgrade groups defined in Central, resent wholesale every
                # heartbeat (like edge_check_targets) - mirrored locally, read-only here.
                if _central_groups_enabled():
                    from services import fleet_schedule
                    stats = fleet_schedule.apply_central_groups(cmd.get("groups") or [])
                    if stats["created"] or stats["updated"] or stats["deleted"]:
                        print(f"[uplink] Central upgrade groups synced: {stats}")
            elif cmd_type == "fleet_group_run":
                group_id = cmd.get("group_id")
                if group_id and _central_groups_enabled():
                    from services import fleet_schedule
                    print(f"[uplink] received FLEET_GROUP_RUN for Central group {group_id}")
                    try:
                        fleet_schedule.run_central_group(int(group_id))
                    except Exception as e:
                        print(f"[uplink] fleet_group_run failed: {e}")
            elif cmd_type == "device_router_override":
                device_id = cmd.get("device_id")
                is_router = cmd.get("is_router")
                if device_id:
                    print(f"[uplink] received DEVICE_ROUTER_OVERRIDE for device {device_id} -> {is_router}")
                    with SessionLocal() as db:
                        d = db.get(Device, int(device_id))
                        if d:
                            d.is_router_override = is_router
                            db.commit()
                else:
                    print(f"[uplink] device_router_override command missing device_id: {cmd}")
            else:
                print(f"[uplink] unknown command type: {cmd_type}")
        else:
            print(f"[uplink] unknown command: {cmd!r}")


def _central_groups_enabled() -> bool:
    """MIKROTIK_CENTRAL_GROUPS_ENABLED=0 makes this agent ignore upgrade
    groups pushed from Central (default: on - same trust as the existing
    firmware_upgrade command, which Central can already send)."""
    return os.environ.get("MIKROTIK_CENTRAL_GROUPS_ENABLED", "1").strip().lower() not in ("0", "false", "no")


async def _deliver(snapshot: dict) -> bool:
    """One attempt to send a report. The events that could not be delivered before (the spool) go in front of this report's own; they leave the spool only
    when the report is accepted, and the report's own events enter it when it is not - so nothing a failed attempt carried is lost, also over a restart."""
    waiting_alerts, waiting_activity = uplink_spool.peek()
    own_alerts = list(snapshot.get("alert_events") or [])
    own_activity = list(snapshot.get("activity_events") or [])
    snapshot["alert_events"] = waiting_alerts + own_alerts
    snapshot["activity_events"] = waiting_activity + own_activity
    ok = await _send_one(snapshot)
    if ok:
        uplink_spool.ack(len(waiting_alerts), len(waiting_activity))
        _state["failing_since"] = None
    else:
        if _state.get("failing_since") is None:
            _state["failing_since"] = _state.get("last_attempt")
        if _state.get("last_status") == 413 and (waiting_alerts or waiting_activity):
            # the relay refused the report as too large: the backlog was part of the reason, and sending it again can never work - give that chunk up
            uplink_spool.ack(len(waiting_alerts), len(waiting_activity))
            uplink_spool.note_dropped(len(waiting_alerts) + len(waiting_activity))
            print("[uplink] gave up a chunk of waiting events the relay refused as too large")
        uplink_spool.add(own_alerts, own_activity)
        for entry in snapshot.get("log_fetch_results") or []:                 # the answers to a request for a device's log are one-off as well
            if len(_log_fetch_results) < 20:
                _log_fetch_results.append(entry)
    s = uplink_spool.stats()
    _state["buffered_count"] = s["alerts"] + s["activity"]
    return ok


async def _cycle() -> bool:
    """Builds a report and sends it (with the waiting events); True when Central took it."""
    _state["building_since"] = datetime.utcnow().isoformat() + "Z"
    t_build = time.time()
    try:
        snapshot = await _build_snapshot()
    finally:
        _state["building_since"] = None
    _state["last_build_sec"] = round(time.time() - t_build, 1)
    return await _deliver(snapshot)


async def send_now() -> dict:
    """Manually trigger one send. Returns result + status."""
    success = await _cycle()
    return {"success": success, "status": status()}


async def _loop():
    # Wait one interval before first try
    while True:
        try:
            await asyncio.sleep(_config["interval_sec"])
            if not is_configured():
                continue
            await _cycle()
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

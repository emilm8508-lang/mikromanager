"""
Mikrotik firewall rule-usage + firewall-log activity summaries for
Central visibility — two of the three "firewall analysis" pieces added
locally (2.38): rule hit-count analysis (DeviceDetail's Firewall tab) and
firewall-only log filtering (Logi page). This module periodically
persists a per-device SUMMARY of both, so Central (which never has a
live connection to any device) can show something too, on its own
dedicated pages — not just the local agent's live, on-demand views.

Runs on resource_monitor.py's existing hourly Mikrotik poll cadence
(DEVICE_RESOURCE_CHECK_MIN) — one extra lightweight REST round trip per
device (/ip/firewall/filter, /ip/firewall/nat, /log), same cost class as
everything else that cycle already does. Deliberately a SEPARATE
connection from resource_monitor.py's own _poll_device_logs() (which
already fetches /log for critical/error alerting) rather than reaching
into that function — keeps the two systems decoupled, at the cost of one
extra /log fetch per device per hour, a cheap trade for not risking the
existing, working critical-log alerting path.

The firewall-log parsing regex mirrors frontend/src/pages/Logs.tsx's
parseFirewallLog() — same RouterOS message format, same capture groups.
Kept in sync by hand since one is TS and the other Python (no shared
source) — a mismatch here just means a firewall log entry falls back to
"unparsed" (silently excluded from the summary), never a crash.
"""
import asyncio
import json
import re
from collections import Counter
from datetime import datetime
from typing import Optional
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential, DeviceFirewallAnalysis
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient

_CHECK_TIMEOUT_SEC = 15
MAX_UNUSED_LABELS = 50
MAX_RECENT_LOGS = 20
MAX_TOP_SOURCES = 5

# Mirrors Logs.tsx's FW_LOG_RE exactly — see this module's docstring.
_FW_LOG_RE = re.compile(
    r"^(\w+):\s*(?:in:([^\s,]+)\s*)?(?:out:([^\s,]+)\s*)?,?\s*proto (\S+)[^,]*,\s*"
    r"([\d.]+)(?::(\d+))?->([\d.]+)(?::(\d+))?"
)


def _rule_active(r) -> bool:
    return isinstance(r, dict) and str(r.get("disabled", "false")).lower() not in ("true", "yes")


def _num(v) -> float:
    """-1 (never "0 packets") for an unparsable value — a field RouterOS
    didn't return must never be silently misread as "this rule is unused",
    the one wrong-direction mistake this module can't afford."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return -1


def _rule_label(r: dict) -> str:
    bits = [str(r.get("chain", "?")), str(r.get("action", "?"))]
    if r.get("dst-port"):
        bits.append(f"dport {r['dst-port']}")
    if r.get("protocol"):
        bits.append(str(r["protocol"]))
    if r.get("src-address"):
        bits.append(f"src {r['src-address']}")
    if r.get("dst-address"):
        bits.append(f"dst {r['dst-address']}")
    if r.get("comment"):
        bits.append(f'"{r["comment"]}"')
    return " · ".join(bits)


def _summarize_rule_usage(filter_rows: list, nat_rows: list) -> dict:
    rows = [r for r in (filter_rows or []) + (nat_rows or []) if isinstance(r, dict)]
    active = [r for r in rows if _rule_active(r)]
    unused = [r for r in active if _num(r.get("packets")) == 0]
    return {
        "rules_active": len(active),
        "rules_unused": len(unused),
        "unused_rule_labels": [_rule_label(r) for r in unused[:MAX_UNUSED_LABELS]],
    }


def _summarize_firewall_logs(logs: list) -> dict:
    parsed_entries = []
    sources: Counter = Counter()
    for entry in (logs or []):
        if not isinstance(entry, dict):
            continue
        topics = (entry.get("topics") or "").lower()
        if "firewall" not in topics:
            continue
        message = entry.get("message") or ""
        m = _FW_LOG_RE.match(message)
        if not m:
            continue
        chain, in_iface, out_iface, proto, src, sport, dst, dport = m.groups()
        sources[src] += 1
        parsed_entries.append({
            "time": entry.get("time"), "chain": chain, "proto": proto,
            "src": src, "src_port": sport, "dst": dst, "dst_port": dport,
        })
    top_sources = [{"ip": ip, "count": c} for ip, c in sources.most_common(MAX_TOP_SOURCES)]
    return {
        "log_count": len(parsed_entries),
        "log_top_sources": top_sources,
        "log_recent": parsed_entries[-MAX_RECENT_LOGS:],
    }


def _persist_error(device_id: int, error: str, now: datetime) -> None:
    with SessionLocal() as db:
        row = db.execute(
            select(DeviceFirewallAnalysis).where(DeviceFirewallAnalysis.device_id == device_id)
        ).scalar_one_or_none()
        if not row:
            row = DeviceFirewallAnalysis(device_id=device_id)
            db.add(row)
        row.last_status, row.last_error, row.checked_at = "error", error, now
        db.commit()


async def _poll_one_device(device_id: int) -> None:
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return
        device, cred = row
        ip, api_port, web_port = device.ip, device.api_port, device.web_port
        username = cred.username
        try:
            password = decrypt(cred.password_enc)
        except Exception as e:
            _persist_error(device_id, f"credential decrypt error: {e}", datetime.utcnow())
            return

    now = datetime.utcnow()
    try:
        client = MikrotikClient(ip, username, password, api_port=api_port, web_port=web_port)
        fw = await asyncio.wait_for(client.get_firewall_rules(), timeout=_CHECK_TIMEOUT_SEC)
        logs = await asyncio.wait_for(client.get_logs(limit=200), timeout=_CHECK_TIMEOUT_SEC)
    except Exception as e:
        _persist_error(device_id, str(e), now)
        return

    usage = _summarize_rule_usage(fw.get("filter") or [], fw.get("nat") or [])
    logsum = _summarize_firewall_logs(logs)

    with SessionLocal() as db:
        row = db.execute(
            select(DeviceFirewallAnalysis).where(DeviceFirewallAnalysis.device_id == device_id)
        ).scalar_one_or_none()
        if not row:
            row = DeviceFirewallAnalysis(device_id=device_id)
            db.add(row)
        row.checked_at = now
        row.rules_active = usage["rules_active"]
        row.rules_unused = usage["rules_unused"]
        row.unused_rule_labels = json.dumps(usage["unused_rule_labels"])
        row.log_count = logsum["log_count"]
        row.log_top_sources = json.dumps(logsum["log_top_sources"])
        row.log_recent = json.dumps(logsum["log_recent"])
        row.last_status, row.last_error = "ok", None
        db.commit()


async def refresh_all_devices() -> dict:
    """Called from resource_monitor.py's existing hourly Mikrotik loop,
    alongside (not instead of) its own device resource/critical-log poll."""
    with SessionLocal() as db:
        devices = db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
        ids = [d.id for d in devices if (d.vendor or "mikrotik").lower() == "mikrotik"]

    sem = asyncio.Semaphore(5)
    checked = 0

    async def _bounded(did):
        nonlocal checked
        async with sem:
            try:
                await _poll_one_device(did)
                checked += 1
            except Exception as e:
                print(f"[firewall_analysis] poll error for device {did}: {e}")

    await asyncio.gather(*[_bounded(i) for i in ids])
    return {"checked": checked, "total": len(ids)}


def list_devices() -> list:
    """For the local agent's own API (not currently surfaced in a local
    page, but kept symmetric with hyperv_manage.py/linux_manage.py's own
    list_hosts() in case a local view is added later)."""
    with SessionLocal() as db:
        rows = db.execute(
            select(DeviceFirewallAnalysis, Device).join(Device, DeviceFirewallAnalysis.device_id == Device.id)
        ).all()
        return [_row_to_dict(fa, device) for fa, device in rows]


def _row_to_dict(fa: DeviceFirewallAnalysis, device: Device) -> dict:
    return {
        "device_id": device.id, "device_name": device.identity or device.name or device.ip,
        "checked_at": fa.checked_at.isoformat() if fa.checked_at else None,
        "rules_active": fa.rules_active, "rules_unused": fa.rules_unused,
        "unused_rule_labels": json.loads(fa.unused_rule_labels or "[]"),
        "log_count": fa.log_count,
        "log_top_sources": json.loads(fa.log_top_sources or "[]"),
        "log_recent": json.loads(fa.log_recent or "[]"),
        "last_status": fa.last_status, "last_error": fa.last_error,
    }


def public_summary() -> list:
    """Redacted per-device summary for the snapshot's plaintext envelope —
    mirrors hyperv_manage.py/linux_manage.py's own public_summary()
    exactly. Capped lists only (never the full raw rule set or full log
    text) — this is meant for an at-a-glance Central view, not a full
    export. Only successfully-checked devices (an error here is not
    actionable for Central, same reasoning as elsewhere)."""
    with SessionLocal() as db:
        rows = db.execute(
            select(DeviceFirewallAnalysis, Device)
            .join(Device, DeviceFirewallAnalysis.device_id == Device.id)
            .where(DeviceFirewallAnalysis.last_status == "ok")
        ).all()
        return [_row_to_dict(fa, device) for fa, device in rows]

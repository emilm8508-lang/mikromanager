"""
Detection rules of the agent itself - what the SOC layer (services/soc.py) looks for in the data the agent already collects, on top of the events
the monitors and the connected systems raise.

A rule is a small function that looks at the current state (the inventory, the open ports of the hosts, the vulnerabilities, the hardening checks ...) and
returns the findings that make an alert. The engine does the rest, the same for every rule:

  - it runs a rule at its own interval (not on every report cycle) and survives a rule that fails (logged, retried later);
  - the first run of a rule is a baseline: what is already there is "known", not an alert (turning the SOC on must not flood anybody with everything that
    has been wrong for months);
  - a thing alerts once: a finding's fingerprint is remembered (`emitted`, forgotten after FORGET_DAYS), so a closed alert does not come back each cycle;
    to see a thing again an analyst reopens it or it has to go away for long;
  - a burst (more than BURST new findings in one run - a whole new range was scanned) is one alert that says how many, not hundreds;
  - a rule can be switched off (data/soc_rules.json); state lives in data/soc_rules_state.json.

The alerts are the ordinary SocAlert rows (rule id "rule.<id>"), so they get the same triage, history and Central view as everything else.
"""
import asyncio
import inspect
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Awaitable, Callable, Dict, List, Optional, Union

from sqlalchemy import select

from models.database import SessionLocal, Asset, VulnHost, VulnService, LinuxHost, WindowsHost, Device, ComplianceCheckResult
from services import soc

_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
STATE_PATH = os.path.join(_DIR, "soc_rules_state.json")
CONFIG_PATH = os.path.join(_DIR, "soc_rules.json")
FORGET_DAYS = 90
BURST = 25
RUN_TIMEOUT_SEC = 120
RETRY_SEC = 300

# ports whose appearance on a host is worth a closer look
RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 135: "MS RPC", 139: "NetBIOS", 445: "SMB", 1433: "MS SQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
               3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    mitre: Optional[str]
    interval: int
    run: Callable[[dict], Union[List[dict], Awaitable[List[dict]]]]
    title: str                 # English fallback; the page translates by "rule.<id>"
    description: str


# ── State and settings ───────────────────────────────────────────────────────

def _read(path: str, default):
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
            return v if isinstance(v, type(default)) else default
    except Exception:
        return default


def _write(path: str, value) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError as e:
        print(f"[soc_rules] could not save {os.path.basename(path)}: {e}")


def _disabled() -> set:
    return set(_read(CONFIG_PATH, {}).get("disabled", []))


# ── The rules ────────────────────────────────────────────────────────────────

def _rule_new_device(ctx: dict) -> List[dict]:
    """Every asset that appeared lately: a device nobody has seen on the network before. Closing the alert is the approval."""
    since = ctx["now"] - timedelta(days=30)
    with SessionLocal() as db:
        rows = db.execute(select(Asset).where(Asset.first_seen_at >= since)).scalars().all()
    out = []
    for a in rows:
        out.append({"fp": a.key, "device": a.name or a.ip or a.key, "ip": a.ip, "asset_id": a.id,
                    "detail": {"ip": a.ip, "mac": a.mac, "manufacturer": a.manufacturer, "model": a.model, "asset_type": a.asset_type, "os": a.os_name,
                               "first_seen": a.first_seen_at.isoformat() + "Z" if a.first_seen_at else None}})
    return out


def _rule_new_port(ctx: dict) -> List[dict]:
    """A host that had a known set of open ports opens a new one (a risky one - RDP, SMB, Telnet, a database - is flagged higher)."""
    prev: Dict[str, List[int]] = ctx["data"].setdefault("ports", {})
    with SessionLocal() as db:
        hosts = {h.id: h.ip for h in db.execute(select(VulnHost)).scalars().all()}
        now_ports: Dict[str, List[int]] = {}
        for s in db.execute(select(VulnService)).scalars().all():
            ip = hosts.get(s.host_id)
            if ip:
                now_ports.setdefault(ip, []).append(s.port)
        # a host seen for the first time is the new-device rule's business
        new = [(ip, p) for ip, ports in now_ports.items() if ip in prev for p in sorted(set(ports) - set(prev[ip]))]
        names = {}
        for ip in {ip for ip, _p in new}:
            a = db.execute(select(Asset).where(Asset.ip == ip).limit(1)).scalars().first()
            if a:
                names[ip] = (a.name, a.id)
    out = []
    for ip, p in new:
        name, aid = names.get(ip, (None, None))
        risky = RISKY_PORTS.get(p)
        out.append({"fp": f"{ip}:{p}", "device": name or ip, "ip": ip, "asset_id": aid, "severity": "medium" if risky else "low",
                    "detail": {"ip": ip, "port": p, "service": risky or None}})
    ctx["data"]["ports"] = {ip: sorted(set(p)) for ip, p in now_ports.items()}
    return out


async def _rule_new_vuln(ctx: dict) -> List[dict]:
    """A critical or high vulnerability that was not on the host before (a new CVE, or a new host with one)."""
    from services import vuln_scan
    out = []
    for h in await vuln_scan.hosts_with_findings(severities=frozenset({"CRITICAL", "HIGH", "MEDIUM"})):
        for f in h["findings"]:
            if (f.get("status") or "open") not in ("open", "in_progress"):
                continue
            kev = bool(f.get("kev"))
            if f["severity"] not in ("CRITICAL", "HIGH") and not kev:
                continue                                  # a medium one only when it is being exploited in attacks
            detail = {"ip": h["ip"], "cve": f["cve_id"], "vuln_severity": f["severity"], "cvss": f.get("cvss_score"),
                      "product": f.get("product"), "version": f.get("version"), "description": (f.get("summary") or "")[:240]}
            if kev:
                detail["exploited"] = "CISA KEV"
            if f.get("epss"):
                detail["epss"] = f"{round(f['epss'] * 100)}%"
            out.append({"fp": f"{h['ip']}|{f['cve_id']}", "device": h.get("device_name") or h["ip"], "ip": h["ip"],
                        "severity": "critical" if kev else "high" if f["severity"] == "CRITICAL" else "medium", "detail": detail})
    return out


def _rule_mac_changed(ctx: dict) -> List[dict]:
    """An address that is now answered by a different network card than before: a replaced device, a DHCP address given to another one - or ARP spoofing.
    Not reported when the old card is still around under another address (the device only moved)."""
    macs: Dict[str, List[str]] = ctx["data"].setdefault("macs", {})
    with SessionLocal() as db:
        rows = db.execute(select(Asset).where(Asset.ip.is_not(None), Asset.mac.is_not(None))).scalars().all()
    by_mac: Dict[str, set] = {}
    for a in rows:
        by_mac.setdefault(a.mac.upper(), set()).add(a.ip)
    out = []
    for a in rows:
        mac = a.mac.upper()
        known = macs.get(a.ip)
        if known is not None and mac not in known:
            moved = [m for m in known if len(by_mac.get(m, set()) - {a.ip}) > 0]
            if not moved:
                out.append({"fp": f"{a.ip}|{known[-1]}|{mac}", "device": a.name or a.ip, "ip": a.ip, "asset_id": a.id,
                            "detail": {"ip": a.ip, "mac": mac, "previous_mac": known[-1], "manufacturer": a.manufacturer}})
        if known is None or mac not in known:
            macs[a.ip] = (known or []) + [mac]
            macs[a.ip] = macs[a.ip][-5:]
    return out


def _rule_compliance_regression(ctx: dict) -> List[dict]:
    """A hardening check that passed and now fails (a changed setting, a weakened policy). Checks that were failing from the start are not news."""
    failed_before: List[str] = ctx["data"].get("failed", [])
    first = not ctx["data"].get("_init")
    with SessionLocal() as db:
        rows = db.execute(select(ComplianceCheckResult).where(ComplianceCheckResult.passed.is_(False))).scalars().all()
        names: Dict[tuple, str] = {}
        for h in db.execute(select(LinuxHost)).scalars().all():
            names[("linux", h.id)] = h.hostname or h.ip
        for h in db.execute(select(WindowsHost)).scalars().all():
            names[("windows", h.id)] = h.hostname or h.ip
        for d in db.execute(select(Device)).scalars().all():
            names[("mikrotik", d.id)] = d.identity or d.name or d.ip
    now_failed = {f"{r.target_type}:{r.target_id}:{r.check_id}": r for r in rows}
    out = []
    if not first:
        for key, r in now_failed.items():
            if key in failed_before or (r.severity or "low").lower() not in ("high", "medium"):
                continue
            out.append({"fp": key, "device": names.get((r.target_type, r.target_id)) or f"{r.target_type} #{r.target_id}",
                        "severity": "medium" if (r.severity or "").lower() == "high" else "low",
                        "detail": {"check": r.title, "check_id": r.check_id, "description": (r.detail or "")[:240]}})
    ctx["data"]["failed"] = sorted(now_failed)
    ctx["data"]["_init"] = True
    return out


RULES: List[Rule] = [
    Rule("new_device", "network", "medium", "T1200", 600, _rule_new_device, "New device on the network",
         "A device that has never been seen on the network appeared in the inventory. Closing the alert approves it."),
    Rule("new_port", "network", "low", None, 900, _rule_new_port, "New open port on a host",
         "A host with a known set of open ports opened a new one; RDP, SMB, Telnet, databases and the like are rated higher."),
    Rule("new_vuln", "vulnerability", "high", None, 1800, _rule_new_vuln, "New critical or high vulnerability",
         "A critical or high CVE that was not on the host before: a new CVE for what runs there, or a new host that has one."),
    Rule("mac_changed", "network", "medium", "T1557.002", 600, _rule_mac_changed, "Address answered by a different network card",
         "An address now belongs to another network card than before - a replaced device, a reused DHCP address, or ARP spoofing."),
    Rule("compliance_regression", "system", "medium", None, 1800, _rule_compliance_regression, "Hardening check started failing",
         "A configuration check that passed now fails: a changed setting or a weakened policy."),
]
_BY_ID = {r.id: r for r in RULES}


# ── The engine ───────────────────────────────────────────────────────────────

async def _call(rule: Rule, ctx: dict) -> List[dict]:
    if inspect.iscoroutinefunction(rule.run):
        return await asyncio.wait_for(rule.run(ctx), timeout=RUN_TIMEOUT_SEC)
    return await asyncio.wait_for(asyncio.get_event_loop().run_in_executor(None, rule.run, ctx), timeout=RUN_TIMEOUT_SEC)


async def _run_rule(rule: Rule, st: dict, now: datetime) -> dict:
    """One run of one rule against its state `st` (modified in place). Returns {"findings", "new", "raised"}."""
    ctx = {"now": now, "data": st.setdefault("data", {})}
    findings = await _call(rule, ctx)
    first = not st.get("baselined")
    emitted: Dict[str, float] = st.setdefault("emitted", {})
    ts = time.time()
    fresh = [f for f in findings if f.get("fp") and f["fp"] not in emitted]
    for f in fresh:
        emitted[f["fp"]] = ts
    raised = 0
    if not first and fresh:
        if len(fresh) > BURST:
            soc.raise_alert(rule=f"rule.{rule.id}", device=None, title=rule.title, severity=rule.severity, category=rule.category,
                            fp_detail=f"burst|{int(ts)}", mitre=rule.mitre, count=len(fresh), now=now,
                            detail={"count": len(fresh), "examples": ", ".join(str(f.get("device")) for f in fresh[:8]) + " ..."})
            raised = 1
        else:
            for f in fresh:
                soc.raise_alert(rule=f"rule.{rule.id}", device=f.get("device"), title=rule.title, severity=f.get("severity") or rule.severity,
                                category=rule.category, fp_detail=f["fp"], ip=f.get("ip"), detail=f.get("detail"), mitre=rule.mitre,
                                asset_id=f.get("asset_id"), now=now)
                raised += 1
    for k in [k for k, v in emitted.items() if ts - v > FORGET_DAYS * 86400]:
        del emitted[k]
    st["baselined"] = True
    st["last_run"] = ts
    st["last_ok"] = ts
    st["last_error"] = None
    st["last_new"] = len(fresh)
    return {"findings": len(findings), "new": len(fresh), "raised": raised, "baseline": first}


async def run_due(now: Optional[datetime] = None, only: Optional[str] = None, force: bool = False) -> dict:
    """Runs the rules that are due (all of them with force, or just `only`). Never raises: a rule that fails is logged and tried again later."""
    now = now or datetime.utcnow()
    state: Dict[str, dict] = _read(STATE_PATH, {})
    off = _disabled()
    result: Dict[str, dict] = {}
    for rule in RULES:
        if only and rule.id != only:
            continue
        if rule.id in off and not only:
            continue
        st = state.setdefault(rule.id, {})
        if not force and time.time() - st.get("last_run", 0) < rule.interval:
            continue
        try:
            result[rule.id] = await _run_rule(rule, st, now)
        except Exception as e:
            st["last_run"] = time.time() - rule.interval + RETRY_SEC       # try again in a few minutes, not at the next cycle
            st["last_error"] = f"{type(e).__name__}: {e}"[:300]
            print(f"[soc_rules] {rule.id} failed: {st['last_error']}")
            result[rule.id] = {"error": st["last_error"]}
    if result:
        _write(STATE_PATH, state)
    return result


# ── For the page ─────────────────────────────────────────────────────────────

def list_rules() -> List[dict]:
    state = _read(STATE_PATH, {})
    off = _disabled()
    out = []
    for r in RULES:
        st = state.get(r.id, {})
        out.append({"id": r.id, "title": r.title, "description": r.description, "category": r.category, "severity": r.severity, "mitre": r.mitre,
                    "interval_sec": r.interval, "enabled": r.id not in off, "baselined": bool(st.get("baselined")),
                    "last_run": datetime.utcfromtimestamp(st["last_ok"]).isoformat() + "Z" if st.get("last_ok") else None,
                    "last_error": st.get("last_error"), "last_new": st.get("last_new"), "known": len(st.get("emitted", {}))})
    return out


def set_enabled(rule_id: str, enabled: bool) -> bool:
    if rule_id not in _BY_ID:
        return False
    cfg = _read(CONFIG_PATH, {})
    off = set(cfg.get("disabled", []))
    (off.discard if enabled else off.add)(rule_id)
    cfg["disabled"] = sorted(off)
    _write(CONFIG_PATH, cfg)
    return True

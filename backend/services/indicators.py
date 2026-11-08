"""
Outside addresses that attacked or probed this client (stage 3 of the ML work: what Central compares across clients).

Each agent lists the public IPv4 addresses that showed up in the last 24 hours in what it detected: the devices' log lines it kept (IPsec
negotiations that failed, refused Winbox connections, failed logins - services/syslog_receiver.py stores warnings and worse) and the
SOC alerts (the address of the alert, and any public address in its message: NetFlow beacon targets, inbound scans, Wazuh source
addresses). Central puts the lists of all clients side by side: an address that probes several clients is a campaign, not chance, and the
same address list can be blocked everywhere at once. Private, reserved and multicast addresses are left out; only addresses go to Central,
never the log lines. Seen live at one client: the same scanner ranges (Censys, Palo Alto Xpanse, Shadowserver, cloud providers) probing
IPsec on both of its public addresses all day.
"""
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import select

from models.database import SessionLocal, SocAlert, SyslogEvent

_IP = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
MAX_ROWS = 20000
MAX_OUT = 300


def kind_of(text: str) -> str:
    t = text.lower()
    if "phase1" in t or "phase 1" in t or "ph1" in t or "ike" in t or "ipsec" in t:
        return "ipsec"
    if "winbox" in t or "dude" in t:
        return "winbox"
    if "login" in t or "password" in t or "authentication" in t or "invalid user" in t:
        return "login"
    if "scan" in t:
        return "scan"
    return "other"


def public_ips(text: str):
    for m in _IP.finditer(text or ""):
        try:
            a = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if a.is_global:
            yield str(a)


def collect(now: Optional[datetime] = None, own: Optional[set] = None) -> Dict[str, dict]:
    """{ip: {"kinds": set, "n": count, "last": datetime}} of the last 24 hours. `own`: this client's own public addresses, left out."""
    now = now or datetime.utcnow()
    since = now - timedelta(hours=24)
    out: Dict[str, dict] = defaultdict(lambda: {"kinds": set(), "n": 0, "last": None})
    own = own or set()

    def add(ip: str, kind: str, at: datetime) -> None:
        if ip in own:
            return
        r = out[ip]
        r["kinds"].add(kind)
        r["n"] += 1
        r["last"] = max(r["last"], at) if r["last"] else at

    with SessionLocal() as db:
        for at, msg in db.execute(select(SyslogEvent.at, SyslogEvent.message).where(SyslogEvent.at >= since, SyslogEvent.severity <= 4)
                                  .order_by(SyslogEvent.id.desc()).limit(MAX_ROWS)).all():
            k = kind_of(msg)
            for ip in public_ips(msg):
                add(ip, k, at)
        for a in db.execute(select(SocAlert).where(SocAlert.last_seen >= since, SocAlert.status != "false_positive")).scalars().all():
            k = "netflow" if (a.rule or "").startswith("net.") else "wazuh" if a.source == "wazuh" else kind_of(f"{a.rule} {a.title or ''}")
            text = f"{a.ip or ''} {a.detail or ''}"
            for ip in set(public_ips(text)):
                add(ip, k, a.last_seen)
    return out


def _own_addresses() -> set:
    """This client's public addresses as its routers know them (so its own WAN address, which every IPsec line carries, is not listed)."""
    own = set()
    try:
        from models.database import Device
        with SessionLocal() as db:
            for (ip,) in db.execute(select(Device.ip)).all():
                if ip:
                    own.add(ip)
            # RouterOS IPsec lines put this side first: "... time up <our address>[500]<=><peer>[port] ..."
            for (msg,) in db.execute(select(SyslogEvent.message).where(SyslogEvent.message.like("%]<=>%")).order_by(SyslogEvent.id.desc()).limit(2000)).all():
                m = re.search(r"([\d.]+)\[\d+\]<=>[\d.]+\[\d+\]", msg)
                if m:
                    own.add(m.group(1))
    except Exception:
        pass
    return own


def public_summary(now: Optional[datetime] = None) -> dict:
    data = collect(now, _own_addresses())
    rows = sorted(data.items(), key=lambda kv: -kv[1]["n"])[:MAX_OUT]
    return {"at": (now or datetime.utcnow()).isoformat() + "Z", "total": len(data),
            "ips": [{"ip": ip, "k": sorted(r["kinds"]), "n": r["n"], "last": r["last"].isoformat() + "Z" if r["last"] else None} for ip, r in rows]}

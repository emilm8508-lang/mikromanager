"""
Wazuh events as metric series (stage 2 of the ML work), when Wazuh is configured on the agent (services/wazuh_client.py).

Every 10 minutes (in the metrics cycle) one aggregation query counts, per Wazuh agent, the alerts of the last 10 minutes at every level,
the failed logins among them, the ones of level 10 and up and the distinct source addresses. They become the series "wz:<agent>:events",
":auth", ":high", ":srcips" (kind "sec"), so the anomaly engine (services/anomaly.py) learns each host's normal rate of security events
per hour of the week and flags a host that suddenly has many more - a brute force, a scan reaching it, malware making noise - even when
no single Wazuh rule is severe enough to alert by itself. Agents seen in the last 7 days read 0 when they had nothing, so their quiet
hours are learned too. The single alerts keep reaching the SOC as before (services/wazuh_monitor.py).
"""
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

from services import wazuh_client

WINDOW_MIN = 10
KEEP_DAYS = 7
_seen: Dict[str, dict] = {}            # agent name -> {"ip", "at"}
_last = {"at": None, "agents": 0, "error": None}

FEATURES = (("events", "security events", "events"), ("auth", "failed logins", "events"), ("high", "events level 10+", "events"),
            ("srcips", "source addresses", "IPs"))


def _name(agent: str, ip: Optional[str]) -> str:
    try:
        from services import syslog_receiver
        n = (syslog_receiver.known_sources().get(ip or "") or {}).get("name")
        return n or agent
    except Exception:
        return agent


async def sample(now: Optional[datetime] = None) -> dict:
    """Reads the counts of the last window and records them. Does nothing when Wazuh is not configured."""
    if not wazuh_client.is_configured():
        return {"configured": False}
    from services import metrics
    from models.database import SessionLocal
    now = now or datetime.utcnow()
    end = now.replace(second=0, microsecond=0)
    start = end - timedelta(minutes=WINDOW_MIN)
    counts = await wazuh_client.alert_counts(start.isoformat() + "Z", end.isoformat() + "Z")
    if counts is None:
        _last.update(error="the Wazuh indexer did not answer")
        return {"configured": True, "ok": False}
    t = time.time()
    for agent, c in counts.items():
        _seen[agent] = {"ip": c.get("ip"), "at": t}
    for agent in [a for a, v in _seen.items() if t - v["at"] > KEEP_DAYS * 86400]:
        del _seen[agent]
    with SessionLocal() as db:
        for agent, v in _seen.items():
            c = counts.get(agent) or {}
            nm = _name(agent, v.get("ip"))
            safe = agent.replace(":", "_")
            for key, label, unit in FEATURES:
                metrics.record(f"wz:{safe}:{key}", float(c.get(key, 0)), name=f"{nm} · {label}", kind="sec", unit=unit, now=end, db=db)
        db.commit()
    _last.update(at=end.isoformat() + "Z", agents=len(_seen), error=None)
    return {"configured": True, "ok": True, "agents": len(_seen)}


def status() -> dict:
    return {"configured": wazuh_client.is_configured(), **_last}

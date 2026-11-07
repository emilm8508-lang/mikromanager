"""
Signals from different sources about the same machine, close in time (stage 2 of the ML work).

One source alone is often noise: an anomaly in a host's traffic, a burst of Wazuh events, failed logins in the syslog. Two independent
sources about the same machine within an hour are much less likely to be coincidence - the shape of an attack that has started (a
brute force followed by unusual traffic, a scan and then events on the scanned host). Every metrics cycle (10 minutes) this looks at the
SOC alerts of the last hour that are not false positives, groups them by the inventory asset (or by the device name when no asset was
matched) and, when they come from at least two families, raises "ml.correlated": high, critical with three or more, with the ATT&CK ids
of the parts. The families: the anomaly engine (ml.anomaly), the NetFlow detectors (net.*), Wazuh, and the logs (the syslog receiver,
the hosts' security logs: failed logins).
"""
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, SocAlert

WINDOW_MIN = 60
RULE = "ml.correlated"


def family(rule: str, source: str) -> Optional[str]:
    if rule == "ml.anomaly":
        return "anomaly"
    if rule.startswith("net."):
        return "netflow"
    if source == "wazuh" or rule.startswith("wazuh"):
        return "wazuh"
    if rule.startswith("syslog") or rule in ("failed_logins", "login_after_failures", "auth_failure"):
        return "logs"
    return None


def run(now: Optional[datetime] = None) -> List[dict]:
    from services import soc
    now = now or datetime.utcnow()
    since = now - timedelta(minutes=WINDOW_MIN)
    groups: Dict[str, dict] = defaultdict(lambda: {"families": defaultdict(list), "name": None, "ip": None, "asset": None, "mitre": set()})
    with SessionLocal() as db:
        rows = db.execute(select(SocAlert).where(SocAlert.last_seen >= since, SocAlert.status != "false_positive", SocAlert.rule != RULE)).scalars().all()
        for a in rows:
            fam = family(a.rule or "", a.source or "")
            if not fam:
                continue
            key = f"asset:{a.asset_id}" if a.asset_id else f"name:{(a.device_name or a.ip or '').strip().lower()}"
            if key in ("name:", "asset:None"):
                continue
            g = groups[key]
            g["families"][fam].append(a.title or a.rule)
            g["name"] = g["name"] or a.device_name
            g["ip"] = g["ip"] or a.ip
            g["asset"] = g["asset"] or a.asset_id
            for m in (a.mitre or "").split(","):
                if m.strip():
                    g["mitre"].add(m.strip())
    raised = []
    for key, g in groups.items():
        fams = sorted(g["families"])
        if len(fams) < 2:
            continue
        parts = "; ".join(f"{f}: {', '.join(sorted(set(t for t in g['families'][f] if t))[:3])}" for f in fams)
        sev = "critical" if len(fams) >= 3 else "high"
        soc.raise_alert(rule=RULE, device=g["name"] or g["ip"], ip=g["ip"], title="Signals from several sources about one machine", severity=sev,
                        category="detection", fp_detail=key, mitre=",".join(sorted(g["mitre"]))[:120] or None, asset_id=g["asset"],
                        detail={"message": f"Within {WINDOW_MIN} minutes: {parts}", "description": ", ".join(fams)}, source="rules", now=now)
        raised.append({"key": key, "name": g["name"], "families": fams, "severity": sev})
    return raised

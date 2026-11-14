"""
The quality of the alerts themselves (stage 7 of docs/plan-jakosc-danych.md): which rules are right, which nobody looks at, which close
by themselves and why.

Seen in production: almost every alert of every client had status "new" - nobody could tell a rule worth attention from a noisy one.
This report, per rule over the last 90 days:
  * total, open, unattended (still "new" after 7 days), closed by a person, marked false positive, closed automatically (by reason:
    recovered, stale, regrouped, version not affected ...);
  * precision = closed by a person / (closed by a person + false positive) - the share of the alerts someone looked at that were real;
  * per category the open and unattended alerts - the categories nobody reacts to;
  * the critical alerts with what they rest on (a confirmed fact - a KEV match on a confirmed product, a service down, a successful login
    after failures, a Wazuh level 13+ - or not), so "critical" can be checked.

It also closes alerts whose condition is gone and that nothing else closes: a "new vulnerability" alert whose finding is no longer there
("auto: condition gone - finding no longer present").
"""
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, SocAlert

DAYS = 90
UNATTENDED_DAYS = 7
# what a critical alert of a rule rests on - anything critical from a rule not listed here is flagged for a look
CRITICAL_BASIS = {
    "rule.new_vuln": "an exploited (KEV) CVE matched by version range on a confirmed product (3.58)",
    "login_after_failures": "a successful login after repeated failures (a fact in the log)",
    "bizservice_problem": "a business service down (its parts not answering)",
    "wazuh_alert": "Wazuh rule level 13 or higher",
    "comm.loss": "a critical asset whose data stopped (3.60)",
    "server.license_expiring": "a Windows licence ending within days (3.63)",
    "ml.correlated": "three or more independent sources about one machine within an hour",
}


def _human(a: SocAlert) -> bool:
    return a.status == "closed" and bool(a.closed_by) and not str(a.closed_by).startswith("auto")


def report(now: Optional[datetime] = None, days: int = DAYS) -> dict:
    from services import soc
    now = now or datetime.utcnow()
    since = now - timedelta(days=days)
    with SessionLocal() as db:
        rows = db.execute(select(SocAlert).where(SocAlert.first_seen >= since)).scalars().all()
    by_rule: Dict[str, dict] = defaultdict(lambda: {"total": 0, "open": 0, "unattended": 0, "human_closed": 0, "false_positive": 0,
                                                    "auto_closed": Counter(), "occurrences": 0})
    by_cat: Dict[str, Counter] = defaultdict(Counter)
    critical: Counter = Counter()
    for a in rows:
        r = by_rule[a.rule]
        r["total"] += 1
        r["occurrences"] += a.count or 1
        is_open = a.status in soc.OPEN
        if is_open:
            r["open"] += 1
            by_cat[a.category]["open"] += 1
            if a.status == "new" and a.first_seen and now - a.first_seen > timedelta(days=UNATTENDED_DAYS):
                r["unattended"] += 1
                by_cat[a.category]["unattended"] += 1
            if a.severity == "critical":
                critical[a.rule] += 1
        if a.status == "false_positive":
            r["false_positive"] += 1
        elif _human(a):
            r["human_closed"] += 1
        elif a.status == "closed":
            r["auto_closed"][str(a.closed_by or "auto")] += 1
    rules = []
    for rule, r in by_rule.items():
        lab = r["human_closed"] + r["false_positive"]
        rules.append({"rule": rule, "total": r["total"], "occurrences": r["occurrences"], "open": r["open"], "unattended": r["unattended"],
                      "human_closed": r["human_closed"], "false_positive": r["false_positive"], "auto_closed": dict(r["auto_closed"]),
                      "precision": round(r["human_closed"] / lab, 2) if lab else None})
    rules.sort(key=lambda x: (-x["unattended"], -x["open"], x["rule"]))
    cats = sorted(({"category": c, "open": v["open"], "unattended": v["unattended"]} for c, v in by_cat.items()), key=lambda x: -x["unattended"])
    crit = [{"rule": k, "open": n, "basis": CRITICAL_BASIS.get(k), "check": k not in CRITICAL_BASIS} for k, n in critical.most_common()]
    return {"days": days, "at": now.isoformat() + "Z", "alerts": len(rows), "rules": rules, "categories": cats, "critical": crit,
            "unattended": sum(r["unattended"] for r in rules), "open": sum(r["open"] for r in rules)}


def public_summary() -> dict:
    """For Central: the rules worth a look (unattended, noisy, low precision) and the categories nobody reacts to."""
    r = report()
    return {"at": r["at"], "open": r["open"], "unattended": r["unattended"],
            "rules": [{"rule": x["rule"], "open": x["open"], "unattended": x["unattended"], "precision": x["precision"], "occurrences": x["occurrences"],
                       "auto": sum(x["auto_closed"].values())} for x in r["rules"][:25]],
            "categories": r["categories"][:12], "critical": r["critical"][:12]}


async def run_once() -> dict:
    """The async entry: close what is gone, then report."""
    from services import soc, vuln_scan
    hosts = await vuln_scan.hosts_with_findings()
    current = {(h["ip"], f["cve_id"]) for h in hosts for f in h["findings"] if (f.get("status") or "open") in ("open", "in_progress")}
    n = 0
    now = datetime.utcnow()
    with SessionLocal() as db:
        for a in db.execute(select(SocAlert).where(SocAlert.rule == "rule.new_vuln", SocAlert.status.in_(soc.OPEN))).scalars().all():
            try:
                d = json.loads(a.detail or "{}")
            except ValueError:
                continue
            key = (d.get("ip") or a.ip, d.get("cve"))
            if key[1] and key not in current:
                a.status, a.closed_at, a.closed_by = "closed", now, "auto: condition gone - finding no longer present"
                n += 1
        db.commit()
    return {"closed": n}


_task = None


async def _loop():
    import asyncio
    await asyncio.sleep(600)
    while True:
        try:
            await run_once()
        except Exception as e:
            print(f"[soc_quality] error: {type(e).__name__}: {e}")
        await asyncio.sleep(3600)


def start():
    import asyncio
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())

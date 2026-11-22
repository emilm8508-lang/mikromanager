"""Stage 8 regression tests: what the agent sends to Central for the MCP tools (docs/plan-jakosc-danych.md).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Feeds(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, syslog_receiver, router_logs, logons
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'f.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        # everything swapped here is put back after the test: a line read over the API goes through router_logs into logons, which wrote
        # to the real data/mikrotik.db before (seen as "no such column" on an old schema), and the swapped sessions leaked into later tests
        saved = [(m, "SessionLocal", m.SessionLocal) for m in (mdb, soc, syslog_receiver, logons)]
        saved += [(router_logs, k, getattr(router_logs, k)) for k in ("_LOGINS_PATH", "_OWNER_PATH", "_SETTINGS_PATH")]
        saved += [(logons, k, getattr(logons, k)) for k in ("_SESSIONS_PATH", "_SETTINGS_PATH")]
        cache = dict(logons._agent_users_cache)
        self.addCleanup(lambda: ([setattr(m, k, v) for m, k, v in saved], logons._agent_users_cache.update(cache)))
        mdb.SessionLocal = soc.SessionLocal = syslog_receiver.SessionLocal = logons.SessionLocal = self.Session
        syslog_receiver._known_cache.update(at=0, ips={})
        router_logs._LOGINS_PATH = os.path.join(tmp, "l.json")
        router_logs._OWNER_PATH = os.path.join(tmp, "o.json")
        router_logs._SETTINGS_PATH = os.path.join(tmp, "s.json")
        logons._SESSIONS_PATH, logons._SETTINGS_PATH = os.path.join(tmp, "ls.json"), os.path.join(tmp, "lset.json")
        logons._agent_users_cache.update(at=0.0, names=set())
        for x in (router_logs._windows, router_logs._agg, router_logs._seen_lines):
            x.clear()
        self.mdb, self.soc, self.sr = mdb, soc, syslog_receiver

    def test_alert_evidence_of_the_new_rules_reaches_central(self):
        self.soc.raise_alert(rule="routerlog.tls_failed", device="AP1", title="TLS handshake failed", severity="info", ip="192.168.2.22",
                             detail={"message": "x", "caused_by": "this agent (api-ssl)", "confidence": "confirmed", "ports": [443, 8443], "secret_thing": "y"})
        a = self.soc.public_summary()["alerts"][0]
        self.assertEqual((a["detail"]["caused_by"], a["detail"]["confidence"], a["detail"]["ports"]), ("this agent (api-ssl)", "confirmed", [443, 8443]))
        self.assertNotIn("secret_thing", a["detail"])

    def test_device_logs_for_central(self):
        now = datetime.utcnow()
        with self.Session() as db:
            for i, (sev, kind, msg) in enumerate([(6, "login_ok", "user admin logged in from 192.168.1.10 via winbox"),
                                                  (6, None, "dhcp lease info"),
                                                  (3, None, "script error: password=Tajne123 in line 3"),
                                                  (4, None, "old warning")]):
                db.add(self.mdb.SyslogEvent(at=now - timedelta(hours=60 if msg == "old warning" else 0, minutes=i), source_ip="192.168.1.1", severity=sev,
                                            kind="syslog", message=msg, app="system,info", log_kind=kind, src_ip="192.168.1.10" if kind else None,
                                            user_name="admin" if kind else None))
            db.commit()
        logs = self.sr.public_logs()
        msgs = [l["msg"] for l in logs]
        self.assertEqual(len(logs), 2, "a recognised info line and the error; not plain info, not older than 48 h")
        self.assertTrue(any("password=***" in m for m in msgs) and not any("Tajne123" in m for m in msgs))
        login = next(l for l in logs if l["kind"] == "login_ok")
        self.assertEqual((login["src"], login["user"]), ("192.168.1.10", "admin"))

    def test_lines_read_over_the_api_are_kept_for_the_log_view(self):
        from services import resource_monitor
        logs = [{"time": "10:00:01", "topics": "system,error,critical", "message": "login failure for user admin from 10.0.0.9 via ssh"}]
        resource_monitor._check_device_log_events({}, 1, "R2", logs, "192.168.2.1")
        out = self.sr.public_logs()
        self.assertEqual((out[0]["via"], out[0]["kind"], out[0]["src"]), ("api", "login_failed", "10.0.0.9"))

    def test_risk_items_carry_the_alert_id(self):
        from services import soc_risk
        row = {"vulns": {"critical": 0, "high": 0}, "lifecycle": None, "scan_level": "credentialed", "type": "linux"}
        f = soc_risk._factors(row, [{"s": "high", "r": "net.portscan", "t": "Network sweep", "id": 7}], [], [], {}, [], [])
        self.assertEqual(f[0]["items"][0]["id"], 7)


if __name__ == "__main__":
    unittest.main()

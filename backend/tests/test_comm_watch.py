"""Stage 3 regression tests: loss of communication with the assets that matter (services/comm_watch.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import comm_watch as cw  # noqa: E402

CFG = json.loads(json.dumps(cw.DEFAULTS))
NOW = datetime(2026, 11, 14, 12, 0, 0)


def src(name, minutes_ago=None, days=5, gap=None, err=None, override=None):
    last = NOW - timedelta(minutes=minutes_ago) if minutes_ago is not None else None
    return {"source": name, "last_seen": last, "gap_avg": gap, "days_seen": days, "expected_override": override,
            "error": err, "error_at": NOW if err else None}


class Evaluate(unittest.TestCase):
    def test_answers_ping_but_sends_no_logs_is_silent(self):
        st, probs = cw.evaluate([src("icmp", 1), src("syslog", 60)], "critical", "up", NOW, CFG)
        self.assertEqual(st, "silent")
        self.assertEqual([p["source"] for p in probs], ["syslog"])

    def test_part_of_the_sources_is_degraded(self):
        self.assertEqual(cw.evaluate([src("icmp", 1), src("syslog", 60), src("routeros_api", 30)], "critical", "up", NOW, CFG)[0], "degraded")

    def test_down_when_nothing_answers(self):
        self.assertEqual(cw.evaluate([src("icmp", 30), src("syslog", 60)], "critical", "down", NOW, CFG)[0], "down")

    def test_error_reading_is_stale(self):
        st, probs = cw.evaluate([src("redfish", 30, err="HTTP 500")], "important", None, NOW, CFG)
        self.assertEqual((st, probs[0]["error"]), ("stale", "HTTP 500"))

    def test_thresholds_follow_criticality_and_the_source(self):
        # 10 minutes without syslog: late for a critical asset, not for a normal one (1 h)
        self.assertEqual(cw.evaluate([src("syslog", 40)], "critical", None, NOW, CFG)[0], "silent")
        self.assertEqual(cw.evaluate([src("syslog", 40)], "normal", None, NOW, CFG)[0], "ok")
        # a source that is quiet by nature (learned gap 2 h) is not late after 3 h
        self.assertEqual(cw.evaluate([src("syslog", 180, gap=7200)], "critical", None, NOW, CFG)[0], "ok")
        # the router's resources are read every 3 h: 4 h is not late even for a critical one
        self.assertEqual(cw.evaluate([src("routeros_api", 240)], "critical", None, NOW, CFG)[0], "ok")

    def test_only_expected_sources_count(self):
        self.assertEqual(cw.evaluate([src("syslog", 600, days=1)], "critical", None, NOW, CFG)[0], "ok")           # seen on one day only
        self.assertEqual(cw.evaluate([src("syslog", 600, days=1, override=1)], "critical", None, NOW, CFG)[0], "silent")
        self.assertEqual(cw.evaluate([src("syslog", 600, override=0)], "critical", None, NOW, CFG)[0], "ok")

    def test_settings_validation(self):
        with self.assertRaises(ValueError):
            cw.update_settings({"thresholds": {"critical": 7200, "important": 900}})


class Cycle(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, syslog_receiver, topology_map, netflow
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'c.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        cw.SessionLocal = soc.SessionLocal = self.Session
        cw._PATH = os.path.join(tmp, "cw.json")
        cw._pending.clear()
        self.mdb, self.soc, self.sl = mdb, soc, syslog_receiver
        syslog_receiver.last_by_ip.clear()
        netflow._exporters.clear()
        self.attach = {}
        topology_map.attachments = lambda: self.attach
        soc._new_alert_events.clear()

    def _asset(self, db, aid, name, ip, crit, typ="network", details=None):
        db.add(self.mdb.Asset(id=aid, key=f"ip:{ip}", ip=ip, name=name, asset_type=typ, criticality=crit, details=json.dumps(details or {})))

    def _expect(self, db, aid, source, last):
        db.add(self.mdb.AssetSource(asset_id=aid, source=source, days_seen=5, last_seen=last, last_day=last.strftime("%Y-%m-%d")))

    def test_case9_one_alert_then_recovery_with_duration(self):
        t0 = NOW
        with self.Session() as db:
            self._asset(db, 1, "R1", "10.0.0.1", "critical", details={"_class": "gateway"})
            db.add(self.mdb.AvailState(asset_id=1, state="up", since=t0 - timedelta(days=1), last_check=t0, first_check=t0 - timedelta(days=9)))
            self._expect(db, 1, "icmp", t0)
            self._expect(db, 1, "syslog", t0 - timedelta(minutes=30))
            db.commit()
        # the router answers pings but its syslog stopped 30 min ago: 60 cycles (two hours) give ONE alert, its count stays 1
        for i in range(60):
            now = t0 + timedelta(minutes=2 * i)
            with self.Session() as db:
                st = db.get(self.mdb.AvailState, 1)
                st.last_check = now
                db.commit()
            cw.run_cycle(now)
        with self.Session() as db:
            alerts = db.query(self.mdb.SocAlert).filter_by(rule="comm.loss").all()
            self.assertEqual(len(alerts), 1)
            self.assertEqual((alerts[0].count, alerts[0].severity, alerts[0].status), (1, "critical", "new"))
            self.assertEqual(db.get(self.mdb.AssetComm, 1).state, "silent")
        lost = [e for e in cw.collect_alert_events() if e["type"] == "comm_lost"]
        self.assertEqual(len(lost), 1)
        self.assertEqual((lost[0]["count"], lost[0]["missing"]), (3, ["syslog"]))
        # logs come back: closed only after the recovery wait, with the length of the outage
        back = t0 + timedelta(hours=2)
        for i in range(4):
            now = back + timedelta(minutes=2 * i)
            self.sl.last_by_ip["10.0.0.1"] = (now - datetime(1970, 1, 1)).total_seconds()
            with self.Session() as db:
                db.get(self.mdb.AvailState, 1).last_check = now
                db.commit()
            cw.run_cycle(now)
        with self.Session() as db:
            a = db.query(self.mdb.SocAlert).filter_by(rule="comm.loss").one()
            self.assertEqual((a.status, a.closed_by), ("closed", "auto: recovered"))
        restored = [e for e in cw.collect_alert_events() if e["type"] == "comm_restored"]
        self.assertEqual(len(restored), 1)
        # from the last log line before the outage (30 min before the first check) to the recovery
        self.assertGreaterEqual(restored[0]["duration_sec"], 2 * 3600 + 30 * 60)

    def test_case10_edge_router_down_groups_what_is_behind_it(self):
        t0 = NOW
        with self.Session() as db:
            self._asset(db, 1, "MC-R1", "10.0.0.1", "critical", details={"_class": "gateway"})
            self._asset(db, 2, "R2-S1", "10.0.0.11", "important", details={"_class": "switch"})
            self._asset(db, 3, "FS1", "10.0.0.20", "important", typ="windows")
            for aid in (1, 2, 3):
                self._expect(db, aid, "syslog" if aid < 3 else "host_logs", t0 - timedelta(hours=2))
            db.commit()
        self.attach.update({2: {"to_id": 1}, 3: {"to_id": 2}})
        cw.run_cycle(t0)
        with self.Session() as db:
            alerts = db.query(self.mdb.SocAlert).filter_by(rule="comm.loss").all()
            self.assertEqual([a.device_name for a in alerts], ["MC-R1"], "one alert, for the cause")
            self.assertEqual(json.loads(alerts[0].detail)["grouped"], ["FS1", "R2-S1"])
            self.assertEqual(db.get(self.mdb.AssetComm, 3).cause, "MC-R1")
            self.assertEqual(db.get(self.mdb.AssetComm, 2).cause, "MC-R1")

    def test_ignored_and_coverage_gaps(self):
        t0 = NOW
        with self.Session() as db:
            self._asset(db, 1, "MC-R1", "10.0.0.1", "critical", details={"_class": "gateway"})
            self._asset(db, 4, "printer", "10.0.0.40", "ignore", typ="printer")
            self._expect(db, 1, "icmp", t0)
            self._expect(db, 4, "icmp", t0 - timedelta(days=2))
            db.commit()
        cw.run_cycle(t0)
        cov = {r["name"]: r for r in cw.coverage(("critical", "important", "normal"))}
        self.assertEqual(sorted(cov["MC-R1"]["never_seen"]), ["netflow", "routeros_api", "syslog"])
        self.assertNotIn("printer", cov)
        with self.Session() as db:
            self.assertIsNone(db.get(self.mdb.AssetComm, 4))

    def test_a_feed_that_stopped_before_the_watch_began_is_expected(self):
        """2be3 HYPERV: security logs silent since 27.10 - the first observation already shows it stopped."""
        t0 = NOW
        with self.Session() as db:
            self._asset(db, 5, "HYPERV", "10.0.0.114", "important", typ="windows")
            db.commit()
            by_asset = cw._record(db, {(5, "host_logs"): (t0 - timedelta(days=18), None)}, t0)
            db.commit()
            r = by_asset[5][0]
            self.assertTrue(cw.is_expected({"days_seen": r.days_seen, "expected_override": None}, CFG["expect_days"]))
            fresh = cw._record(db, {(5, "winrm"): (t0 - timedelta(minutes=5), None)}, t0)[5]
            self.assertFalse(any(cw.is_expected({"days_seen": x.days_seen, "expected_override": None}, CFG["expect_days"]) for x in fresh if x.source == "winrm"))

    def test_standing_soc_condition_is_not_counted_again(self):
        for _ in range(5):
            self.soc.raise_alert(rule="coverage.host_logs", device="Windows / Linux security logs", title="Source silent", count=0)
        with self.Session() as db:
            self.assertEqual(db.query(self.mdb.SocAlert).one().count, 1)


if __name__ == "__main__":
    unittest.main()

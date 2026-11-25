"""Stage 7 regression tests: alert hygiene - TLS per device, factory certificates, tuning from labels, the quality report.

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolate import swap, swap_class  # noqa: E402

NOW = datetime(2026, 11, 14, 12, 0)


def _db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import models.database as mdb
    tmp = tempfile.mkdtemp()
    engine = create_engine(f"sqlite:///{os.path.join(tmp, 'h.db')}", connect_args={"check_same_thread": False})
    mdb.Base.metadata.create_all(engine)
    return mdb, sessionmaker(bind=engine, expire_on_commit=False)


class Tls(unittest.TestCase):
    def setUp(self):
        from services import tls_scan, soc
        self.mdb, self.Session = _db()
        swap(self, tls_scan, "SessionLocal", self.Session)
        swap(self, soc, "SessionLocal", self.Session)
        self.tls, self.soc = tls_scan, soc

    def test_case12_factory_certificate_is_one_low_finding(self):
        r = {"not_after": NOW - timedelta(days=19676), "not_before": datetime(1970, 1, 1), "self_signed": True, "key_kind": "RSA", "key_bits": 2048,
             "sig_alg": "sha256", "legacy": []}
        fs = self.tls.findings(r, NOW)
        self.assertEqual([(f["code"], f["severity"]) for f in fs], [("self_signed_default", "low")])
        long = {"not_after": NOW + timedelta(days=365 * 80), "not_before": NOW - timedelta(days=10), "self_signed": True, "legacy": []}
        self.assertEqual([f["code"] for f in self.tls.findings(long, NOW)], ["self_signed_default"])

    def _check(self, db, ip, port, findings):
        db.add(self.mdb.TlsCheck(ip=ip, port=port, findings=json.dumps(findings), last_check_at=NOW))

    def test_one_alert_per_device_not_counted_per_scan_and_user_ports_high(self):
        with self.Session() as db:
            db.add(self.mdb.Asset(key="ip:10.0.0.50", ip="10.0.0.50", name="CAM-1", asset_type="camera"))
            db.add(self.mdb.Asset(key="ip:10.0.0.10", ip="10.0.0.10", name="RDP", asset_type="windows", role="server"))
            d = [{"code": "self_signed_default", "severity": "low", "message": "factory"}]
            self._check(db, "10.0.0.50", 443, d)
            self._check(db, "10.0.0.50", 8443, d)
            self._check(db, "10.0.0.50", 554, [{"code": "expired", "severity": "high", "message": "certificate expired 3 day(s) ago"}])
            self._check(db, "10.0.0.10", 3389, [{"code": "expired", "severity": "high", "message": "certificate expired 3 day(s) ago"}])
            # an alert of the old per-port form, left by 3.63
            db.add(self.mdb.SocAlert(fingerprint="tls_self_signed|cam-1|10.0.0.50:443", rule="tls_self_signed", source="rules", category="vulnerability",
                                     severity="low", rank=1, device_name="CAM-1", ip="10.0.0.50", status="new", count=87))
            db.commit()
        for _ in range(5):                                       # five scans
            self.tls.alerts(NOW)
        with self.Session() as db:
            rows = {(a.device_name, a.rule): a for a in db.query(self.mdb.SocAlert).filter(self.mdb.SocAlert.status == "new").all()}
            old = db.query(self.mdb.SocAlert).filter_by(fingerprint="tls_self_signed|cam-1|10.0.0.50:443").one()
        cam = rows[("CAM-1", "tls_self_signed_default")]
        self.assertEqual((cam.severity, cam.count), ("low", 1))
        self.assertEqual(json.loads(cam.detail)["ports"], [443, 8443])
        self.assertEqual(rows[("CAM-1", "tls_expired")].severity, "low", "a camera's management port")
        self.assertEqual(rows[("RDP", "tls_expired")].severity, "high", "a server's RDP: people use it")
        self.assertEqual((old.status, old.closed_by), ("closed", "auto: regrouped per device"))


class Tuning(unittest.TestCase):
    def ev(self, verdict, hour, key="win:3:cpu", score=6.0, day=0):
        return {"verdict": verdict, "started_at": datetime(2026, 10, 1 + day, hour, 5), "series": [{"key": key, "score": score}], "host": "glpi2"}

    def test_repeated_false_alarms_raise_the_threshold_and_mute_the_hour(self):
        from services import anomaly_tuning as at
        evs = [self.ev("false", 2, score=6.0, day=0), self.ev("false", 2, score=7.5, day=7), self.ev("false", 2, score=6.8, day=14)]
        t = at.tune(evs, 4.0)["win:3:cpu"]
        self.assertEqual(t["z"], 8.25)
        self.assertEqual(t["quiet_hours"], [2])
        self.assertEqual(at.threshold("win:3:cpu", 2, 4.0, {"win:3:cpu": t}), 8.25)
        self.assertEqual(at.threshold("win:3:cpu", 14, 4.0, {"win:3:cpu": t}), 8.25)
        self.assertEqual(at.threshold("other", 2, 4.0, {"win:3:cpu": t}), 4.0)

    def test_a_true_event_keeps_the_series_detectable(self):
        from services import anomaly_tuning as at
        evs = [self.ev("false", 2, score=9.0), self.ev("false", 3, score=9.5, day=3), self.ev("true", 2, score=6.0, day=9)]
        t = at.tune(evs, 4.0)["win:3:cpu"]
        self.assertEqual(t["z"], 5.4, "never above 90 % of a real problem's peak")
        self.assertEqual(t["quiet_hours"], [], "the hour of a real problem is not muted")

    def test_one_false_alarm_is_not_enough(self):
        from services import anomaly_tuning as at
        self.assertEqual(at.tune([self.ev("false", 2)], 4.0), {})

    def test_precision_report(self):
        from services import anomaly_tuning as at
        r = at.precision_report([self.ev("false", 2), self.ev("true", 5), {"verdict": None, "started_at": NOW, "series": [], "host": "glpi2"}])
        self.assertEqual(r["hosts"][0], {"name": "glpi2", "true": 1, "false": 1, "unlabelled": 1, "precision": 0.5})


class Quality(unittest.TestCase):
    def test_report_and_closing_gone_findings(self):
        from services import soc_quality, soc, vuln_scan
        mdb, Session = _db()
        swap(self, soc_quality, "SessionLocal", Session)
        swap(self, soc, "SessionLocal", Session)
        old = NOW - timedelta(days=10)

        def a(rule, status, sev="medium", closed_by=None, first=old, cat="network", detail=None):
            return mdb.SocAlert(fingerprint=f"{rule}|x|{status}{closed_by}", rule=rule, source="rules", category=cat, severity=sev, rank=soc.RANK[sev],
                                status=status, closed_by=closed_by, first_seen=first, last_seen=first, count=3, detail=json.dumps(detail or {}))
        with Session() as db:
            db.add_all([a("net.beacon", "false_positive"), a("net.beacon", "false_positive"), a("net.beacon", "closed", closed_by="admin"),
                        a("net.beacon", "new"), a("syslog.critical", "new", sev="critical"),
                        a("rule.new_vuln", "new", sev="critical", cat="vulnerability", detail={"ip": "10.0.0.1", "cve": "CVE-2018-7445"}),
                        a("comm.loss", "closed", closed_by="auto: recovered")])
            db.commit()
        r = soc_quality.report(NOW)
        beacon = next(x for x in r["rules"] if x["rule"] == "net.beacon")
        self.assertEqual((beacon["precision"], beacon["unattended"], beacon["false_positive"]), (0.33, 1, 2))
        crit = {c["rule"]: c for c in r["critical"]}
        self.assertTrue(crit["syslog.critical"]["check"], "critical without a listed basis is flagged")
        self.assertFalse(crit["rule.new_vuln"]["check"])
        self.assertEqual(next(x for x in r["rules"] if x["rule"] == "comm.loss")["auto_closed"], {"auto: recovered": 1})

        async def no_findings(*a, **k):
            return []
        orig = vuln_scan.hosts_with_findings
        vuln_scan.hosts_with_findings = no_findings
        try:
            self.assertEqual(asyncio.run(soc_quality.run_once())["closed"], 1)
        finally:
            vuln_scan.hosts_with_findings = orig
        with Session() as db:
            v = db.query(mdb.SocAlert).filter_by(rule="rule.new_vuln").one()
            self.assertEqual(v.closed_by, "auto: condition gone - finding no longer present")


if __name__ == "__main__":
    unittest.main()

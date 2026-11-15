"""Round 2, stage D (3.69) regression tests - docs/plan-runda-2.md: one alert per device across renames, closing alerts whose condition
ended, the topology kept across restarts, the fields and the source of failed Windows logons.

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, tls_scan
        self.tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(self.tmp, 'd.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (soc.SessionLocal, tls_scan.SessionLocal, soc._QUIET_PATH)
        self.addCleanup(lambda: (setattr(soc, "SessionLocal", saved[0]), setattr(tls_scan, "SessionLocal", saved[1]),
                                 setattr(soc, "_QUIET_PATH", saved[2])))
        soc.SessionLocal = tls_scan.SessionLocal = self.Session
        soc._QUIET_PATH = os.path.join(self.tmp, "none.json")
        self.mdb, self.soc, self.tls = mdb, soc, tls_scan


class OneAlertPerDevice(_Db):
    def test_case11_a_rename_counts_up_the_same_alert(self):
        s = self.soc
        s.raise_alert(rule="net.portscan", device="192.168.1.127", ip="192.168.1.127", title="Port scan", fp_detail="scan")
        s.raise_alert(rule="net.portscan", device="ALU-SW2", ip="192.168.1.127", title="Port scan", fp_detail="scan")
        s.raise_alert(rule="net.portscan", device="192.168.1.127", ip="192.168.1.127", title="Port scan", fp_detail="scan")
        with self.Session() as db:
            rows = db.query(self.mdb.SocAlert).all()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].device_name, rows[0].count), ("ALU-SW2", 3))

    def test_tls_alert_follows_the_name(self):
        mdb, now = self.mdb, datetime.utcnow()
        old = now - timedelta(days=1)
        with self.Session() as db:
            db.add(mdb.SocAlert(fingerprint="tls_self_signed_default|192.168.1.127|192.168.1.127", rule="tls_self_signed_default", source="rules",
                                category="vulnerability", severity="low", rank=1, device_name="192.168.1.127", ip="192.168.1.127", status="new",
                                first_seen=old, last_seen=old))
            db.add(mdb.Asset(key="ip:192.168.1.127", ip="192.168.1.127", name="ALU-SW2", asset_type="network"))
            for port in (443, 8443):
                db.add(mdb.TlsCheck(ip="192.168.1.127", port=port, findings=json.dumps([{"code": "self_signed_default", "severity": "low",
                                                                                        "message": "factory certificate"}])))
            db.commit()
        r = self.tls.alerts(now)
        with self.Session() as db:
            rows = db.query(mdb.SocAlert).filter(mdb.SocAlert.status.in_(self.soc.OPEN)).all()
        self.assertEqual(len(rows), 1, r)
        self.assertEqual((rows[0].device_name, rows[0].fingerprint), ("ALU-SW2", "tls_self_signed_default|alu-sw2|192.168.1.127"))
        self.assertEqual(rows[0].first_seen, old, "the alert kept its history")


class ConditionGone(_Db):
    def _add(self, rule, hours, status="new"):
        t = datetime.utcnow() - timedelta(hours=hours)
        with self.Session() as db:
            db.add(self.mdb.SocAlert(fingerprint=f"{rule}|h|{hours}|{status}", rule=rule, source="rules", category="network", severity="medium",
                                     rank=2, device_name="h", status=status, first_seen=t, last_seen=t))
            db.commit()

    def test_closed_after_the_quiet_time(self):
        self._add("net.portscan", 50)
        self._add("net.portscan", 20)
        self._add("net.portscan", 50, "ack")
        self._add("hostlog.user_created", 50)
        self._add("hostlog.user_created", 15 * 24)
        self._add("ml.anomaly", 30)
        self.soc.housekeeping(force=True)
        with self.Session() as db:
            st = {a.fingerprint: (a.status, a.closed_by) for a in db.query(self.mdb.SocAlert).all()}
        self.assertEqual(st["net.portscan|h|50|new"], ("closed", "auto: condition gone for 48 h"))
        self.assertEqual(st["net.portscan|h|20|new"][0], "new")
        self.assertEqual(st["net.portscan|h|50|ack"][0], "ack", "somebody took it up: not closed by the quiet rule")
        self.assertEqual(st["hostlog.user_created|h|50|new"][0], "new", "a one-off security event waits for a person")
        self.assertEqual(st[f"hostlog.user_created|h|{15 * 24}|new"], ("closed", "auto: stale"))
        self.assertEqual(st["ml.anomaly|h|30|new"], ("closed", "auto: condition gone for 24 h"))

    def test_quiet_hours_can_be_changed(self):
        with open(self.soc._QUIET_PATH, "w") as f:
            json.dump({"net.portscan": 6, "hostlog.user_created": 0, "x": "bad"}, f)
        t = self.soc._quiet_table()
        self.assertEqual((self.soc.quiet_hours("net.portscan", t), self.soc.quiet_hours("hostlog.user_created", t)), (6, None))


class TopologyKept(unittest.TestCase):
    def test_attachments_survive_a_restart(self):
        from services import topology_map as tm
        saved = (tm._ATTACH_PATH, dict(tm._cache))
        self.addCleanup(lambda: (setattr(tm, "_ATTACH_PATH", saved[0]), tm._cache.clear(), tm._cache.update(saved[1])))
        tm._ATTACH_PATH = os.path.join(tempfile.mkdtemp(), "a.json")
        tm._save_attach({7: {"to_id": 3, "kind": "client", "port": "ether5"}})
        tm._cache["attach"] = {}                                    # a restart
        self.assertEqual(tm.attachments(), {7: {"to_id": 3, "kind": "client", "port": "ether5"}})
        from services import availability
        self.assertEqual(availability._chain(7, tm.attachments()), [3])


class FailedLogons(unittest.TestCase):
    def _payload(self, n, ip="-", sub="0xc0000064"):
        t = datetime(2026, 11, 14, 13, 42)
        return {"events": [{"id": 4625, "t": (t + timedelta(seconds=30 * i)).isoformat() + "Z",
                            "d": {"TargetUserName": "admin" if i % 2 else "test", "IpAddress": ip, "WorkstationName": "-", "LogonType": "3",
                                  "Status": "0xc000006d", "SubStatus": sub, "FailureReason": "%%2313"}} for i in range(n)]}

    def test_fields_of_4625(self):
        from services import host_logs as hl
        e = hl.parse_windows(self._payload(1, ip="192.168.1.50", sub="0xc000006a"))[0]
        self.assertEqual((e["ip"], e["workstation"], e["logon_type"], e["reason"], e["no_such_user"]),
                         ("192.168.1.50", None, "3", "wrong password", False))
        self.assertIsNone(hl.parse_windows(self._payload(1))[0]["src"], '"-" is no source')

    def test_case_no_address_is_filled_from_netflow(self):
        from services import host_logs as hl, netflow, soc
        captured = []
        saved = (soc.raise_alert, list(netflow._auth))
        self.addCleanup(lambda: (setattr(soc, "raise_alert", saved[0]), netflow._auth.clear(), netflow._auth.extend(saved[1])))
        soc.raise_alert = lambda **kw: captured.append(kw)
        events = hl.parse_windows(self._payload(12))
        t0 = (events[0]["t"] - datetime(1970, 1, 1)).total_seconds()
        netflow._auth.clear()
        netflow._auth.extend([(t0 + 20, "192.168.1.77", "192.168.1.10", 445), (t0 + 40, "192.168.1.77", "192.168.1.10", 445),
                              (t0 + 3600, "192.168.1.99", "192.168.1.10", 445)])
        hl.evaluate("SERWER", "192.168.1.10", "windows", events, now=t0 + 400)
        d = next(c["detail"] for c in captured if c["rule"] == "hostlog.failed_logons")
        self.assertEqual(d["sources"], [])
        self.assertEqual(d["sources_from_netflow"], ["192.168.1.77"])
        self.assertEqual(sorted(d["no_such_users"]), ["admin", "test"])
        self.assertEqual(d["logon_types"], ["network"])
        self.assertIn("NetFlow: 192.168.1.77", d["message"])


if __name__ == "__main__":
    unittest.main()

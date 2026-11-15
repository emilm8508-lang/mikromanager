"""Round 3, stage B (3.75) regression tests - docs/plan-runda-3.md: facts every cycle, fixed_by_upgrade, freshness, RouterBOOT, MNDP.

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

from services import device_facts as df


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, vuln_scan, exploit_intel, identity
        self.tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(self.tmp, 'b.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (df, soc, vuln_scan, identity)
        saved = [(m, m.SessionLocal) for m in mods]
        saved_info, saved_path = exploit_intel.info, df._MISMATCH_PATH
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(exploit_intel, "info", saved_info),
                                 setattr(df, "_MISMATCH_PATH", saved_path)))
        for m in mods:
            m.SessionLocal = self.Session
        exploit_intel.info = lambda cve: {"kev": True, "epss": None}
        df._MISMATCH_PATH = os.path.join(self.tmp, "mm.json")
        self.mdb, self.soc, self.vs = mdb, soc, vuln_scan


class Freshness(_Db):
    def _finding(self, seen):
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.Device(id=1, ip="192.168.2.90", identity="R2-AP1", vendor="mikrotik", ros_version="7.23.2", has_api=True, version_seen_at=seen))
            db.add(mdb.VulnFinding(product="MikroTik RouterOS", version="7.23.2", cve_id="CVE-2026-86060", severity="CRITICAL", cvss_score=9.0,
                                   queried_at=datetime.utcnow(), match_source="cpe-range", evaluation="affected", fixed_version="7.24.2"))
            db.commit()
        return asyncio.run(self.vs.hosts_with_findings())[0]["findings"][0]

    def test_case5_a_version_read_8_days_ago_is_only_suspected(self):
        f = self._finding(datetime.utcnow() - timedelta(days=8))
        self.assertEqual((f["confidence"], f.get("stale_version")), ("suspected", True))
        self.assertTrue(f["version_seen_at"])

    def test_fresh_and_a_few_days(self):
        self.assertEqual(df.freshness(datetime.utcnow() - timedelta(hours=1)), ("confirmed", False))
        self.assertEqual(df.freshness(datetime.utcnow() - timedelta(days=3)), ("likely", False))
        self.assertEqual(df.freshness(None), (None, False), "not read since 3.75 yet: no cap")
        f = self._finding(datetime.utcnow() - timedelta(hours=2))
        self.assertEqual(f["confidence"], "confirmed")


class Upgrade(_Db):
    def test_case6_upgrade_closes_what_it_fixed_and_is_in_the_history(self):
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.Device(id=1, ip="192.168.2.90", identity="R2-AP1", vendor="mikrotik", ros_version="7.23.2 (stable)", has_api=True))
            db.add(mdb.Asset(id=10, key="ip:192.168.2.90", ip="192.168.2.90", name="R2-AP1", asset_type="network", refs=json.dumps({"device_id": 1})))
            for cve, fixed in (("CVE-2026-86060", "7.24.2"), ("CVE-2026-67278", "7.23.6")):
                db.add(mdb.VulnFinding(product="MikroTik RouterOS", version="7.23.2 (stable)", cve_id=cve, severity="CRITICAL", cvss_score=9.0,
                                       queried_at=datetime.utcnow(), match_source="cpe-range", evaluation="affected", fixed_version=fixed))
                db.add(mdb.VulnRemediation(product="MikroTik RouterOS", version="7.23.2 (stable)", cve_id=cve, severity="CRITICAL", status="open"))
                db.add(mdb.SocAlert(fingerprint=f"rule.new_vuln|r2-ap1|192.168.2.90|{cve}", rule="rule.new_vuln", source="rules", category="vulnerability",
                                    severity="critical", rank=4, device_name="R2-AP1", ip="192.168.2.90", status="new",
                                    detail=json.dumps({"ip": "192.168.2.90", "cve": cve})))
            db.commit()

        async def nothing(db, product, version):
            return []                                     # NVD: 7.25.1 has neither
        saved = self.vs._get_findings_for
        self.vs._get_findings_for = nothing
        self.addCleanup(lambda: setattr(self.vs, "_get_findings_for", saved))
        r = asyncio.run(df.apply(1, {"ros_version": "7.25.1 (stable)", "identity": "R2-AP1"}))
        self.assertEqual((r["upgraded"], r["fixed"]), (("7.23.2", "7.25.1"), 4))
        with self.Session() as db:
            rem = db.query(mdb.VulnRemediation).all()
            self.assertTrue(all(x.status == "resolved" and "fixed_by_upgrade: 7.23.2 → 7.25.1" in x.note for x in rem))
            al = db.query(mdb.SocAlert).all()
            self.assertTrue(all(a.closed_by == "auto: fixed_by_upgrade: 7.23.2 → 7.25.1" for a in al))
            h = db.query(mdb.AssetHistory).one()
            self.assertEqual((h.field, h.old, h.new, h.source), ("os_version", "7.23.2 (stable)", "7.25.1 (stable)", "routeros_api: RouterOS updated"))
            d = db.get(mdb.Device, 1)
            self.assertIsNotNone(d.version_seen_at)

    def test_unknown_new_version_closes_nothing(self):
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.Device(id=1, ip="10.0.0.1", identity="R", vendor="mikrotik", ros_version="7.20"))
            db.add(mdb.VulnRemediation(product="MikroTik RouterOS", version="7.20", cve_id="CVE-1", severity="HIGH", status="open"))
            db.commit()

        async def down(db, product, version):
            self.vs._nvd_health["errors"] = self.vs._nvd_health.get("errors", 0) + 1     # what _get_findings_for does: note it, return the cache
            return []
        saved = self.vs._get_findings_for
        self.vs._get_findings_for = down
        self.addCleanup(lambda: setattr(self.vs, "_get_findings_for", saved))
        r = asyncio.run(df.apply(1, {"ros_version": "7.25.1"}))
        self.assertEqual(r["fixed"], 0)
        with self.Session() as db:
            self.assertEqual(db.query(mdb.VulnRemediation).one().status, "open")


class RouterBoot(_Db):
    def test_case7_old_firmware_is_one_low_alert(self):
        self.assertEqual(df.routerboot("R2-AP1", "192.168.2.90", "7.19.6", "7.25.1"), "raised")
        df.routerboot("R2-AP1", "192.168.2.90", "7.19.6", "7.25.1")
        with self.Session() as db:
            a = db.query(self.mdb.SocAlert).one()
            self.assertEqual((a.rule, a.severity, a.count), ("device.routerboot_outdated", "low", 1))
            self.assertIn("/system routerboard upgrade", json.loads(a.detail)["advice"])
        df.routerboot("R2-AP1", "192.168.2.90", "7.25.1", "7.25.1")
        with self.Session() as db:
            self.assertEqual(db.query(self.mdb.SocAlert).one().status, "closed")


class Neighbors(_Db):
    def test_mndp_updates_a_stale_device_and_reports_a_fresh_one(self):
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.Device(id=1, ip="192.168.2.1", identity="R2", vendor="mikrotik"))
            db.add(mdb.Device(id=2, ip="192.168.2.90", identity="wAP", vendor="mikrotik", ros_version="7.23.2", mac_physical="D0:EA:11:13:04:7F",
                              version_seen_at=datetime.utcnow() - timedelta(days=3)))
            db.add(mdb.Device(id=3, ip="192.168.2.95", identity="AP2", vendor="mikrotik", ros_version="7.20", mac="AA:BB:CC:00:00:02",
                              version_seen_at=datetime.utcnow() - timedelta(hours=1)))
            db.commit()
        rows = [{"address": "192.168.2.90", "mac-address": "D0:EA:11:13:04:7F", "identity": "R2-AP1", "version": "7.25.1 (stable)", "board": "wAPG-5HaxD2HaxD"},
                {"address": "192.168.2.95", "mac-address": "AA:BB:CC:00:00:02", "identity": "AP2", "version": "7.21 (stable)"}]
        r = df.neighbors(1, rows)
        self.assertEqual(r, {"updated": 1, "mismatches": 2})
        with self.Session() as db:
            d = db.get(mdb.Device, 2)
            self.assertEqual((d.identity, d.ros_version, d.version_source), ("R2-AP1", "7.25.1 (stable)", "mndp"))
            self.assertEqual(db.get(mdb.Device, 3).ros_version, "7.20", "the API read is fresher: only reported")
        self.assertEqual({m["device"]: m["updated"] for m in df.mismatches()}, {"R2-AP1": True, "AP2": False})


if __name__ == "__main__":
    unittest.main()

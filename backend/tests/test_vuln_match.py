"""Stage 1 regression tests: version-range CVE matching and product identity (services/vuln_match.py, services/vuln_scan.py).

Run from backend/:  python -m unittest discover -s tests -v
The cases come from production data (3.57, five clients) - see docs/plan-jakosc-danych.md.
"""
import asyncio
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import vuln_match as vm  # noqa: E402

ROS = "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*"
# CVE-2018-14847 (Winbox): NVD's configuration - RouterOS up to and including 6.42 (fixed in 6.42.1)
CVE_2018_14847 = [{"criteria": ROS, "vulnerable": True, "versionEndIncluding": "6.42"}]
# CVE-2018-7445 (SMB): fixed in 6.41.3 (and 6.40.7 on the bugfix branch)
CVE_2018_7445 = [{"criteria": ROS, "vulnerable": True, "versionEndExcluding": "6.41.3"}]
# CVE-2026-86060 as described for sanmed R1: fixed in 7.23.4 and 7.24.2
CVE_2026_86060 = [{"criteria": ROS, "vulnerable": True, "versionStartIncluding": "7.0", "versionEndExcluding": "7.23.4"},
                  {"criteria": ROS, "vulnerable": True, "versionStartIncluding": "7.24", "versionEndExcluding": "7.24.2"}]
APACHE = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
CVE_2024_38475 = [{"criteria": APACHE, "vulnerable": True, "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.60"}]


class VersionCompare(unittest.TestCase):
    def test_channel_suffixes_are_ignored(self):
        self.assertEqual(vm.clean_version("7.23.2 (stable)"), "7.23.2")
        self.assertEqual(vm.clean_version("6.49.21 (long-term)"), "6.49.21")
        self.assertEqual(vm.compare("7.24.2 (stable)", "7.24.2"), 0)

    def test_ordering(self):
        self.assertEqual(vm.compare("7.25.1", "6.42.1"), 1)
        self.assertEqual(vm.compare("6.40.5", "6.41.3"), -1)
        self.assertEqual(vm.compare("7.15", "7.15.0"), 0)
        self.assertEqual(vm.compare("7.9", "7.10"), -1)              # numeric, not text
        self.assertEqual(vm.compare("7.15rc3", "7.15"), -1)          # a release candidate comes before the release
        self.assertEqual(vm.compare("7.15beta2", "7.15rc1"), -1)

    def test_not_a_version(self):
        self.assertIsNone(vm.compare("unknown", "7.1"))
        self.assertIsNone(vm.version_key(""))


class RangeEvaluation(unittest.TestCase):
    def test_case1_winbox_cve_not_on_7_25_1_but_on_6_40_5(self):
        self.assertEqual(vm.evaluate(CVE_2018_14847, "mikrotik", "routeros", "7.25.1")[0], "not_affected")
        self.assertEqual(vm.evaluate(CVE_2018_14847, "mikrotik", "routeros", "6.40.5")[0], "affected")
        self.assertEqual(vm.evaluate(CVE_2018_7445, "mikrotik", "routeros", "7.24.4 (stable)")[0], "not_affected")
        self.assertEqual(vm.evaluate(CVE_2018_7445, "mikrotik", "routeros", "6.40.5"), ("affected", "6.41.3"))

    def test_case2_two_fixed_branches(self):
        self.assertEqual(vm.evaluate(CVE_2026_86060, "mikrotik", "routeros", "7.15.2"), ("affected", "7.23.4"))
        self.assertEqual(vm.evaluate(CVE_2026_86060, "mikrotik", "routeros", "7.24.2 (stable)")[0], "not_affected")
        self.assertEqual(vm.evaluate(CVE_2026_86060, "mikrotik", "routeros", "7.24.1"), ("affected", "7.24.2"))
        self.assertEqual(vm.evaluate(CVE_2026_86060, "mikrotik", "routeros", "7.23.4")[0], "not_affected")

    def test_other_products_ranges_do_not_count(self):
        self.assertEqual(vm.evaluate(CVE_2024_38475, "mikrotik", "routeros", "7.15.2")[0], "unknown")

    def test_exact_version_entries(self):
        m = [{"criteria": "cpe:2.3:o:mikrotik:routeros:6.40.5:*:*:*:*:*:*:*", "vulnerable": True}]
        self.assertEqual(vm.evaluate(m, "mikrotik", "routeros", "6.40.5")[0], "affected")
        self.assertEqual(vm.evaluate(m, "mikrotik", "routeros", "6.40.6")[0], "not_affected")

    def test_non_vulnerable_platform_entries_are_ignored(self):
        m = [{"criteria": "cpe:2.3:h:mikrotik:rb3011:-:*:*:*:*:*:*:*", "vulnerable": False}] + CVE_2018_7445
        self.assertEqual(vm.evaluate(m, "mikrotik", "routeros", "6.40")[0], "affected")

    def test_extract_matches_from_nvd_json_and_objects(self):
        item = {"cve": {"id": "CVE-2018-7445", "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": CVE_2018_7445}]}]}}
        self.assertEqual(vm.extract_matches(item)[0]["versionEndExcluding"], "6.41.3")
        obj = NS(configurations=[NS(nodes=[NS(cpeMatch=[NS(criteria=ROS, vulnerable=True, versionEndExcluding="6.41.3")])])])
        self.assertEqual(vm.extract_matches(obj)[0]["criteria"], ROS)
        self.assertEqual(vm.extract_matches(NS(configurations=None)), [])


class ProductIdentity(unittest.TestCase):
    def test_case3_brother_printer_is_not_routeros(self):
        r = vm.routeros_identity(vendor="mikrotik", version="1.37", name="BRN94DDF81D98BE")
        self.assertIsNone(r["product"])
        r = vm.routeros_identity(vendor="mikrotik", version="7.1", name="printer", oui_vendor="Brother Industries, Ltd.")
        self.assertIsNone(r["product"])

    def test_case4_linux_kernel_version_is_not_routeros(self):
        self.assertIsNone(vm.routeros_identity(vendor="mikrotik", version="2.6.18", name="ET0021B73C433C")["product"])
        self.assertIsNone(vm.routeros_identity(vendor="mikrotik", version="2.6.18", name="box")["product"])

    def test_case5_swos_is_not_routeros(self):
        r = vm.routeros_identity(vendor="mikrotik", version="2.18", name="R1-S8", model="CSS326-24G-2S+")
        self.assertEqual(r["product"], "MikroTik SwOS")
        r = vm.routeros_identity(vendor="mikrotik", version="2.19", name="R1-S11")
        self.assertEqual(r["product"], "MikroTik SwOS")

    def test_routeros_confidence_by_evidence(self):
        self.assertEqual(vm.routeros_identity(vendor="mikrotik", version="7.25.1", has_api=True)["confidence"], "confirmed")
        self.assertEqual(vm.routeros_identity(vendor="mikrotik", version="7.25.1", sys_descr="RouterOS RB3011UiAS")["source"], "snmp")
        self.assertEqual(vm.routeros_identity(vendor="mikrotik", version="7.25.1")["confidence"], "likely")
        self.assertEqual(vm.routeros_identity(vendor="mikrotik", version="7.25.1", oui_vendor="Routerboard.com")["product"], "MikroTik RouterOS")
        self.assertIsNone(vm.routeros_identity(vendor="cisco-sb", version="1.4")["product"])


class Confidence(unittest.TestCase):
    def test_case6_backported_apache_is_only_suspected(self):
        distro = vm.distro_from("Apache/2.4.52 (Ubuntu)")
        self.assertEqual(distro, "ubuntu")
        ev = vm.evaluate(CVE_2024_38475, "apache", "http_server", "2.4.52")[0]
        self.assertEqual(ev, "affected")
        self.assertEqual(vm.finding_confidence(match_source="cpe-range", evaluation=ev, product_confidence="likely", distro=distro), "suspected")
        # the same with the distribution's own data for the installed package
        self.assertEqual(vm.finding_confidence(match_source="package", evaluation="affected"), "confirmed")

    def test_device_confidence_follows_identification(self):
        self.assertEqual(vm.finding_confidence(match_source="cpe-range", evaluation="affected", product_confidence="confirmed"), "confirmed")
        self.assertEqual(vm.finding_confidence(match_source="banner", evaluation="unknown", product_confidence="confirmed"), "suspected")


# ── the whole path on a temporary database: NVD answer -> stored findings -> host view -> risk ─────────────────────────────

class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        cls.tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(cls.tmp, 't.db')}", connect_args={"check_same_thread": False})
        mdb.engine = engine
        mdb.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
        mdb.Base.metadata.create_all(engine)
        from services import vuln_scan, exploit_intel
        vuln_scan.SessionLocal = mdb.SessionLocal
        cls.mdb, cls.vs = mdb, vuln_scan
        exploit_intel.info = lambda cve: {"kev": cve in ("CVE-2018-14847", "CVE-2018-7445", "CVE-2026-86060"), "epss": None}

    def _cve(self, cve_id, matches, score=9.8):
        return NS(id=cve_id, v31score=score, v31severity="CRITICAL", descriptions=[NS(lang="en", value=cve_id)], published="2018",
                  url="u", configurations=[NS(nodes=[NS(cpeMatch=[NS(**m) for m in matches])])])

    def test_lookup_store_autoclose_and_host_view(self):
        vs, mdb = self.vs, self.mdb
        db_cves = {"CVE-2018-14847": CVE_2018_14847, "CVE-2018-7445": CVE_2018_7445, "CVE-2026-86060": CVE_2026_86060}
        asked = []

        class FakeNvd:
            def searchCPE(self, **kw):
                return []

            def searchCVE(self, virtualMatchString=None, keywordSearch=None, **kw):
                asked.append(virtualMatchString or keywordSearch)
                # NVD would range-filter itself; this fake returns every RouterOS CVE so the local check is what is tested
                return [self._c(i, m) for i, m in db_cves.items()]

            _c = staticmethod(lambda i, m: EndToEnd._cve(EndToEnd, i, m))

        vs.vuln_settings.nvd_backend = lambda: FakeNvd()
        vs.vuln_settings.nvd_key = lambda: None
        with mdb.SessionLocal() as db:
            # the state of 3.57: both 2018 CVEs cached for 7.25.1, open
            for cid in ("CVE-2018-14847", "CVE-2018-7445"):
                db.add(mdb.VulnFinding(product="MikroTik RouterOS", version="7.25.1", cve_id=cid, severity="CRITICAL", cvss_score=9.8,
                                       queried_at=datetime(2000, 1, 1)))
                db.add(mdb.VulnRemediation(product="MikroTik RouterOS", version="7.25.1", cve_id=cid, severity="CRITICAL", status="open"))
            db.add(mdb.Device(ip="192.168.1.1", identity="MC-R1", vendor="mikrotik", ros_version="7.25.1", has_api=True))
            db.add(mdb.Device(ip="192.168.1.2", identity="R1", vendor="mikrotik", ros_version="7.15.2", has_api=True))
            db.add(mdb.Device(ip="192.168.1.3", identity="BRN94DDF81D98BE", vendor="mikrotik", ros_version="1.37"))
            db.add(mdb.Device(ip="192.168.1.4", identity="R1-S8", vendor="mikrotik", ros_version="2.18", model="CSS326-24G-2S+"))
            db.commit()
            rows_new = asyncio.run(vs._get_findings_for(db, "MikroTik RouterOS", "7.25.1"))
            rows_old = asyncio.run(vs._get_findings_for(db, "MikroTik RouterOS", "7.15.2"))
            rems = {r.cve_id: r for r in db.query(mdb.VulnRemediation).filter_by(version="7.25.1").all()}
        self.assertTrue(asked and asked[0] == "cpe:2.3:o:mikrotik:routeros:7.25.1", asked)
        self.assertEqual([r.cve_id for r in rows_new], [], "7.25.1 must have none of the three")
        self.assertEqual(sorted(r.cve_id for r in rows_old), ["CVE-2026-86060"])
        self.assertEqual(rows_old[0].fixed_version, "7.23.4")
        self.assertEqual(rows_old[0].match_source, "cpe-range")
        for cid in ("CVE-2018-14847", "CVE-2018-7445"):
            self.assertEqual(rems[cid].status, "resolved")
            self.assertIn("auto_closed: version_not_affected", rems[cid].note)

        # a printer / SwOS switch with a cached "RouterOS" finding: never shown
        with mdb.SessionLocal() as db:
            for v in ("1.37", "2.18"):
                db.add(mdb.VulnFinding(product="MikroTik RouterOS", version=v, cve_id="CVE-2018-7445", severity="CRITICAL", cvss_score=9.8,
                                       queried_at=datetime.utcnow(), match_source="cpe-range", evaluation="affected"))
            db.commit()
        hosts = asyncio.run(vs.hosts_with_findings())
        by_ip = {h["ip"]: h for h in hosts}
        self.assertEqual(set(by_ip), {"192.168.1.2"})
        f = by_ip["192.168.1.2"]["findings"][0]
        self.assertEqual((f["cve_id"], f["confidence"], f["match_source"], f["fixed_version"]), ("CVE-2026-86060", "confirmed", "cpe-range", "7.23.4"))

    def test_review_reminder_for_accepted_kev(self):
        vs, mdb = self.vs, self.mdb
        now = datetime.utcnow()
        with mdb.SessionLocal() as db:
            db.add(mdb.VulnFinding(product="MikroTik RouterOS", version="7.15.9", cve_id="CVE-2026-86060", severity="CRITICAL", cvss_score=9.8,
                                   queried_at=now, match_source="cpe-range", evaluation="affected"))
            db.add(mdb.VulnRemediation(product="MikroTik RouterOS", version="7.15.9", cve_id="CVE-2026-86060", severity="CRITICAL",
                                       status="accepted_risk", valid_until=now + timedelta(days=3), approved_by="x"))
            db.commit()
        vs._review_alerted = set()
        ev = vs._review_due(now)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["type"], "vuln_review_due")
        self.assertTrue(any(i["cve_id"] == "CVE-2026-86060" and i["days_left"] <= 3 for i in ev["items"]))
        self.assertIsNone(vs._review_due(now), "the same set is reminded once")


class Reevaluation(unittest.TestCase):
    """The one-off pass after the update (services/vuln_reeval.py) on the state 3.57 left behind."""

    def test_reevaluation_closes_false_findings_and_their_alerts(self):
        import json
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import vuln_scan as vs, vuln_reeval, exploit_intel, soc
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'r.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        vs.SessionLocal = vuln_reeval.SessionLocal = Session
        vuln_reeval._PATH = os.path.join(tmp, "reeval.json")
        vuln_reeval.PAUSE_SEC = 0
        exploit_intel.info = lambda cve: {"kev": cve.startswith("CVE-2018"), "epss": None}

        class FakeNvd:
            def searchCPE(self, **kw):
                return []

            def searchCVE(self, virtualMatchString=None, **kw):
                return [EndToEnd._cve(EndToEnd, "CVE-2018-7445", CVE_2018_7445)]

        vs.vuln_settings.nvd_backend = lambda: FakeNvd()
        vs.vuln_settings.nvd_key = lambda: None
        with Session() as db:
            for v in ("7.25.1", "1.37"):
                db.add(mdb.VulnFinding(product="MikroTik RouterOS", version=v, cve_id="CVE-2018-7445", severity="CRITICAL", cvss_score=9.8,
                                       queried_at=datetime.utcnow()))
                db.add(mdb.VulnRemediation(product="MikroTik RouterOS", version=v, cve_id="CVE-2018-7445", severity="CRITICAL", status="open"))
            db.add(mdb.Device(ip="10.0.0.1", identity="MC-R1", vendor="mikrotik", ros_version="7.25.1", has_api=True))
            db.add(mdb.Device(ip="10.0.0.9", identity="BRN94DDF81D98BE", vendor="mikrotik", ros_version="1.37"))
            db.add(mdb.SocAlert(fingerprint="rule.new_vuln|mc-r1|10.0.0.1|CVE-2018-7445", rule="rule.new_vuln", source="rules", category="vulnerability",
                                severity="critical", rank=5, device_name="MC-R1", ip="10.0.0.1", status="new",
                                detail=json.dumps({"ip": "10.0.0.1", "cve": "CVE-2018-7445"})))
            db.commit()
        r = asyncio.run(vuln_reeval.run(force=True))
        self.assertIsNone(r.get("error"), r)
        self.assertEqual(r["closed_version_not_affected"], 1)          # MC-R1 7.25.1
        self.assertEqual(r["closed_product_not_confirmed"], 1)         # the printer's "RouterOS 1.37"
        self.assertEqual(r["soc_alerts_closed"], 1)
        self.assertEqual((r["open_rows_before"], r["open_rows_after"], r["kev_rows_before"], r["kev_rows_after"]), (2, 0, 2, 0))
        with Session() as db:
            a = db.query(mdb.SocAlert).one()
            self.assertEqual((a.status, a.closed_by), ("closed", "auto: version_not_affected"))
            notes = sorted(x.note for x in db.query(mdb.VulnRemediation).all())
            self.assertEqual(notes, ["[auto_closed: product_not_confirmed]", "[auto_closed: version_not_affected]"])
        self.assertEqual(asyncio.run(vuln_reeval.run())["finished_at"], r["finished_at"], "runs once")


class RiskScoring(unittest.TestCase):
    def test_suspected_kev_does_not_count(self):
        from services import soc_risk
        row = {"vulns": {"critical": 1, "high": 0}, "lifecycle": None, "scan_level": "credentialed", "type": "linux"}
        cves = [{"cve_id": "CVE-2024-38475", "severity": "CRITICAL", "cvss_score": 9.1, "confidence": "suspected"}]
        f = {x["k"]: x["pts"] for x in soc_risk._factors(row, [], [], [], {}, cves, [])}
        self.assertNotIn("kev", f)
        self.assertLess(f["vuln"], 8)                       # a third of a confirmed critical


if __name__ == "__main__":
    unittest.main()

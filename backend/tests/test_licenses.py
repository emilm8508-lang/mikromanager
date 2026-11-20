"""ITAM stage C (3.91): software licenses and compliance (services/licenses.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import licenses as lic

NOW = datetime.utcnow()


class Clean(unittest.TestCase):
    def test_bad_licenses(self):
        for b in ({"product": "", "match": "x", "seats": 1}, {"product": "A", "match": "", "seats": 1}, {"product": "A", "match": "x"},
                  {"product": "A", "match": "x", "seats": -1}, {"product": "A", "match": "x", "seats": 1, "kind": "forever"},
                  {"product": "A", "match": "x", "seats": 1, "valid_from": "2026-05-01", "valid_until": "2026-01-01"}):
            with self.assertRaises(ValueError, msg=b):
                lic.clean(b)
        v = lic.clean({"product": "Office", "match": "Office 2021; Microsoft Office Professional Plus 2021", "kind": "site", "seats": 50})
        self.assertEqual((v["match"], v["seats"]), (["office 2021", "microsoft office professional plus 2021"], None))

    def test_matching(self):
        self.assertTrue(lic.matches("Microsoft Office Professional Plus 2021 - pl-pl", ["office professional plus 2021"], []))
        self.assertFalse(lic.matches("Microsoft Office 2021 Click-to-Run Extensibility Component", ["office 2021"], ["click-to-run"]))


class Compliance(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, crypto
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'l.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (lic.SessionLocal, soc.SessionLocal)
        self.addCleanup(lambda: (setattr(lic, "SessionLocal", saved[0]), setattr(soc, "SessionLocal", saved[1])))
        lic.SessionLocal = soc.SessionLocal = self.Session
        self.mdb = mdb
        with self.Session() as db:
            for i, name, role, state, seen in ((1, "PC1", "workstation", None, NOW), (2, "PC2", "workstation", None, NOW), (3, "PC3", "workstation", None, NOW),
                                               (4, "OLD", "workstation", "decommissioned", NOW - timedelta(days=90)), (5, "SRV", "server", None, NOW)):
                db.add(mdb.VulnHost(id=i, ip=f"10.0.0.{i}"))
                db.add(mdb.Asset(id=i, key=f"ip:10.0.0.{i}", ip=f"10.0.0.{i}", name=name, asset_type="windows", role=role, state=state, last_seen_at=seen,
                                 refs=json.dumps({"vuln_host_id": i})))
            for h in (1, 2, 3, 4):
                db.add(mdb.VulnPackage(host_id=h, name="Microsoft Office Professional Plus 2021", version="16.0"))
            db.add(mdb.VulnPackage(host_id=5, name="Microsoft SQL Server 2019", version="15.0"))
            db.add(mdb.VulnPackage(host_id=1, name="SQL Server Management Studio", version="19"))
            db.add(mdb.VulnPackage(host_id=1, name="7-Zip 23.01", version="23.01"))
            db.add(mdb.VulnPackage(host_id=2, name="7-Zip 23.01", version="23.01"))
            db.add(mdb.VulnPackage(host_id=1, name="Microsoft Visual C++ 2015 Redistributable", version="14"))
            db.commit()

    def test_counts_status_alerts_and_suggestions(self):
        office = lic.save({"product": "Office 2021", "match": "office professional plus 2021", "seats": 2, "key": "XK7Q9-ZZ4WP", "valid_until": (NOW + timedelta(days=10)).date().isoformat()}, None, "admin")
        sql = lic.save({"product": "SQL Server 2019", "match": "sql server", "exclude": "management studio", "kind": "per_server", "seats": 2}, None, "admin")
        rows = {r["product"]: r for r in lic.compliance()}
        o, s = rows["Office 2021"], rows["SQL Server 2019"]
        self.assertEqual((o["installs"], o["used"], o["reclaimable"], o["over"], o["status"]), (4, 3, 1, 1, "over"))
        self.assertEqual((s["installs"], s["used"], s["unused"], s["status"]), (1, 1, 1, "unused"), "per server: only servers count, SSMS left out")
        self.assertEqual(lic.check(NOW), {"over": 1, "expiring": 1})
        with self.Session() as db:
            self.assertEqual(sorted(a.rule for a in db.query(self.mdb.SocAlert).all()), ["license.expiring", "license.over"])
        self.assertEqual([x["name"] for x in lic.suggestions()], ["7-Zip 23.01", "SQL Server Management Studio"],
                         "covered ones and runtimes are not suggested; a program left out of a license is uncovered")
        self.assertEqual(lic.read_key(office), "XK7Q9-ZZ4WP")
        with self.Session() as db:
            self.assertNotIn("XK7Q9", db.get(self.mdb.SoftwareLicense, office).key_enc or "", "the key is stored encrypted")
        ps = lic.public_summary()
        self.assertNotIn("XK7Q9", json.dumps(ps))
        self.assertEqual(ps["counts"]["over"], 1)
        self.assertEqual([x["product"] for x in lic.for_asset(1)], ["Office 2021"])
        lic.save({"product": "Office 2021", "match": "office professional plus 2021", "seats": 5}, office, "admin")
        self.assertEqual(lic.read_key(office), "XK7Q9-ZZ4WP", "an edit without the key keeps it")
        self.assertEqual({r["product"]: r["status"] for r in lic.compliance()}["Office 2021"], "unused")
        self.assertEqual(lic.check(NOW)["over"], 0)
        self.assertTrue(lic.delete(sql))


if __name__ == "__main__":
    unittest.main()

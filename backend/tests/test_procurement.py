"""ITAM stage D (3.92): vendors, contracts, purchase orders, attachments (services/procurement.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import procurement as pc

NOW = datetime.utcnow()


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, identity, assets
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'p.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (pc, soc, identity, assets)
        saved = [(m, m.SessionLocal) for m in mods]
        paths = (pc._FILES, pc._SENT_PATH)
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(pc, "_FILES", paths[0]), setattr(pc, "_SENT_PATH", paths[1]), pc._pending.clear()))
        for m in mods:
            m.SessionLocal = self.Session
        pc._FILES, pc._SENT_PATH = os.path.join(tmp, "att"), os.path.join(tmp, "sent.json")
        pc._pending.clear()
        self.mdb = mdb
        with self.Session() as db:
            db.add(mdb.Asset(id=1, key="ip:10.0.0.5", ip="10.0.0.5", name="FS1", asset_type="server"))
            db.add(mdb.SoftwareLicense(id=1, product="Office 2021", kind="per_device", seats=5, match=json.dumps(["office 2021"])))
            db.commit()


class Vendors(_Db):
    def test_vendor_rules(self):
        v = pc.save_vendor({"name": "  Komputronik  SA ", "email": "biuro@komputronik.pl"})
        with self.assertRaisesRegex(ValueError, "exists"):
            pc.save_vendor({"name": "Komputronik SA"})
        with self.assertRaisesRegex(ValueError, "e-mail"):
            pc.save_vendor({"name": "X", "email": "nope"})
        self.assertEqual(pc.vendors()[0]["name"], "Komputronik SA")
        pc.save_contract({"title": "Wsparcie", "vendor_id": v}, None, "admin")
        with self.assertRaisesRegex(ValueError, "contracts"):
            pc.delete_vendor(v)


class Contracts(_Db):
    def test_status_alert_and_one_notice_to_central(self):
        pc.save_contract({"title": "Serwis serwerów", "kind": "maintenance", "end_at": (NOW + timedelta(days=20)).date().isoformat(), "notice_days": 30,
                          "asset_ids": [1, 99], "value": "12 000,50", "currency": "pln"}, None, "admin")
        pc.save_contract({"title": "Leasing", "kind": "lease", "end_at": (NOW + timedelta(days=5)).date().isoformat(), "auto_renew": True}, None, "admin")
        pc.save_contract({"title": "Przyszła", "start_at": (NOW + timedelta(days=40)).date().isoformat()}, None, "admin")
        rows = {c["title"]: c for c in pc.contracts()}
        self.assertEqual({k: v["status"] for k, v in rows.items()}, {"Serwis serwerów": "expiring", "Leasing": "renewing", "Przyszła": "future"})
        self.assertEqual(([a["name"] for a in rows["Serwis serwerów"]["assets"]], rows["Serwis serwerów"]["value"], rows["Serwis serwerów"]["currency"]), (["FS1"], 12000.5, "PLN"))
        self.assertEqual(pc.check(NOW), 1)
        self.assertEqual([e["type"] for e in pc.collect_alert_events()], ["contract_expiring"])
        pc.check(NOW)
        self.assertEqual(pc.collect_alert_events(), [], "once per contract and end date")
        with self.Session() as db:
            self.assertEqual([a.rule for a in db.query(self.mdb.SocAlert).all()], ["contract.expiring"])
        self.assertEqual([c["title"] for c in pc.contracts_for_asset(1)], ["Serwis serwerów"])
        with self.assertRaises(ValueError):
            pc.save_contract({"title": "Zła", "start_at": "2026-05-01", "end_at": "2026-01-01"})
        ps = pc.public_summary()
        self.assertEqual(ps["counts"]["expiring"], 1)
        self.assertNotIn("owner", json.dumps(ps))


class Orders(_Db):
    def test_flow_and_receiving(self):
        v = pc.save_vendor({"name": "Dostawca"})
        oid = pc.save_order({"number": "ZAM/2026/11/1", "vendor_id": v, "currency": "PLN", "items": [
            {"description": "Dell OptiPlex 7010", "kind": "asset", "qty": 2, "unit_price": "3500", "asset_type": "windows", "model": "OptiPlex 7010"},
            {"description": "Office 2021", "kind": "license", "qty": 3, "unit_price": 900, "license_id": 1},
            {"description": "Montaż", "kind": "service", "qty": 1, "unit_price": 200}]}, None, "jan")
        self.assertEqual(pc.orders()[0]["total"], 9900.0)
        with self.assertRaisesRegex(ValueError, "cannot go"):
            pc.set_order_status(oid, "received", "jan")
        pc.set_order_status(oid, "approved", "ewa")
        pc.set_order_status(oid, "ordered", "ewa")
        made = pc.set_order_status(oid, "received", "jan", "2026-11-18")
        self.assertEqual((len(made["assets"]), made["licenses"]), (2, [{"id": 1, "added": 3}]))
        with self.Session() as db:
            new = [db.get(self.mdb.Asset, i) for i in made["assets"]]
            self.assertEqual([(a.name, a.lifecycle_stage, a.cost, a.supplier, a.invoice_no, a.purchased_at) for a in new],
                             [("Dell OptiPlex 7010 #1", "in_stock", 3500.0, "Dostawca", "ZAM/2026/11/1", datetime(2026, 11, 18)),
                              ("Dell OptiPlex 7010 #2", "in_stock", 3500.0, "Dostawca", "ZAM/2026/11/1", datetime(2026, 11, 18))])
            self.assertEqual(db.get(self.mdb.SoftwareLicense, 1).seats, 8)
        o = pc.orders()[0]
        self.assertEqual(([h["to"] for h in o["history"]], o["next"]), (["approved", "ordered", "received"], []))
        with self.assertRaises(ValueError):
            pc.save_order({"number": "ZAM/2026/11/1", "items": [{"description": "x"}]}, oid, "jan")
        with self.assertRaises(ValueError):
            pc.delete_order(oid)

    def test_received_assets_survive_the_inventory_prune(self):
        from services import assets
        oid = pc.save_order({"number": "Z1", "items": [{"description": "Switch", "kind": "asset", "asset_type": "network"}]}, None, "jan")
        for s in ("approved", "ordered", "received"):
            pc.set_order_status(oid, s, "jan")
        with self.Session() as db:
            db.add(self.mdb.Asset(id=50, key="ip:10.0.0.50", ip="10.0.0.50", name="OLD-WITH-WARRANTY", asset_type="other",
                                  first_seen_at=NOW - timedelta(days=400), warranty_until=NOW + timedelta(days=100)))
            db.add(self.mdb.Asset(id=51, key="ip:10.0.0.51", ip="10.0.0.51", name="OLD", asset_type="other", first_seen_at=NOW - timedelta(days=400)))
            db.commit()
            n = assets._prune(db, {}, NOW)
            db.commit()
            left = sorted(a.name for a in db.query(self.mdb.Asset).all())
        self.assertEqual(n, 1)
        self.assertEqual(left, ["FS1", "OLD-WITH-WARRANTY", "Switch"], "what people entered is kept; the stale passive entry goes")


class Files(_Db):
    def test_attachments(self):
        cid = pc.save_contract({"title": "Umowa"}, None, "admin")
        aid = pc.add_attachment("contract", cid, "../../etc/umowa podpisana.pdf", b"%PDF-1.4 test", "admin")
        a = pc.attachment(aid)
        self.assertEqual((a["filename"], a["content_type"]), ("umowa podpisana.pdf", "application/pdf"))
        self.assertTrue(a["path"].startswith(pc._FILES) and os.path.basename(a["path"]) != "umowa podpisana.pdf", "stored under a random name")
        for name, data in (("x.exe", b"MZ"), ("x.html", b"<html>"), ("fake.pdf", b"not a pdf"), ("empty.png", b"")):
            with self.assertRaises(ValueError, msg=name):
                pc.add_attachment("contract", cid, name, data, "admin")
        with self.assertRaisesRegex(ValueError, "MB"):
            pc.add_attachment("contract", cid, "big.txt", b"x" * (pc.MAX_FILE + 1), "admin")
        self.assertEqual([x["filename"] for x in pc.attachments_of("contract", cid)], ["umowa podpisana.pdf"])
        self.assertTrue(pc.delete_contract(cid))
        self.assertIsNone(pc.attachment(aid))
        self.assertFalse(os.path.exists(a["path"]), "the file goes with the contract")


if __name__ == "__main__":
    unittest.main()

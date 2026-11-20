"""ITAM stage A (3.89): the hardware life of an asset and what it cost (services/asset_itam.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import asset_itam as it

NOW = datetime(2026, 11, 20, 12, 0)


class Clean(unittest.TestCase):
    def test_values_are_checked(self):
        for bad in ({"lifecycle_stage": "lost"}, {"purchased_at": "20.11.2026"}, {"cost": "abc"}, {"cost": -1}, {"currency": "zloty"},
                    {"disposal_method": "burned"}, {"purchased_at": "2026-05-01", "warranty_until": "2025-05-01"}):
            with self.assertRaises(ValueError, msg=bad):
                it.clean(bad)
        v = it.clean({"cost": "1 234,50", "currency": "pln", "supplier": "  Komputronik   SA ", "unknown": 1, "asset_tag": "INV-0001"})
        self.assertEqual(v, {"cost": 1234.5, "currency": "PLN", "supplier": "Komputronik SA", "asset_tag": "INV-0001"})

    def test_disposed_needs_date_and_method(self):
        with self.assertRaisesRegex(ValueError, "date"):
            it.clean({"lifecycle_stage": "disposed"})
        with self.assertRaisesRegex(ValueError, "way"):
            it.clean({"lifecycle_stage": "disposed", "disposed_at": "2026-11-01"})
        self.assertEqual(it.clean({"lifecycle_stage": "disposed", "disposed_at": "2026-11-01", "disposal_method": "recycled"})["lifecycle_stage"], "disposed")


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, identity, assets
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'a.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (it, soc, identity, assets)
        saved = [(m, m.SessionLocal) for m in mods]
        self.addCleanup(lambda: [setattr(m, "SessionLocal", s) for m, s in saved])
        for m in mods:
            m.SessionLocal = self.Session
        self.mdb = mdb
        with self.Session() as db:
            db.add(mdb.Asset(id=1, key="ip:10.0.0.5", ip="10.0.0.5", name="FS1", asset_type="server"))
            db.add(mdb.Asset(id=2, key="ip:10.0.0.6", ip="10.0.0.6", name="PC6", asset_type="windows"))
            db.commit()


class Apply(_Db):
    def test_edit_keeps_history_and_the_inventory_state(self):
        from services import assets
        assets.update_asset(1, {"itam": {"lifecycle_stage": "deployed", "purchased_at": "2023-03-01", "warranty_until": "2026-12-01", "cost": "12000", "currency": "PLN",
                                         "asset_tag": "INV-1"}, "_who": "admin"})
        assets.update_asset(1, {"itam": {"lifecycle_stage": "retired"}, "_who": "admin"})
        with self.Session() as db:
            a = db.get(self.mdb.Asset, 1)
            hist = [(h.field, h.old, h.new, h.source) for h in db.query(self.mdb.AssetHistory).order_by(self.mdb.AssetHistory.id).all()]
        self.assertEqual((a.lifecycle_stage, a.state, a.cost, a.warranty_until), ("retired", "decommissioned", 12000.0, datetime(2026, 12, 1)))
        self.assertIn(("lifecycle_stage", "deployed", "retired", "itam: admin"), hist)
        self.assertIn(("warranty_until", None, "2026-12-01", "itam: admin"), hist)
        assets.update_asset(1, {"itam": {"lifecycle_stage": "deployed"}})
        with self.Session() as db:
            self.assertIsNone(db.get(self.mdb.Asset, 1).state, "back in use: the inventory state follows")

    def test_asset_tag_is_unique(self):
        from services import assets
        assets.update_asset(1, {"itam": {"asset_tag": "INV-1"}})
        with self.assertRaisesRegex(ValueError, "already used"):
            assets.update_asset(2, {"itam": {"asset_tag": "INV-1"}})

    def test_central_set_operation(self):
        from services import assets
        r = assets.apply_central_op({"op": "set", "ids": [2], "itam": {"lifecycle_stage": "in_repair", "warranty_until": "2027-01-31"}}, who="Centrala: jan")
        self.assertTrue(r["ok"], r)
        with self.Session() as db:
            a = db.get(self.mdb.Asset, 2)
        self.assertEqual((a.lifecycle_stage, a.warranty_until), ("in_repair", datetime(2027, 1, 31)))
        self.assertFalse(assets.apply_central_op({"op": "set", "ids": [2], "itam": {"lifecycle_stage": "gone"}})["ok"])


class Alerts(_Db):
    def test_warranty_ending_and_replacement_due(self):
        from services import assets
        assets.update_asset(1, {"itam": {"warranty_until": (NOW + timedelta(days=10)).date().isoformat()}})
        assets.update_asset(2, {"itam": {"replace_at": (NOW - timedelta(days=1)).date().isoformat(), "warranty_until": (NOW + timedelta(days=200)).date().isoformat()}})
        self.assertEqual(it.check(NOW), {"warranty_ending": 1, "replace_due": 1})
        with self.Session() as db:
            rules = sorted((a.rule, a.device_name) for a in db.query(self.mdb.SocAlert).all())
        self.assertEqual(rules, [("itam.replace_due", "PC6"), ("itam.warranty_ending", "FS1")])
        assets.update_asset(1, {"itam": {"lifecycle_stage": "retired"}})
        self.assertEqual(it.check(NOW)["warranty_ending"], 0, "a retired asset is not warned about")
        s = it.summary(NOW)
        self.assertEqual((s["stages"]["retired"], s["stages"]["deployed"], s["replace_due"]), (1, 1, 1))
        f = it.forecast_items(NOW, 365)
        self.assertEqual([(x["kind"], x["name"]) for x in f], [("warranty", "PC6"), ("replacement", "PC6")])


if __name__ == "__main__":
    unittest.main()

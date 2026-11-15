"""Round 3, stage C (3.76) regression tests - docs/plan-runda-3.md: probably removed entries and manual states.

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


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import assets, asset_merge, vuln_scan, identity, asset_state, soc, availability, iface_roles
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'c.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (assets, asset_merge, vuln_scan, identity, asset_state, soc, availability)
        saved = [(m, m.SessionLocal) for m in mods]
        ra, ap = iface_roles.router_addresses, asset_state._PATH
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(iface_roles, "router_addresses", ra),
                                 setattr(asset_state, "_PATH", ap)))
        for m in mods:
            m.SessionLocal = self.Session
        iface_roles.router_addresses = lambda max_age_sec=None: []
        asset_state._PATH = os.path.join(tmp, "state.json")
        self.mdb, self.assets, self.st, self.soc, self.av = mdb, assets, asset_state, soc, availability
        self.old = datetime.utcnow() - timedelta(days=9)
        with self.Session() as db:
            # the .94 row of the reference case: a router row nothing answers at (its liveness loop still writes last_seen)
            db.add(mdb.Device(id=2, ip="192.168.2.94", identity="R2-ĄP1", vendor="mikrotik", model="cAP ac", ros_version="7.23.1", online=False,
                              last_seen=datetime.utcnow()))
            db.add(mdb.Asset(id=5, key="ip:192.168.2.94", ip="192.168.2.94", name="R2-ĄP1", asset_type="network", alive_at=self.old,
                             last_seen_at=datetime.utcnow(), first_seen_at=self.old - timedelta(days=100), refs=json.dumps({"device_id": 2})))
            db.add(mdb.SocAlert(fingerprint="assetdown|r2-ąp1|", rule="asset_down", source="agent", category="availability", severity="high", rank=3,
                                device_name="R2-ĄP1", ip="192.168.2.94", asset_id=5, status="new"))
            db.commit()

    def build(self, directory=()):
        return self.assets._save(self.assets._collect(list(directory)))

    def asset(self):
        with self.Session() as db:
            return db.get(self.mdb.Asset, 5)


class ProbablyRemoved(_Db):
    def test_case8_a_week_without_a_sign_of_life(self):
        self.build()
        a = self.asset()
        self.assertEqual(a.state, "probably_removed")
        with self.Session() as db:
            al = {x.rule: x for x in db.query(self.mdb.SocAlert).all()}
        self.assertEqual((al["asset_down"].status, al["asset_down"].closed_by), ("closed", "auto: probably_removed"))
        self.assertEqual((al["asset.confirm_removal"].severity, al["asset.confirm_removal"].status), ("low", "new"))
        self.assertNotIn(5, [t["id"] for t in self.av._targets()], "not watched (no new down alerts)")
        self.assertIn("192.168.2.94", self.st.inactive_ips(), "no TLS / service tries")

    def test_router_last_seen_written_by_its_liveness_loop_is_no_sign_of_life(self):
        self.build()
        self.assertEqual(self.asset().state, "probably_removed")

    def test_one_answer_brings_it_back(self):
        self.build()
        self.build([{"ip": "192.168.2.94", "mac": "D0:EA:11:13:04:00", "name": "R2-ĄP1", "sources": ["arp"]}])
        a = self.asset()
        self.assertIsNone(a.state)
        with self.Session() as db:
            self.assertEqual(db.query(self.mdb.SocAlert).filter_by(rule="asset.confirm_removal").one().status, "closed")

    def test_the_hourly_ping_is_a_sign_of_life(self):
        self.build()

        async def yes(ip):
            return True, "ping OK"
        saved = self.av._answers
        self.av._answers = yes
        self.addCleanup(lambda: setattr(self.av, "_answers", saved))
        self.av._rechecked.clear()
        self.assertEqual(asyncio.run(self.av._recheck_removed(datetime.utcnow())), 1)
        self.build()
        self.assertIsNone(self.asset().state)

    def test_alive_entries_stay(self):
        with self.Session() as db:
            db.get(self.mdb.Device, 2).online = True
            db.commit()
        self.build()
        self.assertIsNone(self.asset().state)


class Manual(_Db):
    def test_manual_states_keep_the_entry_and_its_history(self):
        from services import identity
        with self.Session() as db:
            db.add(self.mdb.Asset(id=6, key="ip:192.168.2.90", ip="192.168.2.90", name="R2-AP1", asset_type="network"))
            db.commit()
        with self.assertRaises(ValueError):
            self.st.set_state(5, "replaced_by", None)
        self.st.set_state(5, "replaced_by", 6, who="admin")
        a = self.asset()
        self.assertEqual((a.state, a.replaced_by), ("replaced_by", 6))
        self.build()
        self.assertEqual(self.asset().state, "replaced_by", "a manual state is not changed by the rebuild")
        self.assertTrue(self.assets.apply_central_op({"op": "set", "ids": [5], "state": "decommissioned"})["ok"])
        self.assertEqual(self.asset().state, "decommissioned")
        self.assertFalse(self.assets.apply_central_op({"op": "set", "ids": [5], "state": "gone_fishing"})["ok"])
        self.assertEqual([h["field"] for h in identity.asset_history(5)].count("state"), 2)


if __name__ == "__main__":
    unittest.main()

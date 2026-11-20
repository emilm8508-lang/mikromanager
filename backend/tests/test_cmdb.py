"""ITAM stage B (3.90): CMDB - configuration item classes and relations (services/cmdb.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import cmdb


class Suggest(unittest.TestCase):
    def test_classes_from_what_the_inventory_knows(self):
        s = cmdb.suggest
        self.assertEqual(s("windows", "server", None, set(), True, None, "HV1")[0], "hypervisor")
        self.assertEqual(s("virtual", None, "vm", set(), False, None, "VM1")[0], "server_virtual")
        self.assertEqual(s("windows", "server", None, {88, 389, 445}, False, None, "DC1")[0], "domain_controller")
        self.assertEqual(s("linux", "server", None, {22, 5432}, False, None, "db1")[0], "database_server")
        self.assertEqual(s("network", None, "ap", set(), False, "wAP ax", "R2-AP1")[0], "access_point")
        self.assertEqual(s("network", None, None, set(), False, "CRS326-24G-2S+", "SW-CORE")[0], "switch")
        self.assertEqual(s("network", None, "gateway", set(), False, "RB5009", "GW")[0], "router")
        self.assertEqual(s("windows", "workstation", None, set(), False, "Latitude 5440", "PC12")[0], "laptop")
        self.assertEqual(s("windows", "workstation", None, set(), False, "OptiPlex 7010", "PC13")[0], "workstation")
        self.assertEqual(s("printer", None, None, set(), False, "MFC-L8900CDW", "BRN001")[0], "mfp")
        self.assertEqual(s("other", None, None, set(), False, "Smart-UPS 1500", "UPS1")[0], "ups")
        self.assertEqual(len(cmdb.ALL_CLASSES), 46)


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import identity, assets, topology_map
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'c.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (cmdb, identity, assets)
        saved = [(m, m.SessionLocal) for m in mods]
        att = topology_map.attachments
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(topology_map, "attachments", att)))
        for m in mods:
            m.SessionLocal = self.Session
        # the map: PC12 on SW-CORE port 5, VM1 on HV1, SW-CORE on GW
        topology_map.attachments = lambda: {3: {"to_id": 2, "kind": "client", "port": "ether5"}, 5: {"to_id": 4, "kind": "vm"}, 2: {"to_id": 1, "kind": "uplink"}}
        self.mdb = mdb
        with self.Session() as db:
            for i, n, t in ((1, "GW", "network"), (2, "SW-CORE", "network"), (3, "PC12", "windows"), (4, "HV1", "windows"), (5, "VM1", "virtual"), (6, "APP", "other")):
                db.add(mdb.Asset(id=i, key=f"k{i}", name=n, asset_type=t, ip=f"10.0.0.{i}"))
            db.add(mdb.BizService(id=1, name="Księgowość", mode="all", members=json.dumps([5])))
            db.commit()


class Relations(_Db):
    def test_auto_and_manual_relations_impact_and_dependencies(self):
        cmdb.add_relation(6, 5, "runs_on", "ERP", "admin")
        es = cmdb.edges()
        kinds = sorted((e["src_name"], e["kind"], e["dst_name"], e["auto"]) for e in es)
        self.assertIn(("PC12", "connected_to", "SW-CORE", True), kinds)
        self.assertIn(("VM1", "runs_on", "HV1", True), kinds)
        self.assertIn(("VM1", "member_of", "Księgowość", True), kinds)
        self.assertIn(("APP", "runs_on", "VM1", False), kinds)
        imp = cmdb.impact(4, es)                        # HV1 fails: VM1, then APP on it; the business service
        self.assertEqual([(x["name"], x["depth"]) for x in imp["assets"]], [("VM1", 1), ("APP", 2)])
        self.assertEqual([s["name"] for s in imp["services"]], ["Księgowość"])
        self.assertEqual([x["name"] for x in cmdb.dependencies(6, es)], ["VM1", "HV1"])
        self.assertEqual([x["name"] for x in cmdb.impact(1, es)["assets"]], ["SW-CORE", "PC12"])

    def test_hide_auto_and_show_again(self):
        cmdb.hide_auto(3, 2, "connected_to", None, "admin")
        self.assertNotIn(("PC12", "connected_to"), [(e["src_name"], e["kind"]) for e in cmdb.edges()])
        with self.Session() as db:
            rid = db.query(self.mdb.CiRelation).filter_by(hidden=True).one().id
        self.assertTrue(cmdb.remove_relation(rid))
        self.assertIn(("PC12", "connected_to"), [(e["src_name"], e["kind"]) for e in cmdb.edges()])
        cmdb.hide_auto(5, None, "member_of", 1, "admin")
        self.assertEqual(cmdb.impact(4)["services"], [], "the hidden membership no longer counts")

    def test_bad_relations(self):
        for args in ((1, 1, "depends_on"), (1, 99, "depends_on"), (1, 2, "member_of")):
            with self.assertRaises(ValueError, msg=args):
                cmdb.add_relation(*args, None, "x")
        a = cmdb.add_relation(1, 2, "depends_on", None, "x")
        self.assertEqual(cmdb.add_relation(1, 2, "depends_on", None, "x"), a, "the same relation once")

    def test_class_set_from_the_page_and_central(self):
        from services import assets
        assets.update_asset(4, {"ci_class": "hypervisor"})
        r = assets.apply_central_op({"op": "set", "ids": [6], "ci_class": "application"})
        self.assertTrue(r["ok"], r)
        self.assertFalse(assets.apply_central_op({"op": "set", "ids": [6], "ci_class": "toaster"})["ok"])
        o = {x["name"]: x for x in cmdb.overview()["items"]}
        self.assertEqual((o["HV1"]["class"], o["HV1"]["set"], o["APP"]["class"]), ("hypervisor", True, "application"))
        ps = cmdb.public_summary()
        self.assertIn(["VM1", "runs_on", "HV1", 0], ps["relations"])
        self.assertNotIn("10.0.0.", json.dumps(ps), "names only")


if __name__ == "__main__":
    unittest.main()

"""Round 3, stage A (3.74) regression tests - docs/plan-runda-3.md: device identity, history, joining, names, virtual monitors.

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

from services import identity


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import assets, asset_merge, vuln_scan, iface_roles
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'i.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (assets, asset_merge, vuln_scan, identity)
        saved = [(m, m.SessionLocal) for m in mods] + [(iface_roles, None)]
        orig_ra, orig_path = iface_roles.router_addresses, identity._PATH
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved if s is not None],
                                 setattr(iface_roles, "router_addresses", orig_ra), setattr(identity, "_PATH", orig_path)))
        for m in mods:
            m.SessionLocal = self.Session
        iface_roles.router_addresses = lambda max_age_sec=None: []
        identity._PATH = os.path.join(tmp, "identity.json")
        self.mdb, self.assets, self.am = mdb, assets, asset_merge

    def build(self, directory=()):
        return self.assets._save(self.assets._collect(list(directory)))

    def all(self):
        with self.Session() as db:
            return db.query(self.mdb.Asset).all()


class ReferenceCase(_Db):
    """sanmed: the AP "R2-AP1" (wAP ax, HM20B0T2CND, 7.25.1 at .90) listed twice - "wAP" at .90 and "R2-ĄP1" (cAP ac, 7.23.1) at .94."""

    def test_case1_one_entry_with_its_history(self):
        mdb = self.mdb
        old = datetime.utcnow() - timedelta(days=20)
        with self.Session() as db:
            db.add(mdb.Device(id=1, ip="192.168.2.90", identity="wAP", vendor="mikrotik", model="wAP ax", ros_version="7.23.2", serial="HM20B0T2CND",
                              mac_physical="D0:EA:11:13:04:7F", has_api=True, online=True, last_seen=datetime.utcnow()))
            db.add(mdb.Device(id=2, ip="192.168.2.94", identity="R2-ĄP1", vendor="mikrotik", model="cAP ac", ros_version="7.23.1",
                              serial="HM20B0T2CND", has_api=True, online=False, last_seen=old))
            db.commit()
        self.build()
        with self.Session() as db:
            self.assertEqual(db.query(mdb.Device).count(), 2, "before: two router rows (the entries share a serial: joined since 3.59)")
        r = identity.reconcile_devices()
        self.assertEqual((r["groups"], r["absorbed"]), (1, 1))
        with self.Session() as db:                              # the next read of the AP: its identity and version as they are now
            d = db.get(mdb.Device, 1)
            d.identity, d.ros_version = "R2-AP1", "7.25.1"
            db.commit()
        self.build()
        a = self.all()
        self.assertEqual(len(a), 1, "one entry")
        e = a[0]
        self.assertEqual((e.name, e.ip, e.model, e.serial, e.os_version), ("R2-AP1", "192.168.2.90", "wAP ax", "HM20B0T2CND", "7.25.1"))
        was = identity.previously(e.id)
        self.assertEqual(sorted(was["name"]), ["R2-ĄP1", "wAP"])
        self.assertEqual(was["ip"], ["192.168.2.94"])
        self.assertIn("cAP ac", was["model"])
        with self.Session() as db:
            self.assertEqual([d.ip for d in db.query(mdb.Device).all()], ["192.168.2.90"])

    def test_without_a_key_it_is_only_proposed(self):
        """A row of the old hardware with no key in common (other serial or none): a similar name in the same /24, silent for a week -
        offered for joining, never joined by itself (and names differing in diacritics are listed)."""
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.Asset(key="ip:192.168.2.90", ip="192.168.2.90", name="R2-AP1", asset_type="network", last_seen_at=datetime.utcnow(),
                             first_seen_at=datetime.utcnow() - timedelta(days=30)))
            db.add(mdb.Asset(key="ip:192.168.2.94", ip="192.168.2.94", name="R2-ĄP1", asset_type="network", last_seen_at=datetime.utcnow() - timedelta(days=9),
                             first_seen_at=datetime.utcnow() - timedelta(days=300)))
            db.commit()
        self.assertEqual(self.am.auto_merge(), 0, "never joined on the name")
        g = self.am.duplicates()
        self.assertEqual([x["reasons"] for x in g], [["similar_name"]])
        self.assertEqual(identity.diacritic_pairs([(1, "R2-ĄP1"), (2, "R2-AP1"), (3, "SRV1")]), [["R2-AP1", "R2-ĄP1"]])
        keep = g[0]["keep"]
        self.am.merge(keep, [i for i in g[0]["ids"] if i != keep])           # the operator accepts it (asset page or Central, 3.70)
        a = self.all()
        self.assertEqual(len(a), 1)
        self.assertEqual(identity.previously(a[0].id).get("ip"), ["192.168.2.94"])


class Changes(_Db):
    def test_case3_new_identity_of_a_known_serial_renames(self):
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.Device(id=1, ip="192.168.1.1", identity="MC-R1", vendor="mikrotik", ros_version="7.25.1", serial="HGF09ABC", has_api=True))
            db.commit()
        self.build()
        with self.Session() as db:
            db.get(mdb.Device, 1).identity = "MC-R1-NEW"
            db.commit()
        self.build()
        a = self.all()
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].name, "MC-R1-NEW")
        self.assertEqual(identity.previously(a[0].id), {"name": ["MC-R1"]})

    def test_case4_new_address_of_a_known_mac_moves(self):
        self.build([{"ip": "192.168.1.50", "mac": "AA:BB:CC:00:11:22", "name": "PC50", "sources": ["dhcp"]}])
        self.build([{"ip": "192.168.1.77", "mac": "AA:BB:CC:00:11:22", "name": "PC50", "sources": ["dhcp"]}])
        a = self.all()
        self.assertEqual([(x.ip, x.key) for x in a], [("192.168.1.77", "ip:192.168.1.77")])
        self.assertEqual(identity.previously(a[0].id), {"ip": ["192.168.1.50"]})

    def test_router_found_under_a_new_address_is_one_row(self):
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.Device(id=1, ip="10.0.0.1", identity="R4", vendor="mikrotik", software_id="ABCD-1234", online=False,
                              last_seen=datetime.utcnow() - timedelta(days=2)))
            db.add(mdb.Device(id=2, ip="10.0.0.9", identity="R4", vendor="mikrotik", software_id="abcd-1234", online=True, last_seen=datetime.utcnow()))
            db.commit()
        self.assertEqual(identity.reconcile_devices()["absorbed"], 1, "a CHR: its license software-id is its key")
        with self.Session() as db:
            self.assertEqual([d.ip for d in db.query(mdb.Device).all()], ["10.0.0.9"])


class Monitors(_Db):
    def test_virtual_monitors_are_not_assets(self):
        mdb = self.mdb
        with self.Session() as db:
            db.add(mdb.LinuxHost(id=1, ip="192.168.1.10", hostname="h", managed=True))
            db.add(mdb.WindowsHost(id=1, ip="192.168.1.20", hostname="VM1", managed=True))
            db.commit()
        self.build()
        with self.Session() as db:
            host = db.query(mdb.Asset).filter(mdb.Asset.ip == "192.168.1.20").one()
            for i in range(3):
                db.add(mdb.AssetPeripheral(asset_id=host.id, kind="monitor", name="HyperVMonitor", manufacturer="MSH", model="062E"))
            db.add(mdb.AssetPeripheral(asset_id=host.id, kind="monitor", name="DELL P2419H", manufacturer="DEL", model="P2419H", serial="CN0ABC"))
            db.commit()
        self.build()
        mons = [a for a in self.all() if a.asset_type == "monitor"]
        self.assertEqual([m.name for m in mons], ["DELL P2419H"])

    def test_a_screen_is_no_hypervisor(self):
        from services import asset_type as at
        self.assertEqual(at.suggest(asset_type="monitor", dclass=None, name="HyperVMonitor", role=None), ("normal", None))
        self.assertTrue(identity.virtual_monitor("MSH", "062E", "HyperVMonitor"))
        self.assertFalse(identity.virtual_monitor("DEL", "P2419H", "DELL P2419H"))


class Keys(unittest.TestCase):
    def test_keys_are_cleaned(self):
        self.assertIsNone(identity.clean_uuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"))
        self.assertIsNone(identity.clean_uuid("03000200-0400-0500-0006-000700080009"))
        self.assertEqual(identity.clean_uuid("4C4C4544-0051-3010-8052-B4C04F4B4E32"), "4c4c4544-0051-3010-8052-b4c04f4b4e32")
        self.assertIsNone(identity.clean_serial("To be filled by O.E.M."))
        self.assertIsNone(identity.clean_mac("01:00:5E:00:00:01"), "a multicast MAC is no key")

    def test_linux_machine_id_and_windows_uuid_are_read(self):
        from services import linux_manage as lm, windows_manage as wm
        out = lm._parse_resources_output("Filesystem 1 2 3 4 5\n@@MEM@@\nMemTotal: 100 kB\nMemAvailable: 50 kB\n@@CPU@@\n0.1 0.1 0.1 1/2 3\n2\n@@MID@@\n4f1c2b0e9a7d4c3b8e2f1a0b9c8d7e6f\n")
        self.assertEqual(out["machine_id"], "4f1c2b0e9a7d4c3b8e2f1a0b9c8d7e6f")
        self.assertEqual(wm._parse_resources({"Mem": {}, "Uuid": "4C4C4544-0051-3010-8052-B4C04F4B4E32"})["hw_uuid"], "4c4c4544-0051-3010-8052-b4c04f4b4e32")


if __name__ == "__main__":
    unittest.main()

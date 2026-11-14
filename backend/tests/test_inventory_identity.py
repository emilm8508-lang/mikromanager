"""Stage 2 regression tests: inventory and device identity (docs/plan-jakosc-danych.md).

Run from backend/:  python -m unittest discover -s tests -v
The cases come from production data (mcprojekt, psb, 2be3 in Central, 3.58).
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import directory_merge as dm, asset_type as at, iface_roles as ir  # noqa: E402

R2_MAC = "4C:5E:0C:11:22:33"          # MikroTik: the peer router behind proxy-ARP / EoIP
VM_MAC = "00:15:5D:01:02:03"          # Hyper-V
PHONE_MAC = "02:AA:BB:CC:DD:01"       # a phone's random (locally administered) MAC
DELL_MAC = "F8:BC:12:34:56:78"


class Directory(unittest.TestCase):
    def test_proxy_arp_mac_does_not_become_the_devices(self):
        """wazuh (a Hyper-V VM) showed as 'made by MikroTik': R1 lists site 2 under R2's MAC."""
        r1 = {"dev": {"name": "MC-R1"}, "leases": [], "arp": [{"address": f"192.168.2.{i}", "mac-address": R2_MAC} for i in (55, 21, 28, 29)]}
        r2 = {"dev": {"name": "R2"}, "leases": [{"address": "192.168.2.55", "mac-address": VM_MAC, "host-name": "wazuh", "status": "bound"}],
              "arp": [{"address": "192.168.2.55", "mac-address": VM_MAC}]}
        by_ip = {e["ip"]: e for e in dm.build([r1, r2])}
        self.assertEqual(by_ip["192.168.2.55"]["mac"], "00:15:5d:01:02:03")
        self.assertEqual(by_ip["192.168.2.55"]["name"], "wazuh")
        self.assertIsNone(by_ip["192.168.2.21"]["mac"])
        self.assertEqual(by_ip["192.168.2.21"]["shared_mac"], R2_MAC.lower())
        self.assertEqual(len(by_ip), 4, "addresses are never folded into one entry")

    def test_stale_lease_name_does_not_name_the_new_device(self):
        """'Redmi-Note-13-5G' made by Dell: the lease kept the phone's name, a Dell PC has the address now."""
        r = {"dev": {"name": "MC-R1"},
             "leases": [{"address": "192.168.1.21", "mac-address": PHONE_MAC, "host-name": "Redmi-Note-13-5G", "status": "waiting"},
                        {"address": "192.168.1.30", "mac-address": DELL_MAC, "host-name": "MCPROJEKTPC011", "status": "bound"}],
             "arp": [{"address": "192.168.1.21", "mac-address": DELL_MAC}]}
        by_ip = {e["ip"]: e for e in dm.build([r])}
        e = by_ip["192.168.1.21"]
        self.assertEqual(e["mac"], DELL_MAC.lower())
        self.assertEqual(e["name"], "MCPROJEKTPC011", "the name follows the MAC, not the address")
        self.assertTrue(any("another device" in n for n in e["notes"]))

    def test_published_invalid_and_incomplete_arp_rows_are_ignored(self):
        r = {"dev": {"name": "R"}, "leases": [], "arp": [
            {"address": "10.0.0.5", "mac-address": "AA:00:00:00:00:05", "published": "true"},
            {"address": "10.0.0.6", "mac-address": "AA:00:00:00:00:06", "complete": "false"},
            {"address": "10.0.0.7", "mac-address": "AA:00:00:00:00:07", "invalid": "true"}]}
        self.assertEqual(dm.build([r]), [])


class AssetTypes(unittest.TestCase):
    def test_raspberry_with_lighttpd_is_not_windows(self):
        """MEDIABOXPI (psb): a Pi serving lighttpd with Samba (445) was 'windows'."""
        t, why = at.decide(ports={80, 445}, banners="lighttpd/1.4.69", name="MEDIABOXPI", ttl_hint="unix")
        self.assertEqual(t, "linux")
        self.assertTrue(any("lighttpd" in w for w in why), why)

    def test_pc_name_beats_a_router_mac_prefix(self):
        """MCPROJEKTPC007 as 'network' because of a MikroTik MAC prefix."""
        t, _ = at.decide(name="MCPROJEKTPC007", oui_type="network", oui_vendor="MikroTik")
        self.assertEqual(t, "windows")

    def test_printer_name_and_windows_ports(self):
        self.assertEqual(at.decide(name="BRN94DDF81D98BE", ports={80, 9100})[0], "printer")
        self.assertEqual(at.decide(ports={3389, 445}, ttl_hint="windows")[0], "windows")
        self.assertEqual(at.decide()[0], "other")


class Criticality(unittest.TestCase):
    def test_levels_and_legacy_values(self):
        self.assertEqual(at.normalize_level("high"), "important")
        self.assertEqual(at.normalize_level("low"), "normal")
        self.assertEqual(at.normalize_level("IGNORE"), "ignore")
        self.assertIsNone(at.normalize_level("bogus"))

    def test_suggestions(self):
        self.assertEqual(at.suggest(asset_type="network", dclass="gateway", name="MC-R1", role=None), ("important", "edge router"))
        self.assertEqual(at.suggest(asset_type="virtual", dclass="vm", name="DC2", role="server")[0], "important")
        self.assertEqual(at.suggest(asset_type="virtual", dclass="vm", name="FS1", role="server")[1], "file server")
        self.assertEqual(at.suggest(asset_type="windows", dclass=None, name="HYPERV-R2", role="server")[1], "hypervisor")
        self.assertEqual(at.suggest(asset_type="linux", dclass=None, name="oracle1", role="server", ports={1521})[1], "database server")
        self.assertEqual(at.suggest(asset_type="windows", dclass=None, name="MCPROJEKTPC011", role="workstation")[0], "normal")
        self.assertEqual(at.suggest(asset_type="network", dclass="switch", name="R2-S1", role=None)[0], "normal")


class InterfaceRoles(unittest.TestCase):
    def test_switch_ether1_is_uplink_not_wan(self):
        routes = [{"dst-address": "0.0.0.0/0", "gateway": "192.168.2.1", "immediate-gw": "192.168.2.1%ether1", "active": "true"}]
        up = ir.default_route_iface(routes)
        self.assertEqual(up, "ether1")
        self.assertEqual(ir.role_of("ether1", "192.168.2.11", [], up), "uplink")
        self.assertEqual(ir.role_of("ether2", None, [], up), "access")

    def test_router_wan_list_and_public_address(self):
        self.assertEqual(ir.role_of("ether1", "192.168.0.2", ["ether1"], None), "wan")       # MC-R1's WAN behind the ISP's box
        self.assertEqual(ir.role_of("pppoe-out1", "83.1.2.3", [], None), "wan")
        self.assertEqual(ir.role_of("bridge", "192.168.1.1", ["ether1"], None), "access")
        self.assertEqual(ir.default_route_iface([{"dst-address": "0.0.0.0/0", "gateway": "pppoe-out1", "active": "true"}]), "pppoe-out1")
        self.assertIsNone(ir.default_route_iface([{"dst-address": "0.0.0.0/0", "gateway": "1.2.3.4", "active": "false"}]))


# ── on a temporary database: the inventory build and the duplicate rules ─────────────────────────────────────────────────

class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        self.tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(self.tmp, 'a.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        from services import assets, asset_merge, vuln_scan
        assets.SessionLocal = asset_merge.SessionLocal = vuln_scan.SessionLocal = self.Session
        self.mdb, self.assets, self.am = mdb, assets, asset_merge


class InventoryBuild(_Db):
    def test_missing_version_unconfirmed_product_and_router_wan_address(self):
        mdb, assets = self.mdb, self.assets
        with self.Session() as db:
            db.add(mdb.Device(ip="192.168.1.1", identity="MC-R1", vendor="mikrotik", ros_version="7.25.1", has_api=True, credential_id=1, serial="HGF09ABC"))
            db.add(mdb.Device(ip="192.168.10.1", identity="PSB", vendor="mikrotik", model="RB3011UiAS"))                 # no version, no credential
            db.add(mdb.Device(ip="192.168.1.181", identity="BRN94DDF81D98BE", vendor="mikrotik", ros_version="1.37"))  # a Brother printer
            db.commit()
        rows = [{"device_id": 1, "device_name": "MC-R1", "device_ip": "192.168.1.1", "ip": "192.168.0.2", "iface": "ether1", "role": "wan"},
                {"device_id": 1, "device_name": "MC-R1", "device_ip": "192.168.1.1", "ip": "192.168.1.1", "iface": "bridge", "role": "access"}]
        from services import iface_roles
        orig = iface_roles.router_addresses
        iface_roles.router_addresses = lambda max_age_sec=None: rows
        try:
            directory = [{"ip": "192.168.0.2", "mac": "4C:5E:0C:AA:BB:CC", "name": None, "sources": ["arp"]},
                         {"ip": "192.168.1.181", "mac": "94:DD:F8:1D:98:BE", "name": "BRN94DDF81D98BE", "sources": ["dhcp"]}]
            recs = assets._collect(directory)
        finally:
            iface_roles.router_addresses = orig
        self.assertNotIn("ip:192.168.0.2", recs, "the router's WAN address is not a host of its own")
        r1 = recs["ip:192.168.1.1"]
        self.assertEqual({(a["ip"], a["role"]) for a in r1["addrs"]}, {("192.168.0.2", "wan"), ("192.168.1.1", "access")})
        self.assertEqual((r1["os_name"], r1["serial"], r1["asset_type"]), ("RouterOS", "HGF09ABC", "network"))
        self.assertIn("missing_version: no credential", recs["ip:192.168.10.1"]["dq"])
        prn = recs["ip:192.168.1.181"]
        self.assertEqual(prn["asset_type"], "printer")
        self.assertNotEqual(prn.get("manufacturer"), "MikroTik")
        self.assertTrue(any(x.startswith("not_mikrotik") for x in prn["dq"]))


class Duplicates(_Db):
    def _asset(self, db, key, ip, name, mac, seen_days=0, **kw):
        a = self.mdb.Asset(key=key, ip=ip, name=name, mac=mac, asset_type=kw.pop("asset_type", "network"),
                           last_seen_at=datetime.utcnow() - timedelta(days=seen_days), first_seen_at=datetime.utcnow() - timedelta(days=30), **kw)
        db.add(a)
        db.flush()
        return a

    def test_ap_interfaces_shown_on_one_entry_and_different_pcs_not_merged(self):
        with self.Session() as db:
            ap_main = self._asset(db, "ip:192.168.2.42", "192.168.2.42", "AP2", "48:a9:8a:10:20:30", refs=json.dumps({"device_id": 7}))
            ap_alt = self._asset(db, "ip:192.168.2.237", "192.168.2.237", "AP2", "48:a9:8a:10:20:34")
            pc_a = self._asset(db, "ip:192.168.2.28", "192.168.2.28", "MCPROJEKTPC004", "f0:1f:af:00:00:01", asset_type="windows")
            pc_b = self._asset(db, "ip:192.168.2.29", "192.168.2.29", "MCPROJEKTPC004", "8c:8d:28:00:00:02", asset_type="windows", seen_days=5)
            db.commit()
            ids = (ap_main.id, ap_alt.id, pc_a.id, pc_b.id)
        n = self.am.auto_merge()
        self.assertEqual(n, 0, "no entry is joined on the name alone")
        with self.Session() as db:
            alt = db.get(self.mdb.Asset, ids[1])
            self.assertEqual(json.loads(alt.details or "{}").get("_alias_of"), ids[0])
            self.assertIsNone(json.loads(db.get(self.mdb.Asset, ids[3]).details or "{}").get("_alias_of"))
            self.assertEqual(len(db.query(self.mdb.Asset).all()), 4)
        # two different network cards under one name are two machines as far as the data goes: never joined, never auto
        for g in self.am.duplicates():
            self.assertFalse(g["auto"] and set(g["ids"]) >= {ids[2], ids[3]})

    def test_same_serial_is_joined(self):
        with self.Session() as db:
            a = self._asset(db, "ip:10.0.0.114", "10.0.0.114", "HYPERV", None, asset_type="windows", serial="7XQ1J63", seen_days=3)
            b = self._asset(db, "ip:10.0.0.116", "10.0.0.116", "HYPERV", None, asset_type="windows", serial="7XQ1J63")
            db.commit()
        self.assertEqual(self.am.auto_merge(), 1)

    def test_sibling_macs(self):
        self.assertTrue(self.am.sibling_macs("48:a9:8a:10:20:30", "48:a9:8a:10:20:34"))
        self.assertFalse(self.am.sibling_macs("48:a9:8a:10:20:30", "48:a9:8b:10:20:31"))      # another maker prefix
        self.assertFalse(self.am.sibling_macs("02:a9:8a:10:20:30", "02:a9:8a:10:20:31"))      # random MACs
        self.assertFalse(self.am.sibling_macs("48:a9:8a:10:20:30", "48:a9:8a:10:30:30"))


if __name__ == "__main__":
    unittest.main()

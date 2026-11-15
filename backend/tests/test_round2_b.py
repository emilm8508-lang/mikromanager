"""Round 2, stage B (3.67) regression tests - docs/plan-runda-2.md: criticality, maker / type / OS, interface roles.

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import asset_type as at, iface_roles as ir


def _row(i, name, reason, level="important", place=None, crit=None, active=True):
    return {"id": i, "name": name, "ip": f"10.0.0.{i}", "criticality": crit, "criticality_suggested": level, "criticality_reason": reason,
            "place": place, "location": None, "active": active}


class Criticality(unittest.TestCase):
    def test_case7_the_only_way_out_is_critical(self):
        rows = [_row(1, "PSB", "edge router"), _row(2, "SRV1", None, "normal")]
        at.uplift(rows)
        self.assertEqual((rows[0]["criticality_suggested"], rows[0]["criticality_reason"]), ("critical", "edge router: the only way out"))

    def test_one_way_out_per_site(self):
        rows = [_row(1, "R1", "edge router", place="sanmed"), _row(2, "R3", "edge router", place="filia"),
                _row(3, "R1-B", "edge router", place="sanmed")]
        at.uplift(rows)
        self.assertEqual(rows[1]["criticality_suggested"], "critical", "the only exit of its site")
        self.assertEqual((rows[0]["criticality_suggested"], rows[0]["criticality_reason"]), ("important", "edge router: one of 2 at sanmed"))

    def test_sole_dc_hypervisor_file_server(self):
        rows = [_row(1, "DC1", "domain controller"), _row(2, "DC2", "domain controller"), _row(3, "HYPERV", "hypervisor"),
                _row(4, "FS1", "file server")]
        at.uplift(rows)
        self.assertEqual([r["criticality_suggested"] for r in rows], ["important", "important", "critical", "critical"])
        self.assertEqual(rows[2]["criticality_reason"], "hypervisor: the only one")

    def test_review_lists_only_unconfirmed(self):
        from services import assets
        rows = [_row(1, "PSB", "edge router", "critical"), _row(2, "DC1", "domain controller", crit="critical"),
                _row(3, "PC1", None, "normal"), _row(4, "FS1", "file server")]
        self.assertEqual([x["name"] for x in assets.criticality_review(rows)], ["PSB", "FS1"])


class EdgeAndRoles(unittest.TestCase):
    def _addrs(self):
        return [  # the router: ISP box on ether1 (private), LAN on bridge; an AP and a switch from defconf with ether1 in "WAN"
            {"device_id": 1, "ip": "192.168.0.2", "iface": "ether1", "role": "wan"},
            {"device_id": 1, "ip": "192.168.2.1", "iface": "bridge", "role": "access"},
            {"device_id": 1, "ip": "10.10.10.1", "iface": "wireguard1", "role": "access"},
            {"device_id": 2, "ip": "192.168.2.62", "iface": "ether1", "role": "wan"},
            {"device_id": 3, "ip": "192.168.2.11", "iface": "bridge", "role": "uplink"},
        ]

    def test_case9_switch_uplink_in_the_lan_is_not_wan(self):
        addrs = self._addrs()
        edge = ir.refine(addrs, {1: "192.168.0.1", 2: "192.168.2.1", 3: "192.168.2.1"}, {1: ["ether1"], 2: ["ether1"], 3: []})
        self.assertEqual(edge, {1})
        roles = {(a["device_id"], a["iface"]): a["role"] for a in addrs}
        self.assertEqual(roles[(1, "ether1")], "wan", "the router's WAN behind the ISP's box stays a WAN")
        self.assertEqual(roles[(2, "ether1")], "uplink", "AP3: defconf WAN list, default route to the router")
        self.assertEqual(roles[(1, "wireguard1")], "tunnel")

    def test_public_address_is_edge_and_route_not_read_keeps_the_list(self):
        addrs = [{"device_id": 5, "ip": "80.54.58.238", "iface": "ether1", "role": "wan"}]
        self.assertEqual(ir.refine(addrs, {5: None}, {5: []}), {5})
        self.assertEqual(ir.refine([{"device_id": 6, "ip": "192.168.5.2", "iface": "ether1", "role": "wan"}], {}, {6: ["ether1"]}), {6})

    def test_gateway_of_the_default_route(self):
        self.assertEqual(ir.default_route_gateway([{"dst-address": "0.0.0.0/0", "gateway": "192.168.2.1", "active": "true"}]), "192.168.2.1")
        self.assertEqual(ir.default_route_gateway([{"dst-address": "0.0.0.0/0", "immediate-gw": "192.168.0.1%ether1", "gateway": "pppoe-out1"}]),
                         "192.168.0.1")
        self.assertIsNone(ir.default_route_gateway([{"dst-address": "0.0.0.0/0", "gateway": "pppoe-out1"}]))
        self.assertEqual(ir.role_of("eoip-filia", "10.9.9.1", [], None), "tunnel")


class MakerTypeOs(unittest.TestCase):
    def test_maker_fix(self):
        self.assertEqual(at.maker_fix("MikroTik", "Microsoft Corporation", confirmed_mikrotik=False, behind_router=False), (True, "Microsoft Corporation"))
        self.assertEqual(at.maker_fix("MikroTik", "Routerboard.com", confirmed_mikrotik=False, behind_router=True), (True, None),
                         "the router's MAC answers for a routed address")
        self.assertEqual(at.maker_fix("MikroTik", "Routerboard.com", confirmed_mikrotik=False, behind_router=False), (False, "MikroTik"))
        self.assertEqual(at.maker_fix("MikroTik", None, confirmed_mikrotik=True, behind_router=True), (False, "MikroTik"))
        self.assertTrue(at.printer_name("ET0021B73C433C"))

    def test_case8_stored_mikrotik_label_is_corrected(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import assets, asset_merge, vuln_scan
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'b.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (assets.SessionLocal, asset_merge.SessionLocal, vuln_scan.SessionLocal)
        self.addCleanup(lambda: (setattr(assets, "SessionLocal", saved[0]), setattr(asset_merge, "SessionLocal", saved[1]),
                                 setattr(vuln_scan, "SessionLocal", saved[2])))
        assets.SessionLocal = asset_merge.SessionLocal = vuln_scan.SessionLocal = Session
        old = datetime.utcnow() - timedelta(days=30)
        with Session() as db:
            db.add(mdb.Device(ip="192.168.1.181", identity="BRN94DDF81D98BE", vendor="mikrotik", ros_version="1.37"))
            # what 3.58 and before stored: the printer as a MikroTik network device, a VM with the router's maker, a PC typed as a phone
            db.add(mdb.Asset(key="ip:192.168.1.181", ip="192.168.1.181", name="BRN94DDF81D98BE", asset_type="network", manufacturer="MikroTik",
                             os_name="RouterOS", os_version="1.37", first_seen_at=old, last_seen_at=old))
            db.add(mdb.Asset(key="ip:192.168.2.55", ip="192.168.2.55", name="wazuh", asset_type="linux", manufacturer="MikroTik", first_seen_at=old,
                             last_seen_at=old))
            db.add(mdb.Asset(key="ip:192.168.0.151", ip="192.168.0.151", name="KSIEGOWOSC", asset_type="mobile", first_seen_at=old, last_seen_at=old))
            db.commit()
        directory = [{"ip": "192.168.1.181", "mac": "94:DD:F8:1D:98:BE", "name": "BRN94DDF81D98BE", "sources": ["dhcp"]},
                     {"ip": "192.168.2.55", "mac": "00:15:5D:01:02:03", "name": "wazuh", "sources": ["arp"]},
                     {"ip": "192.168.0.151", "mac": "9C:93:4E:01:02:03", "name": "KSIEGOWOSC", "sources": ["dhcp"]}]
        orig = ir.router_addresses
        ir.router_addresses = lambda max_age_sec=None: []
        self.addCleanup(lambda: setattr(ir, "router_addresses", orig))
        assets._save(assets._collect(directory))
        with Session() as db:
            a = {x.ip: x for x in db.query(mdb.Asset).all()}
        prn = a["192.168.1.181"]
        self.assertEqual((prn.asset_type, prn.os_name), ("printer", None))
        self.assertNotEqual(prn.manufacturer, "MikroTik")
        self.assertNotEqual(a["192.168.2.55"].manufacturer, "MikroTik")
        self.assertNotEqual(a["192.168.0.151"].asset_type, "mobile")


if __name__ == "__main__":
    unittest.main()

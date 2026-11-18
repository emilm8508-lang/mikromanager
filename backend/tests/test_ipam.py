"""3.86: IP address management from the routers' tables (services/ipam.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import ipam


def dev(name):
    return {"name": name, "ip": "x", "username": "u", "password": "p", "api_port": None, "web_port": None}


R1 = {"dev": dev("R1"), "error": None,
      "addresses": [{"address": "192.168.1.1/24", "interface": "bridge", "disabled": "false"}, {"address": "10.9.9.2/30", "interface": "ether1"},
                    {"address": "172.16.0.1/12", "interface": "vpn"}, {"address": "192.168.5.1/24", "disabled": "true"}],
      "pools": [{"name": "lan", "ranges": "192.168.1.100-192.168.1.109"}, {"name": "spare", "ranges": "192.168.1.200-192.168.1.210"}],
      "servers": [{"name": "dhcp1", "interface": "bridge", "address-pool": "lan", "disabled": False}],
      "leases": [{"address": "192.168.1.%d" % i, "mac-address": "AA:00:00:00:00:%02X" % i, "status": "bound"} for i in range(100, 109)]
                + [{"address": "192.168.1.150", "mac-address": "AA:00:00:00:01:50", "status": "waiting"}],
      "arp": [{"address": "192.168.1.%d" % i, "mac-address": "AA:00:00:00:00:%02X" % i, "complete": "true"} for i in range(100, 109)]
             + [{"address": "192.168.1.109", "mac-address": "BB:00:00:00:00:09", "complete": "true"},          # a fixed address inside the pool
                {"address": "192.168.1.20", "mac-address": "CC:00:00:00:00:20", "complete": "true"},
                {"address": "192.168.1.21", "mac-address": "", "status": "failed"}]}
R2 = {"dev": dev("R2"), "error": None, "addresses": [{"address": "192.168.1.2/24", "interface": "bridge"}], "pools": [], "servers": [], "leases": [],
      "arp": [{"address": "192.168.1.20", "mac-address": "DD:00:00:00:00:20", "complete": True}]                 # R2 sees another MAC for .20
             + [{"address": "192.168.1.%d" % i, "mac-address": "EE:EE:EE:EE:EE:EE", "complete": True} for i in range(30, 40)]}   # proxy ARP


class Parse(unittest.TestCase):
    def test_ranges(self):
        r = ipam.parse_ranges("192.168.1.100-192.168.1.200, 192.168.1.250, 10.0.0.0/30, junk, fe80::1")
        self.assertEqual(ipam._range_size(r), 101 + 1 + 4)

    def test_networks_skip_disabled(self):
        n = ipam.networks(R1["addresses"] + [{"address": "10.1.1.1/32"}])
        self.assertEqual(sorted(n), ["10.9.9.0/30", "172.16.0.0/12", "192.168.1.0/24"], "a /32 is not a subnet, a disabled address is skipped")


class Build(unittest.TestCase):
    def setUp(self):
        self.res = ipam.build([R1, R2], ["192.168.1.50"])

    def test_pool_usage(self):
        p = {x["name"]: x for x in self.res["pools"]}
        self.assertEqual((p["lan"]["size"], p["lan"]["bound"], p["lan"]["pct"], p["lan"]["served"], p["lan"]["server"]), (10, 9, 90.0, True, "dhcp1"))
        self.assertFalse(p["spare"]["served"])

    def test_subnet_usage_free_and_static_in_pool(self):
        s = {x["network"]: x for x in self.res["subnets"]}
        lan = s["192.168.1.0/24"]
        # used: the gateway .1, leases/ARP .100-.109, .20, .50 from the inventory (the proxy-ARP MAC's .30-.39 are not counted)
        self.assertEqual((lan["size"], lan["used"], lan["free"]), (254, 13, 241))
        self.assertEqual(lan["free_list"][:3], ["192.168.1.2", "192.168.1.3", "192.168.1.4"])
        self.assertEqual([x["ip"] for x in lan["static_in_pool"]], ["192.168.1.109"])
        self.assertEqual(lan["pools"], ["lan"])
        self.assertIsNone(s["172.16.0.0/12"]["used"], "a /12 is listed, not counted")

    def test_conflicts(self):
        c = {x["ip"]: x for x in self.res["conflicts"]}
        self.assertEqual(sorted(c), ["192.168.1.20"], "the fixed .109 has no lease: it is in the pool, not in conflict")
        self.assertEqual((c["192.168.1.20"]["macs"], c["192.168.1.20"]["routers"]), (["CC:00:00:00:00:20", "DD:00:00:00:00:20"], ["R1", "R2"]))

    def test_arp_against_the_bound_lease_of_another_mac(self):
        r3 = {"dev": dev("R3"), "error": None, "addresses": [], "pools": [], "servers": [],
              "leases": [{"address": "10.0.0.60", "mac-address": "AA:AA:AA:AA:AA:60", "status": "bound"}],
              "arp": [{"address": "10.0.0.60", "mac-address": "BB:BB:BB:BB:BB:60", "complete": "true"}]}
        c = ipam.build([r3], [])["conflicts"]
        self.assertEqual([(x["ip"], x["macs"]) for x in c], [("10.0.0.60", ["AA:AA:AA:AA:AA:60", "BB:BB:BB:BB:BB:60"])])


class Alerts(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'i.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (ipam.SessionLocal, soc.SessionLocal)
        self.addCleanup(lambda: (setattr(ipam, "SessionLocal", saved[0]), setattr(soc, "SessionLocal", saved[1]), ipam._streak.clear()))
        ipam.SessionLocal = soc.SessionLocal = self.Session
        ipam._streak.clear()
        self.mdb = mdb

    def open_alerts(self):
        with self.Session() as db:
            return sorted((a.rule, a.severity, a.device_name) for a in db.query(self.mdb.SocAlert).all() if a.status not in ("closed", "false_positive"))

    def test_after_two_passes_and_closed_when_gone(self):
        res = ipam.build([R1, R2], [])
        for p in res["pools"]:
            p["days_to_full"] = None
        now = datetime(2026, 11, 18, 12, 0)
        ipam._judge(res, now)
        self.assertEqual(self.open_alerts(), [])
        ipam._judge(res, now + timedelta(minutes=30))
        self.assertEqual(self.open_alerts(), [("net.dhcp_pool", "medium", "R1"), ("net.ip_conflict", "medium", "192.168.1.20")])
        clean = {"subnets": [], "pools": [], "conflicts": []}
        ipam._judge(clean, now + timedelta(minutes=60))
        self.assertEqual(self.open_alerts(), [])

    def test_open_alert_from_before_a_restart_is_closed(self):
        res = ipam.build([R1, R2], [])
        for p in res["pools"]:
            p["days_to_full"] = None
        now = datetime(2026, 11, 18, 12, 0)
        ipam._judge(res, now)
        ipam._judge(res, now + timedelta(minutes=30))
        ipam._streak.clear()                                     # the agent restarted
        ipam._judge({"subnets": [], "pools": [], "conflicts": []}, now + timedelta(minutes=60))
        self.assertEqual(self.open_alerts(), [])

    def test_summary_has_no_host_addresses(self):
        ipam._result.clear()
        ipam._result.update(ipam.build([R1, R2], []), at="2026-11-18T12:00:00Z")
        self.addCleanup(ipam._result.clear)
        ps = ipam.public_summary()
        self.assertEqual((ps["subnets"], ps["pools"], ps["conflicts"], ps["static_in_pool"]), (3, 2, 1, 1))
        self.assertNotIn("192.168.1.20", str(ps))
        self.assertNotIn("AA:00", str(ps))


if __name__ == "__main__":
    unittest.main()

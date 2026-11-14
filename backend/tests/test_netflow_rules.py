"""Stage 5 regression tests: NetFlow direction, scanner exceptions, beacons (docs/plan-jakosc-danych.md).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import flow_rules as fr  # noqa: E402

SYN, ACK, RST, PSH = 0x02, 0x10, 0x04, 0x08


class Pure(unittest.TestCase):
    def test_initiator_from_flags_then_ports(self):
        self.assertTrue(fr.initiator(6, SYN, 40000, 22))
        self.assertTrue(fr.initiator(6, SYN, 22, 40000), "a SYN alone opened it, whatever the ports say")
        self.assertFalse(fr.initiator(6, RST | ACK, 50123, 40000), "a refusal never opened anything")
        self.assertTrue(fr.initiator(6, SYN | ACK | PSH, 51000, 443))
        self.assertFalse(fr.initiator(17, 0, 53, 51000))
        self.assertIsNone(fr.initiator(1, 0, 0, 0))

    def test_case8_broadcast_and_discovery_are_no_outside_targets(self):
        self.assertTrue(fr.not_beacon_target("255.255.255.255", 1947))
        self.assertTrue(fr.not_beacon_target("8.8.4.4", 10001))
        self.assertTrue(fr.not_beacon_target("239.255.255.250", 1900))
        self.assertFalse(fr.not_beacon_target("34.111.175.102", 443))

    def test_cloud_owner(self):
        self.assertEqual(fr.cloud("Google LLC"), "Google")
        self.assertIsNone(fr.cloud("Some Hosting Sp. z o.o."))

    def test_exceptions_scope(self):
        exc = fr.clean_exceptions([{"source": "192.168.2.21", "ports": "22,80,443,3389,8000-8100", "hours": "01:00-05:00", "max_hosts": 300, "note": "TECHSERVICE"}])
        night = datetime(2026, 11, 14, 2, 30)
        e, beyond = fr.check_exception(exc, "net.portscan", "192.168.2.21", [22, 443, 8080], 250, night)
        self.assertEqual((e["source"], beyond), ("192.168.2.21", []))
        e, beyond = fr.check_exception(exc, "net.portscan", "192.168.2.21", [22, 445], 250, night)
        self.assertTrue(any("445" in b for b in beyond))
        e, beyond = fr.check_exception(exc, "net.portscan", "192.168.2.21", [22], 400, night)
        self.assertTrue(any("400 hosts" in b for b in beyond))
        e, beyond = fr.check_exception(exc, "net.portscan", "192.168.2.21", [22], 10, datetime(2026, 11, 14, 14, 0))
        self.assertTrue(any("14:00" in b for b in beyond))
        self.assertEqual(fr.check_exception(exc, "net.portscan", "192.168.2.22", [22], 10, night), (None, []))
        self.assertEqual(fr.check_exception(exc, "net.lateral", "192.168.2.21", [445], 10, night), (None, []), "only the rules it names")

    def test_case13_one_clients_exception_does_not_cover_another(self):
        client_a = fr.clean_exceptions([{"source": "192.168.1.102", "note": "aluplasti check-mk"}])
        client_b = []
        self.assertIsNotNone(fr.check_exception(client_a, "net.portscan", "192.168.1.102", [22], 5, datetime(2026, 1, 1))[0])
        self.assertIsNone(fr.check_exception(client_b, "net.portscan", "192.168.1.102", [22], 5, datetime(2026, 1, 1))[0])

    def test_exception_validation(self):
        for bad in ([{"source": "nope"}], [{"source": "10.0.0.0/16"}], [{"source": "10.0.0.1", "ports": "0-10"}],
                    [{"source": "10.0.0.1", "hours": "25:00-26:00"}], [{"source": "10.0.0.1", "max_hosts": 0}]):
            with self.assertRaises(ValueError):
                fr.clean_exceptions(bad)

    def test_regular_scanner(self):
        six_h = [i * 6 * 3600 + (i % 2) * 300 for i in range(6)]
        r = fr.regular(six_h)
        self.assertEqual(r["every_h"], 6.0)
        self.assertIsNone(fr.regular([0, 3600 * 1, 3600 * 9, 3600 * 10, 3600 * 30]))


class Collector(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import netflow, soc, router_logs
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'n.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mdb.SessionLocal = soc.SessionLocal = self.Session
        nf = netflow
        nf._settings.clear()
        nf._settings.update(dict(nf.DEFAULTS))
        nf._set_nets(nf.DEFAULTS["local_nets"])
        nf._loaded[0] = True
        for x in (nf._win, nf._pairs, nf._pair_seen, nf._tracked, nf._last_raised, nf._fp_cache, nf._scan_times, nf._recent_by_src, nf._beyond):
            x.clear()
        nf._detections.clear()
        nf._excepted.clear()
        nf._beacon_ignore.clear()
        nf._beacon_ignore.update(nf.DEFAULTS["beacon_ignore_ports"])
        nf._wan.update(ips=set(), at=1e18)
        self.addCleanup(setattr, nf, "_names", nf._names)
        nf._names = lambda: {}
        self.nf, self.mdb = nf, mdb
        self.owner = None
        orig_owner, orig_names = router_logs.owner, nf.__dict__.get("_names")
        self.addCleanup(setattr, router_logs, "owner", orig_owner)
        router_logs.owner = lambda ip: self.owner
        self.t0 = 1_800_000_000.0 - (1_800_000_000.0 % nf.WINDOW_SEC)

    def flow(self, src, dst, sport, dport, flags=SYN, proto=6, b=60):
        return {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto, "flags": flags, "bytes": b}

    def alerts(self, rule=None):
        with self.Session() as db:
            q = db.query(self.mdb.SocAlert)
            return q.filter_by(rule=rule).all() if rule else q.all()

    def test_case7_inbound_scan_of_the_wan_is_not_an_outgoing_scan(self):
        """MC-R1's WAN 192.168.0.2 'tried 263 ports on 172.234.162.56': its RST answers to an inbound scan."""
        flows = []
        for i, port in enumerate(range(40001, 40301)):                 # each probe from its own source port, below the scanned port
            flows.append(self.flow("172.234.162.56", "192.168.0.2", 30000 + i, port, SYN))
            flows.append(self.flow("192.168.0.2", "172.234.162.56", port, 30000 + i, RST | ACK))
        for wan in (set(), {"192.168.0.2"}):                            # by the flags alone, and with the router's WAN known
            self.setUp()
            self.nf._wan.update(ips=wan, at=1e18)
            self.nf.ingest(flows, self.t0 + 10)
            self.nf.close_window(self.t0 + self.nf.WINDOW_SEC + 1)
            self.assertEqual(self.alerts("net.portscan"), [], f"wan known: {bool(wan)}")

    def test_a_real_outgoing_port_scan_is_still_seen(self):
        flows = [self.flow("192.168.2.40", "192.168.2.1", 50000, p, SYN) for p in range(1, 200)]
        self.nf.ingest(flows, self.t0 + 10)
        self.nf.close_window(self.t0 + self.nf.WINDOW_SEC + 1)
        self.assertEqual(len(self.alerts("net.portscan")), 1)

    def test_scanner_exception_inside_and_beyond(self):
        self.nf._settings["scanner_exceptions"] = fr.clean_exceptions([{"source": "192.168.2.21", "ports": "1-1024"}])
        self.nf.ingest([self.flow("192.168.2.21", "192.168.2.1", 50000, p, SYN) for p in range(1, 200)], self.t0 + 10)
        self.nf.close_window(self.t0 + self.nf.WINDOW_SEC + 1)
        self.assertEqual(self.alerts("net.portscan"), [])
        self.assertEqual(len(self.nf._excepted), 1)
        t1 = self.t0 + 2 * self.nf.WINDOW_SEC
        self.nf.ingest([self.flow("192.168.2.21", "192.168.2.3", 50000, p, SYN) for p in range(2000, 2200)], t1 + 10)
        self.nf.close_window(t1 + self.nf.WINDOW_SEC + 1)
        a = self.alerts("net.portscan")
        self.assertEqual(len(a), 1)
        self.assertIn("beyond its scanner exception", json.loads(a[0].detail)["message"])

    def _beacon(self, src, dst, dport, every=60, n=15, proto=6, start=None):
        start = start or self.t0
        for i in range(n):
            self.nf.ingest([self.flow(src, dst, 50000 + i, dport, SYN | ACK | PSH, proto)], start + i * every)
        self.nf._detect_beacons({}, start + n * every)

    def test_case8_broadcast_beacon_is_not_alerted(self):
        self._beacon("192.168.2.30", "255.255.255.255", 1947, proto=17)
        self._beacon("192.168.2.30", "8.8.8.8", 10001, proto=17)
        self.assertEqual(self.alerts("net.beacon"), [])

    def test_beacon_to_a_cloud_is_low_unless_the_host_also_scans(self):
        self.owner = {"owner": "Google LLC"}
        self._beacon("192.168.10.50", "34.111.175.102", 443)
        self.assertEqual([a.severity for a in self.alerts("net.beacon")], ["low"])
        # the same host then sweeps the network and scans the router: one combined high alert (psb DESKTOP-RAMQ0TF)
        t1 = self.t0 + 3 * 3600 - (self.t0 + 3 * 3600) % self.nf.WINDOW_SEC
        self.nf.ingest([self.flow("192.168.10.50", "192.168.10.1", 50000, p, SYN) for p in range(1, 200)], t1 + 10)
        self.nf.close_window(t1 + self.nf.WINDOW_SEC + 1)
        c = self.alerts("net.combined")
        self.assertEqual((len(c), c[0].severity), (1, "high"))

    def test_beacon_to_an_unknown_owner_is_medium(self):
        self._beacon("192.168.10.51", "203.0.113.200", 8443)
        self.assertEqual([a.severity for a in self.alerts("net.beacon")], ["medium"])


class Personal(unittest.TestCase):
    def test_personal_devices(self):
        from services import asset_type as at
        self.assertTrue(at.personal(asset_type="other", name="Redmi-Note-14-Pro-5G"))
        self.assertTrue(at.personal(asset_type="mobile", name="x"))
        self.assertTrue(at.personal(asset_type="other", name="SM-L325F"))
        self.assertFalse(at.personal(asset_type="windows", name="MCPROJEKTPC011"))
        self.assertFalse(at.personal(asset_type="mobile", name="iPhone", managed=True))


if __name__ == "__main__":
    unittest.main()

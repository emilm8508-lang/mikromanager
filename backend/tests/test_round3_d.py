"""Round 3, stage D (3.77) regression tests - docs/plan-runda-3.md: the agent's own traffic, scans, accounts and logins.

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import agent_self

SYN, ACK, RST = 0x02, 0x10, 0x04
AGENT = "192.168.1.38"


class _Agent(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        saved = (agent_self._PATH, dict(agent_self._cache))
        self.addCleanup(lambda: (setattr(agent_self, "_PATH", saved[0]), agent_self._cache.clear(), agent_self._cache.update(saved[1])))
        agent_self._PATH = os.path.join(tmp, "agent_self.json")
        agent_self._cache.update(at=time.time(), addr={AGENT})        # the agent's address, as detected


class Traffic(_Agent):
    def setUp(self):
        super().setUp()
        from services import netflow as nf
        nf._settings.clear()
        nf._settings.update(dict(nf.DEFAULTS))
        nf._set_nets(nf.DEFAULTS["local_nets"])
        nf._loaded[0] = True
        for x in (nf._win, nf._tracked, nf._scan_times, nf._excepted, nf._agent_probes):
            x.clear()
        nf._wan.update(ips=set(), at=1e18)
        self.nf = nf
        self.t0 = 1_800_000_000.0 - (1_800_000_000.0 % nf.WINDOW_SEC)

    def flow(self, src, dst, sport, dport, flags):
        return {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": 6, "flags": flags, "bytes": 60}

    def test_case9_the_agents_tries_to_a_dead_address_are_not_its_traffic(self):
        flows = [self.flow(AGENT, "192.168.2.94", 50000 + p, p, SYN) for p in range(20, 53)] * 2      # 66 tries on 33 ports
        flows += [self.flow("192.168.2.94", AGENT, p, 50000 + p, RST | ACK) for p in range(20, 23)]     # anything coming back
        self.nf.ingest(flows, self.t0 + 10)
        h = self.nf._win["hosts"].get("192.168.2.94", {"in": 0, "out": 0, "flows": 0})
        self.assertEqual((h["in"], h["out"], h["flows"]), (0, 0, 0), "no traffic of .94 - neither in nor out")
        self.nf.close_window(self.t0 + self.nf.WINDOW_SEC + 1)
        self.assertNotIn("192.168.2.94", self.nf._tracked, "no series (and so no anomaly) for the target")
        self.assertEqual(len(self.nf._agent_probes), 66)

    def test_the_agents_scan_inside_its_scope_is_no_alert_beyond_it_is(self):
        self.assertTrue(self.nf._scan_allowed("net.portscan", AGENT, [22, 443, 8291], 40, self.t0, {}))
        self.assertEqual(self.nf._excepted[-1]["exception"], "agent")
        import json
        with open(agent_self._PATH, "w") as f:
            json.dump({"scan_ports": [22, 80, 443, 8291, 8728, 8729]}, f)
        self.assertFalse(self.nf._scan_allowed("net.portscan", AGENT, [22, 3389, 445], 40, self.t0, {}), "beyond the declared ports: alerted")
        self.assertFalse(self.nf._scan_allowed("net.portscan", "192.168.1.77", [22], 40, self.t0, {}), "another source: as before")


class Accounts(_Agent):
    def test_full_rights(self):
        self.assertTrue(agent_self.full_rights("full", None))
        self.assertTrue(agent_self.full_rights("ops", "local,telnet,ssh,read,write,policy,test,winbox"))
        self.assertFalse(agent_self.full_rights("mikromanager", "read,api,rest-api,!write,!policy,!sensitive"))
        self.assertFalse(agent_self.full_rights("read", "local,read,winbox,api"))

    def test_case11_logins_per_router_and_hour(self):
        from services import mikrotik_client as mc
        mc._pool.clear()
        self.addCleanup(mc._pool.clear)
        agent_self._logins.clear()
        key = ("192.168.2.90", 8728, "webshot", "pw")

        class Api:
            def __call__(self, cmd):
                return [{}]

            def close(self):
                pass
        for c in ("/system/resource/print", "/system/identity/print", "/system/routerboard/print", "/log/print", "/user/active/print"):
            mc.pooled_call(key, Api, lambda api, c=c: list(api(c)))
        self.assertEqual(agent_self.logins(), {"routers": 1, "per_hour_avg": 1.0, "max": {"ip": "192.168.2.90", "n": 1}}, "one cycle, one login")

    def test_case10_the_agents_account_is_not_a_last_logon(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import logons
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'd.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (logons.SessionLocal, dict(logons._agent_users_cache), logons._SETTINGS_PATH)
        self.addCleanup(lambda: (setattr(logons, "SessionLocal", saved[0]), logons._agent_users_cache.update(saved[1]),
                                 setattr(logons, "_SETTINGS_PATH", saved[2])))
        logons.SessionLocal = Session
        logons._SETTINGS_PATH = os.path.join(tmp, "l.json")
        logons._agent_users_cache.update(at=time.time(), names={"webshot"})
        from datetime import datetime
        r = logons.record([{"host_ip": "192.168.2.90", "user": "webshot", "logon_type": "api", "source_ip": AGENT, "at": datetime.utcnow(), "source": "routeros_log"}])
        self.assertEqual((r["stored"], r["skipped"]), (0, 1))
        self.assertIn("webshot", agent_self.accounts())


class TlsGate(unittest.TestCase):
    def test_no_tls_tries_on_an_address_that_does_not_answer(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import tls_scan, availability, asset_state
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 't.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (tls_scan.SessionLocal, asset_state.SessionLocal, tls_scan.probe, availability._answers, tls_scan.discover, tls_scan.alerts)
        self.addCleanup(lambda: (setattr(tls_scan, "SessionLocal", saved[0]), setattr(asset_state, "SessionLocal", saved[1]),
                                 setattr(tls_scan, "probe", saved[2]), setattr(availability, "_answers", saved[3]),
                                 setattr(tls_scan, "discover", saved[4]), setattr(tls_scan, "alerts", saved[5])))
        tls_scan.SessionLocal = asset_state.SessionLocal = Session
        with Session() as db:
            for ip in ("192.168.2.94", "192.168.2.90"):
                for port in (443, 8443, 8729):
                    db.add(mdb.TlsCheck(ip=ip, port=port))
            db.commit()
        probed = []

        async def probe(ip, port):
            probed.append((ip, port))
            return {"error": "x"}

        async def answers(ip):
            return (ip == "192.168.2.90"), "ping"
        tls_scan.probe, availability._answers = probe, answers
        tls_scan.discover, tls_scan.alerts = (lambda: None), (lambda now=None: {})
        tls_scan._running = False
        r = asyncio.run(tls_scan.run_all())
        self.assertEqual(sorted({ip for ip, _p in probed}), ["192.168.2.90"])
        self.assertEqual(tls_scan._last["skipped_dead"], 3)


if __name__ == "__main__":
    unittest.main()

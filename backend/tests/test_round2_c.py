"""Round 2, stage C (3.68) regression tests - docs/plan-runda-2.md: router logging reasons and script, the API version over a banner.

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import tempfile
import unittest
from datetime import datetime
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import router_logs as rl


def _db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import models.database as mdb
    tmp = tempfile.mkdtemp()
    engine = create_engine(f"sqlite:///{os.path.join(tmp, 'c.db')}", connect_args={"check_same_thread": False})
    mdb.Base.metadata.create_all(engine)
    return mdb, sessionmaker(bind=engine, expire_on_commit=False), tmp


class Reasons(unittest.TestCase):
    def test_errors_are_classified(self):
        self.assertEqual(rl.classify_error("API: TrapError: invalid user name or password (6)"), "credentials_rejected")
        self.assertEqual(rl.classify_error("REST: HTTPStatusError: 401 Unauthorized; API: TrapError: not enough permissions (9)"), "credentials_rejected")
        self.assertEqual(rl.classify_error("API: TrapError: not enough permissions (9)"), "no_api_permission")
        self.assertEqual(rl.classify_error("TimeoutError: "), "timeout")
        self.assertEqual(rl.classify_error("API: ConnectionRefusedError: [WinError 10061]"), "api_unreachable")
        self.assertEqual(rl.classify_error("ValueError: odd"), "error")

    def test_rest_without_json_does_not_hide_the_api_reason(self):
        """3.72: psb PSB and sanmed R4-S1 ... came out as "error" - the REST answer was a web page and the API's part was cut off."""
        page = "ConnectionError: Wszystkie metody dostępu zawiodły. REST: ContentTypeError: 200, message='Attempt to decode JSON with unexpected mimetype: text/html', url='http://192.168.0.1/rest/system/logging/action'"
        self.assertEqual(rl.explain_error(page + " | API: ConnectionRefusedError: [WinError 10061] refused"),
                         ("no_rest_api_closed", "API: ConnectionRefusedError: [WinError 10061] refused"))
        self.assertEqual(rl.explain_error(page + " | API: TimeoutError: ")[0], "no_rest_api_timeout")
        self.assertEqual(rl.explain_error(page + " | API: TrapError: invalid user name or password (6)")[0], "credentials_rejected")
        self.assertEqual(rl.explain_error(page + " | API: TrapError: not enough permissions (9)")[0], "no_api_permission")
        self.assertEqual(rl.explain_error("ConnectionError: x. REST: ClientResponseError: 404, message='Not Found' | API: ConnectionError: api-ssl previously failed for 1.2.3.4, skipping retry")[0],
                         "api_ssl_failed")
        self.assertIn(rl.explain_error(page)[0], ("no_rest_api_closed",), "the API part cut off: still not a bare error")

    def test_swos_and_printers_are_not_routers(self):
        d = lambda **kw: NS(**{"vendor": "mikrotik", "model": None, "board_name": None, "identity": None, "name": None, "mac": None, "has_api": False,
                               "os_source": None, "ros_version": None, **kw})
        self.assertIsNone(rl.router_kind(d(identity="R1", ros_version="7.24.4", has_api=True)))
        self.assertEqual(rl.router_kind(d(identity="SW1", ros_version="2.18", model="CSS326-24G-2S+")), "swos")
        self.assertEqual(rl.router_kind(d(identity="BRN94DDF81D98BE", ros_version="1.37")), "not_routeros")
        self.assertEqual(rl.router_kind(d(identity="BRN30055C32CB07")), "not_routeros")
        self.assertIsNone(rl.router_kind(d(identity="PSB")), "a router nobody gave a credential yet is checked")

    def test_script_is_for_copying(self):
        s = rl.setup_script("192.168.1.5", firewall_logging=True, port=5514)
        self.assertIn('/system logging action add name=mikromanager target=remote remote=192.168.1.5 remote-port=5514', s)
        for t in ("system,!debug", "account", "critical", "error", "warning", "firewall"):
            self.assertIn(f"topics={t} }}", s)
        self.assertNotIn("firewall", rl.setup_script("192.168.1.5"))
        self.assertIn("<AGENT-IP>", rl.setup_script(None))


class CheckLogging(unittest.TestCase):
    def test_reasons_skipped_and_scripts(self):
        mdb, Session, tmp = _db()
        from services import device_client
        saved = (rl._LOGGING_PATH, rl._agent_ip_for, device_client.build_client)
        self.addCleanup(lambda: (setattr(rl, "_LOGGING_PATH", saved[0]), setattr(rl, "_agent_ip_for", saved[1]),
                                 setattr(device_client, "build_client", saved[2]), setattr(mdb, "SessionLocal", old_sl)))
        old_sl = mdb.SessionLocal
        mdb.SessionLocal = Session
        rl._LOGGING_PATH = os.path.join(tmp, "lg.json")
        rl._agent_ip_for = lambda ip: "192.168.1.5"

        class Client:
            def __init__(self, d):
                self.d = d

            async def _try_methods(self, rest, api):
                if self.d.identity == "PSB":
                    raise RuntimeError("API: TrapError: invalid user name or password (6)")
                if rest == "system/logging/action":
                    return [{"name": "remote", "target": "remote", "remote": "192.168.1.5"}] if self.d.identity == "R3" else []
                if rest == "system/logging":
                    return [{"topics": "info", "action": "remote"}] if self.d.identity == "R3" else []
                return [{"chain": "input", "log": "true"}]

        device_client.build_client = lambda d, c: Client(d)
        with Session() as db:
            db.add(mdb.Credential(id=1, name="c", username="u", password_enc="x"))
            db.add(mdb.Device(ip="192.168.1.1", identity="R1", vendor="mikrotik", ros_version="7.20.1", has_api=True, credential_id=1))
            db.add(mdb.Device(ip="192.168.3.1", identity="R3", vendor="mikrotik", ros_version="7.20.1", has_api=True, credential_id=1))
            db.add(mdb.Device(ip="192.168.0.1", identity="PSB", vendor="mikrotik", ros_version="7.19", has_api=True, credential_id=1))
            db.add(mdb.Device(ip="192.168.4.1", identity="R4", vendor="mikrotik", ros_version="7.18"))               # no credential
            db.add(mdb.Device(ip="192.168.1.21", identity="SW1", vendor="mikrotik", ros_version="2.18", model="CSS326"))
            db.add(mdb.Device(ip="192.168.1.181", identity="BRN94DDF81D98BE", vendor="mikrotik", ros_version="1.37"))
            db.commit()
        out = {r["name"]: r for r in asyncio.run(rl.check_logging())}
        self.assertEqual(set(out), {"R1", "R3", "PSB", "R4"}, "SwOS and the printer are not on the list")
        self.assertTrue(out["R3"]["to_agent"])
        self.assertEqual((out["R1"]["reason"], out["R1"]["firewall_logging"]), ("not_configured", True))
        self.assertIn("topics=firewall", out["R1"]["script"])
        self.assertEqual(out["PSB"]["reason"], "credentials_rejected")
        self.assertEqual(out["R4"]["reason"], "no_credential")
        pub = rl.public_summary()
        self.assertEqual((pub["routers"], pub["to_agent"], pub["skipped"]), (4, 1, {"swos": 1, "not_routeros": 1}))
        self.assertEqual({w["n"]: w["r"] for w in pub["why"]}, {"R1": "not_configured", "PSB": "credentials_rejected", "R4": "no_credential"})
        self.assertEqual(sorted(pub["scripts"][0]["routers"]), ["PSB", "R1", "R4"])
        self.assertIn("topics=firewall", pub["scripts"][0]["script"])


class ApiOverBanner(unittest.TestCase):
    def test_case4_routeros_from_the_api_beats_a_banner(self):
        mdb, Session, tmp = _db()
        from services import vuln_scan, exploit_intel
        saved = (vuln_scan.SessionLocal, exploit_intel.info)
        self.addCleanup(lambda: (setattr(vuln_scan, "SessionLocal", saved[0]), setattr(exploit_intel, "info", saved[1])))
        vuln_scan.SessionLocal = Session
        exploit_intel.info = lambda cve: {"kev": True, "epss": None}
        now = datetime.utcnow()
        with Session() as db:
            db.add(mdb.Device(ip="192.168.1.13", identity="R1-S3", vendor="mikrotik", ros_version="7.24.4", has_api=True, os_source="routeros_api"))
            db.add(mdb.VulnHost(id=1, ip="192.168.1.13"))
            db.add(mdb.VulnService(host_id=1, port=21, service_name="ftp", product="MikroTik RouterOS", version="6.40", banner_raw="220 R1-S3 FTP server (MikroTik 6.40) ready"))
            db.add(mdb.VulnFinding(product="MikroTik RouterOS", version="6.40", cve_id="CVE-2018-14847", severity="CRITICAL", cvss_score=9.1,
                                   queried_at=now, match_source="cpe-range", evaluation="affected", fixed_version="6.42.1"))
            db.add(mdb.VulnFinding(product="MikroTik RouterOS", version="7.24.4", cve_id="CVE-2026-86060", severity="HIGH", cvss_score=7.5,
                                   queried_at=now, match_source="cpe-range", evaluation="affected", fixed_version="7.25"))
            db.commit()
        hosts = asyncio.run(vuln_scan.hosts_with_findings())
        cves = {f["cve_id"]: f for h in hosts if h["ip"] == "192.168.1.13" for f in h["findings"]}
        self.assertNotIn("CVE-2018-14847", cves, "the banner's 6.40 is not used: the API says 7.24.4")
        self.assertEqual((cves["CVE-2026-86060"]["product_source"], cves["CVE-2026-86060"]["confidence"]), ("routeros_api", "confirmed"))


if __name__ == "__main__":
    unittest.main()

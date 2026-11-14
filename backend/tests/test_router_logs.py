"""Stage 4 regression tests: router logs read into fields, the router rules, enrichment and correlation (docs/plan-jakosc-danych.md).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import routeros_log as rl  # noqa: E402

IPSEC = "phase1 negotiation failed due to time up 192.168.0.2[500]<=>66.132.159.71[17082] 0577e921aab0e356:85a8ae1ef2819f31"


class Parse(unittest.TestCase):
    def test_lines_into_fields(self):
        p = rl.parse("login failure for user admin from 45.88.1.2 via winbox", "system,error,critical")
        self.assertEqual((p["kind"], p["user"], p["src_ip"], p["service"], p["topics"]), ("login_failed", "admin", "45.88.1.2", "winbox", ["system", "error", "critical"]))
        p = rl.parse("address changed by winbox-3.41/tcp-msg(winbox):admin@192.168.1.10 (/ip address set *1 address=10.0.0.1/24)")
        self.assertEqual((p["kind"], p["user"], p["src_ip"], p["service"], p["action"]), ("config_change", "admin", "192.168.1.10", "winbox", "changed"))
        p = rl.parse(IPSEC)
        self.assertEqual((p["kind"], p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"]), ("ipsec_fail", "66.132.159.71", 17082, "192.168.0.2", 500))
        self.assertEqual(rl.parse("ether1 link down")["interface"], "ether1")
        self.assertEqual(rl.parse("router was rebooted without proper shutdown")["kind"], "power_fail")
        self.assertEqual(rl.parse("server session, sermgr, ssl: no common ciphers")["kind"], "ssl_no_cipher")
        self.assertEqual(rl.parse("something else from 8.8.8.8 happened")["src_ip"], "8.8.8.8")

    def test_signature_groups_the_same_kind_of_line(self):
        other = IPSEC.replace("66.132.159.71[17082]", "147.185.132.37[4500]").replace("0577e921aab0e356:85a8ae1ef2819f31", "aaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbb")
        self.assertEqual(rl.signature(IPSEC), rl.signature(other))
        self.assertNotEqual(rl.signature(IPSEC), rl.signature("server session, sermgr, ssl: no common ciphers"))


class Rules(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, router_logs, mikrotik_client, netflow
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'r.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        soc.SessionLocal = self.Session
        soc._new_alert_events.clear()
        router_logs._SETTINGS_PATH = os.path.join(tmp, "rl.json")
        router_logs._LOGINS_PATH = os.path.join(tmp, "logins.json")
        router_logs._OWNER_PATH = os.path.join(tmp, "owners.json")
        router_logs._LOGGING_PATH = os.path.join(tmp, "logging.json")
        for x in (router_logs._windows, router_logs._agg, router_logs._seen_lines, router_logs._owner_cache, router_logs._logins):
            x.clear()
        router_logs._logins_loaded[0] = False
        router_logs._owner_queue = None
        mikrotik_client._ACCESS_LOG.clear()
        netflow._mgmt.clear()
        self.mdb, self.rl, self.mc, self.nf = mdb, router_logs, mikrotik_client, netflow
        self.t = time.time()

    def alerts(self, rule=None):
        with self.Session() as db:
            q = db.query(self.mdb.SocAlert)
            if rule:
                q = q.filter_by(rule=rule)
            return q.all()

    def line(self, msg, device="MC-R1", ip="192.168.1.1", dt=0, via="syslog", app=None):
        return self.rl.handle(device=device, device_ip=ip, message=msg, app=app, via=via, now=self.t + dt,
                              at=datetime.utcnow() + timedelta(seconds=dt))

    def test_failed_logins_one_alert_with_sources_users_and_owner(self):
        for i in range(6):
            self.line(f"login failure for user {'admin' if i % 2 else 'root'} from 45.88.1.{i} via winbox", dt=i)
        a = self.alerts("routerlog.login_failed")
        self.assertEqual(len(a), 1)
        d = json.loads(a[0].detail)
        self.assertEqual(a[0].severity, "high", "the sources are outside the management networks")
        self.assertEqual(sorted(d["users"]), ["admin", "root"])
        self.assertEqual(len(d["sources"]), 6)
        self.assertEqual(d["services"], ["winbox"])

    def test_case13_counts_of_one_router_do_not_add_up_with_another(self):
        for i in range(3):
            self.line("login failure for user admin from 10.0.0.5 via ssh", device="A", ip="10.1.1.1", dt=i)
            self.line("login failure for user admin from 10.0.0.5 via ssh", device="B", ip="10.2.2.1", dt=i)
        self.assertEqual(self.alerts("routerlog.login_failed"), [])

    def test_logins_new_source_and_outside(self):
        self.line("user admin logged in from 192.168.1.10 via winbox")
        self.assertEqual(self.alerts(), [], "the first login is the baseline")
        self.line("user admin logged in from 192.168.1.10 via winbox", dt=700)
        self.assertEqual(self.alerts(), [])
        self.line("user admin logged in from 192.168.1.77 via winbox", dt=1400)
        self.assertEqual([a.severity for a in self.alerts("routerlog.login_new_source")], ["medium"])
        self.line("user admin logged in from 83.10.20.30 via ssh", dt=2100)
        a = self.alerts("routerlog.login_outside")
        self.assertEqual((len(a), a[0].severity, a[0].mitre), (1, "high", "T1078"))

    def test_config_change_who_and_from_where(self):
        self.line("address changed by winbox-3.41/tcp-msg(winbox):admin@192.168.1.10 (/ip address set *1)")
        self.line("filter rule added by admin", dt=5)
        a = self.alerts("routerlog.config_change")
        self.assertEqual((len(a), a[0].count, a[0].severity), (1, 2, "low"))
        self.assertIn("admin", json.loads(a[0].detail)["users"])

    def test_ipsec_from_a_known_scanner_is_low_and_labelled(self):
        for i in range(10):
            self.line(IPSEC.replace("66.132.159.71", "147.185.132.37"), dt=i * 30)
        a = self.alerts("routerlog.ipsec_from_outside")
        self.assertEqual((len(a), a[0].severity), (1, "info"))
        d = json.loads(a[0].detail)
        self.assertTrue(d["scanner"])
        self.assertIn("Palo Alto", d["sources"][0])

    def test_ipsec_from_unknown_addresses(self):
        for i in range(10):
            self.line(IPSEC.replace("66.132.159.71", f"66.132.160.{i}"), dt=i * 30)
        a = self.alerts("routerlog.ipsec_from_outside")
        self.assertEqual((len(a), a[0].severity), (1, "low"))
        self.assertFalse(json.loads(a[0].detail)["scanner"])

    def test_tls_failure_traced_to_this_agent(self):
        """mcprojekt AP1-AP3, R2-S1..S3: ~500 "ssl: no common ciphers" each - the agent's own hourly api-ssl try."""
        self.mc._ACCESS_LOG.append({"at": datetime.utcnow() - timedelta(minutes=2), "kind": "api-ssl", "ip": "192.168.2.22", "what": "/system/resource/print",
                                    "origin": "resource_monitor._poll", "via": None})
        self.line("server session, sermgr, ssl: no common ciphers", device="AP1", ip="192.168.2.22")
        a = self.alerts("routerlog.tls_failed")
        self.assertEqual((len(a), a[0].severity), (1, "info"))
        self.assertIn("this agent", json.loads(a[0].detail)["caused_by"])

    def test_tls_failure_traced_by_netflow(self):
        self.nf._mgmt.append((self.t, "192.168.2.150", "192.168.2.22", 443))
        self.line("server session, sermgr, ssl: no common ciphers", device="AP1", ip="192.168.2.22")
        a = self.alerts("routerlog.tls_failed")
        self.assertEqual(a[0].severity, "low")
        self.assertIn("192.168.2.150", json.loads(a[0].detail)["caused_by"])

    def test_the_same_line_by_syslog_and_api_counts_once(self):
        self.line("filter rule added by admin")
        r = self.line("filter rule added by admin", dt=60, via="api")
        self.assertTrue(r["duplicate"])
        self.assertEqual(self.alerts("routerlog.config_change")[0].count, 1)

    def test_api_read_lines_go_through_the_rules(self):
        from services import resource_monitor
        logs = [{"time": "10:00:01", "topics": "system,error,critical", "message": "login failure for user admin from 10.0.0.9 via ssh"},
                {"time": "10:00:02", "topics": "system,error", "message": "unknown thing broke"},
                {"time": "10:00:03", "topics": "system,error", "message": "unknown thing broke again 42"}]
        ev = resource_monitor._check_device_log_events({}, 1, "R2", logs, "192.168.2.1")
        self.assertEqual(len(ev), 2, "the failed login went to the router rules")
        self.assertEqual(ev[0]["signature"], "unknown thing broke")
        self.assertNotEqual(ev[0]["signature"], ev[1]["signature"])

    def test_power_loss_and_psu(self):
        self.line("router was rebooted without proper shutdown")
        self.line("psu1 state changed to fail", dt=5)
        self.assertEqual(self.alerts("routerlog.power_fail")[0].severity, "medium")
        self.assertEqual(self.alerts("routerlog.psu_fail")[0].severity, "high")


class SyslogIntegration(unittest.TestCase):
    def setUp(self):
        Rules.setUp(self)
        from services import syslog_receiver, iface_roles
        self.sr = syslog_receiver
        syslog_receiver._settings = dict(syslog_receiver.DEFAULTS)
        syslog_receiver._windows.clear()
        self._orig = iface_roles.router_addresses
        iface_roles.router_addresses = lambda max_age_sec=None: [
            {"device_id": 1, "device_ip": "192.168.1.1", "ip": "192.168.0.2", "iface": "ether1", "role": "wan"},
            {"device_id": 1, "device_ip": "192.168.1.1", "ip": "192.168.1.1", "iface": "bridge", "role": "access"}]

    def tearDown(self):
        from services import iface_roles
        iface_roles.router_addresses = self._orig

    alerts = Rules.alerts

    def ev(self, msg, app="system,error,critical"):
        return {"kind": "syslog", "ip": "192.168.1.1", "name": "MC-R1", "asset_id": None, "message": msg, "app": app, "severity": 3, "at": datetime.utcnow()}

    def test_builtin_rule_is_not_doubled_and_wan_link_is_high(self):
        for i in range(5):
            self.sr.evaluate(self.ev(f"login failure for user admin from 10.0.0.{i} via winbox"), now=self.t + i)
        self.assertEqual([a.rule for a in self.alerts()], ["routerlog.login_failed"])
        self.sr.evaluate(self.ev("ether1 link down", app="interface,info"), now=self.t + 10)
        a = self.alerts("syslog.link_down")
        self.assertEqual((a[0].severity, a[0].title), ("high", "WAN link down: ether1"))


class LoggingConfig(unittest.TestCase):
    def test_judge_logging(self):
        from services import router_logs
        actions = [{"name": "memory", "target": "memory"}, {"name": "remote", "target": "remote", "remote": "192.168.2.55"}]
        rules = [{"topics": "info", "action": "memory"}, {"topics": "critical,error,warning", "action": "remote"}]
        j = router_logs.judge_logging(actions, rules, "192.168.2.55")
        self.assertEqual((j["to_agent"], j["remote"], j["topics"]), (True, ["192.168.2.55"], ["critical,error,warning"]))
        self.assertFalse(router_logs.judge_logging(actions, rules, "192.168.2.99")["to_agent"])
        self.assertFalse(router_logs.judge_logging(actions, [{"topics": "info", "action": "memory"}], "192.168.2.55")["to_agent"])

    def test_rdap_owner_and_scanner_name(self):
        from services import router_logs
        data = {"name": "CENSYS-ARIN-01", "country": "US", "entities": [{"vcardArray": ["vcard", [["fn", {}, "text", "Censys, Inc."]]]}]}
        o = router_logs.parse_rdap(data)
        self.assertEqual((o["owner"], o["country"]), ("Censys, Inc.", "US"))
        self.assertTrue(o["scanner"])

    def test_api_ssl_retries_back_off(self):
        from services import mikrotik_client as mc
        mc._api_ssl_failures.clear()
        for n, ttl in ((1, 3600), (2, 7200), (3, 14400), (9, 86400)):
            mc._api_ssl_failures["10.0.0.1"] = n
            self.assertEqual(mc._api_ssl_ttl("10.0.0.1"), ttl)


if __name__ == "__main__":
    unittest.main()

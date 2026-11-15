"""Round 2, stage A (3.66) regression tests - docs/plan-runda-2.md.

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MUSL = ("sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass "
        "(related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any "
        "password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.")


def _db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import models.database as mdb
    tmp = tempfile.mkdtemp()
    engine = create_engine(f"sqlite:///{os.path.join(tmp, 'a.db')}", connect_args={"check_same_thread": False})
    mdb.Base.metadata.create_all(engine)
    return mdb, sessionmaker(bind=engine, expire_on_commit=False), tmp


class EnvironmentConditions(unittest.TestCase):
    def test_conditions_read_from_the_description(self):
        from services import vuln_env
        self.assertEqual(vuln_env.conditions(MUSL), {"os": "linux", "libc": "musl", "pam": False})
        self.assertEqual(vuln_env.conditions("A buffer overflow in nginx before 1.25.3 allows remote attackers to ..."), {})

    def test_case1_ubuntu_is_excluded_alpine_matches(self):
        from services import vuln_env
        c = vuln_env.conditions(MUSL)
        ubuntu = vuln_env.host_env(banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", linux_distro="Ubuntu 22.04.4 LTS")
        self.assertEqual(vuln_env.check(c, ubuntu)[0], "excluded")
        oracle = vuln_env.host_env(os_name="Oracle Linux Server 9.8")
        self.assertEqual(vuln_env.check(c, oracle)[0], "excluded")
        alpine = vuln_env.host_env(banner="SSH-2.0-OpenSSH_9.6", linux_distro="Alpine Linux v3.19")
        self.assertEqual(vuln_env.check(c, alpine), ("ok", None))

    def test_case2_windows_openssh_gets_no_linux_cve(self):
        from services import vuln_env
        win = vuln_env.host_env(banner="SSH-2.0-OpenSSH_for_Windows_8.6")
        verdict, why = vuln_env.check(vuln_env.conditions(MUSL), win)
        self.assertEqual(verdict, "excluded")
        self.assertIn("Linux", why)

    def test_unknown_platform_is_only_unconfirmed(self):
        from services import vuln_env
        printer = vuln_env.host_env(banner="SSH-2.0-OpenSSH_3.9p1", asset_type="printer")
        self.assertEqual(vuln_env.check(vuln_env.conditions(MUSL), printer)[0], "unconfirmed")
        self.assertEqual(vuln_env.check({"config": "when the X option is enabled"}, {})[0], "unconfirmed")


class HostView(unittest.TestCase):
    """The per-host findings that the alerts, the risk and Central read (vuln_scan.hosts_with_findings)."""

    def setUp(self):
        mdb, Session, self.tmp = _db()
        from services import vuln_scan, exploit_intel
        old_sl, old_info = vuln_scan.SessionLocal, exploit_intel.info
        self.addCleanup(lambda: (setattr(vuln_scan, "SessionLocal", old_sl), setattr(exploit_intel, "info", old_info)))
        vuln_scan.SessionLocal = Session
        exploit_intel.info = lambda cve: {"kev": cve == "CVE-2026-123158", "epss": None}
        self.mdb, self.Session, self.vs = mdb, Session, vuln_scan
        now = datetime.utcnow()
        with Session() as db:
            for i, (ip, banner, ver) in enumerate([("10.0.0.1", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "8.9"),
                                                   ("10.0.0.2", "SSH-2.0-OpenSSH_9.6", "9.6"),
                                                   ("10.0.0.3", "SSH-2.0-OpenSSH_for_Windows_8.6", "8.6"),
                                                   ("10.0.0.4", "SSH-2.0-OpenSSH_3.9p1", "3.9")], start=1):
                db.add(mdb.VulnHost(id=i, ip=ip))
                db.add(mdb.VulnService(host_id=i, port=22, service_name="ssh", product="OpenSSH", version=ver, banner_raw=banner))
                db.add(mdb.VulnFinding(product="OpenSSH", version=ver, cve_id="CVE-2026-123158", severity="HIGH", cvss_score=8.1, summary=MUSL,
                                       queried_at=now, match_source="cpe-range", evaluation="affected", fixed_version="10.6"))
                db.add(mdb.VulnRemediation(product="OpenSSH", version=ver, cve_id="CVE-2026-123158", severity="HIGH", status="open"))
            db.add(mdb.LinuxHost(ip="10.0.0.2", distro_id="alpine", distro_pretty="Alpine Linux v3.19"))
            db.add(mdb.Asset(key="ip:10.0.0.4", ip="10.0.0.4", asset_type="printer"))
            db.commit()

    def _by_ip(self, **kw):
        return {h["ip"]: h["findings"][0] for h in asyncio.run(self.vs.hosts_with_findings(**kw))}

    def test_environment_closes_and_caps(self):
        f = self._by_ip()
        self.assertEqual(f["10.0.0.1"]["status"], "resolved")
        self.assertTrue(f["10.0.0.1"]["note"].startswith("[auto_closed: environment_not_affected]"))
        self.assertEqual(f["10.0.0.3"]["status"], "resolved")
        self.assertEqual((f["10.0.0.2"]["status"], f["10.0.0.2"]["confidence"]), ("open", "suspected"), "Alpine: matched, a banner is a hint")
        self.assertEqual((f["10.0.0.4"]["status"], f["10.0.0.4"]["confidence"]), ("open", "suspected"))
        self.assertEqual(f["10.0.0.4"]["environment"]["verdict"], "unconfirmed")
        before = self._by_ip(env=False)
        self.assertEqual(before["10.0.0.3"]["confidence"], "likely", "the view before 3.66: Windows OpenSSH was 'likely'")

    def test_case3_suspected_raises_no_critical_and_no_kev_risk(self):
        from services import soc_rules, soc_risk
        out = asyncio.run(soc_rules._rule_new_vuln({}))
        sev = {a["ip"]: a["severity"] for a in out}
        self.assertNotIn("10.0.0.1", sev)
        self.assertNotIn("10.0.0.3", sev)
        self.assertEqual((sev["10.0.0.2"], sev["10.0.0.4"]), ("low", "low"))
        findings = self._by_ip()
        row = {"vulns": {"critical": 0, "high": 1}, "lifecycle": None, "scan_level": "basic", "type": "linux"}
        open_f = [findings["10.0.0.4"]]
        kev = sorted({c["cve_id"] for c in open_f if c.get("kev") and c.get("confidence") != "suspected"})
        self.assertEqual(kev, [])
        self.assertFalse(any(f["k"] == "kev" for f in soc_risk._factors(row, [], [], [], {}, open_f, kev)))

    def test_banner_superseded_by_the_package_audit(self):
        with self.Session() as db:
            db.add(self.mdb.VulnPackage(host_id=1, name="openssh-server", version="1:8.9p1-3ubuntu0.10"))
            db.commit()
        self.assertNotIn("10.0.0.1", self._by_ip(), "the host's package version decides, not the banner")


class EnvironmentPass(unittest.TestCase):
    def test_pass_closes_the_critical_alerts_and_counts(self):
        import json
        mdb, Session, tmp = _db()
        from services import vuln_scan, vuln_reeval, exploit_intel, soc, assets
        saved = (vuln_scan.SessionLocal, vuln_reeval.SessionLocal, soc.SessionLocal, exploit_intel.info, vuln_reeval._PATH)
        self.addCleanup(lambda: (setattr(vuln_scan, "SessionLocal", saved[0]), setattr(vuln_reeval, "SessionLocal", saved[1]),
                                 setattr(soc, "SessionLocal", saved[2]), setattr(exploit_intel, "info", saved[3]),
                                 setattr(vuln_reeval, "_PATH", saved[4])))
        vuln_scan.SessionLocal = vuln_reeval.SessionLocal = soc.SessionLocal = Session
        exploit_intel.info = lambda cve: {"kev": True, "epss": None}
        vuln_reeval._PATH = os.path.join(tmp, "r.json")
        risk_inputs = []

        async def fake_compute():
            by_ip = assets._vuln_cache["by_ip"]
            risk_inputs.append(by_ip)
            return [{"name": ip, "ip": ip, "level": "high" if any(f.get("confidence") != "suspected" and f["status"] == "open" for f in fl) else "low",
                     "score": 94.0 if any(f.get("confidence") != "suspected" and f["status"] == "open" for f in fl) else 10.0} for ip, fl in by_ip.items()]
        from services import soc_risk
        old_compute = soc_risk.compute
        soc_risk.compute = fake_compute
        self.addCleanup(lambda: setattr(soc_risk, "compute", old_compute))
        with Session() as db:
            db.add(mdb.VulnHost(id=1, ip="192.168.0.124"))
            db.add(mdb.VulnService(host_id=1, port=22, service_name="ssh", product="OpenSSH", version="8.6", banner_raw="SSH-2.0-OpenSSH_for_Windows_8.6"))
            db.add(mdb.VulnFinding(product="OpenSSH", version="8.6", cve_id="CVE-2026-123158", severity="HIGH", cvss_score=8.1, summary=MUSL,
                                   queried_at=datetime.utcnow(), match_source="cpe-range", evaluation="affected"))
            db.add(mdb.SocAlert(fingerprint="rule.new_vuln|hyper-v|192.168.0.124|CVE-2026-123158", rule="rule.new_vuln", source="rules",
                                category="vulnerability", severity="critical", rank=5, device_name="HYPER-V", ip="192.168.0.124", status="new",
                                detail=json.dumps({"ip": "192.168.0.124", "cve": "CVE-2026-123158"})))
            db.commit()
        st = asyncio.run(vuln_reeval.env_pass())
        self.assertIsNone(st.get("error"), st)
        self.assertEqual((st["before"]["kev_counted"], st["after"]["kev_counted"], st["after"]["environment_closed"]), (1, 0, 1))
        self.assertEqual((st["vuln_alerts_before"], st["vuln_alerts_after"]), ({"critical": 1}, {}))
        self.assertEqual(st["alerts_closed"]["environment"], 1)
        self.assertEqual(st["risk_biggest_drops"][0], {"asset": "192.168.0.124", "before": 94.0, "after": 10.0})
        with Session() as db:
            self.assertEqual(db.query(mdb.SocAlert).one().closed_by, "auto: environment_not_affected")
        self.assertEqual(vuln_reeval._load()["env_pass"]["version"], vuln_reeval.ENV_VERSION)


class RestartTime(unittest.TestCase):
    def test_case5_pending_since_the_host_says(self):
        from services import server_health as sh
        boot = datetime(2026, 11, 1, 6, 0)
        cause = datetime(2026, 11, 10, 3, 12)
        ep = lambda t: int((t - datetime(1970, 1, 1)).total_seconds())
        self.assertEqual(sh.parse_linux_reboot(f"REBOOT_REQUIRED {ep(cause)} {ep(boot)} file"), (True, cause, "file"))
        self.assertEqual(sh.parse_linux_reboot(f"REBOOT_REQUIRED {ep(boot) - 60} {ep(boot)} kernel"), (True, None, "unknown"),
                         "a kernel installed before the last boot is not why it waits now")
        self.assertEqual(sh.parse_linux_reboot(""), (False, None, ""))

    def test_never_the_time_it_was_first_read(self):
        from types import SimpleNamespace as NS
        from services import server_health as sh
        h = NS(reboot_required=False, reboot_required_since=None, reboot_since_source=None)
        sh.note_reboot(h, True, None, "unknown")
        self.assertEqual((h.reboot_required, h.reboot_required_since, h.reboot_since_source), (True, None, "unknown"))
        sh.note_reboot(h, True, datetime(2026, 11, 10), "update_log")
        sh.note_reboot(h, True, datetime(2026, 11, 14, 17, 53), "agent_install")
        self.assertEqual((h.reboot_required_since, h.reboot_since_source), (datetime(2026, 11, 10), "update_log"), "the earliest known time is kept")
        sh.note_reboot(h, False, None, "")
        self.assertEqual((h.reboot_required_since, h.reboot_since_source), (None, None))

    def test_windows_pending_since_from_the_install_task(self):
        from services import windows_manage as wm
        r = wm.describe_install_result({"Stage": "reboot_pending", "PendingSince": "2026-11-10T08:30:00.0000000+01:00"})
        self.assertEqual(wm.pending_since_utc(r["pending_since"]), datetime(2026, 11, 10, 7, 30))
        self.assertIsNone(wm.pending_since_utc("not a time"))

    def test_migration_forgets_the_deploy_time(self):
        from sqlalchemy import create_engine, text
        import models.database as mdb
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'm.db')}")
        with engine.begin() as c:
            c.execute(text("CREATE TABLE windows_hosts (id INTEGER PRIMARY KEY, ip VARCHAR, reboot_required BOOLEAN, reboot_required_since DATETIME)"))
            c.execute(text("INSERT INTO windows_hosts VALUES (1, '10.0.0.1', 1, '2026-11-14 17:53:10'), (2, '10.0.0.2', 0, NULL)"))
        old = mdb.engine
        self.addCleanup(lambda: setattr(mdb, "engine", old))
        mdb.engine = engine
        mdb._migrate_add_columns()
        mdb._migrate_add_columns()                                  # idempotent
        with engine.begin() as c:
            rows = c.execute(text("SELECT id, reboot_required_since, reboot_since_source FROM windows_hosts ORDER BY id")).all()
        self.assertEqual([tuple(r) for r in rows], [(1, None, "unknown"), (2, None, None)])


class PersonalDevices(unittest.TestCase):
    def test_case6_company_pc_is_not_personal_a_phone_is(self):
        from services import asset_type as at
        company = at.company_prefixes(["MCPROJEKTPC007", "MCPROJEKTPC011", "DC1", "Galaxy-A52"])
        self.assertEqual(company, {"MCPROJEKTPC"})
        p, why = at.personal_signal(name="MCPROJEKTPC014", oui_vendor="Hangzhou BroadLink Technology", company=company, asset_type="mobile")
        self.assertEqual((p, why), (False, "company naming scheme MCPROJEKTPC*"))
        p, why = at.personal_signal(name="Redmi-Note-13-5G", random_mac=True, company=company)
        self.assertTrue(p)
        self.assertIn("phone name", why)
        self.assertIn("random MAC", why)
        self.assertEqual(at.personal_signal(name="KSIEGOWOSC", oui_vendor="Xerox", asset_type="mobile"), (False, "no personal signal"))
        self.assertFalse(at.personal_signal(name=None, random_mac=True)[0], "a random MAC alone is not enough")
        self.assertTrue(at.personal_signal(name="unknown", dhcp_class="android-dhcp-14")[0])
        self.assertFalse(at.personal_signal(name="Galaxy-S21", managed=True)[0])

    def test_dhcp_class_is_read_from_the_lease(self):
        from services import directory_merge as dm
        out = dm.build([{"dev": {"name": "R1"}, "leases": [{"address": "192.168.1.50", "mac-address": "AA:BB:CC:00:11:22", "host-name": "phone",
                                                             "class-id": "android-dhcp-14", "status": "bound"}], "arp": []}])
        self.assertEqual(out[0]["dhcp_class"], "android-dhcp-14")


class ScannerSuggestions(unittest.TestCase):
    def test_case10_every_6h_for_a_week_is_suggested_once_is_not(self):
        from services import flow_rules as fr
        week = [i * 6 * 3600 + ((i * 7) % 11 - 5) * 120 for i in range(28)]          # 6 h +-10 min for 7 days
        del week[9]                                                                  # one run missed (a restart)
        r = fr.regular(week)
        self.assertIsNotNone(r)
        self.assertEqual(r["every_h"], 6.0)
        self.assertGreaterEqual(r["span_h"], 160)
        self.assertIsNone(fr.regular([0]))
        self.assertIsNone(fr.regular([0, 6 * 3600, 12 * 3600, 18 * 3600]), "under a day of history is no rhythm")
        ports, alike = fr.common_ports([[22, 80, 443, 445], [22, 80, 443, 445, 3389], [22, 80, 443]])
        self.assertEqual((ports, alike >= 0.7), ([22, 80, 443, 445], True))

    def test_suggestion_proposes_a_range_and_adds_nothing(self):
        from services import netflow as nf
        saved = (dict(nf._scan_times), dict(nf._scan_ports), dict(nf._settings), nf._names)
        self.addCleanup(lambda: (nf._scan_times.clear(), nf._scan_times.update(saved[0]), nf._scan_ports.clear(), nf._scan_ports.update(saved[1]),
                                 nf._settings.clear(), nf._settings.update(saved[2]), setattr(nf, "_names", saved[3])))
        now = 1_800_000_000.0
        nf._scan_times.clear()
        nf._scan_ports.clear()
        nf._scan_times["192.168.1.102"] = [now - 7 * 86400 + i * 6 * 3600 for i in range(28)]
        nf._scan_ports["192.168.1.102"] = [[22, 80, 443, 444, 445, 6556]] * 10
        nf._settings["scanner_exceptions"] = []
        nf._names = lambda: {"192.168.1.102": {"name": "check-mk"}}
        out = nf.suggested_exceptions(now)
        self.assertEqual(out[0]["proposal"], {"source": "192.168.1.102", "ports": "22,80,443-445,6556", "every_h": 6.0})
        self.assertEqual(nf._settings["scanner_exceptions"], [], "never added by itself")


class NetflowCount(unittest.TestCase):
    def test_summary_counts_the_alerts_not_a_list_in_memory(self):
        mdb, Session, tmp = _db()
        from services import netflow as nf
        old = mdb.SessionLocal
        self.addCleanup(lambda: setattr(mdb, "SessionLocal", old))
        mdb.SessionLocal = Session
        now = datetime(2026, 11, 14, 15, 0)
        with Session() as db:
            for ip, at in (("192.168.0.140", now - timedelta(minutes=30)), ("192.168.0.77", now - timedelta(hours=1, minutes=40)),
                           ("192.168.0.9", now - timedelta(days=2))):
                db.add(mdb.SocAlert(fingerprint=f"net.portscan|{ip}", rule="net.portscan", source="rules", category="network", severity="medium",
                                    rank=3, device_name=ip, ip=ip, status="new", first_seen=at, last_seen=at))
            db.commit()
        nf._detections.clear()                                     # a restart: the list in memory is empty, the alerts are not
        self.assertEqual(nf.detections_by_rule_24h(now), {"net.portscan": 2})


class WindowsName(unittest.TestCase):
    def test_os_name_follows_the_edition(self):
        from services import windows_manage as wm
        p = wm._parse_resources({"Mem": {"TotalVisibleMemorySize": 1000, "FreePhysicalMemory": 500, "Caption": "Microsoft Windows Server 2022 Standard"}})
        self.assertEqual(p["os_name"], "Microsoft Windows Server 2022 Standard")
        self.assertIsNone(wm._parse_resources({"Mem": {}})["os_name"])


if __name__ == "__main__":
    unittest.main()

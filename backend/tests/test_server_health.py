"""Stage 6 regression tests: servers and hardware (services/server_health.py, asset_lifecycle, dell / windows parsing).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolate import swap, swap_class  # noqa: E402

from services import server_health as sh  # noqa: E402

NOW = datetime(2026, 11, 14, 12, 0)


class Health(unittest.TestCase):
    def test_case11_five_is_ok_on_its_scale_and_never_raw(self):
        self.assertEqual(sh.normalize_health("5", "HealthState"), ("OK", None))
        self.assertEqual(sh.normalize_health(25, "HealthState")[0], "Critical")
        self.assertEqual(sh.normalize_health("2", "PrimaryStatus")[0], "Warning")
        self.assertEqual(sh.normalize_health("5", "snmp")[0], "Critical")
        state, err = sh.normalize_health("5")
        self.assertIsNone(state)
        self.assertIn("without its scale", err)
        self.assertEqual(sh.normalize_health("Critical"), ("Critical", None))
        self.assertEqual(sh.normalize_health("Degraded")[0], "Warning")
        self.assertIsNone(sh.normalize_health("Unknown")[0])
        self.assertIsNotNone(sh.normalize_health("purple")[1])

    def test_ism_reading_is_normalised(self):
        from services import dell_local
        r = dell_local._parse_ism({"HealthState": 5, "Model": "PowerEdge R640"})
        self.assertEqual((r["health_rollup"], r["parse_error"]), ("OK", None))

    def test_stored_raw_value_is_not_shown(self):
        from services import dell_monitor
        self.assertIsNone(dell_monitor._norm("5"))
        self.assertEqual(dell_monitor._norm("Warning"), "Warning")

    def test_component_detail_names_the_power_supply(self):
        det = {"power": {"psus": [{"name": "PS1", "health": "Critical", "state": "Input lost"}, {"name": "PS2", "health": "OK"}], "redundancy": "Critical"},
               "fans": [{"name": "Fan3", "health": "Warning", "rpm": 0}], "temps": [{"name": "CPU1 Temp", "health": "OK", "c": 60}]}
        d = sh.component_detail(det)
        self.assertEqual(d["power"], ["PS1: Critical (Input lost)", "redundancy: Critical"])
        self.assertEqual(d["fans_temperature"], ["Fan3: Warning (0 RPM)"])


class Licence(unittest.TestCase):
    ROWS = [{"Name": "Windows(R), ServerStandardEval edition", "Description": "Windows(R) Operating System, TIMEBASED_EVAL channel",
             "LicenseStatus": 1, "GracePeriodRemaining": 20 * 1440}]

    def test_evaluation_and_days_left(self):
        lic = sh.license(self.ROWS, NOW)
        self.assertTrue(lic["evaluation"])
        self.assertEqual(lic["days_left"], 20.0)
        self.assertEqual(lic["expires_at"], NOW + timedelta(days=20))
        self.assertIsNone(sh.license([{"Name": "Windows(R), ServerStandard edition", "LicenseStatus": 1, "GracePeriodRemaining": 0}], NOW)["expires_at"])

    def test_alert_steps(self):
        self.assertEqual(sh.license_alert({"days_left": 20}, False), (30, "medium"))
        self.assertEqual(sh.license_alert({"days_left": 10}, False), (14, "high"))
        self.assertEqual(sh.license_alert({"days_left": 10}, True), (14, "critical"), "a domain controller / file server")
        self.assertEqual(sh.license_alert({"days_left": 2}, False), (3, "critical"))
        self.assertEqual(sh.license_alert({"days_left": -1}, False), (0, "critical"))
        self.assertIsNone(sh.license_alert({"days_left": 90}, True))

    def test_windows_resources_carry_the_licence(self):
        from services import windows_manage
        r = windows_manage._parse_resources({"Disks": [], "Mem": {}, "Cpu": 3, "Lic": self.ROWS[0]})
        self.assertTrue(r["license"]["evaluation"])


class DisksRestarts(unittest.TestCase):
    def test_boot(self):
        gb = 1024 ** 3
        self.assertEqual(sh.boot_space("/boot", gb, int(0.8 * gb), 10)[0], "medium")          # oracle1: 0.2 GB with 10 updates
        self.assertEqual(sh.boot_space("/boot", gb, int(0.9 * gb), 10)[0], "high")
        self.assertIsNone(sh.boot_space("/boot", gb, int(0.5 * gb), 10))
        self.assertIsNone(sh.boot_space("/", gb, int(0.99 * gb), 10), "the root disk has the forecast, not this rule")

    def test_restart_age(self):
        self.assertIsNone(sh.restart_age(NOW - timedelta(days=3), NOW, False))
        self.assertEqual(sh.restart_age(NOW - timedelta(days=8), NOW, False), ("low", 8))
        self.assertEqual(sh.restart_age(NOW - timedelta(days=8), NOW, True), ("medium", 8))


class PowerTemp(unittest.TestCase):
    def test_hyperv_r2_cases(self):
        """mcprojekt HYPERV-R2: 478 W instead of 187 W, CPU at 85 C."""
        self.assertEqual(sh.power_temp(478, 187, 85, 20, "OK", None)["verdict"], "cooling")
        self.assertEqual(sh.power_temp(478, 187, 85, 80, "OK", None)["verdict"], "load")
        self.assertEqual(sh.power_temp(478, 187, 70, 80, "Critical", None)["verdict"], "cooling")
        self.assertEqual(sh.power_temp(478, 187, None, None, None, None)["verdict"], "unclear")
        self.assertIsNone(sh.power_temp(200, 187, 60, 30, "OK", None))


class Lifecycle(unittest.TestCase):
    def test_eol_with_source_and_esu(self):
        from services import asset_lifecycle as l
        f = l.lifecycle("Microsoft Windows Server 2012 R2 Foundation", today=date(2026, 11, 14))
        self.assertEqual((f["status"], f["esu_until"]), ("eol", None))
        self.assertIn("no Extended Security Updates", f["note"])
        self.assertIn("Microsoft", f["source"])
        self.assertEqual(l.lifecycle("Microsoft Windows Server 2012 R2 Standard", today=date(2026, 6, 1))["esu_until"], "2026-10-13")
        self.assertEqual(l.lifecycle("Oracle Linux Server", "8.10")["product"], "Oracle Linux 8")
        self.assertIn("evaluation", l.lifecycle("Microsoft Windows Server 2022 Standard Evaluation")["note"])


class Cycle(unittest.TestCase):
    def test_findings_raise_and_close(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, metrics
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 's.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        for m in (mdb, soc, metrics):
            swap(self, m, "SessionLocal", Session)
        gb = 1024 ** 3
        with Session() as db:
            db.add(mdb.WindowsHost(id=1, ip="10.0.0.3", hostname="DC2", managed=True, license_name="ServerStandardEval", license_eval=True,
                                   license_status="licensed", license_expires_at=NOW + timedelta(days=10), reboot_required=True,
                                   reboot_required_since=NOW - timedelta(days=9)))
            db.add(mdb.LinuxHost(id=1, ip="10.0.0.9", hostname="oracle1", managed=True, upgradable_count=10))
            db.add(mdb.LinuxHostDisk(host_id=1, mount_point="/boot", total_bytes=gb, used_bytes=int(0.8 * gb), pct=80))
            db.commit()
        r = sh.run_cycle(NOW)
        with Session() as db:
            got = {(a.rule, a.severity) for a in db.query(mdb.SocAlert).filter(mdb.SocAlert.status == "new").all()}
        self.assertIn(("server.license_expiring", "critical"), got, "a domain controller's evaluation ending in 10 days")
        self.assertIn(("server.boot_space", "medium"), got)
        self.assertIn(("server.restart_pending", "low"), got)
        # fixed: licensed, restarted, old kernels removed -> the alerts close
        with Session() as db:
            w = db.get(mdb.WindowsHost, 1)
            w.license_expires_at, w.license_eval, w.reboot_required = None, False, False
            db.query(mdb.LinuxHostDisk).first().used_bytes = int(0.3 * gb)
            db.commit()
        r2 = sh.run_cycle(NOW + timedelta(hours=1))
        self.assertEqual(r2["findings"], 0)
        with Session() as db:
            self.assertEqual(db.query(mdb.SocAlert).filter(mdb.SocAlert.status == "new").count(), 0)
            self.assertIsNone(db.get(mdb.WindowsHost, 1).reboot_required_since)


if __name__ == "__main__":
    unittest.main()

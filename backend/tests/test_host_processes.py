"""3.84: processes of a managed host and actions on its services and processes (services/host_processes.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import host_processes as hp

TOP = """top - 10:00:00 up 3 days,  1 user,  load average: 0.10, 0.20, 0.30
Tasks: 120 total,   1 running
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
      1 root      20   0  168000  12000   8000 S   0.0   0.3   0:05.00 systemd
top - 10:00:01 up 3 days,  1 user,  load average: 0.10, 0.20, 0.30
Tasks: 120 total,   1 running
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
   2211 www-data  20   0 1200000   1.2g  30000 R  97.0  30.1  10:05.00 php-fpm8.2
    840 mysql     20   0 2400000 512000  40000 S   3.0  12.0  50:00.00 mysqld
      1 root      20   0  168000  12000   8000 S   0.0   0.3   0:05.00 systemd
@@UNITS@@
   2211 php8.2-fpm.service
    840 mysql.service
      1 init.scope
"""


class Parse(unittest.TestCase):
    def test_linux_second_top_sample_with_units(self):
        rows = hp.parse_linux(TOP)
        self.assertEqual([(r["pid"], r["name"], r["cpu"]) for r in rows], [(2211, "php-fpm8.2", 97.0), (840, "mysqld", 3.0), (1, "systemd", 0.0)])
        self.assertEqual((rows[0]["mem_mb"], round(rows[1]["mem_mb"]), rows[0]["services"]), (1228.8, 500, ["php8.2-fpm.service"]))

    def test_windows_json_one_or_many(self):
        one = json.dumps({"pid": 8600, "name": "sqlservr", "cpu": 6.6, "mem": 54, "services": ["MSSQL$X"]})
        self.assertEqual(hp.parse_windows(one), [{"pid": 8600, "name": "sqlservr", "cpu": 6.6, "mem_mb": 54.0, "services": ["MSSQL$X"]}])
        many = json.dumps([{"pid": 1, "name": "a", "cpu": 0, "mem": 1, "services": []}, {"pid": 2, "name": "b", "cpu": 5, "mem": 2, "services": None}])
        self.assertEqual([r["pid"] for r in hp._top(hp.parse_windows(many))], [2, 1])

    def test_top_keeps_the_memory_heavy_ones(self):
        rows = [{"pid": i, "name": f"p{i}", "cpu": 100 - i, "mem_mb": 1.0, "services": []} for i in range(60)] + [{"pid": 999, "name": "big", "cpu": 0, "mem_mb": 9000.0, "services": []}]
        self.assertIn(999, [r["pid"] for r in hp._top(rows)])


class Scripts(unittest.TestCase):
    def test_service_names_are_checked_and_quoted(self):
        s = hp.service_script("windows", "MSSQL$ELISOFT", "restart")
        self.assertIn("Get-Service -Name 'MSSQL$ELISOFT'", s)
        self.assertIn("Restart-Service -Force", s)
        for bad in ("a;b", "x`y", "a|b", "", "a\nb"):
            with self.assertRaises(ValueError):
                hp.service_script("windows", bad, "start")
        self.assertIn("systemctl restart -- nginx.service", hp.service_script("linux", "nginx.service", "restart"))
        for bad in ("nginx; rm -rf /", "$(id)", "a b"):
            with self.assertRaises(ValueError):
                hp.service_script("linux", bad, "restart")
        with self.assertRaises(ValueError):
            hp.service_script("linux", "nginx", "reload")

    def test_the_agents_own_way_in_is_not_stopped(self):
        with self.assertRaisesRegex(ValueError, "cut the agent off"):
            hp.service_script("windows", "WinRM", "stop")
        with self.assertRaisesRegex(ValueError, "cut the agent off"):
            hp.service_script("linux", "sshd", "stop")
        self.assertIn("Restart-Service", hp.service_script("windows", "WinRM", "restart"))

    def test_kill_checks_the_name_and_refuses_system_processes(self):
        s = hp.kill_script("windows", 4321, "chrome")
        self.assertIn("Get-Process -Id 4321", s)
        self.assertIn("-ne 'chrome'", s)
        s = hp.kill_script("linux", 2211, "php-fpm8.2", force=True)
        self.assertIn("/proc/2211/comm", s)
        self.assertIn("kill -KILL 2211", s)
        for plat, pid, name in (("windows", 4, "System"), ("windows", 700, "lsass"), ("windows", 900, "svchost"), ("linux", 1, "systemd"), ("linux", 900, "sshd"),
                                ("linux", 50, "a'b"), ("linux", 50, "x;y")):
            with self.assertRaises(ValueError, msg=(plat, pid, name)):
                hp.kill_script(plat, pid, name)


class Actions(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'h.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (hp.SessionLocal, hp._host_ctx, hp._manage_enabled, hp._linux_run_sync)
        self.addCleanup(lambda: (setattr(hp, "SessionLocal", saved[0]), setattr(hp, "_host_ctx", saved[1]), setattr(hp, "_manage_enabled", saved[2]),
                                 setattr(hp, "_linux_run_sync", saved[3])))
        hp.SessionLocal = self.Session
        hp._host_ctx = lambda platform, host_id: {"ip": "10.0.0.5", "port": 22, "cred": ("u", "p"), "name": "web1"}
        hp._manage_enabled = lambda platform: True
        self.ran = []

        def run(ip, user, pw, cmd):
            self.ran.append(cmd)
            return {"exit_code": 0, "output": "STATE=active\n"}
        hp._linux_run_sync = run

    def test_restart_is_logged_with_the_reason_and_the_state(self):
        r = asyncio.run(hp.service_action("linux", 3, "nginx", "restart", "502 on the shop", "admin"))
        self.assertEqual((r["status"], r["state"]), ("ok", "active"))
        h = hp.history("linux", 3)
        self.assertEqual((h[0]["kind"], h[0]["target"], h[0]["reason"], h[0]["by"], h[0]["status"]), ("service_restart", "nginx", "502 on the shop", "admin", "ok"))

    def test_reason_and_switch_are_required(self):
        with self.assertRaises(ValueError):
            asyncio.run(hp.service_action("linux", 3, "nginx", "restart", "  ", "admin"))
        hp._manage_enabled = lambda platform: False
        with self.assertRaises(PermissionError):
            asyncio.run(hp.kill_process("linux", 3, 2211, "php-fpm8.2", "runaway", "admin"))
        self.assertEqual(self.ran, [])

    def test_a_state_that_is_not_the_expected_one_is_an_error(self):
        hp._linux_run_sync = lambda ip, u, p, cmd: {"exit_code": 0, "output": "STATE=running\n"}
        r = asyncio.run(hp.kill_process("linux", 3, 2211, "php-fpm8.2", "runaway", "admin"))
        self.assertEqual(r["status"], "error", "the process is still there")


if __name__ == "__main__":
    unittest.main()

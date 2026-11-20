"""3.87: what will run out and when (services/forecasts.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import math
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import forecasts as fc

NOW = datetime(2026, 11, 18, 12, 0)


def series(start, per_day, days=6, every_h=2, wobble=0.0):
    n = int(days * 24 / every_h)
    return [(NOW - timedelta(hours=every_h * (n - i)), start + per_day * (i * every_h / 24) + wobble * math.sin(i)) for i in range(n + 1)]


class Growth(unittest.TestCase):
    def test_steady_growth_gives_days_and_date(self):
        g = fc.growth("disk", series(70, 2.0), NOW)
        self.assertIsNotNone(g)
        self.assertAlmostEqual(g["days"], 9.0, delta=0.5)
        self.assertTrue(g["date"].startswith("2026-11-27"))

    def test_ups_and_downs_are_not_a_forecast(self):
        self.assertIsNone(fc.growth("mem", series(70, 0.3, wobble=12.0), NOW))

    def test_too_slow_too_low_too_far_or_too_short(self):
        self.assertIsNone(fc.growth("mem", series(60, 0.3), NOW), "under the minimum growth for memory")
        self.assertIsNone(fc.growth("disk", series(10, 1.0), NOW), "too low to matter")
        self.assertIsNone(fc.growth("disk", series(40, 0.3), NOW), "full in 200 days: past the horizon")
        self.assertIsNone(fc.growth("disk", series(80, 2.0, days=1), NOW), "one day of readings is not a trend")


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, metrics, app_checks, asset_itam, licenses, procurement
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'f.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (fc, soc, metrics, app_checks, asset_itam, licenses, procurement)
        saved = [(m, m.SessionLocal) for m in mods]
        path = app_checks._PATH
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(app_checks, "_PATH", path)))
        for m in mods:
            m.SessionLocal = self.Session
        app_checks._PATH = os.path.join(tmp, "ac.json")
        self.mdb = mdb
        from services import metrics as mt
        with self.Session() as db:
            for key, name, kind, pts in (("win:1:disk:C", "FS1 · C:", "disk", series(70, 2.0)), ("win:1:mem", "FS1 · memory", "mem", series(70, 2.5)),
                                         ("lin:2:mem", "web1 · memory", "mem", series(60, 0.0)), ("ipam:pool:R1:lan", "DHCP lan (R1)", "other", series(70, 1.5)),
                                         ("win:3:cpu", "DC1 · cpu", "cpu", series(50, 5.0))):
                for at, v in pts:
                    mt.record(key, v, name=name, kind=kind, unit="%", now=at, db=db, asset_id=1 if key.startswith("win:1") else None)
            db.add(mdb.TlsCheck(ip="192.168.1.10", port=443, subject="intranet.local", not_after=NOW + timedelta(days=12), self_signed=True))
            db.add(mdb.TlsCheck(ip="192.168.1.11", port=443, subject="far.local", not_after=NOW + timedelta(days=300)))
            db.commit()


class Overview(_Db):
    def test_one_list_nearest_first(self):
        o = fc.overview(90, NOW)
        got = [(x["kind"], x["where"]) for x in o["items"]]
        self.assertEqual(got[0], ("mem", "FS1"), "memory: 85% now + 2.5 a day -> about 6 days (the disk: 82% + 2 -> 9)")
        self.assertEqual(set(got), {("mem", "FS1"), ("disk", "FS1"), ("dhcp_pool", "DHCP lan (R1)"), ("certificate", "192.168.1.10")})
        self.assertEqual({k: v for k, v in o["counts"].items() if v}, {"disk": 1, "mem": 1, "dhcp_pool": 1, "certificate": 1}, "the other kinds are 0")
        self.assertEqual([x["days"] for x in o["items"]], sorted(x["days"] for x in o["items"]))
        self.assertEqual(len(fc.overview(7, NOW)["items"]), 1, "the horizon filters")

    def test_memory_alert_and_summary_without_addresses(self):
        self.assertEqual(fc.check_memory(NOW), ["win:1:mem"])
        with self.Session() as db:
            a = db.query(self.mdb.SocAlert).filter_by(rule="metric.mem_forecast").one()
        self.assertEqual((a.device_name, a.severity), ("FS1", "medium"))
        import services.forecasts as f2
        saved = f2._now
        f2._now = lambda: NOW
        self.addCleanup(lambda: setattr(f2, "_now", saved))
        ps = fc.public_summary()
        self.assertEqual(ps["within_7"], 1)
        self.assertNotIn("192.168.1.10", str(ps))


if __name__ == "__main__":
    unittest.main()

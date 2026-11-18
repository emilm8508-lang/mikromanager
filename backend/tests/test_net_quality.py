"""3.82: latency, jitter and packet loss (services/net_quality.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import net_quality as nq

WIN_PL = """
Badanie 1.1.1.1 z 32 bajtami danych:
Odpowiedź z 1.1.1.1: bajtów=32 czas=12ms TTL=57
Odpowiedź z 1.1.1.1: bajtów=32 czas=20ms TTL=57
Upłynął limit czasu żądania.
Odpowiedź z 192.168.1.1: Host docelowy jest nieosiągalny.
Odpowiedź z 1.1.1.1: bajtów=32 czas=14ms TTL=57
"""
WIN_LAN = "Reply from 192.168.1.1: bytes=32 time<1ms TTL=64\nReply from 192.168.1.1: bytes=32 time=1ms TTL=64\n"
LINUX = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=10.1 ms

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 10.1/11.2/12.3/1.1 ms
"""


class Parse(unittest.TestCase):
    def test_windows_polish_with_timeouts_and_unreachable(self):
        self.assertEqual(nq.parse_ping(WIN_PL), [12.0, 20.0, 14.0])
        m = nq.summarize(nq.parse_ping(WIN_PL), 5)
        self.assertEqual((m["rtt"], m["jitter"], m["loss"], m["received"]), (15.33, 7.0, 40.0, 3))

    def test_windows_below_one_ms(self):
        self.assertEqual(nq.parse_ping(WIN_LAN), [0.5, 1.0])

    def test_linux_summary_lines_are_not_replies(self):
        self.assertEqual(nq.parse_ping(LINUX), [12.3, 10.1])

    def test_nothing_answered(self):
        m = nq.summarize([], 10)
        self.assertEqual((m["rtt"], m["jitter"], m["loss"]), (None, None, 100.0))


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, metrics
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'q.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (nq, soc, metrics)
        saved = [(m, m.SessionLocal) for m in mods]
        path = nq._PATH
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(nq, "_PATH", path), nq._results.clear(), nq._streak.clear()))
        for m in mods:
            m.SessionLocal = self.Session
        nq._PATH = os.path.join(tmp, "nq.json")
        nq._results.clear()
        nq._streak.clear()
        self.mdb = mdb

    def alerts(self):
        with self.Session() as db:
            return {(a.rule, a.status): a.severity for a in db.query(self.mdb.SocAlert).all()}


class Alerts(_Db):
    T_OWN = {"ip": "1.1.1.1", "name": "Internet", "asset_id": None, "own": True}
    T_NET = {"ip": "192.168.1.2", "name": "SW1", "asset_id": None, "own": False}
    LIM = dict(nq.DEFAULTS["limits"])

    def test_loss_alerts_after_two_bad_bursts_and_closes_after_a_good_one(self):
        now = datetime(2026, 11, 18, 12, 0)
        bad = nq.summarize([10.0] * 8, 10)
        self.assertEqual(nq._judge(self.T_OWN, bad, self.LIM, now), [], "one bad burst is not an alert")
        self.assertEqual(nq._judge(self.T_OWN, bad, self.LIM, now + timedelta(minutes=5)), ["metric.net_loss"])
        self.assertEqual(self.alerts(), {("metric.net_loss", "new"): "high"})
        nq._judge(self.T_OWN, nq.summarize([10.0] * 10, 10), self.LIM, now + timedelta(minutes=10))
        self.assertNotIn(("metric.net_loss", "new"), self.alerts())

    def test_a_network_device_not_answering_at_all_is_left_to_availability(self):
        now = datetime(2026, 11, 18, 12, 0)
        dead = nq.summarize([], 10)
        for i in range(3):
            nq._judge(self.T_NET, dead, self.LIM, now + timedelta(minutes=5 * i))
        self.assertEqual(self.alerts(), {})
        for i in range(2):
            nq._judge(self.T_OWN, dead, self.LIM, now + timedelta(minutes=5 * i))
        self.assertEqual(self.alerts(), {("metric.net_loss", "new"): "high"}, "an own target at 100% is alerted here")

    def test_latency_and_jitter_limits(self):
        now = datetime(2026, 11, 18, 12, 0)
        slow = nq.summarize([120.0, 180.0, 110.0, 190.0], 4)          # avg 150 ms, jitter ~70 ms
        for i in range(2):
            out = nq._judge(self.T_NET, slow, self.LIM, now + timedelta(minutes=5 * i))
        self.assertEqual(sorted(out), ["metric.net_jitter", "metric.net_latency"])
        out = nq._judge(self.T_OWN, slow, self.LIM, now)
        out = nq._judge(self.T_OWN, slow, self.LIM, now + timedelta(minutes=5))
        self.assertEqual(sorted(out), ["metric.net_jitter", "metric.net_latency"], "150 ms reaches the own-target limit too")


class SettingsAndOverview(_Db):
    def test_settings_are_checked(self):
        with self.assertRaises(ValueError):
            nq.save_settings({"targets": [{"name": "x", "ip": "-c 5 evil"}]})
        with self.assertRaises(ValueError):
            nq.save_settings({"limits": {"loss_pct": 150}})
        s = nq.save_settings({"targets": [{"name": "GW", "ip": "10.0.0.1"}, {"ip": "10.0.0.1"}], "limits": {"rtt_ms": 40}, "count": 5})
        self.assertEqual((s["targets"], s["limits"]["rtt_ms"], s["count"]), ([{"name": "GW", "ip": "10.0.0.1"}], 40.0, 5))
        self.assertEqual(nq.load_settings()["targets"], [{"name": "GW", "ip": "10.0.0.1"}])

    def test_overview_from_history_after_a_restart(self):
        now = datetime.utcnow()
        t = {"ip": "1.1.1.1", "name": "Internet", "asset_id": None, "own": True}
        for i, (r, l) in enumerate(((10.0, 0.0), (12.0, 0.0), (40.0, 10.0))):
            nq._record(t, {"rtt": r, "jitter": 2.0, "loss": l}, now - timedelta(minutes=10 - 5 * i))
        o = nq.overview(now)
        x = o["items"][0]
        self.assertEqual((x["name"], x["own"], x["rtt"], x["loss"], x["rtt_p95_24h"], x["bad"]), ("Internet", True, 40.0, 10.0, 40.0, ["loss"]))
        from services import metrics
        self.assertIn(("nq:1.1.1.1:rtt", "rtt"), [(s["key"], s["kind"]) for s in metrics.series_list(now)])
        ps = nq.public_summary()
        self.assertEqual(ps["bad"][0]["n"], "Internet")
        self.assertNotIn("1.1.1.1", str(ps), "no addresses go to Central")


if __name__ == "__main__":
    unittest.main()

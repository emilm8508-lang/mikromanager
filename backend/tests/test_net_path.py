"""3.85: the path to the own targets hop by hop, where a problem starts, path changes (services/net_path.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import net_path as npth


def hop(n, ip, rtt=5.0, loss=0.0):
    return {"n": n, "ip": ip, "rtt": rtt, "jitter": 1.0, "loss": loss} if ip else {"n": n, "ip": None}


class Culprit(unittest.TestCase):
    def test_loss_that_lasts_to_the_target_is_placed_at_its_first_hop(self):
        hops = [hop(1, "192.168.1.1"), hop(2, "10.0.0.1"), hop(3, "80.1.1.1", loss=20.0), hop(4, "80.1.2.1", loss=20.0), hop(5, "1.1.1.1", loss=40.0)]
        self.assertEqual(npth.culprit(hops, 5.0), (3, "loss"))

    def test_a_router_protecting_itself_is_not_a_fault(self):
        hops = [hop(1, "192.168.1.1"), hop(2, "80.1.1.1", rtt=180.0, loss=60.0), hop(3, "80.1.2.1"), hop(4, "1.1.1.1")]
        self.assertEqual(npth.culprit(hops, 5.0), (None, None))

    def test_latency_jump_that_lasts(self):
        hops = [hop(1, "192.168.1.1", 1.0), hop(2, "10.0.0.1", 4.0), hop(3, None), hop(4, "80.1.1.1", 95.0), hop(5, "1.1.1.1", 99.0)]
        self.assertEqual(npth.culprit(hops, 5.0), (4, "latency"))
        hops[4]["rtt"] = 8.0                                # the delay does not last: the router answered its own pings slowly
        self.assertEqual(npth.culprit(hops, 5.0), (None, None))


class Paths(unittest.TestCase):
    def test_signature_and_silent_hops(self):
        a = npth.signature([hop(1, "192.168.1.1"), hop(2, None), hop(3, "1.1.1.1")])
        self.assertEqual(a, "192.168.1.1>->1.1.1.1")
        self.assertTrue(npth._same_path(a, "192.168.1.1>10.0.0.1>1.1.1.1"), "a silent hop is not a change")
        self.assertFalse(npth._same_path(a, "192.168.1.1>10.0.0.9>1.1.1.2"))
        self.assertFalse(npth._same_path(a, "192.168.1.1>1.1.1.1"))

    def test_usual_is_the_most_frequent(self):
        self.assertEqual(npth.usual(["a", "b", "a", "b", "a"]), "a")
        self.assertEqual(npth.usual(["a", "b"]), "b", "the newest wins a tie")
        self.assertIsNone(npth.usual([]))


class Record(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, net_quality
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'p.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (npth.SessionLocal, soc.SessionLocal, net_quality._PATH)
        self.addCleanup(lambda: (setattr(npth, "SessionLocal", saved[0]), setattr(soc, "SessionLocal", saved[1]), setattr(net_quality, "_PATH", saved[2]),
                                 npth._streak.clear()))
        npth.SessionLocal = soc.SessionLocal = self.Session
        net_quality._PATH = os.path.join(tmp, "nq.json")
        npth._streak.clear()
        self.mdb = mdb

    def alerts(self):
        with self.Session() as db:
            return {(a.rule, a.status): a.severity for a in db.query(self.mdb.SocAlert).all()}

    def test_change_against_the_usual_path_and_degraded_alerts(self):
        t = {"ip": "1.1.1.1", "name": "Internet (1.1.1.1)"}
        now = datetime(2026, 11, 18, 12, 0)
        good = [hop(1, "192.168.1.1"), hop(2, "80.1.1.1"), hop(3, "1.1.1.1")]
        for i in range(4):
            r = npth.record(t, good, True, now + timedelta(minutes=15 * i), 5.0)
        self.assertEqual((r["changed"], r["culprit"]), (False, None))
        other = [hop(1, "192.168.1.1"), hop(2, "90.9.9.9", loss=30.0), hop(3, "1.1.1.1", loss=30.0)]
        r = npth.record(t, other, True, now + timedelta(minutes=60), 5.0)
        self.assertEqual((r["changed"], r["culprit"], r["culprit_kind"], r["culprit_ip"]), (True, 2, "loss", "90.9.9.9"))
        self.assertEqual(self.alerts(), {}, "one trace is not an alert")
        npth.record(t, other, True, now + timedelta(minutes=75), 5.0)
        self.assertEqual(self.alerts(), {("metric.path_degraded", "new"): "medium", ("metric.path_changed", "new"): "low"})
        npth.record(t, good, True, now + timedelta(minutes=90), 5.0)
        open_now = [k for k in self.alerts() if k[1] == "new"]
        self.assertEqual(open_now, [], "both closed once the path is back and fine")

    def test_isp_balancing_over_known_routers_is_not_a_change(self):
        """3.94.2: aluplasti counted 85 changes in 96 traces a day - an ISP alternating its paths."""
        t = {"ip": "1.1.1.1", "name": "Internet"}
        now = datetime(2026, 11, 20, 0, 0)
        paths = [[hop(1, "192.168.1.1"), hop(2, "80.1.1.1"), hop(3, "80.2.2.1"), hop(4, "1.1.1.1")],
                 [hop(1, "192.168.1.1"), hop(2, "80.1.1.2"), hop(3, "80.2.2.2"), hop(4, "1.1.1.1")],
                 [hop(1, "192.168.1.1"), hop(2, "80.1.1.1"), hop(3, None), hop(4, "80.2.2.2"), hop(5, "1.1.1.1")]]
        changes = [npth.record(t, paths[i % 3], True, now + timedelta(minutes=15 * i), 5.0)["changed"] for i in range(40)]
        self.assertEqual(sum(changes), 0)
        self.assertNotIn(("metric.path_changed", "new"), self.alerts())
        moved = [hop(1, "192.168.1.1"), hop(2, "95.5.5.5"), hop(3, "95.6.6.6"), hop(4, "1.1.1.1")]
        r = [npth.record(t, moved, True, now + timedelta(minutes=15 * (40 + i)), 5.0) for i in range(6)]
        self.assertEqual([x["changed"] for x in r], [True, True, True, False, False, False], "new routers count until a trace of them is 45 minutes old")
        self.assertEqual(r[0]["new_routers"], ["95.5.5.5", "95.6.6.6"])
        self.assertNotIn(("metric.path_changed", "new"), self.alerts(), "alerted after two traces, closed once the new path is known")
        with self.Session() as db:
            self.assertEqual(db.query(self.mdb.SocAlert).filter_by(rule="metric.path_changed").count(), 1)

    def test_overview_and_summary_without_addresses(self):
        from services import net_quality
        net_quality.save_settings({"targets": [{"name": "Internet", "ip": "1.1.1.1"}]})
        now = datetime.utcnow()
        npth.record({"ip": "1.1.1.1", "name": "Internet"}, [hop(1, "192.168.1.1"), hop(2, "1.1.1.1")], True, now, 5.0)
        o = npth.overview(now)
        self.assertEqual((o["items"][0]["name"], len(o["items"][0]["last"]["hops"]), o["items"][0]["traces_24h"]), ("Internet", 2, 1))
        ps = npth.public_summary()
        self.assertEqual((ps["targets"][0]["n"], ps["targets"][0]["hops"], ps["targets"][0]["reached"]), ("Internet", 2, True))
        self.assertNotIn("192.168", str(ps))
        self.assertNotIn("1.1.1.1", str(ps).replace("Internet", ""))


if __name__ == "__main__":
    unittest.main()

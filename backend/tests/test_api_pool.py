"""3.73 regression: one RouterOS API login per router, kept for a while - before, every read logged in and out (sanmed R2's access point:
"user webshot logged in / out" seven times within 4 seconds).

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from librouteros.exceptions import TrapError
from services import mikrotik_client as mc


class FakeApi:
    def __init__(self, log):
        self.log, self.closed, self.broken = log, False, False

    def __call__(self, cmd):
        if self.broken:
            raise ConnectionResetError("closed by the router")
        if cmd == "/nope/print":
            raise TrapError(message="no such command", category=None)
        self.log.append(cmd)
        return [{"cmd": cmd}]

    def close(self):
        self.closed = True


class Pool(unittest.TestCase):
    def setUp(self):
        mc._pool.clear()
        self.addCleanup(mc._pool.clear)
        self.apis, self.log = [], []
        self.key = ("192.168.1.2", 8728, "webshot", "pw")

    def connect(self):
        a = FakeApi(self.log)
        self.apis.append(a)
        return a

    def call(self, cmd):
        return mc.pooled_call(self.key, self.connect, lambda api: list(api(cmd)))

    def test_one_login_for_many_reads(self):
        for c in ("/system/resource/print", "/log/print", "/ip/arp/print", "/user/active/print", "/ip/route/print"):
            self.call(c)
        self.assertEqual((len(self.apis), mc.pool_stats()["192.168.1.2"]), (1, 1))
        self.assertEqual(len(self.log), 5)

    def test_idle_connection_is_closed_and_a_new_login_made(self):
        self.call("/log/print")
        mc._pool[self.key]["used"] -= mc.API_IDLE_SEC + 1
        mc._pool_reap(__import__("time").time())
        self.assertTrue(self.apis[0].closed, "closed when idle")
        self.call("/log/print")
        self.assertEqual(len(self.apis), 2)

    def test_broken_connection_retried_once_on_a_fresh_one(self):
        self.call("/log/print")
        self.apis[0].broken = True
        self.assertEqual(self.call("/ip/arp/print"), [{"cmd": "/ip/arp/print"}])
        self.assertTrue(self.apis[0].closed)
        self.assertEqual(len(self.apis), 2)

    def test_a_refused_command_keeps_the_connection(self):
        self.call("/log/print")
        with self.assertRaises(TrapError):
            self.call("/nope/print")
        self.call("/ip/arp/print")
        self.assertEqual(len(self.apis), 1)

    def test_login_failure_is_raised_and_nothing_kept(self):
        def bad():
            raise ConnectionRefusedError("refused")
        with self.assertRaises(ConnectionRefusedError):
            mc.pooled_call(("10.0.0.9", 8728, "u", "p"), bad, lambda api: list(api("/log/print")))
        self.assertIsNone(mc._pool[("10.0.0.9", 8728, "u", "p")]["api"])

    def test_parallel_reads_share_one_login(self):
        ts = [threading.Thread(target=self.call, args=(f"/c{i}/print",)) for i in range(12)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual((len(self.apis), len(self.log)), (1, 12))


class AgentLoginLines(unittest.TestCase):
    def test_the_agents_own_login_is_not_a_persons(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import router_logs, logons, soc
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'p.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (logons.SessionLocal, soc.SessionLocal, dict(logons._agent_users_cache), logons._SESSIONS_PATH, logons._SETTINGS_PATH)
        self.addCleanup(lambda: (setattr(logons, "SessionLocal", saved[0]), setattr(soc, "SessionLocal", saved[1]),
                                 logons._agent_users_cache.update(saved[2]), setattr(logons, "_SESSIONS_PATH", saved[3]),
                                 setattr(logons, "_SETTINGS_PATH", saved[4])))
        logons.SessionLocal = soc.SessionLocal = Session
        logons._SESSIONS_PATH, logons._SETTINGS_PATH = os.path.join(tmp, "s.json"), os.path.join(tmp, "l.json")
        logons._agent_users_cache.update(at=0.0, names=set())
        with Session() as db:
            db.add(mdb.Credential(name="r", username="webshot", password_enc="x"))
            db.commit()
        r = router_logs.handle(device="R2-AP", device_ip="192.168.1.60", message="user webshot logged in from 192.168.1.38 via api",
                               app="system,info,account", now=1_900_000_000)
        self.assertTrue(r.get("self"))
        r = router_logs.handle(device="R2-AP", device_ip="192.168.1.60", message="user jan logged in from 192.168.1.10 via winbox",
                               app="system,info,account", now=1_900_000_100)
        self.assertFalse(r.get("self"))
        with Session() as db:
            self.assertEqual([x.user for x in db.query(mdb.AssetLogon).all()], ["jan"])


if __name__ == "__main__":
    unittest.main()

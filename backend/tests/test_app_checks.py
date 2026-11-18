"""3.83: application checks - HTTP(S), TCP and DNS (services/app_checks.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import app_checks as ac


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        code = 500 if self.path == "/broken" else 200
        body = b"<html><form id=login>Sign in</form></html>"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Validation(unittest.TestCase):
    def test_bad_checks_are_refused(self):
        for c in ({"kind": "ftp", "target": "x"}, {"kind": "http", "target": "server/page"}, {"kind": "tcp", "target": "server"},
                  {"kind": "tcp", "target": "server:99999"}, {"kind": "dns", "target": "a b"}, {"kind": "dns", "target": "x.pl", "dns_server": "dns.local"},
                  {"kind": "http", "target": "http://x", "interval_min": 0}, {"kind": "http", "target": "http://x", "expect_status": "ok"}):
            with self.assertRaises(ValueError, msg=c):
                ac.clean(c)
        c = ac.clean({"kind": "http", "target": "https://x.pl/login", "name": ""})
        self.assertEqual((c["name"], c["interval_min"], len(c["id"])), ("https://x.pl/login", 2, 8))

    def test_status_spec(self):
        self.assertTrue(ac._status_ok("200-399", 302))
        self.assertFalse(ac._status_ok("200-399", 500))
        self.assertTrue(ac._status_ok("200,401", 401))


class Dns(unittest.TestCase):
    def test_answer_with_a_records_and_an_error_code(self):
        q = struct.pack(">HHHHHH", 7, 0x8180, 1, 2, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        a1 = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.215.14")
        a2 = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, 2) + b"\xc0\x0c"            # a CNAME is skipped
        self.assertEqual(ac.parse_dns_answer(q + a1 + a2, 7), ["93.184.215.14"])
        nx = struct.pack(">HHHHHH", 8, 0x8183, 1, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "NXDOMAIN"):
            ac.parse_dns_answer(nx, 8)
        with self.assertRaises(ValueError):
            ac.parse_dns_answer(q, 9)


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, metrics
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'a.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (ac, soc, metrics)
        saved = [(m, m.SessionLocal) for m in mods]
        path = ac._PATH
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(ac, "_PATH", path),
                                 ac._results.clear(), ac._streak.clear(), ac._due.clear()))
        for m in mods:
            m.SessionLocal = self.Session
        ac._PATH = os.path.join(tmp, "ac.json")
        ac._results.clear(), ac._streak.clear(), ac._due.clear()
        self.mdb = mdb

    def alerts(self):
        with self.Session() as db:
            return {(a.rule, a.status): a.severity for a in db.query(self.mdb.SocAlert).all()}


class Judge(_Db):
    C = None

    def setUp(self):
        super().setUp()
        self.c = ac.clean({"kind": "http", "target": "https://shop.example/", "name": "Shop", "slow_ms": 800})

    def test_down_after_two_failures_closed_after_success(self):
        now = datetime(2026, 11, 18, 12, 0)
        fail = {"ok": False, "ms": None, "error": "HTTP 500"}
        self.assertEqual(ac._judge(self.c, fail, now, None), [])
        self.assertEqual(ac._judge(self.c, fail, now + timedelta(minutes=2), None), ["app.down"])
        self.assertEqual(self.alerts(), {("app.down", "new"): "high"})
        ac._judge(self.c, {"ok": True, "ms": 120.0, "error": None}, now + timedelta(minutes=4), None)
        self.assertNotIn(("app.down", "new"), self.alerts())

    def test_slow_and_certificate(self):
        now = datetime(2026, 11, 18, 12, 0)
        slow = {"ok": True, "ms": 950.0, "error": None, "cert_not_after": now + timedelta(days=2)}
        self.assertEqual(ac._judge(self.c, slow, now, None), ["app.cert"], "a certificate needs no second look")
        self.assertEqual(sorted(ac._judge(self.c, slow, now + timedelta(minutes=2), None)), ["app.cert", "app.slow"])
        a = self.alerts()
        self.assertEqual((a[("app.cert", "new")], a[("app.slow", "new")]), ("high", "medium"))
        ac._judge(self.c, {"ok": False, "ms": None, "error": "timeout"}, now + timedelta(minutes=4), None)
        self.assertIn(("app.cert", "new"), self.alerts(), "a failed try does not close the certificate alert")


class Live(_Db):
    def test_http_tcp_against_local_servers_and_the_summary(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        lst = socket.socket()
        lst.bind(("127.0.0.1", 0))
        lst.listen(5)
        self.addCleanup(lst.close)

        def greet():
            try:
                while True:
                    s, _ = lst.accept()
                    s.sendall(b"220 mail.local ESMTP\r\n")
                    s.close()
            except OSError:
                pass
        threading.Thread(target=greet, daemon=True).start()
        base = f"http://127.0.0.1:{port}"
        ac.save([{"kind": "http", "target": base + "/login", "name": "Login", "contains": "id=login"},
                 {"kind": "http", "target": base + "/login", "name": "Phrase", "contains": "Welcome back"},
                 {"kind": "http", "target": base + "/broken", "name": "Broken"},
                 {"kind": "tcp", "target": f"127.0.0.1:{lst.getsockname()[1]}", "name": "Mail", "contains": "220"},
                 {"kind": "tcp", "target": f"127.0.0.1:{lst.getsockname()[1]}", "name": "Mail SSH?", "contains": "SSH-", "timeout_s": 2}])
        asyncio.run(ac.run_due(force=True))
        asyncio.run(ac.run_due(force=True))
        o = {x["name"]: x for x in ac.overview()["items"]}
        self.assertEqual({n: o[n]["ok"] for n in o}, {"Login": True, "Phrase": False, "Broken": False, "Mail": True, "Mail SSH?": False})
        self.assertEqual((o["Broken"]["code"], o["Login"]["up_24h"], o["Broken"]["up_24h"]), (500, 100.0, 0.0))
        self.assertIn("does not contain", o["Phrase"]["error"])
        with self.Session() as db:
            self.assertEqual(sorted(a.device_name for a in db.query(self.mdb.SocAlert).filter_by(rule="app.down").all()), ["Broken", "Mail SSH?", "Phrase"])
        ps = ac.public_summary()
        self.assertEqual((ps["total"], ps["ok"], ps["failing"]), (5, 2, 3))
        self.assertNotIn("127.0.0.1", str(ps), "no addresses or URLs go to Central")


if __name__ == "__main__":
    unittest.main()

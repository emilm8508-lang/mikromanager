"""Round 2, stage E (3.70) regression tests - docs/plan-runda-2.md: the last logons of an asset, and editing the inventory from Central.

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import logons, soc, assets, asset_merge, vuln_scan
        self.tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(self.tmp, 'e.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (logons, soc, assets, asset_merge, vuln_scan, mdb)
        saved = [(m, m.SessionLocal) for m in mods]
        paths = (logons._SETTINGS_PATH, logons._SESSIONS_PATH, logons._AD_PATH, asset_merge._DISTINCT_PATH)
        cache = dict(logons._agent_users_cache)
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved],
                                 setattr(logons, "_SETTINGS_PATH", paths[0]), setattr(logons, "_SESSIONS_PATH", paths[1]),
                                 setattr(logons, "_AD_PATH", paths[2]), setattr(asset_merge, "_DISTINCT_PATH", paths[3]),
                                 logons._agent_users_cache.update(cache)))
        for m in mods:
            m.SessionLocal = self.Session
        logons._SETTINGS_PATH = os.path.join(self.tmp, "logons.json")
        logons._SESSIONS_PATH = os.path.join(self.tmp, "sessions.json")
        logons._AD_PATH = os.path.join(self.tmp, "ad.json")
        asset_merge._DISTINCT_PATH = os.path.join(self.tmp, "distinct.json")
        logons._agent_users_cache.update(at=0.0, names=set())
        self.mdb, self.logons, self.assets, self.am = mdb, logons, assets, asset_merge
        with self.Session() as db:
            db.add(mdb.Credential(name="winrm", username="CORP\\mikromanager", password_enc="x"))
            db.add(mdb.Asset(id=1, key="ip:192.168.1.10", ip="192.168.1.10", name="SERWER", asset_type="windows", role="server",
                             refs=json.dumps({"windows_host_id": 1})))
            db.add(mdb.Asset(id=2, key="ip:192.168.1.1", ip="192.168.1.1", name="MC-R1", asset_type="network", refs=json.dumps({"device_id": 1})))
            db.add(mdb.Asset(id=3, key="ip:192.168.1.30", ip="192.168.1.30", name="PRN", asset_type="printer"))
            db.add(mdb.Asset(id=4, key="ip:192.168.1.40", ip="192.168.1.40", name="PC40", asset_type="windows"))
            db.commit()

    def alerts(self):
        with self.Session() as db:
            return {(a.rule, a.fingerprint): a.count for a in db.query(self.mdb.SocAlert).all()}


class WindowsLogons(_Db):
    def _payload(self):
        t = datetime(2026, 11, 14, 9, 0)
        ev = lambda i, dt, **d: {"id": i, "t": (t + timedelta(minutes=dt)).isoformat() + "Z", "d": d}
        return {"events": [ev(4624, 0, TargetUserName="jkowalski", TargetDomainName="CORP", LogonType="10", IpAddress="192.168.1.50",
                              WorkstationName="PC-JK", ElevatedToken="%%1843"),
                           ev(4624, 1, TargetUserName="DC1$", TargetDomainName="CORP", LogonType="3", IpAddress="192.168.1.5"),
                           ev(4624, 2, TargetUserName="mikromanager", TargetDomainName="CORP", LogonType="10", IpAddress="192.168.1.9"),
                           ev(4624, 3, TargetUserName="SYSTEM", TargetDomainName="NT AUTHORITY", LogonType="2"),
                           ev(4647, 30, TargetUserName="jkowalski", TargetDomainName="CORP")],
                "net3": 412, "sessions": " USERNAME  SESSIONNAME  ID  STATE   IDLE TIME  LOGON TIME\n>jkowalski rdp-tcp#3  2  Active  .  14.11.2026 09:00\n"}

    def test_case_e1_rdp_logon_is_the_last_logon_technical_ones_skipped(self):
        from services import host_logs as hl
        p = self._payload()
        r = hl.windows_logons("SERWER", "192.168.1.10", hl.parse_windows(p), p, datetime(2026, 11, 14, 10, 0))
        self.assertEqual(r["stored"], 1, "DC1$, SYSTEM and the agent's own account are never stored")
        s = self.logons.summary(host_ip="192.168.1.10", asset_id=1, asset_type="windows", refs={"windows_host_id": 1}, now=datetime(2026, 11, 14, 10, 0))
        self.assertEqual((s["last_logon"]["user"], s["last_logon"]["type"], s["last_logon"]["from"], s["last_logon"]["source"]),
                         ("jkowalski", "rdp", "192.168.1.50", "event_log"))
        self.assertEqual(s["network_logons_7d"], {"success": 412, "failure": 0}, "type 3 counted, not stored")
        self.assertEqual([x["user"] for x in s["active_sessions"]], ["jkowalski"])
        self.assertEqual(s["distinct_users_30d"], 1)

    def test_elevated_token_is_privileged(self):
        from services import host_logs as hl
        e = hl.parse_windows({"events": [{"id": 4624, "t": "2026-11-14T09:00:00Z", "d": {"TargetUserName": "jnowak", "LogonType": "2",
                                                                                         "ElevatedToken": "%%1842"}}]})[0]
        self.assertTrue(e["elevated"])
        self.logons.record([{"host_ip": "192.168.1.10", "user": "jnowak", "logon_type": "interactive", "at": datetime(2026, 11, 14, 9), "source": "event_log",
                             "privileged": e["elevated"]}])
        with self.Session() as db:
            self.assertTrue(db.query(self.mdb.AssetLogon).one().is_privileged)


class RouterLogons(_Db):
    def test_case_e2_admin_winbox_from_a_new_address_alerts_once(self):
        """RouterOS: the router log rule (routerlog.login_new_source, 3.61) raises it - the logon module does not raise it a second time."""
        from services import router_logs
        for x in (router_logs._windows, router_logs._agg, router_logs._seen_lines, router_logs._logins):
            x.clear()
        saved = (router_logs._LOGINS_PATH, router_logs._SETTINGS_PATH, router_logs._OWNER_PATH)
        self.addCleanup(lambda: (setattr(router_logs, "_LOGINS_PATH", saved[0]), setattr(router_logs, "_SETTINGS_PATH", saved[1]),
                                 setattr(router_logs, "_OWNER_PATH", saved[2])))
        router_logs._LOGINS_PATH, router_logs._SETTINGS_PATH, router_logs._OWNER_PATH = (os.path.join(self.tmp, n) for n in ("l.json", "s.json", "o.json"))
        router_logs._logins_loaded[0] = False
        line = lambda src, dt: router_logs.handle(device="MC-R1", device_ip="192.168.1.1", message=f"user admin logged in from {src} via winbox",
                                                  app="system,info,account", now=1_800_000_000 + dt)
        line("192.168.1.20", 0)
        line("192.168.1.77", 700)
        line("192.168.1.77", 1400)
        rules = [r for r, _fp in self.alerts()]
        self.assertEqual(rules, ["routerlog.login_new_source"], "one alert for the new address, none for the same one again, no duplicate")

    def test_privileged_account_from_a_new_address(self):
        lg = self.logons
        lg.update_settings({"rules": {"builtin_admin": False, "first_on_server": False, "after_hours": False}})
        base = datetime(2026, 11, 1, 10, 0)
        rec = lambda src, d: lg.record([{"host_ip": "192.168.1.10", "host_name": "SERWER", "user": "Administrator", "logon_type": "rdp",
                                         "source_ip": src, "at": base + timedelta(days=d), "source": "event_log"}], now=base + timedelta(days=d))
        rec("192.168.1.20", 0)
        self.assertEqual(self.alerts(), {}, "the first logon of the account is its history")
        rec("45.88.1.2", 3)
        a = self.alerts()
        self.assertEqual(list(a), [("logon.privileged_new_source", "logon.privileged_new_source|serwer|Administrator|45.88.1.2")])
        rec("45.88.1.2", 4)
        self.assertEqual(self.alerts(), a, "the same address again: no new alert")

    def test_router_log_line_is_recorded(self):
        from services import router_logs
        router_logs.handle(device="MC-R1", device_ip="192.168.1.1", message="user admin logged in from 192.168.1.20 via winbox", app="system,info,account")
        with self.Session() as db:
            r = db.query(self.mdb.AssetLogon).one()
        self.assertEqual((r.user, r.logon_type, r.source_ip, r.source, r.is_privileged, r.asset_id), ("admin", "winbox", "192.168.1.20", "routeros_log", True, 2))


class Rules(_Db):
    def test_unknown_accounts_after_hours_first_on_server_builtin(self):
        lg = self.logons
        base = datetime(2026, 11, 1, 10, 0)
        lg.record([{"host_ip": "192.168.1.10", "host_name": "SERWER", "user": "jkowalski", "logon_type": "rdp", "at": base, "source": "event_log"}], now=base)
        with self.Session() as db:
            db.get(self.mdb.Asset, 1).criticality = "critical"
            db.commit()
        late = datetime(2026, 11, 14, 23, 30) - (datetime.now() - datetime.utcnow())          # 23:30 local
        lg.record([{"host_ip": "192.168.1.10", "host_name": "SERWER", "user": "anowak", "logon_type": "rdp", "at": late, "source": "event_log"},
                   {"host_ip": "192.168.1.10", "host_name": "SERWER", "user": "Administrator", "logon_type": "interactive", "at": late + timedelta(minutes=1),
                    "source": "event_log"}] +
                  [{"host_ip": "192.168.1.10", "host_name": "SERWER", "user": u, "logon_type": "network", "at": late, "result": "failure", "source": "event_log",
                    "no_such_user": True} for u in ("admin", "test")] +
                  [{"host_ip": "192.168.1.10", "host_name": "SERWER", "user": u, "logon_type": "rdp", "at": late + timedelta(seconds=i), "result": "failure",
                    "source": "event_log", "no_such_user": True} for i, u in enumerate(("admin", "test"))], now=late + timedelta(minutes=5))
        rules = {r for r, _fp in self.alerts()}
        self.assertTrue({"logon.first_on_server", "logon.after_hours", "logon.builtin_admin", "logon.unknown_account"} <= rules, rules)

    def test_retention_and_settings(self):
        lg = self.logons
        lg.update_settings({"retention_days": 30})
        old = datetime.utcnow() - timedelta(days=40)
        lg.record([{"host_ip": "192.168.1.10", "user": "jkowalski", "logon_type": "rdp", "at": old, "source": "event_log"},
                   {"host_ip": "192.168.1.10", "user": "jkowalski", "logon_type": "rdp", "at": datetime.utcnow(), "source": "event_log"}])
        self.assertEqual(lg.purge()["logons"], 1)
        self.assertEqual(lg.settings()["retention_days"], 30)


class NoData(_Db):
    def test_case_e3_reason_when_there_is_no_logon(self):
        lg = self.logons
        self.assertEqual(lg.summary(host_ip="192.168.1.40", asset_id=4, asset_type="windows", refs={})["reason"], "no_source")
        self.assertEqual(lg.summary(host_ip="192.168.1.30", asset_id=3, asset_type="printer", refs={})["reason"], "not_supported")
        self.assertEqual(lg.summary(host_ip="192.168.1.10", asset_id=1, asset_type="windows", refs={"windows_host_id": 1})["reason"], "source_silent")
        rows = [{"id": 1, "ip": "192.168.1.10", "type": "windows", "refs": {"windows_host_id": 1}}, {"id": 3, "ip": "192.168.1.30", "type": "printer", "refs": {}}]
        self.assertEqual(lg.last_by_host(rows), {1: {"why": "source_silent"}, 3: {"why": "not_supported"}})

    def test_names_are_text_only(self):
        self.logons.record([{"host_ip": "192.168.1.10", "user": "evil\x1b[31m<script>" + "x" * 200, "logon_type": "ssh", "at": datetime.utcnow(),
                             "source": "auth_log"}])
        with self.Session() as db:
            u = db.query(self.mdb.AssetLogon).one().user
        self.assertNotIn("\x1b", u)
        self.assertLessEqual(len(u), 64)

    def test_linux_ssh_and_who(self):
        from services import host_logs as hl
        out = ("2026-11-14T09:00:00+0000 srv sshd[1]: Accepted publickey for root from 192.168.1.50 port 50000 ssh2\n"
               "2026-11-14T09:01:00+0000 srv sshd[1]: Failed password for invalid user test from 45.1.2.3 port 1 ssh2\n"
               "@@WHO@@\nroot     pts/0        2026-11-14 09:00 (192.168.1.50)\n")
        ev = hl.parse_linux(out, datetime(2026, 11, 14), datetime(2026, 11, 14, 10))
        r = hl.linux_logons("oracle1", "192.168.1.60", ev, out, datetime(2026, 11, 14, 10))
        self.assertEqual(r["stored"], 2)
        self.assertEqual(self.logons.active_sessions("192.168.1.60"), [{"user": "root", "type": "ssh", "since": "2026-11-14 09:00", "from": "192.168.1.50"}])
        with self.Session() as db:
            rows = {x.result: x for x in db.query(self.mdb.AssetLogon).all()}
        self.assertTrue(rows["success"].is_privileged)


class CentralEdits(_Db):
    def test_set_delete_merge_and_not_duplicate(self):
        a = self.assets
        self.assertTrue(a.apply_central_op({"op": "set", "ids": [3], "asset_type": "camera", "criticality": "important"})["ok"])
        with self.Session() as db:
            x = db.get(self.mdb.Asset, 3)
            self.assertEqual((x.asset_type, x.criticality, json.loads(x.details)["_over"]["type"]), ("camera", "important", "camera"))
        self.assertFalse(a.apply_central_op({"op": "set", "ids": [3], "asset_type": "toaster"})["ok"])
        self.assertFalse(a.apply_central_op({"op": "drop_table", "ids": [3]})["ok"])
        with self.Session() as db:
            db.add(self.mdb.Asset(id=5, key="ip:192.168.1.41", ip="192.168.1.41", name="PC40", asset_type="windows"))
            db.commit()
        groups = a.public_duplicates()
        self.assertEqual([g["ids"] for g in groups], [[4, 5]])
        self.assertTrue(a.apply_central_op({"op": "not_duplicate", "ids": [4, 5]})["ok"])
        self.assertEqual(a.public_duplicates(), [], "marked as different devices: no longer offered")
        self.assertEqual(a.apply_central_op({"op": "merge", "keep_id": 4, "drop_ids": [5]})["merged"], 1)
        self.assertEqual(a.apply_central_op({"op": "delete", "ids": [3]})["deleted"], 1)
        with self.Session() as db:
            self.assertEqual(sorted(x.id for x in db.query(self.mdb.Asset).all()), [1, 2, 4])

    def test_the_command_is_signed_like_the_others(self):
        from services import uplink
        c = [{"type": "asset_op", "op": '{"op":"delete","ids":[3]}'}]
        import hashlib
        self.assertEqual(uplink._canonical_commands(c), "asset_op:" + hashlib.sha256(b'{"op":"delete","ids":[3]}').hexdigest())


if __name__ == "__main__":
    unittest.main()

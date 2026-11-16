"""Round 3, stage E (3.78) regression tests - docs/plan-runda-3.md: AnyDesk on the hosts (remote_access_tools).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import remote_access as ra


def windows_payload(**kw):
    p = {"reg": {"version": "8.1.0", "path": "C:\\Program Files (x86)\\AnyDesk"}, "svc": {"name": "AnyDesk", "state": "Running", "start": "Auto"},
         "file": {"path": "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", "version": "8.1.0"},
         "procs": ["C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe"], "found": [], "id": "123456789", "unattended": False,
         "trace": ["Incoming    2026-11-14, 21:05    User                      987654321    123456789",
                   "Incoming    2026-11-15, 03:10    REJECTED                  555444333    123456789"]}
    p.update(kw)
    return p


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, logons, assets
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'e.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (ra, soc, logons, assets)
        saved = [(m, m.SessionLocal) for m in mods]
        paths = (ra._PATH, logons._SETTINGS_PATH, logons._SESSIONS_PATH)
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(ra, "_PATH", paths[0]),
                                 setattr(logons, "_SETTINGS_PATH", paths[1]), setattr(logons, "_SESSIONS_PATH", paths[2]), ra._net_seen.clear()))
        for m in mods:
            m.SessionLocal = self.Session
        ra._PATH = os.path.join(tmp, "ra.json")
        logons._SETTINGS_PATH, logons._SESSIONS_PATH = os.path.join(tmp, "l.json"), os.path.join(tmp, "s.json")
        self.mdb = mdb
        with self.Session() as db:
            db.add(mdb.Asset(id=1, key="ip:192.168.1.10", ip="192.168.1.10", name="SRV1", asset_type="windows", role="server",
                             refs=json.dumps({"windows_host_id": 1})))
            db.add(mdb.Asset(id=2, key="ip:192.168.1.50", ip="192.168.1.50", name="PC50", asset_type="windows", role="workstation"))
            db.commit()

    def alerts(self):
        with self.Session() as db:
            return {a.rule: a.severity for a in db.query(self.mdb.SocAlert).all()}


class Windows(_Db):
    def test_case13_installed_service_with_id_and_version(self):
        r = ra.parse_windows(windows_payload())
        self.assertEqual((r["present"], r["install_type"], r["tool_id"], r["version"], r["running"], r["service_start"], r["source"]),
                         ("yes", "service", "123456789", "8.1.0", True, "auto", "registry"))
        self.assertEqual([t["result"] for t in r["trace"]], ["accepted", "rejected"])

    def test_case14_portable_from_downloads_on_a_server_is_high(self):
        p = windows_payload(reg=None, svc=None, file=None, procs=["C:\\Users\\jan\\Downloads\\AnyDesk.exe"], id=None, unattended=None, trace=[])
        r = ra.parse_windows(p)
        self.assertEqual((r["present"], r["install_type"]), ("yes", "portable"))
        ra.record("192.168.1.10", "SRV1", r)
        self.assertEqual(self.alerts().get("remote.portable_on_server"), "high")

    def test_new_install_unattended_outdated_and_incoming_logons(self):
        ra.record("192.168.1.10", "SRV1", ra.parse_windows(windows_payload(reg=None, svc=None, file=None, procs=[], id=None, unattended=None, trace=[])))
        self.assertEqual(self.alerts(), {}, "nothing there at the first read")
        ra.record("192.168.1.10", "SRV1", ra.parse_windows(windows_payload(unattended=True, reg={"version": "7.0.14", "path": ""},
                                                                             file={"path": "x", "version": "7.0.14"})))
        a = self.alerts()
        self.assertEqual((a.get("remote.new_install"), a.get("remote.unattended"), a.get("remote.outdated")), ("medium", "medium", "medium"))
        with self.Session() as db:
            lg = sorted((x.user, x.result, x.source) for x in db.query(self.mdb.AssetLogon).all())
        self.assertEqual(lg, [("AnyDesk 555444333", "failure", "anydesk_trace"), ("AnyDesk 987654321", "success", "anydesk_trace")])

    def test_case16_no_password_or_hash_is_stored(self):
        p = windows_payload(unattended=True)
        p["pwd_hash"] = "deadbeef"                                      # whatever else would come back is never kept
        ra.record("192.168.1.10", "SRV1", ra.parse_windows(p))
        with self.Session() as db:
            row = db.query(self.mdb.RemoteAccessTool).one()
            stored = json.dumps({c.name: str(getattr(row, c.name)) for c in row.__table__.columns})
        self.assertNotIn("deadbeef", stored)
        self.assertEqual(row.unattended, "yes")
        script = ra.WINDOWS_SCRIPT
        self.assertNotIn("$matches[2] }", script)
        self.assertIn("$o.unattended = $true", script, "unattended: only a yes / no leaves the host")
        self.assertNotRegex(script, r"\$o\.\w+\s*=\s*\$matches\[2\]")


class Versions(_Db):
    def test_minimum_per_line(self):
        self.assertTrue(ra.outdated("8.0.7"))
        self.assertFalse(ra.outdated("8.0.8"))
        self.assertTrue(ra.outdated("7.0.14"))
        self.assertFalse(ra.outdated("7.1.13"))
        self.assertTrue(ra.outdated("6.3.2"))
        self.assertFalse(ra.outdated("9.0.1"))
        with open(ra._PATH, "w") as f:
            json.dump({"min_version": "9.0.0"}, f)
        self.assertTrue(ra.outdated("8.1.0"), "one minimum set by the operator")


class LinuxAndNetwork(_Db):
    def test_linux_package_service_and_id(self):
        r = ra.parse_linux("@@PKG@@\n6.3.2\n@@SVC@@\nactive\nenabled\n@@ID@@\nad.anynet.id=444555666\n")
        self.assertEqual((r["present"], r["version"], r["running"], r["service_start"], r["tool_id"], r["source"]),
                         ("yes", "6.3.2", True, "auto", "444555666", "package"))
        self.assertEqual(ra.parse_linux("@@PKG@@\n\n@@SVC@@\ninactive\n@@ID@@\n")["present"], "no")

    def test_case15_traffic_alone_is_likely_never_present(self):
        ra.note_network("192.168.1.50", time.time())
        t = ra.for_asset(2, "192.168.1.50", "windows", {})
        self.assertEqual((t[0]["present"], t[0]["reason"], t[0]["likely"]), ("unknown", "no_agent", "network"))
        t = ra.for_asset(1, "192.168.1.10", "windows", {"windows_host_id": 1})
        self.assertEqual((t[0]["present"], t[0]["reason"]), ("unknown", "no_credential"))

    def test_report(self):
        ra.record("192.168.1.10", "SRV1", ra.parse_windows(windows_payload(unattended=True)))
        ra.record("192.168.1.50", "PC50", ra.parse_windows(windows_payload(reg=None, svc=None, file=None, procs=["C:\\Users\\a\\Desktop\\AnyDesk.exe"])))
        rows = [{"name": "SRV1", "ip": "192.168.1.10", "role": "server", "type": "windows"}, {"name": "PC50", "ip": "192.168.1.50", "role": "workstation", "type": "windows"}]
        rep = ra.report(rows)
        self.assertEqual((rep["hosts"], rep["portable"], rep["unattended"]), (2, 1, 1))
        self.assertEqual(([x["n"] for x in rep["servers"]], [x["n"] for x in rep["workstations"]]), (["SRV1"], ["PC50"]))


if __name__ == "__main__":
    unittest.main()

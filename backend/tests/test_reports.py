"""ITAM stage E (3.93): reports, files and scheduled e-mail (services/reports.py, services/mailer.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import reports as rp, mailer

NOW = datetime.utcnow()


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import licenses, procurement
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'r.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        mods = (rp, licenses, procurement)
        saved = [(m, m.SessionLocal) for m in mods]
        mp, ms = mailer._PATH, mailer._send_sync
        self.addCleanup(lambda: ([setattr(m, "SessionLocal", s) for m, s in saved], setattr(mailer, "_PATH", mp), setattr(mailer, "_send_sync", ms)))
        for m in mods:
            m.SessionLocal = self.Session
        mailer._PATH = os.path.join(tmp, "smtp.json")
        self.mdb = mdb
        with self.Session() as db:
            db.add(mdb.Asset(id=1, key="k1", name="FS1", asset_type="server", lifecycle_stage="deployed", cost=12000, currency="PLN", cost_center="IT",
                             purchased_at=datetime(2024, 3, 1), warranty_until=NOW + timedelta(days=30), model="PowerEdge R650", serial="=cmd|'/c calc'!A1"))
            db.add(mdb.Asset(id=2, key="k2", name="PC2", asset_type="windows", lifecycle_stage="disposed", disposed_at=datetime(2026, 1, 5), disposal_method="recycled"))
            db.add(mdb.Asset(id=3, key="k3", name="PC3", asset_type="windows", cost=3000, currency="PLN", cost_center="IT", purchased_at=datetime(2025, 6, 1)))
            db.commit()


class Build(_Db):
    def test_builtins(self):
        reg = rp.build("asset_register")
        self.assertEqual(sorted(r["name"] for r in reg["rows"]), ["FS1", "PC3"], "a disposed asset is not in the register")
        self.assertEqual([r["name"] for r in rp.build("warranty_ending")["rows"]], ["FS1"])
        self.assertEqual([r["name"] for r in rp.build("disposed_assets")["rows"]], ["PC2"])
        costs = rp.build("costs_by_center")
        self.assertEqual([(r["cost_center"], r["year"], r["total"]) for r in costs["rows"]], [("IT", "2024", 12000.0), ("IT", "2025", 3000.0)])
        for b in rp.BUILTIN:
            rp.build(b)                                         # every ready-made report builds

    def test_custom_filters_and_validation(self):
        d = rp.build(params={"scope": "assets", "columns": ["name", "cost", "bogus"], "filters": {"type": ["windows"], "purchased_from": "2025-01-01"}, "sort": "name"})
        self.assertEqual((d["columns"], [r["name"] for r in d["rows"]]), (["name", "cost"], ["PC3"]))
        with self.assertRaises(ValueError):
            rp.build(params={"scope": "people"})
        with self.assertRaises(ValueError):
            rp.build(params={"scope": "assets", "filters": {"purchased_from": "1.1.2025"}})


class Files(_Db):
    def test_csv_xlsx_docx(self):
        d = rp.build(params={"scope": "assets", "columns": ["name", "serial", "cost"], "filters": {}, "sort": "name"})
        labels = {"name": "Nazwa", "serial": "Nr seryjny", "cost": "Koszt"}
        csv_b, ctype, fname = rp.render("csv", "Rejestr zasobów", d, labels)
        text = csv_b.decode("utf-8")
        self.assertTrue(text.startswith("﻿Nazwa;Nr seryjny;Koszt"))
        self.assertIn("'=cmd|", text, "a formula from device data is written as text")
        self.assertTrue(fname.startswith("Rejestr_zasobów_") and fname.endswith(".csv"))
        xb, _, _ = rp.render("xlsx", "Rejestr", d, labels)
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(xb))
        ws = wb.active
        self.assertEqual([c.value for c in ws[1]], ["Nazwa", "Nr seryjny", "Koszt"])
        self.assertEqual(ws["C2"].value, 12000)
        self.assertEqual(ws["B2"].value, "'=cmd|'/c calc'!A1")
        db, _, _ = rp.render("docx", "Rejestr", d, labels)
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(db)))
        with self.assertRaises(ValueError):
            rp.render("pdf", "x", d)


class Schedule(_Db):
    def test_due(self):
        r = self.mdb.ReportDef(name="x", schedule="daily", hour=7, last_sent_at=None)
        self.assertFalse(rp.due(r, datetime(2026, 11, 20, 6, 59)))
        self.assertTrue(rp.due(r, datetime(2026, 11, 20, 7, 0)))
        r.last_sent_at = datetime(2026, 11, 20, 7, 1)
        self.assertFalse(rp.due(r, datetime(2026, 11, 20, 18, 0)))
        w = self.mdb.ReportDef(name="w", schedule="weekly", hour=7, weekday=0, last_sent_at=None)
        self.assertTrue(rp.due(w, datetime(2026, 11, 23, 8, 0)))          # a Monday
        self.assertFalse(rp.due(w, datetime(2026, 11, 24, 8, 0)))
        m = self.mdb.ReportDef(name="m", schedule="monthly", hour=7, day=1, last_sent_at=datetime(2026, 11, 1, 7, 0))
        self.assertFalse(rp.due(m, datetime(2026, 11, 1, 9, 0)))
        self.assertTrue(rp.due(m, datetime(2026, 12, 1, 7, 0)))

    def test_defs_and_sending(self):
        with self.assertRaisesRegex(ValueError, "recipient"):
            rp.save_def({"name": "R", "builtin": "asset_register", "schedule": "daily"}, None, "jan")
        with self.assertRaisesRegex(ValueError, "e-mail"):
            rp.save_def({"name": "R", "builtin": "asset_register", "schedule": "daily", "recipients": "jan@firma"}, None, "jan")
        rid = rp.save_def({"name": "Rejestr", "builtin": "asset_register", "schedule": "daily", "hour": 0, "format": "xlsx", "recipients": "it@firma.pl; szef@firma.pl"}, None, "jan")
        sent = []
        mailer._send_sync = lambda to, subject, text, files: sent.append((to, subject, [f[0] for f in files]))
        self.assertEqual(asyncio.run(rp.run_due(NOW)), 0, "nothing goes out before SMTP is set up")
        mailer.save({"host": "smtp.firma.pl", "port": 587, "security": "starttls", "username": "mm", "password": "tajne-haslo", "from_addr": "mm@firma.pl"})
        self.assertNotIn("tajne-haslo", open(mailer._PATH, encoding="utf-8").read(), "the password is stored encrypted")
        self.assertTrue(mailer.settings()["password_set"])
        self.assertNotIn("password_enc", mailer.settings())
        self.assertEqual(asyncio.run(rp.run_due(NOW)), 1)
        self.assertEqual(asyncio.run(rp.run_due(NOW + timedelta(minutes=10))), 0, "once per day")
        self.assertEqual(sent[0][0], ["it@firma.pl", "szef@firma.pl"])
        self.assertTrue(sent[0][2][0].endswith(".xlsx"))
        d = rp.defs()[0]
        self.assertEqual((d["runs"][0]["status"], d["runs"][0]["rows"]), ("ok", 2))

        def broken(*a):
            raise ConnectionRefusedError("refused")
        mailer._send_sync = broken
        r = asyncio.run(rp.send(rid))
        self.assertEqual(r["status"], "error")
        self.assertIn("refused", rp.defs()[0]["runs"][0]["error"])

    def test_message(self):
        m = mailer.build_message({"from_addr": "mm@firma.pl"}, ["a@b.pl"], "Raport\r\nBcc: x@y.pl", "treść", [("r.csv", "text/csv", b"a;b")])
        self.assertNotIn("\n", m["Subject"])
        self.assertEqual([p.get_filename() for p in m.iter_attachments()], ["r.csv"])
        with self.assertRaises(ValueError):
            mailer.save({"host": "smtp.firma.pl", "from_addr": "nie-mail"})


if __name__ == "__main__":
    unittest.main()

"""ITAM stage F (3.94): asset labels with a QR code and finding an asset from a phone (services/asset_labels.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import asset_labels as al


class Labels(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'l.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = al.SessionLocal
        self.addCleanup(lambda: setattr(al, "SessionLocal", saved))
        al.SessionLocal = self.Session
        with self.Session() as db:
            db.add(mdb.Asset(id=7, key="k7", name="FS1", ip="10.0.0.5", asset_type="server", asset_tag="INV-0007", serial="CN12345", model="PowerEdge R650"))
            db.add(mdb.Asset(id=8, key="k8", name="PC8", asset_type="windows"))
            db.commit()

    def test_labels_and_qr(self):
        rows = al.labels([7, 8, 99], "https://agent.firma.pl:8000/")
        self.assertEqual([(r["id"], r["url"]) for r in rows], [(7, "https://agent.firma.pl:8000/m/a/7"), (8, "https://agent.firma.pl:8000/m/a/8")])
        svg = base64.b64decode(rows[0]["qr"].split(",", 1)[1]).decode()
        self.assertIn("<svg", svg)
        for bad in ("javascript:alert(1)", "https://x/y?z", "ftp://host", "", "https://a b"):
            with self.assertRaises(ValueError, msg=bad):
                al.labels([7], bad)

    def test_find_by_url_tag_serial_and_search(self):
        self.assertEqual(al.find("https://agent.firma.pl:8000/m/a/7"), 7)
        self.assertEqual(al.find("inv-0007"), 7, "a tag regardless of case")
        self.assertEqual(al.find("CN12345"), 7)
        self.assertIsNone(al.find("https://x/m/a/999"))
        self.assertIsNone(al.find("nothing"))
        self.assertEqual([r["id"] for r in al.search("r650")], [7])
        self.assertEqual(al.search("p"), [], "two characters at least")

    def test_routes_are_not_taken_by_the_asset_id_route(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from api import assets as assets_api
        app = FastAPI()
        app.include_router(assets_api.router)
        c = TestClient(app)
        r = c.get("/api/assets/labels", params={"ids": "7", "base": "http://10.0.0.1:8000"})
        self.assertEqual((r.status_code, r.json()["labels"][0]["url"]), (200, "http://10.0.0.1:8000/m/a/7"))
        self.assertEqual(c.get("/api/assets/find", params={"code": "INV-0007"}).json(), {"id": 7})
        self.assertEqual(c.get("/api/assets/find", params={"code": "zzz"}).status_code, 404)
        self.assertEqual(c.get("/api/assets/labels", params={"ids": "7", "base": "nope"}).status_code, 400)


class Manifest(unittest.TestCase):
    def test_web_manifest(self):
        import json
        import main
        from fastapi.testclient import TestClient
        if not os.path.isdir(main.FRONTEND_DIST):
            self.skipTest("no frontend build here: the manifest route is registered with the built app only")
        c = TestClient(main.app)
        m = c.get("/manifest.webmanifest")
        self.assertEqual(m.headers["content-type"].split(";")[0], "application/manifest+json")
        self.assertEqual(json.loads(m.text)["start_url"], "/m")
        self.assertIn("<svg", c.get("/app-icon.svg").text)


if __name__ == "__main__":
    unittest.main()

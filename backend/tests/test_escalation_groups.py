"""3.88: escalation groups - alerts of chosen equipment escalate on their own times to their own Central rule (services/escalation.py).

Run from backend/:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import escalation as esc

NOW = datetime(2026, 11, 18, 12, 0)


class Validation(unittest.TestCase):
    def test_bad_groups_are_refused(self):
        for g in ({"name": "", "route": "x", "match": {"types": ["network"]}},
                  {"name": "Net", "route": "Network Team", "match": {"types": ["network"]}},
                  {"name": "Net", "route": "net", "match": {}},
                  {"name": "Net", "route": "net", "match": {"types": ["network"]}, "levels": {"high": [60, 30]}}):
            with self.assertRaises(ValueError, msg=g):
                esc.clean_group(g)
        g = esc.clean_group({"name": " Sieć ", "route": "NET-team", "match": {"types": ["network", "toaster"], "groups": ["servers"]}})
        self.assertEqual((g["name"], g["route"], g["match"]["types"], g["exclusive"]), ("Sieć", "net-team", ["network"], True))


class _Db(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models.database as mdb
        from services import soc, maintenance
        tmp = tempfile.mkdtemp()
        engine = create_engine(f"sqlite:///{os.path.join(tmp, 'e.db')}", connect_args={"check_same_thread": False})
        mdb.Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        saved = (esc.SessionLocal, soc.SessionLocal, esc._PATH, json.loads(json.dumps(esc._settings)), maintenance.covers_alert)
        self.addCleanup(lambda: (setattr(esc, "SessionLocal", saved[0]), setattr(soc, "SessionLocal", saved[1]), setattr(esc, "_PATH", saved[2]),
                                 esc._settings.clear(), esc._settings.update(saved[3]), setattr(maintenance, "covers_alert", saved[4])))
        esc.SessionLocal = soc.SessionLocal = self.Session
        esc._PATH = os.path.join(tmp, "esc.json")
        maintenance.covers_alert = lambda *a, **k: None
        esc.load_settings()
        esc._settings["baselined"] = True
        self.mdb = mdb
        with self.Session() as db:
            db.add(mdb.Asset(id=1, key="ip:10.0.0.1", ip="10.0.0.1", name="SW-CORE", asset_type="network", criticality="critical"))
            db.add(mdb.Asset(id=2, key="ip:10.0.0.50", ip="10.0.0.50", name="PC50", asset_type="windows", role="workstation"))
            db.commit()

    def alert(self, asset_id, device, severity, minutes):
        with self.Session() as db:
            a = self.mdb.SocAlert(fingerprint=f"x|{device}|{minutes}", rule="asset_down", source="rules", category="availability", severity=severity,
                                  title="Device not answering", device_name=device, asset_id=asset_id, status="new", count=1,
                                  first_seen=NOW - timedelta(minutes=minutes), last_seen=NOW)
            db.add(a)
            db.commit()
            return a.id


class Groups(_Db):
    def test_group_times_and_route_exclusive(self):
        esc.update_settings({"groups": [{"name": "Sieć", "route": "network-team", "match": {"groups": ["network"]}, "levels": {"high": [5, 20]}}]})
        self.alert(1, "SW-CORE", "high", 25)                   # the group's times: 5 and 20 min -> level 2
        self.alert(2, "PC50", "high", 25)                      # the general times: 60, 240 -> nothing yet
        ev = esc.collect_events(NOW)
        self.assertEqual([(e["type"], e["count"], e.get("group")) for e in ev], [("soc_escalated.network-team", 2, "Sieć")])

    def test_not_exclusive_also_sends_the_general_event(self):
        esc.update_settings({"groups": [{"name": "Krytyczne", "route": "crit", "match": {"criticality": ["critical"]}, "exclusive": False}]})
        self.assertEqual(esc.clean_group({"name": "x", "route": "x", "match": {"criticality": ["high", "important", "bogus"]}})["match"]["criticality"],
                         ["important", "important"], "the asset levels, the old high read as important")
        self.alert(1, "SW-CORE", "critical", 20)               # general critical times 15, 60, 240 -> level 1
        ev = sorted(e["type"] for e in esc.collect_events(NOW))
        self.assertEqual(ev, ["soc_escalated", "soc_escalated.crit"])

    def test_all_conditions_must_hold_and_first_group_wins(self):
        esc.update_settings({"groups": [
            {"name": "A", "route": "a", "match": {"types": ["network"], "name": "edge"}},           # SW-CORE is not "edge"
            {"name": "B", "route": "b", "match": {"types": ["network"], "criticality": ["critical"]}},
            {"name": "C", "route": "c", "match": {"name": "sw-"}}]})
        g = esc.group_for({"groups": ["network"], "type": "network", "criticality": "critical", "name": "SW-CORE"}, "SW-CORE")
        self.assertEqual(g["route"], "b")
        self.assertEqual(esc.group_for(None, "sw-floor2")["route"], "c", "an alert without an asset matches by name only")
        self.assertIsNone(esc.group_for(None, "printer"))

    def test_routes_are_unique_and_saved(self):
        with self.assertRaises(ValueError):
            esc.update_settings({"groups": [{"name": "A", "route": "x", "match": {"types": ["network"]}}, {"name": "B", "route": "x", "match": {"types": ["linux"]}}]})
        esc.update_settings({"groups": [{"name": "A", "route": "x", "match": {"types": ["network"]}}]})
        esc._settings.clear()
        self.assertEqual([g["route"] for g in esc.load_settings()["groups"]], ["x"])

    def test_without_groups_nothing_changes(self):
        self.alert(1, "SW-CORE", "critical", 70)
        self.assertEqual([(e["type"], e["count"]) for e in esc.collect_events(NOW)], [("soc_escalated", 2)])


if __name__ == "__main__":
    unittest.main()

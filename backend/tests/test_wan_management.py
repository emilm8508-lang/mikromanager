"""3.94.7: the "management from the WAN restricted" check walks the input chain like RouterOS (first match wins, no match = accept).

Seen in production: the check passed (no explicit "accept from WAN" rule) while an edge router's Winbox answered the internet - the
input chain never dropped anything, and failed logins for admin came from several public addresses.

Run from backend/:  python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import compliance as c  # noqa: E402

WAN = {"ether1"}
SERVICES = [
    {"name": "winbox", "port": "8291", "address": "", "disabled": "false"},
    {"name": "www", "port": "80", "address": "", "disabled": "false"},
    {"name": "telnet", "port": "23", "address": "", "disabled": "true"},
    {"name": "api", "port": "8728", "address": "192.168.0.0/16", "disabled": "false"},
]
DEFCONF = [
    {"chain": "input", "action": "accept", "connection-state": "established,related,untracked"},
    {"chain": "input", "action": "drop", "connection-state": "invalid"},
    {"chain": "input", "action": "accept", "protocol": "icmp"},
    {"chain": "input", "action": "drop", "in-interface-list": "!LAN"},
]


def exposed(rules, services=SERVICES):
    found, unsure = c.wan_exposure(rules, services, WAN)
    return sorted(label for label, _, _ in found), unsure


class WalkInput(unittest.TestCase):
    def test_a_chain_that_never_drops_exposes_the_services(self):
        rules = [{"chain": "input", "action": "accept", "connection-state": "established,related"}]
        self.assertEqual(exposed(rules), (["WWW", "Winbox"], False))
        found, _ = c.wan_exposure(rules, SERVICES, WAN)
        self.assertIn("nie ma reguły", found[0][2])

    def test_no_rules_at_all_is_exposed(self):
        self.assertEqual(exposed([])[0], ["WWW", "Winbox"])

    def test_default_configuration_drop_not_from_lan_protects(self):
        self.assertEqual(exposed(DEFCONF), ([], False))

    def test_explicit_accept_from_the_wan_before_the_drop(self):
        rules = DEFCONF[:3] + [{"chain": "input", "action": "accept", "protocol": "tcp", "dst-port": "8291", "in-interface-list": "WAN",
                                "comment": "winbox z zewnatrz"}] + DEFCONF[3:]
        found, _ = c.wan_exposure(rules, SERVICES, WAN)
        self.assertEqual([(x[0], x[1]) for x in found], [("Winbox", 8291)])
        self.assertIn("winbox z zewnatrz", found[0][2])

    def test_accept_limited_to_a_source_list_then_drop(self):
        rules = DEFCONF[:3] + [{"chain": "input", "action": "accept", "src-address-list": "MGMT"},
                               {"chain": "input", "action": "drop"}]
        self.assertEqual(exposed(rules)[0], [])

    def test_drop_for_everyone_but_mgmt_protects(self):
        rules = [{"chain": "input", "action": "drop", "src-address-list": "!MGMT", "in-interface": "ether1"}]
        self.assertEqual(exposed(rules)[0], [])

    def test_service_address_and_disabled_service_are_not_exposed(self):
        self.assertNotIn("API", exposed([])[0])
        self.assertNotIn("Telnet", exposed([])[0])

    def test_port_ranges_and_other_interfaces(self):
        rules = [{"chain": "input", "action": "drop", "protocol": "tcp", "dst-port": "8000-8300", "in-interface": "ether1"},
                 {"chain": "input", "action": "drop", "in-interface": "bridge"}]
        self.assertEqual(exposed(rules)[0], ["WWW"], "the range drops Winbox; the bridge rule is not the WAN")

    def test_disabled_rules_do_not_count(self):
        rules = [{"chain": "input", "action": "drop", "disabled": "true"}]
        self.assertEqual(exposed(rules)[0], ["WWW", "Winbox"])

    def test_unmodelled_matchers_and_jumps_make_it_unsure_never_decide(self):
        rules = [{"chain": "input", "action": "drop", "src-address-type": "unicast"},
                 {"chain": "input", "action": "jump", "jump-target": "mgmt"},
                 {"chain": "input", "action": "drop"}]
        self.assertEqual(exposed(rules), ([], True))

    def test_api_field_types_bool_false_is_absent(self):
        rules = [{".id": "*1", "chain": "input", "action": "drop", "disabled": False, "dynamic": False, "invalid": False, "log": False}]
        self.assertEqual(exposed(rules), ([], False))


class FakeClient:
    def __init__(self, members):
        self.members = members

    async def get_interface_list_members(self):
        return self.members


class Check(unittest.TestCase):
    def run_check(self, rules, services, members=({"list": "WAN", "interface": "ether1"},)):
        return asyncio.run(c._check_wan_management_exposed(FakeClient(list(members)), rules, services))

    def test_fails_with_the_services_named(self):
        passed, detail = self.run_check([], SERVICES)
        self.assertFalse(passed)
        self.assertIn("Winbox (port 8291)", detail)

    def test_passes_with_the_default_configuration(self):
        self.assertTrue(self.run_check(DEFCONF, SERVICES)[0])

    def test_without_a_wan_list_it_cannot_tell(self):
        self.assertIsNone(self.run_check([], SERVICES, members=())[0])

    def test_without_the_services_the_old_reading_stays(self):
        self.assertTrue(self.run_check([], None)[0], "no services read: only explicit accept rules from the WAN count, as before")


if __name__ == "__main__":
    unittest.main()

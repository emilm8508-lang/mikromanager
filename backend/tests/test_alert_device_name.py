"""3.81 regression: memory_high / disk_space_low showed "?" as the device in alerts and the alert history - the host events named
their host only as "hostname", which nothing read.

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import soc


class DeviceName(unittest.TestCase):
    def test_older_host_event_names_its_host(self):
        self.assertEqual(soc._device_of({"type": "memory_high", "hostname": "SRV1"}), "SRV1")
        self.assertEqual(soc._device_of({"type": "disk_space_low", "ip": "192.168.1.10"}), "192.168.1.10")
        self.assertEqual(soc._device_of({"device_name": "R1", "hostname": "x"}), "R1")
        self.assertIsNone(soc._device_of({"type": "x"}))

    def test_host_events_carry_device_name(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "services", "resource_monitor.py"),
                   encoding="utf-8").read()
        events = re.findall(r'"hostname": identity,[^\n]*', src)
        self.assertEqual(len(events), 4)
        for line in events:
            self.assertIn('"device_name": identity', line)
            self.assertIn('"device_ip": h.ip', line)


if __name__ == "__main__":
    unittest.main()

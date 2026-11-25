"""3.94.4: the hops of tracert, traceroute and tracepath output (services/traceroute.py).

psb's agent (Ubuntu without traceroute) uses tracepath, whose hops read "1:  192.168.0.1  0.5ms" - the parser wanted a space right after the
number, so NetPath showed 0 hops and "not reached", and routed ranges were not grouped under their gateway.

Run from backend/:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import traceroute as tr

TRACEPATH = """  1?: [LOCALHOST]                      pmtu 1500
  1:  192.168.0.1                                           0.512ms
  1:  192.168.0.1                                           0.401ms
  2:  10.10.0.1                                             3.105ms
  3:  no reply
  4:  80.50.1.2                                             5.900ms asymm  5
  5:  1.1.1.1                                               6.010ms reached
     Resume: pmtu 1500 hops 5 back 5
"""
TRACERT = """Tracing route to 1.1.1.1 over a maximum of 15 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3     5 ms     4 ms     4 ms  1.1.1.1

Trace complete."""
TRACEROUTE = """traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 60 byte packets
 1  192.168.0.1  0.421 ms
 2  *
 3  1.1.1.1  6.102 ms"""


class Parse(unittest.TestCase):
    def test_tracepath(self):
        self.assertEqual([(h["n"], h["ip"]) for h in tr.parse(TRACEPATH)],
                         [(1, "192.168.0.1"), (2, "10.10.0.1"), (3, None), (4, "80.50.1.2"), (5, "1.1.1.1")])
        self.assertEqual(tr.parse(TRACEPATH)[0]["ms"], 0.512, "the first answer of a hop tracepath prints twice")

    def test_tracert_and_traceroute_unchanged(self):
        self.assertEqual([(h["n"], h["ip"]) for h in tr.parse(TRACERT)], [(1, "192.168.1.1"), (2, None), (3, "1.1.1.1")])
        self.assertEqual([(h["n"], h["ip"]) for h in tr.parse(TRACEROUTE)], [(1, "192.168.0.1"), (2, None), (3, "1.1.1.1")])
        self.assertEqual(tr.last_hop(tr.parse(TRACEPATH), "1.1.1.1"), "80.50.1.2")


if __name__ == "__main__":
    unittest.main()

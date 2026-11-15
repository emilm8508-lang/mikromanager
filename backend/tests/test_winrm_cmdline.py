"""3.71 regression: Windows' 8191-character command line. After 3.66 every Windows Update install failed with "couldn't write install
script: The command line is too long" - pywinrm sends a script as one "powershell -encodedcommand <base64 of UTF-16>" command.

Run from backend/:  python -m unittest discover -s tests -v
"""
import base64
import os
import re
import sys
import unittest
from datetime import datetime
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LIMIT = 8191


class FakeSession:
    """Records what would go over WinRM and plays the remote file system for the staged writes."""

    def __init__(self):
        self.sent, self.files = [], {}

    def run_ps(self, script):
        cmd = "powershell -encodedcommand " + base64.b64encode(script.encode("utf-16-le")).decode()
        self.sent.append(cmd)
        if len(cmd) > LIMIT:
            return NS(status_code=1, std_out=b"", std_err=b"The command line is too long.")
        m = re.match(r"\$p = (.+?); \$b = \[Convert\]::FromBase64String\('([A-Za-z0-9+/=]*)'\); \$f = \[IO\.File\]::Open\(\$p, \[IO\.FileMode\]::(\w+)\)", script)
        if m:
            data = base64.b64decode(m.group(2))
            self.files[m.group(1)] = (b"" if m.group(3) == "Create" else self.files.get(m.group(1), b"")) + data
        return NS(status_code=0, std_out=b"ok", std_err=b"")


class CommandLine(unittest.TestCase):
    def test_install_script_is_written_in_pieces_under_the_limit(self):
        from services import vuln_scan as vs, windows_manage as wm
        body = wm._INSTALL_TASK_SCRIPT.format(job_id="abc123")
        s = FakeSession()
        r = vs.write_remote_file(s, "'C:\\Windows\\Temp\\mm_winupdate_abc123.ps1'", body)
        self.assertEqual(r.status_code, 0)
        self.assertGreater(len(s.sent), 1)
        self.assertTrue(all(len(c) <= LIMIT for c in s.sent), max(len(c) for c in s.sent))
        self.assertEqual(s.files["'C:\\Windows\\Temp\\mm_winupdate_abc123.ps1'"], b"\xef\xbb\xbf" + body.encode("utf-8"),
                         "the file on the host is the script, byte for byte (UTF-8 with BOM for PowerShell 5.1)")

    def test_long_scripts_are_staged_short_ones_sent_as_they_are(self):
        from services import vuln_scan as vs, host_logs as hl
        s = FakeSession()
        vs._run_ps_safe(s, "Get-Date")
        self.assertEqual(len(s.sent), 1)
        long = hl.windows_script(datetime(2026, 11, 1), ad=True) + "\n# padding " + "x" * 3000
        s = FakeSession()
        r = vs._run_ps_safe(s, long)
        self.assertEqual(r.status_code, 0)
        self.assertTrue(all(len(c) <= LIMIT for c in s.sent))
        self.assertIn("[ScriptBlock]::Create", base64.b64decode(s.sent[-2].split()[-1]).decode("utf-16-le"), "run as a script block")
        self.assertIn("Remove-Item", base64.b64decode(s.sent[-1].split()[-1]).decode("utf-16-le"), "and the file removed")

    def test_every_script_the_agent_sends_fits_or_is_staged(self):
        from services import vuln_scan as vs, host_logs as hl, windows_manage as wm
        for script in (hl.windows_script(datetime(2026, 11, 1), ad=True), wm._RESOURCES_SCRIPT, wm._INSTALL_TASK_SCRIPT.format(job_id="x")):
            s = FakeSession()
            self.assertEqual(vs._run_ps_safe(s, script).status_code, 0)
            self.assertTrue(all(len(c) <= LIMIT for c in s.sent))


if __name__ == "__main__":
    unittest.main()

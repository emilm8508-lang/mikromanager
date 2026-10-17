"""Keeps the agent's Python environment free of files that antivirus products flag.

impacket (the optional DCOM / WMI scan, requirements-dcom.txt) installs ~60 example scripts of a penetration-testing toolkit into the
interpreter's Scripts folder (secretsdump.py, DumpNTLMInfo.py ...). Windows Defender reports them as "HackTool:Python/Impacket" and
quarantines them, which looks alarming on a client's computer and for nothing: the agent imports the library only and never runs them.
So after an install they are deleted - exactly the files that impacket's own install record lists in the Scripts folder, nothing else."""
import os
import sysconfig
from typing import List


def impacket_example_scripts() -> List[str]:
    """Paths of the example scripts impacket put into this interpreter's Scripts folder (empty when it is not installed).
    The wheel's install record lists them as "impacket-X.data/scripts/NAME" (pip places them in Scripts); a file of that name there is
    taken only if it really is an impacket script (it mentions impacket), so a script of some other package is never touched."""
    try:
        from importlib import metadata
        record = metadata.distribution("impacket").read_text("RECORD") or ""
    except Exception:
        return []
    scripts_dir = sysconfig.get_path("scripts")
    out: List[str] = []
    for line in record.splitlines():
        path = line.split(",", 1)[0].replace("\\", "/")
        if ".data/scripts/" not in path:
            continue
        p = os.path.join(scripts_dir, path.rsplit("/", 1)[-1])
        try:
            with open(p, "rb") as f:
                if os.path.isfile(p) and b"impacket" in f.read(20000):
                    out.append(p)
        except OSError:
            continue
    return out


def remove_impacket_examples() -> int:
    """Deletes them; returns how many were removed. Safe to run any time (nothing to do when impacket is absent or already cleaned)."""
    n = 0
    for p in impacket_example_scripts():
        try:
            os.remove(p)
            n += 1
        except OSError:
            pass
    if n:
        print(f"[pkg_hygiene] removed {n} impacket example script(s) that antivirus products flag")
    return n

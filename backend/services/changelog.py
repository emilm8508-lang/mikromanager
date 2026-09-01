"""
Parses CHANGELOG.md (repo root) into structured version entries — the
single source of truth for both the agent's own reported agent_version
(services/uplink.py's _build_snapshot()) and the in-app "Historia zmian"
view (GET /api/system/changelog). A release now only needs ONE edit — a
new "## <version> — <date>" section at the top of CHANGELOG.md — instead
of two places that could drift (a literal agent_version string here vs.
a separately-maintained changelog entry there).

Format contract (deliberately simple/regex-parseable — this file has
exactly one author, so no need for a general-purpose changelog parser):
    ## <version> — <YYYY-MM-DD>
    - <change line>
    - <change line>
"""
import os
import re

_CHANGELOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "CHANGELOG.md")

_ENTRY_RE = re.compile(r"^##\s+(\S+)\s+—\s+(\d{4}-\d{2}-\d{2})\s*$")


def get_entries() -> list:
    """Newest-first list of {"version", "date", "changes": [...]}.
    Re-parses on every call — the file is small and this is an occasional
    API request, not a hot path, so there's no cache to go stale if
    CHANGELOG.md changes mid-process (e.g. right after a self-update)."""
    if not os.path.exists(_CHANGELOG_PATH):
        return []
    entries = []
    current = None
    with open(_CHANGELOG_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            m = _ENTRY_RE.match(line)
            if m:
                if current:
                    entries.append(current)
                current = {"version": m.group(1), "date": m.group(2), "changes": []}
            elif current and line.strip().startswith("- "):
                current["changes"].append(line.strip()[2:])
    if current:
        entries.append(current)
    return entries


def current_version() -> str:
    """The agent's own reported version — the top entry's version number.
    Falls back to "0.0" only if CHANGELOG.md is ever missing/unparseable,
    which shouldn't happen in a real deployment (it ships with the repo)."""
    entries = get_entries()
    return entries[0]["version"] if entries else "0.0"

"""
RouterOS version checker — fetches latest available versions from
upgrade.mikrotik.com and compares to versions installed on devices.

Mikrotik publishes plain-text version files at:
  https://upgrade.mikrotik.com/routeros/LATEST.6     (stable v6)
  https://upgrade.mikrotik.com/routeros/LATEST.6fix  (long-term v6)
  https://upgrade.mikrotik.com/routeros/LATEST.7     (stable v7)
  https://upgrade.mikrotik.com/routeros/LATEST.7rc   (release candidate v7)

Each file has format:  "<version> <unix_timestamp>"
"""
import asyncio
import re
import time
from typing import Optional
import aiohttp

CHANNELS = {
    "6":      "https://upgrade.mikrotik.com/routeros/LATEST.6",
    "6fix":   "https://upgrade.mikrotik.com/routeros/LATEST.6fix",
    "7":      "https://upgrade.mikrotik.com/routeros/LATEST.7",
    "7rc":    "https://upgrade.mikrotik.com/routeros/LATEST.7rc",
}

CACHE_TTL_SEC = 6 * 3600   # 6h
_cache: dict = {"data": None, "fetched_at": 0}


async def _fetch_one(name: str, url: str) -> Optional[dict]:
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None
                text = (await resp.text()).strip()
                parts = text.split()
                if not parts:
                    return None
                version = parts[0]
                released = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                return {"channel": name, "version": version, "released_at": released}
    except Exception:
        return None


async def fetch_latest(force: bool = False) -> dict:
    """Return cached map channel→{version, released_at}. Refetches if stale."""
    now = time.time()
    if not force and _cache["data"] and (now - _cache["fetched_at"]) < CACHE_TTL_SEC:
        return _cache["data"]

    results = await asyncio.gather(*[
        _fetch_one(name, url) for name, url in CHANNELS.items()
    ])

    data = {r["channel"]: r for r in results if r is not None}
    if data:
        _cache["data"] = data
        _cache["fetched_at"] = now
    return _cache["data"] or {}


# ── Version comparison ────────────────────────────────────────────────────────

_VER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:rc(\d+))?(?:beta(\d+))?")


def parse_version(s: str) -> Optional[tuple]:
    """Convert "7.13.5" or "6.49.18" to comparable tuple. Returns None if unparseable.
    Format: (major, minor, patch, is_rc, rc_or_beta_num)
    Stable releases sort higher than rc/beta of the same x.y.z."""
    if not s:
        return None
    m = _VER_RE.match(s.strip())
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3) or 0)
    rc = int(m.group(4) or 0)
    beta = int(m.group(5) or 0)
    # is_stable = no rc/beta. Stable > rc > beta of same x.y.z
    stable_marker = 999 if (rc == 0 and beta == 0) else (rc if rc else -beta)
    return (major, minor, patch, stable_marker)


def compare_versions(installed: str, latest: str) -> Optional[int]:
    """Return -1 if installed < latest, 0 if equal, 1 if installed > latest, None if unparseable."""
    a = parse_version(installed)
    b = parse_version(latest)
    if a is None or b is None:
        return None
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def pick_target(installed: str, latest_map: dict) -> Optional[dict]:
    """Pick best target version for an installed version. Stays on same major track
    (v6 → LATEST.6 stable; v7 → LATEST.7 stable). Returns None if installed is unknown
    or already up to date."""
    if not installed:
        return None
    iv = parse_version(installed)
    if iv is None:
        return None

    major = iv[0]
    if major == 6:
        candidate = latest_map.get("6")
    elif major == 7:
        candidate = latest_map.get("7")
    else:
        return None

    if not candidate:
        return None

    cmp = compare_versions(installed, candidate["version"])
    if cmp is None:
        return None
    if cmp >= 0:
        # Up to date or running newer (beta/rc).
        return {"status": "up_to_date", "current": installed,
                "target": candidate["version"], "channel": candidate["channel"]}
    return {"status": "outdated", "current": installed,
            "target": candidate["version"], "channel": candidate["channel"],
            "released_at": candidate.get("released_at")}

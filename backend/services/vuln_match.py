"""
Whether a CVE really applies to what a device runs - the part of the vulnerability check that decides, not the part that searches.

Seen in production (3.57, five clients): CVE-2018-14847 (Winbox, fixed in 6.42.1) and CVE-2018-7445 (SMB, fixed in 6.41.3), both KEV with
CVSS 9.8, were attached to RouterOS 7.23-7.25 routers, to SwOS switches (2.16-2.21), to Brother printers (1.03, 1.37) and to a box whose
"version" was a Linux kernel (2.6.18). Two causes: the NVD lookup took the CVEs of whichever RouterOS CPE came first when NVD had none for
the exact version, and nothing compared the version with the affected ranges; and every version of a device marked "mikrotik" was read as
RouterOS. This module is the check both lacked:

  * compare(a, b)              - versions as RouterOS / Linux / Windows write them ("7.25.1", "7.23.2 (stable)", "6.49.21 (long-term)", "7.15rc3")
  * evaluate(matches, ...)     - a CVE's NVD configurations (cpeMatch with versionStart/End Including/Excluding) against one product and version
  * routeros_identity(...)     - whether a device's version is RouterOS at all (RouterOS, SwOS or unknown), with the source and the confidence
  * distro_from(...)           - the Linux distribution behind a banner or a host's OS (backported fixes make the banner version unreliable)
  * finding_confidence(...)    - confirmed / likely / suspected for one finding, from how it was matched and how the product was identified

Pure functions (no database, no network) so the regression cases can be tested directly - backend/tests/test_vuln_match.py.
"""
import re
from typing import Any, Iterable, List, Optional, Tuple

CONFIDENCES = ("confirmed", "likely", "suspected")
MATCH_SOURCES = ("cpe-range", "package", "banner")

# The CPE of the products this agent names itself (product strings of Device / VulnService rows); NVD is asked with these and the version.
PRODUCT_CPE = {
    "mikrotik routeros": "cpe:2.3:o:mikrotik:routeros",
    "mikrotik swos": "cpe:2.3:o:mikrotik:swos",
}

_CHANNEL = re.compile(r"\s*\((stable|long-term|longterm|testing|development|bugfix|lts)\)\s*$", re.I)
_PRE = re.compile(r"^(\d+(?:\.\d+)*)(?:[.\-_]?(rc|beta|alpha|a|b)(\d*))?", re.I)
_PRE_RANK = {"alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1}


def clean_version(v: Any) -> str:
    """The version without its channel or trailing text: "7.23.2 (stable)" -> "7.23.2", " v6.49.21 (long-term) " -> "6.49.21"."""
    s = str(v or "").strip()
    s = _CHANNEL.sub("", s)
    s = re.sub(r"^[vV](?=\d)", "", s)
    return s.strip()


def version_key(v: Any) -> Optional[Tuple]:
    """A sortable key, or None for something that is not a version. 7.15rc3 sorts before 7.15, 7.15 equals 7.15.0."""
    m = _PRE.match(clean_version(v))
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    pre = (0, 0)
    if m.group(2):
        pre = (_PRE_RANK[m.group(2).lower()], int(m.group(3) or 0))
    return tuple(nums), pre


def compare(a: Any, b: Any) -> Optional[int]:
    """-1 / 0 / 1, or None when either side is not a version (then nothing may be concluded from it)."""
    ka, kb = version_key(a), version_key(b)
    if ka is None or kb is None:
        return None
    na, nb = list(ka[0]), list(kb[0])
    n = max(len(na), len(nb))
    na += [0] * (n - len(na))
    nb += [0] * (n - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    if ka[1] != kb[1]:
        return -1 if ka[1] < kb[1] else 1
    return 0


# ── NVD configurations ───────────────────────────────────────────────────────

def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def extract_matches(cve: Any) -> List[dict]:
    """Every cpeMatch of a CVE as plain dicts, from NVD API 2.0 JSON ({"cve": {...}} or the inner object), nvdlib's objects, or the
    "cpe_matches" list this agent stores. Empty when the CVE carries no configurations (e.g. not yet analysed by NVD)."""
    stored = _get(cve, "cpe_matches")
    if isinstance(stored, list):
        return [m for m in stored if isinstance(m, dict)]
    inner = _get(cve, "cve") or cve
    configs = _get(inner, "configurations") or []
    out: List[dict] = []
    for conf in configs if isinstance(configs, list) else []:
        for node in _get(conf, "nodes") or []:
            for m in _get(node, "cpeMatch") or []:
                crit = _get(m, "criteria")
                if not crit:
                    continue
                out.append({k: _get(m, k) for k in ("criteria", "vulnerable", "versionStartIncluding", "versionStartExcluding",
                                                    "versionEndIncluding", "versionEndExcluding") if _get(m, k) is not None})
    return out


def cpe_parts(cpe: str) -> Optional[Tuple[str, str, str, str]]:
    """("o", "mikrotik", "routeros", version) from "cpe:2.3:o:mikrotik:routeros:7.25.1:*:..." - None when it is not a CPE 2.3 name."""
    p = str(cpe or "").split(":")
    if len(p) < 6 or p[0] != "cpe" or p[1] != "2.3":
        return None
    return p[2], p[3].lower(), p[4].lower(), p[5]


def evaluate(matches: Iterable[dict], vendor: str, product: str, version: str) -> Tuple[str, Optional[str]]:
    """("affected", fixed_version) / ("not_affected", None) / ("unknown", None) for one vendor:product at one version.
    Only the vulnerable cpeMatch entries of that vendor:product count; "unknown" when the CVE has none (nothing to compare with).
    The fixed version is the end of the matching range when it is an excluding end (the first version without the flaw)."""
    vendor, product = vendor.lower(), product.lower()
    if version_key(version) is None:
        return "unknown", None
    relevant = 0
    for m in matches:
        parts = cpe_parts(m.get("criteria", ""))
        if not parts or parts[1] != vendor or parts[2] != product or m.get("vulnerable") is False:
            continue
        relevant += 1
        exact = parts[3]
        ranged = any(m.get(k) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
        if exact not in ("*", "-", "") and not ranged:
            c = compare(version, exact)
            if c == 0:
                return "affected", None
            continue
        ok = True
        for key, test in (("versionStartIncluding", lambda c: c >= 0), ("versionStartExcluding", lambda c: c > 0),
                          ("versionEndIncluding", lambda c: c <= 0), ("versionEndExcluding", lambda c: c < 0)):
            bound = m.get(key)
            if bound:
                c = compare(version, bound)
                if c is None or not test(c):
                    ok = False
                    break
        if ok and (ranged or exact in ("*", "")):
            return "affected", clean_version(m.get("versionEndExcluding")) or None
    return ("not_affected", None) if relevant else ("unknown", None)


# ── Is it RouterOS at all? ───────────────────────────────────────────────────

_NOT_ROUTEROS_NAME = re.compile(r"^(BRN|BRW)[0-9A-F]{12}$|^ET[0-9A-F]{12}$|^NPI[0-9A-F]{6}|^HP[0-9A-F]{6}|^EPSON|^KM[0-9A-F]{6}", re.I)
_MIKROTIK_OUI = re.compile(r"mikrotik|routerboard", re.I)
_SWOS_MODEL = re.compile(r"\bcss\d|\bswos\b|\bcrs3\d\d-.*\bswos|\bnetfiber\b|\bnetpower\b|\brb260", re.I)


def routeros_identity(*, vendor: Optional[str], version: Optional[str], model: Optional[str] = None, name: Optional[str] = None,
                      oui_vendor: Optional[str] = None, sys_descr: Optional[str] = None, has_api: bool = False,
                      has_winbox: bool = False) -> dict:
    """{"product": "MikroTik RouterOS" | "MikroTik SwOS" | None, "confidence": ..., "source": ..., "reason": ...} for a device marked mikrotik.

    Evidence, strongest first: the RouterOS API / Winbox answered (only RouterOS runs them), sysDescr naming RouterOS, the MAC's maker,
    the device's name (printers name themselves BRN<MAC>, ET<MAC> ...), then the shape of the version: RouterOS has been 6.x / 7.x for a
    decade (3.x-5.x very old), SwOS is 1.x / 2.x, and a 2.6.x is a Linux kernel. A product that cannot be confirmed gets None - no RouterOS
    CVE is attached to it then (a wrong product is worse than none)."""
    v = clean_version(version)
    key = version_key(v)
    out = {"product": None, "confidence": None, "source": None, "reason": None}
    if (vendor or "").lower() != "mikrotik" or key is None:
        out["reason"] = "not a MikroTik device or no version"
        return out
    if oui_vendor and not _MIKROTIK_OUI.search(oui_vendor):
        out["reason"] = f"the network card is made by {oui_vendor}"
        return out
    if name and _NOT_ROUTEROS_NAME.search(name.strip()):
        out["reason"] = "the name is a printer's / embedded device's default name"
        return out
    major = key[0][0]
    if re.match(r"^2\.6\.\d+", v) or (len(key[0]) >= 3 and major == 2 and key[0][1] == 6):
        out["reason"] = f"{v} is a Linux kernel version, not RouterOS"
        return out
    descr = sys_descr or ""
    if major <= 2:
        if _SWOS_MODEL.search(f"{model or ''} {descr}") or (not has_api and not has_winbox):
            out.update(product="MikroTik SwOS", confidence="likely", source="snmp" if descr else "version",
                       reason=f"{v} is a SwOS version (RouterOS is 6.x / 7.x)")
        else:
            out["reason"] = f"{v} is not a RouterOS version"
        return out
    if has_api:
        out.update(product="MikroTik RouterOS", confidence="confirmed", source="routeros_api")
    elif re.search(r"routeros", descr, re.I):
        out.update(product="MikroTik RouterOS", confidence="confirmed", source="snmp")
    elif has_winbox:
        out.update(product="MikroTik RouterOS", confidence="likely", source="winbox")
    elif major >= 6:
        out.update(product="MikroTik RouterOS", confidence="likely", source="version")
    else:
        out.update(product="MikroTik RouterOS", confidence="suspected", source="version")
    return out


# ── Distributions that backport fixes ────────────────────────────────────────

_DISTRO = re.compile(r"ubuntu|debian|red ?hat|rhel|centos|rocky|alma|oracle linux|\bol\d|\bel\d|suse|amazon linux|fedora", re.I)


def distro_from(*texts: Optional[str]) -> Optional[str]:
    """The distribution named in a banner ("Apache/2.4.52 (Ubuntu)", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10") or a host's OS, else None."""
    for t in texts:
        m = _DISTRO.search(t or "")
        if m:
            return m.group(0).lower()
    return None


def finding_confidence(*, match_source: str, evaluation: str, product_confidence: Optional[str] = None,
                       distro: Optional[str] = None) -> str:
    """confirmed / likely / suspected for one finding.
      package   - the distribution's own advisory data for the installed package version: confirmed
      cpe-range - NVD's ranges say the version is affected: as strong as the product identification; a banner on a distribution that
                  backports fixes (Ubuntu / Debian / RHEL ...) proves nothing without the package version: suspected
      banner / no ranges to compare with: suspected"""
    if match_source == "package":
        return "confirmed"
    if evaluation != "affected":
        return "suspected"
    if match_source == "banner" or distro:
        return "suspected"
    if product_confidence in ("confirmed", "likely"):
        return product_confidence
    return "suspected"

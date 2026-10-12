"""
Operating-system lifecycle: is the system still supported, does support end soon, or has it ended?

A small table of end-of-support dates for the systems found on typical networks (Windows client and server,
Ubuntu, Debian, RHEL and its clones), matched from the OS name and version the agent already holds. The dates are
the vendors' published end of (standard) support, entered by hand as of 2026 and approximate where a vendor gives
different dates per edition — the earlier one (Home/Pro) is used for Windows 11. Anything not in the table
(RouterOS, firmware of printers, ...) is "unknown", never guessed. Update the tables below when a vendor moves a date.
"""
import re
from datetime import date
from typing import Optional

ENDING_SOON_DAYS = 180

# Windows 11 / 10 by build number (the third part of 10.0.<build>)
_WIN_BUILDS = {
    19041: ("Windows 10", date(2025, 10, 14)), 19042: ("Windows 10", date(2025, 10, 14)), 19043: ("Windows 10", date(2025, 10, 14)),
    19044: ("Windows 10", date(2025, 10, 14)), 19045: ("Windows 10 22H2", date(2025, 10, 14)),
    22000: ("Windows 11 21H2", date(2023, 10, 10)), 22621: ("Windows 11 22H2", date(2024, 10, 8)),
    22631: ("Windows 11 23H2", date(2025, 11, 11)), 26100: ("Windows 11 24H2", date(2026, 10, 13)),
    26200: ("Windows 11 25H2", date(2027, 10, 12)),
}

# Windows Server — most specific names first ("2008 R2" before "2008")
_WIN_SERVER = [
    ("2025", date(2034, 10, 10)), ("2022", date(2031, 10, 14)), ("2019", date(2029, 1, 9)), ("2016", date(2027, 1, 12)),
    ("2012 r2", date(2023, 10, 10)), ("2012", date(2023, 10, 10)), ("2008 r2", date(2020, 1, 14)), ("2008", date(2020, 1, 14)),
    ("2003", date(2015, 7, 14)),
]

_UBUNTU = {"16.04": date(2021, 4, 30), "18.04": date(2023, 5, 31), "20.04": date(2025, 5, 31), "22.04": date(2027, 6, 1),
           "24.04": date(2029, 5, 31), "26.04": date(2031, 5, 31)}
_DEBIAN = {"8": date(2018, 6, 17), "9": date(2022, 6, 30), "10": date(2024, 6, 30), "11": date(2026, 8, 31), "12": date(2028, 6, 30),
           "13": date(2030, 6, 30)}
_RHEL = {"6": date(2020, 11, 30), "7": date(2024, 6, 30), "8": date(2029, 5, 31), "9": date(2032, 5, 31), "10": date(2035, 5, 31)}
_CENTOS8 = date(2021, 12, 31)


def _status(eol: Optional[date], today: date) -> dict:
    if eol is None:
        return {"status": "unknown", "eol": None, "days_left": None}
    days = (eol - today).days
    return {"status": "eol" if days < 0 else "ending" if days <= ENDING_SOON_DAYS else "supported", "eol": eol.isoformat(), "days_left": days}


def lifecycle(os_name: Optional[str], os_version: Optional[str] = None, today: Optional[date] = None) -> dict:
    """{"product": str | None, "status": supported | ending | eol | unknown, "eol": iso date | None, "days_left": int | None}"""
    today = today or date.today()
    name = (os_name or "").strip()
    low = name.lower()
    ver = (os_version or "").strip()
    out = {"product": None, **_status(None, today)}
    if not low:
        return out

    if "windows" in low:
        if "server" in low:
            for tag, eol in _WIN_SERVER:
                if re.search(rf"\b{re.escape(tag)}\b", low):
                    return {"product": f"Windows Server {tag.upper()}", **_status(eol, today)}
            return {"product": "Windows Server", **_status(None, today)}
        m = re.search(r"build\s*(\d{4,5})", ver, re.I) or re.search(r"\b10\.0\.(\d{4,5})", ver) or re.search(r"\b(\d{5})\b", ver)
        if m and int(m.group(1)) in _WIN_BUILDS:
            product, eol = _WIN_BUILDS[int(m.group(1))]
            return {"product": product, **_status(eol, today)}
        if re.search(r"windows\s*7\b", low):
            return {"product": "Windows 7", **_status(date(2020, 1, 14), today)}
        if re.search(r"windows\s*8", low):
            return {"product": "Windows 8.1", **_status(date(2023, 1, 10), today)}
        if re.search(r"windows\s*10\b", low):
            return {"product": "Windows 10", **_status(date(2025, 10, 14), today)}
        return {"product": name, **_status(None, today)}

    text = f"{low} {ver.lower()}"
    if "ubuntu" in low:
        m = re.search(r"(\d{2}\.\d{2})", text)
        if m and m.group(1) in _UBUNTU:
            return {"product": f"Ubuntu {m.group(1)}", **_status(_UBUNTU[m.group(1)], today)}
        return {"product": "Ubuntu", **_status(None, today)}
    if "debian" in low:
        m = re.search(r"(?:gnu/linux|debian)\s*(\d{1,2})\b", low) or re.search(r"^\s*(\d{1,2})\b", ver)
        if m and m.group(1) in _DEBIAN:
            return {"product": f"Debian {m.group(1)}", **_status(_DEBIAN[m.group(1)], today)}
        return {"product": "Debian", **_status(None, today)}
    if re.search(r"centos|red hat|rhel|rocky|alma", low):
        m = re.search(r"\b(\d{1,2})(?:\.\d+)*\b", ver) or re.search(r"\b(\d{1,2})(?:\.\d+)+\b", low)
        label = "CentOS" if "centos" in low else "Rocky Linux" if "rocky" in low else "AlmaLinux" if "alma" in low else "RHEL"
        if m:
            major = m.group(1)
            if "centos" in low and "stream" not in low and major == "8":
                return {"product": "CentOS 8", **_status(_CENTOS8, today)}
            if major in _RHEL:
                return {"product": f"{label} {major}", **_status(_RHEL[major], today)}
        return {"product": label, **_status(None, today)}
    return {"product": name, **_status(None, today)}

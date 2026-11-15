"""
The environment a CVE needs, against what this agent knows about the host (3.66).

NVD's version ranges say which versions of a product are affected; the conditions on the platform are often only in the description:
"sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM ..." (CVE-2026-123158). Matched by version alone it sat on Ubuntu
22.04 / 24.04, Oracle Linux 9, a printer's OpenSSH 3.9 and the OpenSSH of a Windows Hyper-V host (psb HYPER-V, risk 94) - 6 critical alerts.

  conditions(summary)   -> {"os": "linux", "libc": "musl", "pam": False, "config": "..."} - only what the text states
  host_env(...)         -> {"os": "linux", "libc": "glibc", "pam": True, "known": "Ubuntu 22.04"} - only what is known
  check(conds, env)     -> ("excluded", why) the host cannot meet a condition: the finding is closed for this host
                           [auto_closed: environment_not_affected]
                           ("unconfirmed", why) a condition is there that nothing confirms: the finding is at most "suspected"
                           ("ok", None) no condition, or every one is met

Never raises; text from devices (banners, OS names) is only matched, never executed.
"""
import re
from typing import Optional, Tuple

_OS = [("linux", re.compile(r"\b(?:on|for|under) (?:GNU/)?linux\b|\blinux (?:systems?|platforms?|hosts?)\b|\bglibc-based linux\b", re.I)),
       ("windows", re.compile(r"\b(?:on|for|under) (?:microsoft )?windows\b", re.I)),
       ("macos", re.compile(r"\b(?:on|for|under) (?:macos|mac os x?|os x)\b", re.I)),
       ("bsd", re.compile(r"\b(?:on|for|under) (?:freebsd|openbsd|netbsd)\b", re.I))]
_MUSL = re.compile(r"\bmusl\b", re.I)
_GLIBC = re.compile(r"\bglibc\b|\bgnu c library\b", re.I)
_NO_PAM = re.compile(r"\bwithout (?:the use of )?PAM\b|\bPAM (?:is )?(?:disabled|not (?:used|enabled))\b|UsePAM(?:\s*=\s*|\s+)no\b", re.I)
_PAM = re.compile(r"\b(?:with|when|if) PAM (?:is )?(?:enabled|used|configured)\b|UsePAM(?:\s*=\s*|\s+)yes\b", re.I)
# a configuration nothing here can see (an option that has to be on, a non-default setting)
_CONFIG = re.compile(r"\bnon-default configuration\b|\bnot (?:the )?default configuration\b|"
                     r"\b(?:when|if) (?:the )?[\w.\-/ ]{2,40}? (?:option|directive|setting|feature|module) (?:is|are) (?:enabled|set|configured|used|on)\b|"
                     r"\b(?:when|if) (?:the )?[A-Z][A-Za-z]+ (?:is|are) (?:enabled|set to|configured)\b", re.I)

# glibc distributions whose OpenSSH is built with PAM by default (Debian / Ubuntu / RHEL family / SUSE / Fedora / Amazon)
_GLIBC_PAM = re.compile(r"ubuntu|debian|red ?hat|rhel|centos|rocky|alma|oracle|\bol\d|\bel\d|suse|sles|fedora|amazon linux|raspbian|mint", re.I)
_ALPINE = re.compile(r"alpine", re.I)
_WIN = re.compile(r"windows|for_windows|microsoft", re.I)
_EMBEDDED_TYPES = {"printer", "camera", "network", "iot", "ups", "storage"}

_cache: dict = {}


def conditions(summary: Optional[str]) -> dict:
    s = summary or ""
    if s in _cache:
        return _cache[s]
    c: dict = {}
    for name, rx in _OS:
        if rx.search(s):
            c["os"] = name
            break
    if _MUSL.search(s):
        c["libc"] = "musl"
    elif _GLIBC.search(s):
        c["libc"] = "glibc"
    if _NO_PAM.search(s):
        c["pam"] = False
    elif _PAM.search(s):
        c["pam"] = True
    m = _CONFIG.search(s)
    if m:
        c["config"] = m.group(0)[:80]
    if len(_cache) > 5000:
        _cache.clear()
    _cache[s] = c
    return c


def host_env(*, banner: Optional[str] = None, os_name: Optional[str] = None, linux_distro: Optional[str] = None,
             windows_host: bool = False, asset_type: Optional[str] = None) -> dict:
    """What is known of the host: its OS family, C library and whether its OpenSSH uses PAM - each only when a source says so."""
    env: dict = {}
    text = " ".join(t for t in (linux_distro, os_name, banner) if t)
    if windows_host or _WIN.search(text) or asset_type == "windows":
        env.update(os="windows", known=(os_name or "Windows host")[:60])
        return env
    if linux_distro or asset_type == "linux" or _GLIBC_PAM.search(text) or _ALPINE.search(text):
        env["os"] = "linux"
        if _ALPINE.search(text):
            env.update(libc="musl", pam=False, known=(linux_distro or "Alpine Linux")[:60])
        elif _GLIBC_PAM.search(text):
            m = _GLIBC_PAM.search(text)
            env.update(libc="glibc", pam=True, known=(linux_distro or os_name or m.group(0))[:60])
        else:
            env["known"] = (linux_distro or os_name or "Linux")[:60]
        return env
    if asset_type in _EMBEDDED_TYPES:
        env["embedded"] = asset_type                 # a printer's / camera's firmware: what it runs on is not known
    return env


def check(conds: dict, env: dict) -> Tuple[str, Optional[str]]:
    if not conds:
        return "ok", None
    unconfirmed = []
    for key, label in (("os", "OS"), ("libc", "C library"), ("pam", "PAM")):
        if key not in conds:
            continue
        want = conds[key]
        have = env.get(key)
        if have is None:
            unconfirmed.append(f"needs {label} {_word(key, want)}, not known on this host")
        elif have != want:
            return "excluded", f"needs {label} {_word(key, want)}; {env.get('known') or 'the host'} has {_word(key, have)}"
    if "config" in conds:
        unconfirmed.append(f"needs a configuration that is not checked ({conds['config']})")
    if unconfirmed:
        return "unconfirmed", "; ".join(unconfirmed)
    return "ok", None


def _word(key: str, v) -> str:
    if key == "pam":
        return "enabled" if v else "disabled"
    return {"linux": "Linux", "windows": "Windows", "macos": "macOS", "bsd": "BSD", "musl": "musl", "glibc": "glibc"}.get(v, str(v))


# products that a distribution packages and patches by backporting: their banner version is only a hint (3.66)
DISTRO_PACKAGED = re.compile(r"^(openssh|apache|apache httpd|apache http server|httpd|openssl|nginx|php|postfix|dovecot|exim|bind|samba|"
                             r"proftpd|vsftpd|mysql|mariadb|postgresql|squid|lighttpd|isc dhcp|ntp|openldap)\b", re.I)


def distro_packaged(product: Optional[str]) -> bool:
    return bool(product and DISTRO_PACKAGED.search(product.strip()))

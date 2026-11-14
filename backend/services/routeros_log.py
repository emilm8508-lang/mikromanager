"""
One RouterOS log line -> structured fields: what happened, who, from where, on which service / interface.

Seen in production (3.59): alerts like "ssl: no common ciphers" (mcprojekt AP1-AP3, R2-S1..S3, ~500 lines each) carried nothing but the
text, so nobody could tell who was connecting; IPsec failures carried the address only inside the text. Here every line is read into

  kind       login_failed | login_ok | logout | config_change | reboot | power_fail | psu_fail | link_down | link_up | ipsec_fail |
             ipsec_respond | ssl_no_cipher | winbox_denied | loop | dhcp | other
  topics     ["system", "info", "account"] (from syslog's tag or the API's "topics")
  src_ip / src_port / dst_ip / dst_port, user, service (winbox, ssh, api, api-ssl, www, www-ssl, telnet, ftp, dude, local), interface
  signature  the text with addresses, numbers and ids taken out - the same kind of line from different moments groups into one alert

Pure (no I/O): backend/tests/test_router_logs.py. RouterOS formats seen live and in MikroTik's documentation; anything else is "other"
with whatever addresses the text holds.
"""
import ipaddress
import re
from typing import List, Optional

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_RE = [
    ("login_failed", re.compile(r"login failure for user (?P<user>\S+) from " + _IP.replace("(", "(?P<src>", 1) + r"(?: via (?P<service>\S+))?", re.I)),
    ("login_ok", re.compile(r"user (?P<user>\S+) logged in from " + _IP.replace("(", "(?P<src>", 1) + r"(?: via (?P<service>\S+))?", re.I)),
    ("login_ok", re.compile(r"user (?P<user>\S+) logged in via (?P<service>local|console|serial)", re.I)),
    ("logout", re.compile(r"user (?P<user>\S+) logged out from " + _IP.replace("(", "(?P<src>", 1) + r"(?: via (?P<service>\S+))?", re.I)),
    ("winbox_denied", re.compile(r"denied (?P<service>winbox(?:/dude)?|ssh|telnet|api|www|ftp) connect from " + _IP.replace("(", "(?P<src>", 1), re.I)),
    # 7.x: "address changed by winbox-3.41/tcp-msg(winbox):admin@192.168.1.10 (/ip address set ...)"; 6.x: "filter rule changed by admin"
    ("config_change", re.compile(r"\b(?P<action>added|changed|removed|moved|enabled|disabled) by (?:(?P<client>[\w.\-/]+(?:\([\w-]+\))?):)?"
                                 r"(?P<user>[\w.\-]+)(?:@" + _IP.replace("(", "(?P<src>", 1) + r")?", re.I)),
    ("power_fail", re.compile(r"router was rebooted without proper shutdown|power (?:failure|outage|lost)|voltage (?:too low|dropped)", re.I)),
    ("psu_fail", re.compile(r"\b(?P<iface>psu\d?|power[- ]?supply ?\d?)\b.{0,30}\b(?:fail|failed|state changed to fail|bad)", re.I)),
    ("reboot", re.compile(r"router rebooted|system rebooted|rebooted by (?P<user>\S+)|reboot(?:ing)? (?:the )?router|system started", re.I)),
    ("link_down", re.compile(r"^(?P<iface>[\w\-./<>@]+) link down", re.I)),
    ("link_up", re.compile(r"^(?P<iface>[\w\-./<>@]+) link up(?: \(speed (?P<speed>[\d.]+[KMG])?)?", re.I)),
    ("ipsec_fail", re.compile(r"(?:phase ?1|phase ?2|IKEv?2?).{0,40}negotiation failed.{0,40}?" + _IP.replace("(", "(?P<local>", 1) +
                              r"\[(?P<lport>\d+)\]<=>" + _IP.replace("(", "(?P<src>", 1) + r"\[(?P<sport>\d+)\]", re.I)),
    ("ipsec_fail", re.compile(r"(?:phase ?1|IKEv?2?).{0,40}negotiation failed", re.I)),
    ("ipsec_respond", re.compile(r"respond new phase 1.{0,40}?" + _IP.replace("(", "(?P<local>", 1) + r"\[(?P<lport>\d+)\]<=>" +
                                 _IP.replace("(", "(?P<src>", 1) + r"\[(?P<sport>\d+)\]", re.I)),
    ("ssl_no_cipher", re.compile(r"ssl: no common ciphers?|no shared cipher|ssl handshake fail", re.I)),
    ("loop", re.compile(r"(?P<iface>[\w\-./]+)? ?(?:transmit )?loop detected", re.I)),
    ("dhcp", re.compile(r"(?:assigned|deassigned) " + _IP.replace("(", "(?P<dst>", 1) + r" (?:to|from) (?P<mac>[0-9A-F:]{17})", re.I)),
]
_ANY_IP = re.compile(r"(?<![\d.])" + _IP + r"(?![\d.])")
_SERVICE = {"winbox": "winbox", "winbox/dude": "winbox", "ssh": "ssh", "api": "api", "api-ssl": "api-ssl", "web": "www", "www": "www",
            "www-ssl": "www-ssl", "telnet": "telnet", "ftp": "ftp", "dude": "dude", "local": "local", "console": "local", "serial": "local",
            "tcp-msg(winbox)": "winbox", "rest-api": "www"}


def topics_of(app: Optional[str]) -> List[str]:
    return [t for t in re.split(r"[,\s]+", (app or "").strip().lower()) if t]


def signature(message: str) -> str:
    """The line without what changes from one occurrence to the next (addresses, ports, numbers, hex ids, quoted values)."""
    s = re.sub(r"\[\d+\]", "[n]", message or "")
    s = _ANY_IP.sub("<ip>", s)
    s = re.sub(r"\b[0-9a-f]{12,}(:[0-9a-f]{12,})?\b", "<id>", s, flags=re.I)
    s = re.sub(r"\b[0-9A-F]{2}(:[0-9A-F]{2}){5}\b", "<mac>", s, flags=re.I)
    s = re.sub(r"\b\d+(\.\d+)?\b", "<n>", s)
    s = re.sub(r'"[^"]*"', '"…"', s)
    return re.sub(r"\s+", " ", s).strip()[:160]


def is_private(ip: Optional[str]) -> bool:
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a in ipaddress.ip_network("100.64.0.0/10")


def parse(message: str, app: Optional[str] = None) -> dict:
    """The structured view of one RouterOS log line (see the module text). Never raises."""
    msg = (message or "").strip()
    out = {"kind": "other", "topics": topics_of(app), "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None,
           "user": None, "service": None, "interface": None, "signature": signature(msg)}
    for kind, rx in _RE:
        m = rx.search(msg)
        if not m:
            continue
        g = {k: v for k, v in m.groupdict().items() if v}
        out["kind"] = kind
        out["user"] = g.get("user")
        out["src_ip"] = g.get("src")
        out["src_port"] = int(g["sport"]) if g.get("sport") else None
        out["dst_ip"] = g.get("local") or g.get("dst")
        out["dst_port"] = int(g["lport"]) if g.get("lport") else None
        out["interface"] = g.get("iface")
        svc = (g.get("service") or "").lower()
        if not svc and g.get("client"):
            c = g["client"].lower()
            svc = "winbox" if "winbox" in c else "ssh" if "ssh" in c else "www" if ("web" in c or "rest" in c) else "api" if "api" in c else c.split("-")[0]
        out["service"] = _SERVICE.get(svc, svc or None)
        if kind == "link_up" and g.get("speed"):
            out["speed"] = g["speed"]
        if kind == "config_change":
            out["action"] = (g.get("action") or "").lower()
        break
    if out["src_ip"] is None and out["kind"] in ("other", "ipsec_fail"):
        ips = _ANY_IP.findall(msg)
        public = [x for x in ips if not is_private(x)]
        if public:
            out["src_ip"] = public[0]
    return out

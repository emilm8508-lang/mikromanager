"""
NetFlow / IPFIX collector and network detections (stage 2 of the ML work).

The routers send their flow records (RouterOS "Traffic Flow": NetFlow v5, v9 or IPFIX) to the agent over UDP. Nothing else is needed on
the hosts. The collector:

  * parses v5 (fixed records), v9 and IPFIX (templates learned per exporter and observation domain); only from devices the agent knows
    (the inventory and the managed devices, like the syslog receiver), unless `accept_unknown`;
  * aggregates every flow into 10-minute windows per internal host (an address in `local_nets`): bytes out and in, the distinct remote
    peers it opened connections to, the distinct destination ports it tried and its connection attempts that got no answer (TCP SYN
    without ACK). At the end of each window those become metric series ("net:<ip>:out_mb" ...), so the anomaly engine of stage 1
    (services/anomaly.py) learns each host's normal traffic per hour of the week like any other series;
  * runs detectors on the window that do not need a learned normal (rules with thresholds, each one a SOC alert with its ATT&CK id):
      - port scan from an internal host: >= scan_ports destination ports on one target, or >= scan_hosts targets with mostly
        unanswered attempts (T1046);
      - lateral movement: an internal host opening admin ports (SMB, RDP, SSH, WinRM, RPC, telnet) on >= lateral_hosts internal hosts (T1021);
      - beaconing: an internal host opening new connections to the same outside address and port at a regular interval (>= 10 in two
        hours, coefficient of variation of the intervals < 0.15, interval 20 s - 30 min, small flows) - the call home of malware (T1071).
        DNS / NTP and destinations most hosts talk to are left out;
      - inbound scan from outside (off by default: an internet-facing router sees it all day).

Which side opened a connection is inferred from the ports (the side with the lower, service port answered), since a flow record does
not say it. Memory is bounded: at most MAX_TRACK_HOSTS series hosts, MAX_PAIRS beacon pairs and capped distinct sets per host.
"""
import asyncio
import ipaddress
import json
import os
import socket
import statistics
import struct
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "netflow.json")
_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "netflow_state.json")
DEFAULTS = {
    "enabled": False, "port": 2055, "accept_unknown": False,
    "local_nets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"],
    "scan_ports": 100, "scan_hosts": 50, "lateral_hosts": 15, "beacon": True, "external_scans": False, "max_hosts": 300,
    # mail (SMTP, POP3, IMAP and their TLS ports) and push / messaging keep-alives (XMPP, Apple, Google): periodic by design - seen
    # live: a mail client polling POP3S every 60 s and a phone's push channel every 211 s were 172 "beaconing" alerts a day
    "beacon_ignore_ports": [25, 110, 143, 465, 587, 993, 995, 5222, 5223, 5228],
}
REPEAT_SEC = {"net.beacon": 86400}  # the same detection (rule, host, target) is reported again only after this; others after an hour
WINDOW_SEC = 600
SET_CAP = 2000                   # distinct peers / ports kept per host per window (counted beyond that, not stored)
MAX_PAIRS = 20000
BEACON_MIN = 10
BEACON_SPAN = 7200
BEACON_CV = 0.15
BEACON_BYTES = 50_000
ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}
QUIET_PORTS = {53, 123, 67, 68, 5353, 137, 138, 1900}      # DNS, NTP, DHCP, mDNS, NetBIOS, SSDP: periodic by nature
TRACK_DAYS = 7

_settings: dict = {}
_loaded = [False]
_nets: List[ipaddress.IPv4Network] = []
_transport = None
_task: Optional[asyncio.Task] = None
_error: Dict[str, Optional[str]] = {"listen": None}
_templates: Dict[tuple, list] = {}            # (exporter, domain, template id) -> [(field type, length)]
_stats = {"since": None, "packets": 0, "flows": 0, "dropped_unknown": 0, "bad": 0, "no_template": 0}
_exporters: Dict[str, dict] = {}              # ip -> {name, version, packets, flows, last}
_unknown: Dict[str, int] = defaultdict(int)
_win: dict = {}                               # the window being filled
_history: deque = deque(maxlen=6)             # the last six closed windows (one hour), for the page
_detections: deque = deque(maxlen=300)        # what the detectors raised, newest last
_pairs: Dict[tuple, deque] = {}               # (src, dst, dport) -> first-seen times of its connections (beaconing)
_pair_seen: Dict[tuple, float] = {}           # (src, sport, dst, dport) -> when that connection was first seen
_tracked: Dict[str, float] = {}               # internal ip -> last time it had traffic
_beacon_ignore: set = set()                   # destination ports the beacon detector leaves out (settings)
_last_raised: Dict[tuple, float] = {}         # (rule, ip, detail) -> when it was last reported
_fp_cache: Dict[str, tuple] = {}              # SOC fingerprint -> (checked at, is a false positive)


# ── Settings ────────────────────────────────────────────────────────────────

def load_settings() -> dict:
    s = dict(DEFAULTS)
    try:
        with open(_PATH, encoding="utf-8") as f:
            s.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except Exception:
        pass
    _settings.clear()
    _settings.update(s)
    _set_nets(s["local_nets"])
    _beacon_ignore.clear()
    _beacon_ignore.update(int(p) for p in s.get("beacon_ignore_ports") or [])
    _loaded[0] = True
    try:
        with open(_STATE_PATH, encoding="utf-8") as f:
            _tracked.update({k: float(v) for k, v in (json.load(f).get("tracked") or {}).items()})
    except Exception:
        pass
    return _settings


def _set_nets(nets: List[str]) -> None:
    _nets.clear()
    for n in nets:
        _nets.append(ipaddress.ip_network(n, strict=False))


def settings() -> dict:
    if not _loaded[0]:
        load_settings()
    return dict(_settings)


def _save() -> None:
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_settings, f, ensure_ascii=False)
    os.replace(tmp, _PATH)


def _int(v, lo: int, hi: int, name: str) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number")
    if not lo <= n <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return n


async def update_settings(body: dict) -> dict:
    """Changes the settings (raises ValueError for a bad value) and re-opens the port."""
    settings()
    new = dict(_settings)
    for k in ("enabled", "accept_unknown", "beacon", "external_scans"):
        if body.get(k) is not None:
            new[k] = bool(body[k])
    if body.get("port") is not None:
        new["port"] = _int(body["port"], 1, 65535, "port")
    for k, lo, hi in (("scan_ports", 10, 10000), ("scan_hosts", 5, 10000), ("lateral_hosts", 3, 1000), ("max_hosts", 10, 2000)):
        if body.get(k) is not None:
            new[k] = _int(body[k], lo, hi, k)
    if body.get("local_nets") is not None:
        nets = [str(n).strip() for n in body["local_nets"] if str(n).strip()]
        if not nets or len(nets) > 50:
            raise ValueError("between 1 and 50 local networks")
        for n in nets:
            try:
                ipaddress.ip_network(n, strict=False)
            except ValueError:
                raise ValueError(f"not a network: {n}")
        new["local_nets"] = nets
    if body.get("beacon_ignore_ports") is not None:
        ports = sorted({_int(p, 1, 65535, "port") for p in body["beacon_ignore_ports"]})
        if len(ports) > 100:
            raise ValueError("at most 100 ports")
        new["beacon_ignore_ports"] = ports
    _settings.clear()
    _settings.update(new)
    _set_nets(new["local_nets"])
    _beacon_ignore.clear()
    _beacon_ignore.update(new.get("beacon_ignore_ports") or [])
    _save()
    await restart()
    return settings()


def is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _nets if n.version == a.version)


# ── Parsing ─────────────────────────────────────────────────────────────────

_V5_HEAD = struct.Struct("!HHIIIIBBH")
_V5_REC = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
# field types (shared by v9 and IPFIX): what a flow needs
F_BYTES, F_PKTS, F_PROTO, F_FLAGS, F_SPORT, F_SRC4, F_DPORT, F_DST4, F_SRC6, F_DST6 = 1, 2, 4, 6, 7, 8, 11, 12, 27, 28
F_BYTES_TOTAL, F_PKTS_TOTAL = 85, 86


def _flow(src: str, dst: str, sport: int, dport: int, proto: int, nbytes: int, pkts: int, flags: int) -> dict:
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto, "bytes": nbytes, "pkts": pkts, "flags": flags}


def parse_v5(data: bytes) -> List[dict]:
    _, count, *_rest = _V5_HEAD.unpack_from(data, 0)
    out = []
    for i in range(min(count, (len(data) - 24) // 48)):
        r = _V5_REC.unpack_from(data, 24 + 48 * i)
        out.append(_flow(socket.inet_ntoa(r[0]), socket.inet_ntoa(r[1]), r[9], r[10], r[13], r[6], r[5], r[12]))
    return out


def _uint(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


def _decode(fields: list, data: bytes, i: int) -> Tuple[Optional[dict], int]:
    """One data record of a template at offset i -> (flow or None, the offset after it). IPFIX variable-length fields are supported."""
    v: dict = {}
    for ftype, flen in fields:
        if flen == 65535:                                      # IPFIX variable length
            flen = data[i]
            i += 1
            if flen == 255:
                flen = struct.unpack_from("!H", data, i)[0]
                i += 2
        raw = data[i:i + flen]
        i += flen
        if ftype in (F_SRC4, F_DST4) and flen == 4:
            v[ftype] = socket.inet_ntoa(raw)
        elif ftype in (F_SRC6, F_DST6) and flen == 16:
            v[ftype] = socket.inet_ntop(socket.AF_INET6, raw)
        elif ftype in (F_BYTES, F_PKTS, F_PROTO, F_FLAGS, F_SPORT, F_DPORT, F_BYTES_TOTAL, F_PKTS_TOTAL):
            v[ftype] = _uint(raw)
    src, dst = v.get(F_SRC4) or v.get(F_SRC6), v.get(F_DST4) or v.get(F_DST6)
    if not src or not dst:
        return None, i
    return _flow(src, dst, v.get(F_SPORT, 0), v.get(F_DPORT, 0), v.get(F_PROTO, 0), v.get(F_BYTES, v.get(F_BYTES_TOTAL, 0)),
                 v.get(F_PKTS, v.get(F_PKTS_TOTAL, 0)), v.get(F_FLAGS, 0)), i


def parse_templated(data: bytes, exporter: str) -> List[dict]:
    """NetFlow v9 or IPFIX: template sets are remembered, data sets decoded with the template they name."""
    version = struct.unpack_from("!H", data, 0)[0]
    if version == 9:
        domain, off, end = struct.unpack_from("!I", data, 16)[0], 20, len(data)
        tmpl_set, opt_set = (0,), (1,)
    else:
        length = struct.unpack_from("!H", data, 2)[0]
        domain, off, end = struct.unpack_from("!I", data, 12)[0], 16, min(len(data), length)
        tmpl_set, opt_set = (2,), (3,)
    out: List[dict] = []
    while off + 4 <= end:
        set_id, set_len = struct.unpack_from("!HH", data, off)
        if set_len < 4:
            break
        body, set_end = off + 4, min(off + set_len, end)
        if set_id in tmpl_set:
            i = body
            while i + 4 <= set_end:
                tid, n = struct.unpack_from("!HH", data, i)
                i += 4
                fields = []
                for _ in range(n):
                    ftype, flen = struct.unpack_from("!HH", data, i)
                    i += 4
                    if version == 10 and ftype & 0x8000:          # an enterprise field: 4 more bytes, not one we read
                        ftype &= 0x7FFF
                        ftype |= 0x10000
                        i += 4
                    fields.append((ftype, flen))
                if tid >= 256:
                    _templates[(exporter, domain, tid)] = fields
        elif set_id in opt_set:
            pass                                                    # options templates (sampling and such) are not needed
        elif set_id >= 256:
            fields = _templates.get((exporter, domain, set_id))
            if fields is None:
                _stats["no_template"] += 1                          # data before its template: the router resends templates periodically
            else:
                fixed = sum(f for _, f in fields if f != 65535)
                i = body
                while i + max(fixed, 1) <= set_end:
                    flow, i = _decode(fields, data, i)
                    if flow:
                        out.append(flow)
        off += set_len
    return out


def parse(data: bytes, exporter: str) -> Tuple[int, List[dict]]:
    if len(data) < 4:
        raise ValueError("too short")
    version = struct.unpack_from("!H", data, 0)[0]
    if version == 5:
        return 5, parse_v5(data)
    if version in (9, 10):
        return version, parse_templated(data, exporter)
    raise ValueError(f"unsupported version {version}")


# ── Aggregation ──────────────────────────────────────────────────────────────

def _new_window(start: float) -> dict:
    return {"start": start, "hosts": {}, "conv": defaultdict(int), "scan_in": {}}


def _host(w: dict, ip: str) -> dict:
    h = w["hosts"].get(ip)
    if h is None:
        h = w["hosts"][ip] = {"out": 0, "in": 0, "flows": 0, "peers": set(), "peers_n": 0, "ports": set(), "ports_n": 0, "unanswered": 0,
                              "attempts": 0, "per_dst_ports": defaultdict(set), "admin_dsts": set(), "syn_dsts": set()}
    return h


def _add(s: set, v, h: dict, counter: str) -> None:
    if v in s:
        return
    if len(s) < SET_CAP:
        s.add(v)
    h[counter] += 1


MGMT_PORTS = {21, 22, 23, 80, 443, 993, 995, 8080, 8291, 8443, 8728, 8729}
_mgmt: deque = deque(maxlen=20000)                 # (time, src, dst, dport) of the flows to management ports, newest last


def mgmt_sources(dst_ips: List[str], at: float, window_sec: float, ports: Tuple[int, ...]) -> List[str]:
    """The addresses that opened a connection to one of these addresses on one of these ports within window_sec of `at`, most frequent first."""
    dsts, cnt = set(dst_ips), defaultdict(int)
    for t, src, dst, dport in reversed(_mgmt):
        if t < at - window_sec:
            break
        if t <= at + window_sec and dst in dsts and dport in ports and src not in dsts:
            cnt[src] += 1
    return sorted(cnt, key=lambda k: -cnt[k])[:10]


def ingest(flows: List[dict], now: Optional[float] = None) -> None:
    """Adds flows to the current window (closing it first when its 10 minutes are over)."""
    now = now or time.time()
    if not _win:
        _win.update(_new_window(now - now % WINDOW_SEC))
    if now - _win["start"] >= WINDOW_SEC:
        close_window(now)
    w = _win
    for f in flows:
        src, dst, sport, dport, proto = f["src"], f["dst"], f["sport"], f["dport"], f["proto"]
        if dport in MGMT_PORTS:
            _mgmt.append((now, src, dst, dport))           # who connects to management ports (services/router_logs.py: a log line without its source)
        src_l, dst_l = is_local(src), is_local(dst)
        if src_l:
            h = _host(w, src)
            h["out"] += f["bytes"]
            h["flows"] += 1
        if dst_l:
            _host(w, dst)["in"] += f["bytes"]
        w["conv"][(src, dst, dport if dport else 0, proto)] += f["bytes"]
        ports = proto in (6, 17) and sport and dport
        initiator = (not ports) or sport >= dport                   # the side with the higher port opened the connection
        syn_only = proto == 6 and f["flags"] & 0x02 and not f["flags"] & 0x10
        if src_l and initiator and ports:
            h = w["hosts"][src]
            _add(h["peers"], dst, h, "peers_n")
            _add(h["ports"], dport, h, "ports_n")
            h["attempts"] += 1
            if len(h["per_dst_ports"]) < SET_CAP:
                h["per_dst_ports"][dst].add(dport)
            if syn_only:
                h["unanswered"] += 1
                if len(h["syn_dsts"]) < SET_CAP:
                    h["syn_dsts"].add(dst)
            if dst_l and dport in ADMIN_PORTS and len(h["admin_dsts"]) < SET_CAP:
                h["admin_dsts"].add(dst)
            if not dst_l and _settings.get("beacon", True) and dport not in QUIET_PORTS and dport not in _beacon_ignore and f["bytes"] <= BEACON_BYTES:
                _beacon_seen(src, sport, dst, dport, now)
        elif not src_l and dst_l and syn_only and ports and initiator:
            s = w["scan_in"].setdefault(src, set())
            if len(s) < SET_CAP:
                s.add((dst, dport))
    for ip, h in w["hosts"].items():
        if h["flows"]:                  # it sent something itself: an address that only received probes (a sweep) gets no series
            _tracked[ip] = now


def _beacon_seen(src: str, sport: int, dst: str, dport: int, now: float) -> None:
    conn = (src, sport, dst, dport)
    if conn in _pair_seen:
        return                                                      # the same connection reported again (active timeout): not a new beat
    if len(_pair_seen) > MAX_PAIRS * 5:
        cutoff = now - BEACON_SPAN
        for k in [k for k, t in _pair_seen.items() if t < cutoff]:
            del _pair_seen[k]
    _pair_seen[conn] = now
    key = (src, dst, dport)
    q = _pairs.get(key)
    if q is None:
        if len(_pairs) >= MAX_PAIRS:
            return
        q = _pairs[key] = deque(maxlen=40)
    q.append(now)


# ── Detections ──────────────────────────────────────────────────────────────

def _names() -> Dict[str, dict]:
    try:
        from services import syslog_receiver
        return syslog_receiver.known_sources()
    except Exception:
        return {}


def _label(ip: str, names: Dict[str, dict]) -> str:
    n = (names.get(ip) or {}).get("name")
    return f"{n} ({ip})" if n and n != ip else ip


def _false_positive(fp: str, now: float) -> bool:
    """Whether the SOC alert with this fingerprint was marked a false positive (checked at most every 10 minutes per fingerprint)."""
    hit = _fp_cache.get(fp)
    if hit and now - hit[0] < 600:
        return hit[1]
    try:
        from models.database import SessionLocal, SocAlert
        from sqlalchemy import select
        with SessionLocal() as db:
            row = db.execute(select(SocAlert.status).where(SocAlert.fingerprint == fp).order_by(SocAlert.id.desc()).limit(1)).first()
        val = bool(row and row[0] == "false_positive")
    except Exception:
        val = False
    _fp_cache[fp] = (now, val)
    return val


def _raise(rule: str, ip: str, title: str, severity: str, mitre: str, message: str, detail: str, names: Dict[str, dict], now: float) -> None:
    from services import soc
    name = (names.get(ip) or {}).get("name") or ip
    key = (rule, ip, detail)
    if now - _last_raised.get(key, 0) < REPEAT_SEC.get(rule, 3600):
        return                                                      # reported already: once a day for a beacon, once an hour otherwise
    if _false_positive(f"{rule}|{name.strip().lower()}|{detail}"[:240], now):
        return                                                      # someone marked this one a false positive in the SOC: never again
    _last_raised[key] = now
    if len(_last_raised) > 20000:
        for k in [k for k, t in _last_raised.items() if now - t > 86400]:
            del _last_raised[k]
    try:
        soc.raise_alert(rule=rule, device=name, ip=ip, title=title, severity=severity, category="network", fp_detail=detail, mitre=mitre,
                        detail={"message": message, "description": title}, source="rules", now=datetime.utcfromtimestamp(now))
    except Exception as e:
        print(f"[netflow] alert error: {e}")
    _detections.append({"at": datetime.utcfromtimestamp(now).isoformat() + "Z", "rule": rule, "ip": ip, "name": name, "severity": severity, "mitre": mitre, "message": message})


def detect(w: dict, now: float) -> List[dict]:
    """The rule detectors over a closed window. Returns what was raised."""
    names = _names()
    before = len(_detections)
    sp, sh, lh = int(_settings.get("scan_ports", 100)), int(_settings.get("scan_hosts", 50)), int(_settings.get("lateral_hosts", 15))
    for ip, h in w["hosts"].items():
        wide = max(((d, len(p)) for d, p in h["per_dst_ports"].items()), key=lambda x: x[1], default=(None, 0))
        if wide[1] >= sp:
            _raise("net.portscan", ip, "Port scan from an internal host", "high", "T1046",
                   f"{_label(ip, names)} tried {wide[1]} ports on {_label(wide[0], names)} in 10 minutes", f"ports|{wide[0]}", names, now)
        elif len(h["syn_dsts"]) >= sh and h["attempts"] and h["unanswered"] / h["attempts"] >= 0.5:
            _raise("net.portscan", ip, "Network sweep from an internal host", "high", "T1046",
                   f"{_label(ip, names)} tried {len(h['syn_dsts'])} hosts, {h['unanswered']} of {h['attempts']} attempts unanswered, in 10 minutes", "sweep", names, now)
        if len(h["admin_dsts"]) >= lh:
            _raise("net.lateral", ip, "Possible lateral movement", "high", "T1021",
                   f"{_label(ip, names)} opened admin ports (SMB / RDP / SSH / WinRM) on {len(h['admin_dsts'])} internal hosts in 10 minutes", "admin", names, now)
    if _settings.get("external_scans"):
        for src, targets in w["scan_in"].items():
            if len(targets) >= sp:
                _raise("net.scan_in", src, "Inbound scan from outside", "low", "T1595",
                       f"{src} probed {len(targets)} address / port pairs of the local networks in 10 minutes", "in", names, now)
    if _settings.get("beacon", True):
        _detect_beacons(names, now)
    return list(_detections)[before:]


def _detect_beacons(names: Dict[str, dict], now: float) -> None:
    active = {ip for ip, t in _tracked.items() if now - t < 3600}
    popular: Dict[tuple, set] = defaultdict(set)                  # (dst, dport) -> internal hosts talking to it
    for (src, dst, dport), q in _pairs.items():
        if q and now - q[-1] < BEACON_SPAN:
            popular[(dst, dport)].add(src)
    for key in list(_pairs):
        q = _pairs[key]
        while q and now - q[0] > BEACON_SPAN:
            q.popleft()
        if not q:
            del _pairs[key]
            continue
        src, dst, dport = key
        if len(q) < BEACON_MIN or len(popular[(dst, dport)]) > max(3, 0.3 * len(active)):
            continue
        gaps = [b - a for a, b in zip(q, list(q)[1:])]
        mean = statistics.mean(gaps)
        if not 20 <= mean <= 1800:
            continue
        cv = statistics.pstdev(gaps) / mean if mean else 1.0
        if cv < BEACON_CV:
            _raise("net.beacon", src, "Regular connections to an outside address (beaconing)", "medium", "T1071",
                   f"{_label(src, names)} opened {len(q)} new connections to {dst}:{dport}, every {mean:.0f} s (spread {cv * 100:.0f} %), in the last two hours",
                   f"{dst}:{dport}", names, now)
            q.clear()                                               # one alert per run of beats; it re-raises if they go on


def close_window(now: Optional[float] = None) -> dict:
    """Ends the current window: records the per-host series, runs the detectors, keeps a summary for the page."""
    now = now or time.time()
    w = dict(_win)
    _win.clear()
    _win.update(_new_window(now - now % WINDOW_SEC))
    if not w.get("hosts") and not w.get("scan_in"):
        _record_idle(now)
        return {}
    detect(w, now)
    names = _names()
    _record(w, names, now)
    top = sorted(w["hosts"].items(), key=lambda kv: -(kv[1]["out"] + kv[1]["in"]))[:30]
    conv = sorted(w["conv"].items(), key=lambda kv: -kv[1])[:20]
    summary = {
        "start": datetime.utcfromtimestamp(w["start"]).isoformat() + "Z", "hosts": len(w["hosts"]),
        "bytes": sum(h["out"] + h["in"] for h in w["hosts"].values()),
        "top": [{"ip": ip, "name": (names.get(ip) or {}).get("name"), "out": h["out"], "in": h["in"], "peers": h["peers_n"], "ports": h["ports_n"],
                 "unanswered": h["unanswered"]} for ip, h in top],
        "conv": [{"src": s, "dst": d, "dport": p, "proto": pr, "bytes": b, "src_name": (names.get(s) or {}).get("name"), "dst_name": (names.get(d) or {}).get("name")}
                 for (s, d, p, pr), b in conv],
    }
    _history.append(summary)
    _save_state()
    return summary


def _series_hosts(now: float) -> List[str]:
    cutoff = now - TRACK_DAYS * 86400
    for ip in [ip for ip, t in _tracked.items() if t < cutoff]:
        del _tracked[ip]
    return sorted(_tracked, key=lambda ip: -_tracked[ip])[: int(_settings.get("max_hosts", 300))]


def _record(w: dict, names: Dict[str, dict], now: float) -> None:
    """One reading per tracked host and feature; a tracked host with no traffic in the window reads 0, so its quiet hours are learned too."""
    from services import metrics
    from models.database import SessionLocal
    at = datetime.utcfromtimestamp(now)
    with SessionLocal() as db:                                      # one transaction for every host of the window
        for ip in _series_hosts(now):
            h = w["hosts"].get(ip)
            nm = (names.get(ip) or {}).get("name") or ip
            vals = (("out_mb", "traffic out", "MB", (h["out"] if h else 0) / 1e6), ("in_mb", "traffic in", "MB", (h["in"] if h else 0) / 1e6),
                    ("peers", "peers", "hosts", h["peers_n"] if h else 0), ("ports", "ports tried", "ports", h["ports_n"] if h else 0),
                    ("unanswered", "unanswered attempts", "conn", h["unanswered"] if h else 0))
            for suffix, label, unit, v in vals:
                metrics.record(f"net:{ip}:{suffix}", round(v, 3), name=f"{nm} · {label}", kind="net", unit=unit, now=at, db=db)
        db.commit()


def _record_idle(now: float) -> None:
    if _transport is not None and _tracked:
        _record(_new_window(now), _names(), now)


def _save_state() -> None:
    try:
        os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
        tmp = _STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"tracked": _tracked}, f)
        os.replace(tmp, _STATE_PATH)
    except Exception as e:
        print(f"[netflow] state save error: {e}")


# ── The socket ───────────────────────────────────────────────────────────────

def handle(data: bytes, ip: str, now: Optional[float] = None) -> int:
    """One datagram from an exporter. Returns how many flows it carried."""
    _stats["packets"] += 1
    known = _names()
    if ip not in known and not _settings.get("accept_unknown"):
        _stats["dropped_unknown"] += 1
        _unknown[ip] += 1
        return 0
    try:
        version, flows = parse(data, ip)
    except Exception:
        _stats["bad"] += 1
        return 0
    e = _exporters.setdefault(ip, {"name": (known.get(ip) or {}).get("name") or ip, "version": version, "packets": 0, "flows": 0, "last": None})
    e["version"], e["packets"], e["flows"], e["last"] = version, e["packets"] + 1, e["flows"] + len(flows), datetime.utcnow().isoformat() + "Z"
    _stats["flows"] += len(flows)
    if flows:
        ingest(flows, now)
    return len(flows)


class _Proto(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr) -> None:
        try:
            handle(data[:65535], addr[0])
        except Exception as e:
            print(f"[netflow] datagram error: {type(e).__name__}: {e}")


async def _ticker() -> None:
    """Closes the window on time even when no flow arrives."""
    while True:
        await asyncio.sleep(30)
        try:
            if _win and time.time() - _win["start"] >= WINDOW_SEC:
                close_window()
        except Exception as e:
            print(f"[netflow] window error: {type(e).__name__}: {e}")


async def start() -> None:
    global _transport, _task
    settings()
    if not _settings.get("enabled") or _transport is not None:
        return
    try:
        _transport, _ = await asyncio.get_event_loop().create_datagram_endpoint(_Proto, local_addr=("0.0.0.0", int(_settings["port"])))
        _error["listen"] = None
        _stats["since"] = datetime.utcnow().isoformat() + "Z"
    except OSError as e:
        _error["listen"] = f"cannot listen on UDP {_settings['port']}: {e.strerror or e}"
        print(f"[netflow] {_error['listen']}")
        return
    _task = asyncio.get_event_loop().create_task(_ticker())


async def stop() -> None:
    global _transport, _task
    if _transport is not None:
        _transport.close()
        _transport = None
        await asyncio.sleep(0.1)
    if _task:
        _task.cancel()
        _task = None


async def restart() -> None:
    await stop()
    await start()


# ── Reading ──────────────────────────────────────────────────────────────────

def status() -> dict:
    s = settings()
    last = _history[-1] if _history else None
    day = time.time() - 86400
    recent = [d for d in _detections if datetime.fromisoformat(d["at"].rstrip("Z")).timestamp() >= day]
    return {
        "settings": s, "listening": _transport is not None, "error": _error["listen"], "stats": dict(_stats),
        "exporters": sorted(({"ip": k, **v} for k, v in _exporters.items()), key=lambda x: -x["flows"]),
        "unknown": sorted(({"ip": k, "n": v} for k, v in _unknown.items()), key=lambda x: -x["n"])[:15],
        "tracked": len(_tracked), "window": last, "windows": list(_history),
        "detections": list(reversed(_detections))[:100], "detections_24h": len(recent),
    }


def public_summary() -> dict:
    """For Central (inside the SOC status): whether flows come in, the busiest hosts of the last window and the detections of the day."""
    st = status()
    w = st["window"] or {}
    by_rule: Dict[str, int] = defaultdict(int)
    for d in st["detections"]:
        if datetime.fromisoformat(d["at"].rstrip("Z")).timestamp() >= time.time() - 86400:
            by_rule[d["rule"]] += 1
    return {
        "on": bool(st["settings"]["enabled"]), "listening": st["listening"], "error": st["error"], "exporters": len(st["exporters"]),
        "unknown": len(st["unknown"]), "hosts": st["tracked"], "window_bytes": w.get("bytes"), "window_at": w.get("start"),
        "top": [{"n": t["name"] or t["ip"], "out": t["out"], "in": t["in"], "peers": t["peers"]} for t in (w.get("top") or [])[:5]],
        "detections_24h": dict(by_rule),
        "recent": [{"at": d["at"], "rule": d["rule"], "n": d["name"], "sev": d["severity"], "msg": d["message"]} for d in st["detections"][:10]],
    }

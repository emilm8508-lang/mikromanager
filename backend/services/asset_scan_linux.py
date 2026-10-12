"""Credentialed hardware scan of Linux computers over SSH (read-only), for services/asset_scan.py.

One shell script reads DMI (/sys/class/dmi/id), lscpu, /proc/meminfo, lsblk, ip, the monitors' EDID from /sys/class/drm,
CUPS printers (lpstat -v) and lsusb. Serial numbers and memory modules need root, so when the account is not root a second,
`sudo -S -p ''` run of `dmidecode` (read-only) is tried with the same password, which is sent over stdin - never on the
command line. Works without sudo too, just without those two items."""
import base64
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from services import asset_scan as base

SSH_TIMEOUT_SEC = 25

SCRIPT = r"""
echo '##OS'; cat /etc/os-release 2>/dev/null
echo '##UNAME'; uname -srm 2>/dev/null
echo '##UID'; id -u 2>/dev/null
echo '##DMI'; for f in sys_vendor product_name product_version product_serial bios_vendor bios_version bios_date board_vendor board_name board_serial chassis_type; do printf '%s=' $f; cat /sys/class/dmi/id/$f 2>/dev/null | head -1; echo; done
echo '##CPU'; lscpu 2>/dev/null
echo '##MEM'; grep -E '^(MemTotal|SwapTotal):' /proc/meminfo 2>/dev/null
echo '##DISK'; lsblk -P -b -d -o NAME,SIZE,TYPE,MODEL,SERIAL,ROTA,TRAN 2>/dev/null
echo '##NIC'; ip -o link 2>/dev/null
echo '##ADDR'; ip -o -4 addr show scope global 2>/dev/null
echo '##GW'; ip -4 route show default 2>/dev/null
echo '##DNS'; grep -E '^nameserver' /etc/resolv.conf 2>/dev/null
echo '##UPTIME'; cat /proc/uptime 2>/dev/null
echo '##USERS'; who 2>/dev/null
echo '##GPU'; lspci 2>/dev/null | grep -iE 'vga|3d controller|display controller'
echo '##USB'; lsusb 2>/dev/null
echo '##PRN'; lpstat -v 2>/dev/null
echo '##EDID'; for e in /sys/class/drm/*/edid; do [ -s "$e" ] && echo "$(basename "$(dirname "$e")") $(base64 -w0 "$e" 2>/dev/null)"; done
echo '##END'
"""
_DMIDECODE = "dmidecode -t system -t baseboard -t memory 2>/dev/null"

_VIRTUAL_IFACES = ("lo", "veth", "docker", "br-", "virbr", "vnet", "tap", "tun", "flannel", "cali", "cni", "kube", "cilium", "lxc", "zt", "wg")
_VIRTUAL_USB = ("root hub", "linux foundation")


# ── Running ──────────────────────────────────────────────────────────────────

def scan_sync(ip: str, username: str, password: str) -> dict:
    """Blocking. {"ok": True, "main": text, "dmi": text|""} or {"ok": False, "error": ..., "auth": bool}."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(ip, port=22, username=username, password=password, timeout=8, banner_timeout=8, auth_timeout=8,
                           look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException as e:
            return {"ok": False, "error": f"SSH login refused: {e}", "auth": True}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}", "auth": False}
        _, out, _ = client.exec_command(SCRIPT, timeout=SSH_TIMEOUT_SEC)
        main = out.read().decode("utf-8", errors="ignore")
        if "##END" not in main:
            return {"ok": False, "error": "the scan script did not finish (is this a Linux host with a POSIX shell?)", "auth": False}
        dmi = ""
        try:
            if re.search(r"##UID\n0\n", main):
                _, o, _ = client.exec_command(_DMIDECODE, timeout=SSH_TIMEOUT_SEC)
            else:
                i, o, _ = client.exec_command(f"sudo -S -p '' {_DMIDECODE}", timeout=SSH_TIMEOUT_SEC)
                i.write(password + "\n")
                i.flush()
            dmi = o.read().decode("utf-8", errors="ignore")
        except Exception:
            dmi = ""
        return {"ok": True, "main": main, "dmi": dmi}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "auth": False}
    finally:
        try:
            client.close()
        except Exception:
            pass


# ── Parsing (pure) ───────────────────────────────────────────────────────────

def sections(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"^##([A-Z]+)$", line.strip())
        if m:
            cur = m.group(1)
            out[cur] = ""
        elif cur:
            out[cur] += line + "\n"
    return out


def _kv(text: str, sep: str = ":") -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        k, s, v = line.partition(sep)
        if s:
            out.setdefault(k.strip(), v.strip())
    return out


def parse_edid(raw: bytes) -> Optional[dict]:
    """The fields of a monitor's EDID block, in the shape of the Windows scan's monitor entries."""
    if len(raw) < 128 or raw[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        return None
    v = (raw[8] << 8) | raw[9]
    maker = "".join(chr(ord("@") + ((v >> s) & 0x1F)) for s in (10, 5, 0))
    name = serial = None
    for off in (54, 72, 90, 108):
        d = raw[off:off + 18]
        if d[:3] == b"\x00\x00\x00":
            text = d[5:18].split(b"\n")[0].decode("ascii", errors="ignore").strip()
            if d[3] == 0xFC and text:
                name = text
            elif d[3] == 0xFF and text:
                serial = text
    num = int.from_bytes(raw[12:16], "little")
    return {"m": maker, "n": name, "s": serial or (str(num) if num else None), "p": f"{(raw[11] << 8) | raw[10]:04X}",
            "y": raw[17] + 1990 if raw[17] else None, "w": raw[21] or None, "h": raw[22] or None}


def _dmidecode(text: str) -> dict:
    """{"serial", "board_serial", "modules": [...]} from `dmidecode -t system -t baseboard -t memory`."""
    out = {"serial": None, "board_serial": None, "modules": []}
    for block in re.split(r"\n\s*\n", text):
        lines = [l for l in block.splitlines() if l.strip()]
        head = next((l.strip() for l in lines if not l.startswith("\t") and not l.startswith(" ") and "Information" in l or l.strip() == "Memory Device"), "")
        f = {}
        for l in lines:
            k, s, v = l.strip().partition(":")
            if s:
                f.setdefault(k.strip(), v.strip())
        if head.startswith("System Information"):
            out["serial"] = base._serial(f.get("Serial Number"))
        elif head.startswith("Base Board"):
            out["board_serial"] = base._serial(f.get("Serial Number"))
        elif head == "Memory Device":
            m = re.match(r"^(\d+)\s*(MB|GB|KB)", f.get("Size", ""))
            if not m:
                continue                                   # "No Module Installed"
            cap = int(m.group(1)) * {"KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}[m.group(2)]
            sp = re.match(r"^(\d+)", f.get("Configured Memory Speed", "") or f.get("Speed", ""))
            mod = {"slot": f.get("Locator"), "cap": cap, "spd": int(sp.group(1)) if sp else None,
                   "m": f.get("Manufacturer"), "pn": f.get("Part Number")}
            out["modules"].append({k: (None if base._s(v) is None or str(v).lower() in ("unknown", "not specified", "[empty]") else v) for k, v in mod.items()})
    return out


def parse(res: dict, now: Optional[datetime] = None) -> dict:
    """The scan's text -> {"asset", "details", "peripherals"} like the Windows scan's parse()."""
    now = now or datetime.utcnow()
    s = sections(res["main"])
    osr = _kv(s.get("OS", ""), "=")
    dmi = _kv(s.get("DMI", ""), "=")
    dd = _dmidecode(res.get("dmi") or "")
    out: Dict = {"asset": {}, "details": {}, "peripherals": []}
    pretty = (osr.get("PRETTY_NAME") or "").strip('"')

    chassis = None
    try:
        chassis = base._CHASSIS.get(int(dmi.get("chassis_type", "")))
    except ValueError:
        pass
    vendor = base._s(dmi.get("sys_vendor"))
    model = base._s(dmi.get("product_name"))
    if vendor and "lenovo" in vendor.lower() and base._s(dmi.get("product_version")):
        model = base._s(dmi.get("product_version"))        # Lenovo keeps the marketing name here ("ThinkPad X1 Carbon")
    serial = base._serial(dmi.get("product_serial")) or dd["serial"]

    boot = None
    try:
        boot = (now - timedelta(seconds=round(float(s.get("UPTIME", "").split()[0])))).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, IndexError):
        pass
    users = sorted({l.split()[0] for l in s.get("USERS", "").splitlines() if l.split()})
    uname = s.get("UNAME", "").strip().split()
    system = {"chassis": chassis, "manufacturer": vendor, "model": model, "logged_user": ", ".join(users) or None,
              "kernel": uname[1] if len(uname) > 1 else None, "architecture": uname[2] if len(uname) > 2 else None, "last_boot": boot}
    out["details"]["system"] = {k: v for k, v in system.items() if v}
    out["details"]["bios"] = {k: v for k, v in {
        "vendor": base._s(dmi.get("bios_vendor")), "version": base._s(dmi.get("bios_version")), "serial": serial, "release_date": base._s(dmi.get("bios_date")),
        "board_manufacturer": base._s(dmi.get("board_vendor")), "board_product": base._s(dmi.get("board_name")),
        "board_serial": base._serial(dmi.get("board_serial")) or dd["board_serial"],
    }.items() if v}

    cpu = _kv(s.get("CPU", ""))
    sockets = base._int(cpu.get("Socket(s)")) or 1
    cores = (base._int(cpu.get("Core(s) per socket")) or 0) * sockets
    threads = base._int(cpu.get("CPU(s)"))
    mhz = re.match(r"^(\d+)", cpu.get("CPU max MHz", ""))
    if cpu.get("Model name"):
        out["details"]["cpu"] = {k: v for k, v in {"name": " ".join(cpu["Model name"].split()), "sockets": sockets, "cores": cores or None,
                                                      "logical": threads, "max_mhz": int(mhz.group(1)) if mhz else None}.items() if v}

    mem = _kv(s.get("MEM", ""))
    kb = base._int((mem.get("MemTotal") or "").split()[0]) if mem.get("MemTotal") else None
    mods = dd["modules"]
    out["details"]["memory"] = {k: v for k, v in {"total_bytes": kb * 1024 if kb else None, "slots_used": len(mods) or None,
                                                  "speed_mhz": mods[0]["spd"] if mods else None}.items() if v}
    out["details"]["memory_modules"] = [{k: v for k, v in {"slot": m["slot"], "capacity_bytes": m["cap"], "speed_mhz": m["spd"],
                                                            "manufacturer": m["m"], "part_number": m["pn"]}.items() if v} for m in mods]

    disks = []
    for line in s.get("DISK", "").splitlines():
        f = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if f.get("TYPE") != "disk" or f.get("NAME", "").startswith(("loop", "ram", "zram", "sr", "fd")):
            continue
        media = "SSD" if f.get("ROTA") == "0" else "HDD" if f.get("ROTA") == "1" else None
        disks.append({k: v for k, v in {"name": " ".join((f.get("MODEL") or f.get("NAME") or "").split()), "size_bytes": base._int(f.get("SIZE")),
                                       "interface": (f.get("TRAN") or "").upper() or None, "media": media, "serial": base._serial(f.get("SERIAL"))}.items() if v})
    out["details"]["physical_disks"] = disks

    addrs: Dict[str, List[str]] = {}
    for line in s.get("ADDR", "").splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/", line)
        if m:
            addrs.setdefault(m.group(1), []).append(m.group(2))
    gw = {}
    for line in s.get("GW", "").splitlines():
        m = re.search(r"default via ([\d.]+) dev (\S+)", line)
        if m:
            gw[m.group(2)] = m.group(1)
    dns = [l.split()[1] for l in s.get("DNS", "").splitlines() if len(l.split()) > 1]
    nics = []
    for line in s.get("NIC", "").splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)[^\n]*?link/ether\s+([0-9a-f:]{17})", line, re.I)
        if not m or m.group(1).startswith(_VIRTUAL_IFACES):
            continue
        n = m.group(1)
        nics.append({k: v for k, v in {"name": n, "mac": m.group(2).upper(), "ips": addrs.get(n), "gateway": [gw[n]] if n in gw else None, "dns": dns if n in gw else None}.items() if v})
    out["details"]["network_adapters"] = nics
    main = next((n for n in nics if n.get("gateway")), None) or next((n for n in nics if n.get("ips")), None)

    out["details"]["gpu"] = [{"name": re.sub(r"^\S+\s+[^:]+:\s*", "", l).strip()} for l in s.get("GPU", "").splitlines() if l.strip()]

    for line in s.get("EDID", "").splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                e = parse_edid(base64.b64decode(parts[1]))
            except Exception:
                e = None
            if e:
                out["peripherals"].append(base.monitor_entry(e))

    for line in s.get("PRN", "").splitlines():
        m = re.match(r"^device for ([^:]+):\s*(\S+)", line.strip())
        if m:
            uri = m.group(2)
            host = re.match(r"^\w+://(?:[^@/]*@)?([^:/]+)", uri)
            out["peripherals"].append({"kind": "printer", "name": m.group(1).replace("_", " "), "manufacturer": None, "model": None, "serial": None,
                                       "details": {k: v for k, v in {"port": uri, "address": host.group(1) if host else None, "network": True if host else None}.items() if v}})

    usb = []
    for line in s.get("USB", "").splitlines():
        m = re.match(r"^Bus \d+ Device \d+: ID ([0-9a-f]{4}:[0-9a-f]{4})\s*(.*)$", line.strip(), re.I)
        if m and not any(x in m.group(2).lower() for x in _VIRTUAL_USB):
            usb.append({"kind": "usb", "name": m.group(2).strip() or m.group(1), "manufacturer": None, "model": None, "serial": None, "details": {"id": m.group(1)}})
    out["peripherals"].extend(usb[:base.MAX_USB])

    out["asset"] = {"manufacturer": vendor, "model": model, "serial": serial, "os_name": pretty or None, "os_version": osr.get("VERSION_ID", "").strip('"') or None,
                    "mac": main["mac"] if main else None}
    return out

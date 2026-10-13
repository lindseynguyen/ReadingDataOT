"""Configuration files of OT network devices (switches, routers, firewalls).

- Cisco IOS / IOS-XE, including Cisco Industrial Ethernet (IE) and Rockwell
  Allen-Bradley Stratix switches: full parse (hostname, version, interfaces,
  VLANs) and hardening checks
- Fortinet FortiOS, including FortiGate Rugged: admin access per interface,
  any-any firewall policies, admin trusted hosts, SNMP communities
- Siemens RUGGEDCOM, Hirschmann (HiOS / Classic), Moxa, Westermo, Phoenix
  Contact, Belden and other industrial vendors: vendor identification and
  keyword-based checks, reported as heuristic until validated on real exports

Secrets are always masked in findings.
"""
from __future__ import annotations

import re
from collections import Counter

from ..core.identify import Identity
from ..core.model import Asset, FileRecord, Finding
from ..core.registry import register

MAX_LINES = 500_000
PUBLIC_COMMUNITIES = {"public", "private"}
IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"


def _mask(s: str) -> str:
    s = s.strip("\"'")
    return s[:2] + "*" * max(0, len(s) - 2) if len(s) > 2 else "**"


def _sections(lines: list[str]) -> list[tuple[str, list[str]]]:
    """IOS-style: a non-indented line opens a section, indented lines belong to it."""
    out: list[tuple[str, list[str]]] = []
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith("!"):
            continue
        if ln[0] in " \t" and out:
            out[-1][1].append(ln.strip())
        else:
            out.append((ln.strip(), []))
    return out


# ------------------------------------------------------------------ Cisco IOS
def parse_ios(lines: list[str], rec: FileRecord) -> None:
    src = rec.path
    secs = _sections(lines)
    top = [h for h, _ in secs]
    text = "\n".join(lines)
    low = text.lower()
    hostname = next((h.split(None, 1)[1] for h in top if h.startswith("hostname ") and len(h.split()) > 1), "")
    version = next((h.split(None, 1)[1] for h in top if re.match(r"^version \d", h)), "")
    vendor = "Rockwell Automation (Cisco IOS)" if "stratix" in low else "Cisco"

    interfaces, vlans, mgmt_ip = [], [], ""
    access = trunk = shut = 0
    for head, body in secs:
        if head.startswith("interface "):
            name = head.split(None, 1)[1]
            ip = ""
            for b in body:
                m = re.match(rf"^ip address ({IPV4}) ({IPV4})", b)
                if m:
                    ip = f"{m.group(1)}/{m.group(2)}"
            mode = "trunk" if "switchport mode trunk" in body else "access" if "switchport mode access" in body else ""
            access += mode == "access"
            trunk += mode == "trunk"
            shut += "shutdown" in body
            interfaces.append({"name": name, "ip": ip, "mode": mode, "shutdown": "shutdown" in body,
                               "description": next((b[12:] for b in body if b.startswith("description ")), "")})
            if ip and not mgmt_ip and not name.lower().startswith(("loopback", "null")):
                mgmt_ip = ip
        elif re.match(r"^vlan \d+$", head):
            vlans.append({"id": head.split()[1], "name": next((b[5:] for b in body if b.startswith("name ")), "")})

    rec.summary.update({"platform": "Cisco IOS", "hostname": hostname, "ios_version": version,
                        "interfaces": interfaces[:500], "interface_count": len(interfaces),
                        "access_ports": access, "trunk_ports": trunk, "shutdown_ports": shut, "vlans": vlans[:500]})
    ip, _, mask = mgmt_ip.partition("/")
    rec.assets.append(Asset(name=hostname or rec.path, kind="Network device", vendor=vendor,
                            model="Stratix" if "stratix" in low else "", version=version, ip=ip, subnet=mask,
                            protocols=sorted({"SSH" if "transport input ssh" in low else "",
                                              "SNMP" if "snmp-server community" in low else ""} - {""}),
                            source=src, extra={"platform": "Cisco IOS", "vlans": len(vlans)}))
    f = rec.findings

    def add(sev, rule, msg):
        f.append(Finding(sev, rule, msg, src, hostname))

    for h in top:
        m = re.match(r"^enable password (?:(\d) )?(\S+)", h)
        if m:
            add("high", "NET-ENABLE-PASSWORD", f"'enable password' stores the privileged password "
                f"{'with reversible type 7' if m.group(1) == '7' else 'in cleartext'} ({_mask(m.group(2))}); use 'enable algorithm-type scrypt secret'")
        m = re.match(r"^enable secret 5 ", h)
        if m:
            add("low", "NET-WEAK-PASSWORD-HASH", "'enable secret 5' uses MD5; prefer type 8 (PBKDF2) or 9 (scrypt)")
        m = re.match(r"^username (\S+) .*?password (?:(\d) )?(\S+)", h)
        if m and m.group(2) in (None, "0", "7"):
            add("high", "NET-PASSWORD-REVERSIBLE",
                f"User '{m.group(1)}' password is {'type 7 (reversible)' if m.group(2) == '7' else 'cleartext'} "
                f"({_mask(m.group(3))}); use 'secret' with type 8/9")
        m = re.match(r"^snmp-server community (\S+)(?: view \S+)?(?: (RO|RW|ro|rw))?(?: (\S+))?", h)
        if m:
            comm, perm, acl = m.group(1), (m.group(2) or "RO").upper(), m.group(3)
            if comm.lower() in PUBLIC_COMMUNITIES:
                add("high", "NET-SNMP-DEFAULT-COMMUNITY", f"SNMP community '{comm}' ({perm}) is a well-known default")
            elif perm == "RW":
                add("medium", "NET-SNMP-RW", f"SNMP read-write community ({_mask(comm)}) allows configuration changes")
            if not acl:
                add("low", "NET-SNMP-NO-ACL", f"SNMP community ({_mask(comm)}) is not restricted by an ACL")
    if "ip http server" in top:
        add("medium", "NET-HTTP-ENABLED", "Cleartext HTTP management is enabled ('ip http server'); use 'ip http secure-server' only")
    if "ip ssh version 1" in top:
        add("medium", "NET-SSH-V1", "SSH version 1 is enabled ('ip ssh version 1')")
    def _cleartext(line: str) -> bool:
        m = re.search(r"\bpassword (\S+)(?: (\S+))?\s*$", line)
        return bool(m) and not (m.group(1) in ("5", "7", "8", "9") and m.group(2))
    if "service password-encryption" not in top and any(_cleartext(b) for _, body in secs for b in body):
        add("medium", "NET-PASSWORD-REVERSIBLE", "Line passwords are stored in cleartext ('service password-encryption' not set)")
    for head, body in secs:
        if head.startswith("line vty"):
            ti = next((b for b in body if b.startswith("transport input")), "")
            if "telnet" in ti or ti.endswith(" all"):
                add("high", "NET-TELNET-ENABLED", f"'{head}' accepts Telnet ({ti})")
            elif not ti:
                add("low", "NET-TELNET-ENABLED", f"'{head}' has no 'transport input' (older IOS releases then accept Telnet)")
            if not any(b.startswith("access-class") for b in body):
                add("medium", "NET-MGMT-NO-ACL", f"'{head}' has no access-class: management is reachable from any address")
            if any(b.startswith("exec-timeout 0") for b in body):
                add("low", "NET-NO-SESSION-TIMEOUT", f"'{head}' never times out idle sessions (exec-timeout 0)")
    if not any(re.match(rf"^logging (host )?{IPV4}", h) for h in top):
        add("low", "NET-NO-REMOTE-LOG", "No remote syslog server configured")
    if not any(h.startswith("ntp server") for h in top):
        add("low", "NET-NO-NTP", "No NTP server: log timestamps cannot be correlated across devices")
    if "no cdp run" not in top:
        add("info", "NET-CDP-ENABLED", "CDP is enabled globally (discloses model, version and addresses to neighbours)")


# ------------------------------------------------------------------ FortiOS
def _forti_blocks(lines: list[str]) -> dict[str, list[dict]]:
    """config <path> / edit <name> / set k v / next / end -> {path: [{"_name": .., k: v}]}.
    'set' lines directly under a config block (no edit) go into an entry named ''."""
    out: dict[str, list[dict]] = {}
    stack: list[str] = []
    cur: dict | None = None
    for raw in lines:
        ln = raw.strip()
        path = " > ".join(stack)
        if ln.startswith("config "):
            stack.append(ln[7:])
            out.setdefault(" > ".join(stack), [])
            cur = None
        elif ln.startswith("edit ") and stack:
            cur = {"_name": ln[5:].strip('"')}
            out[path].append(cur)
        elif ln.startswith("set ") and stack:
            if cur is None:
                cur = {"_name": ""}
                out[path].append(cur)
            parts = ln[4:].split(None, 1)
            cur[parts[0]] = parts[1] if len(parts) > 1 else ""
        elif ln == "next":
            cur = None
        elif ln == "end" and stack:
            stack.pop()
            cur = None
    return out


def parse_fortios(lines: list[str], rec: FileRecord) -> None:
    src = rec.path
    first = lines[0] if lines else ""
    m = re.match(r"#config-version=([A-Z0-9]+)-([\d.]+)", first)
    model, version = (m.group(1), m.group(2)) if m else ("", "")
    blocks = _forti_blocks(lines)
    glob = next(iter(blocks.get("system global", [])), {})
    hostname = glob.get("hostname", "").strip('"')
    f = rec.findings

    def add(sev, rule, msg):
        f.append(Finding(sev, rule, msg, src, hostname or model))

    ifaces = []
    for it in blocks.get("system interface", []):
        acc = it.get("allowaccess", "").split()
        ip = it.get("ip", "").split()
        ifaces.append({"name": it["_name"], "ip": "/".join(ip[:2]), "allowaccess": acc, "role": it.get("role", "")})
        if "telnet" in acc:
            add("high", "NET-TELNET-ENABLED", f"Interface {it['_name']} allows Telnet administration")
        if "http" in acc:
            add("medium", "NET-HTTP-ENABLED", f"Interface {it['_name']} allows cleartext HTTP administration")
        if it.get("role") == "wan" and {"https", "ssh", "http", "telnet"} & set(acc):
            add("high", "NET-ADMIN-ON-WAN", f"Administrative access ({', '.join(acc)}) enabled on WAN interface {it['_name']}")
    for adm in blocks.get("system admin", []):
        if not any(k.startswith("trusthost") for k in adm):
            add("medium", "NET-ADMIN-NO-TRUSTHOST", f"Administrator '{adm['_name']}' can log in from any address (no trusthost)")
    for c in blocks.get("system snmp community", []):
        name = c.get("name", "").strip('"')
        if name.lower() in PUBLIC_COMMUNITIES:
            add("high", "NET-SNMP-DEFAULT-COMMUNITY", f"SNMP community '{name}' is a well-known default")
    policies = blocks.get("firewall policy", [])
    for p in policies:
        if p.get("action") != "accept" or p.get("status") == "disable":
            continue
        s_all = p.get("srcaddr", "").strip('"').lower() == "all"
        d_all = p.get("dstaddr", "").strip('"').lower() == "all"
        svc_all = p.get("service", "").strip('"').upper() == "ALL"
        label = p.get("name", "").strip('"') or f"policy {p['_name']}"
        if s_all and d_all and svc_all:
            add("high", "NET-FW-ANY-ANY", f"Firewall {label} accepts any source to any destination on any service")
        elif svc_all:
            add("medium", "NET-FW-ANY-SERVICE", f"Firewall {label} accepts all services")
        if p.get("logtraffic") == "disable":
            add("low", "NET-FW-NO-LOG", f"Firewall {label} does not log traffic")
    if not blocks.get("log syslogd setting") and not blocks.get("log fortianalyzer setting"):
        add("low", "NET-NO-REMOTE-LOG", "No remote syslog / FortiAnalyzer logging configured")
    rec.summary.update({"platform": "FortiOS", "hostname": hostname, "model": model, "fortios_version": version,
                        "interfaces": ifaces[:500], "firewall_policies": len(policies)})
    usable = [i for i in ifaces if i["ip"] and not i["ip"].startswith("0.0.0.0")]
    usable.sort(key=lambda i: i["role"] == "wan")          # prefer an internal/management address
    ip = usable[0]["ip"].split("/")[0] if usable else ""
    rec.assets.append(Asset(name=hostname or model or rec.path, kind="Firewall", vendor="Fortinet", model=model,
                            version=version, ip=ip, source=src, extra={"platform": "FortiOS"}))


# ------------------------------------------------------------------ industrial vendors (heuristic)
INDUSTRIAL_VENDORS = [
    ("ruggedcom", "Siemens RUGGEDCOM"), ("hirschmann", "Hirschmann (Belden)"), ("hios", "Hirschmann (Belden)"),
    ("moxa", "Moxa"), ("westermo", "Westermo"), ("phoenix contact", "Phoenix Contact"),
    ("scalance", "Siemens SCALANCE"), ("garrettcom", "GarrettCom (Belden)"), ("tofino", "Tofino (Belden)"),
    ("korenix", "Korenix"), ("red lion", "Red Lion"), ("n-tron", "Red Lion N-Tron"),
]
ON = r"(?:=|:|,|\s)\s*\"?(?:enable|enabled|on|yes|true|1)\b"


def parse_generic(lines: list[str], rec: FileRecord, vendor: str) -> None:
    src = rec.path
    text = "\n".join(lines)
    low = text.lower()
    f = rec.findings
    name = ""
    # CSV exports (e.g. RUGGEDCOM ROS) put the header row first and the values on the next line
    m = re.search(r"(?im)^\s*\"?system ?name\"?\s*,[^\r\n]*\r?\n\s*\"?([^\",\r\n]+)", text)
    if not m:
        m = re.search(r"(?im)^\s*(?:hostname|system ?name|sysname|device ?name)\s*(?:=|:|,|\s)\s*\"?([^\"\r\n,]+)", text)
    if m:
        name = m.group(1).strip()
    m = re.search(r"(?i)\b(?:firmware|software|sw|ros|hios)[ _-]?(?:version|rev(?:ision)?)?\s*(?:=|:|,|\s)\s*\"?v?([\d][\w.\-]*)", text)
    version = m.group(1) if m else ""
    ips = re.findall(rf"\b({IPV4})\b", text)
    rec.summary.update({"platform": vendor, "hostname": name, "addresses": sorted(set(ips))[:50],
                        "heuristic": True})
    rec.assets.append(Asset(name=name or rec.path, kind="Network device", vendor=vendor, version=version,
                            ip=ips[0] if ips else "", source=src, extra={"platform": vendor, "heuristic": True}))

    def add(sev, rule, msg):
        f.append(Finding(sev, rule, f"{msg} (heuristic match on {vendor} configuration; verify on the device)",
                         src, name))

    for ln in lines:
        l2 = ln.lower()
        if "telnet" in l2 and re.search(ON, l2):
            add("medium", "NET-TELNET-ENABLED", "Telnet service appears enabled")
            break
    if "https" not in low and any(re.search(r"\b(?:http|web)\b", ln.lower()) and re.search(ON, ln.lower())
                                  for ln in lines):
        add("low", "NET-HTTP-ENABLED", "Web management over HTTP appears enabled and no HTTPS setting was found")
    if any(re.search(r"\bsnmp\s*v?1\b|\bv1\b", ln.lower()) and "snmp" in low and re.search(ON, ln.lower())
           for ln in lines):
        add("medium", "NET-SNMP-V1", "SNMPv1 appears enabled")
    for comm in sorted({c.lower() for c in re.findall(r"(?i)\bcommunity\w*\s*(?:=|:|,|\s)\s*\"?(public|private)\b", text)}):
        add("high", "NET-SNMP-DEFAULT-COMMUNITY", f"SNMP community '{comm}' is a well-known default")
    for user, pw in re.findall(r"(?im)^\s*\"?(admin|operator|guest|user|root)\"?\s*(?:,|=|:)\s*\"?(admin|operator|guest|private|public|password|1234|0000|root)\"?\s*$", text):
        add("high", "NET-DEFAULT-CREDENTIALS", f"Account '{user}' appears to use a default password ({_mask(pw)})")


# ------------------------------------------------------------------ detection
def detect(head: str) -> tuple[str, str] | None:
    """(platform, description) from the first KB of a text file, or None."""
    low = head.lower()
    if low.startswith("#config-version=f") or "\nconfig system global" in low or low.startswith("config system global"):
        return "fortios", "Fortinet FortiOS configuration"
    if re.search(r"(?m)^version \d+\.\d+", head) and re.search(r"(?m)^(hostname |interface |service |no service |boot-)", head):
        return "ios", ("Rockwell Stratix (Cisco IOS) configuration" if "stratix" in low
                       else "Cisco IOS / IOS-XE configuration")
    if re.search(r"(?m)^! (?:Last configuration change|NVRAM config last updated)", head):
        return "ios", "Cisco IOS / IOS-XE configuration"
    for key, vendor in INDUSTRIAL_VENDORS:
        if key in low:
            return f"generic:{vendor}", f"{vendor} device configuration"
    return None


@register
class NetConfigParser:
    name = "netconfig"
    max_size = 64 * 1024 * 1024

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return rec.category == "NetConfig"

    def parse(self, path: str, rec: FileRecord) -> None:
        lines: list[str] = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, ln in enumerate(fh):
                if i >= MAX_LINES:
                    rec.summary["truncated"] = True
                    break
                lines.append(ln.rstrip("\r\n"))
        kind = detect("\n".join(lines[:200]))
        if kind is None:
            rec.error = "netconfig: platform not recognised"
            return
        platform = kind[0]
        if platform == "ios":
            parse_ios(lines, rec)
        elif platform == "fortios":
            parse_fortios(lines, rec)
        else:
            parse_generic(lines, rec, platform.split(":", 1)[1])
        rules = Counter(x.rule for x in rec.findings)
        rec.summary["finding_rules"] = dict(rules)

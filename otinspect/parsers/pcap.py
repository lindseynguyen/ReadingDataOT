"""PCAP / PCAPNG traffic summary for OT networks (pure Python, no scapy/tshark).

Detects Layer-2 OT protocols (GOOSE, SV, PROFINET, EtherCAT, PTP, LLDP) by EtherType
and IP-based OT protocols (MMS/S7comm, IEC 104, Modbus/TCP, DNP3, EtherNet/IP,
OPC UA, BACnet...) by port. Builds a host inventory and flags cleartext admin
protocols and Modbus write activity.
"""
from __future__ import annotations

import struct
from collections import Counter, defaultdict

from ..core.identify import Identity
from ..core.model import Asset, FileRecord, Finding
from ..core.registry import register

MAX_PACKETS = 2_000_000

ETHERTYPES = {
    0x88B8: "GOOSE", 0x88B9: "GSE-Mgmt", 0x88BA: "SV", 0x8892: "PROFINET-RT",
    0x88A4: "EtherCAT", 0x88F7: "PTP", 0x88CC: "LLDP", 0x0806: "ARP",
    0x88E3: "MRP", 0x22F3: "TRILL", 0x8100: "VLAN",
}
TCP_PORTS = {
    102: "MMS/S7comm (ISO-TSAP)", 502: "Modbus/TCP", 2404: "IEC 60870-5-104", 20000: "DNP3",
    44818: "EtherNet/IP", 4840: "OPC UA", 1911: "Niagara Fox", 789: "Red Lion Crimson",
    9600: "OMRON FINS", 5007: "Mitsubishi MELSEC", 18245: "GE SRTP", 2455: "CODESYS",
    1217: "CODESYS v2", 11740: "CODESYS v3", 4000: "Emerson ROC", 5094: "HART-IP",
    23: "Telnet", 21: "FTP", 80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 5900: "VNC",
    161: "SNMP", 445: "SMB", 135: "MS-RPC", 1433: "MSSQL",
}
UDP_PORTS = {
    2222: "EtherNet/IP I/O", 44818: "EtherNet/IP", 47808: "BACnet", 20000: "DNP3",
    161: "SNMP", 162: "SNMP-trap", 69: "TFTP", 123: "NTP", 514: "Syslog", 319: "PTP", 320: "PTP",
    34962: "PROFINET", 34963: "PROFINET", 34964: "PROFINET-CM", 9600: "OMRON FINS",
    1089: "FF HSE", 5050: "Mitsubishi", 102: "MMS",
}
CLEARTEXT_ADMIN = {"Telnet": "high", "FTP": "medium", "TFTP": "medium", "HTTP": "low", "VNC": "medium"}


def _iter_pcap(data: bytes):
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        return None, iter(())
    linktype = struct.unpack(e + "I", data[20:24])[0]

    def gen():
        off = 24
        while off + 16 <= len(data):
            ts, _, incl, _ = struct.unpack(e + "IIII", data[off:off + 16])
            off += 16
            yield ts, linktype, data[off:off + incl]
            off += incl
    return linktype, gen()


def _iter_pcapng(data: bytes):
    links: list[int] = []
    e = "<"

    def gen():
        nonlocal e
        off = 0
        while off + 12 <= len(data):
            btype = struct.unpack(e + "I", data[off:off + 4])[0]
            if btype == 0x0A0D0D0A:
                bom = data[off + 8:off + 12]
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                links.clear()
            blen = struct.unpack(e + "I", data[off + 4:off + 8])[0]
            if blen < 12:
                return
            body = data[off + 8:off + blen - 4]
            if btype == 1:                       # Interface Description Block
                links.append(struct.unpack(e + "H", body[:2])[0])
            elif btype == 6:                     # Enhanced Packet Block
                iface, tsh, _, cap, _ = struct.unpack(e + "IIIII", body[:20])
                lt = links[iface] if iface < len(links) else 1
                yield tsh, lt, body[20:20 + cap]
            elif btype == 3:                     # Simple Packet Block
                lt = links[0] if links else 1
                yield 0, lt, body[4:]
            off += blen
    return gen()


def _ber_len(b: bytes, i: int):
    n = b[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7F
    return int.from_bytes(b[i + 1:i + 1 + k], "big"), i + 1 + k


def _goose_cbref(payload: bytes) -> str:
    """payload starts at APPID. Returns gocbRef if decodable."""
    try:
        i = 8
        if payload[i] != 0x61:
            return ""
        _, i = _ber_len(payload, i + 1)
        if payload[i] != 0x80:
            return ""
        ln, i = _ber_len(payload, i + 1)
        return payload[i:i + ln].decode("ascii", "replace")
    except IndexError:
        return ""


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


@register
class PcapParser:
    name = "pcap"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return rec.category == "PCAP"

    def parse(self, path: str, rec: FileRecord) -> None:
        with open(path, "rb") as fh:
            data = fh.read()
        if data[:4] == b"\x0a\x0d\x0d\x0a":
            packets = _iter_pcapng(data)
            fmt = "pcapng"
        else:
            _, packets = _iter_pcap(data)
            fmt = "pcap"

        proto = Counter()
        l2 = Counter()
        hosts: dict[str, dict] = defaultdict(lambda: {"macs": set(), "serves": set(), "talks": set(), "pkts": 0})
        conv = Counter()
        goose: dict[tuple, dict] = {}
        sv = Counter()
        vlans = Counter()
        modbus_fc = Counter()
        n = 0
        t_first = t_last = None

        for ts, linktype, pkt in packets:
            n += 1
            if n > MAX_PACKETS:
                rec.summary["truncated"] = True
                break
            if ts:
                t_first = ts if t_first is None else min(t_first, ts)
                t_last = ts if t_last is None else max(t_last, ts)
            if linktype != 1 or len(pkt) < 14:
                proto[f"linktype-{linktype}"] += 1
                continue
            dst, src = pkt[0:6], pkt[6:12]
            et = struct.unpack(">H", pkt[12:14])[0]
            off = 14
            while et in (0x8100, 0x88A8) and len(pkt) >= off + 4:
                vlans[struct.unpack(">H", pkt[off:off + 2])[0] & 0x0FFF] += 1
                et = struct.unpack(">H", pkt[off + 2:off + 4])[0]
                off += 4

            if et in ETHERTYPES:
                name = ETHERTYPES[et]
                l2[name] += 1
                proto[name] += 1
                if name == "GOOSE" and len(pkt) >= off + 2:
                    appid = pkt[off:off + 2].hex().upper()
                    key = (_mac(src), appid)
                    g = goose.setdefault(key, {"src_mac": _mac(src), "dst_mac": _mac(dst), "APPID": appid,
                                               "gocbRef": _goose_cbref(pkt[off:]), "packets": 0})
                    g["packets"] += 1
                elif name == "SV" and len(pkt) >= off + 2:
                    sv[(_mac(src), pkt[off:off + 2].hex().upper())] += 1
                continue
            if et != 0x0800 or len(pkt) < off + 20:
                proto[f"ethertype-0x{et:04x}"] += 1
                continue

            ihl = (pkt[off] & 0x0F) * 4
            ipproto = pkt[off + 9]
            sip, dip = _ip(pkt[off + 12:off + 16]), _ip(pkt[off + 16:off + 20])
            hosts[sip]["macs"].add(_mac(src))
            hosts[sip]["pkts"] += 1
            hosts[dip]["pkts"] += 1
            t = off + ihl
            if ipproto in (6, 17) and len(pkt) >= t + 4:
                sp, dp = struct.unpack(">HH", pkt[t:t + 4])
                table = TCP_PORTS if ipproto == 6 else UDP_PORTS
                if dp in table:
                    svc, server, client, port = table[dp], dip, sip, dp
                elif sp in table:
                    svc, server, client, port = table[sp], sip, dip, sp
                else:
                    proto["TCP-other" if ipproto == 6 else "UDP-other"] += 1
                    continue
                proto[svc] += 1
                hosts[server]["serves"].add(svc)
                hosts[client]["talks"].add(svc)
                conv[(client, server, svc)] += 1
                if ipproto == 6 and port == 502 and dp == 502:
                    doff = (pkt[t + 12] >> 4) * 4
                    p = pkt[t + doff:]
                    if len(p) >= 8:
                        modbus_fc[p[7]] += 1
            elif ipproto == 1:
                proto["ICMP"] += 1
            else:
                proto[f"ip-proto-{ipproto}"] += 1

        rec.summary.update({
            "format": fmt, "packets": n,
            "duration_s": (t_last - t_first) if t_first is not None else 0,
            "protocols": dict(proto.most_common()),
            "vlans": {str(k): v for k, v in vlans.most_common(20)},
            "goose_streams": sorted(goose.values(), key=lambda g: -g["packets"])[:100],
            "sv_streams": [{"src_mac": k[0], "APPID": k[1], "packets": v} for k, v in sv.most_common(50)],
            "top_conversations": [{"client": c, "server": s, "service": p, "packets": v}
                                  for (c, s, p), v in conv.most_common(50)],
            "modbus_function_codes": {str(k): v for k, v in sorted(modbus_fc.items())},
        })

        for ip, h in sorted(hosts.items(), key=lambda kv: -kv[1]["pkts"]):
            if not (h["serves"] or h["talks"]):
                continue
            rec.assets.append(Asset(
                name=ip, kind="Host", ip=ip, mac=", ".join(sorted(h["macs"]))[:60],
                protocols=sorted(h["serves"] | h["talks"]), source=rec.path,
                extra={"serves": sorted(h["serves"]), "client_of": sorted(h["talks"]), "packets": h["pkts"]},
            ))
            for svc in h["serves"]:
                if svc in CLEARTEXT_ADMIN:
                    rec.findings.append(Finding(CLEARTEXT_ADMIN[svc], "PCAP-CLEARTEXT-ADMIN",
                                                f"{ip} serves {svc} (cleartext)", rec.path, ip))

        writes = sum(v for k, v in modbus_fc.items() if k in (5, 6, 15, 16, 22, 23))
        if writes:
            rec.findings.append(Finding("medium", "PCAP-MODBUS-WRITE",
                                        f"{writes} Modbus write requests observed (FC 5/6/15/16/22/23)", rec.path))
        diag = modbus_fc.get(8, 0) + modbus_fc.get(43, 0)
        if diag:
            rec.findings.append(Finding("low", "PCAP-MODBUS-RECON",
                                        f"{diag} Modbus diagnostic/identification requests (FC 8/43)", rec.path))
        if goose and not vlans:
            rec.findings.append(Finding("info", "PCAP-GOOSE-UNTAGGED",
                                        "GOOSE traffic captured without VLAN tags", rec.path))
        appid_src = defaultdict(set)
        for g in goose.values():
            appid_src[g["APPID"]].add(g["src_mac"])
        for appid, srcs in appid_src.items():
            if len(srcs) > 1:
                rec.findings.append(Finding("high", "PCAP-GOOSE-APPID-DUP",
                                            f"GOOSE APPID {appid} sent by multiple MACs: {', '.join(sorted(srcs))}",
                                            rec.path))

"""Static SVG network map for the HTML report (no JavaScript, works offline).

Assets are grouped by SCL SubNetwork when known, otherwise by IPv4 /24.
Each group is drawn as a bus with its devices below it. Devices seen only in
captures (undocumented) and devices with high findings are highlighted.
"""
from __future__ import annotations

import html
import ipaddress
from collections import OrderedDict

from ..core.model import ScanResult

NODE_W, NODE_H, GAP_X, GAP_Y, PER_ROW = 168, 54, 14, 14, 5
PAD, BUS_H = 16, 34


def _group_key(ip: str, subnet: str) -> str:
    try:
        if subnet:
            return str(ipaddress.ip_network(f"{ip}/{subnet}", strict=False))
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return "unknown"


def build_svg(res: ScanResult) -> str:
    nodes: dict[str, dict] = OrderedDict()        # keyed by IP
    risky = {f.asset for f in res.findings if f.severity == "high" and f.asset}
    for f in res.files:
        for a in f.assets:
            if not a.ip:
                continue
            n = nodes.get(a.ip)
            documented = f.category != "PCAP"
            if n is None:
                n = nodes[a.ip] = {"ip": a.ip, "name": "", "names": [], "kind": "", "vendor": "", "subnet": "",
                                   "documented": False, "observed": False, "protocols": set(), "risk": False}
            if documented:
                if not n["documented"]:
                    n.update(name=a.name, kind=a.kind, vendor=a.vendor)
                if a.name not in n["names"]:
                    n["names"].append(a.name)
                n["documented"] = True
                n["subnet"] = n["subnet"] or a.subnet
                n["group"] = n.get("group") or a.extra.get("subnetwork")
            else:
                n["observed"] = True
                n["name"] = n["name"] or a.extra.get("documented_as", "")
            n["protocols"].update(a.protocols)
            if a.name in risky or a.ip in risky:
                n["risk"] = True
    if not nodes:
        return ""

    by_net: dict[str, list[dict]] = {}
    for n in nodes.values():
        by_net.setdefault(_group_key(n["ip"], n["subnet"]), []).append(n)

    def _net_sort(k: str):
        try:
            return (0, int(ipaddress.ip_network(k).network_address))
        except ValueError:
            return (1, 0)

    groups: dict[str, list[dict]] = OrderedDict()
    for net in sorted(by_net, key=_net_sort):
        members = by_net[net]
        names = sorted({m["group"] for m in members if m.get("group")})
        groups[f"{' / '.join(names)} · {net}" if names else net] = members
    for g in groups.values():
        g.sort(key=lambda n: tuple(int(x) for x in n["ip"].split(".")) if n["ip"].count(".") == 3 else (999,))

    width = PAD * 2 + PER_ROW * NODE_W + (PER_ROW - 1) * GAP_X
    parts, y = [], PAD
    for label, members in groups.items():
        rows = (len(members) + PER_ROW - 1) // PER_ROW
        parts.append(f'<text x="{PAD}" y="{y + 14}" class="nm-g">{html.escape(label)}</text>')
        bus_y = y + BUS_H - 8
        parts.append(f'<line x1="{PAD}" y1="{bus_y}" x2="{width - PAD}" y2="{bus_y}" class="nm-bus"/>')
        for i, n in enumerate(members):
            r, c = divmod(i, PER_ROW)
            x = PAD + c * (NODE_W + GAP_X)
            ny = y + BUS_H + 10 + r * (NODE_H + GAP_Y)
            cx = x + NODE_W // 2
            if r == 0:
                parts.append(f'<line x1="{cx}" y1="{bus_y}" x2="{cx}" y2="{ny}" class="nm-drop"/>')
            cls = "nm-n"
            if not n["documented"]:
                cls += " nm-undoc"
            if n["risk"]:
                cls += " nm-risk"
            title = f"{', '.join(n['names']) or n['name'] or n['ip']} | {n['kind']} {n['vendor']} | {', '.join(sorted(n['protocols']))}"
            if len(n["names"]) > 1:
                title += " | DUPLICATE IP shared by several devices"
                cls += " nm-risk"
            if not n["documented"]:
                title += " | seen in capture, not in any configuration file"
            name = n["name"] or "unnamed host"
            if len(n["names"]) > 1:
                name = f"{n['names'][0][:14]} +{len(n['names']) - 1} (dup IP)"
            name = name if len(name) <= 24 else name[:23] + "…"
            sub = n["vendor"] or n["kind"] or ", ".join(sorted(n["protocols"]))
            sub = sub if len(sub) <= 25 else sub[:24] + "…"
            parts.append(
                f'<g><title>{html.escape(title)}</title>'
                f'<rect x="{x}" y="{ny}" width="{NODE_W}" height="{NODE_H}" rx="6" class="{cls}"/>'
                f'<text x="{x + 10}" y="{ny + 18}" class="nm-t">{html.escape(name)}</text>'
                f'<text x="{x + 10}" y="{ny + 33}" class="nm-ip">{html.escape(n["ip"])}</text>'
                f'<text x="{x + 10}" y="{ny + 47}" class="nm-s">{html.escape(sub)}</text></g>')
        y += BUS_H + 10 + rows * (NODE_H + GAP_Y) + 18
    height = y
    style = """<style>
.nm-g{font:600 13px system-ui,sans-serif;fill:var(--acc)}
.nm-bus{stroke:var(--acc);stroke-width:3}
.nm-drop{stroke:var(--mut);stroke-width:1.2}
.nm-n{fill:var(--card);stroke:var(--line);stroke-width:1.2}
.nm-undoc{stroke:#c77700;stroke-dasharray:5 3;stroke-width:2}
.nm-risk{stroke:#c0392b;stroke-width:2.4}
.nm-t{font:600 12px system-ui,sans-serif;fill:var(--fg)}
.nm-ip{font:11.5px ui-monospace,Consolas,monospace;fill:var(--fg)}
.nm-s{font:11px system-ui,sans-serif;fill:var(--mut)}
</style>"""
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="Network map" '
            f'xmlns="http://www.w3.org/2000/svg">{style}{"".join(parts)}</svg>')

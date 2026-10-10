"""JSON / CSV / HTML reports (self-contained HTML that opens offline; print to PDF
from a browser, so no external font is needed as in the old version)."""
from __future__ import annotations

import csv
import datetime as dt
import html
import json
import os

from ..core.model import ScanResult
from .netmap import build_svg

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

CSS = """
:root{--bg:#fafaf7;--fg:#1d2329;--mut:#66707a;--line:#e2e2dc;--card:#fff;--acc:#0f6b5c}
@media (prefers-color-scheme:dark){:root{--bg:#14181b;--fg:#e4e6e8;--mut:#98a1aa;--line:#2b3238;--card:#1b2024;--acc:#5ec4ae}}
body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;padding:24px 16px}
main{max-width:1200px;margin:auto} h1{margin:0 0 4px;font-size:24px} h2{font-size:17px;margin:32px 0 10px;color:var(--acc)}
.mut{color:var(--mut)} .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px} .card b{display:block;font-size:24px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%} th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)} .n{text-align:right}
.m{font-family:ui-monospace,Consolas,monospace;font-size:12.5px} .s{font-size:12.5px;word-break:break-all} .err{color:#c0392b;font-size:12px}
.sev{padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600} .high{background:#f8d7d3;color:#8c1d12}
.medium{background:#fbe7c6;color:#7a4b00} .low{background:#dde9f7;color:#1c4a7a} .info{background:#e6e6e1;color:#444}
@media print{body{background:#fff;color:#000} .wrap{overflow:visible}}
.legend{font-size:12.5px;color:var(--mut);margin:6px 0 0} .legend i{display:inline-block;width:18px;height:10px;border-radius:3px;margin:0 4px 0 12px;vertical-align:middle}
.add{color:#1e7a3c;font-weight:700} .rem{color:#b3261e;font-weight:700} .mod{color:#8a5a00;font-weight:700}
"""


def _head(title: str) -> str:
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body><main>")


def to_json(res: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(res.to_dict(), fh, ensure_ascii=False, indent=2)


def to_csv(res: ScanResult, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    files_p = os.path.join(out_dir, "files.csv")
    assets_p = os.path.join(out_dir, "assets.csv")
    find_p = os.path.join(out_dir, "findings.csv")
    with open(files_p, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["path", "category", "type", "size", "sha256", "parser", "error"])
        for f in res.files:
            w.writerow([f.path, f.category, f.file_type, f.size, f.sha256, f.parser, f.error])
    with open(assets_p, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["name", "kind", "vendor", "model", "version", "ip", "subnet", "mac", "protocols", "source"])
        for a in res.assets:
            w.writerow([a.name, a.kind, a.vendor, a.model, a.version, a.ip, a.subnet, a.mac,
                        " ".join(a.protocols), a.source])
    with open(find_p, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "rule", "message", "asset", "source"])
        for x in sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
            w.writerow([x.severity, x.rule, x.message, x.asset, x.source])
    return [files_p, assets_p, find_p]


def _e(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _human(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def to_html(res: ScanResult, path: str) -> None:
    stats = res.stats()
    findings = sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity, 9))
    sev_count = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")

    stat_rows = "".join(f"<tr><td>{_e(k)}</td><td class=n>{v}</td></tr>" for k, v in stats.items())
    asset_rows = "".join(
        f"<tr><td>{_e(a.name)}</td><td>{_e(a.kind)}</td><td>{_e(a.vendor)}</td><td>{_e(a.model)}</td>"
        f"<td>{_e(a.version)}</td><td class=m>{_e(a.ip)}</td><td class=m>{_e(a.mac)}</td>"
        f"<td>{_e(', '.join(a.protocols))}</td><td class=s>{_e(os.path.basename(a.source))}</td></tr>"
        for a in res.assets)
    find_rows = "".join(
        f"<tr><td><span class='sev {x.severity}'>{_e(x.severity)}</span></td><td class=m>{_e(x.rule)}</td>"
        f"<td>{_e(x.message)}</td><td class=s>{_e(os.path.basename(x.source))}</td></tr>" for x in findings)

    goose_rows = ""
    for f in res.files:
        for g in f.summary.get("goose", []) if isinstance(f.summary, dict) else []:
            goose_rows += (f"<tr><td>{_e(g['ied'])}</td><td>{_e(g['ld'])}/{_e(g['name'])}</td>"
                           f"<td class=m>{_e(g['APPID'])}</td><td class=m>{_e(g['MAC'])}</td>"
                           f"<td class=m>{_e(g['VLAN'])}</td><td>{_e(g['dataSet'])}</td></tr>")

    proto_rows = ""
    cmt_rows = ""
    for f in res.files:
        sm = f.summary if isinstance(f.summary, dict) else {}
        if f.category == "PCAP":
            for k, v in sm.get("protocols", {}).items():
                proto_rows += f"<tr><td>{_e(k)}</td><td class=n>{v}</td><td class=s>{_e(os.path.basename(f.path))}</td></tr>"
        if f.parser == "comtrade":
            cmt_rows += (f"<tr><td>{_e(sm.get('station'))}</td><td>{_e(sm.get('recording_device'))}</td>"
                         f"<td class=m>{_e(sm.get('trigger_time'))}</td><td class=n>{sm.get('analog_channels')}A / {sm.get('digital_channels')}D</td>"
                         f"<td class=n>{_e(sm.get('duration_s'))} s</td><td class=s>{_e(os.path.basename(f.path))}</td></tr>")

    file_rows = "".join(
        f"<tr><td class=s>{_e(f.path)}</td><td>{_e(f.category)}</td><td>{_e(f.file_type)}</td>"
        f"<td class=n>{_human(f.size)}</td><td class='m h'>{_e(f.sha256[:16])}</td>"
        f"<td class=err>{_e(f.error)}</td></tr>" for f in res.files)

    svg = build_svg(res)
    netmap = ("<h2>Network map</h2><div class=wrap style='padding:8px'>" + svg + "</div>"
              "<div class=legend><i style='border:2px solid #c0392b'></i>high finding"
              "<i style='border:2px dashed #c77700'></i>seen in capture, undocumented"
              " &nbsp;· hover a box for details</div>") if svg else ""
    doc = _head("OTInspect Report") + f"""<h1>OT Inventory Report</h1><div class=mut>Root: {_e(res.root)} · Generated {now} · OTInspect</div>
<div class=cards>
<div class=card><b>{len(res.files)}</b>files</div><div class=card><b>{len(res.assets)}</b>assets</div>
<div class=card><b>{sev_count['high']}</b>high findings</div><div class=card><b>{sev_count['medium']}</b>medium findings</div>
<div class=card><b>{sev_count['low'] + sev_count['info']}</b>low / info</div></div>
{netmap}
<h2>Asset inventory</h2><div class=wrap><table><tr><th>Name</th><th>Kind</th><th>Vendor</th><th>Model</th><th>Version</th><th>IP</th><th>MAC</th><th>Protocols</th><th>Source</th></tr>{asset_rows or '<tr><td colspan=9 class=mut>None</td></tr>'}</table></div>
<h2>Findings</h2><div class=wrap><table><tr><th>Severity</th><th>Rule</th><th>Message</th><th>Source</th></tr>{find_rows or '<tr><td colspan=4 class=mut>None</td></tr>'}</table></div>
{'<h2>GOOSE</h2><div class=wrap><table><tr><th>IED</th><th>Control block</th><th>APPID</th><th>MAC</th><th>VLAN</th><th>DataSet</th></tr>' + goose_rows + '</table></div>' if goose_rows else ''}
{'<h2>Protocols observed in captures</h2><div class=wrap><table><tr><th>Protocol</th><th class=n>Packets</th><th>Capture</th></tr>' + proto_rows + '</table></div>' if proto_rows else ''}
{'<h2>Disturbance records (COMTRADE)</h2><div class=wrap><table><tr><th>Station</th><th>Device</th><th>Trigger</th><th class=n>Channels</th><th class=n>Length</th><th>File</th></tr>' + cmt_rows + '</table></div>' if cmt_rows else ''}
<h2>File categories</h2><div class=wrap><table><tr><th>Category</th><th class=n>Files</th></tr>{stat_rows}</table></div>
<h2>All files</h2><div class=wrap><table><tr><th>Path</th><th>Category</th><th>Description</th><th class=n>Size</th><th>SHA-256</th><th>Error</th></tr>{file_rows}</table></div>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def diff_to_html(diff, path: str) -> None:
    """HTML report for an SCL diff (otinspect.diff.DiffResult)."""
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    sym = {"added": ("+", "add"), "removed": ("-", "rem"), "modified": ("~", "mod")}
    rows = "".join(
        f"<tr><td class={sym[c.kind][1]}>{sym[c.kind][0]} {c.kind}</td><td>{_e(c.scope)}</td>"
        f"<td class=m>{_e(c.key)}</td><td class=s>{_e(c.detail)}</td></tr>" for c in diff.changes)
    finds = "".join(
        f"<tr><td><span class='sev {x.severity}'>{_e(x.severity)}</span></td><td class=m>{_e(x.rule)}</td><td>{_e(x.message)}</td></tr>"
        for x in sorted(diff.findings, key=lambda x: SEV_ORDER.get(x.severity, 9)))
    c = diff.counts()
    doc = _head("SCL Diff") + f"""<h1>SCL configuration diff</h1>
<div class=mut>Old: {_e(diff.old)}<br>New: {_e(diff.new)}<br>Generated {now} · OTInspect</div>
<div class=cards><div class=card><b>{c.get('added', 0)}</b>added</div><div class=card><b>{c.get('removed', 0)}</b>removed</div>
<div class=card><b>{c.get('modified', 0)}</b>modified</div><div class=card><b>{len(diff.findings)}</b>findings</div></div>
<h2>Findings</h2><div class=wrap><table><tr><th>Severity</th><th>Rule</th><th>Message</th></tr>{finds or '<tr><td colspan=3 class=mut>None</td></tr>'}</table></div>
<h2>Changes</h2><div class=wrap><table><tr><th>Change</th><th>Scope</th><th>Item</th><th>Detail</th></tr>{rows or '<tr><td colspan=4 class=mut>No differences</td></tr>'}</table></div>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)

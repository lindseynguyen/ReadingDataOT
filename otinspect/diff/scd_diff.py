"""Compare two SCL files (typically two SCD revisions handed over by an integrator).

Reports what changed per IED, communication address, GOOSE/SV control block and
DataSet, and flags changes that commonly break a substation:
- DataSet content changed but the control block confRev was not incremented
  (subscribers keep accepting the old layout -> wrong signals mapped)
- APPID / destination MAC / VLAN changed (subscribers stop receiving)
- configuration changed but the Header version/revision did not
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..core.identify import identify
from ..core.model import FileRecord, Finding
from ..core.scanner import analyze_file
from ..core.registry import load_builtin

ASSET_FIELDS = ("vendor", "model", "version", "ip", "subnet", "mac")


@dataclass
class Change:
    kind: str          # added | removed | modified
    scope: str         # Header, IED, GOOSE, SV, DataSet, SubNetwork
    key: str
    detail: str = ""


@dataclass
class DiffResult:
    old: str
    new: str
    changes: list[Change] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in self.changes:
            out[c.kind] = out.get(c.kind, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "old": self.old, "new": self.new, "counts": self.counts(),
            "changes": [c.__dict__ for c in self.changes],
            "findings": [f.__dict__ for f in self.findings],
        }


def _load(path: str) -> FileRecord:
    load_builtin()
    if identify(path).category != "SCL":
        raise ValueError(f"{path} is not an SCL file")
    rec = analyze_file(path)
    if rec.error:
        raise ValueError(f"{path}: {rec.error}")
    return rec


def _cb_index(rec: FileRecord, key: str) -> dict[str, dict]:
    return {f"{g['ied']}/{g['ld']}/{g['name']}": g for g in rec.summary.get(key, [])}


def diff_scl(old_path: str, new_path: str) -> DiffResult:
    a, b = _load(old_path), _load(new_path)
    res = DiffResult(old=os.path.abspath(old_path), new=os.path.abspath(new_path))
    ch = res.changes
    src = res.new

    # ---- header
    for k in ("header_id", "header_version", "header_revision", "tool_id", "scl_version"):
        if a.summary.get(k) != b.summary.get(k):
            ch.append(Change("modified", "Header", k, f"{a.summary.get(k)!r} -> {b.summary.get(k)!r}"))

    # ---- subnetworks
    sa = {s["name"]: s for s in a.summary.get("subnetworks", [])}
    sb = {s["name"]: s for s in b.summary.get("subnetworks", [])}
    for n in sorted(sb.keys() - sa.keys()):
        ch.append(Change("added", "SubNetwork", n, sb[n].get("type", "")))
    for n in sorted(sa.keys() - sb.keys()):
        ch.append(Change("removed", "SubNetwork", n, sa[n].get("type", "")))

    # ---- IEDs
    ia = {x.name: x for x in a.assets}
    ib = {x.name: x for x in b.assets}
    for n in sorted(ib.keys() - ia.keys()):
        x = ib[n]
        ch.append(Change("added", "IED", n, f"{x.vendor} {x.model} {x.ip}".strip()))
    for n in sorted(ia.keys() - ib.keys()):
        x = ia[n]
        ch.append(Change("removed", "IED", n, f"{x.vendor} {x.model} {x.ip}".strip()))
    for n in sorted(ia.keys() & ib.keys()):
        x, y = ia[n], ib[n]
        for f in ASSET_FIELDS:
            if getattr(x, f) != getattr(y, f):
                ch.append(Change("modified", "IED", n, f"{f}: {getattr(x, f)!r} -> {getattr(y, f)!r}"))
        if x.extra.get("gateway") != y.extra.get("gateway"):
            ch.append(Change("modified", "IED", n, f"gateway: {x.extra.get('gateway')!r} -> {y.extra.get('gateway')!r}"))
        lda = {d["inst"]: set(d["lns"]) for d in x.extra.get("ldevices", [])}
        ldb = {d["inst"]: set(d["lns"]) for d in y.extra.get("ldevices", [])}
        for ld in sorted(ldb.keys() - lda.keys()):
            ch.append(Change("added", "LDevice", f"{n}/{ld}", f"{len(ldb[ld])} LNs"))
        for ld in sorted(lda.keys() - ldb.keys()):
            ch.append(Change("removed", "LDevice", f"{n}/{ld}", f"{len(lda[ld])} LNs"))
        for ld in sorted(lda.keys() & ldb.keys()):
            plus, minus = sorted(ldb[ld] - lda[ld]), sorted(lda[ld] - ldb[ld])
            if plus or minus:
                ch.append(Change("modified", "LDevice", f"{n}/{ld}",
                                 f"LN added: {', '.join(plus) or '-'}; LN removed: {', '.join(minus) or '-'}"))

    # ---- DataSets
    da, db = a.summary.get("datasets", {}), b.summary.get("datasets", {})
    ds_changed = set()
    for k in sorted(db.keys() - da.keys()):
        ch.append(Change("added", "DataSet", k, f"{len(db[k])} members"))
    for k in sorted(da.keys() - db.keys()):
        ch.append(Change("removed", "DataSet", k, f"{len(da[k])} members"))
    for k in sorted(da.keys() & db.keys()):
        if da[k] != db[k]:
            ds_changed.add(k)
            plus = [m for m in db[k] if m not in da[k]]
            minus = [m for m in da[k] if m not in db[k]]
            order = "" if plus or minus else " (order only)"
            ch.append(Change("modified", "DataSet", k,
                             f"+{len(plus)} -{len(minus)}{order}: " + "; ".join(["+" + m for m in plus[:5]] + ["-" + m for m in minus[:5]])))

    # ---- GOOSE / SV control blocks
    for key, scope in (("goose", "GOOSE"), ("smv", "SV")):
        ca, cb = _cb_index(a, key), _cb_index(b, key)
        for k in sorted(cb.keys() - ca.keys()):
            ch.append(Change("added", scope, k, f"APPID {cb[k].get('APPID')} MAC {cb[k].get('MAC')}"))
        for k in sorted(ca.keys() - cb.keys()):
            ch.append(Change("removed", scope, k, f"APPID {ca[k].get('APPID')} MAC {ca[k].get('MAC')}"))
            res.findings.append(Finding("medium", f"DIFF-{scope}-REMOVED",
                                        f"{scope} {k} was removed; check every subscriber still has a source", src))
        for k in sorted(ca.keys() & cb.keys()):
            x, y = ca[k], cb[k]
            fields = ("APPID", "MAC", "VLAN", "dataSet", "confRev", "appID", "smvID", "smpRate", "VLAN_prio")
            diffs = [f for f in fields if f in x and x.get(f) != y.get(f)]
            for f in diffs:
                ch.append(Change("modified", scope, k, f"{f}: {x.get(f)!r} -> {y.get(f)!r}"))
            addr = [f for f in diffs if f in ("APPID", "MAC", "VLAN")]
            if addr:
                res.findings.append(Finding("medium", f"DIFF-{scope}-ADDR-CHANGED",
                                            f"{scope} {k} changed {', '.join(addr)}; subscribers must be re-configured", src))
            ied, ld = k.split("/")[:2]
            ds_key = f"{ied}/{ld}/{y.get('dataSet', '')}"
            if (ds_key in ds_changed or "dataSet" in diffs) and "confRev" not in diffs:
                res.findings.append(Finding("high", f"DIFF-{scope}-CONFREV",
                                            f"{scope} {k}: DataSet changed but confRev stayed {y.get('confRev')!r}", src))

    if ch and not any(c.scope == "Header" and c.key in ("header_version", "header_revision") for c in ch):
        res.findings.append(Finding("low", "DIFF-HEADER-NOT-BUMPED",
                                    "Configuration changed but Header version/revision did not", src))
    from ..standards import annotate
    annotate(res.findings)
    return res


def diff_text(res: DiffResult) -> str:
    lines = [f"OLD: {res.old}", f"NEW: {res.new}", ""]
    if not res.changes:
        lines.append("No differences.")
    sym = {"added": "+", "removed": "-", "modified": "~"}
    for c in res.changes:
        lines.append(f"{sym[c.kind]} [{c.scope:<10}] {c.key}  {c.detail}")
    if res.findings:
        lines.append("")
        for f in sorted(res.findings, key=lambda f: ("high", "medium", "low", "info").index(f.severity)):
            lines.append(f"[{f.severity.upper():<6}] {f.rule:<24} {f.message}")
    return "\n".join(lines)

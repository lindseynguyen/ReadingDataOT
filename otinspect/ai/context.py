"""Build the (minimised, pseudonymised) scan context that is sent to the model."""
from __future__ import annotations

import json

from ..core.model import Asset, FileRecord, Finding, ScanResult
from .redact import Redactor

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_ASSET_KEYS = ("kind", "vendor", "model", "version", "protocols")


def load_report(path: str) -> ScanResult:
    """Rebuild a ScanResult from a JSON report written by ``otinspect scan --json``."""
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    if not isinstance(d, dict) or "files" not in d:
        raise ValueError(f"{path} is not an OTInspect JSON report")
    res = ScanResult(root=d.get("root", ""), warnings=list(d.get("warnings", [])))
    for f in d["files"]:
        rec = FileRecord(path=f.get("path", ""), size=f.get("size", 0), sha256=f.get("sha256", ""),
                         category=f.get("category", ""), file_type=f.get("file_type", ""),
                         parser=f.get("parser", ""), summary=f.get("summary", {}) or {}, error=f.get("error", ""))
        rec.assets = [Asset(**{k: v for k, v in a.items() if k in Asset.__dataclass_fields__})
                      for a in f.get("assets", [])]
        rec.findings = [Finding(**{k: v for k, v in x.items() if k in Finding.__dataclass_fields__})
                        for x in f.get("findings", [])]
        res.files.append(rec)
    return res


def build_context(res: ScanResult, profile, focus: Finding | None = None) -> tuple[str, Redactor, dict]:
    """Return (JSON text for the prompt, redactor holding the token map, stats)."""
    red = Redactor.from_profile(profile)
    assets = res.assets
    red.add_names([a.name for a in assets])
    red.add_names([x.asset for x in res.findings])

    findings = sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity, 9))
    if focus is not None:
        findings = [focus] + [x for x in findings if x is not focus]
    kept_f = findings[: max(0, int(profile.max_findings))]
    # assets referenced by kept findings first, then the rest
    named = {x.asset for x in kept_f}
    assets = sorted(assets, key=lambda a: (a.name not in named, a.kind, a.name))
    kept_a = assets[: max(0, int(profile.max_assets))]

    by_sev: dict[str, int] = {}
    for x in res.findings:
        by_sev[x.severity] = by_sev.get(x.severity, 0) + 1
    protos = sorted({p for a in res.assets for p in a.protocols})

    data = {
        "scan": {
            "files": len(res.files),
            "categories": res.stats(),
            "assets": len(res.assets),
            "findings_by_severity": by_sev,
            "protocols_seen": protos,
            "parse_errors": sum(1 for f in res.files if f.error),
            "truncated": {"findings_sent": len(kept_f), "findings_total": len(res.findings),
                          "assets_sent": len(kept_a), "assets_total": len(res.assets)},
        },
        "findings": [{
            "severity": x.severity, "rule": x.rule,
            "message": red.text(x.message),
            "asset": red.name(x.asset) if x.asset else "",
            "source": red.path(x.source) if x.source else "",
            "iec62443_3_3": x.iec62443, "attack_ics": x.attack,
        } for x in kept_f],
        "assets": [{
            "name": red.name(a.name),
            **{k: getattr(a, k) for k in _ASSET_KEYS},
            "ip": red.text(a.ip), "subnet": red.text(a.subnet), "mac": red.text(a.mac),
            "source": red.path(a.source) if a.source else "",
        } for a in kept_a],
    }
    if focus is not None:
        data["focus_finding"] = data["findings"][0] if data["findings"] else {}
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    limit = int(profile.max_prompt_chars)
    while len(text) > limit and (data["findings"] or data["assets"]):
        # shrink from the low-value end until it fits
        if len(data["assets"]) > len(data["findings"]) // 2 and data["assets"]:
            data["assets"].pop()
        elif data["findings"]:
            data["findings"].pop()
        data["scan"]["truncated"].update(findings_sent=len(data["findings"]), assets_sent=len(data["assets"]))
        text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    stats = {"chars": len(text), "findings_sent": len(data["findings"]), "assets_sent": len(data["assets"]),
             "masked": red.summary(), "root_sent": False}
    return text, red, stats


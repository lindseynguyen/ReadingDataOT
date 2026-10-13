"""Exports for other tools.

- SARIF 2.1.0: upload to GitHub code scanning (or any SARIF viewer) so findings
  on a configuration repository show up as alerts on the files that cause them.
- CycloneDX 1.6 JSON: hardware/firmware bill of materials of the discovered
  assets (devices with their firmware as nested components), the analysed
  engineering files with SHA-256 hashes, and advisory matches as vulnerabilities.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import uuid

from .. import __version__
from ..core.model import ScanResult
from ..standards import attack_title, sr_title

REPO_URL = "https://github.com/lindseynguyen/ReadingDataOT"
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
BOM_FILE_CATEGORIES = {"SCL", "PLC", "NetConfig", "DeviceDesc", "Firmware", "COMTRADE", "HMI", "IED"}


def _rel(path: str, root: str) -> str:
    path = path.split("!", 1)[0]                     # archive member -> the archive itself
    base = root if os.path.isdir(root) else os.path.dirname(root)
    try:
        rel = os.path.relpath(os.path.abspath(path), base)
    except ValueError:                               # different drive on Windows
        rel = path
    return rel.replace(os.sep, "/")


# ------------------------------------------------------------------ SARIF
def to_sarif(res: ScanResult, path: str) -> None:
    rules: dict[str, dict] = {}
    index: dict[str, int] = {}
    results = []
    for f in res.files:
        for x in f.findings:
            if x.rule not in rules:
                tags = ["security", "ot-ics"] + [f"IEC62443-3-3/{s.replace(' ', '')}" for s in x.iec62443] \
                    + [f"external/mitre-attack-ics/{t}" for t in x.attack]
                help_lines = [f"- {s}: {sr_title(s)}" for s in x.iec62443] + \
                             [f"- ATT&CK for ICS {t}: {attack_title(t)}" for t in x.attack]
                rules[x.rule] = {
                    "id": x.rule, "name": x.rule.title().replace("-", ""),
                    "shortDescription": {"text": x.rule},
                    "fullDescription": {"text": x.message[:1000]},
                    "help": {"text": "\n".join(help_lines) or x.rule,
                             "markdown": "\n".join(help_lines) or x.rule},
                    "helpUri": f"{REPO_URL}#risk-rules",
                    "defaultConfiguration": {"level": SARIF_LEVEL.get(x.severity, "note")},
                    "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY.get(x.severity, "1.0")},
                }
                index[x.rule] = len(index)
            src = x.source or f.path
            uri = _rel(src, res.root)
            fp = hashlib.sha256(f"{x.rule}|{uri}|{x.asset}|{x.message}".encode("utf-8", "replace")).hexdigest()
            results.append({
                "ruleId": x.rule,
                "ruleIndex": index[x.rule],
                "level": SARIF_LEVEL.get(x.severity, "note"),
                "message": {"text": x.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "SRCROOT"},
                                                    "region": {"startLine": 1}}}],
                "partialFingerprints": {"otinspect/v1": fp[:32]},
                "properties": {"severity": x.severity, "asset": x.asset, "member": src.split("!", 1)[1] if "!" in src else "",
                               "iec62443": x.iec62443, "attack": x.attack},
            })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OTInspect", "version": __version__, "semanticVersion": __version__,
                                "informationUri": REPO_URL, "rules": list(rules.values())}},
            "originalUriBaseIds": {"SRCROOT": {"description": {"text": "Scanned folder"}}},
            "results": results,
            "properties": {"scannedRoot": os.path.basename(os.path.normpath(res.root)), "files": len(res.files)},
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------ CycloneDX
def _props(**kw) -> list[dict]:
    return [{"name": f"otinspect:{k}", "value": str(v)} for k, v in kw.items() if v not in ("", None, [], {})]


def to_cyclonedx(res: ScanResult, path: str) -> None:
    components, refs = [], {}
    seen: dict[tuple, str] = {}
    for a in res.assets:
        key = (a.name, a.kind, a.vendor, a.model, a.version, a.ip)
        if key in seen:
            continue
        ref = f"asset-{len(seen) + 1}"
        seen[key] = ref
        refs.setdefault(a.name, ref)
        comp = {
            "type": "device", "bom-ref": ref, "name": a.name or a.ip or "unnamed",
            "description": " ".join(x for x in (a.kind, a.model) if x),
            "properties": _props(kind=a.kind, model=a.model, ip=a.ip, subnet=a.subnet, mac=a.mac,
                                 protocols=", ".join(a.protocols), source=_rel(a.source, res.root) if a.source else ""),
        }
        if a.vendor:
            comp["manufacturer"] = {"name": a.vendor}
        if a.version:
            comp["components"] = [{
                "type": "firmware", "bom-ref": f"{ref}-fw", "name": f"{a.model or a.name} firmware/configuration",
                "version": a.version, **({"manufacturer": {"name": a.vendor}} if a.vendor else {}),
            }]
        components.append(comp)
    for f in res.files:
        if f.category in BOM_FILE_CATEGORIES and f.sha256:
            components.append({
                "type": "file", "bom-ref": f"file-{f.sha256[:16]}", "name": _rel(f.path, res.root),
                "hashes": [{"alg": "SHA-256", "content": f.sha256}],
                "properties": _props(category=f.category, file_type=f.file_type, size=f.size),
            })
    # de-duplicate file components (same content in several places)
    uniq, done = [], set()
    for c in components:
        if c["bom-ref"] in done:
            continue
        done.add(c["bom-ref"])
        uniq.append(c)

    vulns = []
    for x in res.findings:
        if x.rule.startswith("ADV-") and x.asset in refs:
            vulns.append({
                "id": x.rule[4:], "source": {"name": "CISA ICS advisory (CSAF)"},
                "description": x.message[:2000],
                "analysis": {"state": "in_triage", "detail": "Possible match by vendor/product/version; verify"},
                "affects": [{"ref": refs[x.asset]}],
            })
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "OTInspect", "version": __version__,
                                      "externalReferences": [{"type": "vcs", "url": REPO_URL}]}]},
            "component": {"type": "data", "bom-ref": "scan", "name": os.path.basename(os.path.normpath(res.root)) or "scan",
                          "description": "OT/ICS file set analysed by OTInspect (offline)"},
        },
        "components": uniq,
    }
    if vulns:
        doc["vulnerabilities"] = vulns
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)

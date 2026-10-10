"""Offline matching of discovered assets against ICS security advisories.

Import CSAF 2.0 advisories (e.g. CISA's ICS advisories from
https://github.com/cisagov/CSAF -> csaf_files/OT/white/<year>/*.json) into a
compact JSON database once, on a connected machine:

    otinspect advisories import path/to/csaf_files -o advisories.json

then copy advisories.json to the offline workstation and scan with
    otinspect scan D:\\Backup --advisories advisories.json

Matching is heuristic (vendor + product name + version range), so results are
reported as *possible* matches to verify, never as confirmed vulnerabilities.
"""
from __future__ import annotations

import glob
import json
import os
import re
from typing import Iterable

from ..core.model import Finding, ScanResult
from .engine import version_key

_NORM = re.compile(r"[^a-z0-9]+")
VENDOR_ALIASES = {
    "allen-bradley": "rockwell", "rockwell automation": "rockwell", "schweitzer": "sel",
    "schweitzer engineering laboratories": "sel", "schneider electric": "schneider",
    "general electric": "ge", "ge vernova": "ge", "hitachi energy": "hitachi", "abb": "abb",
}


def _n(s: str) -> str:
    return _NORM.sub("", (s or "").lower())


def _vendor_key(v: str) -> str:
    low = (v or "").lower().strip()
    for k, alias in VENDOR_ALIASES.items():
        if k in low:
            return alias
    return _n(low.split()[0]) if low.split() else ""


# ------------------------------------------------------------------ CSAF import
def _iter_csaf_files(paths: Iterable[str]):
    for p in paths:
        if os.path.isdir(p):
            yield from sorted(glob.glob(os.path.join(p, "**", "*.json"), recursive=True))
        else:
            yield p


def _severity(score: float | None) -> str:
    if score is None:
        return "medium"
    return "high" if score >= 7.0 else "medium" if score >= 4.0 else "low"


def import_csaf(paths: list[str]) -> tuple[list[dict], int, list[str]]:
    """Returns (entries, files_read, errors)."""
    entries, errors, n = [], [], 0
    for f in _iter_csaf_files(paths):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as e:
            errors.append(f"{f}: {e}")
            continue
        doc = d.get("document") if isinstance(d, dict) else None
        if not doc or "product_tree" not in d:
            continue                      # not a CSAF advisory (e.g. feed index)
        n += 1
        adv_id = doc.get("tracking", {}).get("id", os.path.basename(f))
        title = doc.get("title", "")
        url = ""
        for r in doc.get("references", []):
            if r.get("category") == "self":
                url = r.get("url", "")
                break
        scores, cves = [], []
        for v in d.get("vulnerabilities", []):
            if v.get("cve"):
                cves.append(v["cve"])
            for s in v.get("scores", []):
                for key in ("cvss_v4", "cvss_v3"):
                    bs = s.get(key, {}).get("baseScore")
                    if bs is not None:
                        scores.append(float(bs))
        cvss = max(scores) if scores else None

        def walk(branches, vendor="", product=""):
            for b in branches or []:
                cat, name = b.get("category"), b.get("name", "")
                if cat == "vendor":
                    walk(b.get("branches"), name, product)
                elif cat in ("product_name", "product_family"):
                    walk(b.get("branches"), vendor, f"{product} {name}".strip())
                elif cat in ("product_version_range", "product_version"):
                    entries.append({"id": adv_id, "title": title, "vendor": vendor, "product": product,
                                    "range": name if cat == "product_version_range" else f"={name}",
                                    "cves": cves[:20], "cvss": cvss, "url": url})
                else:
                    walk(b.get("branches"), vendor, product)
        walk(d["product_tree"].get("branches"))
    return entries, n, errors


def save_db(entries: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"format": "otinspect-advisories/1", "count": len(entries), "entries": entries}, fh,
                  ensure_ascii=False, indent=0)


def load_db(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    return d.get("entries", []) if isinstance(d, dict) else d


# ------------------------------------------------------------------ matching
def in_range(version: str, rng: str) -> bool | None:
    """True/False if decidable, None if the range or version cannot be compared."""
    rng = (rng or "").strip()
    if rng.startswith("vers:"):
        rng = rng.split("/", 1)[1] if "/" in rng else ""
    if rng in ("*", ""):
        return True
    if not version_key(version):
        return None
    result = True
    for cond in rng.split("|"):
        cond = cond.strip()
        m = re.match(r"^(<=|>=|<|>|=|==)?\s*(.+)$", cond)
        if not m:
            return None
        op, ref = m.group(1) or "=", m.group(2)
        kr, kv = version_key(ref), version_key(version)
        if not kr or re.search(r"[A-Za-z]{3,}", ref.replace("Update", "").lstrip("Vv")):
            return None                     # date-like or textual bound
        n = max(len(kr), len(kv))
        a, b = kv + (0,) * (n - len(kv)), kr + (0,) * (n - len(kr))
        ok = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "=": a == b, "==": a == b}[op]
        result = result and ok
    return result


def _product_match(asset_model: str, asset_name: str, product: str) -> bool:
    p = _n(product)
    if not p:
        return False
    for cand in (asset_model, asset_name):
        c = _n(cand)
        if len(c) >= 4 and (c in p or (len(p) >= 4 and p in c)):
            return True
    return False


def match_assets(res: ScanResult, entries: list[dict]) -> int:
    by_vendor: dict[str, list[dict]] = {}
    for e in entries:
        by_vendor.setdefault(_vendor_key(e["vendor"]), []).append(e)
    added = 0
    for f in res.files:
        for a in f.assets:
            vk = _vendor_key(a.vendor)
            if not vk:
                continue
            cands = by_vendor.get(vk, [])
            hit_ids = set()
            for e in cands:
                if e["id"] in hit_ids or not _product_match(a.model, a.name, e["product"]):
                    continue
                verdict = in_range(a.version, e["range"])
                if verdict is False:
                    continue
                hit_ids.add(e["id"])
                cves = ", ".join(e.get("cves", [])[:3]) + (" …" if len(e.get("cves", [])) > 3 else "")
                if verdict:
                    sev = _severity(e.get("cvss"))
                    why = f"version {a.version or '(any)'} in affected range {e['range']}"
                else:
                    sev = "info"
                    why = f"version {a.version or 'unknown'} could not be compared with {e['range']}; verify"
                f.findings.append(Finding(
                    sev, f"ADV-{e['id']}",
                    f"Possible match: {a.name} ({a.vendor} {a.model}) vs {e['id']} '{e['title']}' [{e['product']}]: "
                    f"{why}. {cves} {e.get('url', '')}".strip(), f.path, a.name))
                added += 1
    return added

"""User-defined rules (YAML or JSON) evaluated against assets and files.

Rule file format (YAML shown; JSON with the same structure also works):

    rules:
      - id: SITE-OLD-SIEMENS-FW
        severity: medium            # high | medium | low | info
        target: asset               # asset | file
        message: "{name} runs {model} firmware {version}"
        match:                      # every condition must hold
          vendor: {regex: "(?i)siemens"}
          model:  {regex: "^7UT8"}
          version: {lt: "8.50"}
          ip:     {in_cidr: ["10.10.0.0/16"]}

Condition operators: eq, ne, regex, not_regex, contains, in, not_in, exists,
lt, le, gt, ge (version-aware: "V08.40" < "8.50" < "8.50.1"),
num_lt, num_le, num_gt, num_ge (plain numbers), in_cidr.
Fields: any Asset/FileRecord attribute, plus extra.<key> and summary.<key>.
"""
from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
from typing import Any

from ..core.model import Finding, ScanResult

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

BUILTIN_DIR = os.path.dirname(os.path.abspath(__file__))
SEVERITIES = ("high", "medium", "low", "info")
_NUM = re.compile(r"\d+")


def version_key(v: Any) -> tuple:
    """'V08.40' -> (8, 40); 'R125' -> (125,); '2.2.5' -> (2, 2, 5)."""
    return tuple(int(x) for x in _NUM.findall(str(v)))


def _cmp(a: Any, b: Any) -> int:
    ka, kb = version_key(a), version_key(b)
    if not ka or not kb:
        raise ValueError
    n = max(len(ka), len(kb))
    ka, kb = ka + (0,) * (n - len(ka)), kb + (0,) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _get(obj: Any, field: str) -> Any:
    cur = obj
    for part in field.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
        if cur is None:
            return None
    return cur


def _check(value: Any, cond: Any) -> bool:
    if not isinstance(cond, dict):
        cond = {"eq": cond}
    sval = "" if value is None else (", ".join(map(str, value)) if isinstance(value, (list, set)) else str(value))
    for op, arg in cond.items():
        try:
            if op == "eq" and sval != str(arg):
                return False
            if op == "ne" and sval == str(arg):
                return False
            if op == "regex" and not re.search(arg, sval):
                return False
            if op == "not_regex" and re.search(arg, sval):
                return False
            if op == "contains":
                items = value if isinstance(value, (list, set)) else [sval]
                if not any(str(arg).lower() in str(i).lower() for i in items):
                    return False
            if op == "in" and sval not in [str(x) for x in arg]:
                return False
            if op == "not_in" and sval in [str(x) for x in arg]:
                return False
            if op == "exists" and bool(sval) != bool(arg):
                return False
            if op in ("lt", "le", "gt", "ge"):
                if not sval:
                    return False
                c = _cmp(sval, arg)
                if not {"lt": c < 0, "le": c <= 0, "gt": c > 0, "ge": c >= 0}[op]:
                    return False
            if op in ("num_lt", "num_le", "num_gt", "num_ge"):
                c = float(sval) - float(arg)
                if not {"num_lt": c < 0, "num_le": c <= 0, "num_gt": c > 0, "num_ge": c >= 0}[op]:
                    return False
            if op == "in_cidr":
                nets = [arg] if isinstance(arg, str) else arg
                ip = ipaddress.ip_address(sval)
                if not any(ip in ipaddress.ip_network(n, strict=False) for n in nets):
                    return False
        except (ValueError, re.error, TypeError):
            return False
    return True


_PLACEHOLDER = re.compile(r"\{([A-Za-z_][\w.]*)\}")


def _format(template: str, obj: Any) -> str:
    """Replace {field} / {summary.key} / {extra.key}; unknown placeholders stay as-is."""
    def rep(m):
        v = _get(obj, m.group(1))
        if v is None:
            return m.group(0)
        return ", ".join(map(str, v)) if isinstance(v, (list, set, tuple)) else str(v)
    return _PLACEHOLDER.sub(rep, template)


def load_rules(paths: list[str] | None = None, include_builtin: bool = True) -> tuple[list[dict], list[str]]:
    """Returns (rules, warnings)."""
    files: list[str] = []
    if include_builtin:
        files += sorted(glob.glob(os.path.join(BUILTIN_DIR, "*.yaml")) + glob.glob(os.path.join(BUILTIN_DIR, "*.json")))
    for p in paths or []:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.y*ml")) + glob.glob(os.path.join(p, "*.json")))
        else:
            files.append(p)
    rules, warns = [], []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                if f.lower().endswith((".yaml", ".yml")):
                    if yaml is None:
                        warns.append(f"{f}: PyYAML not installed, skipped (pip install pyyaml)")
                        continue
                    doc = yaml.safe_load(fh)
                else:
                    doc = json.load(fh)
        except Exception as e:
            warns.append(f"{f}: {e}")
            continue
        items = doc.get("rules", []) if isinstance(doc, dict) else (doc or [])
        for i, r in enumerate(items):
            if not isinstance(r, dict) or not r.get("id") or not isinstance(r.get("match"), dict):
                warns.append(f"{f}: rule #{i + 1} needs 'id' and 'match'")
                continue
            if r.get("severity", "medium") not in SEVERITIES:
                warns.append(f"{f}: rule {r['id']} has invalid severity")
                continue
            r.setdefault("target", "asset")
            r["_file"] = f
            rules.append(r)
    return rules, warns


def apply_rules(res: ScanResult, rules: list[dict]) -> int:
    added = 0
    for f in res.files:
        for r in rules:
            targets = f.assets if r["target"] == "asset" else [f] if r["target"] == "file" else []
            for obj in targets:
                if all(_check(_get(obj, k), c) for k, c in r["match"].items()):
                    msg = _format(str(r.get("message", r["id"])), obj)
                    if r.get("url"):
                        msg += f" ({r['url']})"
                    f.findings.append(Finding(r.get("severity", "medium"), r["id"], msg, f.path,
                                              getattr(obj, "name", "") if r["target"] == "asset" else ""))
                    added += 1
    return added

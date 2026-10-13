"""Map finding rules to IEC 62443-3-3 system requirements (SR) and MITRE ATT&CK
for ICS techniques, so a report can be read against the standard an auditor uses.

Mappings live in mappings.json (rule id or glob pattern -> SR list / technique
list). User rules can set their own "iec62443" / "attack" lists; those win.
The mapping is guidance for prioritising and reporting, not a compliance verdict.
"""
from __future__ import annotations

import fnmatch
import json
import os
from functools import lru_cache
from typing import Iterable

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


@lru_cache(maxsize=1)
def _db() -> dict:
    with open(os.path.join(HERE, "mappings.json"), encoding="utf-8") as fh:
        return json.load(fh)


def lookup(rule: str) -> dict:
    """{'iec62443': [...], 'attack': [...]} for a rule id ({} lists if unmapped)."""
    rules = _db()["rules"]
    if rule in rules:
        return rules[rule]
    best, score = None, -1
    for pat, m in rules.items():
        if "*" in pat and fnmatch.fnmatchcase(rule, pat):
            s = len(pat.replace("*", ""))
            if s > score:
                best, score = m, s
    return best or {"iec62443": [], "attack": []}


def annotate(findings: Iterable) -> None:
    """Fill Finding.iec62443 / Finding.attack where they are empty."""
    for f in findings:
        m = lookup(f.rule)
        if not f.iec62443:
            f.iec62443 = list(m.get("iec62443", []))
        if not f.attack:
            f.attack = list(m.get("attack", []))


def sr_title(sr: str) -> str:
    return _db()["iec62443_3_3"].get(sr, "")


def attack_title(tid: str) -> str:
    return _db()["attack_ics"].get(tid, "")


def attack_url(tid: str) -> str:
    return ATTACK_URL.format(tid.replace(".", "/"))


def sr_key(sr: str) -> tuple:
    try:
        return tuple(int(x) for x in sr.split()[1].split("."))
    except (IndexError, ValueError):
        return (99,)

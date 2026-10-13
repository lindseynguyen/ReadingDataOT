"""Checks on public real-world OT/ICS files (captures from real PLCs/RTUs, SCL
from OpenSCD, COMTRADE from python-comtrade). Files are fetched on demand with
tests/realworld/fetch.py; tests are skipped when they are not present, unless
OTINSPECT_REALWORLD=require (used in CI)."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "realworld"))

from fetch import local_path  # noqa: E402
from otinspect.core.scanner import scan  # noqa: E402

with open(os.path.join(ROOT, "tests", "realworld", "manifest.json"), encoding="utf-8") as _fh:
    FILES = json.load(_fh)["files"]
REQUIRE = os.environ.get("OTINSPECT_REALWORLD") == "require"


@pytest.mark.parametrize("entry", FILES, ids=[os.path.basename(e["path"]) for e in FILES])
def test_realworld(entry):
    path = local_path(entry)
    if not os.path.exists(path):
        if REQUIRE:
            pytest.fail(f"missing {path}: run python tests/realworld/fetch.py")
        pytest.skip("real-world sample not downloaded (python tests/realworld/fetch.py)")
    exp = entry["expect"]
    rec = scan(path).files[0]
    assert rec.category == exp["category"], rec.file_type
    assert not rec.error, rec.error
    rules = {f.rule for f in rec.findings}
    cmds = {f"{c['protocol']} {c['command']}" for c in rec.summary.get("ot_commands", [])}
    names = {a.name for a in rec.assets}
    for c in exp.get("commands", []):
        assert c in cmds, f"{c} not decoded; got {sorted(cmds)}"
    for r in exp.get("rules", []):
        assert r in rules, f"{r} not raised; got {sorted(rules)}"
    for r in exp.get("no_rules", []):
        assert r not in rules, f"unexpected {r}"
    for n in exp.get("assets", []):
        assert n in names, f"asset {n} missing; got {sorted(names)}"
    assert len(rec.assets) >= exp.get("min_assets", 0)
    for k, v in exp.get("summary", {}).items():
        assert rec.summary.get(k) == v, (k, rec.summary.get(k))
    for f in rec.findings:                       # every built-in finding is mapped
        if not f.rule.startswith(("ADV-", "CMT-", "FILE-")):
            assert f.iec62443, f"{f.rule} has no IEC 62443 mapping"

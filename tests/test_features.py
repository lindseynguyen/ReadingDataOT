"""Tests for diff, network map, rules engine, advisories and IEC/AML parsers."""
import json
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from otinspect.cli import main as cli  # noqa: E402
from otinspect.core.model import Asset, FileRecord, ScanResult  # noqa: E402
from otinspect.core.scanner import scan  # noqa: E402
from otinspect.diff import diff_scl  # noqa: E402
from otinspect.report.netmap import build_svg  # noqa: E402
from otinspect.rules.advisories import import_csaf, in_range, match_assets  # noqa: E402
from otinspect.rules.engine import _check, apply_rules, load_rules, version_key  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "samples")


# ---------------------------------------------------------------- diff
def test_diff_detects_integrator_changes():
    d = diff_scl(os.path.join(S, "substation_demo.scd"), os.path.join(S, "substation_demo_v2.scd"))
    keys = {(c.scope, c.key) for c in d.changes}
    assert ("IED", "F21_Q02") in keys and ("DataSet", "F87T_Q01/PROT/dsTrip") in keys
    rules = {f.rule for f in d.findings}
    assert {"DIFF-GOOSE-CONFREV", "DIFF-GOOSE-ADDR-CHANGED", "DIFF-HEADER-NOT-BUMPED"} <= rules


def test_diff_identical_is_empty():
    p = os.path.join(S, "substation_demo.scd")
    d = diff_scl(p, p)
    assert d.changes == [] and d.findings == []


def test_diff_rejects_non_scl():
    try:
        diff_scl(os.path.join(S, "rtu_gateway.log"), os.path.join(S, "substation_demo.scd"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_cli_diff_exit_code():
    a, b = os.path.join(S, "substation_demo.scd"), os.path.join(S, "substation_demo_v2.scd")
    out = tempfile.mkdtemp()
    assert cli(["diff", a, b, "--html", os.path.join(out, "d.html"), "--json", os.path.join(out, "d.json"),
                "--fail-on", "high"]) == 2
    assert cli(["diff", a, a, "--fail-on", "low"]) == 0
    assert json.load(open(os.path.join(out, "d.json")))["counts"]["modified"] >= 4


# ---------------------------------------------------------------- netmap
def test_netmap_svg_groups_and_flags():
    res = scan(S)
    svg = build_svg(res)
    assert svg.startswith("<svg") and "StationBus" in svg
    assert "nm-undoc" in svg and "nm-risk" in svg
    assert build_svg(ScanResult(root=".")) == ""


def test_netmap_escapes_names():
    r = ScanResult(root=".", files=[FileRecord(path="x.scd", size=0, sha256="", category="SCL",
                                               assets=[Asset(name="<script>x</script>", ip="10.0.0.1")])])
    assert "<script>" not in build_svg(r)


# ---------------------------------------------------------------- rules
def test_version_key_and_ops():
    assert version_key("V08.40") == (8, 40) and version_key("R125") == (125,)
    assert _check("V08.40", {"lt": "8.50"}) and not _check("8.60", {"lt": "8.50"})
    assert _check("2.2.5", {"gt": "2.2"}) and _check("10.10.1.5", {"in_cidr": ["10.10.0.0/16"]})
    assert not _check("garbage", {"in_cidr": "10.0.0.0/8"})
    assert _check(7.9, {"num_ge": 7.5}) and not _check(7.45, {"num_ge": 7.5})
    assert _check(["GOOSE", "MMS"], {"contains": "goose"})
    assert not _check("", {"lt": "1.0"})


def test_custom_rule_file_yaml_and_json():
    import pytest
    pytest.importorskip("yaml")
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "site.yaml"), "w") as fh:
        fh.write("rules:\n  - id: SITE-SIEMENS-OLD\n    severity: high\n    message: '{name} {version}'\n"
                 "    match:\n      vendor: {regex: '(?i)siemens'}\n      version: {lt: '9.0'}\n")
    with open(os.path.join(d, "bad.json"), "w") as fh:
        fh.write('{"rules": [{"id": "NO-MATCH-KEY"}, {"id": "X", "severity": "nope", "match": {}}]}')
    rules, warns = load_rules([d], include_builtin=False)
    assert [r["id"] for r in rules] == ["SITE-SIEMENS-OLD"] and len(warns) == 2
    res = scan(os.path.join(S, "substation_demo.scd"), rules=[d], builtin_rules=False)
    hits = [f for f in res.findings if f.rule == "SITE-SIEMENS-OLD"]
    assert len(hits) == 1 and hits[0].message == "F87T_Q01 V08.40"


def test_builtin_rules_load_without_warnings():
    rules, warns = load_rules()
    assert rules and not warns


def test_apply_rules_message_with_missing_placeholder():
    r = ScanResult(root=".", files=[FileRecord(path="a", size=1, sha256="", assets=[Asset(name="A", vendor="v")])])
    apply_rules(r, [{"id": "T", "target": "asset", "severity": "low", "message": "{name} {nope}",
                     "match": {"vendor": "v"}}])
    assert r.findings[0].message == "A {nope}"


# ---------------------------------------------------------------- advisories
CSAF = {
    "document": {"title": "Demo Vendor RTU", "tracking": {"id": "ICSA-99-001-01"},
                 "references": [{"category": "self", "url": "https://example.invalid/adv"}]},
    "product_tree": {"branches": [{"category": "vendor", "name": "SIEMENS AG", "branches": [
        {"category": "product_name", "name": "SIPROTEC 5 7UT85", "branches": [
            {"category": "product_version_range", "name": "vers:intdot/>=7.80|<9.0"}]},
        {"category": "product_name", "name": "Unrelated Product", "branches": [
            {"category": "product_version_range", "name": "vers:all/*"}]}]}]},
    "vulnerabilities": [{"cve": "CVE-2099-0001", "scores": [{"cvss_v3": {"baseScore": 9.8}}]}],
}


def test_in_range_cases():
    assert in_range("V2.9", "<V3.0") is True
    assert in_range("8.60", ">=8.0|<8.50") is False
    assert in_range("x", "vers:all/*") is True
    assert in_range("1.5", "<June2023") is None
    assert in_range("", "<2.0") is None
    assert in_range("7.4.3", ">=V7.4Update0|<V7.4Update7") is True


def test_csaf_import_and_match():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "icsa.json"), "w") as fh:
        json.dump(CSAF, fh)
    with open(os.path.join(d, "feed.json"), "w") as fh:
        json.dump({"feed": []}, fh)
    entries, n, errors = import_csaf([d])
    assert n == 1 and len(entries) == 2 and not errors
    res = scan(os.path.join(S, "substation_demo.scd"))
    assert match_assets(res, entries) == 1
    f = [x for x in res.findings if x.rule == "ADV-ICSA-99-001-01"][0]
    assert f.severity == "high" and "F87T_Q01" in f.message and "CVE-2099-0001" in f.message


def test_cli_advisories_roundtrip():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "icsa.json"), "w") as fh:
        json.dump(CSAF, fh)
    db = os.path.join(d, "db.json")
    assert cli(["advisories", "import", d, "-o", db]) == 0
    out = os.path.join(d, "r.json")
    cli(["scan", os.path.join(S, "substation_demo.scd"), "-q", "--advisories", db, "--json", out])
    rules = [x["rule"] for f in json.load(open(out))["files"] for x in f["findings"]]
    assert "ADV-ICSA-99-001-01" in rules


# ---------------------------------------------------------------- IEC / AML parsers
def test_engineering_exports():
    res = scan(S)
    by = {os.path.basename(f.path): f for f in res.files}
    aml = by["line1_hw.aml"]
    assert aml.parser == "automationml" and aml.summary["device_count"] == 3
    ips = {a.name: a.ip for a in aml.assets}
    assert ips == {"PLC_1": "10.30.0.10", "HMI_1": "10.30.0.20", "ET200SP_1": "10.30.0.31"}
    assert {a.version for a in aml.assets} >= {"V2.9", "V4.2"}
    xef = by["wtp_filters.xef"]
    assert xef.summary["section_languages"] == {"ST": 1, "LD": 1, "FBD": 1}
    assert any(f.rule == "XEF-PASSWORD-VAR" for f in xef.findings)
    po = by["boiler_plcopen.xml"]
    assert po.summary["pou_types"] == {"program": 1, "functionBlock": 1, "function": 1}
    assert po.assets[0].name == "Boiler_PLC"


def test_nested_archive_parsing():
    z = [f for f in scan(S).files if f.path.endswith("contractor_handover.zip")][0]
    assert z.summary["nested"][0]["parser"] == "automationml"
    assert all("!" in a.source for a in z.assets) and len(z.assets) == 3


def test_docs_rule_examples_run():
    """Every YAML example in docs/rules.md must load and execute."""
    import re
    import pytest
    pytest.importorskip("yaml")
    doc = open(os.path.join(ROOT, "docs", "rules.md"), encoding="utf-8").read()
    d = tempfile.mkdtemp()
    for i, b in enumerate(re.findall(r"```yaml\n(.*?)```", doc, re.S)):
        with open(os.path.join(d, f"r{i}.yaml"), "w") as fh:
            fh.write(b)
    rules, warns = load_rules([d], include_builtin=False)
    assert len(rules) == 4 and not warns
    res = scan(S, rules=[d], builtin_rules=False)
    msgs = [f.message for f in res.findings if f.rule == "SITE-GOOSE-WITHOUT-VLAN-POLICY"]
    assert msgs and "2 GOOSE control blocks" in msgs[0]
    assert any(f.rule == "SITE-NO-TELNET" for f in res.findings)

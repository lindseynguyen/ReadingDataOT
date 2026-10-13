"""OT command decoding, network device configurations, standards mapping, SARIF and CycloneDX."""
import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
S = os.path.join(ROOT, "samples")

from otinspect.cli import main as cli  # noqa: E402
from otinspect.core.scanner import scan  # noqa: E402
from otinspect.parsers import otcmd  # noqa: E402
from otinspect.report.interop import to_cyclonedx, to_sarif  # noqa: E402
from otinspect.standards import _db, attack_url, lookup  # noqa: E402


def _rec(name):
    return scan(os.path.join(S, name)).files[0]


# ---------------------------------------------------------------- OT commands
def test_control_center_commands():
    rec = _rec("control_center.pcap")
    cmds = {(c["protocol"], c["command"]) for c in rec.summary["ot_commands"]}
    for c in [("IEC 104", "C_SC_NA_1 single command"), ("IEC 104", "C_RP_NA_1 reset process"),
              ("DNP3", "DIRECT_OPERATE"), ("DNP3", "COLD_RESTART"), ("S7comm", "PLC Stop"),
              ("S7comm", "Write Var"), ("S7comm", "Request download"), ("S7comm", "Read SZL"),
              ("CIP", "Write Tag"), ("CIP", "Reset (Identity)"), ("EtherNet/IP", "ListIdentity")]:
        assert c in cmds, c
    rules = {f.rule: f for f in rec.findings}
    for r, sev in [("PCAP-IEC104-CONTROL", "medium"), ("PCAP-IEC104-RESET", "high"), ("PCAP-DNP3-RESTART", "high"),
                   ("PCAP-S7-STOP", "high"), ("PCAP-S7-PROGRAM", "high"), ("PCAP-CIP-WRITE", "medium"),
                   ("PCAP-CIP-RESET", "high"), ("PCAP-ENIP-RECON", "low"), ("PCAP-DNP3-NO-SA", "info")]:
        assert rules[r].severity == sev, r
    assert "10.30.9.99 -> 10.30.3.40" in rules["PCAP-S7-STOP"].message
    rogue = next(a for a in rec.assets if a.ip == "10.30.9.99")
    assert rogue.extra["sends_commands"]


def test_routine_traffic_is_not_flagged():
    assert otcmd.iec104(bytes.fromhex("680e0000000064010600010000000014"), True)[0].category == "recon"
    assert otcmd.iec104(bytes.fromhex("680e00000000640107000100000000 14".replace(" ", "")), True) == []  # act-con
    assert otcmd.iec104(bytes.fromhex("680e0000000064010600010000000014"), False) == []                  # monitor dir
    assert otcmd.dnp3(b"\x05\x64\x05\xc0\x01\x00\x0a\x00\x00\x00", True) == []                              # no user data


def test_dnp3_response_ignored():
    user = bytes([0xC0, 0xC0, 0x81, 0, 0])
    frame = bytes([0x05, 0x64, 5 + len(user), 0x44, 1, 0, 10, 0, 0, 0]) + user + b"\x00\x00"
    assert otcmd.dnp3(frame, False) == []


def test_s7_pi_service_names():
    param = bytes([0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0x02]) + b"_DELE"
    hdr = bytes([0x32, 1, 0, 0, 0, 1]) + len(param).to_bytes(2, "big") + b"\x00\x00"
    body = bytes([0x02, 0xF0, 0x80]) + hdr + param
    pkt = bytes([3, 0]) + (4 + len(body)).to_bytes(2, "big") + body
    assert otcmd.s7comm(pkt, True)[0].name.endswith("(_DELE)")


# ---------------------------------------------------------------- network configs
def test_stratix_ios():
    rec = _rec("stratix_cell2.cfg")
    assert rec.category == "NetConfig" and rec.parser == "netconfig"
    a = rec.assets[0]
    assert (a.name, a.ip, a.version) == ("CELL2-STRATIX", "10.40.0.2", "15.2")
    assert "Rockwell" in a.vendor
    rules = {f.rule for f in rec.findings}
    assert {"NET-ENABLE-PASSWORD", "NET-PASSWORD-REVERSIBLE", "NET-SNMP-DEFAULT-COMMUNITY", "NET-SNMP-RW",
            "NET-HTTP-ENABLED", "NET-TELNET-ENABLED", "NET-MGMT-NO-ACL", "NET-NO-REMOTE-LOG"} <= rules
    assert not any("Maint2026" in f.message or "Pl4ntRW" in f.message for f in rec.findings)   # masked
    assert rec.summary["vlans"] == [{"id": "10", "name": "CONTROL"}, {"id": "20", "name": "SAFETY"}]


def test_fortios():
    rec = _rec("fgr60f_substation.conf")
    a = rec.assets[0]
    assert (a.name, a.vendor, a.model, a.version, a.ip) == ("SUBSTATION-FW1", "Fortinet", "FGR60F", "7.2.8", "10.50.0.1")
    rules = [f.rule for f in rec.findings]
    assert {"NET-FW-ANY-ANY", "NET-TELNET-ENABLED", "NET-ADMIN-ON-WAN", "NET-ADMIN-NO-TRUSTHOST",
            "NET-SNMP-DEFAULT-COMMUNITY", "NET-FW-NO-LOG"} <= set(rules)
    assert rules.count("NET-ADMIN-NO-TRUSTHOST") == 1          # 'vendor' has a trusthost
    assert not any("scada-to-rtu" in f.message for f in rec.findings)


def test_ruggedcom_heuristic():
    rec = _rec("ruggedcom_bay3.csv")
    assert rec.assets[0].name == "BAY3-RSG" and rec.assets[0].vendor == "Siemens RUGGEDCOM"
    assert all("heuristic" in f.message for f in rec.findings if f.rule.startswith("NET-"))
    assert {"NET-TELNET-ENABLED", "NET-DEFAULT-CREDENTIALS", "NET-SNMP-DEFAULT-COMMUNITY"} <= {f.rule for f in rec.findings}


def test_logs_are_not_netconfig(tmp_path):
    p = tmp_path / "ops.log"
    p.write_text("2026-01-01 10:00:00 moxa switch port 3 link down\n")
    assert scan(str(p)).files[0].category == "Log"


# ---------------------------------------------------------------- standards mapping
def _builtin_rule_ids():
    ids = set()
    for dirpath, _, files in os.walk(os.path.join(ROOT, "otinspect")):
        for n in files:
            if n.endswith(".py"):
                txt = open(os.path.join(dirpath, n), encoding="utf-8").read()
                ids |= set(re.findall(r'"((?:SCL|PCAP|L5X|XEF|PLCOPEN|CFG|FW|ZIP|NET|XREF|ASSET|DIFF)-[A-Z0-9-]+)"', txt))
    ids |= {f"SCL-{k}-{s}" for k in ("GOOSE", "SV") for s in ("APPID-DUP", "MAC-DUP", "NOADDR")}
    ids |= {f"DIFF-{k}-{s}" for k in ("GOOSE", "SV", "IED") for s in ("CONFREV", "ADDR-CHANGED", "REMOVED")}
    ids |= {v[0] for v in __import__("otinspect.parsers.pcap", fromlist=["x"]).COMMAND_RULES.values()}
    return {i for i in ids if not i.endswith("-")}


def test_every_builtin_rule_is_mapped():
    unmapped = sorted(r for r in _builtin_rule_ids() if not lookup(r)["iec62443"])
    assert not unmapped, unmapped


def test_mapping_ids_are_known():
    db = _db()
    for rule, m in db["rules"].items():
        assert all(s in db["iec62443_3_3"] for s in m["iec62443"]), rule
        assert all(t in db["attack_ics"] for t in m["attack"]), rule
    assert attack_url("T1692.001") == "https://attack.mitre.org/techniques/T1692/001/"


def test_findings_carry_mapping_and_user_rules_override(tmp_path):
    rules = tmp_path / "r.yaml"
    rules.write_text("rules:\n  - id: SITE-X\n    severity: low\n    target: asset\n    message: x\n"
                     "    iec62443: [SR 7.8]\n    attack: [T0846]\n    match:\n      kind: {eq: IED}\n")
    res = scan(os.path.join(S, "substation_demo.scd"), rules=[str(rules)])
    f = next(x for x in res.findings if x.rule == "SCL-62351")
    assert f.iec62443 == ["SR 3.1", "SR 1.2"] and "T1692.001" in f.attack
    site = next(x for x in res.findings if x.rule == "SITE-X")
    assert site.iec62443 == ["SR 7.8"] and site.attack == ["T0846"]


# ---------------------------------------------------------------- exports
@pytest.fixture(scope="module")
def sample_scan():
    return scan(S)


def test_sarif(sample_scan, tmp_path):
    p = tmp_path / "o.sarif"
    to_sarif(sample_scan, str(p))
    doc = json.loads(p.read_text(encoding="utf-8"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "OTInspect"
    rules = run["tool"]["driver"]["rules"]
    assert len(run["results"]) == len(sample_scan.findings)
    for r in run["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not os.path.isabs(uri) and "\\" not in uri
    assert any("external/mitre-attack-ics/T0816" in t for r in rules for t in r["properties"]["tags"])
    fps = [r["partialFingerprints"]["otinspect/v1"] for r in run["results"]]
    assert len(set(fps)) == len(fps)


def test_cyclonedx(sample_scan, tmp_path):
    p = tmp_path / "o.cdx.json"
    to_cyclonedx(sample_scan, str(p))
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))
    fw = next(c for c in doc["components"] if c["name"] == "CELL2-STRATIX")
    assert fw["type"] == "device" and fw["manufacturer"]["name"].startswith("Rockwell")
    assert fw["components"][0]["type"] == "firmware" and fw["components"][0]["version"] == "15.2"
    assert any(c["type"] == "file" and c["hashes"][0]["alg"] == "SHA-256" for c in doc["components"])
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(p.read_text(encoding="utf-8")) is None


def test_cli_exports(tmp_path):
    sarif, cdx = tmp_path / "a.sarif", tmp_path / "a.cdx.json"
    assert cli(["scan", os.path.join(S, "control_center.pcap"), "-q", "--sarif", str(sarif),
                "--cyclonedx", str(cdx)]) == 0
    assert sarif.exists() and cdx.exists()

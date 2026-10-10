import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from otinspect.core.identify import identify  # noqa: E402
from otinspect.core.scanner import scan  # noqa: E402
from otinspect.report.export import to_csv, to_html, to_json  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
SCD = os.path.join(SAMPLES, "substation_demo.scd")


def test_scl_namespace_parsed():
    res = scan(SCD)
    rec = res.files[0]
    assert rec.category == "SCL" and not rec.error
    assert rec.summary["ied_count"] == 4
    names = {a.name: a for a in rec.assets}
    assert names["F87T_Q01"].vendor == "SIEMENS"
    assert names["F87T_Q01"].ip == "10.10.1.11"
    assert "GOOSE" in names["F87T_Q01"].protocols
    assert rec.summary["goose_count"] == 2
    assert rec.summary["bay_count"] == 5


def test_scl_rules():
    rules = {f.rule for f in scan(SCD).findings}
    assert {"SCL-IP-DUP", "SCL-GOOSE-APPID-DUP", "SCL-GW-OUTSIDE", "SCL-IP-DEFAULT", "SCL-GOOSE-NOVLAN"} <= rules


def test_log_secrets_and_levels():
    rec = scan(os.path.join(SAMPLES, "rtu_gateway.log")).files[0]
    assert rec.summary["levels"]["error"] >= 1
    assert any(f.rule == "CFG-SNMP-COMMUNITY" and f.severity == "high" for f in rec.findings)


def test_identify_extensions(tmp_path=None):
    d = tempfile.mkdtemp()
    cases = {
        "a.cfg": b"STATION_A,REL1,1999\n4,2A,2D\n",
        "fw.hex": b":10010000214601360121470136007EFE09D2190140\n:00000001FF\n",
        "p.ap17": b"\x00\x01binary",
        "c.pcap": b"\xd4\xc3\xb2\xa1" + b"\x00" * 20,
        "x.l5x": b'<?xml version="1.0"?><RSLogix5000Content SchemaRevision="1.0">',
    }
    expect = {"a.cfg": "COMTRADE", "fw.hex": "Firmware", "p.ap17": "PLC", "c.pcap": "PCAP", "x.l5x": "PLC"}
    for n, data in cases.items():
        p = os.path.join(d, n)
        with open(p, "wb") as fh:
            fh.write(data)
        assert identify(p).category == expect[n], n


def test_zip_and_exports():
    d = tempfile.mkdtemp()
    z = os.path.join(d, "backup.zip")
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(SCD, "proj/substation.scd")
    res = scan(d)
    assert res.files[0].summary["member_categories"].get("SCL") == 1
    out = tempfile.mkdtemp()
    res = scan(SAMPLES)
    to_json(res, os.path.join(out, "r.json"))
    to_html(res, os.path.join(out, "r.html"))
    to_csv(res, out)
    assert os.path.getsize(os.path.join(out, "r.html")) > 1000

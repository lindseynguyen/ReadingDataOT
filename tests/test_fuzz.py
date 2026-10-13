"""Property-based fuzzing (Hypothesis) of the code that reads untrusted bytes.

The scanner catches parser exceptions so a scan never stops, which would also
hide parser bugs; these tests call decoders and parsers directly and require
them to handle arbitrary input without raising.
"""
import os
import struct
import sys
import tempfile

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings, strategies as st  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from otinspect.core.identify import identify  # noqa: E402
from otinspect.core.model import FileRecord  # noqa: E402
from otinspect.parsers import netconfig, otcmd  # noqa: E402
from otinspect.parsers.pcap import PcapParser  # noqa: E402
from otinspect.rules.advisories import in_range  # noqa: E402
from otinspect.rules.engine import version_key  # noqa: E402
from otinspect.standards import lookup  # noqa: E402

settings.register_profile("ci", max_examples=300, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("dev", max_examples=100, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))

DECODERS = [otcmd.iec104, otcmd.dnp3, otcmd.s7comm, otcmd.enip]


def _prefixed(prefixes):
    return st.tuples(st.sampled_from(prefixes), st.binary(max_size=300)).map(lambda t: t[0] + t[1])


PROTO_PREFIXES = [b"", b"\x68", b"\x68\x0e\x00\x00\x00\x00", b"\x05\x64", b"\x05\x64\x10\xc4",
                  b"\x03\x00\x00\x1f\x02\xf0\x80\x32\x01", b"\x03\x00\x00\x1f\x02\xf0\x80\x32\x07",
                  b"\x6f\x00", b"\x70\x00", b"\x63\x00"]


@given(_prefixed(PROTO_PREFIXES), st.booleans())
def test_command_decoders_never_raise(data, to_server):
    for dec in DECODERS:
        for c in dec(data, to_server):
            assert c.category in {"control", "write", "program", "stop", "restart", "config",
                                  "file", "auth", "recon", "time", "other"}


@given(st.integers(0, 65535), st.integers(0, 65535), st.binary(max_size=200), st.sampled_from([6, 17]))
def test_decode_dispatch_never_raises(sp, dp, data, proto):
    otcmd.decode(proto, sp, dp, data)


def _pcap(packets):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for p in packets:
        out += struct.pack("<IIII", 1, 0, len(p), len(p)) + p
    return out


ETH_IP_TCP = (b"\x00" * 12 + b"\x08\x00" + b"\x45\x00\x00\x28" + b"\x00" * 5 + b"\x06" + b"\x00\x00"
              + b"\x0a\x00\x00\x01\x0a\x00\x00\x02")
PKT = st.one_of(st.binary(max_size=120),
                st.tuples(st.sampled_from([502, 2404, 20000, 102, 44818, 23]), st.binary(max_size=120)).map(
                    lambda t: ETH_IP_TCP + struct.pack(">HH", 40000, t[0]) + b"\x00" * 8 + b"\x50\x18" + b"\x00" * 6 + t[1]))


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(PKT, max_size=20), st.binary(max_size=40))
def test_pcap_parser_never_raises(packets, tail):
    data = _pcap(packets) + tail
    rec = FileRecord(path="x.pcap", size=len(data), sha256="", category="PCAP")
    PcapParser()._parse(data, rec)


@given(st.text(max_size=2000))
def test_netconfig_never_raises(text):
    for platform, parse in (("ios", netconfig.parse_ios), ("fortios", netconfig.parse_fortios)):
        rec = FileRecord(path="c.cfg", size=0, sha256="", category="NetConfig")
        parse(text.splitlines(), rec)
    rec = FileRecord(path="c.cfg", size=0, sha256="", category="NetConfig")
    netconfig.parse_generic(text.splitlines(), rec, "Test vendor")
    netconfig.detect(text)


@given(st.lists(st.sampled_from(["version 15.2", "hostname X", "interface Gi1/1", " ip address 10.0.0.1 255.0.0.0",
                                 "snmp-server community public RW", "line vty 0 4", " transport input all",
                                 "config firewall policy", "edit 1", "set action accept", "next", "end",
                                 "enable password 7 abc", "username a password 0 b", "ip http server", ""]),
                max_size=40))
def test_netconfig_structured_never_raises(lines):
    for parse in (netconfig.parse_ios, netconfig.parse_fortios):
        parse(lines, FileRecord(path="c.cfg", size=0, sha256="", category="NetConfig"))


@given(st.binary(max_size=600), st.sampled_from([".scd", ".cfg", ".pcap", ".l5x", ".conf", ".txt", ".hex", ""]))
def test_identify_never_raises(head, ext):
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as fh:
        fh.write(head)
    try:
        identify(fh.name, head)
    finally:
        os.unlink(fh.name)


@given(st.text(max_size=30), st.text(max_size=60))
def test_versions_never_raise(v, rng):
    version_key(v)
    in_range(v, rng)


@given(st.text(max_size=40))
def test_mapping_lookup_total(rule):
    m = lookup(rule)
    assert isinstance(m.get("iec62443", []), list) and isinstance(m.get("attack", []), list)

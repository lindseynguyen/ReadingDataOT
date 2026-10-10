"""Robustness: corrupted, truncated, hostile and large inputs must never crash a scan."""
import os
import random
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from otinspect.core.scanner import scan  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "samples")
EXTS = [".scd", ".icd", ".cfg", ".dat", ".pcap", ".pcapng", ".l5x", ".l5k", ".aml", ".xef", ".eds",
        ".gsd", ".gsdml", ".hex", ".bin", ".zip", ".zap17", ".log", ".xml", ".evtx", ".acd", ""]


def _write(d, name, data):
    p = os.path.join(d, name)
    with open(p, "wb") as fh:
        fh.write(data)
    return p


def test_random_garbage_never_crashes():
    rnd = random.Random(1234)
    d = tempfile.mkdtemp()
    for i in range(300):
        ext = rnd.choice(EXTS)
        size = rnd.choice([0, 1, 3, 15, 64, 512, 5000])
        _write(d, f"g{i}{ext}", bytes(rnd.getrandbits(8) for _ in range(size)))
    res = scan(d)
    assert len(res.files) == 300


def test_truncated_samples_never_crash():
    d = tempfile.mkdtemp()
    rnd = random.Random(99)
    for name in os.listdir(S):
        src = os.path.join(S, name)
        if not os.path.isfile(src) or name.endswith(".py"):
            continue
        data = open(src, "rb").read()
        for k in range(8):
            cut = rnd.randint(0, max(1, len(data) - 1))
            _write(d, f"t{k}_{name}", data[:cut])
            # bit flips in the middle
            b = bytearray(data)
            for _ in range(5):
                if b:
                    b[rnd.randrange(len(b))] ^= 0xFF
            _write(d, f"f{k}_{name}", bytes(b))
    res = scan(d)
    assert res.files and all(f.category != "Error" for f in res.files)


def test_billion_laughs_is_contained():
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="&lol9;"/></SCL>"""
    d = tempfile.mkdtemp()
    _write(d, "bomb.scd", bomb)
    t = time.time()
    res = scan(d)
    assert time.time() - t < 10
    assert res.files[0].error          # rejected, not expanded


def test_xxe_external_entity_not_resolved():
    secret = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt")
    secret.write("TOPSECRET")
    secret.close()
    xxe = f"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file://{secret.name}">]>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="&e;"/></SCL>""".encode()
    d = tempfile.mkdtemp()
    _write(d, "xxe.scd", xxe)
    rec = scan(d).files[0]
    assert "TOPSECRET" not in str(rec.to_dict())


def test_zip_slip_and_bomb_flagged():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "evil.zip")
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../../etc/evil.scd", "x")
        zf.writestr("ok.txt", "fine")
    b = os.path.join(d, "bomb.zip")
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\0" * (30 * 1024 * 1024))
    res = scan(d)
    rules = {f.rule for f in res.findings}
    assert {"ZIP-PATH-TRAVERSAL", "ZIP-BOMB"} <= rules
    assert not os.path.exists(os.path.join(d, "..", "..", "etc", "evil.scd"))


def test_unreadable_and_odd_names():
    d = tempfile.mkdtemp()
    _write(d, "tên file tiếng Việt ✓.log", "2026-01-01 10:00:00 ERROR lỗi kết nối\n".encode("utf-8"))
    _write(d, "utf16.cfg", "password=abc123\n".encode("utf-16"))
    res = scan(d)
    assert len(res.files) == 2 and not any(f.error for f in res.files)


def test_many_files_performance():
    d = tempfile.mkdtemp()
    scd = open(os.path.join(S, "substation_demo.scd"), "rb").read()
    for i in range(1500):
        sub = os.path.join(d, f"bay{i % 30}")
        os.makedirs(sub, exist_ok=True)
        _write(sub, f"f{i}.{'scd' if i % 10 == 0 else 'log'}",
               scd if i % 10 == 0 else b"2026-01-01 00:00:00 INFO ok\n" * 50)
    t = time.time()
    res = scan(d)
    assert len(res.files) == 1500
    assert time.time() - t < 60

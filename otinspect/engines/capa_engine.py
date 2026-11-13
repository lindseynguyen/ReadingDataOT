"""capa (Mandiant FLARE) capability detection for PE / ELF / .NET executables.

capa runs as a separate process (``capa -j``), so a crash or a hang on a hostile binary
cannot take OTInspect down, and the standalone capa executable works as well as the pip
package. capa analyses statically: the sample is never executed.

Compatible with capa 7 to 10 JSON (attack entries as objects) and older releases (attack
entries as "Tactic::Technique [Txxxx]" strings).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field

# exit codes from capa/main.py
CAPA_ERRORS = {
    10: "capa rules not found (pip-installed capa needs --capa-rules, or use the standalone capa executable)",
    11: "file not found", 12: "invalid capa rule", 13: "corrupt file", 14: "file limitation (packed or installer?)",
    15: "invalid capa signatures", 16: "unsupported file type", 17: "unsupported architecture",
    18: "unsupported OS", 19: "unsupported backend",
}
UNSUPPORTED = {13, 14, 16, 17, 18}
MAX_OUTPUT = 64 * 1024 * 1024
_ATTACK_RE = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")

# capability namespace prefix -> (rule id, severity, label, ATT&CK for ICS, IEC 62443-3-3)
# first matching prefix wins; capabilities not listed stay in the summary without a finding
RISK_MAP = [
    ("host-interaction/process/inject", "CAPA-PROCESS-INJECTION", "high", "injects code into other processes", [], ["SR 3.2"]),
    ("malware-family/", "CAPA-MALWARE-FAMILY", "high", "matches a known malware family", [], ["SR 3.2"]),
    ("collection/keylog", "CAPA-CREDENTIAL-THEFT", "high", "captures keystrokes", ["T0859"], ["SR 1.5", "SR 3.2"]),
    ("collection/browser", "CAPA-CREDENTIAL-THEFT", "high", "collects browser data", ["T0859"], ["SR 1.5", "SR 3.2"]),
    ("persistence/authentication-process", "CAPA-CREDENTIAL-THEFT", "high", "hooks the authentication process",
     ["T0859"], ["SR 1.5", "SR 3.2"]),
    ("host-interaction/credential", "CAPA-CREDENTIAL-THEFT", "high", "accesses stored credentials", ["T0859"], ["SR 1.5"]),
    ("host-interaction/bootloader", "CAPA-BOOTKIT", "high", "modifies the boot process", ["T0851"], ["SR 3.4"]),
    ("anti-analysis/anti-forensic", "CAPA-ANTI-FORENSICS", "high", "removes evidence (logs, self-deletion)",
     ["T0872"], ["SR 2.8", "SR 3.9"]),
    ("communication/c2", "CAPA-C2", "medium", "may implement remote command / file-transfer functions (verify; "
     "also seen in installers and admin tools)", ["T0869"], ["SR 3.2", "SR 5.2"]),
    ("impact/", "CAPA-IMPACT", "high", "has destructive / impact capabilities", ["T0809"], ["SR 3.2", "SR 7.3"]),
    ("host-interaction/uac/bypass", "CAPA-DEFENSE-EVASION", "medium", "bypasses UAC", [], ["SR 2.1", "SR 3.2"]),
    ("anti-analysis/anti-av", "CAPA-DEFENSE-EVASION", "medium", "evades security products", [], ["SR 3.2"]),
    ("host-interaction/firewall/modify", "CAPA-DEFENSE-EVASION", "medium", "modifies the host firewall", [], ["SR 5.2", "SR 7.6"]),
    ("load-code/shellcode", "CAPA-CODE-LOADING", "medium", "loads shellcode or in-memory payloads", [], ["SR 3.2"]),
    ("load-code/pe", "CAPA-CODE-LOADING", "medium", "loads executables from memory", [], ["SR 3.2"]),
    ("load-code/powershell", "CAPA-CODE-LOADING", "medium", "hosts PowerShell", ["T1701.001"], ["SR 3.2", "SR 7.7"]),
    ("persistence/", "CAPA-PERSISTENCE", "medium", "installs persistence", [], ["SR 3.2", "SR 7.6"]),
    ("collection/screenshot", "CAPA-SURVEILLANCE", "medium", "captures the screen", ["T0852"], ["SR 3.2", "SR 4.1"]),
    ("host-interaction/clipboard", "CAPA-SURVEILLANCE", "low", "reads the clipboard", [], ["SR 4.1"]),
    ("exploitation/", "CAPA-EXPLOITATION", "medium", "contains exploitation techniques", [], ["SR 3.2"]),
    ("anti-analysis/", "CAPA-ANTI-ANALYSIS", "low", "detects debuggers / VMs or is obfuscated (also common in licensed "
     "engineering software)", [], ["SR 3.2"]),
    ("host-interaction/driver", "CAPA-DRIVER", "low", "loads or talks to kernel drivers", [], ["SR 3.4"]),
]
SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class CapaResult:
    ok: bool
    capabilities: list[dict] = field(default_factory=list)   # {name, namespace, attack: [ids]}
    fmt: str = ""
    arch: str = ""
    os: str = ""
    note: str = ""
    error: str = ""


def find_capa(path: str | list[str] | None = None) -> list[str] | None:
    """Command to run capa: explicit path (or argv list), 'capa' on PATH, or python -m capa.main."""
    if isinstance(path, (list, tuple)) and path:
        return list(path)
    if path:
        if os.path.isfile(path) or shutil.which(path):
            return [shutil.which(path) or path]
        return None
    env = os.environ.get("OTINSPECT_CAPA")
    if env:
        return find_capa(env)
    exe = shutil.which("capa")
    if exe:
        return [exe]
    if not getattr(sys, "frozen", False):
        try:
            import importlib.util
            if importlib.util.find_spec("capa.main"):
                return [sys.executable, "-m", "capa.main"]
        except (ImportError, ValueError):
            pass
    return None


def _run(cmd: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    """Run with a hard timeout that also kills child processes (PyInstaller onefile capa)."""
    kw: dict = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        kw["start_new_session"] = True
    env = dict(os.environ, NO_COLOR="1", PYTHONIOENCODING="utf-8", TERM="dumb")
    p = subprocess.Popen(cmd, env=env, **kw)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        p.communicate()
        raise TimeoutError(f"capa timed out after {timeout:g} s") from None
    return p.returncode, out[:MAX_OUTPUT], err[-4000:]


def _kill_tree(p: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=30)
        else:
            os.killpg(p.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        p.kill()
    except Exception:
        pass


def capa_version(cmd: list[str], timeout: float = 60) -> str:
    try:
        rc, out, err = _run(cmd + ["--version"], timeout)
    except (OSError, TimeoutError) as e:
        raise RuntimeError(f"capa cannot be started: {e}") from None
    text = (out or err).decode("utf-8", "replace").strip()
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
    if rc != 0 or not m:
        raise RuntimeError(f"capa --version failed (exit {rc}): {text[:200]}")
    return m.group(1)


def _attack_ids(items) -> list[str]:
    ids = []
    for a in items or []:
        if isinstance(a, dict):
            i = a.get("id") or ""
        else:
            m = _ATTACK_RE.search(str(a))
            i = m.group(1) if m else ""
        if i and i not in ids:
            ids.append(i)
    return ids


def parse_capa_json(doc: dict) -> CapaResult:
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), dict):
        return CapaResult(False, error="unexpected capa output (no 'rules' object)")
    caps = []
    for name, r in doc["rules"].items():
        meta = (r or {}).get("meta", {}) if isinstance(r, dict) else {}
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        ns = meta.get("namespace") or ""
        if ns.startswith("internal/"):
            continue
        caps.append({"name": meta.get("name", name), "namespace": ns, "attack": _attack_ids(meta.get("attack"))})
    caps.sort(key=lambda c: (c["namespace"], c["name"]))
    an = ((doc.get("meta") or {}).get("analysis") or {})
    return CapaResult(True, caps, fmt=str(an.get("format", "")), arch=str(an.get("arch", "")), os=str(an.get("os", "")))


def analyse(cmd: list[str], path: str, rules: str = "", sigs: str = "", timeout: float = 180) -> CapaResult:
    argv = list(cmd) + ["-j"]
    if rules:
        argv += ["-r", rules]
    if sigs:
        argv += ["-s", sigs]
    argv.append(path)
    try:
        rc, out, err = _run(argv, timeout)
    except TimeoutError as e:
        return CapaResult(False, error=str(e))
    except OSError as e:
        return CapaResult(False, error=f"capa cannot be started: {e}")
    if rc in UNSUPPORTED:
        return CapaResult(False, note=f"capa: {CAPA_ERRORS[rc]}")
    if rc != 0:
        tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        return CapaResult(False, error=f"capa exit {rc}: {CAPA_ERRORS.get(rc, tail[0][:200])}")
    try:
        doc = json.loads(out.decode("utf-8", "replace"))
    except ValueError:
        return CapaResult(False, error="capa returned invalid JSON")
    return parse_capa_json(doc)


def classify(caps: list[dict]) -> list[dict]:
    """Group capabilities into findings: [{rule, severity, label, names, attack, iec, enterprise}]."""
    groups: dict[str, dict] = {}
    for c in caps:
        for prefix, rid, sev, label, attack, iec in RISK_MAP:
            if c["namespace"].startswith(prefix) or (prefix.endswith("/") and c["namespace"] == prefix[:-1]):
                g = groups.setdefault(rid, {"rule": rid, "severity": sev, "label": label, "names": [],
                                            "attack": list(attack), "iec": list(iec), "enterprise": []})
                if SEV_RANK[sev] < SEV_RANK[g["severity"]]:
                    g["severity"], g["label"] = sev, label
                if c["name"] not in g["names"]:
                    g["names"].append(c["name"])
                for t in c["attack"]:
                    if t not in g["enterprise"]:
                        g["enterprise"].append(t)
                break
    return sorted(groups.values(), key=lambda g: (SEV_RANK[g["severity"]], g["rule"]))


def cache_key(sha256: str, version: str, rules: str, sigs: str) -> str:
    h = hashlib.sha256(f"{sha256}|{version}|{os.path.abspath(rules) if rules else ''}|"
                       f"{os.path.abspath(sigs) if sigs else ''}|{_tree_stamp(rules)}".encode()).hexdigest()
    return h[:32]


def _tree_stamp(p: str) -> str:
    """Cheap change detector for a rules directory (count + newest mtime)."""
    if not p or not os.path.exists(p):
        return ""
    if os.path.isfile(p):
        return str(os.path.getmtime(p))
    n, newest = 0, 0.0
    for dp, dn, fn in os.walk(p):
        for f in fn:
            n += 1
            try:
                newest = max(newest, os.path.getmtime(os.path.join(dp, f)))
            except OSError:
                pass
    return f"{n}:{newest}"

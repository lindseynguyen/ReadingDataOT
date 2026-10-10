"""Smoke-test the frozen executables. Prints GitHub annotations so results are
visible in the run summary. Usage: python packaging/smoke_test.py dist"""
import json
import os
import subprocess
import sys
import time

DIST = sys.argv[1] if len(sys.argv) > 1 else "dist"
EXT = ".exe" if os.name == "nt" else ""
CLI = os.path.join(DIST, "otinspect-cli" + EXT)
GUI = os.path.join(DIST, "OTInspect" + EXT)
errors = []


def run(args, expect=0):
    p = subprocess.run([CLI] + args, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != expect:
        errors.append(f"{' '.join(args)} -> exit {p.returncode} (expected {expect}); "
                      f"stderr: {p.stderr.strip()[-600:]!r}; stdout: {p.stdout.strip()[-300:]!r}")
    return p


v = run(["--version"]).stdout.strip()
run(["scan", "samples", "-q", "--json", "smoke.json", "--html", "smoke.html"])
if os.path.exists("smoke.json"):
    r = json.load(open("smoke.json", encoding="utf-8"))
    files = len(r["files"])
    assets = sum(len(f["assets"]) for f in r["files"])
    rules = {x["rule"] for f in r["files"] for x in f["findings"]}
    parsers = {f["parser"] for f in r["files"]}
    print(f"::notice title=CLI scan::version={v} files={files} assets={assets} rules={len(rules)} parsers={sorted(parsers)}")
    if files < 10 or assets < 20:
        errors.append(f"unexpected scan result files={files} assets={assets}")
    for need in ("ASSET-NO-VERSION", "XREF-UNDOCUMENTED-HOST", "SCL-IP-DUP", "PCAP-MODBUS-WRITE", "XEF-PASSWORD-VAR"):
        if need not in rules:
            errors.append(f"rule {need} missing from frozen build")
    for need in ("scl", "pcap", "comtrade", "automationml", "rockwell", "zip"):
        if need not in parsers:
            errors.append(f"parser {need} missing from frozen build")
    if r.get("warnings"):
        errors.append(f"warnings: {r['warnings']}")
else:
    errors.append("smoke.json not written")

run(["diff", os.path.join("samples", "substation_demo.scd"), os.path.join("samples", "substation_demo_v2.scd"),
     "--fail-on", "high"], expect=2)

# GUI: must start and stay up (offscreen platform, no display needed)
env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
g = subprocess.Popen([GUI], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(15)
if g.poll() is not None:
    out, err = g.communicate()
    errors.append(f"GUI exited early with {g.returncode}: {err.decode(errors='replace')[-600:]!r}")
else:
    g.kill()
    print("::notice title=GUI::started and stayed up for 15 s")

for e in errors:
    print(f"::error title=Smoke test::{e}")
sys.exit(1 if errors else 0)

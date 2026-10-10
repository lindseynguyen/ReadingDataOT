"""Headless CLI (suited to air-gapped workstations / jump hosts).

Examples:
    python -m otinspect scan D:\\Substation_A --html report.html --json report.json
    python -m otinspect scan ./samples --csv out/ -q
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .core.scanner import scan
from .report.export import SEV_ORDER, to_csv, to_html, to_json


def _print_summary(res) -> None:
    print(f"\nScanned: {res.root}")
    print(f"Total files: {len(res.files)}")
    for k, v in res.stats().items():
        print(f"  {k:<12} {v}")
    if res.assets:
        print(f"\nAssets ({len(res.assets)}):")
        for a in res.assets:
            print(f"  {a.name[:22]:<22} {a.kind[:22]:<22} {a.vendor[:18]:<18} {a.model[:16]:<16} {a.ip:<15} {','.join(a.protocols)}")
    fs = sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity, 9))
    if fs:
        print(f"\nFindings ({len(fs)}):")
        for x in fs:
            print(f"  [{x.severity.upper():<6}] {x.rule:<22} {x.message}")
    errs = [f for f in res.files if f.error]
    if errs:
        print(f"\nParse errors ({len(errs)}):")
        for f in errs:
            print(f"  {f.path}: {f.error}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="otinspect", description="Inventory and analyze OT/ICS files")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Scan a file or directory")
    s.add_argument("path")
    s.add_argument("--no-recursive", action="store_true", help="Do not descend into subdirectories")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--json", help="Write JSON report")
    s.add_argument("--html", help="Write HTML report (print to PDF from a browser)")
    s.add_argument("--csv", help="Directory for files.csv / assets.csv / findings.csv")
    s.add_argument("-q", "--quiet", action="store_true")
    s.add_argument("--fail-on", choices=["high", "medium", "low"],
                   help="Exit with code 2 if any finding is at or above this severity (for CI / scheduled checks)")
    a = ap.parse_args(argv)

    def prog(i, n, p):
        if not a.quiet:
            sys.stderr.write(f"\r[{i}/{n}] {p[-70:]:<70}")
            sys.stderr.flush()

    res = scan(a.path, recursive=not a.no_recursive, workers=a.workers, progress=prog)
    if not a.quiet:
        sys.stderr.write("\n")
        _print_summary(res)
    if a.json:
        to_json(res, a.json)
        print(f"JSON: {a.json}")
    if a.html:
        to_html(res, a.html)
        print(f"HTML: {a.html}")
    if a.csv:
        for p in to_csv(res, a.csv):
            print(f"CSV:  {p}")
    if a.fail_on:
        lim = SEV_ORDER[a.fail_on]
        if any(SEV_ORDER.get(x.severity, 9) <= lim for x in res.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

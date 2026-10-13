"""Headless CLI (suited to air-gapped workstations / jump hosts).

Examples:
    otinspect scan D:\\Substation_A --html report.html --json report.json
    otinspect scan ./samples --csv out/ -q --fail-on high
    otinspect diff old.scd new.scd --html diff.html
    otinspect advisories import csaf_files/OT/white -o advisories.json
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .report.export import SEV_ORDER, diff_to_html, to_csv, to_html, to_json


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
    for w in res.warnings:
        print(f"Warning: {w}", file=sys.stderr)


def _fail(findings, level) -> bool:
    if not level:
        return False
    lim = SEV_ORDER[level]
    return any(SEV_ORDER.get(x.severity, 9) <= lim for x in findings)


def _safe_console() -> None:
    """Windows consoles/pipes may use cp1252; never crash on Unicode paths or names."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _safe_console()
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
    s.add_argument("--sarif", help="Write SARIF 2.1.0 (GitHub code scanning)")
    s.add_argument("--cyclonedx", help="Write CycloneDX 1.6 JSON bill of materials of the assets")
    s.add_argument("--rules", action="append", default=[], help="Extra rule file or folder (YAML/JSON); repeatable")
    s.add_argument("--no-builtin-rules", action="store_true")
    s.add_argument("--advisories", help="Advisory DB built with 'advisories import' (or set OTINSPECT_ADVISORIES)")
    s.add_argument("--max-file-mb", type=float,
                   help="Size limit for parsing one file, overriding the per-parser defaults "
                        "(SCL 2048, PLC exports 256, device descriptions 32; 0 = no limit). "
                        "Larger files are still hashed and identified")
    s.add_argument("-q", "--quiet", action="store_true")
    s.add_argument("--fail-on", choices=["high", "medium", "low"],
                   help="Exit with code 2 if any finding is at or above this severity (for CI / scheduled checks)")

    d = sub.add_parser("diff", help="Compare two SCL files (e.g. SCD revisions)")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--html")
    d.add_argument("--json")
    d.add_argument("--fail-on", choices=["high", "medium", "low"])

    a = sub.add_parser("advisories", help="Manage the offline advisory database")
    asub = a.add_subparsers(dest="acmd", required=True)
    ai = asub.add_parser("import", help="Import CSAF 2.0 advisory JSON files or folders")
    ai.add_argument("paths", nargs="+")
    ai.add_argument("-o", "--output", default="advisories.json")

    sub.add_parser("gui", help="Start the graphical interface")
    args = ap.parse_args(argv)

    if args.cmd == "gui":
        from .gui.app import main as gui_main
        return gui_main()

    if args.cmd == "advisories":
        from .rules.advisories import import_csaf, save_db
        entries, n, errors = import_csaf(args.paths)
        save_db(entries, args.output)
        for e in errors[:20]:
            print(f"Warning: {e}", file=sys.stderr)
        print(f"Imported {n} advisories ({len(entries)} product/version entries) -> {args.output}")
        return 0 if n else 1

    if args.cmd == "diff":
        from .diff import diff_scl, diff_text
        try:
            res = diff_scl(args.old, args.new)
        except (ValueError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        print(diff_text(res))
        if args.html:
            diff_to_html(res, args.html)
            print(f"HTML: {args.html}")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(res.to_dict(), fh, ensure_ascii=False, indent=2)
            print(f"JSON: {args.json}")
        return 2 if _fail(res.findings, args.fail_on) else 0

    from .core.scanner import scan

    def prog(i, n, p):
        if not args.quiet:
            sys.stderr.write(f"\r[{i}/{n}] {p[-70:]:<70}")
            sys.stderr.flush()

    res = scan(args.path, recursive=not args.no_recursive, workers=args.workers, progress=prog,
               rules=args.rules, builtin_rules=not args.no_builtin_rules, advisories=args.advisories,
               max_file_mb=args.max_file_mb)
    if not args.quiet:
        sys.stderr.write("\n")
        _print_summary(res)
    if args.json:
        to_json(res, args.json)
        print(f"JSON: {args.json}")
    if args.html:
        to_html(res, args.html)
        print(f"HTML: {args.html}")
    if args.csv:
        for p in to_csv(res, args.csv):
            print(f"CSV:  {p}")
    if args.sarif or args.cyclonedx:
        from .report.interop import to_cyclonedx, to_sarif
        if args.sarif:
            to_sarif(res, args.sarif)
            print(f"SARIF: {args.sarif}")
        if args.cyclonedx:
            to_cyclonedx(res, args.cyclonedx)
            print(f"CycloneDX: {args.cyclonedx}")
    return 2 if _fail(res.findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())

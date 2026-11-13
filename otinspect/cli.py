"""Headless CLI (suited to air-gapped workstations / jump hosts).

Examples:
    otinspect scan D:\\Substation_A --html report.html --json report.json
    otinspect scan ./samples --csv out/ -q --fail-on high
    otinspect diff old.scd new.scd --html diff.html
    otinspect advisories import csaf_files/OT/white -o advisories.json
    otinspect scan D:\\Backup --yara --yara-rules vendor_rules/ --capa --html report.html
    otinspect engines                                  # which detection engines are available
    otinspect ai test                                  # check the internal AI profile
    otinspect ai analyze report.json --task prioritise --lang vi -o plan.md
"""
from __future__ import annotations

import argparse
import json
import os
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
    for name, st in (res.engines or {}).items():
        print(f"\n{name}: " + ", ".join(f"{k} {v}" for k, v in st.items() if v not in ("", None)))
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
    e = s.add_argument_group("detection engines (optional; see 'otinspect engines')")
    e.add_argument("--yara", action="store_true", help="Match files against YARA rules (built-in OT rules + --yara-rules)")
    e.add_argument("--yara-rules", action="append", default=[], metavar="PATH",
                   help="Extra YARA rule file or folder; repeatable (implies --yara)")
    e.add_argument("--no-yara-builtin", action="store_true", help="Use only --yara-rules")
    e.add_argument("--yara-timeout", type=int, default=60, help="Seconds per file (default 60)")
    e.add_argument("--capa", action="store_true", help="Identify capabilities of PE/ELF executables with capa")
    e.add_argument("--capa-path", help="capa executable (default: OTINSPECT_CAPA, capa on PATH, or the flare-capa package)")
    e.add_argument("--capa-rules", default=os.environ.get("OTINSPECT_CAPA_RULES", ""),
                   help="capa rules folder (needed with pip-installed capa; OTINSPECT_CAPA_RULES)")
    e.add_argument("--capa-sigs", default=os.environ.get("OTINSPECT_CAPA_SIGS", ""),
                   help="capa signatures folder (OTINSPECT_CAPA_SIGS)")
    e.add_argument("--capa-timeout", type=float, default=180, help="Seconds per executable (default 180)")
    e.add_argument("--capa-workers", type=int, default=2, help="Parallel capa processes (default 2)")
    e.add_argument("--capa-max-mb", type=float, default=32, help="Skip larger executables (default 32, 0 = no limit)")
    e.add_argument("--no-capa-cache", action="store_true", help="Do not reuse cached capa results")
    e.add_argument("--engine-max-mb", type=float, default=128,
                   help="Skip larger files in YARA (default 128, 0 = no limit)")

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

    en = sub.add_parser("engines", help="Show which optional detection engines (YARA, capa) are available")
    en.add_argument("--capa-path")
    en.add_argument("--yara-rules", action="append", default=[], help="Also check that these rules compile")

    x = sub.add_parser("ai", help="Optional AI assistance through an internal model (LiteLLM gateway, vLLM...)")
    xsub = x.add_subparsers(dest="xcmd", required=True)
    xi = xsub.add_parser("init", help="Write a profile template to edit (API keys are never stored in it)")
    xi.add_argument("--force", action="store_true")
    xsub.add_parser("profiles", help="List configured AI profiles")
    xt = xsub.add_parser("test", help="Check policy, TLS, authentication and model availability")
    xt.add_argument("--profile")
    xa = xsub.add_parser("analyze", help="Analyse a JSON report (or scan a path first) with the AI model")
    xa.add_argument("path", help="JSON report from 'scan --json', or a file/folder to scan")
    xa.add_argument("--profile")
    from .ai.analysis import LANGUAGES, TASKS
    xa.add_argument("--task", default="summary", choices=[t for t in TASKS if t != "explain"])
    xa.add_argument("--question", default="", help="Question for --task question")
    xa.add_argument("--lang", default="en", help=f"Answer language ({', '.join(LANGUAGES)} or any name)")
    xa.add_argument("--preview", action="store_true", help="Print exactly what would be sent, and do not send")
    xa.add_argument("-o", "--output", help="Write the answer to a Markdown file")
    args = ap.parse_args(argv)

    if args.cmd == "ai":
        return _ai(args)

    if args.cmd == "engines":
        return _engines(args)

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

    from .engines import EngineConfig
    eng = EngineConfig(yara=args.yara or bool(args.yara_rules), yara_rules=args.yara_rules,
                       yara_builtin=not args.no_yara_builtin, yara_timeout=args.yara_timeout,
                       capa=args.capa, capa_cmd=args.capa_path, capa_rules=args.capa_rules,
                       capa_sigs=args.capa_sigs, capa_timeout=args.capa_timeout, capa_workers=args.capa_workers,
                       capa_max_mb=args.capa_max_mb, capa_cache=not args.no_capa_cache,
                       max_file_mb=args.engine_max_mb, workers=args.workers)
    res = scan(args.path, recursive=not args.no_recursive, workers=args.workers, progress=prog,
               rules=args.rules, builtin_rules=not args.no_builtin_rules, advisories=args.advisories,
               max_file_mb=args.max_file_mb, engines=eng)
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


def _engines(args) -> int:
    from .engines import EngineConfig, status
    from .engines.yara_engine import compile_rules
    st = status(EngineConfig(capa_cmd=args.capa_path))
    y, c = st["yara"], st["capa"]
    print(f"YARA : {'available' if y['available'] else 'not installed (pip install yara-python, or yara-x)'}"
          f"{' - ' + y['backend'] + ' ' + y['version'] if y['available'] else ''}")
    rc = 0
    if y["available"]:
        rs = compile_rules(args.yara_rules)
        print(f"       {len(rs.files)} rule file(s) compiled (built-in: {y['builtin_rules']})")
        for e in rs.errors:
            print(f"       ! {e}")
            rc = 1
    if c["available"]:
        print(f"capa : available - {c['version']} ({c['command']})")
    else:
        print(f"capa : {c.get('error') or 'not found'} - standalone executable from "
              f"https://github.com/mandiant/capa/releases (set --capa-path / OTINSPECT_CAPA), or pip install flare-capa "
              f"with --capa-rules")
    return rc


def _ai(args) -> int:
    from .ai import (AIConfigError, AIRequestError, ChatClient, check_endpoint, get_api_key, get_profile,
                     load_profiles, load_report, prepare, send)
    from .ai.config import config_path, default_profile_name, save_profiles, template_profile
    try:
        if args.xcmd == "init":
            path = config_path()
            if load_profiles() and not args.force:
                print(f"{path} already has profiles; use --force to overwrite", file=sys.stderr)
                return 1
            t = template_profile()
            save_profiles({t.name: t}, t.name)
            print(f"Template written to {path}\nEdit base_url / model, then set the key in the environment "
                  f"variable {t.api_key_env} (or use the GUI to store it in the OS keyring).")
            return 0
        if args.xcmd == "profiles":
            ps, dflt = load_profiles(), default_profile_name()
            if not ps:
                print(f"No AI profile in {config_path()}")
                return 1
            for p in ps.values():
                print(f"{'*' if p.name == dflt else ' '} {p.name:<20} {p.provider:<18} {p.model:<20} {p.base_url}")
            return 0
        p = get_profile(args.profile)
        if args.xcmd == "test":
            p.validate(resolve=False)
            ips = check_endpoint(p)
            print(f"Endpoint policy : OK ({p.host} -> {', '.join(ips)}"
                  f"{', internal only' if p.internal_only else ''})")
            print(f"API key         : {'found' if get_api_key(p) else 'NOT FOUND'} ({p.secret_store})")
            c = ChatClient(p)
            try:
                models = c.list_models()
                ok = p.model in models
                print(f"Models          : {len(models)} available; '{p.model}' {'found' if ok else 'not listed'}")
            except AIRequestError as e:
                print(f"Models          : not listed ({e})")
            r = c.chat([{"role": "user", "content": "Reply with the single word OK."}])
            print(f"Chat            : OK, model {r.model}, answer {r.text.strip()[:40]!r}")
            return 0
        # analyze
        if args.path.lower().endswith(".json"):
            res = load_report(args.path)
        else:
            from .core.scanner import scan
            res = scan(args.path)
        req = prepare(res, p, args.task, question=args.question, language=args.lang)
        if args.preview:
            print(req.preview())
            return 0
        print(f"Sending {req.stats['chars']:,} characters to {p.host} ({req.stats['masked']})", file=sys.stderr)
        ans = send(req)
        print(ans.text)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(f"<!-- OTInspect AI ({ans.task}, model {ans.model}). Decision support only. -->\n\n")
                fh.write(ans.text + "\n")
            print(f"\nSaved: {args.output}", file=sys.stderr)
        return 0
    except (AIConfigError, AIRequestError, ValueError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

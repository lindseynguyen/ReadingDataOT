"""CLI chạy không cần GUI (phù hợp máy trạm air-gapped / jump host).

Ví dụ:
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
    print(f"\nĐã quét: {res.root}")
    print(f"Tổng file: {len(res.files)}")
    for k, v in res.stats().items():
        print(f"  {k:<12} {v}")
    if res.assets:
        print(f"\nThiết bị ({len(res.assets)}):")
        for a in res.assets:
            print(f"  {a.name:<20} {a.vendor:<14} {a.model:<16} {a.ip:<16} {','.join(a.protocols)}")
    fs = sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity, 9))
    if fs:
        print(f"\nPhát hiện ({len(fs)}):")
        for x in fs:
            print(f"  [{x.severity.upper():<6}] {x.rule:<22} {x.message}")
    errs = [f for f in res.files if f.error]
    if errs:
        print(f"\nLỗi phân tích ({len(errs)}):")
        for f in errs:
            print(f"  {f.path}: {f.error}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="otinspect", description="Kiểm kê và phân tích file OT/ICS")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Quét file hoặc thư mục")
    s.add_argument("path")
    s.add_argument("--no-recursive", action="store_true", help="Không quét thư mục con")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--json", help="Xuất JSON")
    s.add_argument("--html", help="Xuất HTML (in ra PDF từ trình duyệt)")
    s.add_argument("--csv", help="Thư mục xuất files.csv / assets.csv / findings.csv")
    s.add_argument("-q", "--quiet", action="store_true")
    s.add_argument("--fail-on", choices=["high", "medium", "low"],
                   help="Trả exit code 2 nếu có phát hiện từ mức này trở lên (dùng cho CI/kiểm tra định kỳ)")
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

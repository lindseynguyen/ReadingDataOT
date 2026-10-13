"""Scan files/folders: recursion, hashing, identification, parser dispatch, parallelism."""
from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable

from .identify import identify, read_head
from .model import FileRecord, Finding, ScanResult
from .registry import find_parser, load_builtin
from .safexml import MISSING_MSG, available as safexml_available

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".svn"}
ProgressCb = Callable[[int, int, str], None]


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def iter_files(root: str, recursive: bool = True) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    if not recursive:
        for n in sorted(os.listdir(root)):
            p = os.path.join(root, n)
            if os.path.isfile(p):
                yield p
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for n in sorted(filenames):
            yield os.path.join(dirpath, n)


def parser_limit(parser, max_file_mb: float | None = None) -> int | None:
    """Size limit (bytes) for a parser: the global override if given, else the
    parser's own default (None = no limit, the parser streams)."""
    if max_file_mb is not None:
        return int(max_file_mb * 1024 * 1024) if max_file_mb > 0 else None
    return getattr(parser, "max_size", None)


def analyze_file(path: str, display_path: str | None = None,
                 max_file_mb: float | None = None) -> FileRecord:
    shown = display_path or path
    try:
        size = os.path.getsize(path)
        head = read_head(path)
        ident = identify(path, head)
        rec = FileRecord(
            path=shown, size=size, sha256=sha256_file(path),
            category=ident.category, file_type=ident.description,
        )
        rec.summary["entropy_head"] = ident.entropy
        if ident.mime:
            rec.summary["mime"] = ident.mime
        parser = find_parser(rec, ident)
        if parser:
            rec.parser = parser.name
            limit = parser_limit(parser, max_file_mb)
            if limit is not None and size > limit:
                rec.error = (f"{parser.name}: not parsed, file is {size / 1048576:.1f} MB and the limit for "
                             f"this parser is {limit / 1048576:.1f} MB (raise it with --max-file-mb)")
                return rec
            try:
                parser.parse(path, rec)
            except Exception as e:  # a failing parser must not break the whole scan
                rec.error = f"{parser.name}: {type(e).__name__}: {e}"
        return rec
    except OSError as e:
        return FileRecord(path=shown, size=0, sha256="", category="Error", error=str(e))


def scan(root: str, recursive: bool = True, workers: int = 4,
         progress: ProgressCb | None = None, rules: list[str] | None = None,
         builtin_rules: bool = True, advisories: str | None = None,
         max_file_mb: float | None = None) -> ScanResult:
    load_builtin()
    paths = list(iter_files(root, recursive))
    result = ScanResult(root=os.path.abspath(root))
    total = len(paths)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for i, rec in enumerate(ex.map(lambda p: analyze_file(p, max_file_mb=max_file_mb), paths), 1):
            result.files.append(rec)
            if progress:
                progress(i, total, rec.path)
    correlate(result)
    from ..rules import apply_rules, load_rules
    loaded, warns = load_rules(rules, include_builtin=builtin_rules)
    result.warnings = warns
    if not safexml_available():
        result.warnings.insert(0, MISSING_MSG)
    apply_rules(result, loaded)
    advisories = advisories or os.environ.get("OTINSPECT_ADVISORIES")
    if advisories:
        from ..rules.advisories import load_db, match_assets
        try:
            match_assets(result, load_db(advisories))
        except Exception as e:
            result.warnings.append(f"advisory DB {advisories}: {e}")
    from ..standards import annotate
    annotate(result.findings)
    return result


def correlate(result: ScanResult) -> None:
    """Cross-check observed traffic (PCAP hosts) against documented assets
    (SCL, PLC exports...). Undocumented hosts are a classic OT inventory gap."""
    documented: dict[str, str] = {}
    for f in result.files:
        if f.category == "PCAP":
            continue
        for a in f.assets:
            if a.ip:
                documented.setdefault(a.ip, a.name)
    if not documented:
        return
    for f in result.files:
        if f.category != "PCAP":
            continue
        for a in f.assets:
            if a.ip in documented:
                a.extra["documented_as"] = documented[a.ip]
            elif a.extra.get("serves"):
                f.findings.append(Finding(
                    "medium", "XREF-UNDOCUMENTED-HOST",
                    f"{a.ip} serves {', '.join(a.extra['serves'])} on the wire but appears in no configuration file",
                    f.path, a.ip))

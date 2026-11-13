"""Optional third-party detection engines run after parsing: YARA and capa.

Both are opt-in (``--yara`` / ``--capa`` or the GUI checkboxes). A missing engine, a broken
rule file, a timeout or a crash on one file is reported as a warning or a per-file note;
it never stops the scan. Nothing is executed: YARA matches bytes, capa analyses statically
in a separate, time-limited process.
"""
from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from ..core.model import Finding, ScanResult
from . import capa_engine, yara_engine

CAPA_CATEGORIES = {"Executable"}
CAPA_EXT = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".elf", ".so", ".ko", ".bin"}
SKIP_YARA_EXT = yara_engine.RULE_EXT          # do not flag rule sources found in a backup


@dataclass
class EngineConfig:
    yara: bool = False
    yara_rules: list[str] = field(default_factory=list)
    yara_builtin: bool = True
    yara_timeout: int = 60
    capa: bool = False
    capa_cmd: str | list[str] | None = None   # path, argv list, or None = auto-detect
    capa_rules: str = ""
    capa_sigs: str = ""
    capa_timeout: float = 180.0
    capa_workers: int = 2
    capa_max_mb: float = 32.0
    capa_cache: bool = True
    max_file_mb: float = 128.0
    workers: int = 4

    @property
    def enabled(self) -> bool:
        return self.yara or self.capa


def cache_dir() -> str:
    return os.environ.get("OTINSPECT_CACHE") or os.path.join(os.path.expanduser("~"), ".otinspect", "cache")


def status(cfg: EngineConfig | None = None) -> dict:
    """Availability and versions, for `otinspect engines` and the GUI."""
    cfg = cfg or EngineConfig()
    b, v = yara_engine.backend_info()
    out = {"yara": {"available": bool(b), "backend": b, "version": v, "builtin_rules": yara_engine.BUILTIN_RULES}}
    cmd = capa_engine.find_capa(cfg.capa_cmd)
    cap = {"available": False, "command": " ".join(cmd) if cmd else "", "version": ""}
    if cmd:
        try:
            cap["version"] = capa_engine.capa_version(cmd)
            cap["available"] = True
        except RuntimeError as e:
            cap["error"] = str(e)
    out["capa"] = cap
    return out


def _real(path: str) -> bool:
    return os.path.isfile(path) and not os.path.islink(path)


def run_engines(result: ScanResult, cfg: EngineConfig,
                progress: Callable[[int, int, str], None] | None = None) -> None:
    if not cfg.enabled:
        return
    info: dict = {}
    lock = threading.Lock()
    limit = int(cfg.max_file_mb * 1048576) if cfg.max_file_mb and cfg.max_file_mb > 0 else None

    # ------------------------------------------------------------------ YARA
    if cfg.yara:
        rs = yara_engine.compile_rules(cfg.yara_rules, builtin=cfg.yara_builtin)
        result.warnings += rs.errors
        info["yara"] = {"backend": rs.backend, "version": rs.version, "rule_files": len(rs.files),
                        "scanned": 0, "matched_files": 0, "skipped": 0, "errors": 0}
        if rs.ok:
            todo = [f for f in result.files if _real(f.path) and f.size > 0
                    and not f.path.lower().endswith(SKIP_YARA_EXT)]
            info["yara"]["skipped"] = len(result.files) - len(todo)

            def yara_one(rec):
                if limit is not None and rec.size > limit:
                    rec.summary["yara_note"] = f"not scanned: larger than {cfg.max_file_mb:g} MB"
                    with lock:
                        info["yara"]["skipped"] += 1
                    return
                try:
                    matches = yara_engine.scan_file(rs, rec.path, cfg.yara_timeout)
                except (TimeoutError, RuntimeError, OSError) as e:
                    rec.summary["yara_note"] = str(e)
                    with lock:
                        info["yara"]["errors"] += 1
                    return
                with lock:
                    info["yara"]["scanned"] += 1
                    info["yara"]["matched_files"] += bool(matches)
                if not matches:
                    return
                rec.summary["yara"] = [{"rule": m.rule, "namespace": m.namespace, "tags": m.tags,
                                        "strings": m.strings[:20], "first_offset": m.first_offset}
                                       for m in matches]
                for m in matches:
                    desc = str(m.meta.get("description") or m.meta.get("desc") or "")
                    where = f" at offset {m.first_offset:#x}" if m.first_offset is not None else ""
                    f = Finding(yara_engine.severity(m.meta), f"YARA-{m.rule}",
                                f"YARA {m.rule}{': ' + desc if desc else ''} "
                                f"({len(m.strings)} pattern{'s' if len(m.strings) != 1 else ''}{where})",
                                rec.path)
                    f.iec62443 = yara_engine.split_list(m.meta.get("iec62443"))
                    f.attack = yara_engine.split_list(m.meta.get("attack"))
                    rec.findings.append(f)

            _pool(todo, yara_one, cfg.workers, progress, "YARA")

    # ------------------------------------------------------------------ capa
    if cfg.capa:
        cmd = capa_engine.find_capa(cfg.capa_cmd)
        info["capa"] = {"command": " ".join(cmd) if cmd else "", "version": "", "analysed": 0, "cached": 0,
                        "unsupported": 0, "skipped": 0, "errors": 0}
        version = ""
        if not cmd:
            result.warnings.append("capa requested but not found: install the standalone capa executable "
                                   "(github.com/mandiant/capa/releases) and set --capa-path, or pip install flare-capa")
        else:
            try:
                version = capa_engine.capa_version(cmd)
                info["capa"]["version"] = version
            except RuntimeError as e:
                result.warnings.append(str(e))
                cmd = None
        for p in (cfg.capa_rules, cfg.capa_sigs):
            if p and not os.path.exists(p):
                result.warnings.append(f"capa path not found: {p}")
                cmd = None
        if cmd:
            cdir = os.path.join(cache_dir(), "capa")
            cmax = int(cfg.capa_max_mb * 1048576) if cfg.capa_max_mb and cfg.capa_max_mb > 0 else None
            todo = [f for f in result.files if _real(f.path) and f.size > 0 and (
                f.category in CAPA_CATEGORIES or (os.path.splitext(f.path)[1].lower() in CAPA_EXT
                                                  and f.category in ("Firmware", "Binary")))]
            stop = threading.Event()

            def capa_one(rec):
                if stop.is_set():
                    return
                if cmax is not None and rec.size > cmax:
                    rec.summary["capa_note"] = f"not analysed: larger than {cfg.capa_max_mb:g} MB"
                    with lock:
                        info["capa"]["skipped"] += 1
                    return
                key = capa_engine.cache_key(rec.sha256, version, cfg.capa_rules, cfg.capa_sigs)
                cpath = os.path.join(cdir, key + ".json")
                res = _cache_get(cpath) if cfg.capa_cache and rec.sha256 else None
                if res is not None:
                    with lock:
                        info["capa"]["cached"] += 1
                else:
                    res = capa_engine.analyse(cmd, rec.path, cfg.capa_rules, cfg.capa_sigs, cfg.capa_timeout)
                    if res.ok and cfg.capa_cache and rec.sha256:
                        _cache_put(cpath, res)
                    if res.error.startswith("capa exit 10") or res.error.startswith("capa cannot be started"):
                        stop.set()                    # configuration problem: same for every file
                        with lock:
                            msg = res.error
                            if msg not in result.warnings:
                                result.warnings.append(msg)
                        return
                with lock:
                    if res.ok:
                        info["capa"]["analysed"] += 1
                    elif res.note:
                        info["capa"]["unsupported"] += 1
                    else:
                        info["capa"]["errors"] += 1
                _apply_capa(rec, res)

            _pool(todo, capa_one, max(1, cfg.capa_workers), progress, "capa")
    result.engines = info


def _apply_capa(rec, res: capa_engine.CapaResult) -> None:
    if not res.ok:
        rec.summary["capa_note"] = res.note or res.error
        return
    rec.summary["capa"] = {"format": res.fmt, "arch": res.arch, "os": res.os,
                           "capabilities": res.capabilities[:300], "count": len(res.capabilities)}
    for g in capa_engine.classify(res.capabilities):
        names = g["names"]
        shown = ", ".join(names[:5]) + (f" (+{len(names) - 5} more)" if len(names) > 5 else "")
        ent = f"; ATT&CK Enterprise {', '.join(g['enterprise'][:6])}" if g["enterprise"] else ""
        f = Finding(g["severity"], g["rule"], f"capa: executable {g['label']}: {shown}{ent}", rec.path)
        f.iec62443, f.attack = list(g["iec"]), list(g["attack"])
        rec.findings.append(f)


def _cache_get(path: str) -> capa_engine.CapaResult | None:
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return capa_engine.CapaResult(True, d["capabilities"], d.get("fmt", ""), d.get("arch", ""), d.get("os", ""))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _cache_put(path: str, res: capa_engine.CapaResult) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"capabilities": res.capabilities, "fmt": res.fmt, "arch": res.arch, "os": res.os}, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def _pool(items, fn, workers, progress, label) -> None:
    total = len(items)
    if not total:
        return
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as ex:
        for i, _ in enumerate(ex.map(_guard(fn), items), 1):
            if progress:
                progress(i, total, f"{label}: {items[i - 1].path}")


def _guard(fn):
    def run(rec):
        try:
            fn(rec)
        except Exception as e:                        # never let one file break the scan
            rec.summary["engine_error"] = f"{type(e).__name__}: {e}"
    return run

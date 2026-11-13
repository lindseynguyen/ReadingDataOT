"""YARA scanning with yara-python (libyara 4.x) or YARA-X, whichever is installed.

Each rule file is compiled on its own first, so one broken user rule file is reported
and skipped instead of disabling every rule. Matching is read-only, time-limited and
size-limited; matched bytes are never copied into reports (they may contain secrets).
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
BUILTIN_RULES = os.path.join(HERE, "rules", "otinspect_builtin.yar")
RULE_EXT = (".yar", ".yara", ".rule", ".rules")
SEVERITIES = {"high", "medium", "low", "info"}
_SEV_ALIASES = {"critical": "high", "crit": "high", "warning": "medium", "moderate": "medium",
                "informational": "info", "none": "info"}
MAX_MATCHES_PER_FILE = 50


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    strings: list[str]          # identifiers only, e.g. ["$a", "$b"]
    first_offset: int | None


@dataclass
class YaraRuleSet:
    backend: str                # "yara-python" | "yara-x"
    version: str
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _rules: object = None
    _local: threading.local = field(default_factory=threading.local)

    @property
    def ok(self) -> bool:
        return self._rules is not None


def backend_info() -> tuple[str, str]:
    """('yara-python', '4.5.4'), ('yara-x', '1.x'), or ('', '') if neither is installed."""
    pref = os.environ.get("OTINSPECT_YARA_BACKEND", "").lower()
    order = ("yara-x", "yara-python") if pref in ("yara-x", "yara_x", "yarax") else ("yara-python", "yara-x")
    for name in order:
        try:
            if name == "yara-python":
                import yara
                if not hasattr(yara, "compile"):          # some unrelated 'yara' module
                    continue
                return name, getattr(yara, "YARA_VERSION", getattr(yara, "__version__", "?"))
            import yara_x
            try:
                from importlib.metadata import version
                v = version("yara-x")
            except Exception:
                v = getattr(yara_x, "__version__", "?")
            return name, v
        except ImportError:
            continue
    return "", ""


def collect_rule_files(paths: list[str]) -> tuple[list[str], list[str]]:
    files, errors = [], []
    for p in paths:
        if os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = sorted(d for d in dn if not d.startswith("."))
                files += [os.path.join(dp, f) for f in sorted(fn) if f.lower().endswith(RULE_EXT)]
        elif os.path.isfile(p):
            files.append(p)
        else:
            errors.append(f"YARA rules not found: {p}")
    return files, errors


def _namespace(path: str, used: set) -> str:
    base = "".join(c if c.isalnum() else "_" for c in os.path.splitext(os.path.basename(path))[0]) or "rules"
    ns, i = base, 2
    while ns in used:
        ns, i = f"{base}_{i}", i + 1
    used.add(ns)
    return ns


def compile_rules(paths: list[str], builtin: bool = True) -> YaraRuleSet:
    backend, version = backend_info()
    rs = YaraRuleSet(backend=backend, version=version)
    if not backend:
        rs.errors.append("YARA requested but neither yara-python nor yara-x is installed "
                         "(pip install yara-python, or pip install yara-x)")
        return rs
    files, errs = collect_rule_files(([BUILTIN_RULES] if builtin else []) + list(paths or []))
    rs.errors += errs
    used: set = set()
    if backend == "yara-python":
        import yara
        good = {}
        for f in files:
            ns = _namespace(f, used)
            try:
                yara.compile(filepaths={ns: f})
                good[ns] = f
            except Exception as e:                    # yara.SyntaxError, yara.Error, OSError
                rs.errors.append(f"YARA rule file skipped: {f}: {e}")
        if good:
            rs._rules = yara.compile(filepaths=good)
            rs.files = list(good.values())
    else:
        import yara_x
        comp = yara_x.Compiler()
        for f in files:
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
                comp.new_namespace(_namespace(f, used))
                comp.add_source(src)
                rs.files.append(f)
            except Exception as e:                    # yara_x.CompileError, OSError
                rs.errors.append(f"YARA rule file skipped: {f}: {str(e).splitlines()[0] if str(e) else e}")
        if rs.files:
            rs._rules = comp.build()
    if rs.ok and not rs.files:
        rs._rules = None
    return rs


def _meta_dict(meta) -> dict:
    if isinstance(meta, dict):
        return dict(meta)
    out: dict = {}
    for k, v in meta or ():                            # yara-x: tuple of (key, value)
        out.setdefault(k, v)
    return out


def _yp_strings(m) -> tuple[list[str], int | None]:
    ids, first = [], None
    for s in getattr(m, "strings", []) or []:
        if isinstance(s, tuple):                       # yara-python < 4.3: (offset, identifier, data)
            off, ident = s[0], s[1]
        else:                                          # >= 4.3: StringMatch(identifier, instances)
            ident = s.identifier
            inst = list(getattr(s, "instances", []) or [])
            off = inst[0].offset if inst else None
        if ident not in ids:
            ids.append(ident)
        if off is not None and (first is None or off < first):
            first = off
    return ids, first


def scan_file(rs: YaraRuleSet, path: str, timeout: int = 60) -> list[YaraMatch]:
    """Match one file. Raises TimeoutError on timeout, RuntimeError on engine errors."""
    if not rs.ok:
        return []
    out: list[YaraMatch] = []
    if rs.backend == "yara-python":
        import yara
        try:
            if os.name == "nt" and not path.isascii():
                # libyara opens files with the ANSI API on Windows: non-ASCII paths fail, so pass the bytes
                matches = rs._rules.match(data=_read(path), timeout=int(timeout))
            else:
                matches = rs._rules.match(path, timeout=int(timeout))
        except yara.TimeoutError:
            raise TimeoutError(f"YARA timed out after {timeout} s") from None
        except yara.Error as e:
            if "could not open" in str(e).lower() and os.path.isfile(path):
                try:
                    matches = rs._rules.match(data=_read(path), timeout=int(timeout))
                except yara.TimeoutError:
                    raise TimeoutError(f"YARA timed out after {timeout} s") from None
                except yara.Error as e2:
                    raise RuntimeError(f"YARA: {e2}") from None
            else:
                raise RuntimeError(f"YARA: {e}") from None
        for m in matches[:MAX_MATCHES_PER_FILE]:
            ids, first = _yp_strings(m)
            out.append(YaraMatch(m.rule, m.namespace, list(m.tags or []), _meta_dict(m.meta), ids, first))
        return out
    import yara_x
    sc = getattr(rs._local, "scanner", None)
    if sc is None:                                     # a YARA-X scanner is not thread-safe: one per thread
        sc = yara_x.Scanner(rs._rules)
        rs._local.scanner = sc
    sc.set_timeout(int(timeout))
    try:
        res = sc.scan_file(path)
    except yara_x.TimeoutError:
        raise TimeoutError(f"YARA timed out after {timeout} s") from None
    except yara_x.ScanError as e:
        raise RuntimeError(f"YARA: {e}") from None
    for m in list(res.matching_rules)[:MAX_MATCHES_PER_FILE]:
        ids, first = [], None
        for p in m.patterns:
            ms = list(p.matches)
            if ms:
                ids.append(p.identifier)
                off = ms[0].offset
                first = off if first is None else min(first, off)
        out.append(YaraMatch(m.identifier, m.namespace, list(getattr(m, "tags", ()) or ()),
                             _meta_dict(m.metadata), ids, first))
    return out


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def severity(meta: dict, default: str = "medium") -> str:
    s = str(meta.get("severity", meta.get("threat_level", ""))).strip().lower()
    s = _SEV_ALIASES.get(s, s)
    if s in SEVERITIES:
        return s
    try:                                               # numeric scores (0-100 or 0-10)
        n = float(s)
        n = n / 10 if n > 10 else n
        return "high" if n >= 7 else "medium" if n >= 4 else "low" if n > 0 else "info"
    except ValueError:
        return default


def split_list(v) -> list[str]:
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").split(",") if x.strip()]

"""ZIP archives (including Siemens TIA .zap/.ap, ...): list contents and
identify each member without extracting to disk."""
from __future__ import annotations

import os
import tempfile
import zipfile
from collections import Counter

from ..core.identify import Identity, identify
from ..core.model import FileRecord, Finding
from ..core.registry import find_parser, register

MAX_MEMBERS = 5000
MAX_RATIO = 200          # zip bomb guard
NESTED_MAX = 50 * 1024 * 1024
NESTED_CATEGORIES = {"SCL", "PLC", "DeviceDesc", "NetConfig"}


@register
class ZipParser:
    name = "zip"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return ident.description.startswith(("ZIP", "Siemens TIA")) or rec.path.lower().endswith(".zip")

    def parse(self, path: str, rec: FileRecord) -> None:
        if not zipfile.is_zipfile(path):
            return
        cats: Counter = Counter()
        members = []
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            rec.summary["member_count"] = len(infos)
            total = sum(i.file_size for i in infos)
            comp = sum(i.compress_size for i in infos) or 1
            if total / comp > MAX_RATIO:
                rec.findings.append(Finding("medium", "ZIP-BOMB",
                                            f"Abnormal compression ratio ({total // comp}x)", rec.path))
                return
            for info in infos[:MAX_MEMBERS]:
                if info.is_dir():
                    continue
                if info.filename.startswith("/") or ".." in info.filename.split("/"):
                    rec.findings.append(Finding("medium", "ZIP-PATH-TRAVERSAL",
                                                f"Entry with dangerous path: {info.filename}", rec.path))
                    continue
                with zf.open(info) as fh:
                    head = fh.read(4096)
                ident = identify(info.filename, head)
                cats[ident.category] += 1
                if ident.category in NESTED_CATEGORIES and info.file_size <= NESTED_MAX:
                    self._nested(zf, info, ident, rec)
                members.append({"name": info.filename, "size": info.file_size,
                                "category": ident.category, "type": ident.description})
        rec.summary["member_categories"] = dict(cats)
        rec.summary["ot_members"] = [m for m in members if m["category"] not in ("Unknown", "Text", "Binary")][:200]

    @staticmethod
    def _nested(zf, info, ident, rec: FileRecord) -> None:
        """Run the matching parser on a supported member (e.g. an SCD or AML inside a
        TIA/contractor archive). Results are merged into the archive's record."""
        inner = FileRecord(path=f"{rec.path}!{info.filename}", size=info.file_size, sha256="",
                           category=ident.category, file_type=ident.description)
        parser = find_parser(inner, ident)
        if parser is None or parser.name in ("zip", "binary"):
            return
        suffix = os.path.splitext(info.filename)[1]
        fd, tmp = tempfile.mkstemp(suffix=suffix)
        try:
            with os.fdopen(fd, "wb") as out, zf.open(info) as src:
                out.write(src.read(NESTED_MAX))
            parser.parse(tmp, inner)
        except Exception as e:
            rec.summary.setdefault("nested_errors", []).append(f"{info.filename}: {type(e).__name__}: {e}")
            return
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        for a in inner.assets:
            a.source = inner.path
        for f in inner.findings:
            f.source = inner.path
        rec.assets.extend(inner.assets)
        rec.findings.extend(inner.findings)
        rec.summary.setdefault("nested", []).append(
            {"member": info.filename, "parser": parser.name, "assets": len(inner.assets),
             "findings": len(inner.findings)})

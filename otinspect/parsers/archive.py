"""ZIP archives (including Siemens TIA .zap/.ap, ...): list contents and
identify each member without extracting to disk."""
from __future__ import annotations

import zipfile
from collections import Counter

from ..core.identify import Identity, identify
from ..core.model import FileRecord, Finding
from ..core.registry import register

MAX_MEMBERS = 5000
MAX_RATIO = 200          # zip bomb guard


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
                members.append({"name": info.filename, "size": info.file_size,
                                "category": ident.category, "type": ident.description})
        rec.summary["member_categories"] = dict(cats)
        rec.summary["ot_members"] = [m for m in members if m["category"] not in ("Unknown", "Text", "Binary")][:200]

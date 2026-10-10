"""Quét file/thư mục: đệ quy, hash, nhận dạng, gọi parser, chạy song song."""
from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable

from .identify import identify, read_head
from .model import FileRecord, ScanResult
from .registry import find_parser, load_builtin

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


def analyze_file(path: str, display_path: str | None = None) -> FileRecord:
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
            try:
                parser.parse(path, rec)
            except Exception as e:  # parser lỗi không làm hỏng cả lần quét
                rec.error = f"{parser.name}: {type(e).__name__}: {e}"
        return rec
    except OSError as e:
        return FileRecord(path=shown, size=0, sha256="", category="Error", error=str(e))


def scan(root: str, recursive: bool = True, workers: int = 4,
         progress: ProgressCb | None = None) -> ScanResult:
    load_builtin()
    paths = list(iter_files(root, recursive))
    result = ScanResult(root=os.path.abspath(root))
    total = len(paths)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for i, rec in enumerate(ex.map(analyze_file, paths), 1):
            result.files.append(rec)
            if progress:
                progress(i, total, rec.path)
    return result

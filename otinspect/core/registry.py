"""Đăng ký parser. Thêm loại file mới = thêm 1 module trong otinspect/parsers
và gắn decorator @register.
"""
from __future__ import annotations

from typing import Callable, Protocol

from .identify import Identity
from .model import FileRecord


class Parser(Protocol):
    name: str

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool: ...
    def parse(self, path: str, rec: FileRecord) -> None: ...


_PARSERS: list[Parser] = []


def register(cls: Callable[[], Parser]):
    _PARSERS.append(cls())
    return cls


def find_parser(rec: FileRecord, ident: Identity) -> Parser | None:
    for p in _PARSERS:
        if p.can_parse(rec, ident):
            return p
    return None


def load_builtin() -> None:
    # import để chạy decorator @register (thứ tự = độ ưu tiên)
    from ..parsers import scl, logfile, archive, binary  # noqa: F401

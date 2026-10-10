"""Parser registry. To support a new file type, add a module in otinspect/parsers
decorated with @register.
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


BUILTIN_PARSERS = ("scl", "comtrade", "pcap", "plc_l5x", "plc_iec", "devicedesc",
                   "logfile", "archive", "binary")      # order = priority


def load_builtin() -> None:
    """Import the built-in parser modules so their @register decorators run."""
    import importlib
    for name in BUILTIN_PARSERS:
        importlib.import_module(f"{__package__.rsplit('.', 1)[0]}.parsers.{name}")

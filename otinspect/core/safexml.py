"""Hardened XML parsing for untrusted OT files.

Every XML parser in OTInspect goes through ``safe_parse``. It requires
defusedxml (blocks XXE, external entities and entity-expansion bombs) and
fails closed: if defusedxml is missing, XML files are reported as parse
errors instead of being read with the unprotected standard-library parser.
"""
from __future__ import annotations

try:
    from defusedxml.ElementTree import parse as _defused_parse  # type: ignore
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    _defused_parse = None

MISSING_MSG = ("defusedxml is not installed; XML files are not parsed "
               "(install it with: pip install defusedxml)")


class InsecureXMLParserError(RuntimeError):
    """Raised instead of parsing XML without defusedxml."""


def available() -> bool:
    return _defused_parse is not None


def safe_parse(source):
    if _defused_parse is None:
        raise InsecureXMLParserError(MISSING_MSG)
    return _defused_parse(source)


try:
    from defusedxml.ElementTree import iterparse as _defused_iterparse  # type: ignore
except ImportError:  # pragma: no cover
    _defused_iterparse = None


def safe_iterparse(source, events=("start", "end")):
    """Streaming variant of safe_parse for very large files (SCD of a whole
    substation can be hundreds of MB). Same fail-closed behaviour."""
    if _defused_iterparse is None or _defused_parse is None:
        raise InsecureXMLParserError(MISSING_MSG)
    return _defused_iterparse(source, events=events)

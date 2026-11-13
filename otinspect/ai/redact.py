"""Pseudonymisation of scan data before it is sent to a model.

Values are replaced by stable tokens (``IP-3``, ``MAC-1``, ``ASSET-7``, ``FILE-2``) so the
model can still reason about relationships ("IP-3 sends a stop command to ASSET-7"). The
mapping never leaves the machine: :meth:`Redactor.restore` puts the real values back into
the answer locally. Secrets are replaced by ``[SECRET]`` and are never restored.
"""
from __future__ import annotations

import ipaddress
import os
import re

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![\w:])")
_MAC = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])"
                  r"|(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PATH = re.compile(r"(?<![\w])(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|*?,;]+"          # C:\dir\file, \\server\share
                   r"|(?<![\w:/.])/(?:[\w.-]+/)+[\w.-]+")              # /dir/sub/file
_STOP = ["is", "was", "are", "stores", "stored", "cleartext", "reversible", "type", "allows", "allowed",
         "not", "appears", "with", "the", "a", "an", "and", "or", "in", "on", "for", "set", "uses", "used",
         "configured", "found", "of", "to", "missing", "without", "policy", "length", "change", "changed",
         "protection", "encryption", "algorithm-type", "required", "enabled", "disabled", "hash", "level",
         "secret", "password", "community", r"\[SECRET\]", "read-only", "read-write", "ro", "rw",
         "default", "well-known", "authentication", "auth", "via", "from"]
_SECRETS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|community|psk|pre-shared-key|api[_-]?key|token|"
               r"key-string)(\s*[:=]?\s*)(?:[0-9]\s+)?(?!(?:" + "|".join(_STOP) + r")\b)"
               r"(?![^\s]*\*\*\*)(?=[^\s,;)]*[A-Za-z0-9])([^\s,;)]+)"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}=*"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),   # JWT
]
_TOKEN = re.compile(r"\b(?:IP|MAC|ASSET|FILE|EMAIL)-\d+\b")


class Redactor:
    def __init__(self, mask_ips: bool = True, mask_macs: bool = True, mask_names: bool = True,
                 mask_paths: bool = True, mask_secrets: bool = True):
        self.mask_ips, self.mask_macs, self.mask_names = mask_ips, mask_macs, mask_names
        self.mask_paths, self.mask_secrets = mask_paths, mask_secrets
        self._fwd: dict[tuple[str, str], str] = {}
        self._rev: dict[str, str] = {}
        self._names: list[str] = []
        self.counts: dict[str, int] = {}
        self.secrets = 0

    @classmethod
    def from_profile(cls, p) -> Redactor:
        return cls(p.mask_ips, p.mask_macs, p.mask_names, p.mask_paths, p.mask_secrets)

    # ------------------------------------------------------------------ tokens
    def _tok(self, kind: str, value: str) -> str:
        key = (kind, value.lower() if kind in ("MAC", "EMAIL", "ASSET") else value)
        if key not in self._fwd:
            n = self.counts.get(kind, 0) + 1
            self.counts[kind] = n
            tok = f"{kind}-{n}"
            self._fwd[key] = tok
            self._rev[tok] = value
        return self._fwd[key]

    def add_names(self, names) -> None:
        """Register asset / host names so they are replaced wherever they appear."""
        if not self.mask_names:
            return
        for n in names:
            n = (n or "").strip()
            if len(n) >= 3 and not _TOKEN.fullmatch(n) and n.lower() not in _GENERIC:
                self._names.append(n)
        self._names = sorted(set(self._names), key=len, reverse=True)

    def name(self, value: str) -> str:
        if not value or not self.mask_names:
            return value
        return self._tok("ASSET", value)

    def path(self, value: str) -> str:
        if not value or not self.mask_paths:
            return value
        ext = os.path.splitext(value)[1].lower()
        return self._tok("FILE", value) + (ext if ext and len(ext) <= 8 else "")

    # ------------------------------------------------------------------ text
    def text(self, s: str) -> str:
        if not s:
            return s
        if self.mask_secrets:
            for rx in _SECRETS:
                s, n = rx.subn(self._secret_sub, s)
                self.secrets += n
        if self.mask_names and self._names:
            for n in self._names:
                s = re.sub(rf"(?<![\w-]){re.escape(n)}(?![\w-])", lambda m: self._tok("ASSET", m.group(0)), s,
                           flags=re.I)
        if self.mask_macs:
            s = _MAC.sub(lambda m: self._tok("MAC", m.group(0)), s)
        if self.mask_ips:
            s = _IPV4.sub(self._ip_sub, s)
            s = _IPV6.sub(self._ip_sub, s)
        if self.mask_paths:
            s = _PATH.sub(lambda m: self.path(m.group(0)), s)
        s = _EMAIL.sub(lambda m: self._tok("EMAIL", m.group(0)), s)
        return s

    @staticmethod
    def _secret_sub(m: re.Match) -> str:
        if m.re.groups >= 3:
            return f"{m.group(1)}{m.group(2)}[SECRET]"
        return "[SECRET]"

    def _ip_sub(self, m: re.Match) -> str:
        v = m.group(0)
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            return v          # version strings such as 1.2.3.4 that are not valid addresses stay
        if v.count(":") >= 2 and not any(c.isdigit() for c in v):
            return v
        return self._tok("IP", v)

    def value(self, v):
        """Redact any JSON-like value recursively."""
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {k: self.value(x) for k, x in v.items()}
        return v

    # ------------------------------------------------------------------ restore
    def restore(self, s: str) -> str:
        if not s or not self._rev:
            return s
        return _TOKEN.sub(lambda m: self._rev.get(m.group(0), m.group(0)), s)

    def summary(self) -> str:
        parts = [f"{v} {k.lower()}{'s' if v != 1 else ''}" for k, v in sorted(self.counts.items())]
        if self.secrets:
            parts.append(f"{self.secrets} secret{'s' if self.secrets != 1 else ''} removed")
        return ", ".join(parts) or "nothing to mask"


_GENERIC = {"ied", "plc", "hmi", "rtu", "switch", "router", "firewall", "unknown", "host", "server",
            "device", "station", "none", "n/a", "default", "test", "main", "gateway"}

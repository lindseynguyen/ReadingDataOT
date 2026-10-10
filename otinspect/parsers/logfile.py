"""Log / text / config parser: severity counts, time range, IPs seen,
and cleartext secrets (passwords, SNMP communities...)."""
from __future__ import annotations

import re
from collections import Counter

from ..core.identify import Identity
from ..core.model import FileRecord, Finding
from ..core.registry import register

MAX_LINES = 2_000_000
LEVELS = {
    "error": re.compile(r"\b(error|err|fail(ed|ure)?|fatal|critical|crit)\b", re.I),
    "warning": re.compile(r"\b(warn(ing)?|timeout|timed out|retry)\b", re.I),
    "alarm": re.compile(r"\b(alarm|trip|fault|interlock|breaker)\b", re.I),
    "auth": re.compile(r"\b(login|logon|logged in|authenticat\w*|password|access denied)\b", re.I),
}
TS_RE = re.compile(r"(\d{4}[-/.]\d{2}[-/.]\d{2})[ T](\d{2}:\d{2}:\d{2})")
IP_RE = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")
SECRET_RES = [
    ("CFG-CLEARTEXT-PASSWORD", re.compile(r"(?i)\b(pass(word)?|pwd)\s*[:=]\s*['\"]?([^\s'\";]{3,})")),
    ("CFG-SNMP-COMMUNITY", re.compile(r"(?i)\bsnmp[-_ ]?(server )?community\s+(\S+)")),
    ("CFG-PRIVATE-KEY", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
TEXT_CATEGORIES = {"Log", "Text", "Config", "Data", "XML"}


def _mask(s: str) -> str:
    return s[:2] + "*" * max(0, len(s) - 2) if len(s) > 2 else "**"


@register
class LogParser:
    name = "text"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return ident.is_text and rec.category in TEXT_CATEGORIES

    def parse(self, path: str, rec: FileRecord) -> None:
        counts: Counter = Counter()
        samples: dict[str, list[str]] = {k: [] for k in LEVELS}
        ips: Counter = Counter()
        first_ts = last_ts = ""
        lines = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                lines += 1
                if lines > MAX_LINES:
                    rec.summary["truncated"] = True
                    break
                for lvl, rx in LEVELS.items():
                    if rx.search(line):
                        counts[lvl] += 1
                        if len(samples[lvl]) < 5:
                            samples[lvl].append(line.strip()[:200])
                m = TS_RE.search(line)
                if m:
                    ts = f"{m.group(1)} {m.group(2)}"
                    first_ts = first_ts or ts
                    last_ts = ts
                for ip in IP_RE.findall(line):
                    ips[ip] += 1
                for rule, rx in SECRET_RES:
                    sm = rx.search(line)
                    if sm and len([f for f in rec.findings if f.rule == rule]) < 5:
                        val = sm.group(sm.lastindex or 0)
                        rec.findings.append(Finding(
                            "high" if rule != "CFG-SNMP-COMMUNITY" or val.lower() in ("public", "private") else "medium",
                            rule, f"Line {lines}: cleartext secret found ({_mask(val)})", rec.path))
        rec.summary.update({
            "lines": lines,
            "levels": dict(counts),
            "samples": {k: v for k, v in samples.items() if v},
            "time_range": [first_ts, last_ts] if first_ts else [],
            "top_ips": dict(ips.most_common(20)),
        })

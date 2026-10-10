"""Generic binary / firmware parser: entropy, embedded signatures, interesting strings,
Intel HEX address range. Replaces the arbitrary struct.unpack of the old version."""
from __future__ import annotations

import re

from ..core.identify import Identity, shannon_entropy
from ..core.model import FileRecord, Finding
from ..core.registry import register

SCAN_LIMIT = 64 * 1024 * 1024
STR_RE = re.compile(rb"[\x20-\x7e]{6,}")
INTERESTING = re.compile(
    rb"(?i)(version|firmware|v\d+\.\d+(\.\d+)?|copyright|siemens|schneider|abb|rockwell|"
    rb"allen-bradley|ge |sel-|moxa|hirschmann|ruggedcom|busybox|linux|vxworks|codesys|"
    rb"password|passwd|admin|root:|telnet|ftp|http://|https://)"
)
EMBED_SIGS = [
    (b"hsqs", "SquashFS"), (b"\x27\x05\x19\x56", "U-Boot uImage"),
    (b"\x1f\x8b\x08", "GZIP stream"), (b"PK\x03\x04", "ZIP"),
    (b"\x7fELF", "ELF"), (b"-----BEGIN", "PEM (key/certificate)"),
    (b"\x5d\x00\x00\x80\x00", "LZMA"), (b"UBI#", "UBI image"),
    (b"\x85\x19\x03\x20", "JFFS2"), (b"CrAm", "CramFS"),
]


def _intel_hex(path: str) -> dict:
    lo, hi, base, records, bad = None, None, 0, 0, 0
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith(":") or len(line) < 11:
                continue
            records += 1
            try:
                raw = bytes.fromhex(line[1:])
            except ValueError:
                bad += 1
                continue
            if sum(raw) & 0xFF:
                bad += 1
            n, addr, rtype = raw[0], (raw[1] << 8) | raw[2], raw[3]
            if rtype == 0x00:
                a = base + addr
                lo = a if lo is None else min(lo, a)
                hi = a + n if hi is None else max(hi, a + n)
            elif rtype == 0x04:
                base = int.from_bytes(raw[4:6], "big") << 16
            elif rtype == 0x02:
                base = int.from_bytes(raw[4:6], "big") << 4
    return {"records": records, "checksum_errors": bad,
            "address_range": [hex(lo), hex(hi)] if lo is not None else []}


@register
class BinaryParser:
    name = "binary"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return rec.category in ("Firmware", "Binary", "Executable", "OLE") or \
            (not ident.is_text and rec.category in ("PLC", "HMI", "IED", "COMTRADE"))

    def parse(self, path: str, rec: FileRecord) -> None:
        if rec.file_type == "Intel HEX image":
            rec.summary["intel_hex"] = _intel_hex(path)
            return
        with open(path, "rb") as fh:
            data = fh.read(SCAN_LIMIT)
        rec.summary["entropy"] = round(shannon_entropy(data), 3)
        # per-64KB-block entropy to reveal compressed/encrypted regions
        blocks = [round(shannon_entropy(data[i:i + 65536]), 2) for i in range(0, min(len(data), 65536 * 64), 65536)]
        rec.summary["entropy_blocks"] = blocks
        rec.summary["header_hex"] = data[:16].hex(" ")

        embedded = []
        for sig, name in EMBED_SIGS:
            start = 1  # skip offset 0 (that is the primary format)
            while len(embedded) < 50:
                i = data.find(sig, start)
                if i < 0:
                    break
                embedded.append({"offset": hex(i), "type": name})
                start = i + 1
        rec.summary["embedded"] = embedded[:50]

        hits = []
        for m in STR_RE.finditer(data):
            s = m.group()
            if INTERESTING.search(s):
                hits.append(s[:120].decode("ascii", "replace"))
                if len(hits) >= 40:
                    break
        rec.summary["interesting_strings"] = hits
        if any(re.search(r"(?i)root:[^:]*:\d+:", h) for h in hits):
            rec.findings.append(Finding("high", "FW-PASSWD-FILE",
                                        "Firmware contains /etc/passwd- or shadow-like content", rec.path))
        if any("BEGIN" in e["type"] or "PEM" in e["type"] for e in embedded):
            rec.findings.append(Finding("medium", "FW-EMBEDDED-KEY",
                                        "Firmware contains a PEM block (possibly an embedded private key)", rec.path))

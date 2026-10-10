"""Nhận dạng loại file: magic bytes + đuôi file + kiểm tra nội dung.

Không phụ thuộc python-magic (khó cài trên Windows / máy air-gapped);
nếu có thì dùng thêm để lấy MIME tham khảo.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass

try:  # tùy chọn
    import magic as _magic  # type: ignore
except Exception:  # pragma: no cover
    _magic = None

HEAD_SIZE = 4096

MAGIC_SIGNATURES: list[tuple[bytes, int, str, str]] = [
    # (signature, offset, category, mô tả)
    (b"PK\x03\x04", 0, "Archive", "ZIP archive (có thể là TIA .zap / .ap / docx...)"),
    (b"7z\xbc\xaf\x27\x1c", 0, "Archive", "7-Zip archive"),
    (b"Rar!\x1a\x07", 0, "Archive", "RAR archive"),
    (b"\x1f\x8b", 0, "Archive", "GZIP"),
    (b"\xd4\xc3\xb2\xa1", 0, "PCAP", "PCAP (little-endian)"),
    (b"\xa1\xb2\xc3\xd4", 0, "PCAP", "PCAP (big-endian)"),
    (b"\x4d\x3c\xb2\xa1", 0, "PCAP", "PCAP nanosecond"),
    (b"\x0a\x0d\x0d\x0a", 0, "PCAP", "PCAPNG"),
    (b"ElfFile\x00", 0, "EventLog", "Windows EVTX"),
    (b"\x7fELF", 0, "Executable", "ELF binary (Linux / firmware nhúng)"),
    (b"MZ", 0, "Executable", "Windows PE (exe/dll)"),
    (b"%PDF", 0, "Document", "PDF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE", "OLE2 compound (xls/doc cũ, Rockwell .ACD, project cũ)"),
    (b"SQLite format 3\x00", 0, "Database", "SQLite database"),
    (b"hsqs", 0, "Firmware", "SquashFS filesystem (firmware)"),
    (b"\x27\x05\x19\x56", 0, "Firmware", "U-Boot uImage (firmware)"),
]

# Đuôi file đặc thù OT -> (category, mô tả)
EXTENSION_MAP: dict[str, tuple[str, str]] = {
    # IEC 61850 SCL
    ".scd": ("SCL", "IEC 61850 Substation Configuration Description"),
    ".icd": ("SCL", "IEC 61850 IED Capability Description"),
    ".cid": ("SCL", "IEC 61850 Configured IED Description"),
    ".iid": ("SCL", "IEC 61850 Instantiated IED Description"),
    ".ssd": ("SCL", "IEC 61850 System Specification Description"),
    ".sed": ("SCL", "IEC 61850 System Exchange Description"),
    # COMTRADE (parser ở giai đoạn 2)
    ".cfg": ("COMTRADE", "COMTRADE config (IEEE C37.111) hoặc file cấu hình"),
    ".dat": ("COMTRADE", "COMTRADE data"),
    ".hdr": ("COMTRADE", "COMTRADE header"),
    ".inf": ("COMTRADE", "COMTRADE info"),
    # PLC
    ".l5x": ("PLC", "Rockwell Logix Designer XML export"),
    ".l5k": ("PLC", "Rockwell Logix Designer ASCII export"),
    ".acd": ("PLC", "Rockwell Logix Designer project (đóng)"),
    ".rss": ("PLC", "Rockwell RSLogix 500 project"),
    ".s7p": ("PLC", "Siemens STEP 7 Classic project"),
    ".xef": ("PLC", "Schneider Unity/EcoStruxure XML export"),
    ".stu": ("PLC", "Schneider Unity Pro project"),
    ".sta": ("PLC", "Schneider Unity Pro archive"),
    ".project": ("PLC", "CODESYS project"),
    ".pcmp": ("IED", "ABB PCM600 project"),
    # Device description
    ".gsd": ("DeviceDesc", "PROFIBUS GSD"),
    ".gse": ("DeviceDesc", "PROFIBUS GSD"),
    ".eds": ("DeviceDesc", "EtherNet/IP / CANopen EDS"),
    # HMI / SCADA
    ".mcp": ("HMI", "Siemens WinCC project"),
    ".med": ("HMI", "FactoryTalk View ME project"),
    ".mer": ("HMI", "FactoryTalk View ME runtime"),
    ".apa": ("HMI", "FactoryTalk View archive"),
    # Firmware
    ".hex": ("Firmware", "Intel HEX image"),
    ".srec": ("Firmware", "Motorola S-record image"),
    ".s19": ("Firmware", "Motorola S-record image"),
    ".bin": ("Firmware", "Binary image"),
    ".fw": ("Firmware", "Firmware image"),
    ".img": ("Firmware", "Disk/firmware image"),
    # Capture / log
    ".pcap": ("PCAP", "Packet capture"),
    ".pcapng": ("PCAP", "Packet capture (pcapng)"),
    ".evtx": ("EventLog", "Windows Event Log"),
    ".log": ("Log", "Log file"),
    ".csv": ("Data", "CSV (historian / export)"),
}

# Siemens TIA Portal: .ap13 ... .ap20, .zap13 ...
_TIA_RE = re.compile(r"^\.(z?ap)(\d{2})$")

# Namespace / root element XML -> (category, mô tả)
XML_SIGNATURES: list[tuple[str, str, str]] = [
    ("iec.ch/61850", "SCL", "IEC 61850 SCL"),
    ("<scl", "SCL", "IEC 61850 SCL"),
    ("plcopen.org/xml/tc6", "PLC", "PLCopen XML (IEC 61131-3)"),
    ("<rslogix5000content", "PLC", "Rockwell Logix L5X"),
    ("gsdml", "DeviceDesc", "PROFINET GSDML"),
    ("ethercatinfo", "DeviceDesc", "EtherCAT ESI"),
    ("opcfoundation.org/ua/2011/03/uanodeset", "DeviceDesc", "OPC UA NodeSet2"),
    ("<fefexport", "PLC", "Schneider Unity XEF"),
]


@dataclass
class Identity:
    category: str
    description: str
    mime: str = ""
    is_text: bool = False
    entropy: float = 0.0


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def looks_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data[:1024] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) > 0.90


def decode_head(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return ""


def read_head(path: str, size: int = HEAD_SIZE) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(size)


def identify(path: str, head: bytes | None = None) -> Identity:
    if head is None:
        head = read_head(path)
    ext = os.path.splitext(path)[1].lower()
    mime = ""
    if _magic is not None:
        try:
            mime = _magic.from_buffer(head, mime=True)
        except Exception:
            mime = ""
    text = looks_text(head)
    ent = round(shannon_entropy(head), 3)

    # 1. Nội dung XML: chính xác hơn đuôi file
    if text:
        low = decode_head(head).lower()
        if "<?xml" in low[:200] or low.lstrip().startswith("<"):
            for needle, cat, desc in XML_SIGNATURES:
                if needle in low:
                    return Identity(cat, desc, mime, True, ent)
        # COMTRADE .cfg: dòng 1 = "station,device[,rev_year]", dòng 2 = "N,nnA,nnD"
        if ext == ".cfg":
            lines = low.splitlines()
            if len(lines) > 1 and re.match(r"^\s*\d+\s*,\s*\d+a\s*,\s*\d+d\s*$", lines[1]):
                return Identity("COMTRADE", "COMTRADE config (IEEE C37.111)", mime, True, ent)
            return Identity("Config", "File cấu hình văn bản", mime, True, ent)
        if ext == ".hex" and low.startswith(":"):
            return Identity("Firmware", "Intel HEX image", mime, True, ent)
        if ext in (".srec", ".s19") and low.startswith("s0"):
            return Identity("Firmware", "Motorola S-record image", mime, True, ent)

    # 2. Magic bytes
    for sig, off, cat, desc in MAGIC_SIGNATURES:
        if head[off:off + len(sig)] == sig:
            m = _TIA_RE.match(ext)
            if cat == "Archive" and m:
                return Identity("PLC", f"Siemens TIA Portal V{m.group(2)} {'archive' if m.group(1) == 'zap' else 'project'}", mime, False, ent)
            return Identity(cat, desc, mime, False, ent)

    # 3. Đuôi file
    m = _TIA_RE.match(ext)
    if m:
        return Identity("PLC", f"Siemens TIA Portal V{m.group(2)} project", mime, text, ent)
    if ext in EXTENSION_MAP:
        cat, desc = EXTENSION_MAP[ext]
        if cat == "COMTRADE" and ext == ".dat" and not text:
            desc = "COMTRADE data (binary)"
        return Identity(cat, desc, mime, text, ent)

    # 4. Fallback
    if text:
        low = decode_head(head).lower()
        if low.lstrip().startswith("<"):
            return Identity("XML", "XML chung", mime, True, ent)
        if re.search(r"\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}|\b(error|warn|alarm|fault)\b", low):
            return Identity("Log", "Văn bản dạng log", mime, True, ent)
        return Identity("Text", "Văn bản", mime, True, ent)
    if ent > 7.5:
        return Identity("Binary", "Nhị phân entropy cao (nén/mã hóa)", mime, False, ent)
    return Identity("Binary", "Nhị phân không xác định", mime, False, ent)

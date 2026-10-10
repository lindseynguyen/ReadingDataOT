from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Asset:
    """Thiết bị/tài sản OT tìm thấy trong file (IED, PLC, HMI...)."""
    name: str
    kind: str = "unknown"            # IED, PLC, HMI, Switch...
    vendor: str = ""
    model: str = ""
    version: str = ""
    ip: str = ""
    mac: str = ""
    subnet: str = ""
    protocols: list[str] = field(default_factory=list)
    source: str = ""                 # file chứa thông tin
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Phát hiện rủi ro bảo mật / cấu hình."""
    severity: str                    # high | medium | low | info
    rule: str
    message: str
    source: str = ""
    asset: str = ""


@dataclass
class FileRecord:
    path: str
    size: int
    sha256: str
    category: str = "Unknown"        # SCL, Log, Firmware, Archive...
    file_type: str = ""              # mô tả chi tiết
    parser: str = ""
    summary: dict[str, Any] = field(default_factory=dict)
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    files: list[FileRecord] = field(default_factory=list)

    @property
    def assets(self) -> list[Asset]:
        return [a for f in self.files for a in f.assets]

    @property
    def findings(self) -> list[Finding]:
        return [x for f in self.files for x in f.findings]

    def stats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.files:
            out[f.category] = out.get(f.category, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "stats": self.stats(),
            "files": [f.to_dict() for f in self.files],
        }

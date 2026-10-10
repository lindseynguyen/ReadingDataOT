"""COMTRADE (IEEE C37.111-1991/1999/2013) disturbance records from protection relays.

Parses the .cfg file and cross-checks the companion .dat file.
"""
from __future__ import annotations

import math
import os

from ..core.identify import Identity
from ..core.model import Asset, FileRecord, Finding
from ..core.registry import register


def _sibling(path: str, ext: str) -> str | None:
    base = os.path.splitext(path)[0]
    folder = os.path.dirname(path) or "."
    want = (os.path.basename(base) + ext).lower()
    try:
        for n in os.listdir(folder):
            if n.lower() == want:
                return os.path.join(folder, n)
    except OSError:
        pass
    return None


def _f(v: str, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


@register
class ComtradeParser:
    name = "comtrade"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return rec.category == "COMTRADE" and ident.is_text and rec.path.lower().endswith(".cfg")

    def parse(self, path: str, rec: FileRecord) -> None:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]
        if len(lines) < 2:
            rec.error = "COMTRADE .cfg is too short"
            return
        l1 = [x.strip() for x in lines[0].split(",")]
        station, device = l1[0], (l1[1] if len(l1) > 1 else "")
        rev = l1[2] if len(l1) > 2 else "1991"
        l2 = [x.strip().upper() for x in lines[1].split(",")]
        n_total = int(l2[0])
        n_a = int(l2[1].rstrip("A")) if len(l2) > 1 else 0
        n_d = int(l2[2].rstrip("D")) if len(l2) > 2 else 0

        idx = 2
        analog, digital = [], []
        for _ in range(n_a):
            p = [x.strip() for x in lines[idx].split(",")]
            idx += 1
            analog.append({
                "n": p[0], "id": p[1] if len(p) > 1 else "", "phase": p[2] if len(p) > 2 else "",
                "unit": p[4] if len(p) > 4 else "",
                "primary": p[10] if len(p) > 10 else "", "secondary": p[11] if len(p) > 11 else "",
                "ps": p[12] if len(p) > 12 else "",
            })
        for _ in range(n_d):
            p = [x.strip() for x in lines[idx].split(",")]
            idx += 1
            digital.append({"n": p[0], "id": p[1] if len(p) > 1 else ""})

        line_freq = _f(lines[idx]); idx += 1
        nrates = int(_f(lines[idx])); idx += 1
        rates = []
        for _ in range(max(nrates, 1) if nrates else 1):
            p = [x.strip() for x in lines[idx].split(",")]
            idx += 1
            rates.append((_f(p[0]), int(_f(p[1])) if len(p) > 1 else 0))
        start = lines[idx] if idx < len(lines) else ""; idx += 1
        trigger = lines[idx] if idx < len(lines) else ""; idx += 1
        ftype = lines[idx].upper() if idx < len(lines) else "ASCII"; idx += 1

        total_samples = rates[-1][1] if rates else 0
        duration = 0.0
        prev = 0
        for sr, end in rates:
            if sr > 0:
                duration += (end - prev) / sr
            prev = end

        units = sorted({a["unit"] for a in analog if a["unit"]})
        rec.summary.update({
            "station": station, "recording_device": device, "revision_year": rev,
            "channels_total": n_total, "analog_channels": n_a, "digital_channels": n_d,
            "line_frequency_hz": line_freq,
            "sample_rates": [{"rate_hz": r, "end_sample": e} for r, e in rates],
            "total_samples": total_samples, "duration_s": round(duration, 4),
            "start_time": start, "trigger_time": trigger, "data_format": ftype,
            "analog_units": units,
            "analog": analog[:64], "digital": digital[:128],
        })
        if n_a + n_d != n_total:
            rec.findings.append(Finding("low", "CMT-CHANNEL-COUNT",
                                        f"Channel count mismatch: header says {n_total}, found {n_a}A + {n_d}D", rec.path))

        dat = _sibling(path, ".dat")
        if not dat:
            rec.findings.append(Finding("info", "CMT-NO-DAT", "No matching .dat file next to the .cfg", rec.path))
        else:
            size = os.path.getsize(dat)
            rec.summary["dat_file"] = os.path.basename(dat)
            rec.summary["dat_size"] = size
            if ftype in ("BINARY", "BINARY32", "FLOAT32"):
                word = 2 if ftype == "BINARY" else 4
                per = 8 + word * n_a + 2 * math.ceil(n_d / 16)
                expected = per * total_samples
                rec.summary["dat_expected_size"] = expected
                if total_samples and size != expected:
                    rec.findings.append(Finding(
                        "low", "CMT-DAT-SIZE",
                        f".dat size {size} B differs from expected {expected} B (truncated or wrong .cfg?)", rec.path))
        for ext in (".hdr", ".inf"):
            s = _sibling(path, ext)
            if s:
                rec.summary[f"{ext[1:]}_file"] = os.path.basename(s)

        rec.assets.append(Asset(
            name=device or station, kind="Recorder/IED", source=rec.path,
            extra={"station": station, "trigger_time": trigger, "comtrade_revision": rev},
        ))

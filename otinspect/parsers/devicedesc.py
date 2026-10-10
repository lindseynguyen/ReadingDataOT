"""Device description files: PROFINET GSDML, EtherNet/IP / CANopen EDS,
EtherCAT ESI, PROFIBUS GSD. They tell you which device models (and firmware
releases) the engineering tools expect to find on the network."""
from __future__ import annotations

import configparser
import re
import xml.etree.ElementTree as ET

from ..core.identify import Identity
from ..core.model import Asset, FileRecord
from ..core.registry import register

try:
    from defusedxml.ElementTree import parse as safe_parse  # type: ignore
except Exception:  # pragma: no cover
    safe_parse = ET.parse


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first(root, name: str):
    for el in root.iter():
        if _local(el.tag) == name:
            return el
    return None


def _all(root, name: str):
    return [el for el in root.iter() if _local(el.tag) == name]


def _strip(v: str) -> str:
    return v.split(";")[0].strip().strip('"')


@register
class DeviceDescParser:
    name = "devicedesc"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return rec.category == "DeviceDesc" and ident.is_text

    def parse(self, path: str, rec: FileRecord) -> None:
        if "GSDML" in rec.file_type:
            return self._gsdml(path, rec)
        if "EtherCAT" in rec.file_type:
            return self._esi(path, rec)
        low = path.lower()
        if low.endswith(".eds"):
            return self._eds(path, rec)
        if low.endswith((".gsd", ".gse")):
            return self._gsd(path, rec)

    # --- PROFINET GSDML
    def _gsdml(self, path, rec):
        root = safe_parse(path).getroot()
        ident = _first(root, "DeviceIdentity")
        vendor_el = _first(ident, "VendorName") if ident is not None else None
        fam = _first(root, "Family")
        dap = _all(root, "DeviceAccessPointItem")
        mods = _all(root, "ModuleItem")
        vendor = vendor_el.get("Value", "") if vendor_el is not None else ""
        rec.summary.update({
            "protocol": "PROFINET",
            "vendor": vendor,
            "vendor_id": ident.get("VendorID", "") if ident is not None else "",
            "device_id": ident.get("DeviceID", "") if ident is not None else "",
            "family": f"{fam.get('MainFamily', '')} / {fam.get('ProductFamily', '')}" if fam is not None else "",
            "access_points": [{"id": d.get("ID", ""), "fw": d.get("SoftwareRelease", ""),
                               "hw": d.get("HardwareRelease", ""), "order": _order(d)} for d in dap][:50],
            "module_count": len(mods),
        })
        for d in dap[:20]:
            rec.assets.append(Asset(name=d.get("ID", ""), kind="Device type (PROFINET)", vendor=vendor,
                                    model=_order(d), version=d.get("SoftwareRelease", ""),
                                    protocols=["PROFINET"], source=rec.path))

    # --- EtherCAT ESI
    def _esi(self, path, rec):
        root = safe_parse(path).getroot()
        vendor = _first(root, "Vendor")
        vname = (_first(vendor, "Name").text or "").strip() if vendor is not None and _first(vendor, "Name") is not None else ""
        devs = _all(root, "Device")
        rec.summary.update({"protocol": "EtherCAT", "vendor": vname, "device_count": len(devs)})
        for d in devs[:50]:
            t = _first(d, "Type")
            n = _first(d, "Name")
            rec.assets.append(Asset(name=(n.text or "").strip() if n is not None else "", kind="Device type (EtherCAT)",
                                    vendor=vname, model=(t.text or "").strip() if t is not None else "",
                                    version=t.get("RevisionNo", "") if t is not None else "",
                                    protocols=["EtherCAT"], source=rec.path))

    # --- EDS (INI)
    def _eds(self, path, rec):
        cp = configparser.ConfigParser(strict=False, interpolation=None, comment_prefixes=("$", ";"))
        txt = open(path, "r", encoding="utf-8", errors="replace").read()
        try:
            cp.read_string(txt)
        except configparser.Error as e:
            rec.error = f"EDS parse error: {e}"
            return
        dev = {k.lower(): _strip(v) for k, v in (cp["Device"].items() if cp.has_section("Device") else [])}
        proto = "CANopen" if cp.has_section("DeviceInfo") else "EtherNet/IP"
        if proto == "CANopen":
            di = {k.lower(): _strip(v) for k, v in cp["DeviceInfo"].items()}
            vendor, model, ver = di.get("vendorname", ""), di.get("productname", ""), di.get("revisionnumber", "")
        else:
            vendor = dev.get("vendname", "")
            model = dev.get("prodname", "") or dev.get("catalog", "")
            ver = f"{dev.get('majrev', '')}.{dev.get('minrev', '')}".strip(".")
        rec.summary.update({"protocol": proto, "vendor": vendor, "product": model, "revision": ver,
                            "vendor_code": dev.get("vendcode", ""), "product_code": dev.get("prodcode", ""),
                            "catalog": dev.get("catalog", ""), "sections": cp.sections()[:40]})
        rec.assets.append(Asset(name=model or rec.path, kind=f"Device type ({proto})", vendor=vendor,
                                model=dev.get("catalog", "") or model, version=ver, protocols=[proto], source=rec.path))

    # --- PROFIBUS GSD
    def _gsd(self, path, rec):
        txt = open(path, "r", encoding="latin-1", errors="replace").read()
        kv = {k.lower(): v.strip().strip('"') for k, v in re.findall(r"^\s*(\w+)\s*=\s*(.+?)\s*$", txt, re.M)}
        rec.summary.update({"protocol": "PROFIBUS", "vendor": kv.get("vendor_name", ""),
                            "model": kv.get("model_name", ""), "ident": kv.get("ident_number", ""),
                            "sw_release": kv.get("sw_release", ""), "hw_release": kv.get("hw_release", "")})
        rec.assets.append(Asset(name=kv.get("model_name", ""), kind="Device type (PROFIBUS)",
                                vendor=kv.get("vendor_name", ""), model=kv.get("model_name", ""),
                                version=kv.get("sw_release", ""), protocols=["PROFIBUS"], source=rec.path))


def _order(el) -> str:
    o = _first(el, "OrderNumber")
    return o.get("Value", "") if o is not None else ""

"""Vendor-neutral and IEC 61131-3 engineering exports.

- AutomationML / CAEX (.aml): hardware configuration exported from Siemens TIA
  Portal (Openness / "Export CAx data") and other tools. Extracts devices with
  order numbers, firmware and network addresses.
- Schneider EcoStruxure / Unity Pro XEF (.xef): application name and version,
  variables, sections by language, DFBs, tasks.
- PLCopen XML (TC6): project header, POUs by type and language, configurations,
  resources, tasks.
"""
from __future__ import annotations

import re
from collections import Counter

from ..core.identify import Identity
from ..core.model import Asset, FileRecord, Finding
from ..core.registry import register
from ..core.safexml import safe_parse


IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SECRET_NAME = re.compile(r"(?i)pass(word)?|pwd|passwd|secret")
LANGS = ("ST", "LD", "FBD", "SFC", "IL", "CFC")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _kids(el, name):
    return [c for c in el if _local(c.tag) == name]


def _iter(el, name):
    return [c for c in el.iter() if _local(c.tag) == name]


# ------------------------------------------------------------------ AutomationML
def _attrs(el) -> dict[str, str]:
    """Direct CAEX <Attribute Name=..><Value>..</Value></Attribute> children."""
    out = {}
    for a in _kids(el, "Attribute"):
        v = _kids(a, "Value")
        out[a.get("Name", "")] = (v[0].text or "").strip() if v else a.get("Value", "")
    return out


def _all_attr_values(el) -> list[tuple[str, str]]:
    out = []
    for a in _iter(el, "Attribute"):
        v = _kids(a, "Value")
        out.append((a.get("Name", ""), (v[0].text or "").strip() if v else a.get("Value", "")))
    return out


@register
class AutomationMLParser:
    name = "automationml"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return "AutomationML" in rec.file_type

    def parse(self, path: str, rec: FileRecord) -> None:
        root = safe_parse(path).getroot()
        src_tool = _iter(root, "WriterName")
        rec.summary.update({
            "caex_version": root.get("SchemaVersion", "") or root.get("CAEXSchemaVersion", ""),
            "writer": (src_tool[0].text or "").strip() if src_tool else "",
            "file_name": root.get("FileName", ""),
        })
        hierarchies = _iter(root, "InstanceHierarchy")
        rec.summary["instance_hierarchies"] = [h.get("Name", "") for h in hierarchies]
        devices = []
        seen = set()
        for ie in _iter(root, "InternalElement"):
            at = _attrs(ie)
            type_id = at.get("TypeIdentifier", "")
            order = ""
            m = re.search(r"OrderNumber:([^/]+)(?:/(\S+))?", type_id)
            if m:
                order = m.group(1).strip()
            order = order or at.get("OrderNumber", "")
            if not order:
                continue
            ident = id(ie)
            if ident in seen:
                continue
            seen.add(ident)
            fw = at.get("FirmwareVersion", "") or (m.group(2) if m and m.group(2) else "")
            ips = sorted({v for n, v in _all_attr_values(ie) if IP_RE.match(v) and "mask" not in n.lower()
                          and "router" not in n.lower() and "gateway" not in n.lower()})
            masks = [v for n, v in _all_attr_values(ie) if IP_RE.match(v) and "mask" in n.lower()]
            devices.append({"name": ie.get("Name", ""), "order": order, "firmware": fw,
                            "type": at.get("TypeName", ""), "ips": ips, "mask": masks[0] if masks else ""})
        # keep the outermost element per IP (rack/station rather than each submodule)
        claimed = set()
        for d in devices:
            new_ips = [ip for ip in d["ips"] if ip not in claimed]
            claimed.update(new_ips)
            d["own_ips"] = new_ips
        rec.summary["device_count"] = len(devices)
        rec.summary["devices"] = [{k: v for k, v in d.items() if k != "own_ips"} for d in devices[:500]]
        vendor = "Siemens" if any(d["order"].startswith(("6ES7", "6GK", "6AV", "6SL", "6ES5", "6EP")) for d in devices) else ""
        for d in devices:
            if d["own_ips"] or d["order"].startswith(("6ES7 5", "6ES7 3", "6ES7 4", "6ES7 2", "6ES7 1", "6AV")):
                kind = "HMI" if d["order"].startswith("6AV") else "PLC/device"
                rec.assets.append(Asset(name=d["name"], kind=kind, vendor=vendor, model=d["order"],
                                        version=d["firmware"], ip=", ".join(d["own_ips"]), subnet=d["mask"],
                                        protocols=["PROFINET"] if vendor else [], source=rec.path,
                                        extra={"type": d["type"]}))


# ------------------------------------------------------------------ Schneider XEF
@register
class XEFParser:
    name = "schneider-xef"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return "Schneider" in rec.file_type and ident.is_text

    def parse(self, path: str, rec: FileRecord) -> None:
        root = safe_parse(path).getroot()
        hdr = (_iter(root, "fileHeader") or [None])[0]
        ch = (_iter(root, "contentHeader") or [None])[0]
        variables = _iter(root, "variables")
        sections = _iter(root, "program")
        langs = Counter()
        for p in sections:
            for c in p:
                t = _local(c.tag)
                if t.endswith("Source"):
                    langs[t.replace("Source", "").upper()] += 1
        tasks = Counter(ip.get("task", "") for ip in _iter(root, "identProg"))
        dfbs = _iter(root, "FBSource")
        rec.summary.update({
            "application": ch.get("name", "") if ch is not None else "",
            "app_version": ch.get("version", "") if ch is not None else "",
            "tool": f"{hdr.get('company', '')} {hdr.get('product', '')}".strip() if hdr is not None else "",
            "date": hdr.get("dateTime", "") if hdr is not None else "",
            "variables": len(variables), "sections": len(sections), "section_languages": dict(langs),
            "tasks": dict(tasks), "dfb_types": len(dfbs),
        })
        name = rec.summary["application"] or path
        rec.assets.append(Asset(name=name, kind="PLC application", vendor="Schneider Electric",
                                version=rec.summary["app_version"], protocols=["Modbus/TCP"], source=rec.path))
        for v in variables:
            if SECRET_NAME.search(v.get("name", "")):
                rec.findings.append(Finding("medium", "XEF-PASSWORD-VAR",
                                            f"Variable '{v.get('name')}' looks like a stored credential", rec.path, name))
                break


# ------------------------------------------------------------------ PLCopen XML
@register
class PLCopenParser:
    name = "plcopen"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return "PLCopen" in rec.file_type

    def parse(self, path: str, rec: FileRecord) -> None:
        root = safe_parse(path).getroot()
        fh = (_iter(root, "fileHeader") or [None])[0]
        ch = (_iter(root, "contentHeader") or [None])[0]
        pous = _iter(root, "pou")
        ptype = Counter(p.get("pouType", "") for p in pous)
        langs = Counter()
        for p in pous:
            for b in _kids(p, "body"):
                for c in b:
                    if _local(c.tag) in LANGS:
                        langs[_local(c.tag)] += 1
        variables = _iter(root, "variable")
        configs = _iter(root, "configuration")
        resources = _iter(root, "resource")
        tasks = [{"name": t.get("name", ""), "interval": t.get("interval", ""), "priority": t.get("priority", "")}
                 for t in _iter(root, "task")]
        rec.summary.update({
            "company": fh.get("companyName", "") if fh is not None else "",
            "product": fh.get("productName", "") if fh is not None else "",
            "product_version": fh.get("productVersion", "") if fh is not None else "",
            "created": fh.get("creationDateTime", "") if fh is not None else "",
            "project": ch.get("name", "") if ch is not None else "",
            "pou_types": dict(ptype), "languages": dict(langs), "pou_count": len(pous),
            "variables": len(variables), "configurations": [c.get("name", "") for c in configs],
            "resources": [r.get("name", "") for r in resources], "tasks": tasks,
        })
        for c in configs:
            rec.assets.append(Asset(name=c.get("name", ""), kind="PLC configuration",
                                    vendor=rec.summary["company"], model=rec.summary["product"],
                                    version=rec.summary["product_version"], source=rec.path,
                                    extra={"project": rec.summary["project"]}))
        for v in variables:
            if SECRET_NAME.search(v.get("name", "")):
                rec.findings.append(Finding("medium", "PLCOPEN-PASSWORD-VAR",
                                            f"Variable '{v.get('name')}' looks like a stored credential", rec.path))
                break

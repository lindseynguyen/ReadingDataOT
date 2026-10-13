"""Rockwell Studio 5000 / RSLogix 5000 exports (.L5X XML, .L5K text).

Extracts the controller, firmware revision, I/O modules with network addresses,
programs/routines/tags, and flags weak protection settings.
"""
from __future__ import annotations

import re
from collections import Counter

from ..core.identify import Identity
from ..core.model import Asset, FileRecord, Finding
from ..core.registry import register
from ..core.safexml import safe_parse


IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@register
class L5XParser:
    name = "rockwell"

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        p = rec.path.lower()
        return rec.category == "PLC" and ident.is_text and (p.endswith((".l5x", ".l5k")) or "Logix L5X" in rec.file_type)

    def parse(self, path: str, rec: FileRecord) -> None:
        if path.lower().endswith(".l5k"):
            return self._l5k(path, rec)
        root = safe_parse(path).getroot()
        rec.summary.update({
            "schema_revision": root.get("SchemaRevision", ""),
            "software_revision": root.get("SoftwareRevision", ""),
            "target_type": root.get("TargetType", ""),
            "export_date": root.get("ExportDate", ""),
        })
        ctrl = root.find("Controller")
        if ctrl is None:
            rec.summary["partial_export"] = True
            return
        cname = ctrl.get("Name", "")
        fw = f"{ctrl.get('MajorRev', '')}.{ctrl.get('MinorRev', '')}".strip(".")
        programs = ctrl.findall("./Programs/Program")
        routines = ctrl.findall("./Programs/Program/Routines/Routine")
        rtype = Counter(r.get("Type", "") for r in routines)
        ctags = ctrl.findall("./Tags/Tag")
        ptags = ctrl.findall("./Programs/Program/Tags/Tag")
        aois = ctrl.findall("./AddOnInstructionDefinitions/AddOnInstructionDefinition")
        tasks = ctrl.findall("./Tasks/Task")

        rec.summary.update({
            "controller": cname, "processor": ctrl.get("ProcessorType", ""), "firmware": fw,
            "programs": len(programs), "routines": len(routines), "routine_types": dict(rtype),
            "controller_tags": len(ctags), "program_tags": len(ptags), "aoi_count": len(aois),
            "tasks": [{"name": t.get("Name", ""), "type": t.get("Type", ""), "rate": t.get("Rate", "")} for t in tasks],
            "safety": ctrl.get("SafetyEnabled", ctrl.get("SafetyLevel", "")),
        })

        ctrl_ip = ""
        modules = []
        for m in ctrl.findall("./Modules/Module"):
            ips = [p.get("Address", "") for p in m.findall("./Ports/Port")
                   if p.get("Type", "") == "Ethernet" and IP_RE.match(p.get("Address", ""))]
            mod = {"name": m.get("Name", ""), "catalog": m.get("CatalogNumber", ""),
                   "vendor": m.get("Vendor", ""), "rev": f"{m.get('Major', '')}.{m.get('Minor', '')}",
                   "parent": m.get("ParentModule", ""), "ip": ips[0] if ips else "",
                   "inhibited": m.get("Inhibited", "false")}
            modules.append(mod)
            if m.get("Name") == "Local" and ips:
                ctrl_ip = ips[0]
            elif ips:
                rec.assets.append(Asset(name=mod["name"], kind="I/O / network module", vendor="Rockwell" if mod["vendor"] == "1" else mod["vendor"],
                                        model=mod["catalog"], version=mod["rev"], ip=mod["ip"],
                                        protocols=["EtherNet/IP"], source=rec.path,
                                        extra={"parent": mod["parent"]}))
        rec.summary["modules"] = modules[:300]
        rec.assets.insert(0, Asset(name=cname, kind="PLC", vendor="Rockwell Automation",
                                   model=ctrl.get("ProcessorType", ""), version=fw, ip=ctrl_ip,
                                   protocols=["EtherNet/IP", "CIP"], source=rec.path,
                                   extra={"programs": len(programs), "tags": len(ctags) + len(ptags)}))

        # risk rules
        src = rec.path
        protected = sum(1 for r in routines if r.get("SourceProtected") or r.find("EncodedData") is not None)
        if routines and not protected:
            rec.findings.append(Finding("info", "L5X-NO-SOURCE-PROTECTION",
                                        "No routine uses source protection (logic is readable from the export)", src, cname))
        ext_rw = sum(1 for t in ctags if t.get("ExternalAccess", "Read/Write") == "Read/Write")
        if ctags and ext_rw / len(ctags) > 0.8:
            rec.findings.append(Finding("low", "L5X-TAGS-EXTERNAL-RW",
                                        f"{ext_rw}/{len(ctags)} controller tags allow external Read/Write", src, cname))
        if ctrl.get("SecurityCode", "0") in ("0", ""):
            rec.findings.append(Finding("info", "L5X-NO-SECURITY-AUTHORITY",
                                        "Controller not bound to a FactoryTalk Security authority (SecurityCode=0)", src, cname))
        for t in ctags + ptags:
            n = t.get("Name", "").lower()
            if re.search(r"pass(word)?|pwd|pin", n) and t.get("DataType", "") in ("STRING", "DINT", "INT"):
                rec.findings.append(Finding("medium", "L5X-PASSWORD-TAG",
                                            f"Tag '{t.get('Name')}' looks like a stored credential", src, cname))
                break

    def _l5k(self, path: str, rec: FileRecord) -> None:
        txt = open(path, "r", encoding="utf-8", errors="replace").read()
        m = re.search(r"CONTROLLER\s+(\w+)\s*\((.*?)\)", txt, re.S)
        name = m.group(1) if m else ""
        attrs = dict(re.findall(r"(\w+)\s*:=\s*\"?([^,\"\)]*)\"?", m.group(2))) if m else {}
        mods = re.findall(r"MODULE\s+(\w+)\s*\((.*?)\)", txt, re.S)
        rec.summary.update({
            "controller": name, "processor": attrs.get("ProcessorType", ""),
            "firmware": f"{attrs.get('Major', '')}", "modules": len(mods),
            "programs": len(re.findall(r"^\s*PROGRAM\s+\w+", txt, re.M)),
            "routines": len(re.findall(r"^\s*ROUTINE\s+\w+", txt, re.M)),
        })
        rec.assets.append(Asset(name=name, kind="PLC", vendor="Rockwell Automation",
                                model=attrs.get("ProcessorType", ""), version=attrs.get("Major", ""),
                                protocols=["EtherNet/IP", "CIP"], source=rec.path))

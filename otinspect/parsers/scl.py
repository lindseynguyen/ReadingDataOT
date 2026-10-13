"""Parser IEC 61850 SCL (SCD/ICD/CID/IID/SSD/SED).

Handles the SCL namespace correctly (the main bug in the old version) and extracts:
- IED: name, vendor, model, configVersion, AccessPoint, LDevice, LN0/LN
- Communication: SubNetwork, ConnectedAP -> IP/subnet/gateway/MAC
- GOOSE (GSEControl + GSE address: APPID, MAC, VLAN), SMV, ReportControl, DataSet
- Substation: VoltageLevel / Bay
and runs basic risk rules.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from ..core.identify import Identity
from ..core.model import Asset, FileRecord, Finding
from ..core.registry import register
from ..core.safexml import safe_iterparse


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(el, name: str):
    return [c for c in el if _local(c.tag) == name]


def _iter(el, name: str):
    return [c for c in el.iter() if _local(c.tag) == name]


def _addr_params(address_el) -> dict[str, str]:
    """<Address><P type="IP">..</P></Address> -> dict"""
    out: dict[str, str] = {}
    if address_el is None:
        return out
    for p in _children(address_el, "P"):
        t = p.get("type", "")
        if t:
            out[t] = (p.text or "").strip()
    return out


DEFAULT_IPS = {"192.168.0.1", "192.168.1.1", "192.168.0.10", "10.0.0.1",
               "192.168.1.100", "172.16.0.1", "0.0.0.0", "127.0.0.1"}


@register
class SCLParser:
    name = "scl"
    max_size = 2048 * 1024 * 1024  # streaming parser

    def can_parse(self, rec: FileRecord, ident: Identity) -> bool:
        return rec.category == "SCL"

    def parse(self, path: str, rec: FileRecord) -> None:
        """Streaming parse: each top-level section (Header, Communication, IED,
        Substation, DataTypeTemplates) is processed as soon as it is complete and
        then freed, so memory stays bounded by the largest single IED, not by the
        whole SCD."""
        root = None
        depth = 0
        hdr: dict = {}
        comm: dict[tuple[str, str], dict] = {}
        gse_addr: dict[tuple[str, str, str], dict] = {}   # (ied, ldInst, cbName)
        smv_addr: dict[tuple[str, str, str], dict] = {}
        subnets: list[dict] = []
        ied_infos: list[dict] = []
        vls: list[dict] = []
        bays = 0
        ln_classes: Counter = Counter()
        datasets: dict[str, list[str]] = {}
        counts = {"report": 0, "dataset": 0}

        for event, el in safe_iterparse(path):
            if event == "start":
                depth += 1
                if root is None:
                    root = el
                    if _local(root.tag) != "SCL":
                        rec.error = f"Root element is <{_local(root.tag)}>, not <SCL>"
                        return
                    rec.summary["scl_version"] = (f"{root.get('version', '')}{root.get('revision', '')}"
                                                  f"{root.get('release', '')}")
                continue
            depth -= 1
            if depth != 1:
                continue
            tag = _local(el.tag)
            if tag == "Header":
                hdr = dict(el.attrib)
            elif tag == "Communication":
                self._communication(el, comm, gse_addr, smv_addr, subnets)
            elif tag == "IED":
                ied_infos.append(self._ied(el, ln_classes, datasets, counts))
            elif tag == "Substation":
                for vl in _iter(el, "VoltageLevel"):
                    volt = next(iter(_children(vl, "Voltage")), None)
                    vtxt = ""
                    if volt is not None:
                        vtxt = f"{(volt.text or '').strip()} {volt.get('multiplier', '')}{volt.get('unit', '')}".strip()
                    nb = len(_children(vl, "Bay"))
                    vls.append({"name": vl.get("name", ""), "voltage": vtxt, "bays": nb})
                    bays += nb
            root.clear()          # free the processed section (and DataTypeTemplates, unused)

        if root is None:
            rec.error = "Empty XML document"
            return
        rec.summary.update({
            "header_id": hdr.get("id", ""),
            "header_version": hdr.get("version", ""),
            "header_revision": hdr.get("revision", ""),
            "tool_id": hdr.get("toolID", ""),
            "subnetworks": subnets,
        })

        # Join IEDs with Communication (order-independent: Communication may follow IEDs)
        goose_list, smv_list = [], []
        for info in ied_infos:
            iname = info["name"]
            ip = mac = subnet = gw = snname = ""
            for apn in info["aps"]:
                a = comm.get((iname, apn))
                if a and not ip:
                    ip, subnet = a.get("IP", ""), a.get("IP-SUBNET", "")
                    gw, mac = a.get("IP-GATEWAY", ""), a.get("MAC-Address", "")
                    snname = a.get("subnetwork", "")
            for g in info["goose"]:
                addr = gse_addr.get((iname, g["ld"], g["name"]), {})
                g.update({"APPID": addr.get("APPID", ""), "MAC": addr.get("MAC-Address", ""),
                          "VLAN": addr.get("VLAN-ID", ""), "VLAN_prio": addr.get("VLAN-PRIORITY", "")})
                goose_list.append(g)
            for sv in info["smv"]:
                addr = smv_addr.get((iname, sv["ld"], sv["name"]), {})
                sv.update({"APPID": addr.get("APPID", ""), "MAC": addr.get("MAC-Address", ""),
                           "VLAN": addr.get("VLAN-ID", "")})
                smv_list.append(sv)
            rec.assets.append(Asset(
                name=iname, kind="IED", vendor=info["manufacturer"], model=info["type"],
                version=info["version"], ip=ip, mac=mac, subnet=subnet,
                protocols=sorted(info["protos"]), source=rec.path,
                extra={"desc": info["desc"], "gateway": gw, "subnetwork": snname,
                       "access_points": info["aps"], "ldevices": info["ldevices"]},
            ))

        rec.summary.update({
            "ied_count": len(ied_infos),
            "goose_count": len(goose_list),
            "smv_count": len(smv_list),
            "report_control_count": counts["report"],
            "dataset_count": counts["dataset"],
            "voltage_levels": vls,
            "bay_count": bays,
            "top_ln_classes": dict(ln_classes.most_common(15)),
            "goose": goose_list,
            "datasets": datasets,
            "smv": smv_list,
        })
        rec.findings.extend(self._rules(rec, goose_list, smv_list))

    @staticmethod
    def _communication(comm_el, comm, gse_addr, smv_addr, subnets) -> None:
        for sn in _children(comm_el, "SubNetwork"):
            subnets.append({"name": sn.get("name", ""), "type": sn.get("type", "")})
            for cap in _children(sn, "ConnectedAP"):
                ied, ap = cap.get("iedName", ""), cap.get("apName", "")
                addr = _addr_params(next(iter(_children(cap, "Address")), None))
                addr["subnetwork"] = sn.get("name", "")
                comm[(ied, ap)] = addr
                for g in _children(cap, "GSE"):
                    gse_addr[(ied, g.get("ldInst", ""), g.get("cbName", ""))] = \
                        _addr_params(next(iter(_children(g, "Address")), None))
                for s in _children(cap, "SMV"):
                    smv_addr[(ied, s.get("ldInst", ""), s.get("cbName", ""))] = \
                        _addr_params(next(iter(_children(s, "Address")), None))

    @staticmethod
    def _ied(ied, ln_classes: Counter, datasets: dict, counts: dict) -> dict:
        """Compact summary of one <IED> element (the element is freed afterwards)."""
        iname = ied.get("name", "")
        protos: set[str] = set()
        aps = _children(ied, "AccessPoint")
        for ap in aps:
            if _iter(ap, "Server"):
                protos.add("MMS")
        goose, smv, ldevices = [], [], []
        for ld in _iter(ied, "LDevice"):
            ld_inst = ld.get("inst", "")
            lns = []
            for ln in list(_children(ld, "LN0")) + list(_children(ld, "LN")):
                cls = ln.get("lnClass", "")
                ln_classes[cls] += 1
                lns.append(f"{ln.get('prefix', '')}{cls}{ln.get('inst', '')}")
                for ds in _children(ln, "DataSet"):
                    counts["dataset"] += 1
                    members = []
                    for fc in _children(ds, "FCDA"):
                        members.append(f"{fc.get('ldInst', '')}/{fc.get('prefix', '')}{fc.get('lnClass', '')}"
                                       f"{fc.get('lnInst', '')}.{fc.get('doName', '')}"
                                       f"{'.' + fc.get('daName') if fc.get('daName') else ''}[{fc.get('fc', '')}]")
                    datasets[f"{iname}/{ld_inst}/{ds.get('name', '')}"] = members
                counts["report"] += len(_children(ln, "ReportControl"))
                for g in _children(ln, "GSEControl"):
                    protos.add("GOOSE")
                    goose.append({
                        "ied": iname, "ld": ld_inst, "name": g.get("name", ""),
                        "appID": g.get("appID", ""), "dataSet": g.get("datSet", ""),
                        "confRev": g.get("confRev", ""), "type": g.get("type", "GOOSE"),
                    })
                for s in _children(ln, "SampledValueControl"):
                    protos.add("SV")
                    smv.append({
                        "ied": iname, "ld": ld_inst, "name": s.get("name", ""),
                        "smvID": s.get("smvID", ""), "dataSet": s.get("datSet", ""),
                        "smpRate": s.get("smpRate", ""),
                    })
            ldevices.append({"inst": ld_inst, "desc": ld.get("desc", ""), "ln_count": len(lns), "lns": lns})
        return {
            "name": iname, "manufacturer": ied.get("manufacturer", ""), "type": ied.get("type", ""),
            "version": ied.get("configVersion", "") or ied.get("originalSclVersion", ""),
            "desc": ied.get("desc", ""), "aps": [a.get("name", "") for a in aps],
            "protos": protos, "goose": goose, "smv": smv, "ldevices": ldevices,
        }

    # ------------------------------------------------------------------ rules
    def _rules(self, rec: FileRecord, goose: list, smv: list) -> list[Finding]:
        out: list[Finding] = []
        src = rec.path

        ip_owner: dict[str, list[str]] = defaultdict(list)
        for a in rec.assets:
            if a.ip:
                ip_owner[a.ip].append(a.name)
                if a.ip in DEFAULT_IPS:
                    out.append(Finding("medium", "SCL-IP-DEFAULT",
                                       f"IED {a.name} uses a default/special IP {a.ip}", src, a.name))
                gw = a.extra.get("gateway", "")
                if a.subnet and gw:
                    try:
                        net = ipaddress.ip_network(f"{a.ip}/{a.subnet}", strict=False)
                        if ipaddress.ip_address(gw) not in net:
                            out.append(Finding("low", "SCL-GW-OUTSIDE",
                                               f"Gateway {gw} of {a.name} is outside subnet {net}", src, a.name))
                    except ValueError:
                        out.append(Finding("low", "SCL-IP-INVALID",
                                           f"Invalid IP/subnet on {a.name}: {a.ip}/{a.subnet}", src, a.name))
            elif "MMS" in a.protocols and rec.summary.get("ied_count", 0) > 1:
                out.append(Finding("info", "SCL-NO-IP",
                                   f"IED {a.name} has an MMS server but no IP in the Communication section", src, a.name))
        for ip, owners in ip_owner.items():
            if len(owners) > 1:
                out.append(Finding("high", "SCL-IP-DUP",
                                   f"Duplicate IP {ip} shared by: {', '.join(owners)}", src))

        for kind, items in (("GOOSE", goose), ("SV", smv)):
            appids = defaultdict(list)
            macs = defaultdict(list)
            for g in items:
                ref = f"{g['ied']}/{g['ld']}/{g['name']}"
                if g.get("APPID"):
                    appids[g["APPID"].upper()].append(ref)
                if g.get("MAC"):
                    macs[g["MAC"].upper()].append(ref)
                if not g.get("APPID") and not g.get("MAC"):
                    out.append(Finding("low", f"SCL-{kind}-NOADDR",
                                       f"{kind} {ref} has no address (APPID/MAC) in the Communication section", src, g["ied"]))
                if kind == "GOOSE" and g.get("VLAN") in ("", "0", "000"):
                    out.append(Finding("info", "SCL-GOOSE-NOVLAN",
                                       f"GOOSE {ref} has no VLAN (protection traffic cannot be segregated)", src, g["ied"]))
            for v, refs in appids.items():
                if len(refs) > 1:
                    out.append(Finding("high", f"SCL-{kind}-APPID-DUP",
                                       f"Duplicate APPID {v}: {', '.join(refs)}", src))
            for v, refs in macs.items():
                if len(refs) > 1:
                    out.append(Finding("medium", f"SCL-{kind}-MAC-DUP",
                                       f"Duplicate destination MAC {v}: {', '.join(refs)}", src))
        if goose or smv:
            out.append(Finding("info", "SCL-62351",
                               "SCL does not express IEC 62351-6 (GOOSE/SV authentication); verify on the devices",
                               src))
        return out

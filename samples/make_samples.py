"""Regenerate the synthetic sample files (COMTRADE, PCAP, L5X, EDS).

All data is fabricated for testing; none of it describes a real installation.
    python samples/make_samples.py
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def comtrade():
    cfg = """SUBSTATION_DEMO,F87T_Q01,1999
5,3A,2D
1,IA,A,,A,0.01,0,0,-32767,32767,1200,1,P
2,IB,B,,A,0.01,0,0,-32767,32767,1200,1,P
3,UA,A,,kV,0.001,0,0,-32767,32767,110,0.1,P
1,TRIP,,,0
2,CB_OPEN,,,0
50
1
1000,200
01/09/2026,09:15:44.100000
01/09/2026,09:15:44.200000
BINARY
1
"""
    with open(os.path.join(HERE, "fault_q01.cfg"), "w", newline="\r\n") as fh:
        fh.write(cfg)
    with open(os.path.join(HERE, "fault_q01.dat"), "wb") as fh:
        for i in range(200):
            fh.write(struct.pack("<IIhhhH", i + 1, i * 1000, 100, -50, 900, 1 if i > 100 else 0))


def _eth(dst, src, et, payload, vlan=None):
    h = bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", ""))
    if vlan is not None:
        h += struct.pack(">HH", 0x8100, (4 << 13) | vlan)
    return h + struct.pack(">H", et) + payload


def _ipv4(src, dst, proto, l4):
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    return struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0) + s + d + l4


def _tcp(sp, dp, payload=b""):
    return struct.pack(">HHIIBBHHH", sp, dp, 1, 0, 5 << 4, 0x18, 1024, 0, 0) + payload


def _goose(appid, ref):
    r = ref.encode()
    pdu = bytes([0x80, len(r)]) + r + bytes([0x81, 2, 0x07, 0xD0])
    apdu = bytes([0x61, len(pdu)]) + pdu
    return struct.pack(">HHHH", appid, 8 + len(apdu), 0, 0) + apdu


def pcap():
    pkts = []
    m1, m2, plc, hmi, gw = "00:0a:dc:00:00:11", "00:30:a7:00:00:12", "00:00:bc:00:00:20", "00:1b:1b:00:00:30", "00:00:00:00:00:40"
    for _ in range(5):
        pkts.append(_eth("01:0c:cd:01:00:01", m1, 0x88B8, _goose(0x0001, "F87T_Q01PROT/LLN0$GO$GoTrip"), vlan=64))
        pkts.append(_eth("01:0c:cd:01:00:02", m2, 0x88B8, _goose(0x0001, "F21_Q02PROT/LLN0$GO$GoTrip"), vlan=64))
    mbap = struct.pack(">HHHB", 1, 0, 6, 1)
    for fc in (3, 3, 6, 16, 43):
        pkts.append(_eth(plc, hmi, 0x0800, _ipv4("10.10.2.30", "10.10.2.20", 6,
                                                 _tcp(50000, 502, mbap + bytes([fc, 0, 1, 0, 1])))))
    pkts.append(_eth(gw, hmi, 0x0800, _ipv4("10.10.2.30", "10.10.1.40", 6, _tcp(50001, 2404, b"\x68\x04\x07\x00\x00\x00"))))
    pkts.append(_eth(hmi, gw, 0x0800, _ipv4("10.10.1.40", "10.10.2.30", 6, _tcp(2404, 50001, b"\x68\x04\x0b\x00\x00\x00"))))
    pkts.append(_eth(plc, hmi, 0x0800, _ipv4("10.20.0.50", "10.10.2.20", 6, _tcp(51000, 23))))
    pkts.append(_eth(m1, gw, 0x0800, _ipv4("10.10.1.40", "10.10.1.11", 6, _tcp(51001, 102, b"\x03\x00\x00\x16"))))
    with open(os.path.join(HERE, "station_bus.pcap"), "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            fh.write(struct.pack("<IIII", 1788000000 + i, 0, len(p), len(p)) + p)


def l5x():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<RSLogix5000Content SchemaRevision="1.0" SoftwareRevision="33.01" TargetName="PUMP_STATION" TargetType="Controller" ExportDate="Tue Sep 01 08:00:00 2026">
<Controller Name="PUMP_STATION" ProcessorType="1756-L83E" MajorRev="33" MinorRev="11" SecurityCode="0">
<Modules>
<Module Name="Local" CatalogNumber="1756-L83E" Vendor="1" Major="33" Minor="11"><Ports><Port Id="2" Address="10.10.2.20" Type="Ethernet"/></Ports></Module>
<Module Name="ENBT_RACK2" CatalogNumber="1756-EN2T" Vendor="1" Major="11" Minor="2" ParentModule="Local"><Ports><Port Id="2" Address="10.10.2.21" Type="Ethernet"/></Ports></Module>
<Module Name="VFD_P1" CatalogNumber="PowerFlex 755" Vendor="1" Major="14" Minor="1" ParentModule="ENBT_RACK2"><Ports><Port Id="2" Address="10.10.2.31" Type="Ethernet"/></Ports></Module>
</Modules>
<Tags>
<Tag Name="Pump1_Run" DataType="BOOL" ExternalAccess="Read/Write"/>
<Tag Name="Pump1_Speed" DataType="REAL" ExternalAccess="Read/Write"/>
<Tag Name="HMI_Password" DataType="STRING" ExternalAccess="Read/Write"/>
</Tags>
<Programs><Program Name="MainProgram"><Routines><Routine Name="MainRoutine" Type="RLL"/><Routine Name="PID" Type="ST"/></Routines></Program></Programs>
<Tasks><Task Name="MainTask" Type="CONTINUOUS"/></Tasks>
</Controller>
</RSLogix5000Content>
"""
    with open(os.path.join(HERE, "pump_station.L5X"), "w", encoding="utf-8") as fh:
        fh.write(xml)


def eds():
    txt = """$ Synthetic EDS for testing
[File]
        DescText = "Demo drive EDS";
        Revision = 1.1;
[Device]
        VendCode = 1;
        VendName = "Rockwell Automation/Allen-Bradley";
        ProdType = 123;
        ProdCode = 9001;
        MajRev = 14;
        MinRev = 1;
        ProdName = "PowerFlex 755";
        Catalog = "20G1";
"""
    with open(os.path.join(HERE, "powerflex755.eds"), "w") as fh:
        fh.write(txt)


if __name__ == "__main__":
    comtrade(); pcap(); l5x(); eds()
    print("samples regenerated")

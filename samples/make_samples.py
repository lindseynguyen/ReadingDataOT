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


def scd_v2():
    """A second revision of substation_demo.scd with typical integrator changes."""
    src = open(os.path.join(HERE, "substation_demo.scd"), encoding="utf-8").read()
    s = src.replace('<P type="IP">10.10.1.12</P>', '<P type="IP">10.10.1.22</P>')
    s = s.replace('<P type="MAC-Address">01-0C-CD-01-00-02</P><P type="APPID">0001</P>',
                  '<P type="MAC-Address">01-0C-CD-01-00-02</P><P type="APPID">0002</P>')
    s = s.replace('<FCDA ldInst="PROT" lnClass="PDIF" lnInst="1" doName="Op" daName="general" fc="ST"/>',
                  '<FCDA ldInst="PROT" lnClass="PDIF" lnInst="1" doName="Op" daName="general" fc="ST"/>\n'
                  '            <FCDA ldInst="PROT" lnClass="PDIF" lnInst="1" doName="Str" daName="general" fc="ST"/>')
    s = s.replace('type="REC670" configVersion="2.2"', 'type="REC670" configVersion="2.2.5"')
    s = s.replace('<LN lnClass="MMXU" inst="1" lnType="MMXU_T"/>',
                  '<LN lnClass="MMXU" inst="1" lnType="MMXU_T"/>\n        <LN lnClass="MSQI" inst="1" lnType="MSQI_T"/>')
    with open(os.path.join(HERE, "substation_demo_v2.scd"), "w", encoding="utf-8") as fh:
        fh.write(s)


AML = """<?xml version="1.0" encoding="utf-8"?>
<CAEXFile FileName="Line1.aml" SchemaVersion="2.15" xmlns="http://www.dke.de/CAEX">
  <SourceDocumentInformation OriginName="TIA Portal Openness" OriginVersion="V17"/>
  <AdditionalInformation><WriterHeader><WriterName>TIA Portal Openness</WriterName></WriterHeader></AdditionalInformation>
  <InstanceHierarchy Name="Line1">
    <InternalElement ID="1" Name="PLC_1">
      <Attribute Name="TypeIdentifier"><Value>OrderNumber:6ES7 515-2AM02-0AB0/V2.9</Value></Attribute>
      <Attribute Name="FirmwareVersion"><Value>V2.9</Value></Attribute>
      <InternalElement ID="2" Name="PROFINET interface_1">
        <InternalElement ID="3" Name="E1">
          <Attribute Name="NetworkAddress"><Value>10.30.0.10</Value></Attribute>
          <Attribute Name="SubnetMask"><Value>255.255.255.0</Value></Attribute>
        </InternalElement>
      </InternalElement>
    </InternalElement>
    <InternalElement ID="4" Name="HMI_1">
      <Attribute Name="TypeIdentifier"><Value>OrderNumber:6AV2 124-0MC01-0AX0/17.0.0.0</Value></Attribute>
      <InternalElement ID="5" Name="X1"><Attribute Name="NetworkAddress"><Value>10.30.0.20</Value></Attribute></InternalElement>
    </InternalElement>
    <InternalElement ID="6" Name="ET200SP_1">
      <Attribute Name="TypeIdentifier"><Value>OrderNumber:6ES7 155-6AU01-0BN0/V4.2</Value></Attribute>
      <InternalElement ID="7" Name="X1"><Attribute Name="NetworkAddress"><Value>10.30.0.31</Value></Attribute></InternalElement>
    </InternalElement>
  </InstanceHierarchy>
</CAEXFile>
"""

XEF = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FEFExportProject>
<fileHeader company="Schneider Automation" product="EcoStruxure Control Expert V15.0" dateTime="date_and_time#2026-9-1-8:0:0" content="Project source file" DTDVersion="41"></fileHeader>
<contentHeader name="WTP_FILTERS" version="0.0.42" dateTime="date_and_time#2026-9-1-8:0:0"></contentHeader>
<program><identProg name="Main" type="section" task="MAST"></identProg><STSource>Pump1 := StartCmd AND NOT Fault;</STSource></program>
<program><identProg name="Alarms" type="section" task="MAST"></identProg><LDSource></LDSource></program>
<program><identProg name="Fast" type="section" task="FAST"></identProg><FBDSource></FBDSource></program>
<dataBlock>
<variables name="StartCmd" typeName="BOOL"></variables>
<variables name="Fault" typeName="BOOL"></variables>
<variables name="Pump1" typeName="EBOOL"></variables>
<variables name="Maint_Password" typeName="STRING"></variables>
</dataBlock>
</FEFExportProject>
"""

PLCOPEN = """<?xml version="1.0" encoding="utf-8"?>
<project xmlns="http://www.plcopen.org/xml/tc6_0201">
  <fileHeader companyName="CODESYS" productName="CODESYS" productVersion="V3.5 SP19" creationDateTime="2026-09-01T08:00:00"/>
  <contentHeader name="Boiler_Control"><coordinateInfo><fbd><scaling x="1" y="1"/></fbd><ld><scaling x="1" y="1"/></ld><sfc><scaling x="1" y="1"/></sfc></coordinateInfo></contentHeader>
  <types><dataTypes/><pous>
    <pou name="PLC_PRG" pouType="program"><interface><localVars><variable name="TempSet"><type><REAL/></type></variable></localVars></interface><body><ST><xhtml xmlns="http://www.w3.org/1999/xhtml">TempSet := 80.0;</xhtml></ST></body></pou>
    <pou name="FB_Burner" pouType="functionBlock"><body><SFC/></body></pou>
    <pou name="F_Scale" pouType="function"><body><ST/></body></pou>
  </pous></types>
  <instances><configurations><configuration name="Boiler_PLC"><resource name="Application"><task name="MainTask" interval="T#20ms" priority="1"/></resource></configuration></configurations></instances>
</project>
"""


def engineering():
    with open(os.path.join(HERE, "line1_hw.aml"), "w", encoding="utf-8") as fh:
        fh.write(AML)
    with open(os.path.join(HERE, "wtp_filters.xef"), "w", encoding="utf-8") as fh:
        fh.write(XEF)
    with open(os.path.join(HERE, "boiler_plcopen.xml"), "w", encoding="utf-8") as fh:
        fh.write(PLCOPEN)
    import zipfile
    with zipfile.ZipFile(os.path.join(HERE, "contractor_handover.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Line1/Hardware/line1_hw.aml", AML)
        zf.writestr("Line1/readme.txt", "Handover package (synthetic)")


if __name__ == "__main__":
    comtrade(); pcap(); l5x(); eds(); scd_v2(); engineering()
    print("samples regenerated")

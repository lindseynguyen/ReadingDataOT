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


def _dnp3_crc(data: bytes) -> bytes:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", ~crc & 0xFFFF)


def _dnp3(fc, dst=10, src=1, objects=b""):
    user = bytes([0xC0, 0xC0, fc]) + objects                # transport FIR|FIN, app ctrl, function
    hdr = bytes([0x05, 0x64, 5 + len(user), 0xC4]) + struct.pack("<HH", dst, src)
    body = b"".join(user[i:i + 16] + _dnp3_crc(user[i:i + 16]) for i in range(0, len(user), 16))
    return hdr + _dnp3_crc(hdr) + body


def _iec104(type_id, cot=6, ioa=1001, value=b"\x01", seq=0):
    asdu = bytes([type_id, 1, cot, 0]) + struct.pack("<H", 1) + struct.pack("<I", ioa)[:3] + value
    apdu = struct.pack("<HH", seq << 1, 0) + asdu
    return bytes([0x68, len(apdu)]) + apdu


def _s7(rosctr, param, data=b""):
    hdr = bytes([0x32, rosctr, 0, 0]) + struct.pack(">HHH", 1, len(param), len(data))
    cotp = bytes([0x02, 0xF0, 0x80])
    body = cotp + hdr + param + data
    return struct.pack(">BBH", 3, 0, 4 + len(body)) + body


def _enip(cmd, data=b""):
    return struct.pack("<HHII8sI", cmd, len(data), 0x1234, 0, b"OTINSPCT", 0) + data


def _cip_rr(cip):
    cpf = struct.pack("<IHH", 0, 10, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
    return _enip(0x006F, cpf)


def _cip_tag_write(tag, value):
    t = tag.encode()
    seg = bytes([0x91, len(t)]) + t + (b"\x00" if len(t) % 2 else b"")
    return bytes([0x4D, len(seg) // 2]) + seg + struct.pack("<HH", 0xC3, 1) + value


def _unconnected_send(inner):
    path = bytes([0x20, 0x06, 0x24, 0x01])                 # Connection Manager, instance 1
    return (bytes([0x52, len(path) // 2]) + path + bytes([0x0A, 0xF0]) + struct.pack("<H", len(inner)) + inner
            + (b"\x00" if len(inner) % 2 else b"") + bytes([1, 0, 1, 0]))


def pcap_commands():
    """Control-centre capture with decoded OT commands (all addresses fabricated)."""
    scada, rogue, eng = "10.30.0.10", "10.30.9.99", "10.30.0.50"
    rtu, outst, s7plc, abplc = "10.30.1.20", "10.30.2.30", "10.30.3.40", "10.30.4.50"
    mac = {scada: "00:1b:1b:00:01:10", rogue: "00:16:3e:00:09:99", eng: "00:1b:1b:00:01:50",
           rtu: "00:30:a7:00:01:20", outst: "00:00:bc:00:02:30", s7plc: "00:1b:1b:00:03:40",
           abplc: "00:00:bc:00:04:50"}
    flows = [
        (scada, rtu, 50100, 2404, b"\x68\x04\x07\x00\x00\x00"),               # STARTDT act
        (scada, rtu, 50100, 2404, _iec104(100, value=b"\x14", ioa=0)),          # interrogation (routine)
        (scada, rtu, 50100, 2404, _iec104(45, seq=1)),                          # single command
        (scada, rtu, 50100, 2404, _iec104(46, seq=2, value=b"\x02")),           # double command
        (rogue, rtu, 50200, 2404, _iec104(105, value=b"\x01", ioa=0)),          # reset process
        (scada, outst, 50300, 20000, _dnp3(1, objects=b"\x3c\x02\x06")),         # read class 1 (routine)
        (scada, outst, 50300, 20000, _dnp3(5, objects=b"\x0c\x01\x28\x01\x00\x00\x00\x03\x01\x64\x00\x00\x00\x00\x00\x00\x00\x00")),
        (rogue, outst, 50301, 20000, _dnp3(13)),                                 # cold restart
        (eng, s7plc, 50400, 102, _s7(1, bytes([0xF0, 0, 0, 1, 0, 1, 0x01, 0xE0]))),                 # setup comm
        (eng, s7plc, 50400, 102, _s7(7, bytes([0, 1, 0x12, 4, 0x11, 0x44, 0x01, 0]), b"\xff\x09\x00\x04\x00\x11\x00\x00")),  # read SZL
        (eng, s7plc, 50400, 102, _s7(1, bytes([0x05, 1, 0x12, 0x0A, 0x10, 2, 0, 1, 0, 1, 0x84, 0, 0, 0]), b"\x00\x04\x00\x08\x01")),  # write var
        (rogue, s7plc, 50401, 102, _s7(1, bytes([0x29, 0, 0, 0, 0, 0, 9]) + b"P_PROGRAM")),              # PLC stop
        (eng, s7plc, 50400, 102, _s7(1, bytes([0x1A, 0, 1, 0, 0, 0, 0, 9]) + b"_0800001P")),            # request download
        (eng, abplc, 50500, 44818, _enip(0x0063)),                                                       # ListIdentity
        (scada, abplc, 50501, 44818, _cip_rr(_unconnected_send(_cip_tag_write("Pump1_Speed", b"\x10\x00")))),
        (rogue, abplc, 50502, 44818, _cip_rr(bytes([0x05, 0x02, 0x20, 0x01, 0x24, 0x01]))),           # Identity Reset
    ]
    pkts = []
    for src, dst, sp, dp, payload in flows:
        pkts.append(_eth(mac[dst], mac[src], 0x0800, _ipv4(src, dst, 6, _tcp(sp, dp, payload))))
    with open(os.path.join(HERE, "control_center.pcap"), "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            fh.write(struct.pack("<IIII", 1788100000 + i, 0, len(p), len(p)) + p)


STRATIX_CFG = """!
! Last configuration change at 09:12:44 UTC Mon Sep 7 2026 by admin
! Stratix 5700 cell/area zone switch (synthetic sample)
version 15.2
service timestamps log datetime msec
no service password-encryption
!
hostname CELL2-STRATIX
!
enable password 7 0822455D0A16
username maint privilege 15 password 0 Maint2026
!
vlan 10
 name CONTROL
vlan 20
 name SAFETY
!
interface FastEthernet1/1
 description PLC-L1 (synthetic)
 switchport access vlan 10
 switchport mode access
!
interface FastEthernet1/2
 description HMI-L1
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/1
 description Uplink to distribution
 switchport mode trunk
!
interface Vlan1
 ip address 10.40.0.2 255.255.255.0
!
ip http server
ip http secure-server
snmp-server community public RO
snmp-server community Pl4ntRW RW
!
line con 0
line vty 0 4
 password 7 104D000A0618
 login
 transport input telnet ssh
line vty 5 15
 login local
 transport input ssh
!
end
"""

FORTI_CFG = """#config-version=FGR60F-7.2.8-FW-build1639-240313:opmode=0:vdom=0:user=admin
#conf_file_ver=000000000000000
#buildno=1639
config system global
    set hostname "SUBSTATION-FW1"
    set timezone 57
end
config system interface
    edit "wan1"
        set ip 198.51.100.10 255.255.255.248
        set allowaccess ping https ssh
        set role wan
    next
    edit "internal"
        set ip 10.50.0.1 255.255.255.0
        set allowaccess ping https http telnet
        set role lan
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
    edit "vendor"
        set trusthost1 10.50.0.0 255.255.255.0
        set accprofile "prof_admin"
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config firewall policy
    edit 1
        set name "temp-commissioning"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set logtraffic disable
    next
    edit 2
        set name "scada-to-rtu"
        set srcintf "internal"
        set dstintf "internal"
        set action accept
        set srcaddr "SCADA"
        set dstaddr "RTU-NET"
        set service "IEC-104"
    next
end
"""

RUGGEDCOM_CSV = """#
# RUGGEDCOM ROS configuration export (synthetic sample, not a real device)
#
# System Identification
System Name,Location,Contact
"BAY3-RSG",Substation demo,ops
# Firmware
Firmware Version,"5.6.0"
# IP Services
Telnet Sessions Allowed,Enabled
Web Server Users Allowed,Enabled
# IP Interfaces
Type,ID,Mgmt,IP Address Type,IP Address,Subnet
VLAN,1,Yes,Static,10.60.0.5,255.255.255.0
# SNMP Users
Community,public
# Passwords
admin,admin
"""


def netconfigs():
    for name, body in (("stratix_cell2.cfg", STRATIX_CFG), ("fgr60f_substation.conf", FORTI_CFG),
                       ("ruggedcom_bay3.csv", RUGGEDCOM_CSV)):
        with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)


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
    comtrade(); pcap(); pcap_commands(); netconfigs(); l5x(); eds(); scd_v2(); engineering()
    print("samples regenerated")

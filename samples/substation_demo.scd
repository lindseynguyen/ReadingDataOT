<?xml version="1.0" encoding="UTF-8"?>
<!-- Synthetic sample for testing, not a real substation configuration -->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="SUBSTATION_DEMO_110kV" version="1.2" revision="A" toolID="DemoTool"/>
  <Substation name="SUBSTATION_DEMO">
    <VoltageLevel name="E1">
      <Voltage unit="V" multiplier="k">110</Voltage>
      <Bay name="Q01"/><Bay name="Q02"/><Bay name="Q03"/>
    </VoltageLevel>
    <VoltageLevel name="J1">
      <Voltage unit="V" multiplier="k">22</Voltage>
      <Bay name="Q11"/><Bay name="Q12"/>
    </VoltageLevel>
  </Substation>
  <Communication>
    <SubNetwork name="StationBus" type="8-MMS">
      <ConnectedAP iedName="F87T_Q01" apName="S1">
        <Address>
          <P type="IP">10.10.1.11</P><P type="IP-SUBNET">255.255.255.0</P><P type="IP-GATEWAY">10.10.1.1</P>
        </Address>
        <GSE ldInst="PROT" cbName="GoTrip">
          <Address><P type="MAC-Address">01-0C-CD-01-00-01</P><P type="APPID">0001</P><P type="VLAN-ID">064</P><P type="VLAN-PRIORITY">4</P></Address>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="F21_Q02" apName="S1">
        <Address>
          <P type="IP">10.10.1.12</P><P type="IP-SUBNET">255.255.255.0</P><P type="IP-GATEWAY">10.10.2.1</P>
        </Address>
        <GSE ldInst="PROT" cbName="GoTrip">
          <Address><P type="MAC-Address">01-0C-CD-01-00-02</P><P type="APPID">0001</P><P type="VLAN-ID">000</P></Address>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="BCU_Q03" apName="S1">
        <Address>
          <P type="IP">10.10.1.11</P><P type="IP-SUBNET">255.255.255.0</P>
        </Address>
      </ConnectedAP>
      <ConnectedAP iedName="GW_SCADA" apName="S1">
        <Address><P type="IP">192.168.1.1</P><P type="IP-SUBNET">255.255.255.0</P></Address>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="F87T_Q01" manufacturer="SIEMENS" type="7UT85" configVersion="V08.40" desc="Transformer differential protection">
    <AccessPoint name="S1"><Server><Authentication/>
      <LDevice inst="PROT">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="dsTrip">
            <FCDA ldInst="PROT" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
            <FCDA ldInst="PROT" lnClass="PDIF" lnInst="1" doName="Op" daName="general" fc="ST"/>
          </DataSet>
          <GSEControl name="GoTrip" appID="F87T_Q01/PROT/GoTrip" datSet="dsTrip" confRev="1"/>
          <ReportControl name="rcbA" datSet="dsTrip"/>
        </LN0>
        <LN lnClass="PDIF" inst="1" lnType="PDIF_T"/>
        <LN lnClass="PTRC" inst="1" lnType="PTRC_T"/>
      </LDevice>
      <LDevice inst="CTRL">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
        <LN lnClass="XCBR" inst="1" lnType="XCBR_T"/>
        <LN prefix="Q0" lnClass="CSWI" inst="1" lnType="CSWI_T"/>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <IED name="F21_Q02" manufacturer="SEL" type="SEL-411L" configVersion="R125">
    <AccessPoint name="S1"><Server><Authentication/>
      <LDevice inst="PROT">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="dsTrip">
            <FCDA ldInst="PROT" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
          </DataSet>
          <GSEControl name="GoTrip" appID="F21_Q02/PROT/GoTrip" datSet="dsTrip" confRev="3"/>
        </LN0>
        <LN lnClass="PDIS" inst="1" lnType="PDIS_T"/>
        <LN lnClass="PTRC" inst="1" lnType="PTRC_T"/>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <IED name="BCU_Q03" manufacturer="ABB" type="REC670" configVersion="2.2">
    <AccessPoint name="S1"><Server><Authentication/>
      <LDevice inst="CTRL">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
        <LN lnClass="XCBR" inst="1" lnType="XCBR_T"/>
        <LN lnClass="MMXU" inst="1" lnType="MMXU_T"/>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <IED name="GW_SCADA" manufacturer="Generic" type="Gateway-IEC104">
    <AccessPoint name="S1"><Server><Authentication/>
      <LDevice inst="GW"><LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/></LDevice>
    </Server></AccessPoint>
  </IED>
</SCL>

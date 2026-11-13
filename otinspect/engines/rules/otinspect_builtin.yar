/*
  OTInspect built-in YARA rules: OT/ICS triage of files found in engineering
  backups, contractor packages and jump hosts. Generic, behaviour-oriented rules,
  not malware-family signatures: add vendor / CISA / in-house rule sets with
  --yara-rules for that.

  Meta used by OTInspect:
    severity  high | medium | low | info
    iec62443  comma-separated IEC 62443-3-3 SRs
    attack    comma-separated MITRE ATT&CK for ICS technique IDs
  Rules must compile with both libyara 4.x (yara-python) and YARA-X.
  Strings of offensive tools are written as hex so that antivirus products do not
  quarantine this rule file itself.
*/

private rule OTI_Is_PE { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }
private rule OTI_Is_ELF { condition: uint32(0) == 0x464C457F }
private rule OTI_Is_Executable { condition: OTI_Is_PE or OTI_Is_ELF }

rule OTI_EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (checks that YARA scanning works)"
        severity = "info"
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }
    condition:
        $eicar at 0
}

rule OTI_Remote_Access_Tool
{
    meta:
        description = "Remote access / tunnelling software: confirm it is approved for OT remote access"
        severity = "medium"
        iec62443 = "SR 1.13,SR 2.6,SR 5.2"
        attack = "T0822,T0886"
    strings:
        $anydesk   = "AnyDesk Software GmbH" ascii wide
        $tv1       = "TeamViewer GmbH" ascii wide
        $tv2       = "TeamViewer Germany GmbH" ascii wide
        $sc        = "ScreenConnect.Client" ascii wide
        $rustdesk  = "rustdesk.com" ascii wide
        $splash    = "Splashtop Inc." ascii wide
        $radmin    = "Famatech" ascii wide
        $ultravnc  = "UltraVNC" ascii wide
        $tightvnc  = "GlavSoft LLC" ascii wide
        $ngrok1    = "ngrok-agent" ascii wide
        $ngrok2    = "tunnel.us.ngrok.com" ascii wide
        $chisel    = "github.com/jpillora/chisel" ascii
        $frp       = "github.com/fatedier/frp" ascii
        $plink     = "PuTTY Link" ascii wide
    condition:
        OTI_Is_Executable and filesize < 200MB and any of them
}

rule OTI_Credential_Dumping_Tool
{
    meta:
        description = "Credential dumping tool strings (Mimikatz family)"
        severity = "high"
        iec62443 = "SR 1.5,SR 3.2"
        attack = "T0859,T0867"
    strings:
        $m1 = /\x73\x65\x6b\x75\x72\x6c\x73\x61\x3a\x3a\x6c\x6f\x67\x6f\x6e\x70\x61\x73\x73\x77\x6f\x72\x64\x73/ ascii wide nocase
        $m2 = /\x6c\x73\x61\x64\x75\x6d\x70\x3a\x3a\x73\x61\x6d/ ascii wide nocase
        $m3 = /\x6b\x65\x72\x62\x65\x72\x6f\x73\x3a\x3a\x67\x6f\x6c\x64\x65\x6e/ ascii wide nocase
        $m4 = /\x67\x65\x6e\x74\x69\x6c\x6b\x69\x77\x69/ ascii wide
        $m5 = /\x6d\x69\x6d\x69\x6b\x61\x74\x7a/ ascii wide nocase
        $m6 = /\x70\x72\x69\x76\x69\x6c\x65\x67\x65\x3a\x3a\x64\x65\x62\x75\x67/ ascii wide nocase
    condition:
        2 of them
}

rule OTI_Offensive_Framework_Artifact
{
    meta:
        description = "Artifacts of offensive frameworks (reflective loader, Meterpreter, Impacket)"
        severity = "high"
        iec62443 = "SR 3.2"
        attack = "T0867,T0886"
    strings:
        $rl   = { 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }
        $met1 = /\x6d\x65\x74\x73\x72\x76\x2e\x64\x6c\x6c/ ascii wide nocase
        $met2 = { 73 74 64 61 70 69 5F 73 79 73 5F 70 72 6F 63 65 73 73 5F 65 78 65 63 75 74 65 }
        $imp1 = { 69 6D 70 61 63 6B 65 74 2E 73 6D 62 63 6F 6E 6E 65 63 74 69 6F 6E }
        $imp2 = { 69 6D 70 61 63 6B 65 74 2E 64 63 65 72 70 63 }
        $psx  = /\x52\x65\x6d\x43\x6f\x6d\x53\x76\x63/ ascii wide
    condition:
        OTI_Is_Executable and any of them
}

rule OTI_PLC_Control_Library
{
    meta:
        description = "Executable embeds an S7 client library able to stop / start PLCs and download blocks (Snap7): confirm it is approved engineering software"
        severity = "medium"
        iec62443 = "SR 2.1,SR 3.2,SR 7.8"
        attack = "T0858,T0843,T1692.001"
    strings:
        $s1 = "Cli_PlcStop" ascii
        $s2 = "Cli_PlcColdStart" ascii
        $s3 = "Cli_PlcHotStart" ascii
        $s4 = "Cli_Download" ascii
        $s5 = "Cli_SetSessionPassword" ascii
        $s6 = "Cli_Delete" ascii
    condition:
        OTI_Is_Executable and 2 of them
}

rule OTI_ICS_Protocol_Library
{
    meta:
        description = "Executable embeds an OT protocol stack (IEC 61850, IEC 104, DNP3, OPC UA, Modbus, CIP): verify it belongs to approved engineering or SCADA software"
        severity = "info"
        iec62443 = "SR 7.8"
        attack = ""
    strings:
        $iec61850 = "libiec61850" ascii
        $iec104   = "lib60870" ascii
        $dnp3     = "opendnp3" ascii
        $opcua    = "open62541" ascii
        $modbus   = "libmodbus" ascii
        $pymodbus = "pymodbus" ascii
        $pycomm   = "pycomm3" ascii
        $cpppo    = "cpppo.server" ascii
    condition:
        OTI_Is_Executable and any of them
}

rule OTI_Script_Download_Execute
{
    meta:
        description = "Script downloads and executes code or decodes an encoded payload (PowerShell / cmd / shell)"
        severity = "medium"
        iec62443 = "SR 3.2,SR 7.7"
        attack = "T1701.001,T1701.002,T0867"
    strings:
        $ps1 = "DownloadString(" ascii wide nocase
        $ps2 = "DownloadFile(" ascii wide nocase
        $ps3 = "Net.WebClient" ascii wide nocase
        $ps4 = "Invoke-Expression" ascii wide nocase
        $ps5 = "FromBase64String" ascii wide nocase
        $ps6 = /\s-(enc|encodedcommand|ec)\s+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $ps7 = "Invoke-WebRequest" ascii wide nocase
        $iex = /\bIEX\s*\(/ ascii wide
        $cu1 = "certutil -urlcache" ascii wide nocase
        $cu2 = "bitsadmin /transfer" ascii wide nocase
    condition:
        filesize < 20MB and not OTI_Is_Executable and (
            ($iex or $ps4) and ($ps1 or $ps2 or $ps3 or $ps5 or $ps7)
            or $ps6 or $cu1 or $cu2
        )
}

rule OTI_Script_Pipe_To_Shell
{
    meta:
        description = "Text pipes a download straight into a shell (curl | sh): common in installers, risky on OT hosts"
        severity = "low"
        iec62443 = "SR 3.2,SR 3.4"
        attack = "T1701.003,T0867"
    strings:
        $sh = /(curl|wget)\s+[^\n|]{1,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/ ascii
    condition:
        filesize < 20MB and not OTI_Is_Executable and $sh
}

rule OTI_Webshell
{
    meta:
        description = "Web shell pattern (request parameter passed to code / command execution): check HMI and SCADA web servers"
        severity = "high"
        iec62443 = "SR 3.2,SR 3.5"
        attack = "T0819,T0886"
    strings:
        $php1 = /(eval|assert|system|exec|shell_exec|passthru|popen)\s*\(\s*(base64_decode\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
        $asp1 = /eval\s*\(\s*Request(\.Item)?\s*[\[\(]/ nocase
        $aspx = /Process\.Start\s*\([^)]{0,80}Request(\.Form|\.QueryString|\.Params)?\s*\[/ nocase
        $jsp  = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter/ nocase
    condition:
        filesize < 5MB and any of them
}

rule OTI_Ransom_Note
{
    meta:
        description = "Ransom note text"
        severity = "high"
        iec62443 = "SR 3.2,SR 7.3"
        attack = "T0828"
    strings:
        $a1 = "your files have been encrypted" ascii wide nocase
        $a2 = "all your files are encrypted" ascii wide nocase
        $a3 = "files are encrypted" ascii wide nocase
        $b1 = ".onion" ascii wide nocase
        $b2 = "bitcoin" ascii wide nocase
        $b3 = "decryption key" ascii wide nocase
        $b4 = "decryptor" ascii wide nocase
    condition:
        filesize < 2MB and any of ($a*) and 2 of ($b*)
}

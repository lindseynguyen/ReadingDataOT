# Detection engines: YARA and capa

OTInspect can run two well-known detection engines over the files it inventories. Both are
**optional and off by default**. They add findings to the same report, with IEC 62443-3-3 and
MITRE ATT&CK for ICS references, so they appear in HTML, CSV, JSON, SARIF and the GUI like any
other finding.

| | YARA | capa |
|---|---|---|
| What it answers | "Does this file contain a known pattern?" | "What can this executable do?" |
| Files | every file (size limit, default 128 MB) | PE / ELF / .NET executables (default 32 MB) |
| How | byte / string / regex rules, in-process | static analysis in a separate process (the sample is **never executed**) |
| Install | `pip install yara-python` (or `yara-x`) | standalone `capa` executable, or `pip install flare-capa` + rules |
| Enable | `--yara`, `--yara-rules PATH` | `--capa` |

## Quick start

```bash
pip install "otinspect[yara]"                 # or: pip install yara-python / yara-x
otinspect engines                             # what is installed, do the rules compile?
otinspect scan D:\Backup --yara --html report.html
otinspect scan D:\Backup --yara --yara-rules C:\rules\vendor --yara-rules C:\rules\site.yar
otinspect scan D:\Backup --capa --capa-path C:\tools\capa.exe
otinspect scan D:\Backup --yara --capa --fail-on high          # exit code 2 on any high finding
```

GUI: tick **YARA** / **capa** next to *Analyze*, or open **Engines…** to add rule sets, set the
capa path and limits, and *Check engines*.

The Windows release bundles yara-python and the built-in rules. capa is not bundled: download
`capa-<version>-windows.zip` from [mandiant/capa releases](https://github.com/mandiant/capa/releases)
(rules and signatures are embedded) and point *Engines… → capa executable* or `--capa-path` at
`capa.exe`. With `pip install flare-capa` you must also give the rules (`--capa-rules`, from
[capa-rules](https://github.com/mandiant/capa-rules) at the matching tag) and, for PE files, the
signatures (`--capa-sigs`, the `sigs/` folder of the capa repository). Both can also come from
`OTINSPECT_CAPA`, `OTINSPECT_CAPA_RULES` and `OTINSPECT_CAPA_SIGS`.

## Built-in YARA rules

`otinspect/engines/rules/otinspect_builtin.yar` holds generic OT/ICS triage rules. They describe
behaviour, not malware families; add vendor, CISA or in-house rule sets with `--yara-rules`.

| Rule | Severity | Looks for |
|---|---|---|
| `OTI_Remote_Access_Tool` | medium | AnyDesk, TeamViewer, ScreenConnect, RustDesk, Splashtop, Radmin, VNC, ngrok, chisel, frp, plink in executables |
| `OTI_Credential_Dumping_Tool` | high | Mimikatz command strings |
| `OTI_Offensive_Framework_Artifact` | high | Reflective loader, Meterpreter, Impacket, RemCom artefacts in executables |
| `OTI_PLC_Control_Library` | medium | Executables embedding the Snap7 S7 client API able to stop / start PLCs and download blocks |
| `OTI_ICS_Protocol_Library` | info | Executables embedding IEC 61850, IEC 104, DNP3, OPC UA, Modbus or CIP stacks |
| `OTI_Script_Download_Execute` | medium | PowerShell download-and-execute, encoded commands, certutil / bitsadmin downloads |
| `OTI_Script_Pipe_To_Shell` | low | `curl … \| sh` style installers |
| `OTI_Webshell` | high | Request parameters passed to eval / system / Process.Start (PHP, ASP, ASPX, JSP) |
| `OTI_Ransom_Note` | high | Ransom note wording |
| `OTI_EICAR_Test_File` | info | The EICAR test file, to check that scanning works |

The rules are checked for false positives on the bundled samples and on about 96,000 files of a
Linux system with Python libraries (one known low-severity hit: installation instructions that
pipe `curl` into a shell). Strings of offensive tools are written in hex so that antivirus products
do not quarantine the rule file itself.

### Your own rules

Any YARA rule works. OTInspect reads these optional `meta` fields:

```yara
rule Site_Unapproved_Engineering_Tool
{
    meta:
        description = "Engineering tool not on the approved software list"
        severity    = "high"            // high | medium | low | info (also critical, or a 0-10 / 0-100 score)
        iec62443    = "SR 7.8,SR 3.2"   // IEC 62443-3-3 SRs
        attack      = "T0867"           // ATT&CK for ICS technique IDs
    strings:
        $a = "ExampleVendor PLC Loader" wide ascii
    condition:
        uint16(0) == 0x5A4D and $a
}
```

Without `severity` a match is *medium*; without `iec62443` it maps to SR 3.2 (malicious code
protection). Each rule file is compiled separately: a broken file is reported as a warning and the
others are still used. Rule files found inside the scanned folder (`.yar`, `.yara`) are not
reported as matches. Matched bytes are never copied into reports (they may be secrets); the report
shows the rule, the pattern identifiers and the first offset.

## capa findings

capa reports dozens of capabilities per executable, most of them normal. OTInspect keeps all of them
in the file details (JSON / GUI) and raises findings only for groups that matter in triage:

| Finding | Severity | capa namespaces |
|---|---|---|
| `CAPA-PROCESS-INJECTION` | high | host-interaction/process/inject |
| `CAPA-MALWARE-FAMILY` | high | malware-family/ |
| `CAPA-CREDENTIAL-THEFT` | high | collection/keylog, collection/browser, persistence/authentication-process |
| `CAPA-BOOTKIT` | high | host-interaction/bootloader |
| `CAPA-ANTI-FORENSICS` | high | anti-analysis/anti-forensic (log clearing, self-deletion) |
| `CAPA-C2` | medium | communication/c2 (also matches benign "write and execute a file" helpers: verify) |
| `CAPA-IMPACT` | high | impact/ |
| `CAPA-DEFENSE-EVASION` | medium | anti-analysis/anti-av, host-interaction/uac/bypass, host-interaction/firewall/modify |
| `CAPA-CODE-LOADING` | medium | load-code/shellcode, load-code/pe, load-code/powershell |
| `CAPA-PERSISTENCE` | medium | persistence/ |
| `CAPA-SURVEILLANCE` | medium / low | collection/screenshot, host-interaction/clipboard |
| `CAPA-EXPLOITATION` | medium | exploitation/ |
| `CAPA-ANTI-ANALYSIS` | low | anti-debugging, anti-VM, obfuscation (also common in licensed engineering software) |
| `CAPA-DRIVER` | low | host-interaction/driver |

Severities were calibrated on real system binaries: only capabilities that are rare
in legitimate software are *high*. The message lists the matched capabilities and the ATT&CK Enterprise techniques capa reports;
the finding itself carries ATT&CK for ICS and IEC 62443-3-3 references.

## Stability and safety

- **Optional**: a missing engine, a missing rules folder or a capa that does not start is a scan
  warning; the rest of the scan runs normally.
- **Isolation**: capa runs as a child process with a hard timeout (default 180 s); on timeout the
  whole process tree is killed (including the second process of the standalone capa executable).
  A crash or invalid output becomes a note on that file. Missing capa rules stop capa after the first
  file instead of failing on every executable.
- **Limits**: YARA timeout per file (default 60 s) and size limit; capa size limit and number of
  parallel processes (default 2); at most 50 YARA matches per file.
- **Read-only**: nothing is executed or modified. Archive members are not extracted for the engines.
- **Cache**: capa results are cached by file SHA-256, capa version and rules
  (`~/.otinspect/cache/capa`, override with `OTINSPECT_CACHE`; `--no-capa-cache` to bypass).

## Compatibility

Tested in CI on Linux and Windows:

| | Versions |
|---|---|
| YARA backends | yara-python 4.2 – 4.5 (libyara 4.x), YARA-X 1.x. If both are installed, yara-python is used; set `OTINSPECT_YARA_BACKEND=yara-x` to prefer YARA-X. The built-in rules compile and give the same results on both |
| capa | 7.x – 10.x (pip package and standalone executable); older JSON formats are parsed as well |
| Python | 3.10 – 3.13 |

# OTInspect (ReadingDataOT)

File inventory and analysis for OT/ICS environments. Point it at a folder (a substation backup, an engineering project, a contractor's share drive…) and it tells you **what is in there, which devices it describes, and which configuration risks it can see**.

It only **reads files**. It never connects to devices.

> **Status: beta.** Tested on synthetic samples, public real-world captures and SCL files, fuzzed and hostile inputs, on Windows and Linux. Please open an issue if a file is misidentified or parsed wrongly.

![OTInspect HTML report: summary cards and network map](docs/images/report-overview.png)

## Screenshots

| Desktop app | Command line |
|---|---|
| ![Findings tab in the desktop app](docs/images/gui-findings.png) | ![otinspect scan output](docs/images/cli-scan.png) |
| *Findings sorted by severity, with details for the selected row* | *Scan summary and findings in a terminal* |

<details>
<summary>More screenshots: findings table, SCD diff, asset inventory, dark mode</summary>

**Findings in the HTML report**, including offline advisory matches

![Findings table](docs/images/report-findings.png)

**SCD diff** between two revisions of a substation configuration

![SCD diff report](docs/images/scd-diff.png)

![otinspect diff in a terminal](docs/images/cli-diff.png)

**Asset inventory** in the desktop app

![Assets tab](docs/images/gui-assets.png)

**Dark mode** (follows the system setting)

![Report in dark mode](docs/images/report-dark.png)

</details>

All screenshots use the fabricated data in `samples/`.

## Download (Windows)

Get `OTInspect-<version>-windows-x64.zip` from the [Releases](https://github.com/lindseynguyen/ReadingDataOT/releases) page. It contains two portable executables, no installation or Python required:

- `OTInspect.exe`: graphical interface (drag a folder onto the window)
- `otinspect-cli.exe`: command line, for scripts and scheduled checks

Verify the download with `SHA256SUMS.txt`. Windows SmartScreen may warn because the executables are not code-signed; choose *More info → Run anyway* only if the checksum matches.

## What it understands

| Area | Formats | What you get |
|---|---|---|
| **IEC 61850** | SCD, ICD, CID, IID, SSD, SED | IEDs (vendor, model, configVersion, IP/subnet/gateway/MAC), LDevice / LN0 / LN, GOOSE & SV (APPID, MAC, VLAN, DataSet), ReportControl, voltage levels and bays |
| **Disturbance records** | COMTRADE `.cfg` + `.dat/.hdr/.inf` (C37.111-1991/1999/2013) | Station, recording device, analog/digital channels with units and CT/VT ratios, sample rates, start/trigger time, duration, `.dat` size check |
| **Network captures** | PCAP, PCAPNG (pure Python) | L2 protocols (GOOSE, SV, PROFINET, EtherCAT, PTP, LLDP), IP-based OT protocols (MMS/S7comm, IEC 104, Modbus/TCP, DNP3, EtherNet/IP, OPC UA, BACnet, FINS, CODESYS…), VLANs, GOOSE streams with gocbRef, host inventory, top conversations, Modbus function codes, and **decoded OT commands**: who sent which control, write, stop, restart, download or password command to which device (see below) |
| **Network devices** | Cisco IOS / IOS-XE (incl. Cisco IE, Rockwell Stratix), Fortinet FortiOS (incl. FortiGate Rugged); RUGGEDCOM, Hirschmann, Moxa, Westermo, Phoenix Contact, SCALANCE… (heuristic) | Hostname, version, management IP, interfaces, VLANs, firewall policies; hardening checks |
| **PLC (Rockwell)** | `.L5X`, `.L5K` | Controller, processor, firmware, I/O and network modules with IPs, programs/routines/tags, AOIs, tasks |
| **Device descriptions** | GSDML, EDS, ESI, GSD | Vendor, product, order number, hardware/software release |
| **Logs / configs** | text logs, `.cfg`, `.ini`, CSV… | error/warning/alarm/auth counts, time range, top IPs, cleartext passwords / SNMP communities / private keys (masked) |
| **Firmware / binaries** | BIN, HEX, SREC, ELF, SquashFS, uImage… | per-block entropy, embedded signatures, interesting strings, Intel HEX address range |
| **Archives** | ZIP, Siemens TIA `.zapXX` | members identified in place (no extraction), zip-bomb and path-traversal guards |
| **Engineering exports** | AutomationML / CAEX `.aml` (Siemens TIA hardware export), Schneider `.xef`, PLCopen XML | Devices with order numbers, firmware and IPs; application/project info, POUs and sections by language, tasks, variables |
| **Identified only** | Siemens TIA/STEP 7, Rockwell `.ACD`, Schneider, CODESYS, ABB PCM600, WinCC, FactoryTalk, EVTX, OPC UA NodeSet, PLCopen XML | category and description |

Supported files inside ZIP archives (contractor handover packages, TIA `.zapXX`) are parsed in place.

Identification uses magic bytes, content (XML namespaces, COMTRADE header layout, device configuration syntax) and extensions; `python-magic` is not required.

Large files are handled in bounded memory: SCL is parsed as a stream (a 74 MB SCD peaks around 50 MB of RAM instead of 400 MB), captures are memory-mapped, and each parser has a size limit (SCL 2 GB, PLC exports 256 MB, device descriptions 32 MB). Files above the limit are still hashed and identified; raise or remove the limit with `--max-file-mb` (`0` = no limit).

### OT commands in captures

| Protocol | Decoded | Flagged |
|---|---|---|
| IEC 60870-5-104 | ASDU type and cause of transmission in the control direction | single/double/regulating commands and setpoints (`PCAP-IEC104-CONTROL`), reset process (`-RESET`), parameter loading, file transfer |
| DNP3 | application function of each request | select/operate/direct operate, write, cold/warm restart, stop/start application, file and configuration functions; commands without Secure Authentication |
| S7comm | job and user-data functions | write var, PLC stop, download, PI services (start, insert/delete block), upload, password functions, SZL/block reconnaissance; S7comm-plus sessions noted |
| EtherNet/IP + CIP | encapsulation command, CIP service and path (Unconnected Send unwrapped) | tag writes, Set_Attribute, Reset/Start/Stop services, ListIdentity reconnaissance |

Routine polling (interrogation, reads, time sync) is summarised in the report but not flagged. Each finding names the sender and the target, so a command from an unexpected host stands out.

## Risk rules

- **SCL**: duplicate IPs, duplicate GOOSE/SV APPID or destination MAC, default/special IPs, gateway outside subnet, GOOSE without VLAN, control blocks without an address, IEC 62351-6 reminder
- **PCAP**: Telnet/FTP/TFTP/HTTP/VNC servers, Modbus write and diagnostic requests, GOOSE APPID sent by several MACs, untagged GOOSE, and the OT commands above
- **Network devices**: Telnet / HTTP management, SSHv1, cleartext or type 7 passwords, MD5 enable secret, default or read-write SNMP communities, management without ACL / trusted hosts, admin access on WAN interfaces, any-any firewall policies, missing remote logging and NTP, default credentials
- **L5X**: credential-like tags, mostly Read/Write external tag access, no source protection, no FactoryTalk Security binding
- **Text**: cleartext passwords, SNMP `public`/`private`, private keys
- **Firmware**: passwd/shadow content, embedded PEM blocks
- **Cross-reference**: hosts serving OT protocols in a capture that appear in **no** configuration file (`XREF-UNDOCUMENTED-HOST`)
- **XEF / PLCopen**: credential-like variables
- **Your own rules** in YAML/JSON: site baselines, approved vendors, minimum firmware, forbidden protocols. See [docs/rules.md](docs/rules.md)
- **Advisories (offline)**: assets matched against CISA ICS advisories imported from CSAF 2.0 (vendor + product + version range), reported as *possible* matches to verify

## IEC 62443 and MITRE ATT&CK for ICS

Every finding is mapped to the **IEC 62443-3-3 system requirements** it gives evidence against and the **MITRE ATT&CK for ICS** techniques it relates to. For example, a PLC stop command seen in a capture maps to SR 2.1 and T0881 / T0858, and an any-any firewall rule maps to SR 5.1 / SR 5.2. The HTML report shows the mapping per finding and a summary table per SR. The same data is in the JSON, CSV and SARIF exports. User rules can set their own mapping (see [docs/rules.md](docs/rules.md)).

The mapping helps an assessor prioritise and write up findings. It is not a compliance verdict.

## SARIF and CycloneDX

```bash
otinspect scan ./site-configs --sarif otinspect.sarif          # GitHub code scanning, any SARIF viewer
otinspect scan D:\Substation_Backup --cyclonedx assets.cdx.json # CycloneDX 1.6 hardware/firmware BOM
```

- **SARIF 2.1.0**: one result per finding with severity, IEC 62443 / ATT&CK tags and stable fingerprints. If you keep switch, firewall or SCL files in a Git repository, upload it to GitHub code scanning so findings appear as alerts on the files:

  ```yaml
  # .github/workflows/otinspect.yml
  on: [push, pull_request]
  permissions: { contents: read, security-events: write }
  jobs:
    scan:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with: { python-version: "3.12" }
        - run: pip install "otinspect @ git+https://github.com/lindseynguyen/ReadingDataOT@v0.4.0"
        - run: otinspect scan . -q --sarif otinspect.sarif
        - uses: github/codeql-action/upload-sarif@v3
          with: { sarif_file: otinspect.sarif }
  ```

- **CycloneDX 1.6**: discovered devices (with vendor, model, IP/MAC and protocols as properties) with their firmware as nested components, the analysed engineering files with SHA-256 hashes, and advisory matches as vulnerabilities. Validated against the official 1.6 schema.

## SCD diff

Compare two revisions of a substation configuration, typically before accepting an integrator's update:

```bash
otinspect diff old.scd new.scd --html diff.html --fail-on high
```

It lists added/removed/modified IEDs, addresses, logical devices and nodes, DataSets and GOOSE/SV control blocks, and flags:

- `DIFF-GOOSE-CONFREV` / `DIFF-SV-CONFREV`: DataSet changed but `confRev` was not incremented, so subscribers may map the wrong signals
- `DIFF-*-ADDR-CHANGED`: APPID, destination MAC or VLAN changed, so subscribers must be re-configured
- `DIFF-*-REMOVED`: a publisher disappeared
- `DIFF-HEADER-NOT-BUMPED`: content changed but the SCL Header version/revision did not

## Network map

![Network map](docs/images/network-map.png)

The HTML report draws every asset with an IP, grouped by SCL SubNetwork or /24. Devices with high findings have a red border, duplicate IPs are marked, and hosts that appear only in captures (undocumented) have a dashed orange border.

## Install from source

```bash
git clone https://github.com/lindseynguyen/ReadingDataOT.git
cd ReadingDataOT
pip install ".[gui]"        # or: pip install -r requirements.txt
```

Python 3.9+ is required, plus `defusedxml` and `PyYAML` (installed automatically). PyQt5 is needed only for the GUI.

XML files are parsed only through defusedxml: if it is missing, OTInspect reports XML files as parse errors instead of falling back to an unprotected parser.

## Usage

```bash
# GUI
otinspect gui                   # or: python -m otinspect gui

# Scan
otinspect scan D:\Substation_Backup --html report.html --json report.json --csv out\
otinspect scan D:\Substation_Backup --sarif report.sarif --cyclonedx assets.cdx.json
otinspect scan ./project --rules site_rules.yaml --fail-on high   # exit code 2 on any high finding

# Compare two SCD revisions
otinspect diff old.scd new.scd --html diff.html

# Build the offline advisory DB (on a connected machine), then use it anywhere
git clone --depth 1 https://github.com/cisagov/CSAF
otinspect advisories import CSAF/csaf_files/OT/white -o advisories.json
otinspect scan D:\Backup --advisories advisories.json
```

With the Windows release, replace `otinspect` with `otinspect-cli.exe`.

Try it on the bundled synthetic data:

```bash
python -m otinspect scan samples --html demo.html
```

`samples/make_samples.py` regenerates the samples (including a second SCD revision for `diff`). All sample data is fabricated.

## Reports

- **HTML**: self-contained and works offline; print to PDF from any browser. Sections: network map, assets, findings with IEC 62443 / ATT&CK references, IEC 62443-3-3 SR summary, GOOSE, observed protocols, COMTRADE records, file categories, full file list with SHA-256.
- **JSON**: everything, including per-file details and decoded OT commands.
- **CSV**: `files.csv`, `assets.csv`, `findings.csv` (with `iec62443_3_3` and `attack_ics` columns).
- **SARIF 2.1.0** and **CycloneDX 1.6**: see above.

## Architecture

```
otinspect/
  core/      identify.py · scanner.py (recursion, hashing, threads, cross-reference) · registry.py · model.py · safexml.py (hardened XML)
  parsers/   scl (streaming) · comtrade · pcap · otcmd (OT command decoders) · plc_l5x · plc_iec · devicedesc
             netconfig (switch / router / firewall) · logfile · archive · binary
  diff/      scd_diff.py
  rules/     engine.py (YAML/JSON rules) · advisories.py (CSAF import + matching) · builtin.json
  standards/ mappings.json (finding -> IEC 62443-3-3 SR / ATT&CK for ICS) · lookup and annotation
  report/    export.py (HTML / JSON / CSV) · interop.py (SARIF / CycloneDX) · netmap.py (SVG network map)
  gui/       app.py (PyQt5)
  cli.py
packaging/   PyInstaller spec for the Windows executables
```

To add a format, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Tests

```bash
pip install -e ".[dev]"
python -m pytest -q --cov                    # unit, robustness and Hypothesis fuzz tests, coverage >= 85 %
python tests/realworld/fetch.py              # optional: download public real-world samples
python -m pytest -q tests/test_realworld.py
```

- **Unit tests** for every parser, the command decoders, network configurations, diff, rules, advisories, standards mapping and all report formats (SARIF and CycloneDX are checked against the official schemas).
- **Robustness**: random garbage under every OT extension, truncated and bit-flipped samples, XML entity bombs, XXE, fail-closed XML without defusedxml, zip slip, zip bombs, Unicode paths, a 1,500-file tree and a 40 MB SCD with a memory ceiling.
- **Fuzzing** with [Hypothesis](https://hypothesis.readthedocs.io/): protocol decoders, the PCAP parser, configuration parsers, file identification and version comparison must accept arbitrary input without raising.
- **Real-world files**: captures from real PLCs and RTUs (DNP3, IEC 104, S7comm including a program download with password, EtherNet/IP stop/reset/firmware change, Modbus), SCL files from OpenSCD and COMTRADE from python-comtrade. They are listed in `tests/realworld/manifest.json`, pinned by commit and SHA-256, downloaded on demand and never committed.

CI runs everything on Windows and Linux with Python 3.9 and 3.13, plus a real-world job. Coverage is measured without the GUI.

## Roadmap

- GOOSE publisher/subscriber matrix from SCL `Inputs/ExtRef`
- MMS (IEC 61850) control and file services, OPC UA write/call, TCP reassembly for commands split across segments
- Full parsers for RUGGEDCOM ROS/ROX, Hirschmann HiOS and Moxa configurations (heuristic today) as anonymized exports become available
- More engineering formats (ABB PCM600, GE EnerVista, SEL AcSELerator) as sample files become available

Contributions and (anonymized) sample files for unsupported formats are very welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and the *File misidentified or parsed wrongly* issue template.

## Handling

Reports contain IPs, MACs and system topology. Treat them as confidential according to your organization's policy.

## Security

To report a vulnerability in OTInspect itself (for example a file that crashes or hangs a scan, or reaches outside the scanned folder), see [SECURITY.md](SECURITY.md). Please do not open a public issue for it.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT

# OTInspect (ReadingDataOT)

File inventory and analysis for OT/ICS environments. Point it at a folder (a substation backup, an engineering project, a contractor's share drive…) and it tells you **what is in there, which devices it describes, and which configuration risks it can see**.

It only **reads files**. It never connects to devices.

## What it understands

| Area | Formats | What you get |
|---|---|---|
| **IEC 61850** | SCD, ICD, CID, IID, SSD, SED | IEDs (vendor, model, configVersion, IP/subnet/gateway/MAC), LDevice / LN0 / LN, GOOSE & SV (APPID, MAC, VLAN, DataSet), ReportControl, voltage levels and bays |
| **Disturbance records** | COMTRADE `.cfg` + `.dat/.hdr/.inf` (C37.111-1991/1999/2013) | Station, recording device, analog/digital channels with units and CT/VT ratios, sample rates, start/trigger time, duration, `.dat` size check |
| **Network captures** | PCAP, PCAPNG (pure Python) | L2 protocols (GOOSE, SV, PROFINET, EtherCAT, PTP, LLDP), IP-based OT protocols (MMS/S7comm, IEC 104, Modbus/TCP, DNP3, EtherNet/IP, OPC UA, BACnet, FINS, CODESYS…), VLANs, GOOSE streams with gocbRef, host inventory, top conversations, Modbus function codes |
| **PLC (Rockwell)** | `.L5X`, `.L5K` | Controller, processor, firmware, I/O and network modules with IPs, programs/routines/tags, AOIs, tasks |
| **Device descriptions** | GSDML, EDS, ESI, GSD | Vendor, product, order number, hardware/software release |
| **Logs / configs** | text logs, `.cfg`, `.ini`, CSV… | error/warning/alarm/auth counts, time range, top IPs, cleartext passwords / SNMP communities / private keys (masked) |
| **Firmware / binaries** | BIN, HEX, SREC, ELF, SquashFS, uImage… | per-block entropy, embedded signatures, interesting strings, Intel HEX address range |
| **Archives** | ZIP, Siemens TIA `.zapXX` | members identified in place (no extraction), zip-bomb and path-traversal guards |
| **Identified only** | Siemens TIA/STEP 7, Rockwell `.ACD`, Schneider, CODESYS, ABB PCM600, WinCC, FactoryTalk, EVTX, OPC UA NodeSet, PLCopen XML | category and description |

Identification uses magic bytes, content (XML namespaces, COMTRADE header layout) and extensions; `python-magic` is not required.

## Risk rules

- **SCL**: duplicate IPs, duplicate GOOSE/SV APPID or destination MAC, default/special IPs, gateway outside subnet, GOOSE without VLAN, control blocks without an address, IEC 62351-6 reminder
- **PCAP**: Telnet/FTP/TFTP/HTTP/VNC servers, Modbus write and diagnostic requests, GOOSE APPID sent by several MACs, untagged GOOSE
- **L5X**: credential-like tags, mostly Read/Write external tag access, no source protection, no FactoryTalk Security binding
- **Text**: cleartext passwords, SNMP `public`/`private`, private keys
- **Firmware**: passwd/shadow content, embedded PEM blocks
- **Cross-reference**: hosts serving OT protocols in a capture that appear in **no** configuration file (`XREF-UNDOCUMENTED-HOST`)

## Install

```bash
git clone https://github.com/lindseynguyen/ReadingDataOT.git
cd ReadingDataOT
pip install -r requirements.txt
```

The core and CLI need only Python 3.9+ (standard library). PyQt5 is needed only for the GUI.

## Usage

```bash
# GUI
python data-kiosk.py            # or: python -m otinspect gui

# CLI
python -m otinspect scan D:\Substation_Backup --html report.html --json report.json --csv out\
python -m otinspect scan ./project --fail-on high   # exit code 2 if any high finding (CI / scheduled checks)
```

Try it on the bundled synthetic data:

```bash
python -m otinspect scan samples --html demo.html
```

`samples/make_samples.py` regenerates the COMTRADE, PCAP, L5X and EDS samples. All sample data is fabricated.

## Reports

- **HTML**: self-contained and works offline; print to PDF from any browser. Sections: assets, findings, GOOSE, observed protocols, COMTRADE records, file categories, full file list with SHA-256.
- **JSON**: everything, including per-file details.
- **CSV**: `files.csv`, `assets.csv`, `findings.csv`.

## Architecture

```
otinspect/
  core/      identify.py · scanner.py (recursion, hashing, threads, cross-reference) · registry.py · model.py
  parsers/   scl · comtrade · pcap · plc_l5x · devicedesc · logfile · archive · binary
  report/    export.py (HTML / JSON / CSV)
  gui/       app.py (PyQt5)
  cli.py
```

To add a format, create a module in `otinspect/parsers/` with a class exposing `can_parse()` and `parse()`, decorate it with `@register`, and import it in `core/registry.py → load_builtin()`. Parsers are tried in import order.

## Tests

```bash
pip install pytest && python -m pytest -q
```

## Roadmap

- Network diagram generated from SCL Communication + PCAP hosts
- SCD diff between two versions (what changed in the substation)
- Siemens TIA archive internals, Schneider XEF, PLCopen XML logic summary
- YAML-defined custom rules and vulnerability lookup by vendor/model/firmware

## Handling

Reports contain IPs, MACs and system topology. Treat them as confidential according to your organization's policy.

## License

MIT

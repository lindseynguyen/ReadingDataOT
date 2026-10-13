# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-13

### Added
- **OT command decoding in captures**: IEC 60870-5-104 (control and setpoint commands, reset process, parameters, file transfer), DNP3 (select/operate/direct operate, write, restarts, stop/start application, file and configuration functions), S7comm (write, PLC stop, download, PI services, upload, password functions, SZL/block reconnaissance, S7comm-plus sessions) and EtherNet/IP + CIP (tag writes, Set_Attribute, Reset/Start/Stop, ListIdentity; Unconnected Send unwrapped). Findings name the sender and the target; routine polling is summarised but not flagged.
- **Network device configurations**: Cisco IOS / IOS-XE including Cisco IE and Rockwell Stratix, Fortinet FortiOS including FortiGate Rugged (full parse and hardening checks); RUGGEDCOM, Hirschmann, Moxa, Westermo, Phoenix Contact, SCALANCE and others (identification and heuristic checks).
- **IEC 62443-3-3 and MITRE ATT&CK for ICS mapping** for every built-in finding (`otinspect/standards/mappings.json`), shown in HTML (per finding and as an SR summary), CSV, JSON, SARIF and the GUI. User rules can set `iec62443` / `attack`. Technique IDs follow the current ATT&CK for ICS matrix (for example T1692.001 for unauthorized command messages, T1694.001 for default credentials).
- **SARIF 2.1.0** export (`--sarif`) for GitHub code scanning and **CycloneDX 1.6** export (`--cyclonedx`) with devices, nested firmware, file hashes and advisory matches; both validated against the official schemas.
- `--max-file-mb` and per-parser size limits; files above the limit are still hashed and identified.
- Hypothesis fuzz tests, coverage measurement in CI (threshold 85 %, GUI excluded), and a real-world test suite on public captures and SCL/COMTRADE files pinned by commit and SHA-256 (`tests/realworld/`).
- `CONTRIBUTING.md`, issue templates (including *File misidentified or parsed wrongly*) and a pull request template.
- Synthetic samples: `control_center.pcap`, `stratix_cell2.cfg`, `fgr60f_substation.conf`, `ruggedcom_bay3.csv`.

### Changed
- SCL files are parsed as a stream: a 74 MB SCD now peaks around 50 MB of memory instead of about 400 MB, with identical results. The Communication section may come before or after the IEDs.
- CI lints the whole package and the tests.

## [0.3.1] - 2026-10-13

### Security
- XML parsing now fails closed: every XML parser goes through `otinspect.core.safexml`, which requires defusedxml. If defusedxml is missing, XML files are reported as parse errors and the scan shows a warning, instead of silently falling back to the unprotected standard-library parser.
- Added `SECURITY.md` with a private reporting process.

### Fixed
- `requirements.txt` now matches `pyproject.toml`: PyYAML is listed (without it YAML rule files were skipped) and defusedxml is marked as required.
- README architecture tree: `gui/` and `cli.py` are shown under `otinspect/`, not `packaging/`.

### Removed
- `data-kiosk.py` legacy launcher. Use `otinspect gui` or `python -m otinspect gui`.

### Added
- Tests for the fail-closed XML behaviour and for XXE.
- This changelog.

## [0.3.0] - 2026-10-10

### Added
- SCD diff (`otinspect diff`) with confRev, address-change, removed-publisher and header-version checks
- Network map (SVG) in the HTML report
- User rules in YAML/JSON (site baselines, approved vendors, minimum firmware, forbidden protocols)
- Offline matching against CISA ICS advisories imported from CSAF 2.0
- Parsers for AutomationML/CAEX, Schneider XEF and PLCopen XML
- Supported files inside nested archives parsed in place
- Windows portable executables (GUI and CLI) built and published by CI, with SHA-256 checksums
- Screenshots in the README

## [0.2.0] - 2026-10-10

### Added
- `otinspect` package structure, CLI, HTML/JSON/CSV reports and OT file identification
- IEC 61850 SCL parsing with correct namespace handling
- English UI and reports
- Parsers for COMTRADE, PCAP/PCAPNG, Rockwell L5X/L5K, and GSDML/EDS/ESI/GSD device descriptions
- Cross-reference of hosts seen in captures against configuration files (`XREF-UNDOCUMENTED-HOST`)

[Unreleased]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/lindseynguyen/ReadingDataOT/releases/tag/v0.3.0
[0.2.0]: https://github.com/lindseynguyen/ReadingDataOT/commit/eb42f4a

# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-11-13

### Added
- **YARA engine** (`--yara`, `--yara-rules`): matches every file against built-in OT/ICS triage rules (remote access tools, credential dumping and offensive tooling, Snap7 PLC control libraries, embedded OT protocol stacks, download-and-execute scripts, web shells, ransom notes, EICAR) and any user rule sets. Rule `meta` `severity`, `iec62443` and `attack` are used in findings. Works with yara-python (libyara 4.x) or YARA-X.
- **capa engine** (`--capa`): capabilities of PE / ELF / .NET executables, grouped into triage findings (process injection, credential theft, C2, anti-forensics, bootkit, defense evasion, code loading, persistence, surveillance, exploitation, anti-analysis, drivers). Standalone capa executable or the flare-capa package with pinned rules.
- `otinspect engines` shows availability, versions and whether the rules compile. GUI: *YARA* / *capa* checkboxes and an *Engines…* dialog with *Check engines*.
- JSON reports include per-engine statistics (`engines`). IEC 62443-3-3 SR 3.2, SR 3.9, SR 7.3 and ATT&CK for ICS techniques T0819, T0828, T0851, T0852, T0867, T0869, T1701.001-003 added to the mapping tables.
- `docs/engines.md`. Optional extras `pip install ".[yara]"` and `".[capa]"`. The Windows release bundles yara-python and the built-in rules.
- CI job *Engines* on Linux and Windows: yara-python and YARA-X side by side, the oldest supported versions (yara-python 4.2, capa 7.4), capa 10 as pip package and as standalone executable.

### Reliability
- Engines never stop a scan: a missing engine or rules folder is a warning, a broken rule file is skipped, timeouts / crashes / invalid output become per-file notes.
- capa runs in a separate process with a hard timeout that kills the whole process tree; missing capa rules stop capa after the first file. Results are cached by SHA-256, capa version and rules.
- Tests cover detection and false positives, both YARA backends agreeing, user rule metadata, broken rules, real and simulated timeouts, hung capa with child processes, crashes, invalid JSON, old capa JSON, caching, size limits, Unicode paths, archives and 8-thread determinism.
- Strings of offensive tools in the rules and tests are stored in hex / reversed so antivirus does not quarantine them.

## [0.5.0] - 2026-11-13

### Added
- **Optional AI assistance through an internal model** (`otinspect/ai/`): executive summary, prioritised remediation plan, IEC 62443-3-3 view, likely attack paths, explanation of a finding and free questions. Works with any OpenAI-compatible endpoint: LiteLLM AI gateway, vLLM, Ollama, LM Studio, LocalAI, TGI, and Azure OpenAI. Off until a profile is configured; scanning stays offline.
- GUI: **AI settings** dialog (connection, API key storage, TLS / mTLS / proxy / internal-only policy, privacy limits, *Test connection*), **AI Assistant** tab with payload preview, and *Explain with AI…* on findings.
- CLI: `otinspect ai init | profiles | test | analyze` (`--preview` prints exactly what would be sent).
- `docs/ai.md`: profile reference, security controls and a LiteLLM gateway checklist. Optional extra `pip install ".[ai]"` for OS keyring storage.

### Security
- Data sent to the model is minimised and pseudonymised (IPs, MACs, asset/host names, file names, e-mail addresses), real values are restored locally; passwords, SNMP communities, keys and tokens are removed. The scanned path, file hashes, contents and captures are never sent.
- Endpoint policy: internal addresses only by default, HTTPS with TLS 1.2+ and verification, internal CA and mTLS support, redirects refused, environment proxies ignored unless configured.
- API keys come from the OS keyring, an environment variable or memory; profiles containing a key are rejected; keys are scrubbed from error messages.
- Prompt-injection guard (per-request fenced untrusted data, plain-text rendering) and a metadata-only audit log.

### Fixed
- CI: Python 3.9 is no longer available on `ubuntu-latest` runners. The test matrix now uses Python 3.10 and 3.13 and `requires-python` is `>=3.10` (3.9 reached end of life in October 2025). Actions updated to `checkout@v5` and `setup-python@v6`.

## [0.4.1] - 2026-10-13

### Security
- Release zip and executables carry GitHub build-provenance attestations (Sigstore); verify with `gh attestation verify`.
- Release workflow ready for Authenticode signing through SignPath (enabled once the `SIGNPATH_API_TOKEN` secret is set): signed files are checked for a valid signature and timestamp and smoke-tested again before publishing.
- Release notes include verification steps; new `docs/code-signing-policy.md`.

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

[Unreleased]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/lindseynguyen/ReadingDataOT/releases/tag/v0.3.0
[0.2.0]: https://github.com/lindseynguyen/ReadingDataOT/commit/eb42f4a

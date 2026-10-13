# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/lindseynguyen/ReadingDataOT/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/lindseynguyen/ReadingDataOT/releases/tag/v0.3.0
[0.2.0]: https://github.com/lindseynguyen/ReadingDataOT/commit/eb42f4a

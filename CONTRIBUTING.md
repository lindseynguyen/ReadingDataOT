# Contributing to OTInspect

Thanks for helping. The most useful contributions are often not code: a file that OTInspect misidentifies or parses wrongly tells us more than anything else.

## Reporting a misidentified or wrongly parsed file

Open an issue with the **File misidentified or parsed wrongly** template. It asks for:

- the OTInspect version (`otinspect --version`) and how you ran it
- the file type and the vendor tool and version that produced it (for example *Siemens TIA Portal V18 hardware export* or *RUGGEDCOM ROS 5.6 config.csv*)
- what OTInspect reported and what you expected
- ideally, a **minimal anonymized sample**

### Anonymizing a sample

Never attach files from an operational site as they are. Before sharing:

1. Keep only the part that shows the problem: one IED, one interface, a few packets.
2. Replace names of sites, substations, plants, people and companies with neutral ones (`SUBSTATION_A`, `IED1`).
3. Change IP addresses to a private range (`10.0.0.0/8`) and MAC addresses to a locally administered range (`02:00:00:…`).
4. Remove passwords, keys, SNMP communities, certificates and serial numbers, or replace them with dummies.
5. For captures, cut the capture to the relevant packets, for example with `editcap -r in.pcap out.pcap 10-20`. Tools such as TraceWrangler can rewrite addresses.
6. Run OTInspect on the reduced file and check that it still shows the problem.

If a file cannot be shared at all, the vendor tool, its version and the structure of the file (element names, header lines) still help.

## Security issues

Do not open a public issue for a vulnerability in OTInspect itself. Follow [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/lindseynguyen/ReadingDataOT.git
cd ReadingDataOT
python -m pip install -e ".[dev,gui]"
python -m pyflakes otinspect tests
python -m pytest -q --cov
```

Optional, with network access:

```bash
python tests/realworld/fetch.py
python -m pytest -q tests/test_realworld.py
```

## Adding a file format

1. Create `otinspect/parsers/<name>.py` with a class that has `name`, `can_parse(rec, ident)` and `parse(path, rec)`, decorated with `@register`. Set `max_size` if the parser loads the whole file into memory.
2. If the format cannot be recognised by extension, add detection to `otinspect/core/identify.py` (magic bytes, an XML namespace or a content signature).
3. Add the module to `BUILTIN_PARSERS` in `otinspect/core/registry.py` (the order is the priority) and to `hidden` in `packaging/otinspect.spec`.
4. Parse untrusted XML only through `otinspect.core.safexml` (`safe_parse` or the streaming `safe_iterparse`). Never use `xml.etree` directly.
5. Never execute, import or extract content from the files you read. Mask secrets in findings.
6. Add a synthetic sample to `samples/make_samples.py`, tests in `tests/`, and a fuzz test in `tests/test_fuzz.py` if the parser decodes binary data.

## Adding a finding rule

- Use an ID prefixed by the area (`SCL-`, `PCAP-`, `NET-`, `L5X-` …), a severity (`high`, `medium`, `low`, `info`) and a message that says what was found, where, and what to verify.
- Map it to IEC 62443-3-3 SRs and, where it fits, MITRE ATT&CK for ICS techniques in `otinspect/standards/mappings.json`. `tests/test_protocols_netconfig_exports.py::test_every_builtin_rule_is_mapped` fails if a built-in rule is not mapped.
- Check technique IDs against the current matrix at <https://attack.mitre.org/techniques/ics/>; IDs change between ATT&CK releases.

## Adding a real-world test file

Public files only, from a source whose license allows use for testing. Add an entry to `tests/realworld/manifest.json` with the repository, the **commit**, the path, the SHA-256 and what OTInspect should find. The files are downloaded on demand and are never committed here.

## Pull requests

- One topic per pull request, with tests.
- `pyflakes` clean and coverage at or above the threshold in `pyproject.toml`.
- Update `CHANGELOG.md` under *Unreleased* and the README if behaviour changes.
- Sample data must be fabricated or anonymized. Do not include data from real installations.

By contributing you agree that your contribution is licensed under the MIT License of this project.

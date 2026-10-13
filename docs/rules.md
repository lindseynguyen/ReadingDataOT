# Writing rules

OTInspect evaluates rules after every scan. Built-in rules live in
`otinspect/rules/builtin.json`. Add your own with `--rules FILE_OR_FOLDER` (CLI,
repeatable) or **Rules folder…** (GUI). Files can be YAML (`.yaml`/`.yml`,
needs PyYAML) or JSON with the same structure.

```yaml
rules:
  - id: SITE-SIPROTEC-OLD-FW          # unique, shown in reports
    severity: medium                  # high | medium | low | info
    target: asset                     # asset (each device) | file (each scanned file)
    message: "{name} ({model}) runs firmware {version}; site baseline is 9.0"
    url: https://intranet.example/baseline   # optional, appended to the message
    iec62443: [SR 3.4, SR 7.8]        # optional IEC 62443-3-3 SRs shown in reports / SARIF
    attack: [T0866]                   # optional MITRE ATT&CK for ICS techniques
    match:                            # ALL conditions must hold
      vendor:  {regex: "(?i)siemens"}
      model:   {regex: "^7(UT|SA|SJ)8"}
      version: {lt: "9.0"}
      ip:      {in_cidr: ["10.10.0.0/16"]}
```

## Fields

| Target | Fields |
|---|---|
| `asset` | `name`, `kind`, `vendor`, `model`, `version`, `ip`, `mac`, `subnet`, `protocols`, `source`, `extra.<key>` (e.g. `extra.gateway`, `extra.subnetwork`, `extra.serves`) |
| `file` | `path`, `size`, `sha256`, `category`, `file_type`, `parser`, `error`, `summary.<key>` (e.g. `summary.entropy`, `summary.goose_count`, `summary.protocols`) |

The message may reference any plain field of the target with `{field}`.

## Standards mapping

Every built-in finding carries the IEC 62443-3-3 system requirements it gives
evidence against and the MITRE ATT&CK for ICS techniques it relates to (see
`otinspect/standards/mappings.json`). Your own rules can set `iec62443` and
`attack` lists; they appear in the HTML report (with an SR summary table), CSV,
JSON and SARIF exactly like the built-in ones. The mapping supports the
assessor; it is not a compliance verdict.

## Operators

| Operator | Meaning |
|---|---|
| `eq`, `ne` | exact text (a bare value means `eq`) |
| `regex`, `not_regex` | Python regular expression (`(?i)` for case-insensitive) |
| `contains` | substring, case-insensitive; on lists (e.g. `protocols`) checks any element |
| `in`, `not_in` | value is / is not in a list |
| `exists` | `true` = non-empty, `false` = empty or missing |
| `lt`, `le`, `gt`, `ge` | **version** comparison: `V08.40` < `8.50` < `8.50.1`, `R125` → 125 |
| `num_lt`, `num_le`, `num_gt`, `num_ge` | plain numeric comparison (e.g. entropy 7.45 < 7.5) |
| `in_cidr` | IP inside one of the networks |

## Examples

```yaml
rules:
  - id: SITE-NO-TELNET
    severity: high
    target: asset
    message: "{ip} exposes Telnet"
    match:
      protocols: {contains: telnet}

  - id: SITE-GOOSE-WITHOUT-VLAN-POLICY
    severity: medium
    target: file
    message: "{path}: {summary.goose_count} GOOSE control blocks; confirm VLAN plan"
    match:
      category: SCL
      summary.goose_count: {num_gt: 0}

  - id: SITE-UNAPPROVED-VENDOR
    severity: low
    target: asset
    message: "{name}: vendor '{vendor}' is not on the approved list"
    match:
      kind: IED
      vendor: {not_in: [SIEMENS, SEL, ABB, GE]}
```

## Advisory database

Vendor vulnerability matching uses CSAF 2.0 advisories rather than hand-written
rules. On a connected machine:

```bash
git clone --depth 1 https://github.com/cisagov/CSAF
otinspect advisories import CSAF/csaf_files/OT/white -o advisories.json
```

Copy `advisories.json` to the offline workstation and use
`--advisories advisories.json`, set `OTINSPECT_ADVISORIES`, or pick it with
**Advisory DB…** in the GUI. Matches are reported as *possible* and must be
verified against the advisory (hardware variants such as CP200/CP300 are not
distinguished from file content).

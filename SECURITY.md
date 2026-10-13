# Security Policy

OTInspect reads files that may come from untrusted sources (contractor handover packages, backups, captures from unknown networks). Bugs in how it handles hostile input are treated as security issues.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x (latest release) | Yes |
| Older | No, please upgrade |

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:

1. Go to the [Security tab](https://github.com/lindseynguyen/ReadingDataOT/security) of this repository.
2. Click **Report a vulnerability**.
3. Include the OTInspect version, your OS, and the steps or a minimal input file that reproduces the problem.

Do not attach real files from an operational site. Reduce them to a minimal synthetic sample, or strip names, IP addresses and other identifying data first.

You should get a first response within 7 days. Once a fix is released, the advisory will be published and you will be credited unless you ask not to be.

## In scope

- Code execution, or reading or writing files outside the scanned path, triggered by a crafted input file
- XML attacks (XXE, external entities, entity expansion) that bypass the defusedxml protection
- Archive attacks (zip slip, zip bombs, deeply nested archives) that bypass the existing guards
- A crafted file that crashes, hangs, or exhausts memory during a scan
- Script or HTML injection into the generated HTML report through file contents or names
- Secrets (passwords, keys, SNMP communities) appearing unmasked in reports
- Tampered or unverifiable release executables

## Out of scope

- Findings about the OT devices or configurations that OTInspect reports on. Those belong to the device vendor or the asset owner.
- Windows SmartScreen warnings about the unsigned executables (see the README for checksum verification)
- Issues that require an attacker who can already modify OTInspect's own code or Python environment

## Safe use

- OTInspect only reads files and never connects to devices, but scan untrusted packages on an isolated analysis machine, not on an engineering workstation.
- Treat generated reports as confidential: they contain IP addresses, MAC addresses and system topology.

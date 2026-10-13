# Code signing policy

This page describes how the Windows executables of OTInspect are built, signed and verified.

## What is published

Each release on the [Releases](https://github.com/lindseynguyen/ReadingDataOT/releases) page contains
`OTInspect-<version>-windows-x64.zip` (with `OTInspect.exe` and `otinspect-cli.exe`) and `SHA256SUMS.txt`.

The executables are built only by the [release workflow](../.github/workflows/release.yml) on GitHub-hosted
runners, from the tagged source in this repository. Nothing is built or signed on a personal computer.

## Build provenance (all releases from 0.4.1)

Every release zip and both executables carry a [GitHub artifact attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
(SLSA build provenance, signed with Sigstore). It proves which repository, workflow, commit and tag produced the file.

```bash
gh attestation verify OTInspect-<version>-windows-x64.zip --repo lindseynguyen/ReadingDataOT
gh attestation verify OTInspect.exe --repo lindseynguyen/ReadingDataOT
```

## Authenticode signing

Status: **application to the [SignPath Foundation](https://signpath.org) open-source program in progress.**
Until it is approved, executables are not Authenticode-signed, Windows SmartScreen may warn on first run, and
the attestation and checksum above are the way to verify a download.

Once approved, the release workflow submits the executables built from the tagged source to SignPath, a
maintainer approves the signing request manually, and the signed files are checked
(`Get-AuthenticodeSignature`: valid signature and timestamp) and smoke-tested before they are published.
The certificate is then issued to *SignPath Foundation*, which appears as the publisher.

Signing does not remove SmartScreen warnings immediately: Microsoft builds reputation for a publisher and
file over time, and since 2024 this applies to EV certificates as well.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [lindseynguyen](https://github.com/lindseynguyen) |
| Approvers (approve each signing request) | [lindseynguyen](https://github.com/lindseynguyen) |

All members use multi-factor authentication for GitHub and SignPath.

## Privacy policy

OTInspect does not transfer any information to other networked systems. It only reads the files and folders
you point it at, and writes reports where you choose. It never connects to devices. The only network access
is the optional `tests/realworld/fetch.py` developer script, which downloads public sample files from GitHub.

## Reporting a problem

If you find a signed OTInspect binary that was not built from this repository, or a signature you believe is
misused, report it privately as described in [SECURITY.md](../SECURITY.md).

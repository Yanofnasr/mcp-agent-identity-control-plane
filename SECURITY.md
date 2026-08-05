# Security Policy

## Scope

This repository is a **reference implementation**. It demonstrates how to preserve the identity and
authority chain of an autonomous agent across MCP tool calls. It is not a hosted service and it is
not a drop-in authorization component.

The reference Rego policy evaluates a trusted envelope that a policy enforcement point assembles
before evaluation. It deliberately does **not** verify cryptographic token proofs, mTLS or DPoP
sender binding, attestation evidence, or delegation artifacts, and it does not implement atomic
approval consumption. Those boundaries are stated in [README.md](README.md) under "Two-stage
enforcement" and "Production hardening".

A report that restates a documented boundary is not a vulnerability. A report showing that the
documentation claims a guarantee the code does not deliver **is** a vulnerability, and is one of the
most valuable findings for this project.

## Supported versions

| Version | Supported |
|---|---|
| 1.3.x   | Yes       |
| < 1.3   | No        |

Only the latest minor release receives fixes. Older releases are historical artifacts of the
published series and are not patched.

## Reporting a vulnerability

Report privately through GitHub: open the **Security** tab and choose **Report a vulnerability**.
This routes to a private advisory that only maintainers can read.

Please do not open a public issue for a suspected vulnerability.

Do not include real credentials, tokens, customer data, or personal data in a report. Every
identity, domain, and record in this repository is synthetic, and reproductions should stay
synthetic. Use the reserved `example.internal` domain and placeholder principal identifiers.

### What to include

- The commit or release tag you evaluated.
- The gate or control you believe is bypassed, by file and rule name.
- A minimal reproduction: for policy findings, the `input` document and trusted data that produce
  the wrong decision.
- The decision you observed and the decision you expected.

### What to expect

- Acknowledgement within 5 business days.
- An assessment, including a rejection with reasoning if the report is out of scope, within 15
  business days.
- Credit in the advisory and changelog unless you ask otherwise.

This project is maintained on a best-effort basis by a single maintainer. There is no service level
agreement and no bug bounty.

## In scope

- A policy path that allows a tool call the documented controls say it must deny.
- A gap between what the README or VALIDATION document claims a gate enforces and what the gate
  actually enforces.
- A canonicalization ambiguity that lets two materially different actions produce the same action
  hash, or that lets a caller influence a field the trust boundary reserves for the enforcement
  point.
- An approval binding that can be replayed, transplanted to another action, agent build, execution
  contract, or policy bundle.
- A packaging or manifest flaw that admits an unreviewed file into the release archive, or that
  breaks archive reproducibility.
- A supply chain weakness in the pinned CI inputs, including an unpinned action, an unverified
  download, or an over-privileged workflow token.

## Out of scope

- The non-goals stated above and in the README, including absent cryptographic verification and
  non-atomic approval consumption.
- The synthetic example identities, domains, timestamps, and repository names.
- Vulnerabilities in OPA, CPython, or GitHub Actions themselves. Report those upstream; if a pinned
  version here is affected, a report asking for the pin to move is welcome.
- Hardening the README explicitly assigns to a production deployment rather than to this reference.

## Security properties this repository maintains

These are verified mechanically on every run, so a regression fails the build rather than shipping:

- Every GitHub Action is pinned to an immutable commit SHA, and the workflow token is limited to
  `contents: read` except in the release job, which elevates only for attestation and publishing.
- The OPA binary is verified against a pinned SHA-256 digest before it executes.
- Every Python dependency is exact-pinned and hash-locked to reviewed binary wheels.
- The release archive is byte-reproducible and is built only from an explicit file allowlist.
- Released archives carry a Sigstore-backed build provenance attestation.
- No secrets are used by the validation workflow.
- A privacy gate rejects any email address, and any file outside the allowlist, in packaged sources.

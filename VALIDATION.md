# Validation status

Release **1.3.0** is dated **2026-08-05**. This validation record was last executed on **2026-08-09**.

## Executed locally

The following gates are executed by `make validate-structure`:

- JSON Schema Draft 2020-12 validation with format checking
- JSON and YAML authorization-example equivalence
- Restricted canonical JSON self-tests, argument-digest reproduction, and action-hash reproduction
- Policy-bundle digest reproduction
- Approval-to-action, identity, environment, and policy-bundle binding checks
- Execution-to-authority-subject and execution-to-agent-actor link checks
- Exact target-to-audience validation
- Issuer, sender constraint, credential lifetime, entitlement, and production-write checks
- Allow and deny audit-event lifecycle consistency, approval-consumption evidence, and record-digest reproduction
- Negative schema checks for caller-supplied time, entitlements, approval state, multiple audiences, and missing identity bindings
- Source package allowlist, README repository-tree completeness, prohibited-file, and direct-email checks
- CI pinning, release-metadata consistency, UTC archive normalization, and release-command checks
- Security-policy completeness, Dependabot ecosystem scoping, and release-workflow privilege, attestation, and tag-to-version checks

The Python dependency graph is exact-pinned, hash-locked, and restricted to reviewed binary wheels for CPython 3.11 and 3.12 on Linux x86-64.

The official OPA **v1.18.2** Linux AMD64 static binary was downloaded outside the repository and verified against its published SHA-256 digest. The following runtime gate passed locally:

```text
opa fmt --fail --check-result -l policy/*.rego
opa check --strict policy
opa test policy data --fail-on-empty -v
python3 scripts/evaluate_example.py
```

Result: **36/36 Rego tests passed**, strict compilation passed, and the live allow-path decision matched the checked-in 1.3 contract.

Two release archives invoked under distinct caller time zones were compared byte-for-byte. The staged tree and extracted ZIP were each checked with `sha256sum --check --strict MANIFEST.sha256` and the explicit package allowlist. The final archive hash is recorded in the release handoff.

## Continuous integration

The included GitHub Actions workflow repeats the structural and runtime gates with Python 3.12, the same hash-locked dependency graph, immutable action SHAs, and the pinned OPA checksum. Publication should still be gated on a passing workflow run after push.

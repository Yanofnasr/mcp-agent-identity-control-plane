# Validation status

Generated for release **1.1.0** on **2026-07-28**.

## Executed locally

The following gates are executed by `make validate-structure`:

- JSON Schema Draft 2020-12 validation with format checking
- JSON and YAML authorization-example equivalence
- Canonical argument digest and action-hash reproduction
- Policy-bundle digest reproduction
- Approval-to-action, identity, environment, and policy-bundle binding checks
- Execution-to-authority-subject and execution-to-agent-actor link checks
- Exact target-to-audience validation
- Issuer, sender constraint, credential lifetime, entitlement, and production-write checks
- Audit-event consistency and record-digest reproduction
- Negative schema checks for caller-supplied time, entitlements, approval state, multiple audiences, and missing identity bindings
- Package allowlist, prohibited-file, direct-email and unresolved-placeholder checks
- CI pinning and release-command checks

The final build also runs `sha256sum -c MANIFEST.sha256` and verifies the extracted ZIP against the source manifest.

## CI-only runtime gate

The isolated build environment does not include an executable OPA binary, so this pack does not claim a local OPA parse, compile, test, or evaluation result.

The included GitHub Actions workflow performs the remaining release gate with pinned OPA **v1.18.2**:

```text
opa fmt --fail --check-result -l policy/*.rego
opa check --strict policy
opa test policy data --fail-on-empty -v
python3 scripts/evaluate_example.py
```

The workflow verifies the official Linux AMD64 static-binary SHA-256 digest before execution. Publication should be gated on a passing workflow run.

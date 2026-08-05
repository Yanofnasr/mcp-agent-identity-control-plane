# Changelog

## 1.3.0 - 2026-08-05

- Added schema-valid blocked/denied audit events without requiring fabricated verified credential evidence.
- Made approval evidence status-sensitive and recorded single-use consumption receipts for successful executions; atomic consumption remains the responsibility of the authoritative service.
- Replaced duplicated permissive JSON serialization with the shared `restricted-json-sort-keys-v1` profile, which rejects duplicate keys, floats, non-finite numbers, unsafe integers, and lone Unicode surrogates.
- Removed the under-specified `prompt_context_hash` field until a canonical source contract exists.
- Added deny-decision coverage for unmapped audiences and expanded the structural regression matrix.
- Enforced lowercase hexadecimal SHA-256 syntax for policy, agent, action, and execution fields at the final Rego gate.
- Normalized deterministic ZIP timestamps to the release date in UTC and added a structural guard against release-metadata drift.
- Added a coordinated disclosure policy, Dependabot coverage for pinned action SHAs, and a least-privilege release workflow that attests build provenance and refuses to publish a tag that disagrees with VERSION.
- Separated the version-dependent diagram comparison from deterministic derived-value packaging, so a missing Graphviz fails closed locally without making releases depend on the renderer version.
- Established a fixed, accessible four-principal visual notation across the reference diagrams and documentation.
- Bound the README repository tree exactly to the package allowlist and rejected missing or non-string credential profiles during derived-value synchronization.
- Enumerated root-level tool and runtime files outside the release boundary while retaining fail-closed handling for unrecognized source files and every unexpected archive entry.

## 1.2.0 - 2026-08-04

- Added trusted agent credential type, issuer, and attestation profile checks to the verified identity envelope.
- Added `authority_chain_verified` to the execution chain and kept the final authority record separate from the caller request.
- Bound approvals to the concrete agent build, runtime, and execution contract, with explicit single-use and consume state. Production must consume that state atomically.
- Aligned the policy decision and audit event with the 1.2 contract, including reason codes and the canonical-json-sort-keys-v2 full-event digest profile.
- Rejected ambiguous action serialization and overlapping target-audience mappings.
- Hardened packaging with an explicit source allowlist, staged-tree verification, and extracted-archive verification against the manifest.
- Hash-locked the complete Python validation dependency graph and retained the checksum-pinned OPA runtime.
- Updated the runtime OPA gate and 31-test suite to cover the 1.2 trust, approval, canonicalization, and entitlement checks.

## 1.1.0 - 2026-07-28

- Separated caller-controlled request data from PEP-verified identity and action context.
- Moved tool catalogs, entitlements, issuer rules, target-audience mappings, production permissions, and approval records into trusted policy data.
- Replaced caller-supplied time with OPA `time.now_ns()`.
- Added execution credential expiry and maximum-lifetime enforcement.
- Added exact target-to-audience binding and rejected multi-audience credentials in the reference profile.
- Added verified links from the execution context to the authority subject and agent actor.
- Added action-hash recomputation in policy.
- Bound approvals to the action, requester, authority subject, agent principal, environment, and policy bundle.
- Added independent-approver separation and credential-profile validation.
- Added negative Rego tests and reproducible structural validation.
- Hardened the OPA formatting gate with the documented `opa fmt --fail --check-result -l` invocation.
- Pinned GitHub Actions and the OPA binary to immutable versions and verified checksums.
- Added synchronized JSON and YAML examples, diagrams, package manifest, and validation report.

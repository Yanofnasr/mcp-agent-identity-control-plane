# Changelog

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
- Added synchronized JSON and YAML examples, diagrams, package manifest, validation report, and publication metadata.

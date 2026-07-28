# MCP Agent Identity Control Plane

A reference implementation for preserving the identity and authority chain of an AI agent across MCP tool calls.

This vendor-neutral reference implementation models four principals:

| Principal | Governing question |
|---|---|
| Requesting principal | Who initiated the task? |
| Authority subject | Whose authority or data is being exercised? |
| Agent principal | Which autonomous workload selected and executed the action? |
| Execution principal | Which identity did the target authorize? |

The package demonstrates action-level policy enforcement, target-bound token audiences, short-lived execution credentials, verified delegation links, approval bound to the final action, and a PII-minimized audit event.

## Security boundary

The most important design decision is not the schema. It is who is allowed to populate each field.

| Data class | Source | Trust treatment |
|---|---|---|
| Raw action proposal | Agent or MCP client | Untrusted |
| `input.request` | Caller | Untrusted references and correlation IDs only |
| `input.verified` | Policy enforcement point | Constructed after identity, delegation, token, target, argument, and environment verification |
| `data.agent_control` | Signed policy bundle or controlled policy store | Trusted tool catalog, entitlements, issuers, audience mappings, and credential profiles |
| `data.approval_records` | Approval service or verified signed record | Trusted approval state and bindings |
| Evaluation time | OPA `time.now_ns()` or trusted PEP clock | Never supplied by the caller |

The agent must not assert its own verified identity, delegation state, approval status, production entitlement, accepted audience, trusted issuer, or evaluation time.

## Two-stage enforcement

A production flow should use two related decisions:

1. **Pre-issuance decision:** determine whether a credential may be requested and return the required authority mode, audience, credential profile, maximum lifetime, and approval contract.
2. **Final enforcement decision:** validate the actual issued credential, confirm the exact target audience, recheck the approval and unchanged action, then allow or deny the MCP tool call.

The Rego entry point in this repository implements the **final enforcement decision**. The returned credential profile and lifetime describe the policy contract and support audit comparison.

## Repository layout

```text
.
├── architecture/
│   ├── agent-identity-control-plane.dot
│   ├── agent-identity-control-plane.png
│   ├── agent-identity-control-plane.svg
│   ├── four-principal-control-plane.dot
│   ├── four-principal-control-plane.png
│   └── four-principal-control-plane.svg
├── data/
│   ├── agent-control.json
│   ├── approval-records.example.json
│   └── test-fixtures.json
├── examples/
│   ├── action-arguments.example.json
│   ├── agent-action-event.example.json
│   ├── authorization-context.example.json
│   └── authorization-context.example.yaml
├── policy/
│   ├── mcp-tool-authorization.rego
│   └── mcp-tool-authorization_test.rego
├── schema/
│   ├── agent-action-audit-event.schema.json
│   └── authorization-context.schema.json
├── scripts/
│   ├── evaluate_example.py
│   ├── hash_action.py
│   ├── package.sh
│   ├── update_derived_values.py
│   ├── validate.sh
│   └── validate_artifacts.py
├── .github/workflows/validate.yml
├── CHANGELOG.md
├── LICENSE
├── Makefile
├── README.md
├── VALIDATION.md
└── VERSION
```

## What the policy enforces

The reference Rego policy denies a tool call unless all applicable controls pass:

- The PEP-produced identity envelope has the expected shape.
- The requester, authority subject, agent, and execution principal are explicit.
- The execution context links the authority subject and agent actor to the verified identity chain.
- The agent has a trusted workload identity and an entitlement for the environment.
- The method, tool, and normalized target are allowed by trusted policy data.
- Production write permission comes from trusted policy data, not request input.
- The action hash is recomputed from the canonical action profile.
- The execution credential issuer is trusted.
- The execution audience is uniquely bound to the normalized target.
- The credential is sender-constrained using an allowed mechanism.
- The credential is active, unexpired, and within the tool-specific maximum lifetime.
- A configured credential profile exists for the authority mode.
- Required approval is present, unexpired, independently approved where configured, and bound to the action, identities, environment, and policy bundle.

## Action hash profile

The example canonicalizes tool arguments as compact JSON with lexicographically sorted object keys, then computes:

```text
arguments_digest = "sha256:" + SHA256(canonical_json(arguments))
```

The action is serialized exactly as:

```text
agent-action-v1
mcp_server=<value>
method=<value>
tool=<value>
target=<normalized-value>
arguments_digest=<sha256-value>
data_classification=<value>
```

The canonical action hash is:

```text
canonical_hash = "sha256:" + SHA256(UTF8(canonical_action_string))
```

The trusted approval record binds this action hash to the requester, authority subject, agent principal, environment, and policy bundle digest. This prevents approval for one operation from authorizing a materially different operation.

Reproduce the checked-in values:

```bash
make hash-action
```

Equivalent direct command:

```bash
python3 scripts/hash_action.py \
  --arguments examples/action-arguments.example.json \
  --context examples/authorization-context.example.json
```

## Validation

### Structural and semantic mirror gate

Requires Python 3.11 or later:

```bash
python3 -m pip install -r requirements-dev.txt
make validate-structure
```

This validates both JSON Schemas, JSON and YAML equivalence, all derived digests, approval bindings, delegation links, audience-to-target binding, trusted policy-data consistency, negative schema cases, and package privacy.

### Full Rego gate

Requires OPA 1.x:

```bash
make validate
```

The full gate runs:

```text
opa fmt --fail --check-result -l policy/*.rego
opa check --strict policy
opa test policy data --fail-on-empty -v
python3 scripts/evaluate_example.py
```

`evaluate_example.py` refreshes the execution and approval timestamps in temporary files before evaluating the allow path, so the checked-in historical example does not depend on the current wall clock.

The CI workflow pins OPA **v1.18.2** and verifies the Linux AMD64 static binary against its published SHA-256 digest before execution. GitHub Actions are pinned to immutable commit SHAs.

## Expected allow decision

```json
{
  "allow": true,
  "requires_approval": true,
  "deny_reasons": [],
  "risk_tier": "critical",
  "credential_profile": "source-control-user-delegated-critical",
  "credential_ttl_seconds": 900,
  "expected_audiences": [
    "https://source-control.example.internal"
  ],
  "policy_id": "urn:example:policy:mcp-agent-tool-authorization",
  "policy_version": "1.1.0"
}
```

## Negative policy tests

The Rego suite explicitly verifies denial for:

- Wrong or multiple token audiences
- Missing sender binding
- Expired execution credential
- Expired or unknown approval
- Missing correlation context
- Authority-mode mismatch
- Mismatched delegated subject or agent actor
- Action-hash mismatch
- Unauthorized target
- Untrusted issuer
- Self-approval where independent approval is required
- Approval bound to a different policy bundle
- Missing credential profile
- Production write access removed from trusted policy data

## Regenerating derived values

After modifying the policy, trusted configuration, action, or example arguments:

```bash
make sync
make validate-structure
```

The synchronization script updates the JSON and YAML authorization examples, test fixture, approval bindings, policy bundle digest, and audit record digest.

## Diagrams

Regenerate the SVG and PNG assets from the editable Graphviz sources:

```bash
make diagrams
```

The four-principal diagram is the compact overview. The wider agent-identity diagram supports detailed architecture review.

## Packaging

Create a clean archive outside the source tree:

```bash
make package
```

The packaging script synchronizes derived values, regenerates diagrams, runs the structural gate, creates `MANIFEST.sha256`, verifies the manifest, normalizes archive timestamps, and writes a deterministic-content ZIP in the parent directory.

## Production hardening

This package is a reference, not a drop-in authorization service. A production implementation should additionally:

- Cryptographically validate workload, user, and execution credentials before constructing `input.verified`.
- Verify delegation claims or equivalent broker evidence before marking `delegation_verified` true.
- Normalize targets and arguments before hashing and reject ambiguous representations.
- Load policy and trusted data from signed bundles or an equivalently controlled distribution channel.
- Retrieve approval records from an authoritative service or verify signed approval assertions.
- Protect against approval replay using single-use state or execution counters where the action is non-idempotent.
- Make the decision and tool invocation transactional enough that a decision cannot be reused for altered arguments.
- Sign or append audit events to tamper-evident storage.
- Define fail-closed behavior for policy, identity, approval, credential broker, and audit-service failures.
- Map target audiences to the actual resource identifiers used by the authorization server and target platform.
- Perform privacy, retention, and access-control review before recording prompt or tool evidence.

## Privacy

All example identities, domains, timestamps, repositories, and records are synthetic. The package contains no personal identifiers, private email addresses, customer data, credentials, prompts, or internal company details.

## Validation status

See [VALIDATION.md](VALIDATION.md) for the exact gates executed in the build environment and the remaining CI-only OPA runtime gate.

## License

MIT. See [LICENSE](LICENSE).

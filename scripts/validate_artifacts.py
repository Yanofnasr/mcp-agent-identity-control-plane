#!/usr/bin/env python3
"""Validate the reference package without requiring an OPA executable."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    ".github/workflows/validate.yml",
    "CHANGELOG.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "VALIDATION.md",
    "VERSION",
    "architecture/agent-identity-control-plane.dot",
    "architecture/agent-identity-control-plane.png",
    "architecture/agent-identity-control-plane.svg",
    "architecture/four-principal-control-plane.dot",
    "architecture/four-principal-control-plane.png",
    "architecture/four-principal-control-plane.svg",
    "data/agent-control.json",
    "data/approval-records.example.json",
    "data/test-fixtures.json",
    "examples/action-arguments.example.json",
    "examples/agent-action-event.example.json",
    "examples/authorization-context.example.json",
    "examples/authorization-context.example.yaml",
    "policy/mcp-tool-authorization.rego",
    "policy/mcp-tool-authorization_test.rego",
    "requirements-dev.txt",
    "schema/agent-action-audit-event.schema.json",
    "schema/authorization-context.schema.json",
    "scripts/evaluate_example.py",
    "scripts/hash_action.py",
    "scripts/package.sh",
    "scripts/update_derived_values.py",
    "scripts/validate.sh",
    "scripts/validate_artifacts.py",
}

PROHIBITED_SUFFIXES = {
    ".ics", ".pst", ".ost", ".mbox", ".eml", ".pem", ".key", ".p12", ".pfx", ".zip"
}

EXPECTED_POLICY_TESTS = {
    "test_valid_production_merge",
    "test_wrong_audience_is_denied",
    "test_multiple_audiences_are_denied",
    "test_missing_sender_binding_is_denied",
    "test_expired_approval_is_denied",
    "test_expired_execution_credential_is_denied",
    "test_missing_correlation_context_is_denied",
    "test_unknown_approval_reference_is_denied",
    "test_authority_chain_mismatch_is_denied",
    "test_delegated_subject_mismatch_is_denied",
    "test_agent_actor_mismatch_is_denied",
    "test_action_hash_mismatch_is_denied",
    "test_unauthorized_target_is_denied",
    "test_untrusted_issuer_is_denied",
    "test_independent_approval_cannot_be_self_approved",
    "test_approval_policy_bundle_mismatch_is_denied",
    "test_missing_credential_profile_is_denied",
    "test_production_write_entitlement_cannot_be_self_asserted",
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def action_canonical_string(action: dict[str, Any]) -> str:
    fields = (
        ("mcp_server", action["mcp_server"]),
        ("method", action["method"]),
        ("tool", action["tool"]),
        ("target", action["target"]),
        ("arguments_digest", action["arguments_digest"]),
        ("data_classification", action["data_classification"]),
    )
    return "\n".join(["agent-action-v1", *[f"{key}={value}" for key, value in fields]])


def load_json(relative: str) -> Any:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def parse_rfc3339(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def target_matches(pattern: str, target: str) -> bool:
    if pattern == target:
        return True
    return pattern.endswith("*") and target.startswith(pattern[:-1])


def validate_schema(schema_path: str, instance_path: str) -> None:
    schema = load_json(schema_path)
    instance = load_json(instance_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        detail = "\n".join(f"  {list(error.path)}: {error.message}" for error in errors)
        raise AssertionError(f"{instance_path} failed {schema_path}:\n{detail}")


def assert_schema_rejects(schema_path: str, instance: Any, label: str) -> None:
    schema = load_json(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    if not list(validator.iter_errors(instance)):
        raise AssertionError(f"Schema should reject negative fixture: {label}")


def assert_required_files() -> None:
    actual = {
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file() and path.name != "MANIFEST.sha256"
    }
    missing = sorted(REQUIRED_FILES - actual)
    if missing:
        raise AssertionError(f"Required package files are missing: {missing}")

    for relative in actual:
        path = Path(relative)
        lowered = relative.lower()
        if path.suffix.lower() in PROHIBITED_SUFFIXES:
            raise AssertionError(f"Prohibited file type in source package: {relative}")
        if any(term in lowered for term in ("calendar", "bricsys", "customer-export")):
            raise AssertionError(f"Potential accidental or organization-specific file in package: {relative}")
        if "__pycache__" in path.parts or path.name == ".DS_Store":
            raise AssertionError(f"Generated local file found in package: {relative}")


def validate_readme_paths() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    referenced = set(re.findall(r"(?:--input|--arguments|--context)\s+([A-Za-z0-9_./-]+)", readme))
    referenced.update(
        re.findall(r"`((?:architecture|data|examples|policy|schema|scripts)/[^`\s]+)`", readme)
    )
    for relative in sorted(referenced):
        if "*" in relative:
            continue
        if not (ROOT / relative).exists():
            raise AssertionError(f"README references a missing path: {relative}")


def validate_workflow() -> None:
    workflow = (ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8")
    required = (
        "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405",
        'OPA_VERSION: "1.18.2"',
        'OPA_LINUX_AMD64_STATIC_SHA256: "9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8"',
        "sha256sum --check --strict",
        "make validate",
        "persist-credentials: false",
    )
    for fragment in required:
        if fragment not in workflow:
            raise AssertionError(f"CI hardening fragment is absent: {fragment}")
    if re.search(r"uses:\s+[^\s]+@v\d+\b", workflow):
        raise AssertionError("GitHub Actions must be pinned to immutable commit SHAs")


def validate_policy_source() -> None:
    rego = (ROOT / "policy/mcp-tool-authorization.rego").read_text(encoding="utf-8")
    required = (
        "time.now_ns()",
        "data.approval_records",
        "expected_audiences_for_target",
        "execution.audiences[0] in expected_audiences_for_target",
        "crypto.sha256(canonical_action_string)",
        "approval_record.policy_bundle_digest == context.policy_bundle_digest",
        "selected_credential_profile",
        "authority_chain_valid",
        "execution.authority_subject_principal_id == authority_subject.principal_id",
        "execution.agent_actor_principal_id == agent.agent_principal",
        "request_context_valid",
        "sender_binding_present",
    )
    for fragment in required:
        if fragment not in rego:
            raise AssertionError(f"Required Rego control is absent: {fragment}")

    forbidden = (
        "input.context.now",
        "input.authorization",
        "input.approval.status",
        "input.request.now",
        'object.get(input, "now"',
    )
    for fragment in forbidden:
        if fragment in rego:
            raise AssertionError(f"Forbidden caller-controlled Rego path is present: {fragment}")

    tests = (ROOT / "policy/mcp-tool-authorization_test.rego").read_text(encoding="utf-8")
    discovered = set(re.findall(r"^(test_[A-Za-z0-9_]+)\s+if\s*\{", tests, flags=re.MULTILINE))
    missing = sorted(EXPECTED_POLICY_TESTS - discovered)
    if missing:
        raise AssertionError(f"Required policy tests are missing: {missing}")
    if "object.union(base_input, patch)" in tests:
        raise AssertionError("Policy tests use a shallow top-level patch that can erase verified context")

    shell_gate = (ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
    for fragment in ("opa fmt --fail --check-result -l", "opa check --strict", "opa test policy data --fail-on-empty"):
        if fragment not in shell_gate:
            raise AssertionError(f"OPA release gate is incomplete: {fragment}")


def validate_privacy() -> None:

    pii_email = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
    text_suffixes = {".md", ".json", ".yaml", ".yml", ".rego", ".dot", ".py", ".sh"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in text_suffixes:
            continue
        text = path.read_text(encoding="utf-8")
        if pii_email.search(text):
            raise AssertionError(f"Potential direct email address found in {path.relative_to(ROOT)}")


def validate_examples_and_policy_data() -> tuple[str, str, str, str, str]:
    validate_schema("schema/authorization-context.schema.json", "examples/authorization-context.example.json")
    validate_schema("schema/agent-action-audit-event.schema.json", "examples/agent-action-event.example.json")

    authz = load_json("examples/authorization-context.example.json")
    authz_yaml = yaml.safe_load((ROOT / "examples/authorization-context.example.yaml").read_text(encoding="utf-8"))
    if authz != authz_yaml:
        raise AssertionError("The JSON and YAML authorization examples diverge")

    arguments = load_json("examples/action-arguments.example.json")
    action = authz["verified"]["action"]
    expected_arguments_digest = sha256_prefixed(canonical_json(arguments))
    if action["arguments_digest"] != expected_arguments_digest:
        raise AssertionError("arguments_digest does not match canonical example arguments")

    expected_action_hash = sha256_prefixed(action_canonical_string(action).encode("utf-8"))
    if action["canonical_hash"] != expected_action_hash:
        raise AssertionError("canonical_hash does not match the documented action profile")

    agent_control = load_json("data/agent-control.json")["agent_control"]
    policy_bytes = (ROOT / "policy/mcp-tool-authorization.rego").read_bytes()
    expected_policy_digest = sha256_prefixed(
        b"mcp-agent-policy-bundle-v1\n" + policy_bytes + b"\n" + canonical_json(agent_control)
    )
    context_policy_digest = authz["verified"]["context"]["policy_bundle_digest"]
    if context_policy_digest != expected_policy_digest:
        raise AssertionError("policy_bundle_digest does not match policy plus trusted configuration")

    verified = authz["verified"]
    execution = verified["execution"]
    if execution["authority_subject_principal_id"] != verified["authority_subject"]["principal_id"]:
        raise AssertionError("Execution credential context is not linked to the authority subject")
    if execution["agent_actor_principal_id"] != verified["agent"]["agent_principal"]:
        raise AssertionError("Execution credential context is not linked to the agent actor")
    if execution["delegation_verified"] is not True:
        raise AssertionError("Delegation verification flag is not true")

    approval_id = authz["request"]["approval_id"]
    approvals = load_json("data/approval-records.example.json")["approval_records"]
    approval = approvals[approval_id]
    if approval["action_hash"] != expected_action_hash:
        raise AssertionError("Trusted approval is not bound to the canonical action hash")
    if approval["policy_bundle_digest"] != expected_policy_digest:
        raise AssertionError("Trusted approval is not bound to the evaluated policy bundle")

    for approval_field, verified_value in (
        ("requester_principal_id", verified["requester"]["principal_id"]),
        ("authority_subject_principal_id", verified["authority_subject"]["principal_id"]),
        ("agent_principal", verified["agent"]["agent_principal"]),
        ("environment", verified["context"]["environment"]),
    ):
        if approval[approval_field] != verified_value:
            raise AssertionError(f"Approval binding mismatch: {approval_field}")

    if approval["approver_principal_id"] in {
        verified["requester"]["principal_id"], verified["authority_subject"]["principal_id"]
    }:
        raise AssertionError("Independent approval example is self-approved")

    approved_at = parse_rfc3339(approval["approved_at"])
    approval_expires = parse_rfc3339(approval["expires_at"])
    if approved_at >= approval_expires:
        raise AssertionError("Approval expiry must be later than approval time")

    issued_at = parse_rfc3339(execution["issued_at"])
    not_before = parse_rfc3339(execution["not_before"])
    expires_at = parse_rfc3339(execution["expires_at"])
    if not_before > expires_at or issued_at >= expires_at:
        raise AssertionError("Execution credential timestamps are inconsistent")
    for label, value in (
        ("execution", execution["credential_thumbprint"]),
        ("agent", verified["agent"]["credential_thumbprint"]),
    ):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
            raise AssertionError(f"{label} credential thumbprint is invalid")

    mode = execution["authority_mode"]
    authority = verified["authority_subject"]
    chain_ok = (
        mode == "user_delegated"
        and authority["authority_basis"] == "explicit_delegation"
        and authority["principal_type"] in {"human", "service"}
    ) or (
        mode == "agent_own"
        and authority["authority_basis"] == "agent_own_authority"
        and authority["principal_type"] == "workload"
        and authority["principal_id"] == verified["agent"]["agent_principal"]
    ) or (
        mode == "brokered_service"
        and authority["authority_basis"] in {"organizational_mandate", "service_delegation"}
        and authority["principal_type"] in {"service", "workload"}
    )
    if not chain_ok:
        raise AssertionError("Authority subject and execution authority mode are inconsistent")

    server_name = action["mcp_server"]
    server = agent_control["servers"][server_name]
    tool = server["tools"][action["tool"]]
    expected_audiences = {
        binding["audience"]
        for binding in server["audience_bindings"]
        if target_matches(binding["target_pattern"], action["target"])
    }
    actual_audiences = execution["audiences"]
    if len(actual_audiences) != 1 or actual_audiences[0] not in expected_audiences:
        raise AssertionError("Execution audience is not uniquely bound to the target")
    if execution["issuer"] not in server["trusted_issuers"]:
        raise AssertionError("Execution issuer is not trusted by policy data")
    if execution["sender_constraint"] not in server["allowed_sender_constraints"]:
        raise AssertionError("Execution sender constraint is not allowed")

    lifetime_seconds = int((expires_at - issued_at).total_seconds())
    if lifetime_seconds > tool["max_credential_ttl_seconds"]:
        raise AssertionError("Execution credential exceeds the tool-specific maximum lifetime")

    entitlement = agent_control["entitlements"][verified["agent"]["agent_principal"]]
    permission = entitlement["server_permissions"][server_name]
    if action["tool"] not in permission["allowed_tools"]:
        raise AssertionError("Example tool is not entitled")
    if not any(target_matches(pattern, action["target"]) for pattern in permission["allowed_targets"]):
        raise AssertionError("Example target is not entitled")
    if verified["context"]["environment"] not in entitlement["allowed_environments"]:
        raise AssertionError("Example environment is not entitled")
    if execution["principal_id"] not in entitlement["allowed_execution_principals"]:
        raise AssertionError("Execution principal is not entitled")
    if mode not in entitlement["allowed_authority_modes"]:
        raise AssertionError("Authority mode is not entitled")
    credential_profile = tool["credential_profiles"].get(mode)
    if not credential_profile:
        raise AssertionError("Credential profile is not configured for the authority mode")
    if verified["context"]["environment"] == "production" and tool["write"]:
        if permission.get("production_write_allowed") is not True:
            raise AssertionError("Production write permission is absent from trusted policy data")

    audit = load_json("examples/agent-action-event.example.json")
    if audit["action"]["canonical_hash"] != expected_action_hash:
        raise AssertionError("Audit action hash does not match the authorization action hash")
    if audit["approval"]["action_hash"] != expected_action_hash:
        raise AssertionError("Audit approval is not bound to the action hash")
    if audit["context"]["policy_bundle_digest"] != expected_policy_digest:
        raise AssertionError("Audit event references a different policy bundle")
    if audit["execution"] != execution:
        raise AssertionError("Audit event and authorization envelope disagree on execution identity")

    audit_without_evidence = {key: value for key, value in audit.items() if key != "evidence"}
    expected_record_digest = sha256_prefixed(canonical_json(audit_without_evidence))
    if audit["evidence"]["record_digest"] != expected_record_digest:
        raise AssertionError("Audit record_digest is inconsistent")


    negative = copy.deepcopy(authz)
    negative["request"]["now"] = "2099-01-01T00:00:00Z"
    assert_schema_rejects("schema/authorization-context.schema.json", negative, "caller-supplied now")

    negative = copy.deepcopy(authz)
    negative["request"]["authorization"] = {"production_write_allowed": True}
    assert_schema_rejects("schema/authorization-context.schema.json", negative, "caller-supplied entitlements")

    negative = copy.deepcopy(authz)
    negative["approval"] = {"status": "approved"}
    assert_schema_rejects("schema/authorization-context.schema.json", negative, "caller-supplied approval state")

    negative = copy.deepcopy(authz)
    negative["verified"]["execution"]["audiences"].append("https://unrelated.example.internal")
    assert_schema_rejects("schema/authorization-context.schema.json", negative, "multiple audiences")

    for path, label in (
        (("verified", "execution", "credential_thumbprint"), "missing execution sender binding"),
        (("verified", "agent", "credential_thumbprint"), "missing agent credential binding"),
        (("verified", "execution", "authority_subject_principal_id"), "missing delegated subject link"),
        (("verified", "execution", "agent_actor_principal_id"), "missing agent actor link"),
    ):
        negative = copy.deepcopy(authz)
        node = negative
        for part in path[:-1]:
            node = node[part]
        del node[path[-1]]
        assert_schema_rejects("schema/authorization-context.schema.json", negative, label)

    return expected_arguments_digest, expected_action_hash, expected_policy_digest, expected_record_digest, credential_profile


def main() -> int:
    assert_required_files()
    validate_readme_paths()
    validate_workflow()
    validate_policy_source()
    arguments_digest, action_hash, policy_digest, record_digest, profile = validate_examples_and_policy_data()
    validate_privacy()

    print("Artifact validation passed")
    print(f"Arguments digest: {arguments_digest}")
    print(f"Action hash: {action_hash}")
    print(f"Policy bundle digest: {policy_digest}")
    print(f"Audit record digest: {record_digest}")
    print(f"Credential profile: {profile}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Regenerate synchronized examples and all derived digests."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_canonical_action_field(name: str, value: Any) -> None:
    if not isinstance(value, str):
        raise RuntimeError(f"Canonical action field must be a string: {name}")
    if value == "":
        raise RuntimeError(f"Canonical action field must not be empty: {name}")
    if "\n" in value or "\r" in value:
        raise RuntimeError(f"Canonical action field must not contain CR/LF: {name}")


def action_canonical_string(action: dict[str, Any]) -> str:
    fields = (
        ("mcp_server", action["mcp_server"]),
        ("method", action["method"]),
        ("tool", action["tool"]),
        ("target", action["target"]),
        ("arguments_digest", action["arguments_digest"]),
        ("data_classification", action["data_classification"]),
    )
    for name, value in fields:
        validate_canonical_action_field(name, value)
    return "\n".join(["agent-action-v1", *[f"{key}={value}" for key, value in fields]])


def target_matches(pattern: str, target: str) -> bool:
    if pattern == target:
        return True
    return pattern.endswith("*") and target.startswith(pattern[:-1])


def read_json(relative: str) -> Any:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def write_json(relative: str, value: Any) -> None:
    (ROOT / relative).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def expected_audiences_for_action(agent_control_doc: dict[str, Any], authz: dict[str, Any]) -> list[str]:
    action = authz["verified"]["action"]
    server = agent_control_doc["agent_control"]["servers"][action["mcp_server"]]
    audiences = {
        binding["audience"]
        for binding in server["audience_bindings"]
        if target_matches(binding["target_pattern"], action["target"])
    }
    return sorted(audiences)


def selected_credential_profile(agent_control_doc: dict[str, Any], authz: dict[str, Any]) -> str:
    action = authz["verified"]["action"]
    mode = authz["verified"]["execution"]["authority_mode"]
    tool = agent_control_doc["agent_control"]["servers"][action["mcp_server"]]["tools"][action["tool"]]
    profile = tool["credential_profiles"].get(mode)
    if not profile:
        raise RuntimeError(f"Missing credential profile for authority_mode={mode}")
    return profile


def allow_reason_codes(tool: dict[str, Any], authz: dict[str, Any]) -> list[str]:
    requires_approval = tool["requires_approval"] or (
        authz["verified"]["context"]["environment"] == "production" and tool["write"]
    )
    approval_reason_code = "APPROVAL_VALID" if requires_approval else "APPROVAL_NOT_REQUIRED"
    return sorted(
        [
            "ACTION_HASH_VALID",
            "AGENT_CREDENTIAL_TRUSTED",
            "AGENT_ENTITLED",
            approval_reason_code,
            "AUTHORITY_CHAIN_VALID",
            "EXECUTION_IDENTITY_VALID",
            "IDENTITY_CONTEXT_VALID",
            "REQUEST_CONTEXT_VALID",
            "TOOL_ACCESS_ALLOWED",
            "VERIFIED_CONTEXT_VALID",
        ]
    )


def build_allow_decision(agent_control_doc: dict[str, Any], authz: dict[str, Any]) -> dict[str, Any]:
    action = authz["verified"]["action"]
    execution = authz["verified"]["execution"]
    tool = agent_control_doc["agent_control"]["servers"][action["mcp_server"]]["tools"][action["tool"]]
    return {
        "allow": True,
        "authority_mode": execution["authority_mode"],
        "requires_approval": tool["requires_approval"]
        or (authz["verified"]["context"]["environment"] == "production" and tool["write"]),
        "deny_reasons": [],
        "reason_codes": allow_reason_codes(tool, authz),
        "risk_tier": tool["risk_tier"],
        "credential_profile": selected_credential_profile(agent_control_doc, authz),
        "credential_ttl_seconds": tool["max_credential_ttl_seconds"],
        "expected_audiences": expected_audiences_for_action(agent_control_doc, authz),
        "policy_id": agent_control_doc["agent_control"]["policy_id"],
        "policy_version": agent_control_doc["agent_control"]["policy_version"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()

    authz = read_json("examples/authorization-context.example.json")
    arguments = read_json("examples/action-arguments.example.json")
    agent_control_doc = read_json("data/agent-control.json")
    approvals_doc = read_json("data/approval-records.example.json")
    audit = read_json("examples/agent-action-event.example.json")

    action = authz["verified"]["action"]
    action["arguments_digest"] = sha256_prefixed(canonical_json(arguments))
    action["canonical_hash"] = sha256_prefixed(action_canonical_string(action).encode("utf-8"))

    policy_bytes = (ROOT / "policy/mcp-tool-authorization.rego").read_bytes()
    policy_digest = sha256_prefixed(
        b"mcp-agent-policy-bundle-v1\n"
        + policy_bytes
        + b"\n"
        + canonical_json(agent_control_doc["agent_control"])
    )
    authz["verified"]["context"]["policy_bundle_digest"] = policy_digest
    authz["schema_version"] = "1.2"

    approval_id = authz["request"]["approval_id"]
    approval = approvals_doc["approval_records"][approval_id]
    expected_audiences = expected_audiences_for_action(agent_control_doc, authz)
    if len(expected_audiences) != 1:
        raise RuntimeError("Expected exactly one audience binding for the reference example")
    credential_profile = selected_credential_profile(agent_control_doc, authz)
    approval.update(
        {
            "action_hash": action["canonical_hash"],
            "requester_principal_id": authz["verified"]["requester"]["principal_id"],
            "authority_subject_principal_id": authz["verified"]["authority_subject"]["principal_id"],
            "agent_principal": authz["verified"]["agent"]["agent_principal"],
            "agent_definition_id": authz["verified"]["agent"]["agent_definition_id"],
            "agent_version": authz["verified"]["agent"]["agent_version"],
            "runtime_instance_id": authz["verified"]["agent"]["runtime_instance_id"],
            "agent_credential_thumbprint": authz["verified"]["agent"]["credential_thumbprint"],
            "authority_mode": authz["verified"]["execution"]["authority_mode"],
            "execution_principal_id": authz["verified"]["execution"]["principal_id"],
            "expected_audience": expected_audiences[0],
            "sender_constraint": authz["verified"]["execution"]["sender_constraint"],
            "credential_profile": credential_profile,
            "single_use": True,
            "consumed": False,
            "environment": authz["verified"]["context"]["environment"],
            "policy_bundle_digest": policy_digest,
        }
    )

    audit["schema_version"] = authz["schema_version"]
    audit["requester"] = {
        **authz["verified"]["requester"],
        "tenant_id": audit["requester"].get("tenant_id", "urn:example:tenant:primary"),
    }
    audit["authority_subject"] = {
        **authz["verified"]["authority_subject"],
        "tenant_id": audit["authority_subject"].get("tenant_id", "urn:example:tenant:primary"),
    }
    audit["agent"] = authz["verified"]["agent"]
    audit["execution"] = authz["verified"]["execution"]
    audit["action"] = authz["verified"]["action"]
    audit["context"].update(
        {
            "approval_id": approval_id,
            "session_id": authz["request"]["session_id"],
            "task_id": authz["request"]["task_id"],
            "correlation_id": authz["request"]["correlation_id"],
            "environment": authz["verified"]["context"]["environment"],
            "policy_bundle_digest": policy_digest,
        }
    )
    audit["approval"].update(
        {
            "approval_id": approval_id,
            "approver_principal_id": approval["approver_principal_id"],
            "agent_definition_id": approval["agent_definition_id"],
            "agent_version": approval["agent_version"],
            "runtime_instance_id": approval["runtime_instance_id"],
            "agent_credential_thumbprint": approval["agent_credential_thumbprint"],
            "authority_mode": approval["authority_mode"],
            "execution_principal_id": approval["execution_principal_id"],
            "expected_audience": approval["expected_audience"],
            "sender_constraint": approval["sender_constraint"],
            "credential_profile": approval["credential_profile"],
            "single_use": approval["single_use"],
            "consumed": approval["consumed"],
            "action_hash": action["canonical_hash"],
            "approved_at": approval["approved_at"],
            "expires_at": approval["expires_at"],
        }
    )
    audit["decision"] = {
        **build_allow_decision(agent_control_doc, authz),
        "evaluated_at": audit["decision"].get("evaluated_at", audit["occurred_at"]),
    }
    audit["evidence"]["digest_profile"] = "canonical-json-sort-keys-v2"

    audit_for_digest = copy.deepcopy(audit)
    audit_for_digest["evidence"].pop("record_digest", None)
    audit["evidence"]["record_digest"] = sha256_prefixed(canonical_json(audit_for_digest))

    write_json("examples/authorization-context.example.json", authz)
    (ROOT / "examples/authorization-context.example.yaml").write_text(
        yaml.safe_dump(authz, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    write_json("data/test-fixtures.json", {"test_fixtures": {"valid_input": authz}})
    write_json("data/approval-records.example.json", approvals_doc)
    write_json("examples/agent-action-event.example.json", audit)

    print(f"arguments_digest={action['arguments_digest']}")
    print(f"action_hash={action['canonical_hash']}")
    print(f"policy_bundle_digest={policy_digest}")
    print(f"audit_record_digest={audit['evidence']['record_digest']}")


if __name__ == "__main__":
    main()

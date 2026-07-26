#!/usr/bin/env python3
"""Regenerate synchronized examples and all derived digests."""

from __future__ import annotations

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


def read_json(relative: str) -> Any:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def write_json(relative: str, value: Any) -> None:
    (ROOT / relative).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
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

    approval_id = authz["request"]["approval_id"]
    approval = approvals_doc["approval_records"][approval_id]
    approval.update(
        {
            "action_hash": action["canonical_hash"],
            "requester_principal_id": authz["verified"]["requester"]["principal_id"],
            "authority_subject_principal_id": authz["verified"]["authority_subject"]["principal_id"],
            "agent_principal": authz["verified"]["agent"]["agent_principal"],
            "environment": authz["verified"]["context"]["environment"],
            "policy_bundle_digest": policy_digest,
        }
    )

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
            "action_hash": action["canonical_hash"],
            "approved_at": approval["approved_at"],
            "expires_at": approval["expires_at"],
        }
    )
    audit["decision"]["policy_id"] = agent_control_doc["agent_control"]["policy_id"]
    audit["decision"]["policy_version"] = agent_control_doc["agent_control"]["policy_version"]

    audit_without_evidence = {key: value for key, value in audit.items() if key != "evidence"}
    audit["evidence"]["record_digest"] = sha256_prefixed(canonical_json(audit_without_evidence))

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

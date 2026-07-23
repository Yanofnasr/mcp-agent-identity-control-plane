#!/usr/bin/env python3
"""Evaluate the current allow-path example with a supplied OPA binary."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa", default="opa", help="Path to the OPA executable")
    args = parser.parse_args()

    authz = json.loads((ROOT / "examples/authorization-context.example.json").read_text(encoding="utf-8"))
    approvals = json.loads((ROOT / "data/approval-records.example.json").read_text(encoding="utf-8"))

    now = datetime.now(timezone.utc)
    execution = authz["verified"]["execution"]
    execution["issued_at"] = rfc3339(now - timedelta(seconds=5))
    execution["not_before"] = rfc3339(now - timedelta(seconds=10))
    execution["expires_at"] = rfc3339(now + timedelta(minutes=10))

    approval_id = authz["request"]["approval_id"]
    approval = approvals["approval_records"][approval_id]
    approval["approved_at"] = rfc3339(now - timedelta(minutes=1))
    approval["expires_at"] = rfc3339(now + timedelta(minutes=5))

    with tempfile.TemporaryDirectory(prefix="agent-authz-") as tmp:
        tmp_path = Path(tmp)
        input_path = tmp_path / "input.json"
        approvals_path = tmp_path / "approvals.json"
        input_path.write_text(json.dumps(authz, indent=2) + "\n", encoding="utf-8")
        approvals_path.write_text(json.dumps(approvals, indent=2) + "\n", encoding="utf-8")

        command = [
            args.opa,
            "eval",
            "--format", "json",
            "--fail",
            "--data", str(ROOT / "policy/mcp-tool-authorization.rego"),
            "--data", str(ROOT / "data/agent-control.json"),
            "--data", str(approvals_path),
            "--input", str(input_path),
            "data.agent.mcp.authz.decision",
        ]
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        payload = json.loads(completed.stdout)
        decision = payload["result"][0]["expressions"][0]["value"]

    expected = {
        "allow": True,
        "requires_approval": True,
        "deny_reasons": [],
        "risk_tier": "critical",
        "credential_profile": "source-control-user-delegated-critical",
        "credential_ttl_seconds": 900,
        "expected_audiences": ["https://source-control.example.internal"],
        "policy_id": "urn:example:policy:mcp-agent-tool-authorization",
        "policy_version": "1.1.0",
    }
    if decision != expected:
        raise SystemExit(
            "Unexpected OPA decision:\n"
            + json.dumps(decision, indent=2)
            + "\nExpected:\n"
            + json.dumps(expected, indent=2)
        )

    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()

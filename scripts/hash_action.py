#!/usr/bin/env python3
"""Reproduce the reference action digest and canonical action hash."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_canonical_action_field(name: str, value: Any) -> None:
    if not isinstance(value, str):
        raise SystemExit(f"Canonical action field must be a string: {name}")
    if value == "":
        raise SystemExit(f"Canonical action field must not be empty: {name}")
    if "\n" in value or "\r" in value:
        raise SystemExit(f"Canonical action field must not contain CR/LF: {name}")


def canonical_action(action: dict[str, Any]) -> str:
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arguments", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    args = parser.parse_args()

    arguments = json.loads(args.arguments.read_text(encoding="utf-8"))
    context = json.loads(args.context.read_text(encoding="utf-8"))
    action = dict(context["verified"]["action"])
    action["arguments_digest"] = sha256_prefixed(canonical_json(arguments))
    canonical = canonical_action(action)
    action_hash = sha256_prefixed(canonical.encode("utf-8"))

    print(canonical)
    print(f"arguments_digest={action['arguments_digest']}")
    print(f"canonical_hash={action_hash}")

    checked_in = context["verified"]["action"]
    if checked_in["arguments_digest"] != action["arguments_digest"]:
        raise SystemExit("Checked-in arguments_digest is stale")
    if checked_in["canonical_hash"] != action_hash:
        raise SystemExit("Checked-in canonical_hash is stale")


if __name__ == "__main__":
    main()

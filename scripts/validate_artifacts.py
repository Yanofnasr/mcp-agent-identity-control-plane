#!/usr/bin/env python3
"""Validate the reference package without requiring an OPA executable."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from canonical_json import (
    PROFILE_NAME,
    CanonicalJSONError,
    canonical_json_bytes,
    load_canonical_json,
    loads_canonical_json,
)
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

SCRIPT_ROOT = Path(__file__).resolve().parents[1]
FORMAT_CHECKER = FormatChecker()

PACKAGE_REQUIRED_FILES = frozenset(
    {
        ".github/dependabot.yml",
        ".github/workflows/release.yml",
        ".github/workflows/validate.yml",
        ".gitignore",
        "CHANGELOG.md",
        "LICENSE",
        "MANIFEST.sha256",
        "Makefile",
        "README.md",
        "SECURITY.md",
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
        "scripts/canonical_json.py",
        "scripts/hash_action.py",
        "scripts/package.sh",
        "scripts/update_derived_values.py",
        "scripts/validate.sh",
        "scripts/validate_artifacts.py",
    }
)

MANIFEST_EXCLUDED_FILES = {"MANIFEST.sha256"}

PACKAGE_EXECUTABLE_FILES = frozenset(
    {
        "scripts/evaluate_example.py",
        "scripts/hash_action.py",
        "scripts/package.sh",
        "scripts/update_derived_values.py",
        "scripts/validate.sh",
    }
)

IGNORED_DIR_NAMES = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
}
ALLOWED_HIDDEN_SOURCE_DIR_NAMES = {".github"}
IGNORED_FILE_NAMES = {".DS_Store", ".coverage"}
IGNORED_SOURCE_PATHS = {
    # Local workspace noise that is not part of the reference package.
    Path(".gitmodules"),
    Path(".npmrc"),
    Path(".yarnrc"),
    Path(".yarnrc.yml"),
    Path("bunfig.toml"),
    Path("pnpm-lock.yaml"),
    Path("yarn.lock"),
}
IGNORED_ROOT_FILE_PATTERNS = {".env*", "package*.json"}
IGNORED_FILE_PATTERNS = {
    "*.py[cod]",
    "*.swp",
    "*.tmp",
}
PROHIBITED_SOURCE_SUFFIXES = {
    ".eml",
    ".ics",
    ".key",
    ".mbox",
    ".ost",
    ".p12",
    ".pem",
    ".pfx",
    ".pst",
    ".zip",
}
SUSPICIOUS_SOURCE_TERMS = ("calendar", "bricsys", "customer-export")

EXPECTED_POLICY_TESTS = frozenset(
    {
        "test_valid_production_merge",
        "test_allow_decision_shape_includes_authority_mode_and_reason_codes",
        "test_wrong_audience_is_denied",
        "test_multiple_audiences_are_denied",
        "test_missing_sender_binding_is_denied",
        "test_non_hex_policy_bundle_digest_is_denied",
        "test_non_hex_agent_version_is_denied",
        "test_non_hex_agent_thumbprint_is_denied",
        "test_non_hex_execution_thumbprint_is_denied",
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
        "test_untrusted_agent_credential_type_is_denied",
        "test_untrusted_agent_credential_issuer_is_denied",
        "test_untrusted_agent_attestation_profile_is_denied",
        "test_independent_approval_cannot_be_self_approved",
        "test_independent_approval_cannot_be_agent_approved",
        "test_independent_approval_cannot_be_execution_principal_approved",
        "test_approval_policy_bundle_mismatch_is_denied",
        "test_approval_runtime_build_binding_mismatch_is_denied",
        "test_empty_approver_identity_is_denied",
        "test_changed_execution_contract_is_denied",
        "test_consumed_approval_is_denied",
        "test_non_single_use_approval_is_denied",
        "test_missing_credential_profile_is_denied",
        "test_missing_tool_write_flag_is_denied",
        "test_missing_tool_requires_approval_flag_is_denied",
        "test_invalid_tool_approval_mode_is_denied",
        "test_production_write_entitlement_cannot_be_self_asserted",
        "test_agent_own_read_only_access_allowed",
        "test_brokered_service_read_only_access_allowed",
        "test_newline_bearing_action_is_denied",
        "test_overlapping_target_audience_bindings_are_denied",
        "test_unmapped_target_returns_empty_expected_audiences",
    }
)

EXPECTED_REQUIREMENT_OPTIONS = ("--only-binary=:all:", "--require-hashes")
EXPECTED_REQUIREMENTS = {
    "attrs": {
        "version": "26.1.0",
        "hashes": {
            "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309",
        },
    },
    "jsonschema": {
        "version": "4.26.0",
        "hashes": {
            "d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce",
        },
    },
    "jsonschema-specifications": {
        "version": "2025.9.1",
        "hashes": {
            "98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe",
        },
    },
    "pyyaml": {
        "version": "6.0.3",
        "hashes": {
            "b8bb0864c5a28024fac8a632c443c87c5aa6f215c0b126c449ae1a150412f31d",
            "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",
        },
    },
    "referencing": {
        "version": "0.37.0",
        "hashes": {
            "381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231",
        },
    },
    "rfc3339-validator": {
        "version": "0.1.4",
        "hashes": {
            "24f6ec1eda14ef823da9e36ec7113124b39c04d50a4d3d3a3c2859577e7791fa",
        },
    },
    "rfc3986-validator": {
        "version": "0.1.1",
        "hashes": {
            "2f235c432ef459970b4306369336b9d5dbdda31b510ca1e327636e01f528bfa9",
        },
    },
    "rpds-py": {
        "version": "2026.6.3",
        "hashes": {
            "9c1255b302953c86a486b81d330d5ee1d5bd937691ce271b6be0ef0e299eaab7",
            "ecabd69db66de867690f9797f2f8fa27ba501bbc24540cbdbdc649cd15888ba6",
        },
    },
    "six": {
        "version": "1.17.0",
        "hashes": {
            "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
        },
    },
    "typing-extensions": {
        "version": "4.16.0",
        "hashes": {
            "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8",
        },
    },
}

EXPECTED_ALLOW_REASON_CODES = sorted(
    [
        "ACTION_HASH_VALID",
        "AGENT_CREDENTIAL_TRUSTED",
        "AGENT_ENTITLED",
        "APPROVAL_VALID",
        "AUTHORITY_CHAIN_VALID",
        "EXECUTION_IDENTITY_VALID",
        "IDENTITY_CONTEXT_VALID",
        "REQUEST_CONTEXT_VALID",
        "TOOL_ACCESS_ALLOWED",
        "VERIFIED_CONTEXT_VALID",
    ]
)


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


def load_json(relative: str, *, root: Path = SCRIPT_ROOT) -> Any:
    try:
        return load_canonical_json(root / relative)
    except CanonicalJSONError as exc:
        raise AssertionError(f"{relative}: {exc}") from exc


def parse_rfc3339(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def target_matches(pattern: str, target: str) -> bool:
    if pattern == target:
        return True
    return pattern.endswith("*") and target.startswith(pattern[:-1])


def is_ignored_source_path(relative: Path) -> bool:
    if relative in IGNORED_SOURCE_PATHS:
        return True
    if len(relative.parts) == 1 and any(
        fnmatch(relative.name, pattern) for pattern in IGNORED_ROOT_FILE_PATTERNS
    ):
        return True
    if any(
        part.startswith(".") and part not in ALLOWED_HIDDEN_SOURCE_DIR_NAMES
        for part in relative.parts[:-1]
    ):
        return True
    if any(part in IGNORED_DIR_NAMES for part in relative.parts):
        return True
    if relative.name in IGNORED_FILE_NAMES:
        return True
    return any(fnmatch(relative.name, pattern) for pattern in IGNORED_FILE_PATTERNS)


def discover_files(root: Path, *, apply_source_ignores: bool) -> set[str]:
    files: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if apply_source_ignores and is_ignored_source_path(relative):
            continue
        files.add(relative.as_posix())
    return files


def validate_package_file_set(actual: set[str], *, context: str) -> None:
    missing = sorted(PACKAGE_REQUIRED_FILES - actual)
    if missing:
        raise AssertionError(
            f"Required package files are missing from {context}: {missing}"
        )
    unexpected = sorted(actual - PACKAGE_REQUIRED_FILES)
    if unexpected:
        raise AssertionError(
            f"Unexpected files are packageable in {context}: {unexpected}"
        )


def package_files_for_root(root: Path, *, include_manifest: bool) -> list[str]:
    files = set(PACKAGE_REQUIRED_FILES)
    if not include_manifest:
        files -= MANIFEST_EXCLUDED_FILES
    return [relative for relative in sorted(files) if (root / relative).is_file()]


def render_manifest(root: Path) -> str:
    lines = []
    for relative in package_files_for_root(root, include_manifest=False):
        path = root / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  ./{relative}")
    return "\n".join(lines) + "\n"


def expected_package_mode(relative: str) -> int:
    return 0o755 if relative in PACKAGE_EXECUTABLE_FILES else 0o644


def normalize_package_modes(root: Path) -> None:
    for relative in package_files_for_root(root, include_manifest=True):
        (root / relative).chmod(expected_package_mode(relative))


def validate_package_modes(root: Path) -> None:
    mismatches = []
    for relative in package_files_for_root(root, include_manifest=True):
        actual = stat.S_IMODE((root / relative).stat().st_mode)
        expected = expected_package_mode(relative)
        if actual != expected:
            mismatches.append(f"{relative}: {actual:#06o} != {expected:#06o}")
    if mismatches:
        raise AssertionError(
            "Package file modes are not canonical: " + ", ".join(mismatches)
        )


def check_manifest(root: Path) -> None:
    manifest_path = root / "MANIFEST.sha256"
    if not manifest_path.is_file():
        raise AssertionError(f"{manifest_path} is missing")
    expected = render_manifest(root)
    actual = manifest_path.read_text(encoding="utf-8")
    if actual != expected:
        raise AssertionError(
            "MANIFEST.sha256 is stale; run `make manifest` and commit the refreshed file"
        )


def write_manifest(root: Path, output: Path | None = None) -> Path:
    manifest_path = output or root / "MANIFEST.sha256"
    manifest_path.write_text(render_manifest(root), encoding="utf-8")
    return manifest_path


def verify_package_tree(root: Path) -> None:
    validate_package_file_set(
        discover_files(root, apply_source_ignores=False), context=str(root)
    )
    check_manifest(root)
    validate_package_modes(root)


def build_schema_validator(
    schema_path: str, *, root: Path = SCRIPT_ROOT
) -> Draft202012Validator:
    schema = load_json(schema_path, root=root)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FORMAT_CHECKER)


def validate_schema(
    schema_path: str, instance_path: str, *, root: Path = SCRIPT_ROOT
) -> None:
    instance = load_json(instance_path, root=root)
    validator = build_schema_validator(schema_path, root=root)
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        detail = "\n".join(f"  {list(error.path)}: {error.message}" for error in errors)
        raise AssertionError(f"{instance_path} failed {schema_path}:\n{detail}")


def assert_schema_rejects(
    schema_path: str, instance: Any, label: str, *, root: Path = SCRIPT_ROOT
) -> None:
    validator = build_schema_validator(schema_path, root=root)
    if not list(validator.iter_errors(instance)):
        raise AssertionError(f"Schema should reject negative fixture: {label}")


def assert_schema_accepts(
    schema_path: str, instance: Any, label: str, *, root: Path = SCRIPT_ROOT
) -> None:
    validator = build_schema_validator(schema_path, root=root)
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        detail = "\n".join(f"  {list(error.path)}: {error.message}" for error in errors)
        raise AssertionError(
            f"Schema should accept positive fixture {label}:\n{detail}"
        )


def validate_python_runtime() -> None:
    for format_name in ("uri", "date-time"):
        if format_name not in FORMAT_CHECKER.checkers:
            raise AssertionError(
                f"jsonschema FormatChecker is missing the required `{format_name}` checker"
            )


def validate_canonical_json_profile() -> None:
    first = loads_canonical_json('{"z":"é😀","a":[true,null,9007199254740991]}')
    second = loads_canonical_json('{"a":[true,null,9007199254740991],"z":"é😀"}')
    expected = '{"a":[true,null,9007199254740991],"z":"é😀"}'.encode()
    if (
        canonical_json_bytes(first) != expected
        or canonical_json_bytes(second) != expected
    ):
        raise AssertionError(
            "Restricted canonical JSON bytes drifted for ordering or Unicode"
        )

    # U+E000 sorts before U+1F600 by Unicode scalar value. This fixture catches
    # accidental adoption of UTF-16 code-unit ordering, where the order reverses.
    unicode_key_order = canonical_json_bytes({"\U0001f600": 2, "\ue000": 1})
    expected_unicode_key_order = '{"\ue000":1,"\U0001f600":2}'.encode()
    if unicode_key_order != expected_unicode_key_order:
        raise AssertionError(
            "Restricted canonical JSON key ordering is not Unicode-scalar order"
        )

    composed = "\u00e9"
    decomposed = "e\u0301"
    expected_without_normalization = f'{{"{decomposed}":2,"{composed}":1}}'.encode()
    if (
        canonical_json_bytes({composed: 1, decomposed: 2})
        != expected_without_normalization
    ):
        raise AssertionError(
            "Restricted canonical JSON unexpectedly normalized Unicode"
        )

    rejected_payloads = {
        "duplicate object key": '{"a":1,"a":2}',
        "NaN": '{"value":NaN}',
        "positive infinity": '{"value":Infinity}',
        "negative infinity": '{"value":-Infinity}',
        "floating-point number": '{"value":1.0}',
        "unsafe integer": '{"value":9007199254740992}',
        "lone Unicode surrogate": '"\\ud800"',
    }
    for label, payload in rejected_payloads.items():
        try:
            loads_canonical_json(payload)
        except CanonicalJSONError:
            continue
        raise AssertionError(f"Restricted canonical JSON accepted {label}")

    try:
        canonical_json_bytes({"value": 1.0})
    except CanonicalJSONError:
        pass
    else:
        raise AssertionError("Restricted canonical JSON accepted a native float")


def validate_package_allowlist_self_tests() -> None:
    validate_package_file_set(
        set(PACKAGE_REQUIRED_FILES), context="the allowlist self-test"
    )

    try:
        validate_package_file_set(
            set(PACKAGE_REQUIRED_FILES) | {"notes.md"},
            context="the allowlist self-test",
        )
    except AssertionError as exc:
        if "Unexpected files are packageable" not in str(exc):
            raise
    else:
        raise AssertionError(
            "Package allowlist self-test did not reject an unexpected file"
        )

    try:
        validate_package_file_set(
            set(PACKAGE_REQUIRED_FILES) - {".gitignore"},
            context="the allowlist self-test",
        )
    except AssertionError as exc:
        if "Required package files are missing" not in str(exc):
            raise
    else:
        raise AssertionError(
            "Package allowlist self-test did not reject a missing required file"
        )

    for relative in (
        Path(".git/config"),
        Path(".cache/state/runtime.json"),
        Path("build/output.zip"),
        Path("__pycache__/x.pyc"),
    ):
        if not is_ignored_source_path(relative):
            raise AssertionError(
                f"Source ignore self-test failed for {relative.as_posix()}"
            )
    if is_ignored_source_path(Path(".github/workflows/validate.yml")):
        raise AssertionError(
            "Source ignore self-test incorrectly ignored an allowlisted hidden directory"
        )
    if is_ignored_source_path(Path("notes.md")):
        raise AssertionError(
            "Source ignore self-test incorrectly ignored a packageable file"
        )

    if not PACKAGE_EXECUTABLE_FILES <= PACKAGE_REQUIRED_FILES:
        raise AssertionError(
            "Executable package files must be present in the allowlist"
        )

    with tempfile.TemporaryDirectory(prefix="mcp-package-mode-test.") as directory:
        root = Path(directory)
        fixtures = {
            "README.md": 0o777,
            "scripts/package.sh": 0o600,
        }
        for fixture_relative, mode in fixtures.items():
            path = root / fixture_relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(fixture_relative, encoding="utf-8")
            path.chmod(mode)
        normalize_package_modes(root)
        validate_package_modes(root)
        for fixture_relative in fixtures:
            actual = stat.S_IMODE((root / fixture_relative).stat().st_mode)
            expected = expected_package_mode(fixture_relative)
            if actual != expected:
                raise AssertionError(
                    f"Package mode self-test failed for {fixture_relative}: "
                    f"{actual:#06o} != {expected:#06o}"
                )
        executable = root / "scripts/package.sh"
        executable.chmod(0o4755)
        try:
            validate_package_modes(root)
        except AssertionError as exc:
            if "Package file modes are not canonical" not in str(exc):
                raise
        else:
            raise AssertionError("Package mode self-test accepted a setuid file")
    for relative in (
        Path(".env"),
        Path(".env.production"),
        Path("package.json"),
        Path("package-lock.json"),
        Path("yarn.lock"),
        Path(".npmrc"),
        Path(".yarnrc.yml"),
        Path(".gitmodules"),
    ):
        if not is_ignored_source_path(relative):
            raise AssertionError(
                f"Source ignore self-test failed for {relative.as_posix()}"
            )
    for relative in (Path("docs/.env"), Path("web/package.json")):
        if is_ignored_source_path(relative):
            raise AssertionError(
                "Source ignore self-test incorrectly ignored nested path "
                f"{relative.as_posix()}"
            )


def validate_gitignore() -> None:
    gitignore = (SCRIPT_ROOT / ".gitignore").read_text(encoding="utf-8")
    required_patterns = (
        "__pycache__/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".venv/",
        "build/",
        "dist/",
        "htmlcov/",
        ".DS_Store",
        "*.zip",
        "node_modules/",
        "/.omx/",
    )
    for pattern in required_patterns:
        if pattern not in gitignore:
            raise AssertionError(
                f".gitignore is missing required packaging ignore pattern: {pattern}"
            )


def normalize_requirement_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements_lock() -> tuple[list[str], dict[str, dict[str, Any]]]:
    options: list[str] = []
    requirements: dict[str, dict[str, Any]] = {}
    for raw_line in (
        (SCRIPT_ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--"):
            options.append(line)
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)(.*)", line)
        if not match:
            raise AssertionError(
                f"requirements-dev.txt contains an invalid locked requirement line: {line}"
            )
        name, version, suffix = match.groups()
        hash_tokens = suffix.split()
        if not hash_tokens or not all(
            re.fullmatch(r"--hash=sha256:[a-f0-9]{64}", token) for token in hash_tokens
        ):
            raise AssertionError(
                f"requirements-dev.txt entry has invalid or missing sha256 hashes: {name}"
            )
        hashes = [token.removeprefix("--hash=sha256:") for token in hash_tokens]
        normalized_name = normalize_requirement_name(name)
        if normalized_name in requirements:
            raise AssertionError(
                f"requirements-dev.txt contains a duplicate package entry: {name}"
            )
        requirements[normalized_name] = {
            "name": name,
            "version": version,
            "hashes": set(hashes),
            "raw": line,
        }
    return options, requirements


def validate_requirements() -> None:
    options, requirements = parse_requirements_lock()
    if options != list(EXPECTED_REQUIREMENT_OPTIONS):
        raise AssertionError(
            f"requirements-dev.txt must start with {EXPECTED_REQUIREMENT_OPTIONS}, found {tuple(options)}"
        )
    if set(requirements) != set(EXPECTED_REQUIREMENTS):
        missing = sorted(set(EXPECTED_REQUIREMENTS) - set(requirements))
        unexpected = sorted(set(requirements) - set(EXPECTED_REQUIREMENTS))
        raise AssertionError(
            f"requirements-dev.txt package set drifted; missing={missing or '[]'} unexpected={unexpected or '[]'}"
        )

    for package_name, expected in EXPECTED_REQUIREMENTS.items():
        locked = requirements[package_name]
        if locked["version"] != expected["version"]:
            raise AssertionError(
                f"requirements-dev.txt pinned {package_name} to {locked['version']} instead of {expected['version']}"
            )
        if locked["hashes"] != expected["hashes"]:
            raise AssertionError(
                f"requirements-dev.txt hashes drifted for {package_name}"
            )


def parse_readme_repository_tree(readme: str) -> set[str]:
    tree_match = re.search(
        r"^## Repository layout\s*\n+```text\n(.*?)\n```",
        readme,
        flags=re.MULTILINE | re.DOTALL,
    )
    if tree_match is None:
        raise AssertionError("README.md is missing its repository layout tree")

    tree_lines = tree_match.group(1).splitlines()
    if not tree_lines or tree_lines[0] != ".":
        raise AssertionError("README repository tree must start at the repository root")

    files: set[str] = set()
    directories: list[str] = []
    for line in tree_lines[1:]:
        entry_match = re.fullmatch(r"((?:(?:│   |    ))*)(?:├──|└──) (.+)", line)
        if entry_match is None:
            raise AssertionError(f"README repository tree has an invalid line: {line}")

        prefix, entry = entry_match.groups()
        depth = len(prefix) // 4
        if depth > len(directories):
            raise AssertionError(
                f"README repository tree has no parent directory for: {line}"
            )
        directories = directories[:depth]

        if entry.endswith("/"):
            directories.append(entry.removesuffix("/"))
            continue
        relative = "/".join([*directories, entry])
        if relative in files:
            raise AssertionError(
                f"README repository tree contains a duplicate file: {relative}"
            )
        files.add(relative)

    return files


def validate_readme_repository_tree(readme: str, package_files: set[str]) -> None:
    documented_files = parse_readme_repository_tree(readme)
    if documented_files != package_files:
        missing = sorted(package_files - documented_files)
        unexpected = sorted(documented_files - package_files)
        raise AssertionError(
            "README repository tree drifted from the package file list; "
            f"missing={missing or '[]'} unexpected={unexpected or '[]'}"
        )


def validate_readme_paths() -> None:
    readme = (SCRIPT_ROOT / "README.md").read_text(encoding="utf-8")
    referenced = set(
        re.findall(r"(?:--input|--arguments|--context)\s+([A-Za-z0-9_./-]+)", readme)
    )
    referenced.update(
        re.findall(
            r"`((?:architecture|data|examples|policy|schema|scripts)/[^`\s]+)`",
            readme,
        )
    )
    for relative in sorted(referenced):
        if "*" in relative:
            continue
        if not (SCRIPT_ROOT / relative).exists():
            raise AssertionError(f"README references a missing path: {relative}")

    package_files = set(package_files_for_root(SCRIPT_ROOT, include_manifest=True))
    validate_readme_repository_tree(readme, package_files)


def validate_release_metadata() -> None:
    version = (SCRIPT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    changelog = (SCRIPT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_match = re.search(
        r"^## ([0-9]+\.[0-9]+\.[0-9]+) - (\d{4}-\d{2}-\d{2})$",
        changelog,
        flags=re.MULTILINE,
    )
    if release_match is None:
        raise AssertionError("CHANGELOG.md is missing a dated release heading")

    changelog_version, release_date = release_match.groups()
    if changelog_version != version:
        raise AssertionError(
            f"VERSION is {version}, but the latest changelog release is {changelog_version}"
        )
    datetime.strptime(release_date, "%Y-%m-%d")

    validation = (SCRIPT_ROOT / "VALIDATION.md").read_text(encoding="utf-8")
    release_statement = f"Release **{version}** is dated **{release_date}**."
    if release_statement not in validation:
        raise AssertionError(
            "VALIDATION.md release version or date disagrees with VERSION and CHANGELOG.md"
        )
    validation_date_match = re.search(
        r"last executed on \*\*(\d{4}-\d{2}-\d{2})\*\*", validation
    )
    if validation_date_match is None:
        raise AssertionError("VALIDATION.md is missing its last-executed date")
    validation_date = datetime.strptime(
        validation_date_match.group(1), "%Y-%m-%d"
    ).date()
    if validation_date < datetime.strptime(release_date, "%Y-%m-%d").date():
        raise AssertionError("VALIDATION.md predates the current release")

    package_script = (SCRIPT_ROOT / "scripts/package.sh").read_text(encoding="utf-8")
    if re.search(r"^export TZ=UTC$", package_script, flags=re.MULTILINE) is None:
        raise AssertionError("Packaging must normalize the archive time zone to UTC")
    epoch_match = re.search(
        r'^: "\$\{SOURCE_DATE_EPOCH:=(\d+)\}"$',
        package_script,
        flags=re.MULTILINE,
    )
    if epoch_match is None:
        raise AssertionError(
            "scripts/package.sh is missing its default SOURCE_DATE_EPOCH"
        )
    archive_date = datetime.fromtimestamp(
        int(epoch_match.group(1)), tz=timezone.utc
    ).date()
    if archive_date.isoformat() != release_date:
        raise AssertionError(
            "The default archive timestamp date disagrees with CHANGELOG.md"
        )


PINNED_ACTION_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")
APPROVED_CHECKOUT_ACTION = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
)
APPROVED_SETUP_PYTHON_ACTION = (
    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
)
APPROVED_OPA_VERSION = "1.18.2"
APPROVED_OPA_SHA256 = (
    "9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8"
)


def assert_actions_are_sha_pinned(steps: list[dict[str, Any]], *, workflow: str) -> None:
    for step in steps:
        uses = step.get("uses")
        if uses and not PINNED_ACTION_SHA.match(uses):
            raise AssertionError(
                f"{workflow} uses an action that is not pinned to a commit SHA: {uses}"
            )


def validate_ci_job_hardening(
    job: dict[str, Any], workflow_text: str, *, workflow: str
) -> None:
    steps = job.get("steps", [])
    assert_actions_are_sha_pinned(steps, workflow=workflow)
    if job.get("runs-on") != "ubuntu-latest":
        raise AssertionError(f"{workflow} must run on ubuntu-latest")

    checkout_step = next(
        (
            step
            for step in steps
            if step.get("uses", "").startswith("actions/checkout@")
        ),
        None,
    )
    if checkout_step is None:
        raise AssertionError(f"{workflow} is missing the checkout step")
    if checkout_step.get("uses") != APPROVED_CHECKOUT_ACTION:
        raise AssertionError(
            f"{workflow} actions/checkout must use the approved commit SHA"
        )
    if checkout_step.get("with", {}).get("persist-credentials") is not False:
        raise AssertionError(f"{workflow} checkout must disable persist-credentials")

    setup_python = next(
        (
            step
            for step in steps
            if step.get("uses", "").startswith("actions/setup-python@")
        ),
        None,
    )
    if setup_python is None:
        raise AssertionError(f"{workflow} is missing the setup-python step")
    if setup_python.get("uses") != APPROVED_SETUP_PYTHON_ACTION:
        raise AssertionError(
            f"{workflow} actions/setup-python must use the approved commit SHA"
        )

    setup_python_with = setup_python.get("with", {})
    if setup_python_with.get("python-version") != "3.12":
        raise AssertionError(f"{workflow} must validate with Python 3.12")
    if setup_python_with.get("cache") != "pip":
        raise AssertionError(f"{workflow} must use setup-python's pip cache")
    cache_path = setup_python_with.get("cache-dependency-path")
    if cache_path != "requirements-dev.txt":
        raise AssertionError(
            f"{workflow} must key its pip cache from requirements-dev.txt"
        )
    if not (SCRIPT_ROOT / cache_path).is_file():
        raise AssertionError(
            f"{workflow} cache-dependency-path does not exist: {cache_path}"
        )

    env = job.get("env", {})
    if env.get("OPA_VERSION") != APPROVED_OPA_VERSION:
        raise AssertionError(f"{workflow} must pin OPA {APPROVED_OPA_VERSION}")
    if env.get("OPA_LINUX_AMD64_STATIC_SHA256") != APPROVED_OPA_SHA256:
        raise AssertionError(f"{workflow} must pin the approved OPA SHA-256 digest")

    install_step = next(
        (step for step in steps if step.get("name") == "Install Python validators"),
        None,
    )
    if install_step is None:
        raise AssertionError(f"{workflow} is missing the Python validator install step")
    install_run = str(install_step.get("run", ""))
    required_install_fragments = (
        "python -m pip install",
        "--disable-pip-version-check",
        "--only-binary=:all:",
        "--require-hashes",
        "--requirement requirements-dev.txt",
    )
    if not all(fragment in install_run for fragment in required_install_fragments):
        raise AssertionError(
            f"{workflow} must install validators from hash-locked binary wheels"
        )
    if "sha256sum --check --strict" not in workflow_text:
        raise AssertionError(
            f"{workflow} must verify the downloaded OPA binary SHA-256 digest"
        )
    if re.search(r"run:\s*make manifest\s*(?:\n|$)", workflow_text):
        raise AssertionError(
            f"{workflow} must not regenerate MANIFEST.sha256 before validating it"
        )
    if "make manifest-check" not in workflow_text:
        raise AssertionError(
            f"{workflow} must explicitly check the checked-in MANIFEST.sha256"
        )
    if "make validate" not in workflow_text:
        raise AssertionError(f"{workflow} must run make validate")


def validate_workflow() -> None:
    workflow_path = SCRIPT_ROOT / ".github/workflows/validate.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)

    if workflow.get("permissions") != {"contents": "read"}:
        raise AssertionError(
            "Workflow permissions must stay least-privileged with contents: read"
        )

    validate_job = workflow.get("jobs", {}).get("validate", {})
    validate_ci_job_hardening(
        validate_job, workflow_text, workflow="Validate workflow"
    )


def validate_release_workflow() -> None:
    workflow_path = SCRIPT_ROOT / ".github/workflows/release.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)

    if workflow.get("permissions") != {"contents": "read"}:
        raise AssertionError(
            "Release workflow must default to least-privileged contents: read"
        )

    # yaml.safe_load turns the bare `on:` key into True.
    triggers = workflow.get(True, workflow.get("on", {}))
    tags = triggers.get("push", {}).get("tags", [])
    if "v*" not in tags:
        raise AssertionError("Release workflow must trigger on v* tags")

    job = workflow.get("jobs", {}).get("release", {})
    steps = job.get("steps", [])
    validate_ci_job_hardening(job, workflow_text, workflow="Release workflow")

    expected_permissions = {
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }
    if job.get("permissions") != expected_permissions:
        raise AssertionError(
            "Release job must elevate exactly to contents, id-token, and attestations write"
        )

    attestation = next(
        (
            step
            for step in steps
            if step.get("uses", "").startswith("actions/attest-build-provenance@")
        ),
        None,
    )
    if attestation is None:
        raise AssertionError("Release workflow must attest build provenance")

    # Publishing an unvalidated or version-mismatched archive is the failure to prevent.
    for fragment, message in (
        ("make package", "Release workflow must build the release through make package"),
        ('!= "v${version}"', "Release workflow must verify the tag matches VERSION"),
        ("--verify-tag", "Release workflow must publish with --verify-tag"),
    ):
        if fragment not in workflow_text:
            raise AssertionError(message)


def validate_dependabot() -> None:
    config = yaml.safe_load(
        (SCRIPT_ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    )
    if config.get("version") != 2:
        raise AssertionError("Dependabot config must declare version 2")

    ecosystems = {update.get("package-ecosystem") for update in config.get("updates", [])}
    if "github-actions" not in ecosystems:
        raise AssertionError("Dependabot must keep the pinned action SHAs current")
    if "pip" in ecosystems:
        raise AssertionError(
            "Dependabot must not manage pip; automated bumps break the hash-locked graph"
        )


def validate_security_policy() -> None:
    policy = (SCRIPT_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    version = (SCRIPT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    minor_series = f"{'.'.join(version.split('.')[:2])}.x"

    for heading in (
        "## Scope",
        "## Supported versions",
        "## Reporting a vulnerability",
        "## In scope",
        "## Out of scope",
    ):
        if heading not in policy:
            raise AssertionError(f"SECURITY.md is missing the section: {heading}")

    if minor_series not in policy:
        raise AssertionError(
            f"SECURITY.md does not declare support for the current series {minor_series}"
        )
    if "Report a vulnerability" not in policy:
        raise AssertionError(
            "SECURITY.md must route reports through GitHub private vulnerability reporting"
        )


def validate_policy_source() -> None:
    rego = (SCRIPT_ROOT / "policy/mcp-tool-authorization.rego").read_text(
        encoding="utf-8"
    )
    required_fragments = (
        "time.now_ns()",
        "data.approval_records",
        "data.agent_control",
        "sha256_digest_valid(value) if {",
        "sha256_digest_valid(context.policy_bundle_digest)",
        "sha256_digest_valid(agent.agent_version)",
        "sha256_digest_valid(agent.credential_thumbprint)",
        "sha256_digest_valid(execution.credential_thumbprint)",
        'object.get(data.agent_control, "trusted_agent_credentials", {})',
        "sole_expected_audience := audience if {",
        "count(matched_audiences) == 1",
        'agent.credential_type in object.get(agent_trust_config, "credential_types", [])',
        'agent.credential_issuer in object.get(agent_trust_config, "credential_issuers", [])',
        'agent.attestation_profile in object.get(agent_trust_config, "attestation_profiles", [])',
        "execution.authority_chain_verified == true",
        "execution.authority_subject_principal_id == authority_subject.principal_id",
        "execution.agent_actor_principal_id == agent.agent_principal",
        "tool_config_valid if {",
        'type_name(tool_config.write) == "boolean"',
        'type_name(tool_config.requires_approval) == "boolean"',
        'tool_config.approval_mode in {"none", "confirmation", "independent"}',
        "approval_record.agent_definition_id == agent.agent_definition_id",
        "approval_record.agent_version == agent.agent_version",
        "approval_record.runtime_instance_id == agent.runtime_instance_id",
        "approval_record.agent_credential_thumbprint == agent.credential_thumbprint",
        "approval_record.expected_audience == execution.audiences[0]",
        "approval_record.sender_constraint == execution.sender_constraint",
        "approval_record.credential_profile == selected_credential_profile",
        "approval_record.single_use == true",
        "approval_record.consumed == false",
        "approval_record.approver_principal_id != agent.agent_principal",
        "approval_record.approver_principal_id != execution.principal_id",
        "expected_audiences_for_target",
        "execution.audiences[0] == sole_expected_audience",
        "action_canonicalizable",
        "sha256_digest_valid(action.arguments_digest)",
        'action.data_classification in {"public", "internal", "confidential", "restricted"}',
        "crypto.sha256(canonical_action_string)",
        "selected_credential_profile",
        "reason_codes := sort([code | allow_reason_codes[code]])",
        "expected_audiences := sort([",
    )
    for fragment in required_fragments:
        if fragment not in rego:
            raise AssertionError(f"Required Rego control is absent: {fragment}")

    forbidden = (
        "input.context.now",
        "input.authorization",
        "input.approval.status",
        "input.request.now",
        "execution.delegation_verified",
        'object.get(input, "now"',
    )
    for fragment in forbidden:
        if fragment in rego:
            raise AssertionError(
                f"Forbidden or legacy Rego path is present: {fragment}"
            )

    tests_path = SCRIPT_ROOT / "policy/mcp-tool-authorization_test.rego"
    if not tests_path.is_file():
        raise AssertionError("policy/mcp-tool-authorization_test.rego is required")
    tests = tests_path.read_text(encoding="utf-8")
    discovered = set(
        re.findall(r"^(test_[A-Za-z0-9_]+)\s+if\s*\{", tests, flags=re.MULTILINE)
    )
    if discovered != EXPECTED_POLICY_TESTS:
        missing = sorted(EXPECTED_POLICY_TESTS - discovered)
        unexpected = sorted(discovered - EXPECTED_POLICY_TESTS)
        raise AssertionError(
            f"Policy tests drifted from the expected {len(EXPECTED_POLICY_TESTS)}-case suite; "
            f"missing={missing or '[]'} unexpected={unexpected or '[]'}"
        )
    if len(discovered) != len(EXPECTED_POLICY_TESTS):
        raise AssertionError(
            f"Policy test suite must contain exactly {len(EXPECTED_POLICY_TESTS)} tests, found {len(discovered)}"
        )
    if "object.union(base_input, patch)" in tests:
        raise AssertionError(
            "Policy tests use a shallow top-level patch that can erase verified context"
        )

    shell_gate = (SCRIPT_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
    for fragment in (
        "opa fmt --fail --check-result -l",
        "opa check --strict",
        "opa test policy data --fail-on-empty",
    ):
        if fragment not in shell_gate:
            raise AssertionError(f"OPA release gate is incomplete: {fragment}")


def validate_privacy() -> None:
    pii_email = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
    text_suffixes = {".md", ".json", ".yaml", ".yml", ".rego", ".dot", ".py", ".sh"}
    # Scoped to packageable sources; local tooling noise never reaches the archive.
    for relative in sorted(discover_files(SCRIPT_ROOT, apply_source_ignores=True)):
        path = SCRIPT_ROOT / relative
        if path.suffix.lower() not in text_suffixes:
            continue
        text = path.read_text(encoding="utf-8")
        if pii_email.search(text):
            raise AssertionError(f"Potential direct email address found in {relative}")


def assert_json_match(expected: Any, actual: Any, label: str) -> None:
    if actual != expected:
        raise AssertionError(
            f"{label} drifted:\nexpected={json.dumps(expected, indent=2, sort_keys=True)}\nactual={json.dumps(actual, indent=2, sort_keys=True)}"
        )


def validate_tool_configs(agent_control: dict[str, Any]) -> None:
    allowed_modes = {"user_delegated", "agent_own", "brokered_service"}
    allowed_approval_modes = {"none", "confirmation", "independent"}
    allowed_risk_tiers = {"low", "medium", "high", "critical"}

    servers = agent_control.get("servers")
    if not isinstance(servers, dict) or not servers:
        raise AssertionError("agent_control.servers must be a non-empty object")

    for server_name, server in servers.items():
        tools = server.get("tools") if isinstance(server, dict) else None
        if not isinstance(tools, dict) or not tools:
            raise AssertionError(f"Server {server_name} must define a non-empty tools object")

        for tool_name, tool in tools.items():
            label = f"Tool {server_name}/{tool_name}"
            if not isinstance(tool, dict):
                raise AssertionError(f"{label} configuration must be an object")
            if type(tool.get("write")) is not bool:
                raise AssertionError(f"{label} write must be an explicit boolean")
            if type(tool.get("requires_approval")) is not bool:
                raise AssertionError(
                    f"{label} requires_approval must be an explicit boolean"
                )
            if tool.get("approval_mode") not in allowed_approval_modes:
                raise AssertionError(f"{label} approval_mode is missing or invalid")
            if tool.get("risk_tier") not in allowed_risk_tiers:
                raise AssertionError(f"{label} risk_tier is missing or invalid")

            ttl = tool.get("max_credential_ttl_seconds")
            if type(ttl) is not int or not 1 <= ttl <= 86400:
                raise AssertionError(
                    f"{label} max_credential_ttl_seconds must be an integer from 1 to 86400"
                )

            profiles = tool.get("credential_profiles")
            if not isinstance(profiles, dict) or not profiles:
                raise AssertionError(
                    f"{label} credential_profiles must be a non-empty object"
                )
            for mode, profile in profiles.items():
                if mode not in allowed_modes:
                    raise AssertionError(
                        f"{label} has an unsupported credential profile mode: {mode}"
                    )
                if not isinstance(profile, str) or not profile:
                    raise AssertionError(
                        f"{label} credential profile for {mode} must be a non-empty string"
                    )


def validate_examples_and_policy_data() -> tuple[str, str, str, str, str, str, str]:
    validate_schema(
        "schema/authorization-context.schema.json",
        "examples/authorization-context.example.json",
    )
    validate_schema(
        "schema/agent-action-audit-event.schema.json",
        "examples/agent-action-event.example.json",
    )

    authz = load_json("examples/authorization-context.example.json")
    audit = load_json("examples/agent-action-event.example.json")
    authz_yaml = yaml.safe_load(
        (SCRIPT_ROOT / "examples/authorization-context.example.yaml").read_text(
            encoding="utf-8"
        )
    )
    if authz != authz_yaml:
        raise AssertionError("The JSON and YAML authorization examples diverge")

    fixtures = load_json("data/test-fixtures.json")
    expected_fixtures = {"test_fixtures": {"valid_input": authz}}
    assert_json_match(expected_fixtures, fixtures, "data/test-fixtures.json")

    if authz["schema_version"] != "1.3":
        raise AssertionError("Authorization example must use schema_version 1.3")
    if audit["schema_version"] != "1.3":
        raise AssertionError("Audit example must use schema_version 1.3")

    arguments = load_json("examples/action-arguments.example.json")
    verified = authz["verified"]
    agent = verified["agent"]
    execution = verified["execution"]
    action = verified["action"]
    context = verified["context"]

    expected_arguments_digest = sha256_prefixed(canonical_json_bytes(arguments))
    if action["arguments_digest"] != expected_arguments_digest:
        raise AssertionError(
            "arguments_digest does not match canonical example arguments"
        )

    expected_action_hash = sha256_prefixed(
        action_canonical_string(action).encode("utf-8")
    )
    if action["canonical_hash"] != expected_action_hash:
        raise AssertionError(
            "canonical_hash does not match the documented action profile"
        )

    agent_control = load_json("data/agent-control.json")["agent_control"]
    validate_tool_configs(agent_control)
    policy_bytes = (SCRIPT_ROOT / "policy/mcp-tool-authorization.rego").read_bytes()
    expected_policy_digest = sha256_prefixed(
        b"mcp-agent-policy-bundle-v1\n"
        + policy_bytes
        + b"\n"
        + canonical_json_bytes(agent_control)
    )
    if context["policy_bundle_digest"] != expected_policy_digest:
        raise AssertionError(
            "policy_bundle_digest does not match policy plus trusted configuration"
        )

    if agent["credential_verified"] is not True:
        raise AssertionError("Agent credential verification must be true")
    if execution["credential_verified"] is not True:
        raise AssertionError("Execution credential verification must be true")
    if execution["authority_chain_verified"] is not True:
        raise AssertionError("authority_chain_verified must be true")
    if (
        execution["authority_subject_principal_id"]
        != verified["authority_subject"]["principal_id"]
    ):
        raise AssertionError(
            "Execution credential context is not linked to the authority subject"
        )
    if execution["agent_actor_principal_id"] != agent["agent_principal"]:
        raise AssertionError(
            "Execution credential context is not linked to the agent actor"
        )

    trusted_agent_credentials = agent_control["trusted_agent_credentials"]
    if agent["agent_principal"] not in trusted_agent_credentials:
        raise AssertionError(
            "Agent principal is missing from trusted_agent_credentials"
        )
    agent_trust_config = trusted_agent_credentials[agent["agent_principal"]]
    if agent["credential_type"] not in agent_trust_config["credential_types"]:
        raise AssertionError(
            "Agent credential_type is not trusted for the live agent principal"
        )
    if agent["credential_issuer"] not in agent_trust_config["credential_issuers"]:
        raise AssertionError(
            "Agent credential_issuer is not trusted for the live agent principal"
        )
    if agent["attestation_profile"] not in agent_trust_config["attestation_profiles"]:
        raise AssertionError(
            "Agent attestation_profile is not trusted for the live agent principal"
        )

    approval_id = authz["request"]["approval_id"]
    approvals = load_json("data/approval-records.example.json")["approval_records"]
    if approval_id not in approvals:
        raise AssertionError(
            "Authorization example references a missing trusted approval record"
        )
    approval = approvals[approval_id]

    server = agent_control["servers"][action["mcp_server"]]
    tool = server["tools"][action["tool"]]
    entitlement = agent_control["entitlements"][agent["agent_principal"]]
    permission = entitlement["server_permissions"][action["mcp_server"]]
    expected_audiences = sorted(
        {
            binding["audience"]
            for binding in server["audience_bindings"]
            if target_matches(binding["target_pattern"], action["target"])
        }
    )
    if expected_audiences != execution["audiences"]:
        raise AssertionError("Execution audience is not uniquely bound to the target")
    if execution["issuer"] not in server["trusted_issuers"]:
        raise AssertionError("Execution issuer is not trusted by policy data")
    if execution["sender_constraint"] not in server["allowed_sender_constraints"]:
        raise AssertionError("Execution sender constraint is not allowed")
    if action["tool"] not in permission["allowed_tools"]:
        raise AssertionError("Example tool is not entitled")
    if not any(
        target_matches(pattern, action["target"])
        for pattern in permission["allowed_targets"]
    ):
        raise AssertionError("Example target is not entitled")
    if context["environment"] not in entitlement["allowed_environments"]:
        raise AssertionError("Example environment is not entitled")
    if execution["principal_id"] not in entitlement["allowed_execution_principals"]:
        raise AssertionError("Execution principal is not entitled")
    if execution["authority_mode"] not in entitlement["allowed_authority_modes"]:
        raise AssertionError("Authority mode is not entitled")

    credential_profile = tool["credential_profiles"].get(execution["authority_mode"])
    if not credential_profile:
        raise AssertionError(
            "Credential profile is not configured for the authority mode"
        )
    if (
        context["environment"] == "production"
        and tool["write"]
        and permission.get("production_write_allowed") is not True
    ):
        raise AssertionError(
            "Production write permission is absent from trusted policy data"
        )

    issued_at = parse_rfc3339(execution["issued_at"])
    not_before = parse_rfc3339(execution["not_before"])
    expires_at = parse_rfc3339(execution["expires_at"])
    if not_before > expires_at or issued_at >= expires_at:
        raise AssertionError("Execution credential timestamps are inconsistent")
    lifetime_seconds = int((expires_at - issued_at).total_seconds())
    if lifetime_seconds > tool["max_credential_ttl_seconds"]:
        raise AssertionError(
            "Execution credential exceeds the tool-specific maximum lifetime"
        )

    if approval["status"] != "approved":
        raise AssertionError("Trusted approval must be in approved status")
    required_approval_bindings = {
        "action_hash": expected_action_hash,
        "requester_principal_id": verified["requester"]["principal_id"],
        "authority_subject_principal_id": verified["authority_subject"]["principal_id"],
        "agent_principal": agent["agent_principal"],
        "environment": context["environment"],
        "policy_bundle_digest": expected_policy_digest,
        "authority_mode": execution["authority_mode"],
        "execution_principal_id": execution["principal_id"],
        "expected_audience": expected_audiences[0],
        "sender_constraint": execution["sender_constraint"],
        "credential_profile": credential_profile,
        "single_use": True,
        "consumed": False,
        "agent_definition_id": agent["agent_definition_id"],
        "agent_version": agent["agent_version"],
        "runtime_instance_id": agent["runtime_instance_id"],
        "agent_credential_thumbprint": agent["credential_thumbprint"],
    }
    for field, expected_value in required_approval_bindings.items():
        if approval.get(field) != expected_value:
            raise AssertionError(f"Approval binding mismatch: {field}")

    approver = approval.get("approver_principal_id", "")
    if not approver:
        raise AssertionError("Approval approver_principal_id must be non-empty")
    if approver in {
        verified["requester"]["principal_id"],
        verified["authority_subject"]["principal_id"],
        agent["agent_principal"],
        execution["principal_id"],
    }:
        raise AssertionError("Independent approval example is self-approved")

    approved_at = parse_rfc3339(approval["approved_at"])
    approval_expires = parse_rfc3339(approval["expires_at"])
    if approved_at >= approval_expires:
        raise AssertionError("Approval expiry must be later than approval time")

    expected_requires_approval = tool["requires_approval"] or (
        context["environment"] == "production" and tool["write"]
    )
    if not expected_requires_approval:
        raise AssertionError("The release example must require approval")

    decision = audit["decision"]
    expected_audit_approval = {
        "required": True,
        "status": "approved",
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
        "consumed": True,
        "consumed_at": decision["evaluated_at"],
        "consumption_id": f"{authz['request']['approval_id']}:{audit['event_id']}",
        "action_hash": approval["action_hash"],
        "approved_at": approval["approved_at"],
        "expires_at": approval["expires_at"],
    }
    assert_json_match(expected_audit_approval, audit["approval"], "Audit approval")

    evaluated_at = parse_rfc3339(decision["evaluated_at"])
    consumed_at = parse_rfc3339(audit["approval"]["consumed_at"])
    completed_at = parse_rfc3339(audit["result"]["completed_at"])
    occurred_at = parse_rfc3339(audit["occurred_at"])
    if not (issued_at <= evaluated_at < expires_at):
        raise AssertionError(
            "Audit decision evaluated_at must fall within the execution credential validity window"
        )
    if not (approved_at <= evaluated_at < approval_expires):
        raise AssertionError(
            "Audit decision evaluated_at must fall within the approval validity window"
        )
    if not (evaluated_at <= consumed_at <= completed_at <= occurred_at):
        raise AssertionError(
            "Audit consumption and completion timestamps are not causally ordered"
        )

    expected_decision = {
        "allow": True,
        "authority_mode": execution["authority_mode"],
        "requires_approval": True,
        "deny_reasons": [],
        "reason_codes": EXPECTED_ALLOW_REASON_CODES,
        "risk_tier": tool["risk_tier"],
        "credential_profile": credential_profile,
        "credential_ttl_seconds": tool["max_credential_ttl_seconds"],
        "expected_audiences": expected_audiences,
        "policy_id": agent_control["policy_id"],
        "policy_version": agent_control["policy_version"],
        "evaluated_at": decision["evaluated_at"],
    }
    assert_json_match(expected_decision, decision, "Audit decision")

    if audit["context"]["policy_bundle_digest"] != expected_policy_digest:
        raise AssertionError("Audit event references a different policy bundle")
    if audit["execution"] != execution:
        raise AssertionError(
            "Audit event and authorization envelope disagree on execution identity"
        )
    if audit["agent"] != agent:
        raise AssertionError(
            "Audit event and authorization envelope disagree on the agent identity"
        )
    if audit["requester"]["principal_id"] != verified["requester"]["principal_id"]:
        raise AssertionError(
            "Audit requester principal_id does not match the authorization example"
        )
    if (
        audit["authority_subject"]["principal_id"]
        != verified["authority_subject"]["principal_id"]
    ):
        raise AssertionError(
            "Audit authority_subject principal_id does not match the authorization example"
        )
    if audit["action"]["canonical_hash"] != expected_action_hash:
        raise AssertionError(
            "Audit action hash does not match the authorization action hash"
        )

    evidence = audit["evidence"]
    if evidence["digest_profile"] != PROFILE_NAME:
        raise AssertionError(f"Audit digest_profile must be {PROFILE_NAME}")
    audit_for_digest = copy.deepcopy(audit)
    audit_for_digest["evidence"].pop("record_digest", None)
    expected_record_digest = sha256_prefixed(canonical_json_bytes(audit_for_digest))
    if evidence["record_digest"] != expected_record_digest:
        raise AssertionError("Audit record_digest is inconsistent")

    negative = copy.deepcopy(authz)
    negative["request"]["now"] = "2099-01-01T00:00:00Z"
    assert_schema_rejects(
        "schema/authorization-context.schema.json", negative, "caller-supplied now"
    )

    negative = copy.deepcopy(authz)
    negative["request"]["authorization"] = {"production_write_allowed": True}
    assert_schema_rejects(
        "schema/authorization-context.schema.json",
        negative,
        "caller-supplied entitlements",
    )

    negative = copy.deepcopy(authz)
    negative["approval"] = {"status": "approved"}
    assert_schema_rejects(
        "schema/authorization-context.schema.json",
        negative,
        "caller-supplied approval state",
    )

    negative = copy.deepcopy(authz)
    negative["verified"]["execution"]["audiences"].append(
        "https://unrelated.example.internal"
    )
    assert_schema_rejects(
        "schema/authorization-context.schema.json", negative, "multiple audiences"
    )

    negative = copy.deepcopy(authz)
    negative["verified"]["action"]["target"] = (
        "scm://platform/example\nmethod=tools/call"
    )
    assert_schema_rejects(
        "schema/authorization-context.schema.json",
        negative,
        "newline-bearing action target",
    )

    negative = copy.deepcopy(authz)
    negative["verified"]["execution"]["issuer"] = "not a URI"
    assert_schema_rejects(
        "schema/authorization-context.schema.json",
        negative,
        "invalid execution issuer URI",
    )

    negative = copy.deepcopy(authz)
    negative["verified"]["execution"]["authority_chain_verified"] = False
    assert_schema_rejects(
        "schema/authorization-context.schema.json",
        negative,
        "false authority-chain verification",
    )

    negative = copy.deepcopy(audit)
    negative["approval"].pop("execution_principal_id", None)
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "missing audit execution_principal_id",
    )

    negative = copy.deepcopy(audit)
    negative["approval"]["single_use"] = False
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "audit single_use must stay true",
    )

    positive = copy.deepcopy(audit)
    positive["decision"]["allow"] = False
    positive["decision"]["authority_mode"] = "unknown"
    positive["decision"]["deny_reasons"] = ["APPROVAL_MISSING"]
    positive["decision"]["reason_codes"] = []
    positive["decision"]["credential_profile"] = "none"
    positive["decision"]["credential_ttl_seconds"] = 0
    positive["decision"]["expected_audiences"] = []
    positive["approval"] = {
        "required": True,
        "status": "missing",
    }
    positive["execution"] = {
        "authority_chain_verified": False,
        "credential_verified": False,
    }
    positive["agent"] = {"credential_verified": False}
    positive["result"]["status"] = "blocked"
    positive["result"].pop("target_event_id", None)
    assert_schema_accepts(
        "schema/agent-action-audit-event.schema.json", positive, "audit deny path"
    )

    negative = copy.deepcopy(positive)
    negative["approval"]["approved_at"] = audit["approval"]["approved_at"]
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "missing approval must not carry approval evidence",
    )

    negative = copy.deepcopy(audit)
    negative["decision"]["expected_audiences"] = []
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "allowed audit must include one expected audience",
    )

    negative = copy.deepcopy(audit)
    negative["agent"].pop("credential_issuer", None)
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "allowed audit must include complete agent evidence",
    )

    negative = copy.deepcopy(audit)
    negative["execution"]["authority_chain_verified"] = False
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "allowed audit must keep authority-chain verification true",
    )

    negative = copy.deepcopy(audit)
    negative["approval"]["consumed"] = False
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "successful audit approval must be marked consumed",
    )

    negative = copy.deepcopy(audit)
    negative["approval"].pop("consumed_at", None)
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "consumed approval must include consumed_at",
    )

    negative = copy.deepcopy(audit)
    negative["approval"].pop("consumption_id", None)
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "consumed approval must include consumption_id",
    )

    negative = copy.deepcopy(audit)
    negative["decision"]["reason_codes"].append(negative["decision"]["reason_codes"][0])
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "duplicate decision reason_codes",
    )

    negative = copy.deepcopy(audit)
    negative["evidence"]["digest_profile"] = "canonical-json-sort-keys-v2"
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json", negative, "legacy digest profile"
    )

    negative = copy.deepcopy(audit)
    negative["decision"]["evaluated_at"] = "not a timestamp"
    assert_schema_rejects(
        "schema/agent-action-audit-event.schema.json",
        negative,
        "invalid decision timestamp",
    )

    return (
        authz["schema_version"],
        agent_control["policy_version"],
        expected_arguments_digest,
        expected_action_hash,
        expected_policy_digest,
        expected_record_digest,
        evidence["digest_profile"],
    )


def assert_required_files() -> None:
    actual = discover_files(SCRIPT_ROOT, apply_source_ignores=True)
    validate_package_file_set(actual, context="the source tree")
    for relative in actual:
        path = Path(relative)
        lowered = relative.lower()
        if path.suffix.lower() in PROHIBITED_SOURCE_SUFFIXES:
            raise AssertionError(
                f"Prohibited file type is packageable from the source tree: {relative}"
            )
        if any(term in lowered for term in SUSPICIOUS_SOURCE_TERMS):
            raise AssertionError(
                f"Potential accidental or organization-specific file is packageable: {relative}"
            )


def validate_source_tree(*, skip_manifest_check: bool) -> int:
    validate_python_runtime()
    validate_canonical_json_profile()
    validate_package_allowlist_self_tests()
    assert_required_files()
    validate_gitignore()
    validate_requirements()
    validate_readme_paths()
    validate_release_metadata()
    validate_workflow()
    validate_release_workflow()
    validate_dependabot()
    validate_security_policy()
    validate_policy_source()
    (
        schema_version,
        policy_version,
        arguments_digest,
        action_hash,
        policy_digest,
        record_digest,
        digest_profile,
    ) = validate_examples_and_policy_data()
    if not skip_manifest_check:
        check_manifest(SCRIPT_ROOT)
    validate_privacy()

    print("Artifact validation passed")
    print(f"Schema version: {schema_version}")
    print(f"Policy version: {policy_version}")
    print(f"Arguments digest: {arguments_digest}")
    print(f"Action hash: {action_hash}")
    print(f"Policy bundle digest: {policy_digest}")
    print(f"Audit record digest: {record_digest}")
    print(f"Audit digest profile: {digest_profile}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-manifest-check",
        action="store_true",
        help="Run structural validation without requiring the checked-in MANIFEST.sha256 to already match.",
    )
    subparsers = parser.add_subparsers(dest="command")

    print_files = subparsers.add_parser(
        "print-package-files", help="Print the explicit package allowlist."
    )
    print_files.add_argument(
        "--exclude-manifest",
        action="store_true",
        help="Exclude MANIFEST.sha256 from the printed list.",
    )

    write_manifest_parser = subparsers.add_parser(
        "write-manifest", help="Write a MANIFEST.sha256 for a package tree."
    )
    write_manifest_parser.add_argument("root", nargs="?", default=".")
    write_manifest_parser.add_argument("output", nargs="?")

    check_manifest_parser = subparsers.add_parser(
        "check-manifest", help="Verify MANIFEST.sha256 matches the current tree."
    )
    check_manifest_parser.add_argument("root", nargs="?", default=".")

    verify_tree_parser = subparsers.add_parser(
        "verify-package-tree",
        help="Verify a package tree against the allowlist and manifest.",
    )
    verify_tree_parser.add_argument("root", nargs="?", default=".")

    normalize_modes_parser = subparsers.add_parser(
        "normalize-package-modes",
        help="Set canonical permissions on every package file.",
    )
    normalize_modes_parser.add_argument("root", nargs="?", default=".")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "print-package-files":
        files = package_files_for_root(
            SCRIPT_ROOT, include_manifest=not args.exclude_manifest
        )
        print("\n".join(files))
        return 0

    if args.command == "write-manifest":
        root = Path(args.root).resolve()
        output = Path(args.output).resolve() if args.output else None
        manifest_path = write_manifest(root, output)
        print(manifest_path)
        return 0

    if args.command == "check-manifest":
        check_manifest(Path(args.root).resolve())
        print("MANIFEST.sha256 matches the current tree")
        return 0

    if args.command == "verify-package-tree":
        verify_package_tree(Path(args.root).resolve())
        print(f"Package tree verified: {Path(args.root).resolve()}")
        return 0

    if args.command == "normalize-package-modes":
        root = Path(args.root).resolve()
        normalize_package_modes(root)
        print(f"Package modes normalized: {root}")
        return 0

    return validate_source_tree(skip_manifest_check=args.skip_manifest_check)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)

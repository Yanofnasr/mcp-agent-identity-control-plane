#!/usr/bin/env python3
"""Deterministic restricted-JSON parsing and serialization helpers.

Object names sort lexicographically by Unicode scalar-value sequences without
Unicode normalization. This local profile intentionally differs from profiles
that use UTF-16 code-unit ordering.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_SAFE_INTEGER = (1 << 53) - 1
PROFILE_NAME = "restricted-json-sort-keys-v1"


class CanonicalJSONError(ValueError):
    """Raised when input violates the restricted canonical JSON profile."""


def _parse_constant(token: str) -> Any:
    raise CanonicalJSONError(f"Non-finite JSON number is not allowed: {token}")


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"Duplicate object key is not allowed: {key}")
        result[key] = value
    return result


def load_canonical_json(path: Path) -> Any:
    return loads_canonical_json(path.read_text(encoding="utf-8"))


def loads_canonical_json(payload: str) -> Any:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_object_pairs,
            parse_constant=_parse_constant,
        )
    except json.JSONDecodeError as exc:
        raise CanonicalJSONError(
            f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    validate_canonical_json(value)
    return value


def _validate_unicode_scalar(value: str, path: str) -> None:
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError(
            f"Invalid Unicode scalar at {path}: lone surrogate"
        ) from exc


def _validate_safe_integer(value: int, path: str) -> None:
    if not (-MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER):
        raise CanonicalJSONError(
            f"Integer at {path} exceeds the exact IEEE-754 safe range: {value}"
        )


def validate_canonical_json(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        _validate_safe_integer(value, path)
        return
    if isinstance(value, float):
        raise CanonicalJSONError(f"Floating-point numbers are not allowed at {path}")
    if isinstance(value, str):
        _validate_unicode_scalar(value, path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_canonical_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(f"Object key at {path} must be a string")
            _validate_unicode_scalar(key, f"{path}.<key>")
            validate_canonical_json(item, f"{path}.{key}")
        return
    raise CanonicalJSONError(
        f"Unsupported JSON value at {path}: {type(value).__name__}"
    )


def _serialize_string(value: str) -> str:
    parts = ['"']
    for ch in value:
        codepoint = ord(ch)
        if ch == '"':
            parts.append('\\"')
        elif ch == "\\":
            parts.append("\\\\")
        elif ch == "\b":
            parts.append("\\b")
        elif ch == "\f":
            parts.append("\\f")
        elif ch == "\n":
            parts.append("\\n")
        elif ch == "\r":
            parts.append("\\r")
        elif ch == "\t":
            parts.append("\\t")
        elif codepoint <= 0x1F:
            parts.append(f"\\u{codepoint:04x}")
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _serialize_canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize_canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value):
            items.append(
                f"{_serialize_string(key)}:{_serialize_canonical_json(value[key])}"
            )
        return "{" + ",".join(items) + "}"
    raise CanonicalJSONError(f"Unsupported JSON value: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    validate_canonical_json(value)
    return _serialize_canonical_json(value).encode("utf-8")

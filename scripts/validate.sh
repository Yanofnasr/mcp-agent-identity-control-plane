#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/validate_artifacts.py

if ! command -v opa >/dev/null 2>&1; then
  echo "OPA is required for the Rego runtime gate." >&2
  echo "Install OPA 1.x and rerun make validate." >&2
  exit 1
fi

opa fmt --fail --check-result -l policy/*.rego
opa check --strict policy
opa test policy data --fail-on-empty -v
python3 scripts/evaluate_example.py --opa "$(command -v opa)"

echo "All structural and OPA runtime gates passed."

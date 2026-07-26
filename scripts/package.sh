#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
OUT="${1:-$ROOT/../mcp-agent-identity-reference-${VERSION}.zip}"
OUT="$(realpath -m "$OUT")"

if [[ "$OUT" == "$ROOT"/* ]]; then
  echo "Refusing to write the archive inside the source tree: $OUT" >&2
  exit 1
fi

cd "$ROOT"
python3 scripts/update_derived_values.py
make diagrams
python3 scripts/validate_artifacts.py
make manifest
sha256sum --check --strict MANIFEST.sha256

TMP="$(mktemp -d -t mcp-agent-identity-package.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/mcp-agent-identity-reference"
mkdir -p "$STAGE"

rsync -a \
  --exclude '.git/' \
  --exclude '__pycache__/' \
  --exclude '.DS_Store' \
  "$ROOT/" "$STAGE/"

# Normalize archive timestamps without changing the source tree.
find "$STAGE" -exec touch -h -d '@1785196800' {} +
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
(
  cd "$TMP"
  LC_ALL=C find mcp-agent-identity-reference -type f -print | LC_ALL=C sort | zip -X -q "$OUT" -@
)

printf 'Created %s\n' "$OUT"
sha256sum "$OUT"

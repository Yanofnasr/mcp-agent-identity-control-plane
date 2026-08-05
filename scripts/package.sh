#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
OUT="${1:-$ROOT/../mcp-agent-identity-reference-${VERSION}.zip}"
OUT="$(realpath -m "$OUT")"
export PYTHONDONTWRITEBYTECODE=1
export TZ=UTC

if [[ "$OUT" == "$ROOT"/* ]]; then
  echo "Refusing to write the archive inside the source tree: $OUT" >&2
  exit 1
fi

cd "$ROOT"
python3 scripts/validate_artifacts.py

TMP="$(mktemp -d -t mcp-agent-identity-package.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/mcp-agent-identity-reference"
EXTRACT="$TMP/extracted"
mkdir -p "$STAGE"

while IFS= read -r relative; do
  mkdir -p "$STAGE/$(dirname "$relative")"
  cp -p "$ROOT/$relative" "$STAGE/$relative"
done < <(python3 scripts/validate_artifacts.py print-package-files)

# Graphviz output is version-dependent, so diagram refresh is a local developer gate.
# Archive integrity never depends on it: MANIFEST.sha256 pins the shipped bytes.
REFRESH_DIAGRAMS=1
if ! command -v dot >/dev/null 2>&1; then
  if [[ "${PACKAGE_ALLOW_MISSING_GRAPHVIZ:-0}" != "1" ]]; then
    echo "Graphviz (dot) is required to verify the checked-in diagrams match their sources." >&2
    echo "Install graphviz, or set PACKAGE_ALLOW_MISSING_GRAPHVIZ=1 to package without" >&2
    echo "that check on a tree whose manifest has already been verified." >&2
    exit 1
  fi
  REFRESH_DIAGRAMS=0
  echo "notice: graphviz absent; skipping the diagram source-consistency check" >&2
fi

(
  cd "$STAGE"
  python3 scripts/update_derived_values.py
  if [[ "$REFRESH_DIAGRAMS" == "1" ]]; then
    make diagrams
  fi
  python3 scripts/validate_artifacts.py --skip-manifest-check
)

REGENERATED_ARTIFACTS=(
  data/approval-records.example.json
  data/test-fixtures.json
  examples/agent-action-event.example.json
  examples/authorization-context.example.json
  examples/authorization-context.example.yaml
)
if [[ "$REFRESH_DIAGRAMS" == "1" ]]; then
  REGENERATED_ARTIFACTS+=(
    architecture/agent-identity-control-plane.png
    architecture/agent-identity-control-plane.svg
    architecture/four-principal-control-plane.png
    architecture/four-principal-control-plane.svg
  )
fi

for relative in "${REGENERATED_ARTIFACTS[@]}"; do
  if ! cmp -s "$ROOT/$relative" "$STAGE/$relative"; then
    echo "Generated source artifact is stale: $relative" >&2
    echo "Refresh tracked derived artifacts in the source tree before packaging." >&2
    exit 1
  fi
done

python3 scripts/validate_artifacts.py write-manifest "$STAGE"
python3 scripts/validate_artifacts.py verify-package-tree "$STAGE"
(
  cd "$STAGE"
  sha256sum --check --strict MANIFEST.sha256
)

# Default reproducible archive mtime: 2026-08-05 UTC.
: "${SOURCE_DATE_EPOCH:=1785888000}"
find "$STAGE" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
(
  cd "$TMP"
  LC_ALL=C find mcp-agent-identity-reference -type f -print | LC_ALL=C sort | zip -X -q "$OUT" -@
)

mkdir -p "$EXTRACT"
unzip -q "$OUT" -d "$EXTRACT"
python3 "$EXTRACT/mcp-agent-identity-reference/scripts/validate_artifacts.py" verify-package-tree \
  "$EXTRACT/mcp-agent-identity-reference"
(
  cd "$EXTRACT/mcp-agent-identity-reference"
  sha256sum --check --strict MANIFEST.sha256
)

printf 'Created %s\n' "$OUT"
sha256sum "$OUT"

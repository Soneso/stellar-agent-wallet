#!/usr/bin/env bash
# Fails if the gate tool versions pinned in docs/maintainers/building.md drift
# from the tool: pins in .github/workflows/ci.yml, so a maintainer following
# the doc can't end up running a different cargo-llvm-cov/cargo-machete/
# cargo-deny than CI and getting different gate results.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CI_FILE="$ROOT/.github/workflows/ci.yml"
BUILDING_DOC="$ROOT/docs/maintainers/building.md"

TOOLS=(cargo-llvm-cov cargo-machete cargo-deny)
MISMATCH=0

for tool in "${TOOLS[@]}"; do
  ci_version=$(grep -oE "tool: ${tool}@[0-9][0-9.]*" "$CI_FILE" | head -1 | cut -d@ -f2 || true)
  if [ -z "$ci_version" ]; then
    echo "error: no 'tool: ${tool}@<version>' pin found in ${CI_FILE#"$ROOT"/}" >&2
    exit 1
  fi

  doc_version=$(grep -oE -- "--locked ${tool} --version [0-9][0-9.]*" "$BUILDING_DOC" | head -1 | awk '{print $NF}' || true)
  if [ -z "$doc_version" ]; then
    echo "error: no '--locked ${tool} --version <version>' line found in ${BUILDING_DOC#"$ROOT"/}" >&2
    exit 1
  fi

  if [ "$ci_version" != "$doc_version" ]; then
    echo "error: ${tool} version mismatch:" >&2
    echo "  ${CI_FILE#"$ROOT"/} pins ${ci_version}" >&2
    echo "  ${BUILDING_DOC#"$ROOT"/} pins ${doc_version}" >&2
    MISMATCH=1
  fi
done

if [ "$MISMATCH" -ne 0 ]; then
  exit 1
fi

echo "gate tool versions match between ci.yml and building.md"

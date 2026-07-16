#!/usr/bin/env bash
# Offline regression checks for publish-crates.sh --check.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/publish-crates.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cd "$ROOT"
env -u CARGO_REGISTRY_TOKEN bash "$SCRIPT" --check >"$TMP/valid.out"
grep -q "match every workspace member exactly once" "$TMP/valid.out"

cp "$SCRIPT" "$TMP/missing.sh"
sed -i.bak 's/ stellar-agent-mpp//' "$TMP/missing.sh"
if env -u CARGO_REGISTRY_TOKEN bash "$TMP/missing.sh" --check >"$TMP/missing.out" 2>&1; then
  echo "missing tier member unexpectedly passed" >&2
  exit 1
fi
grep -q "Tier lists do not match" "$TMP/missing.out"

cp "$SCRIPT" "$TMP/duplicate.sh"
sed -i.bak 's/stellar-agent-mpp stellar-agent-x402/stellar-agent-mpp stellar-agent-mpp stellar-agent-x402/' "$TMP/duplicate.sh"
if env -u CARGO_REGISTRY_TOKEN bash "$TMP/duplicate.sh" --check >"$TMP/duplicate.out" 2>&1; then
  echo "duplicate tier member unexpectedly passed" >&2
  exit 1
fi
grep -q "Tier lists do not match" "$TMP/duplicate.out"

echo "publish check-mode tests passed"

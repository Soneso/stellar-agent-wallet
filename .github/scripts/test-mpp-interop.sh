#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="$ROOT/interop/stellar-mpp-js"

actual_node="$(node -p 'process.versions.node')"
expected_node="$(tr -d '[:space:]' < "$HARNESS/.node-version")"
if [[ "$actual_node" != "$expected_node" ]]; then
  echo "error: MPP interop requires Node $expected_node, found $actual_node" >&2
  exit 1
fi

cd "$HARNESS"
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm run check

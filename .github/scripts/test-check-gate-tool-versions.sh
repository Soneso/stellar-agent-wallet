#!/usr/bin/env bash
# Offline regression checks for check-gate-tool-versions.sh.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT_REL=".github/scripts/check-gate-tool-versions.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

make_fixture() {
  local dir="$1"
  mkdir -p "$dir/.github/scripts" "$dir/.github/workflows" "$dir/docs/maintainers"
  cp "$ROOT/$SCRIPT_REL" "$dir/$SCRIPT_REL"
  cat >"$dir/.github/workflows/ci.yml" <<'EOF'
jobs:
  machete:
    steps:
      - uses: taiki-e/install-action@pinned
        with:
          tool: cargo-machete@0.9.2
  deny:
    steps:
      - uses: taiki-e/install-action@pinned
        with:
          tool: cargo-deny@0.19.9
  coverage:
    steps:
      - uses: taiki-e/install-action@pinned
        with:
          tool: cargo-llvm-cov@0.8.7
EOF
  cat >"$dir/docs/maintainers/building.md" <<'EOF'
cargo install --locked cargo-llvm-cov --version 0.8.7
cargo install --locked cargo-machete --version 0.9.2
cargo install --locked cargo-deny --version 0.19.9
EOF
}

# Matching versions pass.
make_fixture "$TMP/match"
bash "$TMP/match/$SCRIPT_REL" | grep -q "versions match"

# A version bumped in building.md but not ci.yml fails, naming the tool.
make_fixture "$TMP/mismatch"
sed -i.bak 's/cargo-machete --version 0.9.2/cargo-machete --version 0.9.1/' "$TMP/mismatch/docs/maintainers/building.md"
if bash "$TMP/mismatch/$SCRIPT_REL" >"$TMP/mismatch.out" 2>&1; then
  echo "version mismatch unexpectedly passed" >&2
  exit 1
fi
grep -q "cargo-machete version mismatch" "$TMP/mismatch.out"

# A tool pin removed from ci.yml fails with a clear "not found" message,
# rather than silently skipping that tool.
make_fixture "$TMP/missing-ci"
sed -i.bak '/tool: cargo-deny/d' "$TMP/missing-ci/.github/workflows/ci.yml"
if bash "$TMP/missing-ci/$SCRIPT_REL" >"$TMP/missing-ci.out" 2>&1; then
  echo "missing CI pin unexpectedly passed" >&2
  exit 1
fi
grep -q "no 'tool: cargo-deny@<version>' pin found" "$TMP/missing-ci.out"

# A tool line removed from building.md fails the same way.
make_fixture "$TMP/missing-doc"
sed -i.bak '/cargo-llvm-cov --version/d' "$TMP/missing-doc/docs/maintainers/building.md"
if bash "$TMP/missing-doc/$SCRIPT_REL" >"$TMP/missing-doc.out" 2>&1; then
  echo "missing doc line unexpectedly passed" >&2
  exit 1
fi
grep -q "no '--locked cargo-llvm-cov --version <version>' line found" "$TMP/missing-doc.out"

echo "gate tool version check tests passed"

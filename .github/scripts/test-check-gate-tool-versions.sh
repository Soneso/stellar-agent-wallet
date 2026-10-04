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
  cat >"$dir/.github/workflows/release.yml" <<'EOF'
jobs:
  release:
    steps:
      # The release cut checks the dependency graph with cargo-deny again.
      - name: Check cargo-deny
        uses: taiki-e/install-action@pinned
        with:
          tool: cargo-deny@0.19.9
      - run: cargo deny check
EOF
  cat >"$dir/docs/maintainers/building.md" <<'EOF'
cargo install --locked cargo-llvm-cov --version 0.8.7
cargo install --locked cargo-machete --version 0.9.2
cargo install --locked cargo-deny --version 0.19.9
EOF
}

# Runs the check in fixture `$1` and requires it to pass with its summary line
# as the only output.
expect_pass() {
  local dir="$1"
  if ! bash "$dir/$SCRIPT_REL" >"$dir.out" 2>&1 || ! grep -q "versions match" "$dir.out" ||
    [ "$(wc -l <"$dir.out")" -ne 1 ]; then
    echo "$(basename "$dir") unexpectedly failed:" >&2
    cat "$dir.out" >&2
    exit 1
  fi
}

# Runs the check in fixture `$1` and requires it to fail with output that
# contains each further argument as a fixed string.
expect_fail() {
  local dir="$1" message
  shift
  if bash "$dir/$SCRIPT_REL" >"$dir.out" 2>&1; then
    echo "$(basename "$dir") unexpectedly passed" >&2
    exit 1
  fi
  for message in "$@"; do
    if ! grep -qF -- "$message" "$dir.out"; then
      echo "$(basename "$dir") failed without '${message}':" >&2
      cat "$dir.out" >&2
      exit 1
    fi
  done
}

# Requires fixture file `$1` to contain the fixed string `$2`, so a fixture
# edit that did not apply fails the self-test.
require_text() {
  if ! grep -qF -- "$2" "$1"; then
    echo "fixture edit not applied: $1 lacks '$2'" >&2
    exit 1
  fi
}

# Matching versions pass.
make_fixture "$TMP/match"
expect_pass "$TMP/match"

# A version bumped in building.md but not ci.yml fails, naming the tool.
make_fixture "$TMP/mismatch-doc"
sed -i.bak 's/cargo-machete --version 0.9.2/cargo-machete --version 0.9.1/' "$TMP/mismatch-doc/docs/maintainers/building.md"
expect_fail "$TMP/mismatch-doc" "cargo-machete version mismatch" \
  ".github/workflows/ci.yml:6 pins 0.9.2" "docs/maintainers/building.md:2 pins 0.9.1"

# A version bumped in ci.yml but not building.md fails, naming the tool.
make_fixture "$TMP/mismatch-ci"
sed -i.bak 's/cargo-deny@0.19.9/cargo-deny@0.19.10/' "$TMP/mismatch-ci/.github/workflows/ci.yml"
expect_fail "$TMP/mismatch-ci" "cargo-deny version mismatch" \
  ".github/workflows/ci.yml:11 pins 0.19.10" "docs/maintainers/building.md:3 pins 0.19.9"

# A version bumped in another workflow alone fails, naming that workflow.
make_fixture "$TMP/mismatch-release"
sed -i.bak 's/cargo-deny@0.19.9/cargo-deny@0.19.10/' "$TMP/mismatch-release/.github/workflows/release.yml"
expect_fail "$TMP/mismatch-release" "cargo-deny version mismatch" \
  ".github/workflows/ci.yml:11 pins 0.19.9" ".github/workflows/release.yml:8 pins 0.19.10"

# The check reads a workflow and an action with the .yaml extension too.
make_fixture "$TMP/mismatch-yaml"
printf 'jobs:\n  nightly:\n    steps:\n      - with:\n          tool: cargo-llvm-cov@0.8.6\n' \
  >"$TMP/mismatch-yaml/.github/workflows/nightly.yaml"
mkdir -p "$TMP/mismatch-yaml/.github/actions/coverage"
printf 'runs:\n  using: composite\n  steps:\n    - with:\n        tool: cargo-llvm-cov@0.8.5\n' \
  >"$TMP/mismatch-yaml/.github/actions/coverage/action.yaml"
expect_fail "$TMP/mismatch-yaml" "cargo-llvm-cov version mismatch" \
  ".github/workflows/nightly.yaml:5 pins 0.8.6" ".github/actions/coverage/action.yaml:5 pins 0.8.5"

# The check reads composite actions too.
make_fixture "$TMP/mismatch-action"
mkdir -p "$TMP/mismatch-action/.github/actions/lint"
printf 'runs:\n  using: composite\n  steps:\n    - uses: taiki-e/install-action@pinned\n      with:\n        tool: cargo-machete@0.9.3\n' \
  >"$TMP/mismatch-action/.github/actions/lint/action.yml"
expect_fail "$TMP/mismatch-action" "cargo-machete version mismatch" \
  ".github/actions/lint/action.yml:6 pins 0.9.3"

# A pre-release suffix is part of the version.
make_fixture "$TMP/prerelease-ci"
sed -i.bak 's/cargo-deny@0.19.9/cargo-deny@0.19.9-rc.1/' "$TMP/prerelease-ci/.github/workflows/ci.yml"
expect_fail "$TMP/prerelease-ci" "cargo-deny version mismatch" \
  ".github/workflows/ci.yml:11 pins 0.19.9-rc.1"

# A tool pin removed from ci.yml fails with a "not found" message naming the tool.
make_fixture "$TMP/missing-ci"
sed -i.bak '/tool: cargo-deny/d' "$TMP/missing-ci/.github/workflows/ci.yml"
expect_fail "$TMP/missing-ci" "no 'tool: cargo-deny@<version>' pin found"
if grep -q "version mismatch" "$TMP/missing-ci.out"; then
  echo "missing-ci compared versions without a ci.yml pin:" >&2
  cat "$TMP/missing-ci.out" >&2
  exit 1
fi

# A tool line removed from building.md fails the same way.
make_fixture "$TMP/missing-doc"
sed -i.bak '/cargo-llvm-cov --version/d' "$TMP/missing-doc/docs/maintainers/building.md"
expect_fail "$TMP/missing-doc" "no '--locked cargo-llvm-cov --version <version>' line found"

# A second pin of the same tool in ci.yml fails, even at the documented version.
make_fixture "$TMP/duplicate-ci"
printf '  extra:\n    steps:\n      - uses: taiki-e/install-action@pinned\n        with:\n          tool: cargo-deny@0.19.9\n' \
  >>"$TMP/duplicate-ci/.github/workflows/ci.yml"
expect_fail "$TMP/duplicate-ci" "2 'tool: cargo-deny@<version>' pins found"

# A second install line for the same tool in building.md fails the same way.
make_fixture "$TMP/duplicate-doc"
printf 'cargo install --locked cargo-machete --version 0.9.2\n' >>"$TMP/duplicate-doc/docs/maintainers/building.md"
expect_fail "$TMP/duplicate-doc" "2 '--locked cargo-machete --version <version>' lines found"

# An install line without --locked does not count as the documented pin.
make_fixture "$TMP/unlocked-doc"
sed -i.bak 's/cargo install --locked cargo-deny/cargo install cargo-deny/' "$TMP/unlocked-doc/docs/maintainers/building.md"
expect_fail "$TMP/unlocked-doc" "no '--locked cargo-deny --version <version>' line found" \
  "docs/maintainers/building.md:3 names cargo-deny with a version outside"

# An install line with its flags in another order fails the same way.
make_fixture "$TMP/flag-order-doc"
sed -i.bak 's/--locked cargo-deny --version 0.19.9/cargo-deny --version 0.19.9 --locked/' \
  "$TMP/flag-order-doc/docs/maintainers/building.md"
expect_fail "$TMP/flag-order-doc" "no '--locked cargo-deny --version <version>' line found" \
  "docs/maintainers/building.md:3 names cargo-deny with a version outside"

# An install line with the --vers alias fails the same way.
make_fixture "$TMP/vers-alias-doc"
sed -i.bak 's/cargo-deny --version 0.19.9/cargo-deny --vers 0.19.9/' "$TMP/vers-alias-doc/docs/maintainers/building.md"
expect_fail "$TMP/vers-alias-doc" "no '--locked cargo-deny --version <version>' line found" \
  "docs/maintainers/building.md:3 names cargo-deny with a version outside"

# An install line continued onto a second line fails as not found.
make_fixture "$TMP/continuation-doc"
sed -i.bak 's/--locked cargo-deny --version 0.19.9/--locked cargo-deny \\\
  --version 0.19.9/' "$TMP/continuation-doc/docs/maintainers/building.md"
expect_fail "$TMP/continuation-doc" "no '--locked cargo-deny --version <version>' line found"

# A version named in prose next to the install line fails, naming the line.
make_fixture "$TMP/prose-doc"
cat >>"$TMP/prose-doc/docs/maintainers/building.md" <<'EOF'
To test a fix, install `cargo-deny@0.20.0` first.
EOF
expect_fail "$TMP/prose-doc" \
  "docs/maintainers/building.md:4 names cargo-deny with a version outside the '--locked cargo-deny --version <version>' form"

# A second pin in another line shape in ci.yml fails once, naming the line.
make_fixture "$TMP/stray-ci"
printf '      - run: cargo install --locked cargo-deny --version 0.19.9\n' >>"$TMP/stray-ci/.github/workflows/ci.yml"
expect_fail "$TMP/stray-ci" \
  ".github/workflows/ci.yml:17 names cargo-deny with a version outside the 'tool: cargo-deny@<version>' form"
if [ "$(grep -c 'ci.yml:17 names' "$TMP/stray-ci.out")" -ne 1 ]; then
  echo "stray-ci reported the line more than once:" >&2
  cat "$TMP/stray-ci.out" >&2
  exit 1
fi

# One tool: line for two tools fails for both, as neither has a line of its own.
make_fixture "$TMP/combined-ci"
sed -i.bak -e '/tool: cargo-machete/d' \
  -e 's/tool: cargo-deny@0.19.9/tool: cargo-machete@0.9.2,cargo-deny@0.19.9/' \
  "$TMP/combined-ci/.github/workflows/ci.yml"
expect_fail "$TMP/combined-ci" \
  "no 'tool: cargo-machete@<version>' pin found" "no 'tool: cargo-deny@<version>' pin found"

# A v-prefixed version is not a pin.
make_fixture "$TMP/v-prefix-ci"
sed -i.bak 's/cargo-deny@0.19.9/cargo-deny@v0.19.9/' "$TMP/v-prefix-ci/.github/workflows/ci.yml"
expect_fail "$TMP/v-prefix-ci" "no 'tool: cargo-deny@<version>' pin found" \
  ".github/workflows/ci.yml:11 names cargo-deny with a version outside"

# The check ignores a commented-out pin: a stale one before the real pin passes,
# and one in place of the real pin fails as not found.
make_fixture "$TMP/commented-ci"
sed -i.bak 's/^\( *\)tool: cargo-deny@0.19.9/\1# tool: cargo-deny@0.19.8\
\1tool: cargo-deny@0.19.9/' "$TMP/commented-ci/.github/workflows/ci.yml"
require_text "$TMP/commented-ci/.github/workflows/ci.yml" "# tool: cargo-deny@0.19.8"
expect_pass "$TMP/commented-ci"
make_fixture "$TMP/commented-only-ci"
sed -i.bak 's/tool: cargo-deny@0.19.9/# tool: cargo-deny@0.19.9/' "$TMP/commented-only-ci/.github/workflows/ci.yml"
expect_fail "$TMP/commented-only-ci" "no 'tool: cargo-deny@<version>' pin found"

# A commented-out install line in building.md fails, as readers of the guide
# see it.
make_fixture "$TMP/commented-doc"
printf '# cargo install --locked cargo-deny --version 0.19.8\n' >>"$TMP/commented-doc/docs/maintainers/building.md"
expect_fail "$TMP/commented-doc" \
  "docs/maintainers/building.md:4 names cargo-deny with a version outside"

# A pin with a trailing YAML comment passes.
make_fixture "$TMP/trailing-comment-ci"
sed -i.bak 's/tool: cargo-deny@0.19.9/tool: cargo-deny@0.19.9 # pinned/' "$TMP/trailing-comment-ci/.github/workflows/ci.yml"
require_text "$TMP/trailing-comment-ci/.github/workflows/ci.yml" "tool: cargo-deny@0.19.9 # pinned"
expect_pass "$TMP/trailing-comment-ci"

# A tool whose name starts or ends with a gate tool's name is a different tool.
make_fixture "$TMP/other-tool"
printf '  wasm:\n    steps:\n      - uses: taiki-e/install-action@pinned\n        with:\n          tool: wasm-cargo-deny@2.0.0\n' \
  >>"$TMP/other-tool/.github/workflows/ci.yml"
printf 'cargo install --locked cargo-deny-ext --version 2.0.0\n' >>"$TMP/other-tool/docs/maintainers/building.md"
expect_pass "$TMP/other-tool"

# One run reports every problem.
make_fixture "$TMP/all-problems"
sed -i.bak 's/cargo-machete --version 0.9.2/cargo-machete --version 0.9.1/' "$TMP/all-problems/docs/maintainers/building.md"
sed -i.bak 's/cargo-deny@0.19.9/cargo-deny@0.19.10/' "$TMP/all-problems/.github/workflows/release.yml"
expect_fail "$TMP/all-problems" "cargo-machete version mismatch" "cargo-deny version mismatch"

echo "gate tool version check tests passed"

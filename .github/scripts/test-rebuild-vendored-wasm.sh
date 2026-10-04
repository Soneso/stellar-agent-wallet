#!/usr/bin/env bash
# Offline self-test of rebuild-vendored-wasm.sh.
#
# Builds a scratch repository from copies of the smart-account crate's
# build.rs, src, and vendor directories and of contracts/. It runs the script
# against that repository with stub builders, a stub rustc, and a stub git
# placed first on PATH. The stubs read their answers from files beside themselves,
# since the script runs builds under env -i. Their per-row data is the table
# below, never read from the script under test. Each case asserts the exit
# code and the specific table column or message.
#
# Every run of the script gets a fixed environment: git reads no global or
# system configuration and commits with a placeholder identity, and
# CARGO_HOME is an empty scratch directory.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
SCRIPT="$ROOT/.github/scripts/rebuild-vendored-wasm.sh"
CRATE="crates/stellar-agent-smart-account"
BASH_BIN=${BASH:-/bin/bash}
REAL_GIT=$(command -v git)
TMP=$(mktemp -d)
TMP=$(cd "$TMP" && pwd -P)
trap 'rm -rf "$TMP"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME="rebuild self-test"
export GIT_AUTHOR_EMAIL="self-test@example.invalid"
export GIT_COMMITTER_NAME="rebuild self-test"
export GIT_COMMITTER_EMAIL="self-test@example.invalid"
export CARGO_HOME="$TMP/cargo-home"
mkdir -p "$CARGO_HOME"
BASE_PATH=$PATH

# The rebuildable files as the stubs see them: vendored path (relative to the
# crate), source directory key, package ("-" for none), toolchain, target
# directory key, and output (relative to <target dir>/wasm32v1-none/).
ROWS="\
vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm|oz-v0.7.2|stellar-accounts|1.96.0|oz-v0.7.2-stellar-accounts|release/deps/stellar_accounts.wasm
vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm|oz-v0.7.2|multisig-account-example|1.96.0|oz-v0.7.2|release/multisig_account_example.wasm
vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm|oz-v0.7.2|multisig-webauthn-verifier-example|1.96.0|oz-v0.7.2|release/multisig_webauthn_verifier_example.wasm
vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm|oz-v0.7.2|timelock-controller-example|1.96.0|oz-v0.7.2|release/timelock_controller_example.wasm
vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm|oz-v0.7.2|multisig-threshold-policy-example|1.96.0|oz-v0.7.2|release/multisig_threshold_policy_example.wasm
vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm|oz-v0.7.2|multisig-ed25519-verifier-example|1.96.0|oz-v0.7.2|release/multisig_ed25519_verifier_example.wasm
vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm|oz-v0.7.2|multisig-spending-limit-policy-example|1.96.0|oz-v0.7.2|release/multisig_spending_limit_policy_example.wasm
vendor/oz-weighted-threshold-policy/v0.7.2/multisig_weighted_threshold_policy_example.wasm|oz-v0.7.2|multisig-weighted-threshold-policy-example|1.96.0|oz-v0.7.2|release/multisig_weighted_threshold_policy_example.wasm
vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm|oz-v0.7.1|stellar-accounts|1.94.0|oz-v0.7.1-stellar-accounts|release/deps/stellar_accounts.wasm
vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm|oz-v0.7.1|multisig-account-example|1.94.0|oz-v0.7.1|release/multisig_account_example.wasm
vendor/oz-webauthn-verifier/v0.7.1/multisig_webauthn_verifier_example.wasm|oz-v0.7.1|multisig-webauthn-verifier-example|1.94.0|oz-v0.7.1|release/multisig_webauthn_verifier_example.wasm
vendor/oz-timelock-controller/v0.7.1/timelock_controller_example.wasm|oz-v0.7.1|timelock-controller-example|1.94.0|oz-v0.7.1|release/timelock_controller_example.wasm
vendor/oz-threshold-policy/v0.7.1/multisig_threshold_policy_example.wasm|oz-v0.7.1|multisig-threshold-policy-example|1.94.0|oz-v0.7.1|release/multisig_threshold_policy_example.wasm
vendor/cap85-beacon/v0.1.0/cap85_beacon.wasm|tree-contracts-cap85-beacon|-|1.98.0|tree-contracts-cap85-beacon|release/cap85_beacon.wasm"

S25_LINE="stellar 25.2.0"
S28_LINE="stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)"
OZ_V072="a9c42169000638da937577f592ebf61a7a3c94ca"
OZ_V071="3f81125bed3114cc93f5fca6d13240082050269a"
RUSTC_194="rustc 1.94.0 (4a4ef493e 2026-03-02)"
RUSTC_196="rustc 1.96.0 (ac68faa20 2026-05-25)"
RUSTC_198="rustc 1.98.0 (88d9e12ae 2026-08-18)"

PASSED=0

fail() {
  echo "test-rebuild-vendored-wasm: FAIL: $*" >&2
  if [ -n "${OUT:-}" ] && [ -f "$OUT" ]; then
    echo "--- output of the last run ---" >&2
    cat "$OUT" >&2
  fi
  exit 1
}

pass() {
  PASSED=$((PASSED + 1))
  echo "ok - $*"
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# The scratch repository: copies of the crate's build.rs, src, and vendor
# directories and of contracts/, added to a fresh index without a commit.
BASE="$TMP/base"
mkdir -p "$BASE/$CRATE"
cp "$ROOT/$CRATE/build.rs" "$BASE/$CRATE/build.rs"
cp -R "$ROOT/$CRATE/src" "$BASE/$CRATE/src"
cp -R "$ROOT/$CRATE/vendor" "$BASE/$CRATE/vendor"
cp -R "$ROOT/contracts" "$BASE/contracts"
# Build output is never tracked.
find "$BASE/contracts" -type d -name target -prune -exec rm -rf {} +
"$REAL_GIT" -C "$BASE" init -q
"$REAL_GIT" -C "$BASE" add -A

# The vendored bytes each stub row writes by default.
BYTES="$TMP/bytes"
mkdir -p "$BYTES"
n=0
while IFS='|' read -r path _; do
  n=$((n + 1))
  cp "$BASE/$CRATE/$path" "$BYTES/$n.wasm"
done <<<"$ROWS"

# The stub OpenZeppelin clone is a real, empty git repository.
OZ="$TMP/oz"
"$REAL_GIT" init -q "$OZ"

# An empty stub directory for the modes that run no build.
NO_STUBS="$TMP/no-stubs"
mkdir -p "$NO_STUBS"

# Stubs, written once and copied into each case's stub directory.
STUB_SRC="$TMP/stub-src"
mkdir -p "$STUB_SRC"

cat >"$STUB_SRC/stellar" <<'EOF'
#!/bin/sh
# Stub builder: prints the version line of data/<name>.version, logs each
# call, and writes a row's bytes when the toolchain and target directory are
# the row's own.
set -eu
dir=$(cd "$(dirname "$0")" && pwd -P)
data="$dir/data"
me=$(basename "$0")
if [ "${1:-}" = "--version" ]; then
  cat "$data/$me.version"
  exit 0
fi
cwd=$(pwd -P)
names=$(env | awk -F= '/^[A-Za-z_][A-Za-z0-9_-]*=/ { printf "%s ", $1 }')
printf 'builder=%s|args=%s|toolchain=%s|target=%s|cwd=%s|auto_install=%s|env=%s\n' \
  "$me" "$*" "${RUSTUP_TOOLCHAIN:-}" "${CARGO_TARGET_DIR:-}" "$cwd" "${RUSTUP_AUTO_INSTALL:-unset}" "$names" >>"$data/log"
[ "${1:-} ${2:-}" = "contract build" ] || exit 64
shift 2
pkg=-
while [ $# -gt 0 ]; do
  case "$1" in
    --package) pkg=$2; shift 2 ;;
    *) shift ;;
  esac
done
key=$(basename "$cwd")
row=$(awk -F '|' -v k="$key" -v p="$pkg" '$1 == k && $2 == p { print; exit }' "$data/rows")
[ -n "$row" ] || exit 65
toolchain=$(printf '%s' "$row" | awk -F '|' '{ print $3 }')
target=$(printf '%s' "$row" | awk -F '|' '{ print $4 }')
output=$(printf '%s' "$row" | awk -F '|' '{ print $5 }')
bytes=$(printf '%s' "$row" | awk -F '|' '{ print $6 }')
action=$(printf '%s' "$row" | awk -F '|' '{ print $7 }')
if [ -f "$data/rewrite" ]; then
  printf 'x' >>"$(cat "$data/rewrite")"
fi
case "$action" in
  fail) exit 1 ;;
  nothing) exit 0 ;;
esac
if [ "${RUSTUP_TOOLCHAIN:-}" = "$toolchain" ] && [ "${CARGO_TARGET_DIR:-}" = "$target" ]; then
  mkdir -p "$(dirname "$target/wasm32v1-none/$output")"
  cp "$bytes" "$target/wasm32v1-none/$output"
  case "$action" in
    also:*)
      extra=${action#also:}
      mkdir -p "$(dirname "$target/wasm32v1-none/${extra%%=*}")"
      cp "${extra#*=}" "$target/wasm32v1-none/${extra%%=*}"
      ;;
  esac
fi
exit 0
EOF

cat >"$STUB_SRC/rustc" <<'EOF'
#!/bin/sh
# Stub rustc: prints the version string data/rustc pins for RUSTUP_TOOLCHAIN.
set -eu
data="$(cd "$(dirname "$0")" && pwd -P)/data"
line=$(awk -F '|' -v t="${RUSTUP_TOOLCHAIN:-}" '$1 == t { print $2 }' "$data/rustc")
[ -n "$line" ] || exit 1
printf '%s\n' "$line"
EOF

cat >"$STUB_SRC/git" <<'EOF'
#!/bin/sh
# Stub git: answers tag lookups, worktree creation, and status for the stub
# OpenZeppelin clone and its worktrees; every other call runs the real git.
set -eu
data="$(cd "$(dirname "$0")" && pwd -P)/data"
real=$(cat "$data/real-git")
oz=$(cat "$data/oz-clone")
if [ "${1:-}" != "-C" ]; then
  exec "$real" "$@"
fi
target=$(cd "$2" 2>/dev/null && pwd -P) || exec "$real" "$@"
shift 2
while [ "${1:-}" = "-c" ]; do shift 2; done
if [ "$target" = "$oz" ]; then
  case "${1:-}" in
    rev-parse)
      for last in "$@"; do :; done
      tag=$(printf '%s\n' "$last" | sed -e 's|^refs/tags/||' -e 's|\^{commit}$||')
      commit=$(awk -v t="$tag" '$1 == t { print $2 }' "$data/git-tags")
      [ -n "$commit" ] || exit 1
      printf '%s\n' "$commit"
      exit 0
      ;;
    worktree)
      if [ "${2:-}" = add ]; then
        mkdir -p "$4"
        : >"$4/.stub-worktree"
        exit 0
      fi
      ;;
  esac
  exec "$real" -C "$target" "$@"
fi
if [ -f "$target/.stub-worktree" ] && [ "${1:-}" = status ]; then
  key=$(basename "$target")
  if [ -f "$data/dirty-before" ] && [ "$(cat "$data/dirty-before")" = "$key" ]; then
    printf ' M Cargo.lock\000'
  elif [ -f "$data/dirty-after" ] && [ "$(cat "$data/dirty-after")" = "$key" ] &&
    grep -qF "|cwd=$target|" "$data/log" 2>/dev/null; then
    printf ' M Cargo.lock\000'
  fi
  exit 0
fi
exec "$real" -C "$target" "$@"
EOF
chmod +x "$STUB_SRC/stellar" "$STUB_SRC/rustc" "$STUB_SRC/git"

# Creates the case directory $TMP/<case> with repo/, work/, and stubs/, and
# sets CASE, REPO, WORK, STUBS, DATA, and OUT.
new_case() {
  CASE="$TMP/$1"
  REPO="$CASE/repo"
  WORK="$CASE/work"
  STUBS="$CASE/stubs"
  DATA="$STUBS/data"
  OUT="$CASE/out"
  mkdir -p "$CASE" "$DATA"
  cp -R "$BASE" "$REPO"
  cp "$STUB_SRC/stellar" "$STUBS/stellar-25"
  cp "$STUB_SRC/stellar" "$STUBS/stellar-28"
  cp "$STUB_SRC/stellar" "$STUBS/stellar"
  cp "$STUB_SRC/rustc" "$STUB_SRC/git" "$STUBS/"
  printf '%s\n' "$S25_LINE" >"$DATA/stellar-25.version"
  printf '%s\n' "$S28_LINE" >"$DATA/stellar-28.version"
  printf '%s\n' "$S25_LINE" >"$DATA/stellar.version"
  printf '1.94.0|%s\n1.96.0|%s\n1.98.0|%s\n' "$RUSTC_194" "$RUSTC_196" "$RUSTC_198" >"$DATA/rustc"
  printf 'v0.7.2 %s\nv0.7.1 %s\n' "$OZ_V072" "$OZ_V071" >"$DATA/git-tags"
  printf '%s\n' "$REAL_GIT" >"$DATA/real-git"
  printf '%s\n' "$OZ" >"$DATA/oz-clone"
  : >"$DATA/log"
  local i=0 path key pkg tc tkey output
  : >"$DATA/rows"
  while IFS='|' read -r path key pkg tc tkey output; do
    i=$((i + 1))
    printf '%s|%s|%s|%s|%s|%s|\n' "$key" "$pkg" "$tc" "$WORK/target/$tkey" "$output" "$BYTES/$i.wasm" >>"$DATA/rows"
  done <<<"$ROWS"
}

# Sets the action field of the stub row for vendored path $1 to $2.
set_action() {
  local key pkg
  key=$(row_field "$1" 2)
  pkg=$(row_field "$1" 3)
  awk -F '|' -v OFS='|' -v k="$key" -v p="$pkg" -v a="$2" '$1 == k && $2 == p { $7 = a } { print }' \
    "$DATA/rows" >"$DATA/rows.new"
  mv "$DATA/rows.new" "$DATA/rows"
}

# Sets the bytes file of the stub row for vendored path $1 to $2.
set_bytes() {
  local key pkg
  key=$(row_field "$1" 2)
  pkg=$(row_field "$1" 3)
  awk -F '|' -v OFS='|' -v k="$key" -v p="$pkg" -v b="$2" '$1 == k && $2 == p { $6 = b } { print }' \
    "$DATA/rows" >"$DATA/rows.new"
  mv "$DATA/rows.new" "$DATA/rows"
}

# Prints field $2 of the ROWS entry for vendored path $1.
row_field() {
  awk -F '|' -v p="$1" -v f="$2" '$1 == p { print $f }' <<<"$ROWS"
}

# Runs the script under env -i with the fixed environment, the case's stubs
# first on PATH, and the extra NAME=value arguments before "--"; the script
# arguments follow "--". Output goes to $OUT; sets RC.
run_script() {
  local script=$SCRIPT
  local env_args=(
    "PATH=$STUBS:$BASE_PATH"
    "HOME=$CASE"
    "TMPDIR=$TMP"
    "CARGO_HOME=$CARGO_HOME"
    "GIT_CONFIG_GLOBAL=/dev/null"
    "GIT_CONFIG_NOSYSTEM=1"
    "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME"
    "GIT_AUTHOR_EMAIL=$GIT_AUTHOR_EMAIL"
    "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME"
    "GIT_COMMITTER_EMAIL=$GIT_COMMITTER_EMAIL"
  )
  while [ $# -gt 0 ] && [ "$1" != -- ]; do
    case "$1" in
      SCRIPT=*) script=${1#SCRIPT=} ;;
      *) env_args+=("$1") ;;
    esac
    shift
  done
  [ "${1:-}" = -- ] && shift
  RC=0
  env -i "${env_args[@]}" "$BASH_BIN" "$script" "$@" >"$OUT" 2>&1 || RC=$?
}

# Runs full mode on the case repository; extra arguments as for run_script.
run_full() {
  run_script "$@" -- --repo-root "$REPO" --oz-clone "$OZ" --stellar-25 "$STUBS/stellar-25" \
    --stellar-28 "$STUBS/stellar-28" --work "$WORK"
}

run_check_tree() {
  run_script -- --check-tree --repo-root "$REPO"
}

expect_rc() {
  case "$1" in
    0) [ "$RC" = 0 ] || fail "$2: expected exit 0, got $RC" ;;
    nonzero) [ "$RC" != 0 ] || fail "$2: expected a non-zero exit, got 0" ;;
    *) [ "$RC" = "$1" ] || fail "$2: expected exit $1, got $RC" ;;
  esac
}

expect_out() {
  grep -qF -- "$1" "$OUT" || fail "$2: the output lacks '$1'"
}

expect_literal_fixture_status() {
  if grep -qF 'audit_status must use a VerifierAuditStatus variant with literal fields' "$OUT"; then
    fail "$1: a bare unit variant triggered the audit-status refusal"
  fi
  echo "ok - fixture $1 reaches its required diagnostics without an audit-status refusal"
}

builds() {
  awk 'END { print NR }' "$DATA/log"
}

expect_builds() {
  [ "$(builds)" = "$1" ] || fail "$2: expected $1 builds in the log, found $(builds)"
}

# Prints column $2 of the output table row of vendored path $1 (1 = file,
# 7 = cmp, 8 = WASM_PINS, 9 = record, 10 = result).
column() {
  awk -F '|' -v p="$1" -v c="$2" '
    { f = $2; gsub(/^ +| +$/, "", f) }
    f == p { v = $(c + 1); gsub(/^ +| +$/, "", v); print v; exit }
  ' "$OUT"
}

# Asserts that column $2 of the row of vendored path $1 matches the glob $3.
expect_column() {
  local got
  got=$(column "$1" "$2")
  # shellcheck disable=SC2254 # $3 is a glob pattern.
  case "$got" in
    $3) ;;
    *) fail "$4: column $2 of $1 is '$got', expected '$3'" ;;
  esac
}

# Every row other than $1 reports cmp match.
expect_others_match() {
  local path
  while IFS='|' read -r path _; do
    [ "$path" = "$1" ] && continue
    expect_column "$path" 7 match "$2"
  done <<<"$ROWS"
}

# Replaces the first line of file $1 matching the extended regex $2 with $3.
replace_line() {
  RE="$2" TEXT="$3" awk '!done && $0 ~ ENVIRON["RE"] { print ENVIRON["TEXT"]; done = 1; next } { print } END { if (!done) exit 3 }' \
    "$1" >"$1.new" || fail "no line of $1 matches $2"
  mv "$1.new" "$1"
}

# Inserts text $3 into file $1 before the first line matching regex $2.
insert_before() {
  RE="$2" TEXT="$3" awk '!done && $0 ~ ENVIRON["RE"] { print ENVIRON["TEXT"]; done = 1 } { print } END { if (!done) exit 3 }' \
    "$1" >"$1.new" || fail "no line of $1 matches $2"
  mv "$1.new" "$1"
}

# Prints the line number of the first line of file $1 containing $2.
line_of() {
  grep -nF -- "$2" "$1" | head -n 1 | awk -F: '{ print $1 }'
}

sha_of() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

# Replaces every occurrence of the text $2 in file $1 with $3; fails when $2
# does not occur.
replace_text() {
  OLD="$2" NEW="$3" awk '
    {
      rest = $0; out = ""
      while ((i = index(rest, ENVIRON["OLD"])) > 0) {
        out = out substr(rest, 1, i - 1) ENVIRON["NEW"]
        rest = substr(rest, i + length(ENVIRON["OLD"])); n++
      }
      print out rest
    }
    END { if (!n) exit 3 }
  ' "$1" >"$1.new" || fail "$1 does not contain '$2'"
  mv "$1.new" "$1"
}

# Rewrites the 64-hex digest $2 to $3 in file $1.
swap_digest() {
  awk -v a="$2" -v b="$3" '{ gsub(a, b); print }' "$1" >"$1.new"
  mv "$1.new" "$1"
}

stage() {
  "$REAL_GIT" -C "$REPO" add -A
}

V072_MULTISIG="vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm"
V072_TIMELOCK="vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm"
V072_ED25519="vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm"
V072_ACCOUNTS="vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm"
V071_THRESHOLD="vendor/oz-threshold-policy/v0.7.1/multisig_threshold_policy_example.wasm"
V071_WEBAUTHN="vendor/oz-webauthn-verifier/v0.7.1/multisig_webauthn_verifier_example.wasm"
V071_TIMELOCK="vendor/oz-timelock-controller/v0.7.1/timelock_controller_example.wasm"
CAP85="vendor/cap85-beacon/v0.1.0/cap85_beacon.wasm"
MULTICALL="vendor/multicall/v0.1.0/multicall.wasm"

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

# 1. The honest tree passes: 14 builds with the expected packages,
# toolchains, --locked, working directories, and target directories, under
# the build environment allowlist.
new_case c01
run_full "SELFTEST_SENTINEL=1" "CARGO_INCREMENTAL=1" "HTTPS_PROXY=http://proxy.invalid:3128"
expect_rc 0 "pass"
expect_out "rebuild-vendored-wasm: PASS" "pass"
expect_builds 14 "pass"
while IFS='|' read -r path key pkg tc tkey output; do
  if [ "$pkg" = - ]; then
    want_args="contract build --locked"
    want_builder=stellar-28
  else
    want_args="contract build --locked --package $pkg"
    want_builder=stellar-25
  fi
  grep -qF "builder=$want_builder|args=$want_args|toolchain=$tc|target=$WORK/target/$tkey|cwd=$WORK/src/$key|auto_install=0|" "$DATA/log" ||
    fail "pass: no build of $path with builder $want_builder, '$want_args', toolchain $tc, target $tkey, in $key"
  expect_column "$path" 7 match "pass"
  expect_column "$path" 10 pass "pass"
done <<<"$ROWS"
[ "$(awk -F '|' '{ print $4 }' "$DATA/log" | LC_ALL=C sort -u | awk 'END { print NR }')" = 5 ] ||
  fail "pass: expected five target directories (one per tag, one per stellar_accounts.wasm row, one for the tree row)"
if grep -E 'env=.*(SELFTEST_SENTINEL|CARGO_INCREMENTAL)' "$DATA/log" >/dev/null; then
  fail "pass: a build saw SELFTEST_SENTINEL or CARGO_INCREMENTAL"
fi
[ "$(awk -F '|' '{ n = split(substr($7, 5), v, " "); for (i = 1; i <= n; i++) if (v[i] == "HTTPS_PROXY") c++ } END { print c + 0 }' "$DATA/log")" = 14 ] ||
  fail "pass: a build did not see HTTPS_PROXY"
expect_column "$MULTICALL" 7 frozen-match "pass"
expect_column "$MULTICALL" 10 "pass (exception, not rebuilt)" "pass"
pass "1 honest tree: 14 builds, allowlisted environment, every row matches"

# 2. Rebuilt bytes differ for one row: only that row's cmp fails.
for target_row in "$V072_MULTISIG" "$V071_THRESHOLD" "$V072_ACCOUNTS" "$CAP85"; do
  new_case "c02-$(basename "$(dirname "$(dirname "$target_row")")")-$(basename "$(dirname "$target_row")")"
  cp "$REPO/$CRATE/$target_row" "$CASE/different.wasm"
  printf 'x' >>"$CASE/different.wasm"
  set_bytes "$target_row" "$CASE/different.wasm"
  run_full
  expect_rc 1 "bytes differ for $target_row"
  expect_column "$target_row" 7 MISMATCH "bytes differ for $target_row"
  expect_column "$target_row" 10 "FAIL; vendored sha256 $(sha_of "$REPO/$CRATE/$target_row") size *" "bytes differ for $target_row"
  expect_others_match "$target_row" "bytes differ for $target_row"
  expect_builds 14 "bytes differ for $target_row"
done
pass "2 differing bytes fail only their row (v0.7.2, v0.7.1, deps, and the cap85 row, which is built last)"

# 3. A WASM_PINS digest differs from its file: the tree check names it, and
# every row is still built.
new_case c03
digest=$(sha_of "$REPO/$CRATE/$V072_TIMELOCK")
swap_digest "$REPO/$CRATE/build.rs" "$digest" "$(printf '%064d' 0)"
stage
run_full
expect_rc 1 "WASM_PINS digest"
expect_out "tree-check [wasm-pins] $CRATE/$V072_TIMELOCK: the WASM_PINS digest" "WASM_PINS digest"
expect_column "$V072_TIMELOCK" 8 MISMATCH "WASM_PINS digest"
expect_column "$V072_TIMELOCK" 7 match "WASM_PINS digest"
expect_builds 14 "WASM_PINS digest"
pass "3 a WASM_PINS digest that differs from its file fails, and all 14 rows are built"

# 4. A record digest differs from its file; a record with a second distinct
# 64-hex token fails too.
new_case c04a
record="$REPO/$CRATE/vendor/oz-spending-limit-policy/v0.7.2/PROVENANCE.md"
digest=$(sha_of "$REPO/$CRATE/vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm")
swap_digest "$record" "$digest" "$(printf '%064d' 1)"
stage
run_check_tree
expect_rc 1 "record digest"
expect_out "tree-check [record] $CRATE/vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm: the record digest" "record digest"
new_case c04b
record="$REPO/$CRATE/vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md"
printf '\nAnother value: %064d\n' 7 >>"$record"
stage
run_check_tree
expect_rc 1 "second record token"
expect_out "tree-check [record] $CRATE/$V072_ED25519: the record holds 2 distinct 64-hex tokens" "second record token"
pass "4 a record digest that differs, or a second distinct 64-hex token, fails"

# 5. WASM_PINS set: a pin row missing, an extra path, an unreadable block.
new_case c05a
awk '
  /^    WasmPin \{$/ { held = $0; holding = 1; next }
  holding { held = held "\n" $0; if ($0 ~ /^    \},$/) { if (held !~ /multisig_ed25519_verifier_example/) print held; holding = 0 } ; next }
  { print }
' "$REPO/$CRATE/build.rs" >"$REPO/$CRATE/build.rs.new"
mv "$REPO/$CRATE/build.rs.new" "$REPO/$CRATE/build.rs"
stage
run_check_tree
expect_rc 1 "pin row missing"
expect_out "tree-check [wasm-pins] $CRATE/$V072_ED25519: a pin file has no WASM_PINS row" "pin row missing"
new_case c05b
insert_before "$REPO/$CRATE/build.rs" '^];$' "    WasmPin {
        label: \"extra.wasm\",
        path: \"vendor/oz-extra/v1/extra.wasm\",
        expected_sha256: \"$(printf '%064d' 2)\",
    },"
stage
run_check_tree
expect_rc 1 "extra WASM_PINS path"
expect_out "WASM_PINS names vendor/oz-extra/v1/extra.wasm, which is no pin row or pin exception" "extra WASM_PINS path"
new_case c05c
replace_line "$REPO/$CRATE/build.rs" '^    WasmPin \{$' "    WasmPin { label: \"stellar_accounts.wasm\","
stage
run_check_tree
expect_rc 1 "unreadable WasmPin block"
expect_out "tree-check [wasm-pins] $CRATE/build.rs: the WASM_PINS table cannot be read" "unreadable WasmPin block"
new_case c05d
insert_before "$REPO/$CRATE/build.rs" '^];$' "    WasmPin {
        label: \"timelock_controller_example.wasm\",
        path: \"$V071_TIMELOCK\",
        expected_sha256: \"$(sha_of "$REPO/$CRATE/$V071_TIMELOCK")\",
    },"
stage
run_check_tree
expect_rc 1 "WASM_PINS row of a nopin file"
expect_out "tree-check [wasm-pins] $CRATE/$V071_TIMELOCK: a nopin file has a WASM_PINS row" "WASM_PINS row of a nopin file"
expect_out "WASM_PINS names $V071_TIMELOCK, which is no pin row or pin exception" "WASM_PINS row of a nopin file"
pass "5 a missing pin row, an extra WASM_PINS path, an unreadable block, and a row for a nopin file fail"

# 6. The exception's file, pin, and record changed together: the frozen
# digest fails.
new_case c06
old=$(sha_of "$REPO/$CRATE/$MULTICALL")
printf 'x' >>"$REPO/$CRATE/$MULTICALL"
new=$(sha_of "$REPO/$CRATE/$MULTICALL")
swap_digest "$REPO/$CRATE/build.rs" "$old" "$new"
swap_digest "$REPO/$CRATE/vendor/multicall/v0.1.0/REFERENCE.md" "$old" "$new"
stage
run_full
expect_rc 1 "exception frozen digest"
expect_out "tree-check [frozen] $CRATE/$MULTICALL: the exception's sha256 $new differs from its frozen digest $old" "exception frozen digest"
expect_column "$MULTICALL" 7 frozen-MISMATCH "exception frozen digest"
expect_column "$MULTICALL" 8 match "exception frozen digest"
expect_column "$MULTICALL" 9 match "exception frozen digest"
pass "6 an exception changed with its pin and record fails on its frozen digest"

# 7. Completeness.
new_case c07a
mkdir -p "$REPO/$CRATE/vendor/oz-extra/v1"
cp "$REPO/$CRATE/$V072_ED25519" "$REPO/$CRATE/vendor/oz-extra/v1/extra.wasm"
stage
run_check_tree
expect_rc 1 "extra vendored Wasm"
expect_out "tree-check [wasm-magic] $CRATE/vendor/oz-extra/v1/extra.wasm" "extra vendored Wasm"
expect_out "tree-check [vendor-files] $CRATE/vendor/oz-extra/v1/extra.wasm" "extra vendored Wasm"

new_case c07b
printf 'notes\n' >"$REPO/$CRATE/vendor/oz-threshold-policy/v0.7.2/NOTES.txt"
stage
run_check_tree
expect_rc 1 "extra file under vendor"
expect_out "tree-check [vendor-files] $CRATE/vendor/oz-threshold-policy/v0.7.2/NOTES.txt" "extra file under vendor"

new_case c07c
mkdir -p "$REPO/docs"
cp "$REPO/$CRATE/$V072_ED25519" "$REPO/docs/diagram.bin"
stage
run_check_tree
expect_rc 1 "Wasm magic with another extension"
expect_out "tree-check [wasm-magic] docs/diagram.bin" "Wasm magic with another extension"

new_case c07d
cat >>"$REPO/$CRATE/src/bindings.rs" <<'EOF'

/// Extra bytes.
pub const EXTRA_BYTES: &[u8] = include_bytes!(
    "../vendor/oz-threshold-policy/v0.7.2/PROVENANCE.md"
);
EOF
stage
want=$(line_of "$REPO/$CRATE/src/bindings.rs" "pub const EXTRA_BYTES")
run_check_tree
expect_rc 1 "include of a file outside the manifest"
expect_out "tree-check [include] $CRATE/src/bindings.rs:$want: the include argument '../vendor/oz-threshold-policy/v0.7.2/PROVENANCE.md' resolves to no manifest or exception file" "include of a file outside the manifest"

new_case c07e
cat >>"$REPO/$CRATE/src/bindings.rs" <<'EOF'

/// Extra bytes.
pub const EXTRA_BYTES: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/x.wasm"));
EOF
stage
want=$(line_of "$REPO/$CRATE/src/bindings.rs" "pub const EXTRA_BYTES")
run_check_tree
expect_rc 1 "include of a non-literal"
expect_out "tree-check [include] $CRATE/src/bindings.rs:$want: include_bytes! does not take exactly one string literal" "include of a non-literal"

new_case c07f
mkdir -p "$REPO/crates/stellar-agent-extra/src"
printf '%s\n' '//! Extra crate.' '' 'pub const EXTRA: &[u8] = include_bytes!("../extra.wasm");' >"$REPO/crates/stellar-agent-extra/src/lib.rs"
stage
run_check_tree
expect_rc 1 "Wasm include in another crate"
expect_out "tree-check [include] crates/stellar-agent-extra/src/lib.rs:3: the include argument '../extra.wasm' resolves to no manifest or exception file" "Wasm include in another crate"

new_case c07g
"$REAL_GIT" -C "$REPO" rm -q --cached "$CRATE/$V071_WEBAUTHN"
run_check_tree
expect_rc 1 "manifest file removed from the index"
expect_out "tree-check [tracked] $CRATE/$V071_WEBAUTHN: a manifest or exception file is not tracked" "manifest file removed from the index"

new_case c07h
mkdir -p "$REPO/$CRATE/vendor/oz-extra/v1"
printf '# Extra\n' >"$REPO/$CRATE/vendor/oz-extra/v1/PROVENANCE.md"
stage
run_check_tree
expect_rc 1 "record beside no vendored file"
expect_out "tree-check [vendor-files] $CRATE/vendor/oz-extra/v1/PROVENANCE.md: a record or build script beside no manifest or exception file" "record beside no vendored file"

new_case c07i
cp "$REPO/$CRATE/vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md" "$REPO/$CRATE/vendor/oz-ed25519-verifier/v0.7.2/REFERENCE.md"
stage
run_check_tree
expect_rc 1 "two records beside one file"
expect_out "tree-check [record] $CRATE/$V072_ED25519: both PROVENANCE.md and REFERENCE.md exist beside the file" "two records beside one file"

# The joined path of this absolute argument normalizes to a manifest path, so
# only the absolute-path check refuses it.
new_case c07j
cat >>"$REPO/$CRATE/src/bindings.rs" <<'EOF'

/// Extra bytes.
pub const EXTRA_BYTES: &[u8] = include_bytes!("/../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm");
EOF
stage
want=$(line_of "$REPO/$CRATE/src/bindings.rs" "pub const EXTRA_BYTES")
run_check_tree
expect_rc 1 "absolute include path"
expect_out "tree-check [include] $CRATE/src/bindings.rs:$want: the include argument '/../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm' is an absolute path" "absolute include path"

# Another crate may include a non-Wasm file through a non-literal argument.
new_case c07k
mkdir -p "$REPO/crates/stellar-agent-extra/src"
printf '%s\n' '//! Extra crate.' '' \
  'pub const README: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));' \
  >"$REPO/crates/stellar-agent-extra/src/lib.rs"
stage
run_check_tree
expect_rc 0 "non-literal include of a non-Wasm file in another crate"
expect_out "rebuild-vendored-wasm: PASS" "non-literal include of a non-Wasm file in another crate"
pass "7 an extra Wasm file, an extra vendor file, Wasm magic elsewhere, four bad includes, an untracked manifest file, a record beside no file, and two records fail; another crate's non-literal non-Wasm include passes"

# 8. A record missing the commit, the rustc string, or the builder line.
for missing in "$OZ_V071" "$RUSTC_194" "$S25_LINE"; do
  new_case "c08-$(printf '%s' "$missing" | awk '{ gsub(/[^A-Za-z0-9]/, ""); print substr($0, 1, 12) }')"
  replace_text "$REPO/$CRATE/vendor/oz-timelock-controller/v0.7.1/PROVENANCE.md" "$missing" REMOVED
  stage
  run_check_tree
  expect_rc 1 "record lacks '$missing'"
  expect_out "tree-check [record-fields] $CRATE/$V071_TIMELOCK: the record lacks" "record lacks '$missing'"
done
# The builder line and the rustc string count only as whole code spans.
new_case c08-builder-revision
replace_text "$REPO/$CRATE/vendor/oz-timelock-controller/v0.7.1/PROVENANCE.md" "\`$S25_LINE\`" \
  "\`$S25_LINE (28484880988199233a7e8e87c97cb12dac323cb3)\`"
stage
run_check_tree
expect_rc 1 "builder line with a revision"
expect_out "tree-check [record-fields] $CRATE/$V071_TIMELOCK: the record lacks the builder line '$S25_LINE' as a code span" "builder line with a revision"
new_case c08-rustc-suffix
replace_text "$REPO/$CRATE/vendor/oz-timelock-controller/v0.7.1/PROVENANCE.md" "\`$RUSTC_194\`" "\`$RUSTC_194 (Homebrew)\`"
stage
run_check_tree
expect_rc 1 "rustc string inside a longer code span"
expect_out "tree-check [record-fields] $CRATE/$V071_TIMELOCK: the record lacks the rustc string '$RUSTC_194' as a code span" "rustc string inside a longer code span"
new_case c08-cap85-source
replace_text "$REPO/$CRATE/vendor/cap85-beacon/v0.1.0/REFERENCE.md" contracts/cap85-beacon REMOVED
stage
run_check_tree
expect_rc 1 "cap85 record without its source path"
expect_out "tree-check [record-fields] $CRATE/$CAP85: the record lacks the source path contracts/cap85-beacon" "cap85 record without its source path"
pass "8 a record without its commit, rustc string, builder line, or source path fails, and so does a longer version string in either code span"

# 9. A tag that resolves to another commit fails before any build.
new_case c09
printf 'v0.7.2 %s\nv0.7.1 %s\n' "$OZ_V072" "$OZ_V072" >"$DATA/git-tags"
run_full
expect_rc 2 "tag commit"
expect_out "precondition failed: the tag v0.7.1 of the OpenZeppelin clone resolves to '$OZ_V072', not $OZ_V071" "tag commit"
expect_builds 0 "tag commit"
pass "9 a tag that resolves to another commit stops the run before any build"

# 10. A builder whose first --version line differs fails before any build.
new_case c10a
printf 'stellar 25.2.0 (28484880988199233a7e8e87c97cb12dac323cb3)\n' >"$DATA/stellar-25.version"
run_full
expect_rc 2 "builder 25 revision"
expect_out "precondition failed: the s25 builder" "builder 25 revision"
expect_builds 0 "builder 25 revision"
new_case c10b
printf 'stellar 28.0.0 (0000000000000000000000000000000000000000)\n' >"$DATA/stellar-28.version"
run_full
expect_rc 2 "builder 28 version"
expect_out "precondition failed: the s28 builder" "builder 28 version"
expect_builds 0 "builder 28 version"
pass "10 a builder with another version line stops the run before any build"

# 11. A toolchain whose rustc --version differs fails before any build.
new_case c11
printf '1.94.0|%s\n1.96.0|rustc 1.96.0 (0000000 2026-05-25)\n1.98.0|%s\n' "$RUSTC_194" "$RUSTC_198" >"$DATA/rustc"
run_full
expect_rc 2 "rustc string"
expect_out "precondition failed: rustc of toolchain 1.96.0 prints 'rustc 1.96.0 (0000000 2026-05-25)'" "rustc string"
expect_builds 0 "rustc string"
pass "11 a toolchain with another rustc string stops the run before any build"

# 12. Each refused variable, a cargo config in the cargo home or a parent of
# a build directory, and a cargo home with a space fail before any build.
for assignment in RUSTFLAGS=-Dwarnings CARGO_ENCODED_RUSTFLAGS=-Dwarnings CARGO_BUILD_RUSTFLAGS=-Dwarnings \
  TARGET_wasm32v1-none_RUSTFLAGS=-Dwarnings CARGO_TARGET_WASM32V1_NONE_RUSTFLAGS=-Dwarnings \
  RUSTC=/bin/false RUSTC_WRAPPER=/bin/false RUSTC_WORKSPACE_WRAPPER=/bin/false \
  CARGO_BUILD_RUSTC=/bin/false CARGO_BUILD_RUSTC_WRAPPER=/bin/false CARGO_PROFILE_RELEASE_OPT_LEVEL=0; do
  variable=${assignment%%=*}
  new_case "c12-$variable"
  run_full "$assignment"
  expect_rc 2 "refused $variable"
  expect_out "refused: the variable $variable is set" "refused $variable"
  expect_builds 0 "refused $variable"
done
new_case c12-cargo-home-config
mkdir -p "$CASE/cargo-home"
printf '[build]\njobs = 1\n' >"$CASE/cargo-home/config.toml"
run_full "CARGO_HOME=$CASE/cargo-home"
expect_rc 2 "cargo home config"
expect_out "refused: a cargo config file exists in the cargo home '$CASE/cargo-home'" "cargo home config"
expect_builds 0 "cargo home config"
new_case c12-parent-config
mkdir -p "$CASE/.cargo"
printf '[build]\njobs = 1\n' >"$CASE/.cargo/config.toml"
run_full
expect_rc 2 "parent cargo config"
expect_out "refused: a cargo config file exists in '$CASE/.cargo'" "parent cargo config"
expect_builds 0 "parent cargo config"
new_case c12-cargo-home-space
mkdir -p "$CASE/cargo home"
run_full "CARGO_HOME=$CASE/cargo home"
expect_rc 2 "cargo home with a space"
expect_out "refused: the cargo home '$CASE/cargo home' contains whitespace" "cargo home with a space"
expect_builds 0 "cargo home with a space"
new_case c12-cargo-home-legacy-config
mkdir -p "$CASE/cargo-home"
printf '[build]\njobs = 1\n' >"$CASE/cargo-home/config"
run_full "CARGO_HOME=$CASE/cargo-home"
expect_rc 2 "cargo home legacy config"
expect_out "refused: a cargo config file exists in the cargo home '$CASE/cargo-home'" "cargo home legacy config"
expect_builds 0 "cargo home legacy config"
new_case c12-parent-legacy-config
mkdir -p "$CASE/.cargo"
printf '[build]\njobs = 1\n' >"$CASE/.cargo/config"
run_full
expect_rc 2 "parent legacy cargo config"
expect_out "refused: a cargo config file exists in '$CASE/.cargo'" "parent legacy cargo config"
expect_builds 0 "parent legacy cargo config"
# The tree row's copy carries a tracked cargo config of its source.
new_case c12-source-config
mkdir -p "$REPO/contracts/cap85-beacon/.cargo"
printf '[build]\njobs = 1\n' >"$REPO/contracts/cap85-beacon/.cargo/config.toml"
stage
run_full
expect_rc 2 "source directory cargo config"
expect_out "refused: a cargo config file exists in '$WORK/src/tree-contracts-cap85-beacon/.cargo'" "source directory cargo config"
expect_builds 0 "source directory cargo config"
pass "12 every refused variable, a cargo config or legacy config in the cargo home, a parent, or a source directory, and a cargo home with a space stop the run before any build"

# 13. A failing build fails its row; an output left by an earlier build in a
# shared target directory is deleted before the later row's build.
new_case c13
set_action "$V071_WEBAUTHN" fail
set_action "$V072_MULTISIG" "also:release/timelock_controller_example.wasm=$BYTES/4.wasm"
set_action "$V072_TIMELOCK" nothing
run_full
expect_rc 1 "failing and stale rows"
expect_column "$V071_WEBAUTHN" 7 build-failed "failing and stale rows"
expect_column "$V072_TIMELOCK" 7 missing-output "failing and stale rows"
expect_column "$V072_MULTISIG" 7 match "failing and stale rows"
expect_builds 14 "failing and stale rows"
pass "13 a failing build fails its row, and a stale output in a shared target directory does not pass a later row"

# 14. A build that rewrites a vendored file fails the end-of-run check.
new_case c14
printf '%s\n' "$REPO/$CRATE/$V071_THRESHOLD" >"$DATA/rewrite"
run_full
expect_rc 1 "vendored file rewritten"
expect_out "end-check: a vendored file changed during the run" "vendored file rewritten"
new_case c14b
printf '%s\n' "$REPO/written-by-a-build.txt" >"$DATA/rewrite"
run_full
expect_rc 1 "repository status changed"
expect_out "end-check: git status of the repository root changed during the run" "repository status changed"
pass "14 a build that rewrites a vendored file, or writes any file under the repository, fails the end-of-run check"

# 15. A work directory inside the repository is refused.
new_case c15
run_script -- --repo-root "$REPO" --oz-clone "$OZ" --stellar-25 "$STUBS/stellar-25" \
  --stellar-28 "$STUBS/stellar-28" --work "$REPO/work"
expect_rc 2 "work inside the repository"
expect_out "refused: the work directory '$REPO/work' lies inside the repository root '$REPO'" "work inside the repository"
expect_builds 0 "work inside the repository"
pass "15 a work directory inside the repository root is refused"

# 16. A manifest row's toolchain reaches its build: a copy of the script with
# the Ed25519 verifier row on 1.98.0, and its record naming that rustc.
new_case c16
awk '$1 == "vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm" { $4 = "1.98.0" } { print }' \
  "$SCRIPT" >"$CASE/rebuild-copy.sh"
grep -qF "multisig_ed25519_verifier_example.wasm oz:v0.7.2 multisig-ed25519-verifier-example 1.98.0" "$CASE/rebuild-copy.sh" ||
  fail "toolchain row: the script copy was not edited"
printf '\nAlso built with %s.\n' "\`$RUSTC_198\`" >>"$REPO/$CRATE/vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md"
stage
run_full "SCRIPT=$CASE/rebuild-copy.sh"
expect_rc 1 "toolchain row"
grep -qF "args=contract build --locked --package multisig-ed25519-verifier-example|toolchain=1.98.0|" "$DATA/log" ||
  fail "toolchain row: the Ed25519 verifier build did not run with toolchain 1.98.0"
expect_column "$V072_ED25519" 7 missing-output "toolchain row"
expect_column "$V072_ED25519" 9 match "toolchain row"
expect_others_match "$V072_ED25519" "toolchain row"
pass "16 a row's toolchain reaches its build, and only that row fails"

# 17. A source worktree that a build changes fails the end-of-run check.
new_case c17
printf 'oz-v0.7.2\n' >"$DATA/dirty-after"
run_full
expect_rc 1 "dirty worktree"
expect_out "end-check: the v0.7.2 worktree changed during the builds" "dirty worktree"
new_case c17b
printf 'oz-v0.7.1\n' >"$DATA/dirty-before"
run_full
expect_rc 2 "worktree dirty before the builds"
expect_out "precondition failed: the v0.7.1 worktree is not clean before the builds" "worktree dirty before the builds"
expect_builds 0 "worktree dirty before the builds"
pass "17 a worktree that is not clean before the builds, or has a changed Cargo.lock after them, fails"

# 18. --rebuild-needed on a repository with commits.
RN="$TMP/rebuild-needed"
"$REAL_GIT" init -q "$RN"
mkdir -p "$RN/$CRATE/vendor/x" "$RN/$CRATE/src" "$RN/contracts/c" "$RN/.github/scripts" "$RN/.github/workflows" "$RN/docs"
for f in "$CRATE/vendor/x/f" "$CRATE/build.rs" "$CRATE/src/lib.rs" contracts/c/f \
  .github/scripts/rebuild-vendored-wasm.sh .github/scripts/test-rebuild-vendored-wasm.sh \
  .github/workflows/vendored-wasm.yml docs/README.md; do
  printf 'v0\n' >"$RN/$f"
done
"$REAL_GIT" -C "$RN" add -A
"$REAL_GIT" -C "$RN" commit -q -m base
# A stub git whose diff fails; every other call runs the real git.
DIFF_FAILS="$TMP/diff-fails"
mkdir -p "$DIFF_FAILS"
cat >"$DIFF_FAILS/git" <<EOF
#!/bin/sh
for arg in "\$@"; do
  [ "\$arg" = diff ] && exit 1
done
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$DIFF_FAILS/git"
RN_STUBS=$NO_STUBS
rn() {
  OUT="$TMP/rebuild-needed.out"
  STUBS="$RN_STUBS" CASE="$TMP" run_script -- --rebuild-needed --repo-root "$RN" "$@"
  [ "$RC" = 0 ] || fail "rebuild-needed $*: exit $RC"
  cat "$OUT"
}
change() {
  local before
  before=$("$REAL_GIT" -C "$RN" rev-parse HEAD)
  printf 'v%s\n' "$RANDOM" >>"$RN/$1"
  "$REAL_GIT" -C "$RN" add -A
  "$REAL_GIT" -C "$RN" commit -q -m "change $1"
  CHANGE_BASE=$before
  CHANGE_HEAD=$("$REAL_GIT" -C "$RN" rev-parse HEAD)
}
for f in "$CRATE/vendor/x/f" "$CRATE/build.rs" contracts/c/f .github/scripts/rebuild-vendored-wasm.sh \
  .github/scripts/test-rebuild-vendored-wasm.sh .github/workflows/vendored-wasm.yml; do
  change "$f"
  for event in pull_request push; do
    [ "$(rn --event "$event" --base "$CHANGE_BASE" --head "$CHANGE_HEAD")" = true ] ||
      fail "rebuild-needed: a change to $f on $event did not print true"
  done
done
before=$("$REAL_GIT" -C "$RN" rev-parse HEAD)
mkdir -p "$RN/moved"
"$REAL_GIT" -C "$RN" mv contracts/c/f moved/f
"$REAL_GIT" -C "$RN" commit -q -m "move out of contracts"
[ "$(rn --event push --base "$before" --head "$("$REAL_GIT" -C "$RN" rev-parse HEAD)")" = true ] ||
  fail "rebuild-needed: a file moved out of contracts/ did not print true"
for f in docs/README.md "$CRATE/src/lib.rs"; do
  change "$f"
  [ "$(rn --event pull_request --base "$CHANGE_BASE" --head "$CHANGE_HEAD")" = false ] ||
    fail "rebuild-needed: a change to $f did not print false"
done
head=$("$REAL_GIT" -C "$RN" rev-parse HEAD)
for base in "1111111111111111111111111111111111111111" "0000000000000000000000000000000000000000" ""; do
  [ "$(rn --event push --base "$base" --head "$head")" = true ] ||
    fail "rebuild-needed: the base '$base' did not print true"
done
for event in tag schedule workflow_dispatch unknown_event; do
  [ "$(rn --event "$event" --base "$CHANGE_BASE" --head "$CHANGE_HEAD")" = true ] ||
    fail "rebuild-needed: the event $event did not print true"
done
# A diff that fails after both revisions resolve prints true.
change docs/README.md
RN_STUBS=$DIFF_FAILS
[ "$(rn --event pull_request --base "$CHANGE_BASE" --head "$CHANGE_HEAD")" = true ] ||
  fail "rebuild-needed: a failing git diff did not print true"
RN_STUBS=$NO_STUBS
# The workflow's pull_request form: base HEAD^1 and head HEAD on a merge commit,
# whose first parent is the base branch tip.
main_branch=$("$REAL_GIT" -C "$RN" symbolic-ref --short HEAD)
merge_change() {
  "$REAL_GIT" -C "$RN" checkout -q -b "$1"
  printf '%s\n' "$1" >>"$RN/$2"
  "$REAL_GIT" -C "$RN" add -A
  "$REAL_GIT" -C "$RN" commit -q -m "$1: change $2"
  "$REAL_GIT" -C "$RN" checkout -q "$main_branch"
  printf '%s\n' "$1" >>"$RN/$3"
  "$REAL_GIT" -C "$RN" add -A
  "$REAL_GIT" -C "$RN" commit -q -m "$main_branch: change $3"
  "$REAL_GIT" -C "$RN" merge -q --no-ff -m "merge $1" "$1"
}
merge_change pr-vendor "$CRATE/vendor/x/f" docs/README.md
[ "$(rn --event pull_request --base 'HEAD^1' --head HEAD)" = true ] ||
  fail "rebuild-needed: a merge commit that brings a vendor/ change did not print true"
merge_change pr-docs docs/README.md "$CRATE/vendor/x/f"
[ "$(rn --event pull_request --base 'HEAD^1' --head HEAD)" = false ] ||
  fail "rebuild-needed: a merge commit that brings only a docs/ change did not print false"
pass "18 --rebuild-needed prints true for each rebuild prefix, a move out of contracts/, bad bases, a failing diff, and other events, and false otherwise, also on a merge commit against HEAD^1"

# 19. --gate.
gate() {
  OUT="$TMP/gate.out"
  STUBS="$NO_STUBS" CASE="$TMP" run_script -- --gate "$@"
}
gate success true success success success
expect_rc 0 "gate rebuild true"
expect_out "check=success rebuild=true stellar-cli-25=success stellar-cli-28=success rebuild-job=success" "gate rebuild true"
gate success false skipped skipped skipped
expect_rc 0 "gate rebuild false"
expect_out "check=success rebuild=false stellar-cli-25=skipped stellar-cli-28=skipped rebuild-job=skipped" "gate rebuild false"
gate_fails() {
  gate "$@"
  expect_rc 1 "gate '$1' '$2' '$3' '$4' '$5'"
  expect_out "gate FAIL" "gate '$1' '$2' '$3' '$4' '$5'"
}
for value in failure cancelled; do
  gate_fails "$value" true success success success
  gate_fails "$value" false skipped skipped skipped
  gate_fails success true "$value" success success
  gate_fails success true success "$value" success
  gate_fails success true success success "$value"
  gate_fails success false "$value" skipped skipped
  gate_fails success false skipped "$value" skipped
  gate_fails success false skipped skipped "$value"
done
gate_fails skipped true success success success
gate_fails skipped false skipped skipped skipped
gate_fails success true skipped success success
gate_fails success true success skipped success
gate_fails success true success success skipped
gate_fails success false success skipped skipped
gate_fails success false skipped success skipped
gate_fails success false skipped skipped success
gate_fails success "" skipped skipped skipped
gate_fails success "" success success success
pass "19 --gate passes only the two passing combinations; every failure, cancelled, or skipped input elsewhere and an empty rebuild fail"

# 20. --exec refuses before running the command, and runs a passing command in
# its directory under the allowlist.
new_case c20
mkdir -p "$CASE/build"
OUT="$CASE/out"
run_script "RUSTFLAGS=-Dwarnings" -- --exec --dir "$CASE/build" -- /bin/sh -c ": >'$CASE/ran'"
expect_rc 2 "exec refused"
expect_out "refused: the variable RUSTFLAGS is set" "exec refused"
[ ! -e "$CASE/ran" ] || fail "exec refused: the command ran"
run_script "SELFTEST_SENTINEL=1" "RUSTUP_TOOLCHAIN=1.96.0" -- --exec --dir "$CASE/build" -- \
  /bin/sh -c "pwd -P >'$CASE/pwd'; env >'$CASE/env'"
expect_rc 0 "exec passes"
[ "$(cat "$CASE/pwd")" = "$CASE/build" ] || fail "exec passes: the command ran in $(cat "$CASE/pwd")"
if grep -q '^SELFTEST_SENTINEL=' "$CASE/env"; then fail "exec passes: the command saw SELFTEST_SENTINEL"; fi
grep -qx 'RUSTUP_AUTO_INSTALL=0' "$CASE/env" || fail "exec passes: the command did not see RUSTUP_AUTO_INSTALL=0"
grep -qx 'RUSTUP_TOOLCHAIN=1.96.0' "$CASE/env" || fail "exec passes: the command did not see RUSTUP_TOOLCHAIN"
pass "20 --exec refuses before the command runs, and runs a passing command in its directory under the allowlist"

# 21. --list-toolchains.
OUT="$TMP/list.out"
STUBS="$NO_STUBS" CASE="$TMP" run_script -- --list-toolchains
expect_rc 0 "list-toolchains"
[ "$(cat "$OUT")" = "1.94.0 wasm32v1-none
1.96.0 wasm32v1-none
1.98.0 wasm32v1-none" ] || fail "list-toolchains printed: $(cat "$OUT")"
pass "21 --list-toolchains prints the three toolchain and target pairs"

# 22. cfg rules, one edit at a time in the scratch src/.
new_case c22a
file="$REPO/$CRATE/src/verifier_allowlist.rs"
insert_before "$file" '^\];$' "    #[cfg(not(test))]
    VerifierAllowlistEntry {
        wasm_hash: [0x11; 32],
        audit_status: VerifierAuditStatus::Unaudited,
    },"
stage
want=$(line_of "$file" "#[cfg(not(test))]")
run_check_tree
expect_rc 1 "cfg(not(test)) allowlist entry"
expect_out "tree-check [cfg] $CRATE/src/verifier_allowlist.rs:$want: a cfg predicate negates a setting other than unix or windows" "cfg(not(test)) allowlist entry"
expect_out "tree-check [cfg] $CRATE/src/verifier_allowlist.rs:$want: the value of VERIFIER_ALLOWLIST carries #[cfg(not(test))]" "cfg(not(test)) allowlist entry"

expect_literal_fixture_status "c22a"

new_case c22b
file="$REPO/$CRATE/src/deployment/deploy.rs"
insert_before "$file" '^pub const MULTISIG_ACCOUNT_WASM: ' "#[cfg(test)]"
stage
want=$(line_of "$file" "#[cfg(test)]")
run_check_tree
expect_rc 1 "cfg(test) on a constant"
expect_out "tree-check [cfg] $CRATE/src/deployment/deploy.rs:$want: the definition of MULTISIG_ACCOUNT_WASM carries #[cfg(test)]" "cfg(test) on a constant"

new_case c22c
file="$REPO/$CRATE/src/bindings.rs"
printf '\n/// Test build marker.\npub const TEST_BUILD: bool = cfg!(test);\n' >>"$file"
stage
want=$(line_of "$file" "pub const TEST_BUILD")
run_check_tree
expect_rc 1 "cfg! expression"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs:$want: the cfg! macro is used" "cfg! expression"

new_case c22d
file="$REPO/$CRATE/src/lib.rs"
insert_before "$file" '^pub mod bindings;$' '#[cfg_attr(not(test), path = "x.rs")]
mod extra_module;'
stage
want=$(line_of "$file" "#[cfg_attr(not(test), path")
run_check_tree
expect_rc 1 "cfg_attr path"
expect_out "tree-check [cfg] $CRATE/src/lib.rs:$want: a cfg_attr applies a path attribute" "cfg_attr path"

new_case c22e
file="$REPO/$CRATE/src/lib.rs"
insert_before "$file" '^pub mod bindings;$' '#[path = "x.rs"]
mod extra_module;'
stage
want=$(line_of "$file" '#[path = "x.rs"]')
run_check_tree
expect_rc 1 "path attribute"
expect_out "tree-check [cfg] $CRATE/src/lib.rs:$want: a path attribute loads another source file" "path attribute"

new_case c22f
file="$REPO/$CRATE/src/bindings.rs"
printf '\ninclude!("x.rs");\n' >>"$file"
stage
want=$(line_of "$file" 'include!("x.rs");')
run_check_tree
expect_rc 1 "include! macro"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs:$want: the include! macro is used" "include! macro"

new_case c22g
file="$REPO/$CRATE/src/bindings.rs"
printf '\n/// Release marker.\n#[cfg_attr(not(test), derive(Debug))]\npub struct ReleaseMarker;\n' >>"$file"
stage
want=$(line_of "$file" "#[cfg_attr(not(test), derive(Debug))]")
run_check_tree
expect_rc 1 "negated cfg_attr with a non-lint attribute"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs:$want: a cfg_attr with a negated predicate applies an attribute other than a lint level: #[cfg_attr(not(test),derive(Debug))]" "negated cfg_attr with a non-lint attribute"

new_case c22h
file="$REPO/$CRATE/src/bindings.rs"
printf '\n/// Lint level outside tests.\n#[cfg_attr(not(test), forbid(unsafe_code))]\npub fn lint_level_marker() {}\n' >>"$file"
stage
run_check_tree
expect_rc 0 "negated cfg_attr with forbid"
expect_out "rebuild-vendored-wasm: PASS" "negated cfg_attr with forbid"
pass "22 a negated cfg entry, a cfg on a pinned constant, cfg!, a cfg_attr path, a path attribute, include!, and a negated cfg_attr with a non-lint attribute fail with their file and line; a negated cfg_attr with forbid passes"

# 23. Raw identifiers read as their names.
new_case c23a
file="$REPO/$CRATE/src/verifier_allowlist.rs"
insert_before "$file" '^\];$' "    #[r#cfg(not(test))]
    VerifierAllowlistEntry {
        wasm_hash: [0x11; 32],
        audit_status: VerifierAuditStatus::Unaudited,
    },"
stage
want=$(line_of "$file" "#[r#cfg(not(test))]")
run_check_tree
expect_rc 1 "r#cfg allowlist entry"
expect_out "tree-check [cfg] $CRATE/src/verifier_allowlist.rs:$want: a cfg predicate negates a setting other than unix or windows: #[r#cfg(not(test))]" "r#cfg allowlist entry"
expect_out "tree-check [cfg] $CRATE/src/verifier_allowlist.rs:$want: the value of VERIFIER_ALLOWLIST carries #[r#cfg(not(test))]" "r#cfg allowlist entry"

expect_literal_fixture_status "c23a"

new_case c23b
file="$REPO/$CRATE/src/lib.rs"
insert_before "$file" '^pub mod bindings;$' '#[r#cfg_attr(not(test), path = "x.rs")]
mod extra_module;'
stage
want=$(line_of "$file" "#[r#cfg_attr(not(test), path")
run_check_tree
expect_rc 1 "r#cfg_attr path"
expect_out "tree-check [cfg] $CRATE/src/lib.rs:$want: a cfg_attr applies a path attribute: #[r#cfg_attr(not(test),path=\"x.rs\")]" "r#cfg_attr path"

new_case c23c
file="$REPO/$CRATE/src/lib.rs"
insert_before "$file" '^pub mod bindings;$' '#[r#path = "x.rs"]
mod extra_module;'
stage
want=$(line_of "$file" '#[r#path = "x.rs"]')
run_check_tree
expect_rc 1 "r#path attribute"
expect_out "tree-check [cfg] $CRATE/src/lib.rs:$want: a path attribute loads another source file: #[r#path=\"x.rs\"]" "r#path attribute"

new_case c23d
file="$REPO/$CRATE/src/bindings.rs"
printf '\n/// Test build marker.\npub const TEST_BUILD: bool = r#cfg!(test);\n' >>"$file"
stage
want=$(line_of "$file" "pub const TEST_BUILD")
run_check_tree
expect_rc 1 "r#cfg! expression"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs:$want: the cfg! macro is used" "r#cfg! expression"
pass "23 r#cfg, r#cfg_attr, r#path, and r#cfg! read as cfg, cfg_attr, path, and cfg!"

# 24. A use declaration that renames cfg or include, on one line or several.
new_case c24a
file="$REPO/$CRATE/src/bindings.rs"
printf '\nuse core::cfg as build_mode;\n' >>"$file"
stage
want=$(line_of "$file" "use core::cfg as build_mode;")
run_check_tree
expect_rc 1 "cfg imported under another name"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs:$want: the cfg macro is imported under another name" "cfg imported under another name"

# Both multisig constants select their file and digest through the renamed
# macro; both include paths are manifest paths.
new_case c24b
file="$REPO/$CRATE/src/deployment/deploy.rs"
insert_before "$file" '^use std::time::Duration;$' 'use core::{
    cfg as build_mode,
};'
replace_line "$file" '^pub const MULTISIG_ACCOUNT_WASM: &\[u8\] =$' 'pub const MULTISIG_ACCOUNT_WASM: &[u8] = if build_mode!(test) { include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm") } else {'
replace_line "$file" '^    include_bytes!\("\.\./\.\./vendor/oz-smart-account-multisig/v0\.7\.2/multisig_account_example\.wasm"\);$' '    include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm") };'
replace_line "$file" '^pub const MULTISIG_ACCOUNT_WASM_SHA256: &str =$' 'pub const MULTISIG_ACCOUNT_WASM_SHA256: &str = if build_mode!(test) { "5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286" } else {'
replace_line "$file" '^    "5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286";$' '    "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239" };'
stage
want=$(line_of "$file" "    cfg as build_mode,")
run_check_tree
expect_rc 1 "grouped multiline import of cfg"
expect_out "tree-check [cfg] $CRATE/src/deployment/deploy.rs:$want: the cfg macro is imported under another name" "grouped multiline import of cfg"

new_case c24c
file="$REPO/$CRATE/src/bindings.rs"
printf '\nuse core::{\n    include as inline_source,\n};\n' >>"$file"
stage
want=$(line_of "$file" "    include as inline_source,")
run_check_tree
expect_rc 1 "include imported under another name"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs:$want: the include macro is imported under another name" "include imported under another name"
pass "24 a use declaration that renames cfg or include fails, on one line or across lines"

# 25. Each bound definition and each module declaration on its path is
# unindented and appears once.
new_case c25a
file="$REPO/$CRATE/src/bindings.rs"
replace_line "$file" '^pub const WASM: &\[u8\] =$' '    pub const WASM: &[u8] ='
stage
run_check_tree
expect_rc 1 "indented definition"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs: WASM is not defined exactly once, unindented, in this file" "indented definition"

new_case c25b
file="$REPO/$CRATE/src/bindings.rs"
printf '\n/// A second definition.\nmod shadow {\n    pub const WASM: &[u8] = &[];\n}\n' >>"$file"
stage
run_check_tree
expect_rc 1 "second, indented definition"
expect_out "tree-check [cfg] $CRATE/src/bindings.rs: WASM is not defined exactly once, unindented, in this file" "second, indented definition"

new_case c25c
file="$REPO/$CRATE/src/lib.rs"
insert_before "$file" '^pub mod deployment;$' '#[cfg(test)]'
stage
want=$(line_of "$file" "#[cfg(test)]")
run_check_tree
expect_rc 1 "cfg on a module declaration"
expect_out "tree-check [cfg] $CRATE/src/lib.rs:$want: the declaration of module deployment carries #[cfg(test)]" "cfg on a module declaration"

new_case c25d
file="$REPO/$CRATE/src/lib.rs"
replace_line "$file" '^pub mod bindings;$' '    pub mod bindings;'
stage
run_check_tree
expect_rc 1 "indented module declaration"
expect_out "tree-check [cfg] $CRATE/src/lib.rs: the module bindings is not declared exactly once, unindented, as mod bindings;" "indented module declaration"
pass "25 an indented or second definition, a cfg on a module declaration on its path, and an indented module declaration fail"

# 26. The test-only allowlist fixture: one item, under its permitted attribute.
new_case c26a
file="$REPO/$CRATE/src/verifier_allowlist.rs"
awk '!done && $0 == "    #[cfg(any(test, feature = \"test-helpers\"))]" { done = 1; next } { print } END { if (!done) exit 3 }' \
  "$file" >"$file.new" || fail "the fixture gate of $file was not found"
mv "$file.new" "$file"
stage
want=$(line_of "$file" "pub const VERIFIER_ALLOWLIST")
run_check_tree
expect_rc 1 "fixture without its attribute"
expect_out "tree-check [cfg] $CRATE/src/verifier_allowlist.rs:$want: the value of VERIFIER_ALLOWLIST holds 0 items with wasm_hash:[0xee;32] under #[cfg(any(test,feature=\"test-helpers\"))], not exactly one" "fixture without its attribute"

new_case c26b
file="$REPO/$CRATE/src/verifier_allowlist.rs"
insert_before "$file" '^\];$' "    VerifierAllowlistEntry {
        wasm_hash: [0xee; 32],
        audit_status: VerifierAuditStatus::Unaudited,
    },"
stage
want=$(line_of "$file" "pub const VERIFIER_ALLOWLIST")
run_check_tree
expect_rc 1 "second fixture without the attribute"
expect_out "tree-check [cfg] $CRATE/src/verifier_allowlist.rs:$want: the value of VERIFIER_ALLOWLIST contains wasm_hash:[0xee;32] 2 times, not exactly once" "second fixture without the attribute"

expect_literal_fixture_status "c26b"

new_case c26c
file="$REPO/$CRATE/src/verifier_allowlist.rs"
insert_before "$file" '^    VerifierAllowlistEntry \{$' '    #[cfg(any(test, feature = "test-helpers"))]'
stage
want=$(line_of "$file" '    #[cfg(any(test, feature = "test-helpers"))]')
run_check_tree
expect_rc 1 "fixture attribute on a production entry"
expect_out "tree-check [cfg] $CRATE/src/verifier_allowlist.rs:$want: #[cfg(any(test,feature=\"test-helpers\"))] in VERIFIER_ALLOWLIST applies to an item without wasm_hash:[0xee;32]" "fixture attribute on a production entry"
pass "26 the allowlist fixture without its attribute, a second fixture, and its attribute on a production entry fail"

# 27. Full mode builds in fresh source and target directories: content left
# under --work by an earlier run is removed first.
new_case c27
mkdir -p "$WORK/src/tree-contracts-cap85-beacon" "$WORK/target/oz-v0.7.2"
: >"$WORK/src/tree-contracts-cap85-beacon/stale"
: >"$WORK/target/oz-v0.7.2/stale"
run_full
expect_rc 0 "stale work directory"
[ ! -e "$WORK/src/tree-contracts-cap85-beacon/stale" ] || fail "stale work directory: a stale source file survived the run"
[ ! -e "$WORK/target/oz-v0.7.2/stale" ] || fail "stale work directory: a stale target file survived the run"
[ -f "$WORK/src/tree-contracts-cap85-beacon/Cargo.toml" ] ||
  fail "stale work directory: the tree row's source copy lacks the tracked Cargo.toml"
pass "27 full mode replaces the source and target directories left by an earlier run"

# 28. Each corpus row is one spelling, its verdict, and its diagnostic.
# All rows run in one scratch repository, restored from BASE between rows.
new_case c28

set_ed25519_hash() {
  HASH="$1" awk '
    /^        wasm_hash: \[/ { entry++ }
    entry == 3 && !done {
      if (!skip) print "        wasm_hash: " ENVIRON["HASH"] ","
      skip = 1
      if ($0 ~ /^        \],$/) { done = 1; skip = 0 }
      next
    }
    { print }
    END { if (!done) exit 3 }
  ' "$REPO/$CRATE/src/verifier_allowlist.rs" >"$CASE/hash.new" || fail "missing Ed25519 hash"
  mv "$CASE/hash.new" "$REPO/$CRATE/src/verifier_allowlist.rs"
}

select_multisig() {
  local file="$REPO/$CRATE/src/deployment/deploy.rs"
  replace_line "$file" '^pub const MULTISIG_ACCOUNT_WASM: &\[u8\] =$' "pub const MULTISIG_ACCOUNT_WASM: &[u8] = if $1 {"
  replace_line "$file" '^    include_bytes!\("\.\./\.\./vendor/oz-smart-account-multisig/v0\.7\.2/multisig_account_example\.wasm"\);$' '    include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm") } else { include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm") };'
  replace_line "$file" '^pub const MULTISIG_ACCOUNT_WASM_SHA256: &str =$' "pub const MULTISIG_ACCOUNT_WASM_SHA256: &str = if $1 {"
  replace_line "$file" '^    "5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286";$' '    "5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286" } else { "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239" };'
}

remove_fixture_gate() {
  replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" '    #[cfg(any(test, feature = "test-helpers"))]' ''
}

CORPUS_PASSED=0
CONTROLS_PASSED=0

SPELLINGS='n1|1|the cfg! macro is used
n2|1|src/release_hashes.rs:1: a cfg predicate negates
raw_cfg_invocation_refused|1|the cfg! macro is used
comment_predicate|1|a cfg predicate negates
nested_path|1|a cfg_attr applies a path attribute
n5|1|include_bytes! does not take exactly one string literal
e5|1|a cfg predicate negates
n6|1|a cfg predicate negates
char_unicode|1|a cfg predicate negates
char_escape|1|a cfg predicate negates
u1|1|non-ASCII bytes in code text
ws0085|1|non-ASCII bytes in code text
ws200e|1|non-ASCII bytes in code text
ws200f|1|non-ASCII bytes in code text
ws2029|1|non-ASCII bytes in code text
unicode_literals|0|PASS
e1|1|a cfg_attr applies cfg or cfg_attr
cfg_false|1|a cfg_attr applies cfg or cfg_attr
cfg_nested|1|a cfg_attr applies cfg or cfg_attr
e8|1|src/release_hashes.rs:1: a cfg_attr applies cfg or cfg_attr
e2|1|a metavariable supplies an attribute or macro name
macro_name|1|a metavariable supplies an attribute or macro name
e3|1|a metavariable occurs in attribute text
e4|1|a metavariable supplies an attribute or macro name
inner_meta|1|a metavariable supplies an attribute or macro name
e7|1|VERIFIER_ALLOWLIST hash must use a direct
dependency_macro_unused|0|PASS
e6|1|VERIFIER_ALLOWLIST hash must use a direct
l1|1|the definition of MULTISIG_ACCOUNT_WASM carries #[cfg(test)]
module_attachment|1|the declaration of module bindings carries #[cfg(test)]
split_definition|1|WASM is not defined exactly once
split_module|1|the module bindings is not declared exactly once
module_duplicate|1|the module bindings is not declared exactly once
split_primary|0|PASS
macro_forward|1|MULTISIG_ACCOUNT_WASM must use a direct
helper_direct|1|MULTISIG_ACCOUNT_WASM must use a direct
helper_nested|1|MULTISIG_ACCOUNT_WASM must use a direct
initializer_identifier|1|WASM must use a direct
initializer_path|1|WASM must use a direct
initializer_macro|1|WASM must use a direct
digest_identifier|1|WASM_SHA256 must use a direct
policy_identifier|1|THRESHOLD_POLICY_WASM_HASHES must use a direct
literal_bytes|0|PASS
f1|1|VERIFIER_ALLOWLIST entry must use a direct
f2|1|contains wasm_hash:[0xee;32] 2 times
fixture_decimal|0|PASS
fixture_uppercase|0|PASS
fixture_list|0|PASS
string_marker|1|VERIFIER_ALLOWLIST must use a direct
hash_string_marker|1|VERIFIER_ALLOWLIST hash must use a direct
fixture_attr_nested|1|VERIFIER_ALLOWLIST field must use a direct
fixture_ungated|1|holds 0 items
fixture_missing|1|contains wasm_hash:[0xee;32] 0 times
byte_expression|1|VERIFIER_ALLOWLIST hash must use a direct
byte_range|1|VERIFIER_ALLOWLIST hash must use a direct
byte_count|1|VERIFIER_ALLOWLIST hash must use a direct
literal_lifetimes|0|PASS
replace_contains_old|0|PASS
definition_indented|1|WASM is not defined exactly once
module_indented|1|the module bindings is not declared exactly once
digest_short|1|WASM_SHA256 must use a direct
digest_nonhex|1|WASM_SHA256 must use a direct
byte_hex_range|1|VERIFIER_ALLOWLIST hash must use a direct
byte_hex_list_range|1|VERIFIER_ALLOWLIST hash must use a direct
byte_repeat_expression|1|VERIFIER_ALLOWLIST hash must use a direct
byte_list_short|1|VERIFIER_ALLOWLIST hash must use a direct
hash_duplicate_field|1|VERIFIER_ALLOWLIST field must use a direct
status_missing|1|VERIFIER_ALLOWLIST entry must hold exactly one audit_status field
status_absent|1|VERIFIER_ALLOWLIST entry must hold exactly one audit_status field
fixture_attribute_production|1|applies to an item without wasm_hash:[0xee;32]
array_brackets|1|VERIFIER_ALLOWLIST must use a direct
punctuation_in_literals|0|PASS
attribute_string_metavariable|0|PASS
char_ascii_quote|1|a cfg predicate negates
x1|1|a macro_rules! definition is outside the known list
x2|1|a macro_rules! definition is outside the known list
x3|1|a macro_rules! definition is outside the known list
x4|1|a macro_rules! definition is outside the known list
x5|1|an inner cfg or cfg_attr attribute occurs in a watched file
x6|1|MULTISIG_ACCOUNT_WASM is not a top-level item of this file
x7|1|the module deployment is not declared at the top level of this file
u2|1|a macro_use attribute is used
codex_wrapper|1|a macro_rules! definition is outside the known list
macro_use_plain|1|a macro_use attribute is used
macro_use_nested|1|a macro_use attribute is used
inner_cfg_attr_definition|1|an inner cfg or cfg_attr attribute occurs in a watched file
inner_cfg_module|1|an inner cfg or cfg_attr attribute occurs in a watched file
inner_cfg_attr_module|1|an inner cfg or cfg_attr attribute occurs in a watched file
known_macro_duplicate|1|a macro_rules! definition is outside the known list
known_macro_body|1|a macro_rules! definition is outside the known list
known_macro_scope|1|a macro_rules! definition is outside the known list
known_macro_outside_owner|1|a macro_rules! definition is outside the known list
known_macro_file|1|a macro_rules! definition is outside the known list
status_macro|1|VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields
status_field_identifier|1|VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields
status_duplicate|1|VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields
status_unknown_field|1|VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields
status_unknown_variant|1|VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields
status_missing_field|1|VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields
status_raw_literal|0|PASS
status_identifier|1|VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields
status_variants|0|PASS'

while IFS='|' read -r spelling verdict diagnostic; do
  rm -rf "$REPO/$CRATE/src" "$REPO/crates/stellar-agent-core"
  cp -R "$BASE/$CRATE/src" "$REPO/$CRATE/src"
  file="$REPO/$CRATE/src/bindings.rs"
  echo "case - corpus $spelling"
  case "$spelling" in
    n1)
      cat >>"$file" <<'RS'
      const _: bool = ::core::cfg ! (test);
RS
      ;;
    n2)
      printf '#![cfg(not(test))]\n' >"$REPO/$CRATE/src/release_hashes.rs"
      printf '\nmod release_hashes;\n' >>"$REPO/$CRATE/src/lib.rs"
      ;;
    raw_cfg_invocation_refused)
      printf '\nconst _: bool = r#cfg!(test);\n' >>"$file"
      ;;
    comment_predicate)
      printf '\n#[cfg(not /* x */ (test))]\nconst _: bool = true;\n' >>"$file"
      ;;
    nested_path)
      printf '\n#[cfg_attr(test, cfg_attr(all(), path = "x.rs"))]\nmod x;\n' >>"$file"
      ;;
    n5)
      cat >>"$file" <<'RS'
      const P: &str = "../vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm";
      const _: &[u8] = include_bytes!(P);
RS
      ;;
    e5)
      cat >>"$file" <<'RS'
      const _: &str = stringify!('\x41'"'" );
      #[cfg(not(test))]
      const H: [u8; 32] = [0x33; 32]; // "
      #[cfg(test)]
      const H: [u8; 32] = [0x11; 32];
RS
      ;;
    n6)
      cat >>"$file" <<'RS'
      const _: &str = stringify!('UTF8_CHAR'"'" );
      #[cfg(not(test))]
      const H: [u8; 32] = [0x33; 32]; // "
      #[cfg(test)]
      const H: [u8; 32] = [0x11; 32];
RS
      utf8=$(printf '\303\251')
      replace_text "$file" UTF8_CHAR "$utf8"
      ;;
    char_unicode)
      cat >>"$file" <<'RS'
      const _: &str = stringify!('\u{0041}'"'" );
      #[cfg(not(test))]
      const H: [u8; 32] = [0x33; 32]; // "
      #[cfg(test)]
      const H: [u8; 32] = [0x11; 32];
RS
      ;;
    char_escape)
      cat >>"$file" <<'RS'
      const _: &str = stringify!('\n'"'" );
      #[cfg(not(test))]
      const H: [u8; 32] = [0x33; 32]; // "
      #[cfg(test)]
      const H: [u8; 32] = [0x11; 32];
RS
      ;;
    u1)
      ws=$(printf '\342\200\250')
      printf '\n#[cfg(not%s(test))]\nconst _: bool = cfg%s!(test);\n' "$ws" "$ws" >>"$file"
      ;;
    ws0085)
      ws=$(printf '\302\205')
      printf '\n#[cfg(not%s(test))]\nconst _: bool = cfg%s!(test);\n' "$ws" "$ws" >>"$file"
      ;;
    ws200e)
      ws=$(printf '\342\200\216')
      printf '\n#[cfg(not%s(test))]\nconst _: bool = cfg%s!(test);\n' "$ws" "$ws" >>"$file"
      ;;
    ws200f)
      ws=$(printf '\342\200\217')
      printf '\n#[cfg(not%s(test))]\nconst _: bool = cfg%s!(test);\n' "$ws" "$ws" >>"$file"
      ;;
    ws2029)
      ws=$(printf '\342\200\251')
      printf '\n#[cfg(not%s(test))]\nconst _: bool = cfg%s!(test);\n' "$ws" "$ws" >>"$file"
      ;;
    unicode_literals)
      utf8=$(printf '\303\251')
      printf '\nconst _: &str = "%s cfg!(test)"; // %s\nconst _: char = '\''%s'\'';\n' "$utf8" "$utf8" "$utf8" >>"$file"
      ;;
    e1)
      cat >>"$file" <<'RS'
      #[cfg_attr(test, cfg(any()))]
      const H: [u8; 32] = [0x33; 32];
RS
      ;;
    cfg_false)
      cat >>"$file" <<'RS'
      #[cfg_attr(test, cfg(false))]
      const H: [u8; 32] = [0x33; 32];
RS
      ;;
    cfg_nested)
      cat >>"$file" <<'RS'
      #[cfg_attr(all(), cfg_attr(test, cfg(any())))]
      const H: [u8; 32] = [0x33; 32];
RS
      ;;
    e8)
      printf '#![cfg_attr(test, cfg(any()))]\n' >"$REPO/$CRATE/src/release_hashes.rs"
      printf '\nmod release_hashes;\n#[cfg_attr(test, cfg(any()))]\nuse release_hashes::*;\n' >>"$file"
      ;;
    e2)
      cat >>"$file" <<'RS'
      macro_rules! forward { ($m:ident, $($a:tt)*) => { $m!($($a)*) }; }
RS
      select_multisig "forward!(cfg, test)"
      ;;
    macro_name)
      cat >>"$file" <<'RS'
      macro_rules! forward { ($m:ident) => { $m ! (test) }; }
RS
      ;;
    e3)
      cat >>"$file" <<'RS'
      macro_rules! gated { ($p:meta, $i:item) => { #[cfg($p)] $i }; }
      gated!(not(test), const H: [u8; 32] = [0x33; 32];);
RS
      ;;
    e4)
      cat >>"$file" <<'RS'
      macro_rules! attach { ($a:tt $i:item) => { #$a $i }; }
      attach!([cfg(not(test))] const H: [u8; 32] = [0x33; 32];);
RS
      ;;
    inner_meta)
      cat >>"$file" <<'RS'
      macro_rules! attach { ($a:tt) => { #!$a }; }
RS
      ;;
    e7)
      mkdir -p "$REPO/crates/stellar-agent-core/src"
      printf '#[macro_export]\nmacro_rules! in_unit_tests { () => { cfg!(test) }; }\n' >"$REPO/crates/stellar-agent-core/src/lib.rs"
      set_ed25519_hash 'if stellar_agent_core::in_unit_tests!() { [0xea; 32] } else { [0x33; 32] }'
      ;;
    dependency_macro_unused)
      mkdir -p "$REPO/crates/stellar-agent-core/src"
      printf '#[macro_export]\nmacro_rules! in_unit_tests { () => { cfg!(test) }; }\n' >"$REPO/crates/stellar-agent-core/src/lib.rs"
      ;;
    e6)
      cat >>"$file" <<'RS'
      mod release_hashes { pub(super) const H: [u8; 32] = [0x33; 32]; }
      #[allow(unused_imports)] use release_hashes::*;
      #[cfg(test)] const H: [u8; 32] = [0xea; 32];
RS
      set_ed25519_hash H
      ;;
    l1)
      file="$REPO/$CRATE/src/deployment/deploy.rs"
      replace_line "$file" '^use crate::deployment::address::derive_interop_deployer_seed;$' 'use crate::deployment::address::derive_interop_deployer_seed; #[cfg(test)]'
      ;;
    module_attachment)
      file="$REPO/$CRATE/src/lib.rs"
      insert_before "$file" '^pub mod bindings;$' 'const _: () = (); #[cfg(test)]'
      ;;
    split_definition)
      cat >>"$file" <<'RS'
      mod shadow { pub const
      WASM: &[u8] = &[]; }
RS
      ;;
    split_module)
      printf '\nmod shadow { pub mod\nbindings; }\n' >>"$REPO/$CRATE/src/lib.rs"
      ;;
    module_duplicate)
      printf '\nmod shadow {\n    pub mod bindings;\n}\n' >>"$REPO/$CRATE/src/lib.rs"
      ;;
    split_primary)
      replace_line "$file" '^pub const WASM: &\[u8\] =$' 'pub const
      WASM: &[u8] ='
      replace_line "$REPO/$CRATE/src/lib.rs" '^pub mod bindings;$' 'pub mod
      bindings;'
      ;;
    macro_forward)
      cat >>"$file" <<'RS'
      macro_rules! test_mode { ($m:ident) => { $m!(test) }; }
RS
      select_multisig "test_mode!(cfg)"
      ;;
    helper_direct)
      cat >>"$file" <<'RS'
      #[cfg(test)] const USE_CURRENT: bool = true;
      #[cfg_attr(test, cfg(any()))] const USE_CURRENT: bool = false;
RS
      select_multisig USE_CURRENT
      ;;
    helper_nested)
      cat >>"$file" <<'RS'
      #[cfg(test)] const USE_CURRENT: bool = true;
      #[cfg_attr(all(), cfg_attr(test, cfg(any())))] const USE_CURRENT: bool = false;
RS
      select_multisig USE_CURRENT
      ;;
    initializer_identifier)
      replace_line "$file" '^    include_bytes!\("\.\./vendor/oz-stellar-accounts/v0\.7\.2/stellar_accounts\.wasm"\);$' '    HELPER;'
      printf '\nconst HELPER: &[u8] = include_bytes!("../vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm");\n' >>"$file"
      ;;
    initializer_path)
      replace_line "$file" '^    include_bytes!\("\.\./vendor/oz-stellar-accounts/v0\.7\.2/stellar_accounts\.wasm"\);$' '    core::include_bytes!("../vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm");'
      ;;
    initializer_macro)
      replace_line "$file" '^    include_bytes!\("\.\./vendor/oz-stellar-accounts/v0\.7\.2/stellar_accounts\.wasm"\);$' '    choose!();'
      ;;
    digest_identifier)
      replace_text "$file" 'pub const WASM_SHA256: &str =' 'pub const WASM_SHA256: &str = HELPER;
      const HELPER: &str ='
      ;;
    policy_identifier)
      file="$REPO/$CRATE/src/signers/policy_identification.rs"
      replace_line "$file" '^pub const THRESHOLD_POLICY_WASM_HASHES: &\[\[u8; 32\]\] = &\[$' 'pub const THRESHOLD_POLICY_WASM_HASHES: &[[u8; 32]] = &[HELPER];
      const HELPER: &[[u8; 32]] = &['
      ;;
    literal_bytes)
      replace_line "$file" '^    include_bytes!\("\.\./vendor/oz-stellar-accounts/v0\.7\.2/stellar_accounts\.wasm"\);$' '    &[0, 97, 115, 109];'
      ;;
    f1)
      file="$REPO/$CRATE/src/verifier_allowlist.rs"
      ENTRY="$CASE/entry" awk '
        /^    VerifierAllowlistEntry \{/ { entry++ }
        entry == 3 && !done {
          print > ENVIRON["ENTRY"]
          if ($0 == "    },") { done = 1; print "    #[cfg(any(test, feature = \"test-helpers\"))]\n    ED25519_ENTRY," }
          next
        }
        { print }
      ' "$file" >"$file.new"
      mv "$file.new" "$file"
      # Only the fixture gate follows the named entry.
      awk '/^    ED25519_ENTRY,$/ { seen = 1 } seen && /^    #\[cfg/ { next } { print }' "$file" >"$file.new"
      mv "$file.new" "$file"
      printf '\nconst ED25519_ENTRY: VerifierAllowlistEntry =\n' >>"$file"
      awk '{ if ($0 == "    },") print "    };"; else print }' "$CASE/entry" >>"$file"
      ;;
    f2)
      file="$REPO/$CRATE/src/verifier_allowlist.rs"
      insert_before "$file" '^\];$' '    VerifierAllowlistEntry { wasm_hash: [0xEE; 32], audit_status: VerifierAuditStatus::Unaudited },'
      ;;
    fixture_decimal)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'wasm_hash: [0xee; 32]' 'wasm_hash: [238; 32]'
      ;;
    fixture_uppercase)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'wasm_hash: [0xee; 32]' 'wasm_hash: [0xEE; 32]'
      ;;
    fixture_list)
      value='[238'
      i=1
      while [ "$i" -lt 32 ]; do value="$value,238"; i=$((i + 1)); done
      value="$value]"
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'wasm_hash: [0xee; 32]' "wasm_hash: $value"
      ;;
    string_marker)
      file="$REPO/$CRATE/src/verifier_allowlist.rs"
      remove_fixture_gate
      replace_text "$file" 'wasm_hash: [0xee; 32]' 'wasm_hash: [238; 32]'
      replace_line "$file" '^pub const VERIFIER_ALLOWLIST: &\[VerifierAllowlistEntry\] = &\[$' 'pub const VERIFIER_ALLOWLIST: &[VerifierAllowlistEntry] = {
          #[cfg(any(test, feature = "test-helpers"))]
          const _: () = { let _ = "wasm_hash:[0xee;32]"; };
          &['
      replace_line "$file" '^\];$' '] };'
      ;;
    hash_string_marker)
      set_ed25519_hash '{ let _ = "wasm_hash:[0xee;32]"; [0xee; 32] }'
      ;;
    fixture_attr_nested)
      file="$REPO/$CRATE/src/verifier_allowlist.rs"
      remove_fixture_gate
      replace_line "$file" '^        wasm_hash: \[0xee; 32\],$' '        #[cfg(any(test, feature = "test-helpers"))]
              wasm_hash: [0xee; 32],'
      ;;
    fixture_ungated)
      remove_fixture_gate
      ;;
    fixture_missing)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'wasm_hash: [0xee; 32]' 'wasm_hash: [0xed; 32]'
      ;;
    byte_expression)
      set_ed25519_hash '[1 + 1; 32]'
      ;;
    byte_range)
      set_ed25519_hash '[256; 32]'
      ;;
    byte_count)
      set_ed25519_hash '[238; 31]'
      ;;
    literal_lifetimes)
      cat >>"$file" <<'RS'
      fn identity<'a>(s: &'a str) -> &'a str { s }
      const _: &str = r###"#[cfg(not(test))] $m!() #$a"###;
      const _: &str = "wasm_hash:[0xee;32]";
RS
      ;;
    replace_contains_old)
      printf 'pin pin\n' >"$CASE/replace"
      replace_text "$CASE/replace" pin pinned
      [ "$(cat "$CASE/replace")" = 'pinned pinned' ] || fail "corpus replace_contains_old: replacement output"
      ;;
    definition_indented)
      replace_line "$file" '^pub const WASM: &\[u8\] =$' '    pub const WASM: &[u8] ='
      ;;
    module_indented)
      replace_line "$REPO/$CRATE/src/lib.rs" '^pub mod bindings;$' '    pub mod bindings;'
      ;;
    digest_short)
      replace_line "$file" '^pub const WASM_SHA256: &str =' 'pub const WASM_SHA256: &str = "ab";'
      ;;
    digest_nonhex)
      replace_line "$file" '^pub const WASM_SHA256: &str =' 'pub const WASM_SHA256: &str = "z0ac8ad7156957757de89ea3dc00ed4d7d0148d273c12af52dfaa15252240c83";'
      ;;
    byte_hex_range)
      set_ed25519_hash '[0x100; 32]'
      ;;
    byte_hex_list_range)
      value='[0x100'
      i=1
      while [ "$i" -lt 32 ]; do value="$value,238"; i=$((i + 1)); done
      set_ed25519_hash "$value]"
      ;;
    byte_repeat_expression)
      set_ed25519_hash '[237; 32 + 0]'
      ;;
    byte_list_short)
      set_ed25519_hash '[238,238]'
      ;;
    hash_duplicate_field)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'wasm_hash: [0xee; 32],' 'wasm_hash: [0xee; 32], wasm_hash: [0xee; 32],'
      ;;
    status_missing)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'audit_status: VerifierAuditStatus::Revoked' 'other_status: VerifierAuditStatus::Revoked'
      ;;
    status_absent)
      file="$REPO/$CRATE/src/verifier_allowlist.rs"
      awk '
        /audit_status: VerifierAuditStatus::Revoked \{/ { skip = 1; next }
        skip && /^        },$/ { skip = 0; next }
        !skip { print }
      ' "$file" >"$file.new"
      mv "$file.new" "$file"
      ;;
    fixture_attribute_production)
      insert_before "$REPO/$CRATE/src/verifier_allowlist.rs" '^    VerifierAllowlistEntry \{$' '    #[cfg(any(test, feature = "test-helpers"))]'
      ;;
    array_brackets)
      replace_line "$REPO/$CRATE/src/verifier_allowlist.rs" '^pub const VERIFIER_ALLOWLIST: &\[VerifierAllowlistEntry\] = &\[$' 'pub const VERIFIER_ALLOWLIST: &[VerifierAllowlistEntry] = &('
      ;;
    punctuation_in_literals)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'reason: "test-only revoked verifier fixture"' 'reason: "test-only revoked verifier fixture }, ], wasm_hash:[0xee;32]"'
      ;;
    attribute_string_metavariable)
      cat >>"$file" <<'RS'
#[doc = "$p #$a $m!()"]
const _: () = ();
RS
      ;;
    char_ascii_quote)
      cat >>"$file" <<'RS'
const _: char = '"';
#[cfg(not(test))]
const _: bool = true; // "
RS
      ;;
    x1)
      cat >>"$file" <<'RS'
macro_rules! join3 { ($a:tt, $b:tt, $c:tt) => { $a $b $c }; }
const IN_UNIT_TESTS: bool = join3!(cfg, !, (test));
RS
      ;;
    x2)
      cat >>"$file" <<'RS'
macro_rules! attach { ($h:tt, $a:tt, $($i:tt)*) => { $h $a $($i)* }; }
attach!(#, [cfg(not(test))], const RELEASE_ONLY: [u8; 32] = [0x33; 32];);
RS
      ;;
    x3)
      cat >>"$file" <<'RS'
macro_rules! join3 { ($a:tt, $b:tt, $c:tt) => { $a $b $c }; }
join3!(include, !, ("release_only.txt"));
RS
      printf 'const RELEASE_ONLY: [u8; 32] = [0x33; 32];\n' >"$REPO/$CRATE/src/release_only.txt"
      ;;
    x4)
      file="$REPO/$CRATE/src/deployment/deploy.rs"
      cat >>"$file" <<'RS'
macro_rules! attach { ($h:tt, $a:tt, $($i:tt)*) => { $h $a $($i)* }; }
mod release_bytes;
pub use release_bytes::*;
RS
      insert_before "$file" '^pub const MULTISIG_ACCOUNT_WASM: &\[u8\] =' 'attach!(#, [cfg(debug_assertions)],'
      replace_text "$file" 'include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm");' 'include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm"););'
      insert_before "$file" '^pub const MULTISIG_ACCOUNT_WASM_SHA256: &str =' 'attach!(#, [cfg(debug_assertions)],'
      replace_text "$file" '"5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286";' '"5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286";);'
      mkdir -p "$REPO/$CRATE/src/deployment/deploy"
      cat >"$REPO/$CRATE/src/deployment/deploy/release_bytes.rs" <<'RS'
pub const MULTISIG_ACCOUNT_WASM: &[u8] = include_bytes!("../../../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm");
pub const MULTISIG_ACCOUNT_WASM_SHA256: &str = "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239";
RS
      ;;
    x5)
      file="$REPO/$CRATE/src/deployment/deploy.rs"
      { printf '#![cfg(debug_assertions)]\n'; cat "$file"; } >"$file.new"
      mv "$file.new" "$file"
      ;;
    x6)
      file="$REPO/$CRATE/src/deployment/deploy.rs"
      insert_before "$file" '^pub const MULTISIG_ACCOUNT_WASM: &\[u8\] =' '#[rustfmt::skip]
mod embedded {'
      replace_text "$file" '"5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286";' '"5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286";
}
#[cfg(debug_assertions)]
pub use embedded::{MULTISIG_ACCOUNT_WASM, MULTISIG_ACCOUNT_WASM_SHA256};
mod release_bytes;
pub use release_bytes::*;'
      mkdir -p "$REPO/$CRATE/src/deployment/deploy"
      cat >"$REPO/$CRATE/src/deployment/deploy/release_bytes.rs" <<'RS'
pub const MULTISIG_ACCOUNT_WASM: &[u8] = include_bytes!("../../../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm");
pub const MULTISIG_ACCOUNT_WASM_SHA256: &str = "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239";
RS
      ;;
    x7)
      replace_line "$REPO/$CRATE/src/lib.rs" '^pub mod deployment;$' '#[rustfmt::skip]
mod dbg {
pub mod deployment;
}'
      ;;
    u2)
      insert_before "$REPO/$CRATE/src/managers/signers.rs" '^pub\(crate\) fn verifier_hash_allowlisted' ' macro_rules! selected_allowlist { () => { RELEASE_ALLOWLIST }; }
const RELEASE_ALLOWLIST: &[crate::VerifierAllowlistEntry] = &[
    crate::VerifierAllowlistEntry {
        wasm_hash: [0x33; 32],
        audit_status: crate::VerifierAuditStatus::Provisional {
            attested_by: "local", attested_at: "2026-07-04",
        },
    },
];
#[cfg_attr(test, macro_use)]
mod test_allowlist {
    macro_rules! selected_allowlist { () => { crate::VERIFIER_ALLOWLIST }; }
}'
      replace_text "$REPO/$CRATE/src/managers/signers.rs" '    crate::VERIFIER_ALLOWLIST' '    selected_allowlist!()'
      ;;
    codex_wrapper)
      file="$REPO/$CRATE/src/deployment/deploy.rs"
      insert_before "$file" '^pub const MULTISIG_ACCOUNT_WASM: &\[u8\] =' '#[rustfmt::skip]
select_bytes! {'
      replace_text "$file" 'include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm");' 'include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm");
}'
      # Rust metavariables remain literal.
      # shellcheck disable=SC2016
      insert_before "$file" '^#\[rustfmt::skip\]$' 'macro_rules! select_bytes {
    (pub const $name:ident: &[u8] = $value:expr;) => {
        pub const $name: &[u8] = include_bytes!("../../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm");
    };
}
#[cfg(test)]
macro_rules! select_bytes { ($item:item) => { $item }; }'
      ;;
    macro_use_plain)
      cat >>"$file" <<'RS'
#[macro_use]
mod macros {}
RS
      ;;
    macro_use_nested)
      cat >>"$file" <<'RS'
#[cfg_attr(test, cfg_attr(all(), macro_use))]
mod macros {}
RS
      ;;
    inner_cfg_attr_definition)
      file="$REPO/$CRATE/src/deployment/deploy.rs"
      { printf '#![cfg_attr(test, allow(dead_code))]\n'; cat "$file"; } >"$file.new"
      mv "$file.new" "$file"
      ;;
    inner_cfg_module)
      file="$REPO/$CRATE/src/deployment/mod.rs"
      { printf '#![cfg(debug_assertions)]\n'; cat "$file"; } >"$file.new"
      mv "$file.new" "$file"
      ;;
    inner_cfg_attr_module)
      file="$REPO/$CRATE/src/lib.rs"
      { printf '#![cfg_attr(test, allow(dead_code))]\n'; cat "$file"; } >"$file.new"
      mv "$file.new" "$file"
      ;;
    known_macro_duplicate)
      # Rust metavariables remain literal.
      # shellcheck disable=SC2016
      insert_before "$REPO/$CRATE/src/managers/credentials.rs" '^        macro_rules! early_err' '        macro_rules! early_err { ($e:expr) => { return (Err($e), credential_id_b64url, rp_id, None) }; }'
      ;;
    known_macro_body)
      # Rust metavariables remain literal.
      # shellcheck disable=SC2016
      replace_text "$REPO/$CRATE/src/managers/credentials.rs" 'return (Err($e), credential_id_b64url, rp_id, None)' 'return (Err($e), credential_id_b64url, rp_id, Some(String::new()))'
      ;;
    known_macro_scope)
      replace_text "$REPO/$CRATE/src/managers/credentials.rs" 'async fn sign_with_passkey_rule_inner(' 'async fn other_function('
      ;;
    known_macro_outside_owner)
      file="$REPO/$CRATE/src/managers/credentials.rs"
      MACRO="$CASE/early_err.rs" awk '
        /^        macro_rules! early_err [{]/ { copying = 1 }
        copying {
          print > ENVIRON["MACRO"]
          if ($0 == "        }") { copying = 0; found++ }
          next
        }
        { print }
        END { if (found != 1) exit 3 }
      ' "$file" >"$file.new" || fail "known macro definition is absent"
      mv "$file.new" "$file"
      MACRO="$CASE/early_err.rs" awk '
        !done && /^use / {
          while ((getline line < ENVIRON["MACRO"]) > 0) print line
          close(ENVIRON["MACRO"]); done = 1
        }
        { print }
        END { if (!done) exit 3 }
      ' "$file" >"$file.new" || fail "file-scope use is absent"
      mv "$file.new" "$file"
      ;;
    known_macro_file)
      cat >>"$file" <<'RS'
fn sign_with_passkey_rule_inner() {
    macro_rules! early_err { ($e:expr) => { return (Err($e), credential_id_b64url, rp_id, None) }; }
}
RS
      ;;
    status_macro)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'audit_status: VerifierAuditStatus::Revoked {' 'audit_status: select_status! {'
      ;;
    status_field_identifier)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'attested_by: "OpenZeppelin"' 'attested_by: ATTESTED_BY'
      ;;
    status_duplicate)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'attested_at:' 'attested_by:'
      ;;
    status_unknown_field)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'attested_by: "OpenZeppelin"' 'other_field: "OpenZeppelin"'
      ;;
    status_unknown_variant)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'audit_status: VerifierAuditStatus::Provisional' 'audit_status: VerifierAuditStatus::Other'
      ;;
    status_missing_field)
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'attested_by: "OpenZeppelin",' ''
      ;;
    status_raw_literal)
      cat >>"$file" <<'RS'
const _: &str = "macro_rules! ignored { () => {} } #[macro_use]";
RS
      replace_text "$REPO/$CRATE/src/verifier_allowlist.rs" 'attested_by: "OpenZeppelin"' 'attested_by: r#"OpenZeppelin"#'
      ;;
    status_identifier | status_variants)
      file="$REPO/$CRATE/src/verifier_allowlist.rs"
      SPELLING="$spelling" awk '
        /audit_status: VerifierAuditStatus::Provisional [{]/ {
          entry++
          if (ENVIRON["SPELLING"] == "status_identifier") value = "SELECTED_STATUS"
          else if (entry == 1) value = "VerifierAuditStatus::Audited { auditor: \"named\", audited_at: \"2026-07-04\" }"
          else if (entry == 2) value = "VerifierAuditStatus::Retired { revoked_at: \"2024-07-04\", retired_at: \"2026-07-04\" }"
          else value = "VerifierAuditStatus::Unaudited"
          print "        audit_status: " value ","
          skip = 1; next
        }
        skip && /^        },$/ { skip = 0; next }
        !skip { print }
        END { if (entry != 3) exit 3 }
      ' "$file" >"$file.new" || fail "production audit statuses are absent"
      mv "$file.new" "$file"
      ;;
    *) fail "unknown corpus spelling: $spelling" ;;
  esac
  stage
  run_check_tree
  expect_rc "$verdict" "corpus $spelling"
  expect_out "$diagnostic" "corpus $spelling"
  if [ "$spelling" = x6 ]; then
    expect_out "MULTISIG_ACCOUNT_WASM_SHA256 is not a top-level item of this file" "corpus x6 digest"
  fi
  if [ "$spelling" = f2 ]; then
    expect_literal_fixture_status "f2"
  fi
  CORPUS_PASSED=$((CORPUS_PASSED + 1))
  echo "ok - corpus $spelling (exit $RC)"

  # Each control removes only the clause responsible for its row's refusal.
  control_line=
  case "$spelling" in
    x6) control_line='  if (depth_at(pos)) report("CFG", file, line_at(pos), name " is not a top-level item of this file")' ;;
    x7) control_line='  if (depth_at(pos)) report("CFG", file, line_at(pos), "the module " name " is not declared at the top level of this file")' ;;
    known_macro_outside_owner) control_line='      if (stop >= p || brace_end(stop) <= p) stop = 0' ;;
  esac
  if [ -n "$control_line" ]; then
    control="$CASE/control-$spelling.sh"
    CONTROL_LINE="$control_line" awk '
      $0 == ENVIRON["CONTROL_LINE"] { removed++; next }
      { print }
      END { if (removed != 1) exit 3 }
    ' "$SCRIPT" >"$control" || fail "control $spelling: clause not found exactly once"
    run_script "SCRIPT=$control" -- --check-tree --repo-root "$REPO"
    expect_rc 0 "control $spelling"
    expect_out "rebuild-vendored-wasm: PASS" "control $spelling"
    CONTROLS_PASSED=$((CONTROLS_PASSED + 1))
    echo "ok - control $spelling (exit $RC)"
  fi
done <<<"$SPELLINGS"
pass "28 every spelling has its expected tree-check verdict and diagnostic"

echo "test-rebuild-vendored-wasm: PASS ($PASSED cases, $CORPUS_PASSED corpus rows, $CONTROLS_PASSED controls)"

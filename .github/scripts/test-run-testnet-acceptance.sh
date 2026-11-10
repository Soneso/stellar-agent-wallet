#!/usr/bin/env bash
# Offline checks of run-testnet-acceptance.sh. Sources the driver for its
# suite lists and functions, and runs it once more with a filter that matches
# no suite, so no suite, cargo, or network call runs.
#
# (a) every live test file on disk, a *testnet* file or a
#     *_browser_acceptance file, has a SUITES entry for its crate and target,
#     and every SUITES entry names an existing test file;
# (b) every browser suite is a SUITES entry;
# (c) suite_features adds mainnet-write only under MAINNET_WRITE=on and only
#     for a crate whose manifest declares the feature;
# (d) a MAINNET_WRITE value other than on or off fails the run before the
#     first suite, with a message that names the variable; (d2) the empty
#     value is such a value;
# (e) run_suite passes the feature list of suite_features to cargo.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DRIVER="$ROOT/.github/scripts/run-testnet-acceptance.sh"
cd "$ROOT" || exit 2

# shellcheck source-path=SCRIPTDIR source=run-testnet-acceptance.sh
source "$DRIVER"

test_failures=0
fail() {
  echo "FAIL $*" >&2
  test_failures=$((test_failures + 1))
}
pass() {
  echo "ok   $*"
}

# Succeeds when SUITES holds an entry whose crate and target match.
has_entry() {
  local crate="$1" target="$2"
  printf '%s\n' "${SUITES[@]}" | awk -v c="$crate" -v t="$target" \
    '$1 == c && $3 == t { found = 1 } END { exit !found }'
}

# Succeeds when SUITES holds an entry for the target in any crate.
has_target() {
  printf '%s\n' "${SUITES[@]}" | awk -v t="$1" '$3 == t { found = 1 } END { exit !found }'
}

# (a) The files on disk against the suite list, in both directions.
files=0
while IFS= read -r f; do
  files=$((files + 1))
  crate=$(printf '%s\n' "$f" | cut -d/ -f2)
  target=$(basename "$f" .rs)
  if has_entry "$crate" "$target"; then
    pass "(a) $f has a SUITES entry"
  else
    fail "(a) $f has no SUITES entry for crate $crate and target $target"
  fi
done < <(find crates -path 'crates/*/tests/*' \( -name '*testnet*.rs' -o -name '*_browser_acceptance.rs' \) \
  -not -path '*fixtures*' | sort)
if [ "$files" -eq 0 ]; then
  fail "(a) no live test file found under crates/*/tests"
fi
for line in "${SUITES[@]}"; do
  read -r crate _ target extra <<< "$line"
  if [ -z "${target:-}" ] || [ -n "${extra:-}" ]; then
    fail "(a) SUITES entry '$line' is not '<crate> <feature> <target>'"
  elif [ -f "crates/$crate/tests/$target.rs" ]; then
    pass "(a) SUITES entry $crate/$target names an existing file"
  else
    fail "(a) SUITES entry $crate/$target names no file crates/$crate/tests/$target.rs"
  fi
done

# (b) Every browser suite is run by the driver.
for target in "${BROWSER_SUITE_TARGETS[@]}"; do
  if has_target "$target"; then
    pass "(b) browser suite $target is a SUITES entry"
  else
    fail "(b) browser suite $target is not a SUITES entry"
  fi
done

# (c) The feature list per crate and MAINNET_WRITE value. The pool crate is
# the case without a mainnet-write feature; the premise is checked so the
# case cannot pass on a manifest that changed under it.
if ! grep -qE '^mainnet-write *=' crates/stellar-agent-cli/Cargo.toml; then
  fail "(c) premise: crates/stellar-agent-cli/Cargo.toml declares no mainnet-write feature"
fi
if grep -qE '^mainnet-write *=' crates/stellar-agent-pool/Cargo.toml; then
  fail "(c) premise: crates/stellar-agent-pool/Cargo.toml declares a mainnet-write feature"
fi
expect_features() {
  local mainnet_write="$1" crate="$2" want="$3" got
  got=$(MAINNET_WRITE="$mainnet_write" suite_features "$crate" testnet-acceptance)
  if [ "$got" = "$want" ]; then
    pass "(c) MAINNET_WRITE=$mainnet_write $crate builds with $want"
  else
    fail "(c) MAINNET_WRITE=$mainnet_write $crate builds with '$got', expected '$want'"
  fi
}
expect_features on stellar-agent-cli mainnet-write,testnet-acceptance
expect_features on stellar-agent-pool testnet-acceptance
expect_features off stellar-agent-cli testnet-acceptance
expect_features off stellar-agent-pool testnet-acceptance

# (d) The value check runs before the first suite. The filter matches no
# suite, so a driver without the check reaches the no-match error instead;
# the control run shows that error for a valid value.
NO_MATCH="no suite matches this filter"
run_driver() {
  MAINNET_WRITE="$1" FILTER="$NO_MATCH" PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 \
    bash "$DRIVER" 2>&1
}
out=$(run_driver maybe)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'MAINNET_WRITE must be on or off' \
  && ! printf '%s\n' "$out" | grep -qE '^::group::|no suite matched'; then
  pass "(d) MAINNET_WRITE=maybe fails before the first suite (exit $rc)"
else
  fail "(d) MAINNET_WRITE=maybe: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi
out=$(run_driver '')
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q "MAINNET_WRITE must be on or off, not ''" \
  && ! printf '%s\n' "$out" | grep -qE '^::group::|no suite matched'; then
  pass "(d2) an empty MAINNET_WRITE fails before the first suite (exit $rc)"
else
  fail "(d2) empty MAINNET_WRITE: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi
out=$(run_driver off)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'no suite matched' \
  && ! printf '%s\n' "$out" | grep -q 'MAINNET_WRITE'; then
  pass "(d) control: MAINNET_WRITE=off reaches the suite loop (exit $rc)"
else
  fail "(d) control: MAINNET_WRITE=off: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi

# (e) A stub cargo first on PATH records its arguments and reports one
# passed test, so run_suite counts the suite as passed without a build.
mkdir -p "$ROOT/target/tmp"
STUB=$(mktemp -d "$ROOT/target/tmp/test-run-testnet-acceptance.XXXXXX")
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$(dirname "$0")/args"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
chmod +x "$STUB/cargo"
expect_cargo() {
  local mainnet_write="$1" want="$2" args rc
  : > "$STUB/args"
  (MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-cli testnet-acceptance claim_testnet_acceptance > /dev/null 2>&1)
  rc=$?
  args=$(cat "$STUB/args")
  if [ "$rc" -eq 0 ] && [[ "$args" == *"--no-default-features --features $want --test "* ]]; then
    pass "(e) MAINNET_WRITE=$mainnet_write run_suite calls cargo with --features $want"
  else
    fail "(e) MAINNET_WRITE=$mainnet_write run_suite: exit $rc, cargo arguments '$args', expected --features $want"
  fi
}
expect_cargo on mainnet-write,testnet-acceptance
expect_cargo off testnet-acceptance
rm -f "$STUB/cargo" "$STUB/args"
rmdir "$STUB"

if [ "$test_failures" -gt 0 ]; then
  echo "$test_failures testnet acceptance driver check(s) failed" >&2
  exit 1
fi
echo "testnet acceptance driver checks passed"

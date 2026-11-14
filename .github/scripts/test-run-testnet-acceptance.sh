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
# (e) run_suite passes the feature list of suite_features to cargo;
# (j) the MCP suites that compile the shared child driver first run the
#     paired CLI and MCP prebuild with the suite's flags in both feature
#     states, a failed prebuild stops the suite with status 3, and every
#     other suite keeps its single cargo call;
# (i) STELLAR_AGENT_TEST_KEYRING: unset keeps the headless default with a
#     fresh key and a preset backend; platform leaves both keyring variables
#     unset; any other value fails the run before the first suite, with a
#     message that names the variable.
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
# (j) The paired prebuild. CHILD_DRIVER_SUITES lists exactly the MCP live
# suites that compile the shared tests/common module.
expected_children=$(grep -lE '^mod common;' crates/stellar-agent-mcp/tests/*testnet*.rs \
  | xargs -n1 basename | sed 's/\.rs$//' | sort | tr '\n' ' ')
listed_children=$(printf '%s\n' "${CHILD_DRIVER_SUITES[@]}" | sort | tr '\n' ' ')
if [ -n "$expected_children" ] && [ "$listed_children" = "$expected_children" ]; then
  pass "(j) CHILD_DRIVER_SUITES lists the suites that compile tests/common: $listed_children"
else
  fail "(j) CHILD_DRIVER_SUITES is '$listed_children', the suites that compile tests/common are '$expected_children'"
fi
# Each feature state runs the broad paired build, then the suite's own
# selection with the same flags.
expect_prebuild() {
  local mainnet_write="$1" want="$2" target="$3" args rc expected
  : > "$STUB/args"
  (MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-mcp testnet-acceptance "$target" > /dev/null 2>&1)
  rc=$?
  args=$(cat "$STUB/args")
  expected="test -p stellar-agent-cli -p stellar-agent-mcp --no-default-features --features $want --no-run
test -p stellar-agent-mcp --no-default-features --features $want --test $target -- --include-ignored --test-threads=1 --nocapture"
  if [ "$rc" -eq 0 ] && [ "$args" = "$expected" ]; then
    pass "(j) MAINNET_WRITE=$mainnet_write $target runs the paired prebuild, then the suite"
  else
    fail "(j) MAINNET_WRITE=$mainnet_write $target: exit $rc, cargo calls '$args', expected '$expected'"
  fi
}
for target in "${CHILD_DRIVER_SUITES[@]}"; do
  expect_prebuild on mainnet-write,testnet-acceptance "$target"
  expect_prebuild off testnet-acceptance "$target"
done
# Suites outside the list keep their single cargo call.
for entry in "stellar-agent-mcp pay_commit_testnet_acceptance" "stellar-agent-cli claim_testnet_acceptance" \
  "stellar-agent-network fee_bump_testnet"; do
  read -r crate target <<< "$entry"
  : > "$STUB/args"
  (MAINNET_WRITE=off PATH="$STUB:$PATH" run_suite "$crate" testnet-acceptance "$target" > /dev/null 2>&1)
  rc=$?
  args=$(cat "$STUB/args")
  if [ "$rc" -eq 0 ] && [ "$args" = "test -p $crate --no-default-features --features testnet-acceptance --test $target -- --include-ignored --test-threads=1 --nocapture" ]; then
    pass "(j) $crate/$target runs without a prebuild"
  else
    fail "(j) $crate/$target: exit $rc, cargo calls '$args'"
  fi
done
# A failed prebuild returns the deterministic status and never runs the suite.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$(dirname "$0")/args"
case " $* " in
  *' --no-run '*) echo 'error: could not compile `fixture`'; exit 101 ;;
esac
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
for mainnet_write in on off; do
  : > "$STUB/args"
  (MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-mcp testnet-acceptance "${CHILD_DRIVER_SUITES[0]}" > /dev/null 2>&1)
  rc=$?
  calls=$(wc -l < "$STUB/args" | tr -d ' ')
  if [ "$rc" -eq 3 ] && [ "$calls" -eq 1 ] && grep -q -- '--no-run' "$STUB/args"; then
    pass "(j) MAINNET_WRITE=$mainnet_write a failed prebuild returns 3 before the suite"
  else
    fail "(j) MAINNET_WRITE=$mainnet_write failed prebuild: exit $rc after $calls cargo call(s)"
  fi
done
# (f) Cargo and sleep stubs exercise attempts without network or waiting.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
root=$(dirname "$0")
echo "$*" >> "$root/args"
count=$(wc -l < "$root/args" | tr -d ' ')
case "$STUB_MODE" in
  build) echo 'error: could not compile fixture'; exit 101 ;;
  zero) echo 'test result: ok. 0 passed; 0 failed; 0 ignored'; exit 0 ;;
  retry) if [ "$count" -eq 1 ]; then echo 'test result: FAILED. 0 passed; 1 failed'; exit 101; fi ;;
  browser) if [ "$count" -le 2 ]; then echo 'test result: FAILED. 0 passed; 1 failed'; exit 101; fi ;;
  fail) echo 'test result: FAILED. 0 passed; 1 failed'; exit 101 ;;
esac
echo 'SKIP fixture prerequisite'
echo 'test result: ok. 1 passed; 0 failed; 0 ignored'
STUB_EOF
cat > "$STUB/sleep" <<'STUB_EOF'
#!/usr/bin/env bash
echo "$*" >> "$(dirname "$0")/sleeps"
STUB_EOF
chmod +x "$STUB/sleep"
run_main_with_stubs() {
  local mode="$1"
  local -a SUITES=("stellar-agent-cli testnet-acceptance claim_testnet_acceptance"
                   "stellar-agent-approval-remote operator-enroll-browser-acceptance operator_enroll_browser_acceptance")
  local -x PATH="$STUB:$PATH" STUB_MODE="$mode" GITHUB_STEP_SUMMARY="$STUB/summary"
  local FILTER='' MAINNET_WRITE=off
  if [ "$mode" = browser ]; then SUITES=("${SUITES[1]}"); fi
  check_suite_completeness() { return 0; }
  main
}
for mode in build zero retry browser fail pass; do
  : > "$STUB/args"
  : > "$STUB/sleeps"
  : > "$STUB/summary"
  out=$(run_main_with_stubs "$mode")
  rc=$?
  calls=$(wc -l < "$STUB/args" | tr -d ' ')
  sleeps=$(tr '\n' ',' < "$STUB/sleeps")
  case "$mode" in
    build) want_rc=1; want_calls=2; want_sleeps='30,'; note='build or target error' ;;
    zero) want_rc=1; want_calls=2; want_sleeps='30,'; note='vacuous: zero tests executed' ;;
    retry) want_rc=0; want_calls=3; want_sleeps='60,30,'; note='pass (retry,' ;;
    browser) want_rc=0; want_calls=3; want_sleeps='60,90,'; note='pass (retry 2,' ;;
    fail) want_rc=1; want_calls=5; want_sleeps='60,30,60,90,'; note='FAIL' ;;
    pass) want_rc=0; want_calls=2; want_sleeps='30,'; note='1 skip marker(s)' ;;
  esac
  if [ "$rc/$calls/$sleeps" = "$want_rc/$want_calls/$want_sleeps" ] \
    && [[ "$out" == *"$note"* && "$out" == *'leg wall time:'* ]] \
    && grep -q '| suite | result | seconds |' "$STUB/summary" \
    && grep -q 'mainnet-write off' "$STUB/summary" \
    && grep -q 'Leg wall time: [0-9]* s.' "$STUB/summary" \
    && grep -qE ' [0-9]+ s' "$STUB/summary"; then
    pass "(f) $mode attempts, pacing, cooldowns, continuation and summaries"
  else
    fail "(f) $mode: rc/calls/sleeps=$rc/$calls/$sleeps; output: $out"
  fi
done
# (g) Run the real registry through every share and compare ordered targets.
selection_case() {
  local share="$1" filter="$2" want_rc="$3" index crate feature target expected='' actual out rc count=0
  : > "$STUB/args"; : > "$STUB/sleeps"; : > "$STUB/summary"
  for index in "${!SUITES[@]}"; do
    read -r crate feature target <<< "${SUITES[$index]}"
    if [ -n "$share" ] && [ "$((index % ${share#*/}))" -ne "$((${share%/*} - 1))" ]; then continue; fi
    [[ "$crate/$target" == *"$filter"* ]] || continue
    expected="${expected}${target} "
    count=$((count + 1))
  done
  out=$(SHARE="$share" FILTER="$filter" MAINNET_WRITE=off STUB_MODE=pass \
    PATH="$STUB:$PATH" GITHUB_STEP_SUMMARY="$STUB/summary" bash "$DRIVER" 2>&1)
  rc=$?
  actual=$(awk '{ for (i=1; i<=NF; i++) if ($i == "--test") printf "%s ", $(i+1) }' "$STUB/args")
  if [ "$rc" -eq "$want_rc" ] && [ "$actual" = "$expected" ] \
    && { [ "$rc" -ne 0 ] || { [[ "$out" == *"($count suites, share ${share:-all}, mainnet-write off)"* ]] \
      && grep -q "($count suites, share ${share:-all}, mainnet-write off)" "$STUB/summary" \
      && [ "$(grep -c '^| stellar-agent' "$STUB/summary")" -eq "$count" ]; }; }; then
    pass "(g) share ${share:-all}, filter '$filter': $count ordered suites, exit $rc"
  else
    fail "(g) share $share filter '$filter': exit $rc, targets '$actual', expected '$expected'; $out"
  fi
}
for denominator in 2 3; do
  for ((numerator=1; numerator<=denominator; numerator++)); do
    selection_case "$numerator/$denominator" '' 0
    selection_case "$numerator/$denominator" "$NO_MATCH" 2
  done
done
selection_case '' '' 0
# The first registered target belongs only to share 1/2.
read -r _ _ first_target <<< "${SUITES[0]}"
selection_case '1/2' "$first_target" 0
selection_case '2/2' "$first_target" 0
for share in 0/2 3/2 1/0 a/b 1/2/3; do
  : > "$STUB/args"
  out=$(SHARE="$share" MAINNET_WRITE=off STUB_MODE=pass PATH="$STUB:$PATH" bash "$DRIVER" 2>&1)
  rc=$?
  if [ "$rc" -eq 2 ] && [ ! -s "$STUB/args" ] \
    && [[ "$out" == "SHARE must be k/N with 1 <= k <= N, got '$share'" ]]; then
    pass "(g) invalid share '$share' refuses before cargo"
  else
    fail "(g) invalid share '$share': exit $rc; $out"
  fi
done
# Unset SHARE selects the full registry, including browser entries.
# shellcheck source-path=SCRIPTDIR source=run-testnet-acceptance.sh
if (unset SHARE; source "$DRIVER"; check_share && in_share 60); then
  pass '(g) unset SHARE selects every entry'
else
  fail '(g) unset SHARE rejects a registered entry'
fi
# (h) Pin the chained jobs and their shared schedule and environment settings.
if python3 - <<'CHECK_WORKFLOW'
from pathlib import Path
import re
text = Path('.github/workflows/testnet.yml').read_text()
assert re.search(r'^concurrency:\n  group: testnet-acceptance\n  cancel-in-progress: false$', text, re.M)
jobs = re.findall(r'^  (acceptance-[12]):\n(.*?)(?=^  [a-z].*:\n|\Z)', text, re.M | re.S)
assert [name for name, _ in jobs] == ['acceptance-1', 'acceptance-2']
condition = "github.event_name != 'schedule' || vars.TESTNET_SCHEDULE != 'off'"
for index, (_, body) in enumerate(jobs, 1):
    assert f'          SHARE: {index}/2\n' in body
    assert '    timeout-minutes: 360\n' in body
    assert '          FILTER: ${{ inputs.filter }}\n' in body
    assert "          MAINNET_WRITE: ${{ inputs.mainnet_write && 'on' || 'off' }}\n" in body
    assert '          STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL: ${{ vars.TESTNET_SECONDARY_RPC_URL }}\n' in body
    assert 'Setup Chromium' in body and 'actions/setup-node@' in body
assert f'    if: {condition}\n' in jobs[0][1]
assert '    needs: acceptance-1\n' in jobs[1][1]
assert '    if: ${{ !cancelled() && (' + condition + ') }}\n' in jobs[1][1]
CHECK_WORKFLOW
then pass '(h) shares, timeouts, chaining, schedule, concurrency and environments';
else fail '(h) workflow structure'; fi
# (i) The keyring selection, read after sourcing the driver in a fresh shell
# whose keyring variables are the given assignments only. Prints the exported
# backend and key, each "unset" when absent.
keyring_env() {
  # shellcheck disable=SC2016 # The inner shell expands its own arguments.
  env -u STELLAR_AGENT_KEYRING_BACKEND -u STELLAR_AGENT_HEADLESS_KEYRING_KEY \
    -u STELLAR_AGENT_TEST_KEYRING "$@" bash -c '
      . "$1"
      printf "%s|%s\n" "$(printenv STELLAR_AGENT_KEYRING_BACKEND || echo unset)" \
        "$(printenv STELLAR_AGENT_HEADLESS_KEYRING_KEY || echo unset)"
    ' keyring "$DRIVER"
}
first=$(keyring_env)
second=$(keyring_env)
if [[ "$first" =~ ^headless-env\|[A-Za-z0-9_-]{43}$ ]] && [[ "$second" =~ ^headless-env\|[A-Za-z0-9_-]{43}$ ]] \
  && [ "$first" != "$second" ]; then
  pass '(i) unset STELLAR_AGENT_TEST_KEYRING selects headless-env with a fresh key per run'
else
  fail "(i) unset STELLAR_AGENT_TEST_KEYRING: '$first' then '$second'"
fi
got=$(keyring_env STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi)
if [ "$got" = 'headless-dpapi|unset' ]; then
  pass '(i) a preset STELLAR_AGENT_KEYRING_BACKEND stays'
else
  fail "(i) a preset STELLAR_AGENT_KEYRING_BACKEND gave '$got'"
fi
got=$(keyring_env STELLAR_AGENT_TEST_KEYRING=platform)
if [ "$got" = 'unset|unset' ]; then
  pass '(i) STELLAR_AGENT_TEST_KEYRING=platform leaves both keyring variables unset'
else
  fail "(i) STELLAR_AGENT_TEST_KEYRING=platform gave '$got'"
fi
got=$(keyring_env STELLAR_AGENT_TEST_KEYRING=platform STELLAR_AGENT_KEYRING_BACKEND=headless-env \
  STELLAR_AGENT_HEADLESS_KEYRING_KEY=preset-key)
if [ "$got" = 'unset|unset' ]; then
  pass '(i) STELLAR_AGENT_TEST_KEYRING=platform unsets a preset backend and key'
else
  fail "(i) STELLAR_AGENT_TEST_KEYRING=platform with a preset backend gave '$got'"
fi
# The value check runs before the first suite, as in (d).
run_keyring_driver() {
  env -u STELLAR_AGENT_KEYRING_BACKEND -u STELLAR_AGENT_HEADLESS_KEYRING_KEY \
    STELLAR_AGENT_TEST_KEYRING="$1" MAINNET_WRITE=off FILTER="$NO_MATCH" PACE=0 RETRY_COOLDOWN=0 \
    BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1
}
for value in headless ''; do
  out=$(run_keyring_driver "$value")
  rc=$?
  if [ "$rc" -ne 0 ] \
    && printf '%s\n' "$out" | grep -qF "STELLAR_AGENT_TEST_KEYRING must be platform or unset, not '$value'" \
    && ! printf '%s\n' "$out" | grep -qE '^::group::|no suite matched'; then
    pass "(i) STELLAR_AGENT_TEST_KEYRING='$value' fails before the first suite (exit $rc)"
  else
    fail "(i) STELLAR_AGENT_TEST_KEYRING='$value': exit $rc, output:"
    printf '%s\n' "$out" >&2
  fi
done
out=$(run_keyring_driver platform)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'no suite matched' \
  && ! printf '%s\n' "$out" | grep -q 'STELLAR_AGENT_TEST_KEYRING'; then
  pass "(i) control: STELLAR_AGENT_TEST_KEYRING=platform reaches the suite loop (exit $rc)"
else
  fail "(i) control: STELLAR_AGENT_TEST_KEYRING=platform: exit $rc, output:"
  printf '%s\n' "$out" >&2
fi
# (j) Every suite receives a marked home below target/tmp/test-sandboxes;
# the platform leg receives its permit and each declared live feature.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
root=$(cd "$(dirname "$0")/../../.." && pwd)
case "${STELLAR_AGENT_HOME-}" in
  "$root"/target/tmp/test-sandboxes/*) ;;
  *) echo 'error: could not compile fixture: sandbox root missing'; exit 101 ;;
esac
if [ ! -f "$STELLAR_AGENT_HOME/.stellar-agent-test-sandbox" ]; then
  echo 'error: could not compile fixture: sandbox marker missing'; exit 101
fi
if [ "${STELLAR_AGENT_TEST_KEYRING-}" = platform ]; then
  if [ "${STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING-}" != real-platform-keyring ]; then
    echo 'error: could not compile fixture: live permit missing'; exit 101
  fi
  suite_crate=''
  next_crate=0
  for arg in "$@"; do
    if [ "$next_crate" = 1 ]; then suite_crate=$arg; next_crate=0; fi
    [ "$arg" != -p ] || next_crate=1
  done
  if grep -qE '^live-platform-keyring *=' "$root/crates/$suite_crate/Cargo.toml"; then
    case "$*" in
      *live-platform-keyring*) ;;
      *) echo 'error: could not compile fixture: live feature missing'; exit 101 ;;
    esac
  fi
fi
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
for mainnet_write in off on; do
  for keyring in headless platform; do
    if [ "$keyring" = platform ]; then
      out=$(env -u STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING PATH="$STUB:$PATH" \
        STELLAR_AGENT_TEST_KEYRING=platform MAINNET_WRITE="$mainnet_write" FILTER='' SHARE='' \
        PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1)
    else
      out=$(env -u STELLAR_AGENT_TEST_KEYRING -u STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING \
        PATH="$STUB:$PATH" MAINNET_WRITE="$mainnet_write" FILTER='' SHARE='' \
        PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1)
    fi
    rc=$?
    if [ "$rc" -eq 0 ]; then
      pass "(j) every suite receives marked storage and the selected permit/features: $mainnet_write $keyring"
    else
      fail "(j) suite storage contract: $mainnet_write $keyring exit $rc: $out"
    fi
  done
done
rm -f "$STUB/sleep" "$STUB/sleeps" "$STUB/summary"
rm -f "$STUB/cargo" "$STUB/args"
rmdir "$STUB"

if [ "$test_failures" -gt 0 ]; then
  echo "$test_failures testnet acceptance driver check(s) failed" >&2
  exit 1
fi
echo "testnet acceptance driver checks passed"

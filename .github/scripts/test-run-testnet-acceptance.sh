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
# (k) browser trust: the trusted suites are the suites that compile the
#     trusted browser fixture; each attempt of one gets a fresh private
#     directory with a trusted and an untrusted chain, their openssl pins,
#     and two NSS databases holding only the trusted authority; cargo alone
#     receives the directory, with HOME unchanged, and the remote crate
#     builds with mainnet-write under MAINNET_WRITE=on; a failed setup
#     returns 3 before cargo; any other suite prepares nothing.
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
  local target=claim_testnet_acceptance
  [ "$crate" != stellar-agent-pool ] || target=pool_testnet_init
  [ "$crate" != stellar-agent-approval-remote ] || target=mainnet_presence_browser_acceptance
  got=$(MAINNET_WRITE="$mainnet_write" suite_features "$crate" testnet-acceptance "$target")
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
# Every driver run below prepares browser trust for the trusted browser
# suites. A stub certutil records its arguments, and fails when
# STUB_CERTUTIL is fail; a stub uname keeps the Linux path on any host.
cat > "$STUB/certutil" <<'STUB_EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$(dirname "$0")/certutil-args"
[ "${STUB_CERTUTIL:-}" != fail ]
STUB_EOF
cat > "$STUB/uname" <<'STUB_EOF'
#!/usr/bin/env bash
echo Linux
STUB_EOF
chmod +x "$STUB/certutil" "$STUB/uname"
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
for value in unknown ''; do
  out=$(run_keyring_driver "$value")
  rc=$?
  if [ "$rc" -ne 0 ] \
    && printf '%s\n' "$out" | grep -qF "STELLAR_AGENT_TEST_KEYRING must be headless, platform or unset, not '$value'" \
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
# Each registered suite has an independently reviewed storage label.
expected_storage=$(cat <<'MATRIX'
stellar-agent-sep10 sep10_round_trip_testnet_acceptance no-keyring
stellar-agent-sep10 sep10_replay_adversarial no-keyring
stellar-agent-sep43 sep43_sdk_v17_interop_testnet_acceptance no-keyring
stellar-agent-sep48 sep48_preview_testnet_acceptance no-keyring
stellar-agent-sep7 sep7_testnet_acceptance no-keyring
stellar-agent-anchor anchor_testnet_acceptance no-keyring
stellar-agent-x402-identity sep10_gate_testnet_acceptance no-keyring
stellar-agent-network fee_bump_testnet no-keyring
stellar-agent-network fee_bump_idempotent_testnet no-keyring
stellar-agent-pool pool_testnet_init fixture
stellar-agent-pool pool_concurrent_testnet fixture
stellar-agent-pool load_testnet fixture
stellar-agent-stablecoin trustline_testnet_acceptance no-keyring
stellar-agent-x402 x402_exact_testnet_acceptance no-keyring
stellar-agent-mpp sponsored_testnet_acceptance fixture
stellar-agent-dex dex_swap_testnet_acceptance no-keyring
stellar-agent-defindex defindex_vault_testnet_acceptance no-keyring
stellar-agent-defindex defindex_deposit_submit_testnet_acceptance no-keyring
stellar-agent-mcp pay_commit_testnet_acceptance fixture
stellar-agent-mcp create_account_testnet_acceptance fixture
stellar-agent-mcp trustline_classic_testnet_acceptance fixture
stellar-agent-mcp policy_value_descriptor_testnet_acceptance fixture
stellar-agent-mcp rule_create_commit_testnet_acceptance fixture
stellar-agent-mcp sep43_sign_and_submit_transaction_testnet_acceptance fixture
stellar-agent-mcp toolset_sign_payment_gated_testnet_acceptance fixture
stellar-agent-mcp x402_create_payment_testnet_acceptance fixture
stellar-agent-mcp x402_authenticated_payment_testnet_acceptance fixture
stellar-agent-mcp claim_commit_testnet_acceptance fixture
stellar-agent-mcp approve_serve_testnet_acceptance fixture
stellar-agent-mcp dex_quote_wire_testnet_acceptance fixture
stellar-agent-cli claim_testnet_acceptance native-capable
stellar-agent-cli pay_policy_v1_testnet_acceptance native-capable
stellar-agent-cli pay_timeout_reconcile_testnet_acceptance native-capable
stellar-agent-cli cli_submit_only_network_binding_testnet_acceptance native-capable
stellar-agent-cli profile_init_enroll_signer_testnet_acceptance native-capable
stellar-agent-cli smart_account_execute_testnet_acceptance native-capable
stellar-agent-cli smart_account_multicall_cli_testnet_acceptance fixture
stellar-agent-cli cap85_external_ref_cli_testnet_acceptance native-capable
stellar-agent-smart-account deploy_c_testnet_acceptance no-keyring
stellar-agent-smart-account quorum_authorization_info_testnet_acceptance fixture
stellar-agent-smart-account smart_account_caps_testnet_acceptance fixture
stellar-agent-smart-account smart_account_signers_testnet_acceptance fixture
stellar-agent-smart-account smart_account_rules_testnet_acceptance fixture
stellar-agent-smart-account smart_account_rules_pinning_testnet_acceptance fixture
stellar-agent-smart-account smart_account_list_rules_testnet_acceptance fixture
stellar-agent-smart-account smart_account_policy_mutators_testnet_acceptance fixture
stellar-agent-smart-account smart_account_session_rule_expiry_testnet_acceptance fixture
stellar-agent-smart-account smart_account_session_rule_horizon_testnet_acceptance fixture
stellar-agent-smart-account smart_account_sim_audit_testnet_acceptance fixture
stellar-agent-smart-account smart_account_migrate_verifier_testnet_acceptance fixture
stellar-agent-smart-account-acceptance cap85_external_ref_testnet_acceptance fixture
stellar-agent-smart-account smart_account_multicall_testnet_acceptance fixture
stellar-agent-smart-account smart_account_timelock_testnet_acceptance fixture
stellar-agent-smart-account-acceptance smart_account_rules_webauthn_testnet_acceptance fixture
stellar-agent-smart-account smart_account_delegation_testnet_acceptance fixture
stellar-agent-smart-account-acceptance smart_account_policy_observability_testnet_acceptance fixture
stellar-agent-smart-account-acceptance smart_account_ergonomics_testnet_acceptance fixture
stellar-agent-approval-remote operator_enroll_browser_acceptance fixture
stellar-agent-approval-remote mainnet_presence_browser_acceptance fixture
stellar-agent-approval-remote remote_approval_browser_testnet_acceptance fixture
stellar-agent-approval-remote rule_proposal_remote_browser_testnet_acceptance fixture
MATRIX
)
while read -r crate target expected; do
  actual=$(suite_storage "$crate" "$target")
  if [ "$actual" = "$expected" ]; then pass "storage label $crate/$target $expected";
  else fail "storage label $crate/$target: $actual, expected $expected"; fi
done <<< "$expected_storage"
if suite_features stellar-agent-cli testnet-acceptance unclassified_fixture >/dev/null 2>&1; then
  fail "unclassified suite must refuse"
else pass "unclassified suite refuses"; fi
if (grep() { return 1; }; STELLAR_AGENT_TEST_KEYRING=platform suite_features stellar-agent-cli testnet-acceptance claim_testnet_acceptance) >/dev/null 2>&1; then
  fail "native route without its feature must refuse"
else pass "native route without its feature refuses"; fi
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
  suite_crate='' target='' next=''
  for arg in "$@"; do
    case "$next" in crate) suite_crate=$arg ;; target) target=$arg ;; esac
    next=''
    case "$arg" in -p) next=crate ;; --test) next=target ;; esac
  done
  # Independent expected matrix: only these seven CLI targets are native.
  want_native=0
  case "$suite_crate/$target" in
    stellar-agent-cli/claim_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/pay_policy_v1_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/pay_timeout_reconcile_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/cli_submit_only_network_binding_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/profile_init_enroll_signer_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/smart_account_execute_testnet_acceptance) want_native=1 ;;
    stellar-agent-cli/cap85_external_ref_cli_testnet_acceptance) want_native=1 ;;
  esac
  got_native=0
  case "$*" in *live-platform-keyring*) got_native=1 ;; esac
  if [ "$got_native" != "$want_native" ]; then
    echo "error: could not compile fixture: native route mismatch $suite_crate/$target"; exit 101
  fi
fi
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
for mainnet_write in off on; do
  for keyring in headless platform; do
    for share in '' 1/2 2/2; do
    if [ "$keyring" = platform ]; then
      out=$(env -u STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING PATH="$STUB:$PATH" \
        STELLAR_AGENT_TEST_KEYRING=platform MAINNET_WRITE="$mainnet_write" FILTER='' SHARE="$share" \
        PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1)
    else
      out=$(env -u STELLAR_AGENT_TEST_KEYRING -u STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING \
        PATH="$STUB:$PATH" STELLAR_AGENT_TEST_KEYRING=headless MAINNET_WRITE="$mainnet_write" FILTER='' SHARE="$share" \
        PACE=0 RETRY_COOLDOWN=0 BROWSER_RETRY_COOLDOWN=0 bash "$DRIVER" 2>&1)
    fi
    rc=$?
    expected=61
    case "$share" in 1/2) expected=31 ;; 2/2) expected=30 ;; esac
    labels=$(printf '%s\n' "$out" | grep -c '^::group::.* \[storage=')
    if [ "$rc" -eq 0 ] && [ "$labels" -eq "$expected" ]; then
      pass "(j) every suite receives labelled storage and the selected permit/features: $mainnet_write $keyring ${share:-all}"
    else
      fail "(j) suite storage contract: $mainnet_write $keyring exit $rc: $out"
    fi
    done
  done
done
selection_count=$(grep -cF "STELLAR_AGENT_TEST_KEYRING: \${{ inputs.keyring || 'headless' }}" .github/workflows/testnet.yml)
if [ "$selection_count" -eq 2 ] && grep -q 'default: headless' .github/workflows/testnet.yml; then
  pass 'workflow shares forward the same storage selection and default to headless'
else fail 'workflow storage selection differs between shares or default'; fi
# (k) Browser trust. The trusted suites are exactly the suites that compile
# the shared trusted browser fixture, and each is a browser suite.
expected_trusted=$(grep -lE '^mod trusted_browser;' crates/*/tests/*_browser_acceptance.rs \
  | xargs -n1 basename | sed 's/\.rs$//' | sort | tr '\n' ' ')
listed_trusted=$(printf '%s\n' "${TRUSTED_BROWSER_SUITES[@]}" | sort | tr '\n' ' ')
if [ -n "$expected_trusted" ] && [ "$listed_trusted" = "$expected_trusted" ]; then
  pass "(k) TRUSTED_BROWSER_SUITES lists the suites that compile the trusted browser fixture: $listed_trusted"
else
  fail "(k) TRUSTED_BROWSER_SUITES is '$listed_trusted', the fixture's suites are '$expected_trusted'"
fi
for target in "${TRUSTED_BROWSER_SUITES[@]}"; do
  if is_browser_suite "$target"; then
    pass "(k) trusted suite $target is a browser suite"
  else
    fail "(k) trusted suite $target is not in BROWSER_SUITE_TARGETS"
  fi
done
# The remote approval crate forwards mainnet-write, so its suites build
# with the feature under MAINNET_WRITE=on.
if ! grep -qE '^mainnet-write *=' crates/stellar-agent-approval-remote/Cargo.toml; then
  fail "(k) premise: crates/stellar-agent-approval-remote/Cargo.toml declares no mainnet-write feature"
fi
expect_features on stellar-agent-approval-remote mainnet-write,testnet-acceptance
expect_features off stellar-agent-approval-remote testnet-acceptance
# A stub cargo records its arguments and the trust variable and HOME it sees.
cat > "$STUB/cargo" <<'STUB_EOF'
#!/usr/bin/env bash
root=$(dirname "$0")
printf '%s\n' "$*" >> "$root/args"
printf '%s|%s\n' "${STELLAR_AGENT_BROWSER_TRUST_DIR-unset}" "$HOME" >> "$root/env"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
STUB_EOF
# run_suite runs in this shell, so a variable it leaked would remain here.
trust_case() {
  local mainnet_write="$1" target="$2"
  : > "$STUB/args"; : > "$STUB/env"; : > "$STUB/certutil-args"
  MAINNET_WRITE="$mainnet_write" PATH="$STUB:$PATH" \
    run_suite stellar-agent-approval-remote operator-enroll-browser-acceptance "$target" > /dev/null 2>&1
}
trust_dirs=''
for mainnet_write in on off; do
  want=operator-enroll-browser-acceptance
  [ "$mainnet_write" = on ] && want="mainnet-write,$want"
  trust_case "$mainnet_write" mainnet_presence_browser_acceptance
  rc=$?
  IFS='|' read -r dir home < "$STUB/env"
  trust_dirs="$trust_dirs $dir"
  problems=''
  [ "$rc" -eq 0 ] || problems="$problems exit $rc;"
  [[ "$(cat "$STUB/args")" == *"--no-default-features --features $want --test mainnet_presence_browser_acceptance "* ]] \
    || problems="$problems features '$(cat "$STUB/args")';"
  [ "$home" = "$HOME" ] || problems="$problems cargo HOME '$home';"
  [ -z "${STELLAR_AGENT_BROWSER_TRUST_DIR+set}" ] || problems="$problems the trust variable leaked;"
  case "$dir" in
    "$ROOT"/target/tmp/browser-trust/attempt.*) ;;
    *) problems="$problems trust directory '$dir';" ;;
  esac
  for name in trusted-chain.pem trusted-key.pem untrusted-chain.pem untrusted-key.pem trusted.pin untrusted.pin; do
    [ -s "$dir/$name" ] || problems="$problems $name missing;"
  done
  for name in trusted-key.pem untrusted-key.pem trusted-ca-key.pem untrusted-ca-key.pem; do
    [ "$(stat -c %a "$dir/$name" 2> /dev/null || stat -f %Lp "$dir/$name")" = 600 ] \
      || problems="$problems $name is not 0600;"
  done
  pin=$(openssl x509 -in "$dir/trusted-leaf.pem" -pubkey -noout | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -r | cut -c1-64)
  [ "$(cat "$dir/trusted.pin")" = "$pin" ] || problems="$problems trusted.pin differs from the leaf;"
  openssl verify -CAfile "$dir/trusted-ca.pem" "$dir/trusted-leaf.pem" > /dev/null 2>&1 \
    || problems="$problems the trusted leaf does not verify;"
  ! openssl verify -CAfile "$dir/trusted-ca.pem" "$dir/untrusted-leaf.pem" > /dev/null 2>&1 \
    || problems="$problems the untrusted leaf verifies against the trusted authority;"
  openssl x509 -in "$dir/trusted-leaf.pem" -noout -ext subjectAltName 2> /dev/null \
    | grep -qF "DNS:$BROWSER_TRUST_HOST, DNS:$BROWSER_TRUST_FOREIGN_HOST" \
    || problems="$problems the leaf lacks DNS:$BROWSER_TRUST_HOST and DNS:$BROWSER_TRUST_FOREIGN_HOST;"
  expected_certutil=''
  for db in "$dir/home/.pki/nssdb" "$dir/home/.local/share/pki/nssdb"; do
    expected_certutil="${expected_certutil}-N --empty-password -d sql:$db
-A -d sql:$db -n stellar-agent-test-ca -t C,, -i $dir/trusted-ca.pem
"
  done
  [ "$(cat "$STUB/certutil-args")" = "${expected_certutil%$'\n'}" ] \
    || problems="$problems certutil calls '$(cat "$STUB/certutil-args")';"
  if [ -z "$problems" ]; then
    pass "(k) MAINNET_WRITE=$mainnet_write the presence browser suite gets fresh private trust and --features $want"
  else
    fail "(k) MAINNET_WRITE=$mainnet_write trust setup:$problems"
  fi
done
read -r first_dir second_dir <<< "$trust_dirs"
if [ -n "$first_dir" ] && [ "$first_dir" != "$second_dir" ]; then
  pass '(k) each attempt gets its own trust directory'
else
  fail "(k) attempts share the trust directory '$first_dir'"
fi
# A failed setup stops the suite before cargo, with the deterministic status.
STUB_CERTUTIL=fail trust_case off operator_enroll_browser_acceptance
rc=$?
if [ "$rc" -eq 3 ] && [ ! -s "$STUB/args" ] && [ -s "$STUB/certutil-args" ]; then
  pass '(k) a failed trust setup returns 3 before any cargo call'
else
  fail "(k) failed trust setup: exit $rc, cargo calls '$(cat "$STUB/args")'"
fi
# Another suite never prepares trust and never sees the variable.
: > "$STUB/args"; : > "$STUB/env"; : > "$STUB/certutil-args"
(MAINNET_WRITE=off PATH="$STUB:$PATH" run_suite stellar-agent-cli testnet-acceptance claim_testnet_acceptance \
  > /dev/null 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ ! -s "$STUB/certutil-args" ] && [ "$(cut -d'|' -f1 "$STUB/env")" = unset ]; then
  pass '(k) a suite outside TRUSTED_BROWSER_SUITES runs without trust setup'
else
  fail "(k) claim_testnet_acceptance: exit $rc, certutil '$(cat "$STUB/certutil-args")', env '$(cat "$STUB/env")'"
fi
rm -f "$STUB/sleep" "$STUB/sleeps" "$STUB/summary"
rm -f "$STUB/cargo" "$STUB/args" "$STUB/env" "$STUB/certutil" "$STUB/certutil-args" "$STUB/uname"
rmdir "$STUB"

if [ "$test_failures" -gt 0 ]; then
  echo "$test_failures testnet acceptance driver check(s) failed" >&2
  exit 1
fi
echo "testnet acceptance driver checks passed"

#!/usr/bin/env bash
# Serialized driver for the live testnet-acceptance suites.
#
# Runs every live suite one binary at a time (and --test-threads=1 inside each
# binary) with a pause between suites: the suites share the public testnet's
# Friendbot and RPC load balancer, and back-to-back fund/deploy bursts trip
# rate limits and eventual-consistency windows that have nothing to do with
# the code under test. For the same reason a failing suite is retried once
# after a cooldown; a pass on retry is reported as "pass (retry)" so
# environmental flakiness stays visible instead of disappearing into green.
#
# A suite that executes zero tests fails the run: several test files are
# compiled empty when their feature flag is missing, so an empty test binary
# would otherwise report a vacuous pass.
#
# Environment:
#   SHARE           k/N selects registry indices i where i % N == k - 1.
#                   Unset or empty selects all entries; FILTER applies within it.
#   FILTER          only run suites whose "<crate>/<target>" contains this
#                   substring (empty runs everything)
#   STELLAR_AGENT_KEYRING_BACKEND
#                   keyring backend for the spawned binary. Unset selects the
#                   encrypted headless store with a key generated for this
#                   run, so no suite reaches the machine's own keyring.
#   STELLAR_AGENT_TEST_KEYRING
#                   platform or unset. With platform, the driver unsets
#                   STELLAR_AGENT_KEYRING_BACKEND and
#                   STELLAR_AGENT_HEADLESS_KEYRING_KEY and skips the headless
#                   default, so the spawned binary uses the platform keyring
#                   of the session. Any other value, the empty one included,
#                   fails the run before the first suite.
#   MAINNET_WRITE   on or off (default off). With on, every suite of a crate
#                   that declares a mainnet-write feature builds with that
#                   feature beside the suite's own, which is the build the
#                   binaries ship by default; a crate without the feature
#                   builds as with off. Any other value fails the run before
#                   the first suite.
#   PACE            seconds to sleep between suites (default 30)
#   RETRY_COOLDOWN  seconds to sleep before the single retry (default 60)
#
# Each result line, the summary, and the step summary carry the wall seconds
# of the attempt that produced the result, and for a retried suite the
# seconds of all its attempts; the summary closes with the leg's wall time.
#
# The WebAuthn suite (smart_account_rules_webauthn_testnet_acceptance), the
# remote-approval browser suite (remote_approval_browser_testnet_acceptance),
# and the rule-proposal remote browser suite
# (rule_proposal_remote_browser_testnet_acceptance) each launch a headless
# Chromium and need chromium/google-chrome on PATH or the CHROME env var
# pointing at the executable. The ergonomics suite
# (smart_account_ergonomics_testnet_acceptance) has the same Chromium
# dependency for its ONE `#[ignore]`d passkey-genesis test only — its other
# five tests need no browser. The operator-enroll browser acceptance suite
# (operator_enroll_browser_acceptance) has the same Chromium dependency for
# its one browser-driven test only; its two negative-path tests drive the
# real HTTP surface directly and need no browser. The mainnet consent browser
# suite (mainnet_presence_browser_acceptance) has the same Chromium
# dependency for its one test. Both suites serve their pages over loopback
# HTTP and need no testnet or RPC.
#
# Every suite that signs a smart-account authorization needs
# STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL: a testnet Soroban RPC endpoint on
# a host other than the primary's, for the ledger witness and the cross-RPC
# check. Such a suite fails when it is unset or does not parse.
#
# The multicall suites deploy the vendored router themselves. The library
# suite (smart_account_multicall_testnet_acceptance) also reads an optional
# override: STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS names a deployed
# router to use instead. An override that does not parse fails the suite.

set -u -o pipefail

PACE="${PACE:-30}"
RETRY_COOLDOWN="${RETRY_COOLDOWN:-60}"
BROWSER_RETRY_COOLDOWN="${BROWSER_RETRY_COOLDOWN:-90}"
FILTER="${FILTER:-}"
SHARE="${SHARE:-}"
# Unset means off; a value set to the empty string is refused like any other
# value that is not on or off.
MAINNET_WRITE="${MAINNET_WRITE-off}"

# Every suite uses a fresh marked wallet root.
storage_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/tmp/test-sandboxes
mkdir -p "$storage_root"
STELLAR_AGENT_HOME=$(mktemp -d "$storage_root/acceptance.XXXXXX")
touch "$STELLAR_AGENT_HOME/.stellar-agent-test-sandbox"
export STELLAR_AGENT_HOME

# The suites spawn the real binary, which reads its audit keys, window-state
# generation counters and tip anchors from the OS keyring. On macOS that is
# the login Keychain, and an unsigned development build is a program the
# Keychain has not seen before, so it asks the person at the machine for
# access, once per item per build, and waits for an answer that an unattended
# run never gives. The encrypted headless store needs no such permission.
# An environment that already selects a backend keeps it, and
# STELLAR_AGENT_TEST_KEYRING=platform selects the platform keyring instead.
if [ "${STELLAR_AGENT_TEST_KEYRING-}" = platform ]; then
  unset STELLAR_AGENT_KEYRING_BACKEND STELLAR_AGENT_HEADLESS_KEYRING_KEY
  export STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING=real-platform-keyring
elif [ -z "${STELLAR_AGENT_KEYRING_BACKEND:-}" ]; then
  export STELLAR_AGENT_KEYRING_BACKEND=headless-env
  # 32 random bytes, URL-safe base64, unpadded: the key format the headless
  # store requires. The store decodes the value strictly, as the encoding of
  # exactly 32 bytes, so the key is encoded from the bytes. It lives for this
  # run only, so the store it protects is discarded with it.
  STELLAR_AGENT_HEADLESS_KEYRING_KEY="${STELLAR_AGENT_HEADLESS_KEYRING_KEY:-$(
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
  )}"
  export STELLAR_AGENT_HEADLESS_KEYRING_KEY
fi

# Suites that launch a headless Chromium (see the module comment above for
# which test within each suite actually drives the browser). Page-load
# failures in a headless Chromium under CI load are a distinct environmental
# flake from the rest of the suites' RPC/Friendbot flakiness, so these get
# ONE additional retry beyond the universal retry-once default, preceded by
# BROWSER_RETRY_COOLDOWN instead of RETRY_COOLDOWN.
BROWSER_SUITE_TARGETS=(
  "smart_account_rules_webauthn_testnet_acceptance"
  "smart_account_ergonomics_testnet_acceptance"
  "operator_enroll_browser_acceptance"
  "mainnet_presence_browser_acceptance"
  "remote_approval_browser_testnet_acceptance"
  "rule_proposal_remote_browser_testnet_acceptance"
)

is_browser_suite() {
  local target="$1"
  printf '%s\n' "${BROWSER_SUITE_TARGETS[@]}" | grep -qxF "$target"
}

# MCP suites that compile the shared tests/common module, whose child-driver
# tests start the stellar-agent executable of stellar-agent-cli. Before such a
# suite, the driver builds the tests of both packages with the suite's feature
# list, so that executable exists with the features of this run.
CHILD_DRIVER_SUITES=(
  "create_account_testnet_acceptance"
  "trustline_classic_testnet_acceptance"
  "policy_value_descriptor_testnet_acceptance"
)

needs_server_child() {
  local crate="$1" target="$2"
  [ "$crate" = stellar-agent-mcp ] && printf '%s\n' "${CHILD_DRIVER_SUITES[@]}" | grep -qxF "$target"
}

# Completeness guard: every live test file on disk, a *testnet* file or a
# *_browser_acceptance file, must be listed in SUITES below. The per-suite
# zero-tests guard cannot catch a file that is never invoked at all, so an
# unlisted file would silently not execute while the run reports green.
check_suite_completeness() {
  local missing=0
  while IFS= read -r f; do
    local target
    target="$(basename "$f" .rs)"
    if ! printf '%s\n' "${SUITES[@]}" | grep " ${target}$" > /dev/null; then
      echo "ERROR: ${f} is not listed in SUITES; add it, or rename it away from the *testnet* and *_browser_acceptance patterns if it is not a live suite" >&2
      missing=1
    fi
  done < <(find crates -path '*/tests/*' \( -name '*testnet*.rs' -o -name '*_browser_acceptance.rs' \) \
    -not -path '*fixtures*' | sort)
  return "$missing"
}

# Refuses a MAINNET_WRITE value other than on or off, so a misspelled value
# never runs the leg against a build the caller did not ask for.
check_mainnet_write() {
  case "$MAINNET_WRITE" in
    on | off) return 0 ;;
  esac
  echo "error: MAINNET_WRITE must be on or off, not '${MAINNET_WRITE}'" >&2
  return 1
}

# Refuses a set STELLAR_AGENT_TEST_KEYRING other than platform, so a
# misspelled value never runs the leg against a keyring the caller did not
# ask for.
check_test_keyring() {
  if [ -z "${STELLAR_AGENT_TEST_KEYRING+set}" ] || [ "$STELLAR_AGENT_TEST_KEYRING" = platform ]; then
    return 0
  fi
  echo "error: STELLAR_AGENT_TEST_KEYRING must be platform or unset, not '${STELLAR_AGENT_TEST_KEYRING}'" >&2
  return 1
}

# Prints the --features list of one suite: the suite's feature, preceded by
# mainnet-write when MAINNET_WRITE is on and the crate's manifest declares a
# mainnet-write feature. A crate without that feature has no mainnet-write
# gate of its own, and naming the feature would fail its build.
suite_features() {
  local crate="$1" feature="$2"
  if [ "${STELLAR_AGENT_TEST_KEYRING-}" = platform ] && grep -qE '^live-platform-keyring *=' "crates/$crate/Cargo.toml"; then
    feature="$feature,live-platform-keyring"
  fi
  if [ "$MAINNET_WRITE" = "on" ] && grep -qE '^mainnet-write *=' "crates/$crate/Cargo.toml"; then
    printf 'mainnet-write,%s\n' "$feature"
  else
    printf '%s\n' "$feature"
  fi
}

# "<crate> <feature> <test target>", ordered light-to-heavy: auth round-trips
# and read-only previews first, single-tx submit flows next, then the
# smart-account deploy-heavy suites so Friendbot usage ramps up gradually.
# The timelock and WebAuthn suites go last: they are the longest and the most
# sensitive to testnet propagation delay.
SUITES=(
  "stellar-agent-sep10 testnet-integration sep10_round_trip_testnet_acceptance"
  "stellar-agent-sep10 testnet-integration sep10_replay_adversarial"
  "stellar-agent-sep43 testnet-acceptance sep43_sdk_v17_interop_testnet_acceptance"
  "stellar-agent-sep48 testnet-acceptance sep48_preview_testnet_acceptance"
  "stellar-agent-sep7 testnet-acceptance sep7_testnet_acceptance"
  "stellar-agent-anchor testnet-acceptance anchor_testnet_acceptance"
  "stellar-agent-x402-identity testnet-acceptance sep10_gate_testnet_acceptance"
  "stellar-agent-network testnet-acceptance fee_bump_testnet"
  "stellar-agent-network testnet-acceptance fee_bump_idempotent_testnet"
  "stellar-agent-pool testnet-acceptance pool_testnet_init"
  "stellar-agent-pool testnet-acceptance pool_concurrent_testnet"
  "stellar-agent-pool testnet-acceptance load_testnet"
  "stellar-agent-stablecoin testnet-acceptance trustline_testnet_acceptance"
  "stellar-agent-x402 testnet-acceptance x402_exact_testnet_acceptance"
  "stellar-agent-mpp testnet-acceptance sponsored_testnet_acceptance"
  "stellar-agent-dex testnet-acceptance dex_swap_testnet_acceptance"
  "stellar-agent-defindex testnet-acceptance defindex_vault_testnet_acceptance"
  "stellar-agent-defindex testnet-acceptance defindex_deposit_submit_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance pay_commit_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance create_account_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance trustline_classic_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance policy_value_descriptor_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance rule_create_commit_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance sep43_sign_and_submit_transaction_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance toolset_sign_payment_gated_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance x402_create_payment_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance x402_authenticated_payment_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance claim_commit_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance approve_serve_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance dex_quote_wire_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance claim_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance pay_policy_v1_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance pay_timeout_reconcile_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance cli_submit_only_network_binding_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance profile_init_enroll_signer_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance smart_account_execute_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance smart_account_multicall_cli_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance cap85_external_ref_cli_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration deploy_c_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration quorum_authorization_info_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_caps_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_signers_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_rules_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_rules_pinning_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_list_rules_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_policy_mutators_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_session_rule_expiry_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_session_rule_horizon_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_sim_audit_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_migrate_verifier_testnet_acceptance"
  "stellar-agent-smart-account-acceptance testnet-integration cap85_external_ref_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_multicall_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_timelock_testnet_acceptance"
  "stellar-agent-smart-account-acceptance testnet-integration smart_account_rules_webauthn_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_delegation_testnet_acceptance"
  "stellar-agent-smart-account-acceptance testnet-integration smart_account_policy_observability_testnet_acceptance"
  "stellar-agent-smart-account-acceptance testnet-integration smart_account_ergonomics_testnet_acceptance"
  "stellar-agent-approval-remote operator-enroll-browser-acceptance operator_enroll_browser_acceptance"
  "stellar-agent-approval-remote operator-enroll-browser-acceptance mainnet_presence_browser_acceptance"
  "stellar-agent-approval-remote testnet-acceptance remote_approval_browser_testnet_acceptance"
  "stellar-agent-approval-remote testnet-acceptance rule_proposal_remote_browser_testnet_acceptance"
)

# Validate decimal shares before any build. Length comparisons avoid overflow.
check_share() {
  [ -z "$SHARE" ] && return 0
  if [[ "$SHARE" =~ ^[1-9][0-9]*/[1-9][0-9]*$ ]]; then
    SHARE_K=${SHARE%/*}
    SHARE_N=${SHARE#*/}
    if [ "${#SHARE_K}" -lt "${#SHARE_N}" ] \
      || { [ "${#SHARE_K}" -eq "${#SHARE_N}" ] && [[ "$SHARE_K" < "$SHARE_N" || "$SHARE_K" = "$SHARE_N" ]]; }; then
      return 0
    fi
  fi
  echo "SHARE must be k/N with 1 <= k <= N, got '$SHARE'" >&2
  return 2
}

# Selection keeps registry order. A denominator beyond the registry selects at most one.
in_share() {
  [ -z "$SHARE" ] && return 0
  local count=${#SUITES[@]}
  if [ "${#SHARE_N}" -gt "${#count}" ] || [ "$SHARE_N" -gt "$count" ]; then
    [ "$(( $1 + 1 ))" = "$SHARE_K" ]
  else
    [ "$(( $1 % SHARE_N ))" -eq "$(( SHARE_K - 1 ))" ]
  fi
}

# Runs one suite; prints the cargo output as it streams. Returns 0 on a real
# pass (at least one test executed), 1 on test failure, 2 on a vacuous pass
# (the binary ran zero tests, which means the feature gating is broken), 3 on
# a deterministic cargo error (compile failure, unknown test target, unknown
# feature) that a retry cannot change.
#
# Sets LAST_SKIPS to the number of self-skip markers the suite printed. Tests
# that need an unavailable precondition print a SKIP line and return without
# failing; surfacing the count in the summary keeps a green run honest about
# what did not execute. Sets LAST_SECONDS to the wall seconds of the attempt.
#
# Every suite builds with --no-default-features and the list suite_features
# prints, so mainnet-write is on only under MAINNET_WRITE=on and only for a
# crate that declares the feature.
#
# A suite of CHILD_DRIVER_SUITES first runs the paired prebuild of the CLI
# and MCP tests with the same flags. A failed prebuild returns 3 before the
# suite runs.
run_suite() {
  local crate="$1" feature="$2" target="$3" features log status summary executed deterministic tmp_root start
  features=$(suite_features "$crate" "$feature")
  tmp_root=${TMPDIR:-/tmp}
  log=$(mktemp "${tmp_root%/}/run-testnet-acceptance.XXXXXX")
  start=$SECONDS
  LAST_SKIPS=0
  if needs_server_child "$crate" "$target"; then
    cargo test -p stellar-agent-cli -p "$crate" --no-default-features --features "$features" --no-run 2>&1 | tee "$log"
    status=${PIPESTATUS[0]}
    if [ "$status" -ne 0 ]; then
      LAST_SECONDS=$((SECONDS - start))
      rm -f "$log"
      echo "error: the paired prebuild for $crate/$target failed with status $status" >&2
      return 3
    fi
  fi
  cargo test -p "$crate" --no-default-features --features "$features" --test "$target" \
    -- --include-ignored --test-threads=1 --nocapture 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  LAST_SECONDS=$((SECONDS - start))
  # Last harness summary line, e.g.:
  #   test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; ...
  summary=$(grep -E '^test result:' "$log" | tail -1)
  executed=$(echo "$summary" | sed -nE 's/^test result: [^.]+\. ([0-9]+) passed; ([0-9]+) failed.*/\1 \2/p' \
    | awk '{ print $1 + $2 }')
  LAST_SKIPS=$(grep -cE '\bSKIP\b' "$log")
  deterministic=0
  if grep -qE '^error(\[E[0-9]+\])?: (could not compile|no test target)|does not contain (this|these) feature' "$log"; then
    deterministic=1
  fi
  rm -f "$log"
  if [ "$status" -ne 0 ]; then
    if [ "$deterministic" -eq 1 ]; then
      return 3
    fi
    return 1
  fi
  if [ -z "${executed:-}" ] || [ "$executed" -eq 0 ]; then
    echo "error: $crate/$target passed but executed zero tests (broken feature gating?)" >&2
    return 2
  fi
  return 0
}

# Prints a suite result: the outcome, then in parentheses its notes, the wall
# seconds of the attempt that produced it, and for a retried suite the wall
# seconds of all attempts, as in "pass (retry, 412 s, 830 s total)".
format_result() {
  local outcome="$1" notes="$2" attempts="$3" last="$4" total="$5" detail
  detail="${notes:+$notes, }${last} s"
  if [ "$attempts" -gt 1 ]; then
    detail="${detail}, ${total} s total"
  fi
  printf '%s (%s)\n' "$outcome" "$detail"
}

main() {
  local line crate feature target suite rc attempts suite_seconds outcome notes result leg_start leg_seconds i
  check_mainnet_write || exit 2
  check_test_keyring || exit 2
  check_share || exit 2
  check_suite_completeness || exit 3

  local matched=0 index
  for line in "${SUITES[@]}"; do
    read -r crate feature target <<< "$line"
    if [[ "$crate/$target" == *"$FILTER"* ]]; then matched=1; fi
  done
  if [ "$matched" -eq 0 ]; then
    echo "error: no suite matched FILTER='$FILTER'" >&2
    exit 2
  fi

  report_status=()
  report_suite=()
  report_seconds=()
  failures=0
  ran=0
  leg_start=$SECONDS
  echo "testnet acceptance: share ${SHARE:-all}, mainnet-write ${MAINNET_WRITE}"

  for index in "${!SUITES[@]}"; do
    in_share "$index" || continue
    line=${SUITES[$index]}
    read -r crate feature target <<< "$line"
    suite="$crate/$target"
    if [ -n "$FILTER" ] && [[ "$suite" != *"$FILTER"* ]]; then
      continue
    fi
    if [ "$ran" -gt 0 ]; then
      echo "pacing: sleeping ${PACE}s before the next suite"
      sleep "$PACE"
    fi
    ran=$((ran + 1))
    echo "::group::$suite"
    run_suite "$crate" "$feature" "$target"
    rc=$?
    attempts=1
    suite_seconds=$LAST_SECONDS
    # A vacuous pass (2) and a compile, unknown-target, or unknown-feature
    # error (3) are deterministic; retrying cannot change them. A test
    # failure (1) is retried once after a cooldown.
    if [ "$rc" -eq 1 ]; then
      echo "suite $suite failed; retrying once after ${RETRY_COOLDOWN}s cooldown"
      sleep "$RETRY_COOLDOWN"
      run_suite "$crate" "$feature" "$target"
      rc=$?
      attempts=2
      suite_seconds=$((suite_seconds + LAST_SECONDS))
      if [ "$rc" -ne 0 ] && is_browser_suite "$target"; then
        # Headless-Chromium page-load failures are a distinct environmental
        # flake from the rest of this suite's dependencies; browser suites
        # get one additional retry beyond the universal retry-once default.
        echo "browser suite $suite failed twice; retrying once more after \
${BROWSER_RETRY_COOLDOWN}s cooldown"
        sleep "$BROWSER_RETRY_COOLDOWN"
        run_suite "$crate" "$feature" "$target"
        rc=$?
        attempts=3
        suite_seconds=$((suite_seconds + LAST_SECONDS))
      fi
    fi
    notes=""
    if [ "$rc" -eq 0 ]; then
      outcome="pass"
      case "$attempts" in
        2) notes="retry" ;;
        3) notes="retry 2" ;;
      esac
      if [ "${LAST_SKIPS:-0}" -gt 0 ]; then
        notes="${notes:+$notes, }${LAST_SKIPS} skip marker(s)"
      fi
    else
      outcome="FAIL"
      failures=$((failures + 1))
      if [ "$attempts" -eq 1 ] && [ "$rc" -eq 2 ]; then
        notes="vacuous: zero tests executed"
      elif [ "$attempts" -eq 1 ] && [ "$rc" -eq 3 ]; then
        notes="build or target error"
      fi
    fi
    result=$(format_result "$outcome" "$notes" "$attempts" "$LAST_SECONDS" "$suite_seconds")
    echo "::endgroup::"
    echo "result: $suite -> $result"
    report_status+=("$result")
    report_suite+=("$suite")
    report_seconds+=("$suite_seconds")
  done

  leg_seconds=$((SECONDS - leg_start))

  echo ""
  echo "==== testnet acceptance summary ($ran suites, share ${SHARE:-all}, mainnet-write ${MAINNET_WRITE}) ===="
  for i in "${!report_suite[@]}"; do
    printf '%-90s %s\n' "${report_suite[$i]}" "${report_status[$i]}"
  done
  echo "leg wall time: ${leg_seconds} s"

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "## Testnet acceptance ($ran suites, share ${SHARE:-all}, mainnet-write ${MAINNET_WRITE})"
      echo ""
      echo "| suite | result | seconds |"
      echo "| --- | --- | --- |"
      for i in "${!report_suite[@]}"; do
        echo "| ${report_suite[$i]} | ${report_status[$i]} | ${report_seconds[$i]} |"
      done
      echo ""
      echo "Leg wall time: ${leg_seconds} s."
    } >> "$GITHUB_STEP_SUMMARY"
  fi

  if [ "$failures" -gt 0 ]; then
    echo ""
    echo "$failures suite(s) failed"
    exit 1
  fi
  echo ""
  echo "all suites passed"
}

# The run starts only when the script is executed; a test sources it for its
# functions and suite lists.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

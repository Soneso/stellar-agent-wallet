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
#   FILTER          only run suites whose "<crate>/<target>" contains this
#                   substring (empty runs everything)
#   PACE            seconds to sleep between suites (default 30)
#   RETRY_COOLDOWN  seconds to sleep before the single retry (default 60)
#
# The WebAuthn suite (smart_account_rules_webauthn_testnet_acceptance), the
# remote-approval browser suite (remote_approval_browser_testnet_acceptance),
# and the rule-proposal remote browser suite
# (rule_proposal_remote_browser_testnet_acceptance) each launch a headless
# Chromium and need chromium/google-chrome on PATH or the CHROME env var
# pointing at the executable.
#
# The multicall suite's happy-path test additionally wants
# STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS and
# STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL; it skips itself (without failing)
# when they are absent.

set -u -o pipefail

PACE="${PACE:-30}"
RETRY_COOLDOWN="${RETRY_COOLDOWN:-60}"
FILTER="${FILTER:-}"

# "<crate> <feature> <test target>", ordered light-to-heavy: auth round-trips
# and read-only previews first, single-tx submit flows next, then the
# smart-account deploy-heavy suites so Friendbot usage ramps up gradually.
# The timelock and WebAuthn suites go last: they are the longest and the most
# sensitive to testnet propagation delay.
SUITES=(
  "stellar-agent-sep10 testnet-integration sep10_round_trip_testnet_acceptance"
  "stellar-agent-sep10 testnet-integration sep10_replay_adversarial"
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
  "stellar-agent-dex testnet-acceptance dex_swap_testnet_acceptance"
  "stellar-agent-blend testnet-acceptance blend_lend_testnet_acceptance"
  "stellar-agent-blend testnet-acceptance blend_supply_submit_testnet_acceptance"
  "stellar-agent-defindex testnet-acceptance defindex_vault_testnet_acceptance"
  "stellar-agent-defindex testnet-acceptance defindex_deposit_submit_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance pay_commit_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance sep43_sign_and_submit_transaction_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance toolset_sign_payment_gated_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance x402_create_payment_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance x402_authenticated_payment_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance claim_commit_testnet_acceptance"
  "stellar-agent-mcp testnet-acceptance approve_serve_testnet_acceptance"
  "stellar-agent-cli testnet-acceptance claim_testnet_acceptance"
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
  "stellar-agent-smart-account testnet-integration smart_account_multicall_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_timelock_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_rules_webauthn_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_delegation_testnet_acceptance"
  "stellar-agent-smart-account testnet-integration smart_account_policy_observability_testnet_acceptance"
  "stellar-agent-approval-remote testnet-acceptance remote_approval_browser_testnet_acceptance"
  "stellar-agent-approval-remote testnet-acceptance rule_proposal_remote_browser_testnet_acceptance"
)

# Runs one suite; prints the cargo output as it streams. Returns 0 on a real
# pass (at least one test executed), 1 on test failure, 2 on a vacuous pass
# (the binary ran zero tests, which means the feature gating is broken), 3 on
# a deterministic cargo error (compile failure, unknown test target, unknown
# feature) that a retry cannot change.
#
# Sets LAST_SKIPS to the number of self-skip markers the suite printed. Tests
# that need an unavailable precondition (for example the multicall suite's
# router env vars) print a SKIP line and return without failing; surfacing the
# count in the summary keeps a green run honest about what did not execute.
run_suite() {
  local crate="$1" feature="$2" target="$3" log status summary executed deterministic
  log=$(mktemp)
  cargo test -p "$crate" --features "$feature" --test "$target" \
    -- --include-ignored --test-threads=1 --nocapture 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
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

declare -a report_status report_suite
failures=0
ran=0

for line in "${SUITES[@]}"; do
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
  if run_suite "$crate" "$feature" "$target"; then
    result="pass"
    if [ "${LAST_SKIPS:-0}" -gt 0 ]; then
      result="pass (${LAST_SKIPS} skip marker(s))"
    fi
  else
    rc=$?
    if [ "$rc" -eq 2 ]; then
      # A vacuous pass is deterministic; retrying cannot change it.
      result="FAIL (vacuous: zero tests executed)"
      failures=$((failures + 1))
    elif [ "$rc" -eq 3 ]; then
      # Compile / unknown-target / unknown-feature errors are deterministic;
      # retrying cannot change them.
      result="FAIL (build or target error)"
      failures=$((failures + 1))
    else
      echo "suite $suite failed; retrying once after ${RETRY_COOLDOWN}s cooldown"
      sleep "$RETRY_COOLDOWN"
      if run_suite "$crate" "$feature" "$target"; then
        result="pass (retry)"
        if [ "${LAST_SKIPS:-0}" -gt 0 ]; then
          result="pass (retry, ${LAST_SKIPS} skip marker(s))"
        fi
      else
        result="FAIL"
        failures=$((failures + 1))
      fi
    fi
  fi
  echo "::endgroup::"
  echo "result: $suite -> $result"
  report_status+=("$result")
  report_suite+=("$suite")
done

if [ "$ran" -eq 0 ]; then
  echo "error: no suite matched FILTER='$FILTER'" >&2
  exit 2
fi

echo ""
echo "==== testnet acceptance summary ($ran suites) ===="
for i in "${!report_suite[@]}"; do
  printf '%-90s %s\n' "${report_suite[$i]}" "${report_status[$i]}"
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Testnet acceptance ($ran suites)"
    echo ""
    echo "| suite | result |"
    echo "| --- | --- |"
    for i in "${!report_suite[@]}"; do
      echo "| ${report_suite[$i]} | ${report_status[$i]} |"
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$failures" -gt 0 ]; then
  echo ""
  echo "$failures suite(s) failed"
  exit 1
fi
echo ""
echo "all suites passed"

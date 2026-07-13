#!/bin/bash
# Publishes every workspace crate to crates.io in dependency order.
#
# The workspace is a 7-tier dependency DAG; each tier must be fully live on
# the registry before the next tier's verify builds can resolve it. Within a
# tier, order is free. `cargo publish` verifies (builds) each crate before
# upload and blocks until the published version is visible in the index.
#
# Resumable: a version that is already on the registry counts as success, so
# re-running after a partial failure publishes only what is missing.
# Rate-limit aware: crates.io throttles publishes; on HTTP 429 the loop
# sleeps past the refill window and retries the same crate.
#
# Requires CARGO_REGISTRY_TOKEN in the environment (in CI this is the
# short-lived OIDC token minted by rust-lang/crates-io-auth-action).
set -u

if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
  echo "CARGO_REGISTRY_TOKEN is not set" >&2
  exit 2
fi

TIER0="stellar-agent-loopback-http stellar-agent-mcp-macros stellar-agent-sep5 stellar-agent-test-support stellar-agent-toolsets stellar-agent-windows-identity stellar-agent-xdr-limits"
TIER1="stellar-agent-core stellar-agent-headless-keyring stellar-agent-sep10 stellar-agent-sep45"
TIER2="stellar-agent-network stellar-agent-toolsets-install"
TIER3="stellar-agent-anchor stellar-agent-claimable stellar-agent-defi stellar-agent-nonce stellar-agent-pool stellar-agent-sep48 stellar-agent-sep53 stellar-agent-sep7 stellar-agent-smart-account stellar-agent-stablecoin stellar-agent-toolsets-runtime stellar-agent-x402-identity"
TIER4="stellar-agent-approval-ui stellar-agent-blend stellar-agent-defindex stellar-agent-dex stellar-agent-sep43 stellar-agent-webauthn-bridge"
TIER5="stellar-agent-approval-remote stellar-agent-x402"
TIER6="stellar-agent-cli stellar-agent-mcp"

# Completeness guard: every workspace member must appear in exactly the tier
# lists above. A crate added to the workspace without a tier assignment fails
# the run here, before anything is uploaded.
ALL_TIERED=$(echo "$TIER0 $TIER1 $TIER2 $TIER3 $TIER4 $TIER5 $TIER6" | tr ' ' '\n' | sort)
ALL_WORKSPACE=$(cargo metadata --no-deps --format-version 1 |
  python3 -c "import json,sys; [print(p['name']) for p in json.load(sys.stdin)['packages']]" | sort)
if [ "$ALL_TIERED" != "$ALL_WORKSPACE" ]; then
  echo "Tier lists do not match the workspace members:" >&2
  diff <(echo "$ALL_TIERED") <(echo "$ALL_WORKSPACE") >&2
  exit 2
fi

publish_one() {
  local name=$1
  local log
  log=$(mktemp)
  local attempt=0
  while : ; do
    attempt=$((attempt + 1))
    cargo publish -p "$name"
    local rc=$?
    if [ $rc -eq 0 ]; then
      echo "OK $name (attempt $attempt)"
      rm -f "$log"
      return 0
    fi
    # Re-run capturing output for classification; the first failing run above
    # already streamed its output to the job log.
    cargo publish -p "$name" >"$log" 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
      echo "OK $name (attempt $attempt, retry)"
      rm -f "$log"
      return 0
    fi
    if grep -qiE "already (exists|uploaded)|is already uploaded" "$log"; then
      echo "OK $name (already published)"
      rm -f "$log"
      return 0
    fi
    if grep -qiE "429|rate limit|too many" "$log"; then
      echo "RATE-LIMITED $name (attempt $attempt), sleeping 620s"
      sleep 620
      continue
    fi
    if grep -qiE "no matching package named|failed to select a version" "$log" && [ $attempt -le 6 ]; then
      echo "INDEX-WAIT $name (attempt $attempt), sleeping 60s"
      sleep 60
      continue
    fi
    if grep -qiE "503|service unavailable|connection|timed out|spurious network" "$log" && [ $attempt -le 8 ]; then
      echo "NET-RETRY $name (attempt $attempt), sleeping 120s"
      sleep 120
      continue
    fi
    echo "FAIL $name rc=$rc (attempt $attempt):"
    cat "$log"
    rm -f "$log"
    return 1
  done
}

tier_index=0
for tier in "$TIER0" "$TIER1" "$TIER2" "$TIER3" "$TIER4" "$TIER5" "$TIER6"; do
  echo "=== tier $tier_index start $(date -u '+%H:%M:%S') ==="
  for name in $tier; do
    if ! publish_one "$name"; then
      echo "=== HALT in tier $tier_index at $name ==="
      exit 1
    fi
  done
  echo "=== tier $tier_index done $(date -u '+%H:%M:%S') ==="
  tier_index=$((tier_index + 1))
done
echo "All crates published."

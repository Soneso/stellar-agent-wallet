#!/bin/bash
# Publishes every workspace crate to crates.io in dependency order.
#
# The workspace is a 7-tier dependency DAG; each tier must be live on the
# registry before cargo can package the next tier against it. Within a tier,
# order is free. The script uploads each crate with
# `cargo publish --no-verify`: the verify job built every crate without
# credentials and recorded the archive checksums in SHA256SUMS, so this
# script compiles nothing.
#
# A crate counts as published only when crates.io serves the checksum that
# SHA256SUMS records for it. The script reads the checksum from the crates.io
# API after every successful upload and whenever crates.io reports the
# version as already uploaded; a different checksum halts the run and prints
# both values. A successful upload whose checksum is not yet visible is
# re-read every 30 seconds for up to 10 minutes, because cargo reports success
# when its own index wait times out.
#
# Resumable: re-running after a partial failure uploads only what is missing
# and checks the checksum of everything already published.
# Rate-limit aware: crates.io throttles publishes; on HTTP 429 the loop
# sleeps past the refill window and retries the same crate.
#
# Usage: publish-crates.sh --check
#        publish-crates.sh --sums <SHA256SUMS>
# --check verifies only that the tier lists cover the workspace. Publishing
# requires CARGO_REGISTRY_TOKEN in the environment (in CI the short-lived
# OIDC token minted by rust-lang/crates-io-auth-action) and runs in the
# workspace root.
set -u

usage() {
  echo "usage: $0 --check | --sums <SHA256SUMS>" >&2
  exit 2
}

MODE=""
SUMS=""
if [ "$#" -eq 1 ] && [ "$1" = "--check" ]; then
  MODE="check"
elif [ "$#" -eq 2 ] && [ "$1" = "--sums" ]; then
  MODE="publish"
  SUMS=$2
else
  usage
fi

TIER0="stellar-agent-loopback-http stellar-agent-mcp-macros stellar-agent-sep5 stellar-agent-soroban-auth stellar-agent-test-support stellar-agent-toolsets stellar-agent-windows-identity stellar-agent-xdr-limits"
TIER1="stellar-agent-core stellar-agent-headless-keyring stellar-agent-sep10 stellar-agent-sep45"
TIER2="stellar-agent-network stellar-agent-toolsets-install"
TIER3="stellar-agent-anchor stellar-agent-claimable stellar-agent-defi stellar-agent-nonce stellar-agent-pool stellar-agent-sep48 stellar-agent-sep53 stellar-agent-sep7 stellar-agent-smart-account stellar-agent-stablecoin stellar-agent-toolsets-runtime stellar-agent-x402-identity"
TIER4="stellar-agent-approval-ui stellar-agent-defindex stellar-agent-dex stellar-agent-sep43 stellar-agent-webauthn-bridge"
TIER5="stellar-agent-approval-remote stellar-agent-mpp stellar-agent-x402"
TIER6="stellar-agent-cli stellar-agent-mcp"

CRATES_IO_API="https://crates.io/api/v1/crates"
USER_AGENT="stellar-agent-wallet (https://github.com/Soneso/stellar-agent-wallet)"
VERIFY_INTERVAL=30
VERIFY_TIMEOUT=600

if ! METADATA=$(cargo metadata --no-deps --format-version 1); then
  echo "cargo metadata failed" >&2
  exit 2
fi
# One "name version" line per workspace member.
if ! MEMBERS=$(printf '%s' "$METADATA" |
  python3 -c "import json,sys; [print(p['name'], p['version']) for p in json.load(sys.stdin)['packages']]"); then
  echo "cannot read the workspace members from cargo metadata" >&2
  exit 2
fi

# Completeness guard: every workspace member must appear in exactly the tier
# lists above. A crate added to the workspace without a tier assignment fails
# the run here, before anything is uploaded.
ALL_TIERED=$(echo "$TIER0 $TIER1 $TIER2 $TIER3 $TIER4 $TIER5 $TIER6" | tr ' ' '\n' | sort)
ALL_WORKSPACE=$(printf '%s\n' "$MEMBERS" | awk '{print $1}' | sort)
if [ "$ALL_TIERED" != "$ALL_WORKSPACE" ]; then
  echo "Tier lists do not match the workspace members:" >&2
  diff <(echo "$ALL_TIERED") <(echo "$ALL_WORKSPACE") >&2
  exit 2
fi

if [ "$MODE" = "check" ]; then
  echo "Publish tiers match every workspace member exactly once."
  exit 0
fi

if [ ! -f "$SUMS" ] || [ ! -r "$SUMS" ]; then
  echo "SHA256SUMS file not readable: $SUMS" >&2
  exit 2
fi
if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
  echo "CARGO_REGISTRY_TOKEN is not set" >&2
  exit 2
fi

version_of() {
  printf '%s\n' "$MEMBERS" | awk -v n="$1" '$1 == n { print $2 }'
}

# Prints the SHA256SUMS hash of <file>; fails unless exactly one well-formed
# line names it.
expected_checksum() {
  local file=$1 sum
  sum=$(awk -v f="$file" '$2 == f && NF == 2 { print $1; n++ } END { exit n == 1 ? 0 : 1 }' "$SUMS") || return 1
  [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$sum"
}

# Every crate needs its SHA256SUMS entry before the first upload, so a sums
# file that misses one crate stops the run with nothing published.
for name in $ALL_TIERED; do
  version=$(version_of "$name")
  if ! expected_checksum "$name-$version.crate" >/dev/null; then
    echo "SHA256SUMS has no single valid entry for $name-$version.crate" >&2
    exit 2
  fi
done

# Prints the checksum crates.io records for <name> <version>. Returns 0 when
# found, 1 when crates.io has no such version (HTTP 404), and 2 on any other
# outcome (network error, other status, or a body without a checksum).
published_checksum() {
  local name=$1 version=$2 body code checksum
  body=$(mktemp)
  if ! code=$(curl --silent --show-error --location --max-time 30 \
    --user-agent "$USER_AGENT" --output "$body" --write-out '%{http_code}' \
    "$CRATES_IO_API/$name/$version"); then
    rm -f "$body"
    return 2
  fi
  if [ "$code" = "404" ]; then
    rm -f "$body"
    return 1
  fi
  if [ "$code" != "200" ]; then
    echo "crates.io API answered HTTP $code for $name $version" >&2
    rm -f "$body"
    return 2
  fi
  checksum=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['version']['checksum'])" "$body" 2>/dev/null)
  rm -f "$body"
  if ! [[ "$checksum" =~ ^[0-9a-f]{64}$ ]]; then
    echo "crates.io API returned no checksum for $name $version" >&2
    return 2
  fi
  printf '%s\n' "$checksum"
}

# Requires crates.io to serve <expected> for <name> <version>. Mode "uploaded"
# follows a successful upload: a missing or unreadable checksum is re-read
# until VERIFY_TIMEOUT. Mode "existing" follows an "already uploaded" answer:
# the version must already be on record, so a missing checksum fails at once
# and only an unreadable response is re-read.
verify_published() {
  local name=$1 version=$2 expected=$3 mode=$4 waited=0 checksum rc
  while : ; do
    checksum=$(published_checksum "$name" "$version")
    rc=$?
    if [ "$rc" -eq 0 ]; then
      if [ "$checksum" = "$expected" ]; then
        echo "VERIFIED $name $version sha256 $checksum"
        return 0
      fi
      echo "CHECKSUM MISMATCH $name $version: crates.io $checksum, SHA256SUMS $expected"
      return 1
    fi
    if [ "$rc" -eq 1 ] && [ "$mode" = "existing" ]; then
      echo "MISSING $name $version: reported as already uploaded, but crates.io has no record of it"
      return 1
    fi
    if [ "$waited" -ge "$VERIFY_TIMEOUT" ]; then
      echo "UNVERIFIED $name $version: no published checksum after ${waited}s"
      return 1
    fi
    echo "CHECKSUM-WAIT $name $version (${waited}s), sleeping ${VERIFY_INTERVAL}s"
    sleep "$VERIFY_INTERVAL"
    waited=$((waited + VERIFY_INTERVAL))
  done
}

publish_one() {
  local name=$1 version expected log attempt=0 rc
  version=$(version_of "$name")
  expected=$(expected_checksum "$name-$version.crate")
  log=$(mktemp)
  while : ; do
    attempt=$((attempt + 1))
    cargo publish -p "$name" --locked --no-verify 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    if [ "$rc" -eq 0 ]; then
      echo "UPLOADED $name (attempt $attempt)"
      rm -f "$log"
      verify_published "$name" "$version" "$expected" uploaded
      return $?
    fi
    if grep -qiE "already (exists|uploaded)|is already uploaded" "$log"; then
      echo "ALREADY UPLOADED $name"
      rm -f "$log"
      verify_published "$name" "$version" "$expected" existing
      return $?
    fi
    if grep -qiE "429|rate limit|too many" "$log"; then
      echo "RATE-LIMITED $name (attempt $attempt), sleeping 620s"
      sleep 620
      continue
    fi
    if grep -qiE "no matching package named|failed to select a version" "$log" && [ "$attempt" -le 6 ]; then
      echo "INDEX-WAIT $name (attempt $attempt), sleeping 60s"
      sleep 60
      continue
    fi
    if grep -qiE "503|service unavailable|connection|timed out|spurious network" "$log" && [ "$attempt" -le 8 ]; then
      echo "NET-RETRY $name (attempt $attempt), sleeping 120s"
      sleep 120
      continue
    fi
    echo "FAIL $name rc=$rc (attempt $attempt)"
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

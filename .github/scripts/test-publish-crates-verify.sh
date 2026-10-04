#!/usr/bin/env bash
# Offline regression checks for the publish path of publish-crates.sh.
#
# Stubs for cargo, curl, and sleep on PATH drive the real script end to end.
# The stub cargo serves the workspace metadata and answers each publish call
# from a per-scenario sequence. The stub curl answers HTTP 403 to a request
# without the expected User-Agent, which names only this repository and its
# URL. Otherwise it answers for one target crate from a sequence and serves
# the SHA256SUMS checksum for every other crate. The stub sleep only records
# its argument.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/publish-crates.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

TARGET=stellar-agent-core
LATER=stellar-agent-network
USER_AGENT="stellar-agent-wallet (https://github.com/Soneso/stellar-agent-wallet)"

(cd "$ROOT" && cargo metadata --no-deps --format-version 1) >"$TMP/metadata.json"
python3 - "$TMP/metadata.json" "$TMP/SHA256SUMS" <<'PY'
import hashlib, json, sys
packages = json.load(open(sys.argv[1]))["packages"]
with open(sys.argv[2], "w") as out:
    for p in sorted(packages, key=lambda p: p["name"]):
        digest = hashlib.sha256(p["name"].encode()).hexdigest()
        out.write(f"{digest}  {p['name']}-{p['version']}.crate\n")
PY
TARGET_VERSION=$(python3 -c "import json,sys; print([p['version'] for p in json.load(open(sys.argv[1]))['packages'] if p['name'] == sys.argv[2]][0])" "$TMP/metadata.json" "$TARGET")
TARGET_SUM=$(awk -v f="$TARGET-$TARGET_VERSION.crate" '$2 == f { print $1 }' "$TMP/SHA256SUMS")
OTHER_SUM=$(printf 'other' | python3 -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())")

mkdir -p "$TMP/bin"
cat >"$TMP/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -u
echo "cargo $*" >>"$STUB_STATE/cargo.log"
case "${1:-}" in
  metadata)
    cat "$STUB_METADATA"
    ;;
  publish)
    name=""
    prev=""
    for arg in "$@"; do
      [ "$prev" = "-p" ] && name=$arg
      prev=$arg
    done
    case " $* " in
      *" --no-verify "*) ;;
      *) echo "stub cargo: publish without --no-verify" >&2; exit 98 ;;
    esac
    behavior=success
    if [ "$name" = "$STUB_TARGET" ]; then
      count=$(cat "$STUB_STATE/publish.count" 2>/dev/null || echo 0)
      count=$((count + 1))
      echo "$count" >"$STUB_STATE/publish.count"
      line=$(sed -n "${count}p" "$STUB_STATE/publish.seq")
      [ -n "$line" ] && behavior=$line
    fi
    case "$behavior" in
      success) echo "   Uploading $name"; exit 0 ;;
      exists) echo "error: failed to publish $name to registry at https://crates.io"; echo "crate version is already uploaded"; exit 101 ;;
      ratelimit) echo "error: the remote server responded with an error (status 429 Too Many Requests)"; exit 101 ;;
      fail) echo "error: some other failure"; exit 101 ;;
    esac
    ;;
  *)
    echo "stub cargo: unexpected call: $*" >&2
    exit 99
    ;;
esac
STUB
cat >"$TMP/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -u
out=""
agent=""
prev=""
url=""
for arg in "$@"; do
  [ "$prev" = "--output" ] && out=$arg
  [ "$prev" = "--user-agent" ] && agent=$arg
  prev=$arg
  url=$arg
done
echo "curl $url" >>"$STUB_STATE/curl.log"
if [ "$agent" != "$STUB_USER_AGENT" ]; then
  printf '{"errors":[{"detail":"user agent"}]}' >"$out"
  printf '403'
  exit 0
fi
path=${url#https://crates.io/api/v1/crates/}
name=${path%%/*}
version=${path#*/}
if [ "$name" = "$STUB_TARGET" ]; then
  count=$(cat "$STUB_STATE/curl.count" 2>/dev/null || echo 0)
  count=$((count + 1))
  echo "$count" >"$STUB_STATE/curl.count"
  line=$(sed -n "${count}p" "$STUB_STATE/curl.seq")
  [ -n "$line" ] || line=404
else
  line="200 $(awk -v f="$name-$version.crate" '$2 == f { print $1 }' "$STUB_SUMS")"
fi
code=${line%% *}
if [ "$code" = 200 ]; then
  printf '{"version":{"num":"%s","checksum":"%s"}}' "$version" "${line#* }" >"$out"
else
  printf '{"errors":[{"detail":"stub"}]}' >"$out"
fi
printf '%s' "$code"
STUB
cat >"$TMP/bin/sleep" <<'STUB'
#!/usr/bin/env bash
echo "sleep $*" >>"$STUB_STATE/sleep.log"
STUB
chmod +x "$TMP/bin/cargo" "$TMP/bin/curl" "$TMP/bin/sleep"

failures=0
fail() {
  echo "FAIL $1: $2" >&2
  failures=$((failures + 1))
}
# Prints "ok" for <label> when no failure was recorded since <count>.
report() {
  [ "$failures" -eq "$2" ] && echo "ok   $1"
  return 0
}

# run_case <label> <expected exit> <publish sequence> <curl sequence> [sums file]
run_case() {
  local label=$1 want=$2 publish_seq=$3 curl_seq=$4 sums=${5:-$TMP/SHA256SUMS}
  STATE="$TMP/state-$(printf '%s' "$label" | tr -c 'A-Za-z0-9' '_')"
  mkdir -p "$STATE"
  printf '%b' "$publish_seq" >"$STATE/publish.seq"
  printf '%b' "$curl_seq" >"$STATE/curl.seq"
  : >"$STATE/cargo.log"
  : >"$STATE/curl.log"
  : >"$STATE/sleep.log"
  set +e
  OUT=$(cd "$ROOT" && PATH="$TMP/bin:$PATH" STUB_STATE="$STATE" STUB_TARGET="$TARGET" \
    STUB_METADATA="$TMP/metadata.json" STUB_SUMS="$TMP/SHA256SUMS" STUB_USER_AGENT="$USER_AGENT" \
    CARGO_REGISTRY_TOKEN=stub bash "$SCRIPT" --sums "$sums" 2>&1)
  RC=$?
  set -e
  if [ "$RC" -ne "$want" ]; then
    fail "$label" "exit $RC, expected $want; output tail: $(tail -5 <<<"$OUT")"
    return 1
  fi
  return 0
}

expect_output() {
  grep -qF -- "$2" <<<"$OUT" || fail "$1" "output lacks '$2'"
}
expect_no_publish_of() {
  if grep -q "publish -p $2 " "$STATE/cargo.log"; then
    fail "$1" "$2 was published after the halt"
  fi
}
count_lines() {
  grep -c -- "$2" "$1" || true
}

label="upload with a matching checksum"
before=$failures
if run_case "$label" 0 "success\n" "200 $TARGET_SUM\n"; then
  expect_output "$label" "VERIFIED $TARGET $TARGET_VERSION sha256 $TARGET_SUM"
  expect_output "$label" "All crates published."
  report "$label" "$before"
fi

label="upload with a different checksum"
before=$failures
if run_case "$label" 1 "success\n" "200 $OTHER_SUM\n"; then
  expect_output "$label" "crates.io $OTHER_SUM, SHA256SUMS $TARGET_SUM"
  expect_output "$label" "HALT in tier 1 at $TARGET"
  expect_no_publish_of "$label" "$LATER"
  report "$label" "$before"
fi

label="upload missing on the first read, matching on the second"
before=$failures
if run_case "$label" 0 "success\n" "404\n200 $TARGET_SUM\n"; then
  [ "$(count_lines "$STATE/sleep.log" 'sleep 30')" -eq 1 ] || fail "$label" "expected one 30 s wait"
  expect_output "$label" "VERIFIED $TARGET"
  report "$label" "$before"
fi

label="upload missing until the bound"
before=$failures
if run_case "$label" 1 "success\n" ""; then
  [ "$(count_lines "$STATE/sleep.log" 'sleep 30')" -eq 20 ] || fail "$label" "expected 20 waits of 30 s"
  [ "$(count_lines "$STATE/curl.log" "/$TARGET/")" -eq 21 ] || fail "$label" "expected 21 reads"
  expect_output "$label" "UNVERIFIED $TARGET $TARGET_VERSION: no published checksum after 600s"
  expect_no_publish_of "$label" "$LATER"
  report "$label" "$before"
fi

label="upload with an unreadable answer, then matching"
before=$failures
if run_case "$label" 0 "success\n" "500\n200 $TARGET_SUM\n"; then
  expect_output "$label" "HTTP 500"
  expect_output "$label" "VERIFIED $TARGET"
  report "$label" "$before"
fi

label="already uploaded with a matching checksum"
before=$failures
if run_case "$label" 0 "exists\n" "200 $TARGET_SUM\n"; then
  expect_output "$label" "ALREADY UPLOADED $TARGET"
  expect_output "$label" "VERIFIED $TARGET"
  report "$label" "$before"
fi

label="already uploaded with a different checksum"
before=$failures
if run_case "$label" 1 "exists\n" "200 $OTHER_SUM\n"; then
  expect_output "$label" "crates.io $OTHER_SUM, SHA256SUMS $TARGET_SUM"
  expect_no_publish_of "$label" "$LATER"
  report "$label" "$before"
fi

label="already uploaded with a missing checksum"
before=$failures
if run_case "$label" 1 "exists\n" "404\n200 $TARGET_SUM\n"; then
  expect_output "$label" "MISSING $TARGET $TARGET_VERSION"
  [ "$(count_lines "$STATE/sleep.log" 'sleep 30')" -eq 0 ] || fail "$label" "waited before refusing"
  expect_no_publish_of "$label" "$LATER"
  report "$label" "$before"
fi

label="already uploaded with an unreadable answer, then matching"
before=$failures
if run_case "$label" 0 "exists\n" "500\n200 $TARGET_SUM\n"; then
  expect_output "$label" "VERIFIED $TARGET"
  report "$label" "$before"
fi

label="rate limited, then uploaded"
before=$failures
if run_case "$label" 0 "ratelimit\nsuccess\n" "200 $TARGET_SUM\n"; then
  [ "$(count_lines "$STATE/sleep.log" 'sleep 620')" -eq 1 ] || fail "$label" "expected one 620 s wait"
  expect_output "$label" "UPLOADED $TARGET (attempt 2)"
  report "$label" "$before"
fi

label="other publish failure"
before=$failures
if run_case "$label" 1 "fail\n" ""; then
  expect_output "$label" "FAIL $TARGET rc=101"
  [ "$(count_lines "$STATE/curl.log" "/$TARGET/")" -eq 0 ] || fail "$label" "read a checksum after a failed upload"
  report "$label" "$before"
fi

label="sums file without an entry for one crate"
grep -v " $TARGET-$TARGET_VERSION.crate\$" "$TMP/SHA256SUMS" >"$TMP/SHA256SUMS.missing"
before=$failures
if run_case "$label" 2 "" "" "$TMP/SHA256SUMS.missing"; then
  expect_output "$label" "SHA256SUMS has no single valid entry for $TARGET-$TARGET_VERSION.crate"
  [ "$(count_lines "$STATE/cargo.log" 'publish')" -eq 0 ] || fail "$label" "published before refusing"
  report "$label" "$before"
fi

label="sums file with a duplicate entry"
{ cat "$TMP/SHA256SUMS"; grep " $TARGET-$TARGET_VERSION.crate\$" "$TMP/SHA256SUMS"; } >"$TMP/SHA256SUMS.dup"
before=$failures
if run_case "$label" 2 "" "" "$TMP/SHA256SUMS.dup"; then
  [ "$(count_lines "$STATE/cargo.log" 'publish')" -eq 0 ] || fail "$label" "published before refusing"
  report "$label" "$before"
fi

label="sums file absent"
before=$failures
if run_case "$label" 2 "" "" "$TMP/absent"; then
  expect_output "$label" "SHA256SUMS file not readable"
  report "$label" "$before"
fi

label="every cargo publish call carries --no-verify and --locked"
before=$failures
if run_case "$label" 0 "" "200 $TARGET_SUM\n"; then
  calls=$(count_lines "$STATE/cargo.log" '^cargo publish ')
  flagged=$(grep '^cargo publish ' "$STATE/cargo.log" | grep -c -- ' --locked --no-verify' || true)
  members=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['packages']))" "$TMP/metadata.json")
  [ "$calls" -eq "$members" ] || fail "$label" "$calls publish calls for $members members"
  [ "$calls" -eq "$flagged" ] || fail "$label" "$((calls - flagged)) publish call(s) without --locked --no-verify"
  report "$label" "$before"
fi

label="every cargo publish in the script source carries --no-verify"
# One shell command per line: the scan cuts off comments and splits lines at
# ;, &, |, and ), so it checks each cargo publish call on its own.
commands=$(sed -E 's/(^|[[:space:]])#.*$//' "$SCRIPT" | tr ';&|)' '[\n*]')
calls=$(grep -E '(^|[^[:alnum:]_-])cargo[[:space:]]+publish' <<<"$commands" || true)
unflagged=$(grep -v -- '--no-verify' <<<"$calls" || true)
total=$(grep -c . <<<"$calls" || true)
if [ -n "$unflagged" ]; then
  fail "$label" "$unflagged"
elif [ "$total" -lt 1 ]; then
  fail "$label" "no cargo publish call found in the script"
else
  echo "ok   $label"
fi

label="no registry token"
set +e
OUT=$(cd "$ROOT" && PATH="$TMP/bin:$PATH" STUB_STATE="$TMP" STUB_TARGET="$TARGET" \
  STUB_METADATA="$TMP/metadata.json" STUB_SUMS="$TMP/SHA256SUMS" \
  env -u CARGO_REGISTRY_TOKEN bash "$SCRIPT" --sums "$TMP/SHA256SUMS" 2>&1)
RC=$?
set -e
if [ "$RC" -eq 2 ] && grep -q "CARGO_REGISTRY_TOKEN is not set" <<<"$OUT"; then
  echo "ok   $label"
else
  fail "$label" "exit $RC: $OUT"
fi

for args in "" "--sums" "--publish" "--check extra" "--sums a b"; do
  label="usage error for '$args'"
  set +e
  # shellcheck disable=SC2086
  OUT=$(cd "$ROOT" && bash "$SCRIPT" $args 2>&1)
  RC=$?
  set -e
  if [ "$RC" -eq 2 ] && grep -q "usage:" <<<"$OUT"; then
    echo "ok   $label"
  else
    fail "$label" "exit $RC: $OUT"
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "$failures publish-crates verify case(s) failed" >&2
  exit 1
fi
echo "publish-crates verify tests passed"

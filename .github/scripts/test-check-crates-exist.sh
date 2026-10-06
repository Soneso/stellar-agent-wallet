#!/usr/bin/env bash
# Offline regression checks for check-crates-exist.sh.
#
# Stubs for cargo, curl, and sleep come first on PATH and drive the real
# script. The stub cargo accepts only the call
# "metadata --format-version 1 --no-deps --offline --frozen" and prints the
# metadata document of the case, or fails when the case has none. The stub
# curl answers HTTP 403 to a request without the expected User-Agent, which
# names only this repository and its URL. Otherwise it answers per crate name
# from the answers file of the case: an HTTP status, or exit:<n>[:<status>]
# for a curl failure with exit code n that prints <status>, 000 when absent.
# It logs each requested URL. The stub sleep only records its argument. The
# cases cover named crates and the workspace list, the default mode and the
# --warn mode, and the usage and metadata errors.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/check-crates-exist.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

API=https://crates.io/api/v1/crates
USER_AGENT="stellar-agent-wallet (https://github.com/Soneso/stellar-agent-wallet)"

mkdir -p "$TMP/bin"
cat >"$TMP/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -u
echo "cargo $*" >>"$STUB_STATE/cargo.log"
if [ "$*" != "metadata --format-version 1 --no-deps --offline --frozen" ]; then
  echo "stub cargo: unexpected call: $*" >&2
  exit 99
fi
if [ ! -f "$STUB_STATE/metadata" ]; then
  echo "error: stub cargo metadata failure" >&2
  exit 101
fi
cat "$STUB_STATE/metadata"
STUB
cat >"$TMP/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -u
agent=""
format=""
prev=""
url=""
for arg in "$@"; do
  [ "$prev" = "--user-agent" ] && agent=$arg
  [ "$prev" = "--write-out" ] && format=$arg
  prev=$arg
  url=$arg
done
echo "$url" >>"$STUB_STATE/curl.log"
if [ "$format" != '%{http_code}' ]; then
  echo "stub curl: unexpected --write-out '$format'" >&2
  exit 99
fi
if [ "$agent" != "$STUB_USER_AGENT" ]; then
  printf '403'
  exit 0
fi
name=${url#https://crates.io/api/v1/crates/}
answer=$(awk -v n="$name" '$1 == n { print $2; exit }' "$STUB_STATE/answers")
case "$answer" in
  exit:*)
    spec=${answer#exit:}
    code=${spec%%:*}
    printed=000
    if [ "$spec" != "$code" ]; then
      printed=${spec#*:}
    fi
    echo "curl: ($code) stub failure" >&2
    printf '%s' "$printed"
    exit "$code"
    ;;
  "")
    echo "stub curl: no answer for $name" >&2
    exit 98
    ;;
  *)
    printf '%s' "$answer"
    ;;
esac
STUB
cat >"$TMP/bin/sleep" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$STUB_STATE/sleep.log"
STUB
chmod +x "$TMP/bin/cargo" "$TMP/bin/curl" "$TMP/bin/sleep"

failures=0
fail() {
  echo "FAIL $1: $2" >&2
  failures=$((failures + 1))
}

# prepare_case <label> <answers>
# Sets STATE to a new directory for the case and writes <answers> there, one
# "<name> <answer>" line per crate, as printf %b reads it. The cargo, URL, and
# sleep logs start empty, and the case has no metadata document.
prepare_case() {
  STATE="$TMP/state-$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"
  mkdir -p "$STATE"
  printf '%b' "$2" >"$STATE/answers"
  : >"$STATE/cargo.log"
  : >"$STATE/curl.log"
  : >"$STATE/sleep.log"
}

# invoke <argument>...
# Runs the script with the stubs first on PATH. Sets RC and leaves stdout and
# stderr in STATE.
invoke() {
  set +e
  PATH="$TMP/bin:$PATH" STUB_STATE="$STATE" STUB_USER_AGENT="$USER_AGENT" \
    bash "$SCRIPT" "$@" >"$STATE/stdout" 2>"$STATE/stderr"
  RC=$?
  set -e
}

# run_case <label> <answers> <argument>...
# Runs a case whose stub cargo fails on any call.
run_case() {
  prepare_case "$1" "$2"
  shift 2
  invoke "$@"
}

# run_metadata_case <label> <answers> <metadata file> <argument>...
# Runs a case whose stub cargo prints <metadata file>.
run_metadata_case() {
  prepare_case "$1" "$2"
  cp "$3" "$STATE/metadata"
  shift 3
  invoke "$@"
}

# expect <label> <exit code> <stream> <line>...
# Fails unless the case exited with <exit code> and <stream> (stdout or
# stderr) holds each <line> as a whole line.
expect() {
  local label=$1 want=$2 stream=$3 line
  shift 3
  if [ "$RC" -ne "$want" ]; then
    fail "$label" "exit $RC, expected $want; stderr: $(cat "$STATE/stderr")"
    return 0
  fi
  for line in "$@"; do
    if ! grep -qxF -- "$line" "$STATE/$stream"; then
      fail "$label" "$stream lacks the line '$line': $(cat "$STATE/$stream")"
    fi
  done
}

# expect_file <label> <file> <content>
# Fails unless the bytes of the case file equal <content> and one newline, or
# the file is empty when <content> is empty.
expect_file() {
  local expected="$STATE/expected-$2"
  if [ -n "$3" ]; then
    printf '%s\n' "$3" >"$expected"
  else
    : >"$expected"
  fi
  if ! cmp -s "$expected" "$STATE/$2"; then
    fail "$1" "$2 holds '$(cat "$STATE/$2")', expected '$3'"
  fi
}

# report <label> <count>
# Prints "ok" for <label> when the failure count still equals <count>.
report() {
  [ "$failures" -eq "$2" ] && echo "ok   $1"
  return 0
}

# expect_warnings <label> <count>: stdout holds <count> annotation lines.
expect_warnings() {
  local count
  count=$(grep -c '^::warning::' "$STATE/stdout" || true)
  if [ "$count" -ne "$2" ]; then
    fail "$1" "stdout holds $count warning annotation(s), expected $2: $(cat "$STATE/stdout")"
  fi
}

# expect_usage_error <label>: the case exited 2 with the usage line and sent
# no request.
expect_usage_error() {
  if [ "$RC" -ne 2 ]; then
    fail "$1" "exit $RC, expected 2; stderr: $(cat "$STATE/stderr")"
  fi
  if ! grep -q '^usage:' "$STATE/stderr"; then
    fail "$1" "stderr lacks the usage line"
  fi
  expect_file "$1" curl.log ""
}

MISSING_HINT='the publish run halts at this crate until a maintainer uploads it once by hand, see docs/maintainers/releasing.md, section "Publish a new crate for the first time"'

label="every crate exists"
before=$failures
run_case "$label" "alpha 200\nbeta 200\ngamma 200\n" alpha beta gamma
expect "$label" 0 stdout "alpha: exists" "beta: exists" "gamma: exists" "3 crates exist on crates.io"
expect_file "$label" stdout "$(printf 'alpha: exists\nbeta: exists\ngamma: exists\n3 crates exist on crates.io')"
expect_file "$label" stderr ""
expect_file "$label" curl.log "$(printf '%s\n' "$API/alpha" "$API/beta" "$API/gamma")"
expect_file "$label" sleep.log "$(printf '1\n1')"
report "$label" "$before"

label="one crate exists"
before=$failures
run_case "$label" "alpha 200\n" alpha
expect "$label" 0 stdout "alpha: exists" "1 crate exists on crates.io"
expect_file "$label" sleep.log ""
report "$label" "$before"

label="one crate missing"
before=$failures
run_case "$label" "alpha 200\nbeta 404\ngamma 200\n" alpha beta gamma
expect "$label" 1 stderr "beta: missing" "1 crate(s) missing on crates.io: beta"
expect_file "$label" stdout "$(printf 'alpha: exists\ngamma: exists')"
expect_file "$label" stderr "$(printf 'beta: missing\n1 crate(s) missing on crates.io: beta')"
expect_file "$label" curl.log "$(printf '%s\n' "$API/alpha" "$API/beta" "$API/gamma")"
expect_file "$label" sleep.log "$(printf '1\n1')"
report "$label" "$before"

label="crates.io answers 503"
before=$failures
run_case "$label" "alpha 503\nbeta 200\n" alpha beta
expect "$label" 1 stderr "alpha: crates.io answered 503" "1 crate(s) not confirmed on crates.io: alpha"
expect_file "$label" stdout "beta: exists"
expect_file "$label" stderr "$(printf 'alpha: crates.io answered 503\n1 crate(s) not confirmed on crates.io: alpha')"
report "$label" "$before"

label="curl fails with exit code 6"
before=$failures
run_case "$label" "alpha exit:6\nbeta 200\n" alpha beta
expect "$label" 1 stderr "alpha: crates.io answered no status (curl exit 6)" \
  "1 crate(s) not confirmed on crates.io: alpha"
expect_file "$label" stdout "beta: exists"
expect_file "$label" stderr "$(printf 'curl: (6) stub failure\nalpha: crates.io answered no status (curl exit 6)\n1 crate(s) not confirmed on crates.io: alpha')"
report "$label" "$before"

for status in 201 204 403 429; do
  label="crates.io answers $status"
  before=$failures
  run_case "$label" "alpha $status\nbeta 200\n" alpha beta
  expect "$label" 1 stderr "alpha: crates.io answered $status" \
    "1 crate(s) not confirmed on crates.io: alpha"
  expect_file "$label" stdout "beta: exists"
  report "$label" "$before"

  label="--warn with crates.io answering $status"
  before=$failures
  run_case "$label" "alpha $status\nbeta 200\n" --warn alpha beta
  expect "$label" 0 stdout "::warning::alpha: crates.io answered $status, existence not confirmed" \
    "beta: exists"
  expect "$label" 0 stderr "1 crate(s) not confirmed on crates.io: alpha"
  expect_warnings "$label" 1
  report "$label" "$before"
done

label="curl fails with exit code 28 after printing 200"
before=$failures
run_case "$label" "alpha exit:28:200\n" alpha
expect "$label" 1 stderr "alpha: crates.io answered no status (curl exit 28)" \
  "1 crate(s) not confirmed on crates.io: alpha"
expect_file "$label" stdout ""
report "$label" "$before"

label="--warn with curl failing with exit code 28 after printing 200"
before=$failures
run_case "$label" "alpha exit:28:200\n" --warn alpha
expect_file "$label" stdout "::warning::alpha: crates.io answered no status (curl exit 28), existence not confirmed"
expect "$label" 0 stderr "1 crate(s) not confirmed on crates.io: alpha"
report "$label" "$before"

label="missing and unconfirmed crates"
before=$failures
run_case "$label" "alpha 404\nbeta 404\ngamma 500\ndelta 200\n" alpha beta gamma delta
expect "$label" 1 stderr "2 crate(s) missing on crates.io: alpha beta" \
  "1 crate(s) not confirmed on crates.io: gamma"
expect_file "$label" stdout "delta: exists"
expect_file "$label" stderr "$(printf '%s\n' "alpha: missing" "beta: missing" "gamma: crates.io answered 500" \
  "2 crate(s) missing on crates.io: alpha beta" "1 crate(s) not confirmed on crates.io: gamma")"
report "$label" "$before"

label="--warn with every crate present"
before=$failures
run_case "$label" "alpha 200\nbeta 200\n" --warn alpha beta
expect "$label" 0 stdout "2 crates exist on crates.io"
expect_file "$label" stdout "$(printf 'alpha: exists\nbeta: exists\n2 crates exist on crates.io')"
expect_file "$label" stderr ""
expect_file "$label" curl.log "$(printf '%s\n' "$API/alpha" "$API/beta")"
expect_warnings "$label" 0
report "$label" "$before"

label="--warn with one crate missing"
before=$failures
run_case "$label" "alpha 200\nbeta 404\n" --warn alpha beta
expect "$label" 0 stdout "alpha: exists" "::warning::beta is missing on crates.io; $MISSING_HINT"
expect_file "$label" stdout "$(printf '%s\n' "alpha: exists" "::warning::beta is missing on crates.io; $MISSING_HINT")"
expect_file "$label" stderr "$(printf 'beta: missing\n1 crate(s) missing on crates.io: beta')"
expect_warnings "$label" 1
report "$label" "$before"

label="--warn with crates.io answering 503"
before=$failures
run_case "$label" "alpha 503\nbeta 200\n" --warn alpha beta
expect "$label" 0 stdout "::warning::alpha: crates.io answered 503, existence not confirmed" "beta: exists"
expect "$label" 0 stderr "1 crate(s) not confirmed on crates.io: alpha"
expect_warnings "$label" 1
report "$label" "$before"

label="--warn with curl failing with exit code 6"
before=$failures
run_case "$label" "alpha exit:6\n" --warn alpha
expect "$label" 0 stdout "::warning::alpha: crates.io answered no status (curl exit 6), existence not confirmed"
expect "$label" 0 stderr "1 crate(s) not confirmed on crates.io: alpha"
expect_warnings "$label" 1
report "$label" "$before"

label="--warn with missing and unconfirmed crates"
before=$failures
run_case "$label" "alpha 404\nbeta 500\ngamma 200\n" --warn alpha beta gamma
expect "$label" 0 stdout "::warning::alpha is missing on crates.io; $MISSING_HINT" \
  "::warning::beta: crates.io answered 500, existence not confirmed" "gamma: exists"
expect "$label" 0 stderr "1 crate(s) missing on crates.io: alpha" "1 crate(s) not confirmed on crates.io: beta"
expect_warnings "$label" 2
report "$label" "$before"

for name in "bad/name" "" "crate?x=1" "two words"; do
  label="bad name '$name'"
  before=$failures
  run_case "$label" "alpha 200\n" alpha "$name"
  expect_usage_error "$label"
  expect "$label" 2 stderr "not a crate name: '$name'"
  report "$label" "$before"
done

# The workspace list: members with publish null, publish = false (an empty
# list), and a registry list, and a package with a source. Their names are out
# of order, so the URL log pins the sort.
cat >"$TMP/metadata-mixed.json" <<'JSON'
{"packages": [
  {"name": "zeta", "source": null, "publish": null},
  {"name": "private", "source": null, "publish": []},
  {"name": "alpha", "source": null, "publish": null},
  {"name": "vendored", "source": "registry+https://github.com/rust-lang/crates.io-index", "publish": null},
  {"name": "mirror", "source": null, "publish": ["crates-io"]}
], "version": 1}
JSON
cat >"$TMP/metadata-none.json" <<'JSON'
{"packages": [
  {"name": "private", "source": null, "publish": []},
  {"name": "vendored", "source": "registry+https://github.com/rust-lang/crates.io-index", "publish": null}
], "version": 1}
JSON
printf 'not json\n' >"$TMP/metadata-text"
printf '{}\n' >"$TMP/metadata-no-packages.json"
ALL_200="alpha 200\nmirror 200\nzeta 200\nprivate 200\nvendored 200\n"
METADATA_CALL="cargo metadata --format-version 1 --no-deps --offline --frozen"

label="workspace list"
before=$failures
run_metadata_case "$label" "$ALL_200" "$TMP/metadata-mixed.json"
expect "$label" 0 stdout "3 crates exist on crates.io"
expect_file "$label" stdout "$(printf '%s\n' "alpha: exists" "mirror: exists" "zeta: exists" "3 crates exist on crates.io")"
expect_file "$label" curl.log "$(printf '%s\n' "$API/alpha" "$API/mirror" "$API/zeta")"
expect_file "$label" sleep.log "$(printf '1\n1')"
expect_file "$label" stderr ""
expect_file "$label" cargo.log "$METADATA_CALL"
report "$label" "$before"

label="workspace list with --warn and a missing member"
before=$failures
run_metadata_case "$label" "alpha 200\nmirror 404\nzeta 200\n" "$TMP/metadata-mixed.json" --warn
expect "$label" 0 stdout "::warning::mirror is missing on crates.io; $MISSING_HINT"
expect_file "$label" curl.log "$(printf '%s\n' "$API/alpha" "$API/mirror" "$API/zeta")"
expect_file "$label" sleep.log "$(printf '1\n1')"
expect_warnings "$label" 1
report "$label" "$before"

label="named crates skip cargo metadata"
before=$failures
run_metadata_case "$label" "alpha 200\n" "$TMP/metadata-mixed.json" alpha
expect "$label" 0 stdout "1 crate exists on crates.io"
expect_file "$label" cargo.log ""
report "$label" "$before"

label="cargo metadata fails"
before=$failures
run_case "$label" "$ALL_200" --warn
expect "$label" 2 stderr "cargo metadata failed"
expect_file "$label" cargo.log "$METADATA_CALL"
expect_file "$label" curl.log ""
report "$label" "$before"

label="metadata that is not JSON"
before=$failures
run_metadata_case "$label" "$ALL_200" "$TMP/metadata-text" --warn
expect "$label" 2 stderr "cannot read the workspace members from cargo metadata"
expect_file "$label" curl.log ""
report "$label" "$before"

label="metadata without a packages list"
before=$failures
run_metadata_case "$label" "$ALL_200" "$TMP/metadata-no-packages.json" --warn
expect "$label" 2 stderr "cannot read the workspace members from cargo metadata"
expect_file "$label" curl.log ""
report "$label" "$before"

label="no publishable member"
before=$failures
run_metadata_case "$label" "$ALL_200" "$TMP/metadata-none.json" --warn
expect "$label" 2 stderr "cargo metadata lists no publishable workspace member"
expect_file "$label" curl.log ""
report "$label" "$before"

label="bad name with --warn"
before=$failures
run_case "$label" "alpha 200\n" --warn alpha "bad/name"
expect_usage_error "$label"
expect "$label" 2 stderr "not a crate name: 'bad/name'"
report "$label" "$before"

label="unknown option --x"
before=$failures
run_case "$label" "alpha 200\n" --x alpha
expect_usage_error "$label"
expect "$label" 2 stderr "unknown option or misplaced --warn: '--x'"
report "$label" "$before"

label="unknown option -x"
before=$failures
run_case "$label" "alpha 200\n" alpha -x
expect_usage_error "$label"
expect "$label" 2 stderr "unknown option or misplaced --warn: '-x'"
report "$label" "$before"

label="--warn after a crate name"
before=$failures
run_case "$label" "alpha 200\n" alpha --warn
expect_usage_error "$label"
expect "$label" 2 stderr "unknown option or misplaced --warn: '--warn'"
report "$label" "$before"

label="--warn twice"
before=$failures
run_case "$label" "alpha 200\n" --warn --warn alpha
expect_usage_error "$label"
report "$label" "$before"

if [ "$failures" -ne 0 ]; then
  echo "$failures check-crates-exist case(s) failed" >&2
  exit 1
fi
echo "check-crates-exist tests passed"

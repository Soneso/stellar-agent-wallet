#!/usr/bin/env bash
# Rebuilds the vendored contract Wasm files of stellar-agent-smart-account from
# their pinned sources with pinned tools, and checks the tree that pins them.
#
# Invariant: every vendored Wasm file that the wallet uploads or recognizes is
# a manifest row below or an exception. Full mode rebuilds each manifest row
# and fails unless the rebuilt bytes equal the vendored file. Both modes fail
# unless each vendored file equals its record and, where one exists, its
# build.rs WASM_PINS row. An exception is held at a frozen digest. A tracked
# Wasm file outside the manifest, the exceptions, and the out-of-scope list
# fails the tree check.
#
# Modes:
#   --check-tree --repo-root <dir>
#       The offline tree checks only (git and coreutils).
#   --repo-root <dir> --oz-clone <dir> --stellar-25 <binary>
#   --stellar-28 <binary> --work <dir>
#       Full mode. The environment refusals and the preconditions stop the run
#       before any build. A tree check failure does not: every row is built
#       and reported, and the exit code is non-zero.
#   --list-toolchains
#       Each distinct "toolchain target" pair of the manifest, one per line.
#   --rebuild-needed --repo-root <dir> --event <name> --base <rev> --head <rev>
#       Prints true or false: whether the change can affect a rebuild.
#   --gate <check-result> <rebuild> <cli-25-result> <cli-28-result> <rebuild-result>
#       Exits 0 only for a passing combination of the workflow's job results.
#   --exec --dir <dir> -- <command...>
#       Applies the environment refusals for <dir>, then runs the command in
#       <dir> under the build environment allowlist. Full mode builds and every
#       vendor/*/build.sh use this one code path.
#
# Exit codes: 0 when every check passed, 1 when a check failed, 2 for a usage
# error, a refusal, or a failed precondition. The script installs nothing and
# writes nothing under --repo-root. It runs under bash 3.2 with BSD or GNU
# tools. No environment variable or argument overrides the manifest, the
# exceptions, or the pinned versions below.
set -euo pipefail

NAME="rebuild-vendored-wasm"
CRATE="crates/stellar-agent-smart-account"

# One row per rebuildable file, with fields separated by spaces. The fields
# are the vendored path (relative to the crate), the source (oz:<tag> or
# tree:<repository path>), the package ("-" builds the source's only package),
# the toolchain, the target, and the builder. The last two fields are the output
# (relative to <target dir>/<target>/) and pin or nopin, which says whether
# build.rs carries a WASM_PINS row for the file.
MANIFEST="\
vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm oz:v0.7.2 stellar-accounts 1.96.0 wasm32v1-none s25 release/deps/stellar_accounts.wasm pin
vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm oz:v0.7.2 multisig-account-example 1.96.0 wasm32v1-none s25 release/multisig_account_example.wasm pin
vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm oz:v0.7.2 multisig-webauthn-verifier-example 1.96.0 wasm32v1-none s25 release/multisig_webauthn_verifier_example.wasm pin
vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm oz:v0.7.2 timelock-controller-example 1.96.0 wasm32v1-none s25 release/timelock_controller_example.wasm pin
vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm oz:v0.7.2 multisig-threshold-policy-example 1.96.0 wasm32v1-none s25 release/multisig_threshold_policy_example.wasm pin
vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm oz:v0.7.2 multisig-ed25519-verifier-example 1.96.0 wasm32v1-none s25 release/multisig_ed25519_verifier_example.wasm pin
vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm oz:v0.7.2 multisig-spending-limit-policy-example 1.96.0 wasm32v1-none s25 release/multisig_spending_limit_policy_example.wasm pin
vendor/oz-weighted-threshold-policy/v0.7.2/multisig_weighted_threshold_policy_example.wasm oz:v0.7.2 multisig-weighted-threshold-policy-example 1.96.0 wasm32v1-none s25 release/multisig_weighted_threshold_policy_example.wasm pin
vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm oz:v0.7.1 stellar-accounts 1.94.0 wasm32v1-none s25 release/deps/stellar_accounts.wasm nopin
vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm oz:v0.7.1 multisig-account-example 1.94.0 wasm32v1-none s25 release/multisig_account_example.wasm nopin
vendor/oz-webauthn-verifier/v0.7.1/multisig_webauthn_verifier_example.wasm oz:v0.7.1 multisig-webauthn-verifier-example 1.94.0 wasm32v1-none s25 release/multisig_webauthn_verifier_example.wasm nopin
vendor/oz-timelock-controller/v0.7.1/timelock_controller_example.wasm oz:v0.7.1 timelock-controller-example 1.94.0 wasm32v1-none s25 release/timelock_controller_example.wasm nopin
vendor/oz-threshold-policy/v0.7.1/multisig_threshold_policy_example.wasm oz:v0.7.1 multisig-threshold-policy-example 1.94.0 wasm32v1-none s25 release/multisig_threshold_policy_example.wasm nopin
vendor/cap85-beacon/v0.1.0/cap85_beacon.wasm tree:contracts/cap85-beacon - 1.98.0 wasm32v1-none s28 release/cap85_beacon.wasm pin"

# Vendored files that are not rebuilt: path (relative to the crate), frozen
# digest, and pin or nopin. The multicall router's source is not in the
# repository, so its bytes stay at one digest until that source is committed.
EXCEPTIONS="\
vendor/multicall/v0.1.0/multicall.wasm 267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4 pin"

# Tracked Wasm files that the wallet neither deploys nor recognizes
# (repository-relative).
OUT_OF_SCOPE="\
crates/stellar-agent-sep48/tests/fixtures/sep41_token.wasm"

# Each OpenZeppelin stellar-contracts tag with the commit it must resolve to.
OZ_TAGS="\
v0.7.2 a9c42169000638da937577f592ebf61a7a3c94ca
v0.7.1 3f81125bed3114cc93f5fca6d13240082050269a"

# Each builder with the first line its --version must print. s25 is built
# from a git archive of stellar-cli tag v25.2.0 outside any git work tree, so
# it carries no revision. s28 is the crates.io package of stellar-cli 28.1.0.
BUILDERS="\
s25|stellar 25.2.0
s28|stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)"

# Each toolchain with the full string its rustc --version must print.
TOOLCHAINS="\
1.94.0|rustc 1.94.0 (4a4ef493e 2026-03-02)
1.96.0|rustc 1.96.0 (ac68faa20 2026-05-25)
1.98.0|rustc 1.98.0 (88d9e12ae 2026-08-18)"

# Repository paths whose change can change a rebuild or its verdict.
REBUILD_PREFIXES="\
crates/stellar-agent-smart-account/vendor/
crates/stellar-agent-smart-account/build.rs
contracts/
.github/scripts/rebuild-vendored-wasm.sh
.github/scripts/test-rebuild-vendored-wasm.sh
.github/workflows/vendored-wasm.yml"

# Each line names a definition that the identity tests bind to a vendored file.
# Fields: file (relative to the crate), name, permitted definition attribute,
# permitted value attribute, and the fixture hash field. Attributes are written
# without whitespace. Watched bytes and digests use direct literal values;
# allowlist hashes use byte-array literals. These lexical rules provide defense
# in depth alongside integration tests of the library without cfg(test).
DEFINITIONS="\
src/bindings.rs|WASM|||
src/bindings.rs|WASM_SHA256|||
src/deployment/deploy.rs|MULTISIG_ACCOUNT_WASM|||
src/deployment/deploy.rs|MULTISIG_ACCOUNT_WASM_SHA256|||
src/webauthn_verifier.rs|WEBAUTHN_VERIFIER_WASM|||
src/webauthn_verifier.rs|WEBAUTHN_VERIFIER_WASM_SHA256|||
src/signers/verifier_identification.rs|VERIFIER_WASM_FIXTURE|cfg(any(test,feature=\"deploy-cli\"))||
src/deployment/deploy_timelock_controller.rs|TIMELOCK_CONTROLLER_WASM|||
src/deployment/deploy_timelock_controller.rs|TIMELOCK_CONTROLLER_WASM_SHA256|||
src/signers/policy_identification.rs|THRESHOLD_POLICY_WASM|||
src/signers/policy_identification.rs|THRESHOLD_POLICY_WASM_HASHES|||
src/ed25519_verifier.rs|ED25519_VERIFIER_WASM|||
src/ed25519_verifier.rs|ED25519_VERIFIER_WASM_SHA256|||
src/spending_limit_policy.rs|SPENDING_LIMIT_POLICY_WASM|||
src/spending_limit_policy.rs|SPENDING_LIMIT_POLICY_WASM_SHA256|||
src/weighted_threshold_policy.rs|WEIGHTED_THRESHOLD_POLICY_WASM|||
src/weighted_threshold_policy.rs|WEIGHTED_THRESHOLD_POLICY_WASM_SHA256|||
src/weighted_threshold_policy.rs|WEIGHTED_THRESHOLD_POLICY_WASM_HASHES|||
src/cap85_beacon.rs|CAP85_BEACON_WASM|||
src/cap85_beacon.rs|CAP85_BEACON_WASM_SHA256|||
src/multicall.rs|MULTICALL_WASM|||
src/multicall.rs|MULTICALL_WASM_SHA256|||
src/verifier_allowlist.rs|VERIFIER_ALLOWLIST||cfg(any(test,feature=\"test-helpers\"))|wasm_hash:[0xee;32]"

# Module declarations on the path to a definition that may carry a cfg
# attribute: file (relative to the crate), module, and the attribute.
MODULE_GATES="\
src/lib.rs|cap85_beacon|cfg(any(test,feature=\"test-helpers\"))"

# Variables that reach builds and rustc --version, each when set. Proxy and
# certificate settings reach only the network, never the compiler.
PASS_VARS="PATH HOME TMPDIR CARGO_HOME RUSTUP_HOME DEVELOPER_DIR SDKROOT \
HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy \
SSL_CERT_FILE SSL_CERT_DIR CARGO_HTTP_CAINFO"

# Variables that change what rustc compiles or which compiler runs.
# stellar-cli skips its registry path remap when RUSTFLAGS,
# CARGO_ENCODED_RUSTFLAGS, or TARGET_<target>_RUSTFLAGS is set. Names such as
# TARGET_wasm32v1-none_RUSTFLAGS are not shell identifiers, so the check reads
# the output of env.
REFUSED_VARS='^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|TARGET_[^=]*_RUSTFLAGS|CARGO_TARGET_[^=]*_RUSTFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_RUSTC[^=]*|CARGO_PROFILE_[^=]*)='

NL='
'
TAB=$(printf '\t')

usage() {
  cat >&2 <<'EOF'
usage:
  rebuild-vendored-wasm.sh --check-tree --repo-root <dir>
  rebuild-vendored-wasm.sh --repo-root <dir> --oz-clone <dir> --stellar-25 <binary> \
      --stellar-28 <binary> --work <dir>
  rebuild-vendored-wasm.sh --list-toolchains
  rebuild-vendored-wasm.sh --rebuild-needed --repo-root <dir> --event <name> --base <rev> --head <rev>
  rebuild-vendored-wasm.sh --gate <check-result> <rebuild> <cli-25-result> <cli-28-result> <rebuild-result>
  rebuild-vendored-wasm.sh --exec --dir <dir> -- <command...>
EOF
  exit 2
}

die() {
  echo "$NAME: $*" >&2
  exit 2
}

sha256_of() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

size_of() {
  wc -c <"$1" | awk '{ print $1 }'
}

# Prints the absolute physical path of the existing directory $1.
abs_dir() {
  (cd "$1" 2>/dev/null && pwd -P) || return 1
}

# Prints the value of key $2 in the "key|value" list $1.
lookup() {
  local key value
  while IFS='|' read -r key value; do
    if [ "$key" = "$2" ]; then
      printf '%s\n' "$value"
      return 0
    fi
  done <<<"$1"
  return 1
}

tag_commit() {
  local tag commit
  while read -r tag commit; do
    if [ "$tag" = "$1" ]; then
      printf '%s\n' "$commit"
      return 0
    fi
  done <<<"$OZ_TAGS"
  return 1
}

# Prints the first line of the standard output of "$@"; returns 1 when the
# command fails.
first_line() {
  local out
  out=$("$@" 2>/dev/null) || return 1
  printf '%s\n' "${out%%"$NL"*}"
}

# Exits 0 when $1 is a line of the newline-separated list $2.
in_list() {
  case "$NL$2$NL" in
    *"$NL$1$NL"*) return 0 ;;
  esac
  return 1
}

# The work directory key of a manifest source: oz-<tag> or
# tree-<path with each / replaced by ->.
source_key() {
  local path
  case "$1" in
    oz:*) printf 'oz-%s\n' "${1#oz:}" ;;
    tree:*)
      path=${1#tree:}
      printf 'tree-%s\n' "${path//\//-}"
      ;;
    *) return 1 ;;
  esac
}

# Effective cargo home of this environment.
cargo_home() {
  if [ -n "${CARGO_HOME:-}" ]; then
    printf '%s\n' "$CARGO_HOME"
  else
    printf '%s\n' "${HOME:-}/.cargo"
  fi
}

# Refuses an environment that changes what the compiler builds. Prints one line
# per reason and returns 1 when any applies.
environment_refusals() {
  local status=0 name home
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    echo "$NAME: refused: the variable $name is set; unset it before a rebuild" >&2
    status=1
  done <<EOF
$(env | awk -v re="$REFUSED_VARS" '$0 ~ re { sub(/=.*/, ""); print }')
EOF
  home=$(cargo_home)
  case "$home" in
    *[[:space:]]*)
      echo "$NAME: refused: the cargo home '$home' contains whitespace, which makes stellar-cli keep local registry paths in the Wasm" >&2
      status=1
      ;;
  esac
  if [ -f "$home/config.toml" ] || [ -f "$home/config" ]; then
    echo "$NAME: refused: a cargo config file exists in the cargo home '$home'; set CARGO_HOME to a directory without one" >&2
    status=1
  fi
  return "$status"
}

# Refuses the build directory $1 when it or a parent directory holds a cargo
# config file, since cargo reads every one of them.
directory_refusals() {
  local dir
  dir=$(abs_dir "$1") || {
    echo "$NAME: refused: the build directory '$1' does not exist" >&2
    return 1
  }
  while :; do
    if [ -f "$dir/.cargo/config.toml" ] || [ -f "$dir/.cargo/config" ]; then
      echo "$NAME: refused: a cargo config file exists in '$dir/.cargo', which cargo reads for the build directory '$1'" >&2
      return 1
    fi
    [ "$dir" = "/" ] && break
    dir=$(dirname "$dir")
  done
  return 0
}

# Runs the command "${@:4}" in directory $1 under env -i with the variables of
# PASS_VARS that are set, RUSTUP_AUTO_INSTALL=0 so that a missing toolchain
# fails, RUSTUP_TOOLCHAIN=$2, and CARGO_TARGET_DIR=$3. An empty $2 or $3
# leaves that variable unset.
run_clean() {
  local dir=$1 toolchain=$2 target_dir=$3 name value
  shift 3
  local env_args=("RUSTUP_AUTO_INSTALL=0")
  for name in $PASS_VARS; do
    if eval "[ \"\${$name+set}\" = set ]"; then
      eval "value=\${$name}"
      env_args+=("$name=$value")
    fi
  done
  if [ -n "$toolchain" ]; then
    env_args+=("RUSTUP_TOOLCHAIN=$toolchain")
  fi
  if [ -n "$target_dir" ]; then
    env_args+=("CARGO_TARGET_DIR=$target_dir")
  fi
  (cd "$dir" && exec env -i "${env_args[@]}" "$@")
}

# ---------------------------------------------------------------------------
# Tree checks
# ---------------------------------------------------------------------------

# Records one tree check failure: check name, path, reason.
tree_fail() {
  printf 'tree-check [%s] %s: %s\n' "$1" "$2" "$3" >>"$TMP/tree-failures"
}

# Prints field $2 (2 = WASM_PINS, 3 = record) of the row status of path $1.
row_status_of() {
  awk -F '\t' -v p="$1" -v f="$2" '$1 == p { v = $f } END { print (v == "" ? "-" : v) }' "$TMP/row-status"
}

# Parses the WASM_PINS table of build.rs $1 into "path<TAB>digest" lines, or
# one "ERROR<TAB>reason" line when the table cannot be read. The table runs
# from the line naming const WASM_PINS to its closing ]; line.
parse_wasm_pins() {
  LC_ALL=C awk '
    function fail(msg) { print "ERROR\t" msg; failed = 1; exit }
    function hex64(s) { return length(s) == 64 && s ~ /^[0-9a-f]+$/ }
    /^[[:space:]]*\/\// { next }
    {
      line = $0
      sub(/[[:space:]]*\/\/.*$/, "", line)
    }
    !inside && line ~ /const[[:space:]]+WASM_PINS/ { inside = 1; next }
    !inside { next }
    line ~ /^[[:space:]]*\];[[:space:]]*$/ { closed = 1; exit }
    {
      if (line ~ /^[[:space:]]*WasmPin \{$/) { blocks++; current = blocks }
      rest = line
      while (match(rest, /path:[[:space:]]*"[^"]*"/)) {
        value = substr(rest, RSTART, RLENGTH)
        sub(/^path:[[:space:]]*"/, "", value)
        sub(/"$/, "", value)
        paths++
        if (current == 0 || P[current] != "") fail("a path value outside a WasmPin { block, or a second one inside a block")
        P[current] = value
        rest = substr(rest, RSTART + RLENGTH)
      }
      rest = line
      while (match(rest, /expected_sha256:[[:space:]]*"[^"]*"/)) {
        value = substr(rest, RSTART, RLENGTH)
        sub(/^expected_sha256:[[:space:]]*"/, "", value)
        sub(/"$/, "", value)
        if (hex64(value)) {
          digests++
          if (current == 0 || D[current] != "") fail("a digest outside a WasmPin { block, or a second one inside a block")
          D[current] = value
        }
        rest = substr(rest, RSTART + RLENGTH)
      }
    }
    END {
      if (failed) exit
      if (!inside) { print "ERROR\tno const WASM_PINS table"; exit }
      if (!closed) { print "ERROR\tthe WASM_PINS table has no closing ];"; exit }
      if (blocks != paths || blocks != digests) {
        print "ERROR\t" blocks " WasmPin { lines, " paths " path values, and " digests " 64-hex digests differ in number"
        exit
      }
      for (i = 1; i <= blocks; i++) print P[i] "\t" D[i]
    }
  ' "$1"
}

# Scans Rust sources. Reads "scope<TAB>path" lines from $2 (scope "sa" for
# the smart-account crate, "other" for every other crate) relative to the
# repository root $1, and the definition and module specs from $3. Prints
#   INC<TAB>file<TAB>line<TAB>scope<TAB>literal  for each include_bytes! or
#                                                include_str! of one literal,
#   BADINC<TAB>file<TAB>line<TAB>reason          for any other use of them in
#                                                the smart-account crate,
#   CFG<TAB>file<TAB>line<TAB>reason             for a cfg check failure.
# The lexer blanks comments and literal contents for structural scans. Literal
# checks read their original text at parsed positions. A raw identifier reads
# as its name, so r#cfg is cfg. The self-test corpus pins supported spellings.
rust_scan() {
  LC_ALL=C awk -v root="$1" -v list="$2" -v specs="$3" '
function blanks(n,    s) { s = ""; while (n-- > 0) s = s " "; return s }

# Lexes one line, continuing the lexical state of the lines before it. Sets KL
# (comments blanked) and SL (comments and literal contents blanked, and the r#
# of each raw identifier blanked); both keep the column of every character.
function lex(line,    n, c, ch, pair, tail) {
  if (!block_depth && raw_end == "" && !quoted && line !~ /["\047\/]/ && index(line, "r#") == 0) { KL = line; SL = line; return }
  KL = ""; SL = ""; n = length(line)
  for (c = 1; c <= n; c++) {
    ch = substr(line, c, 1); pair = substr(line, c, 2)
    if (block_depth) {
      if (pair == "/*") { block_depth++; KL = KL "  "; SL = SL "  "; c++ }
      else if (pair == "*/") { block_depth--; KL = KL "  "; SL = SL "  "; c++ }
      else { KL = KL " "; SL = SL " " }
    } else if (raw_end != "") {
      if (substr(line, c, length(raw_end)) == raw_end) {
        KL = KL raw_end; SL = SL "\"" blanks(length(raw_end) - 1)
        c += length(raw_end) - 1; raw_end = ""
      } else { KL = KL ch; SL = SL " " }
    } else if (quoted) {
      if (ch == "\\") { KL = KL pair; SL = SL blanks(length(pair)); c++ }
      else if (ch == "\"") { quoted = 0; KL = KL ch; SL = SL ch }
      else { KL = KL ch; SL = SL " " }
    } else if (pair == "//") break
    else if (pair == "/*") { block_depth = 1; KL = KL "  "; SL = SL "  "; c++ }
    else if (ch == "r" && match(substr(line, c), /^r#*"/)) {
      tail = substr(line, c, RLENGTH)
      raw_end = "\"" substr(tail, 2, RLENGTH - 2)
      KL = KL tail; SL = SL "r" blanks(RLENGTH - 2) "\""
      c += RLENGTH - 1
    } else if (pair == "r#" && substr(line, c + 2, 1) ~ /[A-Za-z_]/ && (c == 1 || substr(line, c - 1, 1) !~ /[A-Za-z0-9_]/)) {
      KL = KL pair; SL = SL "  "; c++
    } else if (ch == "\"") { quoted = 1; KL = KL ch; SL = SL ch }
    else if (ch == SQ && match(substr(line, c), /^\047(\\x[0-9A-Fa-f][0-9A-Fa-f]|\\u[{][0-9A-Fa-f_]+[}]|\\[^[:space:]]|[\300-\367][\200-\277]+|[^\047\\\200-\377])\047/)) {
      KL = KL substr(line, c, RLENGTH); SL = SL SQ blanks(RLENGTH - 2) SQ
      c += RLENGTH - 1
    } else { KL = KL ch; SL = SL ch }
  }
}

# Moves the cursor (CL, CC) to the first non-blank character of S at or after
# line l, column c. Returns 0 at the end of the file.
function seek(l, c) {
  while (l <= NLINES) {
    while (c <= length(S[l]) && substr(S[l], c, 1) ~ /[[:space:]]/) c++
    if (c <= length(S[l])) { CL = l; CC = c; return 1 }
    l++; c = 1
  }
  return 0
}

function at() { return substr(S[CL], CC, 1) }

function report(kind, file, line, msg) { print kind "\t" file "\t" line "\t" msg }

# Returns 1 when the whitespace-free attribute text t negates any setting
# other than unix or windows.
function bad_not(t,    rest, off, p, before) {
  rest = t; off = 0
  while (match(rest, /not[(]/)) {
    p = off + RSTART
    before = p > 1 ? substr(t, p - 1, 1) : ""
    if (before !~ /[A-Za-z0-9_]/ && substr(t, p + 4) !~ /^(unix|windows)[)]/) return 1
    off = p + 3; rest = substr(t, off + 1)
  }
  return 0
}

# Splits t at commas outside brackets into parts[1..n]; returns n.
function split_top(t, parts,    n, i, ch, depth, cur) {
  n = 0; depth = 0; cur = ""
  for (i = 1; i <= length(t); i++) {
    ch = substr(t, i, 1)
    if (ch ~ /[([{]/) depth++
    else if (ch ~ /[])}]/) depth--
    if (ch == "," && depth == 0) { parts[++n] = cur; cur = "" } else cur = cur ch
  }
  parts[++n] = cur
  return n
}

# Reads the outer or inner attribute whose # is at line l, column c, if one
# starts there.
function read_attr(l, c,    el, ec, depth, ch, kc, s, k, inner) {
  if (!seek(l, c + 1)) return
  inner = at() == "!"
  if (inner && !seek(CL, CC + 1)) return
  if (at() != "[") return
  el = CL; ec = CC + 1; depth = 1; s = ""; k = ""
  while (1) {
    if (ec > length(S[el])) { el++; ec = 1; if (el > NLINES) return; continue }
    ch = substr(S[el], ec, 1)
    if (ch == "[") depth++
    else if (ch == "]") { depth--; if (depth == 0) break }
    if (ch !~ /[[:space:]]/) s = s ch
    kc = substr(K[el], ec, 1)
    if (kc != "" && kc !~ /[[:space:]]/) k = k kc
    ec++
  }
  NA++
  A_SL[NA] = l; A_SC[NA] = c; A_EL[NA] = el; A_EC[NA] = ec
  A_S[NA] = s; A_K[NA] = k; A_INNER[NA] = inner
  A_HEAD[NA] = match(s, /^[A-Za-z_][A-Za-z0-9_]*/) ? substr(s, 1, RLENGTH) : ""
}

# Applies the cfg rules to attribute j.
function check_attr(file, j,    s, h, x, n, i, parts) {
  s = A_S[j]; h = A_HEAD[j]
  if (index(s, "$")) report("CFG", file, A_SL[j], "a metavariable occurs in attribute text")
  if (h == "macro_use" || (h == "cfg_attr" && s ~ /[(,]macro_use([(,)]|$)/))
    report("CFG", file, A_SL[j], "a macro_use attribute is used")
  if (h == "path") report("CFG", file, A_SL[j], "a path attribute loads another source file: #[" A_K[j] "]")
  else if (h == "cfg") {
    if (bad_not(s)) report("CFG", file, A_SL[j], "a cfg predicate negates a setting other than unix or windows: #[" A_K[j] "]")
  } else if (h == "cfg_attr") {
    x = s; sub(/^cfg_attr[(]/, "", x); sub(/[)]$/, "", x)
    n = split_top(x, parts)
    for (i = 2; i <= n; i++) {
      if (parts[i] ~ /^(cfg|cfg_attr)[(]/)
        report("CFG", file, A_SL[j], "a cfg_attr applies cfg or cfg_attr: #[" A_K[j] "]")
    }
    if (s ~ /[(,]path=/) report("CFG", file, A_SL[j], "a cfg_attr applies a path attribute: #[" A_K[j] "]")
    if (bad_not(s)) {
      for (i = 2; i <= n; i++) {
        if (parts[i] != "" && parts[i] !~ /^(allow|expect|warn|deny|forbid)([(]|$)/) {
          report("CFG", file, A_SL[j], "a cfg_attr with a negated predicate applies an attribute other than a lint level: #[" A_K[j] "]")
          break
        }
      }
    }
  }
}

# Returns the identifier at the cursor, or "".
function ident_at() {
  return match(substr(S[CL], CC), /^[A-Za-z_][A-Za-z0-9_]*/) ? substr(S[CL], CC, RLENGTH) : ""
}

# Reports an invocation of the cfg or include identifier id that ends at line
# l, column c - 1.
function check_macro(file, l, c, id) {
  if (seek(l, c) && at() == "!") report("CFG", file, l, "the " id "! macro is used")
}

# Reports each cfg or include identifier that a use declaration imports under
# another name. A use declaration runs from the use keyword to its terminating
# ;, across lines and tokens, so a grouped or multiline import is read whole.
function scan_uses(file,    i, rest, off, id, l, c, tok) {
  for (i = 1; i <= NLINES; i++) {
    if (S[i] !~ /use/) continue
    rest = S[i]; off = 0
    while (match(rest, /[A-Za-z_][A-Za-z0-9_]*/)) {
      id = substr(rest, RSTART, RLENGTH)
      off += RSTART + RLENGTH - 1
      rest = substr(S[i], off + 1)
      if (id != "use") continue
      l = i; c = off + 1
      while (seek(l, c) && at() != ";") {
        l = CL; c = CC
        tok = ident_at()
        if (tok == "") { c++; continue }
        c += length(tok)
        if ((tok == "cfg" || tok == "include") && seek(l, c) && ident_at() == "as")
          report("CFG", file, l, "the " tok " macro is imported under another name")
      }
    }
  }
}

# Records a use of include_bytes! or include_str! that is not one string
# literal. Only the smart-account crate restricts the argument form.
function bad_include(file, scope, l, msg) {
  if (scope == "sa") report("BADINC", file, l, msg)
}

# Checks the include_bytes or include_str identifier id that ends at line l,
# column c - 1.
function check_include(file, scope, l, c, id,    open, closer, ln, col, t, lit, endc, h, rest, q, why) {
  why = id "! does not take exactly one string literal"
  if (!seek(l, c) || at() != "!") { bad_include(file, scope, l, id " is named without an invocation"); return }
  if (!seek(CL, CC + 1)) { bad_include(file, scope, l, why); return }
  open = at()
  closer = open == "(" ? ")" : open == "[" ? "]" : open == "{" ? "}" : ""
  if (closer == "" || !seek(CL, CC + 1)) { bad_include(file, scope, l, why); return }
  ln = CL; col = CC
  t = substr(K[ln], col)
  if (substr(S[ln], col, 1) == "\"" && match(t, /^"[^"\\]*"/)) {
    lit = substr(t, 2, RLENGTH - 2); endc = col + RLENGTH
  } else if (substr(S[ln], col, 1) == "r" && match(t, /^r#*"/)) {
    h = substr(t, 2, RLENGTH - 2)
    rest = substr(t, RLENGTH + 1)
    q = index(rest, "\"" h)
    if (!q) { bad_include(file, scope, l, why); return }
    lit = substr(rest, 1, q - 1)
    endc = col + RLENGTH + q + length(h)
  } else { bad_include(file, scope, l, why); return }
  if (!seek(ln, endc)) { bad_include(file, scope, l, why); return }
  if (at() == "," && !seek(CL, CC + 1)) { bad_include(file, scope, l, why); return }
  if (at() != closer) { bad_include(file, scope, l, why); return }
  print "INC\t" file "\t" l "\t" scope "\t" lit
}

function scan_tokens(file, scope,    i, rest, off, id) {
  for (i = 1; i <= NLINES; i++) {
    if (S[i] !~ /cfg|include/) continue
    rest = S[i]; off = 0
    while (match(rest, /[A-Za-z_][A-Za-z0-9_]*/)) {
      id = substr(rest, RSTART, RLENGTH)
      off += RSTART + RLENGTH - 1
      rest = substr(S[i], off + 1)
      if ((id == "cfg" || id == "include") && scope == "sa") check_macro(file, i, off + 1, id)
      else if (id == "include_bytes" || id == "include_str") check_include(file, scope, i, off + 1, id)
    }
  }
}

# Blanks every attribute span in T, a copy of S, so a line that holds only
# attributes reads blank.
function blank_attrs(    j, l, a, b) {
  for (l = 1; l <= NLINES; l++) T[l] = S[l]
  for (j = 1; j <= NA; j++) {
    for (l = A_SL[j]; l <= A_EL[j]; l++) {
      a = l == A_SL[j] ? A_SC[j] : 1
      b = l == A_EL[j] ? A_EC[j] : length(T[l])
      T[l] = substr(T[l], 1, a - 1) blanks(b - a + 1) substr(T[l], b + 1)
    }
  }
}

# Joined text keeps byte offsets, including newlines, for declaration counts
# and attribute attachment. T has attributes blanked; S keeps their spans.
function join_source(    l, j) {
  JS = ""; JK = ""; JT = ""
  for (l = 1; l <= NLINES; l++) {
    OFF[l] = length(JS)
    JS = JS S[l] "\n"; JK = JK K[l] "\n"; JT = JT T[l] "\n"
  }
  for (j = 1; j <= NA; j++) {
    A_START[j] = OFF[A_SL[j]] + A_SC[j]
    A_END[j] = OFF[A_EL[j]] + A_EC[j]
  }
}

function line_at(p,    l) {
  for (l = 1; l < NLINES && OFF[l + 1] < p; l++) { }
  return l
}

# Returns the brace depth of byte position p in the joined code text.
function depth_at(p,    t, o) {
  t = substr(JS, 1, p - 1); o = gsub(/[{]/, "", t)
  return o - gsub(/[}]/, "", t)
}

function compact(t) { gsub(/[[:space:]]/, "", t); return t }
function next_pos(p) { while (substr(JS, p, 1) ~ /[[:space:]]/ && p <= length(JS)) p++; return p }

# A declaration starts at its first keyword. Split declarations count too.
# Sets FOUND, TOTAL, and TOP, including declarations inside nested scopes.
function declarations(name, kind,    re, rest, off, p, len, dl) {
  re = "(^|[^A-Za-z0-9_])(pub([(][^)]*[)])?[[:space:]]+)?" kind "[[:space:]]+(mut[[:space:]]+)?" name "([^A-Za-z0-9_]|$)"
  rest = JT; off = 0; TOTAL = 0; TOP = 0; FOUND = 0
  while (match(rest, re)) {
    p = off + RSTART; len = RLENGTH
    if (substr(JT, p, 1) !~ /[A-Za-z_]/) p++
    TOTAL++
    dl = line_at(p)
    if (p == OFF[dl] + 1) { TOP++; FOUND = p }
    off += RSTART + len - 1; rest = substr(JT, off + 1)
  }
}

# An attached attribute starts after the last code character before the item
# and ends before the first keyword, regardless of line layout.
function check_attached(file, pos, permitted, what,    i, j) {
  i = pos - 1
  while (i > 0 && substr(JT, i, 1) ~ /[[:space:]]/) i--
  for (j = 1; j <= NA; j++) {
    if (A_START[j] > i && A_END[j] < pos && (A_HEAD[j] == "cfg" || A_HEAD[j] == "cfg_attr") && A_K[j] != permitted)
      report("CFG", file, A_SL[j], what " carries #[" A_K[j] "]")
  }
}

# The expression runs from the first top-level = to the terminating ;.
function initializer(pos,    p, depth, ch) {
  VALUE_START = 0; VALUE_END = 0; depth = 0
  for (p = pos; p <= length(JS); p++) {
    ch = substr(JS, p, 1)
    if (ch ~ /[([{]/) depth++
    else if (ch ~ /[])}]/) depth--
    else if (ch == "=" && depth == 0 && VALUE_START == 0) VALUE_START = p + 1
    else if (ch == ";" && depth == 0) { VALUE_END = p - 1; return }
  }
}

# Splits code at top-level commas and records each entry by absolute offset.
# Literal contents are blank in JS, so their punctuation has no structural role.
function entries(a, b, starts, ends,    p, depth, ch, n) {
  n = 0; depth = 0
  for (p = a; p <= b + 1; p++) {
    ch = substr(JS, p, 1)
    if (p == b + 1 || (ch == "," && depth == 0)) {
      if (compact(substr(JS, a, p - a)) != "") { starts[++n] = a; ends[n] = p - 1 }
      a = p + 1
    } else if (ch ~ /[([{]/) depth++
    else if (ch ~ /[])}]/) depth--
  }
  return n
}

# Accepts decimal and hexadecimal byte literals and returns their value.
function byte_number(t,    n, i, digit) {
  if (t ~ /^0x[0-9a-fA-F]+$/) {
    n = 0
    for (i = 3; i <= length(t); i++) {
      digit = index("0123456789abcdef", tolower(substr(t, i, 1))) - 1
      n = n * 16 + digit
      if (n > 255) return -1
    }
    return n
  }
  if (t ~ /^[0-9]+$/ && t + 0 <= 255) return t + 0
  return -1
}

# A byte array contains only numeric literals. FIXTURE is true only for the
# 32-byte revoked-fixture value, including decimal and uppercase spellings.
function byte_array(t, size,    parts, n, i, v, count) {
  FIXTURE = 0
  if (t !~ /^\[.*\]$/) return 0
  t = substr(t, 2, length(t) - 2)
  if (index(t, ";")) {
    n = split(t, parts, ";")
    if (n != 2 || parts[2] !~ /^[0-9]+$/) return 0
    v = byte_number(parts[1]); count = parts[2] + 0
    if (v < 0 || (size && count != size)) return 0
    FIXTURE = count == 32 && v == 238
    return 1
  }
  sub(/,$/, "", t)
  n = split(t, parts, ","); FIXTURE = n == 32
  for (i = 1; i <= n; i++) {
    v = byte_number(parts[i])
    if (v < 0) return 0
    if (v != 238) FIXTURE = 0
  }
  return !size || n == size
}

function bad_value(file, pos, name) {
  report("CFG", file, line_at(pos), name " must use a direct include_bytes! literal, hex digest literal, or byte-array literal")
}

# Audit statuses use a named variant and its exact fields as string literals.
function literal_status(a, b,    p, text, variant, h, n, i, field, names, starts, ends, seen) {
  p = next_pos(a)
  text = substr(JS, p, b - p + 1)
  variant = compact(text); sub(/^VerifierAuditStatus::/, "", variant)
  if (compact(text) == "VerifierAuditStatus::" variant && variant in STATUS_FIELDS && STATUS_FIELDS[variant] == "") return 1
  if (!match(text, /^VerifierAuditStatus[[:space:]]*::[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[{]/)) return 0
  h = p + RLENGTH
  variant = compact(substr(text, 1, RLENGTH)); sub(/^VerifierAuditStatus::/, "", variant); sub(/[{]$/, "", variant)
  if (!(variant in STATUS_FIELDS)) return 0
  while (substr(JS, b, 1) ~ /[[:space:]]/) b--
  if (substr(JS, b, 1) != "}") return 0
  n = entries(h, b - 1, starts, ends)
  if (n != split(STATUS_FIELDS[variant], names, ",")) return 0
  for (i = 1; i <= n; i++) {
    text = compact(substr(JS, starts[i], ends[i] - starts[i] + 1))
    if (!match(text, /^[A-Za-z_][A-Za-z0-9_]*:/)) return 0
    field = substr(text, 1, RLENGTH - 1)
    if (index("," STATUS_FIELDS[variant] ",", "," field ",") == 0 || seen[field]++) return 0
    text = substr(text, RLENGTH + 1)
    if (text != "\"\"" && text != "r\"\"") return 0
  }
  return 1
}

# Each verifier array entry has its own literal hash field. Fixture attributes
# attach to that entry by position; only the parsed hash supplies its value.
function verifier_entry(file, a, b, body_attr, marker,    p, j, gate, n, i, h, hash, starts, ends, text, status) {
  p = next_pos(a); gate = 0
  for (j = 1; j <= NA; j++) {
    if (A_START[j] == p && A_END[j] <= b) {
      if (A_K[j] == body_attr) gate++
      p = next_pos(A_END[j] + 1)
    }
  }
  text = substr(JS, p, b - p + 1)
  if (!match(text, /^VerifierAllowlistEntry[[:space:]]*[{]/) || compact(text) !~ /[}]$/) {
    bad_value(file, p, "VERIFIER_ALLOWLIST entry"); return
  }
  h = p + RLENGTH
  while (substr(JS, b, 1) ~ /[[:space:]]/) b--
  n = entries(h, b - 1, starts, ends); hash = ""; status = 0
  for (i = 1; i <= n; i++) {
    text = compact(substr(JS, starts[i], ends[i] - starts[i] + 1))
    if (text ~ /^wasm_hash:/ && hash == "") {
      hash = compact(substr(JK, starts[i], ends[i] - starts[i] + 1))
      sub(/^wasm_hash:/, "", hash)
    } else if (text ~ /^audit_status:/) {
      status++
      h = starts[i] + index(substr(JS, starts[i], ends[i] - starts[i] + 1), ":")
      if (!literal_status(h, ends[i]))
        report("CFG", file, line_at(h), "VERIFIER_ALLOWLIST audit_status must use a VerifierAuditStatus variant with literal fields")
    } else bad_value(file, starts[i], "VERIFIER_ALLOWLIST field")
  }
  if (status != 1) report("CFG", file, line_at(p), "VERIFIER_ALLOWLIST entry must hold exactly one audit_status field")
  if (!byte_array(hash, 32)) { bad_value(file, p, "VERIFIER_ALLOWLIST hash"); return }
  if (FIXTURE) { FIXTURE_COUNT++; FIXTURE_GATED += gate }
  else if (gate) report("CFG", file, line_at(next_pos(a)), "#[" body_attr "] in VERIFIER_ALLOWLIST applies to an item without " marker)
}

function literal_value(file, name, pos, a, b, body_attr, marker,    t, n, i, starts, ends) {
  t = compact(substr(JK, a, b - a + 1))
  if (name == "VERIFIER_ALLOWLIST" || name ~ /_WASM_HASHES$/) {
    a = next_pos(a)
    if (substr(JS, a, 1) != "&") { bad_value(file, pos, name); return }
    a = next_pos(a + 1)
    while (substr(JS, b, 1) ~ /[[:space:]]/) b--
    if (substr(JS, a, 1) != "[" || substr(JS, b, 1) != "]") { bad_value(file, pos, name); return }
    n = entries(a + 1, b - 1, starts, ends)
    FIXTURE_COUNT = 0; FIXTURE_GATED = 0
    for (i = 1; i <= n; i++) {
      if (name == "VERIFIER_ALLOWLIST") verifier_entry(file, starts[i], ends[i], body_attr, marker)
      else if (!byte_array(compact(substr(JK, starts[i], ends[i] - starts[i] + 1)), 32)) bad_value(file, starts[i], name)
    }
    if (body_attr == "") return
    if (FIXTURE_GATED != 1) report("CFG", file, line_at(pos), "the value of " name " holds " FIXTURE_GATED " items with " marker " under #[" body_attr "], not exactly one")
    if (FIXTURE_COUNT != 1) report("CFG", file, line_at(pos), "the value of " name " contains " marker " " FIXTURE_COUNT " times, not exactly once")
    return
  }
  if (name ~ /_SHA256$/) {
    if (t !~ /^"[0-9a-fA-F]+"$/ || length(t) != 66) bad_value(file, pos, name)
  } else if (t !~ /^include_bytes![(]"[^"\\]*"[)]$/ && !(substr(t, 1, 1) == "&" && byte_array(substr(t, 2), 0))) bad_value(file, pos, name)
}

# Watched definitions occur once at file scope, start at column one, and carry
# only known cfg attributes. Their bytes and hashes have direct literal initializers.
function check_definition(file, name, def_attr, body_attr, marker,    pos, a, b, j) {
  declarations(name, "(const|static)")
  if (TOP != 1 || TOTAL != 1) {
    report("CFG", file, 0, name " is not defined exactly once, unindented, in this file")
    return
  }
  pos = FOUND
  if (depth_at(pos)) report("CFG", file, line_at(pos), name " is not a top-level item of this file")
  check_attached(file, pos, def_attr, "the definition of " name)
  initializer(pos); a = VALUE_START; b = VALUE_END
  if (!a || !b) { bad_value(file, pos, name); return }
  for (j = 1; j <= NA; j++) {
    if (A_START[j] < a || A_END[j] > b || (A_HEAD[j] != "cfg" && A_HEAD[j] != "cfg_attr")) continue
    if (body_attr == "" || A_K[j] != body_attr)
      report("CFG", file, A_SL[j], "the value of " name " carries #[" A_K[j] "]")
  }
  literal_value(file, name, pos, a, b, body_attr, marker)
}

function check_module(file, name, permitted,    pos, tail) {
  declarations(name, "mod")
  pos = FOUND
  if (depth_at(pos)) report("CFG", file, line_at(pos), "the module " name " is not declared at the top level of this file")
  tail = compact(substr(JT, pos))
  if (TOP != 1 || TOTAL != 1 || tail !~ ("^(pub([(][^)]*[)])?)?mod" name ";")) {
    report("CFG", file, 0, "the module " name " is not declared exactly once, unindented, as mod " name ";")
    return
  }
  check_attached(file, pos, permitted, "the declaration of module " name)
}

# Reports $name!, #$name, and #!$name token sequences.
function scan_metavariables(file,    l, c, ch, id) {
  for (l = 1; l <= NLINES; l++) {
    if (S[l] !~ /[$#]/) continue
    for (c = 1; c <= length(S[l]); c++) {
      ch = substr(S[l], c, 1)
      if (ch == "$" && seek(l, c + 1)) {
        id = ident_at()
        if (id != "" && seek(CL, CC + length(id)) && at() == "!")
          report("CFG", file, l, "a metavariable supplies an attribute or macro name")
      } else if (ch == "#" && seek(l, c + 1)) {
        if (at() == "!" && !seek(CL, CC + 1)) continue
        if (at() == "$") report("CFG", file, l, "a metavariable supplies an attribute or macro name")
      }
    }
  }
}

# Returns the matching closing brace in text with literal contents blanked.
function brace_end(p,    depth, ch) {
  depth = 0
  for (; p <= length(JS); p++) {
    ch = substr(JS, p, 1)
    if (ch == "{") depth++
    else if (ch == "}" && --depth == 0) return p
  }
  return 0
}

# A listed macro has one definition, its pinned body, and its named function scope.
function scan_macro_definitions(file,    rest, off, p, end, text, name, key, owner, start, stop, seen) {
  rest = JS; off = 0
  while (match(rest, /(^|[^A-Za-z0-9_])macro_rules[[:space:]]*!/)) {
    p = off + RSTART + RLENGTH
    off = p - 1; rest = substr(JS, p)
    p = next_pos(p)
    text = substr(JS, p)
    name = match(text, /^[A-Za-z_][A-Za-z0-9_]*/) ? substr(text, 1, RLENGTH) : ""
    key = file SUBSEP name
    start = next_pos(p + length(name))
    end = substr(JS, start, 1) == "{" ? brace_end(start) : 0
    owner = KNOWN_MACRO_OWNER[key]
    stop = 0
    if (owner != "" && match(JS, "(^|[^A-Za-z0-9_])fn[[:space:]]+" owner "[[:space:]]*[(]")) {
      stop = RSTART + RLENGTH
      stop += index(substr(JS, stop), "{") - 1
      if (stop >= p || brace_end(stop) <= p) stop = 0
    }
    if (!(key in KNOWN_MACROS) || seen[key]++ || !stop || !end || compact(substr(JK, start, end - start + 1)) != KNOWN_MACROS[key])
      report("CFG", file, line_at(p), "a macro_rules! definition is outside the known list: " name)
  }
}

function process(file, scope,    line, n, j, x, path, has_macro, watched) {
  n = 0; has_macro = 0; split("", K); split("", S); split("", T)
  block_depth = 0; raw_end = ""; quoted = 0
  path = root "/" file
  while ((getline line < path) > 0) {
    lex(line); n++; K[n] = KL; S[n] = SL
    if (index(SL, "macro_rules")) has_macro = 1
    if (scope == "sa" && SL ~ /[\200-\377]/) report("CFG", file, n, "non-ASCII bytes in code text")
  }
  close(path)
  NLINES = n
  NA = 0
  split("", A_SL); split("", A_SC); split("", A_EL); split("", A_EC)
  split("", A_S); split("", A_K); split("", A_HEAD); split("", A_INNER)
  if (scope == "sa") {
    for (x = 1; x <= n; x++) {
      if (index(S[x], "#") == 0) continue
      line = S[x]
      for (j = 1; j <= length(line); j++) if (substr(line, j, 1) == "#") read_attr(x, j)
    }
    for (j = 1; j <= NA; j++) check_attr(file, j)
    scan_uses(file)
  }
  scan_tokens(file, scope)
  if (scope != "sa") return
  scan_metavariables(file)
  for (x = 1; x <= NSPEC; x++) if (SP_FILE[x] == file) break
  watched = x <= NSPEC
  if (!watched && !has_macro) return
  blank_attrs()
  join_source()
  scan_macro_definitions(file)
  if (!watched) return
  for (j = 1; j <= NA; j++) {
    if (A_INNER[j] && (A_HEAD[j] == "cfg" || A_HEAD[j] == "cfg_attr"))
      report("CFG", file, A_SL[j], "an inner cfg or cfg_attr attribute occurs in a watched file")
  }
  for (x = 1; x <= NSPEC; x++) {
    if (SP_FILE[x] != file) continue
    if (SP_KIND[x] == "def") check_definition(file, SP_NAME[x], SP_A1[x], SP_A2[x], SP_A3[x])
    else check_module(file, SP_NAME[x], SP_A1[x])
  }
}

BEGIN {
  SQ = sprintf("%c", 39)
  # Known macro definitions: file, name, owner function, and literal body.
  key = "crates/stellar-agent-smart-account/src/managers/credentials.rs" SUBSEP "early_err"
  KNOWN_MACRO_OWNER[key] = "sign_with_passkey_rule_inner"
  KNOWN_MACROS[key] = "{($e:expr)=>{return(Err($e),credential_id_b64url,rp_id,None)};}"
  STATUS_FIELDS["Audited"] = "auditor,audited_at"
  STATUS_FIELDS["Provisional"] = "attested_by,attested_at"
  STATUS_FIELDS["Unaudited"] = ""
  STATUS_FIELDS["Revoked"] = "revoked_at,reason"
  STATUS_FIELDS["Retired"] = "revoked_at,retired_at"
  NSPEC = 0
  while ((getline line < specs) > 0) {
    NSPEC++
    split(line, f, "|")
    SP_KIND[NSPEC] = f[1]; SP_FILE[NSPEC] = f[2]; SP_NAME[NSPEC] = f[3]
    SP_A1[NSPEC] = f[4]; SP_A2[NSPEC] = f[5]; SP_A3[NSPEC] = f[6]
  }
  close(specs)
  while ((getline line < list) > 0) {
    tab = index(line, "\t")
    process(substr(line, tab + 1), substr(line, 1, tab - 1))
  }
  close(list)
}
'
}

# Normalizes the repository-relative path $1, resolving "." and "..", into
# NORMALIZED. Returns 1 when the path leaves the repository.
normalize_path() {
  local IFS=/ part out=""
  set -f
  for part in $1; do
    case "$part" in
      '' | .) ;;
      ..)
        if [ -z "$out" ]; then
          set +f
          return 1
        fi
        case "$out" in
          */*) out=${out%/*} ;;
          *) out="" ;;
        esac
        ;;
      *) out="${out:+$out/}$part" ;;
    esac
  done
  set +f
  NORMALIZED=$out
}

# Checks the vendored file $2 (relative to the crate) of repository $1 against
# its record and its WASM_PINS row; $3 is pin or nopin. Sets FILE_SHA,
# FILE_RECORD (the record path, or empty), PINS_STATE, and RECORD_STATE.
check_vendored_file() {
  local repo=$1 rel=$2 want_pin=$3
  local full="$repo/$CRATE/$rel" dir tokens count pin_digest
  FILE_SHA=""
  FILE_RECORD=""
  PINS_STATE="-"
  RECORD_STATE="-"
  if [ ! -f "$full" ]; then
    tree_fail tracked "$CRATE/$rel" "the vendored file does not exist"
    PINS_STATE=missing
    RECORD_STATE=missing
    return
  fi
  FILE_SHA=$(sha256_of "$full")
  dir=$(dirname "$full")
  if [ -f "$dir/PROVENANCE.md" ] && [ -f "$dir/REFERENCE.md" ]; then
    tree_fail record "$CRATE/$rel" "both PROVENANCE.md and REFERENCE.md exist beside the file"
    RECORD_STATE=MISMATCH
  elif [ -f "$dir/PROVENANCE.md" ]; then
    FILE_RECORD="$dir/PROVENANCE.md"
  elif [ -f "$dir/REFERENCE.md" ]; then
    FILE_RECORD="$dir/REFERENCE.md"
  else
    tree_fail record "$CRATE/$rel" "no PROVENANCE.md or REFERENCE.md exists beside the file"
    RECORD_STATE=missing
  fi
  if [ -n "$FILE_RECORD" ]; then
    tokens=$({ grep -oE '[0-9A-Fa-f]+' "$FILE_RECORD" || true; } |
      awk 'length($0) == 64 { print tolower($0) }' | LC_ALL=C sort -u)
    count=$(printf '%s' "$tokens" | awk 'END { print NR }')
    if [ "$count" != 1 ]; then
      tree_fail record "$CRATE/$rel" "the record holds $count distinct 64-hex tokens, not exactly one"
      RECORD_STATE=MISMATCH
    elif [ "$tokens" != "$FILE_SHA" ]; then
      tree_fail record "$CRATE/$rel" "the record digest $tokens differs from the file sha256 $FILE_SHA"
      RECORD_STATE=MISMATCH
    else
      RECORD_STATE=match
    fi
  fi
  if [ "$PINS_OK" != 1 ]; then
    PINS_STATE=unreadable
    return
  fi
  pin_digest=$(awk -F '\t' -v p="$rel" '$1 == p { print $2 }' "$TMP/wasm-pins")
  if [ "$want_pin" = pin ]; then
    if [ -z "$pin_digest" ]; then
      tree_fail wasm-pins "$CRATE/$rel" "a pin file has no WASM_PINS row"
      PINS_STATE=missing
    elif [ "$pin_digest" != "$FILE_SHA" ]; then
      tree_fail wasm-pins "$CRATE/$rel" "the WASM_PINS digest $pin_digest differs from the file sha256 $FILE_SHA"
      PINS_STATE=MISMATCH
    else
      PINS_STATE=match
    fi
  elif [ -n "$pin_digest" ]; then
    tree_fail wasm-pins "$CRATE/$rel" "a nopin file has a WASM_PINS row"
    PINS_STATE=unexpected
  else
    PINS_STATE=none
  fi
}

# Runs every tree check on the repository $1. Failures go to
# $TMP/tree-failures, and the per-file states the output table shows go to
# $TMP/row-status.
check_tree() {
  local repo=$1
  local path magic dir base line vpath frozen flag pin
  local row_path source package toolchain target builder output
  local vendored="" vendored_dirs="" seen="" pin_paths="" pinned_rows=""
  local commit tc_string builder_line

  : >"$TMP/tree-failures"
  : >"$TMP/row-status"
  : >"$TMP/rust-files"
  : >"$TMP/other-files"
  : >"$TMP/wasm-pins"

  while read -r row_path _ _ _ _ _ _ pin; do
    vendored="$vendored$CRATE/$row_path$NL"
    vendored_dirs="$vendored_dirs$CRATE/$(dirname "$row_path")$NL"
    [ "$pin" = pin ] && pinned_rows="$pinned_rows$row_path$NL"
  done <<<"$MANIFEST"
  while read -r vpath _ flag; do
    [ -n "$vpath" ] || continue
    vendored="$vendored$CRATE/$vpath$NL"
    vendored_dirs="$vendored_dirs$CRATE/$(dirname "$vpath")$NL"
    [ "$flag" = pin ] && pinned_rows="$pinned_rows$vpath$NL"
  done <<<"$EXCEPTIONS"
  vendored=${vendored%"$NL"}
  vendored_dirs=${vendored_dirs%"$NL"}
  pinned_rows=${pinned_rows%"$NL"}

  if ! git -C "$repo" -c core.quotePath=false ls-files -z >"$TMP/tracked"; then
    tree_fail tracked "$repo" "git ls-files failed"
    return
  fi

  while IFS= read -r -d '' path; do
    case "$path" in
      *"$NL"*)
        tree_fail tracked "$path" "a tracked path contains a newline"
        continue
        ;;
    esac
    if in_list "$path" "$vendored"; then
      seen="$seen$path$NL"
    fi
    # Wasm magic: every tracked file whose first four bytes are 00 61 73 6d.
    if [ -f "$repo/$path" ]; then
      magic=$(od -An -tx1 -N4 "$repo/$path" 2>/dev/null) || magic=""
      magic=${magic//[[:space:]]/}
      if [ "$magic" = "0061736d" ] && ! in_list "$path" "$vendored" && ! in_list "$path" "$OUT_OF_SCOPE"; then
        tree_fail wasm-magic "$path" "a tracked Wasm file is neither in the manifest, nor an exception, nor out of scope"
      fi
    fi
    # Vendor directory contents.
    case "$path" in
      "$CRATE/vendor/"*)
        if ! in_list "$path" "$vendored"; then
          dir=$(dirname "$path")
          base=$(basename "$path")
          case "$base" in
            PROVENANCE.md | REFERENCE.md | build.sh)
              in_list "$dir" "$vendored_dirs" ||
                tree_fail vendor-files "$path" "a record or build script beside no manifest or exception file"
              ;;
            *)
              tree_fail vendor-files "$path" "a file under vendor/ that is neither a vendored Wasm file nor its record or build script"
              ;;
          esac
        fi
        ;;
    esac
    # Rust sources for the include and cfg checks.
    case "$path" in
      "$CRATE/src/"*.rs) printf 'sa\t%s\n' "$path" >>"$TMP/rust-files" ;;
      crates/*/src/*.rs) printf '%s\0' "$path" >>"$TMP/other-files" ;;
    esac
  done <"$TMP/tracked"
  # Other crates are scanned only for include_bytes! and include_str!, so only
  # the files that name either are lexed.
  if [ -s "$TMP/other-files" ]; then
    (cd "$repo" && xargs -0 grep -lE 'include_(bytes|str)' -- <"$TMP/other-files" || true) |
      awk '{ print "other\t" $0 }' >>"$TMP/rust-files"
  fi

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    in_list "$path" "$seen" || tree_fail tracked "$path" "a manifest or exception file is not tracked"
  done <<<"$vendored"

  # The WASM_PINS table of build.rs.
  PINS_OK=1
  if [ ! -f "$repo/$CRATE/build.rs" ]; then
    tree_fail wasm-pins "$CRATE/build.rs" "build.rs does not exist"
    PINS_OK=0
  else
    parse_wasm_pins "$repo/$CRATE/build.rs" >"$TMP/wasm-pins"
    line=$(head -n 1 "$TMP/wasm-pins")
    case "$line" in
      "ERROR$TAB"*)
        tree_fail wasm-pins "$CRATE/build.rs" "the WASM_PINS table cannot be read: ${line#ERROR"$TAB"}"
        PINS_OK=0
        : >"$TMP/wasm-pins"
        ;;
    esac
  fi
  if [ "$PINS_OK" = 1 ]; then
    pin_paths=$(awk -F '\t' '{ print $1 }' "$TMP/wasm-pins")
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      in_list "$path" "$pinned_rows" ||
        tree_fail wasm-pins "$CRATE/build.rs" "WASM_PINS names $path, which is no pin row or pin exception"
    done <<<"$pin_paths"
  fi

  # Per-file checks: WASM_PINS row, record digest, record fields.
  while read -r row_path source package toolchain target builder output pin; do
    check_vendored_file "$repo" "$row_path" "$pin"
    if [ -n "$FILE_RECORD" ]; then
      case "$source" in
        oz:*)
          commit=$(tag_commit "${source#oz:}") || commit=""
          if [ -z "$commit" ]; then
            tree_fail record-fields "$CRATE/$row_path" "the source $source names no pinned tag"
            RECORD_STATE=MISMATCH
          elif ! grep -qF -- "$commit" "$FILE_RECORD"; then
            tree_fail record-fields "$CRATE/$row_path" "the record lacks the source commit $commit"
            RECORD_STATE=MISMATCH
          fi
          ;;
        tree:*)
          if ! grep -qF -- "${source#tree:}" "$FILE_RECORD"; then
            tree_fail record-fields "$CRATE/$row_path" "the record lacks the source path ${source#tree:}"
            RECORD_STATE=MISMATCH
          fi
          ;;
      esac
      # The rustc string and the builder line are whole code spans, so a
      # longer version string that contains either never matches.
      tc_string=$(lookup "$TOOLCHAINS" "$toolchain") || tc_string=""
      if [ -z "$tc_string" ] || ! grep -qF -- "\`$tc_string\`" "$FILE_RECORD"; then
        tree_fail record-fields "$CRATE/$row_path" "the record lacks the rustc string '${tc_string:-$toolchain}' as a code span"
        RECORD_STATE=MISMATCH
      fi
      builder_line=$(lookup "$BUILDERS" "$builder") || builder_line=""
      if [ -z "$builder_line" ] || ! grep -qF -- "\`$builder_line\`" "$FILE_RECORD"; then
        tree_fail record-fields "$CRATE/$row_path" "the record lacks the builder line '${builder_line:-$builder}' as a code span"
        RECORD_STATE=MISMATCH
      fi
    fi
    printf '%s\t%s\t%s\n' "$row_path" "$PINS_STATE" "$RECORD_STATE" >>"$TMP/row-status"
  done <<<"$MANIFEST"

  while read -r vpath frozen flag; do
    [ -n "$vpath" ] || continue
    check_vendored_file "$repo" "$vpath" "$flag"
    if [ -n "$FILE_SHA" ] && [ "$FILE_SHA" != "$frozen" ]; then
      tree_fail frozen "$CRATE/$vpath" "the exception's sha256 $FILE_SHA differs from its frozen digest $frozen"
    fi
    printf '%s\t%s\t%s\n' "$vpath" "$PINS_STATE" "$RECORD_STATE" >>"$TMP/row-status"
  done <<<"$EXCEPTIONS"

  # include_bytes! and include_str! arguments, and the cfg rules.
  local def_file def_name a1 a2 a3 chain_file mod_name parent
  awk -F '\t' '{ print $2 }' "$TMP/rust-files" >"$TMP/rust-paths"
  : >"$TMP/specs"
  : >"$TMP/chain"
  while IFS='|' read -r def_file def_name a1 a2 a3; do
    printf 'def|%s|%s|%s|%s|%s\n' "$CRATE/$def_file" "$def_name" "$a1" "$a2" "$a3" >>"$TMP/specs"
    grep -qxF -- "$CRATE/$def_file" "$TMP/rust-paths" ||
      tree_fail cfg "$CRATE/$def_file" "the file that defines $def_name is not a tracked source file"
    # The module declarations from src/lib.rs down to the defining file.
    chain_file=$def_file
    while [ "$chain_file" != src/lib.rs ]; do
      case "$chain_file" in
        */mod.rs)
          mod_name=$(basename "$(dirname "$chain_file")")
          parent=$(dirname "$(dirname "$chain_file")")
          ;;
        *)
          mod_name=$(basename "$chain_file" .rs)
          parent=$(dirname "$chain_file")
          ;;
      esac
      if [ "$parent" = src ]; then
        parent=src/lib.rs
      elif [ -f "$repo/$CRATE/$parent/mod.rs" ]; then
        parent="$parent/mod.rs"
      else
        parent="$parent.rs"
      fi
      printf '%s|%s\n' "$parent" "$mod_name" >>"$TMP/chain"
      chain_file=$parent
    done
  done <<<"$DEFINITIONS"
  LC_ALL=C sort -u "$TMP/chain" >"$TMP/chain.sorted"
  while IFS='|' read -r chain_file mod_name; do
    a1=$(awk -F '|' -v f="$chain_file" -v m="$mod_name" '$1 == f && $2 == m { print $3 }' <<<"$MODULE_GATES")
    printf 'mod|%s|%s|%s||\n' "$CRATE/$chain_file" "$mod_name" "$a1" >>"$TMP/specs"
    grep -qxF -- "$CRATE/$chain_file" "$TMP/rust-paths" ||
      tree_fail cfg "$CRATE/$chain_file" "the file that declares module $mod_name is not a tracked source file"
  done <"$TMP/chain.sorted"

  rust_scan "$repo" "$TMP/rust-files" "$TMP/specs" >"$TMP/rust-scan"
  local kind file lno f4 f5
  while IFS="$TAB" read -r kind file lno f4 f5; do
    case "$kind" in
      INC)
        if [ "$f4" = other ]; then
          case "$f5" in
            *.wasm) ;;
            *) continue ;;
          esac
        fi
        case "$f5" in
          /*)
            tree_fail include "$file:$lno" "the include argument '$f5' is an absolute path"
            continue
            ;;
        esac
        if ! normalize_path "$(dirname "$file")/$f5" || ! in_list "$NORMALIZED" "$vendored"; then
          tree_fail include "$file:$lno" "the include argument '$f5' resolves to no manifest or exception file"
        fi
        ;;
      BADINC) tree_fail include "$file:$lno" "$f4" ;;
      CFG)
        if [ "$lno" = 0 ]; then
          tree_fail cfg "$file" "$f4"
        else
          tree_fail cfg "$file:$lno" "$f4"
        fi
        ;;
    esac
  done <"$TMP/rust-scan"
}

tree_failure_count() {
  awk 'END { print NR }' "$TMP/tree-failures"
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

mode_list_toolchains() {
  awk '{ print $4 " " $5 }' <<<"$MANIFEST" | LC_ALL=C sort -u
}

mode_check_tree() {
  local repo="" n
  while [ $# -gt 0 ]; do
    case "$1" in
      --repo-root) [ $# -ge 2 ] || usage; repo=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$repo" ] || usage
  repo=$(abs_dir "$repo") || die "the repository root '$repo' does not exist"
  check_tree "$repo"
  cat "$TMP/tree-failures"
  n=$(tree_failure_count)
  if [ "$n" != 0 ]; then
    echo "$NAME: FAIL: $n tree check failures"
    return 1
  fi
  echo "$NAME: PASS: tracked Wasm files, records, pins, includes, and watched source forms satisfy the tree rules"
}

mode_rebuild_needed() {
  local repo="" event="" base="" head="" base_set=0 head_set=0 path prefix
  while [ $# -gt 0 ]; do
    case "$1" in
      --repo-root) [ $# -ge 2 ] || usage; repo=$2; shift 2 ;;
      --event) [ $# -ge 2 ] || usage; event=$2; shift 2 ;;
      --base) [ $# -ge 2 ] || usage; base=$2; base_set=1; shift 2 ;;
      --head) [ $# -ge 2 ] || usage; head=$2; head_set=1; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$repo" ] && [ "$base_set" = 1 ] && [ "$head_set" = 1 ] || usage
  case "$event" in
    pull_request | push) ;;
    *)
      echo true
      return 0
      ;;
  esac
  case "$base" in
    '' | *[!0]*) ;;
    *)
      echo true
      return 0
      ;;
  esac
  if [ -z "$base" ] || [ -z "$head" ] ||
    ! git -C "$repo" rev-parse --verify --quiet "$base^{commit}" >/dev/null 2>&1 ||
    ! git -C "$repo" rev-parse --verify --quiet "$head^{commit}" >/dev/null 2>&1; then
    echo true
    return 0
  fi
  if ! git -C "$repo" -c core.quotePath=false diff --no-renames --name-only -z "$base" "$head" >"$TMP/changed" 2>/dev/null; then
    echo true
    return 0
  fi
  while IFS= read -r -d '' path; do
    while IFS= read -r prefix; do
      case "$path" in
        "$prefix"*)
          echo true
          return 0
          ;;
      esac
    done <<<"$REBUILD_PREFIXES"
  done <"$TMP/changed"
  echo false
}

mode_gate() {
  [ $# -eq 5 ] || usage
  local check=$1 rebuild=$2 cli25=$3 cli28=$4 rebuilt=$5
  echo "check=$check rebuild=$rebuild stellar-cli-25=$cli25 stellar-cli-28=$cli28 rebuild-job=$rebuilt"
  if [ "$check" != success ]; then
    echo "$NAME: gate FAIL: the check job reported '$check', not success"
    return 1
  fi
  case "$rebuild" in
    true)
      if [ "$cli25" = success ] && [ "$cli28" = success ] && [ "$rebuilt" = success ]; then
        echo "$NAME: gate PASS: the vendored Wasm files were rebuilt and matched"
        return 0
      fi
      echo "$NAME: gate FAIL: a rebuild was needed, and the macOS jobs reported '$cli25', '$cli28', and '$rebuilt', not success"
      return 1
      ;;
    false)
      if [ "$cli25" = skipped ] && [ "$cli28" = skipped ] && [ "$rebuilt" = skipped ]; then
        echo "$NAME: gate PASS: no rebuild was needed, and the tree check passed"
        return 0
      fi
      echo "$NAME: gate FAIL: no rebuild was needed, and the macOS jobs reported '$cli25', '$cli28', and '$rebuilt', not skipped"
      return 1
      ;;
    *)
      echo "$NAME: gate FAIL: the rebuild decision is '$rebuild', not true or false"
      return 1
      ;;
  esac
}

mode_exec() {
  local dir="" refused=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --dir) [ $# -ge 2 ] || usage; dir=$2; shift 2 ;;
      --)
        shift
        break
        ;;
      *) usage ;;
    esac
  done
  [ -n "$dir" ] && [ $# -gt 0 ] || usage
  environment_refusals || refused=1
  directory_refusals "$dir" || refused=1
  [ "$refused" = 0 ] || exit 2
  run_clean "$dir" "${RUSTUP_TOOLCHAIN:-}" "${CARGO_TARGET_DIR:-}" "$@"
}

# Prints one row of the output table.
table_row() {
  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' "$@"
}

# Writes the sha256 of every manifest and exception file of repository $1,
# with "missing" for an absent one, to file $2.
vendored_digests() {
  local path
  : >"$2"
  while read -r path _; do
    [ -n "$path" ] || continue
    if [ -f "$1/$CRATE/$path" ]; then
      printf '%s %s\n' "$(sha256_of "$1/$CRATE/$path")" "$path" >>"$2"
    else
      printf 'missing %s\n' "$path" >>"$2"
    fi
  done <<<"$MANIFEST$NL$EXCEPTIONS"
}

mode_full() {
  local repo="" oz="" s25="" s28="" work="" refused=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --repo-root) [ $# -ge 2 ] || usage; repo=$2; shift 2 ;;
      --oz-clone) [ $# -ge 2 ] || usage; oz=$2; shift 2 ;;
      --stellar-25) [ $# -ge 2 ] || usage; s25=$2; shift 2 ;;
      --stellar-28) [ $# -ge 2 ] || usage; s28=$2; shift 2 ;;
      --work) [ $# -ge 2 ] || usage; work=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$repo" ] && [ -n "$oz" ] && [ -n "$s25" ] && [ -n "$s28" ] && [ -n "$work" ] || usage

  # Refusals and preconditions: each stops the run before any build.
  environment_refusals || refused=1
  repo=$(abs_dir "$repo") || die "the repository root does not exist"
  oz=$(abs_dir "$oz") || die "the OpenZeppelin clone does not exist"
  # The work directory's physical path, resolved before anything is created.
  local work_parent
  work_parent=$(abs_dir "$(dirname "$work")") || die "the parent of the work directory does not exist"
  work="$work_parent/$(basename "$work")"
  if [ -d "$work" ]; then
    work=$(abs_dir "$work")
  fi
  case "$work/" in
    "$repo/"*)
      echo "$NAME: refused: the work directory '$work' lies inside the repository root '$repo'" >&2
      exit 2
      ;;
  esac
  mkdir -p "$work"
  directory_refusals "$work" || refused=1
  [ "$refused" = 0 ] || exit 2

  local id want got bin tag commit tc tc_string
  for id in s25 s28; do
    if [ "$id" = s25 ]; then bin=$s25; else bin=$s28; fi
    want=$(lookup "$BUILDERS" "$id")
    got=$(first_line "$bin" --version) || got=""
    [ "$got" = "$want" ] ||
      die "precondition failed: the $id builder '$bin' prints '$got' as its first --version line, not '$want'"
  done
  while read -r tag commit; do
    got=$(git -C "$oz" rev-parse --verify --quiet "refs/tags/$tag^{commit}" 2>/dev/null) || got=""
    [ "$got" = "$commit" ] ||
      die "precondition failed: the tag $tag of the OpenZeppelin clone resolves to '$got', not $commit"
  done <<<"$OZ_TAGS"
  while read -r tc; do
    tc_string=$(lookup "$TOOLCHAINS" "$tc") ||
      die "precondition failed: the manifest names the toolchain $tc, which has no pinned rustc string"
    got=$(first_line run_clean "$work" "$tc" "" rustc --version) || got=""
    [ "$got" = "$tc_string" ] ||
      die "precondition failed: rustc of toolchain $tc prints '$got', not '$tc_string'"
  done < <(awk '{ print $4 }' <<<"$MANIFEST" | LC_ALL=C sort -u)

  # The repository state that no step may change.
  GIT_OPTIONAL_LOCKS=0 git -C "$repo" -c core.quotePath=false status --porcelain -z >"$TMP/status-before" ||
    die "git status of the repository root failed"
  vendored_digests "$repo" "$TMP/digests-before"

  # Sources: one detached worktree per OpenZeppelin tag and one copy of the
  # tracked files of each tree source, all under the work directory.
  rm -rf "$work/src" "$work/target"
  mkdir -p "$work/src" "$work/target"
  git -C "$oz" worktree prune || die "git worktree prune failed in the OpenZeppelin clone"
  while read -r tag commit; do
    git -C "$oz" worktree add --detach "$work/src/oz-$tag" "$commit" >/dev/null 2>&1 ||
      die "precondition failed: git worktree add of $tag failed"
    GIT_OPTIONAL_LOCKS=0 git -C "$work/src/oz-$tag" -c core.quotePath=false status --porcelain -z >"$TMP/oz-status" ||
      die "precondition failed: git status of the $tag worktree failed"
    [ ! -s "$TMP/oz-status" ] || die "precondition failed: the $tag worktree is not clean before the builds"
  done <<<"$OZ_TAGS"
  local row_path source package toolchain target builder output pin key srcdir prefix file copied
  while read -r row_path source _; do
    case "$source" in
      tree:*) ;;
      *) continue ;;
    esac
    key=$(source_key "$source")
    srcdir="$work/src/$key"
    [ -d "$srcdir" ] && continue
    mkdir -p "$srcdir"
    prefix="${source#tree:}/"
    copied=0
    while IFS= read -r -d '' file; do
      mkdir -p "$srcdir/$(dirname "${file#"$prefix"}")"
      cp "$repo/$file" "$srcdir/${file#"$prefix"}"
      copied=1
    done < <(git -C "$repo" -c core.quotePath=false ls-files -z -- "$prefix")
    [ "$copied" = 1 ] || die "precondition failed: no tracked files under $prefix"
  done <<<"$MANIFEST"
  while read -r row_path source _; do
    key=$(source_key "$source") || die "the manifest row $row_path names the unknown source $source"
    directory_refusals "$work/src/$key" || exit 2
  done <<<"$MANIFEST"

  # Tree checks: failures are reported, and every row is still built.
  check_tree "$repo"

  # Builds and comparisons.
  local n=0 failures=0 targetdir out vendored_file rebuilt_sha rebuilt_size cmp_state result
  local pins_state record_state log build_status vpath frozen flag
  : >"$TMP/table"
  while read -r row_path source package toolchain target builder output pin; do
    n=$((n + 1))
    key=$(source_key "$source")
    srcdir="$work/src/$key"
    case "$output" in
      release/deps/*) targetdir="$work/target/$key-$package" ;;
      *) targetdir="$work/target/$key" ;;
    esac
    if [ "$builder" = s25 ]; then bin=$s25; else bin=$s28; fi
    out="$targetdir/$target/$output"
    vendored_file="$repo/$CRATE/$row_path"
    mkdir -p "$targetdir"
    rm -f "$out"
    log="$TMP/build-$n.log"
    echo "$NAME: building $row_path ($source, package $package, toolchain $toolchain, builder $builder)" >&2
    build_status=0
    if [ "$package" = - ]; then
      run_clean "$srcdir" "$toolchain" "$targetdir" "$bin" contract build --locked >"$log" 2>&1 || build_status=$?
    else
      run_clean "$srcdir" "$toolchain" "$targetdir" "$bin" contract build --locked --package "$package" >"$log" 2>&1 || build_status=$?
    fi
    rebuilt_sha="-"
    rebuilt_size="-"
    if [ "$build_status" != 0 ]; then
      cmp_state="build-failed"
      echo "$NAME: the build of $row_path exited $build_status; the end of its log:" >&2
      tail -n 40 "$log" >&2 || true
    elif [ ! -f "$out" ]; then
      cmp_state="missing-output"
    else
      rebuilt_sha=$(sha256_of "$out")
      rebuilt_size=$(size_of "$out")
      if [ -f "$vendored_file" ] && cmp -s "$out" "$vendored_file"; then
        cmp_state=match
      else
        cmp_state=MISMATCH
      fi
    fi
    pins_state=$(row_status_of "$row_path" 2)
    record_state=$(row_status_of "$row_path" 3)
    result=pass
    if [ "$cmp_state" != match ] || { [ "$pins_state" != match ] && [ "$pins_state" != none ]; } ||
      [ "$record_state" != match ]; then
      result=FAIL
      failures=$((failures + 1))
      if [ -f "$vendored_file" ]; then
        result="FAIL; vendored sha256 $(sha256_of "$vendored_file") size $(size_of "$vendored_file")"
      fi
    fi
    table_row "$row_path" "$source" "$toolchain" "$builder" "$rebuilt_sha" "$rebuilt_size" \
      "$cmp_state" "$pins_state" "$record_state" "$result" >>"$TMP/table"
  done <<<"$MANIFEST"

  while read -r vpath frozen flag; do
    [ -n "$vpath" ] || continue
    vendored_file="$repo/$CRATE/$vpath"
    pins_state=$(row_status_of "$vpath" 2)
    record_state=$(row_status_of "$vpath" 3)
    rebuilt_size="-"
    cmp_state="frozen-MISMATCH"
    if [ -f "$vendored_file" ]; then
      rebuilt_size=$(size_of "$vendored_file")
      [ "$(sha256_of "$vendored_file")" = "$frozen" ] && cmp_state="frozen-match"
    fi
    result="pass (exception, not rebuilt)"
    if [ "$cmp_state" != frozen-match ] || { [ "$pins_state" != match ] && [ "$pins_state" != none ]; } ||
      [ "$record_state" != match ]; then
      result="FAIL (exception, not rebuilt)"
      failures=$((failures + 1))
    fi
    table_row "$vpath" "exception" "-" "-" "-" "$rebuilt_size" "$cmp_state" "$pins_state" "$record_state" "$result" >>"$TMP/table"
  done <<<"$EXCEPTIONS"

  # No step may change a source worktree, the repository, or a vendored file.
  : >"$TMP/end-failures"
  while read -r tag commit; do
    if ! GIT_OPTIONAL_LOCKS=0 git -C "$work/src/oz-$tag" -c core.quotePath=false status --porcelain -z >"$TMP/oz-status" 2>/dev/null; then
      echo "end-check: git status of the $tag worktree failed" >>"$TMP/end-failures"
    elif [ -s "$TMP/oz-status" ]; then
      echo "end-check: the $tag worktree changed during the builds" >>"$TMP/end-failures"
    fi
  done <<<"$OZ_TAGS"
  if ! GIT_OPTIONAL_LOCKS=0 git -C "$repo" -c core.quotePath=false status --porcelain -z >"$TMP/status-after" 2>/dev/null ||
    ! cmp -s "$TMP/status-before" "$TMP/status-after"; then
    echo "end-check: git status of the repository root changed during the run" >>"$TMP/end-failures"
  fi
  vendored_digests "$repo" "$TMP/digests-after"
  if ! cmp -s "$TMP/digests-before" "$TMP/digests-after"; then
    echo "end-check: a vendored file changed during the run" >>"$TMP/end-failures"
  fi

  table_row file source toolchain builder "rebuilt sha256" size cmp WASM_PINS record result
  table_row --- --- --- --- --- --- --- --- --- ---
  cat "$TMP/table"
  cat "$TMP/tree-failures" "$TMP/end-failures"
  local tree_failures end_failures
  tree_failures=$(tree_failure_count)
  end_failures=$(awk 'END { print NR }' "$TMP/end-failures")
  if [ "$failures" != 0 ] || [ "$tree_failures" != 0 ] || [ "$end_failures" != 0 ]; then
    echo "$NAME: FAIL: $failures failing rows, $tree_failures tree check failures, $end_failures end-of-run check failures"
    return 1
  fi
  echo "$NAME: PASS: $n files rebuilt byte for byte, every exception at its frozen digest, every pin and record equal to its file"
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

[ $# -gt 0 ] || usage
case "$1" in
  --check-tree)
    shift
    mode_check_tree "$@"
    ;;
  --list-toolchains)
    shift
    [ $# -eq 0 ] || usage
    mode_list_toolchains
    ;;
  --rebuild-needed)
    shift
    mode_rebuild_needed "$@"
    ;;
  --gate)
    shift
    mode_gate "$@"
    ;;
  --exec)
    shift
    mode_exec "$@"
    ;;
  --repo-root | --oz-clone | --stellar-25 | --stellar-28 | --work) mode_full "$@" ;;
  *) usage ;;
esac

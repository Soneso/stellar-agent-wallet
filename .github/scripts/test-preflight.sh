#!/usr/bin/env bash
# Offline self-test of preflight.sh.
#
# Builds a scratch Git repository with one commit on main. It holds copies of
# the root manifest, lockfile, toolchain, every crates/*/Cargo.toml, four crate
# sources, and the cap85-beacon record of the smart-account crate. It also
# holds .github, CHANGELOG.md, CONTRIBUTING.md, the building guide, and the skill.
# Each case copies that repository, changes it on a branch, and runs
# preflight.sh against main.
#
# Planning cases compare the whole --list output with the expected gates. The
# package cases pin the clippy, rustdoc, and test packages, and check them
# against the fixture manifests with a TOML reader of their own. Execution
# cases run preflight.sh on a PATH with only the driver's tools and logging shims
# for python3, bash, cargo, actionlint, and shellcheck, and the scripts that
# preflight.sh executes by path are logging stubs. No real gate, cargo,
# actionlint, or shellcheck runs.
#
# The drift case checks the registry against the workflows. Every CI step
# that a registry entry names exists exactly once in its job and runs a
# command. Every step of a cited job that runs a command has a registry entry
# or a NOT_CARRIED entry. The case reads step names and run: keys only, never
# the commands.
#
# Usage: test-preflight.sh [--case <name>]
# Prints "preflight test: N of N passed" and exits 0, or lists each failed
# case with its output and exits 1. Needs bash 3.2 or later and Python 3.11
# or later.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
SCRIPT_REL=.github/scripts/preflight.sh
TMP=$(mktemp -d)
TMP=$(cd "$TMP" && pwd -P)
trap 'rm -rf "$TMP"' EXIT

# Git reads no global, system, or XDG configuration, and it commits with a
# placeholder identity, so the host's settings never reach a case.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 XDG_CONFIG_HOME="$TMP/xdg"
export GIT_AUTHOR_NAME="preflight self-test" GIT_AUTHOR_EMAIL=self-test@example.invalid
export GIT_COMMITTER_NAME="preflight self-test" GIT_COMMITTER_EMAIL=self-test@example.invalid

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "test-preflight.sh needs python3 3.11 or later" >&2
  exit 1
fi
REAL_BASH=$(command -v bash)
REAL_PYTHON=$(python3 -c 'import sys; print(sys.executable)')
FIXTURE="$TMP/fixture"

CASES="docs-only install-surface-doc deleted-install-surface-doc welcome-workflow ci-yml-only
python-check-script shell-check-script skill one-crate two-owners target-specific-edge
dev-dependency-edge root-manifest lockfile toolchain unowned-rust-path wallet-manifest
removed-member untracked-test-file fixture-markdown
committed-cross-scope-rename staged-rename-record spaces-and-an-apostrophe
full vendored contracts action-script invariants-helper duplicate-triggers changed-self-test
deleted-shell-script deleted-self-test unavailable-tool
exit-aggregation table bad-base malformed-manifest unloadable-install-surface-check
the-preflight-itself registry-completeness
drift drift-new-step drift-unnamed-step drift-removed-step drift-renamed-step
install-hint coverage-suppression coverage-unavailable coverage-written"

ALWAYS=(docs-style install-surface gate-tool-versions)
RUST=(fmt clippy rustdoc)
# The scripts that preflight.sh executes by path; an execution case replaces
# them with logging stubs.
DIRECT_SCRIPTS=(package-skill.sh publish-crates.sh test-mpp-interop.sh test-publish-crates-check.sh
  test-sdk-v17-interop.sh)
# The tools of the controlled PATH; nothing else resolves there.
DRIVER_TOOLS=(git awk grep sed sort uniq mktemp dirname basename cat tr wc rm mkdir env)

# The --full --list output on a branch that changes only Markdown: every gate
# record, in registry order, as <id><TAB><command>.
EXPECTED_REGISTRY=$(
  cat <<'EOF'
docs-style	python3 .github/scripts/check-docs-style.py
install-surface	python3 .github/scripts/check-install-surface.py
gate-tool-versions	bash .github/scripts/check-gate-tool-versions.sh
actionlint	actionlint
workflow-invariants	python3 .github/scripts/check-workflow-invariants.py
self-test:test-check-crates-exist.sh	bash .github/scripts/test-check-crates-exist.sh
self-test:test-check-docs-style.py	python3 .github/scripts/test-check-docs-style.py
self-test:test-check-gate-tool-versions.sh	bash .github/scripts/test-check-gate-tool-versions.sh
self-test:test-check-install-surface.py	python3 .github/scripts/test-check-install-surface.py
self-test:test-check-no-direct-sasignersetbaselined-emit.sh	bash .github/scripts/test-check-no-direct-sasignersetbaselined-emit.sh
self-test:test-check-ref-on-main.sh	bash .github/scripts/test-check-ref-on-main.sh
self-test:test-check-workflow-invariants.py	python3 .github/scripts/test-check-workflow-invariants.py
self-test:test-compare-crate-sums.py	python3 .github/scripts/test-compare-crate-sums.py
self-test:test-preflight.sh	bash .github/scripts/test-preflight.sh
self-test:test-publish-crates-check.sh	.github/scripts/test-publish-crates-check.sh
self-test:test-publish-crates-verify.sh	bash .github/scripts/test-publish-crates-verify.sh
self-test:test-rebuild-vendored-wasm.sh	bash .github/scripts/test-rebuild-vendored-wasm.sh
self-test:test-sync-labels.py	python3 .github/scripts/test-sync-labels.py
self-test:test-take-workflow.py	python3 .github/scripts/test-take-workflow.py
self-test:test-triage-workflow.py	python3 .github/scripts/test-triage-workflow.py
self-test:test-validate-unsigned-archive.py	python3 .github/scripts/test-validate-unsigned-archive.py
self-test:test-welcome-workflow.py	python3 .github/scripts/test-welcome-workflow.py
shellcheck-preflight	shellcheck -s bash .github/scripts/preflight.sh .github/scripts/test-preflight.sh
package-skill	.github/scripts/package-skill.sh --check
vendored-tree-check	bash .github/scripts/rebuild-vendored-wasm.sh --check-tree --repo-root .
publish-check	.github/scripts/publish-crates.sh --check
baseline-gate	bash .github/scripts/check-no-direct-sasignersetbaselined-emit.sh
fmt	cargo fmt --all -- --check
clippy	cargo clippy --all-targets --all-features -- -D warnings
rustdoc	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
test	cargo test --workspace --features test-helpers,test-hooks,test-loopback,verifier-registry
test-vendored-release-cfg	cargo test -p stellar-agent-smart-account --test vendored_wasm_release_cfg
machete	cargo machete
deny	cargo deny check
coverage	cargo llvm-cov --workspace --features test-helpers,test-hooks,test-loopback,verifier-registry --json --output-path cov.json
coverage-floors	python3 .github/scripts/check-coverage.py cov.json
interop:mpp	.github/scripts/test-mpp-interop.sh
interop:sdk-v17	.github/scripts/test-sdk-v17-interop.sh
EOF
)

# The CI steps of the cited jobs that run a command but mirror no gate, as
# workflow, job, step name, and the reason the preflight does not run them.
NOT_CARRIED=$(
  cat <<'EOF'
ci.yml	clippy	Install libudev (Linux hidapi)	installs Linux system headers on the runner
ci.yml	doc	Install libudev (Linux hidapi)	installs Linux system headers on the runner
ci.yml	test	Free disk space	reclaims runner disk space
ci.yml	test	Install libudev (Linux hidapi)	installs Linux system headers on the runner
ci.yml	test	Check each test-support feature set	the per-feature compile matrix runs in CI only
ci.yml	mpp-interop	Enable Corepack	activates Corepack on the runner
ci.yml	sdk-v17-interop	Enable Corepack	activates Corepack on the runner
coverage.yml	coverage	Free disk space	reclaims runner disk space
coverage.yml	coverage	Install libudev (Linux hidapi)	installs Linux system headers on the runner
install-surface.yml	install-surface	Self-test Python checks on Python 3.11	repeats the Python self-tests on a second interpreter
install-surface.yml	install-surface	Install actionlint	installs a gate tool on the runner
vendored-wasm.yml	check	Decide whether the change needs a rebuild	decides whether the CI rebuild jobs run
EOF
)
RUSTDOC_PREFIX='RUSTDOCFLAGS="-D warnings" '

fail() {
  echo "$*" >&2
  exit 1
}

# Prints the expected --list row of gate $1.
registry_row() {
  local row
  row=$(printf '%s\n' "$EXPECTED_REGISTRY" | awk -F '\t' -v id="$1" '$1 == id')
  if [ -z "$row" ]; then
    fail "no expected row for gate $1"
  fi
  printf '%s\n' "$row"
}

# Prints the expected --list output: one row per argument, each a gate id of
# EXPECTED_REGISTRY or "<id>=<command>" for a computed command.
expected_rows() {
  local argument
  for argument in "$@"; do
    case "$argument" in
      *=*) printf '%s\t%s\n' "${argument%%=*}" "${argument#*=}" ;;
      *) registry_row "$argument" ;;
    esac
  done
}

build_fixture() {
  local dir=$1 manifest file
  mkdir -p "$dir"
  cp "$ROOT/Cargo.toml" "$dir/Cargo.toml"
  for manifest in "$ROOT"/crates/*/Cargo.toml; do
    file=${manifest#"$ROOT"/}
    mkdir -p "$dir/$(dirname "$file")"
    cp "$manifest" "$dir/$file"
  done
  for file in Cargo.lock rust-toolchain.toml \
    crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/REFERENCE.md \
    crates/stellar-agent-sep7/src/lib.rs crates/stellar-agent-sep5/src/lib.rs \
    crates/stellar-agent-windows-identity/src/lib.rs crates/stellar-agent-test-support/src/lib.rs \
    CHANGELOG.md CONTRIBUTING.md docs/maintainers/building.md skills/stellar-agent-wallet/SKILL.md; do
    mkdir -p "$dir/$(dirname "$file")"
    cp "$ROOT/$file" "$dir/$file"
  done
  cp -R "$ROOT/.github" "$dir/.github"
  (cd "$dir" && git init -q -b main && git add -A && git commit -q -m fixture)
  mkdir -p "$dir/contracts/cap85-beacon/src" "$dir/crates/stellar-agent-sep7/tests"
}

# Fails unless the fixture holds the member manifests and the dependency
# shapes that the package cases read.
assert_fixture_complete() {
  python3 - "$1" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
problems = []
manifests = sorted(root.glob("crates/*/Cargo.toml"))
if len(manifests) != 36:
    problems.append(f"{len(manifests)} member manifests, expected 36")
top = tomllib.loads((root / "Cargo.toml").read_text())
for member in top["workspace"]["members"]:
    if not (root / member / "Cargo.toml").is_file():
        problems.append(f"no manifest for member {member}")
mcp = tomllib.loads((root / "crates/stellar-agent-mcp/Cargo.toml").read_text())
if mcp.get("dependencies", {}).get("stellar-agent-sep7", {}).get("workspace") is not True:
    problems.append("the MCP manifest does not inherit stellar-agent-sep7")
if "path" not in top["workspace"].get("dependencies", {}).get("stellar-agent-sep7", {}):
    problems.append("[workspace.dependencies] holds no stellar-agent-sep7 path")
core = tomllib.loads((root / "crates/stellar-agent-core/Cargo.toml").read_text())
windows = core.get("target", {}).get('cfg(target_os = "windows")', {}).get("dependencies", {})
if "stellar-agent-windows-identity" not in windows:
    problems.append("the core manifest has no Windows target table with stellar-agent-windows-identity")
for problem in problems:
    print(f"fixture incomplete: {problem}", file=sys.stderr)
raise SystemExit(1 if problems else 0)
PY
}

# Sets the paths of case $1: CASE_DIR, the fixture copy; STATE, the call log
# and status file of its shims; BIN, its controlled PATH directory.
set_case_paths() {
  CASE_DIR="$TMP/cases/$1"
  STATE="$TMP/cases/$1.state"
  BIN="$TMP/cases/$1.bin"
}

# Copies fixture $1 to the case directory and enters it.
copy_fixture() {
  set_case_paths "$CASE_NAME"
  cp -R "$1" "$CASE_DIR"
  cd "$CASE_DIR"
}

# Starts a planning case on a new branch of a fixture copy.
start_case() {
  copy_fixture "$FIXTURE"
  git checkout -q -b case
}

# Fails unless each path differs from main as a committed, staged, unstaged,
# or untracked change.
assert_changed() {
  local path
  for path in "$@"; do
    if git diff --quiet main -- "$path" && [ -z "$(git ls-files --others -- "$path")" ]; then
      fail "the fixture change did not modify $path"
    fi
  done
}

# Appends a line to each path and fails unless the change reached Git.
edit() {
  local path
  for path in "$@"; do
    printf '\n# preflight self-test edit\n' >>"$path"
  done
  assert_changed "$@"
}

# Runs preflight.sh --list --base main, with --full when the first argument
# is --full, and fails unless it exits 0 with nothing on stderr and prints
# exactly the rows the other arguments name (see expected_rows).
expect_list() {
  local rc=0 flags=(--list --base main)
  if [ "${1-}" = --full ]; then
    flags+=(--full)
    shift
  fi
  expected_rows "$@" >"$CASE_DIR.expected"
  "$REAL_BASH" "$SCRIPT_REL" "${flags[@]}" >"$CASE_DIR.actual" 2>"$CASE_DIR.stderr" || rc=$?
  if [ "$rc" -ne 0 ] || [ -s "$CASE_DIR.stderr" ]; then
    cat "$CASE_DIR.stderr" >&2
    fail "preflight.sh ${flags[*]} exited $rc"
  fi
  if ! diff -u "$CASE_DIR.expected" "$CASE_DIR.actual" >&2; then
    fail "the list differs from the expected gates"
  fi
}

# Prints "<packages>|<features>" for changed paths $@. The packages are the
# members that own a path, in path order, then the members that depend on an
# owner directly through any dependency table, sorted. The features are the
# offline test features that a selected package declares. It reads the case
# manifests apart from the planner of preflight.sh.
computed_packages() {
  python3 - "$CASE_DIR" "$@" <<'PY'
import pathlib
import posixpath
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
changed = sorted(sys.argv[2:])
workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
shared = workspace.get("dependencies", {})
manifests = {}
for directory in workspace["members"]:
    path = root / directory / "Cargo.toml"
    if path.is_file():
        manifests[directory] = tomllib.loads(path.read_text())


def uses(directory, manifest):
    tables = [manifest.get("dependencies", {}), manifest.get("dev-dependencies", {})]
    for target in manifest.get("target", {}).values():
        tables += [target.get("dependencies", {}), target.get("dev-dependencies", {})]
    found = set()
    for table in tables:
        for key, spec in table.items():
            if isinstance(spec, dict) and "path" in spec:
                found.add(posixpath.normpath(posixpath.join(directory, spec["path"])))
            elif isinstance(spec, dict) and spec.get("workspace") and "path" in shared.get(key, {}):
                found.add(posixpath.normpath(shared[key]["path"]))
    return found


owners = []
for path in changed:
    for directory in manifests:
        if path.startswith(directory + "/") and directory not in owners:
            owners.append(directory)
name = {directory: manifest["package"]["name"] for directory, manifest in manifests.items()}
dependents = sorted(
    name[directory]
    for directory, manifest in manifests.items()
    if directory not in owners and uses(directory, manifest) & set(owners)
)
selection = [name[directory] for directory in owners] + dependents
declared = set()
for directory, manifest in manifests.items():
    if name[directory] in selection:
        declared.update(manifest.get("features", {}))
wanted = ["test-helpers", "test-hooks", "test-loopback", "verifier-registry"]
print(" ".join(selection) + "|" + ",".join(feature for feature in wanted if feature in declared))
PY
}

# Fails unless the computed packages for changed paths $3... are the pinned
# packages $1 with the feature subset $2. Sets PACKAGE_GATES to explicit
# clippy, rustdoc, and test commands built from that pinned selection.
pin_packages() {
  local packages=$1 features=$2 computed package list operands="" test_command
  shift 2
  computed=$(computed_packages "$@")
  if [ "$computed" != "$packages|$features" ]; then
    fail "computed '$computed', pinned '$packages|$features'"
  fi
  read -r -a list <<<"$packages"
  for package in "${list[@]}"; do
    operands="$operands -p $package"
  done
  test_command="cargo test$operands"
  if [ -n "$features" ]; then
    test_command="$test_command --features $features"
  fi
  PACKAGE_GATES=(fmt "clippy=cargo clippy$operands --all-targets --all-features -- -D warnings"
    "rustdoc=${RUSTDOC_PREFIX}cargo doc --no-deps$operands --all-features" "test=$test_command")
}

# Prints the .github/scripts/ paths that EXPECTED_REGISTRY runs with
# interpreter $1, one per line.
registry_scripts() {
  printf '%s\n' "$EXPECTED_REGISTRY" | awk -F '\t' -v interpreter="$1" '
    split($2, words, " ") >= 2 && words[1] == interpreter && words[2] ~ /^\.github\/scripts\// { print words[2] }
  '
}

# Writes an executable shim or stub $1 that appends its name $2 and its
# arguments to the case call log. Each argument is logged as "ARG <bytes>:"
# and its exact bytes, so an argument cannot forge a log line. Kind $3
# decides the rest.
#   python  Runs the real python3 for a planner block (-) and for the two
#           probes of preflight.sh. For a script that EXPECTED_REGISTRY runs
#           with python3, it exits the configured status. Any other call
#           logs UNEXPECTED and exits 97.
#   bash    For a script that EXPECTED_REGISTRY runs with bash, it exits the
#           configured status. Any other call runs the real bash.
#   cargo   Exits the configured status of "cargo <subcommand>", or of
#           "cargo <subcommand> --version" for that probe. A passing
#           llvm-cov run writes the file its --output-path names.
#   plain   Exits the configured status of its name.
# A configured status is a "<key>=<status>" line of the case status file.
# The python and bash shims key it by the script path. The default is 0.
write_shim() {
  local file=$1 name=$2 kind=$3 gates=""
  case "$kind" in
    python) gates=$(registry_scripts python3) ;;
    bash) gates=$(registry_scripts bash) ;;
  esac
  {
    printf '#!%s\n' "$REAL_BASH"
    printf 'STATE=%q\nNAME=%q\nREAL_BASH=%q\nREAL_PYTHON=%q\nGATES=%q\n' \
      "$STATE" "$name" "$REAL_BASH" "$REAL_PYTHON" "$gates"
    cat <<'SHIM'
log_call() {
  local LC_ALL=C argument
  {
    printf 'CALL %s\n' "$NAME"
    for argument in "$@"; do
      printf 'ARG %d:%s\n' "${#argument}" "$argument"
    done
  } >>"$STATE/calls.log"
}
status_of() {
  local line
  while IFS= read -r line; do
    if [ "${line%%=*}" = "$1" ]; then
      echo "${line#*=}"
      return 0
    fi
  done <"$STATE/status"
  echo 0
}
is_gate() {
  case $'\n'"$GATES"$'\n' in
    *$'\n'"$1"$'\n'*) return 0 ;;
  esac
  return 1
}
log_call "$@"
SHIM
    case "$kind" in
      python)
        cat <<'SHIM'
case "${1-}" in
  -) exec "$REAL_PYTHON" "$@" ;;
  -c)
    case "${2-}" in
      'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' | 'import yaml')
        exec "$REAL_PYTHON" "$@"
        ;;
    esac
    ;;
  *)
    if is_gate "${1-}"; then
      exit "$(status_of "$1")"
    fi
    ;;
esac
echo UNEXPECTED >>"$STATE/calls.log"
exit 97
SHIM
        ;;
      bash)
        cat <<'SHIM'
if is_gate "${1-}"; then
  exit "$(status_of "$1")"
fi
exec "$REAL_BASH" "$@"
SHIM
        ;;
      cargo)
        cat <<'SHIM'
key="cargo ${1-}"
if [ "${2-}" = --version ]; then
  key="$key --version"
fi
status=$(status_of "$key")
if [ "${1-}" = llvm-cov ] && [ "$status" = 0 ]; then
  previous=""
  for argument in "$@"; do
    if [ "$previous" = --output-path ]; then
      printf '{"written by": "the cargo shim"}\n' >"$argument"
    fi
    previous=$argument
  done
fi
exit "$status"
SHIM
        ;;
      plain)
        cat <<'SHIM'
exit "$(status_of "$NAME")"
SHIM
        ;;
    esac
  } >"$file"
  chmod +x "$file"
}

# Starts an execution case. Its fixture copy commits logging stubs on main
# for the scripts that preflight.sh executes by path, then checks out a new
# branch. BIN, the controlled PATH directory, holds the driver tools and the
# python3 and bash shims. Each case adds the other shims it needs.
start_run_case() {
  local script tool path
  copy_fixture "$FIXTURE"
  mkdir -p "$STATE" "$BIN"
  : >"$STATE/calls.log"
  : >"$STATE/status"
  for script in "${DIRECT_SCRIPTS[@]}"; do
    write_shim ".github/scripts/$script" ".github/scripts/$script" plain
  done
  git commit -q -am "logging stubs"
  git checkout -q -b case
  for tool in "${DRIVER_TOOLS[@]}"; do
    path=$(command -v "$tool")
    case "$path" in
      /*) ln -s "$path" "$BIN/$tool" ;;
      *) fail "$tool does not resolve to a file" ;;
    esac
  done
  write_shim "$BIN/python3" python3 python
  write_shim "$BIN/bash" bash bash
}

# Runs preflight.sh in the case directory on the controlled PATH. The
# combined output goes to $CASE_DIR.out and the exit code to RUN_RC.
run_preflight() {
  RUN_RC=0
  PATH="$BIN" "$REAL_BASH" "$SCRIPT_REL" --base main "$@" >"$CASE_DIR.out" 2>&1 || RUN_RC=$?
}

# A call record is the JSON array of a call's name and arguments, on one
# line. JSON escapes every control character, and the array keeps each
# argument whole, so equal records mean equal argument vectors.

# Prints its arguments as one call record.
argv_record() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "$@"
}

# Prints one call record per command on standard input. The words are split
# at blanks, since the expected commands hold no quotes.
command_records() {
  python3 -c 'import json, sys; [print(json.dumps(line.split())) for line in sys.stdin.read().splitlines()]'
}

# Prints command $1 as one call record.
command_record() {
  printf '%s\n' "$1" | command_records
}

# Writes the call log to $CASE_DIR.calls as call records, one per line,
# without the python3 planner blocks and probes. An UNEXPECTED marker of the
# python3 shim becomes the line "UNEXPECTED". A log line outside the format
# fails the case.
record_gate_calls() {
  python3 - "$STATE/calls.log" >"$CASE_DIR.calls" <<'PY' || fail "the call log is malformed"
import json
import sys

data = open(sys.argv[1], "rb").read()
call = None


def finish():
    if call is not None and not (call[0] == "python3" and call[1:2] in (["-"], ["-c"])):
        print(json.dumps(call))


position = 0
while position < len(data):
    end = data.index(b"\n", position)
    line = data[position:end]
    if line.startswith(b"CALL "):
        finish()
        call = [line[5:].decode("utf-8", "surrogateescape")]
        position = end + 1
    elif line.startswith(b"ARG ") and call is not None:
        colon = data.index(b":", position)
        size = int(data[position + 4:colon])
        start = colon + 1
        if data[start + size:start + size + 1] != b"\n":
            raise SystemExit(f"malformed argument at byte {position}")
        call.append(data[start:start + size].decode("utf-8", "surrogateescape"))
        position = start + size + 1
    elif line == b"UNEXPECTED":
        finish()
        call = None
        print("UNEXPECTED")
        position = end + 1
    else:
        raise SystemExit(f"malformed call log line at byte {position}")
finish()
PY
}

# Fails unless the gates ran exactly as the arguments list them, in order.
# Each argument is a command; calls compare as argument vectors.
expect_calls() {
  record_gate_calls
  printf '%s\n' "$@" | command_records >"$CASE_DIR.expected-calls"
  if ! cmp -s "$CASE_DIR.expected-calls" "$CASE_DIR.calls"; then
    diff -u "$CASE_DIR.expected-calls" "$CASE_DIR.calls" >&2
    fail "the gates ran differently"
  fi
}

# Rejects unexpected Python invocations and cargo metadata calls. Other calls
# must match an expected registry command, a Cargo requirement probe, or an
# extra call supplied by the case. Registry commands omit their environment
# prefix. Calls compare as call records, and each extra call is an
# argv_record line.
assert_clean_calls() {
  local id command
  record_gate_calls
  if grep -qx UNEXPECTED "$CASE_DIR.calls"; then
    fail "python3 ran outside the planner blocks, the probes, and the gates"
  fi
  if grep -qF '["cargo", "metadata"' "$CASE_DIR.calls"; then
    fail "cargo metadata ran"
  fi
  {
    {
      while IFS=$'\t' read -r id command; do
        if [ "$id" = rustdoc ]; then
          command=${command#"$RUSTDOC_PREFIX"}
        fi
        printf '%s\n' "$command"
      done <<<"$EXPECTED_REGISTRY"
      printf '%s\n' "cargo llvm-cov --version" "cargo machete --version" "cargo deny --version"
    } | command_records
    if [ "$#" -gt 0 ]; then
      printf '%s\n' "$@"
    fi
  } >"$CASE_DIR.allowed-calls"
  if grep -vxF -f "$CASE_DIR.allowed-calls" "$CASE_DIR.calls" >"$CASE_DIR.stray-calls"; then
    cat "$CASE_DIR.stray-calls" >&2
    fail "the run made calls outside the expected registry"
  fi
}

# Fails unless the run output holds line $1.
expect_line() {
  if ! grep -qxF -- "$1" "$CASE_DIR.out"; then
    cat "$CASE_DIR.out" >&2
    fail "the run printed no line '$1'"
  fi
}

# Fails unless the run exited $1 and its last line is $2.
expect_end() {
  if [ "$RUN_RC" -ne "$1" ] || [ "$(tail -n 1 "$CASE_DIR.out")" != "$2" ]; then
    cat "$CASE_DIR.out" >&2
    fail "the run exited $RUN_RC, expected $1 with the last line '$2'"
  fi
}

# Prints the table rows and the summary line of run output $1: the lines
# after the last RC= line, without blank lines.
table_lines() {
  awk '/^RC=/ { n = 0; next } NF { rows[++n] = $0 } END { for (i = 1; i <= n; i++) print rows[i] }' "$1"
}

# Prints the Node version that the fixture's ci.yml sets up.
fixture_node_version() {
  awk '$1 == "node-version:" { print $2; exit }' .github/workflows/ci.yml
}

# Prints install_hint $1 of the case's preflight.sh, sourced.
hint_of() {
  # shellcheck disable=SC2016 # The inner shell expands its own arguments.
  "$REAL_BASH" -c '. "$1" && install_hint "$2"' hint "$SCRIPT_REL" "$1"
}

# Fails unless the test-* files in .github/scripts/ of directory $1 equal the
# paths that preflight.sh registers: each self-test record and each interop
# script.
check_registry_completeness() {
  local dir=$1 file
  (cd "$dir" && "$REAL_BASH" "$SCRIPT_REL" --full --list --base main) >"$dir.list" || return 1
  awk -F '\t' '
    $1 ~ /^self-test:/ { print ".github/scripts/" substr($1, 11) }
    $1 ~ /^interop:/ { print $2 }
  ' "$dir.list" | sort >"$dir.registered"
  for file in "$dir"/.github/scripts/test-*; do
    if [ -f "$file" ]; then
      printf '%s\n' "${file#"$dir"/}"
    fi
  done | sort >"$dir.present"
  diff -u "$dir.registered" "$dir.present" >&2
}

# Prints one line per step of job $2 in workflow file $1, as
# <line><TAB><runs><TAB><name>. A step is an item of the job's steps:
# sequence. runs is 1 when the step has a run: key at its key indentation,
# and name is its name: value or empty. Exits 1 when the file has no such
# job.
workflow_steps() {
  awk -v job="$2" '
    function indent_of(text) {
      match(text, /^ */)
      return RLENGTH
    }
    function flush() {
      if (step_line) printf "%d\t%d\t%s\n", step_line, step_runs, step_name
      step_line = 0
      step_runs = 0
      step_name = ""
    }
    function take(key, value, quote) {
      if (key ~ /^name:/) {
        value = key
        sub(/^name:[ \t]*/, "", value)
        sub(/[ \t]+#.*$/, "", value)
        quote = substr(value, 1, 1)
        if (length(value) > 1 && (quote == "\"" || quote == sprintf("%c", 39)) && substr(value, length(value)) == quote) {
          value = substr(value, 2, length(value) - 2)
        }
        step_name = value
      } else if (key ~ /^run:/) {
        step_runs = 1
      }
    }
    BEGIN { job_indent = -1 }
    {
      line = $0
      sub(/\r$/, "", line)
      if (line ~ /^[ \t]*$/ || line ~ /^[ \t]*#/) next
      indent = indent_of(line)
      text = substr(line, indent + 1)
      if (indent == 0) {
        flush()
        in_jobs = (text ~ /^jobs:[ \t]*$/)
        in_target = 0
        next
      }
      if (!in_jobs) next
      if (job_indent < 0) job_indent = indent
      if (indent == job_indent) {
        flush()
        in_target = (text == job ":")
        if (in_target) found = 1
        in_steps = 0
        item_indent = -1
        next
      }
      if (!in_target) next
      if (!in_steps) {
        if (text ~ /^steps:[ \t]*$/) {
          in_steps = 1
          steps_indent = indent
        }
        next
      }
      if (indent < steps_indent || (indent == steps_indent && text !~ /^- /)) {
        flush()
        in_steps = 0
        next
      }
      if (text ~ /^- / && (item_indent < 0 || indent == item_indent)) {
        flush()
        item_indent = indent
        step_line = FNR
        rest = substr(text, 2)
        sub(/^ +/, "", rest)
        key_indent = indent + length(text) - length(rest)
        take(rest)
        next
      }
      if (indent == key_indent) take(text)
    }
    END {
      flush()
      exit found ? 0 : 1
    }
  ' "$1"
}

# Checks the registry of the preflight.sh in directory $1 against the
# workflows there. Each problem prints one line that names the workflow, the
# job, and the step. Returns 1 when there is a problem.
check_drift() {
  local dir=$1 status=0 workflow job
  {
    # shellcheck disable=SC2016 # The inner shell expands its own argument.
    (cd "$dir" && "$REAL_BASH" -c '. "$1" && registry_records' records "$SCRIPT_REL") |
      awk -F '\t' '$4 != "-" { print $4 "\t" $5 "\t" $6 "\tregistry entry " $1 }'
    printf '%s\n' "$NOT_CARRIED" | awk -F '\t' '{ print $1 "\t" $2 "\t" $3 "\tthe not-carried list" }'
  } >"$dir.citations"
  while IFS=$'\t' read -r workflow job; do
    if [ ! -f "$dir/.github/workflows/$workflow" ]; then
      echo "drift: no workflow $workflow" >&2
      status=1
      continue
    fi
    if ! workflow_steps "$dir/.github/workflows/$workflow" "$job" >"$dir.steps"; then
      echo "drift: $workflow has no job $job" >&2
      status=1
      continue
    fi
    awk -F '\t' -v wf="$workflow" -v job="$job" '
      FILENAME == ARGV[1] {
        if ($1 != wf || $2 != job) next
        if (!($3 in owner)) {
          names[++cited] = $3
          owner[$3] = $4
        } else if ((owner[$3] ~ /^registry/) != ($4 ~ /^registry/)) {
          printf "drift: %s job %s: step \047%s\047 is in the registry and in the not-carried list\n", wf, job, $3
          bad = 1
        }
        next
      }
      {
        if ($2 == 1) runs++
        if ($3 != "") {
          seen[$3]++
          step_runs[$3] = $2
        }
        if ($2 == 1 && $3 == "") {
          printf "drift: %s job %s: the step at line %d runs a command and has no name\n", wf, job, $1
          bad = 1
        } else if ($2 == 1 && !($3 in owner)) {
          printf "drift: %s job %s: step \047%s\047 runs a command without a registry entry\n", wf, job, $3
          bad = 1
        }
      }
      END {
        for (i = 1; i <= cited; i++) {
          name = names[i]
          if (!(name in seen)) {
            printf "drift: %s job %s: no step \047%s\047 (%s)\n", wf, job, name, owner[name]
            bad = 1
          } else if (seen[name] > 1) {
            printf "drift: %s job %s: %d steps named \047%s\047, expected one\n", wf, job, seen[name], name
            bad = 1
          } else if (!step_runs[name]) {
            printf "drift: %s job %s: step \047%s\047 runs no command (%s)\n", wf, job, name, owner[name]
            bad = 1
          }
        }
        if (runs != cited) {
          printf "drift: %s job %s: %d steps run a command, and the registry and the not-carried list name %d\n", wf, job, runs, cited
          bad = 1
        }
        exit bad
      }
    ' "$dir.citations" "$dir.steps" >&2 || status=1
  done < <(cut -f 1,2 "$dir.citations" | sort -u)
  return "$status"
}

# Replaces the one line of file $1 that equals $2 with the lines $3...; no
# further argument deletes the line.
replace_line() {
  local file=$1 old=$2
  shift 2
  if [ "$(grep -cxF -- "$old" "$file")" -ne 1 ]; then
    fail "$file holds no single line '$old'"
  fi
  printf '%s\n' "$@" >"$file.lines"
  awk -v old="$old" -v lines="$file.lines" -v count="$#" '
    $0 == old {
      if (count > 0) while ((getline line < lines) > 0) print line
      next
    }
    { print }
  ' "$file" >"$file.new"
  mv "$file.new" "$file"
  rm "$file.lines"
}

# Fails unless the drift check fails in directory $1 and prints every line
# $2... as a whole line.
expect_drift() {
  local dir=$1 message
  shift
  if check_drift "$dir" 2>"$dir.drift"; then
    fail "the drift check passed"
  fi
  for message in "$@"; do
    if ! grep -qxF -- "$message" "$dir.drift"; then
      cat "$dir.drift" >&2
      fail "the drift check printed no line '$message'"
    fi
  done
}

# CHANGELOG.md is Markdown outside the surface scope.
case_docs_only() {
  start_case
  edit CHANGELOG.md
  expect_list "${ALWAYS[@]}"
}

# The install-surface check reads CONTRIBUTING.md, and its self-test injects
# into copies of the files that check reads.
case_install_surface_doc() {
  start_case
  edit CONTRIBUTING.md
  expect_list "${ALWAYS[@]}" self-test:test-check-install-surface.py
}

# A deleted path of the surface scope selects the self-test too: a case that
# injects into the deleted file fails.
case_deleted_install_surface_doc() {
  start_case
  git rm -q docs/maintainers/building.md
  git commit -q -m "remove the building guide"
  assert_changed docs/maintainers/building.md
  expect_list "${ALWAYS[@]}" self-test:test-check-install-surface.py
}

case_welcome_workflow() {
  start_case
  edit .github/workflows/welcome.yml
  expect_list "${ALWAYS[@]}" actionlint workflow-invariants self-test:test-welcome-workflow.py
}

case_ci_yml_only() {
  start_case
  edit .github/workflows/ci.yml
  expect_list "${ALWAYS[@]}" actionlint
}

case_python_check_script() {
  start_case
  edit .github/scripts/check-docs-style.py
  expect_list "${ALWAYS[@]}" self-test:test-check-docs-style.py
}

case_shell_check_script() {
  start_case
  edit .github/scripts/check-gate-tool-versions.sh
  expect_list "${ALWAYS[@]}" self-test:test-check-gate-tool-versions.sh \
    "shellcheck-changed=shellcheck -s bash .github/scripts/check-gate-tool-versions.sh"
}

case_skill() {
  start_case
  edit skills/stellar-agent-wallet/SKILL.md
  expect_list "${ALWAYS[@]}" self-test:test-check-install-surface.py package-skill
}

# The MCP manifest inherits stellar-agent-sep7 from [workspace.dependencies].
case_one_crate() {
  start_case
  edit crates/stellar-agent-sep7/src/lib.rs
  pin_packages "stellar-agent-sep7 stellar-agent-mcp" test-helpers crates/stellar-agent-sep7/src/lib.rs
  expect_list "${ALWAYS[@]}" "${PACKAGE_GATES[@]}"
}

case_two_owners() {
  start_case
  edit crates/stellar-agent-sep7/src/lib.rs crates/stellar-agent-sep5/src/lib.rs
  pin_packages "stellar-agent-sep5 stellar-agent-sep7 stellar-agent-cli stellar-agent-mcp stellar-agent-pool" \
    test-helpers crates/stellar-agent-sep7/src/lib.rs crates/stellar-agent-sep5/src/lib.rs
  expect_list "${ALWAYS[@]}" "${PACKAGE_GATES[@]}"
}

# Core and headless-keyring depend on windows-identity only in their Windows
# target tables.
case_target_specific_edge() {
  start_case
  edit crates/stellar-agent-windows-identity/src/lib.rs
  pin_packages "stellar-agent-windows-identity stellar-agent-core stellar-agent-headless-keyring" test-helpers \
    crates/stellar-agent-windows-identity/src/lib.rs
  expect_list "${ALWAYS[@]}" "${PACKAGE_GATES[@]}"
}

# Most members reach test-support through a dev-dependency path; the
# smart-account crate is among them.
case_dev_dependency_edge() {
  start_case
  edit crates/stellar-agent-test-support/src/lib.rs
  pin_packages "stellar-agent-test-support stellar-agent-approval-remote stellar-agent-approval-ui \
stellar-agent-claimable stellar-agent-cli stellar-agent-core stellar-agent-defi stellar-agent-defindex \
stellar-agent-dex stellar-agent-mcp stellar-agent-mpp stellar-agent-network stellar-agent-nonce \
stellar-agent-pool stellar-agent-sep43 stellar-agent-sep48 stellar-agent-sep53 stellar-agent-sep7 \
stellar-agent-smart-account stellar-agent-stablecoin stellar-agent-toolsets-install \
stellar-agent-toolsets-runtime stellar-agent-x402" test-helpers,test-hooks,test-loopback,verifier-registry \
    crates/stellar-agent-test-support/src/lib.rs
  expect_list "${ALWAYS[@]}" "${PACKAGE_GATES[@]}" test-vendored-release-cfg
}

case_root_manifest() {
  start_case
  edit Cargo.toml
  expect_list "${ALWAYS[@]}" self-test:test-check-install-surface.py "${RUST[@]}" test \
    test-vendored-release-cfg
}

case_lockfile() {
  start_case
  edit Cargo.lock
  expect_list "${ALWAYS[@]}" "${RUST[@]}" test test-vendored-release-cfg
}

case_toolchain() {
  start_case
  edit rust-toolchain.toml
  expect_list "${ALWAYS[@]}" "${RUST[@]}" test test-vendored-release-cfg
}

case_unowned_rust_path() {
  start_case
  mkdir -p tests
  edit tests/unowned.rs
  expect_list "${ALWAYS[@]}" "${RUST[@]}" test test-vendored-release-cfg
}

# The install-surface check reads the binstall metadata of the wallet crate
# manifests.
case_wallet_manifest() {
  start_case
  edit crates/stellar-agent-cli/Cargo.toml
  pin_packages stellar-agent-cli test-helpers crates/stellar-agent-cli/Cargo.toml
  expect_list "${ALWAYS[@]}" self-test:test-check-install-surface.py "${PACKAGE_GATES[@]}"
}

case_removed_member() {
  start_case
  git rm -q -r crates/stellar-agent-sep53
  git commit -q -m "remove sep53"
  assert_changed crates/stellar-agent-sep53/Cargo.toml
  expect_list "${ALWAYS[@]}" "${RUST[@]}" test test-vendored-release-cfg
}

case_untracked_test_file() {
  start_case
  printf '#[test]\nfn new_case() {}\n' >crates/stellar-agent-sep7/tests/new_case.rs
  assert_changed crates/stellar-agent-sep7/tests/new_case.rs
  pin_packages "stellar-agent-sep7 stellar-agent-mcp" test-helpers crates/stellar-agent-sep7/tests/new_case.rs
  expect_list "${ALWAYS[@]}" "${PACKAGE_GATES[@]}"
}

# Markdown under the test fixtures of a crate is outside the surface scope.
case_fixture_markdown() {
  start_case
  mkdir -p crates/stellar-agent-sep7/tests/fixtures
  printf '# Fixture\n' >crates/stellar-agent-sep7/tests/fixtures/notes.md
  assert_changed crates/stellar-agent-sep7/tests/fixtures/notes.md
  pin_packages "stellar-agent-sep7 stellar-agent-mcp" test-helpers \
    crates/stellar-agent-sep7/tests/fixtures/notes.md
  expect_list "${ALWAYS[@]}" "${PACKAGE_GATES[@]}"
}

case_committed_cross_scope_rename() {
  start_case
  git mv skills/stellar-agent-wallet/SKILL.md docs/skill.md
  git commit -q -m "move the skill"
  assert_changed skills/stellar-agent-wallet/SKILL.md docs/skill.md
  expect_list "${ALWAYS[@]}" self-test:test-check-install-surface.py package-skill
}

# The staged rename has two NUL-delimited paths outside the Rust scope.
# Its source, xx/Cargo.toml, has a three-byte directory prefix.
case_staged_rename_record() {
  copy_fixture "$FIXTURE"
  mkdir xx
  printf '[package]\nname = "xx"\n' >xx/Cargo.toml
  git add xx/Cargo.toml
  git commit -q -m "add xx"
  git checkout -q -b case
  git mv xx/Cargo.toml yy.txt
  git status --porcelain=v1 >"$CASE_DIR.porcelain"
  grep -qxF 'R  xx/Cargo.toml -> yy.txt' "$CASE_DIR.porcelain" || fail "git status shows no rename record"
  assert_changed xx/Cargo.toml yy.txt
  expect_list "${ALWAYS[@]}"
}

case_spaces_and_an_apostrophe() {
  local shellcheck_call
  start_case
  : >".github/scripts/with space.sh"
  : >".github/scripts/it's.sh"
  assert_changed ".github/scripts/with space.sh" ".github/scripts/it's.sh"
  expect_list "${ALWAYS[@]}" \
    "shellcheck-changed=shellcheck -s bash '.github/scripts/it'\"'\"'s.sh' '.github/scripts/with space.sh'"

  # Execution passes the two pathnames to shellcheck as two arguments.
  CASE_NAME="$CASE_NAME-run"
  start_run_case
  : >".github/scripts/with space.sh"
  : >".github/scripts/it's.sh"
  write_shim "$BIN/shellcheck" shellcheck plain
  run_preflight
  expect_end 0 "preflight: 4 gates run, 0 failed, 0 unavailable"
  shellcheck_call=$(argv_record shellcheck -s bash ".github/scripts/it's.sh" ".github/scripts/with space.sh")
  record_gate_calls
  if [ "$(grep -c '^\["shellcheck"' "$CASE_DIR.calls")" -ne 1 ] ||
    ! grep -qxF -- "$shellcheck_call" "$CASE_DIR.calls"; then
    cat "$CASE_DIR.calls" >&2
    fail "shellcheck received other arguments"
  fi
  assert_clean_calls "$shellcheck_call"
}

case_full() {
  local ids
  start_case
  edit CONTRIBUTING.md
  read -r -a ids <<<"$(printf '%s\n' "$EXPECTED_REGISTRY" | awk -F '\t' '{ printf "%s ", $1 }')"
  if [ "${#ids[@]}" -ne 38 ]; then
    fail "the expected registry holds ${#ids[@]} rows, expected 38"
  fi
  expect_list --full "${ids[@]}"
}

# The vendored REFERENCE.md is Markdown outside the surface scope.
case_vendored() {
  start_case
  edit crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/REFERENCE.md
  pin_packages "stellar-agent-smart-account stellar-agent-approval-remote stellar-agent-cli \
stellar-agent-defindex stellar-agent-dex stellar-agent-mcp stellar-agent-webauthn-bridge" test-helpers \
    crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/REFERENCE.md
  expect_list "${ALWAYS[@]}" vendored-tree-check "${PACKAGE_GATES[@]}" test-vendored-release-cfg
}

case_contracts() {
  start_case
  printf '// extra\n' >contracts/cap85-beacon/src/extra.rs
  assert_changed contracts/cap85-beacon/src/extra.rs
  expect_list "${ALWAYS[@]}" vendored-tree-check
}

case_action_script() {
  start_case
  edit .github/actions/macos-sign-notarize/sign-notarize.sh
  expect_list "${ALWAYS[@]}" actionlint workflow-invariants \
    "shellcheck-changed=shellcheck -s bash .github/actions/macos-sign-notarize/sign-notarize.sh"
}

# release.yml names the helper, so the computed input set of the invariants
# gate holds it; the helper has no self-test.
case_invariants_helper() {
  start_case
  # shellcheck disable=SC2016 # The inner shell expands its own argument.
  "$REAL_BASH" -c '. "$1" && invariant_script_paths' paths "$SCRIPT_REL" >"$CASE_DIR.inputs"
  if ! grep -qxF .github/scripts/release-preflight-version-check.sh "$CASE_DIR.inputs"; then
    cat "$CASE_DIR.inputs" >&2
    fail "the invariants inputs lack release-preflight-version-check.sh"
  fi
  edit .github/scripts/release-preflight-version-check.sh
  expect_list "${ALWAYS[@]}" workflow-invariants \
    "shellcheck-changed=shellcheck -s bash .github/scripts/release-preflight-version-check.sh"
}

case_duplicate_triggers() {
  start_case
  edit .github/scripts/check-docs-style.py .github/scripts/test-check-docs-style.py
  expect_list "${ALWAYS[@]}" self-test:test-check-docs-style.py
}

case_changed_self_test() {
  start_case
  edit .github/scripts/test-compare-crate-sums.py
  expect_list "${ALWAYS[@]}" self-test:test-compare-crate-sums.py
}

# A deleted script still selects the gates of its scope, but it is never an
# operand of the shellcheck-changed gate.
case_deleted_shell_script() {
  start_case
  git rm -q .github/scripts/check-ref-on-main.sh
  git commit -q -m "remove check-ref-on-main.sh"
  assert_changed .github/scripts/check-ref-on-main.sh
  expect_list "${ALWAYS[@]}" workflow-invariants self-test:test-check-ref-on-main.sh
}

# A deleted self-test file selects neither its own record nor shellcheck.
case_deleted_self_test() {
  start_case
  git rm -q .github/scripts/test-check-ref-on-main.sh
  assert_changed .github/scripts/test-check-ref-on-main.sh
  expect_list "${ALWAYS[@]}"
}

case_unavailable_tool() {
  local version
  start_run_case
  edit .github/workflows/ci.yml
  if (
    PATH=$BIN
    command -v actionlint >/dev/null 2>&1
  ); then
    fail "actionlint resolves on the controlled PATH"
  fi
  run_preflight
  version=$(sed -n 's/.*actionlint_\([0-9][0-9.]*\)_linux_amd64.*/\1/p' .github/workflows/install-surface.yml)
  [ -n "$version" ] || fail "install-surface.yml pins no actionlint archive"
  expect_line "- \`actionlint\`: unavailable (actionlint: brew install actionlint, or the $version release archive)"
  expect_end 1 "preflight: 3 gates run, 0 failed, 1 unavailable"
  expect_calls "python3 .github/scripts/check-docs-style.py" "python3 .github/scripts/check-install-surface.py" \
    "bash .github/scripts/check-gate-tool-versions.sh"
  assert_clean_calls
}

# Runs the exit aggregation scenario: ci.yml and check-docs-style.py change,
# actionlint exits 3, and every other gate exits 0.
run_exit_aggregation() {
  start_run_case
  edit .github/workflows/ci.yml .github/scripts/check-docs-style.py
  write_shim "$BIN/actionlint" actionlint plain
  echo actionlint=3 >>"$STATE/status"
  run_preflight
}

case_exit_aggregation() {
  run_exit_aggregation
  expect_line "- \`actionlint\`: exit 3"
  expect_end 1 "preflight: 5 gates run, 1 failed, 0 unavailable"
  expect_calls "python3 .github/scripts/check-docs-style.py" "python3 .github/scripts/check-install-surface.py" \
    "bash .github/scripts/check-gate-tool-versions.sh" "actionlint" "python3 .github/scripts/test-check-docs-style.py"
  assert_clean_calls
}

# Reads the table of the exit aggregation run, and runs that scenario first
# when this case runs alone.
case_table() {
  local node rows
  if [ -f "$TMP/cases/exit-aggregation.out" ]; then
    set_case_paths exit-aggregation
    cd "$CASE_DIR"
  else
    run_exit_aggregation
  fi
  node=$(fixture_node_version)
  table_lines "$CASE_DIR.out" >"$CASE_DIR.table"
  {
    printf '%s\n' \
      "- \`python3 .github/scripts/check-docs-style.py\`: exit 0" \
      "- \`python3 .github/scripts/check-install-surface.py\`: exit 0" \
      "- \`bash .github/scripts/check-gate-tool-versions.sh\`: exit 0" \
      "- \`actionlint\`: exit 3" \
      "- \`python3 .github/scripts/test-check-docs-style.py\`: exit 0" \
      "- \`.github/scripts/test-mpp-interop.sh\`: not run (--full; needs Node $node and Corepack)" \
      "- \`.github/scripts/test-sdk-v17-interop.sh\`: not run (--full; needs Node $node and Corepack)" \
      "preflight: 5 gates run, 1 failed, 0 unavailable"
  } >"$CASE_DIR.expected-table"
  if ! diff -u "$CASE_DIR.expected-table" "$CASE_DIR.table" >&2; then
    fail "the table differs"
  fi
  rows=$(grep -c '^- ' "$CASE_DIR.table" || true)
  if [ "$rows" -ne 7 ]; then
    fail "the table holds $rows rows, expected 7"
  fi
  # shellcheck disable=SC2016 # The backticks are literal row characters.
  if grep '^- ' "$CASE_DIR.table" |
    grep -vE '^- `[^`]+`: (exit [0-9]+|unavailable \(.+\)|not run \(.+\))$' >&2; then
    fail "a table row has another form"
  fi
  if ! tail -n 1 "$CASE_DIR.table" | grep -qE '^preflight: [0-9]+ gates run, [0-9]+ failed, [0-9]+ unavailable$'; then
    fail "the summary line has another form"
  fi
  assert_clean_calls
}

case_bad_base() {
  local rc=0
  start_case
  "$REAL_BASH" "$SCRIPT_REL" --list --base no-such-ref >"$CASE_DIR.out" 2>&1 || rc=$?
  if [ "$rc" -ne 2 ] || [ "$(cat "$CASE_DIR.out")" != \
    "preflight: cannot find a merge base with no-such-ref; run git fetch origin main or pass --base <ref>" ]; then
    cat "$CASE_DIR.out" >&2
    fail "a bad base exited $rc"
  fi
}

case_malformed_manifest() {
  local rc=0
  start_case
  printf '[\n' >crates/stellar-agent-sep5/Cargo.toml
  edit crates/stellar-agent-sep5/src/lib.rs
  assert_changed crates/stellar-agent-sep5/Cargo.toml
  "$REAL_BASH" "$SCRIPT_REL" --list --base main >"$CASE_DIR.out" 2>"$CASE_DIR.err" || rc=$?
  if [ "$rc" -ne 2 ] || ! grep -qF crates/stellar-agent-sep5/Cargo.toml "$CASE_DIR.err" || [ -s "$CASE_DIR.out" ]; then
    cat "$CASE_DIR.out" "$CASE_DIR.err" >&2
    fail "a malformed manifest exited $rc"
  fi
}

# A check-install-surface.py that does not load stops the planner, and the
# message names it.
case_unloadable_install_surface_check() {
  local rc=0
  start_case
  printf 'def is_scanned(:\n' >.github/scripts/check-install-surface.py
  assert_changed .github/scripts/check-install-surface.py
  "$REAL_BASH" "$SCRIPT_REL" --list --base main >"$CASE_DIR.out" 2>"$CASE_DIR.err" || rc=$?
  if [ "$rc" -ne 2 ] || [ -s "$CASE_DIR.out" ] ||
    ! grep -qF "preflight: cannot load .github/scripts/check-install-surface.py: " "$CASE_DIR.err"; then
    cat "$CASE_DIR.out" "$CASE_DIR.err" >&2
    fail "an unloadable install-surface check exited $rc"
  fi
}

case_the_preflight_itself() {
  start_case
  edit .github/scripts/preflight.sh
  expect_list "${ALWAYS[@]}" self-test:test-preflight.sh shellcheck-preflight
}

case_registry_completeness() {
  start_case
  check_registry_completeness "$CASE_DIR" || fail "the registry differs from the test files of the fixture"
  cp -R "$CASE_DIR" "$CASE_DIR-extra"
  : >"$CASE_DIR-extra/.github/scripts/test-extra.py"
  if check_registry_completeness "$CASE_DIR-extra" 2>/dev/null; then
    fail "an unregistered test-extra.py passed"
  fi
  cp -R "$CASE_DIR" "$CASE_DIR-missing"
  rm "$CASE_DIR-missing/.github/scripts/test-compare-crate-sums.py"
  if check_registry_completeness "$CASE_DIR-missing" 2>/dev/null; then
    fail "a registration for a missing file passed"
  fi
}

case_drift() {
  start_case
  check_drift "$CASE_DIR" || fail "the registry differs from the workflows"
}

# Each drift case edits the workflow copy of the fixture, never the tree's
# copy.
case_drift_new_step() {
  start_case
  replace_line .github/workflows/ci.yml "        run: cargo fmt --all -- --check" \
    "        run: cargo fmt --all -- --check" "      - name: Check spelling" "        run: cargo xyz"
  expect_drift "$CASE_DIR" \
    "drift: ci.yml job fmt: step 'Check spelling' runs a command without a registry entry" \
    "drift: ci.yml job fmt: 2 steps run a command, and the registry and the not-carried list name 1"
}

case_drift_unnamed_step() {
  local line
  start_case
  replace_line .github/workflows/ci.yml "        run: cargo fmt --all -- --check" \
    "        run: cargo fmt --all -- --check" "      - run: cargo xyz"
  line=$(grep -nxF -- "      - run: cargo xyz" .github/workflows/ci.yml | cut -d : -f 1)
  expect_drift "$CASE_DIR" \
    "drift: ci.yml job fmt: the step at line $line runs a command and has no name" \
    "drift: ci.yml job fmt: 2 steps run a command, and the registry and the not-carried list name 1"
}

case_drift_removed_step() {
  start_case
  replace_line .github/workflows/ci.yml "      - name: Check formatting"
  replace_line .github/workflows/ci.yml "        run: cargo fmt --all -- --check"
  expect_drift "$CASE_DIR" \
    "drift: ci.yml job fmt: no step 'Check formatting' (registry entry fmt)" \
    "drift: ci.yml job fmt: 0 steps run a command, and the registry and the not-carried list name 1"
}

case_drift_renamed_step() {
  start_case
  replace_line .github/workflows/ci.yml "      - name: Check formatting" "      - name: Check the formatting"
  expect_drift "$CASE_DIR" \
    "drift: ci.yml job fmt: step 'Check the formatting' runs a command without a registry entry" \
    "drift: ci.yml job fmt: no step 'Check formatting' (registry entry fmt)"
}

case_install_hint() {
  local pin hint missing
  start_case
  pin=$(awk '$1 == "tool:" && $2 ~ /^cargo-machete@/ { sub(/^cargo-machete@/, "", $2); print $2 }' .github/workflows/ci.yml)
  [ -n "$pin" ] || fail "ci.yml pins no cargo-machete version"
  hint=$(hint_of cargo-machete)
  case "$hint" in
    *" $pin") ;;
    *) fail "the hint '$hint' does not end in the pinned version $pin" ;;
  esac
  sed "s/cargo-machete@$pin/cargo-machete@9.9.9/" .github/workflows/ci.yml >"$CASE_DIR.ci"
  cp "$CASE_DIR.ci" .github/workflows/ci.yml
  grep -q 'tool: cargo-machete@9.9.9' .github/workflows/ci.yml || fail "the pin edit was not applied"
  hint=$(hint_of cargo-machete)
  case "$hint" in
    *" 9.9.9") ;;
    *) fail "the hint '$hint' does not follow the pin to 9.9.9" ;;
  esac
  # shellcheck disable=SC2016 # The inner shell expands its own variables.
  missing=$("$REAL_BASH" -c '
    . "$1"
    load_registry
    for list in "${REG_REQ[@]}"; do
      IFS=,
      for requirement in $list; do
        if [ "$requirement" != - ] && [ -z "$(install_hint "$requirement")" ]; then
          echo "$requirement"
        fi
      done
    done
  ' requirements "$SCRIPT_REL")
  [ -z "$missing" ] || fail "no install hint for: $missing"
}

# Starts a --full run on a branch that changes only Markdown, with a stale
# cov.json in the work tree and cargo answering from the status lines $@,
# each 0 by default.
run_full_with_stale_coverage() {
  local status
  start_run_case
  edit CONTRIBUTING.md
  write_shim "$BIN/cargo" cargo cargo
  for status in "$@"; do
    echo "$status" >>"$STATE/status"
  done
  printf '{"stale": true}\n' >cov.json
  cp cov.json "$CASE_DIR.stale"
  run_preflight --full
}

case_coverage_suppression() {
  local coverage floors
  coverage=$(registry_row coverage | cut -f 2)
  floors=$(registry_row coverage-floors | cut -f 2)
  run_full_with_stale_coverage "cargo llvm-cov=1"
  [ "$RUN_RC" -eq 1 ] || fail "the run exited $RUN_RC"
  expect_line "- \`$coverage\`: exit 1"
  expect_line "- \`$floors\`: not run (no coverage file from this run)"
  record_gate_calls
  grep -qxF -- "$(command_record "$coverage")" "$CASE_DIR.calls" || fail "coverage did not run"
  if grep -qF check-coverage.py "$CASE_DIR.calls"; then
    fail "check-coverage.py ran"
  fi
  cmp -s cov.json "$CASE_DIR.stale" || fail "cov.json changed"
  assert_clean_calls
}

# A passing coverage run writes cov.json, and coverage-floors runs right
# after it.
case_coverage_written() {
  local coverage floors first second
  coverage=$(registry_row coverage | cut -f 2)
  floors=$(registry_row coverage-floors | cut -f 2)
  run_full_with_stale_coverage
  expect_line "- \`$coverage\`: exit 0"
  expect_line "- \`$floors\`: exit 0"
  # The controlled PATH lacks actionlint, shellcheck, jq, and the archive and
  # Node tools, so their gates are unavailable and the run exits 1. No gate
  # fails.
  [ "$RUN_RC" -eq 1 ] || fail "the run exited $RUN_RC, expected 1"
  if ! tail -n 1 "$CASE_DIR.out" | grep -qE '^preflight: [0-9]+ gates run, 0 failed, [1-9][0-9]* unavailable$'; then
    tail -n 1 "$CASE_DIR.out" >&2
    fail "the summary line does not show 0 failed and unavailable gates"
  fi
  grep -qxF '{"written by": "the cargo shim"}' cov.json || fail "coverage did not write cov.json"
  record_gate_calls
  first=$(grep -nxF -- "$(command_record "$coverage")" "$CASE_DIR.calls" | cut -d : -f 1)
  second=$(grep -nxF -- "$(command_record "$floors")" "$CASE_DIR.calls" | cut -d : -f 1)
  if [ -z "$first" ] || [ "$second" != "$((first + 1))" ]; then
    cat "$CASE_DIR.calls" >&2
    fail "coverage-floors did not run right after coverage"
  fi
  assert_clean_calls
}

case_coverage_unavailable() {
  local coverage floors
  coverage=$(registry_row coverage | cut -f 2)
  floors=$(registry_row coverage-floors | cut -f 2)
  run_full_with_stale_coverage "cargo llvm-cov --version=1"
  [ "$RUN_RC" -eq 1 ] || fail "the run exited $RUN_RC"
  if ! grep -qF -- "- \`$coverage\`: unavailable (cargo-llvm-cov: " "$CASE_DIR.out"; then
    cat "$CASE_DIR.out" >&2
    fail "the coverage row is not unavailable"
  fi
  expect_line "- \`$floors\`: not run (no coverage file from this run)"
  record_gate_calls
  grep -qxF -- "$(command_record "cargo llvm-cov --version")" "$CASE_DIR.calls" ||
    fail "the cargo-llvm-cov probe did not run"
  if grep -qxF -- "$(command_record "$coverage")" "$CASE_DIR.calls" || grep -qF check-coverage.py "$CASE_DIR.calls"; then
    fail "a coverage command ran"
  fi
  cmp -s cov.json "$CASE_DIR.stale" || fail "cov.json changed"
  assert_clean_calls
}

usage() {
  echo "usage: test-preflight.sh [--case <name>]" >&2
  exit 2
}

main() {
  local selected=$CASES name passed=0 total=0 failures="" rc
  if [ "$#" -gt 0 ]; then
    if [ "$#" -ne 2 ] || [ "$1" != --case ]; then
      usage
    fi
    case " $(printf '%s' "$CASES" | tr '\n' ' ') " in
      *" $2 "*) selected=$2 ;;
      *) usage ;;
    esac
  fi
  mkdir -p "$TMP/cases" "$TMP/logs" "$TMP/xdg"
  build_fixture "$FIXTURE"
  if ! assert_fixture_complete "$FIXTURE"; then
    exit 1
  fi
  for name in $selected; do
    total=$((total + 1))
    set +e
    (
      set -e
      CASE_NAME=$name
      "case_${name//-/_}"
    ) >"$TMP/logs/$name.log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      passed=$((passed + 1))
    else
      failures="$failures $name"
    fi
  done
  for name in $failures; do
    echo "FAILED $name"
    sed 's/^/  /' "$TMP/logs/$name.log"
  done
  echo "preflight test: $passed of $total passed"
  if [ -n "$failures" ]; then
    exit 1
  fi
}

main "$@"

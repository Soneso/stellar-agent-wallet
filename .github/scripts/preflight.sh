#!/usr/bin/env bash
# Runs the local CI gates that apply to the files a branch changes, then
# prints one table row per gate for the pull request description.
#
# Usage: preflight.sh [--base <ref>] [--full] [--list]
#
#   --base <ref>  Compares the branch with its merge base with <ref>. The
#                 default is origin/main, or main when origin/main does not
#                 exist.
#   --full        Selects every gate, with the workspace test command.
#   --list        Prints the selected gates as <id><TAB><command>, one per
#                 line in registry order, and runs nothing.
#
# The changed set is the union of the paths that differ from the merge base
# and the paths git status lists, untracked files included. Deleted paths stay
# in the set: they select gates, but they are never a shellcheck operand or a
# self-test trigger of their own. Each path selects the gates of every scope
# class it matches:
#
#   workflows  .github/workflows/*.yml, .github/actions/, .github/labels.yml
#   scripts    .github/scripts/
#   surface    each path that is_scanned of check-install-surface.py accepts:
#              the Markdown files and manifests that check reads
#   skill      skills/, .claude-plugin/
#   rust       crates/, tests/, examples/, and the root files Cargo.toml,
#              Cargo.lock, rust-toolchain.toml, rustfmt.toml, Cross.toml, and
#              deny.toml
#
# A docs path outside the surface scope adds no gates beyond the three always
# gates. Directory scopes also apply to Markdown files. A path under interop/
# adds no gate of its own; the interop harnesses run under --full.
# select_for_path holds the triggers, and plan_surface_self_test the trigger
# of the surface scope. A gate that several triggers select runs once, at its
# registry position.
#
# A selected gate whose tool or Python module is missing is unavailable: its
# row names the requirement and an install hint, and the later gates still
# run. A failing gate does not stop the later gates either.
#
# Exit codes: 0 when every selected gate ran and passed, and 1 when a gate
# failed or was unavailable. Exit code 2 means a usage error, a missing
# prerequisite, a base without a merge base, an unreadable workspace
# manifest, or, without --full, a check-install-surface.py that Python cannot
# load.
#
# Needs bash 3.2 or later, git, python3 3.11 or later (for tomllib), awk,
# grep, sed, sort, uniq, and mktemp. The Python blocks use the standard
# library only. The script keeps its temporary files under ${TMPDIR:-/tmp} and
# removes them on exit.
set -euo pipefail

# The test features of the CI test and coverage jobs.
OFFLINE_FEATURES=test-helpers,test-hooks,test-loopback,verifier-registry
# The crate that embeds the vendored contract Wasm files. Its release
# configuration test runs whenever the test packages include it.
VENDORED_CRATE=stellar-agent-smart-account
# The workflows that check-workflow-invariants.py reads, as its docstring
# names them.
INVARIANT_WORKFLOWS="release publish notarize-smoke labels stale triage welcome coverage"

die() {
  echo "preflight: $*" >&2
  exit 2
}

usage() {
  echo "usage: preflight.sh [--base <ref>] [--full] [--list]" >&2
  exit 2
}

# Prints the gate registry, one record per line with six tab-separated
# fields: id, command, requirements, and the workflow, job, and step name of
# the CI step the gate mirrors. Requirements are comma-separated and checked
# in order. A "-" requirement means none, and a "-" CI step means the gate
# mirrors none. test-preflight.sh checks every named step against the
# workflows. The line order is the order of --list, of the run, and of the
# table.
registry_records() {
  cat <<EOF
docs-style	python3 .github/scripts/check-docs-style.py	-	install-surface.yml	install-surface	Check the docs style
install-surface	python3 .github/scripts/check-install-surface.py	-	install-surface.yml	install-surface	Check the install surface
gate-tool-versions	bash .github/scripts/check-gate-tool-versions.sh	-	install-surface.yml	install-surface	Check the gate tool versions
actionlint	actionlint	actionlint	install-surface.yml	install-surface	Check workflows
workflow-invariants	python3 .github/scripts/check-workflow-invariants.py	yaml	ci.yml	release-contracts	Check the workflow structure and the label sync
self-test:test-check-crates-exist.sh	bash .github/scripts/test-check-crates-exist.sh	jq	ci.yml	release-contracts	Self-test the crates.io existence check
self-test:test-check-docs-style.py	python3 .github/scripts/test-check-docs-style.py	-	install-surface.yml	install-surface	Self-test Python checks on Python 3.13
self-test:test-check-gate-tool-versions.sh	bash .github/scripts/test-check-gate-tool-versions.sh	-	install-surface.yml	install-surface	Self-test the gate tool version check
self-test:test-check-install-surface.py	python3 .github/scripts/test-check-install-surface.py	-	install-surface.yml	install-surface	Self-test Python checks on Python 3.13
self-test:test-check-no-direct-sasignersetbaselined-emit.sh	bash .github/scripts/test-check-no-direct-sasignersetbaselined-emit.sh	-	ci.yml	release-contracts	Self-test the signer-set baseline gate
self-test:test-check-ref-on-main.sh	bash .github/scripts/test-check-ref-on-main.sh	-	ci.yml	release-contracts	Self-test the ref-on-main check
self-test:test-check-workflow-invariants.py	python3 .github/scripts/test-check-workflow-invariants.py	yaml	ci.yml	release-contracts	Check the workflow structure and the label sync
self-test:test-compare-crate-sums.py	python3 .github/scripts/test-compare-crate-sums.py	-	ci.yml	release-contracts	Self-test the crate checksum comparison
self-test:test-preflight.sh	bash .github/scripts/test-preflight.sh	-	install-surface.yml	install-surface	Self-test the preflight
self-test:test-publish-crates-check.sh	.github/scripts/test-publish-crates-check.sh	cargo	ci.yml	release-contracts	Self-test the publish tier check
self-test:test-publish-crates-verify.sh	bash .github/scripts/test-publish-crates-verify.sh	cargo	ci.yml	release-contracts	Self-test the publish verification
self-test:test-rebuild-vendored-wasm.sh	bash .github/scripts/test-rebuild-vendored-wasm.sh	shasum	vendored-wasm.yml	check	Self-test (bash 5, GNU tools)
self-test:test-sync-labels.py	python3 .github/scripts/test-sync-labels.py	yaml	ci.yml	release-contracts	Check the workflow structure and the label sync
self-test:test-take-workflow.py	python3 .github/scripts/test-take-workflow.py	yaml,jq	ci.yml	release-contracts	Check the workflow structure and the label sync
self-test:test-triage-workflow.py	python3 .github/scripts/test-triage-workflow.py	yaml,jq	ci.yml	release-contracts	Check the workflow structure and the label sync
self-test:test-validate-unsigned-archive.py	python3 .github/scripts/test-validate-unsigned-archive.py	-	ci.yml	release-contracts	Self-test the unsigned archive validation
self-test:test-welcome-workflow.py	python3 .github/scripts/test-welcome-workflow.py	jq	ci.yml	release-contracts	Check the workflow structure and the label sync
shellcheck-preflight	shellcheck -s bash .github/scripts/preflight.sh .github/scripts/test-preflight.sh	shellcheck	install-surface.yml	install-surface	Shellcheck the preflight
shellcheck-changed	shellcheck -s bash	shellcheck	-	-	-
package-skill	.github/scripts/package-skill.sh --check	zip,unzip,zipinfo,shasum	ci.yml	release-contracts	Check the skill archive
vendored-tree-check	bash .github/scripts/rebuild-vendored-wasm.sh --check-tree --repo-root .	shasum	vendored-wasm.yml	check	Tree check
publish-check	.github/scripts/publish-crates.sh --check	cargo	ci.yml	release-contracts	Check the publish tiers
baseline-gate	bash .github/scripts/check-no-direct-sasignersetbaselined-emit.sh	-	ci.yml	release-contracts	Check the signer-set baseline gate
fmt	cargo fmt --all -- --check	cargo	ci.yml	fmt	Check formatting
clippy	cargo clippy --all-targets --all-features -- -D warnings	cargo	ci.yml	clippy	Run clippy
rustdoc	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features	cargo	ci.yml	doc	Build the rustdoc
test	cargo test --workspace --features $OFFLINE_FEATURES	cargo	ci.yml	test	Run the offline tests
test-vendored-release-cfg	cargo test -p $VENDORED_CRATE --test vendored_wasm_release_cfg	cargo	ci.yml	test	Test the vendored Wasm release configuration
machete	cargo machete	cargo,cargo-machete	ci.yml	machete	Check for unused dependencies
deny	cargo deny check	cargo,cargo-deny	ci.yml	deny	Check licenses and advisories
coverage	cargo llvm-cov --workspace --features $OFFLINE_FEATURES --json --output-path cov.json	cargo,cargo-llvm-cov	coverage.yml	coverage	Measure offline line coverage
coverage-floors	python3 .github/scripts/check-coverage.py cov.json	-	coverage.yml	coverage	Enforce per-crate line-coverage floors
interop:mpp	.github/scripts/test-mpp-interop.sh	node,corepack	ci.yml	mpp-interop	Run the MPP interop harness
interop:sdk-v17	.github/scripts/test-sdk-v17-interop.sh	node,corepack	ci.yml	sdk-v17-interop	Run the stellar-sdk v17 interop harness
EOF
}

# Loads the id, command, and requirements of each registry record into
# REG_ID, REG_CMD, and REG_REQ. A per-package run replaces the workspace test
# command, and the planner appends the operands of the shellcheck-changed
# command.
load_registry() {
  local id command requirements
  REG_COUNT=0
  while IFS=$'\t' read -r id command requirements _; do
    REG_ID[REG_COUNT]=$id
    REG_CMD[REG_COUNT]=$command
    REG_REQ[REG_COUNT]=$requirements
    REG_COUNT=$((REG_COUNT + 1))
  done < <(registry_records)
}

# Sets GATE to the registry position of gate id $1, or to -1.
find_gate() {
  local position=0
  GATE=-1
  while [ "$position" -lt "$REG_COUNT" ]; do
    if [ "${REG_ID[position]}" = "$1" ]; then
      GATE=$position
      return 0
    fi
    position=$((position + 1))
  done
}

# Selects the gate at registry position $1. plan() orders the selection and
# keeps each position once.
select_position() {
  SELECTED="$SELECTED$1"$'\n'
}

# Selects gate id $1. Every trigger names a registered id.
select_gate() {
  find_gate "$1"
  if [ "$GATE" -lt 0 ]; then
    die "no gate named $1"
  fi
  select_position "$GATE"
}

check_prerequisites() {
  local tool
  if [ "${BASH_VERSINFO[0]}" -lt 3 ] ||
    { [ "${BASH_VERSINFO[0]}" -eq 3 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
    die "bash 3.2 or later is required"
  fi
  for tool in git python3 awk grep sed sort uniq mktemp; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
  done
  python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' ||
    die "python3 3.11 or later is required"
}

# Sets BASE to the ref that the branch is diffed against, and exits 2 unless
# BASE names a commit that shares a merge base with HEAD.
resolve_base() {
  if [ -z "$BASE" ]; then
    if git rev-parse --verify --quiet 'origin/main^{commit}' >/dev/null; then
      BASE=origin/main
    else
      BASE=main
    fi
  fi
  if ! git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null ||
    ! git merge-base HEAD "$BASE" >/dev/null 2>&1; then
    die "cannot find a merge base with $BASE; run git fetch origin main or pass --base <ref>"
  fi
}

# Writes the changed set to $SCRATCH/changed: the union of the paths that
# differ from the merge base with $BASE and the paths of git status, sorted by
# bytes, each followed by NUL.
collect_changed_set() {
  git diff --name-only -z --no-renames --merge-base "$BASE" -- >"$SCRATCH/diff" ||
    die "cannot compare the branch with its merge base with $BASE"
  git status --porcelain=v1 -z --untracked-files=all >"$SCRATCH/status" ||
    die "git status failed"
  python3 - "$SCRATCH/diff" "$SCRATCH/status" >"$SCRATCH/changed" <<'PY'
import sys

with open(sys.argv[1], "rb") as stream:
    paths = [path for path in stream.read().split(b"\0") if path]
with open(sys.argv[2], "rb") as stream:
    records = iter(stream.read().split(b"\0"))
for record in records:
    if not record:
        continue
    # A record is "XY <path>". A rename or copy record carries its source
    # path as the next field.
    status, path = record[:2], record[3:]
    paths.append(path)
    if b"R" in status or b"C" in status:
        paths.append(next(records))
out = sys.stdout.buffer
for path in sorted(set(paths)):
    out.write(path + b"\0")
PY
}

# Prints the .github/scripts/ paths that the invariants workflows and the
# files under .github/actions/ name, one per line, sorted.
invariant_script_paths() {
  local name inputs=()
  for name in $INVARIANT_WORKFLOWS; do
    if [ -f ".github/workflows/$name.yml" ]; then
      inputs+=(".github/workflows/$name.yml")
    fi
  done
  if [ -d .github/actions ]; then
    inputs+=(.github/actions)
  fi
  if [ "${#inputs[@]}" -eq 0 ]; then
    return 0
  fi
  { grep -rho '\.github/scripts/[A-Za-z0-9_.-]*' "${inputs[@]}" || true; } | sort -u
}

# Succeeds when path $1 is one of INVARIANT_SCRIPTS.
is_invariant_script() {
  case $'\n'"$INVARIANT_SCRIPTS"$'\n' in
    *$'\n'"$1"$'\n'*) return 0 ;;
  esac
  return 1
}

# Selects the self-test records that a change to path $1 triggers: the
# self-test of each checked file, and the record of a changed self-test file
# that still exists.
select_self_tests() {
  case "$1" in
    .github/scripts/check-crates-exist.sh) select_gate self-test:test-check-crates-exist.sh ;;
    .github/scripts/check-docs-style.py) select_gate self-test:test-check-docs-style.py ;;
    .github/scripts/check-gate-tool-versions.sh) select_gate self-test:test-check-gate-tool-versions.sh ;;
    .github/scripts/check-install-surface.py) select_gate self-test:test-check-install-surface.py ;;
    .github/scripts/check-no-direct-sasignersetbaselined-emit.sh)
      select_gate self-test:test-check-no-direct-sasignersetbaselined-emit.sh
      ;;
    .github/scripts/check-ref-on-main.sh) select_gate self-test:test-check-ref-on-main.sh ;;
    .github/scripts/check-workflow-invariants.py) select_gate self-test:test-check-workflow-invariants.py ;;
    .github/scripts/compare-crate-sums.py) select_gate self-test:test-compare-crate-sums.py ;;
    .github/scripts/preflight.sh) select_gate self-test:test-preflight.sh ;;
    .github/scripts/publish-crates.sh)
      select_gate self-test:test-publish-crates-check.sh
      select_gate self-test:test-publish-crates-verify.sh
      ;;
    .github/scripts/rebuild-vendored-wasm.sh) select_gate self-test:test-rebuild-vendored-wasm.sh ;;
    .github/scripts/sync-labels.py | .github/labels.yml | .github/workflows/labels.yml)
      select_gate self-test:test-sync-labels.py
      ;;
    .github/workflows/take.yml) select_gate self-test:test-take-workflow.py ;;
    .github/workflows/triage.yml) select_gate self-test:test-triage-workflow.py ;;
    .github/scripts/validate-unsigned-archive.py) select_gate self-test:test-validate-unsigned-archive.py ;;
    .github/workflows/welcome.yml) select_gate self-test:test-welcome-workflow.py ;;
    .github/scripts/test-*)
      find_gate "self-test:${1#.github/scripts/}"
      if [ "$GATE" -ge 0 ] && [ -f "$1" ]; then
        select_position "$GATE"
      fi
      ;;
  esac
}

# Selects the gates that a change to path $1 triggers. Records a Rust path in
# $SCRATCH/rust for the package planner, and an existing shell script in
# $SCRATCH/shell as an operand of the shellcheck-changed gate.
select_for_path() {
  local path=$1 name
  case "$path" in
    .github/workflows/*.yml | .github/actions/* | .github/labels.yml) select_gate actionlint ;;
  esac
  case "$path" in
    .github/actions/*) select_gate workflow-invariants ;;
    .github/workflows/*.yml)
      for name in $INVARIANT_WORKFLOWS; do
        if [ "$path" = ".github/workflows/$name.yml" ]; then
          select_gate workflow-invariants
        fi
      done
      ;;
    .github/scripts/*)
      if is_invariant_script "$path"; then
        select_gate workflow-invariants
      fi
      ;;
  esac
  select_self_tests "$path"
  case "$path" in
    .github/scripts/preflight.sh | .github/scripts/test-preflight.sh) select_gate shellcheck-preflight ;;
    .github/scripts/*.sh | .github/actions/*.sh)
      if [ -f "$path" ]; then
        printf '%s\0' "$path" >>"$SCRATCH/shell"
      fi
      ;;
  esac
  case "$path" in
    skills/* | .claude-plugin/*) select_gate package-skill ;;
  esac
  case "$path" in
    "crates/$VENDORED_CRATE/"* | contracts/* | .github/scripts/rebuild-vendored-wasm.sh)
      select_gate vendored-tree-check
      ;;
  esac
  case "$path" in
    crates/* | tests/* | examples/* | Cargo.toml | Cargo.lock | rust-toolchain.toml | \
      rustfmt.toml | Cross.toml | deny.toml)
      select_gate fmt
      select_gate clippy
      select_gate rustdoc
      select_gate test
      printf '%s\0' "$path" >>"$SCRATCH/rust"
      ;;
  esac
}

# Selects the self-test of check-install-surface.py when a changed path is in
# the surface scope. The self-test injects violations into copies of the
# files that check reads, so a change to one of them can break it. The
# check's own is_scanned decides, so the scope follows the check's file set.
plan_surface_self_test() {
  local selects
  python3 - "$SCRATCH/changed" >"$SCRATCH/surface" <<'PY' || exit 2
import importlib.util
import os
import sys

# Loading the check must not leave a __pycache__ directory in the tree. Its
# dataclasses resolve their module through sys.modules, so the block
# registers the module there before running it.
sys.dont_write_bytecode = True
check = ".github/scripts/check-install-surface.py"
try:
    spec = importlib.util.spec_from_file_location("check_install_surface", check)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
except Exception as error:
    print(f"preflight: cannot load {check}: {error}", file=sys.stderr)
    raise SystemExit(2)
with open(sys.argv[1], "rb") as stream:
    changed = [os.fsdecode(path) for path in stream.read().split(b"\0") if path]
print(1 if any(module.is_scanned(path) for path in changed) else 0)
PY
  IFS= read -r selects <"$SCRATCH/surface"
  if [ "$selects" = 1 ]; then
    select_gate self-test:test-check-install-surface.py
  fi
}

# Replaces the test command with the per-package command when every changed
# Rust path belongs to a workspace member. Selects the release configuration
# test of the vendored crate when the packages include it or the workspace
# command applies.
plan_tests() {
  local command vendored
  # Any planner failure, an unexpected exception included, exits 2.
  python3 - "$OFFLINE_FEATURES" "$VENDORED_CRATE" "$SCRATCH/rust" >"$SCRATCH/plan" <<'PY' || exit 2
import pathlib
import posixpath
import shlex
import sys
import tomllib

offline_features = sys.argv[1].split(",")
vendored_crate = sys.argv[2]
with open(sys.argv[3], "rb") as stream:
    changed = [path.decode("utf-8", "surrogateescape") for path in stream.read().split(b"\0") if path]


def fail(message):
    print(f"preflight: {message}", file=sys.stderr)
    raise SystemExit(2)


def load(path):
    try:
        with open(path, "rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {path}: {error}")


workspace = load("Cargo.toml").get("workspace", {})
members = []
for pattern in workspace.get("members", []):
    if any(character in pattern for character in "*?["):
        members.extend(sorted(path.as_posix() for path in pathlib.Path().glob(pattern) if path.is_dir()))
    else:
        members.append(posixpath.normpath(pattern))
excluded = {posixpath.normpath(path) for path in workspace.get("exclude", [])}
members = [member for member in members if member not in excluded]

# A member whose manifest the change deletes has no package; a path under it
# selects the workspace command.
names = {}
manifests = {}
for member in members:
    manifest = f"{member}/Cargo.toml"
    if manifest in changed and not pathlib.Path(manifest).exists():
        continue
    data = load(manifest)
    package = data.get("package")
    name = package.get("name") if isinstance(package, dict) else None
    if not isinstance(name, str):
        fail(f"cannot read {manifest}: no package name")
    names[member] = name
    manifests[member] = data


def owner(path):
    containing = [member for member in members if path.startswith(member + "/")]
    return names.get(max(containing, key=len)) if containing else None


# The output is two lines: the per-package test command, or an empty line for
# the workspace command; then 1 when the release configuration test of the
# vendored crate applies, else 0.
owners = []
for path in changed:
    name = owner(path)
    if name is None:
        print()
        print(1)
        raise SystemExit(0)
    if name not in owners:
        owners.append(name)

shared = workspace.get("dependencies", {})


def dependency_tables(manifest):
    yield manifest.get("dependencies", {})
    yield manifest.get("dev-dependencies", {})
    for platform in manifest.get("target", {}).values():
        yield platform.get("dependencies", {})
        yield platform.get("dev-dependencies", {})


def member_of(member, key, entry):
    if not isinstance(entry, dict):
        return None
    if "path" in entry:
        return names.get(posixpath.normpath(posixpath.join(member, entry["path"])))
    inherited = shared.get(key)
    if entry.get("workspace") is True and isinstance(inherited, dict) and "path" in inherited:
        return names.get(posixpath.normpath(inherited["path"]))
    return None


dependents = set()
for member, manifest in manifests.items():
    try:
        for table in dependency_tables(manifest):
            for key, entry in table.items():
                if member_of(member, key, entry) in owners:
                    dependents.add(names[member])
    except (AttributeError, TypeError) as error:
        fail(f"cannot read {member}/Cargo.toml: {error}")
selected = owners + sorted(dependents - set(owners))
declared = set()
for member, manifest in manifests.items():
    if names[member] in selected:
        feature_table = manifest.get("features", {})
        if not isinstance(feature_table, dict):
            fail(f"cannot read {member}/Cargo.toml: [features] is not a table")
        declared.update(feature_table)
features = [feature for feature in offline_features if feature in declared]

command = ["cargo", "test"]
for package in selected:
    command += ["-p", package]
if features:
    command += ["--features", ",".join(features)]
print(shlex.join(command))
print(1 if vendored_crate in selected else 0)
PY
  { IFS= read -r command && IFS= read -r vendored; } <"$SCRATCH/plan"
  if [ -n "$command" ]; then
    find_gate test
    REG_CMD[GATE]=$command
  fi
  if [ "$vendored" = 1 ]; then
    select_gate test-vendored-release-cfg
  fi
}

# Appends the changed shell scripts to the shellcheck-changed command, each
# rendered with shlex.quote, and selects the gate. SHELLCHECK_ARGV holds the
# command words and the original pathnames, which execution passes as
# separate arguments.
plan_shellcheck_changed() {
  local path rendered
  python3 - "$SCRATCH/shell" >"$SCRATCH/rendered" <<'PY'
import os
import shlex
import sys

with open(sys.argv[1], "rb") as stream:
    paths = [os.fsdecode(path) for path in stream.read().split(b"\0") if path]
sys.stdout.buffer.write(os.fsencode(" ".join(shlex.quote(path) for path in paths)))
PY
  rendered=$(cat "$SCRATCH/rendered")
  find_gate shellcheck-changed
  read -r -a SHELLCHECK_ARGV <<<"${REG_CMD[GATE]}"
  while IFS= read -r -d '' path; do
    SHELLCHECK_ARGV+=("$path")
  done <"$SCRATCH/shell"
  REG_CMD[GATE]="${REG_CMD[GATE]} $rendered"
  select_gate shellcheck-changed
}

# Sets SELECTED_POSITIONS to the registry positions of the selected gates, in
# order and each once.
plan() {
  local full=$1 path position
  SELECTED=""
  : >"$SCRATCH/rust"
  : >"$SCRATCH/shell"
  INVARIANT_SCRIPTS=$(invariant_script_paths)
  select_gate docs-style
  select_gate install-surface
  select_gate gate-tool-versions
  while IFS= read -r -d '' path; do
    select_for_path "$path"
  done <"$SCRATCH/changed"
  if [ "$full" -eq 1 ]; then
    position=0
    while [ "$position" -lt "$REG_COUNT" ]; do
      if [ "${REG_ID[position]}" != shellcheck-changed ]; then
        select_position "$position"
      fi
      position=$((position + 1))
    done
  else
    plan_surface_self_test
    if [ -s "$SCRATCH/rust" ]; then
      plan_tests
    fi
  fi
  if [ -s "$SCRATCH/shell" ]; then
    plan_shellcheck_changed
  fi
  SELECTED_POSITIONS=$(printf '%s' "$SELECTED" | sort -n | uniq)
}

# Prints the version that a "tool: <tool>@<version>" line of workflow $1 pins
# for tool $2, or nothing.
tool_pin() {
  awk -v tool="$2" '$1 == "tool:" && index($2, tool "@") == 1 {
    print substr($2, length(tool) + 2)
    exit
  }' "$1" 2>/dev/null || true
}

# Prints the actionlint version of the release archive that workflow $1
# downloads, or nothing.
actionlint_pin() {
  awk 'match($0, /releases\/download\/v[0-9][^\/]*\/actionlint_/) {
    version = substr($0, RSTART, RLENGTH)
    sub(/^releases\/download\/v/, "", version)
    sub(/\/actionlint_$/, "", version)
    print version
    exit
  }' "$1" 2>/dev/null || true
}

# Prints the Node versions that the jobs of ci.yml set up, joined by "or".
node_version() {
  awk '$1 == "node-version:" { print $2 }' .github/workflows/ci.yml 2>/dev/null |
    tr -d "\"'" | sort -u | awk 'NR > 1 { printf " or " } { printf "%s", $0 }'
}

# Prints version $1, or a pointer to file $2 when the version is empty.
version_or_file() {
  if [ -n "$1" ]; then
    printf '%s' "$1"
  else
    printf '<the version in %s>' "$2"
  fi
}

# Prints the install hint for requirement $1. The versions come from the
# files that pin them, so a hint follows a pin change.
install_hint() {
  local ci=.github/workflows/ci.yml coverage=.github/workflows/coverage.yml
  local surface=.github/workflows/install-surface.yml
  case "$1" in
    actionlint)
      echo "brew install actionlint, or the $(version_or_file "$(actionlint_pin "$surface")" "$surface") release archive"
      ;;
    shellcheck)
      echo "brew install shellcheck, or the $(version_or_file "$(tool_pin "$surface" shellcheck)" "$surface") release archive"
      ;;
    cargo) echo "install Rust with rustup from https://rustup.rs" ;;
    cargo-llvm-cov)
      echo "cargo install --locked $1 --version $(version_or_file "$(tool_pin "$coverage" "$1")" "$coverage")"
      ;;
    cargo-machete | cargo-deny)
      echo "cargo install --locked $1 --version $(version_or_file "$(tool_pin "$ci" "$1")" "$ci")"
      ;;
    yaml) echo "python3 -m pip install --require-hashes -r .github/scripts/workflow-check-requirements.txt" ;;
    jq | zip) echo "brew install $1 or apt-get install $1" ;;
    unzip | zipinfo) echo "brew install unzip or apt-get install unzip" ;;
    shasum) echo "brew install perl or apt-get install perl" ;;
    node) echo "install Node $(version_or_file "$(node_version)" "$ci")" ;;
    corepack) echo "npm install --global corepack" ;;
  esac
}

# Prints the first requirement of comma-separated list $1 that this machine
# lacks, or nothing when it has them all.
missing_requirement() {
  local requirement IFS=,
  for requirement in $1; do
    case "$requirement" in
      -) ;;
      yaml)
        python3 -c 'import yaml' >/dev/null 2>&1 || {
          echo "$requirement"
          return 0
        }
        ;;
      cargo-llvm-cov | cargo-machete | cargo-deny)
        cargo "${requirement#cargo-}" --version >/dev/null 2>&1 || {
          echo "$requirement"
          return 0
        }
        ;;
      *)
        command -v "$requirement" >/dev/null 2>&1 || {
          echo "$requirement"
          return 0
        }
        ;;
    esac
  done
}

# Runs the gate at registry position $1 and returns its exit code. The
# commands are registry literals or planner output that shlex.quote renders,
# so eval runs them as written.
execute_gate() {
  if [ "${REG_ID[$1]}" = shellcheck-changed ]; then
    "${SHELLCHECK_ARGV[@]}"
  else
    eval "${REG_CMD[$1]}"
  fi
}

print_list() {
  local position
  for position in $SELECTED_POSITIONS; do
    printf '%s\t%s\n' "${REG_ID[position]}" "${REG_CMD[position]}"
  done
}

# Runs the selected gates in registry order, prints the table, and exits.
# coverage-floors reads the cov.json that coverage writes, so it runs only
# after coverage ran and passed in this run.
run_gates() {
  local full=$1 position id command missing rc
  local table="" run=0 failed=0 unavailable=0 coverage_written=0
  for position in $SELECTED_POSITIONS; do
    id=${REG_ID[position]}
    command=${REG_CMD[position]}
    if [ "$id" = coverage-floors ] && [ "$coverage_written" -eq 0 ]; then
      table+="- \`$command\`: not run (no coverage file from this run)"$'\n'
      continue
    fi
    missing=$(missing_requirement "${REG_REQ[position]}")
    if [ -n "$missing" ]; then
      unavailable=$((unavailable + 1))
      table+="- \`$command\`: unavailable ($missing: $(install_hint "$missing"))"$'\n'
      continue
    fi
    printf '=== %s: %s\n' "$id" "$command"
    rc=0
    execute_gate "$position" </dev/null || rc=$?
    printf 'RC=%s\n' "$rc"
    run=$((run + 1))
    if [ "$rc" -ne 0 ]; then
      failed=$((failed + 1))
    elif [ "$id" = coverage ]; then
      coverage_written=1
    fi
    table+="- \`$command\`: exit $rc"$'\n'
  done
  if [ "$full" -eq 0 ]; then
    for id in interop:mpp interop:sdk-v17; do
      find_gate "$id"
      table+="- \`${REG_CMD[GATE]}\`: not run (--full; needs Node $(version_or_file "$(node_version)" .github/workflows/ci.yml) and Corepack)"$'\n'
    done
  fi
  printf '\n%s' "$table"
  printf 'preflight: %s gates run, %s failed, %s unavailable\n' "$run" "$failed" "$unavailable"
  if [ "$failed" -eq 0 ] && [ "$unavailable" -eq 0 ]; then
    exit 0
  fi
  exit 1
}

main() {
  local full=0 list=0 top tmp_root
  BASE=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --base)
        if [ "$#" -lt 2 ]; then
          usage
        fi
        BASE=$2
        shift 2
        ;;
      --full)
        full=1
        shift
        ;;
      --list)
        list=1
        shift
        ;;
      *) usage ;;
    esac
  done
  check_prerequisites
  top=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a Git checkout"
  cd "$top"
  resolve_base
  tmp_root=${TMPDIR:-/tmp}
  SCRATCH=$(mktemp -d "${tmp_root%/}/preflight.XXXXXX")
  trap 'rm -rf "$SCRATCH"' EXIT
  collect_changed_set
  load_registry
  plan "$full"
  if [ "$list" -eq 1 ]; then
    print_list
    exit 0
  fi
  run_gates "$full"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi

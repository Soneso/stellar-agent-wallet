#!/usr/bin/env bash
# Fails when a gate tool version in docs/maintainers/building.md, a workflow,
# or a composite action differs from the tool's reference pin. The guide and
# CI install the same cargo-llvm-cov, cargo-machete, and cargo-deny so a local
# gate run reproduces the CI result.
#
# TOOLS gives each tool's reference workflow and exact pin count. Each
# reference line uses `tool: <tool>@<version>` and may end in a YAML comment.
# coverage.yml pins cargo-llvm-cov once
# for each measurement job. The first reference pin supplies the reference
# version, and every further reference pin carries it. building.md installs
# each tool on exactly one
# `cargo install --locked <tool> --version <version>` line. Every other
# workflow and composite action pins a tool only on `tool: <tool>@<version>`
# lines, each at the reference version. A line names a tool with a version
# when it holds `<tool>@`, or the tool name and `--version` or its alias
# `--vers`. Any such line outside these shapes fails the check, so the check
# compares every version it finds. It ignores YAML comment lines and reports
# every problem before it exits.
set -euo pipefail
shopt -s nullglob

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORKFLOW_DIR="$ROOT/.github/workflows"
ACTION_DIR="$ROOT/.github/actions"
BUILDING_DOC="$ROOT/docs/maintainers/building.md"

# Each gate tool, the workflow that holds its reference pins, and their count.
TOOLS=(cargo-llvm-cov=coverage.yml:2 cargo-machete=ci.yml:1 cargo-deny=ci.yml:1)
VERSION_RE='([0-9][0-9A-Za-z.+-]*)'
FAILED=0

# Sets PINS to one `<line> <version>` pair per line of file `$1` that matches
# the line pattern `$4` for tool `$2`, and reports every other line that names
# the tool with a version as outside the `$5` form. YAML comment lines are
# skipped when `$3` is `yaml`.
collect_pins() {
  local file="$1" tool="$2" syntax="$3" pattern="$4" shape="$5" named stray line
  named=$(grep -nE "(^|[^[:alnum:]_-])${tool}([^[:alnum:]_-]|$)" "$file" |
    grep -E "${tool}@|--vers" || true)
  if [ "$syntax" = yaml ]; then
    named=$(printf '%s\n' "$named" | grep -vE '^[0-9]+:[[:space:]]*#' || true)
  fi
  stray=$(printf '%s\n' "$named" | grep -E . | grep -vE "^[0-9]+:${pattern}$" |
    cut -d: -f1 || true)
  for line in $stray; do
    echo "error: ${file#"$ROOT"/}:${line} names ${tool} with a version outside the '${shape}' form" >&2
    FAILED=1
  done
  PINS=$(printf '%s\n' "$named" | sed -nE "s/^([0-9]+):${pattern}$/\1 \2/p")
}

# Sets PIN_LINE and PIN_VERSION from the one pair in PINS. With none or more
# than one, reports the expected `$2` `$3` in file `$1` and returns 1.
single_pin() {
  local file="$1" shape="$2" noun="$3" count
  count=$(printf '%s' "$PINS" | awk 'END { print NR }')
  case "$count" in
    1)
      read -r PIN_LINE PIN_VERSION <<<"$PINS"
      return 0
      ;;
    0) echo "error: no '${shape}' ${noun} found in ${file#"$ROOT"/}" >&2 ;;
    *) echo "error: ${count} '${shape}' ${noun}s found in ${file#"$ROOT"/}, expected one" >&2 ;;
  esac
  FAILED=1
  return 1
}

# Sets REF_LINE and REF_VERSION from the first pair in PINS when file `$1`
# holds exactly `$3` pairs, which `$4` spells as a word. Otherwise reports
# the expected `$2` pins in file `$1` and returns 1.
reference_pins() {
  local file="$1" shape="$2" expected="$3" word="$4" count noun=pins
  count=$(printf '%s' "$PINS" | awk 'END { print NR }')
  if [ "$count" -eq "$expected" ]; then
    read -r REF_LINE REF_VERSION <<<"$PINS"
    return 0
  fi
  [ "$count" -ne 1 ] || noun=pin
  if [ "$count" -eq 0 ]; then
    echo "error: no '${shape}' pin found in ${file#"$ROOT"/}" >&2
  else
    echo "error: ${count} '${shape}' ${noun} found in ${file#"$ROOT"/}, expected ${word}" >&2
  fi
  FAILED=1
  return 1
}

# Reports that tool `$1` has version `$3` on `$2` and version `$5` on `$4`,
# each location a `<file>:<line>`.
report_mismatch() {
  echo "error: $1 version mismatch:" >&2
  echo "  $2 pins $3" >&2
  echo "  $4 pins $5" >&2
  FAILED=1
}

for entry in "${TOOLS[@]}"; do
  tool=${entry%%=*}
  reference=${entry#*=}
  ref_file="$WORKFLOW_DIR/${reference%:*}"
  ref_count=${reference##*:}
  ref_word=one
  [ "$ref_count" -ne 2 ] || ref_word=two
  pin_re="[[:space:]]*tool: ${tool}@${VERSION_RE}[[:space:]]*(#.*)?"
  pin_shape="tool: ${tool}@<version>"
  install_re="cargo install --locked ${tool} --version ${VERSION_RE}"
  install_shape="--locked ${tool} --version <version>"

  # The first of the expected reference pins supplies the comparison version,
  # and every further reference pin carries it. The guide's line count and
  # every file's line shapes are checked on their own.
  ref_version=""
  collect_pins "$ref_file" "$tool" yaml "$pin_re" "$pin_shape"
  if reference_pins "$ref_file" "$pin_shape" "$ref_count" "$ref_word"; then
    ref_at="${ref_file#"$ROOT"/}:${REF_LINE}"
    ref_version=$REF_VERSION
    while read -r line version; do
      if [ "$version" != "$ref_version" ]; then
        report_mismatch "$tool" "$ref_at" "$ref_version" "${ref_file#"$ROOT"/}:${line}" "$version"
      fi
    done < <(printf '%s\n' "$PINS" | sed 1d)
  fi

  collect_pins "$BUILDING_DOC" "$tool" markdown "$install_re" "$install_shape"
  if single_pin "$BUILDING_DOC" "$install_shape" line &&
    [ -n "$ref_version" ] && [ "$PIN_VERSION" != "$ref_version" ]; then
    report_mismatch "$tool" "$ref_at" "$ref_version" \
      "${BUILDING_DOC#"$ROOT"/}:${PIN_LINE}" "$PIN_VERSION"
  fi

  for file in "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml \
    "$ACTION_DIR"/*/action.yml "$ACTION_DIR"/*/action.yaml; do
    [ "$file" != "$ref_file" ] || continue
    collect_pins "$file" "$tool" yaml "$pin_re" "$pin_shape"
    while read -r line version; do
      if [ -n "$line" ] && [ -n "$ref_version" ] && [ "$version" != "$ref_version" ]; then
        report_mismatch "$tool" "$ref_at" "$ref_version" "${file#"$ROOT"/}:${line}" "$version"
      fi
    done <<<"$PINS"
  done
done

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi

echo "gate tool versions match the reference workflow pins in building.md, the workflows, and the actions"

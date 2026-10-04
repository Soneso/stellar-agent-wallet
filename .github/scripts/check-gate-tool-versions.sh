#!/usr/bin/env bash
# Fails when a gate tool version in docs/maintainers/building.md differs from
# the tool: pin in .github/workflows/ci.yml. The guide and CI install the same
# cargo-llvm-cov, cargo-machete, and cargo-deny so a local gate run reproduces
# the CI result.
#
# ci.yml pins each tool on exactly one `tool: <tool>@<version>` line, which may
# end in a YAML comment. building.md installs each tool on exactly one
# `cargo install --locked <tool> --version <version>` line. The other workflows
# and the composite actions pin a tool only on `tool: <tool>@<version>` lines,
# each at the ci.yml version. A line names a tool with a version when it holds
# `<tool>@`, or the tool name and `--version` or its alias `--vers`. Any such
# line outside these shapes fails the check, so the check compares every
# version it finds. It ignores YAML comment lines and reports every problem
# before it exits.
set -euo pipefail
shopt -s nullglob

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORKFLOW_DIR="$ROOT/.github/workflows"
CI_FILE="$WORKFLOW_DIR/ci.yml"
ACTION_DIR="$ROOT/.github/actions"
BUILDING_DOC="$ROOT/docs/maintainers/building.md"

TOOLS=(cargo-llvm-cov cargo-machete cargo-deny)
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

# Reports that tool `$1` has version `$3` on `$2` and version `$5` on `$4`,
# each location a `<file>:<line>`.
report_mismatch() {
  echo "error: $1 version mismatch:" >&2
  echo "  $2 pins $3" >&2
  echo "  $4 pins $5" >&2
  FAILED=1
}

for tool in "${TOOLS[@]}"; do
  pin_re="[[:space:]]*tool: ${tool}@${VERSION_RE}[[:space:]]*(#.*)?"
  pin_shape="tool: ${tool}@<version>"
  install_re="cargo install --locked ${tool} --version ${VERSION_RE}"
  install_shape="--locked ${tool} --version <version>"

  # Without one ci.yml pin there is no version to compare against, but the
  # other files are still checked for their own line shape and count.
  ci_version=""
  collect_pins "$CI_FILE" "$tool" yaml "$pin_re" "$pin_shape"
  if single_pin "$CI_FILE" "$pin_shape" pin; then
    ci_at="${CI_FILE#"$ROOT"/}:${PIN_LINE}"
    ci_version=$PIN_VERSION
  fi

  collect_pins "$BUILDING_DOC" "$tool" markdown "$install_re" "$install_shape"
  if single_pin "$BUILDING_DOC" "$install_shape" line &&
    [ -n "$ci_version" ] && [ "$PIN_VERSION" != "$ci_version" ]; then
    report_mismatch "$tool" "$ci_at" "$ci_version" \
      "${BUILDING_DOC#"$ROOT"/}:${PIN_LINE}" "$PIN_VERSION"
  fi

  for file in "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml \
    "$ACTION_DIR"/*/action.yml "$ACTION_DIR"/*/action.yaml; do
    [ "$file" != "$CI_FILE" ] || continue
    collect_pins "$file" "$tool" yaml "$pin_re" "$pin_shape"
    while read -r line version; do
      if [ -n "$line" ] && [ -n "$ci_version" ] && [ "$version" != "$ci_version" ]; then
        report_mismatch "$tool" "$ci_at" "$ci_version" "${file#"$ROOT"/}:${line}" "$version"
      fi
    done <<<"$PINS"
  done
done

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi

echo "gate tool versions match the ci.yml pins in building.md, the workflows, and the actions"

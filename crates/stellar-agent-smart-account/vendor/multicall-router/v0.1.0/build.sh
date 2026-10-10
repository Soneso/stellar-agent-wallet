#!/usr/bin/env bash
# Re-vendors vendor/multicall-router/v0.1.0/multicall_router.wasm.
# It builds the file from the committed source with its pinned tools and copies
# the output here. The vendored-wasm workflow rebuilds the file with
# .github/scripts/rebuild-vendored-wasm.sh and never runs this script.
#
# Usage: vendor/multicall-router/v0.1.0/build.sh (from any working directory).
# Prerequisites:
#   - rustup toolchain install 1.99.0 --profile minimal --target wasm32v1-none;
#   - stellar on PATH whose first --version line is
#     "stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)", built by
#     RUSTUP_TOOLCHAIN=1.98.0 cargo install --locked stellar-cli --version 28.1.0;
#   - a CARGO_HOME without a cargo config file, since the build refuses one.
#
# The source is the independent Cargo workspace at contracts/multicall-router/ in
# the repository root. It is not a member of the wallet workspace and is not
# part of the published smart-account package; only the Wasm built here is.
# The build runs through the --exec mode of rebuild-vendored-wasm.sh, so it
# applies the same environment refusals and allowlist as the workflow. It runs
# --locked against the committed Cargo.lock, in a copy of the tracked source
# files and a fresh target directory that are removed on exit.
set -euo pipefail

ARTIFACT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$ARTIFACT_DIR/../../../../.." && pwd -P)
REBUILD="$REPO_ROOT/.github/scripts/rebuild-vendored-wasm.sh"
SOURCE="contracts/multicall-router"
WASM_NAME="multicall_router.wasm"
TOOLCHAIN="1.99.0"
STELLAR_VERSION_LINE="stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)"
# Optimizer bundled with stellar-cli 28.1.0: the wasm-opt crate at this
# version (stellar-cli v28.1.0 Cargo.lock).
PINNED_OPTIMIZER="wasm-opt crate 0.116.1"

STELLAR_BIN=$(command -v stellar) || {
  echo "ERROR: stellar is not on PATH" >&2
  exit 1
}
STELLAR_VERSION=$("$STELLAR_BIN" --version)
STELLAR_VERSION=${STELLAR_VERSION%%$'\n'*}
if [ "$STELLAR_VERSION" != "$STELLAR_VERSION_LINE" ]; then
  echo "ERROR: $STELLAR_BIN prints '$STELLAR_VERSION' as its first --version line, not '$STELLAR_VERSION_LINE'" >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/src" "$WORK/target"
copied=0
while IFS= read -r -d '' file; do
  mkdir -p "$WORK/src/$(dirname "${file#"$SOURCE"/}")"
  cp "$REPO_ROOT/$file" "$WORK/src/${file#"$SOURCE"/}"
  copied=1
done < <(git -C "$REPO_ROOT" -c core.quotePath=false ls-files -z -- "$SOURCE/")
if [ "$copied" != 1 ]; then
  echo "ERROR: no tracked files under $REPO_ROOT/$SOURCE" >&2
  exit 1
fi

RUSTUP_TOOLCHAIN="$TOOLCHAIN" CARGO_TARGET_DIR="$WORK/target" \
  /bin/bash "$REBUILD" --exec --dir "$WORK/src" -- \
  "$STELLAR_BIN" contract build --locked 2>&1 | tee "$WORK/build.log"

# stellar-cli reports "<N> bytes optimized (original size was <M> bytes)" when
# its optimizer ran; any other report means the optimizer did not run.
OPTIMIZER_LINE=$(grep -m1 "Wasm File:" "$WORK/build.log" || true)
if printf '%s' "$OPTIMIZER_LINE" | grep -q "optimized"; then
  OPTIMIZER_DETAIL="${OPTIMIZER_LINE#*(}"
  OPTIMIZER_STATE="enabled: ${OPTIMIZER_DETAIL%)}"
else
  OPTIMIZER_STATE="not run"
fi

cp "$WORK/target/wasm32v1-none/release/$WASM_NAME" "$ARTIFACT_DIR/$WASM_NAME"

SHA=$(shasum -a 256 "$ARTIFACT_DIR/$WASM_NAME" | awk '{print $1}')
SIZE=$(wc -c <"$ARTIFACT_DIR/$WASM_NAME" | awk '{print $1}')
RUSTC_VERSION=$(RUSTUP_TOOLCHAIN="$TOOLCHAIN" /bin/bash "$REBUILD" --exec --dir "$WORK/src" -- rustc --version)
SOROBAN_SDK_VERSION=$(awk '/^name = "soroban-sdk"$/ { getline; gsub(/version = |"/, ""); print; exit }' \
  "$WORK/src/Cargo.lock")

echo ""
echo "sha256($WASM_NAME) = $SHA"
echo "size = $SIZE bytes"
echo "rustc-version = $RUSTC_VERSION"
echo "stellar-cli-version = $STELLAR_VERSION"
echo "soroban-sdk-version = $SOROBAN_SDK_VERSION"
echo "target = wasm32v1-none"
echo "optimizer = $OPTIMIZER_STATE"
echo "optimizer-version = $PINNED_OPTIMIZER (bundled with stellar-cli 28.1.0)"
echo ""
echo "If the sha256 differs from the committed value, update, in one change:"
echo "  - vendor/multicall-router/v0.1.0/REFERENCE.md (digest, size, versions),"
echo "  - the multicall_router.wasm row of WASM_PINS in build.rs,"
echo "  - MULTICALL_WASM_SHA256 in src/multicall.rs."
echo "The committed source, toolchain, and stellar-cli reproduce the committed digest"
echo "on macOS (Apple Silicon); a different digest means an input differs."

#!/usr/bin/env bash
# Re-vendors vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm.
# It builds the file from its pinned source with its pinned tools and copies
# the output here. The vendored-wasm workflow rebuilds the file with
# .github/scripts/rebuild-vendored-wasm.sh and never runs this script.
#
# This Wasm is cargo's cdylib output of the v0.7.1 stellar-accounts library. It
# keeps the full contractspecv0 section; the release/ output has that section
# filtered away by spec shaking.
#
# Usage: OZ_CONTRACTS_DIR=<clone> vendor/oz-stellar-accounts/v0.7.1/build.sh
# Prerequisites:
#   - a clone of https://github.com/OpenZeppelin/stellar-contracts in
#     OZ_CONTRACTS_DIR that holds commit 3f81125bed3114cc93f5fca6d13240082050269a
#     (tag v0.7.1);
#   - rustup toolchain install 1.94.0 --profile minimal --target wasm32v1-none;
#   - stellar on PATH, built as PROVENANCE.md states, whose first --version
#     line is "stellar 25.2.0";
#   - a CARGO_HOME without a cargo config file, since the build refuses one.
#
# The build runs through the --exec mode of rebuild-vendored-wasm.sh, so it
# applies the same environment refusals and allowlist as the workflow, in a
# detached worktree and a fresh target directory that are removed on exit.
set -euo pipefail

ARTIFACT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$ARTIFACT_DIR/../../../../.." && pwd -P)
REBUILD="$REPO_ROOT/.github/scripts/rebuild-vendored-wasm.sh"
OZ_CLONE="${OZ_CONTRACTS_DIR:?set OZ_CONTRACTS_DIR to a clone of https://github.com/OpenZeppelin/stellar-contracts}"
PIN_COMMIT="3f81125bed3114cc93f5fca6d13240082050269a"
TOOLCHAIN="1.94.0"
STELLAR_VERSION_LINE="stellar 25.2.0"
PACKAGE="stellar-accounts"
OUTPUT="release/deps/stellar_accounts.wasm"
WASM_NAME="stellar_accounts.wasm"

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
if ! git -C "$OZ_CLONE" cat-file -e "$PIN_COMMIT^{commit}" 2>/dev/null; then
  echo "ERROR: $OZ_CLONE does not hold commit $PIN_COMMIT" >&2
  exit 1
fi

WORK=$(mktemp -d)
cleanup() {
  git -C "$OZ_CLONE" worktree remove --force "$WORK/src" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
git -C "$OZ_CLONE" worktree add --detach --quiet "$WORK/src" "$PIN_COMMIT"
mkdir "$WORK/target"

echo "The build passes no --optimize; stellar-cli 25.2.0 runs its bundled wasm-opt only with that flag."
# Each example build that depends on stellar-accounts rewrites its deps/
# cdylib, so this build runs alone in its fresh target directory.
RUSTUP_TOOLCHAIN="$TOOLCHAIN" CARGO_TARGET_DIR="$WORK/target" \
  /bin/bash "$REBUILD" --exec --dir "$WORK/src" -- \
  "$STELLAR_BIN" contract build --locked --package "$PACKAGE"

cp "$WORK/target/wasm32v1-none/$OUTPUT" "$ARTIFACT_DIR/$WASM_NAME"

SHA=$(shasum -a 256 "$ARTIFACT_DIR/$WASM_NAME" | awk '{print $1}')
SIZE=$(wc -c <"$ARTIFACT_DIR/$WASM_NAME" | awk '{print $1}')
RUSTC_VERSION=$(RUSTUP_TOOLCHAIN="$TOOLCHAIN" /bin/bash "$REBUILD" --exec --dir "$WORK/src" -- rustc --version)

echo ""
echo "sha256($WASM_NAME) = $SHA"
echo "size = $SIZE bytes"
echo "rustc-version = $RUSTC_VERSION"
echo "stellar-cli-version = $STELLAR_VERSION"
echo "optimizer = none"
echo ""
echo "If the sha256 differs from the committed value, update, in one change:"
echo "  - vendor/oz-stellar-accounts/v0.7.1/PROVENANCE.md (digest, size, versions)."
echo "The pinned commit, toolchain, and stellar-cli reproduce the committed digest on"
echo "macOS (Apple Silicon); a different digest means an input differs."

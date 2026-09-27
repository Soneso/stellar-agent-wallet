#!/usr/bin/env bash
# Reproducibility script for vendor/cap85-beacon/v0.1.0/cap85_beacon.wasm.
# Usage: ./vendor/cap85-beacon/v0.1.0/build.sh   (from crates/stellar-agent-smart-account)
#        or run it by path from anywhere; it resolves every location itself.
# Pre-requisite: stellar-cli 28.1.0 (`stellar contract build`, which compiles
#   for wasm32v1-none and runs its bundled optimizer by default).
# Pre-requisite: rustup target add wasm32v1-none --toolchain stable
#
# The source is the independent Cargo workspace at contracts/cap85-beacon/ in
# the repository root. It is not a member of the wallet workspace and is not
# part of the published smart-account package; only the Wasm built here is.
# The build is --locked against the committed contracts/cap85-beacon/Cargo.lock.
set -euo pipefail

ARTEFACT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${ARTEFACT_DIR}/../../../../.." && pwd)"
SOURCE_DIR="${REPO_ROOT}/contracts/cap85-beacon"
WASM_NAME="cap85_beacon.wasm"
PINNED_STELLAR_CLI="28.1.0"
# Optimizer bundled with stellar-cli 28.1.0: the wasm-opt crate at this
# version (stellar-cli v28.1.0 Cargo.lock).
PINNED_OPTIMIZER="wasm-opt crate 0.116.1"

if [ ! -f "${SOURCE_DIR}/Cargo.toml" ]; then
    echo "ERROR: beacon source not found at ${SOURCE_DIR}" >&2
    exit 1
fi

STELLAR_VERSION=$(stellar version --only-version)
if [ "${STELLAR_VERSION}" != "${PINNED_STELLAR_CLI}" ]; then
    echo "WARNING: stellar-cli ${STELLAR_VERSION} differs from the pinned ${PINNED_STELLAR_CLI};" >&2
    echo "         the optimizer it bundles may differ and the digest may not reproduce." >&2
    OPTIMIZER_VERSION="bundled with stellar-cli ${STELLAR_VERSION} (see its Cargo.lock)"
else
    OPTIMIZER_VERSION="${PINNED_OPTIMIZER} (bundled with stellar-cli ${STELLAR_VERSION})"
fi

BUILD_LOG=$(mktemp)
trap 'rm -f "${BUILD_LOG}"' EXIT

pushd "${SOURCE_DIR}" >/dev/null
stellar contract build --locked 2>&1 | tee "${BUILD_LOG}"
popd >/dev/null

# stellar-cli reports "<N> bytes optimized (original size was <M> bytes)" when
# its optimizer ran; anything else means the optimizer did not run.
OPTIMIZER_LINE=$(grep -m1 "Wasm File:" "${BUILD_LOG}" || true)
if printf '%s' "${OPTIMIZER_LINE}" | grep -q "optimized"; then
    OPTIMIZER_DETAIL="${OPTIMIZER_LINE#*(}"
    OPTIMIZER_STATE="enabled: ${OPTIMIZER_DETAIL%)}"
else
    OPTIMIZER_STATE="not run"
fi

cp "${SOURCE_DIR}/target/wasm32v1-none/release/${WASM_NAME}" "${ARTEFACT_DIR}/${WASM_NAME}"

SHA=$(shasum -a 256 "${ARTEFACT_DIR}/${WASM_NAME}" | awk '{print $1}')
SIZE=$(wc -c < "${ARTEFACT_DIR}/${WASM_NAME}" | awk '{print $1}')
RUSTC_VERSION=$(rustc --version)
SOROBAN_SDK_VERSION=$(awk '/^name = "soroban-sdk"$/ { getline; gsub(/version = |"/, ""); print; exit }' \
    "${SOURCE_DIR}/Cargo.lock")

echo ""
echo "sha256(${WASM_NAME}) = ${SHA}"
echo "size = ${SIZE} bytes"
echo "rustc-version = ${RUSTC_VERSION}"
echo "stellar-cli-version = $(stellar --version | head -1)"
echo "soroban-sdk-version = ${SOROBAN_SDK_VERSION}"
echo "target = wasm32v1-none"
echo "optimizer = ${OPTIMIZER_STATE}"
echo "optimizer-version = ${OPTIMIZER_VERSION}"
echo ""
echo "If the sha256 differs from the committed value, update, in one change:"
echo "  - vendor/cap85-beacon/v0.1.0/REFERENCE.md (digest, size, toolchain),"
echo "  - the cap85_beacon.wasm row of WASM_PINS in build.rs,"
echo "  - CAP85_BEACON_WASM_SHA256 in src/cap85_beacon.rs."
echo "Rust to Wasm compilation is not bit-identical across rustc or stellar-cli"
echo "versions; a differing digest after a toolchain change is expected and is"
echo "re-attested by re-vendoring, never accepted silently."

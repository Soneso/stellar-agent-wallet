#!/usr/bin/env bash
# Reproducibility script for vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm.
# Usage: ./vendor/oz-smart-account-multisig/v0.7.1/build.sh
# Pre-requisite: a local clone of the OpenZeppelin stellar-contracts repository
#   (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.1, with its path
#   supplied via the OZ_CONTRACTS_DIR environment variable.
# Pre-requisite: stellar-cli >= 25.2.0 installed (builds via `stellar contract build`).
# Pre-requisite: rustup target add wasm32v1-none --toolchain stable
#
# WASM artefact provenance note:
# This WASM is the DEPLOYABLE multisig-account-example contract for on-chain
# upload via UploadContractWasm. Unlike the stellar-accounts library WASM at
# vendor/oz-stellar-accounts/v0.7.1/ (which is needed for contractimport!
# type generation), this artefact is the deployable contract that exposes
# __constructor(signers: Vec<Signer>, policies: Map<Address, Val>).
set -euo pipefail

CRATE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OZ_CLONE="${OZ_CONTRACTS_DIR:?set OZ_CONTRACTS_DIR to a local clone of OpenZeppelin/stellar-contracts v0.7.1}"
PIN_SHA="3f81125bed3114cc93f5fca6d13240082050269a"
ARTEFACT_DIR="${CRATE_ROOT}/vendor/oz-smart-account-multisig/v0.7.1"

# Restore the OZ clone's prior HEAD on exit so the operator running build.sh
# from an unrelated working state does not silently lose their place.
# Trap fires on normal exit, error exit, and signal-interrupted exit.
PRIOR_HEAD=$(cd "${OZ_CLONE}" && git rev-parse HEAD)
trap "cd '${OZ_CLONE}' && git checkout --quiet '${PRIOR_HEAD}'" EXIT

pushd "${OZ_CLONE}" >/dev/null
git fetch --quiet origin
git checkout --quiet "${PIN_SHA}"

# Build the deployable multisig-account-example WASM.
# Package name is multisig-account-example per
# examples/multisig-smart-account/account/Cargo.toml.
stellar contract build --package multisig-account-example

popd >/dev/null

# Copy the release WASM (not deps/ — this is a deployable, not a type-binding).
cp "${OZ_CLONE}/target/wasm32v1-none/release/multisig_account_example.wasm" \
    "${ARTEFACT_DIR}/multisig_account_example.wasm"

SHA=$(shasum -a 256 "${ARTEFACT_DIR}/multisig_account_example.wasm" | awk '{print $1}')
SIZE=$(wc -c < "${ARTEFACT_DIR}/multisig_account_example.wasm" | awk '{print $1}')
RUSTC_VERSION=$(rustup run stable rustc --version)
STELLAR_VERSION=$(stellar --version | head -1)
WASM_OPT_VERSION=$(wasm-opt --version 2>/dev/null || echo "not available")

echo "sha256(multisig_account_example.wasm) = ${SHA}"
echo "size = ${SIZE} bytes"
echo "rustc-version = ${RUSTC_VERSION}"
echo "stellar-cli = ${STELLAR_VERSION}"
echo "wasm-opt = ${WASM_OPT_VERSION}"
echo ""
echo "Update vendor/oz-smart-account-multisig/v0.7.1/PROVENANCE.md with the values above and"
echo "crates/stellar-agent-smart-account/src/deployment/deploy.rs MULTISIG_ACCOUNT_WASM_SHA256"
echo "const with the sha256."

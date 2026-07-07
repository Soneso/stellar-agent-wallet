#!/usr/bin/env bash
# Reproducibility script for vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm.
# Usage: ./vendor/oz-stellar-accounts/v0.7.2/build.sh
# Pre-requisite: a local clone of the OpenZeppelin stellar-contracts repository
#   (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2, with its path
#   supplied via the OZ_CONTRACTS_DIR environment variable.
# Pre-requisite: stellar-cli >= 25.2.0 installed (builds via `stellar contract build`
#   which sets SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2).
# Pre-requisite: rustup target add wasm32v1-none --toolchain stable
#
# WASM artefact provenance note:
# The correct artefact for contractimport! is the UNOPTIMISED cdylib from
# target/wasm32v1-none/release/deps/ because the optimised release/ output
# has its contractspecv0 section stripped by spec-shaking (experimental_spec_shaking_v2
# feature in the OZ workspace Cargo.toml). The deps/ cdylib retains the full
# 16 KB contractspecv0 section which contractimport! parses to generate
# host-side typed bindings.
set -euo pipefail
CRATE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OZ_CLONE="${OZ_CONTRACTS_DIR:?set OZ_CONTRACTS_DIR to a local clone of OpenZeppelin/stellar-contracts v0.7.2}"
PIN_SHA="a9c42169000638da937577f592ebf61a7a3c94ca"
ARTEFACT_DIR="${CRATE_ROOT}/vendor/oz-stellar-accounts/v0.7.2"

# Restore the OZ clone's prior HEAD on exit so the operator running build.sh
# from an unrelated working state does not silently lose their place.
PRIOR_HEAD=$(cd "${OZ_CLONE}" && git rev-parse HEAD)
trap "cd '${OZ_CLONE}' && git checkout --quiet '${PRIOR_HEAD}'" EXIT

pushd "${OZ_CLONE}" >/dev/null
git fetch --quiet origin
git checkout --quiet "${PIN_SHA}"

# Use `stellar contract build` which sets SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2
# (required by the experimental_spec_shaking_v2 soroban-sdk feature in the OZ workspace).
stellar contract build --package stellar-accounts

popd >/dev/null

# Copy the UNOPTIMISED cdylib from deps/ (retains full contractspecv0 section).
# The optimised release/ output has contractspecv0 stripped to 15 bytes by spec-shaking;
# contractimport! requires the full 16 KB spec for type generation.
cp "${OZ_CLONE}/target/wasm32v1-none/release/deps/stellar_accounts.wasm" "${ARTEFACT_DIR}/stellar_accounts.wasm"
SHA=$(shasum -a 256 "${ARTEFACT_DIR}/stellar_accounts.wasm" | awk '{print $1}')
SIZE=$(wc -c < "${ARTEFACT_DIR}/stellar_accounts.wasm" | awk '{print $1}')
RUSTC_VERSION=$(rustup run stable rustc --version)

echo "sha256(stellar_accounts.wasm) = ${SHA}"
echo "size = ${SIZE} bytes"
echo "rustc-version = ${RUSTC_VERSION}"
echo ""
echo "Update vendor/oz-stellar-accounts/v0.7.2/PROVENANCE.md with the three values above"
echo "(sha256, size, rustc-version) and"
echo "crates/stellar-agent-smart-account/src/bindings.rs WASM_SHA256 const with the sha256."
echo ""
echo "Note: soroban_sdk::contractimport! sha256 arg is NOT used (E0425 compile failure"
echo "— contractimport! fails on this WASM). The runtime WASM_SHA256 const +"
echo "wasm_sha256_matches_provenance test is the integrity gate."

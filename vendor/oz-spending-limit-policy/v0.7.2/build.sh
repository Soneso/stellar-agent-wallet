#!/usr/bin/env bash
# Reproducibility script for vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm.
# Usage: ./vendor/oz-spending-limit-policy/v0.7.2/build.sh
# Pre-requisite: a local clone of the OpenZeppelin stellar-contracts repository
#   (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2, with its path
#   supplied via the OZ_CONTRACTS_DIR environment variable.
# Pre-requisite: stellar-cli >= 25.2.0 installed (builds via `stellar contract build`).
# Pre-requisite: rustup target add wasm32v1-none --toolchain stable
#
# WASM artefact provenance note:
# This WASM is the DEPLOYABLE multisig-spending-limit-policy-example contract for
# on-chain upload via UploadContractWasm. The wallet deploys it as a one-shot
# per-network singleton via `smart-account deploy-spending-limit-policy`. One
# deployed instance serves every account and context rule on the network because
# the policy keys all state by AccountContext(smart_account, context_rule_id).
# The deployed contract is invoked by the smart-account's __check_auth to enforce
# a rolling-window transfer spending limit on CallContract-scoped rules.
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OZ_CLONE="${OZ_CONTRACTS_DIR:?set OZ_CONTRACTS_DIR to a local clone of OpenZeppelin/stellar-contracts v0.7.2}"
PIN_SHA="a9c42169000638da937577f592ebf61a7a3c94ca"
ARTEFACT_DIR="${WORKSPACE_ROOT}/vendor/oz-spending-limit-policy/v0.7.2"

# Restore the OZ clone's prior HEAD on exit so the operator running build.sh
# from an unrelated working state does not silently lose their place.
# Trap fires on normal exit, error exit, and signal-interrupted exit.
PRIOR_HEAD=$(cd "${OZ_CLONE}" && git rev-parse HEAD)
trap "cd '${OZ_CLONE}' && git checkout --quiet '${PRIOR_HEAD}'" EXIT

pushd "${OZ_CLONE}" >/dev/null
CURRENT_HEAD=$(git rev-parse HEAD)
if [ "${CURRENT_HEAD}" != "${PIN_SHA}" ]; then
    echo "INFO: OZ HEAD ${CURRENT_HEAD} differs from pinned ${PIN_SHA}; checking out pin."
    git checkout --quiet "${PIN_SHA}"
fi

# Build the deployable multisig-spending-limit-policy-example WASM.
# Package name is multisig-spending-limit-policy-example per
# examples/multisig-smart-account/spending-limit-policy/Cargo.toml.
stellar contract build --package multisig-spending-limit-policy-example

popd >/dev/null

# Copy the release WASM (not deps/ — this is a deployable, not a type-binding).
cp "${OZ_CLONE}/target/wasm32v1-none/release/multisig_spending_limit_policy_example.wasm" \
    "${ARTEFACT_DIR}/multisig_spending_limit_policy_example.wasm"

SHA=$(shasum -a 256 "${ARTEFACT_DIR}/multisig_spending_limit_policy_example.wasm" | awk '{print $1}')
SIZE=$(wc -c < "${ARTEFACT_DIR}/multisig_spending_limit_policy_example.wasm" | awk '{print $1}')
RUSTC_VERSION=$(rustup run stable rustc --version)
STELLAR_VERSION=$(stellar --version | head -1)
WASM_OPT_VERSION=$(wasm-opt --version 2>/dev/null || echo "not available")

echo "sha256(multisig_spending_limit_policy_example.wasm) = ${SHA}"
echo "size = ${SIZE} bytes"
echo "rustc-version = ${RUSTC_VERSION}"
echo "stellar-cli-version = ${STELLAR_VERSION}"
echo "wasm-opt-version = ${WASM_OPT_VERSION}"
echo ""
echo "Update vendor/oz-spending-limit-policy/v0.7.2/PROVENANCE.md with the values above,"
echo "crates/stellar-agent-smart-account/src/spending_limit_policy.rs"
echo "SPENDING_LIMIT_POLICY_WASM_SHA256 const with the sha256, and the build.rs pin."
echo ""
echo "If the rebuilt sha256 differs from the committed value: Rust -> WASM compilation"
echo "is not always bit-identical across rustc / stellar-cli patch versions. Bump the"
echo "toolchain pin in PROVENANCE.md (with operator authorisation), re-vendor, and"
echo "re-attest. Do NOT silently accept."

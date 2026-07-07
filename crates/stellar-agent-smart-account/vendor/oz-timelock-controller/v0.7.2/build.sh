#!/usr/bin/env bash
# Reproducibility script for vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm.
# Usage: ./vendor/oz-timelock-controller/v0.7.2/build.sh
# Pre-requisite: a local clone of the OpenZeppelin stellar-contracts repository
#   (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2, with its path
#   supplied via the OZ_CONTRACTS_DIR environment variable.
# Pre-requisite: stellar-cli >= 25.2.0 installed (builds via `stellar contract build`
#   which sets SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2).
# Pre-requisite: rustup target add wasm32v1-none --toolchain stable
set -euo pipefail
CRATE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OZ_CLONE="${OZ_CONTRACTS_DIR:?set OZ_CONTRACTS_DIR to a local clone of OpenZeppelin/stellar-contracts v0.7.2}"
PIN_SHA="a9c42169000638da937577f592ebf61a7a3c94ca"
ARTEFACT_DIR="${CRATE_ROOT}/vendor/oz-timelock-controller/v0.7.2"

# Restore the OZ clone's prior HEAD on exit so the operator running build.sh
# from an unrelated working state does not silently lose their place.
PRIOR_HEAD=$(cd "${OZ_CLONE}" && git rev-parse HEAD)
trap "cd '${OZ_CLONE}' && git checkout --quiet '${PRIOR_HEAD}'" EXIT

pushd "${OZ_CLONE}" >/dev/null
git fetch --quiet origin
git checkout --quiet "${PIN_SHA}"

stellar contract build --package timelock-controller-example

popd >/dev/null

# Copy the optimised release/ output (on-chain deployable; has all exported functions).
# Unlike the stellar-accounts library WASM, the timelock-controller-example release/
# output is the correct deployable — it is not spec-shaked to empty because it is a
# standalone contract with real exported function bodies.
cp "${OZ_CLONE}/target/wasm32v1-none/release/timelock_controller_example.wasm" \
   "${ARTEFACT_DIR}/timelock_controller_example.wasm"

SHA=$(shasum -a 256 "${ARTEFACT_DIR}/timelock_controller_example.wasm" | awk '{print $1}')
SIZE=$(wc -c < "${ARTEFACT_DIR}/timelock_controller_example.wasm" | awk '{print $1}')
RUSTC_VERSION=$(rustup run stable rustc --version)

echo "sha256(timelock_controller_example.wasm) = ${SHA}"
echo "size = ${SIZE} bytes"
echo "rustc-version = ${RUSTC_VERSION}"
echo ""
echo "Update vendor/oz-timelock-controller/v0.7.2/PROVENANCE.md with the three values above."

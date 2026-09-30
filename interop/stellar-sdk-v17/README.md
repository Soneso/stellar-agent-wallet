# Stellar SDK v17 authorization preimage harness

This frozen harness checks the wallet's Soroban authorization preimages against
the released Stellar JavaScript SDK, which builds CAP-71 `AddressV2`
credentials by default. It is not a runtime dependency of any wallet crate.

Pins:

- `@stellar/stellar-sdk@17.2.0`
- Node `24.5.0`
- pnpm `10.33.0`

The SDK is Apache-2.0 licensed as recorded in the frozen lockfile package
metadata. The fixtures and the live driver use only public SDK exports.

Contents:

- `build-fixtures.mjs` builds one envelope type 9 (`Address` credentials) and
  one envelope type 10 (`AddressV2` credentials) preimage from fixed inputs.
  No signer and no secret key is involved.
- `gen-fixture.mjs` writes them to `fixtures/`; the Rust test
  `crates/stellar-agent-soroban-auth/tests/sdk_preimage_fixtures.rs` rebuilds
  both preimages and compares bytes and hashes.
- `check.mjs` asserts the checked-in fixtures equal the pinned SDK's output.
- `sign-roundtrip.mjs` is the live driver of the SEP-43 testnet acceptance
  test `crates/stellar-agent-sep43/tests/sep43_sdk_v17_interop_testnet_acceptance.rs`,
  which spawns it and speaks line-delimited JSON on its stdin and stdout.

Run the offline check from the repository root:

```sh
.github/scripts/test-sdk-v17-interop.sh
```

Regenerate the fixtures after a deliberate SDK pin change:

```sh
cd interop/stellar-sdk-v17
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm run gen-fixture
```

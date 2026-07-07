# OZ multisig-account-example v0.7.1 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `3f81125bed3114cc93f5fca6d13240082050269a`
  (tag `v0.7.1`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **Package name:** `multisig-account-example` (per
  `examples/multisig-smart-account/account/Cargo.toml`). The compiled WASM filename
  derives from the package name: `multisig_account_example.wasm`. Do NOT rename the
  file without re-running this build.sh step and updating this PROVENANCE.md.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.94.0 (4a4ef493e 2026-03-02) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package multisig-account-example`
  (stellar-cli 25.2.0) inside a local clone of the OpenZeppelin stellar-contracts repository
  (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.1.
  See `vendor/oz-smart-account-multisig/v0.7.1/build.sh` for the full reproducibility
  script including the EXIT-trap HEAD-restoration discipline.
- **stellar-cli version:** `stellar 25.2.0` (captured at build time; pin this specific
  version so `experimental_spec_shaking_v2` behaviour is reproducible).
- **Optimiser version:** not used; `wasm-opt` was not available on the build host.
  The artefact is the `release` profile output (`stellar contract build` release mode).
  Note `stellar contract build` applies spec-shaking internally when the OZ workspace
  enables `experimental_spec_shaking_v2`; the result is a self-contained deployable
  WASM with no `contractspecv0` section needed (unlike the `stellar-accounts` library
  WASM at `vendor/oz-stellar-accounts/v0.7.1/` which IS needed for `contractimport!`).
- **sha256(multisig_account_example.wasm):** `06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239`
- **Size:** 44199 bytes.
- **Why optimised-release, not deps/:** This WASM is deployed on-chain via
  `UploadContractWasm`. On-chain storage cost scales with size; the `release` profile
  output is the production deployment artefact. Off-chain type-binding parity is NOT
  a requirement here — `contractimport!` is not used against this WASM; type
  re-exports from `stellar_accounts::smart_account` supply all type shapes.
- **Cross-reference:** `vendor/oz-stellar-accounts/v0.7.1/` is the contracts-library
  WASM used for `contractimport!`-based type bindings. That artefact has no
  `__constructor`, no `__check_auth`, and no deployable contract entry. This artefact
  IS the deployable entry — `examples/multisig-smart-account/account/src/contract.rs:32`
  defines `pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>)`.
- **Integrity gate:** the `MULTISIG_ACCOUNT_WASM_SHA256` constant in
  `crates/stellar-agent-smart-account/src/deployment/deploy.rs` matches this value;
  the `multisig_account_wasm_sha256_matches_provenance` unit test verifies equality
  on every `cargo test` invocation. Additionally a `debug_assert!` at the entry of
  `deploy_smart_account()` re-verifies the hash on every runtime invocation in debug
  builds.

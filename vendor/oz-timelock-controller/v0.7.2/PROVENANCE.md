# OZ timelock-controller-example v0.7.2 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
  (tag `v0.7.2`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **What changed vs v0.7.1:** v0.7.2 bumps `soroban_sdk` to 26.1.0 (upstream
  `Context`-type fix, `rs-soroban-sdk#1875`). The contract source
  (`examples/timelock-controller/src/contract.rs`) is byte-identical to v0.7.1; only the
  SDK pin changed, so the constructor and role semantics are unchanged. The WASM bytes
  differ only because of the toolchain and SDK bump. Only NEW timelock deployments use
  these v0.7.2 bytes.
- **Package:** `timelock-controller-example`
  (`examples/timelock-controller/src/contract.rs`).
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package timelock-controller-example`
  (stellar-cli 25.2.0) inside the OZ clone, then copy the optimised WASM from
  `target/wasm32v1-none/release/timelock_controller_example.wasm`.
  See `vendor/oz-timelock-controller/v0.7.2/build.sh` for the full reproducibility script.
- **Why release/ not deps/:** the optimised `release/` output is the correct deployable
  artefact for on-chain upload. Unlike `stellar-accounts` (a library crate), the
  timelock-controller-example is a standalone deployable; its `release/` output retains
  all exported functions needed for on-chain invocation. The `deps/` cdylib is NOT used
  here because we do not use `contractimport!` against this WASM (the timelock surface
  is invoked via raw `InvokeHostFunction` XDR construction, not soroban-sdk host bindings).
- **sha256(timelock_controller_example.wasm):**
  `ef360d61a44648176f0aae923b9884c6ac5e5a9229af5eb8ab120e81cc4cc1f4`
- **Size:** 31283 bytes.
- **Usage:** Uploaded to testnet in `smart_account_timelock_testnet_acceptance.rs`
  via `HostFunction::UploadContractWasm` + `HostFunction::CreateContractV2`.
  The contract is instantiated inline per test (not a one-time singleton).
- **Constructor:** `__constructor(min_delay: u32, proposers: Vec<Address>,
  executors: Vec<Address>, admin: Option<Address>)` — sets the minimum delay,
  grants PROPOSER + CANCELLER roles to proposers, EXECUTOR role to executors,
  and sets the admin (defaults to the contract itself if `None`).
- **Role semantics:** Proposers automatically get CANCELLER_ROLE at construction time
  (contract.rs:255-258, SHA `a9c4216`). If no executors are configured, anyone can
  execute ready operations (contract.rs:296, SHA `a9c4216`).
- **Integrity:** The WASM is protected by a three-layer supply-chain gate:
  1. **Compile-time** — `build.rs` in `stellar-agent-smart-account` verifies
     `sha256(TIMELOCK_CONTROLLER_WASM bytes)` against the const
     `TIMELOCK_CONTROLLER_WASM_SHA256` at build time; a mismatch is a compile error.
  2. **Runtime** — `deploy_timelock_controller_body` re-verifies the hash before any
     upload attempt and returns `SaError::DeploymentFailed` on mismatch (not a panic).
  3. **Provenance** — this file is the supply-chain audit trail; the sha256 value
     above is the canonical reference.
  The const `TIMELOCK_CONTROLLER_WASM_SHA256` is declared `pub` in the production
  code path (`deployment/deploy_timelock_controller.rs`) and used by both the
  compile-time and runtime gates.

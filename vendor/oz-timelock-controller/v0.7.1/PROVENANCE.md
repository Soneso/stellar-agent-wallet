# OZ timelock-controller-example v0.7.1 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `3f81125bed3114cc93f5fca6d13240082050269a`
  (tag `v0.7.1`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **Package:** `timelock-controller-example`
  (`examples/timelock-controller/src/contract.rs`).
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.94.0 (4a4ef493e 2026-03-02) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package timelock-controller-example`
  (stellar-cli 25.2.0) inside the OZ clone, then copy the optimised WASM from
  `target/wasm32v1-none/release/timelock_controller_example.wasm`.
  See `vendor/oz-timelock-controller/v0.7.1/build.sh` for the full reproducibility script.
- **Why release/ not deps/:** the optimised `release/` output is the correct deployable
  artefact for on-chain upload. Unlike `stellar-accounts` (a library crate), the
  timelock-controller-example is a standalone deployable; its `release/` output retains
  all exported functions needed for on-chain invocation. The `deps/` cdylib is NOT used
  here because we do not use `contractimport!` against this WASM (the timelock surface
  is invoked via raw `InvokeHostFunction` XDR construction, not soroban-sdk host bindings).
- **sha256(timelock_controller_example.wasm):**
  `36299255cf77678a59d7fdfe9823d803be2bdddb9cc375be3130daed265295eb`
- **Size:** 28357 bytes.
- **Usage:** Uploaded to testnet in `wallet_smart_account_timelock_testnet_acceptance.rs`
  via `HostFunction::UploadContractWasm` + `HostFunction::CreateContractV2`.
  The contract is instantiated inline per test (not a one-time singleton).
- **Constructor:** `__constructor(min_delay: u32, proposers: Vec<Address>,
  executors: Vec<Address>, admin: Option<Address>)` — sets the minimum delay,
  grants PROPOSER + CANCELLER roles to proposers, EXECUTOR role to executors,
  and sets the admin (defaults to the contract itself if `None`).
- **Role semantics:** Proposers automatically get CANCELLER_ROLE at construction time
  (contract.rs:255-258, SHA `3f81125`). If no executors are configured, anyone can
  execute ready operations (contract.rs:296, SHA `3f81125`).
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

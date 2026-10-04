# OZ timelock-controller-example v0.7.2: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.2`,
  commit `a9c42169000638da937577f592ebf61a7a3c94ca`.
- **Version roles:** new timelock deployments use these v0.7.2 bytes, built
  with `soroban_sdk` 26.1.0. The contract source
  (`examples/timelock-controller/src/contract.rs`) is the same at v0.7.1 and
  v0.7.2, so the constructor and role semantics are the same. The two files
  differ in bytes because their toolchains and SDK versions differ.
- **Package:** `timelock-controller-example`
  (`examples/timelock-controller/src/contract.rs`).
- **Toolchain:** `rustc 1.96.0 (ac68faa20 2026-05-25)`, selected with
  `RUSTUP_TOOLCHAIN=1.96.0`, since the OZ `rust-toolchain.toml` names the
  floating `stable` channel. Target `wasm32v1-none`.
- **stellar-cli:** the first line of `stellar --version` is `stellar 25.2.0`.
  The binary is built by `cargo install --locked --path cmd/stellar-cli` from a
  `git archive` of stellar-cli tag `v25.2.0` (commit
  `28484880988199233a7e8e87c97cb12dac323cb3`) with host rustc 1.94.0, outside
  any git work tree. Its `cliver` meta entry then reads `25.2.0#`. A crates.io
  install of 25.2.0 records its revision in `cliver`, which adds 40 bytes.
- **Build command:** in a checkout of the source commit, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.96.0 stellar contract build --locked --package timelock-controller-example`.
  The output is `<target dir>/wasm32v1-none/release/timelock_controller_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries.
- **Why release/, not deps/:** the `release/` output is the deployable artifact for
  on-chain upload. The timelock-controller-example is a standalone deployable
  contract, so its `release/` output keeps every exported function needed for
  on-chain invocation; `stellar-accounts` is a library crate. The wallet does not
  `contractimport!` against this Wasm and invokes the timelock through raw
  `InvokeHostFunction` XDR, so it needs no `deps/` spec.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(timelock_controller_example.wasm):**
  `ef360d61a44648176f0aae923b9884c6ac5e5a9229af5eb8ab120e81cc4cc1f4`
- **Size:** 31283 bytes.
- **Usage:** the testnet suite `smart_account_timelock_testnet_acceptance.rs` uploads it
  with `HostFunction::UploadContractWasm` and `HostFunction::CreateContractV2` and
  instantiates the contract inline per test (not a one-time singleton).
- **Constructor:** `__constructor(min_delay: u32, proposers: Vec<Address>,
  executors: Vec<Address>, admin: Option<Address>)`. It sets the minimum delay,
  grants the PROPOSER and CANCELLER roles to proposers and the EXECUTOR role to
  executors, and sets the admin (the contract itself when `None`).
- **Role semantics:** proposers get CANCELLER_ROLE at construction time
  (contract.rs:255-258, commit `a9c4216`). With no executors configured, anyone can
  execute ready operations (contract.rs:296, commit `a9c4216`).
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record and the file's `WASM_PINS` row in `build.rs`.
  That row also fails every build of the crate on a mismatch. The unit tests in
  `src/vendored_wasm_tests.rs` fail unless `TIMELOCK_CONTROLLER_WASM` equals
  this file and `TIMELOCK_CONTROLLER_WASM_SHA256` equals its sha256. Before any
  upload, `deploy_timelock_controller` hashes `TIMELOCK_CONTROLLER_WASM` and
  returns `SaError::DeploymentFailed` unless the hash equals
  `TIMELOCK_CONTROLLER_WASM_SHA256`.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.

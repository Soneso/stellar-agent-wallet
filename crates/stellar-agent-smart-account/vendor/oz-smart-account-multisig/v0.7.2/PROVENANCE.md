# OZ multisig-account-example v0.7.2: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.2`,
  commit `a9c42169000638da937577f592ebf61a7a3c94ca`.
- **Version roles:** new smart-account deployments use these v0.7.2 bytes,
  built with `soroban_sdk` 26.1.0. The entrypoints, the ABI, and the
  `__constructor(signers: Vec<Signer>, policies: Map<Address, Val>)` surface
  are the same as at v0.7.1. The two files differ in bytes because their
  toolchains and SDK versions differ. Smart accounts deployed from the v0.7.1
  bytes stay valid and recognized.
- **Package:** `multisig-account-example`
  (`examples/multisig-smart-account/account/Cargo.toml`). The Wasm file name derives
  from the package name. Renaming the file takes a rebuild with `build.sh` and an
  update of this record.
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
  `RUSTUP_TOOLCHAIN=1.96.0 stellar contract build --locked --package multisig-account-example`.
  The output is `<target dir>/wasm32v1-none/release/multisig_account_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries. The result is a
  self-contained deployable Wasm that needs no `contractspecv0` section; the
  `stellar-accounts` library Wasm at `vendor/oz-stellar-accounts/v0.7.2/` keeps
  its spec for `contractimport!`.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(multisig_account_example.wasm):** `5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286`
- **Size:** 46253 bytes.
- **Why release/, not deps/:** the wallet uploads this Wasm with
  `UploadContractWasm`. On-chain storage cost scales with size; the `release`
  output is the production deployment artifact. Off-chain type-binding parity is
  not a requirement here: the wallet does not `contractimport!` against this Wasm,
  and type re-exports from `stellar_accounts::smart_account` supply all type shapes.
- **Cross-reference:** `vendor/oz-stellar-accounts/v0.7.2/` is the contracts-library
  Wasm used for `contractimport!`-based type bindings. That artifact has no
  `__constructor`, no `__check_auth`, and no deployable contract entry. This artifact
  is the deployable entry: `examples/multisig-smart-account/account/src/contract.rs`
  defines `pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>)`.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record and the file's `WASM_PINS` row in `build.rs`.
  That row also fails every build of the crate on a mismatch. The unit tests in
  `src/vendored_wasm_tests.rs` fail unless `MULTISIG_ACCOUNT_WASM` equals this
  file and `MULTISIG_ACCOUNT_WASM_SHA256` equals its sha256. In every build
  profile, `deploy_smart_account` hashes `MULTISIG_ACCOUNT_WASM` before any
  network request and returns `SaError::DeploymentFailed` unless the hash equals
  `MULTISIG_ACCOUNT_WASM_SHA256`.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.

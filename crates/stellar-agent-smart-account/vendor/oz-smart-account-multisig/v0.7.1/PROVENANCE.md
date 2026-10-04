# OZ multisig-account-example v0.7.1: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.1`,
  commit `3f81125bed3114cc93f5fca6d13240082050269a`.
- **Package:** `multisig-account-example`
  (`examples/multisig-smart-account/account/Cargo.toml`). The Wasm file name derives
  from the package name. Renaming the file takes a rebuild with `build.sh` and an
  update of this record.
- **Toolchain:** `rustc 1.94.0 (4a4ef493e 2026-03-02)`, selected with
  `RUSTUP_TOOLCHAIN=1.94.0`, since the OZ `rust-toolchain.toml` names the
  floating `stable` channel. Target `wasm32v1-none`.
- **stellar-cli:** the first line of `stellar --version` is `stellar 25.2.0`.
  The binary is built by `cargo install --locked --path cmd/stellar-cli` from a
  `git archive` of stellar-cli tag `v25.2.0` (commit
  `28484880988199233a7e8e87c97cb12dac323cb3`) with host rustc 1.94.0, outside
  any git work tree. Its `cliver` meta entry then reads `25.2.0#`. A crates.io
  install of 25.2.0 records its revision in `cliver`, which adds 40 bytes.
- **Build command:** in a checkout of the source commit, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.94.0 stellar contract build --locked --package multisig-account-example`.
  The output is `<target dir>/wasm32v1-none/release/multisig_account_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries. The result is a
  self-contained deployable Wasm that needs no `contractspecv0` section; the
  `stellar-accounts` library Wasm at `vendor/oz-stellar-accounts/v0.7.1/` keeps
  its spec for `contractimport!`.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(multisig_account_example.wasm):** `06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239`
- **Size:** 44199 bytes.
- **Why release/, not deps/:** smart accounts deployed on-chain from these bytes
  run this Wasm. On-chain storage cost scales with size; the `release` output is the
  production deployment artifact. The wallet does not `contractimport!` against this
  Wasm, and type re-exports from `stellar_accounts::smart_account` supply all type
  shapes. The wallet recognizes these accounts by their ABI, which v0.7.2 keeps;
  new deployments use the v0.7.2 bytes.
- **Cross-reference:** `vendor/oz-stellar-accounts/v0.7.1/` is the v0.7.1
  contracts-library Wasm. That artifact has no `__constructor`, no `__check_auth`,
  and no deployable contract entry. This artifact is the deployable entry:
  `examples/multisig-smart-account/account/src/contract.rs:32` defines
  `pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>)`.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record. `build.rs` carries no `WASM_PINS` row for
  this file, since the package excludes the v0.7.1 files and `build.rs` runs
  during `cargo package` verification. The unit test
  `vendored_table_entries_are_the_files_at_their_paths` in
  `src/vendored_wasm_tests.rs` fails unless the `VENDORED` entry for this path
  holds this file's bytes. No constant or allowlist of the crate pins this
  file's digest; `MULTISIG_ACCOUNT_WASM_SHA256` pins the v0.7.2 file.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file and this record in one change.

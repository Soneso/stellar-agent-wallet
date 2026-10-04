# OZ timelock-controller-example v0.7.1: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.1`,
  commit `3f81125bed3114cc93f5fca6d13240082050269a`.
- **Package:** `timelock-controller-example`
  (`examples/timelock-controller/src/contract.rs`).
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
  `RUSTUP_TOOLCHAIN=1.94.0 stellar contract build --locked --package timelock-controller-example`.
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
  `36299255cf77678a59d7fdfe9823d803be2bdddb9cc375be3130daed265295eb`
- **Size:** 28357 bytes.
- **Usage:** timelocks deployed from these bytes keep their code on-chain. New
  timelock deployments use the v0.7.2 bytes.
- **Constructor:** `__constructor(min_delay: u32, proposers: Vec<Address>,
  executors: Vec<Address>, admin: Option<Address>)`. It sets the minimum delay,
  grants the PROPOSER and CANCELLER roles to proposers and the EXECUTOR role to
  executors, and sets the admin (the contract itself when `None`).
- **Role semantics:** proposers get CANCELLER_ROLE at construction time
  (contract.rs:255-258, commit `3f81125`). With no executors configured, anyone can
  execute ready operations (contract.rs:296, commit `3f81125`).
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record. `build.rs` carries no `WASM_PINS` row for
  this file, since the package excludes the v0.7.1 files and `build.rs` runs
  during `cargo package` verification. The unit test
  `vendored_table_entries_are_the_files_at_their_paths` in
  `src/vendored_wasm_tests.rs` fails unless the `VENDORED` entry for this path
  holds this file's bytes. No constant or allowlist of the crate pins this
  file's digest.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file and this record in one change.

# cap85-beacon v0.1.0: vendored Wasm provenance

- **Purpose:** test infrastructure for the CAP-85 external-reference testnet
  acceptance suites. The beacon owns executable-reference entries, deploys
  contracts whose executable is an external reference to itself, and repoints
  those entries, so the suites can prove the wallet's handling of
  owner-managed executables against a live network. The wallet never deploys
  or invokes it outside those suites.
- **In-tree source path:** `contracts/cap85-beacon/src/lib.rs` (repository
  root). The source is an independent Cargo workspace (`[workspace]` table,
  `publish = false`), listed in the root workspace `exclude`, with its own
  committed `contracts/cap85-beacon/Cargo.lock`. It is outside this crate's
  directory, so `cargo package` of the smart-account crate ships only this
  directory's `cap85_beacon.wasm`, `REFERENCE.md`, and `build.sh`.
- **Package name:** `cap85-beacon`; the Wasm file name derives from it.
- **Exported functions:**
  - `__constructor(admin: Address)`: records the admin that authorizes every
    write.
  - `publish(tag: String, wasm_hash: BytesN<32>)`: admin-authorized; sets the
    executable-reference entry `ScVal::ExecutableTag(tag)` (persistent) to
    `wasm_hash`, which the host requires to be an uploaded Wasm.
  - `get_ref(tag: String) -> Option<BytesN<32>>`.
  - `deploy_ref(tag: String, salt: BytesN<32>) -> Address`: admin-authorized;
    deploys a contract with no constructor arguments whose executable is
    `ContractExecutable::ExternalRef { executable_owner: <beacon>, tag }`,
    at the address derived from the beacon and `salt`. The host refuses an
    unpublished tag.
- **Build host:** macOS (Apple Silicon, Darwin 25.6.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **Toolchain:** `rustc 1.98.0 (88d9e12ae 2026-08-18)`, selected with
  `RUSTUP_TOOLCHAIN=1.98.0`, since the repository's `rust-toolchain.toml`
  names the floating `stable` channel. Target `wasm32v1-none`.
- **soroban-sdk version:** `=28.0.0` (Protocol 28).
- **stellar-cli:** the first line of `stellar --version` is
  `stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)`. The binary is
  built by `cargo install --locked stellar-cli --version 28.1.0` with host rustc
  1.98.0; the crates.io package's `.cargo_vcs_info.json` sets that revision.
- **Build command:** in a copy of the tracked files of `contracts/cap85-beacon/`,
  with `RUSTFLAGS` unset, `RUSTUP_TOOLCHAIN=1.98.0 stellar contract build --locked`.
  The output is `<target dir>/wasm32v1-none/release/cap85_beacon.wasm`.
  `vendor/cap85-beacon/v0.1.0/build.sh` runs this build and copies the output
  here.
- **Optimizer:** enabled (the `stellar contract build` default); 2393 bytes
  before optimization, 2179 bytes after.
- **Optimizer version:** the `wasm-opt` crate 0.116.1 bundled with
  stellar-cli 28.1.0 (per the stellar-cli v28.1.0 `Cargo.lock`).
- **Release profile:** the stellar-cli 28 contract template profile
  (`opt-level = "z"`, `overflow-checks = true`, `debug = 0`,
  `strip = "symbols"`, `debug-assertions = false`, `panic = "abort"`,
  `codegen-units = 1`, `lto = true`).
- **sha256(cap85_beacon.wasm):**
  `b3495f664a6c6a3bf52daf0089f3790670b2033d78e02a53f0fa765521e51813`
- **Size:** 2179 bytes.
- **Rebuild instructions:**
  1. Install the toolchain:
     `rustup toolchain install 1.98.0 --profile minimal --target wasm32v1-none`.
  2. Build stellar-cli 28.1.0 with host rustc 1.98.0:
     `RUSTUP_TOOLCHAIN=1.98.0 cargo install --locked stellar-cli --version 28.1.0`.
     Its first `--version` line must read as recorded here.
  3. Run `vendor/cap85-beacon/v0.1.0/build.sh` (any working directory).
  4. When the printed sha256 differs, update in one change: this file (digest,
     size, toolchain), the `cap85_beacon.wasm` row of `WASM_PINS` in
     `crates/stellar-agent-smart-account/build.rs`, and
     `CAP85_BEACON_WASM_SHA256` in `src/cap85_beacon.rs`.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  committed source with the pinned toolchain and stellar-cli, and fails unless
  the rebuilt bytes equal this file. Its tree check fails unless the file's
  sha256 equals the digest in this record and the file's `WASM_PINS` row in
  `build.rs`. That row also fails every build of the crate on a mismatch. The
  unit tests in `src/vendored_wasm_tests.rs` fail unless `CAP85_BEACON_WASM`
  equals this file and `CAP85_BEACON_WASM_SHA256` equals its sha256.
  `CAP85_BEACON_WASM` compiles only with the `test-helpers` feature and in the
  crate's own unit-test build. Review of the source diff is what keeps the
  committed source honest.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.

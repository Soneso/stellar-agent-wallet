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
  directory's `cap85_beacon.wasm`, `REFERENCE.md` and `build.sh`.
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
- **Build host:** macOS (Apple Silicon, Darwin 25.6.0).
- **Toolchain:** rustc 1.98.0 (88d9e12ae 2026-08-18), stable channel;
  target `wasm32v1-none`.
- **soroban-sdk version:** `=28.0.0` (Protocol 28).
- **Build command:** `stellar contract build --locked`, run in
  `contracts/cap85-beacon/` by `vendor/cap85-beacon/v0.1.0/build.sh`, which
  copies `target/wasm32v1-none/release/cap85_beacon.wasm` here and prints the
  record below.
- **stellar-cli version:** `stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)`.
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
  1. Install stellar-cli 28.1.0 and the `wasm32v1-none` target
     (`rustup target add wasm32v1-none --toolchain stable`).
  2. Run `vendor/cap85-beacon/v0.1.0/build.sh` (any working directory).
  3. When the printed sha256 differs, update in one change: this file (digest,
     size, toolchain), the `cap85_beacon.wasm` row of `WASM_PINS` in
     `crates/stellar-agent-smart-account/build.rs`, and
     `CAP85_BEACON_WASM_SHA256` in `src/cap85_beacon.rs`.
- **Integrity gates:** the `build.rs` `WASM_PINS` row pins the digest at
  compile time and fails the build on a mismatch; the
  `cap85_beacon_wasm_sha256_matches_reference` unit test re-hashes the
  embedded bytes against `CAP85_BEACON_WASM_SHA256`. The embedded bytes are
  `CAP85_BEACON_WASM`, compiled only with the `test-helpers` feature and in
  the crate's own unit-test build, where the digest test runs.
- **Reproducibility caveat:** Rust to Wasm compilation is not bit-identical
  across rustc or stellar-cli versions. A digest that changes after a
  toolchain change is re-attested by re-vendoring with the new record, never
  accepted silently.

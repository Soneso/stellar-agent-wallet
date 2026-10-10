# multicall-router v0.1.0: vendored Wasm provenance

- **Purpose:** the router that `smart-account multicall` and the live
  multicall suite target. The wallet submits a bundle as one call to the
  router's `exec`, which the smart account authorizes. The digest of this file
  is the trust anchor of the multicall registry. `register` and `lookup`
  refuse any other digest, and the submit path requires the on-chain router
  hash on both RPCs to equal it.
- **In-tree source path:** `contracts/multicall-router/src/lib.rs` (repository
  root), tested by `contracts/multicall-router/src/test.rs`. The source is an
  independent Cargo workspace (`[workspace]` table, `publish = false`), listed
  in the root workspace `exclude`, with its own committed
  `contracts/multicall-router/Cargo.lock`. It is outside this crate's
  directory, so `cargo package` of the smart-account crate ships only this
  directory's `multicall_router.wasm`, `REFERENCE.md`, and `build.sh`.
- **Package name:** `multicall-router`; the Wasm file name derives from it.
- **Exported function:**
  - `exec(caller: Address, invocations: Vec<(Address, Symbol, Vec<Val>)>) -> Vec<Val>`:
    extends the instance TTL, requires the caller's authorization of `exec`
    with its full arguments, invokes each entry in input order, and returns
    the results in input order. A failing inner call aborts `exec`, and the
    host rolls back the whole bundle. The router directly invokes every inner
    call, so any caller can satisfy `require_auth` for the router's address
    through it; that address must hold no assets or roles. The instance TTL
    extends to 30 days when fewer than 23 days remain, at 17,280 ledgers per
    day.
- **Interface origin:** the `exec` interface follows the router of
  `https://github.com/stellar/smart-wallet-demo-app`,
  `contracts/router/src/lib.rs` at commit
  `8f4bfdcd3a60d125073534db298de2f297001bb4`. That file names its base:
  Creit Tech's `Stellar-Router-Contract`, `contracts/router-v0/src/lib.rs` at
  commit `04975c434dec362584aa99458ae2c25d803ec570`. The implementation here
  is original and copies no code from either repository, since neither shows
  a license.
- **Build host:** macOS (Apple Silicon, Darwin 25.6.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon) across two builds in separate
  temporary directories; a rebuild on Linux is not tested.
- **Toolchain:** `rustc 1.99.0 (b940084d7 2026-09-28)`, selected with
  `RUSTUP_TOOLCHAIN=1.99.0`, since the repository's `rust-toolchain.toml`
  names the floating `stable` channel. Target `wasm32v1-none`.
- **soroban-sdk version:** `=29.0.0` (Protocol 29). The file's
  `contractmetav0` section records `rsver` = `1.99.0` and `rssdkver` =
  `29.0.0#73ea6c0e61ff2cb63696bcbbb613a3fb71222918`;
  `stellar contract info meta --wasm multicall_router.wasm` prints both.
- **stellar-cli:** the first line of `stellar --version` is
  `stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)`. The binary is
  built by `cargo install --locked stellar-cli --version 28.1.0` with host rustc
  1.98.0; the crates.io package's `.cargo_vcs_info.json` sets that revision.
- **Build command:** in a copy of the tracked files of
  `contracts/multicall-router/`, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.99.0 stellar contract build --locked`. The output is
  `<target dir>/wasm32v1-none/release/multicall_router.wasm`.
  `vendor/multicall-router/v0.1.0/build.sh` runs this build and copies the
  output here.
- **Optimizer:** enabled (the `stellar contract build` default); 1201 bytes
  before optimization, 1032 bytes after.
- **Optimizer version:** the `wasm-opt` crate 0.116.1 bundled with
  stellar-cli 28.1.0 (per the stellar-cli v28.1.0 `Cargo.lock`).
- **Release profile:** the stellar-cli 28 contract template profile
  (`opt-level = "z"`, `overflow-checks = true`, `debug = 0`,
  `strip = "symbols"`, `debug-assertions = false`, `panic = "abort"`,
  `codegen-units = 1`, `lto = true`).
- **sha256(multicall_router.wasm):**
  `2bf863ffdeba3315e1d9ca4fc2a970b2f16fe72ca92a7fdef0166eb3699db69d`
- **Size:** 1032 bytes.
- **Where the digest is pinned:** the `multicall_router.wasm` row of
  `WASM_PINS` in `crates/stellar-agent-smart-account/build.rs` and the
  `MULTICALL_WASM_SHA256` constant in `src/multicall.rs`.
- **Rebuild instructions:**
  1. Install the toolchain:
     `rustup toolchain install 1.99.0 --profile minimal --target wasm32v1-none`.
  2. Build stellar-cli 28.1.0 with host rustc 1.98.0:
     `RUSTUP_TOOLCHAIN=1.98.0 cargo install --locked stellar-cli --version 28.1.0`.
     Its first `--version` line must read as recorded here.
  3. Run `vendor/multicall-router/v0.1.0/build.sh` (any working directory).
  4. When the printed sha256 differs, update in one change: this file (digest,
     size, toolchain), the `multicall_router.wasm` row of `WASM_PINS` in
     `crates/stellar-agent-smart-account/build.rs`, and
     `MULTICALL_WASM_SHA256` in `src/multicall.rs`. A new digest makes every
     registered router fail lookup until `smart-account unregister-multicall`
     removes its entry and `smart-account register-multicall` registers a
     router deployed from the new file.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  committed source with the pinned toolchain and stellar-cli, and fails unless
  the rebuilt bytes equal this file. Its tree check fails unless the file's
  sha256 equals the digest in this record and the file's `WASM_PINS` row in
  `build.rs`. That row also fails every build of the crate on a mismatch. The
  unit test `multicall_wasm_sha256_matches_provenance` fails unless
  `MULTICALL_WASM` hashes to `MULTICALL_WASM_SHA256`. The unit tests in
  `src/vendored_wasm_tests.rs` and the integration test
  `tests/vendored_wasm_release_cfg.rs` fail unless `MULTICALL_WASM` equals this
  file and `MULTICALL_WASM_SHA256` equals its sha256. `MULTICALL_WASM`
  compiles in every build of the crate. Review of the source diff is what
  keeps the committed source honest.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.

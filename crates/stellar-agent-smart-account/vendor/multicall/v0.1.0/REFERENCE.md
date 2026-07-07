# multicall v0.1.0 — vendored WASM provenance

- **Upstream source:** Meridian Pay smart-wallet-demo-app,
  `contracts/router/src/lib.rs` at SHA `8f4bfdc`.
  Itself a port of Creit Tech's Stellar-Router-Contract at SHA `04975c4`.
- **Port type:** verbatim-modulo-doc-comments. Contract logic is byte-identical
  to upstream at SHA `8f4bfdc`. Only `//!` and `///` rustdoc blocks were added;
  no functional code was changed.
- **In-tree source path:** `contracts/multicall/src/lib.rs`
- **In-tree source commit SHA:** pinned at the commit that introduced this file
  (see `git log --follow vendor/multicall/v0.1.0/REFERENCE.md`).
- **Package name:** `multicall` (per `contracts/multicall/Cargo.toml`).
  The compiled WASM filename derives from the package name.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.94.0 (4a4ef493e 2026-03-02) — stable channel.
  Target: `wasm32-unknown-unknown`.
- **Build command:**
  ```
  cargo build --release --target wasm32-unknown-unknown -p multicall
  cp target/wasm32-unknown-unknown/release/multicall.wasm \
     vendor/multicall/v0.1.0/multicall.wasm
  ```
  Run from the workspace root `stellar-agent-wallet/`.
- **soroban-sdk version:** `=25.3.0` (the workspace pin at this artifact's
  build time, then paired with OZ `stellar-accounts = "=0.7.1"`; the artifact
  has not been rebuilt since).
- **sha256(multicall.wasm):**
  `267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4`
- **Size:** 11825 bytes.
- **Rebuild instructions:**
  1. Restore the workspace Rust toolchain: `rustup show` (pinned in
     `rust-toolchain.toml`; ensure `wasm32-unknown-unknown` target is installed).
  2. From the repo root: `cargo build --release --target wasm32-unknown-unknown -p multicall`
  3. Copy: `cp target/wasm32-unknown-unknown/release/multicall.wasm vendor/multicall/v0.1.0/multicall.wasm`
  4. Recompute SHA-256: `shasum -a 256 vendor/multicall/v0.1.0/multicall.wasm`
     (Linux: `sha256sum vendor/multicall/v0.1.0/multicall.wasm`)
  5. Update `expected_sha256` in `crates/stellar-agent-smart-account/build.rs`
     `WASM_PINS` row for `"multicall.wasm"`.
  6. Update `sha256(multicall.wasm)` in this file.
- **Integrity gate:** the `build.rs` `WASM_PINS` table in
  `crates/stellar-agent-smart-account/build.rs` SHA-pins this artefact at
  compile time; the build fails if the vendored WASM does not match the pinned
  SHA. The `MULTICALL_WASM` const and `include_bytes!` binding are in `multicall.rs`.
- **Repo gate:** CI asserts `contracts/multicall/src/lib.rs` is byte-identical-modulo-doc-comments
  to the upstream at SHA `8f4bfdc`.

# OZ stellar-accounts v0.7.2: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.2`,
  commit `a9c42169000638da937577f592ebf61a7a3c94ca`.
- **Version roles:** the wallet's bindings use this v0.7.2 file, built with
  `soroban_sdk` 26.1.0. That SDK version carries the upstream fix of a
  `Context` type defect in the `packages/accounts` package
  (`rs-soroban-sdk#1875`), and `soroban_sdk::contractimport!` does not compile
  against the v0.7.1 file. The re-exported `AuthPayload`, `ContextRule`,
  `ContextRuleEntry`, `ContextRuleType`, `Signer`, and `SmartAccountError` type
  shapes are the same at both tags. The two files differ in bytes because their
  toolchains and SDK versions differ.
- **Package:** `stellar-accounts` (`packages/accounts/Cargo.toml`, which declares
  `crate-type = ["lib", "cdylib"]`).
- **Toolchain:** `rustc 1.96.0 (ac68faa20 2026-05-25)`, selected with
  `RUSTUP_TOOLCHAIN=1.96.0`, since the OZ `rust-toolchain.toml` names the
  floating `stable` channel. Target `wasm32v1-none`.
- **stellar-cli:** the first line of `stellar --version` is `stellar 25.2.0`.
  The binary is built by `cargo install --locked --path cmd/stellar-cli` from a
  `git archive` of stellar-cli tag `v25.2.0` (commit
  `28484880988199233a7e8e87c97cb12dac323cb3`) with host rustc 1.94.0, outside
  any git work tree. This file is cargo's `deps/` output, which carries no
  stellar-cli meta entry, so a crates.io install of 25.2.0 builds the same bytes.
  The rebuild script still requires the archive build: it refuses a binary
  whose first `--version` line carries a revision.
- **Build command:** in a checkout of the source commit, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.96.0 stellar contract build --locked --package stellar-accounts`,
  in a fresh target directory of its own. The output is
  `<target dir>/wasm32v1-none/release/deps/stellar_accounts.wasm`. The package
  declares a `cdylib`, so the build of any example contract that depends on it
  rewrites this file in a shared target directory. `build.sh` beside this record runs
  this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass.
- **Why deps/, not release/:** stellar-cli derives the `release/` output from the
  `deps/` output. It filters the `contractspecv0` section to the entries a
  contract exports (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and appends its meta entries. For this library,
  which exports no functions, the filter leaves a 346-byte file without a spec. The
  `deps/` cdylib keeps the full `contractspecv0` section that
  `soroban_sdk::contractimport!` parses to generate host-side typed bindings.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(stellar_accounts.wasm):** `b0ac8ad7156957757de89ea3dc00ed4d7d0148d273c12af52dfaa15252240c83`
- **Size:** 19887 bytes. The Wasm is small because `stellar-accounts` is a contracts
  library with mostly events and UDT field names, not a standalone deployable with
  executable function bodies.
- **`contractimport!` posture:** with soroban-sdk 26.1.0, `soroban_sdk::contractimport!`
  compiles against this artifact. The wallet re-exports the OZ
  `stellar_accounts::smart_account` types: the crate is the canonical Rust source of
  these types, and the re-export yields the same `#[contracttype]` XDR layout without a
  second, macro-derived copy.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record and the file's `WASM_PINS` row in `build.rs`.
  That row also fails every build of the crate on a mismatch. The unit tests in
  `src/vendored_wasm_tests.rs` fail unless `bindings::WASM` equals this file and
  `bindings::WASM_SHA256` equals its sha256.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc
  versions, so this record pins the toolchain. A rebuild with any other version is
  a re-vendor that replaces the file, this record, and every pin of its digest in
  one change.

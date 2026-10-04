# OZ stellar-accounts v0.7.1: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.1`,
  commit `3f81125bed3114cc93f5fca6d13240082050269a`.
- **Package:** `stellar-accounts` (`packages/accounts/Cargo.toml`, which declares
  `crate-type = ["lib", "cdylib"]`).
- **Toolchain:** `rustc 1.94.0 (4a4ef493e 2026-03-02)`, selected with
  `RUSTUP_TOOLCHAIN=1.94.0`, since the OZ `rust-toolchain.toml` names the
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
  `RUSTUP_TOOLCHAIN=1.94.0 stellar contract build --locked --package stellar-accounts`,
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
  which exports no functions, the filter leaves a 346-byte file without a spec;
  with `--optimize` the `release/` output also has no spec. The `deps/` cdylib
  keeps the full 16 KB `contractspecv0` section that `soroban_sdk::contractimport!`
  parses to generate host-side typed bindings.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(stellar_accounts.wasm):** `5603378c6039b5ccd4038d04a261d5f08467d5f68046e863b40ca85e4d779322`
- **Size:** 17179 bytes. The Wasm is small because `stellar-accounts` is a contracts
  library with mostly events and UDT field names, not a standalone deployable with
  executable function bodies.
- **`contractimport!` posture:** `soroban_sdk::contractimport!` does not compile against
  this file (E0425: cannot find type `Context` in scope). The wallet's bindings use the
  v0.7.2 library Wasm.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record. `build.rs` carries no `WASM_PINS` row for
  this file, since the package excludes the v0.7.1 files and `build.rs` runs
  during `cargo package` verification. The unit test
  `vendored_table_entries_are_the_files_at_their_paths` in
  `src/vendored_wasm_tests.rs` fails unless the `VENDORED` entry for this path
  holds this file's bytes. No constant or allowlist of the crate pins this
  file's digest; `bindings::WASM_SHA256` pins the v0.7.2 file.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc
  versions, so this record pins the toolchain. A rebuild with any other version is
  a re-vendor that replaces the file and this record in one change.

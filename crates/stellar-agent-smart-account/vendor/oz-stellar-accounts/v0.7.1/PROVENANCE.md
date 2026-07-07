# OZ stellar-accounts v0.7.1 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `3f81125bed3114cc93f5fca6d13240082050269a`
  (tag `v0.7.1`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.94.0 (4a4ef493e 2026-03-02) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package stellar-accounts` (stellar-cli 25.2.0)
  inside the OZ clone, then copy the UNOPTIMISED cdylib from
  `target/wasm32v1-none/release/deps/stellar_accounts.wasm`.
  See `vendor/oz-stellar-accounts/v0.7.1/build.sh` for the full reproducibility script.
- **Why deps/ not release/:** `stellar contract build` applies `experimental_spec_shaking_v2`
  which strips the `contractspecv0` custom section from the optimised `release/` output
  (reducing it to 346 bytes with no exported functions). The unoptimised cdylib in `deps/`
  retains the full 16 KB `contractspecv0` section that `soroban_sdk::contractimport!` parses
  to generate host-side typed bindings. The spec-shaked output cannot be used with
  `contractimport!`.
- **sha256(stellar_accounts.wasm):** `5603378c6039b5ccd4038d04a261d5f08467d5f68046e863b40ca85e4d779322`
- **Size:** 17179 bytes (the WASM is small because `stellar-accounts` is a contracts
  library with mostly events and UDT field names, not a standalone deployable with
  executable function bodies).
- **Verified-empty soroban-cli optimisation:** `stellar contract build --optimize` was
  attempted; it reduces to 327 bytes optimised, also with contractspecv0 stripped. No
  further optimization step is viable; the deps/ cdylib is the correct artefact.
- **Integrity gate:** the `WASM_SHA256` constant in
  `crates/stellar-agent-smart-account/src/bindings.rs` matches this value; the
  `wasm_sha256_matches_provenance` unit test verifies equality on every `cargo test`
  invocation. The integrity gate is reviewer attention plus the runtime test: a
  substitution attack must update both the WASM bytes AND the `WASM_SHA256` const in a
  single commit, which is detectable by reviewer attention to either the binary diff
  (large diff stat for the `.wasm` file) or the const update (a one-line text change
  adjacent to the `include_bytes!`).
  Note: `soroban_sdk::contractimport!`'s compile-time `sha256` argument is not used
  here because `contractimport!` fails to compile against this WASM (E0425: cannot
  find type `Context` in scope); the re-export strategy is used instead, with this
  runtime SHA-256 test as the equivalent supply-chain integrity gate.

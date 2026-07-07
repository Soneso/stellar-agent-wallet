# OZ stellar-accounts v0.7.2 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
  (tag `v0.7.2`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **What changed vs v0.7.1:** v0.7.2 bumps `soroban_sdk` to 26.1.0, which fixes an
  upstream `Context`-type defect (`rs-soroban-sdk#1875`) affecting the `packages/accounts`
  package. No entrypoint or ABI change: the re-exported `AuthPayload`, `ContextRule`,
  `ContextRuleEntry`, `ContextRuleType`, `Signer`, and `SmartAccountError` type shapes are
  identical to v0.7.1. The WASM bytes differ only because of the toolchain and SDK bump.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package stellar-accounts` (stellar-cli 25.2.0)
  inside the OZ clone, then copy the UNOPTIMISED cdylib from
  `target/wasm32v1-none/release/deps/stellar_accounts.wasm`.
  See `vendor/oz-stellar-accounts/v0.7.2/build.sh` for the full reproducibility script.
- **Why deps/ not release/:** `stellar contract build` applies `experimental_spec_shaking_v2`
  which strips the `contractspecv0` custom section from the optimised `release/` output
  (reducing it to 346 bytes with no exported functions). The unoptimised cdylib in `deps/`
  retains the full `contractspecv0` section that `soroban_sdk::contractimport!` parses
  to generate host-side typed bindings. The spec-shaked output cannot be used with
  `contractimport!`.
- **sha256(stellar_accounts.wasm):** `b0ac8ad7156957757de89ea3dc00ed4d7d0148d273c12af52dfaa15252240c83`
- **Size:** 19887 bytes (the WASM is small because `stellar-accounts` is a contracts
  library with mostly events and UDT field names, not a standalone deployable with
  executable function bodies).
- **Integrity gate:** the `WASM_SHA256` constant in
  `crates/stellar-agent-smart-account/src/bindings.rs` matches this value; the
  `wasm_sha256_matches_provenance` unit test verifies equality on every `cargo test`
  invocation, and `build.rs` re-verifies it at compile time. The integrity gate is
  reviewer attention plus the runtime test: a substitution attack must update both the
  WASM bytes AND the `WASM_SHA256` const in a single commit, which is detectable by
  reviewer attention to either the binary diff (large diff stat for the `.wasm` file) or
  the const update (a one-line text change adjacent to the `include_bytes!`).
- **contractimport! posture:** With soroban-sdk 26.1.0, `soroban_sdk::contractimport!`
  compiles against this artefact (the earlier E0425 `Context`-in-scope constraint is
  resolved upstream). The wallet nevertheless keeps the direct re-export of the OZ
  `stellar_accounts::smart_account` types rather than a macro-generated client, because
  the crate is the canonical Rust source of these types and re-exporting yields the same
  `#[contracttype]` XDR layout without a second, macro-derived copy. The runtime
  `WASM_SHA256` const plus the `wasm_sha256_matches_provenance` test are the supply-chain
  integrity gate for the vendored artefact.

# OZ multisig-threshold-policy-example v0.7.2 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
  (tag `v0.7.2`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **What changed vs v0.7.1:** v0.7.2 bumps `soroban_sdk` to 26.1.0 (upstream
  `Context`-type fix, `rs-soroban-sdk#1875`). The contract source
  (`examples/multisig-smart-account/threshold-policy/src/contract.rs`) is byte-identical to
  v0.7.1; only the SDK pin changed, so the entrypoint set and ABI are unchanged. The WASM
  bytes differ only because of the toolchain and SDK bump. Threshold-policy contracts
  already deployed on-chain from the v0.7.1 bytes remain recognised (their hash stays in the
  allowlist); only NEW deployments use these v0.7.2 bytes.
- **Package name:** `multisig-threshold-policy-example` (per
  `examples/multisig-smart-account/threshold-policy/Cargo.toml`).  The compiled WASM
  filename derives from the package name: `multisig_threshold_policy_example.wasm`.
  Do NOT rename the file without re-running this build.sh step and updating this
  PROVENANCE.md.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package multisig-threshold-policy-example`
  (stellar-cli 25.2.0) inside a local clone of the OpenZeppelin stellar-contracts repository
  (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2.
  See `vendor/oz-threshold-policy/v0.7.2/build.sh` for the full reproducibility script
  including the EXIT-trap HEAD-restoration discipline.
- **stellar-cli version:** `stellar 25.2.0` (captured at build time; pin this specific
  version so `experimental_spec_shaking_v2` behaviour is reproducible).
- **Optimiser version:** not used; `wasm-opt` was not available on the build host.
  The artefact is the `release` profile output (`stellar contract build` release mode).
  `stellar contract build` applies spec-shaking internally when the OZ workspace enables
  `experimental_spec_shaking_v2`; the result is a self-contained deployable WASM with no
  external `contractspecv0` dependency.
- **sha256(multisig_threshold_policy_example.wasm):**
  `4c14f402df29675d4155283698c436ee588aacb39adc313845010a565c07567d`
- **Size:** 12 521 bytes.
- **Exported functions** (per
  `examples/multisig-smart-account/threshold-policy/src/contract.rs` at SHA `a9c4216`):
  - `enforce(context: Context, authenticated_signers: Vec<Signer>, context_rule: ContextRule, smart_account: Address)` —
     the `Policy::enforce` entry point.  Validates that the number of authenticated
     signers meets the stored threshold for the given `(context_rule, smart_account)`
     pair, records that authorisation occurred, and emits an event.  Delegates to
     `stellar_accounts::policies::simple_threshold::enforce`.
  - `install(install_params: SimpleThresholdAccountParams, context_rule: ContextRule, smart_account: Address)` —
     the `Policy::install` entry point.  Stores the threshold configuration for the
     given `(context_rule, smart_account)` pair.  Delegates to
     `stellar_accounts::policies::simple_threshold::install`.
  - `uninstall(context_rule: ContextRule, smart_account: Address)` —
     the `Policy::uninstall` entry point.  Removes the threshold configuration for
     the given `(context_rule, smart_account)` pair.  Delegates to
     `stellar_accounts::policies::simple_threshold::uninstall`.
  - `get_threshold(context_rule_id: u32, smart_account: Address) -> u32` —
     returns the current threshold for a smart account's context rule.  Delegates to
     `stellar_accounts::policies::simple_threshold::get_threshold`
     (`examples/multisig-smart-account/threshold-policy/src/contract.rs:65-67`).
  - `set_threshold(threshold: u32, context_rule: ContextRule, smart_account: Address)` —
     sets a new threshold for a smart account.  The smart account itself must authorise
     this call via `e.current_contract_address().require_auth()` (enforced inside
     `simple_threshold::set_threshold` at
     `packages/accounts/src/policies/simple_threshold.rs:235`, SHA `a9c4216`).
     The `context_rule` argument carries both the `rule_id: u32` and the rule's current
     `signers: Vec<Signer>` and `policies: Vec<Address>` — the same `ContextRule` struct
     used by `SmartAccount::add_signer` / `SmartAccount::remove_signer`
     (`packages/accounts/src/smart_account/mod.rs:374-410`, SHA `a9c4216`).
     (`examples/multisig-smart-account/threshold-policy/src/contract.rs:70-78`).
- **Why deployable (release/), not deps/:** This contract is deployed on-chain via
  `UploadContractWasm` and called by the smart-account's `__check_auth` to enforce the
  threshold policy at signing time.  On-chain storage cost scales with size; the `release`
  profile output is the production deployment artefact.  The wallet does not
  `contractimport!` against this WASM; invocations are typed Soroban calls to
  `set_threshold(...)` and `get_threshold(...)` from `managers/signers.rs`.
- **Cross-reference:** `vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm`
  is the deployable WebAuthn-verifier contract.
  `vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm` is the
  deployable smart-account contract.  This threshold-policy artefact is the fourth
  vendored OZ WASM; it is deployed via `smart-account deploy-threshold-policy`.
- **Integrity gate (CI side):** CI re-hashes the in-repo WASM against the SHA-256 in this
  `PROVENANCE.md` at every run (iterates `vendor/*/v*/PROVENANCE.md` with per-file
  expected-SHA extraction).  This catches uncoordinated mutation of the WASM.  The defence
  against coordinated mutation is the Rust compile-time SHA pin in
  `crates/stellar-agent-smart-account/src/signers/policy_identification.rs`
  (`THRESHOLD_POLICY_WASM_HASHES` const + unit tests). This v0.7.2 hash is
  `THRESHOLD_POLICY_WASM_HASHES[0]` (the deploy hash); the v0.7.1 hash remains at index 1
  as a still-recognised legacy entry.
- **Reproducibility caveat:** Rust → WASM compilation is **not always bit-identical**
  across patch-version drifts of `rustc` or `stellar-cli`.  If the CI gate flags a
  benign drift after a toolchain bump, the response is to bump the toolchain pin in
  this PROVENANCE.md (with operator authorisation), re-vendor, and re-attest — NOT to
  silently accept the diff.

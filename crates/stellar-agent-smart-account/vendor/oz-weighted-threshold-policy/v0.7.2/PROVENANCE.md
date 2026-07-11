# OZ multisig-weighted-threshold-policy-example v0.7.2 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
  (tag `v0.7.2`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **Package name:** `multisig-weighted-threshold-policy-example` (per
  `examples/multisig-smart-account/weighted-threshold-policy/Cargo.toml`).  The compiled WASM
  filename derives from the package name: `multisig_weighted_threshold_policy_example.wasm`.
  Do NOT rename the file without re-running this build.sh step and updating this
  PROVENANCE.md.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package multisig-weighted-threshold-policy-example`
  (stellar-cli 25.2.0) inside a local clone of the OpenZeppelin stellar-contracts repository
  (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2.
  See `vendor/oz-weighted-threshold-policy/v0.7.2/build.sh` for the full reproducibility script
  including the EXIT-trap HEAD-restoration discipline.
- **stellar-cli version:** `stellar 25.2.0` (captured at build time; pin this specific
  version so `experimental_spec_shaking_v2` behaviour is reproducible).
- **Optimiser version:** not used; `wasm-opt` was not available on the build host.
  The artefact is the `release` profile output (`stellar contract build` release mode).
  `stellar contract build` applies spec-shaking internally when the OZ workspace enables
  `experimental_spec_shaking_v2`; the result is a self-contained deployable WASM with no
  external `contractspecv0` dependency.
- **sha256(multisig_weighted_threshold_policy_example.wasm):**
  `e3d8cc5ab9668526d5cf2bab17ee42e84ee4b972ba7cca8d3a37b2ed8d9baee3`
- **Size:** 15 745 bytes.
- **Exported functions** (`Policy` trait impl plus query/mutator surface, per
  `examples/multisig-smart-account/weighted-threshold-policy/src/contract.rs` at SHA
  `a9c4216`, delegating to `stellar_accounts::policies::weighted_threshold`):
  - `enforce(context: Context, authenticated_signers: Vec<Signer>, context_rule: ContextRule, smart_account: Address)` —
    the `Policy::enforce` entry point.  Sums the weight of every authenticated signer
    present in the stored `signer_weights` map (`calculate_weight`,
    `packages/accounts/src/policies/weighted_threshold.rs:248-266`, SHA `a9c4216`) and
    panics `NotAllowed` (3213) if the total is below the stored `threshold`; otherwise
    emits `WeightedEnforced`.  Signers absent from the map contribute zero weight.
  - `install(install_params: WeightedThresholdAccountParams, context_rule: ContextRule, smart_account: Address)` —
    the `Policy::install` entry point.  Unlike the spending-limit policy, install
    places **no restriction** on `context_rule.context_type` (no `CallContract`-only
    gate; `weighted_threshold.rs:482-512`, SHA `a9c4216`).  Panics `InvalidThreshold`
    (3211) when `threshold == 0` or `threshold` exceeds the checked sum of
    `signer_weights` values, `MathOverflow` (3212) on weight-sum overflow, and
    `AlreadyInstalled` (3214) on re-install for the same `(smart_account,
    context_rule.id)` pair.  Stores `{ signer_weights: Map<Signer, u32>, threshold: u32 }`.
  - `uninstall(context_rule: ContextRule, smart_account: Address)` — the `Policy::uninstall`
    entry point.  Removes the weighted-threshold configuration for the pair.
  - `get_threshold(context_rule_id: u32, smart_account: Address) -> u32` — exported view;
    returns the stored threshold or panics `SmartAccountNotInstalled` (3210).
  - `get_signer_weights(context_rule: ContextRule, smart_account: Address) -> Map<Signer, u32>` —
    exported view; returns the stored signer-weights map or panics
    `SmartAccountNotInstalled` (3210).
  - `set_threshold(threshold: u32, context_rule: ContextRule, smart_account: Address)` —
    updates the stored threshold; panics `InvalidThreshold` (3211) if the new value is
    `0` or exceeds the current total signer weight (`weighted_threshold.rs:352-383`, SHA
    `a9c4216`).
  - `set_signer_weight(signer: Signer, weight: u32, context_rule: ContextRule, smart_account: Address)` —
    updates one signer's weight; panics `InvalidThreshold` (3211) if the adjusted total
    weight would fall below the stored threshold (`weighted_threshold.rs:413-447`, SHA
    `a9c4216`).
  - `WeightedThresholdAccountParams` is a `#[contracttype]` struct whose ScMap encoding
    sorts keys alphabetically by field name, so the install param ScMap has
    `signer_weights` before `threshold` ('s' 0x73 < 't' 0x74).
- **Per-network singleton:** the policy keys all state by
  `WeightedThresholdStorageKey::AccountContext(smart_account, context_rule_id)`
  (`weighted_threshold.rs:158`), so one deployed instance serves every account and
  every context rule on the network.  The wallet deploys exactly one per network via
  `smart-account deploy-policy --kind weighted-threshold` and records the address in
  the wallet-local registry (`<canonical_data_root>/networks.toml`).
- **Why deployable (release/), not deps/:** This contract is deployed on-chain via
  `UploadContractWasm` and called by the smart-account's `__check_auth` to enforce
  the weighted-signer quorum at signing time.  On-chain storage cost scales with
  size; the `release` profile output is the production deployment artefact.  The
  wallet does not `contractimport!` against this WASM; the install param is built
  as a typed ScMap and the policy is attached to a context rule via `add_policy`.
- **Security-relevant divergence risk (documented in OZ source, not mitigated
  by this WASM):** the policy is not automatically notified when signers are
  added to or removed from the parent `ContextRule`; the wallet's
  `set-weighted-threshold` / `set-signer-weight` mutators exist specifically so
  operators can re-tune the stored weights/threshold after a signer-set change
  (`weighted_threshold.rs:1-51`, SHA `a9c4216`).
- **Cross-reference:** `vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm`
  is the simple (unweighted) threshold-policy contract, and
  `vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm`
  is the spending-limit policy contract; all three are `Policy` implementations
  vendored by this wallet and are mutually exclusive per context rule (the OZ
  per-rule policy list allows attaching all three simultaneously, but the wallet's
  typed CLI treats them as independent policy kinds).
- **Integrity gate (CI side):** CI re-hashes the in-repo WASM against the SHA-256 in
  this `PROVENANCE.md` at every run (iterates `vendor/*/v*/PROVENANCE.md` with
  per-file expected-SHA extraction).  This catches uncoordinated mutation of the
  WASM.  The defence against coordinated mutation is the Rust compile-time SHA pin
  in `crates/stellar-agent-smart-account/src/weighted_threshold_policy.rs`
  (`WEIGHTED_THRESHOLD_POLICY_WASM_SHA256` const + unit tests) and the `build.rs`
  WASM pin.
- **Reproducibility caveat:** Rust → WASM compilation is **not always bit-identical**
  across patch-version drifts of `rustc` or `stellar-cli`.  If the CI gate flags a
  benign drift after a toolchain bump, the response is to bump the toolchain pin in
  this PROVENANCE.md (with operator authorisation), re-vendor, and re-attest — NOT to
  silently accept the diff.

# OZ multisig-spending-limit-policy-example v0.7.2 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
  (tag `v0.7.2`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **Package name:** `multisig-spending-limit-policy-example` (per
  `examples/multisig-smart-account/spending-limit-policy/Cargo.toml`).  The compiled WASM
  filename derives from the package name: `multisig_spending_limit_policy_example.wasm`.
  Do NOT rename the file without re-running this build.sh step and updating this
  PROVENANCE.md.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package multisig-spending-limit-policy-example`
  (stellar-cli 25.2.0) inside a local clone of the OpenZeppelin stellar-contracts repository
  (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2.
  See `vendor/oz-spending-limit-policy/v0.7.2/build.sh` for the full reproducibility script
  including the EXIT-trap HEAD-restoration discipline.
- **stellar-cli version:** `stellar 25.2.0` (captured at build time; pin this specific
  version so `experimental_spec_shaking_v2` behaviour is reproducible).
- **Optimiser version:** not used; `wasm-opt` was not available on the build host.
  The artefact is the `release` profile output (`stellar contract build` release mode).
  `stellar contract build` applies spec-shaking internally when the OZ workspace enables
  `experimental_spec_shaking_v2`; the result is a self-contained deployable WASM with no
  external `contractspecv0` dependency.
- **sha256(multisig_spending_limit_policy_example.wasm):**
  `0e8da0ccff5c444520085ac1973d3c8023fdd04f727ee11ae7290a49dffbbaf5`
- **Size:** 15 927 bytes.
- **Exported functions** (`Policy` trait impl per
  `examples/multisig-smart-account/spending-limit-policy/src/contract.rs` at SHA `a9c4216`,
  delegating to `stellar_accounts::policies::spending_limit`):
  - `enforce(context: Context, authenticated_signers: Vec<Signer>, context_rule: ContextRule, smart_account: Address)` —
     the `Policy::enforce` entry point.  Accepts only a `Context::Contract(ContractContext)`
     whose `fn_name == symbol_short!("transfer")` and whose `args.get(2)` decodes as `i128`
     (the transfer amount for a SEP-41 `transfer(from, to, amount)`); any other context
     panics `NotAllowed` (3223).  Evicts spending-history entries outside the rolling
     `period_ledgers` window, then panics `SpendingLimitExceeded` (3221) if the cumulative
     total plus the new amount exceeds the stored limit; otherwise records the transfer.
     Delegates to `spending_limit::enforce`
     (`packages/accounts/src/policies/spending_limit.rs:222-292`, SHA `a9c4216`).
  - `install(install_params: SpendingLimitAccountParams, context_rule: ContextRule, smart_account: Address)` —
     the `Policy::install` entry point.  Requires `context_rule.context_type` to be
     `CallContract(_)` — otherwise panics `OnlyCallContractAllowed` (3227,
     `spending_limit.rs:376-377`).  Stores `{ spending_limit: i128, period_ledgers: u32 }`
     for the `(smart_account, context_rule.id)` pair.  Delegates to
     `spending_limit::install` (`packages/accounts/src/policies/spending_limit.rs:367-408`,
     SHA `a9c4216`).  `SpendingLimitAccountParams` is a `#[contracttype]` struct whose
     ScMap encoding sorts keys alphabetically by field name, so the install param ScMap has
     `period_ledgers` before `spending_limit` ('p' 0x70 < 's' 0x73).
  - `uninstall(context_rule: ContextRule, smart_account: Address)` — the `Policy::uninstall`
     entry point.  Removes the spending-limit configuration and history for the pair.
  - `get_spending_limit_data(context_rule_id: u32, smart_account: Address) -> SpendingLimitData` —
     returns the current limit, period, spending history, and cached total.
  - `set_spending_limit(spending_limit: i128, context_rule: ContextRule, smart_account: Address)` —
     updates the stored limit for the pair.
- **Per-network singleton:** the policy keys all state by
  `SpendingLimitStorageKey::AccountContext(smart_account, context_rule_id)`
  (`spending_limit.rs:145-147`), so one deployed instance serves every account and every
  context rule on the network.  The wallet deploys exactly one per network via
  `smart-account deploy-spending-limit-policy` and records the address in the wallet-local
  registry (`<canonical_data_root>/networks.toml`).
- **Why deployable (release/), not deps/:** This contract is deployed on-chain via
  `UploadContractWasm` and called by the smart-account's `__check_auth` to enforce the
  spending limit at signing time.  On-chain storage cost scales with size; the `release`
  profile output is the production deployment artefact.  The wallet does not
  `contractimport!` against this WASM; the install param is built as a typed ScMap and the
  policy is attached to a context rule via `add_policy`.
- **Cross-reference:** `vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm`
  is the deployable threshold-policy contract (the other `Policy` implementation vendored
  by this wallet).  This spending-limit-policy artefact is deployed via
  `smart-account deploy-spending-limit-policy`.
- **Integrity gate (CI side):** CI re-hashes the in-repo WASM against the SHA-256 in this
  `PROVENANCE.md` at every run (iterates `vendor/*/v*/PROVENANCE.md` with per-file
  expected-SHA extraction).  This catches uncoordinated mutation of the WASM.  The defence
  against coordinated mutation is the Rust compile-time SHA pin in
  `crates/stellar-agent-smart-account/src/spending_limit_policy.rs`
  (`SPENDING_LIMIT_POLICY_WASM_SHA256` const + unit tests) and the `build.rs` WASM pin.
- **Reproducibility caveat:** Rust → WASM compilation is **not always bit-identical**
  across patch-version drifts of `rustc` or `stellar-cli`.  If the CI gate flags a
  benign drift after a toolchain bump, the response is to bump the toolchain pin in
  this PROVENANCE.md (with operator authorisation), re-vendor, and re-attest — NOT to
  silently accept the diff.

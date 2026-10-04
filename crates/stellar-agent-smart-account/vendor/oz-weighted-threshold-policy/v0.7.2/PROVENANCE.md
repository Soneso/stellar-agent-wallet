# OZ multisig-weighted-threshold-policy-example v0.7.2: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.2`,
  commit `a9c42169000638da937577f592ebf61a7a3c94ca`.
- **Package:** `multisig-weighted-threshold-policy-example`
  (`examples/multisig-smart-account/weighted-threshold-policy/Cargo.toml`). The
  Wasm file name derives from the package name. Renaming the file takes a
  rebuild with `build.sh` and an update of this record.
- **Toolchain:** `rustc 1.96.0 (ac68faa20 2026-05-25)`, selected with
  `RUSTUP_TOOLCHAIN=1.96.0`, since the OZ `rust-toolchain.toml` names the
  floating `stable` channel. Target `wasm32v1-none`.
- **stellar-cli:** the first line of `stellar --version` is `stellar 25.2.0`.
  The binary is built by `cargo install --locked --path cmd/stellar-cli` from a
  `git archive` of stellar-cli tag `v25.2.0` (commit
  `28484880988199233a7e8e87c97cb12dac323cb3`) with host rustc 1.94.0, outside
  any git work tree. Its `cliver` meta entry then reads `25.2.0#`. A crates.io
  install of 25.2.0 records its revision in `cliver`, which adds 40 bytes.
- **Build command:** in a checkout of the source commit, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.96.0 stellar contract build --locked --package multisig-weighted-threshold-policy-example`.
  The output is `<target dir>/wasm32v1-none/release/multisig_weighted_threshold_policy_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries. The result is a
  self-contained deployable Wasm.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(multisig_weighted_threshold_policy_example.wasm):**
  `e3d8cc5ab9668526d5cf2bab17ee42e84ee4b972ba7cca8d3a37b2ed8d9baee3`
- **Size:** 15 745 bytes.
- **Exported functions** (`Policy` trait impl plus query and mutator surface, per
  `examples/multisig-smart-account/weighted-threshold-policy/src/contract.rs` at commit
  `a9c4216`, delegating to `stellar_accounts::policies::weighted_threshold`):
  - `enforce(context: Context, authenticated_signers: Vec<Signer>, context_rule: ContextRule, smart_account: Address)`:
    the `Policy::enforce` entry point. Sums the weight of every authenticated signer
    present in the stored `signer_weights` map (`calculate_weight`,
    `packages/accounts/src/policies/weighted_threshold.rs:248-266`, commit `a9c4216`) and
    panics `NotAllowed` (3213) if the total is below the stored `threshold`; otherwise
    emits `WeightedEnforced`. Signers absent from the map contribute zero weight.
  - `install(install_params: WeightedThresholdAccountParams, context_rule: ContextRule, smart_account: Address)`:
    the `Policy::install` entry point. Install places no restriction on
    `context_rule.context_type`, where the spending-limit policy accepts only
    `CallContract` (`weighted_threshold.rs:482-512`, commit `a9c4216`). Panics
    `InvalidThreshold` (3211) when `threshold == 0` or `threshold` exceeds the checked sum
    of `signer_weights` values, `MathOverflow` (3212) on weight-sum overflow, and
    `AlreadyInstalled` (3214) on re-install for the same `(smart_account,
    context_rule.id)` pair. Stores `{ signer_weights: Map<Signer, u32>, threshold: u32 }`.
  - `uninstall(context_rule: ContextRule, smart_account: Address)`: the `Policy::uninstall`
    entry point. Removes the weighted-threshold configuration for the pair.
  - `get_threshold(context_rule_id: u32, smart_account: Address) -> u32`: exported view;
    returns the stored threshold or panics `SmartAccountNotInstalled` (3210).
  - `get_signer_weights(context_rule: ContextRule, smart_account: Address) -> Map<Signer, u32>`:
    exported view; returns the stored signer-weights map or panics
    `SmartAccountNotInstalled` (3210).
  - `set_threshold(threshold: u32, context_rule: ContextRule, smart_account: Address)`:
    updates the stored threshold; panics `InvalidThreshold` (3211) if the new value is
    `0` or exceeds the current total signer weight (`weighted_threshold.rs:352-383`,
    commit `a9c4216`).
  - `set_signer_weight(signer: Signer, weight: u32, context_rule: ContextRule, smart_account: Address)`:
    updates one signer's weight; panics `InvalidThreshold` (3211) if the adjusted total
    weight would fall below the stored threshold (`weighted_threshold.rs:413-447`,
    commit `a9c4216`).
  - `WeightedThresholdAccountParams` is a `#[contracttype]` struct whose ScMap encoding
    sorts keys alphabetically by field name, so the install param ScMap has
    `signer_weights` before `threshold` ('s' 0x73 < 't' 0x74).
- **Per-network singleton:** the policy keys all state by
  `WeightedThresholdStorageKey::AccountContext(smart_account, context_rule_id)`
  (`weighted_threshold.rs:158`), so one deployed instance serves every account and
  every context rule on the network. The wallet deploys exactly one per network with
  `smart-account deploy-policy --kind weighted-threshold` and records the address in
  the wallet-local registry (`<canonical_data_root>/networks.toml`).
- **Why deployable (release/), not deps/:** the wallet uploads this contract with
  `UploadContractWasm`, and the smart account's `__check_auth` calls it to enforce
  the weighted-signer quorum at signing time. On-chain storage cost scales with
  size; the `release` output is the production deployment artifact. The
  wallet does not `contractimport!` against this Wasm; the install param is built
  as a typed ScMap, and the wallet attaches the policy to a context rule with
  `add_policy`.
- **Security-relevant divergence risk (documented in the OZ source, not mitigated
  by this Wasm):** the policy is not notified when signers are added to or removed
  from the parent `ContextRule`. The wallet's `set-weighted-threshold` and
  `set-signer-weight` mutators let operators re-tune the stored weights and threshold
  after a signer-set change (`weighted_threshold.rs:1-51`, commit `a9c4216`).
- **Cross-reference:** `vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm`
  is the simple (unweighted) threshold-policy contract, and
  `vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm`
  is the spending-limit policy contract. All three implement `Policy` and can be
  attached to the same context rule. The CLI treats them as separate policy kinds.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record and the file's `WASM_PINS` row in `build.rs`.
  That row also fails every build of the crate on a mismatch. The unit tests in
  `src/vendored_wasm_tests.rs` fail unless `WEIGHTED_THRESHOLD_POLICY_WASM`
  equals this file, `WEIGHTED_THRESHOLD_POLICY_WASM_SHA256` equals its sha256,
  and `WEIGHTED_THRESHOLD_POLICY_WASM_HASHES` holds exactly that sha256.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.

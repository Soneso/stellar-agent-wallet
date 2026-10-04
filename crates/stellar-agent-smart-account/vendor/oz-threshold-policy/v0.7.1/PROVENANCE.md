# OZ multisig-threshold-policy-example v0.7.1: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.1`,
  commit `3f81125bed3114cc93f5fca6d13240082050269a`.
- **Package:** `multisig-threshold-policy-example`
  (`examples/multisig-smart-account/threshold-policy/Cargo.toml`). The Wasm file
  name derives from the package name. Renaming the file takes a rebuild with
  `build.sh` and an update of this record.
- **Toolchain:** `rustc 1.94.0 (4a4ef493e 2026-03-02)`, selected with
  `RUSTUP_TOOLCHAIN=1.94.0`, since the OZ `rust-toolchain.toml` names the
  floating `stable` channel. Target `wasm32v1-none`.
- **stellar-cli:** the first line of `stellar --version` is `stellar 25.2.0`.
  The binary is built by `cargo install --locked --path cmd/stellar-cli` from a
  `git archive` of stellar-cli tag `v25.2.0` (commit
  `28484880988199233a7e8e87c97cb12dac323cb3`) with host rustc 1.94.0, outside
  any git work tree. Its `cliver` meta entry then reads `25.2.0#`. A crates.io
  install of 25.2.0 records its revision in `cliver`, which adds 40 bytes.
- **Build command:** in a checkout of the source commit, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.94.0 stellar contract build --locked --package multisig-threshold-policy-example`.
  The output is `<target dir>/wasm32v1-none/release/multisig_threshold_policy_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries. The result is a
  self-contained deployable Wasm.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0, Darwin Starseed.local 25.3.0 Darwin
  Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64).
  The bytes reproduce byte for byte on macOS (Apple Silicon); a rebuild on Linux
  is not tested.
- **sha256(multisig_threshold_policy_example.wasm):**
  `43c48790b83fbe283e139f881aa091198c4df554022aa10c12d9ca484edf0702`
- **Size:** 10 018 bytes.
- **Exported functions** (per
  `examples/multisig-smart-account/threshold-policy/src/contract.rs` at commit `3f81125`):
  - `enforce(context: Context, authenticated_signers: Vec<Signer>, context_rule: ContextRule, smart_account: Address)`:
     the `Policy::enforce` entry point. Validates that the number of authenticated
     signers meets the stored threshold for the given `(context_rule, smart_account)`
     pair, records that authorization occurred, and emits an event. Delegates to
     `stellar_accounts::policies::simple_threshold::enforce`.
  - `install(install_params: SimpleThresholdAccountParams, context_rule: ContextRule, smart_account: Address)`:
     the `Policy::install` entry point. Stores the threshold configuration for the
     given `(context_rule, smart_account)` pair. Delegates to
     `stellar_accounts::policies::simple_threshold::install`.
  - `uninstall(context_rule: ContextRule, smart_account: Address)`:
     the `Policy::uninstall` entry point. Removes the threshold configuration for
     the given `(context_rule, smart_account)` pair. Delegates to
     `stellar_accounts::policies::simple_threshold::uninstall`.
  - `get_threshold(context_rule_id: u32, smart_account: Address) -> u32`:
     returns the current threshold for a smart account's context rule. Delegates to
     `stellar_accounts::policies::simple_threshold::get_threshold`
     (`examples/multisig-smart-account/threshold-policy/src/contract.rs:65-67`).
  - `set_threshold(threshold: u32, context_rule: ContextRule, smart_account: Address)`:
     sets a new threshold for a smart account. The smart account itself must authorize
     this call through `e.current_contract_address().require_auth()` (enforced inside
     `simple_threshold::set_threshold` at
     `packages/accounts/src/policies/simple_threshold.rs:235`, commit `3f81125`).
     The `context_rule` argument carries both the `rule_id: u32` and the rule's current
     `signers: Vec<Signer>` and `policies: Vec<Address>`: the same `ContextRule` struct
     that `SmartAccount::add_signer` and `SmartAccount::remove_signer` use
     (`packages/accounts/src/smart_account/mod.rs:374-410`, commit `3f81125`;
     `examples/multisig-smart-account/threshold-policy/src/contract.rs:70-78`).
- **Why deployable (release/), not deps/:** policy contracts deployed on-chain from
  these bytes enforce the threshold when a smart account's `__check_auth` calls them at
  signing time. On-chain storage cost scales with size; the `release` output is the
  production deployment artifact. The wallet does not
  `contractimport!` against this Wasm; `managers/signers.rs` makes typed Soroban calls to
  `set_threshold(...)` and `get_threshold(...)`.
- **Cross-reference:** `vendor/oz-webauthn-verifier/v0.7.1/multisig_webauthn_verifier_example.wasm`
  is the v0.7.1 WebAuthn-verifier contract.
  `vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm` is the
  v0.7.1 smart-account contract. New deployments use the v0.7.2 threshold policy.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record. `build.rs` carries no `WASM_PINS` row for
  this file, since the package excludes the v0.7.1 files and `build.rs` runs
  during `cargo package` verification. The unit tests in `src/vendored_wasm_tests.rs` fail unless
  `THRESHOLD_POLICY_WASM_HASHES[1]` equals this file's sha256, which keeps
  policies deployed from these bytes recognized.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.

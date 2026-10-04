# OZ multisig-spending-limit-policy-example v0.7.2: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.2`,
  commit `a9c42169000638da937577f592ebf61a7a3c94ca`.
- **Package:** `multisig-spending-limit-policy-example`
  (`examples/multisig-smart-account/spending-limit-policy/Cargo.toml`). The Wasm
  file name derives from the package name. Renaming the file takes a rebuild
  with `build.sh` and an update of this record.
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
  `RUSTUP_TOOLCHAIN=1.96.0 stellar contract build --locked --package multisig-spending-limit-policy-example`.
  The output is `<target dir>/wasm32v1-none/release/multisig_spending_limit_policy_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries. The result is a
  self-contained deployable Wasm.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(multisig_spending_limit_policy_example.wasm):**
  `0e8da0ccff5c444520085ac1973d3c8023fdd04f727ee11ae7290a49dffbbaf5`
- **Size:** 15 927 bytes.
- **Exported functions** (`Policy` trait impl per
  `examples/multisig-smart-account/spending-limit-policy/src/contract.rs` at commit `a9c4216`,
  delegating to `stellar_accounts::policies::spending_limit`):
  - `enforce(context: Context, authenticated_signers: Vec<Signer>, context_rule: ContextRule, smart_account: Address)`:
     the `Policy::enforce` entry point. Accepts only a `Context::Contract(ContractContext)`
     whose `fn_name == symbol_short!("transfer")` and whose `args.get(2)` decodes as `i128`
     (the transfer amount for a SEP-41 `transfer(from, to, amount)`); any other context
     panics `NotAllowed` (3223). Evicts spending-history entries outside the rolling
     `period_ledgers` window, then panics `SpendingLimitExceeded` (3221) if the cumulative
     total plus the new amount exceeds the stored limit; otherwise records the transfer.
     Delegates to `spending_limit::enforce`
     (`packages/accounts/src/policies/spending_limit.rs:222-292`, commit `a9c4216`).
  - `install(install_params: SpendingLimitAccountParams, context_rule: ContextRule, smart_account: Address)`:
     the `Policy::install` entry point. Requires `context_rule.context_type` to be
     `CallContract(_)`, and otherwise panics `OnlyCallContractAllowed` (3227,
     `spending_limit.rs:376-377`). Stores `{ spending_limit: i128, period_ledgers: u32 }`
     for the `(smart_account, context_rule.id)` pair. Delegates to
     `spending_limit::install` (`packages/accounts/src/policies/spending_limit.rs:367-408`,
     commit `a9c4216`). `SpendingLimitAccountParams` is a `#[contracttype]` struct whose
     ScMap encoding sorts keys alphabetically by field name, so the install param ScMap has
     `period_ledgers` before `spending_limit` ('p' 0x70 < 's' 0x73).
  - `uninstall(context_rule: ContextRule, smart_account: Address)`: the `Policy::uninstall`
     entry point. Removes the spending-limit configuration and history for the pair.
  - `get_spending_limit_data(context_rule_id: u32, smart_account: Address) -> SpendingLimitData`:
     returns the current limit, period, spending history, and cached total.
  - `set_spending_limit(spending_limit: i128, context_rule: ContextRule, smart_account: Address)`:
     updates the stored limit for the pair.
- **Per-network singleton:** the policy keys all state by
  `SpendingLimitStorageKey::AccountContext(smart_account, context_rule_id)`
  (`spending_limit.rs:145-147`), so one deployed instance serves every account and every
  context rule on the network. The wallet deploys exactly one per network with
  `smart-account deploy-spending-limit-policy` and records the address in the wallet-local
  registry (`<canonical_data_root>/networks.toml`).
- **Why deployable (release/), not deps/:** the wallet uploads this contract with
  `UploadContractWasm`, and the smart account's `__check_auth` calls it to enforce the
  spending limit at signing time. On-chain storage cost scales with size; the `release`
  output is the production deployment artifact. The wallet does not
  `contractimport!` against this Wasm; the install param is built as a typed ScMap and the
  wallet attaches the policy to a context rule with `add_policy`.
- **Cross-reference:** `vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm`
  is the deployable threshold-policy contract (the other `Policy` implementation vendored
  by this wallet). The wallet deploys this spending-limit policy with
  `smart-account deploy-spending-limit-policy`.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record and the file's `WASM_PINS` row in `build.rs`. That row also
  fails every build of the crate on a mismatch. The unit tests in
  `src/vendored_wasm_tests.rs` fail unless `SPENDING_LIMIT_POLICY_WASM` equals
  this file and `SPENDING_LIMIT_POLICY_WASM_SHA256` equals its sha256.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.

//! OZ `multisig-spending-limit-policy-example` v0.7.2 vendored WASM.
//!
//! Built from OZ `stellar-contracts` at SHA `a9c4216` (tag `v0.7.2`) via
//! `stellar contract build --package multisig-spending-limit-policy-example`
//! (stellar-cli 25.2.0). The resulting cdylib is the `release` profile output
//! (`target/wasm32v1-none/release/multisig_spending_limit_policy_example.wasm`)
//! — the deployable production contract, not a `contractimport!` artefact.
//!
//! # What this WASM does
//!
//! Soroban contract implementing the OZ `Policy` trait (per
//! OZ `examples/multisig-smart-account/spending-limit-policy/src/contract.rs`
//! at SHA `a9c4216`), delegating to `stellar_accounts::policies::spending_limit`.
//! It enforces a rolling-window transfer spending limit on a `CallContract`-scoped
//! context rule:
//!
//! - `enforce(...)` accepts only a `Context::Contract(ContractContext)` whose
//!   `fn_name == symbol_short!("transfer")` and whose `args.get(2)` decodes as
//!   `i128` (the amount of a SEP-41 `transfer(from, to, amount)`); any other
//!   context panics `NotAllowed` (3223). It evicts spending-history entries
//!   outside the rolling `period_ledgers` window, then panics
//!   `SpendingLimitExceeded` (3221) if the cumulative total plus the new amount
//!   exceeds the stored limit; otherwise it records the transfer
//!   (`packages/accounts/src/policies/spending_limit.rs:222-292`, SHA `a9c4216`).
//! - `install(...)` requires `context_rule.context_type` to be `CallContract(_)`
//!   — otherwise panics `OnlyCallContractAllowed` (3227,
//!   `spending_limit.rs:376-377`). It stores
//!   `{ spending_limit: i128, period_ledgers: u32 }` for the
//!   `(smart_account, context_rule.id)` pair.
//! - `uninstall`, `get_spending_limit_data`, `set_spending_limit` — as per the
//!   `spending_limit` module.
//!
//! `SpendingLimitAccountParams` is a `#[contracttype]` struct whose ScMap
//! encoding sorts keys alphabetically by field name, so the install param ScMap
//! has `period_ledgers` before `spending_limit` ('p' 0x70 < 's' 0x73).
//!
//! # Per-network singleton
//!
//! The policy keys all state by
//! `SpendingLimitStorageKey::AccountContext(smart_account, context_rule_id)`
//! (`spending_limit.rs:145-147`), so one deployed instance serves every account
//! and every context rule on the network. The wallet deploys exactly one per
//! network via `smart-account deploy-spending-limit-policy` and records the
//! address in the wallet-local registry (`<canonical_data_root>/networks.toml`).
//!
//! # Supply-chain integrity
//!
//! The SHA-256 of the vendored WASM is verified in the unit test
//! `tests::spending_limit_policy_wasm_sha256_matches_provenance` below, on every
//! `cargo test`. The SHA-256 value is pinned in three places (this file,
//! `build.rs`, and `vendor/oz-spending-limit-policy/v0.7.2/PROVENANCE.md`), and
//! the CI vendored-wasm gate re-hashes the in-repo WASM against PROVENANCE.md on
//! every run.

/// SHA-256 of the vendored `multisig_spending_limit_policy_example.wasm`
/// artefact.
///
/// Pinned here, in `build.rs`, and in
/// `vendor/oz-spending-limit-policy/v0.7.2/PROVENANCE.md` (same value in all
/// places). The compile-time integrity gate is `build.rs`; the runtime
/// `tests::spending_limit_policy_wasm_sha256_matches_provenance` test remains as
/// defense in depth.
///
/// Built from OZ `stellar-contracts` at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
/// (tag `v0.7.2`) via `stellar contract build --package multisig-spending-limit-policy-example`
/// (stellar-cli 25.2.0), then copying the release cdylib from
/// `target/wasm32v1-none/release/multisig_spending_limit_policy_example.wasm`.
pub const SPENDING_LIMIT_POLICY_WASM_SHA256: &str =
    "0e8da0ccff5c444520085ac1973d3c8023fdd04f727ee11ae7290a49dffbbaf5";

/// The vendored `multisig_spending_limit_policy_example.wasm` binary, embedded
/// at compile time.
///
/// Embedded so the deploy CLI (`smart-account deploy-spending-limit-policy`) can
/// upload the WASM via `UploadContractWasm` without re-fetching from disk at
/// runtime; the bytes are passed by reference to the deployment substrate.
pub const SPENDING_LIMIT_POLICY_WASM: &[u8] = include_bytes!(
    "../vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm"
);

use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScSymbol, ScVal, VecM};

use crate::SaError;
use crate::managers::rules::RuleContext;

/// Builds the OZ `SpendingLimitAccountParams` install-parameter ScVal for
/// `add_policy`.
///
/// `SpendingLimitAccountParams { spending_limit: i128, period_ledgers: u32 }` is
/// a soroban-sdk `#[contracttype]` struct
/// (`packages/accounts/src/policies/spending_limit.rs:87-93`, SHA `a9c4216`).
/// A `#[contracttype]` struct encodes to `ScVal::Map` with one `ScMapEntry` per
/// field, keyed by `ScVal::Symbol(field_name)`, and the entries MUST be in
/// ascending key order per the soroban host's ScMap validity rule (the same
/// canonical `ScVal` `Ord` rule the AuthPayload signers map relies on). Because
/// the keys are the field-name Symbols, ascending order is
/// byte-lexicographic over the names: `"period_ledgers"` precedes
/// `"spending_limit"` (`'p'` 0x70 < `'s'` 0x73), so the built map places
/// `period_ledgers` FIRST regardless of the struct's declaration order.
///
/// The i128 `spending_limit` is encoded as `ScVal::I128(Int128Parts { hi, lo })`
/// where `value == ((hi as i128) << 64) | (lo as i128)`.
///
/// # Errors
///
/// Returns [`SaError::SpendingLimitInstallRefused`] if the (fixed, short) Symbol
/// or the two-entry ScMap cannot be XDR-encoded — unreachable for these bounded
/// inputs, but surfaced rather than panicking.
pub fn build_spending_limit_install_param(
    spending_limit: i128,
    period_ledgers: u32,
) -> Result<ScVal, SaError> {
    let refuse = |reason: String| SaError::SpendingLimitInstallRefused { reason };

    let period_sym = ScSymbol::try_from("period_ledgers")
        .map_err(|e| refuse(format!("encode period_ledgers symbol: {e:?}")))?;
    let limit_sym = ScSymbol::try_from("spending_limit")
        .map_err(|e| refuse(format!("encode spending_limit symbol: {e:?}")))?;

    #[allow(
        clippy::cast_possible_truncation,
        reason = "canonical i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
    )]
    let limit_parts = Int128Parts {
        hi: (spending_limit >> 64) as i64,
        lo: spending_limit as u64,
    };

    // period_ledgers FIRST (alphabetical key order), spending_limit second.
    let entries: VecM<ScMapEntry> = vec![
        ScMapEntry {
            key: ScVal::Symbol(period_sym),
            val: ScVal::U32(period_ledgers),
        },
        ScMapEntry {
            key: ScVal::Symbol(limit_sym),
            val: ScVal::I128(limit_parts),
        },
    ]
    .try_into()
    .map_err(|e| refuse(format!("encode SpendingLimitAccountParams ScMap: {e:?}")))?;

    Ok(ScVal::Map(Some(ScMap(entries))))
}

/// Refuses a typed spending-limit install against a non-`CallContract` rule
/// before any simulate/submit.
///
/// OZ `install` panics `OnlyCallContractAllowed` (3227) for any rule whose
/// `context_type` is not `CallContract`
/// (`packages/accounts/src/policies/spending_limit.rs:376-377`, SHA `a9c4216`);
/// catching it client-side avoids a wasted round-trip and names the constraint.
///
/// # Errors
///
/// Returns [`SaError::SpendingLimitInstallRefused`] when `context` is
/// [`RuleContext::Default`] or [`RuleContext::CreateContract`].
pub fn ensure_call_contract_context_for_spending_limit(
    context: &RuleContext,
) -> Result<(), SaError> {
    match context {
        RuleContext::CallContract { .. } => Ok(()),
        RuleContext::Default => Err(SaError::SpendingLimitInstallRefused {
            reason: "the spending-limit policy requires a CallContract-scoped rule, but the \
                     target rule is Default; OZ install rejects non-CallContract rules \
                     (OnlyCallContractAllowed). Create a CallContract rule for the token \
                     contract first."
                .to_owned(),
        }),
        RuleContext::CreateContract { .. } => Err(SaError::SpendingLimitInstallRefused {
            reason: "the spending-limit policy requires a CallContract-scoped rule, but the \
                     target rule is CreateContract; OZ install rejects non-CallContract rules \
                     (OnlyCallContractAllowed)."
                .to_owned(),
        }),
    }
}

/// Refuses a typed spending-limit install whose `limit` or `period` values
/// fail the OZ install-time value constraint, before any simulate/submit.
///
/// OZ `install` panics `InvalidLimitOrPeriod` (3222) when
/// `params.spending_limit <= 0 || params.period_ledgers == 0`
/// (`packages/accounts/src/policies/spending_limit.rs:380-381`, SHA `a9c4216`);
/// catching it client-side avoids a wasted round-trip and names the
/// constraint.
///
/// # Errors
///
/// Returns [`SaError::SpendingLimitInstallRefused`] when `limit <= 0` or
/// `period == 0`.
pub fn ensure_valid_spending_limit_params(limit: i128, period: u32) -> Result<(), SaError> {
    if limit <= 0 && period == 0 {
        return Err(SaError::SpendingLimitInstallRefused {
            reason: format!(
                "--limit must be positive and --period must be non-zero; got limit={limit}, \
                 period={period} (OZ install rejects both with InvalidLimitOrPeriod)"
            ),
        });
    }
    if limit <= 0 {
        return Err(SaError::SpendingLimitInstallRefused {
            reason: format!(
                "--limit must be positive; got {limit} (OZ install rejects non-positive \
                 spending_limit with InvalidLimitOrPeriod)"
            ),
        });
    }
    if period == 0 {
        return Err(SaError::SpendingLimitInstallRefused {
            reason: "--period must be non-zero (OZ install rejects a zero period_ledgers with \
                      InvalidLimitOrPeriod)"
                .to_owned(),
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only shape assertions")]

    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Asserts that `SHA256(SPENDING_LIMIT_POLICY_WASM)` matches the pinned
    /// `SPENDING_LIMIT_POLICY_WASM_SHA256` const. Supply-chain integrity gate;
    /// fires on every `cargo test`.
    #[test]
    fn spending_limit_policy_wasm_sha256_matches_provenance() {
        let mut hasher = Sha256::new();
        hasher.update(SPENDING_LIMIT_POLICY_WASM);
        let digest: [u8; 32] = hasher.finalize().into();
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, SPENDING_LIMIT_POLICY_WASM_SHA256,
            "vendored multisig_spending_limit_policy_example.wasm sha256 mismatch: \
             expected {SPENDING_LIMIT_POLICY_WASM_SHA256}, got {actual}. \
             If the WASM was intentionally updated, regenerate via \
             vendor/oz-spending-limit-policy/v0.7.2/build.sh and update both \
             SPENDING_LIMIT_POLICY_WASM_SHA256 and PROVENANCE.md."
        );
    }

    /// Asserts the embedded WASM starts with the WASM binary magic bytes
    /// `\0asm`.
    #[test]
    fn spending_limit_policy_wasm_has_correct_magic_bytes() {
        assert_eq!(
            &SPENDING_LIMIT_POLICY_WASM[..4],
            b"\0asm",
            "SPENDING_LIMIT_POLICY_WASM must start with WASM magic bytes"
        );
    }

    /// Asserts the embedded WASM byte length matches the value recorded in
    /// PROVENANCE.md.
    #[test]
    fn spending_limit_policy_wasm_size_matches_provenance() {
        assert_eq!(
            SPENDING_LIMIT_POLICY_WASM.len(),
            15_927,
            "vendored WASM byte count must match the value recorded in \
             vendor/oz-spending-limit-policy/v0.7.2/PROVENANCE.md"
        );
    }

    /// The install-param ScMap places `period_ledgers` FIRST and `spending_limit`
    /// second (ascending Symbol-key order), with the correct u32 and i128 values.
    #[test]
    fn install_param_scmap_period_ledgers_first() {
        let scval = build_spending_limit_install_param(10_000_000_i128, 17_280_u32)
            .expect("build install param");

        let ScVal::Map(Some(ScMap(entries))) = &scval else {
            panic!("install param must be ScVal::Map");
        };
        assert_eq!(entries.len(), 2, "two struct fields");

        // Entry 0: period_ledgers (u32).
        let ScVal::Symbol(k0) = &entries[0].key else {
            panic!("key0 must be Symbol")
        };
        assert_eq!(
            k0.to_utf8_string_lossy(),
            "period_ledgers",
            "period_ledgers must be first (0x70 < 0x73)"
        );
        assert_eq!(entries[0].val, ScVal::U32(17_280));

        // Entry 1: spending_limit (i128).
        let ScVal::Symbol(k1) = &entries[1].key else {
            panic!("key1 must be Symbol")
        };
        assert_eq!(k1.to_utf8_string_lossy(), "spending_limit");
        let ScVal::I128(parts) = &entries[1].val else {
            panic!("spending_limit must be I128")
        };
        let recovered: i128 = ((parts.hi as i128) << 64) | i128::from(parts.lo);
        assert_eq!(recovered, 10_000_000_i128);
    }

    /// The map key order equals the canonical ScVal Ord (the soroban host's
    /// ScMap validity rule): re-sorting the keys is a no-op.
    #[test]
    fn install_param_keys_are_in_canonical_scval_order() {
        let scval = build_spending_limit_install_param(1_i128, 1_u32).expect("build");
        let ScVal::Map(Some(ScMap(entries))) = &scval else {
            panic!("must be Map")
        };
        let mut keys: Vec<&ScVal> = entries.iter().map(|e| &e.key).collect();
        let before = keys.clone();
        keys.sort();
        assert_eq!(keys, before, "install-param keys must be in ScVal Ord");
    }

    /// A negative / large i128 round-trips through the Int128Parts split.
    #[test]
    fn install_param_i128_split_round_trips() {
        for v in [i128::MIN, -1, 0, 1, i128::MAX, 1_i128 << 100] {
            let scval = build_spending_limit_install_param(v, 5).expect("build");
            let ScVal::Map(Some(ScMap(entries))) = &scval else {
                panic!("map")
            };
            let ScVal::I128(parts) = &entries[1].val else {
                panic!("i128")
            };
            let recovered: i128 = ((parts.hi as i128) << 64) | i128::from(parts.lo);
            assert_eq!(recovered, v, "i128 {v} must round-trip through Int128Parts");
        }
    }

    /// The CallContract-only client-side refusal fires for Default and
    /// CreateContract rule contexts and does NOT fire for CallContract.
    #[test]
    fn call_contract_only_refusal_matrix() {
        use stellar_xdr::{ContractId, Hash, ScAddress};

        let call_contract = RuleContext::CallContract {
            contract: ScAddress::Contract(ContractId(Hash([7u8; 32]))),
        };
        assert!(
            ensure_call_contract_context_for_spending_limit(&call_contract).is_ok(),
            "CallContract rule must be accepted"
        );

        let default_err = ensure_call_contract_context_for_spending_limit(&RuleContext::Default)
            .expect_err("Default must be refused");
        assert!(matches!(
            default_err,
            SaError::SpendingLimitInstallRefused { .. }
        ));

        let create_err =
            ensure_call_contract_context_for_spending_limit(&RuleContext::CreateContract {
                wasm_hash: [0u8; 32],
            })
            .expect_err("CreateContract must be refused");
        assert!(matches!(
            create_err,
            SaError::SpendingLimitInstallRefused { .. }
        ));
    }

    /// `ensure_valid_spending_limit_params` refuses `limit <= 0`, refuses
    /// `period == 0`, refuses both simultaneously, and accepts a valid pair —
    /// mirroring the OZ `InvalidLimitOrPeriod` constraint
    /// (`spending_limit.rs:380-381`, SHA `a9c4216`).
    #[test]
    fn valid_spending_limit_params_refusal_matrix() {
        assert!(
            matches!(
                ensure_valid_spending_limit_params(0, 100),
                Err(SaError::SpendingLimitInstallRefused { .. })
            ),
            "limit == 0 must be refused"
        );
        assert!(
            matches!(
                ensure_valid_spending_limit_params(-1, 100),
                Err(SaError::SpendingLimitInstallRefused { .. })
            ),
            "negative limit must be refused"
        );
        assert!(
            matches!(
                ensure_valid_spending_limit_params(100, 0),
                Err(SaError::SpendingLimitInstallRefused { .. })
            ),
            "period == 0 must be refused"
        );
        assert!(
            matches!(
                ensure_valid_spending_limit_params(0, 0),
                Err(SaError::SpendingLimitInstallRefused { .. })
            ),
            "limit == 0 and period == 0 together must be refused"
        );
        assert!(
            ensure_valid_spending_limit_params(1, 1).is_ok(),
            "a positive limit and non-zero period must be accepted"
        );
        assert!(
            ensure_valid_spending_limit_params(50_000_000, 17_280).is_ok(),
            "a realistic limit/period pair must be accepted"
        );
    }
}

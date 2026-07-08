//! Bundle decomposition and overlay substrate for multicall policy evaluation.
//!
//! This module provides:
//!
//! - [`crate::policy::v1::bundle::InnerOpDescriptor`] — typed description of a single inner operation in a
//!   multicall bundle, produced by [`crate::policy::v1::bundle::decompose_bundle`].
//! - [`crate::policy::v1::bundle::BundleView`] — a read-only view of the full bundle passed into each
//!   [`crate::policy::v1::EvalContext`] during
//!   [`crate::policy::v1::PolicyEngineV1::evaluate_bundle`].
//! - `BundleStateOverlay` — a per-`StateKey` `i128` accumulator that lets
//!   stateful criteria (`per_period_cap`, `rate_limit`) account for inners
//!   evaluated earlier in the same bundle without committing to the persistent
//!   [`crate::policy::v1::criteria::state_store::PolicyStateStore`].
//! - [`crate::policy::v1::bundle::decompose_bundle`] — converts raw `(target, fn_name, args)` triples into
//!   typed `InnerOpDescriptor` values, recognising canonical SAC token-transfer
//!   invocations.
//!
//! # SAC token-transfer recognition
//!
//! An inner is classified as `InnerOpDescriptor::TokenTransfer` when ALL of:
//!
//! 1. `target` decodes via [`stellar_strkey::Contract::from_string`] (strict).
//! 2. `fn_name == "transfer"` (exact byte equality).
//! 3. `args.len() == 3`.
//! 4. `args[0]` and `args[1]` are strings that decode via
//!    [`stellar_strkey::ed25519::PublicKey::from_string`] (strict).
//! 5. `args[2]` is a string parseable as `i128` via `parse_i128_arg`.
//!
//! If any condition fails, the inner is classified as
//! `InnerOpDescriptor::Generic`.
//!
//! # i128 amount convention
//!
//! Policy amounts for bundle aggregation use `i128` because the per-bundle sum
//! may exceed `i64::MAX` when multiple inners are combined.  Individual inner
//! amounts in a SAC token transfer are `i128` at the XDR layer (the SAC ABI
//! uses `Int128Parts` for transfer amounts).
//!
//! The JSON convention (matching the wallet's existing `per_tx_cap` / `per_period_cap`
//! string-amount style) passes `args[2]` as a decimal string `"<decimal>"`.
//! `parse_i128_arg` accepts that form.

use std::collections::HashMap;

use crate::policy::v1::criteria::state_store::StateKey;

// ─────────────────────────────────────────────────────────────────────────────
// InnerOpDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Typed descriptor for a single inner operation within a multicall bundle.
///
/// Produced by [`decompose_bundle`] from raw `(target, fn_name, args)` triples.
/// The `#[non_exhaustive]` attribute ensures that new recognised kinds (e.g.
/// clawback, mint) can be added in future releases without breaking downstream
/// `match` exhaustion.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::bundle::{InnerOpDescriptor, decompose_bundle};
///
/// // SOURCE_G and DEST_G are valid G-strkeys from the codebase test fixtures.
/// let raw = vec![(
///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
///     "transfer".to_owned(),
///     vec![
///         serde_json::Value::String("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned()),
///         serde_json::Value::String("GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned()),
///         serde_json::Value::String("1000000000".to_owned()),
///     ],
/// )];
/// let descriptors = decompose_bundle(&raw);
/// assert!(matches!(descriptors[0], InnerOpDescriptor::TokenTransfer { .. }));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum InnerOpDescriptor {
    /// A canonical SAC (Stellar Asset Contract) token transfer.
    ///
    /// All fields are validated at decomposition time:
    /// - `asset` — the contract address (C-strkey) of the SAC.
    /// - `from` — the sender G-strkey (ed25519 public key).
    /// - `to` — the recipient G-strkey.
    /// - `amount` — the transfer amount as `i128` (raw stroop units from the
    ///   SAC ABI).
    TokenTransfer {
        /// SAC contract address (C-strkey).
        asset: String,
        /// Sender address (G-strkey).
        from: String,
        /// Recipient address (G-strkey).
        to: String,
        /// Transfer amount in SAC raw units (i128; typically stroop-scale).
        amount: i128,
    },
    /// An inner operation whose ABI shape does not match any recognised pattern.
    ///
    /// Any inner that fails SAC recognition falls through to `Generic`.
    /// [`crate::policy::v1::criteria::restrict_bundle_to_recognised_kinds::RestrictBundleToRecognisedKindsCriterion`]
    /// denies bundles containing this variant when enabled.
    ///
    /// The `arg_count` field has been deliberately omitted: counting raw args would
    /// require a `u8` truncation (`usize → u8`) that is unsound for arg lists
    /// longer than 255, and the count is not used by any criterion.
    Generic {
        /// Raw target contract address (may be any string; not strkey-validated).
        target: String,
        /// Raw function name.
        fn_name: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// BundleStateOverlay
// ─────────────────────────────────────────────────────────────────────────────

/// Per-`StateKey` `i128` accumulator for in-flight bundle evaluation.
///
/// Stateful criteria (`per_period_cap`, `rate_limit`) read from both the
/// persistent [`crate::policy::v1::criteria::state_store::PolicyStateStore`]
/// and this overlay to account for amounts already approved in earlier inners
/// of the same bundle, without writing to the persistent store mid-bundle.
///
/// # Overflow discipline
///
/// Accumulation uses `i128` end-to-end (no clamp): each `TokenTransfer`
/// inner's amount is already `i128` at the descriptor layer, so it is
/// accumulated directly.  [`i128::saturating_add`] guards only against the
/// running total itself overflowing `i128::MAX`, not against narrowing to a
/// smaller integer type.
///
/// # Single-tx path
///
/// When `bundle` is `None` in [`crate::policy::v1::EvalContext`], stateful
/// criteria see `bundle_accumulated_stroops = 0` (the `unwrap_or(0)` guard at
/// the call site), preserving byte-identical behaviour with single-tx
/// evaluation.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::bundle::BundleStateOverlay;
///
/// let overlay = BundleStateOverlay::default();
/// // Overlay is constructed via Default; individual read-back is crate-internal.
/// assert!(format!("{overlay:?}").contains("BundleStateOverlay"));
/// ```
#[derive(Debug, Default)]
pub struct BundleStateOverlay {
    per_key_accumulated_stroops: HashMap<StateKey, i128>,
}

impl BundleStateOverlay {
    /// Returns the accumulated stroops for `state_key`, or `0` when absent.
    ///
    /// This is a `pub(crate)` method.  Only criteria within `stellar-agent-core`
    /// (specifically `per_period_cap` and `rate_limit`) call this to read back
    /// the overlay they wrote via [`accumulate`].  External code has no
    /// legitimate read use case; reading without understanding the key-shape
    /// convention would yield misleading results.
    #[must_use]
    pub(crate) fn get(&self, state_key: &StateKey) -> i128 {
        self.per_key_accumulated_stroops
            .get(state_key)
            .copied()
            .unwrap_or(0)
    }

    /// Adds `attempted_stroops` to the running total for `state_key`.
    ///
    /// Uses [`i128::saturating_add`] to prevent overflow.  When the accumulated
    /// total saturates at `i128::MAX`, subsequent `get` calls return `i128::MAX`,
    /// which will cause the per-period cap to deny (over-deny rather than
    /// under-deny — a safe-fail posture).
    ///
    /// This is a `pub(crate)` method; only [`crate::policy::v1::PolicyEngineV1::evaluate_bundle`]
    /// calls it.
    pub(crate) fn accumulate(&mut self, state_key: StateKey, attempted_stroops: i128) {
        let entry = self
            .per_key_accumulated_stroops
            .entry(state_key)
            .or_insert(0);
        *entry = entry.saturating_add(attempted_stroops);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BundleView
// ─────────────────────────────────────────────────────────────────────────────

/// Read-only view of a multicall bundle passed into [`crate::policy::v1::EvalContext`].
///
/// `BundleView` is constructed fresh for each inner evaluation inside
/// [`crate::policy::v1::PolicyEngineV1::evaluate_bundle`] and also for the
/// final bundle-level criteria pass.  The `inners` slice always covers the
/// **full** bundle regardless of which inner is currently being evaluated, so
/// bundle-level criteria (count cap, aggregate cap) can inspect all inners.
///
/// # Lifetime
///
/// Both `inners` and `overlay` are borrows with lifetime `'a` tied to the
/// `evaluate_bundle` stack frame.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::bundle::{BundleView, BundleStateOverlay, InnerOpDescriptor};
///
/// let overlay = BundleStateOverlay::default();
/// let inners: Vec<InnerOpDescriptor> = vec![];
/// let view = BundleView { inners: &inners, overlay: &overlay };
/// assert_eq!(view.inners.len(), 0);
/// ```
#[derive(Debug)]
pub struct BundleView<'a> {
    /// All inner operation descriptors in the bundle.
    pub inners: &'a [InnerOpDescriptor],
    /// In-flight state overlay (amounts accumulated from already-evaluated inners).
    pub overlay: &'a BundleStateOverlay,
}

// ─────────────────────────────────────────────────────────────────────────────
// decompose_bundle
// ─────────────────────────────────────────────────────────────────────────────

/// Converts raw `(target, fn_name, args)` triples into typed [`InnerOpDescriptor`] values.
///
/// Each triple is matched against the canonical SAC token-transfer shape; any
/// triple that fails one or more conditions falls through to
/// [`InnerOpDescriptor::Generic`].
///
/// # SAC recognition criteria
///
/// 1. `target` decodes via [`stellar_strkey::Contract::from_string`] (strict).
/// 2. `fn_name == "transfer"` (exact).
/// 3. `args.len() == 3`.
/// 4. `args[0]` and `args[1]` are strings decodable via
///    [`stellar_strkey::ed25519::PublicKey::from_string`] (strict).
/// 5. `args[2]` is a string parseable as `i128` via [`parse_i128_arg`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::bundle::{InnerOpDescriptor, decompose_bundle};
///
/// // Generic triple (wrong function name).
/// let raw = vec![(
///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
///     "mint".to_owned(),
///     vec![
///         serde_json::Value::String("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".to_owned()),
///         serde_json::Value::String("1000000000".to_owned()),
///     ],
/// )];
/// let descriptors = decompose_bundle(&raw);
/// assert!(matches!(descriptors[0], InnerOpDescriptor::Generic { .. }));
/// ```
#[must_use]
pub fn decompose_bundle(
    raw: &[(String, String, Vec<serde_json::Value>)],
) -> Vec<InnerOpDescriptor> {
    raw.iter()
        .map(|(target, fn_name, args)| {
            try_decompose_as_token_transfer(target, fn_name, args).unwrap_or_else(|| {
                InnerOpDescriptor::Generic {
                    target: target.clone(),
                    fn_name: fn_name.clone(),
                }
            })
        })
        .collect()
}

/// Attempts to recognise a single raw triple as a SAC token transfer.
///
/// Returns `Some(TokenTransfer { .. })` when all five recognition criteria are
/// met; `None` otherwise.
fn try_decompose_as_token_transfer(
    target: &str,
    fn_name: &str,
    args: &[serde_json::Value],
) -> Option<InnerOpDescriptor> {
    // Condition 1: target must be a valid C-strkey.
    stellar_strkey::Contract::from_string(target).ok()?;

    // Condition 2: function name must be exactly "transfer".
    if fn_name != "transfer" {
        return None;
    }

    // Condition 3: must have exactly 3 arguments.
    if args.len() != 3 {
        return None;
    }

    // Condition 4a: args[0] must be a string decodable as a G-strkey.
    let from_str = args[0].as_str()?;
    stellar_strkey::ed25519::PublicKey::from_string(from_str).ok()?;

    // Condition 4b: args[1] must be a string decodable as a G-strkey.
    let to_str = args[1].as_str()?;
    stellar_strkey::ed25519::PublicKey::from_string(to_str).ok()?;

    // Condition 5: args[2] must be a string parseable as i128.
    let amount = parse_i128_arg(&args[2])?;

    // Condition 6: amount must be non-negative (defence-in-depth).
    // A negative amount does not represent a valid token transfer quantity.
    // Falling through to Generic lets RestrictBundleToRecognisedKindsCriterion
    // deny the inner when enabled, which is the correct fail-CLOSED posture.
    if amount < 0 {
        return None;
    }

    Some(InnerOpDescriptor::TokenTransfer {
        asset: target.to_owned(),
        from: from_str.to_owned(),
        to: to_str.to_owned(),
        amount,
    })
}

/// Parses a JSON value as an `i128`.
///
/// The wallet uses a string-encoded decimal convention for large integer amounts
/// (matching the `per_tx_cap` / `per_period_cap` style).  This function accepts:
///
/// - A JSON string containing a decimal `i128` (e.g. `"1000000000"`).
/// - A JSON unsigned 64-bit integer (`u64`-range; checked BEFORE `i64` so that
///   values such as `u64::MAX` are not silently rejected by `as_i64()`).
/// - A JSON signed 64-bit integer (`i64`-range; for forward compat with callers
///   that emit bare negative integers).
///
/// Returns `None` when the value is neither a parseable string nor a JSON integer.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::bundle::parse_i128_arg;
/// use serde_json::json;
///
/// assert_eq!(parse_i128_arg(&json!("1000000000")), Some(1_000_000_000_i128));
/// assert_eq!(parse_i128_arg(&json!(42i64)), Some(42_i128));
/// assert_eq!(parse_i128_arg(&json!(u64::MAX)), Some(i128::from(u64::MAX)));
/// assert_eq!(parse_i128_arg(&json!("not-a-number")), None);
/// assert_eq!(parse_i128_arg(&json!(null)), None);
/// ```
#[must_use]
pub fn parse_i128_arg(v: &serde_json::Value) -> Option<i128> {
    if let Some(s) = v.as_str() {
        return s.parse::<i128>().ok();
    }
    // Check u64 first: serde_json represents large positive integers (e.g. u64::MAX)
    // as unsigned, which as_i64() would reject.  Both branches widen losslessly to i128.
    if let Some(n) = v.as_u64() {
        return Some(i128::from(n));
    }
    if let Some(n) = v.as_i64() {
        return Some(i128::from(n));
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use serde_json::json;

    use super::*;
    use crate::policy::v1::criteria::state_store::StateKey;

    // ── SAC strkey test fixtures ──────────────────────────────────────────────
    //
    // Contract (C-strkey): CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM
    // This is a valid Stellar C-strkey (32 zero bytes with CRC-16 checksum).
    // Verified via stellar_strkey::Contract::from_string (passes).
    //
    // Public keys (G-strkeys): both verified via
    // stellar_strkey::ed25519::PublicKey::from_string (passes).

    const SAC_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    const ADDR_FROM: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const ADDR_TO: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

    fn make_transfer_triple(amount: &str) -> (String, String, Vec<serde_json::Value>) {
        (
            SAC_CONTRACT.to_owned(),
            "transfer".to_owned(),
            vec![json!(ADDR_FROM), json!(ADDR_TO), json!(amount)],
        )
    }

    // ── decompose_bundle tests ────────────────────────────────────────────────

    #[test]
    fn decompose_recognises_sac_transfer() {
        let raw = vec![make_transfer_triple("1000000000")];
        let descriptors = decompose_bundle(&raw);
        assert_eq!(descriptors.len(), 1);
        match &descriptors[0] {
            InnerOpDescriptor::TokenTransfer {
                asset,
                from,
                to,
                amount,
            } => {
                assert_eq!(asset, SAC_CONTRACT);
                assert_eq!(from, ADDR_FROM);
                assert_eq!(to, ADDR_TO);
                assert_eq!(*amount, 1_000_000_000_i128);
            }
            other => panic!("expected TokenTransfer, got {other:?}"),
        }
    }

    #[test]
    fn decompose_falls_through_to_generic_on_wrong_fn_name() {
        let raw = vec![(
            SAC_CONTRACT.to_owned(),
            "mint".to_owned(),
            vec![json!(ADDR_FROM), json!("1000000000")],
        )];
        let descriptors = decompose_bundle(&raw);
        assert!(
            matches!(descriptors[0], InnerOpDescriptor::Generic { .. }),
            "wrong fn_name must produce Generic"
        );
    }

    #[test]
    fn decompose_falls_through_to_generic_on_invalid_contract() {
        let raw = vec![(
            "not-a-strkey".to_owned(),
            "transfer".to_owned(),
            vec![json!(ADDR_FROM), json!(ADDR_TO), json!("100")],
        )];
        let descriptors = decompose_bundle(&raw);
        assert!(
            matches!(descriptors[0], InnerOpDescriptor::Generic { .. }),
            "invalid contract address must produce Generic"
        );
    }

    #[test]
    fn decompose_falls_through_to_generic_on_wrong_arg_count() {
        let raw = vec![(
            SAC_CONTRACT.to_owned(),
            "transfer".to_owned(),
            vec![json!(ADDR_FROM), json!("100")], // only 2 args
        )];
        let descriptors = decompose_bundle(&raw);
        assert!(
            matches!(descriptors[0], InnerOpDescriptor::Generic { .. }),
            "wrong arg count must produce Generic"
        );
    }

    #[test]
    fn decompose_falls_through_to_generic_on_invalid_from_address() {
        let raw = vec![(
            SAC_CONTRACT.to_owned(),
            "transfer".to_owned(),
            vec![json!("not-a-gstrkey"), json!(ADDR_TO), json!("100")],
        )];
        let descriptors = decompose_bundle(&raw);
        assert!(
            matches!(descriptors[0], InnerOpDescriptor::Generic { .. }),
            "invalid from address must produce Generic"
        );
    }

    #[test]
    fn decompose_falls_through_to_generic_on_invalid_to_address() {
        let raw = vec![(
            SAC_CONTRACT.to_owned(),
            "transfer".to_owned(),
            vec![json!(ADDR_FROM), json!("not-a-gstrkey"), json!("100")],
        )];
        let descriptors = decompose_bundle(&raw);
        assert!(
            matches!(descriptors[0], InnerOpDescriptor::Generic { .. }),
            "invalid to address must produce Generic"
        );
    }

    #[test]
    fn decompose_falls_through_to_generic_on_non_parseable_amount() {
        let raw = vec![(
            SAC_CONTRACT.to_owned(),
            "transfer".to_owned(),
            vec![json!(ADDR_FROM), json!(ADDR_TO), json!("not-a-number")],
        )];
        let descriptors = decompose_bundle(&raw);
        assert!(
            matches!(descriptors[0], InnerOpDescriptor::Generic { .. }),
            "non-parseable amount must produce Generic"
        );
    }

    #[test]
    fn decompose_empty_bundle_returns_empty_vec() {
        let descriptors = decompose_bundle(&[]);
        assert!(descriptors.is_empty());
    }

    #[test]
    fn decompose_mixed_bundle_classifies_correctly() {
        let raw = vec![
            make_transfer_triple("500"),
            (SAC_CONTRACT.to_owned(), "unknown_fn".to_owned(), vec![]),
        ];
        let descriptors = decompose_bundle(&raw);
        assert_eq!(descriptors.len(), 2);
        assert!(matches!(
            descriptors[0],
            InnerOpDescriptor::TokenTransfer { .. }
        ));
        assert!(matches!(descriptors[1], InnerOpDescriptor::Generic { .. }));
    }

    // ── BundleStateOverlay tests ──────────────────────────────────────────────

    #[test]
    fn overlay_get_returns_zero_for_unknown_key() {
        let overlay = BundleStateOverlay::default();
        let key = StateKey::new("alice", 1, "native", 3_600);
        assert_eq!(overlay.get(&key), 0);
    }

    #[test]
    fn overlay_accumulate_and_get_round_trips() {
        let mut overlay = BundleStateOverlay::default();
        let key = StateKey::new("alice", 1, "native", 86_400);
        overlay.accumulate(key.clone(), 500_000_000);
        overlay.accumulate(key.clone(), 300_000_000);
        assert_eq!(overlay.get(&key), 800_000_000);
    }

    #[test]
    fn overlay_accumulate_saturates_at_i128_max() {
        let mut overlay = BundleStateOverlay::default();
        let key = StateKey::new("alice", 1, "native", 3_600);
        overlay.accumulate(key.clone(), i128::MAX);
        overlay.accumulate(key.clone(), 1);
        assert_eq!(overlay.get(&key), i128::MAX, "must saturate, not overflow");
    }

    /// A value strictly greater than `i64::MAX` must accumulate exactly, with
    /// no narrowing clamp to `i64::MAX` — the overlay stores an on-chain
    /// `i128` token quantity directly.
    #[test]
    fn overlay_accumulate_and_get_round_trips_value_beyond_i64_max() {
        let mut overlay = BundleStateOverlay::default();
        let key = StateKey::new("alice", 1, "native", 3_600);
        let beyond_i64_max = i128::from(i64::MAX) + 1_000;
        overlay.accumulate(key.clone(), beyond_i64_max);
        assert_eq!(
            overlay.get(&key),
            beyond_i64_max,
            "amounts beyond i64::MAX must accumulate exactly, not clamp"
        );
    }

    #[test]
    fn overlay_separate_keys_do_not_share_state() {
        let mut overlay = BundleStateOverlay::default();
        let k1 = StateKey::new("alice", 1, "native", 3_600);
        let k2 = StateKey::new("alice", 1, "USDC:GISSUER", 3_600);
        overlay.accumulate(k1.clone(), 100);
        assert_eq!(overlay.get(&k2), 0);
    }

    // ── parse_i128_arg tests ──────────────────────────────────────────────────

    #[test]
    fn parse_i128_arg_string_decimal() {
        assert_eq!(
            parse_i128_arg(&json!("1000000000")),
            Some(1_000_000_000_i128)
        );
    }

    #[test]
    fn parse_i128_arg_negative_string() {
        assert_eq!(parse_i128_arg(&json!("-1")), Some(-1_i128));
    }

    #[test]
    fn parse_i128_arg_i64_integer() {
        assert_eq!(parse_i128_arg(&json!(42i64)), Some(42_i128));
    }

    #[test]
    fn parse_i128_arg_non_parseable_string_returns_none() {
        assert_eq!(parse_i128_arg(&json!("not-a-number")), None);
    }

    #[test]
    fn parse_i128_arg_null_returns_none() {
        assert_eq!(parse_i128_arg(&serde_json::Value::Null), None);
    }

    /// Regression test: u64::MAX exceeds i64::MAX and must be returned via the
    /// `as_u64` branch, not silently rejected.  The `as_u64` branch must be
    /// checked before `as_i64` because serde_json represents large positive
    /// integers (e.g. `u64::MAX`) only as unsigned.
    #[test]
    fn parse_i128_arg_u64_max_returns_some() {
        // serde_json stores u64::MAX as a Number in u64 range; as_i64() returns None.
        assert_eq!(
            parse_i128_arg(&json!(u64::MAX)),
            Some(i128::from(u64::MAX)),
            "u64::MAX must be returned via the as_u64 branch"
        );
    }

    /// Negative amounts are not valid token transfer quantities.  A negative
    /// `args[2]` value falls through to `Generic` so that
    /// `RestrictBundleToRecognisedKindsCriterion` can deny the inner when
    /// enabled — the correct fail-closed posture.
    #[test]
    fn decompose_negative_amount_falls_through_to_generic() {
        let raw = vec![make_transfer_triple("-1")];
        let descriptors = decompose_bundle(&raw);
        assert!(
            matches!(descriptors[0], InnerOpDescriptor::Generic { .. }),
            "negative amount must produce Generic (fallthrough; defence-in-depth)"
        );
    }
}

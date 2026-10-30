//! Typed bundle decomposition and state overlays for multicall policy evaluation.
//!
//! A valued call is exactly `transfer(Address from, Address to, I128 amount)`
//! on a contract address, with a nonnegative amount and `from` equal to the
//! wallet. The recipient has an account or contract strkey. Every other call
//! is generic.
//! The gate values the calls the wallet authorizes. A transfer between other
//! addresses needs their authorization and contributes no sized wallet outflow.

use crate::sc_address::scaddress_to_strkey;
use std::collections::HashMap;
use stellar_xdr::{InvokeContractArgs, ScAddress, ScVal};

use crate::policy::v1::criteria::state_store::StateKey;

// ─────────────────────────────────────────────────────────────────────────────
// InnerOpDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Typed descriptor for a call in a multicall bundle.
///
/// Produced by [`decompose_bundle_calls`] from the encoded calls.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::bundle::{InnerOpDescriptor, decompose_bundle_calls};
/// use stellar_xdr::{ContractId, Hash, Int128Parts, InvokeContractArgs, ScAddress, ScVal};
/// let wallet = ScAddress::Contract(ContractId(Hash([0x44; 32])));
/// let call = InvokeContractArgs {
///     contract_address: ScAddress::Contract(ContractId(Hash([0x47; 32]))),
///     function_name: "transfer".try_into().unwrap(),
///     args: vec![ScVal::Address(wallet.clone()), ScVal::Address(wallet.clone()),
///         ScVal::I128(Int128Parts { hi: 0, lo: 30 })].try_into().unwrap(),
/// };
/// let descriptors = decompose_bundle_calls(&[call], &wallet);
/// assert!(matches!(descriptors[0], InnerOpDescriptor::TokenTransfer { amount: 30, .. }));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum InnerOpDescriptor {
    /// A token transfer from the wallet, with a nonnegative amount.
    TokenTransfer {
        /// SAC contract address (C-strkey).
        asset: String,
        /// Wallet address (account or contract strkey).
        from: String,
        /// Recipient address (account or contract strkey).
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
        /// Target strkey, or the name of an unsupported address variant.
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
// decompose_bundle_calls
// ─────────────────────────────────────────────────────────────────────────────

/// Decomposes encoded calls into wallet transfers and unsized calls.
///
/// Only `transfer` on a contract address, with exactly two addresses and an
/// `I128` amount, counts: the token is the called contract, so a call whose
/// target is any other address variant names no token to value. The sender
/// equals `wallet`, the recipient has a strkey, and the amount is
/// nonnegative. Every other shape is [`InnerOpDescriptor::Generic`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::bundle::{InnerOpDescriptor, decompose_bundle_calls};
/// use stellar_xdr::{ContractId, Hash, Int128Parts, InvokeContractArgs, ScAddress, ScVal};
/// let wallet = ScAddress::Contract(ContractId(Hash([0x44; 32])));
/// let call = InvokeContractArgs {
///     contract_address: ScAddress::Contract(ContractId(Hash([0x47; 32]))),
///     function_name: "transfer".try_into().unwrap(),
///     args: vec![ScVal::Address(wallet.clone()), ScVal::Address(wallet.clone()),
///         ScVal::I128(Int128Parts { hi: 0, lo: 30 })].try_into().unwrap(),
/// };
/// let descriptors = decompose_bundle_calls(&[call], &wallet);
/// assert!(matches!(descriptors[0], InnerOpDescriptor::TokenTransfer { amount: 30, .. }));
/// ```
#[must_use]
pub fn decompose_bundle_calls(
    calls: &[InvokeContractArgs],
    wallet: &ScAddress,
) -> Vec<InnerOpDescriptor> {
    calls
        .iter()
        .map(|call| {
            let target = scaddress_to_strkey(&call.contract_address)
                .unwrap_or_else(|error| error.variant.to_owned());
            if matches!(call.contract_address, ScAddress::Contract(_))
                && call.function_name.0.as_slice() == b"transfer"
                && let [ScVal::Address(from), ScVal::Address(to), ScVal::I128(parts)] =
                    call.args.as_slice()
                && from == wallet
                && let (Ok(from), Ok(to)) = (scaddress_to_strkey(from), scaddress_to_strkey(to))
            {
                let amount = (i128::from(parts.hi) << 64) | i128::from(parts.lo);
                if amount >= 0 {
                    return InnerOpDescriptor::TokenTransfer {
                        asset: target,
                        from,
                        to,
                        amount,
                    };
                }
            }
            InnerOpDescriptor::Generic {
                target,
                fn_name: String::from_utf8_lossy(call.function_name.0.as_slice()).into_owned(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use stellar_xdr::{AccountId, ContractId, Hash, Int128Parts, PublicKey, Uint256};

    use super::*;
    use crate::policy::v1::criteria::state_store::StateKey;

    fn contract(byte: u8) -> ScAddress {
        ScAddress::Contract(ContractId(Hash([byte; 32])))
    }

    fn account() -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [0x48; 32],
        ))))
    }

    fn transfer(from: ScAddress, to: ScAddress) -> InvokeContractArgs {
        InvokeContractArgs {
            contract_address: contract(0x47),
            function_name: "transfer".try_into().unwrap(),
            args: vec![
                ScVal::Address(from),
                ScVal::Address(to),
                ScVal::I128(Int128Parts { hi: 0, lo: 30 }),
            ]
            .try_into()
            .unwrap(),
        }
    }

    #[test]
    fn a_transfer_from_the_wallet_is_a_token_transfer() {
        let wallet = contract(0x44);
        for to in [contract(0x48), account()] {
            let result = decompose_bundle_calls(&[transfer(wallet.clone(), to.clone())], &wallet);
            let InnerOpDescriptor::TokenTransfer {
                asset,
                from,
                to: recipient,
                amount,
            } = &result[0]
            else {
                panic!("wallet transfer must be valued");
            };
            assert_eq!(asset, &scaddress_to_strkey(&contract(0x47)).unwrap());
            assert_eq!(from, &scaddress_to_strkey(&wallet).unwrap());
            assert_eq!(recipient, &scaddress_to_strkey(&to).unwrap());
            assert_eq!(*amount, 30);
        }
    }

    #[test]
    fn a_transfer_from_another_address_is_not_valued() {
        for from in [account(), contract(0x45)] {
            let result = decompose_bundle_calls(&[transfer(from, contract(0x48))], &contract(0x44));
            assert!(matches!(result[0], InnerOpDescriptor::Generic { .. }));
        }
    }

    #[test]
    fn a_transfer_on_an_account_address_is_not_a_token_transfer() {
        let wallet = contract(0x44);
        let mut call = transfer(wallet.clone(), contract(0x48));
        call.contract_address = account();
        let result = decompose_bundle_calls(&[call], &wallet);
        let InnerOpDescriptor::Generic { target, fn_name } = &result[0] else {
            panic!("a transfer on an account address must not be valued");
        };
        assert_eq!(target, &scaddress_to_strkey(&account()).unwrap());
        assert_eq!(fn_name, "transfer");
    }

    #[test]
    fn string_arguments_are_not_a_transfer() {
        let mut call = transfer(contract(0x44), account());
        let address = ScVal::String(stellar_xdr::ScString(
            scaddress_to_strkey(&account()).unwrap().try_into().unwrap(),
        ));
        call.args = vec![
            address.clone(),
            address,
            ScVal::I128(Int128Parts { hi: 0, lo: 30 }),
        ]
        .try_into()
        .unwrap();
        assert!(matches!(
            decompose_bundle_calls(&[call], &contract(0x44))[0],
            InnerOpDescriptor::Generic { .. }
        ));
    }

    #[test]
    fn a_negative_or_misshaped_transfer_is_not_valued() {
        let wallet = contract(0x44);
        let call = transfer(wallet.clone(), account());
        let args = call.args.to_vec();
        let cases = [
            vec![
                args[0].clone(),
                args[1].clone(),
                ScVal::I128(Int128Parts {
                    hi: -1,
                    lo: u64::MAX,
                }),
            ],
            args[..2].to_vec(),
            vec![
                args[0].clone(),
                args[1].clone(),
                args[2].clone(),
                ScVal::Void,
            ],
            vec![args[0].clone(), args[1].clone(), ScVal::I64(30)],
        ];
        for args in cases {
            let mut malformed = call.clone();
            malformed.args = args.try_into().unwrap();
            assert!(matches!(
                decompose_bundle_calls(&[malformed], &wallet)[0],
                InnerOpDescriptor::Generic { .. }
            ));
        }
        let mut call = call;
        call.function_name = "transfer_from".try_into().unwrap();
        assert!(matches!(
            decompose_bundle_calls(&[call], &wallet)[0],
            InnerOpDescriptor::Generic { .. }
        ));
        assert!(decompose_bundle_calls(&[], &wallet).is_empty());
    }

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
}

//! Typed value descriptor consumed by the value-policy criteria.
//!
//! [`ValueClass`] describes what a tool call does to on-chain value. It is
//! DERIVED at the dispatch gate from the same authoritative source the tool
//! signs from — never from raw agent args that are not also signed (see the
//! design's derivation-point invariant). Value criteria read the typed
//! [`ValueLeg`]s out of [`crate::policy::v1::EvalContext::value`] rather than
//! pattern-matching hard-coded tool names against `args`.
//!
//! # Type reuse
//!
//! The `asset` and `destination` fields of [`ValueLeg`] are `String`, reusing
//! the representation the criteria already use: an asset is the canonical
//! policy asset id (`"native"` for XLM, or `"CODE:GISSUER"` for a classic
//! asset / a SAC C-strkey), and a destination is the raw G-/C-strkey (or a
//! home-domain string) the counterparty criteria already compare. No parallel
//! asset/counterparty value types are introduced; the canonical asset id is
//! produced by [`asset_normalise`], which is the single normalisation both the
//! derivation site and the criteria share so their comparisons cannot drift.

use serde_json::Value;

use crate::policy::v1::bundle::InnerOpDescriptor;
use crate::policy::v1::criteria::amount_extract::resolve_pay_or_create_account_stroops;

// ─────────────────────────────────────────────────────────────────────────────
// ValueClass
// ─────────────────────────────────────────────────────────────────────────────

/// What a tool call does to on-chain value.
///
/// Populated at the dispatch gate from the same bytes the tool signs. Value
/// criteria consult this instead of reading value fields out of `args` by
/// string key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueClass {
    /// Moves no on-chain value (reads, quotes, status, message-sign/verify,
    /// `get_*`). Value criteria are not-applicable by construction and return
    /// `Ok(None)`.
    ReadOnly,
    /// Moves value; the dispatch site resolved the concrete effect(s).
    Value(ValueEffects),
    /// Signs caller-supplied / opaque material whose value effect the dispatch
    /// site cannot resolve (sign arbitrary transaction / auth-entry XDR). Value
    /// criteria cannot size it.
    Opaque(OpaqueReason),
}

impl ValueClass {
    /// Constructs a [`ValueClass::Value`] from a single [`ValueLeg`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::value::{ActionKind, ValueClass, ValueLeg};
    ///
    /// let vc = ValueClass::single(ValueLeg {
    ///     kind: ActionKind::Payment,
    ///     amount: Some(1_000_000),
    ///     asset: Some("native".into()),
    ///     destination: Some("GAAA".into()),
    /// });
    /// assert!(matches!(vc, ValueClass::Value(_)));
    /// ```
    #[must_use]
    pub fn single(leg: ValueLeg) -> Self {
        Self::Value(ValueEffects::single(leg))
    }

    /// Returns the sole value leg when this is a [`ValueClass::Value`] carrying
    /// exactly one leg; `None` otherwise (`ReadOnly`, `Opaque`, or a
    /// multi-leg effect).
    ///
    /// Single-shot classic tools (`stellar_pay` / `stellar_create_account`)
    /// carry exactly one leg; their value criteria read it through this
    /// accessor. Multi-leg effects (Blend / vault) are aggregated per-asset by
    /// the criteria that consume them and do not use this accessor.
    #[must_use]
    pub fn sole_value_leg(&self) -> Option<&ValueLeg> {
        match self {
            Self::Value(effects) if effects.legs.len() == 1 => effects.legs.first(),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValueEffects
// ─────────────────────────────────────────────────────────────────────────────

/// The concrete value effect(s) of a single tool call.
///
/// One tool call may move value on several legs (a Blend `lend` carries a
/// `Vec<BlendRequest>`; a vault deposit carries `Vec<amounts_desired>` per
/// asset). Value criteria aggregate per-asset across legs.
///
/// # Invariant
///
/// `legs` is non-empty whenever a [`ValueEffects`] is wrapped in
/// [`ValueClass::Value`]. A value-moving call always has at least one leg; an
/// empty [`ValueEffects`] is a construction bug. Use [`ValueEffects::single`]
/// or [`ValueEffects::new`], which document and (in debug builds) assert the
/// invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueEffects {
    /// The per-leg effects. Non-empty for a [`ValueClass::Value`].
    pub legs: Vec<ValueLeg>,
}

impl ValueEffects {
    /// Constructs a [`ValueEffects`] from a non-empty leg vector.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `legs` is non-empty. In release builds an empty
    /// vector is accepted structurally, but the non-empty invariant is part of
    /// the type's contract and callers must uphold it.
    #[must_use]
    pub fn new(legs: Vec<ValueLeg>) -> Self {
        debug_assert!(
            !legs.is_empty(),
            "ValueEffects must carry at least one leg for a value-moving call"
        );
        Self { legs }
    }

    /// Constructs a single-leg [`ValueEffects`].
    #[must_use]
    pub fn single(leg: ValueLeg) -> Self {
        Self { legs: vec![leg] }
    }

    /// Returns the legs.
    #[must_use]
    pub fn legs(&self) -> &[ValueLeg] {
        &self.legs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValueLeg
// ─────────────────────────────────────────────────────────────────────────────

/// One value-moving leg of a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueLeg {
    /// The kind of on-chain action this leg performs.
    pub kind: ActionKind,
    /// The debit amount in stroops / raw SAC units.
    ///
    /// `None` only for kinds that move no debit (e.g. an inbound `Claim`), or
    /// when the dispatch site could not resolve the amount. Held as `i128`
    /// internally; the decimal-string wire encoding is used only at the wire
    /// boundary.
    pub amount: Option<i128>,
    /// The canonical policy asset id: `"native"` for XLM, or `"CODE:GISSUER"`
    /// / a SAC C-strkey for a non-native asset. Produced by [`asset_normalise`].
    pub asset: Option<String>,
    /// The counterparty this leg moves value to: a raw G-/C-strkey, or a
    /// home-domain string, matching what the counterparty criteria compare.
    pub destination: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ActionKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of on-chain action a [`ValueLeg`] performs.
///
/// `#[non_exhaustive]`: new kinds are added as tools are migrated onto the
/// descriptor. Consumers match with a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    /// A classic payment (`stellar_pay`).
    Payment,
    /// A create-account operation (`stellar_create_account`).
    AccountCreation,
    /// Claiming a claimable balance (inbound; typically no debit leg).
    Claim,
    /// A change-trust (trustline) operation.
    Trustline,
    /// A DEX path-payment / manage-offer trade.
    DexTrade,
    /// A Blend lending deposit / borrow.
    Lend,
    /// A vault deposit.
    VaultDeposit,
    /// A vault withdrawal.
    VaultWithdraw,
    /// An x402 payment.
    X402Payment,
    /// A metered pay-per-call (MPP) charge.
    MppCharge,
    /// A generic Soroban contract invocation that moves value.
    ContractInvoke,
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueReason
// ─────────────────────────────────────────────────────────────────────────────

/// Why a tool call's value effect cannot be resolved by the dispatch site.
///
/// `#[non_exhaustive]`: new opaque-signing shapes may be added.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueReason {
    /// The tool signs a caller-supplied transaction envelope whose value
    /// effect the wallet does not decode (`sep43_sign_transaction`,
    /// `sep43_sign_and_submit_transaction`).
    RawTransactionSignature,
    /// The tool signs a caller-supplied Soroban authorization entry
    /// (`sep43_sign_auth_entry`).
    RawAuthEntrySignature,
}

// ─────────────────────────────────────────────────────────────────────────────
// asset_normalise
// ─────────────────────────────────────────────────────────────────────────────

/// Normalises an asset identifier to the canonical policy asset id.
///
/// Maps `"native"` / `"XLM"` (case-insensitively) to `"native"`; leaves a
/// non-native `"CODE:GISSUER"` (or a SAC C-strkey) verbatim so allowlist and
/// cap matching compares byte-for-byte. This is the single normalisation
/// shared by the descriptor derivation and the value criteria; keeping one
/// implementation is what makes the derived asset comparable to the
/// criterion-configured asset.
#[must_use]
pub fn asset_normalise(asset: &str) -> String {
    if asset.eq_ignore_ascii_case("native") || asset.eq_ignore_ascii_case("xlm") {
        "native".to_owned()
    } else {
        asset.to_owned()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// derive_value_class
// ─────────────────────────────────────────────────────────────────────────────

/// Derives a [`ValueClass`] for a tool call from `(tool_name, args)`.
///
/// This is the single derivation point for the two already-covered tools
/// (`stellar_pay` / `stellar_create_account`, and their two-phase `_commit`
/// twins). The amount is resolved from the SAME resolved-key logic the value
/// criteria already use ([`resolve_pay_or_create_account_stroops`]); when the
/// engine is called on the commit path, `args` is the HMAC-bound
/// `authoritative_args`, so the derived leg is transitively bound to the signed
/// envelope.
///
/// A present-but-unparseable amount is resolved to `None` here (rather than a
/// hard error) so the derivation stays infallible and does not fire an error
/// for rules that carry no value criterion. The value criteria treat a
/// pay/create leg with `amount == None` as unresolvable and deny/error exactly
/// as the args-read path does today.
///
/// Every other tool derives [`ValueClass::ReadOnly`] in this step; the
/// per-tool `MovesValue` / `OpaqueSign` classification of the remaining tools
/// is wired in a later migration step.
#[must_use]
pub fn derive_value_class(tool_name: &str, args: &Value) -> ValueClass {
    match tool_name {
        "stellar_pay" | "stellar_pay_commit" => {
            let amount = resolve_pay_or_create_account_stroops(tool_name, args, "derive")
                .ok()
                .flatten()
                .map(i128::from);
            let asset = args
                .get("asset")
                .and_then(Value::as_str)
                .map(asset_normalise);
            let destination = args
                .get("destination")
                .and_then(Value::as_str)
                .map(str::to_owned);
            ValueClass::single(ValueLeg {
                kind: ActionKind::Payment,
                amount,
                asset,
                destination,
            })
        }
        "stellar_create_account" | "stellar_create_account_commit" => {
            let amount = resolve_pay_or_create_account_stroops(tool_name, args, "derive")
                .ok()
                .flatten()
                .map(i128::from);
            let destination = args
                .get("destination")
                .and_then(Value::as_str)
                .map(str::to_owned);
            ValueClass::single(ValueLeg {
                kind: ActionKind::AccountCreation,
                amount,
                asset: Some("native".to_owned()),
                destination,
            })
        }
        _ => ValueClass::ReadOnly,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// value_class_for_inner
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a decomposed multicall inner descriptor to its [`ValueClass`].
///
/// A recognised [`InnerOpDescriptor::TokenTransfer`] maps to a single-leg
/// value effect (SAC contract as the asset, the transfer `to` as the
/// destination). An [`InnerOpDescriptor::Generic`] maps to
/// [`ValueClass::ReadOnly`] on the value axis: it contributes nothing to
/// value caps (matching the existing per-inner zero-contribution for Generic),
/// and Generic-inner policing stays with the dedicated
/// `restrict_bundle_to_recognised_kinds` criterion. Mapping Generic to a leg
/// with `amount == None` would wrongly trip the fail-closed `None`-is-deny
/// rule and over-deny any bundle containing a Generic inner.
#[must_use]
pub fn value_class_for_inner(inner: &InnerOpDescriptor) -> ValueClass {
    match inner {
        InnerOpDescriptor::TokenTransfer {
            asset, to, amount, ..
        } => ValueClass::single(ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(*amount),
            asset: Some(asset_normalise(asset)),
            destination: Some(to.clone()),
        }),
        _ => ValueClass::ReadOnly,
    }
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

    #[test]
    fn read_only_and_value_and_opaque_construct_and_compare() {
        let leg = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(100),
            asset: Some("native".into()),
            destination: Some("GAAA".into()),
        };
        let a = ValueClass::single(leg.clone());
        let b = ValueClass::Value(ValueEffects::new(vec![leg]));
        assert_eq!(a, b);
        assert_ne!(a, ValueClass::ReadOnly);
        assert_ne!(
            ValueClass::Opaque(OpaqueReason::RawTransactionSignature),
            ValueClass::Opaque(OpaqueReason::RawAuthEntrySignature)
        );
    }

    #[test]
    fn value_effects_single_has_exactly_one_leg() {
        let effects = ValueEffects::single(ValueLeg {
            kind: ActionKind::AccountCreation,
            amount: Some(50),
            asset: Some("native".into()),
            destination: None,
        });
        assert_eq!(effects.legs().len(), 1);
        assert_eq!(effects.legs()[0].kind, ActionKind::AccountCreation);
    }

    #[test]
    fn asset_normalise_maps_native_and_xlm_but_preserves_non_native() {
        assert_eq!(asset_normalise("native"), "native");
        assert_eq!(asset_normalise("XLM"), "native");
        assert_eq!(asset_normalise("xlm"), "native");
        let usdc = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        assert_eq!(asset_normalise(usdc), usdc);
    }

    #[test]
    fn derive_pay_builds_payment_leg_from_authoritative_args() {
        let args = json!({
            "amount_stroops": "1500000000",
            "asset": "native",
            "destination": "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
        });
        let vc = derive_value_class("stellar_pay", &args);
        let ValueClass::Value(effects) = vc else {
            panic!("expected Value, got {vc:?}");
        };
        assert_eq!(effects.legs().len(), 1);
        let leg = &effects.legs()[0];
        assert_eq!(leg.kind, ActionKind::Payment);
        assert_eq!(leg.amount, Some(1_500_000_000_i128));
        assert_eq!(leg.asset.as_deref(), Some("native"));
        assert_eq!(
            leg.destination.as_deref(),
            Some("GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL")
        );
    }

    #[test]
    fn derive_pay_commit_reads_authoritative_args_shape() {
        let args = json!({
            "source": "GAAA",
            "destination": "GBBB",
            "amount_stroops": "500000000",
            "asset": "XLM",
        });
        let vc = derive_value_class("stellar_pay_commit", &args);
        let ValueClass::Value(effects) = vc else {
            panic!("expected Value");
        };
        let leg = &effects.legs()[0];
        assert_eq!(leg.amount, Some(500_000_000_i128));
        // "XLM" normalises to the canonical "native".
        assert_eq!(leg.asset.as_deref(), Some("native"));
    }

    #[test]
    fn derive_create_account_builds_native_account_creation_leg() {
        let args = json!({
            "starting_balance_stroops": "50000000",
            "destination": "GBBB",
        });
        let vc = derive_value_class("stellar_create_account", &args);
        let ValueClass::Value(effects) = vc else {
            panic!("expected Value");
        };
        let leg = &effects.legs()[0];
        assert_eq!(leg.kind, ActionKind::AccountCreation);
        assert_eq!(leg.amount, Some(50_000_000_i128));
        assert_eq!(leg.asset.as_deref(), Some("native"));
        assert_eq!(leg.destination.as_deref(), Some("GBBB"));
    }

    #[test]
    fn derive_pay_with_malformed_amount_yields_none_amount_leg() {
        let args = json!({ "amount_stroops": "not-a-number", "asset": "native" });
        let vc = derive_value_class("stellar_pay", &args);
        let ValueClass::Value(effects) = vc else {
            panic!("expected Value");
        };
        // Malformed amount collapses to None; the criterion treats a pay/create
        // leg with amount None as unresolvable (error), matching the args path.
        assert_eq!(effects.legs()[0].amount, None);
    }

    #[test]
    fn derive_unknown_tool_is_read_only() {
        let args = json!({ "any": "thing" });
        assert_eq!(
            derive_value_class("stellar_balances", &args),
            ValueClass::ReadOnly
        );
    }

    #[test]
    fn inner_token_transfer_maps_to_payment_leg() {
        let inner = InnerOpDescriptor::TokenTransfer {
            asset: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA".into(),
            from: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".into(),
            to: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".into(),
            amount: 1_000_000_000,
        };
        let ValueClass::Value(effects) = value_class_for_inner(&inner) else {
            panic!("token transfer must map to a value leg");
        };
        let leg = &effects.legs()[0];
        assert_eq!(leg.kind, ActionKind::Payment);
        assert_eq!(leg.amount, Some(1_000_000_000_i128));
        assert_eq!(
            leg.asset.as_deref(),
            Some("CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA")
        );
        assert_eq!(
            leg.destination.as_deref(),
            Some("GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL")
        );
    }

    #[test]
    fn inner_generic_maps_to_read_only() {
        // A Generic inner must NOT become a leg with amount None (which would
        // trip the fail-closed None-is-deny rule and over-deny bundles); it maps
        // to ReadOnly on the value axis.
        let inner = InnerOpDescriptor::Generic {
            target: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA".into(),
            fn_name: "do_something".into(),
        };
        assert_eq!(value_class_for_inner(&inner), ValueClass::ReadOnly);
    }
}

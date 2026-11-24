//! Destination-specific memo requirements.
//!
//! [`MemoBindingCriterion`] requires a payment to a bound destination to carry
//! a memo of the bound kind and value, as an exchange deposit address requires
//! its customer memo:
//!
//! ```toml
//! { kind = "memo_binding", bindings = [
//!     { destination = "GABC...", kind = "id", value = "123456" },
//!     { destination = "GXYZ...", kind = "any" },
//! ] }
//! ```
//!
//! A criterion carries 1 to 64 bindings with distinct G-strkey destinations.
//! `kind` is `text`, `id`, `hash`, `return`, or `any`. `value` is required for
//! every kind except `any`, which refuses it. A text value is UTF-8 of at most
//! 28 bytes, and an id value a `u64` decimal without sign or leading zero. A
//! hash or return value is 64 lowercase hex digits. `any` accepts every memo
//! except none.
//!
//! A debit leg to a bound destination, or to a muxed address whose base
//! account is bound, needs the bound memo; the memo fact is
//! [`crate::policy::v1::ValueEffects::memo`]. An absent fact and
//! [`ClassicMemo::None`] both refuse with
//! [`DenyReason::MemoBindingMismatch`], which names the required kind only.
//! Unbound and contract destinations pass.

use stellar_strkey::{
    Contract,
    ed25519::{MuxedAccount, PublicKey},
};

use crate::envelope_decode::ClassicMemo;
use crate::hex::decode_hex32;
use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::value::{ValueGate, classify_value};
use crate::policy::{DenyReason, PolicyError};

/// The most bindings one criterion accepts.
pub const MAX_MEMO_BINDINGS: usize = 64;

/// The most bytes a text memo carries.
pub const MAX_TEXT_MEMO_BYTES: usize = 28;

/// The memo a bound destination requires.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoRequirement {
    /// A text memo with exactly this text.
    Text(String),
    /// An id memo with exactly this id.
    Id(u64),
    /// A hash memo with exactly these bytes.
    Hash([u8; 32]),
    /// A return memo with exactly these bytes.
    Return([u8; 32]),
    /// Any memo other than none.
    Any,
}

impl MemoRequirement {
    /// Parses a binding's `kind` and optional `value`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret description of the first violated rule. The value
    /// itself never appears in it.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::memo_binding::MemoRequirement;
    ///
    /// assert_eq!(MemoRequirement::parse("id", Some("42")).unwrap(), MemoRequirement::Id(42));
    /// assert!(MemoRequirement::parse("id", Some("042")).is_err());
    /// assert!(MemoRequirement::parse("any", Some("x")).is_err());
    /// ```
    pub fn parse(kind: &str, value: Option<&str>) -> Result<Self, &'static str> {
        match (kind, value) {
            ("any", None) => Ok(Self::Any),
            ("any", Some(_)) => Err("`value` is not accepted with kind `any`"),
            ("text" | "id" | "hash" | "return", None) => Err("`value` is required for this kind"),
            ("text", Some(text)) => {
                if text.len() > MAX_TEXT_MEMO_BYTES {
                    Err("a text `value` holds at most 28 bytes of UTF-8")
                } else {
                    Ok(Self::Text(text.to_owned()))
                }
            }
            ("id", Some(id)) => parse_memo_id(id).map(Self::Id),
            ("hash", Some(hex)) => parse_hash(hex).map(Self::Hash),
            ("return", Some(hex)) => parse_hash(hex).map(Self::Return),
            _ => Err("`kind` must be text, id, hash, return, or any"),
        }
    }

    /// Returns the kind label: `text`, `id`, `hash`, `return`, or `any`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Id(_) => "id",
            Self::Hash(_) => "hash",
            Self::Return(_) => "return",
            Self::Any => "any",
        }
    }

    /// Whether `memo` meets the requirement. The kind and the value must both
    /// match; `any` admits every memo except none.
    #[must_use]
    pub fn is_met_by(&self, memo: &ClassicMemo) -> bool {
        match (self, memo) {
            (_, ClassicMemo::None) => false,
            (Self::Any, _) => true,
            (Self::Text(required), ClassicMemo::Text(text)) => required == text,
            (Self::Id(required), ClassicMemo::Id(id)) => required == id,
            (Self::Hash(required), ClassicMemo::Hash(hash)) => required == hash,
            (Self::Return(required), ClassicMemo::Return(hash)) => required == hash,
            _ => false,
        }
    }
}

/// Parses a `u64` decimal without sign or leading zero.
fn parse_memo_id(id: &str) -> Result<u64, &'static str> {
    let canonical = !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_digit())
        && (id == "0" || !id.starts_with('0'));
    if !canonical {
        return Err("an id `value` is a decimal without sign or leading zero");
    }
    id.parse::<u64>()
        .map_err(|_| "an id `value` must fit in an unsigned 64-bit integer")
}

/// Parses 64 lowercase hex digits. Uppercase digits are refused, so one value
/// has one spelling in the signed policy.
fn parse_hash(hex: &str) -> Result<[u8; 32], &'static str> {
    const DETAIL: &str = "a hash or return `value` is 64 lowercase hex digits";
    if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(DETAIL);
    }
    decode_hex32(hex).map_err(|_| DETAIL)
}

/// One bound destination and the memo it requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoBinding {
    destination: String,
    requirement: MemoRequirement,
}

impl MemoBinding {
    /// Binds the G-strkey `destination` to `requirement`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret description when `destination` is not a G-strkey;
    /// a muxed or contract address is refused.
    pub fn new(destination: &str, requirement: MemoRequirement) -> Result<Self, &'static str> {
        PublicKey::from_string(destination)
            .map_err(|_| "`destination` must be a G-strkey; M and C addresses are refused")?;
        Ok(Self {
            destination: destination.to_owned(),
            requirement,
        })
    }

    /// Returns the bound G-strkey.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// Returns the required memo.
    #[must_use]
    pub fn requirement(&self) -> &MemoRequirement {
        &self.requirement
    }
}

/// Requires the bound memo on every debit leg to a bound destination.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::Criterion;
/// use stellar_agent_core::policy::v1::criteria::memo_binding::{
///     MemoBinding, MemoBindingCriterion, MemoRequirement,
/// };
///
/// let binding = MemoBinding::new(
///     "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
///     MemoRequirement::Id(7),
/// )
/// .unwrap();
/// let criterion = MemoBindingCriterion::new(vec![binding]);
/// assert_eq!(criterion.kind(), "memo_binding");
/// ```
#[derive(Debug, Clone)]
pub struct MemoBindingCriterion {
    bindings: Vec<MemoBinding>,
}

impl MemoBindingCriterion {
    /// Constructs the criterion from validated bindings.
    #[must_use]
    pub fn new(bindings: Vec<MemoBinding>) -> Self {
        Self { bindings }
    }

    /// Returns the bindings.
    #[must_use]
    pub fn bindings(&self) -> &[MemoBinding] {
        &self.bindings
    }
}

impl Criterion for MemoBindingCriterion {
    fn kind(&self) -> &'static str {
        "memo_binding"
    }

    /// Refuses with [`DenyReason::MemoBindingMismatch`] when a debit leg to a
    /// bound destination lacks the bound memo.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when a debit leg's
    /// destination is missing or is not a G, M, or C strkey.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let effects = match classify_value(ctx) {
            ValueGate::NotApplicable => return Ok(None),
            ValueGate::Deny(reason) => return Ok(Some(reason)),
            ValueGate::Effects(effects) => effects,
        };
        for leg in effects.legs() {
            if !leg.kind.carries_debit() {
                continue;
            }
            let destination = leg.destination.as_deref().ok_or_else(|| {
                PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "memo_binding: a debit leg of tool '{}' carries no destination",
                        ctx.tool.name
                    ),
                }
            })?;
            let base = if PublicKey::from_string(destination).is_ok() {
                destination.to_owned()
            } else if let Ok(muxed) = MuxedAccount::from_string(destination) {
                format!("{}", PublicKey(muxed.ed25519))
            } else if Contract::from_string(destination).is_ok() {
                continue;
            } else {
                return Err(PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "memo_binding: a debit leg of tool '{}' carries a destination that is \
                         not a G, M, or C strkey",
                        ctx.tool.name
                    ),
                });
            };
            let Some(binding) = self.bindings.iter().find(|b| b.destination == base) else {
                continue;
            };
            let met = effects
                .memo()
                .is_some_and(|memo| binding.requirement.is_met_by(memo));
            if !met {
                return Ok(Some(DenyReason::MemoBindingMismatch {
                    kind: binding.requirement.kind().to_owned(),
                }));
            }
        }
        Ok(None)
    }
}

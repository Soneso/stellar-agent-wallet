//! Capability taxonomy and capability-set types.
//!
//! A [`Capability`] is a typed wallet operation a toolset may request access to.
//! A [`CapabilitySet`] is the de-duplicated set of capabilities parsed from the
//! `stellar-agent-capabilities` metadata key.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ToolsetFormatError;

/// The reserved metadata key that carries the capability manifest.
pub(crate) const CAPABILITY_KEY: &str = "stellar-agent-capabilities";

/// The reserved metadata key prefix for wallet-internal extensions.
pub(crate) const RESERVED_PREFIX: &str = "stellar-agent-";

/// The explicitly-forbidden capability token.
pub(crate) const SIGN_TRANSACTION_TOKEN: &str = "sign-transaction";

/// The `sign-payment` capability token.
///
/// Distinguished from the forbidden bare `sign-transaction` token: this token
/// is DECLARABLE by a toolset.  Declaring it confers NOTHING at parse or install
/// time — the capability is INERT until the wallet's first-invoke gate converts
/// it into a runtime grant.
pub(crate) const SIGN_PAYMENT_TOKEN: &str = "sign-payment";

/// The `sign-rule-create` capability token (Package D, GH issue #8).
///
/// Same inert-at-declaration posture as [`SIGN_PAYMENT_TOKEN`]: declaring it
/// confers nothing until the first-invoke gate converts it into a runtime
/// grant. Gates `stellar_rule_create_commit` — installing an agent-proposed
/// context rule on-chain.
pub(crate) const SIGN_RULE_CREATE_TOKEN: &str = "sign-rule-create";

/// A wallet capability that a toolset may declare in its manifest.
///
/// `#[non_exhaustive]` so that future releases can add capability kinds without
/// a breaking change to downstream consumers that match on the enum.
///
/// There is deliberately **no** `SignTransaction` variant.  Signing is not
/// grantable as a flat capability — the `sign-transaction` token in a manifest
/// is refused with [`ToolsetFormatError::BareSignTransactionForbidden`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Read the account balance of the agent's configured account.
    ///
    /// Maps to the `read-balance` token.
    ReadBalance,

    /// Propose a transaction for user review (but not sign or submit it).
    ///
    /// Maps to the `propose-transaction` token.
    ProposeTransaction,

    /// Suggest a destination address for a payment.
    ///
    /// Maps to the `suggest-destination` token.
    SuggestDestination,

    /// Observe a ledger event (streaming / webhook subscription).
    ///
    /// Maps to the `observe-event` token.
    ObserveEvent,

    /// Sign and submit a classic payment transaction (signing-adjacent; gated).
    ///
    /// Maps to the `sign-payment` token.
    ///
    /// # Inert at declaration
    ///
    /// Declaring `sign-payment` in a toolset manifest confers NOTHING at parse
    /// time or install time — unlike the ungated capabilities above, which
    /// immediately grant their matrix tool at dispatch.  This capability is
    /// INERT until the wallet's first-invoke gate queues an out-of-band user
    /// approval and, after the operator approves, converts it into a runtime
    /// grant stored in the grant store.
    ///
    /// The first-invoke gate fires on every invocation where no current,
    /// matching grant exists (first call, expired grant, novel destination /
    /// asset / amount-bucket).
    ///
    /// Even with a current grant, the per-action payment approval fires
    /// unconditionally for every toolset-routed payment.  `sign-payment` NEVER
    /// replaces per-action approval; it is an additive first-invoke consent
    /// layered before it.
    SignPayment,

    /// Read the agent's own context rules (spending-limit budgets, expiry,
    /// signer/policy counts) via the read-only rules-observability tools.
    ///
    /// Maps to the `read-rules` token. Separately grantable from
    /// `read-balance`: rule visibility and balance visibility are distinct
    /// concerns, so a toolset must request each independently.
    ReadRules,

    /// Install an agent-proposed context rule on-chain (signing-adjacent;
    /// gated).
    ///
    /// Maps to the `sign-rule-create` token.
    ///
    /// # Inert at declaration
    ///
    /// Same posture as [`Capability::SignPayment`]: declaring `sign-rule-create`
    /// confers NOTHING at parse or install time. This capability is INERT
    /// until the wallet's first-invoke gate queues an out-of-band operator
    /// approval and, after the operator approves, converts it into a
    /// runtime grant.
    ///
    /// Even with a current grant, the per-proposal `RuleProposalSimulated`
    /// attestation fires unconditionally for every toolset-routed
    /// `stellar_rule_create_commit` call. `sign-rule-create` NEVER replaces
    /// that per-action approval; it is an additive first-invoke consent
    /// layered before it — same relationship `sign-payment` has to the
    /// per-action `PaymentSimulated` approval.
    SignRuleCreate,
}

impl Capability {
    /// Returns `true` if this capability involves access to the agent's signing
    /// key (either for signing or key-derivation purposes).
    ///
    /// This predicate is the single source of truth for the install-time
    /// attestation gate.  The gate calls this function and NEVER matches the
    /// capability variant directly, so that a future key-touching capability
    /// forces a compile error here until classified.
    ///
    /// The explicit `match` with NO wildcard arm (`_ =>`) ensures that every
    /// future variant addition requires a conscious classification decision —
    /// a compile error here is intentional, not accidental.  Any future
    /// key-touching capability (such as a key-derivation variant) must be
    /// classified as `true` when added.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_toolsets::Capability;
    ///
    /// assert!(Capability::SignPayment.is_key_touching());
    /// assert!(!Capability::ReadBalance.is_key_touching());
    /// assert!(!Capability::ProposeTransaction.is_key_touching());
    /// assert!(!Capability::SuggestDestination.is_key_touching());
    /// assert!(!Capability::ObserveEvent.is_key_touching());
    /// ```
    #[must_use]
    pub fn is_key_touching(self) -> bool {
        // IMPORTANT: NO wildcard arm (`_ =>`).  Every variant must be explicitly
        // classified.  Adding a new `Capability` variant without updating this
        // match is a compile error, which is the desired forcing function for
        // the attestation gate.
        match self {
            Self::ReadBalance => false,
            Self::ProposeTransaction => false,
            Self::SuggestDestination => false,
            Self::ObserveEvent => false,
            Self::SignPayment => true,
            Self::ReadRules => false,
            Self::SignRuleCreate => true,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadBalance => f.write_str("read-balance"),
            Self::ProposeTransaction => f.write_str("propose-transaction"),
            Self::SuggestDestination => f.write_str("suggest-destination"),
            Self::ObserveEvent => f.write_str("observe-event"),
            Self::SignPayment => f.write_str("sign-payment"),
            Self::ReadRules => f.write_str("read-rules"),
            Self::SignRuleCreate => f.write_str("sign-rule-create"),
        }
    }
}

/// The de-duplicated set of capabilities declared by a toolset.
///
/// An empty set is valid — a toolset that declares no capabilities will be
/// refused access to every gated wallet operation at dispatch time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    /// Construct an empty `CapabilitySet`.
    #[must_use]
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Returns `true` if the set contains no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of distinct capabilities in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the set contains `cap`.
    #[must_use]
    pub fn contains(&self, cap: Capability) -> bool {
        self.0.contains(&cap)
    }

    /// Returns an iterator over the capabilities in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.0.iter().copied()
    }
}

impl IntoIterator for CapabilitySet {
    type Item = Capability;
    type IntoIter = std::collections::btree_set::IntoIter<Capability>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// ── Serde impls for Capability and CapabilitySet ──────────────────────────────
//
// CapabilitySet serialises as a JSON array of display-token strings
// (e.g. ["read-balance","propose-transaction"]) — human-readable and
// forward-compatible with the #[non_exhaustive] rule.
//
// Deserialise semantics:
//
// - Routes each token through the canonical `match_capability_token` (the same
//   function used by `parse_capability_value`), so the deserialiser and the
//   parser cannot drift.
// - `Ok(cap)` → insert into the set.
// - `Err(ToolsetFormatError::UnknownCapability)` → silently skipped (forward-compat:
//   a capability added in a future version of the binary should not break an
//   existing stored record that was written with that capability).
// - `Err(ToolsetFormatError::BareSignTransactionForbidden)` → serde deserialize error.
//   A stored record that declares "sign-transaction" is structurally malformed;
//   we reject the entire deserialise rather than silently dropping the token,
//   which would mask a corrupt or tampered record.
// - Other errors → serde deserialize error (e.g. invalid-charset tokens that should
//   never appear in a well-formed record but may appear in a tampered one).

impl Serialize for CapabilitySet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for cap in &self.0 {
            seq.serialize_element(&cap.to_string())?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct CapSetVisitor;

        impl<'de> de::Visitor<'de> for CapSetVisitor {
            type Value = CapabilitySet;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of capability token strings")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut set = BTreeSet::new();
                while let Some(token) = seq.next_element::<String>()? {
                    // Route through the canonical token matcher so the
                    // deserialiser and the parser cannot drift.
                    //
                    // Only charset-valid tokens reach match_capability_token; a
                    // token stored in a record that contains characters outside
                    // [a-z0-9-] is rejected below.
                    if !token.chars().all(is_valid_token_char) {
                        // A tampered or malformed record contains an invalid-charset
                        // token.  Reject the entire deserialise.
                        return Err(de::Error::custom(format!(
                            "capability token '{token}' contains characters outside [a-z0-9-]"
                        )));
                    }

                    match match_capability_token(&token) {
                        Ok(cap) => {
                            set.insert(cap);
                        }
                        Err(ToolsetFormatError::UnknownCapability { .. }) => {
                            // Forward-compat: a capability added in a future binary
                            // version was stored in this record; ignore it so the
                            // record remains loadable on an older binary.
                        }
                        Err(ToolsetFormatError::BareSignTransactionForbidden) => {
                            // A record declaring "sign-transaction" is structurally
                            // malformed.  Reject the entire deserialise — do NOT
                            // silently drop.  This surfaces corrupt or tampered records.
                            return Err(de::Error::custom(
                                "capability token 'sign-transaction' is forbidden in a \
                                 stored record; the record is structurally malformed",
                            ));
                        }
                        Err(other) => {
                            // Any other parse error (should not occur given the charset
                            // gate above, but handled for robustness).
                            return Err(de::Error::custom(format!(
                                "invalid capability token '{token}': {other}"
                            )));
                        }
                    }
                }
                Ok(CapabilitySet(set))
            }
        }

        d.deserialize_seq(CapSetVisitor)
    }
}

/// Parse the `stellar-agent-capabilities` metadata value into a [`CapabilitySet`].
///
/// # Public test-helper
///
/// This function is `pub(crate)` for internal use; a thin public re-export
/// `parse_capability_value_pub` is exposed under `#[cfg(any(test, feature = "test-helpers"))]`
/// so tests in sibling crates can build `CapabilitySet` values without
/// duplicating the parse logic.
///
/// See [`parse_capability_value_pub`].
///
/// ## Algorithm
///
/// 1. Tokenise on ASCII whitespace, dropping empty tokens.
/// 2. For each token apply the charset gate: characters outside `[a-z0-9-]` →
///    [`ToolsetFormatError::CapabilityTokenInvalidChar`].  This gate is applied
///    BEFORE name-matching so that no casing variant of a recognised or forbidden
///    token can reach the matching step.
/// 3. After the charset gate, the token is guaranteed `[a-z0-9-]`:
///    - `sign-transaction` → [`ToolsetFormatError::BareSignTransactionForbidden`].
///    - A recognised taxonomy token → its [`Capability`].
///    - Any other token → [`ToolsetFormatError::UnknownCapability`].
/// 4. Duplicate tokens in the value deduplicate (a token appearing twice does
///    not cause an error — only duplicate mapping KEYS cause an error).
///
/// # Errors
///
/// Returns the first error encountered in token order.
///
/// - [`ToolsetFormatError::CapabilityTokenInvalidChar`] — a token with a character
///   outside `[a-z0-9-]` (catches uppercase, underscores, unicode homoglyphs,
///   whitespace-internal, control characters).
/// - [`ToolsetFormatError::BareSignTransactionForbidden`] — the token
///   `sign-transaction` appears in the manifest.
/// - [`ToolsetFormatError::UnknownCapability`] — a `[a-z0-9-]` token that is not in
///   the recognised taxonomy.
pub(crate) fn parse_capability_value(value: &str) -> Result<CapabilitySet, ToolsetFormatError> {
    let mut set = BTreeSet::new();

    for token in value.split_ascii_whitespace() {
        // Step 2: charset gate — must be [a-z0-9-] only.
        if !token.chars().all(is_valid_token_char) {
            return Err(ToolsetFormatError::CapabilityTokenInvalidChar {
                token: token.to_owned(),
            });
        }

        // Step 3: name-match within [a-z0-9-] tokens.
        let cap = match_capability_token(token)?;
        set.insert(cap);
    }

    Ok(CapabilitySet(set))
}

/// Returns `true` if `ch` is in the valid token charset `[a-z0-9-]`.
///
/// This is a named predicate so the charset definition lives in one place and is
/// shared with the `name` field validator in [`crate::parse`].
#[inline]
pub(crate) fn is_valid_token_char(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'
}

/// Public test-helper for `parse_capability_value`.
///
/// Exposed under `#[cfg(any(test, feature = "test-helpers"))]` so sibling
/// crates can build `CapabilitySet` values in tests without reimplementing
/// the parse logic.
///
/// This function has the same behaviour as the internal `parse_capability_value`.
///
/// # Errors
///
/// Same as `parse_capability_value`.
#[cfg(any(test, feature = "test-helpers"))]
pub fn parse_capability_value_pub(value: &str) -> Result<CapabilitySet, ToolsetFormatError> {
    parse_capability_value(value)
}

/// Match a token that has already passed the charset gate to a [`Capability`].
///
/// # Errors
///
/// - [`ToolsetFormatError::BareSignTransactionForbidden`] if `token == "sign-transaction"`.
/// - [`ToolsetFormatError::UnknownCapability`] if the token is not in the taxonomy.
fn match_capability_token(token: &str) -> Result<Capability, ToolsetFormatError> {
    match token {
        SIGN_TRANSACTION_TOKEN => Err(ToolsetFormatError::BareSignTransactionForbidden),
        "read-balance" => Ok(Capability::ReadBalance),
        "propose-transaction" => Ok(Capability::ProposeTransaction),
        "suggest-destination" => Ok(Capability::SuggestDestination),
        "observe-event" => Ok(Capability::ObserveEvent),
        // sign-payment is declarable but INERT at parse/install time.
        // The first-invoke gate is the sole admission control for this code path.
        SIGN_PAYMENT_TOKEN => Ok(Capability::SignPayment),
        "read-rules" => Ok(Capability::ReadRules),
        // sign-rule-create is declarable but INERT at parse/install time.
        // The first-invoke gate is the sole admission control for this code path.
        SIGN_RULE_CREATE_TOKEN => Ok(Capability::SignRuleCreate),
        other => Err(ToolsetFormatError::UnknownCapability {
            token: other.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn empty_value_yields_empty_set() {
        assert!(parse_capability_value("").unwrap().is_empty());
    }

    #[test]
    fn whitespace_only_yields_empty_set() {
        assert!(parse_capability_value("   \t  ").unwrap().is_empty());
    }

    #[test]
    fn all_taxonomy_tokens_parse() {
        let set = parse_capability_value(
            "read-balance propose-transaction suggest-destination observe-event sign-payment",
        )
        .unwrap();
        assert!(set.contains(Capability::ReadBalance));
        assert!(set.contains(Capability::ProposeTransaction));
        assert!(set.contains(Capability::SuggestDestination));
        assert!(set.contains(Capability::ObserveEvent));
        assert!(set.contains(Capability::SignPayment));
        assert_eq!(set.len(), 5);
    }

    // ── sign-payment is declarable and parses to SignPayment ─────────────────

    #[test]
    fn sign_payment_parses_to_sign_payment_capability() {
        let set = parse_capability_value("sign-payment").unwrap();
        assert!(set.contains(Capability::SignPayment));
        assert_eq!(set.len(), 1);
    }

    // ── sign-rule-create is declarable and parses to SignRuleCreate ──────────

    #[test]
    fn sign_rule_create_parses_to_sign_rule_create_capability() {
        let set = parse_capability_value("sign-rule-create").unwrap();
        assert!(set.contains(Capability::SignRuleCreate));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn sign_rule_create_display_roundtrip() {
        assert_eq!(Capability::SignRuleCreate.to_string(), "sign-rule-create");
    }

    #[test]
    fn sign_payment_display_roundtrip() {
        assert_eq!(Capability::SignPayment.to_string(), "sign-payment");
    }

    #[test]
    fn duplicate_tokens_deduplicate() {
        let set = parse_capability_value("read-balance read-balance read-balance").unwrap();
        assert_eq!(set.len(), 1);
    }

    // ── No-bare-sign airtightness ─────────────────────────────────────────────

    #[test]
    fn bare_sign_transaction_forbidden() {
        let err = parse_capability_value("sign-transaction").unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::BareSignTransactionForbidden),
            "expected BareSignTransactionForbidden, got {err:?}"
        );
    }

    #[test]
    fn sign_transaction_uppercase_refused_at_charset_gate() {
        // "Sign-Transaction" has uppercase — charset gate catches it BEFORE
        // the name-match step, so it must be CapabilityTokenInvalidChar,
        // never BareSignTransactionForbidden or UnknownCapability.
        let err = parse_capability_value("Sign-Transaction").unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
            "expected CapabilityTokenInvalidChar, got {err:?}"
        );
    }

    #[test]
    fn sign_transaction_all_caps_refused_at_charset_gate() {
        let err = parse_capability_value("SIGN-TRANSACTION").unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
            "expected CapabilityTokenInvalidChar, got {err:?}"
        );
    }

    #[test]
    fn sign_transaction_underscore_refused_at_charset_gate() {
        let err = parse_capability_value("sign_transaction").unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
            "expected CapabilityTokenInvalidChar, got {err:?}"
        );
    }

    #[test]
    fn sign_transaction_whitespace_padded_refused() {
        // Whitespace tokenisation strips leading/trailing whitespace,
        // so " sign-transaction " produces the exact token "sign-transaction"
        // which then hits BareSignTransactionForbidden.
        let err = parse_capability_value(" sign-transaction ").unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::BareSignTransactionForbidden),
            "expected BareSignTransactionForbidden, got {err:?}"
        );
    }

    #[test]
    fn sign_transaction_unicode_homoglyph_refused_at_charset_gate() {
        // Use Cyrillic 'ѕ' (U+0455) which looks like 's' — the charset gate must
        // refuse it as CapabilityTokenInvalidChar.
        let homoglyph = "ѕign-transaction"; // Cyrillic ѕ, not ASCII s
        let err = parse_capability_value(homoglyph).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
            "expected CapabilityTokenInvalidChar, got {err:?}"
        );
    }

    #[test]
    fn read_balance_homoglyph_refused_at_charset_gate() {
        // Cyrillic 'а' (U+0430) looks like ASCII 'a'
        let homoglyph = "re\u{0430}d-balance"; // 'а' instead of 'a'
        let err = parse_capability_value(homoglyph).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::CapabilityTokenInvalidChar { .. }),
            "expected CapabilityTokenInvalidChar, got {err:?}"
        );
    }

    #[test]
    fn unknown_token_refused() {
        let err = parse_capability_value("send-xdr").unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::UnknownCapability { .. }),
            "expected UnknownCapability, got {err:?}"
        );
    }

    #[test]
    fn tab_in_token_refused_at_charset_gate() {
        // A token containing a tab that survived tokenisation would be caught by
        // the charset gate.  (Tokenisation on ASCII whitespace should strip tabs,
        // but an embedded tab in a long token could arrive here — test it.)
        let s = "read\tbalance";
        // split_ascii_whitespace will split on \t, producing "read" and "balance"
        // both of which are unknown tokens (not in taxonomy).
        let err = parse_capability_value(s).unwrap_err();
        assert!(
            matches!(err, ToolsetFormatError::UnknownCapability { .. }),
            "got {err:?}"
        );
    }

    // ── CapabilitySet Deserialize tests ──────────────────────────────────────

    #[test]
    fn deserialize_sign_transaction_is_serde_error() {
        // A stored record with "sign-transaction" must be a deserialize error,
        // NOT a silent drop.
        let json = r#"["sign-transaction"]"#;
        let result: Result<CapabilitySet, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deserialising sign-transaction must be a serde error, not a silent drop"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("sign-transaction"),
            "error message must mention the forbidden token: {msg}"
        );
    }

    #[test]
    fn deserialize_known_tokens_roundtrip() {
        // Known tokens deserialise successfully.
        let json = r#"["read-balance","propose-transaction","suggest-destination","observe-event","sign-payment"]"#;
        let set: CapabilitySet = serde_json::from_str(json).unwrap();
        assert!(set.contains(Capability::ReadBalance));
        assert!(set.contains(Capability::ProposeTransaction));
        assert!(set.contains(Capability::SuggestDestination));
        assert!(set.contains(Capability::ObserveEvent));
        assert!(set.contains(Capability::SignPayment));
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn deserialize_sign_payment_is_ok() {
        // sign-payment is a valid capability token and must deserialise to SignPayment.
        let json = r#"["sign-payment"]"#;
        let set: CapabilitySet = serde_json::from_str(json).unwrap();
        assert!(
            set.contains(Capability::SignPayment),
            "sign-payment must deserialise to SignPayment variant"
        );
    }

    #[test]
    fn deserialize_sign_rule_create_is_ok() {
        let json = r#"["sign-rule-create"]"#;
        let set: CapabilitySet = serde_json::from_str(json).unwrap();
        assert!(
            set.contains(Capability::SignRuleCreate),
            "sign-rule-create must deserialise to SignRuleCreate variant"
        );
    }

    #[test]
    fn deserialize_unknown_token_silently_skipped() {
        // Unknown tokens (future capabilities) are silently skipped so old
        // binaries can load records written by new binaries.
        let json = r#"["read-balance","future-unknown-cap"]"#;
        let set: CapabilitySet = serde_json::from_str(json).unwrap();
        assert!(set.contains(Capability::ReadBalance));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn deserialize_invalid_charset_token_is_serde_error() {
        // A token with invalid chars in a stored record is a serde error.
        let json = r#"["read-balance","UPPERCASE"]"#;
        let result: Result<CapabilitySet, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deserialising a token with invalid charset must be a serde error"
        );
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let set = parse_capability_value("read-balance propose-transaction").unwrap();
        let json = serde_json::to_string(&set).unwrap();
        let restored: CapabilitySet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, restored);
    }

    // ── CapabilitySet API ─────────────────────────────────────────────────────

    #[test]
    fn capability_set_iter_is_sorted() {
        let set = parse_capability_value("observe-event read-balance propose-transaction").unwrap();
        let v: Vec<Capability> = set.iter().collect();
        // BTreeSet order = the Ord-derived order on Capability variants
        // (ReadBalance < ProposeTransaction < SuggestDestination < ObserveEvent < SignPayment)
        assert_eq!(v[0], Capability::ReadBalance);
        assert_eq!(v[1], Capability::ProposeTransaction);
        assert_eq!(v[2], Capability::ObserveEvent);
    }

    #[test]
    fn into_iterator_consumes_set_by_value() {
        // Exercises the `IntoIterator for CapabilitySet` impl: consume the set
        // by value with a `for` loop and assert all inserted capabilities are
        // yielded exactly once.
        let set =
            parse_capability_value("read-balance propose-transaction suggest-destination").unwrap();
        assert_eq!(set.len(), 3);

        let mut seen = Vec::new();
        for cap in set {
            seen.push(cap);
        }

        // BTreeSet iteration is sorted; verify the yielded order.
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], Capability::ReadBalance);
        assert_eq!(seen[1], Capability::ProposeTransaction);
        assert_eq!(seen[2], Capability::SuggestDestination);
    }

    #[test]
    fn capability_display() {
        assert_eq!(Capability::ReadBalance.to_string(), "read-balance");
        assert_eq!(
            Capability::ProposeTransaction.to_string(),
            "propose-transaction"
        );
        assert_eq!(
            Capability::SuggestDestination.to_string(),
            "suggest-destination"
        );
        assert_eq!(Capability::ObserveEvent.to_string(), "observe-event");
        assert_eq!(Capability::SignPayment.to_string(), "sign-payment");
        assert_eq!(Capability::ReadRules.to_string(), "read-rules");
        assert_eq!(Capability::SignRuleCreate.to_string(), "sign-rule-create");
    }

    // ── is_key_touching ───────────────────────────────────────────────────────
    //
    // Exhaustive table — every variant must be explicitly classified.
    // Adding a variant without updating the match arm produces a compile error.

    #[test]
    fn sign_payment_is_key_touching() {
        assert!(
            Capability::SignPayment.is_key_touching(),
            "SignPayment must be key-touching (accesses signing key)"
        );
    }

    #[test]
    fn sign_rule_create_is_key_touching() {
        assert!(
            Capability::SignRuleCreate.is_key_touching(),
            "SignRuleCreate must be key-touching (installs a rule via the signing key)"
        );
    }

    #[test]
    fn non_signing_capabilities_are_not_key_touching() {
        // Exhaustive check — every non-signing variant must return false.
        // This list MUST be updated if a new variant is added.
        let non_key_touching = [
            Capability::ReadBalance,
            Capability::ProposeTransaction,
            Capability::SuggestDestination,
            Capability::ObserveEvent,
        ];
        for cap in non_key_touching {
            assert!(
                !cap.is_key_touching(),
                "{cap} must NOT be key-touching (does not access signing key)"
            );
        }
    }

    #[test]
    fn is_key_touching_exhaustive_table() {
        // Complete classification table.  When a new variant is added, the match
        // arm in is_key_touching will fail to compile until classified, and this
        // table should be updated accordingly.
        let table: &[(Capability, bool)] = &[
            (Capability::ReadBalance, false),
            (Capability::ProposeTransaction, false),
            (Capability::SuggestDestination, false),
            (Capability::ObserveEvent, false),
            (Capability::SignPayment, true),
            (Capability::ReadRules, false),
            (Capability::SignRuleCreate, true),
        ];
        for (cap, expected) in table {
            assert_eq!(
                cap.is_key_touching(),
                *expected,
                "is_key_touching({cap}) should be {expected}"
            );
        }
    }
}

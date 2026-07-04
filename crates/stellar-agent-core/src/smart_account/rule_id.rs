//! Per-context rule identifier for smart-account authorisation.
//!
//! A [`ContextRuleId`] is a `u32` identifier that anchors an authorisation
//! rule in a Soroban smart account.  The identifier is bound into the
//! signing payload at digest-computation time (see [`super::auth_digest`])
//! to prevent rule-ID downgrade attacks.
//!
//! This type mirrors the on-chain representation in OpenZeppelin
//! `stellar-accounts` v0.7.2, where `AuthPayload::context_rule_ids` is
//! `Vec<u32>` (see `smart_account/storage.rs`).
//!
//! # XDR encoding
//!
//! The [`encode_context_rule_ids`] function produces the exact byte
//! layout that the on-chain contract consumes when computing the auth
//! digest — an `ScVal::Vec(Some(ScVec([ScVal::U32(id0), ...])))` in
//! Stellar XDR.  Pass the result to
//! [`super::auth_digest::compute_auth_digest`] as the
//! `context_rule_ids_xdr` argument.

use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use stellar_xdr::{Error as XdrError, Limits, ScVal, ScVec, WriteXdr};
use thiserror::Error;

/// Error returned when parsing a [`ContextRuleId`] from a string fails.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::smart_account::rule_id::{ContextRuleId, ParseContextRuleIdError};
/// use std::str::FromStr;
///
/// let err = ContextRuleId::from_str("not-a-number").unwrap_err();
/// assert!(matches!(err, ParseContextRuleIdError::InvalidInteger(_)));
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseContextRuleIdError {
    /// The input string is not a valid decimal or `0x`-prefixed hexadecimal
    /// representation of a `u32`.
    #[error("invalid integer for ContextRuleId: {0}")]
    InvalidInteger(#[from] ParseIntError),
}

/// Error returned when encoding a slice of [`ContextRuleId`] to the on-chain
/// XDR byte layout fails.
///
/// The underlying `stellar-xdr` encoder only fails if the wrapped
/// `Vec<ScVal>` does not fit into the XDR `VecM` length cap
/// (`u32::MAX` elements). On 64-bit targets this bound is well above
/// any realistic slice length, so this variant is effectively
/// unreachable for callers in practice. Realistic smart-account
/// rule-ID lists (a handful of entries per the OpenZeppelin
/// `stellar-accounts` v0.7.2 model) never approach the bound.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::smart_account::rule_id::{
///     ContextRuleId, encode_context_rule_ids,
/// };
///
/// let empty: Vec<ContextRuleId> = Vec::new();
/// let bytes = encode_context_rule_ids(&empty).expect("empty list encodes");
/// assert_eq!(bytes.len(), 12); // SCV_VEC + Some + len(0) = 3 × 4 bytes
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EncodeContextRuleIdsError {
    /// The underlying `stellar-xdr` XDR encoder rejected the input.
    #[error("XDR encoding of context rule IDs failed: {0}")]
    Xdr(#[from] XdrError),
}

/// A `u32` per-context rule identifier for an OpenZeppelin smart-account
/// context rule.
///
/// Each context rule on an OpenZeppelin `stellar-accounts` v0.7.2 C-account
/// is selected by a `u32` identifier carried in
/// `AuthPayload::context_rule_ids`.  The
/// [`super::auth_digest::compute_auth_digest`] primitive binds the
/// XDR-encoded rule-IDs into the signing payload, which closes the
/// rule-ID downgrade attack.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::smart_account::rule_id::ContextRuleId;
/// use std::str::FromStr;
///
/// let id = ContextRuleId::new(7);
/// assert_eq!(id.as_u32(), 7);
///
/// let text = id.to_string();
/// assert_eq!(text, "7");
///
/// let roundtrip = ContextRuleId::from_str(&text).unwrap();
/// assert_eq!(id, roundtrip);
/// ```
///
/// # `#[non_exhaustive]` exemption
///
/// This is a newtype over `u32`, mirroring the on-chain `AuthPayload::context_rule_ids`
/// element type in OZ `stellar-accounts` v0.7.2.  The width is fixed by the
/// on-chain protocol.  The single field is private; external callers use
/// [`ContextRuleId::new`] or `FromStr`.  `#[non_exhaustive]` on a newtype
/// with a private field adds no forward-compat guarantee and is omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContextRuleId(u32);

impl ContextRuleId {
    /// Constructs a [`ContextRuleId`] from a raw `u32`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::smart_account::rule_id::ContextRuleId;
    ///
    /// let id = ContextRuleId::new(42);
    /// assert_eq!(id.as_u32(), 42);
    /// ```
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the underlying `u32`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::smart_account::rule_id::ContextRuleId;
    ///
    /// let id = ContextRuleId::new(0xabcd);
    /// assert_eq!(id.as_u32(), 0xabcd);
    /// ```
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<u32> for ContextRuleId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<ContextRuleId> for u32 {
    fn from(id: ContextRuleId) -> Self {
        id.0
    }
}

impl fmt::Display for ContextRuleId {
    /// Formats the identifier as a decimal integer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for ContextRuleId {
    type Err = ParseContextRuleIdError;

    /// Parses a [`ContextRuleId`] from a decimal or `0x`-prefixed hex string.
    ///
    /// Leading and trailing whitespace is not accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ParseContextRuleIdError::InvalidInteger`] when the input is
    /// not a valid `u32` representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::smart_account::rule_id::ContextRuleId;
    /// use std::str::FromStr;
    ///
    /// // Decimal round-trip.
    /// let id = ContextRuleId::new(42);
    /// let parsed = ContextRuleId::from_str(&id.to_string()).unwrap();
    /// assert_eq!(id, parsed);
    ///
    /// // Hex with 0x prefix is also accepted.
    /// let parsed_hex = ContextRuleId::from_str("0x2a").unwrap();
    /// assert_eq!(parsed_hex, ContextRuleId::new(0x2a));
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u32::from_str_radix(rest, 16)?
        } else {
            s.parse::<u32>()?
        };
        Ok(Self(id))
    }
}

/// Encodes a slice of [`ContextRuleId`] to the XDR byte layout the on-chain
/// OpenZeppelin `stellar-accounts` v0.7.2 contract consumes at
/// `__check_auth` time.
///
/// Produces exactly the bytes required as the `context_rule_ids_xdr` argument
/// to [`super::auth_digest::compute_auth_digest`].  The byte layout is
/// `ScVal::Vec(Some(ScVec([ScVal::U32(id0), ScVal::U32(id1), ...])))` in
/// Stellar XDR, matching the on-chain computation at
/// `smart_account/storage.rs` of OpenZeppelin `stellar-contracts` v0.7.2,
/// which
/// calls `signatures.context_rule_ids.clone().to_xdr(e)` on its host
/// `Vec<u32>`.
///
/// # Layout
///
/// For `rule_ids = [7u32, 42u32]` the encoding is 28 bytes:
///
/// ```text
/// 00 00 00 10                  # SCV_VEC discriminant (0x10)
/// 00 00 00 01                  # Option<ScVec>::Some marker
/// 00 00 00 02                  # ScVec length = 2
/// 00 00 00 03 00 00 00 07      # ScVal::U32(7):  discriminant + value
/// 00 00 00 03 00 00 00 2a      # ScVal::U32(42): discriminant + value
/// ```
///
/// An empty list encodes to 12 bytes (`SCV_VEC || Some || 0`).
///
/// Total size for `N` elements: `12 + 8 × N` bytes.
///
/// # Errors
///
/// Returns [`EncodeContextRuleIdsError::Xdr`] only if the wrapped
/// `Vec<ScVal>` does not fit into the XDR `VecM` length cap
/// (`u32::MAX` elements). On 64-bit targets the input slice length is
/// bounded by `isize::MAX`, which is well below `u32::MAX`, so this
/// variant cannot fire for any realistic caller. The `Result` return
/// preserves future-proofing if `stellar-xdr` adds encoder limits in
/// a future major version, and to match the `#[non_exhaustive]` enum
/// shape.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::smart_account::rule_id::{
///     ContextRuleId, encode_context_rule_ids,
/// };
///
/// let ids = [ContextRuleId::new(7), ContextRuleId::new(42)];
/// let xdr = encode_context_rule_ids(&ids).unwrap();
/// assert_eq!(xdr.len(), 28);
/// ```
///
/// Typical end-to-end use with [`super::auth_digest::compute_auth_digest`]:
///
/// ```
/// use stellar_agent_core::smart_account::auth_digest::compute_auth_digest;
/// use stellar_agent_core::smart_account::rule_id::{
///     ContextRuleId, encode_context_rule_ids,
/// };
///
/// let rule_ids = [ContextRuleId::new(1)];
/// let rules_xdr = encode_context_rule_ids(&rule_ids).unwrap();
/// let digest = compute_auth_digest(b"signature_payload_bytes", &rules_xdr);
/// assert_eq!(digest.as_bytes().len(), 32);
/// ```
pub fn encode_context_rule_ids(
    rule_ids: &[ContextRuleId],
) -> Result<Vec<u8>, EncodeContextRuleIdsError> {
    // Build the Vec<ScVal> on the off-chain side, matching what the host
    // `Vec<u32>::to_xdr(env)` produces on-chain: each rule ID becomes an
    // `ScVal::U32`, wrapped in an `ScVec`, wrapped in `ScVal::Vec(Some(..))`.
    let scvals: Vec<ScVal> = rule_ids.iter().map(|id| ScVal::U32(id.as_u32())).collect();

    // Vec -> ScVec conversion is fallible only if the input length
    // exceeds `u32::MAX` (the XDR cap on VecM).
    let scvec: ScVec = scvals.try_into()?;

    // The on-chain `ScVal::Vec(Option<ScVec>)` always carries `Some` when
    // produced by `Vec<u32>::to_xdr(env)`; a `None` payload would encode
    // to a different byte layout the contract does not match.
    let scval = ScVal::Vec(Some(scvec));

    // `Limits::none()` disables all encoder limits — safe because we just
    // built the value from a bounded slice of `u32`s; no string or
    // recursion limits apply. The underlying writer is an in-memory
    // `Vec<u8>`, so write failures cannot occur.
    Ok(scval.to_xdr(Limits::none())?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn new_and_as_u32_roundtrip() {
        let id = ContextRuleId::new(0xdead_beef);
        assert_eq!(id.as_u32(), 0xdead_beef);
    }

    #[test]
    fn display_is_decimal() {
        let id = ContextRuleId::new(123);
        assert_eq!(id.to_string(), "123");
    }

    #[test]
    fn from_str_accepts_decimal() {
        let parsed = ContextRuleId::from_str("12345").unwrap();
        assert_eq!(parsed, ContextRuleId::new(12_345));
    }

    #[test]
    fn from_str_accepts_zero() {
        let parsed = ContextRuleId::from_str("0").unwrap();
        assert_eq!(parsed, ContextRuleId::new(0));
    }

    #[test]
    fn from_str_accepts_u32_max() {
        let parsed = ContextRuleId::from_str(&u32::MAX.to_string()).unwrap();
        assert_eq!(parsed, ContextRuleId::new(u32::MAX));
    }

    #[test]
    fn from_str_accepts_lowercase_hex_prefix() {
        let parsed = ContextRuleId::from_str("0xff").unwrap();
        assert_eq!(parsed, ContextRuleId::new(0xff));
    }

    #[test]
    fn from_str_accepts_uppercase_hex_prefix() {
        let parsed = ContextRuleId::from_str("0XFF").unwrap();
        assert_eq!(parsed, ContextRuleId::new(0xff));
    }

    #[test]
    fn from_str_rejects_negative() {
        let err = ContextRuleId::from_str("-1").unwrap_err();
        assert!(matches!(err, ParseContextRuleIdError::InvalidInteger(_)));
    }

    #[test]
    fn from_str_rejects_overflow() {
        // u32::MAX + 1
        let err = ContextRuleId::from_str("4294967296").unwrap_err();
        assert!(matches!(err, ParseContextRuleIdError::InvalidInteger(_)));
    }

    #[test]
    fn from_str_rejects_non_numeric() {
        let err = ContextRuleId::from_str("not-a-number").unwrap_err();
        assert!(matches!(err, ParseContextRuleIdError::InvalidInteger(_)));
    }

    #[test]
    fn from_str_rejects_leading_whitespace() {
        let err = ContextRuleId::from_str(" 42").unwrap_err();
        assert!(matches!(err, ParseContextRuleIdError::InvalidInteger(_)));
    }

    #[test]
    fn equality_and_hash_consistent() {
        use std::collections::HashSet;
        let a = ContextRuleId::new(1);
        let b = ContextRuleId::new(1);
        let c = ContextRuleId::new(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b); // duplicate
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn copy_semantics_work() {
        let a = ContextRuleId::new(0);
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn ord_is_numeric() {
        let mut ids = [
            ContextRuleId::new(3),
            ContextRuleId::new(1),
            ContextRuleId::new(2),
        ];
        ids.sort();
        assert_eq!(
            ids,
            [
                ContextRuleId::new(1),
                ContextRuleId::new(2),
                ContextRuleId::new(3),
            ]
        );
    }

    #[test]
    fn u32_round_trip_via_from() {
        let id: ContextRuleId = 7u32.into();
        let back: u32 = id.into();
        assert_eq!(back, 7);
    }

    proptest! {
        #[test]
        fn display_then_from_str_is_identity(raw in any::<u32>()) {
            let id = ContextRuleId::new(raw);
            let parsed = ContextRuleId::from_str(&id.to_string()).unwrap();
            prop_assert_eq!(id, parsed);
        }

        #[test]
        fn different_values_produce_different_display(a in any::<u32>(), b in any::<u32>()) {
            prop_assume!(a != b);
            let id_a = ContextRuleId::new(a);
            let id_b = ContextRuleId::new(b);
            prop_assert_ne!(id_a.to_string(), id_b.to_string());
        }
    }

    // -------------------------------------------------------------------------
    // encode_context_rule_ids — byte-layout known-answer tests
    //
    // KAT ground truth verified via the `stellar-xdr` MCP `encode` tool and
    // cross-checked against OpenZeppelin `stellar-contracts` v0.7.2
    // (`smart_account/storage.rs`).
    // -------------------------------------------------------------------------

    /// Empty list encodes to exactly 12 bytes:
    /// `SCV_VEC (0x00000010) || Some (0x00000001) || length (0x00000000)`.
    #[test]
    fn encode_empty_list_is_12_bytes_vec_some_zero() {
        let bytes = encode_context_rule_ids(&[]).unwrap();
        assert_eq!(bytes.len(), 12);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x10, // SCV_VEC discriminant
                0x00, 0x00, 0x00, 0x01, // Some marker
                0x00, 0x00, 0x00, 0x00, // length = 0
            ]
        );
    }

    /// Single-element list `[42]` encodes to 20 bytes with the expected
    /// ScVal layout.
    #[test]
    fn encode_single_element_list() {
        let bytes = encode_context_rule_ids(&[ContextRuleId::new(42)]).unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x10, // SCV_VEC
                0x00, 0x00, 0x00, 0x01, // Some
                0x00, 0x00, 0x00, 0x01, // length = 1
                0x00, 0x00, 0x00, 0x03, // SCV_U32
                0x00, 0x00, 0x00, 0x2a, // value = 42
            ]
        );
    }

    /// Two-element list `[7, 42]` matches the canonical 28-byte KAT
    /// produced by the `stellar-xdr` MCP `encode` tool for
    /// `ScVal::Vec(Some([U32(7), U32(42)]))`.
    #[test]
    fn encode_two_elements_matches_canonical_xdr_kat() {
        let ids = [ContextRuleId::new(7), ContextRuleId::new(42)];
        let bytes = encode_context_rule_ids(&ids).unwrap();
        assert_eq!(bytes.len(), 28);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x10, // SCV_VEC
                0x00, 0x00, 0x00, 0x01, // Some
                0x00, 0x00, 0x00, 0x02, // length = 2
                0x00, 0x00, 0x00, 0x03, // SCV_U32
                0x00, 0x00, 0x00, 0x07, // value = 7
                0x00, 0x00, 0x00, 0x03, // SCV_U32
                0x00, 0x00, 0x00, 0x2a, // value = 42
            ]
        );
    }

    /// Big-endian u32 layout — verify that `ContextRuleId::new(0x01020304)`
    /// encodes its bytes in big-endian order, not little-endian. XDR is
    /// big-endian per RFC 4506.
    #[test]
    fn encode_big_endian_u32_layout() {
        let bytes = encode_context_rule_ids(&[ContextRuleId::new(0x0102_0304)]).unwrap();
        assert_eq!(&bytes[12..16], &[0x00, 0x00, 0x00, 0x03]); // SCV_U32 discriminant
        assert_eq!(&bytes[16..20], &[0x01, 0x02, 0x03, 0x04]); // value big-endian
    }

    /// `u32::MAX` rule ID round-trips through the encoder (no overflow
    /// trap; this just exercises the boundary value).
    #[test]
    fn encode_u32_max_element() {
        let bytes = encode_context_rule_ids(&[ContextRuleId::new(u32::MAX)]).unwrap();
        assert_eq!(&bytes[16..20], &[0xff, 0xff, 0xff, 0xff]);
    }

    /// Size invariant for N elements: `12 + 8 × N` bytes. Exercised for a
    /// handful of realistic list lengths.
    #[test]
    fn encode_size_invariant_holds_for_small_n() {
        for n in [0usize, 1, 2, 5, 10] {
            let ids: Vec<ContextRuleId> = (0..n as u32).map(ContextRuleId::new).collect();
            let bytes = encode_context_rule_ids(&ids).unwrap();
            assert_eq!(bytes.len(), 12 + 8 * n, "N={n}");
        }
    }

    proptest! {
        /// Encoder is deterministic: the same input always produces the same
        /// bytes. Exercises list length 0..=8 with arbitrary `u32`s.
        #[test]
        fn encode_is_deterministic(
            ids in prop::collection::vec(any::<u32>(), 0..8).prop_map(|v|
                v.into_iter().map(ContextRuleId::new).collect::<Vec<_>>()),
        ) {
            let a = encode_context_rule_ids(&ids).unwrap();
            let b = encode_context_rule_ids(&ids).unwrap();
            prop_assert_eq!(a, b);
        }

        /// Different inputs produce different byte encodings (per XDR
        /// determinism). Excludes the permutation edge case by requiring
        /// length-differ inputs; same-length inputs are covered separately.
        #[test]
        fn encode_distinct_lists_produce_distinct_bytes(
            a in prop::collection::vec(any::<u32>(), 0..8).prop_map(|v|
                v.into_iter().map(ContextRuleId::new).collect::<Vec<_>>()),
            b in prop::collection::vec(any::<u32>(), 0..8).prop_map(|v|
                v.into_iter().map(ContextRuleId::new).collect::<Vec<_>>()),
        ) {
            prop_assume!(a != b);
            let ea = encode_context_rule_ids(&a).unwrap();
            let eb = encode_context_rule_ids(&b).unwrap();
            prop_assert_ne!(ea, eb);
        }
    }
}

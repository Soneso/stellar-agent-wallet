//! Claimable-balance-ID normalization.
//!
//! A claimable balance is identified on the Stellar network by a
//! `ClaimableBalanceID` XDR union (currently a single variant,
//! `ClaimableBalanceIdTypeV0`, wrapping a 32-byte hash). Agents and users
//! encounter this id in three interchangeable textual forms:
//!
//! - The `B...` strkey (`stellar_strkey::ClaimableBalance::V0`), the form
//!   shown by wallets and block explorers.
//! - The canonical 72-hex-character id: an 8-hex-character big-endian
//!   `00000000` type-V0 discriminant followed by the 64-hex-character hash.
//!   This is the form `CreateClaimableBalance` transaction results and
//!   Horizon return.
//! - The bare 64-hex-character hash with no discriminant prefix. This form
//!   is accepted as a documented convenience for callers who already
//!   stripped the discriminant; it is assumed to be a V0 id since V0 is the
//!   only id type the protocol defines.
//!
//! [`BalanceId::parse`] accepts all three and normalizes to the underlying
//! 32-byte hash. [`BalanceId::to_hex64`] produces the bare-hex form that
//! `stellar-baselib`'s `Operation::claim_claimable_balance` requires.

use crate::error::ClaimError;

/// The 8-hex-character big-endian encoding of the `ClaimableBalanceIdTypeV0`
/// discriminant (`0`), as it appears at the start of the canonical 72-hex
/// balance-id rendering.
const V0_DISCRIMINANT_HEX: &str = "00000000";

/// A normalized claimable-balance identifier.
///
/// Holds the 32-byte hash. Construct via [`BalanceId::parse`]; render via
/// [`BalanceId::to_hex72`], [`BalanceId::to_strkey`], or
/// [`BalanceId::to_hex64`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BalanceId {
    hash: [u8; 32],
}

impl BalanceId {
    /// Parses a claimable-balance id from any of the three accepted textual
    /// forms (see module docs).
    ///
    /// Input is trimmed of leading/trailing whitespace before classification.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError::InvalidBalanceId`] when:
    /// - the input is not a valid `B...` claimable-balance strkey, and
    /// - the input is not exactly 72 hex characters with a `00000000` V0
    ///   discriminant prefix, and
    /// - the input is not exactly 64 hex characters.
    ///
    /// A 72-character hex input whose first 8 characters decode to a
    /// discriminant other than `00000000` is rejected outright — it is not
    /// silently reinterpreted as a bare-hash or truncated to the trailing 64
    /// characters, since that would accept an id of an id-type the protocol
    /// does not (yet) define as if it were V0.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_claimable::id::BalanceId;
    ///
    /// let hex64 = "0".repeat(64);
    /// let id = BalanceId::parse(&hex64).unwrap();
    /// assert_eq!(id.hash(), [0u8; 32]);
    ///
    /// let hex72 = format!("00000000{hex64}");
    /// assert_eq!(BalanceId::parse(&hex72).unwrap(), id);
    ///
    /// assert!(BalanceId::parse("not-a-balance-id").is_err());
    /// ```
    pub fn parse(input: &str) -> Result<Self, ClaimError> {
        let trimmed = input.trim();

        if let Ok(stellar_strkey::ClaimableBalance::V0(hash)) =
            stellar_strkey::ClaimableBalance::from_string(trimmed)
        {
            return Ok(Self { hash });
        }

        // Every accepted form is ASCII (hex or base32). Rejecting non-ASCII
        // up front makes the byte-length dispatch below equal to the character
        // count and keeps `split_at` on a char boundary for any input.
        if !trimmed.is_ascii() {
            return Err(ClaimError::InvalidBalanceId {
                detail: "balance id must contain only ASCII hex or strkey characters".to_owned(),
            });
        }

        match trimmed.len() {
            72 => {
                let (prefix, hash_hex) = trimmed.split_at(8);
                if !prefix.eq_ignore_ascii_case(V0_DISCRIMINANT_HEX) {
                    return Err(ClaimError::InvalidBalanceId {
                        detail: format!(
                            "72-character hex id must carry the V0 discriminant prefix \
                             '{V0_DISCRIMINANT_HEX}'; found a different type prefix"
                        ),
                    });
                }
                let hash = stellar_agent_core::hex::decode_hex32(hash_hex).map_err(|e| {
                    ClaimError::InvalidBalanceId {
                        detail: format!("72-character hex id has an invalid hash portion: {e}"),
                    }
                })?;
                Ok(Self { hash })
            }
            64 => {
                let hash = stellar_agent_core::hex::decode_hex32(trimmed).map_err(|e| {
                    ClaimError::InvalidBalanceId {
                        detail: format!("64-character hex hash is invalid: {e}"),
                    }
                })?;
                Ok(Self { hash })
            }
            other => Err(ClaimError::InvalidBalanceId {
                detail: format!(
                    "unrecognized balance-id form: expected a 'B...' strkey, a 72-character \
                     hex id, or a bare 64-character hex hash; got {other} characters"
                ),
            }),
        }
    }

    /// Constructs a `BalanceId` directly from an already-decoded 32-byte
    /// hash.
    ///
    /// Crate-internal: used by [`crate::preview::ClaimPreview::build`] to
    /// reuse this type's display renderings for an id that arrived already
    /// decoded (from a fetched `ClaimableBalanceEntry`) rather than as text.
    #[must_use]
    pub(crate) fn from_hash(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Returns the underlying 32-byte hash.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_claimable::id::BalanceId;
    ///
    /// let id = BalanceId::parse(&"ab".repeat(32)).unwrap();
    /// assert_eq!(id.hash(), [0xab_u8; 32]);
    /// ```
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Renders the canonical 72-hex-character form (`00000000` V0
    /// discriminant + 64-hex hash).
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_claimable::id::BalanceId;
    ///
    /// let id = BalanceId::parse(&"00".repeat(32)).unwrap();
    /// assert_eq!(id.to_hex72(), format!("00000000{}", "00".repeat(32)));
    /// ```
    #[must_use]
    pub fn to_hex72(&self) -> String {
        format!(
            "{V0_DISCRIMINANT_HEX}{}",
            stellar_agent_core::hex::encode(&self.hash)
        )
    }

    /// Renders the bare 64-hex-character hash with no discriminant prefix.
    ///
    /// This is the form `stellar-baselib`'s `Operation::claim_claimable_balance`
    /// requires; [`stellar_agent_network::builder::ClassicOpBuilder::claim_claimable_balance`]
    /// takes exactly this string.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_claimable::id::BalanceId;
    ///
    /// let id = BalanceId::parse(&"ff".repeat(32)).unwrap();
    /// assert_eq!(id.to_hex64(), "ff".repeat(32));
    /// ```
    #[must_use]
    pub fn to_hex64(&self) -> String {
        stellar_agent_core::hex::encode(&self.hash)
    }

    /// Renders the `B...` claimable-balance strkey form.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_claimable::id::BalanceId;
    ///
    /// let id = BalanceId::parse(&"00".repeat(32)).unwrap();
    /// assert!(id.to_strkey().starts_with('B'));
    /// ```
    #[must_use]
    pub fn to_strkey(&self) -> String {
        let heapless = stellar_strkey::ClaimableBalance::V0(self.hash).to_string();
        format!("{heapless}")
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;

    const KNOWN_HASH_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    // ─── Accept: three input forms round-trip ─────────────────────────────

    #[test]
    fn parses_bare_64_hex_hash() {
        let id = BalanceId::parse(KNOWN_HASH_HEX).expect("valid 64-hex hash");
        assert_eq!(id.to_hex64(), KNOWN_HASH_HEX);
    }

    #[test]
    fn parses_canonical_72_hex_id() {
        let hex72 = format!("00000000{KNOWN_HASH_HEX}");
        let id = BalanceId::parse(&hex72).expect("valid 72-hex id");
        assert_eq!(id.to_hex72(), hex72);
        assert_eq!(id.to_hex64(), KNOWN_HASH_HEX);
    }

    #[test]
    fn parses_uppercase_72_hex_discriminant() {
        let hex72 = format!("00000000{}", KNOWN_HASH_HEX.to_uppercase());
        let id = BalanceId::parse(&hex72).expect("uppercase hex must be accepted");
        assert_eq!(id.to_hex64(), KNOWN_HASH_HEX);
    }

    #[test]
    fn parses_strkey_form() {
        let hex72 = format!("00000000{KNOWN_HASH_HEX}");
        let from_hex = BalanceId::parse(&hex72).expect("valid 72-hex id");
        let strkey = from_hex.to_strkey();
        assert!(strkey.starts_with('B'));

        let from_strkey = BalanceId::parse(&strkey).expect("valid strkey");
        assert_eq!(from_strkey, from_hex);
    }

    #[test]
    fn three_forms_round_trip_to_the_same_id() {
        let hex64 = KNOWN_HASH_HEX.to_owned();
        let hex72 = format!("00000000{hex64}");
        let from_64 = BalanceId::parse(&hex64).unwrap();
        let from_72 = BalanceId::parse(&hex72).unwrap();
        let strkey = from_72.to_strkey();
        let from_strkey = BalanceId::parse(&strkey).unwrap();

        assert_eq!(from_64, from_72);
        assert_eq!(from_72, from_strkey);
    }

    // ─── Reject: wrong discriminant, lengths, non-hex, malformed strkey ──

    #[test]
    fn rejects_non_v0_discriminant_prefix() {
        // 00000001 is not a defined ClaimableBalanceID type; must be rejected
        // outright, not reinterpreted as V0.
        let hex72 = format!("00000001{KNOWN_HASH_HEX}");
        let err = BalanceId::parse(&hex72).expect_err("non-V0 discriminant must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_too_short_input() {
        let err = BalanceId::parse("abcd").expect_err("too-short input must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_too_long_input() {
        let too_long = "0".repeat(73);
        let err = BalanceId::parse(&too_long).expect_err("73-char input must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_65_char_input() {
        let input = "0".repeat(65);
        let err = BalanceId::parse(&input).expect_err("65-char input must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_non_hex_characters_in_64_form() {
        let mut bad = KNOWN_HASH_HEX.to_owned();
        bad.replace_range(0..1, "z");
        let err = BalanceId::parse(&bad).expect_err("non-hex char must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_non_hex_characters_in_72_form_hash_portion() {
        let mut hex72 = format!("00000000{KNOWN_HASH_HEX}");
        hex72.replace_range(10..11, "z");
        let err = BalanceId::parse(&hex72).expect_err("non-hex char must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_malformed_strkey() {
        let err = BalanceId::parse("BNOTAVALIDSTRKEY").expect_err("malformed strkey rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_g_address_strkey() {
        // A valid strkey of the WRONG kind (G-account, not claimable balance)
        // must not fall through to a hex-length match by coincidence.
        let g = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let err = BalanceId::parse(g).expect_err("G-strkey must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_empty_input() {
        let err = BalanceId::parse("").expect_err("empty input must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn rejects_non_ascii_without_panicking() {
        // 72 BYTES whose byte index 8 falls inside a multi-byte UTF-8
        // sequence: a byte-offset split would panic on the char boundary,
        // so the parser must reject on the ASCII check before any slicing.
        let input = format!("aaaaaa\u{20AC}{}", "0".repeat(63));
        assert_eq!(input.len(), 72);
        let err = BalanceId::parse(&input).expect_err("non-ASCII input must be rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");

        // Non-ASCII at other lengths and positions must reject the same way.
        let err = BalanceId::parse("\u{20AC}").expect_err("short non-ASCII rejected");
        assert_eq!(err.code(), "claim.invalid_balance_id");
    }

    #[test]
    fn trims_whitespace() {
        let hex64 = format!("  {KNOWN_HASH_HEX}\n");
        let id = BalanceId::parse(&hex64).expect("whitespace must be trimmed");
        assert_eq!(id.to_hex64(), KNOWN_HASH_HEX);
    }
}

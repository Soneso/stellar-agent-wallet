//! Typed Stellar amount value and unit-enforcing parsers.
//!
//! The central type is [`StellarAmount`], which stores amounts internally as
//! `i64` stroops and requires an explicit unit label (`XLM`) on every
//! human-supplied input string.  A 100-stroop payment cannot be silently
//! interpreted as 100 XLM, since bare-number inputs are rejected with
//! [`ValidationError::AmountUnitsRequired`].
//!
//! # Protocol constants
//!
//! [`STELLAR_DECIMALS`] and [`STROOPS_PER_XLM`] are the two authoritative
//! numeric constants derived from the Stellar XDR `Amount` type definition
//! (`i64` units of `1/10^7 XLM`).
//!
//! Only the `XLM` unit label is recognised.  Asset-code units
//! (e.g. `"100 USDC:issuer"`) belong to the asset-parsing layer and are
//! not handled here.

use std::fmt;

use crate::error::ValidationError;

// ──────────────────────────────────────────────────────────────────────────────
// Protocol constants
// ──────────────────────────────────────────────────────────────────────────────

/// The number of decimal places in the Stellar protocol's `Amount` type.
///
/// The Stellar XDR `Amount` is defined as an `i64` whose units are
/// `1/10^7 XLM` (one ten-millionth of one lumen).  This constant captures
/// that protocol invariant so callers do not need to embed the magic number 7.
///
/// # Protocol provenance
///
/// Defined in the Stellar XDR schema as the number of sub-units per
/// native unit.  Every amount on the Stellar network is quantised to
/// one stroop; fractional-stroop amounts are not representable.
pub const STELLAR_DECIMALS: u32 = 7;

/// The number of stroops in one XLM (10,000,000).
///
/// Derived from [`STELLAR_DECIMALS`]: `10^7 = 10_000_000`.  Asserted at
/// compile time below to prevent drift if either constant is changed.
///
/// # Protocol provenance
///
/// The smallest representable Stellar `Amount` is 1 stroop = 1e-7 XLM.
/// The base fee for a classic transaction is 100 stroops = 0.0000100 XLM.
pub const STROOPS_PER_XLM: i64 = 10_000_000;

// Compile-time assertion: STROOPS_PER_XLM == 10^STELLAR_DECIMALS.
const _: () = {
    let expected: i64 = {
        let mut v: i64 = 1;
        let mut i = 0u32;
        while i < STELLAR_DECIMALS {
            v *= 10;
            i += 1;
        }
        v
    };
    assert!(
        STROOPS_PER_XLM == expected,
        "STROOPS_PER_XLM must equal 10^STELLAR_DECIMALS"
    );
};

// ──────────────────────────────────────────────────────────────────────────────
// StellarAmount type
// ──────────────────────────────────────────────────────────────────────────────

/// A typed Stellar amount stored as `i64` stroops.
///
/// Construct via [`StellarAmount::from_stroops`] for programmatic construction,
/// [`StellarAmount::parse_with_unit`] for human-supplied strings (requires
/// an explicit `XLM` unit label), or [`StellarAmount::parse_stroops`] when
/// the input is already in base units.
///
/// # Negative amounts
///
/// Negative values are representable at the type level.  Domain-specific
/// rejection (e.g. payment operations that require a positive amount) is the
/// caller's responsibility.
///
/// Only `XLM` is accepted as a unit label.  Asset-code units
/// (`"100 USDC:GA…"`) are not handled by this type; they live in the
/// asset-parsing layer.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::amount::{StellarAmount, STROOPS_PER_XLM};
///
/// let a = StellarAmount::parse_with_unit("100 XLM").unwrap();
/// assert_eq!(a.as_stroops(), 100 * STROOPS_PER_XLM);
/// assert_eq!(a.as_xlm_decimal_string(), "100.0000000");
/// assert_eq!(a.to_string(), "100.0000000 XLM");
/// ```
///
/// # Construction
///
/// External crates cannot construct `StellarAmount` via struct-literal
/// syntax because the single field is private. `#[non_exhaustive]`
/// additionally signals future-growth intent (e.g. a potential
/// `metadata` field for asset-scoped amounts) so downstream pattern
/// matches stay forward-compatible.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StellarAmount {
    stroops: i64,
}

impl StellarAmount {
    /// Constructs a [`StellarAmount`] directly from a stroop value.
    ///
    /// This is a zero-cost constructor; no parsing or allocation occurs.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::{StellarAmount, STROOPS_PER_XLM};
    ///
    /// let fee = StellarAmount::from_stroops(100);
    /// assert_eq!(fee.as_stroops(), 100);
    ///
    /// let one_xlm = StellarAmount::from_stroops(STROOPS_PER_XLM);
    /// assert_eq!(one_xlm.to_string(), "1.0000000 XLM");
    /// ```
    #[must_use]
    pub const fn from_stroops(stroops: i64) -> Self {
        Self { stroops }
    }

    /// Parses a human-supplied amount string that includes an explicit unit label.
    ///
    /// The input must be of the form `"<decimal> XLM"` where the decimal part
    /// may contain up to [`STELLAR_DECIMALS`] fractional digits and optional
    /// leading minus sign.  At least one ASCII whitespace character must
    /// separate the numeric part from the unit label.  The unit label is
    /// case-insensitive (`"xlm"`, `"Xlm"`, and `"XLM"` are all accepted).
    ///
    /// Bare numbers without a unit (e.g. `"100"`) are rejected with
    /// [`ValidationError::AmountUnitsRequired`] to close threat T3
    /// (hallucinated amount units).
    ///
    /// # Parsing rules
    ///
    /// - No floating-point arithmetic is used; parsing is integer-only.
    /// - A single `.` separator is allowed; multiple dots are rejected.
    /// - A trailing `.` with an empty fractional part is accepted
    ///   (`"100. XLM"` == `"100 XLM"`). A leading-only `.` (no integer
    ///   part, e.g. `".5 XLM"`) is rejected as
    ///   [`ValidationError::AmountMalformed`] for grammar simplicity.
    /// - Leading `+` signs are rejected for grammar simplicity.
    /// - Leading `-` produces a negative stroop value.
    /// - Fractional digits beyond seven are rejected with
    ///   [`ValidationError::AmountPrecisionExceeded`].
    /// - Integer overflow is detected with `checked_mul` / `checked_add` /
    ///   `checked_neg` and reported as
    ///   [`ValidationError::AmountOutOfRange`].
    ///
    /// # Errors
    ///
    /// - [`ValidationError::AmountUnitsRequired`] — no unit label present.
    /// - [`ValidationError::AmountMalformed`] — the numeric part is invalid,
    ///   the unit is not `XLM`, multiple dots, or empty input.
    /// - [`ValidationError::AmountPrecisionExceeded`] — more than seven
    ///   fractional digits.
    /// - [`ValidationError::AmountOutOfRange`] — value overflows `i64`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::StellarAmount;
    /// use stellar_agent_core::error::ValidationError;
    ///
    /// assert_eq!(
    ///     StellarAmount::parse_with_unit("100 XLM").unwrap().as_stroops(),
    ///     1_000_000_000,
    /// );
    ///
    /// assert!(matches!(
    ///     StellarAmount::parse_with_unit("100"),
    ///     Err(ValidationError::AmountUnitsRequired),
    /// ));
    ///
    /// assert!(matches!(
    ///     StellarAmount::parse_with_unit("0.00000001 XLM"),
    ///     Err(ValidationError::AmountPrecisionExceeded { .. }),
    /// ));
    /// ```
    pub fn parse_with_unit(s: &str) -> Result<Self, ValidationError> {
        let s = s.trim();

        // Split at the first ASCII whitespace character.  Everything before is
        // the numeric part; everything after (trimmed) is the unit label.
        let ws_pos = s.as_bytes().iter().position(|b| b.is_ascii_whitespace());

        let (numeric_str, unit_str) = match ws_pos {
            None => {
                // No whitespace at all.  If the input looks purely numeric we
                // return AmountUnitsRequired; otherwise AmountMalformed.
                if looks_like_bare_number(s) {
                    return Err(ValidationError::AmountUnitsRequired);
                }
                return Err(ValidationError::AmountMalformed {
                    input: s.to_owned(),
                });
            }
            Some(pos) => {
                let numeric = &s[..pos];
                let rest = s[pos..].trim();
                (numeric, rest)
            }
        };

        // Validate unit label (case-insensitive; only XLM is accepted).
        if !unit_str.eq_ignore_ascii_case("xlm") {
            // If the unit is empty (trailing whitespace only) we check if the
            // numeric part could be a bare number.
            if unit_str.is_empty() && looks_like_bare_number(numeric_str) {
                return Err(ValidationError::AmountUnitsRequired);
            }
            return Err(ValidationError::AmountMalformed {
                input: s.to_owned(),
            });
        }

        parse_decimal_to_stroops(numeric_str, s)
    }

    /// Parses a bare stroop integer string (for `--amount-base <stroops>`).
    ///
    /// Accepts an optional leading `-` sign followed by decimal digits.
    /// No unit label is expected or allowed.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::AmountMalformed`] — the string is not a valid
    ///   decimal integer.
    /// - [`ValidationError::AmountOutOfRange`] — the value overflows `i64`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::StellarAmount;
    ///
    /// let a = StellarAmount::parse_stroops("1000000000").unwrap();
    /// assert_eq!(a.as_stroops(), 1_000_000_000);
    ///
    /// let b = StellarAmount::parse_stroops("-50000000").unwrap();
    /// assert_eq!(b.as_stroops(), -50_000_000);
    /// ```
    pub fn parse_stroops(s: &str) -> Result<Self, ValidationError> {
        let s = s.trim();

        if s.is_empty() {
            return Err(ValidationError::AmountMalformed {
                input: s.to_owned(),
            });
        }

        let (negative, digits) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else {
            (false, s)
        };

        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ValidationError::AmountMalformed {
                input: s.to_owned(),
            });
        }

        // Parse the absolute value using u64 to accommodate i64::MIN whose
        // absolute value (9223372036854775808) exceeds i64::MAX.
        let abs_val: u64 = parse_digits_to_u64(digits, s)?;

        if negative {
            // The valid range for a negative i64 stroop is
            // -i64::MAX .. i64::MIN (inclusive), i.e. abs_val <= 2^63.
            let min_abs = (i64::MAX as u64) + 1; // |i64::MIN| = 2^63
            if abs_val > min_abs {
                return Err(ValidationError::AmountOutOfRange {
                    amount: s.to_owned(),
                });
            }
            // Safe: abs_val fits in the negative i64 range.
            if abs_val == min_abs {
                Ok(Self::from_stroops(i64::MIN))
            } else {
                Ok(Self::from_stroops(-(abs_val as i64)))
            }
        } else {
            // Positive: abs_val must fit in i64::MAX.
            if abs_val > i64::MAX as u64 {
                return Err(ValidationError::AmountOutOfRange {
                    amount: s.to_owned(),
                });
            }
            Ok(Self::from_stroops(abs_val as i64))
        }
    }

    /// Returns the internal stroop representation.
    ///
    /// This is a zero-cost extraction; no allocation occurs.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::StellarAmount;
    ///
    /// assert_eq!(StellarAmount::from_stroops(42).as_stroops(), 42);
    /// ```
    #[must_use]
    pub const fn as_stroops(self) -> i64 {
        self.stroops
    }

    /// Formats the amount as a decimal XLM string with exactly seven
    /// fractional digits.
    ///
    /// Trailing zeros are preserved for auditability (a human reader can
    /// immediately verify the decimal position without counting digits).
    ///
    /// Negative amounts are prefixed with `-`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::StellarAmount;
    ///
    /// assert_eq!(StellarAmount::from_stroops(1_000_000_000).as_xlm_decimal_string(), "100.0000000");
    /// assert_eq!(StellarAmount::from_stroops(1).as_xlm_decimal_string(), "0.0000001");
    /// assert_eq!(StellarAmount::from_stroops(-50_000_000).as_xlm_decimal_string(), "-5.0000000");
    /// assert_eq!(StellarAmount::from_stroops(0).as_xlm_decimal_string(), "0.0000000");
    /// ```
    #[must_use]
    pub fn as_xlm_decimal_string(self) -> String {
        format_stroops_as_xlm(self.stroops)
    }
}

impl fmt::Display for StellarAmount {
    /// Formats the amount as `"<decimal> XLM"` (e.g. `"100.0000000 XLM"`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} XLM", format_stroops_as_xlm(self.stroops))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// McpAmountArgument — T3 boundary type for MCP tool arguments
// ──────────────────────────────────────────────────────────────────────────────

/// A typed wrapper around [`StellarAmount`] for use as an MCP tool argument.
///
/// The only construction path is `serde::Deserialize`, which routes through
/// [`StellarAmount::parse_with_unit`] internally.  JSON Schema output carries
/// dual-unit metadata (`x-amount-unit`, `x-amount-decimals`) for codegen
/// tooling.
///
/// Every MCP tool argument whose name matches `*_amount`, `*_fee`,
/// `*_starting_balance`, or similar patterns MUST use this type (or
/// `Option<McpAmountArgument>`).
///
/// # Examples
///
/// ```
/// use stellar_agent_core::amount::McpAmountArgument;
///
/// let a: McpAmountArgument = serde_json::from_str(r#""100 XLM""#).unwrap();
/// assert_eq!(a.as_stroops(), 1_000_000_000);
/// ```
#[derive(Clone, Debug)]
pub struct McpAmountArgument(StellarAmount);

impl serde::Serialize for McpAmountArgument {
    /// Serialises as the inner stroop `i64` value.
    ///
    /// The serde round-trip uses the stroop representation on the write path;
    /// the read path (`Deserialize`) goes through `parse_with_unit` (string
    /// form), so a serialized `McpAmountArgument` is not directly
    /// deserializable as `McpAmountArgument` (the round-trip is
    /// `McpAmountArgument` → `i64` (write) → `"100 XLM"` (read)).
    /// This is intentional: the struct is only ever deserialized from
    /// agent-supplied string inputs; serialization is for audit-log / envelope
    /// output where the stroop value is the authoritative representation.
    ///
    // This Serialize impl writes stroops as i64; the Deserialize impl reads a
    // unit-bearing string. The asymmetry is safe because the audit log hashes
    // neither the pre-deserialise string nor the post-deserialise i64. If the
    // audit log is extended to hash-chain entries, revisit this asymmetry: the
    // hash should commit to the agent-supplied string (the integrity-chain
    // principle).
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i64(self.0.as_stroops())
    }
}

impl std::fmt::Display for McpAmountArgument {
    /// Formats the wrapped amount using the inner [`StellarAmount`] Display impl.
    ///
    /// Produces `"<decimal> XLM"` (e.g. `"100.0000000 XLM"`).
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::McpAmountArgument;
    ///
    /// let a: McpAmountArgument = serde_json::from_str(r#""100 XLM""#).unwrap();
    /// assert_eq!(a.to_string(), "100.0000000 XLM");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl McpAmountArgument {
    /// Returns a reference to the wrapped [`StellarAmount`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::McpAmountArgument;
    ///
    /// let a: McpAmountArgument = serde_json::from_str(r#""1 XLM""#).unwrap();
    /// assert_eq!(a.as_stellar_amount().as_stroops(), 10_000_000);
    /// ```
    #[must_use]
    pub fn as_stellar_amount(&self) -> &StellarAmount {
        &self.0
    }

    /// Consumes the wrapper and returns the inner [`StellarAmount`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::McpAmountArgument;
    ///
    /// let a: McpAmountArgument = serde_json::from_str(r#""1 XLM""#).unwrap();
    /// let inner = a.into_stellar_amount();
    /// assert_eq!(inner.as_stroops(), 10_000_000);
    /// ```
    #[must_use]
    pub fn into_stellar_amount(self) -> StellarAmount {
        self.0
    }

    /// Returns the amount in stroops.
    ///
    /// Convenience shortcut equivalent to `self.as_stellar_amount().as_stroops()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::McpAmountArgument;
    ///
    /// let a: McpAmountArgument = serde_json::from_str(r#""0.0000001 XLM""#).unwrap();
    /// assert_eq!(a.as_stroops(), 1);
    /// ```
    #[must_use]
    pub fn as_stroops(&self) -> i64 {
        self.0.as_stroops()
    }
}

impl<'de> serde::Deserialize<'de> for McpAmountArgument {
    /// Deserialises a JSON string as a unit-bearing Stellar amount.
    ///
    /// The string must match the format accepted by
    /// [`StellarAmount::parse_with_unit`]: a decimal number followed by a
    /// space and the unit label `XLM` (case-insensitive).  Bare numbers (e.g.
    /// `"100"`) are rejected with `AmountUnitsRequired`.
    ///
    /// # Errors
    ///
    /// Any error from `parse_with_unit` is forwarded as a serde custom error.
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        StellarAmount::parse_with_unit(&s)
            .map(McpAmountArgument)
            .map_err(serde::de::Error::custom)
    }
}

/// Manual `JsonSchema` implementation that produces the dual-unit schema.
///
/// The generated schema is:
/// ```json
/// {
///   "type": "string",
///   "description": "Stellar amount with explicit unit suffix; e.g. '100 XLM'.",
///   "x-amount-unit": "ui",
///   "x-amount-decimals": 7
/// }
/// ```
///
/// The `x-amount-unit` and `x-amount-decimals` extension fields are consumed by
/// codegen tooling to enforce the T3 boundary at schema-generation time.
impl schemars::JsonSchema for McpAmountArgument {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "McpAmountArgument".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        concat!(module_path!(), "::McpAmountArgument").into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Stellar amount with explicit unit suffix; e.g. '100 XLM'. \
                            For base units (stroops), a dedicated base-unit arg type \
                            is not yet available.",
            "x-amount-unit": "ui",
            "x-amount-decimals": 7
        })
    }
}

// -----------------------------------------------------------------------------
// McpMemoTextArgument - MCP MEMO_TEXT boundary type
// -----------------------------------------------------------------------------

/// Maximum byte length for Stellar `MEMO_TEXT`.
pub const MCP_MEMO_TEXT_MAX_BYTES: usize = 28;

/// Error returned when constructing an [`McpMemoTextArgument`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpMemoTextArgumentError {
    /// The text memo is longer than Stellar's 28-byte `MEMO_TEXT` cap.
    #[error("memo_text must be at most {max} bytes, got {actual} bytes")]
    TooLong {
        /// Maximum allowed UTF-8 byte length.
        max: usize,
        /// Actual UTF-8 byte length.
        actual: usize,
    },
}

/// A typed wrapper around Stellar `MEMO_TEXT` for MCP tool arguments.
///
/// JSON strings are already valid UTF-8 at the serde boundary. This wrapper
/// closes the remaining wire-boundary gap by rejecting strings whose UTF-8 byte
/// length exceeds Stellar's 28-byte `MEMO_TEXT` limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpMemoTextArgument(String);

impl McpMemoTextArgument {
    /// Constructs a memo text argument after enforcing the 28-byte cap.
    ///
    /// # Errors
    ///
    /// Returns [`McpMemoTextArgumentError::TooLong`] when `value` exceeds
    /// [`MCP_MEMO_TEXT_MAX_BYTES`] bytes.
    pub fn new(value: String) -> Result<Self, McpMemoTextArgumentError> {
        let actual = value.len();
        if actual > MCP_MEMO_TEXT_MAX_BYTES {
            return Err(McpMemoTextArgumentError::TooLong {
                max: MCP_MEMO_TEXT_MAX_BYTES,
                actual,
            });
        }
        Ok(Self(value))
    }

    /// Returns the wrapped memo text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for McpMemoTextArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<String> for McpMemoTextArgument {
    type Error = McpMemoTextArgumentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for McpMemoTextArgument {
    type Error = McpMemoTextArgumentError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_owned())
    }
}

impl<'de> serde::Deserialize<'de> for McpMemoTextArgument {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for McpMemoTextArgument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl schemars::JsonSchema for McpMemoTextArgument {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "McpMemoTextArgument".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        concat!(module_path!(), "::McpMemoTextArgument").into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Stellar MEMO_TEXT value encoded as UTF-8, capped at 28 bytes.",
            "maxLength": MCP_MEMO_TEXT_MAX_BYTES
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AnchorAmount — asset-agnostic validated decimal for SEP-24 anchor params
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum total string length accepted by [`AnchorAmount::parse`].
///
/// A limit of 40 characters comfortably exceeds any realistic decimal that an
/// anchor could require while bounding memory and ruling out payload-injection
/// attacks through an oversized field.  The tightest real-world case is 18
/// decimal places of precision plus up to ~20 integer digits, with one dot
/// separator.  40 characters covers that range with room to spare and is the
/// simplest single bound that avoids dual length+precision tracking.
pub const ANCHOR_AMOUNT_MAX_LEN: usize = 40;

/// Maximum decimal places accepted by [`AnchorAmount::parse`].
///
/// Asset-agnostic: USDC has 6, most fiat anchors have 2.  18 decimal places is
/// beyond any known Stellar-connected asset and matches the precision of
/// `uint256` DeFi amounts, giving a wide but bounded ceiling.  The limit
/// prevents infinite-precision strings from bypassing the [`ANCHOR_AMOUNT_MAX_LEN`]
/// cap through an all-fractional input like `"0.000000000000000000123456789"`.
pub const ANCHOR_AMOUNT_MAX_DECIMAL_PLACES: usize = 18;

/// Error type for [`AnchorAmount::parse`].
///
/// Each variant is non-overlapping and maps to a distinct rejection reason so
/// callers can give precise feedback to the operator.
///
/// # Wire codes
///
/// | Variant | `Display` |
/// |---------|-----------|
/// | `Empty` | `"anchor amount must not be empty"` |
/// | `LeadingSign` | `"anchor amount must not have a leading sign"` |
/// | `ScientificNotation` | `"anchor amount must not use scientific notation"` |
/// | `InvalidChar` | `"anchor amount contains an invalid character ..."` |
/// | `MultipleDots` | `"anchor amount contains more than one decimal point"` |
/// | `LeadingDot` | `"anchor amount must not start with a decimal point"` |
/// | `TrailingDot` | `"anchor amount must not end with a decimal point"` |
/// | `Zero` | `"anchor amount must be greater than zero"` |
/// | `TooLong` | `"anchor amount exceeds the maximum length of ... characters"` |
/// | `TooManyDecimals` | `"anchor amount exceeds the maximum precision of ... decimal places"` |
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorAmountError {
    /// The input string is empty.
    #[error("anchor amount must not be empty")]
    Empty,

    /// The input starts with `+` or `-`.
    ///
    /// Only positive amounts are meaningful as SEP-24 deposit hints.  A leading
    /// minus sign would constitute a negative amount; a leading plus sign is
    /// syntactically ambiguous and rejected for grammar simplicity.
    #[error("anchor amount must not have a leading sign ('+' or '-')")]
    LeadingSign,

    /// The input contains an `e` or `E` (scientific notation).
    ///
    /// Scientific notation would require floating-point parsing and makes the
    /// string non-canonical.  Anchors expect a plain decimal string.
    #[error("anchor amount must not use scientific notation ('e'/'E')")]
    ScientificNotation,

    /// The input contains a character that is neither an ASCII digit nor `.`.
    #[error("anchor amount contains an invalid character {ch:?}; only digits and '.' are allowed")]
    InvalidChar {
        /// The first offending character.
        ch: char,
    },

    /// The input contains more than one `.`.
    #[error("anchor amount contains more than one decimal point")]
    MultipleDots,

    /// The input starts with `.` (no integer part before the decimal point).
    ///
    /// `".5"` is rejected because it is ambiguous to humans; use `"0.5"`.
    #[error("anchor amount must not start with a decimal point; use '0.5' instead of '.5'")]
    LeadingDot,

    /// The input ends with `.` (no fractional part after the decimal point).
    ///
    /// `"5."` is rejected because a trailing dot is redundant and inconsistent.
    /// Use `"5"` or `"5.0"`.
    #[error("anchor amount must not end with a decimal point; use '5' or '5.0' instead of '5.'")]
    TrailingDot,

    /// The value is zero or all-zero (e.g. `"0"`, `"0.0"`, `"0.000"`).
    ///
    /// A deposit hint of zero is meaningless to an anchor: the anchor's
    /// interactive UI would pre-fill the amount field with `"0"`, which the user
    /// would have to erase before entering the real amount — worse UX than
    /// omitting the field entirely.
    #[error("anchor amount must be greater than zero; omit the field to let the anchor collect it")]
    Zero,

    /// The total string length exceeds [`ANCHOR_AMOUNT_MAX_LEN`].
    #[error("anchor amount exceeds the maximum length of {max} bytes (got {actual})")]
    TooLong {
        /// Maximum allowed length.
        max: usize,
        /// Actual length of the rejected input.
        actual: usize,
    },

    /// The number of decimal places exceeds [`ANCHOR_AMOUNT_MAX_DECIMAL_PLACES`].
    #[error("anchor amount exceeds the maximum precision of {max} decimal places (got {actual})")]
    TooManyDecimals {
        /// Maximum allowed decimal places.
        max: usize,
        /// Actual number of decimal places in the rejected input.
        actual: usize,
    },
}

/// A validated, asset-agnostic positive decimal string for SEP-24 anchor parameters.
///
/// `AnchorAmount` holds a canonical decimal string that has passed all format
/// validations.  It carries no unit label and imposes no XLM-stroop semantics;
/// the precision is bounded at [`ANCHOR_AMOUNT_MAX_DECIMAL_PLACES`] decimal
/// places (18) to cover any known Stellar-connected asset without imposing the
/// 7-decimal XLM constraint of [`McpAmountArgument`].
///
/// # Why this type and not `McpAmountArgument`
///
/// [`McpAmountArgument`] wraps [`StellarAmount`], which:
///
/// - Requires an explicit `"XLM"` unit label on every input.
/// - Stores the value as `i64` stroops (10^−7 XLM units).
/// - Rejects any input with more than 7 decimal places.
///
/// SEP-24 anchor amounts are denominated in **the deposit asset's precision**,
/// not in XLM stroops.  A USDC deposit hint of `"100.50"` has 2 decimal places
/// and no unit suffix; a `"1e3"` representation or a unit-label requirement
/// would violate the SEP-24 wire contract.  `AnchorAmount` captures exactly
/// this domain without the XLM semantics.
///
/// # Amount-field naming
///
/// Any field whose name contains `amount`, `fee`, `balance`, or `charge` as a
/// `_`-separated token MUST be typed `McpAmountArgument` or
/// `Option<McpAmountArgument>` so the dual-unit metadata is always present. The
/// SEP-24 field is named `deposit_hint` — none of those trigger tokens appear —
/// so `AnchorAmount` is the correct type for it. The field name MUST NOT be
/// changed to contain those trigger words without revisiting that typing rule.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::amount::AnchorAmount;
///
/// // USDC-style (2 dp) — common fiat anchor
/// let a = AnchorAmount::parse("100.50").unwrap();
/// assert_eq!(a.as_str(), "100.50");
/// assert_eq!(a.to_string(), "100.50");
///
/// // Integer amount
/// let b = AnchorAmount::parse("100").unwrap();
/// assert_eq!(b.as_str(), "100");
///
/// // High-precision asset (up to 18 dp)
/// let c = AnchorAmount::parse("0.000000000000000001").unwrap();
/// assert_eq!(c.as_str(), "0.000000000000000001");
/// ```
///
/// # Errors
///
/// [`AnchorAmount::parse`] returns [`AnchorAmountError`] for any rejected input.
/// See the variant documentation on [`AnchorAmountError`] for the full rejection
/// set.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AnchorAmount(String);

impl AnchorAmount {
    /// Parses and validates a positive decimal anchor amount from a string slice.
    ///
    /// The validated canonical string is stored as-is (no normalisation or
    /// rounding is applied).  The caller is responsible for supplying the
    /// intended precision.
    ///
    /// # Validation rules
    ///
    /// 1. The input must not be empty.
    /// 2. No leading sign (`+` or `-`).
    /// 3. No scientific notation (`e` or `E`).
    /// 4. Only ASCII digits and at most one `.` are allowed.
    /// 5. At most one `.` (multiple dots are rejected).
    /// 6. No leading dot (`.5` → use `0.5`).
    /// 7. No trailing dot (`5.` → use `5` or `5.0`).
    /// 8. The value must be greater than zero (all-zero strings are rejected).
    /// 9. Total string length ≤ [`ANCHOR_AMOUNT_MAX_LEN`] (40 characters).
    /// 10. Decimal places ≤ [`ANCHOR_AMOUNT_MAX_DECIMAL_PLACES`] (18).
    ///
    /// Rules 3, 6, 7, and 8 are checked after the character scan so that a
    /// single pass suffices for common inputs.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorAmountError`] — see the variant documentation for each
    /// rejection case.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::{AnchorAmount, AnchorAmountError};
    ///
    /// assert!(AnchorAmount::parse("100.50").is_ok());
    /// assert!(AnchorAmount::parse("1").is_ok());
    ///
    /// assert!(matches!(AnchorAmount::parse(""), Err(AnchorAmountError::Empty)));
    /// assert!(matches!(AnchorAmount::parse("-5"), Err(AnchorAmountError::LeadingSign)));
    /// assert!(matches!(AnchorAmount::parse("1e3"), Err(AnchorAmountError::ScientificNotation)));
    /// assert!(matches!(AnchorAmount::parse("0"), Err(AnchorAmountError::Zero)));
    /// assert!(matches!(AnchorAmount::parse(".5"), Err(AnchorAmountError::LeadingDot)));
    /// assert!(matches!(AnchorAmount::parse("5."), Err(AnchorAmountError::TrailingDot)));
    /// assert!(matches!(AnchorAmount::parse("1.2.3"), Err(AnchorAmountError::MultipleDots)));
    /// ```
    pub fn parse(s: &str) -> Result<Self, AnchorAmountError> {
        // Rule 1: not empty.
        if s.is_empty() {
            return Err(AnchorAmountError::Empty);
        }

        // Rule 9: total length bound (checked before full scan to reject garbage fast).
        if s.len() > ANCHOR_AMOUNT_MAX_LEN {
            return Err(AnchorAmountError::TooLong {
                max: ANCHOR_AMOUNT_MAX_LEN,
                actual: s.len(),
            });
        }

        // Rule 2: no leading sign.
        if s.starts_with('+') || s.starts_with('-') {
            return Err(AnchorAmountError::LeadingSign);
        }

        // Rules 3, 4, 5 — single character scan.
        // Track dot count and position for rules 5, 6, 7.
        let mut dot_count: usize = 0;
        let mut last_is_dot = false;
        for ch in s.chars() {
            match ch {
                'e' | 'E' => return Err(AnchorAmountError::ScientificNotation),
                '.' => {
                    dot_count += 1;
                    if dot_count > 1 {
                        return Err(AnchorAmountError::MultipleDots);
                    }
                    last_is_dot = true;
                }
                '0'..='9' => {
                    last_is_dot = false;
                }
                other => {
                    return Err(AnchorAmountError::InvalidChar { ch: other });
                }
            }
        }

        // Rule 6: leading dot.
        // INVARIANT: s is non-empty (checked at top) and s.len() ≤ 40 (ASCII only here).
        if s.starts_with('.') {
            return Err(AnchorAmountError::LeadingDot);
        }

        // Rule 7: trailing dot.
        if last_is_dot {
            return Err(AnchorAmountError::TrailingDot);
        }

        // Rule 10: decimal precision bound.
        if dot_count > 0 {
            // INVARIANT: we verified exactly one '.' exists in s.
            let frac_part = s.split('.').nth(1).unwrap_or("");
            let dp = frac_part.len();
            if dp > ANCHOR_AMOUNT_MAX_DECIMAL_PLACES {
                return Err(AnchorAmountError::TooManyDecimals {
                    max: ANCHOR_AMOUNT_MAX_DECIMAL_PLACES,
                    actual: dp,
                });
            }
        }

        // Rule 8: value must be greater than zero.
        // The string passes all character checks (digits + optional single dot,
        // no leading/trailing dot).  Check whether every digit is '0'.
        let is_zero = s.bytes().filter(|b| b.is_ascii_digit()).all(|b| b == b'0');
        if is_zero {
            return Err(AnchorAmountError::Zero);
        }

        Ok(Self(s.to_owned()))
    }

    /// Returns the validated canonical decimal string.
    ///
    /// The returned string is the exact input that was accepted by [`Self::parse`];
    /// no normalisation (trailing-zero stripping, rounding, or re-formatting) is
    /// applied.  This string is appropriate for use as the SEP-24 wire `amount`
    /// form parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::AnchorAmount;
    ///
    /// let a = AnchorAmount::parse("100.50").unwrap();
    /// assert_eq!(a.as_str(), "100.50");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the owned decimal string.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::AnchorAmount;
    ///
    /// let a = AnchorAmount::parse("100.50").unwrap();
    /// assert_eq!(a.into_string(), "100.50");
    /// ```
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for AnchorAmount {
    /// Formats the anchor amount as the validated decimal string.
    ///
    /// Identical to [`AnchorAmount::as_str`]; provided so `format!("{}", a)` and
    /// `to_string()` produce the canonical wire form without an explicit
    /// `.as_str()` call.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::amount::AnchorAmount;
    ///
    /// let a = AnchorAmount::parse("100.50").unwrap();
    /// assert_eq!(a.to_string(), "100.50");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for AnchorAmount {
    /// Deserialises a JSON string as a validated positive anchor amount.
    ///
    /// The string must satisfy all rules of [`AnchorAmount::parse`].  Invalid
    /// strings produce a serde custom error carrying the [`AnchorAmountError`]
    /// message.
    ///
    /// # Errors
    ///
    /// Any [`AnchorAmountError`] from `parse` is forwarded as a serde custom
    /// error.
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for AnchorAmount {
    /// Serialises as the validated decimal string.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl schemars::JsonSchema for AnchorAmount {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AnchorAmount".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        concat!(module_path!(), "::AnchorAmount").into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Positive decimal amount in the deposit asset's precision (e.g. '100.50' \
                            for USDC, '100' for fiat).  Asset-agnostic: no XLM unit label required \
                            and no 7-decimal stroop constraint.  Supply the value denominated in \
                            asset_code units.  Omit the field to let the anchor collect the amount \
                            in its interactive UI.",
            // Advisory superset of `AnchorAmount::parse`: structural shape only
            // (>=1 leading digit, optional single dot + 1..=18 fractional digits,
            // no sign/exponent). It intentionally does NOT encode the all-zero
            // rejection (a regex cannot express "not all-zero" cleanly) — `parse`
            // is the authoritative validator and additionally rejects all-zero
            // values. Kept a SUPERSET (never narrower than `parse`) so a
            // schema-validating client never pre-rejects an amount the wallet
            // would accept (e.g. "0.50", "100.00").
            "pattern": "^[0-9]+(\\.[0-9]{1,18})?$",
            "maxLength": ANCHOR_AMOUNT_MAX_LEN
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the string looks approximately like a bare decimal
/// number (digits plus optional leading `-` and any number of `.`
/// characters), without any alphabetic bytes.
///
/// Used only to disambiguate `AmountUnitsRequired` (input is plausibly a
/// number with a missing unit label) from `AmountMalformed` (input is
/// clearly not numeric).  The looseness around dots is deliberate:
/// `"1.2.3"` would be a malformed number, but returning `true` here
/// still routes the caller to the more specific "you forgot the unit"
/// error rather than a generic "malformed" one.  Callers who need a
/// stricter numeric check must run their own validation.
fn looks_like_bare_number(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let s = s.strip_prefix('-').unwrap_or(s);
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// Formats `stroops` as a fixed-seven-decimal-place XLM string.
///
/// Works entirely with integer arithmetic; no floating-point.  Handles
/// `i64::MIN` correctly via `i64::unsigned_abs` (stdlib-blessed idiom that
/// returns the mathematical absolute value as a `u64`, never overflowing).
fn format_stroops_as_xlm(stroops: i64) -> String {
    let negative = stroops < 0;
    let abs: u64 = stroops.unsigned_abs();

    let whole = abs / (STROOPS_PER_XLM as u64);
    let frac = abs % (STROOPS_PER_XLM as u64);

    if negative {
        format!("-{whole}.{frac:07}")
    } else {
        format!("{whole}.{frac:07}")
    }
}

/// Parses a signed decimal string into stroops, validating precision and range.
///
/// `original` is the full original input string used in error messages.
fn parse_decimal_to_stroops(
    numeric_str: &str,
    original: &str,
) -> Result<StellarAmount, ValidationError> {
    if numeric_str.is_empty() {
        return Err(ValidationError::AmountMalformed {
            input: original.to_owned(),
        });
    }

    // Handle leading sign (only `-` is allowed; `+` is rejected).
    let (negative, unsigned_str) = if let Some(rest) = numeric_str.strip_prefix('-') {
        (true, rest)
    } else if numeric_str.starts_with('+') {
        return Err(ValidationError::AmountMalformed {
            input: original.to_owned(),
        });
    } else {
        (false, numeric_str)
    };

    if unsigned_str.is_empty() {
        return Err(ValidationError::AmountMalformed {
            input: original.to_owned(),
        });
    }

    // Split on `.`.  At most one `.` is allowed.
    let (integer_part, frac_part_raw) = match unsigned_str.find('.') {
        None => (unsigned_str, ""),
        Some(pos) => {
            let after_dot = &unsigned_str[pos + 1..];
            // Reject a second `.` anywhere in the remaining string.
            if after_dot.contains('.') {
                return Err(ValidationError::AmountMalformed {
                    input: original.to_owned(),
                });
            }
            (&unsigned_str[..pos], after_dot)
        }
    };

    // Validate that both halves contain only ASCII digits.
    if !integer_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part_raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ValidationError::AmountMalformed {
            input: original.to_owned(),
        });
    }

    // Reject if integer part is empty (e.g. `".5 XLM"` has no integer part).
    if integer_part.is_empty() {
        return Err(ValidationError::AmountMalformed {
            input: original.to_owned(),
        });
    }

    // Check fractional precision.
    if frac_part_raw.len() > STELLAR_DECIMALS as usize {
        return Err(ValidationError::AmountPrecisionExceeded {
            amount: original.to_owned(),
        });
    }

    // Pad fractional part to exactly 7 digits on the right.
    let frac_padded = {
        let mut s = String::from(frac_part_raw);
        while s.len() < STELLAR_DECIMALS as usize {
            s.push('0');
        }
        s
    };

    // Compute absolute stroop value: integer_part * 10^7 + frac_padded.
    // Use checked arithmetic throughout.

    // Parse integer part.
    let int_val: i64 = parse_digits_to_i64(integer_part, original)?;

    // Parse fractional part (already padded to 7 digits).
    let frac_val: i64 = parse_digits_to_i64(&frac_padded, original)?;

    // Combine: int_val * STROOPS_PER_XLM + frac_val.
    let abs_stroops = int_val
        .checked_mul(STROOPS_PER_XLM)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| ValidationError::AmountOutOfRange {
            amount: original.to_owned(),
        })?;

    if negative {
        abs_stroops
            .checked_neg()
            .ok_or_else(|| ValidationError::AmountOutOfRange {
                amount: original.to_owned(),
            })
            .map(StellarAmount::from_stroops)
    } else {
        Ok(StellarAmount::from_stroops(abs_stroops))
    }
}

/// Parses a string of ASCII decimal digits into an `i64`.
///
/// Returns [`ValidationError::AmountOutOfRange`] if the value exceeds
/// `i64::MAX` and [`ValidationError::AmountMalformed`] if any non-digit
/// character is encountered.  `original` is the full original input used
/// in error messages.
///
/// Note: does not accept values for `i64::MIN` (whose absolute value exceeds
/// `i64::MAX`).  For `parse_stroops` which must handle `i64::MIN`, use
/// [`parse_digits_to_u64`] instead.
fn parse_digits_to_i64(digits: &str, original: &str) -> Result<i64, ValidationError> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ValidationError::AmountMalformed {
            input: original.to_owned(),
        });
    }

    // Use i128 accumulation to detect overflow past i64::MAX cleanly.
    let mut acc: i128 = 0;
    for b in digits.bytes() {
        let digit = i128::from(b - b'0');
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| ValidationError::AmountOutOfRange {
                amount: original.to_owned(),
            })?;
        // Reject once we exceed i64::MAX to give a good error before
        // converting back to i64 at the end.
        if acc > i128::from(i64::MAX) {
            return Err(ValidationError::AmountOutOfRange {
                amount: original.to_owned(),
            });
        }
    }

    // Safe: we've guarded acc <= i64::MAX above.
    Ok(acc as i64)
}

/// Parses a string of ASCII decimal digits into a `u64`.
///
/// Returns [`ValidationError::AmountOutOfRange`] if the value exceeds
/// `u64::MAX` and [`ValidationError::AmountMalformed`] if any non-digit
/// character is encountered.  `original` is the full original input used
/// in error messages.
///
/// Used by [`StellarAmount::parse_stroops`] to handle `i64::MIN` whose
/// absolute value (2^63) exceeds `i64::MAX` (2^63 - 1) but fits in `u64`.
fn parse_digits_to_u64(digits: &str, original: &str) -> Result<u64, ValidationError> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ValidationError::AmountMalformed {
            input: original.to_owned(),
        });
    }

    // Use u128 accumulation to detect overflow past u64::MAX cleanly.
    let mut acc: u128 = 0;
    for b in digits.bytes() {
        let digit = u128::from(b - b'0');
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| ValidationError::AmountOutOfRange {
                amount: original.to_owned(),
            })?;
        if acc > u128::from(u64::MAX) {
            return Err(ValidationError::AmountOutOfRange {
                amount: original.to_owned(),
            });
        }
    }

    // Safe: we've guarded acc <= u64::MAX above.
    Ok(acc as u64)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test-only; panics on failure are the correct test assertion mechanism"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::error::ValidationError;

    // ── Acceptance criteria ───────────────────────────────────────────────────

    /// Criterion 1: bare number is rejected as AmountUnitsRequired.
    #[test]
    fn bare_number_is_amount_units_required() {
        assert!(
            matches!(
                StellarAmount::parse_with_unit("100"),
                Err(ValidationError::AmountUnitsRequired),
            ),
            "expected AmountUnitsRequired for bare '100'"
        );
    }

    /// Criterion 2: 100 XLM == 1_000_000_000 stroops; round-trip with
    /// parse_stroops.
    #[test]
    fn hundred_xlm_equals_one_billion_stroops() {
        let by_unit =
            StellarAmount::parse_with_unit("100 XLM").expect("100 XLM should parse successfully");
        let by_stroops = StellarAmount::parse_stroops("1000000000")
            .expect("1000000000 stroops should parse successfully");
        assert_eq!(by_unit, StellarAmount::from_stroops(1_000_000_000));
        assert_eq!(by_unit, by_stroops);
    }

    /// Criterion 3a: 0.0000001 XLM == 1 stroop (boundary: seven fractional digits).
    #[test]
    fn seven_decimal_places_accepted_as_one_stroop() {
        let amt = StellarAmount::parse_with_unit("0.0000001 XLM")
            .expect("0.0000001 XLM (7 decimals) should be accepted");
        assert_eq!(amt.as_stroops(), 1);
    }

    /// Criterion 3b: 0.00000001 XLM has 8 fractional digits — rejected as
    /// AmountPrecisionExceeded.
    #[test]
    fn eight_decimal_places_rejected_as_precision_exceeded() {
        assert!(
            matches!(
                StellarAmount::parse_with_unit("0.00000001 XLM"),
                Err(ValidationError::AmountPrecisionExceeded { .. }),
            ),
            "expected AmountPrecisionExceeded for '0.00000001 XLM'"
        );
    }

    /// Criterion 4: 0.001 XLM == 10_000 stroops (base-fee case).
    #[test]
    fn point_zero_zero_one_xlm_is_ten_thousand_stroops() {
        let amt = StellarAmount::parse_with_unit("0.001 XLM")
            .expect("0.001 XLM should parse successfully");
        assert_eq!(amt, StellarAmount::from_stroops(10_000));
    }

    // ── Unit-case insensitivity ───────────────────────────────────────────────

    #[test]
    fn unit_case_insensitive() {
        let expected = StellarAmount::from_stroops(1_000_000_000);
        for input in &["100 xlm", "100 Xlm", "100 XLM", "100 xLm", "100 XlM"] {
            assert_eq!(
                StellarAmount::parse_with_unit(input)
                    .unwrap_or_else(|e| panic!("failed for '{input}': {e}")),
                expected,
                "mismatch for '{input}'"
            );
        }
    }

    // ── Whitespace flexibility ────────────────────────────────────────────────

    #[test]
    fn flexible_whitespace_between_number_and_unit() {
        let expected = StellarAmount::from_stroops(1_000_000_000);
        for input in &["100 XLM", "100  XLM", "100\tXLM", "100   XLM"] {
            assert_eq!(
                StellarAmount::parse_with_unit(input)
                    .unwrap_or_else(|e| panic!("failed for '{input}': {e}")),
                expected,
                "mismatch for '{input}'"
            );
        }
    }

    /// Ensure at least one whitespace character is mandatory between number
    /// and unit: "100XLM" must not parse.
    #[test]
    fn no_whitespace_between_number_and_unit_is_malformed() {
        assert!(
            matches!(
                StellarAmount::parse_with_unit("100XLM"),
                Err(ValidationError::AmountMalformed { .. }),
            ),
            "expected AmountMalformed for '100XLM'"
        );
    }

    // ── Negative amounts ─────────────────────────────────────────────────────

    #[test]
    fn negative_xlm_accepted_with_correct_stroops() {
        let amt =
            StellarAmount::parse_with_unit("-5 XLM").expect("-5 XLM should parse successfully");
        assert_eq!(amt.as_stroops(), -50_000_000);
    }

    #[test]
    fn negative_xlm_display_has_minus_prefix() {
        let amt = StellarAmount::from_stroops(-50_000_000);
        assert_eq!(amt.as_xlm_decimal_string(), "-5.0000000");
        assert_eq!(amt.to_string(), "-5.0000000 XLM");
    }

    #[test]
    fn negative_stroops_parse_stroops() {
        let amt = StellarAmount::parse_stroops("-50000000")
            .expect("-50000000 stroops should parse successfully");
        assert_eq!(amt.as_stroops(), -50_000_000);
    }

    // ── Display / as_xlm_decimal_string ──────────────────────────────────────

    #[test]
    fn display_always_seven_decimal_places() {
        let cases: &[(i64, &str)] = &[
            (0, "0.0000000 XLM"),
            (1, "0.0000001 XLM"),
            (10_000_000, "1.0000000 XLM"),
            (1_000_000_000, "100.0000000 XLM"),
            (10_050_000, "1.0050000 XLM"),
            (-50_000_000, "-5.0000000 XLM"),
        ];
        for (stroops, expected) in cases {
            let amt = StellarAmount::from_stroops(*stroops);
            assert_eq!(
                amt.to_string(),
                *expected,
                "display mismatch for {stroops} stroops"
            );
        }
    }

    /// Pins the exact decimal string at the `i64` extremes so no caller can
    /// regress `as_xlm_decimal_string` back to lossy `f64` division, which
    /// loses precision well below this magnitude (an `f64` mantissa carries
    /// only ~15-17 significant decimal digits; these stroop counts need 19).
    #[test]
    fn as_xlm_decimal_string_exact_at_i64_extremes() {
        assert_eq!(
            StellarAmount::from_stroops(i64::MAX).as_xlm_decimal_string(),
            "922337203685.4775807"
        );
        assert_eq!(
            StellarAmount::from_stroops(i64::MIN).as_xlm_decimal_string(),
            "-922337203685.4775808"
        );
    }

    #[test]
    fn as_xlm_decimal_string_matches_display_without_unit() {
        for stroops in &[
            0i64,
            1,
            100,
            10_000_000,
            -1,
            -10_000_000,
            i64::MAX,
            i64::MIN,
        ] {
            let amt = StellarAmount::from_stroops(*stroops);
            let decimal = amt.as_xlm_decimal_string();
            let display = amt.to_string();
            assert!(
                display.starts_with(&decimal),
                "Display '{display}' should start with decimal '{decimal}'"
            );
            assert!(
                display.ends_with(" XLM"),
                "Display '{display}' should end with ' XLM'"
            );
        }
    }

    // ── Round-trip tests ──────────────────────────────────────────────────────

    #[test]
    fn round_trip_xlm_string_via_stroop_equality() {
        let inputs: &[(&str, i64)] = &[
            ("0 XLM", 0),
            ("1 XLM", 10_000_000),
            ("100 XLM", 1_000_000_000),
            ("0.5 XLM", 5_000_000),
            ("0.0000001 XLM", 1),
            ("0.001 XLM", 10_000),
            ("0.1234567 XLM", 1_234_567),
        ];
        for (input, expected_stroops) in inputs {
            let amt = StellarAmount::parse_with_unit(input)
                .unwrap_or_else(|e| panic!("parse failed for '{input}': {e}"));
            assert_eq!(
                amt.as_stroops(),
                *expected_stroops,
                "stroop mismatch for '{input}'"
            );
        }
    }

    #[test]
    fn round_trip_parse_stroops_identity() {
        let values: &[i64] = &[
            0,
            1,
            100,
            10_000,
            10_000_000,
            1_000_000_000,
            -1,
            -10_000_000,
            i64::MAX,
            i64::MIN,
        ];
        for &v in values {
            let s = v.to_string();
            let result = StellarAmount::parse_stroops(&s)
                .unwrap_or_else(|e| panic!("parse_stroops failed for {v}: {e}"));
            assert_eq!(result.as_stroops(), v, "round-trip failed for {v}");
        }
    }

    // ── Error variant exhaustiveness ──────────────────────────────────────────

    /// Tests that every new ValidationError variant added by this module has
    /// the correct code() string, extending the round-trip table from error.rs.
    #[test]
    #[allow(
        clippy::panic,
        reason = "test-only panic in an unreachable match arm; documented in the arm body"
    )]
    fn amount_error_codes() {
        use crate::error::WalletError;

        let malformed = WalletError::Validation(ValidationError::AmountMalformed {
            input: "abc".to_owned(),
        });
        assert_eq!(malformed.code(), "validation.amount_malformed");

        let out_of_range = WalletError::Validation(ValidationError::AmountOutOfRange {
            amount: "99999999999999999999".to_owned(),
        });
        assert_eq!(out_of_range.code(), "validation.amount_out_of_range");
    }

    // ── Overflow / out-of-range ───────────────────────────────────────────────

    #[test]
    fn parse_stroops_overflow_is_out_of_range() {
        assert!(
            matches!(
                StellarAmount::parse_stroops("99999999999999999999"),
                Err(ValidationError::AmountOutOfRange { .. }),
            ),
            "expected AmountOutOfRange for '99999999999999999999'"
        );
    }

    #[test]
    fn parse_with_unit_xlm_overflow_is_out_of_range() {
        assert!(
            matches!(
                StellarAmount::parse_with_unit("99999999999999999999 XLM"),
                Err(ValidationError::AmountOutOfRange { .. }),
            ),
            "expected AmountOutOfRange for '99999999999999999999 XLM'"
        );
    }

    #[test]
    fn parse_stroops_i64_min_special_case() {
        // i64::MIN = -9223372036854775808; this is a valid stroop value.
        let s = i64::MIN.to_string();
        let result = StellarAmount::parse_stroops(&s)
            .unwrap_or_else(|e| panic!("i64::MIN should parse: {e}"));
        assert_eq!(result.as_stroops(), i64::MIN);
    }

    #[test]
    fn parse_with_unit_xlm_for_i64_min_is_out_of_range() {
        // The XLM decimal rendering of `i64::MIN` stroops is
        // "-922337203685.4775808 XLM".  Round-tripping it back via
        // parse_with_unit overflows during int_part * STROOPS_PER_XLM
        // (the absolute value exceeds i64::MAX by 1), so the parser
        // MUST reject it with AmountOutOfRange rather than silently
        // wrapping.  This locks the boundary that prop_xlm_string_round_trip
        // excludes via `prop_assume!`.
        let formatted = format_stroops_as_xlm(i64::MIN);
        let input = format!("{formatted} XLM");
        assert!(
            matches!(
                StellarAmount::parse_with_unit(&input),
                Err(ValidationError::AmountOutOfRange { .. }),
            ),
            "expected AmountOutOfRange for i64::MIN XLM round-trip: got {:?}",
            StellarAmount::parse_with_unit(&input)
        );
    }

    // ── Invalid inputs ────────────────────────────────────────────────────────

    #[test]
    fn invalid_inputs_for_parse_with_unit() {
        // Note: "100. XLM" (trailing dot, empty fractional part) is VALID and
        // parses as 100 XLM; it is deliberately excluded from this list.
        let malformed_cases: &[&str] = &[
            "abc XLM",
            "100 BTC",
            "100..5 XLM",
            "",
            " ",
            "XLM",
            "+100 XLM",
        ];
        for &input in malformed_cases {
            let result = StellarAmount::parse_with_unit(input);
            assert!(
                result.is_err(),
                "expected error for input '{input}', got Ok({:?})",
                result.ok()
            );
        }
    }

    #[test]
    fn amount_malformed_input_field_holds_the_raw_input() {
        // Regression guard: the AmountMalformed.input field must carry the
        // full raw input (not just the numeric portion) so callers rendering
        // error messages see what the user actually typed.
        let result = StellarAmount::parse_with_unit("abc XLM");
        match result {
            Err(ValidationError::AmountMalformed { input }) => {
                assert_eq!(input, "abc XLM", "input should be the raw full string");
            }
            other => panic!("expected AmountMalformed, got {other:?}"),
        }
    }

    #[test]
    fn bare_number_inputs_give_correct_error() {
        // "100" and "100.0" are bare numbers with no unit label.
        for input in &["100", "100.0", "-5"] {
            assert!(
                matches!(
                    StellarAmount::parse_with_unit(input),
                    Err(ValidationError::AmountUnitsRequired),
                ),
                "expected AmountUnitsRequired for bare '{input}'"
            );
        }
    }

    #[test]
    fn plus_sign_is_malformed() {
        assert!(
            matches!(
                StellarAmount::parse_with_unit("+100 XLM"),
                Err(ValidationError::AmountMalformed { .. }),
            ),
            "expected AmountMalformed for '+100 XLM'"
        );
    }

    #[test]
    fn wrong_unit_is_malformed() {
        for input in &["100 BTC", "100 USDC", "100 EUR"] {
            assert!(
                matches!(
                    StellarAmount::parse_with_unit(input),
                    Err(ValidationError::AmountMalformed { .. }),
                ),
                "expected AmountMalformed for '{input}'"
            );
        }
    }

    #[test]
    fn double_dot_is_malformed() {
        assert!(
            matches!(
                StellarAmount::parse_with_unit("100..5 XLM"),
                Err(ValidationError::AmountMalformed { .. }),
            ),
            "expected AmountMalformed for '100..5 XLM'"
        );
    }

    #[test]
    fn empty_string_is_malformed() {
        assert!(matches!(
            StellarAmount::parse_with_unit(""),
            Err(ValidationError::AmountMalformed { .. }),
        ));
        assert!(matches!(
            StellarAmount::parse_with_unit(" "),
            Err(ValidationError::AmountMalformed { .. })
                | Err(ValidationError::AmountUnitsRequired),
        ));
    }

    #[test]
    fn xlm_alone_is_malformed() {
        // "XLM" with no numeric part before it.
        assert!(
            matches!(
                StellarAmount::parse_with_unit("XLM"),
                Err(ValidationError::AmountMalformed { .. }),
            ),
            "expected AmountMalformed for 'XLM'"
        );
    }

    // ── Fractional-padding edge cases ─────────────────────────────────────────

    #[test]
    fn fractional_part_is_padded_correctly() {
        // "100.5 XLM" -> frac "5" padded to "5000000" -> 5_000_000 stroops for frac
        // total: 100 * 10_000_000 + 5_000_000 = 1_005_000_000
        let amt = StellarAmount::parse_with_unit("100.5 XLM").expect("100.5 XLM should parse");
        assert_eq!(amt.as_stroops(), 1_005_000_000);
    }

    #[test]
    fn zero_fractional_part() {
        let amt = StellarAmount::parse_with_unit("0 XLM").expect("0 XLM should parse");
        assert_eq!(amt.as_stroops(), 0);
        assert_eq!(amt.as_xlm_decimal_string(), "0.0000000");
    }

    #[test]
    fn exactly_seven_fractional_digits() {
        // "1.1234567 XLM" -> 1*10_000_000 + 1_234_567 = 11_234_567
        let amt = StellarAmount::parse_with_unit("1.1234567 XLM")
            .expect("exactly 7 fractional digits should be accepted");
        assert_eq!(amt.as_stroops(), 11_234_567);
    }

    // ── i64::MIN edge case for format_stroops_as_xlm ─────────────────────────

    #[test]
    fn format_i64_min_does_not_panic() {
        // i64::MIN cannot be negated as i64; the formatter must handle it
        // without panicking.
        let amt = StellarAmount::from_stroops(i64::MIN);
        let s = amt.as_xlm_decimal_string();
        assert!(
            s.starts_with('-'),
            "i64::MIN should format as negative: {s}"
        );
    }

    // ── Proptest round-trips ──────────────────────────────────────────────────

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(256))]

        /// For any i64, from_stroops(n).as_stroops() == n.
        #[test]
        fn prop_from_stroops_identity(n in proptest::num::i64::ANY) {
            let amt = StellarAmount::from_stroops(n);
            prop_assert_eq!(amt.as_stroops(), n);
        }

        /// For any valid i64, parse_stroops(&n.to_string()) round-trips.
        #[test]
        fn prop_parse_stroops_round_trip(n in proptest::num::i64::ANY) {
            let s = n.to_string();
            let parsed = StellarAmount::parse_stroops(&s);
            prop_assert!(parsed.is_ok(), "parse_stroops failed for {n}: {:?}", parsed.err());
            prop_assert_eq!(parsed.unwrap().as_stroops(), n);
        }

        /// For any i64 stroop value (excluding i64::MIN), formatting and
        /// re-parsing via as_xlm_decimal_string + " XLM" recovers the original
        /// stroop value.
        ///
        /// i64::MIN is excluded because its absolute value (2^63) exceeds
        /// i64::MAX (2^63 - 1), so the XLM decimal representation overflows
        /// during re-parsing.  In practice Stellar amounts never approach
        /// i64::MIN (protocol maximum supply is well under i64::MAX stroops).
        #[test]
        fn prop_xlm_string_round_trip(n in proptest::num::i64::ANY) {
            // i64::MIN cannot round-trip through parse_with_unit (its absolute
            // value overflows i64); skip it here.  The parse_stroops round-trip
            // (prop_parse_stroops_round_trip) covers i64::MIN.
            prop_assume!(n != i64::MIN);

            let amt = StellarAmount::from_stroops(n);
            let s = format!("{} XLM", amt.as_xlm_decimal_string());
            let parsed = StellarAmount::parse_with_unit(&s);
            prop_assert!(
                parsed.is_ok(),
                "re-parse of formatted amount failed for {n}: string='{s}', err={:?}",
                parsed.err()
            );
            prop_assert_eq!(
                parsed.unwrap().as_stroops(),
                n,
                "round-trip stroop mismatch for {} (string='{}')",
                n,
                s
            );
        }
    }

    // ── McpAmountArgument Display ─────────────────────────────────────────────

    /// Display output of a parsed wrapper preserves the unit form.
    #[test]
    fn mcp_amount_arg_display_preserves_unit_form() {
        let a: McpAmountArgument = serde_json::from_str(r#""100 XLM""#).expect("parse");
        assert_eq!(a.to_string(), "100.0000000 XLM");
    }

    /// Display output for 1 stroop.
    #[test]
    fn mcp_amount_arg_display_one_stroop() {
        let a: McpAmountArgument = serde_json::from_str(r#""0.0000001 XLM""#).expect("parse");
        assert_eq!(a.to_string(), "0.0000001 XLM");
    }

    // ── McpAmountArgument tests ───────────────────────────────────────────────

    /// Bare integer (no unit) is rejected.
    #[test]
    fn mcp_amount_arg_bare_integer_rejected() {
        let result = serde_json::from_str::<McpAmountArgument>(r#""100""#);
        assert!(result.is_err(), "bare integer must be rejected: {result:?}");
    }

    /// Missing unit (trailing space with nothing after) is rejected.
    #[test]
    fn mcp_amount_arg_missing_unit_rejected() {
        let result = serde_json::from_str::<McpAmountArgument>(r#""100 ""#);
        assert!(result.is_err(), "missing unit must be rejected: {result:?}");
    }

    /// Valid 100 XLM deserialises to 1_000_000_000 stroops.
    #[test]
    fn mcp_amount_arg_valid_100_xlm() {
        let a: McpAmountArgument =
            serde_json::from_str(r#""100 XLM""#).expect("100 XLM must parse");
        assert_eq!(a.as_stroops(), 1_000_000_000);
    }

    /// Decimal: 0.0000001 XLM = 1 stroop.
    #[test]
    fn mcp_amount_arg_one_stroop() {
        let a: McpAmountArgument =
            serde_json::from_str(r#""0.0000001 XLM""#).expect("0.0000001 XLM must parse");
        assert_eq!(a.as_stroops(), 1);
    }

    /// Negative: -5 XLM = -50_000_000 stroops.
    #[test]
    fn mcp_amount_arg_negative() {
        let a: McpAmountArgument = serde_json::from_str(r#""-5 XLM""#).expect("-5 XLM must parse");
        assert_eq!(a.as_stroops(), -50_000_000);
    }

    /// Oversize amount overflows and is rejected.
    ///
    /// i64::MAX is 9_223_372_036_854_775_807 stroops = ~922_337_203_685 XLM.
    /// 923 trillion XLM overflows i64.
    #[test]
    fn mcp_amount_arg_oversize_rejected() {
        let result = serde_json::from_str::<McpAmountArgument>(r#""922337203686 XLM""#);
        assert!(
            result.is_err(),
            "oversize amount must be rejected: {result:?}"
        );
    }

    /// `JsonSchema` output carries the dual-unit extension fields.
    #[test]
    fn mcp_amount_arg_schema_has_dual_unit_metadata() {
        let schema =
            schemars::SchemaGenerator::default().into_root_schema_for::<McpAmountArgument>();
        let json = serde_json::to_string(&schema).expect("schema serialisation");
        assert!(
            json.contains("x-amount-unit"),
            "schema must carry x-amount-unit: {json}"
        );
        assert!(json.contains("ui"), "x-amount-unit must be 'ui': {json}");
        assert!(
            json.contains("x-amount-decimals"),
            "schema must carry x-amount-decimals: {json}"
        );
        assert!(
            json.contains("\"x-amount-decimals\""),
            "x-amount-decimals key must be present: {json}"
        );
    }

    /// Serde round-trip: serialize (via Display → Serialize) then deserialize.
    #[test]
    fn mcp_amount_arg_serde_round_trip() {
        let original: McpAmountArgument = serde_json::from_str(r#""100 XLM""#).expect("parse");
        let serialised = serde_json::to_string(&original).expect("serialise");
        // Serialized form is the wrapped StellarAmount's Serialize output
        // which yields the stroop i64.
        let stroops: i64 = serde_json::from_str(&serialised).expect("deserialise stroops");
        assert_eq!(stroops, original.as_stroops());
    }

    /// `as_stellar_amount` returns the wrapped amount.
    #[test]
    fn mcp_amount_arg_as_stellar_amount() {
        let a: McpAmountArgument = serde_json::from_str(r#""1 XLM""#).expect("parse");
        assert_eq!(a.as_stellar_amount().as_stroops(), 10_000_000);
    }

    /// `into_stellar_amount` consumes the wrapper.
    #[test]
    fn mcp_amount_arg_into_stellar_amount() {
        let a: McpAmountArgument = serde_json::from_str(r#""1 XLM""#).expect("parse");
        let inner = a.into_stellar_amount();
        assert_eq!(inner.as_stroops(), 10_000_000);
    }

    // ── AnchorAmount tests ────────────────────────────────────────────────────

    /// Acceptance: USDC-style 2-decimal-place amounts are accepted.
    #[test]
    fn anchor_amount_usdc_style_accepted() {
        let a = AnchorAmount::parse("100.50").expect("100.50 should be accepted");
        assert_eq!(
            a.as_str(),
            "100.50",
            "as_str should return the canonical input"
        );
        assert_eq!(a.to_string(), "100.50", "Display should match as_str");
    }

    /// Acceptance: fiat-style 2-decimal-place amounts are accepted.
    #[test]
    fn anchor_amount_fiat_style_accepted() {
        let a = AnchorAmount::parse("100.00").expect("100.00 should be accepted");
        assert_eq!(a.as_str(), "100.00");
    }

    /// Acceptance: integer (no decimal point) amounts are accepted.
    #[test]
    fn anchor_amount_integer_accepted() {
        let a = AnchorAmount::parse("100").expect("100 should be accepted");
        assert_eq!(a.as_str(), "100");
    }

    /// Acceptance: high-precision amounts within the 18 dp bound are accepted.
    #[test]
    fn anchor_amount_high_precision_accepted() {
        // 18 decimal places — the exact limit.
        let a = AnchorAmount::parse("0.000000000000000001")
            .expect("18 dp should be accepted (at the limit)");
        assert_eq!(a.as_str(), "0.000000000000000001");
    }

    /// Rejection: empty string.
    #[test]
    fn anchor_amount_empty_rejected() {
        let err = AnchorAmount::parse("").expect_err("empty must be rejected");
        assert!(
            matches!(err, AnchorAmountError::Empty),
            "expected Empty, got {err:?}"
        );
    }

    /// Rejection: negative sign.
    #[test]
    fn anchor_amount_negative_rejected() {
        let err = AnchorAmount::parse("-5").expect_err("-5 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::LeadingSign),
            "expected LeadingSign, got {err:?}"
        );
    }

    /// Rejection: positive sign.
    #[test]
    fn anchor_amount_plus_sign_rejected() {
        let err = AnchorAmount::parse("+5").expect_err("+5 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::LeadingSign),
            "expected LeadingSign, got {err:?}"
        );
    }

    /// Rejection: scientific notation with `e`.
    #[test]
    fn anchor_amount_scientific_notation_e_rejected() {
        let err = AnchorAmount::parse("1e3").expect_err("1e3 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::ScientificNotation),
            "expected ScientificNotation, got {err:?}"
        );
    }

    /// Rejection: scientific notation with `E`.
    #[test]
    fn anchor_amount_scientific_notation_cap_e_rejected() {
        let err = AnchorAmount::parse("1E3").expect_err("1E3 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::ScientificNotation),
            "expected ScientificNotation, got {err:?}"
        );
    }

    /// Rejection: multiple decimal points.
    #[test]
    fn anchor_amount_multiple_dots_rejected() {
        let err = AnchorAmount::parse("1.2.3").expect_err("1.2.3 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::MultipleDots),
            "expected MultipleDots, got {err:?}"
        );
    }

    /// Rejection: leading dot with no integer part.
    #[test]
    fn anchor_amount_leading_dot_rejected() {
        let err = AnchorAmount::parse(".5").expect_err(".5 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::LeadingDot),
            "expected LeadingDot, got {err:?}"
        );
    }

    /// Rejection: trailing dot with no fractional part.
    #[test]
    fn anchor_amount_trailing_dot_rejected() {
        let err = AnchorAmount::parse("5.").expect_err("5. must be rejected");
        assert!(
            matches!(err, AnchorAmountError::TrailingDot),
            "expected TrailingDot, got {err:?}"
        );
    }

    /// Rejection: Unicode (non-ASCII) digits MUST be rejected as `InvalidChar`.
    ///
    /// The parser uses the ASCII literal range `'0'..='9'` (not `char::is_numeric`
    /// / `is_ascii_digit`), so Arabic-Indic, fullwidth, and other Unicode `Nd`
    /// codepoints are never accepted. This locks that property against a future
    /// refactor that might reintroduce a Unicode-digit bypass.
    #[test]
    fn anchor_amount_unicode_digits_rejected() {
        for s in [
            "\u{0661}",   // Arabic-Indic ONE
            "\u{FF11}",   // fullwidth ONE
            "1\u{0660}",  // ASCII 1 + Arabic-Indic ZERO
            "\u{0660}.5", // Arabic-Indic ZERO + .5
        ] {
            let err = AnchorAmount::parse(s).expect_err("Unicode digit must be rejected");
            assert!(
                matches!(err, AnchorAmountError::InvalidChar { .. }),
                "expected InvalidChar for {s:?}, got {err:?}"
            );
        }
    }

    /// Rejection: whitespace (leading / trailing / internal) — `AnchorAmount`
    /// intentionally does NOT trim, so whitespace is an `InvalidChar`.
    #[test]
    fn anchor_amount_whitespace_rejected() {
        for s in [" 5", "5 ", "5 0", "\t5", "1.0\n"] {
            let err = AnchorAmount::parse(s).expect_err("whitespace must be rejected");
            assert!(
                matches!(err, AnchorAmountError::InvalidChar { .. }),
                "expected InvalidChar for {s:?}, got {err:?}"
            );
        }
    }

    /// Rejection: non-digit, non-dot character.
    #[test]
    fn anchor_amount_alpha_rejected() {
        let err = AnchorAmount::parse("abc").expect_err("abc must be rejected");
        assert!(
            matches!(err, AnchorAmountError::InvalidChar { .. }),
            "expected InvalidChar, got {err:?}"
        );
    }

    /// Rejection: zero value as bare `"0"`.
    #[test]
    fn anchor_amount_zero_bare_rejected() {
        let err = AnchorAmount::parse("0").expect_err("0 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::Zero),
            "expected Zero, got {err:?}"
        );
    }

    /// Rejection: all-zero fractional `"0.0"`.
    #[test]
    fn anchor_amount_zero_fractional_rejected() {
        let err = AnchorAmount::parse("0.0").expect_err("0.0 must be rejected");
        assert!(
            matches!(err, AnchorAmountError::Zero),
            "expected Zero, got {err:?}"
        );
    }

    /// Rejection: over-length string (exceeds `ANCHOR_AMOUNT_MAX_LEN`).
    #[test]
    fn anchor_amount_over_length_rejected() {
        // 41 characters: "1" followed by 40 zeros.
        let over_len: String = "1".to_owned() + &"0".repeat(40);
        assert_eq!(over_len.len(), 41, "fixture must be 41 chars");
        let err = AnchorAmount::parse(&over_len).expect_err("41-char string must be rejected");
        assert!(
            matches!(
                err,
                AnchorAmountError::TooLong {
                    max: ANCHOR_AMOUNT_MAX_LEN,
                    actual: 41
                }
            ),
            "expected TooLong {{ max: {ANCHOR_AMOUNT_MAX_LEN}, actual: 41 }}, got {err:?}"
        );
    }

    /// Rejection: over-precision string (exceeds `ANCHOR_AMOUNT_MAX_DECIMAL_PLACES`).
    #[test]
    fn anchor_amount_over_precision_rejected() {
        // 19 decimal places — one past the limit.
        let over_prec = "0.0000000000000000001";
        assert_eq!(
            over_prec.split('.').nth(1).map_or(0, str::len),
            19,
            "fixture must have 19 decimal places"
        );
        let err = AnchorAmount::parse(over_prec).expect_err("19 dp must be rejected");
        assert!(
            matches!(
                err,
                AnchorAmountError::TooManyDecimals {
                    max: ANCHOR_AMOUNT_MAX_DECIMAL_PLACES,
                    actual: 19
                }
            ),
            "expected TooManyDecimals {{ max: {ANCHOR_AMOUNT_MAX_DECIMAL_PLACES}, actual: 19 }}, got {err:?}"
        );
    }

    /// Serde: deserialise a valid JSON string to `AnchorAmount`.
    #[test]
    fn anchor_amount_serde_valid_deserialises() {
        let a: AnchorAmount =
            serde_json::from_str(r#""100.50""#).expect("valid JSON string must deserialise");
        assert_eq!(a.as_str(), "100.50");
    }

    /// Serde: invalid input produces a deserialise error.
    #[test]
    fn anchor_amount_serde_invalid_deserialise_error() {
        let err = serde_json::from_str::<AnchorAmount>(r#""-5""#)
            .expect_err("invalid anchor amount must fail deserialisation");
        assert!(
            err.to_string().contains("leading sign"),
            "serde error must mention the rejection reason; got: {err}"
        );
    }

    /// Serde: round-trip (parse → serialise → deserialise).
    #[test]
    fn anchor_amount_serde_round_trip() {
        let original = AnchorAmount::parse("42.5").expect("42.5 should parse");
        let json = serde_json::to_string(&original).expect("serialise");
        assert_eq!(
            json, r#""42.5""#,
            "serialised form must be a quoted decimal string"
        );
        let back: AnchorAmount = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(
            back.as_str(),
            original.as_str(),
            "round-trip must preserve value"
        );
    }

    /// Serde: `Option<AnchorAmount>` with `"null"` deserialises to `None`.
    #[test]
    fn anchor_amount_option_serde_null_is_none() {
        let v: Option<AnchorAmount> =
            serde_json::from_str("null").expect("null must deserialise to None");
        assert!(v.is_none());
    }

    /// Serde: `Option<AnchorAmount>` with a valid string deserialises to `Some`.
    #[test]
    fn anchor_amount_option_serde_valid_is_some() {
        let v: Option<AnchorAmount> =
            serde_json::from_str(r#""50.00""#).expect("valid string must deserialise to Some");
        assert_eq!(v.as_ref().map(AnchorAmount::as_str), Some("50.00"));
    }

    /// Serde: `Option<AnchorAmount>` with an invalid string produces an error.
    #[test]
    fn anchor_amount_option_serde_invalid_is_error() {
        let err = serde_json::from_str::<Option<AnchorAmount>>(r#""0""#)
            .expect_err("zero must fail even inside Option<AnchorAmount>");
        assert!(
            err.to_string().contains("greater than zero"),
            "error must mention zero-rejection; got: {err}"
        );
    }

    /// `JsonSchema` output carries the correct `maxLength` and `pattern`.
    #[test]
    fn anchor_amount_schema_fields() {
        let schema = schemars::SchemaGenerator::default().into_root_schema_for::<AnchorAmount>();
        let json = serde_json::to_string(&schema).expect("schema serialisation");
        assert!(
            json.contains("\"maxLength\""),
            "schema must carry maxLength: {json}"
        );
        assert!(
            json.contains("\"pattern\""),
            "schema must carry pattern: {json}"
        );
        // Lock the relaxed superset pattern (must NOT pre-reject values `parse`
        // accepts, e.g. "0.50"/"100.00"; `parse` is authoritative). Asserting the
        // exact pattern string guards against a regression to an over-strict form.
        assert!(
            json.contains(r"^[0-9]+(\\.[0-9]{1,18})?$"),
            "schema pattern must be the relaxed superset of parse: {json}"
        );
        // Cross-check: a few values `parse` accepts must satisfy the schema shape
        // (verified structurally — leading digit + optional <=18dp fraction).
        for v in ["100.50", "100.00", "0.50", "0.10", "100"] {
            assert!(
                AnchorAmount::parse(v).is_ok(),
                "{v} must be accepted by parse (and is covered by the schema superset)"
            );
        }
    }

    // -- McpMemoTextArgument tests --------------------------------------------

    /// Empty text memo is accepted; downstream memo parsing normalizes it.
    #[test]
    fn mcp_memo_text_arg_empty_string_accepted() {
        let memo: McpMemoTextArgument = serde_json::from_str(r#""""#).expect("empty memo parses");
        assert_eq!(memo.as_str(), "");
    }

    /// Exactly 28 UTF-8 bytes is accepted.
    #[test]
    fn mcp_memo_text_arg_28_bytes_accepted() {
        let memo: McpMemoTextArgument =
            serde_json::from_str(r#""abcdefghijklmnopqrstuvwx1234""#).expect("28-byte memo parses");
        assert_eq!(memo.as_str().len(), MCP_MEMO_TEXT_MAX_BYTES);
    }

    /// 29 UTF-8 bytes is rejected with the typed constructor error.
    #[test]
    fn mcp_memo_text_arg_29_bytes_rejected_with_typed_error() {
        let err = McpMemoTextArgument::new("abcdefghijklmnopqrstuvwx12345".to_owned())
            .expect_err("29-byte memo must be rejected");
        assert_eq!(
            err,
            McpMemoTextArgumentError::TooLong {
                max: MCP_MEMO_TEXT_MAX_BYTES,
                actual: MCP_MEMO_TEXT_MAX_BYTES + 1
            }
        );

        let serde_err =
            serde_json::from_str::<McpMemoTextArgument>(r#""abcdefghijklmnopqrstuvwx12345""#)
                .expect_err("serde must reject 29-byte memo");
        assert!(
            serde_err
                .to_string()
                .contains("memo_text must be at most 28 bytes"),
            "serde error must mention byte cap: {serde_err}"
        );
    }

    /// Multi-byte UTF-8 fitting within 28 bytes is accepted.
    #[test]
    fn mcp_memo_text_arg_multibyte_utf8_within_limit_accepted() {
        let memo: McpMemoTextArgument =
            serde_json::from_str(r#""cafe \u00e9toile""#).expect("UTF-8 memo parses");
        assert_eq!(memo.as_str(), "cafe \u{e9}toile");
        assert!(memo.as_str().len() <= MCP_MEMO_TEXT_MAX_BYTES);
    }

    /// `JsonSchema` output carries the MEMO_TEXT byte cap.
    #[test]
    fn mcp_memo_text_arg_schema_has_max_length() {
        let schema =
            schemars::SchemaGenerator::default().into_root_schema_for::<McpMemoTextArgument>();
        let json = serde_json::to_string(&schema).expect("schema serialisation");
        assert!(
            json.contains("\"maxLength\":28"),
            "schema must carry maxLength 28: {json}"
        );
    }
}

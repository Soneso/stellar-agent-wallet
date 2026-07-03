//! JSON wire-format envelope for every CLI command, MCP tool, and library API.
//!
//! # Overview
//!
//! Every response produced by the wallet — success or error — is wrapped in an
//! [`Envelope<T>`] that carries three fields in stable key order:
//!
//! ```json
//! { "ok": true,  "data": { ... },             "request_id": "uuid-v4-string" }
//! { "ok": false, "error": { "code": "...",
//!                           "message": "..." }, "request_id": "uuid-v4-string" }
//! ```
//!
//! The `ok` flag appears first, followed by `data` (on success) or `error` (on
//! failure), and finally `request_id`.  Absent fields (`data` on error,
//! `error` on success) are omitted entirely — not serialised as `null` — via
//! `#[serde(skip_serializing_if = "Option::is_none")]`.  This keeps the output
//! clean and predictable for `jq` pipelines.
//!
//! # Key types
//!
//! - [`Envelope<T>`] — the outer response wrapper; `T` is the payload type for
//!   success responses.
//! - [`EnvelopeError`] — the error payload carried by a failure envelope.
//! - [`OutputFormat`] — the `--output` flag value; parsed by CLI commands.
//!
//! # Invariants enforced
//!
//! - `ok: true` implies `data` is `Some`, `error` is `None`.
//! - `ok: false` implies `error` is `Some`, `data` is `None`.
//! - `request_id` is always present and is a valid UUIDv4 string.
//! - JSON key order is stable across serialisations (struct field order).
//!
//! # Wire-format stability policy
//!
//! The envelope shape is part of the stable public API.  Agents and human
//! operators parse these responses to route and display results.  The
//! guarantees:
//!
//! - **Key order** is `ok`, then `data` or `error`, then `request_id`.
//!   Order is stable across `serde_json` serialisations because the struct
//!   fields are written in declaration order.
//! - **Adding a new field** to [`Envelope<T>`] or [`EnvelopeError`] is
//!   non-breaking via `#[non_exhaustive]` (external match arms must carry
//!   a wildcard fallback).  New fields are appended; existing key order
//!   is preserved.
//! - **Removing or renaming a field silently is a breaking change** and is
//!   forbidden pre-1.0 without a `Changed` or `Removed` CHANGELOG entry
//!   carrying a migration note.
//! - **`request_id` is the only non-deterministic byte** in identical-input
//!   invocations; two calls with the same inputs produce byte-identical
//!   JSON apart from that field.
//! - **`Envelope::<()>::ok(())` emits `"data": null`** because the unit
//!   success payload is intentionally serialised rather than omitted.  The
//!   error envelope omits `"data"` entirely (no key) via
//!   `skip_serializing_if`.  Callers that want a data-less success without
//!   the `null` key should either use a dedicated marker type or post-process
//!   the JSON; this asymmetry is the stable contract.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{ValidationError, WalletError};

// ──────────────────────────────────────────────────────────────────────────────
// Envelope<T>
// ──────────────────────────────────────────────────────────────────────────────

/// The uniform JSON envelope emitted by every wallet API, CLI command, and
/// MCP tool.
///
/// `T` is the success-payload type.  For commands that produce no data on
/// success (e.g. a fire-and-forget operation), use `Envelope<()>` and call
/// [`Envelope::ok`] with `()`.
///
/// The `ok` field appears first in the serialised JSON, followed by `data` or
/// `error`, then `request_id`.  Absent optional fields are omitted (not
/// emitted as `null`).
///
/// # Construction and forward compatibility
///
/// `Envelope<T>` is `#[non_exhaustive]` with `pub` fields.  External crates
/// therefore cannot use struct-literal construction (`Envelope { ok: ..., }`)
/// or functional-update syntax (`Envelope { request_id, ..env }`), and are
/// required to add a wildcard arm when destructuring.  This lets the
/// struct grow fields in future minor versions without breaking downstream match
/// arms.  The intended construction path is the typed constructors
/// [`Envelope::ok`], [`Envelope::ok_with_request_id`], [`Envelope::err`],
/// and [`Envelope::err_with_request_id`] — using a constructor ensures the
/// `request_id` generation is not skipped.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::envelope::Envelope;
///
/// let env = Envelope::ok(42_i32);
/// assert!(env.ok);
/// assert_eq!(env.data, Some(42));
/// assert!(env.error.is_none());
/// // request_id is a non-empty UUIDv4 string.
/// assert!(!env.request_id.is_empty());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Envelope<T: Serialize> {
    /// `true` when the operation succeeded; `false` when it failed.
    pub ok: bool,

    /// The success payload.  Present only when `ok` is `true`.
    ///
    /// Omitted from JSON output when `None` (no `"data": null` key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// The error detail.  Present only when `ok` is `false`.
    ///
    /// Omitted from JSON output when `None` (no `"error": null` key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<EnvelopeError>,

    /// Per-invocation UUIDv4 correlation identifier.
    ///
    /// Generated fresh by [`Envelope::ok`] / [`Envelope::err`].  Use
    /// [`Envelope::ok_with_request_id`] / [`Envelope::err_with_request_id`]
    /// when threading an existing ID through a multi-step flow or for
    /// deterministic tests.
    pub request_id: String,
}

impl<T: Serialize> Envelope<T> {
    /// Constructs a success envelope carrying `data`.
    ///
    /// Generates a fresh UUIDv4 `request_id`.
    ///
    /// # Panics
    ///
    /// Only if the OS randomness source is unavailable — see
    /// [`uuid::Uuid::new_v4`].  UUID generation delegates to `getrandom`,
    /// which panics on systems that cannot provide entropy (extremely rare
    /// in the deployment targets this wallet supports).  Call
    /// [`Envelope::ok_with_request_id`] with an externally-sourced ID to
    /// avoid this path entirely.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    ///
    /// let env = Envelope::ok("hello");
    /// assert!(env.ok);
    /// assert_eq!(env.data, Some("hello"));
    /// assert!(env.error.is_none());
    /// ```
    #[must_use]
    pub fn ok(data: T) -> Self {
        Self::ok_with_request_id(data, new_request_id())
    }

    /// Constructs a success envelope carrying `data` with a caller-supplied
    /// `request_id`.
    ///
    /// Use this overload when threading a request ID through a multi-step
    /// flow or when a deterministic ID is required in tests.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    ///
    /// let env = Envelope::ok_with_request_id(42_i32, "fixed-id".to_owned());
    /// assert_eq!(env.request_id, "fixed-id");
    /// ```
    #[must_use]
    pub fn ok_with_request_id(data: T, request_id: String) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            request_id,
        }
    }

    /// Serialises the envelope to a single-line (compact) JSON string.
    ///
    /// The output is a valid JSON object whose key order is stable and
    /// matches the struct field order: `ok`, then `data` or `error`, then
    /// `request_id`.  Absent optional fields are omitted entirely.
    ///
    /// Suitable for scripting pipelines.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] wrapping
    /// [`crate::error::InternalError::SerialisationFailed`] if `serde_json` fails to
    /// serialise the value.  In practice this can only happen if `T`'s
    /// `Serialize` impl panics or if the value contains a floating-point
    /// `NaN`/`Infinity` (neither applies to the wallet's payload types).
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    ///
    /// let env = Envelope::ok_with_request_id(42_i32, "id-1".to_owned());
    /// let json = env.to_json_compact().unwrap();
    /// assert!(json.starts_with(r#"{"ok":true"#));
    /// assert!(json.contains(r#""request_id":"id-1""#));
    /// assert!(!json.contains('\n'));
    /// ```
    pub fn to_json_compact(&self) -> Result<String, WalletError> {
        serde_json::to_string(self).map_err(|e| WalletError::Internal(e.into()))
    }

    /// Serialises the envelope to an indented (pretty-printed) JSON string.
    ///
    /// Output uses two-space indentation as produced by `serde_json`'s
    /// default pretty printer.  Suitable for human inspection.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] wrapping
    /// [`crate::error::InternalError::SerialisationFailed`] if `serde_json` fails to
    /// serialise the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    ///
    /// let env = Envelope::ok_with_request_id(42_i32, "id-1".to_owned());
    /// let json = env.to_json_pretty().unwrap();
    /// assert!(json.contains('\n'));
    /// assert!(json.contains(r#""ok": true"#));
    /// ```
    pub fn to_json_pretty(&self) -> Result<String, WalletError> {
        serde_json::to_string_pretty(self).map_err(|e| WalletError::Internal(e.into()))
    }
}

/// Partial-failure constructor for envelopes that carry both `data` and `error`.
///
/// This `impl` block provides [`Envelope::partial_failure_with_request_id`],
/// which emits `ok: false` alongside a populated `data` field.  The shape is
/// used when some steps of an operation succeed before the overall operation
/// fails — the partial result is forensically valuable and must appear in the
/// same JSON root as the error.
///
/// # Wire-format note
///
/// A partial-failure envelope breaks the `ok: true ↔ data present` invariant
/// stated in the module docs.  The intended invariant is therefore refined:
///
/// - `ok: true` → `data: Some(...)`, `error: None`.
/// - `ok: false`, `data: None` → pure error (the common case).
/// - `ok: false`, `data: Some(...)` → **partial failure**: operation made
///   partial progress but terminated in error; both fields are present.
///
/// This shape is stable wire-format.
impl<T: Serialize> Envelope<T> {
    /// Constructs a partial-failure envelope carrying both `data` and `error`.
    ///
    /// Sets `ok: false`, `data: Some(data)`, `error: Some(EnvelopeError::from(err))`,
    /// `request_id: request_id`.
    ///
    /// Use this constructor when an operation makes partial progress (some steps
    /// succeed) but ultimately fails — the partial result is forensically
    /// important and must appear alongside the error in a single JSON root.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    /// use stellar_agent_core::error::{WalletError, ValidationError};
    ///
    /// let partial_data = 42_i32;
    /// let err = WalletError::Validation(ValidationError::AmountUnitsRequired);
    /// let env = Envelope::partial_failure_with_request_id(
    ///     partial_data,
    ///     &err,
    ///     "fixed-id".to_owned(),
    /// );
    /// assert!(!env.ok);
    /// assert_eq!(env.data, Some(42));
    /// assert!(env.error.is_some());
    /// assert_eq!(env.request_id, "fixed-id");
    /// ```
    #[must_use]
    pub fn partial_failure_with_request_id(data: T, err: &WalletError, request_id: String) -> Self {
        Self {
            ok: false,
            data: Some(data),
            error: Some(EnvelopeError {
                code: err.code().to_owned(),
                message: err.message(),
            }),
            request_id,
        }
    }
}

/// Error-envelope constructors and unit-specialisation notes.
///
/// `Envelope<()>` is the canonical error-envelope type because an error
/// envelope never carries data.  The unit payload is intentionally
/// overloaded: `Envelope::<()>::ok(())` produces a data-less success envelope
/// (serialised as `"data": null`; see the module-level wire-format stability
/// policy), while `Envelope::<()>::err(&err)` produces the error envelope.
/// Callers wanting a data-less success should prefer a dedicated marker
/// type if the trailing `"data": null` is undesirable in their wire
/// contract.
impl Envelope<()> {
    /// Constructs an error envelope from a [`WalletError`].
    ///
    /// The `data` field is `None` (omitted in JSON output).  Generates a
    /// fresh UUIDv4 `request_id`.
    ///
    /// `Envelope<()>` is used for the error case because an error envelope
    /// never carries data.  Using the unit type `()` as the phantom type
    /// parameter keeps the type system honest without requiring a separate
    /// error-envelope type.
    ///
    /// # Panics
    ///
    /// Only if the OS randomness source is unavailable — see
    /// [`uuid::Uuid::new_v4`].  Call
    /// [`Envelope::err_with_request_id`] to avoid this path.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    /// use stellar_agent_core::error::{WalletError, ValidationError};
    ///
    /// let err = WalletError::Validation(ValidationError::MemoRequired {
    ///     destination: "GABC".to_owned(),
    /// });
    /// let env = Envelope::err(&err);
    /// assert!(!env.ok);
    /// assert!(env.data.is_none());
    /// let e = env.error.as_ref().unwrap();
    /// assert_eq!(e.code, "validation.memo_required");
    /// assert!(e.message.contains("GABC"));
    /// ```
    #[must_use]
    pub fn err(err: &WalletError) -> Self {
        Self::err_with_request_id(err, new_request_id())
    }

    /// Constructs an error envelope from a [`WalletError`] with a
    /// caller-supplied `request_id`.
    ///
    /// Use this overload when threading a request ID through a multi-step
    /// flow or when a deterministic ID is required in tests.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    /// use stellar_agent_core::error::{WalletError, ValidationError};
    ///
    /// let err = WalletError::Validation(ValidationError::AmountUnitsRequired);
    /// let env = Envelope::err_with_request_id(&err, "fixed-id".to_owned());
    /// assert_eq!(env.request_id, "fixed-id");
    /// assert!(!env.ok);
    /// ```
    #[must_use]
    pub fn err_with_request_id(err: &WalletError, request_id: String) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(EnvelopeError {
                code: err.code().to_owned(),
                message: err.message(),
            }),
            request_id,
        }
    }

    /// Constructs an error envelope from a raw code string and message.
    ///
    /// Use this overload when the error originates outside the [`WalletError`]
    /// hierarchy and carries its own stable wire-code namespace (for example,
    /// `"counterparty.fetch_failed"` or a subsystem-specific code).  Callers
    /// are responsible for ensuring that `code` is a stable wire-format string
    /// that does not leak secret material.
    ///
    /// Generates a fresh UUIDv4 `request_id`.
    ///
    /// # Panics
    ///
    /// Only if the OS randomness source is unavailable — see
    /// [`uuid::Uuid::new_v4`].  Call [`Envelope::err_raw_with_request_id`] to
    /// avoid this path.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    ///
    /// let env = Envelope::err_raw("counterparty.fetch_failed", "connection refused");
    /// assert!(!env.ok);
    /// assert!(env.data.is_none());
    /// let e = env.error.as_ref().unwrap();
    /// assert_eq!(e.code, "counterparty.fetch_failed");
    /// assert_eq!(e.message, "connection refused");
    /// ```
    #[must_use]
    pub fn err_raw(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::err_raw_with_request_id(code, message, new_request_id())
    }

    /// Constructs an error envelope from a raw code string and message with a
    /// caller-supplied `request_id`.
    ///
    /// Use this overload when threading a request ID through a multi-step flow
    /// or when a deterministic ID is required in tests.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::Envelope;
    ///
    /// let env = Envelope::err_raw_with_request_id(
    ///     "counterparty.hmac_mismatch",
    ///     "HMAC tag did not match",
    ///     "fixed-id".to_owned(),
    /// );
    /// assert_eq!(env.request_id, "fixed-id");
    /// assert_eq!(env.error.as_ref().unwrap().code, "counterparty.hmac_mismatch");
    /// ```
    #[must_use]
    pub fn err_raw_with_request_id(
        code: impl Into<String>,
        message: impl Into<String>,
        request_id: String,
    ) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(EnvelopeError {
                code: code.into(),
                message: message.into(),
            }),
            request_id,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// EnvelopeError
// ──────────────────────────────────────────────────────────────────────────────

/// The error payload embedded in a failure [`Envelope`].
///
/// Both fields are stable wire-format strings sourced from
/// [`WalletError::code`] and [`WalletError::message`].  The `message` field
/// is derived from the error's `Display` impl; callers that move public
/// identifiers or other boundary-sensitive values into an external wire
/// response must apply the target boundary's redaction policy before using
/// [`Envelope::err`].
///
/// # Non-exhaustive note
///
/// [`EnvelopeError`] is marked `#[non_exhaustive]` so downstream match/struct
/// expressions can add fields in a future minor version without breaking
/// callers.  Direct construction is blocked; use [`Envelope::err`] or
/// [`Envelope::err_with_request_id`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::envelope::Envelope;
/// use stellar_agent_core::error::{WalletError, NetworkError};
///
/// let err = WalletError::Network(NetworkError::FriendbotMainnetForbidden);
/// let env = Envelope::err(&err);
/// let e = env.error.as_ref().unwrap();
/// assert_eq!(e.code, "network.friendbot_mainnet_forbidden");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EnvelopeError {
    /// Stable wire-format error code (e.g. `"validation.memo_required"`).
    ///
    /// Sourced from [`WalletError::code`].  Always a `<category>.<subcode>`
    /// string in lowercase snake_case.
    pub code: String,

    /// Human-readable error message.
    ///
    /// Sourced from [`WalletError::message`] (which delegates to `Display`).
    /// Safe to display to operators; contains no secret material.
    pub message: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// OutputFormat
// ──────────────────────────────────────────────────────────────────────────────

/// The value of the `--output` flag accepted by every CLI command.
///
/// The default is [`OutputFormat::Json`] (deterministic, scriptable output).
/// [`OutputFormat::Table`] selects the human-readable renderer, which is
/// per-command and deferred to individual command implementations.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::envelope::OutputFormat;
///
/// assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
/// assert_eq!(OutputFormat::parse("TABLE").unwrap(), OutputFormat::Table);
/// assert!(OutputFormat::parse("xml").is_err());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Emit the JSON envelope (default).
    Json,
    /// Emit a human-readable table.  The exact layout is per-command.
    Table,
}

impl OutputFormat {
    /// The default output format (JSON).
    ///
    /// CLI commands use this as the `clap` default value.
    pub const DEFAULT: Self = Self::Json;

    /// Parses a string into an [`OutputFormat`].
    ///
    /// Accepted values are `"json"` and `"table"`, case-insensitive.
    /// Leading or trailing whitespace is **not** trimmed — `" json"` is
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::OutputFormatInvalid`] (code
    /// `"validation.output_format_invalid"`) if `s` does not match any
    /// known format.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::envelope::OutputFormat;
    ///
    /// assert_eq!(OutputFormat::parse("json").unwrap(),  OutputFormat::Json);
    /// assert_eq!(OutputFormat::parse("JSON").unwrap(),  OutputFormat::Json);
    /// assert_eq!(OutputFormat::parse("Json").unwrap(),  OutputFormat::Json);
    /// assert_eq!(OutputFormat::parse("table").unwrap(), OutputFormat::Table);
    /// assert_eq!(OutputFormat::parse("TABLE").unwrap(), OutputFormat::Table);
    ///
    /// let err = OutputFormat::parse("xml").unwrap_err();
    /// assert_eq!(err.code(), "validation.output_format_invalid");
    /// ```
    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            _ => Err(ValidationError::OutputFormatInvalid {
                input: s.to_owned(),
            }),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = ValidationError;

    /// Parses a string into an [`OutputFormat`] via the [`std::str::FromStr`] trait.
    ///
    /// Delegates to [`OutputFormat::parse`] for the case-insensitive
    /// `"json"` / `"table"` match.  `FromStr` is implemented so that `clap`
    /// can wire `--output` via `#[arg(value_parser)]` without the caller
    /// needing to construct a closure:
    ///
    /// ```ignore
    /// use clap::Parser;
    /// use stellar_agent_core::envelope::OutputFormat;
    ///
    /// #[derive(Parser)]
    /// struct Args {
    ///     #[arg(long, default_value_t = OutputFormat::DEFAULT)]
    ///     output: OutputFormat,
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::OutputFormatInvalid`] (code
    /// `"validation.output_format_invalid"`) if `s` does not match any
    /// known format.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for OutputFormat {
    /// Formats the output format as a lowercase string (`"json"` or
    /// `"table"`).
    ///
    /// Used by `clap` default-value display in help text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Table => f.write_str("table"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Generates a fresh UUIDv4 string for use as a `request_id`.
fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{InternalError, NetworkError, ValidationError, WalletError};
    use stellar_agent_test_support::assert_no_secret_bytes;

    // ── 1. JSON round-trip ────────────────────────────────────────────────────

    /// Serialise a success envelope to compact JSON and parse it back;
    /// assert equality of all observable fields.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation or parse failure"
    )]
    fn json_round_trip_success() {
        let original = Envelope::ok_with_request_id(42_i32, "round-trip-id".to_owned());
        let json = original
            .to_json_compact()
            .expect("serialisation must succeed for i32 payload");
        let parsed: Envelope<i32> = serde_json::from_str(&json)
            .expect("round-trip must produce valid JSON for i32 payload");
        assert_eq!(parsed.ok, original.ok);
        assert_eq!(parsed.data, original.data);
        assert!(parsed.error.is_none());
        assert_eq!(parsed.request_id, original.request_id);
    }

    /// Serialise an error envelope to compact JSON and parse it back.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation or parse failure"
    )]
    fn json_round_trip_error() {
        let err = WalletError::Validation(ValidationError::MemoRequired {
            destination: "GABC".to_owned(),
        });
        let original = Envelope::err_with_request_id(&err, "err-round-trip-id".to_owned());
        let json = original
            .to_json_compact()
            .expect("serialisation must succeed for error envelope");
        let parsed: Envelope<()> = serde_json::from_str(&json)
            .expect("round-trip must produce valid JSON for error envelope");
        assert!(!parsed.ok);
        assert!(parsed.data.is_none());
        let parsed_error = parsed
            .error
            .as_ref()
            .expect("parsed error field must be present");
        let orig_error = original
            .error
            .as_ref()
            .expect("original error field must be present");
        assert_eq!(parsed_error.code, orig_error.code);
        assert_eq!(parsed_error.message, orig_error.message);
        assert_eq!(parsed.request_id, original.request_id);
    }

    #[test]
    fn to_json_compact_serde_failure_returns_serialisation_failed() -> Result<(), String> {
        use std::collections::BTreeMap;
        use std::error::Error as _;

        let payload = BTreeMap::from([((1_u8, 2_u8), "unsupported-key")]);
        let env = Envelope::ok_with_request_id(payload, "serde-failure-id".to_owned());

        let err = match env.to_json_compact() {
            Ok(_) => {
                return Err(
                    "tuple-keyed map unexpectedly serialised as JSON object successfully"
                        .to_owned(),
                );
            }
            Err(err) => err,
        };
        let WalletError::Internal(InternalError::SerialisationFailed { .. }) = &err else {
            return Err(format!("expected SerialisationFailed, got {err:?}"));
        };
        let inner = err
            .source()
            .ok_or_else(|| "WalletError source missing".to_owned())?;
        assert!(
            inner.is::<serde_json::Error>()
                || inner
                    .source()
                    .is_some_and(|source| source.is::<serde_json::Error>()),
            "source chain must expose serde_json::Error"
        );
        Ok(())
    }

    // ── 2. Key order ──────────────────────────────────────────────────────────

    /// Assert that compact JSON output starts with `{"ok":true,"data":...` for
    /// success envelopes and ends with `"request_id":"..."`.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn key_order_success() {
        let env = Envelope::ok_with_request_id(42_i32, "order-test-id".to_owned());
        let json = env.to_json_compact().expect("serialisation must succeed");
        // ok comes first.
        assert!(
            json.starts_with(r#"{"ok":true,"data":"#),
            "expected ok first, data second; got: {json}"
        );
        // request_id is last (the JSON ends with ,"request_id":"..."}
        assert!(
            json.ends_with(r#","request_id":"order-test-id"}"#),
            "expected request_id last; got: {json}"
        );
        // error key is absent.
        assert!(
            !json.contains(r#""error""#),
            "error key must be absent on success; got: {json}"
        );
    }

    /// Assert that compact JSON output starts with `{"ok":false,"error":...`
    /// for error envelopes and that `"data"` is absent.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn key_order_error() {
        let err = WalletError::Validation(ValidationError::AmountUnitsRequired);
        let env = Envelope::err_with_request_id(&err, "err-order-id".to_owned());
        let json = env.to_json_compact().expect("serialisation must succeed");
        assert!(
            json.starts_with(r#"{"ok":false,"error":"#),
            "expected ok first, error second; got: {json}"
        );
        assert!(
            json.ends_with(r#","request_id":"err-order-id"}"#),
            "expected request_id last; got: {json}"
        );
        assert!(
            !json.contains(r#""data""#),
            "data key must be absent on error; got: {json}"
        );
    }

    // ── 3. Request-ID is a valid UUIDv4 ──────────────────────────────────────

    /// Every auto-generated request_id must parse as a valid UUIDv4.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on UUID parse failure is the assertion"
    )]
    fn request_id_is_uuidv4() {
        for _ in 0..20 {
            let env = Envelope::ok(());
            let parsed =
                uuid::Uuid::parse_str(&env.request_id).expect("request_id must be a valid UUID");
            // Version 4 == random.
            assert_eq!(parsed.get_version_num(), 4, "request_id must be UUIDv4");
            // Variant == RFC 4122.
            assert_eq!(
                parsed.get_variant(),
                uuid::Variant::RFC4122,
                "request_id must carry RFC 4122 variant bits"
            );
        }
    }

    // ── 4. OutputFormat parsing ───────────────────────────────────────────────

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "test-only; unwrap on expected-Ok is the assertion"
    )]
    fn output_format_parse_valid() {
        assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("JSON").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("Json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("table").unwrap(), OutputFormat::Table);
        assert_eq!(OutputFormat::parse("TABLE").unwrap(), OutputFormat::Table);
        assert_eq!(OutputFormat::parse("Table").unwrap(), OutputFormat::Table);
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test-only; unwrap_err on expected-Err and panic in else-branch are assertions"
    )]
    fn output_format_parse_invalid() {
        for bad in &["xml", "", " json", "json ", "jsOn table", "0"] {
            let result = OutputFormat::parse(bad);
            assert!(result.is_err(), "expected error for input {bad:?}");
            let err = result.unwrap_err();
            assert_eq!(
                err.code(),
                "validation.output_format_invalid",
                "wrong code for input {bad:?}"
            );
            // Confirm the input string is preserved.
            if let ValidationError::OutputFormatInvalid { input } = err {
                assert_eq!(input, *bad, "input field mismatch for {bad:?}");
            } else {
                panic!("wrong variant for input {bad:?}");
            }
        }
    }

    // ── 5. OutputFormat::Display ──────────────────────────────────────────────

    #[test]
    fn output_format_display() {
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Table.to_string(), "table");
    }

    // ── 6. Error envelope from WalletError ────────────────────────────────────

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on Option is the assertion"
    )]
    fn error_envelope_from_wallet_error() {
        let err = WalletError::Validation(ValidationError::MemoRequired {
            destination: "GABC".to_owned(),
        });
        let env = Envelope::err(&err);
        assert!(!env.ok);
        assert!(env.data.is_none());
        let e = env.error.as_ref().expect("error must be present");
        assert_eq!(e.code, "validation.memo_required");
        assert!(
            e.message.contains("GABC"),
            "message must contain destination; got: {}",
            e.message
        );
    }

    // ── 7. Empty data case — Envelope<()> ────────────────────────────────────

    /// `Envelope::ok(())` serialises with `"data":null` (serde serialises
    /// `Some(())` as `null`).  This is the degenerate no-payload success
    /// envelope.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn unit_payload_serialises_data_null() {
        let env = Envelope::ok_with_request_id((), "unit-id".to_owned());
        let json = env
            .to_json_compact()
            .expect("serialisation must succeed for () payload");
        // serde serialises () as null; the data key must therefore be present
        // with a null value (Some(()) -> present, value = null).
        assert!(
            json.contains(r#""data":null"#),
            "unit payload must serialise as null; got: {json}"
        );
    }

    // ── 8. skip_serializing_if behaviour ─────────────────────────────────────

    /// `error: None` must not appear in a success envelope's JSON output.
    /// `data: None` must not appear in an error envelope's JSON output.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn absent_fields_not_serialised() {
        let success = Envelope::ok_with_request_id(1_i32, "s-id".to_owned());
        let success_json = success
            .to_json_compact()
            .expect("serialisation must succeed");
        assert!(
            !success_json.contains(r#""error""#),
            "error key must be absent on success; got: {success_json}"
        );

        let err = WalletError::Network(NetworkError::FriendbotMainnetForbidden);
        let failure = Envelope::err_with_request_id(&err, "f-id".to_owned());
        let failure_json = failure
            .to_json_compact()
            .expect("serialisation must succeed");
        assert!(
            !failure_json.contains(r#""data""#),
            "data key must be absent on error; got: {failure_json}"
        );
    }

    // ── 9. Acceptance criteria: valid JSON, deterministic modulo request_id ──

    /// Two invocations with the same data but different request_ids produce
    /// JSON that is byte-identical after removing the request_id field.
    /// Also asserts no literal `"null"` appears in the output for omitted
    /// fields (i.e. `skip_serializing_if` is working correctly).
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn deterministic_modulo_request_id() {
        let payload = 99_i32;
        let a = Envelope::ok_with_request_id(payload, "id-a".to_owned())
            .to_json_compact()
            .expect("serialisation must succeed");
        let b = Envelope::ok_with_request_id(payload, "id-b".to_owned())
            .to_json_compact()
            .expect("serialisation must succeed");

        // Replace request_id values and compare the rest.
        let a_stripped = a.replace("id-a", "ID");
        let b_stripped = b.replace("id-b", "ID");
        assert_eq!(
            a_stripped, b_stripped,
            "output must be deterministic modulo request_id"
        );

        // No literal null for omitted fields (error is absent, not null).
        assert!(
            !a.contains(r#""error":null"#),
            "omitted error field must not appear as null; got: {a}"
        );
    }

    // ── No secret bytes in error envelope output ──────────────────────────────

    /// `Envelope::err` output must contain no S-strkey byte patterns.
    /// Relies on `stellar_agent_test_support::assert_no_secret_bytes`.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn error_envelope_contains_no_secret_bytes() {
        let err = WalletError::Validation(ValidationError::ProfileNotFound {
            name: "my-profile".to_owned(),
        });
        let env = Envelope::err_with_request_id(&err, "sec-test-id".to_owned());
        let json = env.to_json_compact().expect("serialisation must succeed");
        assert_no_secret_bytes(json.as_bytes());
    }

    // ── Pretty-print smoke test ───────────────────────────────────────────────

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn pretty_print_contains_newlines() {
        let env = Envelope::ok_with_request_id("hello", "pretty-id".to_owned());
        let pretty = env
            .to_json_pretty()
            .expect("pretty serialisation must succeed");
        assert!(pretty.contains('\n'), "pretty output must contain newlines");
        assert!(
            pretty.contains(r#""ok": true"#),
            "pretty output must contain spaced ok field; got: {pretty}"
        );
    }

    // ── partial_failure_with_request_id ───────────────────────────────────────

    /// Partial-failure envelopes carry `ok: false`, `data: Some(...)`, and
    /// `error: Some(...)` simultaneously.  Verify all three fields plus the
    /// exact request_id, and confirm the JSON wire shape.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation or field-access failure"
    )]
    fn partial_failure_wire_shape() {
        let partial = vec![1_i32, 2, 3];
        let err = WalletError::Validation(ValidationError::AmountUnitsRequired);

        let env = Envelope::partial_failure_with_request_id(
            partial.clone(),
            &err,
            "partial-id".to_owned(),
        );

        // Invariant: ok is false, both data and error are present.
        assert!(!env.ok, "partial-failure envelope must have ok: false");
        assert_eq!(
            env.data.as_ref(),
            Some(&partial),
            "partial-failure envelope must carry the partial data"
        );
        assert!(
            env.error.is_some(),
            "partial-failure envelope must carry an error payload"
        );
        assert_eq!(env.request_id, "partial-id");

        // Wire format: both "data" and "error" keys must appear.
        let json = env.to_json_compact().expect("serialisation must succeed");
        assert!(
            json.starts_with(r#"{"ok":false,"data":"#),
            "partial-failure JSON must start ok:false then data; got: {json}"
        );
        assert!(
            json.contains(r#""error":"#),
            "partial-failure JSON must contain error key; got: {json}"
        );
        assert!(
            json.contains(r#""request_id":"partial-id""#),
            "partial-failure JSON must contain request_id; got: {json}"
        );

        // The error code must be the validation code, not a generic one.
        let e = env.error.as_ref().expect("error must be present");
        assert_eq!(
            e.code,
            err.code(),
            "error code must match WalletError::code()"
        );
    }

    // ── err_raw and err_raw_with_request_id ──────────────────────────────────

    /// `Envelope::err_raw` constructs an error envelope from a raw code +
    /// message string without a `WalletError`.  The auto-generated request_id
    /// must be a non-empty string; the code and message fields must round-trip
    /// exactly.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on Option is the assertion"
    )]
    fn err_raw_sets_code_and_message() {
        let env = Envelope::err_raw("counterparty.fetch_failed", "connection refused");
        assert!(!env.ok);
        assert!(env.data.is_none());
        assert!(!env.request_id.is_empty(), "request_id must be non-empty");

        let e = env.error.as_ref().expect("error must be present");
        assert_eq!(e.code, "counterparty.fetch_failed");
        assert_eq!(e.message, "connection refused");
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on Option is the assertion"
    )]
    fn err_raw_with_request_id_sets_all_fields() {
        let env = Envelope::err_raw_with_request_id(
            "counterparty.hmac_mismatch",
            "HMAC tag did not match",
            "raw-fixed-id".to_owned(),
        );
        assert!(!env.ok);
        assert!(env.data.is_none());
        assert_eq!(env.request_id, "raw-fixed-id");

        let e = env.error.as_ref().expect("error must be present");
        assert_eq!(e.code, "counterparty.hmac_mismatch");
        assert_eq!(e.message, "HMAC tag did not match");
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; panic on unexpected serialisation failure"
    )]
    fn err_raw_with_request_id_json_key_order() {
        let env = Envelope::err_raw_with_request_id(
            "test.code",
            "test message",
            "raw-order-id".to_owned(),
        );
        let json = env.to_json_compact().expect("serialisation must succeed");
        // ok appears first, error second (no data), request_id last.
        assert!(
            json.starts_with(r#"{"ok":false,"error":"#),
            "err_raw JSON must start ok:false then error; got: {json}"
        );
        assert!(
            json.ends_with(r#","request_id":"raw-order-id"}"#),
            "err_raw JSON must end with request_id; got: {json}"
        );
        assert!(
            !json.contains(r#""data""#),
            "err_raw JSON must not contain a data key; got: {json}"
        );
    }

    // ── OutputFormat::DEFAULT constant ────────────────────────────────────────

    #[test]
    fn output_format_default_is_json() {
        assert_eq!(
            OutputFormat::DEFAULT,
            OutputFormat::Json,
            "OutputFormat::DEFAULT must be Json"
        );
    }

    // ── OutputFormat::FromStr trait ───────────────────────────────────────────

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "test-only; unwrap on expected-Ok is the assertion"
    )]
    fn output_format_from_str_delegates_to_parse() {
        use std::str::FromStr as _;

        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
        assert_eq!(
            OutputFormat::from_str("table").unwrap(),
            OutputFormat::Table
        );
        // Case-insensitive, same as parse.
        assert_eq!(OutputFormat::from_str("JSON").unwrap(), OutputFormat::Json);
        assert_eq!(
            OutputFormat::from_str("TABLE").unwrap(),
            OutputFormat::Table
        );
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "test-only; unwrap_err on expected-Err is the assertion"
    )]
    fn output_format_from_str_invalid_returns_error() {
        use std::str::FromStr as _;

        let result = OutputFormat::from_str("csv");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "validation.output_format_invalid");
    }

    // ── to_json_pretty serde-failure path ────────────────────────────────────

    #[test]
    fn to_json_pretty_serde_failure_returns_serialisation_failed() -> Result<(), String> {
        use std::collections::BTreeMap;

        // A BTreeMap with a tuple key cannot be serialised as a JSON object.
        let payload = BTreeMap::from([((1_u8, 2_u8), "bad-key")]);
        let env = Envelope::ok_with_request_id(payload, "pretty-fail-id".to_owned());

        match env.to_json_pretty() {
            Ok(_) => Err("tuple-keyed map unexpectedly serialised via to_json_pretty".to_owned()),
            Err(WalletError::Internal(InternalError::SerialisationFailed { .. })) => Ok(()),
            Err(other) => Err(format!("expected SerialisationFailed, got {other:?}")),
        }
    }

    // ── Envelope::ok generates unique request_ids ─────────────────────────────

    #[test]
    fn ok_generates_unique_request_ids() {
        let ids: std::collections::HashSet<String> =
            (0..50).map(|_| Envelope::ok(0_i32).request_id).collect();
        assert_eq!(
            ids.len(),
            50,
            "Envelope::ok must generate a unique UUIDv4 request_id on each call"
        );
    }

    // ── Envelope::err generates a valid UUIDv4 request_id ────────────────────

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on UUID parse failure is the assertion"
    )]
    fn err_auto_generates_uuidv4_request_id() {
        let err = WalletError::Validation(ValidationError::AmountUnitsRequired);
        let env = Envelope::err(&err);
        let parsed = uuid::Uuid::parse_str(&env.request_id)
            .expect("auto-generated request_id on err must be a valid UUID");
        assert_eq!(
            parsed.get_version_num(),
            4,
            "auto-generated request_id on err must be UUIDv4"
        );
    }

    // ── err_raw generates a valid UUIDv4 request_id ──────────────────────────

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on UUID parse failure is the assertion"
    )]
    fn err_raw_auto_generates_uuidv4_request_id() {
        let env = Envelope::err_raw("some.code", "some message");
        let parsed = uuid::Uuid::parse_str(&env.request_id)
            .expect("auto-generated request_id on err_raw must be a valid UUID");
        assert_eq!(
            parsed.get_version_num(),
            4,
            "auto-generated request_id on err_raw must be UUIDv4"
        );
    }

    // ── partial-failure JSON round-trip ───────────────────────────────────────

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on parse failure is the assertion"
    )]
    fn partial_failure_json_round_trip() {
        let err = WalletError::Validation(ValidationError::AmountUnitsRequired);
        let env = Envelope::partial_failure_with_request_id(42_i32, &err, "pf-rt-id".to_owned());
        let json = env.to_json_compact().expect("serialisation must succeed");
        let parsed: Envelope<i32> =
            serde_json::from_str(&json).expect("round-trip must produce valid JSON");
        assert!(!parsed.ok);
        assert_eq!(parsed.data, Some(42));
        assert!(parsed.error.is_some());
        assert_eq!(parsed.request_id, "pf-rt-id");
    }
}

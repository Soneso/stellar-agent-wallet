//! Process-wide tracing subscriber stack and runtime redaction layer.
//!
//! This module provides two public entry-points:
//!
//! 1. [`init_subscriber`] — installs the process-wide tracing subscriber
//!    (env-filter, fmt layer, panic hook, and `log`-crate bridge) once at binary
//!    startup.
//!
//! 2. `RedactingLayer` — a [`tracing_subscriber::fmt::FormatFields`] wrapper and
//!    companion JSON event formatter ([`RedactingJsonFormatter`]) that enforce the
//!    runtime (belt-and-braces) half of the two-layer redaction strategy.
//!
//! # Architecture: two integration points, one for each format
//!
//! ## Pretty format
//!
//! The `tracing_subscriber` `Format<Full>` and `Format<Pretty>` formatters call
//! `ctx.format_fields(writer, event)` inside `format_event`, which ultimately
//! delegates to the `fmt_fields` field-formatter parameter (see
//! `tracing-subscriber/src/fmt/format/mod.rs` lines 1045 and 1164, commit
//! `54ede4d`).  Therefore, a custom [`FormatFields`] implementation passed via
//! `Layer::fmt_fields` intercepts event fields **before** they are written.
//! `RedactingLayer<DefaultFields>` takes this path.
//!
//! ## JSON format
//!
//! The `Format<Json>` formatter does **not** call `format_fields` for event fields.
//! Instead it serialises events directly via `tracing_serde::fields::AsMap` (see
//! `tracing-subscriber/src/fmt/format/json.rs` line 272, same commit):
//!
//! ```text
//! serializer.serialize_entry("fields", &event.field_map())?;
//! ```
//!
//! This bypasses the `fmt_fields` parameter entirely for event-level fields.
//! (The `fmt_fields` parameter is only used for *span* field storage in the JSON
//! path.)
//!
//! Therefore, for JSON output, we use a custom [`FormatEvent`] implementation —
//! [`RedactingJsonFormatter`] — that visits the event with a `FieldCollector` and
//! writes the JSON `"fields"` object with already-redacted values.
//!
//! ## Call-order note
//!
//! `tracing_subscriber`'s layered dispatch calls the **inner** subscriber/layers
//! first, then the outer layer (`layered.rs` lines 156–159, same commit).  A
//! registry `Layer`'s `on_event` therefore fires *after* the fmt layer has
//! already serialised the event — too late to redact.  The `FormatFields` /
//! `FormatEvent` integration points run *during* serialisation and are the correct
//! hooks.
//!
//! # Stellar strkey version bytes
//!
//! Layer 2 redacts three strkey classes unconditionally:
//!
//! | Prefix | Version byte   | Type              |
//! |--------|---------------|-------------------|
//! | `S`    | `18 << 3 = 0x90` | `PrivateKeyEd25519` (ed25519SecretSeed) |
//! | `T`    | `19 << 3 = 0x98` | `PreAuthTx`       |
//! | `X`    | `23 << 3 = 0xB8` | `HashX` (sha256Hash) |
//!
//! Version bytes are defined by the Stellar strkey specification.
//! Validation is delegated to [`stellar_strkey::Strkey::from_string`].
//!
//! `G`, `C`, `M`, `P`-prefixed keys (public keys, contract addresses, muxed
//! accounts, signed payloads) are handled at Layer 1 (redacting newtypes) and
//! are NOT caught by Layer 2 to preserve the Layer-1 first-5-last-5 rendering.
//!
//! # Invariants
//!
//! * [`init_subscriber`] must be called at most once per process; a second call
//!   returns [`InitError::Init`].
//! * The panic hook installed by [`init_subscriber`] deliberately does NOT invoke
//!   the default Rust panic hook after routing the payload through
//!   `tracing::error!`.  See `InitOptions::install_panic_hook` for the rationale.
//! * `RedactingLayer` and [`RedactingJsonFormatter`] never re-inspect events with
//!   the target `stellar_agent_core::observability::redaction_fired`, preventing
//!   infinite recursion on the warning emitted when redaction fires.
//! * Fields whose names start with `log.` (injected by the `tracing-log` bridge)
//!   are silently skipped in `FieldCollector` so they do not appear in output.

pub mod redact;
pub use redact::redact_strkey_first5_last5;

use std::fmt as std_fmt;
use std::ops::Deref;
use std::time::SystemTime;

use crate::audit_log::redact::redact_account_strkeys_first5_last5;
use crate::timefmt::epoch_to_datetime;
use serde::{Deserialize, Serialize};

use tracing_subscriber::{
    EnvFilter,
    fmt::{
        self, FmtContext, FormatEvent, FormatFields, FormattedFields,
        format::{DefaultFields, Writer},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

/// Target string used for the "Layer 2 fired" warning.
///
/// Events with this target are not re-inspected by redacting formatters to
/// prevent infinite recursion.
const REDACTION_FIRED_TARGET: &str = "stellar_agent_core::observability::redaction_fired";

/// Redacts a string to first-5-last-5 char form.
///
/// Returns the input verbatim if shorter than 10 chars because the pattern
/// cannot be applied without head/tail overlap. This is intentional for
/// non-secret display sentinels and short audit fields such as `""`; callers
/// handling secret or user-controlled short values must mask those values
/// before or after calling this helper. Failing to mask a secret short value
/// before calling this helper would write the secret verbatim into a log line.
/// For base64url-like inputs, 10+-char outputs match the operator-canonical
/// `^[A-Za-z0-9_-]{5}\.\.\.[A-Za-z0-9_-]{5}$` shape; other input alphabets
/// such as hex digests or the `<no-credential-id>` sentinel retain their own
/// head and tail alphabets.
#[must_use]
pub fn redact_first5_last5(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 10 {
        // first-5-last-5 is a shape-preserving display helper.
        // Short inputs have no non-overlapping head/tail; preserving them keeps
        // empty audit fields and display sentinels semantically distinct.
        return s.to_owned();
    }
    let head: String = chars[..5].iter().collect();
    let tail: String = chars[chars.len() - 5..].iter().collect();
    format!("{head}...{tail}")
}

/// Redacted Stellar strkey display value.
///
/// This wrapper makes Layer-1 strkey redaction explicit in error and audit
/// schemas while preserving the existing JSON wire shape via transparent serde.
///
/// # Construction discipline
///
/// The newtype has **no `From<&str>` / `From<String>` impls** to prevent a
/// future caller from silently routing a raw `G…` / `C…` strkey through
/// `.into()`. Every construction goes through one of two named constructors:
///
/// - [`Self::from_full`] — the **preferred** path. Pass the raw strkey; the
///   constructor applies [`redact_strkey_first5_last5`]. Use this everywhere
///   the call site still has the original strkey in scope.
/// - [`Self::from_already_redacted`] — for paths where the caller only carries
///   the pre-redacted display string (e.g. a `let X_redacted = redact_…(&strkey);`
///   binding reused across multiple constructions, or test fixtures that hard-code
///   the redacted shape). The constructor performs no validation — the caller
///   asserts the precondition by name.
///
/// Redaction discipline is enforced at the API boundary, not just by convention.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedactedStrkey(String);

impl RedactedStrkey {
    /// Redact a full Stellar strkey to first-5-last-5 form.
    ///
    /// **Preferred constructor.** Use this at every emission site where the raw
    /// strkey is in scope; it forecloses the "I forgot to call
    /// `redact_strkey_first5_last5` first" failure mode.
    #[must_use]
    pub fn from_full(strkey: &str) -> Self {
        Self(redact_strkey_first5_last5(strkey))
    }

    /// Wrap a value that has already been redacted.
    ///
    /// Use only where the call site does not have the original strkey
    /// in scope (e.g. shared binding reused across multiple constructions,
    /// test fixtures that hard-code the redacted shape, or deserialization
    /// paths). Prefer [`Self::from_full`] at every emission site that still
    /// has the raw strkey.
    ///
    /// This constructor performs no shape validation — the caller asserts the
    /// precondition by name.
    #[must_use]
    pub fn from_already_redacted(redacted: impl Into<String>) -> Self {
        Self(redacted.into())
    }

    /// Borrow the redacted display string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std_fmt::Display for RedactedStrkey {
    fn fmt(&self, f: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RedactedStrkey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for RedactedStrkey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl PartialEq<&str> for RedactedStrkey {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<str> for RedactedStrkey {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<RedactedStrkey> for &str {
    fn eq(&self, other: &RedactedStrkey) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<String> for RedactedStrkey {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<RedactedStrkey> for String {
    fn eq(&self, other: &RedactedStrkey) -> bool {
        self == other.as_str()
    }
}

impl From<RedactedStrkey> for String {
    fn from(value: RedactedStrkey) -> Self {
        value.0
    }
}

/// Returns true iff `url` is an `http://` URL bound to loopback.
///
/// Accepted hosts are the `localhost` label and the IPv4 / IPv6 loopback
/// literals `127.0.0.1` and `[::1]`. The `url` crate returns IPv6
/// `host_str()` values in bracketed form, so the IPv6 arm intentionally matches
/// `[::1]`. Other schemes, missing hosts, userinfo bypass forms that resolve
/// to a non-loopback host, and non-loopback hosts return `false`.
#[must_use]
pub fn is_loopback_http_url(candidate: &str) -> bool {
    let Ok(parsed) = url::Url::parse(candidate) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    matches!(
        parsed.host_str(),
        Some(host)
            if host.eq_ignore_ascii_case("localhost")
                || host == "127.0.0.1"
                || host == "[::1]"
    )
}

// ── Environment variable names ──────────────────────────────────────────────

/// Well-known environment variable names used for log configuration.
///
/// Exported so binary crates can include the names in `--help` output and tests
/// can clear them without hard-coding the strings.
pub mod env_var {
    /// Primary log-level filter expression (`RUST_LOG`-style syntax).
    ///
    /// Takes precedence over [`RUST_LOG_FALLBACK`] when both are set.
    pub const LOG_LEVEL: &str = "STELLAR_AGENT_LOG";

    /// Output format selector: `json` or `pretty`.
    ///
    /// Overridden by the `log_format_override` argument to
    /// [`crate::observability::init_subscriber`].
    pub const LOG_FORMAT: &str = "STELLAR_AGENT_LOG_FORMAT";

    /// Fallback log-level filter used when [`LOG_LEVEL`] is unset.
    pub const RUST_LOG_FALLBACK: &str = "RUST_LOG";

    /// When set (to any value), disables ANSI colour codes in the pretty format,
    /// regardless of TTY detection.  Follows the <https://no-color.org> convention.
    pub const NO_COLOR: &str = "NO_COLOR";
}

// ── FormatChoice ─────────────────────────────────────────────────────────────

/// Output format for structured logs.
///
/// `Json` emits newline-delimited JSON on stderr (machine-readable default).
/// `Pretty` emits a human-readable multi-line format suitable for interactive
/// use.
///
/// # Stability
///
/// `#[non_exhaustive]` because a `Custom(Box<dyn …>)` or additional format
/// variant (e.g. `Logfmt`) may be added in the future without a breaking
/// change.  External match arms must include a wildcard fallback.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatChoice {
    /// Newline-delimited JSON (default for non-TTY / scripted use).
    Json,
    /// Human-readable pretty format (default when stderr is a TTY).
    Pretty,
}

impl FormatChoice {
    /// Resolve the output format with the following precedence:
    ///
    /// 1. `log_format_override` — typically the `--log-format` CLI flag (highest
    ///    priority).
    /// 2. `STELLAR_AGENT_LOG_FORMAT` env var (`json` or `pretty`,
    ///    case-insensitive).
    /// 3. Auto-detect via `isatty(stderr)`: `Pretty` when attached to a TTY,
    ///    `Json` otherwise (default for CI, pipes, and MCP stdio).
    ///
    /// An unrecognised override or env-var value is treated as `Json` (safe
    /// default) and does not panic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_agent_core::observability::FormatChoice;
    ///
    /// // Explicit override wins regardless of environment.
    /// let choice = FormatChoice::from_env_and_tty(Some("json"));
    /// assert_eq!(choice, FormatChoice::Json);
    ///
    /// let choice = FormatChoice::from_env_and_tty(Some("pretty"));
    /// assert_eq!(choice, FormatChoice::Pretty);
    ///
    /// // Unknown value falls back to Json (safe default).
    /// let choice = FormatChoice::from_env_and_tty(Some("unknown"));
    /// assert_eq!(choice, FormatChoice::Json);
    /// ```
    pub fn from_env_and_tty(log_format_override: Option<&str>) -> Self {
        // 1. Explicit override (highest priority).
        if let Some(s) = log_format_override {
            return Self::parse_format_str(s);
        }

        // 2. Environment variable.
        if let Ok(val) = std::env::var(env_var::LOG_FORMAT) {
            return Self::parse_format_str(&val);
        }

        // 3. TTY auto-detect (stable since Rust 1.70, well below MSRV 1.89).
        use std::io::IsTerminal as _;
        if std::io::stderr().is_terminal() {
            FormatChoice::Pretty
        } else {
            FormatChoice::Json
        }
    }

    /// Parse a string (`"json"` or `"pretty"`, case-insensitive).
    ///
    /// Anything not recognised maps to [`FormatChoice::Json`] as a safe default.
    pub(crate) fn parse_format_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "pretty" => FormatChoice::Pretty,
            _ => FormatChoice::Json,
        }
    }
}

// ── InitError ────────────────────────────────────────────────────────────────

/// Errors that can occur during subscriber initialisation.
///
/// Returned by [`init_subscriber`]; see each variant for trigger conditions.
///
/// # Stability
///
/// `#[non_exhaustive]` because new infrastructure-level failures (e.g. an
/// OpenTelemetry-exporter init error) may be added in the future without a
/// breaking change.  External match arms must include a wildcard fallback.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The `STELLAR_AGENT_LOG` (or `RUST_LOG`) value could not be parsed as a
    /// valid `EnvFilter` expression.
    #[error("failed to parse log-filter expression: {0}")]
    Filter(#[source] tracing_subscriber::filter::FromEnvError),

    /// The `log`-crate bridge (`tracing_log::LogTracer`) could not be installed.
    ///
    /// Most commonly because another `log`-crate logger was installed first.
    #[error("failed to install log-crate bridge: {0}")]
    LogBridge(#[source] tracing_log::log_tracer::SetLoggerError),

    /// The tracing subscriber `try_init` call failed.
    ///
    /// Most commonly because a global subscriber was already installed by
    /// the first successful [`init_subscriber`] call. On a second call by
    /// the same process, [`Self::LogBridge`] is typically returned first
    /// (the `log`-crate bridge is installed earlier in the init sequence),
    /// so reaching `Init` requires a caller that installed a subscriber
    /// through some other code path without going through
    /// [`init_subscriber`].
    #[error("failed to install tracing subscriber: {0}")]
    Init(#[source] tracing_subscriber::util::TryInitError),
}

// ── Field collection ─────────────────────────────────────────────────────────

/// Maximum bytes captured from a single `Debug` or `Error` field value.
///
/// Fields whose `Debug` rendering exceeds this limit are captured up to the
/// limit and tagged `[TRUNCATED]`.  This bounds the per-event allocation cost
/// on the hot-path to at most `MAX_FIELD_BYTES + overhead` per field, regardless
/// of the payload size.
///
/// 16 KiB is generous for any structured log field; real wallet events are
/// typically under 512 bytes.
pub(crate) const MAX_FIELD_BYTES: usize = 16 * 1024;

/// Collected by the internal `FieldCollector` visitor after all redaction checks
/// have been applied.
pub(crate) enum RedactedValue {
    /// String value (from `record_str` or `record_debug`), possibly redacted.
    Str(String),
    /// Unsigned 64-bit integer, possibly redacted to `[REDACTED]`.
    U64(u64),
    /// Signed 64-bit integer, possibly redacted to `[REDACTED]`.
    I64(i64),
    /// Double-precision float, possibly redacted to `[REDACTED]`.
    F64(f64),
    /// Boolean, possibly redacted to `[REDACTED]`.
    Bool(bool),
}

/// Visitor that collects field name/value pairs from a tracing `Event`,
/// applying all Layer 2 redaction checks.
///
/// Fields whose names start with `log.` are silently dropped.  These are
/// injected by the `tracing-log` bridge (`tracing_log::LogTracer`) and carry
/// metadata (`log.module_path`, `log.file`, `log.line`) that the upstream
/// `DefaultVisitor` already suppresses (verified at
/// `tracing-subscriber/src/fmt/format/mod.rs` lines 1306–1311, commit
/// `54ede4d`).  Surfacing them inline would clutter every bridged `log::*`
/// event.
#[derive(Default)]
pub(crate) struct FieldCollector {
    /// Collected fields after redaction.  Field names are `&'static str`
    /// because `tracing::field::Field::name()` returns `&'static str`.
    pub(crate) fields: Vec<(&'static str, RedactedValue)>,
    /// Set to `true` if any field was redacted during collection.
    pub(crate) did_redact: bool,
    /// Set to `true` if any `Debug` or `Error` field's rendering exceeded
    /// [`MAX_FIELD_BYTES`] and was truncated.  Emits `[TRUNCATED]` suffix.
    ///
    /// This flag is informational: the truncated output was still scanned
    /// for redactable patterns up to the captured length.  The truncated
    /// suffix is never itself a secret.
    pub(crate) field_truncated_for_redaction: bool,
}

impl tracing::field::Visit for FieldCollector {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // Skip log.* bridge metadata fields.
        if field.name().starts_with("log.") {
            return;
        }
        // Size-capped capture: writing the full Debug rendering into a LimitedWriter
        // prevents unbounded allocation on oversized payloads.
        let (raw, truncated) = format_debug_capped(value, MAX_FIELD_BYTES);
        if truncated {
            self.field_truncated_for_redaction = true;
        }
        let (out, redacted) = redact_value(field.name(), &raw);
        if redacted {
            self.did_redact = true;
        }
        self.fields.push((field.name(), RedactedValue::Str(out)));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        // Skip log.* bridge metadata fields.
        if field.name().starts_with("log.") {
            return;
        }
        let (out, redacted) = redact_value(field.name(), value);
        if redacted {
            self.did_redact = true;
        }
        self.fields.push((field.name(), RedactedValue::Str(out)));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        // Skip log.* bridge metadata fields.
        if field.name().starts_with("log.") {
            return;
        }
        // Numeric fields with sensitive names must be redacted.
        if should_redact_by_name(field.name()) {
            self.did_redact = true;
            self.fields
                .push((field.name(), RedactedValue::Str("[REDACTED]".to_owned())));
        } else {
            self.fields.push((field.name(), RedactedValue::U64(value)));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        // Skip log.* bridge metadata fields.
        if field.name().starts_with("log.") {
            return;
        }
        // Numeric fields with sensitive names must be redacted.
        if should_redact_by_name(field.name()) {
            self.did_redact = true;
            self.fields
                .push((field.name(), RedactedValue::Str("[REDACTED]".to_owned())));
        } else {
            self.fields.push((field.name(), RedactedValue::I64(value)));
        }
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        // Skip log.* bridge metadata fields.
        if field.name().starts_with("log.") {
            return;
        }
        // Numeric fields with sensitive names must be redacted.
        if should_redact_by_name(field.name()) {
            self.did_redact = true;
            self.fields
                .push((field.name(), RedactedValue::Str("[REDACTED]".to_owned())));
        } else {
            self.fields.push((field.name(), RedactedValue::F64(value)));
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        // Skip log.* bridge metadata fields.
        if field.name().starts_with("log.") {
            return;
        }
        // Boolean fields with sensitive names must be redacted.
        if should_redact_by_name(field.name()) {
            self.did_redact = true;
            self.fields
                .push((field.name(), RedactedValue::Str("[REDACTED]".to_owned())));
        } else {
            self.fields.push((field.name(), RedactedValue::Bool(value)));
        }
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        // Skip log.* bridge metadata fields.
        if field.name().starts_with("log.") {
            return;
        }
        // Size-capped capture for Display-formatted errors.
        let (raw, truncated) = format_display_capped(value, MAX_FIELD_BYTES);
        if truncated {
            self.field_truncated_for_redaction = true;
        }
        let (out, redacted) = redact_value(field.name(), &raw);
        if redacted {
            self.did_redact = true;
        }
        self.fields.push((field.name(), RedactedValue::Str(out)));
    }
}

// ── RedactingLayer ────────────────────────────────────────────────────────────

/// A [`FormatFields`] wrapper that intercepts field values and rewrites
/// sensitive material to `[REDACTED]` before the fmt layer serialises them.
///
/// **Integration path:** used with the *pretty* format only, via
/// [`fmt::Layer::fmt_fields`](tracing_subscriber::fmt::Layer::fmt_fields).  The
/// `Full` and `Pretty` event formatters call `ctx.format_fields(writer, event)`
/// (`tracing-subscriber/src/fmt/format/mod.rs` lines 1045 / 1164, commit
/// `54ede4d`), which delegates to the `fmt_fields` parameter — our
/// `RedactingLayer`.
///
/// **JSON path:** the `Format<Json>` event formatter does NOT call `format_fields`
/// for event fields; it uses `tracing_serde::fields::AsMap` directly (line 272,
/// same commit).  For JSON output, redaction is handled by
/// [`RedactingJsonFormatter`], which implements [`FormatEvent`] and visits the
/// event with a `FieldCollector` before writing the `"fields"` JSON object.
///
/// # Redaction rules (Layer 2)
///
/// 1. **Validated S/T/X-strkey** — any `[STX][A-Z2-7]{55}` candidate that
///    parses as a `PrivateKeyEd25519` (`S`), `PreAuthTx` (`T`), or `HashX`
///    (`X`) strkey is replaced with `[REDACTED]`.  Validation covers version
///    byte, payload length, and CRC-16.
/// 2. **Field-name exact match (case-insensitive)** — fields on the redact list
///    have their value replaced with `[REDACTED]`.  Fields on the pass-through
///    list are never touched; pass-through is checked first.
/// 3. **BIP-39 mnemonic check** — 12–24 words in multiples of 3, separated by
///    single spaces, where every word is in the English BIP-39 word list; no
///    checksum required (permissive mode; see [`is_bip39_mnemonic`] for
///    rationale).
///
/// # Telemetry on redaction
///
/// Every redaction emits a `tracing::warn!` on the dedicated target
/// `stellar_agent_core::observability::redaction_fired`.
#[derive(Debug, Clone)]
pub(crate) struct RedactingLayer<N> {
    _marker: std::marker::PhantomData<fn() -> N>,
}

impl<N> Default for RedactingLayer<N> {
    fn default() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl RedactingLayer<DefaultFields> {
    /// Create a new `RedactingLayer` for the pretty (default) field format.
    ///
    /// Use with [`fmt::layer().pretty()`](tracing_subscriber::fmt::layer).
    #[must_use]
    pub(crate) fn new_pretty() -> Self {
        Self::default()
    }
}

/// `FormatFields` for the pretty variant.
///
/// Writes `key=value` pairs separated by spaces, matching `DefaultVisitor`
/// output (`tracing-subscriber/src/fmt/format/mod.rs` lines 1299–1340, commit
/// `54ede4d`).
impl<'writer> FormatFields<'writer> for RedactingLayer<DefaultFields> {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        let mut collector = FieldCollector::default();
        fields.record(&mut collector);
        emit_redaction_warning(collector.did_redact);
        write_pretty_fields(&mut writer, &collector.fields)?;
        // Append [TRUNCATED] marker when any field value was size-capped.
        if collector.field_truncated_for_redaction {
            write!(writer, " [TRUNCATED]")?;
        }
        Ok(())
    }
}

// ── RedactingJsonFormatter ────────────────────────────────────────────────────

/// A custom [`FormatEvent`] that produces newline-delimited JSON output with
/// Layer 2 redaction applied to event field values and span fields.
///
/// **Why a custom `FormatEvent` is needed for JSON:** The standard
/// `Format<Json>` formatter serialises event fields via
/// `tracing_serde::fields::AsMap` (verified at
/// `tracing-subscriber/src/fmt/format/json.rs` line 272, commit `54ede4d`),
/// which bypasses the `fmt_fields` field-formatter parameter.  A custom
/// `FormatEvent` is the only way to intercept field values in the JSON output
/// path.
///
/// # Output schema
///
/// ```json
/// {
///   "timestamp": "2026-04-23T18:40:00.123456Z",
///   "level": "INFO",
///   "fields": { "account": "GAAAA..ZZZZZ", "operation": "sign" },
///   "truncated": true,
///   "target": "stellar_agent_core::smart_account::auth",
///   "span": { "name": "sign_tx", "fields": "request_id=abc" },
///   "spans": [
///     { "name": "wallet_request", "fields": "tool=stellar_pay_commit" },
///     { "name": "sign_tx", "fields": "request_id=abc" }
///   ]
/// }
/// ```
///
/// The `"span"` key carries the immediate (innermost) span.  The `"spans"`
/// array is ordered root-to-leaf (outermost first, matching
/// `tracing_subscriber`'s own JSON formatter convention).  Both keys are
/// omitted when no span context is active.
///
/// The `"truncated": true` top-level key appears between `"fields"` and
/// `"target"` when any field value was capped at `MAX_FIELD_BYTES` by the
/// `FieldCollector`.  It is absent when no field was capped.  Consumers
/// that need to distinguish truncated log lines from full ones should test
/// for this key's presence.
///
/// Span field values are run through `redact_strkeys` to catch any
/// S/T/X strkeys embedded in pre-formatted field strings.  Per-field
/// name-based redaction is not possible on pre-formatted strings (a
/// known limitation of the `FormattedFields<N>` architecture); strkey
/// pattern matching covers the most security-critical cases.
///
/// # Construction
///
/// Created by [`init_subscriber`] when [`FormatChoice::Json`] is selected.
/// Not normally constructed directly by callers.
#[derive(Debug)]
pub struct RedactingJsonFormatter {
    display_timestamp: bool,
    display_target: bool,
}

impl Default for RedactingJsonFormatter {
    fn default() -> Self {
        Self {
            display_timestamp: true,
            display_target: true,
        }
    }
}

impl RedactingJsonFormatter {
    /// Create a new formatter.
    ///
    /// Used by [`init_subscriber`] when [`FormatChoice::Json`] is selected,
    /// and by external crates building a test subscriber with redaction
    /// (e.g. `stellar-agent-network/tests/redaction_audit.rs`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a formatter that omits timestamps (used in tests for
    /// deterministic output). Gated on `cfg(test)` because production paths
    /// always want timestamps.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn without_time() -> Self {
        Self {
            display_timestamp: false,
            display_target: true,
        }
    }
}

impl<S, N> FormatEvent<S, N> for RedactingJsonFormatter
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        // Do NOT return early for REDACTION_FIRED_TARGET events.
        // The warning message is a static literal and will not match any
        // redaction pattern, so no infinite recursion occurs.  Serialising
        // this event normally ensures the warning is visible in JSON output.

        // Collect and redact event fields.
        let mut collector = FieldCollector::default();
        event.record(&mut collector);
        emit_redaction_warning(collector.did_redact);

        // Collect span chain (innermost to outermost) for later emission.
        // Each entry is (span_name, redacted_fields_string).
        // Span fields are stored as pre-formatted strings in FormattedFields<N>;
        // redact_strkeys is applied as a belt-and-braces pass to catch any
        // S/T/X strkeys that appeared in span field values.  Per-field
        // name-based redaction is not available on pre-formatted strings — a
        // known limitation of the FormattedFields<N> architecture.
        let span_chain: Vec<(String, String)> = ctx
            .parent_span()
            .map(|span| {
                span.scope()
                    .map(|s| {
                        let name = s.metadata().name().to_owned();
                        let fields_str = s
                            .extensions()
                            .get::<FormattedFields<N>>()
                            .map(|ff| {
                                // Apply S/T/X strkey redaction.
                                let (after_stx, stx_redacted) = redact_strkeys(ff.fields.as_str());
                                // Also apply G/C account-ID redaction.
                                // Span field strings are pre-formatted; we apply both
                                // redaction passes to cover all strkey classes.
                                let (after_gc, gc_redacted) =
                                    redact_account_strkeys_first5_last5(&after_stx);
                                if stx_redacted || gc_redacted {
                                    emit_redaction_warning(true);
                                }
                                after_gc
                            })
                            .unwrap_or_default();
                        (name, fields_str)
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Write the JSON object.
        write!(writer, "{{")?;
        let mut comma = false;

        // timestamp
        if self.display_timestamp
            && let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        {
            // Format as ISO-8601 UTC (simplified: seconds + microseconds).
            let secs = now.as_secs();
            let micros = now.subsec_micros();
            let (year, month, day, hour, min, sec) = epoch_to_datetime(secs);
            let ts = std::format!(
                "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{micros:06}Z"
            );
            write!(writer, "\"timestamp\":")?;
            write_json_str(&mut writer, &ts)?;
            comma = true;
        }

        // level
        if comma {
            write!(writer, ",")?;
        }
        write!(writer, "\"level\":")?;
        write_json_str(&mut writer, event.metadata().level().as_str())?;

        // fields
        write!(writer, ",\"fields\":{{")?;
        write_json_fields(&mut writer, &collector.fields)?;
        write!(writer, "}}")?;

        // Emit top-level "truncated":true when any field value was capped.
        if collector.field_truncated_for_redaction {
            write!(writer, ",\"truncated\":true")?;
        }

        // target
        if self.display_target {
            write!(writer, ",\"target\":")?;
            write_json_str(&mut writer, event.metadata().target())?;
        }

        // span — the immediate (innermost) span, if any.
        // Emitted after "target" to keep the stable schema order:
        // timestamp → level → fields → target → span → spans.
        if !span_chain.is_empty() {
            // span_chain is innermost-first from scope(); innermost = index 0.
            let (ref name, ref fields) = span_chain[0];
            write!(writer, ",\"span\":{{")?;
            write!(writer, "\"name\":")?;
            write_json_str(&mut writer, name)?;
            write!(writer, ",\"fields\":")?;
            write_json_str(&mut writer, fields)?;
            write!(writer, "}}")?;

            // spans — root-to-leaf order (matching tracing_subscriber JSON convention).
            write!(writer, ",\"spans\":[")?;
            for (i, (span_name, span_fields)) in span_chain.iter().rev().enumerate() {
                if i > 0 {
                    write!(writer, ",")?;
                }
                write!(writer, "{{")?;
                write!(writer, "\"name\":")?;
                write_json_str(&mut writer, span_name)?;
                write!(writer, ",\"fields\":")?;
                write_json_str(&mut writer, span_fields)?;
                write!(writer, "}}")?;
            }
            write!(writer, "]")?;
        }

        writeln!(writer, "}}")
    }
}

// ── Size-capped formatting helpers ────────────────────────────────────────────

/// Suffix appended to truncated field values.
const TRUNCATION_SUFFIX: &str = "...[TRUNCATED]";

/// Maximum byte length of the pre-redaction formatted string.
///
/// A custom [`LimitedWriter`] caps `fmt::Debug` / `fmt::Display` output at
/// this size, bounding allocation before redaction fires.  1 MiB is generous
/// for any realistic field value.
pub(crate) const MAX_PRE_REDACT_BYTES: usize = 1024 * 1024;

// ── LimitedWriter ─────────────────────────────────────────────────────────────

/// A [`std::fmt::Write`] adapter that caps output at `limit` bytes.
///
/// Once the buffer reaches `limit`, additional writes are silently dropped and
/// `overflowed` is set to `true`.  A fixed truncation marker
/// (`...[TRUNCATED]`) is appended when the limit is first crossed.
///
/// # Invariant
///
/// After every call to [`write_str`](std::fmt::Write::write_str), the internal
/// buffer satisfies `buf.len() <= limit + TRUNCATION_SUFFIX.len()`:
///
/// - Before overflow: `buf.len() <= limit` (only the prefix up to the UTF-8
///   boundary that fits within `remaining = limit - buf.len()` is pushed).
/// - On overflow: `buf.len() <= limit` immediately after the prefix is pushed
///   (proven by the `remaining` bound), so the unconditional
///   `buf.push_str(suffix)` brings the total to at most
///   `limit + TRUNCATION_SUFFIX.len()`.
/// - After overflow: all further writes are rejected early.
///
/// This bounds the allocation made during `value.fmt(&mut writer)` to at most
/// `MAX_PRE_REDACT_BYTES + TRUNCATION_SUFFIX.len()` regardless of how much
/// output the `Debug`/`Display` impl tries to write.
struct LimitedWriter {
    buf: String,
    limit: usize,
    overflowed: bool,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            buf: String::with_capacity(limit.min(64 * 1024)),
            limit,
            overflowed: false,
        }
    }

    fn into_string(self) -> (String, bool) {
        (self.buf, self.overflowed)
    }
}

impl std::fmt::Write for LimitedWriter {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.overflowed {
            return Ok(());
        }
        let remaining = self.limit.saturating_sub(self.buf.len());
        if s.len() <= remaining {
            self.buf.push_str(s);
        } else {
            // Write as much as fits at a UTF-8 boundary.
            let mut end = remaining;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            self.buf.push_str(&s[..end]);
            // Invariant: buf.len() <= self.limit here because end <= remaining
            // = self.limit - self.buf.len() (before the push_str above).
            // The suffix push below therefore stays within limit + suffix.len().
            debug_assert!(
                self.buf.len() <= self.limit,
                "LimitedWriter invariant: buf must not exceed limit before suffix append"
            );
            self.overflowed = true;
            self.buf.push_str(TRUNCATION_SUFFIX);
        }
        Ok(())
    }
}

/// Format a `Debug` value with bounded pre-redaction allocation, then redact,
/// then cap at `max_bytes`.
///
/// # Ordering
///
/// The pipeline is: render → cap → redact → cap-again.  Specifically:
/// 1. Render `value` into a [`LimitedWriter`] capped at [`MAX_PRE_REDACT_BYTES`].
///    The writer silently drops bytes beyond the cap and appends
///    `...[TRUNCATED]`, bounding allocation upfront.
/// 2. Run `redact_strkeys` on the bounded rendering.
/// 3. Cap the redacted string at `max_bytes`, appending `...[TRUNCATED]`
///    if needed.
///
/// Returns `(formatted_string, truncated)`.
pub(crate) fn format_debug_capped(value: &dyn std::fmt::Debug, max_bytes: usize) -> (String, bool) {
    use std::fmt::Write as _;
    let mut writer = LimitedWriter::new(MAX_PRE_REDACT_BYTES);
    // Infallible: LimitedWriter::write_str always returns Ok(()).
    let _ = write!(writer, "{value:?}");
    let (raw, pre_truncated) = writer.into_string();
    // Redact complete strkeys and cap-boundary fragments in the bounded rendering.
    let raw = redact_partial_sensitive_strkey_at_cap_boundary(raw, pre_truncated);
    let (redacted, _) = redact_strkeys(&raw);
    // Final cap at max_bytes.
    let (capped, cap_truncated) = cap_string(redacted, max_bytes);
    (capped, pre_truncated || cap_truncated)
}

/// Format a `Display` value with bounded pre-redaction allocation, then
/// redact, then cap at `max_bytes`.
///
/// See [`format_debug_capped`] for the full ordering rationale.
///
/// Returns `(formatted_string, truncated)`.
pub(crate) fn format_display_capped(
    value: &dyn std::fmt::Display,
    max_bytes: usize,
) -> (String, bool) {
    use std::fmt::Write as _;
    let mut writer = LimitedWriter::new(MAX_PRE_REDACT_BYTES);
    let _ = write!(writer, "{value}");
    let (raw, pre_truncated) = writer.into_string();
    let raw = redact_partial_sensitive_strkey_at_cap_boundary(raw, pre_truncated);
    let (redacted, _) = redact_strkeys(&raw);
    let (capped, cap_truncated) = cap_string(redacted, max_bytes);
    (capped, pre_truncated || cap_truncated)
}

fn redact_partial_sensitive_strkey_at_cap_boundary(mut raw: String, pre_truncated: bool) -> String {
    if !pre_truncated || !raw.ends_with(TRUNCATION_SUFFIX) {
        return raw;
    }

    let suffix_start = raw.len() - TRUNCATION_SUFFIX.len();
    let scan_start = suffix_start.saturating_sub(56);
    let bytes = raw.as_bytes();
    let mut fragment_start = suffix_start;

    while fragment_start > scan_start && is_base32_byte(bytes[fragment_start - 1]) {
        fragment_start -= 1;
    }

    let fragment = &raw[fragment_start..suffix_start];
    if fragment.len() >= 16
        && let Some(sensitive_offset) = fragment
            .as_bytes()
            .iter()
            .position(|b| matches!(b, b'S' | b'T' | b'X'))
    {
        raw.replace_range(
            fragment_start + sensitive_offset..suffix_start,
            "[REDACTED-PARTIAL]",
        );
    }

    raw
}

fn is_base32_byte(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'2'..=b'7')
}

/// Cap `s` at `max_bytes`, appending [`TRUNCATION_SUFFIX`] if truncated.
///
/// Truncation is at a UTF-8 char boundary to avoid invalid UTF-8.
fn cap_string(mut s: String, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s, false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push_str(TRUNCATION_SUFFIX);
    (s, true)
}

// ── Output helpers ────────────────────────────────────────────────────────────

/// Write pre-redacted fields in the pretty format to `writer`.
///
/// Mimics [`DefaultVisitor`](tracing_subscriber::fmt::format::DefaultVisitor)
/// output (verified at `tracing-subscriber/src/fmt/format/mod.rs`
/// lines 1263–1340, commit `54ede4d`):
///
/// - Fields are separated by a single space.
/// - `message` is written as `{value:?}` without a key prefix.
/// - Other fields are written as `key={value:?}` (strings are `Debug`-quoted).
fn write_pretty_fields(
    writer: &mut Writer<'_>,
    fields: &[(&'static str, RedactedValue)],
) -> std::fmt::Result {
    let mut is_empty = true;
    for (name, value) in fields {
        if !is_empty {
            write!(writer, " ")?;
        }
        is_empty = false;
        match value {
            RedactedValue::Str(s) => {
                if *name == "message" {
                    write!(writer, "{s:?}")?;
                } else {
                    write!(writer, "{name}={s:?}")?;
                }
            }
            RedactedValue::U64(v) => write!(writer, "{name}={v}")?,
            RedactedValue::I64(v) => write!(writer, "{name}={v}")?,
            RedactedValue::F64(v) => write!(writer, "{name}={v}")?,
            RedactedValue::Bool(v) => write!(writer, "{name}={v}")?,
        }
    }
    Ok(())
}

/// Write pre-redacted fields as the content of a JSON object (no surrounding
/// braces).
///
/// String values are JSON-escaped; numeric and boolean values are bare JSON.
/// Keys are sorted lexicographically, matching `JsonVisitor`'s `BTreeMap`
/// serialisation order (`tracing-subscriber/src/fmt/format/json.rs`
/// lines 458–476, commit `54ede4d`).
fn write_json_fields(
    writer: &mut Writer<'_>,
    fields: &[(&'static str, RedactedValue)],
) -> std::fmt::Result {
    // Sort by key to match JsonVisitor's BTreeMap serialisation order.
    let mut sorted: Vec<(&'static str, &RedactedValue)> =
        fields.iter().map(|(k, v)| (*k, v)).collect();
    sorted.sort_by_key(|(k, _)| *k);

    let mut first = true;
    for (name, value) in &sorted {
        if !first {
            write!(writer, ",")?;
        }
        first = false;
        write_json_str(writer, name)?;
        write!(writer, ":")?;
        match value {
            RedactedValue::Str(s) => write_json_str(writer, s)?,
            RedactedValue::U64(v) => write!(writer, "{v}")?,
            RedactedValue::I64(v) => write!(writer, "{v}")?,
            RedactedValue::F64(v) => write!(writer, "{v}")?,
            RedactedValue::Bool(v) => write!(writer, "{v}")?,
        }
    }
    Ok(())
}

/// Write `s` as a JSON string literal (with surrounding double-quote chars).
///
/// Escapes per RFC 8259 §7: `"`, `\`, and control characters U+0000–U+001F.
fn write_json_str(writer: &mut Writer<'_>, s: &str) -> std::fmt::Result {
    write!(writer, "\"")?;
    for ch in s.chars() {
        match ch {
            '"' => write!(writer, "\\\"")?,
            '\\' => write!(writer, "\\\\")?,
            '\n' => write!(writer, "\\n")?,
            '\r' => write!(writer, "\\r")?,
            '\t' => write!(writer, "\\t")?,
            c if (c as u32) < 0x20 => write!(writer, "\\u{:04X}", c as u32)?,
            c => write!(writer, "{c}")?,
        }
    }
    write!(writer, "\"")
}

/// Emit the Layer 2 "redaction fired" warning if `did_redact` is `true`.
///
/// Uses a dedicated target (`REDACTION_FIRED_TARGET`) that the redacting
/// formatters never re-inspect, preventing infinite recursion.
fn emit_redaction_warning(did_redact: bool) {
    if did_redact {
        tracing::warn!(
            target: REDACTION_FIRED_TARGET,
            "Layer 2 redaction fired — audit callers for unguarded secret material"
        );
    }
}

// ── Redaction logic ───────────────────────────────────────────────────────────

/// Case-insensitive exact-match pass-through field names.
///
/// A field on this list is never touched by Layer 2; Layer 1's redacting
/// newtype output is preserved as-is.  Pass-through is checked **before** the
/// redact list.
const PASS_THROUGH: &[&str] = &[
    "public_key",
    "pubkey",
    "account_id",
    "account",
    "contract_address",
    "contract",
    "muxed_account",
    "tx_hash",
    "transaction_hash",
    "counterparty",
    "destination",
    "source",
];

/// Case-insensitive exact-match redact field names.
///
/// A field on this list always has its value replaced with `[REDACTED]`.
const REDACT_NAMES: &[&str] = &[
    "key",
    "private_key",
    "privatekey",
    "priv",
    "sk",
    "signing_key",
    "seed",
    "seed_phrase",
    "secret",
    "secret_key",
    "mnemonic",
    "passphrase",
    "password",
    "keypair",
    "credential",
    "credentials",
    "entropy",
    "wif",
    "xdr_secret",
    "auth_cred",
];

/// Returns `true` if the field name (case-insensitive) is on the redact list
/// AND not on the pass-through list.
///
/// Used by numeric/bool `record_*` handlers that cannot apply string-content
/// checks.  Pass-through is checked first so that any overlap (there is none
/// currently) would not accidentally suppress pass-through fields.
fn should_redact_by_name(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    let lower = lower.as_str();
    // Pass-through list takes priority.
    if PASS_THROUGH.contains(&lower) {
        return false;
    }
    REDACT_NAMES.contains(&lower)
}

/// Apply all Layer 2 redaction checks to a single field value string.
///
/// Returns `(output_value, did_redact)`.
///
/// # Precedence
///
/// 1. Pass-through list — if the field name matches, return `(value, false)`
///    immediately.
/// 2. Redact-name list — if the field name matches, return `("[REDACTED]", true)`.
/// 3. S/T/X-strkey scan — scan the value for any valid sensitive strkey
///    (`PrivateKeyEd25519`, `PreAuthTx`, `HashX`) and replace matching
///    substrings with `[REDACTED]`.
/// 4. BIP-39 mnemonic check — if the entire value looks like a mnemonic,
///    replace it with `[REDACTED]`.
fn redact_value(field_name: &str, value: &str) -> (String, bool) {
    let name_lower = field_name.to_ascii_lowercase();
    let name_lower = name_lower.as_str();

    // 1. Pass-through list (exact match, case-insensitive) — checked first.
    if PASS_THROUGH.contains(&name_lower) {
        return (value.to_owned(), false);
    }

    // 2. Redact-name list (exact match, case-insensitive).
    if REDACT_NAMES.contains(&name_lower) {
        return ("[REDACTED]".to_owned(), true);
    }

    // 3. S-strkey substring scan.
    let (after_strkey, strkey_redacted) = redact_strkeys(value);

    // 4. BIP-39 mnemonic heuristic (whole-value check).
    if is_bip39_mnemonic(&after_strkey) {
        return ("[REDACTED]".to_owned(), true);
    }

    (after_strkey, strkey_redacted)
}

/// Replace all validated sensitive strkeys in `input` with `[REDACTED]`.
///
/// A candidate is a 56-byte window starting with `S`, `T`, or `X` where every
/// byte is a valid base32 ASCII character (`A-Z` or `2-7`), and the window
/// parses as one of the three strkey classes that are always redacted at Layer 2:
///
/// | Prefix | Type |
/// |--------|------|
/// | `S`    | `PrivateKeyEd25519` (ed25519SecretSeed) |
/// | `T`    | `PreAuthTx` |
/// | `X`    | `HashX` (sha256Hash) |
///
/// `G`, `C`, `M`, `P` keys are handled by Layer 1 (redacting newtypes) and are
/// deliberately NOT caught here, to preserve Layer 1's first-5-last-5 rendering.
///
/// Validation is performed by [`stellar_strkey::Strkey::from_string`] which
/// validates version byte, payload length, and CRC-16 in one call.
///
/// # Char-boundary safety
///
/// This implementation operates exclusively on the byte slice
/// (`input.as_bytes()`).  When the leading byte is `b'S'`, `b'T'`, or `b'X'`,
/// it validates the entire 56-byte window is pure ASCII base32 before treating
/// it as a `str`.  A window that contains any non-ASCII byte cannot be a valid
/// strkey (the base32 alphabet is ASCII-only), so the ASCII validation gate
/// guarantees `pos + 56` is always on a char boundary for any window that
/// reaches the `Strkey::from_string` call.
///
/// Returns `(output, did_replace)`.
fn redact_strkeys(input: &str) -> (String, bool) {
    let bytes = input.as_bytes();
    let len = bytes.len();
    if len < 56 {
        return (input.to_owned(), false);
    }

    let mut output = String::with_capacity(len);
    let mut pos = 0usize;
    let mut did_replace = false;

    while pos < len {
        // Candidate gate: first byte must be one of S / T / X.
        let first = bytes[pos];
        if matches!(first, b'S' | b'T' | b'X') && pos + 56 <= len {
            // Validate all 56 bytes are ASCII base32 BEFORE slicing as str.
            // This guarantees:
            // (a) No non-ASCII byte in the window → pos+56 is always on a char boundary.
            // (b) The window is at least a base32 candidate — version+CRC validation follows.
            let window = &bytes[pos..pos + 56];
            // Every byte in `window` is ASCII (single-byte UTF-8), so
            // `from_utf8` is infallible when the base32 gate passes.  The
            // `Ok` pattern is used instead of `unwrap` to remain panic-free.
            if window
                .iter()
                .all(|&b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
                && let Ok(candidate) = std::str::from_utf8(window)
                && is_valid_sensitive_strkey(candidate)
            {
                output.push_str("[REDACTED]");
                pos += 56;
                did_replace = true;
                continue;
            }
        }
        // Advance by one UTF-8 character to avoid splitting multi-byte sequences.
        // This branch handles the non-candidate case and windows that failed the
        // ASCII base32 gate or strkey validation.
        if let Some(ch) = input[pos..].chars().next() {
            output.push(ch);
            pos += ch.len_utf8();
        } else {
            break;
        }
    }

    (output, did_replace)
}

/// Validate a 56-character candidate as a strkey that must be unconditionally
/// redacted at Layer 2.
///
/// Returns `true` if the candidate is a valid strkey of a sensitive type:
/// - private-key seed — `S`-prefix, version byte `0x90` (`18 << 3`).
/// - pre-authorized transaction hash — `T`-prefix, version byte `0x98` (`19 << 3`).
/// - hash-x signer — `X`-prefix, version byte `0xB8` (`23 << 3`).
///
/// Validation (version byte, payload length, CRC-16) is delegated to
/// `stellar-strkey`. Its `Strkey` enum intentionally omits the private-key
/// variant, so `S`-prefixed seeds are decoded through
/// [`stellar_strkey::ed25519::PrivateKey::from_string`].
///
/// `G`, `C`, `M`, `P` keys are public identifiers handled by Layer 1 and return
/// `false` here so Layer-1 rendering is preserved.
///
/// Not public API — callers inside this crate use it via `redact_strkeys`.
pub(crate) fn is_valid_sensitive_strkey(candidate: &str) -> bool {
    use stellar_strkey::{Strkey, ed25519};
    ed25519::PrivateKey::from_string(candidate).is_ok()
        || matches!(
            Strkey::from_string(candidate),
            Ok(Strkey::PreAuthTx(_) | Strkey::HashX(_))
        )
}

/// BIP-39 mnemonic check.
///
/// Returns `true` if `input` is a valid BIP-39 mnemonic phrase under the
/// English word list, using the permissive
/// [`bip39::Mnemonic::parse_in_normalized_without_checksum_check`] API.
///
/// The permissive variant (no checksum validation) is deliberately chosen over
/// `Mnemonic::from_str` so that any sequence of valid BIP-39 English words in
/// an accepted word-count (12–24 in multiples of 3) triggers redaction,
/// regardless of whether the phrase has a valid mnemonic checksum.  A random
/// 12-word English sentence where every word is in the BIP-39 list is still
/// sensitive material; requiring a valid checksum before redacting would create
/// a bypass for slightly-corrupted or partial key material.
///
/// The `stellar-agent-test-support` oracle uses a separate hand-rolled word-list
/// scan so the two implementations remain independent: a bug in the `bip39`
/// crate would still be caught by the hand-rolled oracle.
///
/// Not public API — callers inside this crate use it via `redact_value`.
pub(crate) fn is_bip39_mnemonic(input: &str) -> bool {
    use bip39::{Language, Mnemonic};
    Mnemonic::parse_in_normalized_without_checksum_check(Language::English, input).is_ok()
}

/// Redact absolute paths under the operator's home directory to `<HOME>/...`.
///
/// Operator-facing diagnostic strings can embed paths via error display, for
/// example `open: /Users/alice/.config/stellar-agent/profile/networks.toml`.
/// Leaking that absolute prefix reveals the operator's home directory and
/// local profile layout through a wire envelope. This helper replaces every
/// occurrence of `$HOME` with the literal `<HOME>`, preserving the relative tail
/// so the operator can still identify which wallet file failed.
///
/// If `$HOME` is unset, empty, or absent from the message, the input is returned
/// unchanged.
#[must_use]
pub fn redact_path_in_message(msg: &str) -> String {
    let Ok(home) = std::env::var("HOME") else {
        return msg.to_owned();
    };
    redact_path_in_message_with_home(msg, Some(home.as_str()))
}

fn redact_path_in_message_with_home(msg: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return msg.to_owned();
    };
    if home.is_empty() {
        return msg.to_owned();
    }
    // `HOME=/` is pathological: literal `str::replace("/", "<HOME>")` would
    // shred every path separator (e.g. `/tmp/x` → `<HOME>tmp<HOME>x`). Treat
    // root-home as no-redaction; the leak surface here is the same as an
    // unset HOME (every absolute path looks home-relative).
    if home == "/" {
        return msg.to_owned();
    }
    msg.replace(home, "<HOME>")
}

// ── SubscriberConfig ─────────────────────────────────────────────────────────

/// Writer-factory type used by [`SubscriberConfig::writer_factory`].
///
/// A type-erased `Fn` that produces a fresh [`Write`](std::io::Write) handle
/// per tracing event.  Matches the per-event semantics of
/// [`tracing_subscriber::fmt::MakeWriter`]: the closure is invoked every time
/// an event is written, not once at subscriber-install time.  Tests typically
/// clone an `Arc<Mutex<Vec<u8>>>` into the closure so every event appends to
/// the shared buffer.
///
/// The trait-object form (`Box<dyn Fn() -> Box<dyn Write + Send>>`) is used
/// in preference to a generic type parameter because [`SubscriberConfig`]
/// needs to be nameable without threading a writer type through the config.
pub type BoxedMakeWriterFn = Box<dyn Fn() -> Box<dyn std::io::Write + Send> + Send + Sync>;

/// Adapter wrapping a [`BoxedMakeWriterFn`] as a `MakeWriter`.
///
/// Private helper used by [`init_subscriber_with`] when
/// [`SubscriberConfig::writer_factory`] is `Some`.
struct FactoryMakeWriter(BoxedMakeWriterFn);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FactoryMakeWriter {
    type Writer = Box<dyn std::io::Write + Send + 'a>;

    fn make_writer(&'a self) -> Self::Writer {
        (self.0)()
    }
}

/// Configuration for [`init_subscriber_with`].
///
/// Use [`SubscriberConfig::default`] for standard CLI / daemon behaviour —
/// stderr writer, three-level env-filter fallback
/// ([`env_var::LOG_LEVEL`] → [`env_var::RUST_LOG_FALLBACK`] → `"info"`),
/// panic hook installed, log-crate bridge installed, format auto-detected
/// from env + TTY.  Override individual fields via the consuming setters
/// (`with_*` methods).
///
/// ```
/// use stellar_agent_core::observability::{FormatChoice, SubscriberConfig};
///
/// // Force JSON and skip panic-hook installation (e.g. test harness):
/// let config = SubscriberConfig::default()
///     .with_format_override(Some(FormatChoice::Json))
///     .with_install_panic_hook(false);
/// ```
///
/// The struct is `#[non_exhaustive]` so external crates cannot use
/// struct-literal construction directly; the `with_*` setter chain is the
/// canonical construction path and preserves the option of adding fields
/// later without a breaking change.  Within this crate the fields remain
/// public for direct mutation / pattern destructuring in tests.
#[non_exhaustive]
pub struct SubscriberConfig {
    /// Explicit output-format choice.  Highest priority — overrides both the
    /// [`env_var::LOG_FORMAT`] environment variable and TTY auto-detection.
    /// `None` means "resolve via the normal
    /// [`FormatChoice::from_env_and_tty`] rules".
    pub format_override: Option<FormatChoice>,

    /// Explicit [`EnvFilter`] to install.  Bypasses the env-var lookup
    /// entirely.  `None` means "use the three-level fallback"
    /// ([`env_var::LOG_LEVEL`] → [`env_var::RUST_LOG_FALLBACK`] → `"info"`).
    pub filter_override: Option<EnvFilter>,

    /// Factory producing the writer the subscriber emits to.  `None` means
    /// "use [`std::io::stderr`]".  A factory returning a capture buffer is
    /// how tests and MCP-replay consumers inject writers.  See
    /// [`BoxedMakeWriterFn`] for the shape.
    pub writer_factory: Option<BoxedMakeWriterFn>,

    /// Whether to install the panic hook.  Default `true` — panic messages
    /// route through `tracing::error!` for redaction.  Tests that do not
    /// want to disturb the process-global panic hook can set this to `false`.
    ///
    /// **Redaction consequence when `false`:** panic messages bypass Layer
    /// 2 redaction entirely (the default Rust hook writes the raw payload
    /// to stderr).  Do NOT set to `false` in any code path that interpolates
    /// sensitive values into panic messages, and do NOT set to `false` in
    /// production binaries.  The CLI and MCP binaries use the `true`
    /// default.
    pub install_panic_hook: bool,

    /// Whether to install the `log`-crate bridge
    /// ([`tracing_log::LogTracer::init`]).  Default `true` — third-party
    /// `log::*` events traverse the subscriber pipeline.  Tests that have
    /// already installed a `log` logger, or that do not want to touch the
    /// global `log` bridge, can set this to `false`.
    ///
    /// **Redaction consequence when `false`:** third-party `log::*` events
    /// bypass the subscriber pipeline entirely and are NOT routed through
    /// Layer 2.  A dependency that emits a URL with a credential via
    /// `log::warn!` will surface the credential unredacted.  Do NOT set
    /// to `false` in production binaries.
    pub install_log_bridge: bool,
}

impl Default for SubscriberConfig {
    fn default() -> Self {
        Self {
            format_override: None,
            filter_override: None,
            writer_factory: None,
            install_panic_hook: true,
            install_log_bridge: true,
        }
    }
}

impl SubscriberConfig {
    /// Set the explicit output-format override.  See
    /// [`format_override`](Self::format_override) for semantics.
    #[must_use]
    pub fn with_format_override(mut self, format_override: Option<FormatChoice>) -> Self {
        self.format_override = format_override;
        self
    }

    /// Set the explicit [`EnvFilter`] override.  See
    /// [`filter_override`](Self::filter_override) for semantics.
    #[must_use]
    pub fn with_filter_override(mut self, filter_override: Option<EnvFilter>) -> Self {
        self.filter_override = filter_override;
        self
    }

    /// Set the writer factory.  See [`writer_factory`](Self::writer_factory)
    /// for semantics.
    #[must_use]
    pub fn with_writer_factory(mut self, writer_factory: Option<BoxedMakeWriterFn>) -> Self {
        self.writer_factory = writer_factory;
        self
    }

    /// Enable or disable panic-hook installation.  See
    /// [`install_panic_hook`](Self::install_panic_hook) for semantics.
    #[must_use]
    pub fn with_install_panic_hook(mut self, install_panic_hook: bool) -> Self {
        self.install_panic_hook = install_panic_hook;
        self
    }

    /// Enable or disable log-crate-bridge installation.  See
    /// [`install_log_bridge`](Self::install_log_bridge) for semantics.
    #[must_use]
    pub fn with_install_log_bridge(mut self, install_log_bridge: bool) -> Self {
        self.install_log_bridge = install_log_bridge;
        self
    }
}

/// `Debug` impl that omits the writer factory (not `Debug`-printable) and
/// the filter override (opaque) to keep redaction guarantees intact.
impl std::fmt::Debug for SubscriberConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriberConfig")
            .field("format_override", &self.format_override)
            .field(
                "filter_override",
                &self.filter_override.as_ref().map(|_| "<EnvFilter>"),
            )
            .field(
                "writer_factory",
                &self.writer_factory.as_ref().map(|_| "<fn>"),
            )
            .field("install_panic_hook", &self.install_panic_hook)
            .field("install_log_bridge", &self.install_log_bridge)
            .finish()
    }
}

// ── init_subscriber ───────────────────────────────────────────────────────────

/// Initialise the process-wide tracing subscriber stack.
///
/// Builds and installs:
/// - An [`EnvFilter`] driven by
///   `STELLAR_AGENT_LOG` (falling back to `RUST_LOG`, then `info`).
/// - A fmt layer (pretty or JSON per `log_format_override` / env / TTY
///   detection) writing to `stderr`.  Layer 2 redaction is applied in both
///   format paths — via `RedactingLayer<DefaultFields>` for pretty, and via
///   [`RedactingJsonFormatter`] for JSON.
/// - A `tracing_log::LogTracer` bridge so third-party `log`-crate events
///   traverse the same subscriber pipeline.
/// - A `std::panic::set_hook` that routes panic payloads through
///   `tracing::error!` for redaction before they reach stderr.
///
/// # ANSI colour control
///
/// When the pretty format is active, ANSI colour codes are enabled only when
/// both: (a) stderr is a TTY, and (b) the `NO_COLOR` environment variable is
/// unset.  Setting `NO_COLOR` to any value disables ANSI regardless of the TTY
/// state, following the <https://no-color.org> convention.
/// [`env_var::NO_COLOR`] holds the variable name.
///
/// # Errors
///
/// - [`InitError::Filter`] if `STELLAR_AGENT_LOG` is set to an invalid filter
///   expression and `RUST_LOG` is also set to an invalid expression.
/// - [`InitError::LogBridge`] if `LogTracer::init()` fails.
/// - [`InitError::Init`] if `try_init` fails (most commonly because a subscriber
///   was already installed).
///
/// # Examples
///
/// ```rust,no_run
/// use stellar_agent_core::observability::init_subscriber;
///
/// fn main() {
///     if let Err(e) = init_subscriber(None) {
///         eprintln!("failed to install subscriber: {e}");
///         std::process::exit(1);
///     }
///     tracing::info!("subscriber initialised");
/// }
/// ```
pub fn init_subscriber(log_format_override: Option<&str>) -> Result<(), InitError> {
    let format_override = log_format_override.map(FormatChoice::parse_format_str);
    init_subscriber_with(SubscriberConfig::default().with_format_override(format_override))
}

/// Initialise the process-wide tracing subscriber stack with a caller-provided
/// [`SubscriberConfig`].
///
/// Richer variant of [`init_subscriber`] accepting a writer factory, filter
/// override, and toggles for panic-hook / log-bridge installation.  Used by
/// the MCP binary for replay capture and by tests that want a bespoke
/// subscriber without env-var scrubbing.  See [`SubscriberConfig`] for the
/// field semantics and defaults.
///
/// # Errors
///
/// Same variants as [`init_subscriber`]:
///
/// - [`InitError::Filter`] if [`env_var::LOG_LEVEL`] is set to an invalid
///   expression and [`env_var::RUST_LOG_FALLBACK`] is also invalid (only
///   when [`SubscriberConfig::filter_override`] is `None`).
/// - [`InitError::LogBridge`] if `LogTracer::init()` fails (only when
///   [`SubscriberConfig::install_log_bridge`] is `true`).
/// - [`InitError::Init`] if `try_init` fails (most commonly because a
///   subscriber was already installed).
///
/// # Examples
///
/// ```rust,no_run
/// use stellar_agent_core::observability::{
///     FormatChoice, SubscriberConfig, init_subscriber_with,
/// };
///
/// fn main() {
///     let config = SubscriberConfig::default()
///         .with_format_override(Some(FormatChoice::Json));
///     if let Err(e) = init_subscriber_with(config) {
///         eprintln!("failed to install subscriber: {e}");
///         std::process::exit(1);
///     }
///     tracing::info!("subscriber initialised");
/// }
/// ```
pub fn init_subscriber_with(config: SubscriberConfig) -> Result<(), InitError> {
    // 1. Install the log-crate bridge first, unless skipped.
    if config.install_log_bridge {
        tracing_log::LogTracer::init().map_err(InitError::LogBridge)?;
    }

    // 2. Build the EnvFilter: use override if provided, else three-level fallback.
    let filter = match config.filter_override {
        Some(f) => f,
        None => build_env_filter()?,
    };

    // 3. Resolve format: explicit override > env/TTY auto-detect.
    let format = match config.format_override {
        Some(f) => f,
        None => FormatChoice::from_env_and_tty(None),
    };

    // 4. Detect TTY + NO_COLOR for ANSI colour toggle.
    //    ANSI is enabled only when stderr is a TTY AND NO_COLOR is unset.
    use std::io::IsTerminal as _;
    let is_tty = std::io::stderr().is_terminal();
    let no_color = std::env::var_os(env_var::NO_COLOR).is_some();
    let use_ansi = resolve_ansi(is_tty, no_color);

    // 5. Build a type-erased fmt layer.  Type erasure is required because the
    //    four (format × writer) combinations have different concrete layer
    //    types.  All four paths receive identical redaction treatment via
    //    the [`RedactingLayer`] / [`RedactingJsonFormatter`] wrappers.
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::Layered;
    type S = Layered<EnvFilter, Registry>;
    let fmt_layer: Box<dyn tracing_subscriber::Layer<S> + Send + Sync> =
        match (format, config.writer_factory) {
            (FormatChoice::Pretty, None) => Box::new(
                fmt::layer()
                    .pretty()
                    .with_writer(std::io::stderr)
                    .with_ansi(use_ansi)
                    .fmt_fields(RedactingLayer::<DefaultFields>::new_pretty()),
            ),
            (FormatChoice::Pretty, Some(factory)) => Box::new(
                fmt::layer()
                    .pretty()
                    .with_writer(FactoryMakeWriter(factory))
                    .with_ansi(use_ansi)
                    .fmt_fields(RedactingLayer::<DefaultFields>::new_pretty()),
            ),
            (FormatChoice::Json, None) => Box::new(
                fmt::layer()
                    .event_format(RedactingJsonFormatter::new())
                    .with_writer(std::io::stderr),
            ),
            (FormatChoice::Json, Some(factory)) => Box::new(
                fmt::layer()
                    .event_format(RedactingJsonFormatter::new())
                    .with_writer(FactoryMakeWriter(factory)),
            ),
        };

    // 6. Compose and install.
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init()
        .map_err(InitError::Init)?;

    // 7. Install the panic hook, unless skipped.
    if config.install_panic_hook {
        install_panic_hook();
    }

    Ok(())
}

/// Build the `EnvFilter` with three-level fallback.
///
/// Precedence: [`env_var::LOG_LEVEL`] → [`env_var::RUST_LOG_FALLBACK`] →
/// `"info"`.  This wrapper reads the current process environment and
/// delegates to the pure helper [`resolve_env_filter_from`].
fn build_env_filter() -> Result<EnvFilter, InitError> {
    let stellar = std::env::var(env_var::LOG_LEVEL).ok();
    let rust_log = std::env::var(env_var::RUST_LOG_FALLBACK).ok();
    resolve_env_filter_from(stellar.as_deref(), rust_log.as_deref())
}

/// Pure variant of [`build_env_filter`] parameterised on the caller's env
/// snapshot.
///
/// Separated out so tests can exercise the three-level fallback without
/// mutating the process-global environment (Rust 2024 forbids `unsafe` and
/// env-var mutation requires it).  Precedence:
///
/// 1. `stellar_agent_log` if set AND parseable → return it.
/// 2. `stellar_agent_log` set but unparseable: try `rust_log` as fallback;
///    if it parses, return it.  If both fail, return the primary error.
/// 3. `stellar_agent_log` unset: try `rust_log`; if it parses, return it.
/// 4. Neither set (or both unparseable when `stellar_agent_log` was unset):
///    hard-coded default `"info"`.
///
/// An unparseable `rust_log` by itself (when `stellar_agent_log` is unset)
/// is ignored silently and the hard-coded default is used; this matches the
/// upstream `EnvFilter::from_env` behaviour for `RUST_LOG`.
fn resolve_env_filter_from(
    stellar_agent_log: Option<&str>,
    rust_log: Option<&str>,
) -> Result<EnvFilter, InitError> {
    // (1) primary: STELLAR_AGENT_LOG.
    if let Some(value) = stellar_agent_log {
        match EnvFilter::builder().parse(value) {
            Ok(f) => return Ok(f),
            Err(primary_err) => {
                // (2) STELLAR_AGENT_LOG set but unparseable: try RUST_LOG.
                if let Some(rust_value) = rust_log
                    && let Ok(f) = EnvFilter::builder().parse(rust_value)
                {
                    return Ok(f);
                }
                return Err(InitError::Filter(
                    tracing_subscriber::filter::FromEnvError::from(primary_err),
                ));
            }
        }
    }
    // (3) STELLAR_AGENT_LOG unset: try RUST_LOG.
    if let Some(rust_value) = rust_log
        && let Ok(f) = EnvFilter::builder().parse(rust_value)
    {
        return Ok(f);
    }
    // (4) Hard-coded default: always valid.
    Ok(EnvFilter::builder().parse_lossy("info"))
}

/// Pure helper: decide whether ANSI colour codes should be emitted.
///
/// Matches the semantics of `init_subscriber_with` step 4 — ANSI is enabled
/// only when `is_tty` is `true` AND `no_color` is `false`.  Setting
/// [`env_var::NO_COLOR`] to any value disables ANSI regardless of TTY state
/// (<https://no-color.org> convention).
///
/// Private helper exposed only to the sibling `tests` module.
fn resolve_ansi(is_tty: bool, no_color: bool) -> bool {
    is_tty && !no_color
}

/// Install the panic hook.
///
/// Routes panic payloads through `tracing::error!` so that Layer 2 redaction
/// applies to the panic message before any bytes are written to stderr.
///
/// The default Rust panic hook is deliberately NOT invoked after
/// `tracing::error!`.  The default hook writes the raw panic payload to stderr,
/// bypassing redaction, which would leak any sensitive value interpolated into
/// a panic message.  The `tracing::error!` path carries the redacted panic to
/// the subscriber, which writes to stderr.
///
/// # Backtraces
///
/// Because the default panic hook is replaced without being chained, the
/// standard stderr backtrace that `RUST_BACKTRACE=1` normally emits does
/// not appear.  Instead, this hook captures [`std::backtrace::Backtrace`]
/// explicitly and emits it as a structured `backtrace` field on the same
/// `tracing::error!` event.  Capture honours the usual `RUST_BACKTRACE` /
/// `RUST_LIB_BACKTRACE` environment-variable semantics via
/// [`Backtrace::capture`]; when both are unset, `capture()` returns a
/// disabled backtrace that formats as a short placeholder string.  No
/// stack frames reach stderr unredacted.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_owned()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "(non-string panic payload)".to_owned()
        };

        let backtrace = std::backtrace::Backtrace::capture().to_string();

        let loc = info
            .location()
            .map_or_else(|| "unknown location".to_owned(), |l| l.to_string());

        tracing::error!(
            target: "stellar_agent_core::observability::panic",
            panic_message = %msg,
            location = %loc,
            backtrace = %backtrace,
            "panic"
        );

        // The default hook is deliberately NOT called here.
        // See function-level rustdoc for rationale.
    }));
}

// Tests live in a sibling file (modules longer than ~400 lines move tests out).
#[cfg(test)]
mod tests;

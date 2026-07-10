//! Unified `WalletError` taxonomy for the Stellar agent wallet.
//!
//! Every CLI command, MCP tool, and library API surfaces errors through this
//! module.  Policy-engine denials are a distinct taxonomy at
//! `stellar_agent_core::policy::PolicyError`; this module carries only the
//! substrate-level error categories.
//!
//! # Taxonomy overview
//!
//! | Top-level variant | Category slug | Domain |
//! |-------------------|---------------|--------|
//! | [`WalletError::Validation`]   | `validation`   | User-supplied input validation |
//! | [`WalletError::Network`]      | `network`      | RPC / Horizon connectivity |
//! | [`WalletError::Auth`]         | `auth`         | Keyring and signing auth |
//! | [`WalletError::WalletState`]  | `wallet_state` | Hardware-wallet / keyring state |
//! | [`WalletError::Protocol`]     | `protocol`     | XDR / Soroban protocol errors |
//! | [`WalletError::Ledger`]       | `ledger`       | On-chain ledger-state errors |
//! | [`WalletError::Submission`]   | `submission`   | Transaction-submission errors |
//! | [`WalletError::Internal`]     | `internal`     | Invariant violations / unexpected state |
//! | [`WalletError::Io`]           | `io`           | Filesystem I/O failures |
//!
//! # Wire format
//!
//! Machine-readable output uses [`WalletError::code`] to emit a stable
//! `<category>.<subcode>` string (e.g. `"validation.memo_required"`,
//! `"network.rpc_timeout"`).  The human-readable counterpart is
//! [`WalletError::message`], which delegates to [`std::fmt::Display`].
//!
//! # Classification guide
//!
//! Use [`WalletError::code`] for wire-format routing and remediation,
//! [`WalletError::category`] for coarse programmatic grouping, and
//! [`WalletError::message`] only for operator-facing text.  Callers should
//! make one classification decision per error value and carry that decision
//! through the response or log record instead of reparsing the rendered
//! message.
//!
//! # Wire-format stability policy
//!
//! Every `<category>.<subcode>` code string is part of the stable public API.
//! Agents and human operators parse these strings to route, display, and
//! remediate errors.
//!
//! - **Adding a new code** is always non-breaking.  Every outer and inner
//!   enum carries `#[non_exhaustive]`, so downstream match arms include a
//!   wildcard fallback.
//! - **Deprecating a code** requires a CHANGELOG entry under
//!   `### Deprecated` naming the code, the replacement (if any), and the
//!   target removal version.  Grace window: at least one minor version.
//! - **Renaming or removing a code silently is a breaking change** and is
//!   forbidden pre-1.0 without a `Changed` or `Removed` CHANGELOG entry
//!   carrying a migration note.
//!
//! # Account-ID redaction policy
//!
//! When an error variant carries a public account ID (`G…`/`C…`), the
//! rendered `Display` message shows the **full** account ID.  Account IDs are
//! not secret material; they are user-visible identifiers that a human
//! operator needs to audit an error.  The first-5-last-5 redaction rule
//! applies at the **tracing / logging** boundary, not at the user-error-message
//! boundary.  Callers that log a [`WalletError`] must apply the redaction
//! before emitting the structured log event; they must not rely on the error's
//! `Display` being pre-redacted.
//!
//! # Secret-material discipline
//!
//! No error variant carries raw secret material.  Fields named `account_id`,
//! `destination`, etc. hold public identifiers only.  No variant accepts or
//! stores private key bytes, mnemonic words, raw signature bytes, or any
//! other material classified as secret.  Each field-carrying variant documents
//! the exact class of data its fields hold.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Top-level error enum
// ──────────────────────────────────────────────────────────────────────────────

/// Closed-set discriminator for [`WalletError::Io`] sources.
///
/// Adding a new I/O source means extending this enum. The compiler then
/// requires updating [`IoSource::wire_code`] and [`IoSource::label`], which
/// prevents a call-site typo from silently degrading to a generic wire code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IoSource {
    /// Multicall registry load from the per-profile networks TOML.
    MulticallRegistryLoad,
    /// Multicall registry save to the per-profile networks TOML.
    MulticallRegistrySave,
    /// Audit-writer file setup.
    AuditWriterSetup,
}

impl IoSource {
    /// Stable, operator-facing wire code.
    ///
    /// Never change a row in this map without recording the wire-code schema
    /// change in `CHANGELOG.md`.
    #[must_use]
    pub const fn wire_code(self) -> &'static str {
        match self {
            Self::MulticallRegistryLoad => "io.multicall_registry_load",
            Self::MulticallRegistrySave => "io.multicall_registry_save",
            Self::AuditWriterSetup => "io.audit_writer_setup",
        }
    }

    /// Operator-facing human label embedded in [`WalletError::Io`] display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MulticallRegistryLoad => "multicall registry load",
            Self::MulticallRegistrySave => "multicall registry save",
            Self::AuditWriterSetup => "audit writer setup",
        }
    }
}

/// The unified error type for every public API in this crate.
///
/// `WalletError` is a nested enum: each variant wraps a category-specific
/// sub-enum that carries the fine-grained error detail.  The outer variant
/// identifies the broad domain; the inner variant identifies the exact
/// condition.
///
/// Use [`WalletError::code`] to obtain the stable wire-format code string
/// (e.g. `"validation.memo_required"`), [`WalletError::category`] for
/// programmatic category filtering, and [`WalletError::message`] for the
/// human-readable text.
///
/// All variants are `#[non_exhaustive]` so downstream match arms must include
/// a wildcard fallback.  This guarantees forward compatibility as new codes
/// are added without breaking existing callers.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::error::{WalletError, ValidationError};
///
/// let err = WalletError::Validation(ValidationError::MemoRequired {
///     destination: "GABC...XYZ".to_owned(),
/// });
/// assert_eq!(err.code(), "validation.memo_required");
/// assert!(err.message().contains("GABC...XYZ"));
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletError {
    /// User-supplied input failed a validation check.
    #[error(transparent)]
    Validation(#[from] ValidationError),

    /// A network operation (RPC, Horizon) failed.
    #[error(transparent)]
    Network(#[from] NetworkError),

    /// An authentication or keyring operation failed.
    #[error(transparent)]
    Auth(#[from] AuthError),

    /// The hardware wallet or keyring is in an unexpected state.
    #[error(transparent)]
    WalletState(#[from] WalletStateError),

    /// An XDR or protocol-level error occurred.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// A ledger-state pre-condition was not met (e.g. insufficient balance).
    #[error(transparent)]
    Ledger(#[from] LedgerError),

    /// Transaction submission was rejected or timed out.
    #[error(transparent)]
    Submission(#[from] SubmissionError),

    /// An internal invariant was violated.  If you see this, it is a bug.
    #[error(transparent)]
    Internal(#[from] InternalError),

    /// A filesystem I/O operation failed.
    ///
    /// `source_kind` is a closed-set, non-secret operator-facing discriminator for
    /// the failing I/O site. `message` is the sanitized I/O diagnostic.
    ///
    /// # Wire-code table
    ///
    /// | `source_kind` | `WalletError::code()` |
    /// |---|---|
    /// | [`IoSource::MulticallRegistryLoad`] | `io.multicall_registry_load` |
    /// | [`IoSource::MulticallRegistrySave`] | `io.multicall_registry_save` |
    /// | [`IoSource::AuditWriterSetup`] | `io.audit_writer_setup` |
    #[error("io ({}): {message}", source_kind.label())]
    Io {
        /// Closed-set source for the failing I/O site.
        source_kind: IoSource,
        /// Sanitized human-readable I/O diagnostic.
        message: Cow<'static, str>,
    },

    /// A smart-account orchestration operation failed.
    ///
    /// Wraps `SaError` wire-code + display text so that the CLI and MCP
    /// layers can route the typed `sa.*` wire code through the shared
    /// `WalletError` envelope without introducing a circular crate dependency
    /// (`stellar-agent-core` does not depend on `stellar-agent-smart-account`).
    ///
    /// Callers construct this variant from `SaError` via:
    ///
    /// ```text
    /// WalletError::SmartAccount {
    ///     wire_code: sa_err.wire_code(),
    ///     message: sa_err.to_string(),
    /// }
    /// ```
    ///
    /// # Wire code
    ///
    /// `WalletError::code()` delegates to the `wire_code` field directly, so
    /// the CLI/MCP envelope emits `"sa.deployment_failed"` (or any other
    /// `sa.*` code) in the `"error.code"` field.
    #[error("smart-account operation failed ({wire_code}): {message}")]
    SmartAccount {
        /// Stable `SaError::wire_code()` value (e.g. `"sa.deployment_failed"`).
        ///
        /// Always `'static` because `SaError::wire_code()` is `&'static str`.
        wire_code: &'static str,
        /// Human-readable failure message from `SaError::to_string()`.
        ///
        /// Pre-redacted at the call site (no secret material).
        message: String,
    },
}

/// The top-level category of a [`WalletError`].
///
/// Returned by [`WalletError::category`] for programmatic filtering without
/// needing to match on error variants or parse the wire code string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCategory {
    /// User-supplied input validation failure.
    Validation,
    /// Network connectivity or RPC failure.
    Network,
    /// Keyring or signing authentication failure.
    Auth,
    /// Hardware wallet or keyring state error.
    WalletState,
    /// XDR / Soroban protocol error.
    Protocol,
    /// On-chain ledger-state pre-condition failure.
    Ledger,
    /// Transaction submission failure.
    Submission,
    /// Internal invariant violation.
    Internal,
    /// Filesystem I/O failure.
    Io,
    /// Smart-account orchestration failure (`sa.*` wire code).
    SmartAccount,
}

impl WalletError {
    /// Returns the stable wire-format error code for this error.
    ///
    /// The code is a `<category>.<subcode>` string in lowercase snake_case,
    /// for example `"validation.memo_required"` or `"network.rpc_timeout"`.
    /// The string is `'static` — no allocation occurs.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::error::{WalletError, NetworkError};
    ///
    /// let err = WalletError::Network(NetworkError::FriendbotMainnetForbidden);
    /// assert_eq!(err.code(), "network.friendbot_mainnet_forbidden");
    /// ```
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(e) => e.code(),
            Self::Network(e) => e.code(),
            Self::Auth(e) => e.code(),
            Self::WalletState(e) => e.code(),
            Self::Protocol(e) => e.code(),
            Self::Ledger(e) => e.code(),
            Self::Submission(e) => e.code(),
            Self::Internal(e) => e.code(),
            Self::Io { source_kind, .. } => source_kind.wire_code(),
            // Delegates to the SaError wire code stored at construction time.
            // The wire code is &'static str from SaError::wire_code(); the
            // WalletError::SmartAccount variant stores a copy so that no
            // circular crate dependency is required.
            Self::SmartAccount { wire_code, .. } => wire_code,
        }
    }

    /// Returns the [`ErrorCategory`] for this error.
    ///
    /// Useful for downstream filtering by broad domain without matching on
    /// inner variants.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::error::{WalletError, ValidationError, ErrorCategory};
    ///
    /// let err = WalletError::Validation(ValidationError::AmountUnitsRequired);
    /// assert_eq!(err.category(), ErrorCategory::Validation);
    /// ```
    #[must_use]
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::Validation(_) => ErrorCategory::Validation,
            Self::Network(_) => ErrorCategory::Network,
            Self::Auth(_) => ErrorCategory::Auth,
            Self::WalletState(_) => ErrorCategory::WalletState,
            Self::Protocol(_) => ErrorCategory::Protocol,
            Self::Ledger(_) => ErrorCategory::Ledger,
            Self::Submission(_) => ErrorCategory::Submission,
            Self::Internal(_) => ErrorCategory::Internal,
            Self::Io { .. } => ErrorCategory::Io,
            Self::SmartAccount { .. } => ErrorCategory::SmartAccount,
        }
    }

    /// Returns the human-readable error message.
    ///
    /// This is a thin wrapper over [`std::string::ToString::to_string`]
    /// (which delegates to [`std::fmt::Display`]) provided for API symmetry
    /// with [`WalletError::code`] and [`WalletError::category`].
    /// Capture it once per emitted error response if the same message is
    /// needed in multiple output fields.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::error::{WalletError, LedgerError};
    ///
    /// let err = WalletError::Ledger(LedgerError::InsufficientBalance {
    ///     asset: "XLM".to_owned(),
    ///     have: "1.0".to_owned(),
    ///     need: "5.0".to_owned(),
    /// });
    /// assert!(err.message().contains("XLM"));
    /// ```
    #[must_use]
    pub fn message(&self) -> String {
        self.to_string()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Validation errors — support types
// ──────────────────────────────────────────────────────────────────────────────

/// The kind of entity (signer or policy) that exceeded the per-rule cap.
///
/// Used as a discriminant in [`ValidationError::ContextRuleCapsExceeded`] to
/// produce a precise, machine-readable wire code that callers can route on
/// without parsing the human-readable message.
///
/// Distinguishes the two OZ per-rule hard limits: `MAX_SIGNERS = 15` and
/// `MAX_POLICIES = 5` (OpenZeppelin Stellar contracts v0.7.2,
/// `smart_account/mod.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CapKind {
    /// The per-rule signer cap was exceeded (`MAX_SIGNERS = 15`).
    Signer,
    /// The per-rule policy cap was exceeded (`MAX_POLICIES = 5`).
    Policy,
}

// ──────────────────────────────────────────────────────────────────────────────
// Validation errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors arising from user-supplied input validation.
///
/// These are returned before any network call or signing operation when the
/// inputs provided by the user or calling code do not satisfy the requirements
/// of the requested operation.
///
/// # Secret-material policy
///
/// No field in any variant carries secret material.  All `String` fields hold
/// user-visible public data (amounts, destination account IDs, asset codes,
/// rule identifiers, profile names).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// The amount was specified without explicit units (e.g. `"100"` instead
    /// of `"100 XLM"` or `"100.0000000"`).
    #[error("amount must specify units (e.g. '100 XLM' or '100.0000000')")]
    AmountUnitsRequired,

    /// The amount string exceeds the seven-decimal-place precision allowed by
    /// the Stellar protocol.
    ///
    /// `amount` holds the user-entered amount string (e.g. `"1.12345678"`).
    #[error("amount '{amount}' exceeds the maximum precision of 7 decimal places")]
    AmountPrecisionExceeded {
        /// The user-entered amount string that exceeded protocol precision.
        amount: String,
    },

    /// A destination account requires a memo but none was provided.
    ///
    /// `destination` holds the public account ID (`G…`) of the destination
    /// account that requires the memo.
    #[error("destination '{destination}' requires a memo but none was provided")]
    MemoRequired {
        /// The public account ID (`G…`) of the destination that requires a memo.
        destination: String,
    },

    /// The supplied memo type is not valid for the requested operation.
    ///
    /// `memo_type` holds the memo-type string as supplied by the caller
    /// (e.g. `"MEMO_HASH"`, `"invalid"`).
    #[error("memo type '{memo_type}' is not valid for this operation")]
    MemoInvalidType {
        /// The memo-type string as supplied by the caller.
        memo_type: String,
    },

    /// More than one memo variant was supplied simultaneously.
    ///
    /// Stellar transactions carry at most one memo.  The four memo variants
    /// (`text`, `id`, `hash`, `return`) are mutually exclusive; providing two
    /// or more at once is a validation error.
    ///
    /// # Wire code
    ///
    /// `"validation.memo_mutually_exclusive"`.
    #[error("at most one memo variant may be provided; multiple memo fields were set")]
    MemoMutuallyExclusive,

    /// A Stellar account address could not be parsed.
    ///
    /// `input` holds the raw input string provided by the user or calling
    /// code (e.g. `"GABC"`).  This is a public identifier; it is safe to
    /// display.
    #[error("address '{input}' is not a valid Stellar account address")]
    AddressInvalid {
        /// The raw input string that failed to parse as a Stellar address.
        input: String,
    },

    /// An asset descriptor could not be parsed.
    ///
    /// `input` holds the raw asset string provided by the user or calling
    /// code (e.g. `"USDC:invalid"`).
    #[error("asset '{input}' is not a valid asset descriptor")]
    AssetInvalid {
        /// The raw input string that failed to parse as an asset descriptor.
        input: String,
    },

    /// A named profile was not found in the wallet configuration.
    ///
    /// `name` holds the profile name as supplied by the caller.
    #[error("profile '{name}' was not found in the wallet configuration")]
    ProfileNotFound {
        /// The profile name that was not found.
        name: String,
    },

    /// An amount string failed numeric parsing.
    ///
    /// `input` holds the raw input string provided by the user or calling
    /// code (e.g. `"abc XLM"`, `"100.5.0 XLM"`, empty string).  This is
    /// a user-supplied value with no secret material.
    ///
    /// This variant covers syntactic invalidity.  For semantic invalidity
    /// (precision exceeded, out of range) see [`ValidationError::AmountPrecisionExceeded`]
    /// and [`ValidationError::AmountOutOfRange`].
    #[error("amount '{input}' could not be parsed as a valid amount")]
    AmountMalformed {
        /// The raw input string that failed to parse.
        input: String,
    },

    /// An amount is outside the representable `i64` stroop range.
    ///
    /// Reserved for **parse-level overflow** only — i.e. the numeric value
    /// cannot fit in the on-wire `i64` stroop type.  Semantic-domain
    /// rejections (e.g. a payment operation that requires a positive
    /// amount, or a fee that exceeds a policy cap) must use a distinct
    /// variant, not this one; do not recycle `AmountOutOfRange` for domain
    /// checks or the stable wire code `validation.amount_out_of_range`
    /// loses its parse-level semantics.
    ///
    /// `amount` holds the amount string that overflowed (e.g.
    /// `"99999999999999999999 XLM"`).  This is a user-supplied value with
    /// no secret material.
    #[error("amount '{amount}' is outside the representable i64 stroop range")]
    AmountOutOfRange {
        /// The amount string that overflowed the `i64` stroop range.
        amount: String,
    },

    /// The `--output` flag value is not a recognised output format.
    ///
    /// `input` holds the raw string supplied by the user or calling code
    /// (e.g. `"xml"`, `" json"` with a leading space, `""`).  Accepted
    /// values are `"json"` and `"table"` (case-insensitive).
    ///
    /// This variant is produced by [`crate::envelope::OutputFormat::parse`]
    /// when the supplied string does not match a known format.  It is also
    /// the code emitted in an error envelope when a CLI flag value is
    /// rejected before the command runs.
    #[error("output format '{input}' is not recognised; accepted values are 'json' and 'table'")]
    OutputFormatInvalid {
        /// The raw input string that did not match a known output format.
        input: String,
    },

    /// A plugin name failed audit-log construction validation.
    ///
    /// `reason` is a stable, non-secret diagnostic selected by the validator.
    /// Plugin names are limited to 1-64 characters from `[a-z0-9_-]` so they
    /// cannot inject JSON, line breaks, or additional audit-log tool segments.
    #[error("plugin name is invalid: {reason}")]
    InvalidPluginName {
        /// Stable validation reason.
        reason: String,
    },

    /// An external-only context rule was rejected because it lacks a
    /// delegated (ed25519) fallback signer.
    ///
    /// A rule whose signers are exclusively external (WebAuthn passkey
    /// and/or raw Ed25519) with no delegated ed25519 fallback is permanently
    /// inaccessible if the authenticator device or external signing key is
    /// lost (a WebAuthn credential's RP-ID binding is irrecoverable; a raw
    /// Ed25519 external signer has no keyring-backed recovery path either).
    ///
    /// The operator must either add a `--signer-delegated` entry or pass
    /// `--accept-no-delegated-fallback` to explicitly acknowledge the risk.
    ///
    /// # Wire code
    ///
    /// `"validation.passkey_only_rule_no_delegated_fallback"`.
    #[error(
        "external-only rule refused: {credential_count} WebAuthn passkey and/or raw Ed25519 \
         signer(s), no delegated fallback signer; pass --accept-no-delegated-fallback to \
         acknowledge the risk"
    )]
    PasskeyOnlyRuleNoDelegatedFallback {
        /// Number of external (WebAuthn passkey and/or raw Ed25519) signers
        /// that would be the sole signers.
        credential_count: usize,
    },

    /// A per-rule cap was exceeded — adding the requested signer or policy
    /// would push the rule over the OZ on-chain hard limit.
    ///
    /// The CLI orchestration layer refuses cap-exceeding operations
    /// fail-closed, before the simulate/submit cycle reaches the contract.
    /// The on-chain panic discriminants `TooManySigners = 3010` and
    /// `TooManyPolicies = 3011` (OpenZeppelin Stellar contracts v0.7.2,
    /// `smart_account/mod.rs`)
    /// remain the authoritative last-line defence if the CLI check is
    /// bypassed (e.g. concurrent on-chain mutation between fetch and submit).
    ///
    /// `kind` identifies which cap was exceeded. `attempted` is the total
    /// count the operation would produce (one past the current count).
    /// `max` is the OZ canonical cap value.
    ///
    /// # Wire code
    ///
    /// `"validation.context_rule_caps_exceeded"`.
    #[error(
        "context rule cap exceeded: cannot add {kind:?} #{attempted} (current cap: {max}); \
         alternative: create a new rule with the additional {kind:?}, then delete the old \
         rule, or use the rule-rotation pattern"
    )]
    ContextRuleCapsExceeded {
        /// Which cap was exceeded — signer (`MAX_SIGNERS = 15`) or policy
        /// (`MAX_POLICIES = 5`). OpenZeppelin Stellar contracts v0.7.2,
        /// `smart_account/mod.rs`.
        kind: CapKind,
        /// The count the operation would produce (current count + 1).
        attempted: u32,
        /// The OZ canonical per-rule hard cap.
        max: u32,
    },

    /// An XDR argument supplied by the operator failed base64 decode or XDR
    /// parse.
    ///
    /// `arg` is the CLI flag name (e.g. `"install-param"`).  `reason` is a
    /// non-secret diagnostic from the XDR library.
    ///
    /// This variant is distinct from [`ValidationError::AddressInvalid`] (which
    /// covers Stellar account/contract address strings) because XDR arguments
    /// are opaque binary blobs encoded in base64, not human-readable address
    /// strings.  Routing them through `AddressInvalid` would misrepresent the
    /// error domain to tooling that routes on wire-codes.
    ///
    /// # Wire code
    ///
    /// `"validation.xdr_argument_malformed"`.
    #[error("XDR argument '--{arg}' malformed: {reason}")]
    XdrArgumentMalformed {
        /// The CLI flag name that carried the malformed XDR value
        /// (e.g. `"install-param"`).  Never contains secret material.
        arg: String,
        /// Non-secret diagnostic from the XDR library (e.g.
        /// `"base64 decode failed"`, `"unexpected end of input"`).
        reason: String,
    },

    /// The session-rule `valid_until - current_ledger` horizon exceeds the
    /// per-profile maximum.
    ///
    /// `rule_id_or_pending = None` on the `install_rule` path (the rule has
    /// not been created yet); `Some(id)` on the `update_valid_until` path
    /// (post-install update).
    ///
    /// The default maximum horizon is
    /// `stellar_agent_smart_account::managers::rules::DEFAULT_SESSION_RULE_HORIZON_LEDGERS`
    /// (1000 ledgers ≈ 80 minutes at 5 s ledger times).
    /// Operators may raise it via `session_rule_max_horizon_ledgers` in their
    /// profile TOML, up to the safety cap
    /// `stellar_agent_smart_account::managers::rules::UPPER_BOUND_HORIZON_LEDGERS`
    /// (10,000 ledgers; ~13.9–15.3 hours at 5 s ledgers).
    ///
    /// The OZ on-chain contract (`smart_account/storage.rs`) only
    /// rejects `valid_until < current_ledger` (`PastValidUntil = 3005`).
    /// There is **no on-chain max-horizon cap** — this is a wallet-side
    /// orchestration discipline to bound the in-flight envelope race window.
    ///
    /// # Wire code
    ///
    /// `"validation.session_rule_horizon_exceeded"`.
    #[error(
        "session-rule horizon exceeded: requested {requested_horizon} ledgers \
         exceeds max {max_horizon} (per-profile `session_rule_max_horizon_ledgers`); \
         lower the --valid-until value or override the profile cap"
    )]
    SessionRuleHorizonExceeded {
        /// `None` when the rule has not yet been installed (install path);
        /// `Some(id)` when the rule already exists (update path).
        rule_id_or_pending: Option<u32>,
        /// The computed `valid_until - current_ledger` horizon in ledgers.
        requested_horizon: u32,
        /// The effective maximum horizon in ledgers (profile override if set,
        /// otherwise `DEFAULT_SESSION_RULE_HORIZON_LEDGERS = 1000`).
        max_horizon: u32,
    },

    /// A multicall bundle was empty.
    #[error("multicall bundle must contain at least one invocation")]
    BundleEmpty,

    /// A multicall bundle exceeds the supported wallet maximum.
    #[error("bundle too large: got {got}, max {max} (configured MULTICALL_BUNDLE_CAP)")]
    BundleTooLarge {
        /// Number of invocations supplied.
        got: usize,
        /// Maximum supported invocation count.
        max: u32,
    },

    /// A fee mode was parsed but is not supported by the current command.
    #[error("unsupported fee mode '{mode}': {reason}")]
    UnsupportedFeeMode {
        /// Parsed or user-supplied fee mode.
        mode: String,
        /// Non-secret remediation text.
        reason: String,
    },

    /// The `--use-oz-relayer` opt-in was set but relayer submission is not
    /// implemented in this build.
    ///
    /// The wallet emits an AGPL-3.0 disclosure banner to stderr at opt-in
    /// time and then returns this error to decline the operation.  The default
    /// in-process submission path requires no external relayer dependency; the
    /// operator should re-run without `--use-oz-relayer`.
    ///
    /// # Wire code
    ///
    /// `"validation.relayer_not_implemented"`.
    #[error(
        "relayer submission is not implemented in this build; \
         re-run without --use-oz-relayer to use the default in-process path"
    )]
    RelayerNotImplemented,

    /// The `--valid-until` argument could not be parsed as `none` or a `u32`
    /// ledger sequence.
    ///
    /// `input` holds the raw value provided by the caller (e.g. `"foo"`,
    /// `"99999999999"`). This is a user-visible non-secret string.
    ///
    /// Distinct from [`ValidationError::AddressInvalid`]: `--valid-until`
    /// accepts a ledger sequence or the literal `"none"` — it is not an
    /// address; routing parse failures through `AddressInvalid` produces a
    /// misleading wire code.
    ///
    /// # Wire code
    ///
    /// `"validation.valid_until_invalid"`.
    #[error("--valid-until '{input}' is not 'none' or a valid u32 ledger sequence")]
    ValidUntilInvalid {
        /// The raw input string that failed to parse.
        input: String,
    },

    /// A component configuration value could not be parsed or resolved.
    ///
    /// `component` names the subsystem or flag whose configuration failed
    /// (e.g. `"ContextRuleManager"`, `"rpc_url"`).  `reason` is a non-secret
    /// diagnostic string.
    ///
    /// Distinct from [`ValidationError::AddressInvalid`]: this covers
    /// construction-time configuration errors (manager init, URL parse, profile
    /// resolution) that are not address-parsing failures.
    ///
    /// # Wire code
    ///
    /// `"validation.config_invalid"`.
    #[error("configuration invalid for '{component}': {reason}")]
    ConfigInvalid {
        /// The subsystem or flag whose configuration is invalid.
        component: &'static str,
        /// Non-secret diagnostic string.
        reason: String,
    },

    /// The rule name exceeds the OZ on-chain maximum length.
    ///
    /// `name_len` is the byte length of the supplied name. `max` is the
    /// OZ canonical cap (`MAX_NAME_SIZE = 20` bytes, OpenZeppelin Stellar
    /// contracts v0.7.2, `smart_account/mod.rs`).
    ///
    /// The on-chain enforcement (`SmartAccountError::NameTooLong = 3015`,
    /// `smart_account/mod.rs`) is the authoritative last-line defence.
    /// This pre-flight check gives the operator an actionable error before
    /// the simulate/submit cycle.
    ///
    /// # Wire code
    ///
    /// `"validation.rule_name_too_long"`.
    #[error("rule name is {name_len} bytes, exceeding the OZ maximum of {max} bytes")]
    RuleNameTooLong {
        /// Byte length of the supplied name.
        name_len: usize,
        /// OZ canonical maximum byte length (`MAX_NAME_SIZE = 20`).
        max: usize,
    },

    /// The audit log file to verify does not exist at the supplied path.
    ///
    /// A user-actionable condition, not an integrity violation: either nothing
    /// has been written to the audit log yet, or the `--log-path` is wrong.
    /// Carries the `audit.log_not_found` wire code (audit taxonomy) while being
    /// a validation-class error so callers can distinguish "no log yet" from a
    /// tamper-evidence failure.
    ///
    /// # Wire code
    ///
    /// `"audit.log_not_found"`.
    #[error(
        "audit log not found at {path}; nothing has been written to the audit \
         log yet, or the --log-path is incorrect"
    )]
    AuditLogNotFound {
        /// Display path of the missing primary audit-log file.
        path: String,
    },
}

impl ValidationError {
    /// Returns the stable wire-format subcode for this validation error.
    ///
    /// Always prefixed with `"validation."` when accessed through
    /// [`WalletError::code`].
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::AmountUnitsRequired => "validation.amount_units_required",
            Self::AmountPrecisionExceeded { .. } => "validation.amount_precision_exceeded",
            Self::MemoRequired { .. } => "validation.memo_required",
            Self::MemoInvalidType { .. } => "validation.memo_invalid_type",
            Self::MemoMutuallyExclusive => "validation.memo_mutually_exclusive",
            Self::AddressInvalid { .. } => "validation.address_invalid",
            Self::AssetInvalid { .. } => "validation.asset_invalid",
            Self::ProfileNotFound { .. } => "validation.profile_not_found",
            Self::AmountMalformed { .. } => "validation.amount_malformed",
            Self::AmountOutOfRange { .. } => "validation.amount_out_of_range",
            Self::OutputFormatInvalid { .. } => "validation.output_format_invalid",
            Self::InvalidPluginName { .. } => "validation.invalid_plugin_name",
            Self::PasskeyOnlyRuleNoDelegatedFallback { .. } => {
                "validation.passkey_only_rule_no_delegated_fallback"
            }
            Self::ContextRuleCapsExceeded { .. } => "validation.context_rule_caps_exceeded",
            Self::XdrArgumentMalformed { .. } => "validation.xdr_argument_malformed",
            Self::SessionRuleHorizonExceeded { .. } => "validation.session_rule_horizon_exceeded",
            Self::BundleEmpty => "validation.bundle_empty",
            Self::BundleTooLarge { .. } => "validation.bundle_too_large",
            Self::UnsupportedFeeMode { .. } => "validation.unsupported_fee_mode",
            Self::RelayerNotImplemented => "validation.relayer_not_implemented",
            Self::ValidUntilInvalid { .. } => "validation.valid_until_invalid",
            Self::ConfigInvalid { .. } => "validation.config_invalid",
            Self::RuleNameTooLong { .. } => "validation.rule_name_too_long",
            // Audit taxonomy code on a validation-class variant: the code names
            // the subsystem (audit.*) while the category stays Validation.
            Self::AuditLogNotFound { .. } => "audit.log_not_found",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Network errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors arising from network connectivity failures or protocol-level
/// rejection from Stellar RPC or Horizon endpoints.
///
/// # Secret-material policy
///
/// No field in any variant carries secret material.  `url` fields hold
/// endpoint URLs (not credentials).  `account_id` fields hold public `G…`
/// account identifiers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetworkError {
    /// The RPC endpoint did not respond within the configured timeout.
    ///
    /// `url` holds the RPC endpoint URL.  `timeout_secs` holds the timeout
    /// in seconds as configured or defaulted.
    #[error("RPC endpoint '{url}' timed out after {timeout_secs}s")]
    RpcTimeout {
        /// The RPC endpoint URL that timed out.
        url: String,
        /// The timeout duration in seconds.
        timeout_secs: u64,
    },

    /// The RPC endpoint was not reachable (connection refused, DNS failure,
    /// TLS error, etc.).
    ///
    /// `url` holds the RPC endpoint URL.  `reason` holds a non-secret
    /// description of the underlying network error (e.g. `"connection
    /// refused"`, `"DNS resolution failed"`).
    #[error("RPC endpoint '{url}' is unreachable: {reason}")]
    RpcUnreachable {
        /// The RPC endpoint URL that was not reachable.
        url: String,
        /// A non-secret description of the underlying network error.
        ///
        /// Named `reason` rather than `source` because the field is a
        /// free-form diagnostic string, not a typed error-source chain.
        /// Variants that preserve an error source chain do so via a
        /// dedicated `#[from] source: T` typed field (see
        /// [`InternalError::SerialisationFailed`]).
        reason: String,
    },

    /// Friendbot is not available on mainnet.
    ///
    /// This error is returned when a caller attempts to fund an account via
    /// Friendbot against a mainnet RPC endpoint.
    #[error(
        "friendbot is not available on mainnet; switch to testnet or fund the account manually"
    )]
    FriendbotMainnetForbidden,

    /// The specified account was not found on the network.
    ///
    /// `account_id` holds the public account ID (`G…` or `C…`) that was
    /// queried.  The full ID is shown for operator auditability; apply log-layer
    /// redaction before emitting to structured logs.
    #[error("account '{account_id}' was not found on the network")]
    AccountNotFound {
        /// The public account ID (`G…` or `C…`) that was not found.
        account_id: String,
    },

    /// A mainnet write operation was attempted but the policy engine has not
    /// been initialised.
    #[error("mainnet write operations require the policy engine to be configured")]
    MainnetWriteForbidden,

    /// The Horizon API returned an unexpected HTTP status code.
    ///
    /// `status` holds the HTTP status code returned by Horizon.
    #[error("Horizon API is unavailable (HTTP {status})")]
    HorizonUnavailable {
        /// The HTTP status code returned by Horizon.
        status: u16,
    },

    /// The RPC backend returned a response that could not be decoded or mapped.
    #[error("RPC method '{method}' returned a malformed response: {detail}")]
    RpcResponseMalformed {
        /// JSON-RPC method name.
        method: String,
        /// Non-secret parse or mapping detail.
        detail: String,
    },

    /// The primary and secondary RPCs disagree on an on-chain data value.
    ///
    /// Emitted by cross-RPC consistency checks (e.g. SEP-29 `config.memo_required`
    /// cross-check when `secondary_rpc` is configured).
    /// The caller MUST NOT proceed with the operation when this error is returned —
    /// the disagreement indicates either an active manipulation or a transient
    /// ledger-propagation race.  The recovery action is always to re-simulate after
    /// the disagreement clears.
    ///
    /// `context` holds a non-secret description of what diverged
    /// (e.g. `"SEP-29 config.memo_required"`).  The description MUST NOT
    /// include key material, account balances, or other sensitive data.
    #[error("{context} differs between primary and secondary RPC; re-simulate")]
    RpcDivergence {
        /// Non-secret description of the diverging value.
        context: String,
    },

    /// A Friendbot HTTP response was successful but the funded account never
    /// became visible on the queried RPC endpoint within the verification
    /// window.
    ///
    /// `account_id` holds the public account ID (`G…`) that was funded. The
    /// full ID is shown for operator auditability, matching
    /// [`NetworkError::AccountNotFound`]. `waited_secs` holds the elapsed
    /// verification time so the operator can tell a slow-but-progressing
    /// network from Friendbot silently failing.
    #[error(
        "Friendbot funded account '{account_id}' but it did not become visible on RPC \
         within {waited_secs}s"
    )]
    FriendbotFundingNotConfirmed {
        /// The public account ID (`G…`) that was funded but not yet visible.
        account_id: String,
        /// Seconds spent polling before giving up.
        waited_secs: u64,
    },
}

impl NetworkError {
    /// Returns the stable wire-format subcode for this network error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RpcTimeout { .. } => "network.rpc_timeout",
            Self::RpcUnreachable { .. } => "network.rpc_unreachable",
            Self::FriendbotMainnetForbidden => "network.friendbot_mainnet_forbidden",
            Self::AccountNotFound { .. } => "network.account_not_found",
            Self::MainnetWriteForbidden => "network.mainnet_write_forbidden",
            Self::HorizonUnavailable { .. } => "network.horizon_unavailable",
            Self::RpcResponseMalformed { .. } => "network.rpc_response_malformed",
            Self::RpcDivergence { .. } => "network.rpc_divergence",
            Self::FriendbotFundingNotConfirmed { .. } => "network.friendbot_funding_not_confirmed",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Auth errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors arising from keyring access or signing authentication.
///
/// # Secret-material policy
///
/// No field in any variant carries secret material.  The `name` field in
/// `KeyringNotFound` holds a keyring label (a non-secret identifier).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The keyring is locked and must be unlocked before use.
    #[error("the keyring is locked; unlock it before proceeding")]
    KeyringLocked,

    /// The platform keyring backend failed or is unavailable.
    ///
    /// Distinct from [`AuthError::KeyringLocked`]: unlocking the user's
    /// keyring is not expected to fix platform backend failures, missing
    /// storage access, or keyring service misconfiguration.
    ///
    /// Upstream mappings intentionally share one stable wire code:
    /// `keyring_core::Error::PlatformFailure(_)` means the keyring service
    /// failed or is misconfigured, while `keyring_core::Error::NoStorageAccess(_)`
    /// means the backend refused storage access, often due to a user-denied
    /// prompt. Operator remediation differs, but the variant remains lumped to
    /// preserve `auth.keyring_platform_error` wire compatibility until a
    /// dedicated wire-code-change cycle splits it.
    /// Carries no fields; no secret material crosses the variant boundary.
    #[error("platform keyring backend error; check keyring service configuration")]
    KeyringPlatformError,

    /// The specified keyring entry was not found.
    ///
    /// `name` holds the keyring entry label as supplied by the caller.
    #[error("keyring entry '{name}' was not found")]
    KeyringNotFound {
        /// The keyring entry label that was not found.
        name: String,
    },

    /// The user refused the signing request on the hardware device.
    #[error("the user refused the signing request on the hardware device")]
    HardwareUserRefused,

    /// The signing key's derived public key does not match `--source`.
    ///
    /// `expected` holds the `--source` G-strkey supplied by the caller.
    /// `got` holds the public key derived from the signing key (software) or
    /// fetched from the device (hardware). Neither carries secret material.
    #[error("signing key public key '{got}' does not match --source '{expected}'")]
    SignerKeyMismatch {
        /// The `--source` G-strkey supplied by the caller.
        expected: String,
        /// The public key derived from or fetched via the signing key.
        got: String,
    },

    /// The signing key's kind cannot fulfil the requested signing primitive.
    ///
    /// Each signer primitive is bound to a specific signer kind:
    /// `sign_tx_payload` and `sign_auth_digest` are ed25519-signer primitives;
    /// `sign_webauthn_assertion` is a passkey-signer primitive. Asking a
    /// software ed25519 signer to produce a WebAuthn assertion (or vice-versa)
    /// is a category error caught at the trait-impl boundary.
    ///
    /// `signer_kind` is a `&'static str` operator-safe taxonomy label
    /// (`"software"`, `"hardware"`, `"keyring"`, `"passkey"`); no secret material.
    /// `requested_primitive` names the trait method the signer was asked to fulfil.
    ///
    /// Distinct from [`AuthError::SignerKeyMismatch`] (pubkey-derivation
    /// mismatch — same kind, different pubkey).
    #[error("signer kind '{signer_kind}' cannot fulfil '{requested_primitive}'")]
    SignerKindMismatch {
        /// Operator-safe taxonomy label for the signer's kind.
        signer_kind: &'static str,
        /// The trait method the signer was asked to fulfil.
        requested_primitive: &'static str,
    },
}

impl AuthError {
    /// Returns the stable wire-format subcode for this auth error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::KeyringLocked => "auth.keyring_locked",
            Self::KeyringPlatformError => "auth.keyring_platform_error",
            Self::KeyringNotFound { .. } => "auth.keyring_not_found",
            Self::HardwareUserRefused => "auth.hardware_user_refused",
            Self::SignerKeyMismatch { .. } => "auth.signer_key_mismatch",
            Self::SignerKindMismatch { .. } => "auth.signer_kind_mismatch",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// WalletState errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors representing unexpected or invalid hardware-wallet or keyring state.
///
/// These differ from [`AuthError`] in that they describe a physical or
/// environmental condition (device not found, device timeout, wrong app) rather
/// than an authentication rejection.
///
/// # Secret-material policy
///
/// No field in any variant carries secret material.  `expected`/`got` fields
/// in `HardwareWrongApp` hold application-name strings.  `detail` in
/// `KeyringCorrupted` holds a non-secret diagnostic string.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletStateError {
    /// No hardware wallet device was found.
    #[error("no hardware wallet device was found; connect the device and try again")]
    HardwareNotFound,

    /// The hardware wallet device timed out.
    #[error("the hardware wallet device timed out; confirm the device is responsive")]
    HardwareTimeout,

    /// The hardware wallet device has the wrong application open.
    ///
    /// `expected` holds the name of the application that should be open.
    /// `got` holds the name (or identifier) of the application currently open.
    #[error("hardware wallet has wrong app open (expected '{expected}', got '{got}')")]
    HardwareWrongApp {
        /// The name of the application that should be open on the device.
        expected: String,
        /// The name or identifier of the application currently open.
        got: String,
    },

    /// The hardware wallet has blind signing disabled in the Stellar app
    /// settings.
    ///
    /// Blind signing must be enabled in the Stellar Ledger app before signing
    /// a transaction hash (hash-signing mode). The user must open the Stellar
    /// app settings on the device, enable "Allow blind signing", and retry.
    ///
    /// Maps `stellar_ledger::Error::BlindSigningModeNotEnabled` to a distinct,
    /// actionable taxonomy entry rather than collapsing it into `HardwareWrongApp`.
    /// The user-facing message differs: wrong-app tells the user to switch apps;
    /// blind-signing-disabled tells them to change a setting within the correct app.
    ///
    /// # Wire code
    ///
    /// `"wallet_state.hardware_blind_signing_disabled"`
    #[error(
        "blind signing is disabled on the Ledger Stellar app; \
        enable it in the app settings and retry"
    )]
    HardwareBlindSigningDisabled,

    /// The keyring store is corrupted and cannot be read.
    ///
    /// `detail` holds a non-secret diagnostic string describing the nature of
    /// the corruption (e.g. `"invalid CBOR encoding"`, `"checksum mismatch"`).
    #[error("keyring store is corrupted and cannot be read: {detail}")]
    KeyringCorrupted {
        /// A non-secret diagnostic string describing the nature of the corruption.
        detail: String,
    },

    /// The browser-handoff WebAuthn bridge is unavailable.
    ///
    /// Returned when the wallet cannot dispatch a WebAuthn ceremony to the
    /// operator's browser via the approval spine. Typical causes:
    /// - The local approval HTTP listener is not running.
    /// - The configured browser command failed to launch.
    ///
    /// # Wire code
    ///
    /// `"wallet_state.platform_authenticator_unavailable"`
    ///
    /// # Stability
    ///
    /// The variant name is retained for semver stability. The "platform
    /// authenticator" wording in the wire code refers to the WebAuthn ceremony
    /// as a whole, regardless of which surface (in-process FFI vs. browser
    /// handoff) drives it.
    #[error("WebAuthn browser-handoff bridge is not available on this system")]
    PlatformAuthenticatorUnavailable,

    /// An unexpected internal error occurred in the WebAuthn browser-handoff
    /// bridge.
    ///
    /// `reason` is an operator-safe diagnostic string (no credential bytes,
    /// no signature bytes, no secret material).
    ///
    /// # Wire code
    ///
    /// `"wallet_state.platform_authenticator_error"`
    ///
    /// # Stability
    ///
    /// Variant name retained for semver stability. The "platform authenticator"
    /// wording refers to the WebAuthn ceremony as a whole, regardless of the
    /// underlying transport.
    #[error("WebAuthn browser-handoff bridge error: {reason}")]
    PlatformAuthenticatorError {
        /// Operator-safe diagnostic string. Must not contain raw cryptographic
        /// material.
        reason: String,
    },

    /// The requested passkey credential was not found in the authenticator's
    /// secure storage.
    ///
    /// Returned when the platform authenticator cannot locate a credential
    /// matching any entry in the `allow_credentials` list. The wallet's
    /// `PasskeyCredentialRecord` store may be out of sync with the platform
    /// authenticator (e.g. the credential was deleted from the Secure Enclave
    /// after the wallet record was written).
    ///
    /// # Wire code
    ///
    /// `"wallet_state.passkey_credential_not_found"`
    #[error(
        "passkey credential not found on the platform authenticator; re-register the credential"
    )]
    PasskeyCredentialNotFound,
}

impl WalletStateError {
    /// Returns the stable wire-format subcode for this wallet-state error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::HardwareNotFound => "wallet_state.hardware_not_found",
            Self::HardwareTimeout => "wallet_state.hardware_timeout",
            Self::HardwareWrongApp { .. } => "wallet_state.hardware_wrong_app",
            Self::HardwareBlindSigningDisabled => "wallet_state.hardware_blind_signing_disabled",
            Self::KeyringCorrupted { .. } => "wallet_state.keyring_corrupted",
            Self::PlatformAuthenticatorUnavailable => {
                "wallet_state.platform_authenticator_unavailable"
            }
            Self::PlatformAuthenticatorError { .. } => "wallet_state.platform_authenticator_error",
            Self::PasskeyCredentialNotFound => "wallet_state.passkey_credential_not_found",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Protocol errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors arising from XDR encoding/decoding or Soroban protocol violations.
///
/// # Secret-material policy
///
/// No field in any variant carries secret material.  `detail` fields hold
/// non-secret diagnostic strings (XDR error descriptions, field names).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// XDR codec operation (encode or decode) failed, constructed directly
    /// with a free-form diagnostic string.
    ///
    /// `detail` holds a non-secret diagnostic string describing which XDR
    /// type or field failed to encode / decode (e.g. `"TransactionEnvelope:
    /// unexpected discriminant 42"`).
    #[error("XDR codec operation failed: {detail}")]
    XdrCodecFailed {
        /// A non-secret diagnostic string describing the XDR codec failure.
        detail: String,
    },
}

impl ProtocolError {
    /// Returns the stable wire-format subcode for this protocol error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::XdrCodecFailed { .. } => "protocol.xdr_codec_failed",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Ledger errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors representing on-chain ledger-state pre-condition failures.
///
/// These are typically surfaced after a preflight or simulation step confirms
/// that the ledger state does not allow the requested operation.
///
/// # Secret-material policy
///
/// No field carries secret material.  `asset` fields hold asset codes or
/// descriptors.  `account`/`destination` fields hold public account IDs
/// (`G…`/`C…`).  `have`/`need` fields hold amount strings.  `op` and
/// `result_code` fields hold operation names and ledger result-code strings.
/// Full account IDs are included in `Display` output for operator
/// auditability; apply log-layer redaction before emitting to structured logs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// The source account does not have sufficient balance to cover the
    /// operation plus the base reserve.
    ///
    /// `asset` holds the asset code (e.g. `"XLM"`, `"USDC:GA…"`).
    /// `have` holds the available balance string.  `need` holds the
    /// required balance string.
    #[error("insufficient balance: have {have} {asset}, need {need} {asset}")]
    InsufficientBalance {
        /// The asset code or descriptor for the asset with insufficient balance.
        asset: String,
        /// The available balance as a string.
        have: String,
        /// The required balance as a string.
        need: String,
    },

    /// The destination account address is invalid for the requested operation
    /// (e.g. does not exist on-chain when required).
    ///
    /// `destination` holds the public account ID (`G…`/`C…`) that was
    /// invalid.  Full ID shown for operator auditability; apply log-layer
    /// redaction before emitting to structured logs.
    #[error("destination '{destination}' is not a valid destination for this operation")]
    DestinationInvalid {
        /// The public account ID (`G…`/`C…`) that was invalid as a destination.
        destination: String,
    },

    /// A required trustline is missing on an account.
    ///
    /// `asset` holds the asset code or descriptor.  `account` holds the
    /// public account ID (`G…`/`C…`) that is missing the trustline.
    #[error("account '{account}' is missing a trustline for asset '{asset}'")]
    TrustlineMissing {
        /// The asset code or descriptor for which the trustline is missing.
        asset: String,
        /// The public account ID (`G…`/`C…`) that is missing the trustline.
        account: String,
    },

    /// A Stellar operation failed with a ledger-level result code.
    ///
    /// `op` holds the operation type name (e.g. `"Payment"`,
    /// `"ChangeTrust"`).  `result_code` holds the ledger result-code string
    /// (e.g. `"op_no_trust"`, `"op_underfunded"`).
    #[error("operation '{op}' failed with result code '{result_code}'")]
    OpFailed {
        /// The operation type name.
        op: String,
        /// The ledger result-code string.
        result_code: String,
    },
}

impl LedgerError {
    /// Returns the stable wire-format subcode for this ledger error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InsufficientBalance { .. } => "ledger.insufficient_balance",
            Self::DestinationInvalid { .. } => "ledger.destination_invalid",
            Self::TrustlineMissing { .. } => "ledger.trustline_missing",
            Self::OpFailed { .. } => "ledger.op_failed",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Submission-error helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Redacts a transaction hash to first-8-last-8 for use in `Display` impls
/// and error messages.
///
/// Returns the full hash unchanged when it is 16 characters or shorter (only
/// for very short test values; real hashes are 64 hex characters).
fn redact_tx_hash_display(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}...{}", &hash[..8], &hash[hash.len() - 8..])
    } else {
        hash.to_owned()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Submission errors
// ──────────────────────────────────────────────────────────────────────────────

/// The reason a Soroban auth-entry fingerprint check failed.
///
/// Closed-set enum: the type is structurally incapable of carrying auth-entry
/// bytes, signature bytes, or account strkeys.  Every label is a public
/// diagnostic string with no secret content — the no-secret guarantee is
/// structural, not reviewer-trust.
///
/// Used by [`SubmissionError::AuthMismatch`] (network-crate / external-submit
/// paths) and `SaError::AuthMismatch` (smart-account submit path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthMismatchReason {
    /// The envelope carries a `OperationBody::InvokeHostFunction` with a
    /// different number of auth entries than the expected fingerprint.
    ///
    /// Produced when `actual_count != expected_count` in
    /// `verify_auth_entries_unchanged`; covers both "entry was added" and
    /// "entry was removed" cases (the ordered-compare model collapses both
    /// to this single count-mismatch discriminant rather than requiring a
    /// diff algorithm).
    EntryCountMismatch,
    /// The entry count matches but at least one entry's XDR digest differs
    /// from the expected fingerprint (covers: nonce change, invocation swap,
    /// signature substitution, credential-address swap, reorder).
    EntryMutated,
    /// The envelope is not a single-operation `InvokeHostFunction` transaction.
    ///
    /// C7 requires a single-op [`InvokeHostFunction`] (CAP-46 already restricts
    /// Soroban transactions to at most one `InvokeHostFunction`; this variant
    /// fires for multi-op envelopes, `TxFeeBump` envelopes, or envelopes whose
    /// sole operation is not `InvokeHostFunction`).
    ///
    /// [`InvokeHostFunction`]: stellar_xdr::OperationBody::InvokeHostFunction
    NotSingleInvokeHostFunction,
}

impl AuthMismatchReason {
    /// Returns the stable public label for this reason.
    ///
    /// The label is a fixed, secret-free string suitable for use in wire codes,
    /// audit-log fields, and operator-facing diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::error::AuthMismatchReason;
    /// assert_eq!(AuthMismatchReason::EntryMutated.label(), "entry_mutated");
    /// ```
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::EntryCountMismatch => "entry_count_mismatch",
            Self::EntryMutated => "entry_mutated",
            Self::NotSingleInvokeHostFunction => "not_single_invoke_host_function",
        }
    }
}

impl std::fmt::Display for AuthMismatchReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Errors arising from transaction submission to the Stellar network.
///
/// # Secret-material policy
///
/// No field carries secret material.  `hash` fields hold transaction hash
/// strings (public identifiers).  `detail` fields hold non-secret diagnostic
/// strings.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SubmissionError {
    /// The transaction's sequence number is no longer current; the account's
    /// ledger sequence has advanced since the transaction was built.
    #[error(
        "the transaction sequence number is stale; rebuild the transaction with the current sequence"
    )]
    SequenceNumberStale,

    /// The transaction envelope is malformed and was rejected by the network.
    ///
    /// `detail` holds a non-secret diagnostic string (e.g. `"invalid
    /// source account"`, `"fee exceeds u32::MAX"`).
    #[error("the transaction is malformed: {detail}")]
    TxMalformed {
        /// A non-secret diagnostic string describing why the transaction is malformed.
        detail: String,
    },

    /// The transaction was already submitted (duplicate hash).
    ///
    /// `hash` holds the transaction hash as a hex string. Display output
    /// redacts to first-8-last-8; the field itself stores the full hash for
    /// callers that need it.
    #[error(
        "transaction '{redacted}' was already submitted",
        redacted = redact_tx_hash_display(hash)
    )]
    TxAlreadySubmitted {
        /// The hex-encoded transaction hash (public identifier). The variant's Display
        /// impl redacts this to first-8-last-8 automatically; callers reading the field
        /// directly must apply redaction before logging.
        hash: String,
    },

    /// The transaction was not included in a ledger within the allowed time.
    ///
    /// `tx_hash` holds the hex-encoded transaction hash (public identifier).
    /// Display output redacts to first-8-last-8.
    /// `seconds` holds the submission timeout in seconds.
    #[error(
        "transaction '{redacted}' was not confirmed within {seconds}s",
        redacted = redact_tx_hash_display(tx_hash)
    )]
    TxTimeout {
        /// The hex-encoded transaction hash (public identifier). The variant's Display
        /// impl redacts this to first-8-last-8 automatically; callers reading the field
        /// directly must apply redaction before logging.
        tx_hash: String,
        /// The submission timeout in seconds.
        seconds: u64,
    },

    /// The fee-bump transaction was accepted by the network, but the inner
    /// transaction was rejected.
    ///
    /// Returned when `TransactionResultResult::TxFeeBumpInnerFailed` is
    /// observed in the on-chain result.  The fee-payer's fee was consumed;
    /// the inner transaction did not apply.
    ///
    /// # Field semantics
    ///
    /// - `inner_result_code` — the public enum NAME of the
    ///   `InnerTransactionResultResult` variant (e.g. `"TxBadSeq"`,
    ///   `"TxBadAuth"`).  This is the variant discriminant label only — no
    ///   secret operation-result fields are included.
    /// - `inner_tx_hash_redacted` — the inner transaction hash rendered
    ///   first-8-last-8 for operator diagnostics.
    ///
    /// # Wire code
    ///
    /// `submission.feebump_inner_rejected`
    ///
    /// # Secret-material policy
    ///
    /// Neither field carries secret material.  `inner_result_code` is a
    /// public enum name.  `inner_tx_hash_redacted` is a pre-redacted
    /// public transaction identifier (first-8-last-8).
    ///
    /// Fail-closed typed error surface for fee-bump result checking.
    #[error(
        "fee-bump inner transaction rejected (code={inner_result_code}, inner_hash={inner_tx_hash_redacted})"
    )]
    FeeBumpInnerRejected {
        /// The `InnerTransactionResultResult` variant name (e.g. `"TxBadSeq"`).
        ///
        /// This is a public enum discriminant label only; no secret operation
        /// results or account data are included.
        inner_result_code: String,
        /// The inner transaction hash redacted to first-8-last-8.
        ///
        /// The pre-redacted form is suitable for direct operator-facing output
        /// without additional redaction at the caller.
        inner_tx_hash_redacted: String,
    },

    /// A Soroban auth-entry fingerprint check failed before submission.
    ///
    /// Produced by `stellar_agent_network::simulation_audit::verify_auth_entries_unchanged`
    /// when the set of `SorobanAuthorizationEntry` items in the about-to-be-submitted
    /// envelope differs from the set captured at sign time.
    ///
    /// # Field semantics
    ///
    /// `reason` is an [`AuthMismatchReason`] closed-set enum — structurally
    /// incapable of carrying auth-entry bytes or signatures.  The only
    /// information surfaced is the diagnostic class of the mismatch.
    ///
    /// # Wire code
    ///
    /// `submission.auth_mismatch`
    ///
    /// # Secret-material policy
    ///
    /// This variant carries NO secret material.  `reason` is a public enum
    /// discriminant with a fixed label string (see [`AuthMismatchReason::label`]).
    /// No entry bytes, no signature bytes, no strkeys are included.
    ///
    #[error("auth-entry fingerprint mismatch before submission: reason={reason}")]
    AuthMismatch {
        /// The closed-set reason for the mismatch.
        ///
        /// Carries no secret material — see [`AuthMismatchReason`] type docs.
        reason: AuthMismatchReason,
    },

    /// A transaction that previously failed on-chain, surfaced again from a
    /// durable submission receipt.
    ///
    /// This is a deterministic, non-retryable outcome: the transaction reached
    /// the ledger and was rejected. It is categorised under
    /// [`ErrorCategory::Submission`] — never [`ErrorCategory::Network`] — so a
    /// cached replay is not mistaken for a transient connectivity failure.
    ///
    /// # Field semantics
    ///
    /// `code` carries the original wire `code()` of the failure as recorded at
    /// submission time (for example `ledger.insufficient_balance`), preserved
    /// for diagnostics. It is a non-secret stable error code.
    #[error("transaction previously failed on-chain (code={code})")]
    OnChainFailed {
        /// The original wire error code recorded when the transaction failed.
        code: String,
    },
}

impl SubmissionError {
    /// Returns the stable wire-format subcode for this submission error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SequenceNumberStale => "submission.sequence_number_stale",
            Self::TxMalformed { .. } => "submission.tx_malformed",
            Self::TxAlreadySubmitted { .. } => "submission.tx_already_submitted",
            Self::TxTimeout { .. } => "submission.tx_timeout",
            Self::FeeBumpInnerRejected { .. } => "submission.feebump_inner_rejected",
            Self::AuthMismatch { .. } => "submission.auth_mismatch",
            Self::OnChainFailed { .. } => "submission.on_chain_failed",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors representing internal invariant violations.
///
/// If a caller encounters one of these, it indicates a bug in this library.
/// Please file an issue with the full error message.
///
/// # Secret-material policy
///
/// `detail` fields hold non-secret diagnostic strings.  Callers must not
/// construct these variants with secret material in the detail string.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InternalError {
    /// An internal invariant was violated.
    ///
    /// `detail` holds a non-secret description of the violated invariant.
    /// If you see this, it is a bug.
    #[error("internal invariant violated: {detail}")]
    InvariantViolated {
        /// A non-secret description of the violated invariant.
        detail: String,
    },

    /// The system reached a state that should be unreachable by design.
    ///
    /// `detail` holds a non-secret description of the unexpected state.
    #[error("unexpected internal state: {detail}")]
    UnexpectedState {
        /// A non-secret description of the unexpected state.
        detail: String,
    },

    /// Serialisation of an envelope or other typed output via `serde_json`
    /// failed.
    ///
    /// Preserves the underlying [`serde_json::Error`] via the error source
    /// chain so callers walking [`std::error::Error::source`] can recover the
    /// typed cause.
    ///
    /// Wire code: `internal.serialisation_failed`.
    #[error("JSON serialisation failed")]
    SerialisationFailed {
        /// The underlying JSON serialisation error. Accessible via
        /// [`std::error::Error::source`].
        #[from]
        source: serde_json::Error,
    },
}

impl InternalError {
    /// Returns the stable wire-format subcode for this internal error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvariantViolated { .. } => "internal.invariant_violated",
            Self::UnexpectedState { .. } => "internal.unexpected_state",
            Self::SerialisationFailed { .. } => "internal.serialisation_failed",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_agent_test_support::assert_no_secret_bytes;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Asserts that a rendered message does not contain any of the
    /// compile-time secret-marker strings that must never appear in user-facing
    /// error output.
    fn assert_no_compile_time_secret_markers(msg: &str) {
        assert!(
            !msg.contains("expose_secret"),
            "message contains 'expose_secret': {msg}"
        );
        assert!(
            !msg.contains("SecretBox"),
            "message contains 'SecretBox': {msg}"
        );
    }

    fn serde_json_error_fixture() -> serde_json::Error {
        serde_json::Error::io(std::io::Error::other("fixture JSON error"))
    }

    macro_rules! assert_code_round_trips {
        ($cases:expr) => {
            for (variant, expected_code) in $cases {
                let code = variant.code();
                assert_eq!(code, *expected_code, "code mismatch for {variant:?}");
            }
        };
    }

    // ── Validation errors ────────────────────────────────────────────────────

    /// Exhaustive code round-trip for every ValidationError variant.
    ///
    /// If a new variant is added without updating this test, the missing
    /// arm in the `match` below will cause a compile-time error.
    #[test]
    #[allow(
        clippy::panic,
        reason = "test-only panic in an unreachable match arm; documented in the arm body"
    )]
    fn validation_code_round_trip() {
        // Construct every variant; ensure the match is exhaustive.
        let cases: &[(ValidationError, &'static str)] = &[
            (
                ValidationError::AmountUnitsRequired,
                "validation.amount_units_required",
            ),
            (
                ValidationError::AmountPrecisionExceeded {
                    amount: "1.12345678".to_owned(),
                },
                "validation.amount_precision_exceeded",
            ),
            (
                ValidationError::MemoRequired {
                    destination: "GABCDE".to_owned(),
                },
                "validation.memo_required",
            ),
            (
                ValidationError::MemoInvalidType {
                    memo_type: "MEMO_HASH".to_owned(),
                },
                "validation.memo_invalid_type",
            ),
            (
                ValidationError::AddressInvalid {
                    input: "GABC".to_owned(),
                },
                "validation.address_invalid",
            ),
            (
                ValidationError::AssetInvalid {
                    input: "USDC:bad".to_owned(),
                },
                "validation.asset_invalid",
            ),
            (
                ValidationError::ProfileNotFound {
                    name: "default".to_owned(),
                },
                "validation.profile_not_found",
            ),
            (
                ValidationError::AmountMalformed {
                    input: "abc XLM".to_owned(),
                },
                "validation.amount_malformed",
            ),
            (
                ValidationError::AmountOutOfRange {
                    amount: "99999999999999999999".to_owned(),
                },
                "validation.amount_out_of_range",
            ),
            (
                ValidationError::OutputFormatInvalid {
                    input: "xml".to_owned(),
                },
                "validation.output_format_invalid",
            ),
            (
                ValidationError::MemoMutuallyExclusive,
                "validation.memo_mutually_exclusive",
            ),
            (
                ValidationError::InvalidPluginName {
                    reason: "empty".to_owned(),
                },
                "validation.invalid_plugin_name",
            ),
            (
                ValidationError::PasskeyOnlyRuleNoDelegatedFallback {
                    credential_count: 1,
                },
                "validation.passkey_only_rule_no_delegated_fallback",
            ),
            (
                ValidationError::ContextRuleCapsExceeded {
                    kind: CapKind::Signer,
                    attempted: 16,
                    max: 15,
                },
                "validation.context_rule_caps_exceeded",
            ),
            (
                ValidationError::XdrArgumentMalformed {
                    arg: "install-param".to_owned(),
                    reason: "base64 decode failed".to_owned(),
                },
                "validation.xdr_argument_malformed",
            ),
            (
                ValidationError::SessionRuleHorizonExceeded {
                    rule_id_or_pending: None,
                    requested_horizon: 2000,
                    max_horizon: 1000,
                },
                "validation.session_rule_horizon_exceeded",
            ),
            (
                ValidationError::SessionRuleHorizonExceeded {
                    rule_id_or_pending: Some(7),
                    requested_horizon: 2000,
                    max_horizon: 1000,
                },
                "validation.session_rule_horizon_exceeded",
            ),
            (ValidationError::BundleEmpty, "validation.bundle_empty"),
            (
                ValidationError::BundleTooLarge { got: 51, max: 50 },
                "validation.bundle_too_large",
            ),
            (
                ValidationError::UnsupportedFeeMode {
                    mode: "auto".to_owned(),
                    reason: "pass an explicit stroops value".to_owned(),
                },
                "validation.unsupported_fee_mode",
            ),
            (
                ValidationError::RelayerNotImplemented,
                "validation.relayer_not_implemented",
            ),
            (
                ValidationError::ValidUntilInvalid {
                    input: "foo".to_owned(),
                },
                "validation.valid_until_invalid",
            ),
            (
                ValidationError::ConfigInvalid {
                    component: "ContextRuleManager",
                    reason: "invalid RPC URL".to_owned(),
                },
                "validation.config_invalid",
            ),
            (
                ValidationError::RuleNameTooLong {
                    name_len: 22,
                    max: 20,
                },
                "validation.rule_name_too_long",
            ),
            (
                ValidationError::AuditLogNotFound {
                    path: "/tmp/audit.jsonl".to_owned(),
                },
                "audit.log_not_found",
            ),
        ];

        for (variant, expected_code) in cases {
            let wallet_err = WalletError::Validation(match variant {
                ValidationError::AmountUnitsRequired => ValidationError::AmountUnitsRequired,
                ValidationError::AmountPrecisionExceeded { amount } => {
                    ValidationError::AmountPrecisionExceeded {
                        amount: amount.clone(),
                    }
                }
                ValidationError::MemoRequired { destination } => ValidationError::MemoRequired {
                    destination: destination.clone(),
                },
                ValidationError::MemoInvalidType { memo_type } => {
                    ValidationError::MemoInvalidType {
                        memo_type: memo_type.clone(),
                    }
                }
                ValidationError::AddressInvalid { input } => ValidationError::AddressInvalid {
                    input: input.clone(),
                },
                ValidationError::AssetInvalid { input } => ValidationError::AssetInvalid {
                    input: input.clone(),
                },
                ValidationError::ProfileNotFound { name } => {
                    ValidationError::ProfileNotFound { name: name.clone() }
                }
                ValidationError::AmountMalformed { input } => ValidationError::AmountMalformed {
                    input: input.clone(),
                },
                ValidationError::AmountOutOfRange { amount } => ValidationError::AmountOutOfRange {
                    amount: amount.clone(),
                },
                ValidationError::OutputFormatInvalid { input } => {
                    ValidationError::OutputFormatInvalid {
                        input: input.clone(),
                    }
                }
                ValidationError::MemoMutuallyExclusive => ValidationError::MemoMutuallyExclusive,
                ValidationError::InvalidPluginName { reason } => {
                    ValidationError::InvalidPluginName {
                        reason: reason.clone(),
                    }
                }
                ValidationError::PasskeyOnlyRuleNoDelegatedFallback { credential_count } => {
                    ValidationError::PasskeyOnlyRuleNoDelegatedFallback {
                        credential_count: *credential_count,
                    }
                }
                ValidationError::ContextRuleCapsExceeded {
                    kind,
                    attempted,
                    max,
                } => ValidationError::ContextRuleCapsExceeded {
                    kind: *kind,
                    attempted: *attempted,
                    max: *max,
                },
                ValidationError::XdrArgumentMalformed { arg, reason } => {
                    ValidationError::XdrArgumentMalformed {
                        arg: arg.clone(),
                        reason: reason.clone(),
                    }
                }
                ValidationError::SessionRuleHorizonExceeded {
                    rule_id_or_pending,
                    requested_horizon,
                    max_horizon,
                } => ValidationError::SessionRuleHorizonExceeded {
                    rule_id_or_pending: *rule_id_or_pending,
                    requested_horizon: *requested_horizon,
                    max_horizon: *max_horizon,
                },
                ValidationError::BundleEmpty => ValidationError::BundleEmpty,
                ValidationError::BundleTooLarge { got, max } => ValidationError::BundleTooLarge {
                    got: *got,
                    max: *max,
                },
                ValidationError::UnsupportedFeeMode { mode, reason } => {
                    ValidationError::UnsupportedFeeMode {
                        mode: mode.clone(),
                        reason: reason.clone(),
                    }
                }
                ValidationError::RelayerNotImplemented => ValidationError::RelayerNotImplemented,
                ValidationError::ValidUntilInvalid { input } => {
                    ValidationError::ValidUntilInvalid {
                        input: input.clone(),
                    }
                }
                ValidationError::ConfigInvalid { component, reason } => {
                    ValidationError::ConfigInvalid {
                        component,
                        reason: reason.clone(),
                    }
                }
                ValidationError::RuleNameTooLong { name_len, max } => {
                    ValidationError::RuleNameTooLong {
                        name_len: *name_len,
                        max: *max,
                    }
                }
                ValidationError::AuditLogNotFound { path } => {
                    ValidationError::AuditLogNotFound { path: path.clone() }
                }
            });
            assert_eq!(
                wallet_err.code(),
                *expected_code,
                "code mismatch for variant {:?}",
                wallet_err
            );
            assert_eq!(wallet_err.category(), ErrorCategory::Validation);
        }
    }

    // ── Network errors ───────────────────────────────────────────────────────

    #[test]
    fn network_code_round_trip() {
        let cases: &[(NetworkError, &'static str)] = &[
            (
                NetworkError::RpcTimeout {
                    url: "https://rpc.example.com".to_owned(),
                    timeout_secs: 30,
                },
                "network.rpc_timeout",
            ),
            (
                NetworkError::RpcUnreachable {
                    url: "https://rpc.example.com".to_owned(),
                    reason: "connection refused".to_owned(),
                },
                "network.rpc_unreachable",
            ),
            (
                NetworkError::FriendbotMainnetForbidden,
                "network.friendbot_mainnet_forbidden",
            ),
            (
                NetworkError::AccountNotFound {
                    account_id: "GABCDE".to_owned(),
                },
                "network.account_not_found",
            ),
            (
                NetworkError::MainnetWriteForbidden,
                "network.mainnet_write_forbidden",
            ),
            (
                NetworkError::HorizonUnavailable { status: 503 },
                "network.horizon_unavailable",
            ),
        ];

        assert_code_round_trips!(cases);

        // Category consistency check is independent of the loop body; a
        // single wrapper instance suffices to prove `WalletError::Network`
        // reports `ErrorCategory::Network`.
        let wallet_err = WalletError::Network(NetworkError::FriendbotMainnetForbidden);
        assert_eq!(wallet_err.category(), ErrorCategory::Network);
    }

    // ── Auth errors ──────────────────────────────────────────────────────────

    #[test]
    fn auth_code_round_trip() {
        let cases: &[(AuthError, &'static str)] = &[
            (AuthError::KeyringLocked, "auth.keyring_locked"),
            (
                AuthError::KeyringPlatformError,
                "auth.keyring_platform_error",
            ),
            (
                AuthError::KeyringNotFound {
                    name: "main".to_owned(),
                },
                "auth.keyring_not_found",
            ),
            (AuthError::HardwareUserRefused, "auth.hardware_user_refused"),
            (
                AuthError::SignerKeyMismatch {
                    expected: "GABC".to_owned(),
                    got: "GDEF".to_owned(),
                },
                "auth.signer_key_mismatch",
            ),
            (
                AuthError::SignerKindMismatch {
                    signer_kind: "software",
                    requested_primitive: "sign_webauthn_assertion",
                },
                "auth.signer_kind_mismatch",
            ),
        ];

        assert_code_round_trips!(cases);

        let wallet_err = WalletError::Auth(AuthError::KeyringLocked);
        assert_eq!(wallet_err.category(), ErrorCategory::Auth);
    }

    /// Round-trip coverage for `SubmissionError::TxTimeout` and related variants.
    #[test]
    fn new_issue_61_variants_round_trip() {
        // SubmissionError::TxTimeout carries both tx_hash and seconds.
        let e = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: "aabb1122ccddeeff".to_owned(),
            seconds: 60,
        });
        assert_eq!(e.code(), "submission.tx_timeout");
        // short hash (≤16 chars) is not redacted.
        assert!(e.message().contains("aabb1122ccddeeff"));

        // AuthError::SignerKeyMismatch
        let e = WalletError::Auth(AuthError::SignerKeyMismatch {
            expected: "GABC123".to_owned(),
            got: "GDEF456".to_owned(),
        });
        assert_eq!(e.code(), "auth.signer_key_mismatch");
        assert!(e.message().contains("GABC123"));
        assert!(e.message().contains("GDEF456"));

        // NetworkError::MainnetWriteForbidden (already existed, verify code unchanged)
        let e = WalletError::Network(NetworkError::MainnetWriteForbidden);
        assert_eq!(e.code(), "network.mainnet_write_forbidden");
    }

    // ── WalletState errors ───────────────────────────────────────────────────

    #[test]
    fn wallet_state_code_round_trip() {
        let cases: &[(WalletStateError, &'static str)] = &[
            (
                WalletStateError::HardwareNotFound,
                "wallet_state.hardware_not_found",
            ),
            (
                WalletStateError::HardwareTimeout,
                "wallet_state.hardware_timeout",
            ),
            (
                WalletStateError::HardwareWrongApp {
                    expected: "Stellar".to_owned(),
                    got: "Ethereum".to_owned(),
                },
                "wallet_state.hardware_wrong_app",
            ),
            (
                WalletStateError::HardwareBlindSigningDisabled,
                "wallet_state.hardware_blind_signing_disabled",
            ),
            (
                WalletStateError::KeyringCorrupted {
                    detail: "checksum mismatch".to_owned(),
                },
                "wallet_state.keyring_corrupted",
            ),
        ];

        assert_code_round_trips!(cases);

        let wallet_err = WalletError::WalletState(WalletStateError::HardwareNotFound);
        assert_eq!(wallet_err.category(), ErrorCategory::WalletState);
    }

    // ── Protocol errors ──────────────────────────────────────────────────────

    #[test]
    fn protocol_code_round_trip() {
        let cases: &[(ProtocolError, &'static str)] = &[(
            ProtocolError::XdrCodecFailed {
                detail: "unexpected discriminant".to_owned(),
            },
            "protocol.xdr_codec_failed",
        )];

        assert_code_round_trips!(cases);

        let wallet_err = WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: "unexpected discriminant".to_owned(),
        });
        assert_eq!(wallet_err.category(), ErrorCategory::Protocol);
    }

    // ── Ledger errors ────────────────────────────────────────────────────────

    #[test]
    fn ledger_code_round_trip() {
        let cases: &[(LedgerError, &'static str)] = &[
            (
                LedgerError::InsufficientBalance {
                    asset: "XLM".to_owned(),
                    have: "1.0".to_owned(),
                    need: "5.0".to_owned(),
                },
                "ledger.insufficient_balance",
            ),
            (
                LedgerError::DestinationInvalid {
                    destination: "GABCDE".to_owned(),
                },
                "ledger.destination_invalid",
            ),
            (
                LedgerError::TrustlineMissing {
                    asset: "USDC:GA...".to_owned(),
                    account: "GABCDE".to_owned(),
                },
                "ledger.trustline_missing",
            ),
            (
                LedgerError::OpFailed {
                    op: "Payment".to_owned(),
                    result_code: "op_no_trust".to_owned(),
                },
                "ledger.op_failed",
            ),
        ];

        assert_code_round_trips!(cases);

        let wallet_err = WalletError::Ledger(LedgerError::InsufficientBalance {
            asset: "XLM".to_owned(),
            have: "1.0".to_owned(),
            need: "5.0".to_owned(),
        });
        assert_eq!(wallet_err.category(), ErrorCategory::Ledger);
    }

    // ── Submission errors ────────────────────────────────────────────────────

    #[test]
    fn submission_code_round_trip() {
        // SubmissionError::TxTimeout carries both tx_hash and seconds.
        let full_hash =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned();
        let cases: Vec<(SubmissionError, &'static str)> = vec![
            (
                SubmissionError::SequenceNumberStale,
                "submission.sequence_number_stale",
            ),
            (
                SubmissionError::TxMalformed {
                    detail: "invalid source account".to_owned(),
                },
                "submission.tx_malformed",
            ),
            (
                SubmissionError::TxAlreadySubmitted {
                    hash: "deadbeef".to_owned(),
                },
                "submission.tx_already_submitted",
            ),
            (
                SubmissionError::TxTimeout {
                    tx_hash: full_hash.clone(),
                    seconds: 30,
                },
                "submission.tx_timeout",
            ),
            (
                SubmissionError::FeeBumpInnerRejected {
                    inner_result_code: "TxBadAuth".to_owned(),
                    inner_tx_hash_redacted: "abcd1234...efgh5678".to_owned(),
                },
                "submission.feebump_inner_rejected",
            ),
            (
                SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryMutated,
                },
                "submission.auth_mismatch",
            ),
            (
                SubmissionError::OnChainFailed {
                    code: "ledger.insufficient_balance".to_owned(),
                },
                "submission.on_chain_failed",
            ),
        ];

        assert_code_round_trips!(&cases);

        let wallet_err = WalletError::Submission(SubmissionError::SequenceNumberStale);
        assert_eq!(wallet_err.category(), ErrorCategory::Submission);

        // A cached on-chain failure is categorised as Submission (non-network),
        // never Network, and preserves the original wire code in its field.
        let on_chain = WalletError::Submission(SubmissionError::OnChainFailed {
            code: "ledger.insufficient_balance".to_owned(),
        });
        assert_eq!(on_chain.category(), ErrorCategory::Submission);
        assert_eq!(on_chain.code(), "submission.on_chain_failed");

        // TxTimeout Display redacts to first-8-last-8.
        let timeout_err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: full_hash.clone(),
            seconds: 60,
        });
        let msg = timeout_err.message();
        assert!(
            msg.contains("..."),
            "TxTimeout Display must redact the hash: {msg}"
        );
        assert!(msg.contains("abcdef01"), "must show first-8: {msg}");
        assert!(msg.contains("23456789"), "must show last-8: {msg}");
        assert!(!msg.contains(&full_hash), "must NOT show full hash: {msg}");

        // TxAlreadySubmitted Display redacts to first-8-last-8.
        let already_err = WalletError::Submission(SubmissionError::TxAlreadySubmitted {
            hash: full_hash.clone(),
        });
        let msg = already_err.message();
        assert!(
            msg.contains("..."),
            "TxAlreadySubmitted Display must redact the hash: {msg}"
        );
        assert!(msg.contains("abcdef01"), "must show first-8: {msg}");
        assert!(msg.contains("23456789"), "must show last-8: {msg}");
        assert!(!msg.contains(&full_hash), "must NOT show full hash: {msg}");
    }

    // ── Internal errors ──────────────────────────────────────────────────────

    #[test]
    fn internal_code_round_trip() {
        let cases: &[(InternalError, &'static str)] = &[
            (
                InternalError::InvariantViolated {
                    detail: "option was None".to_owned(),
                },
                "internal.invariant_violated",
            ),
            (
                InternalError::UnexpectedState {
                    detail: "state machine in terminal state".to_owned(),
                },
                "internal.unexpected_state",
            ),
            (
                InternalError::SerialisationFailed {
                    source: serde_json_error_fixture(),
                },
                "internal.serialisation_failed",
            ),
        ];

        assert_code_round_trips!(cases);

        let wallet_err = WalletError::Internal(InternalError::InvariantViolated {
            detail: "test".to_owned(),
        });
        assert_eq!(wallet_err.category(), ErrorCategory::Internal);
    }

    // ── WalletError::SmartAccount variant ────────────────────────────────────

    /// `WalletError::SmartAccount` must emit its `wire_code` as the envelope
    /// `error.code` field.
    #[test]
    #[allow(clippy::expect_used, reason = "test-only")]
    fn wallet_error_smart_account_envelope_emits_sa_wire_code() {
        use crate::envelope::Envelope;

        let err = WalletError::SmartAccount {
            wire_code: "sa.deployment_failed",
            message: "build phase: address derivation failed".to_owned(),
        };
        let envelope = Envelope::<()>::err(&err);
        let json = serde_json::to_string(&envelope).expect("Envelope serialises to JSON");
        assert!(
            json.contains("\"code\":\"sa.deployment_failed\""),
            "envelope JSON must contain sa.deployment_failed wire code; got: {json}"
        );
        assert!(
            !json.contains("validation.address_invalid"),
            "envelope must NOT contain old validation code; got: {json}"
        );
        assert!(!envelope.ok);
    }

    /// `WalletError::SmartAccount` code round-trip.
    #[test]
    fn smart_account_code_round_trip() {
        let cases: &[(&'static str, &'static str)] = &[
            ("sa.ok", "sa.ok"),
            ("sa.deployment_failed", "sa.deployment_failed"),
        ];
        for (wire_code, expected_code) in cases {
            let err = WalletError::SmartAccount {
                wire_code,
                message: "test message".to_owned(),
            };
            assert_eq!(
                err.code(),
                *expected_code,
                "code() must return the wire_code for SmartAccount variant"
            );
        }
    }

    /// `WalletError::SmartAccount` Display must not produce S-strkey-shaped or
    /// raw-signature-shaped output from non-secret inputs.
    ///
    /// The `message` field is expected to carry a pre-redacted reason; this test
    /// verifies that the Display implementation does not itself GENERATE secret-adjacent
    /// material (e.g. by formatting wire_code or fixed strings into a 56-char ALL-CAPS run).
    ///
    /// The test uses ordinary diagnostic strings as input — it does NOT attempt to pass
    /// raw S-strkeys as `message` (that would be a caller-discipline violation; redaction
    /// is enforced at the construction site, not the Display impl).
    #[test]
    fn display_no_secret_markers_smart_account() {
        let payloads: &[&str] = &[
            "non-secret diagnostic: build phase",
            "rpc call failed at simulate: connection refused",
            "WASM hash mismatch: observed 06186e93, expected 5603378c",
            &"a".repeat(64), // 64-char hex run (acceptable in message; must not be amplified)
        ];
        for p in payloads {
            let err = WalletError::SmartAccount {
                wire_code: "sa.deployment_failed",
                message: (*p).to_owned(),
            };
            let display = err.to_string();
            // Assert no 56-char ALL-CAPS run in the Display OUTPUT.
            // The Display impl formats the struct fields; if it were to accidentally
            // construct such a run from wire_code + message concatenation that would
            // be a regression this test would catch.
            let has_sstrkey_shape = display.split_whitespace().any(|word| {
                word.len() == 56
                    && word
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            });
            assert!(
                !has_sstrkey_shape,
                "WalletError::SmartAccount Display must not produce an S-strkey-shaped run \
                 (payload={p:?}): {display}"
            );
        }
    }

    // ── Display does not contain secret markers ───────────────────────────────

    /// For every variant that carries a String field, assert the rendered
    /// Display does not contain secret-marker strings or an S-strkey shaped
    /// value (all-uppercase 56-char run).
    #[test]
    fn display_no_secret_markers_validation() {
        let cases = [
            WalletError::Validation(ValidationError::AmountUnitsRequired),
            WalletError::Validation(ValidationError::AmountPrecisionExceeded {
                amount: "1.12345678".to_owned(),
            }),
            WalletError::Validation(ValidationError::MemoRequired {
                destination: "GABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567890123456".to_owned(),
            }),
            WalletError::Validation(ValidationError::MemoInvalidType {
                memo_type: "MEMO_HASH".to_owned(),
            }),
            WalletError::Validation(ValidationError::AddressInvalid {
                input: "GABC".to_owned(),
            }),
            WalletError::Validation(ValidationError::AssetInvalid {
                input: "BAD:ASSET".to_owned(),
            }),
            WalletError::Validation(ValidationError::ProfileNotFound {
                name: "my-profile".to_owned(),
            }),
            WalletError::Validation(ValidationError::InvalidPluginName {
                reason: "invalid character".to_owned(),
            }),
            WalletError::Validation(ValidationError::MemoMutuallyExclusive),
            WalletError::Validation(ValidationError::BundleTooLarge { got: 51, max: 50 }),
            WalletError::Validation(ValidationError::UnsupportedFeeMode {
                mode: "auto".to_owned(),
                reason: "pass an explicit stroops value".to_owned(),
            }),
            WalletError::Validation(ValidationError::RelayerNotImplemented),
        ];
        for err in &cases {
            let msg = err.message();
            assert_no_compile_time_secret_markers(&msg);
            assert_no_secret_bytes(msg.as_bytes());
        }
    }

    #[test]
    fn display_no_secret_markers_network() {
        let cases = [
            WalletError::Network(NetworkError::RpcTimeout {
                url: "https://rpc.example.com".to_owned(),
                timeout_secs: 30,
            }),
            WalletError::Network(NetworkError::RpcUnreachable {
                url: "https://rpc.example.com".to_owned(),
                reason: "connection refused".to_owned(),
            }),
            WalletError::Network(NetworkError::FriendbotMainnetForbidden),
            WalletError::Network(NetworkError::AccountNotFound {
                account_id: "GABCDEFGHIJKLMNOPQR".to_owned(),
            }),
            WalletError::Network(NetworkError::MainnetWriteForbidden),
            WalletError::Network(NetworkError::HorizonUnavailable { status: 503 }),
        ];
        for err in &cases {
            let msg = err.message();
            assert_no_compile_time_secret_markers(&msg);
            assert_no_secret_bytes(msg.as_bytes());
        }
    }

    #[test]
    fn display_no_secret_markers_remaining() {
        let full_hash =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned();
        let cases = [
            WalletError::Auth(AuthError::KeyringLocked),
            WalletError::Auth(AuthError::KeyringPlatformError),
            WalletError::Auth(AuthError::KeyringNotFound {
                name: "main".to_owned(),
            }),
            WalletError::Auth(AuthError::HardwareUserRefused),
            WalletError::Auth(AuthError::SignerKindMismatch {
                signer_kind: "software",
                requested_primitive: "sign_webauthn_assertion",
            }),
            WalletError::WalletState(WalletStateError::HardwareNotFound),
            WalletError::WalletState(WalletStateError::HardwareTimeout),
            WalletError::WalletState(WalletStateError::HardwareWrongApp {
                expected: "Stellar".to_owned(),
                got: "Ethereum".to_owned(),
            }),
            WalletError::WalletState(WalletStateError::KeyringCorrupted {
                detail: "bad checksum".to_owned(),
            }),
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: "bad bytes".to_owned(),
            }),
            WalletError::Ledger(LedgerError::InsufficientBalance {
                asset: "XLM".to_owned(),
                have: "1.0".to_owned(),
                need: "5.0".to_owned(),
            }),
            WalletError::Ledger(LedgerError::DestinationInvalid {
                destination: "GABCDE".to_owned(),
            }),
            WalletError::Ledger(LedgerError::TrustlineMissing {
                asset: "USDC".to_owned(),
                account: "GABCDE".to_owned(),
            }),
            WalletError::Ledger(LedgerError::OpFailed {
                op: "Payment".to_owned(),
                result_code: "op_no_trust".to_owned(),
            }),
            WalletError::Submission(SubmissionError::SequenceNumberStale),
            WalletError::Submission(SubmissionError::TxMalformed {
                detail: "bad".to_owned(),
            }),
            WalletError::Submission(SubmissionError::TxAlreadySubmitted {
                hash: full_hash.clone(),
            }),
            WalletError::Submission(SubmissionError::TxTimeout {
                tx_hash: "aabb1122ccddeeff".to_owned(),
                seconds: 30,
            }),
            WalletError::Submission(SubmissionError::FeeBumpInnerRejected {
                inner_result_code: "TxBadAuth".to_owned(),
                inner_tx_hash_redacted: "abcd1234...efgh5678".to_owned(),
            }),
            WalletError::Submission(SubmissionError::AuthMismatch {
                reason: AuthMismatchReason::EntryMutated,
            }),
            WalletError::Internal(InternalError::InvariantViolated {
                detail: "test".to_owned(),
            }),
            WalletError::Internal(InternalError::UnexpectedState {
                detail: "test".to_owned(),
            }),
            WalletError::Internal(InternalError::SerialisationFailed {
                source: serde_json_error_fixture(),
            }),
            WalletError::Io {
                source_kind: IoSource::AuditWriterSetup,
                message: "permission denied".into(),
            },
        ];
        for err in &cases {
            let msg = err.message();
            assert_no_compile_time_secret_markers(&msg);
            assert_no_secret_bytes(msg.as_bytes());
        }
    }

    // ── category() consistency ────────────────────────────────────────────────

    /// Every WalletError variant must return the category matching its wrapper.
    #[test]
    fn category_consistency() {
        let pairs: &[(WalletError, ErrorCategory)] = &[
            (
                WalletError::Validation(ValidationError::AmountUnitsRequired),
                ErrorCategory::Validation,
            ),
            (
                WalletError::Network(NetworkError::FriendbotMainnetForbidden),
                ErrorCategory::Network,
            ),
            (
                WalletError::Auth(AuthError::KeyringLocked),
                ErrorCategory::Auth,
            ),
            (
                WalletError::WalletState(WalletStateError::HardwareNotFound),
                ErrorCategory::WalletState,
            ),
            (
                WalletError::Protocol(ProtocolError::XdrCodecFailed {
                    detail: "bad bytes".to_owned(),
                }),
                ErrorCategory::Protocol,
            ),
            (
                WalletError::Ledger(LedgerError::InsufficientBalance {
                    asset: "XLM".to_owned(),
                    have: "1".to_owned(),
                    need: "2".to_owned(),
                }),
                ErrorCategory::Ledger,
            ),
            (
                WalletError::Submission(SubmissionError::SequenceNumberStale),
                ErrorCategory::Submission,
            ),
            (
                WalletError::Internal(InternalError::InvariantViolated {
                    detail: "x".to_owned(),
                }),
                ErrorCategory::Internal,
            ),
            (
                WalletError::Io {
                    source_kind: IoSource::MulticallRegistryLoad,
                    message: "permission denied".into(),
                },
                ErrorCategory::Io,
            ),
            (
                WalletError::SmartAccount {
                    wire_code: "sa.deployment_failed",
                    message: "test".to_owned(),
                },
                ErrorCategory::SmartAccount,
            ),
        ];
        for (err, expected_cat) in pairs {
            assert_eq!(err.category(), *expected_cat);
        }
    }

    #[test]
    fn io_code_round_trip_known_labels() {
        let cases = [
            IoSource::MulticallRegistryLoad,
            IoSource::MulticallRegistrySave,
            IoSource::AuditWriterSetup,
        ];

        for source in cases {
            // COMPILE-CHECK: this match intentionally enumerates the closed
            // set so a new IoSource variant forces this test to be updated.
            match source {
                IoSource::MulticallRegistryLoad
                | IoSource::MulticallRegistrySave
                | IoSource::AuditWriterSetup => (),
            }
            let err = WalletError::Io {
                source_kind: source,
                message: "permission denied".into(),
            };
            assert_eq!(err.code(), source.wire_code());
            assert_eq!(err.category(), ErrorCategory::Io);
            assert!(err.message().contains(source.label()));
        }
    }

    // ── message() delegates to Display ───────────────────────────────────────

    #[test]
    fn message_delegates_to_display() {
        let err = WalletError::Validation(ValidationError::MemoRequired {
            destination: "GABC".to_owned(),
        });
        assert_eq!(err.message(), err.to_string());
    }

    // ── Non-exhaustive note ───────────────────────────────────────────────────
    //
    // The #[non_exhaustive] attribute on every enum prevents external callers
    // from constructing struct-literal variants or writing exhaustive match
    // arms without a wildcard.  This is verified by the type system at
    // compile time.  A compile-fail doctest is the most direct demonstration,
    // but doctests that are expected to fail require `compile_fail` which is
    // already exercised by the thiserror macro tests.
    //
    // The key contract: adding a new variant is not a breaking change for
    // callers that use `_ => ...` fallbacks.
}

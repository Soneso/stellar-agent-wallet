//! Audit-log entry schema, canonical-JSON serialisation, and redaction helpers.
//!
//! Defines [`AuditEntry`] — one JSON line in the hash-chained audit log file
//! — and the helpers for serialising it in the canonical form used for
//! hash-chain computation.
//!
//! # Canonical JSON
//!
//! The hash chain is computed over
//! `SHA-256(canonical_json(entry without previous_entry_hash) || previous_entry_hash)`.
//! "Canonical JSON" here means the entry serialised with fields in a fixed
//! insertion order using `serde_json::to_vec` (struct field order is
//! declaration order in Rust, which is stable).  The `previous_entry_hash`
//! field is excluded from the hash-input body.
//!
//! # Canonical-form contract
//!
//! Fields appear in struct-declaration order; strings are passed through as-is
//! (no Unicode normalisation enforced — operators MUST NOT use mixed-form
//! Unicode in tool/chain_id/decision_reason fields); numbers are JSON integers
//! only; no NaN/Infinity allowed (serde_json would reject them at serialisation
//! time).
//!
//! The `previous_entry_hash` field is set to `""` (empty string) in the
//! hash-input body so the hash does not depend on itself.  An empty string is
//! the canonical sentinel; JSON `null` is NOT used.
//!
//! # First-entry-per-file rule
//!
//! - The very first file's first entry uses
//!   `previous_entry_hash = SHA-256([0u8; 32])` (the
//!   [`chain::ZERO_BLOCK_HASH`](super::chain::ZERO_BLOCK_HASH)).
//! - Subsequent files' first entries chain via the rotation handoff entry's
//!   hash — NOT the zero-block hash.  The zero-block hash is only used for
//!   the very first file in the chain.
//!
//! # Redaction discipline
//!
//! - Argument VALUES are never logged at any level; only key names in
//!   `arg_keys`.
//! - Public/account-like strkeys (`G...` / `C...` / `T...` / `M...` / `P...`) in
//!   `decision_reason`: first-5-last-5 redaction.
//! - Tx-hashes in `decision_reason`: first-8-last-8 redaction.
//! - `envelope_hash` is included unredacted (SHA-256 digest; no user data).

use serde::{Deserialize, Serialize};

use super::schema::{ContractKind, EventKind, PolicyDecision, VerifierAdvisoryKind};
use crate::error::ValidationError;
use crate::observability::RedactedStrkey;
use crate::redact_first5_last5;
use crate::timefmt::current_iso8601_utc;

// ── Size limits ───────────────────────────────────────────────────────────────

/// Maximum serialised byte length of a single audit entry.
///
/// Entries exceeding this limit have their `arg_keys` list truncated to the
/// number of keys that fit, with an `arg_keys_truncated` count appended.
pub const MAX_ENTRY_BYTES: usize = 4096;

/// Maximum number of arg-key strings stored without truncation.
///
/// A guard to prevent extreme key-count blowup even before byte limits are
/// reached.  If `arg_keys.len() > MAX_ARG_KEYS`, excess keys are dropped and
/// `arg_keys_truncated` is set accordingly.
pub const MAX_ARG_KEYS: usize = 64;

/// Intentionally-lax RFC 3339 timestamp prefix check, used inside
/// `debug_assert!` only (release builds compile this away).
///
/// Verifies the `YYYY-MM-DDTHH:MM:SS` prefix plus a terminator that is either
/// `Z` or an ASCII digit (covers `Z`, fractional seconds, `+HH:MM` offsets,
/// `-HH:MM` offsets — the latter two only by their leading digit). Does NOT
/// verify timezone-offset bounds, day-of-month bounds, leap seconds, or the
/// full byte set after position 20. The strict check is intentionally
/// avoided here so we don't pull in `chrono` solely for a debug-time
/// sanity gate.
fn looks_like_rfc3339_timestamp(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && matches!(bytes.last(), Some(b'Z') | Some(b'0'..=b'9'))
}

// ── AuditEntry ────────────────────────────────────────────────────────────────

/// Converts constructor inputs into the optional audit `chain_id` wire field.
///
/// Public constructors accept this trait so callers can pass existing string
/// inputs for chain-scoped events while internal events can pass `None` without
/// serialising an empty-string sentinel.
pub trait IntoOptionalChainId {
    /// Convert into the optional CAIP-2 chain identifier.
    fn into_optional_chain_id(self) -> Option<String>;
}

impl IntoOptionalChainId for String {
    fn into_optional_chain_id(self) -> Option<String> {
        Some(self)
    }
}

impl IntoOptionalChainId for &str {
    fn into_optional_chain_id(self) -> Option<String> {
        Some(self.to_owned())
    }
}

impl IntoOptionalChainId for &String {
    fn into_optional_chain_id(self) -> Option<String> {
        Some(self.clone())
    }
}

impl IntoOptionalChainId for Option<String> {
    fn into_optional_chain_id(self) -> Option<String> {
        self
    }
}

impl IntoOptionalChainId for Option<&str> {
    fn into_optional_chain_id(self) -> Option<String> {
        self.map(str::to_owned)
    }
}

/// Named parameters for [`AuditEntry::new_tool_invocation`].
///
/// Use [`NewToolInvocation::new`] for the required audit fields, then assign
/// optional metadata fields before passing the value to
/// [`AuditEntry::new_tool_invocation`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewToolInvocation {
    /// MCP tool name being audited.
    pub tool: String,
    /// Optional CAIP-2 chain identifier, absent for chain-independent calls.
    pub chain_id: Option<String>,
    /// Argument key names from the tool invocation. Values must not be logged.
    pub arg_keys: Vec<String>,
    /// SHA-256 hash of the signed transaction envelope, when present.
    pub envelope_hash: Option<String>,
    /// First-8 identifier derived from the nonce, when present.
    pub nonce_id: Option<String>,
    /// Policy-engine decision for the tool invocation.
    pub policy_decision: PolicyDecision,
    /// Human-readable decision reason; redacted by `AuditEntry` construction.
    pub decision_reason: Option<String>,
    /// Per-invocation UUIDv4 request correlation ID.
    pub request_id: String,
}

impl NewToolInvocation {
    /// Constructs required parameters for a tool-invocation audit entry.
    ///
    /// Optional fields default to `None`; assign them on the returned value
    /// before calling [`AuditEntry::new_tool_invocation`].
    #[must_use]
    pub fn new(
        tool: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        arg_keys: Vec<String>,
        policy_decision: PolicyDecision,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys,
            envelope_hash: None,
            nonce_id: None,
            policy_decision,
            decision_reason: None,
            request_id: request_id.into(),
        }
    }
}

/// One entry in the hash-chained structured audit log.
///
/// Each entry is serialised as a single JSON line (`\n`-terminated) and
/// written in append mode to `~/.local/state/stellar-agent/audit/<profile>.jsonl`
/// (or the OS-conventional equivalent).
///
/// # Hash-chain mechanism
///
/// `current_entry_hash = SHA-256(canonical_json_body || previous_entry_hash)`
///
/// where `canonical_json_body` is the JSON serialisation of the entry with the
/// `previous_entry_hash` field set to `""` (empty string — excluded from the
/// hash-input body).
///
/// The very first file's first entry uses
/// `previous_entry_hash = SHA-256(zero_block)` (32 zero bytes).
/// Subsequent files' first entries chain via the rotation handoff hash.
///
/// # Redaction
///
/// - `arg_keys` contains argument key names only — values are never logged.
/// - `decision_reason` has account-IDs redacted to first-5-last-5 and
///   tx-hashes to first-8-last-8 (see [`redact_decision_reason`]).
/// - `envelope_hash` is unredacted (SHA-256 digest; no user data).
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::entry::{AuditEntry, NewToolInvocation};
/// use stellar_agent_core::audit_log::schema::PolicyDecision;
///
/// let mut params = NewToolInvocation::new(
///     "stellar_pay_commit",
///     "stellar:testnet",
///     vec!["destination".to_owned(), "amount".to_owned()],
///     PolicyDecision::Allow,
///     "req-uuid-1234",
/// );
/// params.envelope_hash = Some("sha256:abcdef01".to_owned());
/// params.nonce_id = Some("nonce0001".to_owned());
/// let entry = AuditEntry::new_tool_invocation(params);
/// assert_eq!(entry.tool, "stellar_pay_commit");
/// // previous_entry_hash is populated by AuditWriter::write_entry.
/// assert!(entry.previous_entry_hash.is_empty());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO-8601 UTC timestamp with millisecond precision.
    ///
    /// Format: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub ts: String,

    /// MCP tool name or wallet-internal event name.
    pub tool: String,

    /// CAIP-2 chain identifier (`stellar:testnet` or `stellar:mainnet`).
    ///
    /// Absent for internal events without an associated chain context
    /// (e.g. `WalletMlockFailed`, `AuditRotationHandoff`), preserving a sparse
    /// wire shape instead of an empty-string sentinel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,

    /// Argument key names from the tool invocation (values NOT logged).
    ///
    /// Truncated if needed to stay within [`MAX_ENTRY_BYTES`]; see
    /// `arg_keys_truncated`.
    pub arg_keys: Vec<String>,

    /// Number of arg keys that were dropped to stay within the byte limit.
    ///
    /// `None` when no truncation occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arg_keys_truncated: Option<usize>,

    /// Set to `true` when any arg_key was dropped or the entry was truncated.
    ///
    /// Emitted only when `true` to keep the schema sparse. `#[serde(default)]`
    /// supplies `false` when the field is absent from older entries, maintaining
    /// backwards-compatibility. The redact-then-truncate pipeline in
    /// [`AuditEntry::truncate_arg_keys_if_needed`] is the only production writer
    /// that sets this flag. It is set after redaction if dropped `arg_keys` or an
    /// oversized fixed field exceed [`MAX_ENTRY_BYTES`], so secret values are
    /// never preserved by truncation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,

    /// SHA-256 hash of the signed transaction envelope.
    ///
    /// Format: `sha256:<hex-digest>`.  `None` for events that have no
    /// associated envelope (e.g. `WalletMlockFailed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_hash: Option<String>,

    /// First-8 hex characters of the base64-decoded nonce value.
    ///
    /// Used to correlate simulate → approve → commit triplets.  `None` for
    /// events that have no associated nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_id: Option<String>,

    /// Policy-engine decision serialised as a display string.
    ///
    /// Values: `"allow"`, `"deny:<reason>"`, or `"require_approval"`.
    pub policy_decision: PolicyDecision,

    /// Human-readable explanation of the decision (redacted).
    ///
    /// Account-IDs are first-5-last-5; tx-hashes are first-8-last-8.
    /// `None` when no explanation is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_reason: Option<String>,

    /// Per-invocation UUIDv4 request correlation ID.
    pub request_id: String,

    /// The event kind for this entry.
    ///
    /// `ToolInvocation` for standard tool audit entries; other variants for
    /// smart-account, passkey, channel, and other specialised audit surfaces.
    #[serde(flatten)]
    pub event_kind: EventKind,

    /// SHA-256 hash of the previous entry in the chain.
    ///
    /// Format: `sha256:<hex>`.
    ///
    /// For the very first file's first entry, this is `SHA-256(zero_block)`.
    /// For subsequent files' first entries, this is the hash of the rotation
    /// handoff entry in the preceding file (the cross-file chain bridge).
    ///
    /// This field is EXCLUDED from the hash-input body (set to `""` before
    /// computing the current entry's hash).  See `AuditEntry::canonical_json_body`.
    pub previous_entry_hash: String,
}

impl AuditEntry {
    /// Constructs a standard tool-invocation audit entry.
    ///
    /// This is the common-case constructor for MCP tool calls.  For other
    /// event kinds (plugin invocations, mlock failures, rotation handoffs),
    /// use the specific constructors below.
    ///
    /// The `previous_entry_hash` field is initialised to an empty string.
    /// [`AuditWriter::write_entry`](super::writer::AuditWriter::write_entry)
    /// overwrites this field with the writer's current chain tip before
    /// appending — callers MUST go through the writer; direct construction
    /// is for test or pre-write mutation only.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn new_tool_invocation(params: NewToolInvocation) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: params.tool,
            chain_id: params.chain_id,
            arg_keys: params.arg_keys,
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: params.envelope_hash,
            nonce_id: params.nonce_id,
            policy_decision: params.policy_decision,
            decision_reason: params.decision_reason.map(|r| redact_decision_reason(&r)),
            request_id: params.request_id,
            event_kind: EventKind::ToolInvocation,
            // The writer populates this field on append; this constructor
            // leaves it as empty string.  See AuditWriter::write_entry.
            previous_entry_hash: String::new(),
        }
    }

    /// Returns the already-redacted human-readable decision reason.
    #[must_use]
    pub fn decision_reason(&self) -> Option<&str> {
        self.decision_reason.as_deref()
    }

    /// Replaces the human-readable decision reason after applying audit-log redaction.
    ///
    /// The supplied `reason` is filtered through [`redact_decision_reason`]
    /// before storage; the field is otherwise immutable from outside the
    /// module. This is the only sanctioned post-construction mutation path
    /// for `decision_reason`.
    ///
    /// # Errors
    ///
    /// Infallible.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[allow(
        dead_code,
        reason = "crate-internal mutation hook for future audit emitters; exercised in test builds"
    )]
    pub(crate) fn set_decision_reason(&mut self, reason: Option<String>) {
        self.decision_reason = reason.map(|r| redact_decision_reason(&r));
    }

    /// Constructs a `PluginInvoked` audit entry.
    ///
    /// Schema variant is defined so `audit verify` recognises this kind without
    /// a retroactive schema change.
    ///
    /// The `previous_entry_hash` field is initialised to an empty string.
    /// [`AuditWriter::write_entry`](super::writer::AuditWriter::write_entry)
    /// overwrites this field with the writer's current chain tip before
    /// appending — callers MUST go through the writer.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidPluginName`] when `plugin_name` is
    /// empty, longer than 64 characters, or contains characters outside
    /// `[a-z0-9_-]`.
    pub fn new_plugin_invoked(
        plugin_name: impl Into<String>,
        exit_code: i32,
        decision: PolicyDecision,
        duration_ms: u64,
        request_id: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let plugin_name = plugin_name.into();
        validate_plugin_name(&plugin_name)?;
        Ok(Self {
            ts: current_iso8601_utc(),
            tool: format!("audit.plugin_invoked.{plugin_name}"),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: decision.clone(),
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::PluginInvoked {
                plugin_name,
                exit_code,
                decision,
                duration_ms,
            },
            // The writer populates this field on append; this constructor
            // leaves it as empty string.  See AuditWriter::write_entry.
            previous_entry_hash: String::new(),
        })
    }

    /// Constructs an `AuditRotationHandoff` entry (last entry in a rotated file).
    ///
    /// Written as the last entry in the outgoing log file before rotation.
    /// `audit verify` uses `next_file_name` to follow rotation boundaries.
    ///
    /// The `previous_entry_hash` field is initialised to an empty string.
    /// [`AuditWriter::rotate`](super::writer::AuditWriter) sets this field
    /// directly before serialising the handoff entry.
    #[must_use]
    pub fn new_rotation_handoff(
        next_file_name: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        let next = next_file_name.into();
        Self {
            ts: current_iso8601_utc(),
            tool: "audit.rotation_handoff_to".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::AuditRotationHandoff {
                next_file_name: next,
            },
            // The writer populates this field on append; this constructor
            // leaves it as empty string.  See AuditWriter::write_entry.
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `WalletMlockFailed` audit entry.
    ///
    /// Emitted when `mlock` fails and `wallet.mlock_required = "warn"`.
    ///
    /// The `previous_entry_hash` field is initialised to an empty string.
    /// [`AuditWriter::write_entry`](super::writer::AuditWriter::write_entry)
    /// overwrites this field with the writer's current chain tip before
    /// appending — callers MUST go through the writer.
    #[must_use]
    pub fn new_mlock_failed(
        profile: impl Into<String>,
        reason: impl Into<String>,
        errno: Option<i32>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "wallet.mlock_failed".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::WalletMlockFailed {
                profile: profile.into(),
                reason: reason.into(),
                errno,
            },
            // The writer populates this field on append; this constructor
            // leaves it as empty string.  See AuditWriter::write_entry.
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaRawInvocation` audit entry for smart-account operations.
    ///
    /// Emitted at smart-account operation boundaries (success and failure).
    /// `auth_digest_prefix` is `None` for deployment operations (where the
    /// deployer's source-account signature is the auth); it is `Some("16-char-hex-prefix")`
    /// for post-deployment invocations with Soroban auth.
    ///
    /// The `previous_entry_hash` field is initialised to an empty string.
    /// [`AuditWriter::write_entry`](super::writer::AuditWriter::write_entry)
    /// overwrites this field with the writer's current chain tip before
    /// appending — callers MUST go through the writer.
    ///
    /// # Redaction
    ///
    /// `smart_account` MUST be pre-redacted to first-5-last-5 form via
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` before
    /// passing to this constructor. The constructor does NOT redact internally.
    #[must_use]
    pub fn new_sa_raw_invocation(
        smart_account: impl Into<String>,
        wire_code: impl Into<String>,
        auth_digest_prefix: Option<String>,
        context_rule_ids_count: u32,
        result: super::schema::SaInvocationResult,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let wire_code = wire_code.into();
        Self {
            ts: current_iso8601_utc(),
            tool: format!("sa.invocation.{wire_code}"),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaRawInvocation {
                smart_account: smart_account.into(),
                wire_code,
                auth_digest_prefix,
                context_rule_ids_count,
                result,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SmartAccountDeployed` audit entry.
    ///
    /// Emitted on every successful deployment by `deployment::deploy_smart_account`.
    ///
    /// # Redaction
    ///
    /// All strkey and hash fields MUST be pre-redacted at the call site before
    /// passing to this constructor:
    /// - `smart_account`, `deployer`: first-5-last-5 via `redact_strkey_first5_last5`.
    /// - `wasm_hash_prefix`, `tx_hash_redacted`: first-8-last-8 hex prefix.
    ///
    /// The constructor does NOT redact internally.
    ///
    /// # Argument count
    ///
    /// This constructor intentionally exceeds clippy's 7-argument limit.
    /// The parameters map 1:1 to the required `SmartAccountDeployed` audit fields;
    /// grouping them into a struct would duplicate the `DeploymentResult` type already
    /// in `stellar-agent-smart-account`, creating a circular-dep risk.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set; see doc above"
    )]
    pub fn new_smart_account_deployed(
        smart_account: impl Into<String>,
        deployer: impl Into<String>,
        wasm_hash_prefix: impl Into<String>,
        wasm_uploaded: bool,
        tx_hash_redacted: impl Into<String>,
        ledger: u32,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.smart_account_deployed".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SmartAccountDeployed {
                smart_account: smart_account.into(),
                deployer: deployer.into(),
                wasm_hash_prefix: wasm_hash_prefix.into(),
                wasm_uploaded,
                tx_hash_redacted: tx_hash_redacted.into(),
                ledger,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaContextRuleCreated` audit entry.
    ///
    /// Emitted from `ContextRuleManager::install_rule`.
    ///
    /// # Redaction
    ///
    /// `smart_account` MUST be pre-redacted at the call site to first-5-last-5
    /// form via `redact_strkey_first5_last5`. The constructor does NOT redact
    /// internally. `rule_id`, `signers_count`, `policies_count` are
    /// non-sensitive on-chain identifiers.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set; mirrors new_sa_signer_set_baselined shape"
    )]
    pub fn new_sa_context_rule_created(
        smart_account: impl Into<String>,
        rule_id: u32,
        context_type: impl Into<String>,
        signers_count: u32,
        policies_count: u32,
        valid_until: Option<u32>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
        pinned_verifier_wasm_hashes_first8: Vec<String>,
        pinned_policy_wasm_hashes_first8: Vec<String>,
        mutable_override: bool,
        unknown_override: bool,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.context_rule_created".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaContextRuleCreated {
                smart_account: smart_account.into(),
                rule_id,
                context_type: context_type.into(),
                signers_count,
                policies_count,
                valid_until,
                pinned_verifier_wasm_hashes_first8,
                pinned_policy_wasm_hashes_first8,
                mutable_override,
                unknown_override,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaContextRuleDeleted` audit entry.
    ///
    /// Emitted from `ContextRuleManager::delete_rule`.
    ///
    /// # Redaction
    ///
    /// `smart_account` MUST be pre-redacted at the call site to first-5-last-5
    /// form via `redact_strkey_first5_last5`. `rule_id` is non-sensitive.
    #[must_use]
    pub fn new_sa_context_rule_deleted(
        smart_account: impl Into<String>,
        rule_id: u32,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.context_rule_deleted".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaContextRuleDeleted {
                smart_account: smart_account.into(),
                rule_id,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaContextRuleNameUpdated` audit entry.
    ///
    /// Emitted by `ContextRuleManager::update_name` on success, alongside the
    /// `SaRawInvocation(sa.ok)` row.
    ///
    /// `smart_account_redacted` MUST be pre-redacted via
    /// `redact_strkey_first5_last5`. `new_name` is internally redacted to
    /// first-3-chars + `" len=N"` form. The previous name is not recorded — the
    /// update flow never fetches it (see the schema variant doc).
    #[must_use]
    pub fn new_sa_context_rule_name_updated(
        smart_account_redacted: impl Into<String>,
        rule_id: u32,
        new_name: &str,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let rid: String = request_id.into();
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.context_rule_name_updated".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: rid.clone(),
            event_kind: EventKind::SaContextRuleNameUpdated {
                smart_account: smart_account_redacted.into(),
                rule_id,
                new_name_redacted: redact_free_text_name(new_name),
                audit_request_id: rid,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaContextRuleValidUntilUpdated` audit entry.
    ///
    /// Emitted by `ContextRuleManager::update_valid_until` on success, alongside
    /// the `SaRawInvocation(sa.ok)` row.
    ///
    /// `smart_account_redacted` MUST be pre-redacted via
    /// `redact_strkey_first5_last5`. `new_valid_until` is a ledger sequence
    /// (non-sensitive). The previous expiry is not recorded — the update flow
    /// never fetches it (see the schema variant doc).
    #[must_use]
    pub fn new_sa_context_rule_valid_until_updated(
        smart_account_redacted: impl Into<String>,
        rule_id: u32,
        new_valid_until: Option<u32>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let rid: String = request_id.into();
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.context_rule_valid_until_updated".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: rid.clone(),
            event_kind: EventKind::SaContextRuleValidUntilUpdated {
                smart_account: smart_account_redacted.into(),
                rule_id,
                new_valid_until,
                audit_request_id: rid,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaSignerAdded` audit entry.
    ///
    /// Emitted by `SignersManager::add_signer` after a successful on-chain
    /// `add_signer` invocation. `smart_account_redacted` MUST be the result of
    /// `redact_strkey_first5_last5` applied before calling this constructor.
    #[must_use]
    pub fn new_sa_signer_added(
        rule_id: u32,
        signer_id: u32,
        resulting: &super::signer_set::ObservedSignerSet,
        resulting_signer_pubkeys_first8: Vec<String>,
        smart_account_redacted: impl Into<RedactedStrkey>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.signer_added".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaSignerAdded {
                rule_id,
                signer_id,
                resulting_signer_count: resulting.signer_count,
                resulting_threshold: resulting.threshold,
                resulting_signer_ids: resulting.signer_ids.clone(),
                resulting_signer_pubkeys: resulting.signer_pubkeys.clone(),
                resulting_signer_pubkeys_first8,
                smart_account_redacted: smart_account_redacted.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaSignerRemoved` audit entry.
    ///
    /// Emitted by `SignersManager::remove_signer` after a successful on-chain
    /// `remove_signer` invocation. `smart_account_redacted` MUST be the result
    /// of `redact_strkey_first5_last5` applied before calling this constructor.
    #[must_use]
    pub fn new_sa_signer_removed(
        rule_id: u32,
        signer_id: u32,
        resulting: &super::signer_set::ObservedSignerSet,
        resulting_signer_pubkeys_first8: Vec<String>,
        smart_account_redacted: impl Into<RedactedStrkey>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.signer_removed".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaSignerRemoved {
                rule_id,
                signer_id,
                resulting_signer_count: resulting.signer_count,
                resulting_threshold: resulting.threshold,
                resulting_signer_ids: resulting.signer_ids.clone(),
                resulting_signer_pubkeys: resulting.signer_pubkeys.clone(),
                resulting_signer_pubkeys_first8,
                smart_account_redacted: smart_account_redacted.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaThresholdChanged` audit entry.
    ///
    /// Emitted by `SignersManager::set_threshold` after a successful on-chain
    /// `set_threshold` invocation. `smart_account_redacted` MUST be the result
    /// of `redact_strkey_first5_last5` applied before calling this constructor.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible per-entry constructor surface"
    )]
    #[must_use]
    pub fn new_sa_threshold_changed(
        rule_id: u32,
        old_threshold: u32,
        new_threshold: u32,
        resulting: &super::signer_set::ObservedSignerSet,
        resulting_signer_pubkeys_first8: Vec<String>,
        smart_account_redacted: impl Into<RedactedStrkey>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.threshold_changed".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaThresholdChanged {
                rule_id,
                old_threshold,
                new_threshold,
                resulting_threshold: resulting.threshold,
                resulting_signer_count: resulting.signer_count,
                resulting_signer_ids: resulting.signer_ids.clone(),
                resulting_signer_pubkeys: resulting.signer_pubkeys.clone(),
                resulting_signer_pubkeys_first8,
                smart_account_redacted: smart_account_redacted.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaSignerSetDiverged` audit entry.
    ///
    /// Emitted by `SignersManager::verify_signer_set_against_chain` when the
    /// on-chain signer set does not match the audit-log baseline.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible per-entry constructor surface"
    )]
    #[must_use]
    pub fn new_sa_signer_set_diverged(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        expected_signer_count: u32,
        observed_signer_count: u32,
        expected_threshold: u32,
        observed_threshold: u32,
        expected_signer_set_digest: impl Into<String>,
        observed_signer_set_digest: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.signer_set_diverged".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaSignerSetDiverged {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                expected_signer_count,
                observed_signer_count,
                expected_threshold,
                observed_threshold,
                expected_signer_set_digest: expected_signer_set_digest.into(),
                observed_signer_set_digest: observed_signer_set_digest.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaSignerSetBaselined` audit entry.
    ///
    /// This constructor MUST ONLY be called from `SignersManager::list_signers`
    /// (first-observation path) and `SignersManager::refresh_signer_baseline`
    /// (explicit-refresh path). A repo-gate enforces the single-caller
    /// invariant at CI time.
    ///
    /// The `prev_chain_tip_hash` MUST be sourced from
    /// `AuditWriter::current_chain_tip()` inside the same write critical section
    /// to prevent replay-anchor races.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible per-entry constructor surface"
    )]
    #[must_use]
    pub fn new_sa_signer_set_baselined(
        rule_id: u32,
        observed: &super::signer_set::ObservedSignerSet,
        observed_signer_pubkeys_first8: Vec<String>,
        observed_at_unix_ms: u64,
        baseline_reason: super::signer_set::BaselineReason,
        prev_chain_tip_hash: [u8; 32],
        smart_account_redacted: impl Into<RedactedStrkey>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.signer_set_baselined".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec!["rule_id".to_owned()],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaSignerSetBaselined {
                rule_id,
                observed_signer_count: observed.signer_count,
                observed_threshold: observed.threshold,
                observed_signer_ids: observed.signer_ids.clone(),
                observed_signer_pubkeys: observed.signer_pubkeys.clone(),
                observed_signer_pubkeys_first8,
                observed_at_ledger_seq: 0, // Not available from view call; 0 is the sentinel.
                observed_at_unix_ms,
                baseline_reason,
                prev_chain_tip_hash,
                smart_account_redacted: smart_account_redacted.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMutableContractOverride` audit entry.
    ///
    /// Emitted by `managers::verifiers::pin_referenced_contracts` when a
    /// referenced verifier or policy contract has a non-zero Admin / Owner storage
    /// key AND `--accept-mutable-verifier` is set.  Records the acknowledgement
    /// with an ISO-8601 timestamp.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `contract_address_redacted` MUST be
    /// pre-redacted (first-5-last-5) at the call site.  The constructor does NOT
    /// redact internally.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set for contract override telemetry"
    )]
    pub fn new_sa_mutable_contract_override(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        contract_address_redacted: impl Into<RedactedStrkey>,
        contract_kind: ContractKind,
        override_acknowledged_at: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.mutable_contract_override".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaMutableContractOverride {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                contract_address_redacted: contract_address_redacted.into(),
                contract_kind,
                override_acknowledged_at: override_acknowledged_at.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaUnknownContractOverride` audit entry.
    ///
    /// Emitted by `managers::verifiers::pin_referenced_contracts` when a
    /// referenced verifier or policy contract's wasm hash is NOT in the
    /// compile-time allowlist AND `--accept-unknown-verifier` is set.  Records
    /// the acknowledgement with an ISO-8601 timestamp.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `contract_address_redacted` MUST be
    /// pre-redacted (first-5-last-5) at the call site.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set for contract override telemetry"
    )]
    pub fn new_sa_unknown_contract_override(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        contract_address_redacted: impl Into<RedactedStrkey>,
        contract_kind: ContractKind,
        override_acknowledged_at: impl Into<String>,
        observed_hash_first8: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.unknown_contract_override".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaUnknownContractOverride {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                contract_address_redacted: contract_address_redacted.into(),
                contract_kind,
                override_acknowledged_at: override_acknowledged_at.into(),
                observed_hash_first8: observed_hash_first8.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaVerifierHashDrift` audit entry.
    ///
    /// Emitted by `managers::verifiers::verify_pinned_verifier_against_chain`
    /// when the live two-RPC wasm-hash re-fetch disagrees with the hash pinned
    /// at rule-install time.  The signing operation is aborted before any
    /// signature bytes are produced.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `deploy_address_redacted` MUST be
    /// pre-redacted (first-5-last-5) at the call site.  `pinned_hash_first8`
    /// and `observed_hash_first8` are the first-8 hex chars of the respective
    /// 32-byte wasm hashes.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set for verifier drift telemetry"
    )]
    pub fn new_sa_verifier_hash_drift(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        deploy_address_redacted: impl Into<RedactedStrkey>,
        pinned_hash_first8: impl Into<String>,
        observed_hash_first8: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.verifier_hash_drift".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Deny("verifier_hash_drift".to_owned()),
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaVerifierHashDrift {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                deploy_address_redacted: deploy_address_redacted.into(),
                pinned_hash_first8: pinned_hash_first8.into(),
                observed_hash_first8: observed_hash_first8.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaPolicyHashDrift` audit entry.
    ///
    /// Parallel to [`AuditEntry::new_sa_verifier_hash_drift`] for the
    /// threshold-policy contract path.  Emitted by
    /// `managers::verifiers::verify_pinned_policy_against_chain` when the live
    /// two-RPC wasm-hash re-fetch disagrees with the hash pinned at rule-install
    /// time.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `deploy_address_redacted` MUST be
    /// pre-redacted (first-5-last-5) at the call site.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set for policy drift telemetry"
    )]
    pub fn new_sa_policy_hash_drift(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        deploy_address_redacted: impl Into<RedactedStrkey>,
        pinned_hash_first8: impl Into<String>,
        observed_hash_first8: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.policy_hash_drift".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Deny("policy_hash_drift".to_owned()),
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaPolicyHashDrift {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                deploy_address_redacted: deploy_address_redacted.into(),
                pinned_hash_first8: pinned_hash_first8.into(),
                observed_hash_first8: observed_hash_first8.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaVerifierMigrated` audit entry.
    ///
    /// Emitted by `managers::verifiers::migrate_verifier` after a successful
    /// on-chain verifier contract migration.  Records the source and destination
    /// wasm hashes (first-8 hex chars each) and the redacted transaction hash.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5) at the
    /// call site.  `from_hash_first8` and `to_hash_first8` are the first-8 hex
    /// chars of the respective 32-byte wasm hashes.  `tx_hash_redacted` MUST be
    /// pre-redacted (first-8-last-8) at the call site.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set for verifier migration telemetry"
    )]
    pub fn new_sa_verifier_migrated(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        from_hash_first8: impl Into<String>,
        to_hash_first8: impl Into<String>,
        tx_hash_redacted: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.verifier_migrated".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaVerifierMigrated {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                from_hash_first8: from_hash_first8.into(),
                to_hash_first8: to_hash_first8.into(),
                tx_hash_redacted: tx_hash_redacted.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaVerifierDiversificationOverride` audit entry.
    ///
    /// Emitted by `managers::verifiers::check_verifier_diversification` when the
    /// operator explicitly acknowledges that a single verifier is in use despite
    /// a transaction value above the diversification threshold.  Records the
    /// acknowledgement timestamp and the observed threshold value.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5) at the
    /// call site.  `verifier_hash_first8` is the first-8 hex chars of the
    /// 32-byte verifier wasm hash.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set for verifier diversification override telemetry"
    )]
    pub fn new_sa_verifier_diversification_override(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        verifier_hash_first8: impl Into<String>,
        observed_value_threshold_stroops: i64,
        override_acknowledged_at: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let override_acknowledged_at = override_acknowledged_at.into();
        debug_assert!(
            looks_like_rfc3339_timestamp(&override_acknowledged_at),
            "override_acknowledged_at must be RFC 3339-like UTC timestamp"
        );
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.verifier_diversification_override".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaVerifierDiversificationOverride {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                verifier_hash_first8: verifier_hash_first8.into(),
                observed_value_threshold_stroops,
                override_acknowledged_at,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaVerifierAllowlistAdvisory` audit entry.
    ///
    /// Emitted by `managers::verifiers::check_verifier_allowlist` when a verifier
    /// wasm hash that a rule references appears on the revoked or retired advisory
    /// list.  Signing is blocked for revoked hashes; a warning is emitted for
    /// retired hashes.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5) at the
    /// call site.  `revoked_hash_first8` is the first-8 hex chars of the
    /// 32-byte wasm hash.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "symmetric with adjacent audit-entry constructors for the same surface"
    )]
    pub fn new_sa_verifier_allowlist_advisory(
        rule_id: u32,
        smart_account_redacted: impl Into<RedactedStrkey>,
        revoked_hash_first8: impl Into<String>,
        advised_status: VerifierAdvisoryKind,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.verifier_allowlist_advisory".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaVerifierAllowlistAdvisory {
                rule_id,
                smart_account_redacted: smart_account_redacted.into(),
                revoked_hash_first8: revoked_hash_first8.into(),
                advised_status,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaPolicyAdded` audit entry.
    ///
    /// Emitted by `ContextRuleManager::add_policy` after a successful on-chain
    /// `add_policy` invocation.
    ///
    /// # Arguments
    ///
    /// - `rule_id` — on-chain context rule ID the policy was added to.
    /// - `policy_id` — on-chain policy ID returned by `add_policy`.
    /// - `policy_address_redacted` — policy contract C-strkey, already
    ///   redacted first-5-last-5 via
    ///   `stellar_agent_core::observability::redact_strkey_first5_last5`.
    ///   Callers MUST NOT pass the unredacted address.
    /// - `transaction_hash_redacted` — Stellar transaction hash, already
    ///   redacted first-8-last-8 via
    ///   `stellar_agent_network::redact_tx_hash`.
    /// - `smart_account_redacted` — smart-account C-strkey, already
    ///   redacted first-5-last-5. Callers MUST NOT pass the unredacted address.
    #[must_use]
    pub fn new_sa_policy_added(
        rule_id: u32,
        policy_id: u32,
        policy_address_redacted: impl Into<RedactedStrkey>,
        transaction_hash_redacted: impl Into<String>,
        smart_account_redacted: impl Into<RedactedStrkey>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.policy_added".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaPolicyAdded {
                rule_id,
                policy_id,
                policy_address_redacted: policy_address_redacted.into(),
                transaction_hash_redacted: transaction_hash_redacted.into(),
                smart_account_redacted: smart_account_redacted.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaPolicyRemoved` audit entry.
    ///
    /// Emitted by `ContextRuleManager::remove_policy` after a successful
    /// on-chain `remove_policy` invocation.
    ///
    /// # Arguments
    ///
    /// - `rule_id` — on-chain context rule ID the policy was removed from.
    /// - `policy_id` — on-chain policy ID that was removed.
    /// - `transaction_hash_redacted` — Stellar transaction hash, already
    ///   redacted first-8-last-8 via `stellar_agent_network::redact_tx_hash`.
    /// - `smart_account_redacted` — smart-account C-strkey, already
    ///   redacted first-5-last-5 via
    ///   `stellar_agent_core::observability::redact_strkey_first5_last5`.
    ///   Callers MUST NOT pass the unredacted address.
    #[must_use]
    pub fn new_sa_policy_removed(
        rule_id: u32,
        policy_id: u32,
        transaction_hash_redacted: impl Into<String>,
        smart_account_redacted: impl Into<RedactedStrkey>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.policy_removed".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaPolicyRemoved {
                rule_id,
                policy_id,
                transaction_hash_redacted: transaction_hash_redacted.into(),
                smart_account_redacted: smart_account_redacted.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `PasskeyRegistered` audit entry.
    ///
    /// Emitted by `CredentialsManager::add_passkey` on completion (success or
    /// non-success) of a WebAuthn registration ceremony. The constructor accepts
    /// the raw `credential_id` bytes and applies the audit-log redaction
    /// (first-5-last-5 base64url) internally — callers MUST NOT pre-redact.
    ///
    /// # Redaction
    ///
    /// The `credential_id_redacted` field stores `"<head>...<tail>"` where
    /// `<head>` is the first 5 base64url characters of the credential ID and
    /// `<tail>` is the last 5. The full credential ID and public-key bytes are
    /// never written to the audit log.
    #[must_use]
    pub fn new_passkey_registered(
        credential_name: impl Into<String>,
        credential_id_b64url: impl AsRef<str>,
        rp_id: impl Into<String>,
        status: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        // Redact credential_id to first-5-last-5 base64url.
        let id = credential_id_b64url.as_ref();
        let credential_id_redacted = redact_credential_id_b64url(id);
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.passkey_registered".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::PasskeyRegistered {
                credential_name: credential_name.into(),
                credential_id_redacted,
                rp_id: rp_id.into(),
                status: status.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `PasskeyAssertion` audit entry.
    ///
    /// Emitted by `CredentialsManager::sign_with_passkey_rule` on completion
    /// (success or non-success) of a WebAuthn signing ceremony. Redaction is
    /// applied internally — callers MUST NOT pre-redact.
    ///
    /// # Parameters
    ///
    /// - `credential_name`: human-readable credential name from the registry.
    /// - `credential_id_b64url`: the full base64url-encoded credential ID;
    ///   the constructor applies first-5-last-5 redaction before storing.
    ///   Pass `""` on early-exit paths where the credential metadata is
    ///   unavailable (e.g. `ApprovalStoreUnavailable` fires before `show()`).
    /// - `rp_id`: the relying-party identifier (non-sensitive; stored as-is).
    ///   Pass `""` on early-exit paths where the credential metadata is
    ///   unavailable.
    /// - `smart_account`: the full C-strkey of the target smart account;
    ///   the constructor applies first-5-last-5 redaction before storing.
    ///   Pass `""` if the smart account is unknown.
    /// - `auth_digest_hex`: 64-char hex string of the 32-byte auth digest;
    ///   the constructor applies first-5-last-5 redaction before storing.
    ///   Pass `""` on non-success paths where the digest is unavailable.
    /// - `signed_at_unix_ms`: Unix timestamp (ms) of the ceremony outcome.
    /// - `result`: one of the closed-set classes enumerated in the rustdoc of
    ///   the `result` field on `EventKind::PasskeyAssertion` in `schema.rs`
    ///   (see the field-level rustdoc for the canonical 12-class list); do not
    ///   hand-roll new values.
    /// - `request_id`: forensic correlation ID for this signing invocation.
    ///
    /// # Redaction
    ///
    /// `credential_id_redacted`: first-5-last-5 of `credential_id_b64url`.
    /// `smart_account_redacted`: first-5-last-5 of `smart_account`.
    /// `auth_digest_redacted`: first-5-last-5 of `auth_digest_hex`.
    /// Neither full credential ID, smart account strkey, nor signature bytes
    /// appear in the log.  Callers MUST pass the raw (non-pre-redacted) values;
    /// this constructor is the single redaction point.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "audit entry captures credential_name, credential_id, rp_id, \
                  smart_account, auth_digest, timestamp, result, request_id — \
                  each field is independently meaningful; no logical grouping \
                  reduces the count without losing caller ergonomics"
    )]
    pub fn new_passkey_assertion(
        credential_name: impl Into<String>,
        credential_id_b64url: impl AsRef<str>,
        rp_id: impl Into<String>,
        smart_account: impl AsRef<str>,
        auth_digest_hex: impl AsRef<str>,
        signed_at_unix_ms: u64,
        result: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        let credential_id_redacted = redact_credential_id_b64url(credential_id_b64url.as_ref());

        // Redact auth_digest_hex to first-5-last-5.  The hex string is 64 chars
        // for a 32-byte digest; always long enough for the 10-char threshold.
        // Pass "" if the digest is unavailable (non-success paths).
        let auth_digest_redacted = redact_first5_last5(auth_digest_hex.as_ref());
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.passkey_assertion".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::PasskeyAssertion {
                credential_name: credential_name.into(),
                credential_id_redacted,
                rp_id: rp_id.into(),
                smart_account_redacted: RedactedStrkey::from_full(smart_account.as_ref()),
                auth_digest_redacted,
                signed_at_unix_ms,
                result: result.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMulticallBundleSubmitted` audit entry.
    ///
    /// Emitted by `multicall::submit_multicall_bundle` after a successful
    /// `submit_signed_invoke` + on-chain confirmation cycle.
    ///
    /// # Redaction
    ///
    /// - `smart_account_redacted`: MUST be pre-redacted to first-5-last-5 via
    ///   `redact_strkey_first5_last5` at the call site. The constructor does NOT
    ///   redact internally.
    /// - `bundle_tx_hash_redacted`: MUST be pre-redacted to first-8-last-8 at the
    ///   call site.
    ///
    /// `rule_id` and `inner_count` are non-sensitive on-chain identifiers.
    #[must_use]
    pub fn new_sa_multicall_bundle_submitted(
        smart_account_redacted: impl Into<RedactedStrkey>,
        rule_id: u32,
        bundle_tx_hash_redacted: impl Into<String>,
        inner_count: u32,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.multicall_bundle_submitted".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaMulticallBundleSubmitted {
                smart_account_redacted: smart_account_redacted.into(),
                rule_id,
                bundle_tx_hash_redacted: bundle_tx_hash_redacted.into(),
                inner_count,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMulticallInnerExecuted` audit entry.
    ///
    /// Emitted once per inner invocation, immediately after
    /// [`AuditEntry::new_sa_multicall_bundle_submitted`], in bundle order.
    ///
    /// # Redaction
    ///
    /// - `bundle_tx_hash_redacted`: MUST be pre-redacted to first-8-last-8 at the
    ///   call site.
    /// - `target_contract_redacted`: MUST be pre-redacted to first-5-last-5 via
    ///   `redact_strkey_first5_last5` at the call site.
    ///
    /// `inner_index` and `fn_name` are non-sensitive on-chain identifiers.
    /// `return_scval_b64_prefix` carries only the first 32 base64 chars; callers
    /// MUST NOT pass the full return value.
    #[must_use]
    pub fn new_sa_multicall_inner_executed(
        bundle_tx_hash_redacted: impl Into<String>,
        inner_index: u32,
        target_contract_redacted: impl Into<RedactedStrkey>,
        fn_name: impl Into<String>,
        return_scval_b64_prefix: Option<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.multicall_inner_executed".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaMulticallInnerExecuted {
                bundle_tx_hash_redacted: bundle_tx_hash_redacted.into(),
                inner_index,
                target_contract_redacted: target_contract_redacted.into(),
                fn_name: fn_name.into(),
                return_scval_b64_prefix,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMulticallBundleDenied` audit entry.
    ///
    /// Emitted by `multicall::submit_multicall_bundle` when the bundle is
    /// refused at any phase: `build` validation, `policy_gate` denial,
    /// `rpc_divergence` trust-anchor failure, `simulate` error, `sign` error,
    /// `submit` error, or `post_submit_verification` mismatch.
    ///
    /// # Redaction
    ///
    /// - `smart_account_redacted`: MUST be pre-redacted to first-5-last-5 via
    ///   `redact_strkey_first5_last5` at the call site.
    /// - `bundle_tx_hash_redacted`: MUST be pre-redacted to first-8-last-8, or
    ///   `None` for pre-submission denials.
    ///
    /// `rule_id`, `inner_count`, `deny_wire_code`, and `refusal_phase` are
    /// non-sensitive identifiers.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible denial-audit field set; all fields map 1:1 to SaMulticallBundleDenied EventKind"
    )]
    pub fn new_sa_multicall_bundle_denied(
        smart_account_redacted: impl Into<RedactedStrkey>,
        rule_id: u32,
        inner_count: u32,
        denied_inner_index: Option<u32>,
        observed_inner_count: Option<u32>,
        deny_wire_code: impl Into<String>,
        refusal_phase: impl Into<String>,
        bundle_tx_hash_redacted: Option<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.multicall_bundle_denied".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Deny("multicall.bundle_denied".to_owned()),
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaMulticallBundleDenied {
                smart_account_redacted: smart_account_redacted.into(),
                rule_id,
                inner_count,
                denied_inner_index,
                observed_inner_count,
                deny_wire_code: deny_wire_code.into(),
                refusal_phase: refusal_phase.into(),
                bundle_tx_hash_redacted,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMulticallRegistered` audit entry.
    ///
    /// Emitted by `smart-account register-multicall` on success, after the registry
    /// entry is written to disk.
    ///
    /// # Redaction
    ///
    /// - `address_redacted`: MUST be pre-redacted to first-5-last-5 via
    ///   `redact_strkey_first5_last5` at the call site. The constructor does NOT
    ///   redact internally.
    ///
    /// `network_safename` and `wasm_sha256` are non-sensitive configuration values.
    #[must_use]
    pub fn new_sa_multicall_registered(
        network_safename: impl Into<String>,
        address_redacted: impl Into<RedactedStrkey>,
        wasm_sha256: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.multicall_registered".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaMulticallRegistered {
                network_safename: network_safename.into(),
                address_redacted: address_redacted.into(),
                wasm_sha256: wasm_sha256.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMulticallRegistrationRefused` audit entry.
    ///
    /// Emitted by `smart-account register-multicall` when registration is refused due
    /// to a WASM SHA-256 mismatch (either at the CLI handler level or at
    /// `MulticallRegistry::register`).
    ///
    /// # Redaction
    ///
    /// - `address_redacted`: MUST be pre-redacted to first-5-last-5 via
    ///   `redact_strkey_first5_last5` at the call site.
    ///
    /// `attempted_wasm_sha256`, `existing_wasm_sha256`, and `refusal_reason` are
    /// non-sensitive configuration identifiers.
    #[must_use]
    pub fn new_sa_multicall_registration_refused(
        network_safename: impl Into<String>,
        address_redacted: impl Into<RedactedStrkey>,
        attempted_wasm_sha256: impl Into<String>,
        existing_wasm_sha256: Option<String>,
        refusal_reason: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.multicall_registration_refused".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Deny("multicall.registration_refused".to_owned()),
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaMulticallRegistrationRefused {
                network_safename: network_safename.into(),
                address_redacted: address_redacted.into(),
                attempted_wasm_sha256: attempted_wasm_sha256.into(),
                existing_wasm_sha256,
                refusal_reason: refusal_reason.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMulticallUnregistered` audit entry.
    ///
    /// Emitted by `smart-account unregister-multicall` (normal path, not `--force`)
    /// on success, after the registry entry is removed from disk.
    ///
    /// # Redaction
    ///
    /// - `prior_address_redacted`: MUST be pre-redacted to first-5-last-5 via
    ///   `redact_strkey_first5_last5` at the call site.
    ///
    /// `network_safename` and `prior_wasm_sha256` are non-sensitive configuration values.
    #[must_use]
    pub fn new_sa_multicall_unregistered(
        network_safename: impl Into<String>,
        prior_address_redacted: impl Into<RedactedStrkey>,
        prior_wasm_sha256: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.multicall_unregistered".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::SaMulticallUnregistered {
                network_safename: network_safename.into(),
                prior_address_redacted: prior_address_redacted.into(),
                prior_wasm_sha256: prior_wasm_sha256.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaMulticallUnregisteredForce` audit entry.
    ///
    /// Emitted by `smart-account unregister-multicall --force` BEFORE any file mutation.
    /// Raw field values from the TOML file are included without validation; each is
    /// truncated to 64 characters.
    ///
    /// # Truncation (per-field cap)
    ///
    /// - `prior_address_raw` — truncated to 64 chars; `prior_address_raw_truncated`
    ///   indicates whether truncation occurred.
    /// - `prior_wasm_sha256_raw` — truncated to 64 chars; `prior_wasm_sha256_raw_truncated`
    ///   indicates whether truncation occurred.
    /// - `load_warnings` — capped at 32 entries; `load_warnings_truncated` set when more.
    ///
    /// # Post-serialisation size guard — sentinel-row fallback
    ///
    /// After per-field truncation the constructor serialises the entry and checks
    /// whether its JSON length exceeds [`MAX_ENTRY_BYTES`] (4 096 bytes). If it
    /// does, the entry is rebuilt as a sentinel row:
    ///
    /// 1. `prior_address_raw` and `prior_wasm_sha256_raw` are replaced by
    ///    `"<oversized>"`, and the `_truncated` flags are set `true`.
    /// 2. `load_warnings` is iteratively drained (last entry per iteration)
    ///    until the serialised size fits within `MAX_ENTRY_BYTES`.
    /// 3. The outer `AuditEntry::truncated` flag is set `true`.
    ///
    /// Callers MUST NOT pre-truncate — this constructor applies all truncation.
    #[must_use]
    pub fn new_sa_multicall_unregistered_force(
        network_safename: impl Into<String>,
        prior_address_raw_full: impl AsRef<str>,
        prior_wasm_sha256_raw_full: impl AsRef<str>,
        load_warnings_full: Vec<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        const RAW_FIELD_CAP: usize = 64;
        const WARN_CAP: usize = 32;
        const OVERSIZED_SENTINEL: &str = "<oversized>";

        let addr = prior_address_raw_full.as_ref();
        let (prior_address_raw, prior_address_raw_truncated) = if addr.len() > RAW_FIELD_CAP {
            (addr[..RAW_FIELD_CAP].to_owned(), true)
        } else {
            (addr.to_owned(), false)
        };

        let sha = prior_wasm_sha256_raw_full.as_ref();
        let (prior_wasm_sha256_raw, prior_wasm_sha256_raw_truncated) = if sha.len() > RAW_FIELD_CAP
        {
            (sha[..RAW_FIELD_CAP].to_owned(), true)
        } else {
            (sha.to_owned(), false)
        };

        let warnings_truncated_by_cap = load_warnings_full.len() > WARN_CAP;
        let load_warnings: Vec<String> = load_warnings_full.into_iter().take(WARN_CAP).collect();

        // Resolve impl-generic parameters before the borrow-in-EventKind below.
        let network_safename: String = network_safename.into();
        let chain_id = chain_id.into_optional_chain_id();
        let request_id: String = request_id.into();

        let mut entry = Self {
            ts: current_iso8601_utc(),
            tool: "sa.multicall_unregistered_force".to_owned(),
            chain_id,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id,
            event_kind: EventKind::SaMulticallUnregisteredForce {
                network_safename,
                prior_address_raw,
                prior_address_raw_truncated,
                prior_wasm_sha256_raw,
                prior_wasm_sha256_raw_truncated,
                load_warnings,
                load_warnings_truncated: warnings_truncated_by_cap,
            },
            previous_entry_hash: String::new(),
        };

        // Post-serialisation size guard.
        // If per-field truncation was insufficient, apply the sentinel-row fallback.
        if serde_json::to_vec(&entry)
            .map(|v| v.len() > MAX_ENTRY_BYTES)
            .unwrap_or(false)
        {
            // Step 1: replace raw fields with sentinel strings.
            if let EventKind::SaMulticallUnregisteredForce {
                ref mut prior_address_raw,
                ref mut prior_address_raw_truncated,
                ref mut prior_wasm_sha256_raw,
                ref mut prior_wasm_sha256_raw_truncated,
                ..
            } = entry.event_kind
            {
                *prior_address_raw = OVERSIZED_SENTINEL.to_owned();
                *prior_address_raw_truncated = true;
                *prior_wasm_sha256_raw = OVERSIZED_SENTINEL.to_owned();
                *prior_wasm_sha256_raw_truncated = true;
            }

            // Step 2: iteratively drop load_warnings until the entry fits.
            // Borrows entry mutably in a separate scope from the serialisation check.
            loop {
                let size = serde_json::to_vec(&entry).map(|v| v.len()).unwrap_or(0);
                if size <= MAX_ENTRY_BYTES {
                    break;
                }
                if let EventKind::SaMulticallUnregisteredForce {
                    ref mut load_warnings,
                    ref mut load_warnings_truncated,
                    ..
                } = entry.event_kind
                {
                    if load_warnings.is_empty() {
                        // Cannot shrink further; accept the oversized entry.
                        break;
                    }
                    load_warnings.pop();
                    *load_warnings_truncated = true;
                } else {
                    break;
                }
            }

            // Step 3: mark the outer entry as truncated.
            entry.truncated = true;
        }

        entry
    }

    /// Constructs a `SaTimelockScheduled` audit entry.
    ///
    /// Emitted by `stellar_agent_smart_account::timelock::schedule_upgrade` after
    /// successful on-chain confirmation of the `Timelock::schedule` call.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible audit-field set; grouping into a builder would add indirection without reducing the field count"
    )]
    #[must_use]
    pub fn new_sa_timelock_scheduled(
        operation_id_redacted: impl Into<String>,
        operation_id_full_hex: impl Into<String>,
        timelock_contract_redacted: impl Into<RedactedStrkey>,
        target_redacted: impl Into<RedactedStrkey>,
        function: impl Into<String>,
        delay_ledgers: u32,
        proposer_redacted: impl Into<RedactedStrkey>,
        schedule_tx_hash_redacted: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let request_id: String = request_id.into();
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.timelock_scheduled".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.clone(),
            event_kind: EventKind::SaTimelockScheduled {
                operation_id_redacted: operation_id_redacted.into(),
                operation_id_full_hex: operation_id_full_hex.into(),
                timelock_contract_redacted: timelock_contract_redacted.into(),
                target_redacted: target_redacted.into(),
                function: function.into(),
                delay_ledgers,
                proposer_redacted: proposer_redacted.into(),
                schedule_tx_hash_redacted: schedule_tx_hash_redacted.into(),
                audit_request_id: request_id,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaTimelockCancelled` audit entry.
    ///
    /// Emitted by `stellar_agent_smart_account::timelock::cancel` after
    /// successful on-chain confirmation of the `Timelock::cancel` call.
    #[must_use]
    pub fn new_sa_timelock_cancelled(
        operation_id_redacted: impl Into<String>,
        operation_id_full_hex: impl Into<String>,
        timelock_contract_redacted: impl Into<RedactedStrkey>,
        canceller_redacted: impl Into<RedactedStrkey>,
        cancel_tx_hash_redacted: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let request_id: String = request_id.into();
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.timelock_cancelled".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.clone(),
            event_kind: EventKind::SaTimelockCancelled {
                operation_id_redacted: operation_id_redacted.into(),
                operation_id_full_hex: operation_id_full_hex.into(),
                timelock_contract_redacted: timelock_contract_redacted.into(),
                canceller_redacted: canceller_redacted.into(),
                cancel_tx_hash_redacted: cancel_tx_hash_redacted.into(),
                audit_request_id: request_id,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaTimelockExecuted` audit entry.
    ///
    /// Emitted by `stellar_agent_smart_account::timelock::execute` after
    /// successful on-chain confirmation of the `Timelock::execute` call.
    #[must_use]
    pub fn new_sa_timelock_executed(
        operation_id_redacted: impl Into<String>,
        operation_id_full_hex: impl Into<String>,
        timelock_contract_redacted: impl Into<RedactedStrkey>,
        executor_redacted: Option<RedactedStrkey>,
        execute_tx_hash_redacted: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let request_id: String = request_id.into();
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.timelock_executed".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.clone(),
            event_kind: EventKind::SaTimelockExecuted {
                operation_id_redacted: operation_id_redacted.into(),
                operation_id_full_hex: operation_id_full_hex.into(),
                timelock_contract_redacted: timelock_contract_redacted.into(),
                executor_redacted,
                execute_tx_hash_redacted: execute_tx_hash_redacted.into(),
                audit_request_id: request_id,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `SaTimelockDivergencePostSubmit` audit entry.
    ///
    /// Emitted before the divergence error is propagated on the `schedule`,
    /// `cancel`, or `execute` paths when `cross_confirm_event` returns
    /// `Divergence`.  Records that the on-chain op may have landed even though
    /// both RPCs did not agree on the event.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` MUST be pre-redacted via
    /// `redact_strkey_first5_last5`.  `operation_id_redacted` and
    /// `tx_hash_redacted` MUST be pre-redacted to first-8-last-8 form.
    /// The constructor does NOT redact internally.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "struct initialiser — all args are semantically distinct and a builder would be over-engineered for an internal audit constructor"
    )]
    pub fn new_sa_timelock_divergence_post_submit(
        smart_account_redacted: impl Into<crate::observability::RedactedStrkey>,
        operation_id_redacted: impl Into<String>,
        tx_hash_redacted: impl Into<String>,
        path: impl Into<String>,
        primary_present: bool,
        secondary_present: bool,
        chain_id: impl IntoOptionalChainId,
        request_id: impl Into<String>,
    ) -> Self {
        let request_id: String = request_id.into();
        Self {
            ts: current_iso8601_utc(),
            tool: "sa.timelock_divergence_post_submit".to_owned(),
            chain_id: chain_id.into_optional_chain_id(),
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.clone(),
            event_kind: EventKind::SaTimelockDivergencePostSubmit {
                smart_account_redacted: smart_account_redacted.into(),
                operation_id_redacted: operation_id_redacted.into(),
                tx_hash_redacted: tx_hash_redacted.into(),
                path: path.into(),
                primary_present,
                secondary_present,
                audit_request_id: request_id,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `ChannelAcquired` audit entry.
    ///
    /// Emitted by `stellar-agent-pool::allocator::acquire` immediately after a
    /// channel is marked `InFlight`.
    ///
    /// # Redaction
    ///
    /// `channel_redacted` MUST be pre-redacted to first-5-last-5 form via
    /// `redact_strkey_first5_last5`.  The constructor does NOT redact internally.
    ///
    #[must_use]
    pub fn new_channel_acquired(
        channel_redacted: impl Into<String>,
        index: u32,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "pool.channel_acquired".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::ChannelAcquired {
                channel_redacted: channel_redacted.into(),
                index,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `ChannelReleased` audit entry.
    ///
    /// Emitted by `stellar-agent-pool::allocator::release` immediately after a
    /// channel transitions back to `Free`.
    ///
    /// # Redaction
    ///
    /// `channel_redacted` MUST be pre-redacted to first-5-last-5 form via
    /// `redact_strkey_first5_last5`.  The constructor does NOT redact internally.
    ///
    /// `outcome` is one of `"success"`, `"tx_bad_seq"`, or `"failed"` — the
    /// string-serialised form of `TerminalOutcome`.
    #[must_use]
    pub fn new_channel_released(
        channel_redacted: impl Into<String>,
        index: u32,
        outcome: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "pool.channel_released".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::ChannelReleased {
                channel_redacted: channel_redacted.into(),
                index,
                outcome: outcome.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs a `ChannelPoolInitialised` audit entry.
    ///
    /// Emitted by `stellar-agent-cli pool init` AFTER the CAP-33 sponsored-reserve
    /// sandwich confirms on-chain, immediately after the pool master seed is written
    /// to the OS keyring and the `PoolConfig` is persisted to the profile TOML.
    ///
    /// # Redaction
    ///
    /// `funder_redacted` MUST be pre-redacted to first-5-last-5 form via
    /// `redact_strkey_first5_last5`.  `tx_hash_redacted` MUST be pre-redacted to
    /// first-8-last-8 hex form.  The constructor does NOT redact internally.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; existing wildcard-match arms in
    /// `audit verify` continue to compile.
    #[must_use]
    pub fn new_channel_pool_initialised(
        funder_redacted: impl Into<String>,
        channel_count: usize,
        tx_hash_redacted: impl Into<String>,
        ledger: u32,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "pool.channel_pool_initialised".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::ChannelPoolInitialised {
                funder_redacted: funder_redacted.into(),
                channel_count,
                tx_hash_redacted: tx_hash_redacted.into(),
                ledger,
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs an `ApprovalAttested` audit entry.
    ///
    /// Emitted from the shared `stellar_agent_core::approval::attest` path
    /// after a pending approval's attestation (or recorded consent) is
    /// durably persisted. `approval_nonce` is truncated internally to its
    /// first 8 characters — callers MUST pass the full nonce, not a
    /// pre-truncated value.
    #[must_use]
    pub fn new_approval_attested(
        approval_kind: impl Into<String>,
        gated_tool: impl Into<String>,
        envelope_sha256_hex: Option<String>,
        approval_nonce: &str,
        origin: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "approval.attested".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::ApprovalAttested {
                approval_kind: approval_kind.into(),
                gated_tool: gated_tool.into(),
                envelope_sha256_hex,
                nonce_prefix: nonce_prefix8(approval_nonce),
                origin: origin.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs an `ApprovalRejected` audit entry.
    ///
    /// Emitted after a pending approval is replaced by a rejection
    /// tombstone. `approval_nonce` is truncated internally to its first 8
    /// characters — callers MUST pass the full nonce, not a pre-truncated
    /// value.
    #[must_use]
    pub fn new_approval_rejected(
        approval_kind: impl Into<String>,
        approval_nonce: &str,
        origin: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "approval.rejected".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::ApprovalRejected {
                approval_kind: approval_kind.into(),
                nonce_prefix: nonce_prefix8(approval_nonce),
                origin: origin.into(),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs an `ApprovalAttestedRemote` audit entry.
    ///
    /// Emitted after a remote-approval-surface attestation (or recorded
    /// consent) is durably persisted, from an operator identity
    /// authenticated by a WebAuthn passkey assertion rather than the OS
    /// process boundary. `approval_nonce` is truncated internally to its
    /// first 8 characters, and `operator_credential_id_b64url` is hashed
    /// internally into its redacted pseudonym — callers MUST pass the full
    /// nonce and the full credential ID, not pre-truncated or pre-hashed
    /// values.
    #[must_use]
    pub fn new_approval_attested_remote(
        approval_kind: impl Into<String>,
        gated_tool: impl Into<String>,
        envelope_sha256_hex: Option<String>,
        approval_nonce: &str,
        operator_credential_id_b64url: &str,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "approval.attested".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::ApprovalAttestedRemote {
                approval_kind: approval_kind.into(),
                gated_tool: gated_tool.into(),
                envelope_sha256_hex,
                nonce_prefix: nonce_prefix8(approval_nonce),
                operator_credential_id_redacted: pseudonymize_credential_id(
                    operator_credential_id_b64url,
                ),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Constructs an `ApprovalRejectedRemote` audit entry.
    ///
    /// Emitted after a pending approval is rejected by an operator
    /// authenticated over the remote-approval HTTP surface.
    /// `approval_nonce` is truncated internally to its first 8 characters,
    /// and `operator_credential_id_b64url` is hashed internally into its
    /// redacted pseudonym — callers MUST pass the full nonce and the full
    /// credential ID.
    #[must_use]
    pub fn new_approval_rejected_remote(
        approval_kind: impl Into<String>,
        approval_nonce: &str,
        operator_credential_id_b64url: &str,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: current_iso8601_utc(),
            tool: "approval.rejected".to_owned(),
            chain_id: None,
            arg_keys: vec![],
            arg_keys_truncated: None,
            truncated: false,
            envelope_hash: None,
            nonce_id: None,
            policy_decision: PolicyDecision::Allow,
            decision_reason: None,
            request_id: request_id.into(),
            event_kind: EventKind::ApprovalRejectedRemote {
                approval_kind: approval_kind.into(),
                nonce_prefix: nonce_prefix8(approval_nonce),
                operator_credential_id_redacted: pseudonymize_credential_id(
                    operator_credential_id_b64url,
                ),
            },
            previous_entry_hash: String::new(),
        }
    }

    /// Returns the canonical JSON bytes used as the hash-input body.
    ///
    /// The `previous_entry_hash` field is set to `""` (empty string) in the
    /// hash-input body so the hash does not depend on itself.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` if the entry cannot be serialised.
    pub fn canonical_json_body(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut body = Vec::new();
        self.canonical_json_write(&mut body)?;
        Ok(body)
    }

    /// Writes the canonical JSON bytes used as the hash-input body.
    ///
    /// The `previous_entry_hash` field is set to `""` (empty string) in the
    /// hash-input body so the hash does not depend on itself.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` if the entry cannot be serialised or if
    /// the supplied writer returns an I/O error.
    pub fn canonical_json_write<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> Result<(), serde_json::Error> {
        // Clone and set previous_entry_hash to empty string for body computation.
        let mut body = self.clone();
        body.previous_entry_hash = String::new();
        serde_json::to_writer(writer, &body)
    }

    /// Truncates `arg_keys` to fit within the `MAX_ENTRY_BYTES` budget.
    ///
    /// Called by the writer before serialising if the initial estimate exceeds
    /// the per-entry byte limit.  Sets `arg_keys_truncated` when truncation
    /// occurs.  Sets `truncated = true` if any key was dropped.
    ///
    /// Distinguishes serialisation errors (returned as `Err`) from oversized
    /// entries (handled by dropping keys).
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` only when `serde_json::to_vec` fails for
    /// a reason other than the entry being too large (e.g. a non-serialisable
    /// value in the entry).
    pub fn truncate_arg_keys_if_needed(&mut self) -> Result<(), serde_json::Error> {
        // First apply the hard cap on count.
        if self.arg_keys.len() > MAX_ARG_KEYS {
            let dropped = self.arg_keys.len() - MAX_ARG_KEYS;
            self.arg_keys.truncate(MAX_ARG_KEYS);
            self.arg_keys_truncated = Some(self.arg_keys_truncated.unwrap_or(0) + dropped);
            self.truncated = true;
        }

        // Then iteratively reduce until we fit within MAX_ENTRY_BYTES.
        loop {
            match serde_json::to_vec(self) {
                Ok(bytes) if bytes.len() <= MAX_ENTRY_BYTES => break,
                Ok(bytes) => {
                    // Oversized — drop a key and retry.
                    if self.arg_keys.is_empty() {
                        // No keys left to drop; the fixed-shape fields
                        // themselves exceed MAX_ENTRY_BYTES.  Set truncated
                        // and emit a warn so operators can detect entries
                        // with pathologically large tool/chain_id/etc. fields.
                        self.truncated = true;
                        tracing::warn!(
                            target: "stellar_agent_core::audit_log::entry",
                            entry_size = bytes.len(),
                            max = MAX_ENTRY_BYTES,
                            "audit entry exceeds MAX_ENTRY_BYTES after dropping all arg_keys"
                        );
                        break;
                    }
                    self.arg_keys.pop();
                    self.arg_keys_truncated = Some(self.arg_keys_truncated.unwrap_or(0) + 1);
                    self.truncated = true;
                }
                Err(e) => {
                    // Genuine serialisation failure — propagate.
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

fn validate_plugin_name(plugin_name: &str) -> Result<(), ValidationError> {
    let reason = if plugin_name.is_empty() {
        Some("empty")
    } else if plugin_name.len() > 64 {
        Some("too_long")
    } else if plugin_name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        None
    } else {
        Some("invalid_character")
    };

    match reason {
        Some(reason) => Err(ValidationError::InvalidPluginName {
            reason: reason.to_owned(),
        }),
        None => Ok(()),
    }
}

// ── Redaction helpers ─────────────────────────────────────────────────────────

/// Apply `decision_reason` redaction.
///
/// - Stellar G/C/T/M/P strkeys: first-5-last-5.
/// - 64-char hex transaction hashes: first-8-last-8.
///
/// Returns the redacted string.
#[must_use]
pub fn redact_decision_reason(reason: &str) -> String {
    let after_accounts = redact_strkey_account_ids(reason);
    redact_tx_hashes(&after_accounts)
}

/// Replace G-/C-/T-/M-/P-prefixed strkeys with first-5-last-5 in `input`.
///
/// Delegates to `audit_log::redact` so audit-log decision reasons and
/// observability span/event fields share the same first-5-last-5 rendering.
fn redact_strkey_account_ids(input: &str) -> String {
    crate::audit_log::redact::redact_account_strkeys_first5_last5_string(input)
}

/// Replace 64-character lowercase hex transaction hashes with
/// `<first8>...<last8>` in `input`.
fn redact_tx_hashes(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    if len < 64 {
        // 64: hex-encoded SHA-256 length (32 bytes × 2 hex chars per byte).
        return input.to_owned();
    }

    let mut output = String::with_capacity(len);
    let mut pos = 0usize;

    while pos < len {
        if pos + 64 <= len {
            let window = &bytes[pos..pos + 64];
            if window
                .iter()
                .all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                // Confirm this is NOT immediately preceded/followed by more hex
                // so we don't split longer sequences.
                let prev_ok = pos == 0 || !matches!(bytes[pos - 1], b'0'..=b'9' | b'a'..=b'f');
                let next_ok =
                    pos + 64 == len || !matches!(bytes[pos + 64], b'0'..=b'9' | b'a'..=b'f');
                if prev_ok && next_ok {
                    // first-8-last-8 redaction
                    let s = std::str::from_utf8(window).unwrap_or("");
                    output.push_str(&s[..8]);
                    output.push_str("...");
                    output.push_str(&s[56..64]);
                    pos += 64;
                    continue;
                }
            }
        }
        if let Some(ch) = input[pos..].chars().next() {
            output.push(ch);
            pos += ch.len_utf8();
        } else {
            break;
        }
    }
    output
}

/// Redacts a free-text rule name to `"<first3> len=N"` form.
///
/// Rule names are user-supplied free text that may contain identifying
/// information. The first 3 Unicode scalar values provide forensic correlation
/// (enough to distinguish "admin" from "payment" rules) while `len=N` is the
/// byte length and confirms the full name is unchanged without logging the
/// full string.
///
/// For names shorter than 3 chars the entire name is included (no truncation
/// risk — the name cannot be mistaken for a strkey or sensitive identifier).
///
/// # Examples
///
/// ```
/// # // Private function — tested via the public constructor tests.
/// // "admin-rule" → "adm len=10"
/// // "go"         → "go len=2"
/// ```
fn redact_free_text_name(name: &str) -> String {
    let prefix: String = name.chars().take(3).collect();
    format!("{prefix} len={}", name.len())
}

/// Redacts a base64url-encoded credential ID to `"<first5>...<last5>"` form.
///
/// Analogous to `redact_strkey_first5_last5` for account keys but adapted for
/// base64url credential IDs. The full credential ID is never written to the
/// audit log.
///
/// If the input is shorter than 10 base64url characters (< 7 raw bytes, which
/// cannot be a valid credential ID per CTAP2 minimum 16 bytes) the entire
/// string is returned as-is to prevent the `...<last5>` from aliasing the head.
fn redact_credential_id_b64url(id: &str) -> String {
    redact_first5_last5(id)
}

/// Truncates an approval nonce to its first 8 characters for forensic
/// correlation without persisting the full nonce value.
///
/// Returns the full string unchanged if it is shorter than 8 characters
/// (should not occur for a real `approval_nonce`, which is always exactly 22
/// base64url characters, but keeps this helper panic-free on malformed input).
fn nonce_prefix8(nonce: &str) -> String {
    nonce
        .get(..8)
        .map_or_else(|| nonce.to_owned(), ToOwned::to_owned)
}

/// Derives a stable, non-reversible per-operator pseudonym for a
/// remote-approval operator credential ID: the first 8 hex characters of
/// `SHA-256(credential_id_b64url)`.
///
/// Deterministic — the same credential ID always produces the same tag, so
/// audit rows from the same operator correlate — but one-way: the tag cannot
/// be inverted back to the credential ID. Distinct from
/// [`redact_credential_id_b64url`], which preserves a partial view of the
/// original string (first-5-last-5) rather than a hash; the audit-log
/// attribution field intentionally uses the non-reversible form because it
/// is persisted indefinitely in a hash-chained log that operators may share
/// for forensic review.
fn pseudonymize_credential_id(credential_id_b64url: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(credential_id_b64url.as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use crate::audit_log::redact::tests::{long_signed_payload_strkey, pre_auth_tx_strkey};
    use crate::audit_log::schema::SaInvocationResult;

    use super::*;

    const ACCOUNT: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const MUXED_ACCOUNT: &str =
        "MA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCICBKU";
    const SIGNED_PAYLOAD: &str =
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAACAAAAAABNWS";

    #[allow(
        clippy::too_many_arguments,
        reason = "test adapter keeps fixture construction readable"
    )]
    fn new_tool_invocation(
        tool: impl Into<String>,
        chain_id: impl IntoOptionalChainId,
        arg_keys: Vec<String>,
        envelope_hash: Option<String>,
        nonce_id: Option<String>,
        policy_decision: PolicyDecision,
        decision_reason: Option<String>,
        request_id: impl Into<String>,
    ) -> AuditEntry {
        let mut params =
            NewToolInvocation::new(tool, chain_id, arg_keys, policy_decision, request_id);
        params.envelope_hash = envelope_hash;
        params.nonce_id = nonce_id;
        params.decision_reason = decision_reason;
        AuditEntry::new_tool_invocation(params)
    }

    fn make_entry() -> AuditEntry {
        new_tool_invocation(
            "stellar_pay_commit",
            "stellar:testnet",
            vec!["destination".to_owned(), "amount".to_owned()],
            Some("sha256:abcdef01".to_owned()),
            Some("nonce0001".to_owned()),
            PolicyDecision::Allow,
            None,
            "req-1234",
        )
    }

    #[test]
    fn entry_tool_name() {
        assert_eq!(make_entry().tool, "stellar_pay_commit");
    }

    fn fix_kat_ts(entry: &mut AuditEntry) {
        entry.ts = "2026-04-29T00:00:00.000Z".to_owned();
    }

    fn decode_hex_literal(hex: &str) -> Vec<u8> {
        let compact: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(
            compact.len() % 2,
            0,
            "hex literal must have an even number of digits"
        );

        compact
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

    fn assert_canonical_body_hex(name: &str, entry: &AuditEntry, expected_hex: &str) {
        let body = entry.canonical_json_body().unwrap();
        let mut streamed = Vec::new();
        entry.canonical_json_write(&mut streamed).unwrap();
        assert_eq!(
            streamed, body,
            "streamed canonical body differs from canonical_json_body for {name}",
        );
        let expected = decode_hex_literal(expected_hex);

        assert_eq!(
            body,
            expected,
            "canonical body byte mismatch for {name} — field reordering or serialisation drift\ngot:      {}\nexpected: {}",
            std::str::from_utf8(&body).unwrap_or("<invalid utf8>"),
            std::str::from_utf8(&expected).unwrap_or("<invalid utf8>"),
        );
    }

    /// Known-answer tests (KATs) pinning exact canonical body bytes for every
    /// current [`EventKind`] variant plus max-size edge cases.
    ///
    /// These tests use byte-exact comparison to catch field-reordering, key
    /// renaming, or serialisation drift at the byte level — not just at the
    /// parsed-value level. Expected bytes are pinned as hex literals.
    #[test]
    fn canonical_body_byte_exact_kat() {
        let mut tool_invocation = new_tool_invocation(
            "test_tool",
            "stellar:testnet",
            vec!["param_a".to_owned()],
            None,
            None,
            PolicyDecision::Allow,
            None,
            "req-kat-tool",
            // previous_entry_hash defaults to "" from the constructor and is set
            // to "" in the canonical body — neither affects the expected bytes.
        );
        fix_kat_ts(&mut tool_invocation);

        let mut plugin_invoked = AuditEntry::new_plugin_invoked(
            "my-plugin",
            7,
            PolicyDecision::RequireApproval,
            42,
            "req-kat-plugin",
        )
        .expect("valid plugin name");
        fix_kat_ts(&mut plugin_invoked);

        let mut mlock_failed =
            AuditEntry::new_mlock_failed("default", "ENOMEM", Some(12), "req-kat-mlock");
        fix_kat_ts(&mut mlock_failed);

        let mut sa_raw_invocation = AuditEntry::new_sa_raw_invocation(
            "CDABC...12345",
            "sa.ok",
            Some("deadbeef".to_owned()),
            3,
            SaInvocationResult::Success,
            "stellar:testnet",
            "req-kat-sa-raw",
        );
        fix_kat_ts(&mut sa_raw_invocation);

        let mut smart_account_deployed = AuditEntry::new_smart_account_deployed(
            "CDABC...12345",
            "GAAAA...BBBBB",
            "06186e93...a56cb239",
            true,
            "deadbeef...cafebabe",
            100_000,
            "stellar:testnet",
            "req-kat-deploy",
        );
        fix_kat_ts(&mut smart_account_deployed);

        let mut sa_context_rule_created = AuditEntry::new_sa_context_rule_created(
            "CDABC...12345",
            42,
            "call_contract",
            2,
            5,
            Some(123_456),
            "stellar:testnet",
            "req-kat-rule-create",
            vec![], // pinned_verifier_wasm_hashes_first8 (empty → skipped in wire)
            vec![], // pinned_policy_wasm_hashes_first8 (empty → skipped in wire)
            false,  // mutable_override (false → skipped in wire)
            false,  // unknown_override (false → skipped in wire)
        );
        fix_kat_ts(&mut sa_context_rule_created);

        let mut sa_context_rule_deleted = AuditEntry::new_sa_context_rule_deleted(
            "CDABC...12345",
            42,
            "stellar:testnet",
            "req-kat-rule-delete",
        );
        fix_kat_ts(&mut sa_context_rule_deleted);

        let mut rotation_handoff = AuditEntry::new_rotation_handoff(
            "default.jsonl.20260429T000000000",
            "req-kat-rotation",
        );
        fix_kat_ts(&mut rotation_handoff);

        let mut max_arg_keys = new_tool_invocation(
            "test_tool",
            "stellar:testnet",
            (0..MAX_ARG_KEYS).map(|i| format!("k{i:02}")).collect(),
            None,
            None,
            PolicyDecision::Allow,
            None,
            "req-kat-max-args",
        );
        fix_kat_ts(&mut max_arg_keys);

        let cases = [
            (
                "tool_invocation",
                &tool_invocation,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a22746573745f746f6f6c222c22636861696e5f6964223a227374656c6c61723a746573746e6574222c226172675f6b657973223a5b22706172616d5f61225d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d746f6f6c222c226b696e64223a22746f6f6c5f696e766f636174696f6e222c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "plugin_invoked",
                &plugin_invoked,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a2261756469742e706c7567696e5f696e766f6b65642e6d792d706c7567696e222c226172675f6b657973223a5b5d2c22706f6c6963795f6465636973696f6e223a22726571756972655f617070726f76616c222c22726571756573745f6964223a227265712d6b61742d706c7567696e222c226b696e64223a22706c7567696e5f696e766f6b6564222c22706c7567696e5f6e616d65223a226d792d706c7567696e222c22657869745f636f6465223a372c226465636973696f6e223a22726571756972655f617070726f76616c222c226475726174696f6e5f6d73223a34322c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "wallet_mlock_failed",
                &mlock_failed,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a2277616c6c65742e6d6c6f636b5f6661696c6564222c226172675f6b657973223a5b5d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d6d6c6f636b222c226b696e64223a2277616c6c65745f6d6c6f636b5f6661696c6564222c2270726f66696c65223a2264656661756c74222c22726561736f6e223a22454e4f4d454d222c226572726e6f223a31322c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "sa_raw_invocation",
                &sa_raw_invocation,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a2273612e696e766f636174696f6e2e73612e6f6b222c22636861696e5f6964223a227374656c6c61723a746573746e6574222c226172675f6b657973223a5b5d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d73612d726177222c226b696e64223a2273615f7261775f696e766f636174696f6e222c22736d6172745f6163636f756e74223a2243444142432e2e2e3132333435222c22776972655f636f6465223a2273612e6f6b222c22617574685f6469676573745f707265666978223a226465616462656566222c22636f6e746578745f72756c655f6964735f636f756e74223a332c22726573756c74223a2273756363657373222c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "smart_account_deployed",
                &smart_account_deployed,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a2273612e736d6172745f6163636f756e745f6465706c6f796564222c22636861696e5f6964223a227374656c6c61723a746573746e6574222c226172675f6b657973223a5b5d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d6465706c6f79222c226b696e64223a22736d6172745f6163636f756e745f6465706c6f796564222c22736d6172745f6163636f756e74223a2243444142432e2e2e3132333435222c226465706c6f796572223a2247414141412e2e2e4242424242222c227761736d5f686173685f707265666978223a2230363138366539332e2e2e6135366362323339222c227761736d5f75706c6f61646564223a747275652c2274785f686173685f7265646163746564223a2264656164626565662e2e2e6361666562616265222c226c6564676572223a3130303030302c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "sa_context_rule_created",
                &sa_context_rule_created,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a2273612e636f6e746578745f72756c655f63726561746564222c22636861696e5f6964223a227374656c6c61723a746573746e6574222c226172675f6b657973223a5b5d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d72756c652d637265617465222c226b696e64223a2273615f636f6e746578745f72756c655f63726561746564222c22736d6172745f6163636f756e74223a2243444142432e2e2e3132333435222c2272756c655f6964223a34322c22636f6e746578745f74797065223a2263616c6c5f636f6e7472616374222c227369676e6572735f636f756e74223a322c22706f6c69636965735f636f756e74223a352c2276616c69645f756e74696c223a3132333435362c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "sa_context_rule_deleted",
                &sa_context_rule_deleted,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a2273612e636f6e746578745f72756c655f64656c65746564222c22636861696e5f6964223a227374656c6c61723a746573746e6574222c226172675f6b657973223a5b5d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d72756c652d64656c657465222c226b696e64223a2273615f636f6e746578745f72756c655f64656c65746564222c22736d6172745f6163636f756e74223a2243444142432e2e2e3132333435222c2272756c655f6964223a34322c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "audit_rotation_handoff",
                &rotation_handoff,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a2261756469742e726f746174696f6e5f68616e646f66665f746f222c226172675f6b657973223a5b5d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d726f746174696f6e222c226b696e64223a2261756469745f726f746174696f6e5f68616e646f6666222c226e6578745f66696c655f6e616d65223a2264656661756c742e6a736f6e6c2e323032363034323954303030303030303030222c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
            (
                "max_arg_keys",
                &max_arg_keys,
                "7b227473223a22323032362d30342d32395430303a30303a30302e3030305a222c22746f6f6c223a22746573745f746f6f6c222c22636861696e5f6964223a227374656c6c61723a746573746e6574222c226172675f6b657973223a5b226b3030222c226b3031222c226b3032222c226b3033222c226b3034222c226b3035222c226b3036222c226b3037222c226b3038222c226b3039222c226b3130222c226b3131222c226b3132222c226b3133222c226b3134222c226b3135222c226b3136222c226b3137222c226b3138222c226b3139222c226b3230222c226b3231222c226b3232222c226b3233222c226b3234222c226b3235222c226b3236222c226b3237222c226b3238222c226b3239222c226b3330222c226b3331222c226b3332222c226b3333222c226b3334222c226b3335222c226b3336222c226b3337222c226b3338222c226b3339222c226b3430222c226b3431222c226b3432222c226b3433222c226b3434222c226b3435222c226b3436222c226b3437222c226b3438222c226b3439222c226b3530222c226b3531222c226b3532222c226b3533222c226b3534222c226b3535222c226b3536222c226b3537222c226b3538222c226b3539222c226b3630222c226b3631222c226b3632222c226b3633225d2c22706f6c6963795f6465636973696f6e223a22616c6c6f77222c22726571756573745f6964223a227265712d6b61742d6d61782d61726773222c226b696e64223a22746f6f6c5f696e766f636174696f6e222c2270726576696f75735f656e7472795f68617368223a22227d",
            ),
        ];

        for (name, entry, expected_hex) in cases {
            assert_canonical_body_hex(name, entry, expected_hex);
        }
    }

    #[test]
    fn canonical_body_truncation_preserves_utf8_codepoints() {
        let overflow_key = "y".repeat(2_000);
        let fitting_unicode_key = (0..MAX_ENTRY_BYTES)
            .rev()
            .map(|ascii_len| format!("{}é", "x".repeat(ascii_len)))
            .find(|key| {
                let mut candidate = new_tool_invocation(
                    "test_tool",
                    "stellar:testnet",
                    vec![key.clone(), overflow_key.clone()],
                    None,
                    None,
                    PolicyDecision::Allow,
                    None,
                    "req-kat-utf8",
                );
                fix_kat_ts(&mut candidate);
                candidate.truncate_arg_keys_if_needed().unwrap();
                candidate.arg_keys == vec![key.clone()]
                    && serde_json::to_vec(&candidate).unwrap().len() <= MAX_ENTRY_BYTES
            })
            .expect("must find a unicode-bearing key that fits after truncation metadata");

        let mut entry = new_tool_invocation(
            "test_tool",
            "stellar:testnet",
            vec![fitting_unicode_key.clone(), overflow_key],
            None,
            None,
            PolicyDecision::Allow,
            None,
            "req-kat-utf8",
        );
        fix_kat_ts(&mut entry);

        assert!(
            serde_json::to_vec(&entry).unwrap().len() > MAX_ENTRY_BYTES,
            "fixture must cross the byte limit only after adding the overflow key"
        );

        entry.truncate_arg_keys_if_needed().unwrap();
        let body = entry.canonical_json_body().unwrap();
        let rendered = std::str::from_utf8(&body).expect("canonical body must remain valid UTF-8");

        assert!(entry.truncated, "fixture must exercise truncation");
        assert_eq!(entry.arg_keys, vec![fitting_unicode_key]);
        assert_eq!(entry.arg_keys_truncated, Some(1));
        assert!(
            rendered.contains("\\u00e9") || rendered.contains('é'),
            "canonical body should preserve the boundary UTF-8 code point as a whole escaped or literal character: {rendered}"
        );
    }

    #[test]
    fn canonical_json_body_excludes_previous_hash() {
        let entry = make_entry();
        let body = entry.canonical_json_body().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // previous_entry_hash must be empty string in the canonical body.
        let prev = v.get("previous_entry_hash").unwrap();
        assert!(
            prev.as_str().unwrap_or("x").is_empty(),
            "canonical body previous_entry_hash must be empty string, got: {prev:?}"
        );
    }

    #[test]
    fn internal_event_omits_absent_chain_id_from_json() {
        let entry = AuditEntry::new_mlock_failed("default", "ENOMEM", Some(12), "req");
        let value = serde_json::to_value(entry).unwrap();
        assert!(
            value.get("chain_id").is_none(),
            "internal audit events must omit absent chain_id, got {value:?}"
        );
    }

    #[test]
    fn chain_scoped_event_serialises_chain_id() {
        let entry = make_entry();
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(
            value.get("chain_id").and_then(serde_json::Value::as_str),
            Some("stellar:testnet")
        );
    }

    #[test]
    fn truncate_arg_keys_no_op_when_small() {
        let mut entry = make_entry();
        entry.truncate_arg_keys_if_needed().unwrap();
        assert!(entry.arg_keys_truncated.is_none());
        assert_eq!(entry.arg_keys.len(), 2);
    }

    #[test]
    fn truncate_arg_keys_over_max_count() {
        let mut entry = make_entry();
        entry.arg_keys = (0..100).map(|i| format!("key_{i}")).collect();
        entry.truncate_arg_keys_if_needed().unwrap();
        assert!(entry.arg_keys.len() <= MAX_ARG_KEYS);
        assert!(entry.arg_keys_truncated.is_some());
        assert!(entry.truncated, "truncated flag must be set");
    }

    #[test]
    fn truncate_sets_truncated_flag() {
        let mut entry = make_entry();
        // Large enough key names to force truncation by byte count.
        let big_key = "k".repeat(200);
        entry.arg_keys = (0..30).map(|_| big_key.clone()).collect();
        entry.truncate_arg_keys_if_needed().unwrap();
        assert!(
            entry.truncated,
            "truncated flag must be set when bytes overflow"
        );
    }

    /// When an entry exceeds MAX_ENTRY_BYTES even after dropping all arg_keys,
    /// `truncated` is set to `true`.  The test also verifies the function
    /// returns `Ok` (no panic / error for this case).
    #[test]
    fn entry_exceeds_max_with_no_arg_keys_sets_truncated() {
        // Construct an entry whose tool name alone exceeds MAX_ENTRY_BYTES.
        let mut entry = new_tool_invocation(
            "x".repeat(MAX_ENTRY_BYTES + 100),
            "stellar:testnet",
            vec![],
            None,
            None,
            PolicyDecision::Allow,
            None,
            "req-oversized",
        );
        let result = entry.truncate_arg_keys_if_needed();
        assert!(
            result.is_ok(),
            "must not error when entry is oversized: {result:?}"
        );
        assert!(
            entry.truncated,
            "truncated flag must be set when entry exceeds MAX_ENTRY_BYTES with no arg_keys"
        );
    }

    #[test]
    fn set_decision_reason_redacts_post_construction_value() {
        let mut entry = make_entry();

        entry.set_decision_reason(Some(format!("destination={ACCOUNT} approved")));

        let reason = entry.decision_reason().unwrap();
        assert_eq!(reason, "destination=GA5ZS...4KZVN approved");
        assert!(
            !reason.contains(ACCOUNT),
            "full account strkey must not be exposed after setter mutation"
        );
    }

    #[test]
    fn redact_decision_reason_no_op_on_plain() {
        let r = redact_decision_reason("operation succeeded");
        assert_eq!(r, "operation succeeded");
    }

    #[test]
    fn redact_decision_reason_redacts_mixed_g_m_p_strkeys() {
        let reason = format!("g={ACCOUNT} m={MUXED_ACCOUNT} p={SIGNED_PAYLOAD}");

        let out = redact_decision_reason(&reason);

        assert_eq!(out, "g=GA5ZS...4KZVN m=MA3D5...ICBKU p=PA7QY...ABNWS");
    }

    #[test]
    fn redact_decision_reason_redacts_pre_auth_tx_strkey() {
        let pre_auth_tx = pre_auth_tx_strkey();
        assert_eq!(pre_auth_tx.len(), 56);
        let reason = format!("signer={pre_auth_tx}");

        let out = redact_decision_reason(&reason);

        assert_eq!(
            out,
            format!("signer={}...{}", &pre_auth_tx[..5], &pre_auth_tx[51..])
        );
    }

    #[test]
    fn redact_decision_reason_redacts_165_char_signed_payload() {
        let signed_payload = long_signed_payload_strkey();
        assert_eq!(signed_payload.len(), 165);
        let reason = format!("signer={signed_payload}");

        let out = redact_decision_reason(&reason);

        assert_eq!(
            out,
            format!(
                "signer={}...{}",
                &signed_payload[..5],
                &signed_payload[160..]
            )
        );
        assert!(
            !out.contains(&signed_payload),
            "full signed-payload strkey must be redacted"
        );
    }

    #[test]
    fn iso8601_format() {
        use crate::timefmt::current_iso8601_utc;
        let ts = current_iso8601_utc();
        // Should be YYYY-MM-DDTHH:MM:SS.mmmZ
        assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
        assert_eq!(ts.len(), 24, "length must be 24: {ts}");
    }

    #[test]
    fn redact_tx_hash_in_reason() {
        // 64 lowercase hex chars.
        let hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let reason = format!("tx hash={hash} rejected");
        let out = redact_decision_reason(&reason);
        assert!(!out.contains(hash), "full hash must be redacted: {out}");
        assert!(out.contains("a1b2c3d4"), "first-8 must be present: {out}");
        assert!(out.contains("6a1b2"), "last-8 chars must be present: {out}");
    }

    #[test]
    fn rotation_handoff_entry_has_event_kind() {
        let entry = AuditEntry::new_rotation_handoff("default.jsonl.20260428", "req");
        assert_eq!(entry.tool, "audit.rotation_handoff_to");
        assert!(matches!(
            entry.event_kind,
            EventKind::AuditRotationHandoff { .. }
        ));
        // previous_entry_hash is populated by the writer, not the constructor.
        assert!(entry.previous_entry_hash.is_empty());
    }

    #[test]
    fn mlock_failed_entry() {
        let entry = AuditEntry::new_mlock_failed("default", "ENOMEM", Some(12), "req");
        assert_eq!(entry.tool, "wallet.mlock_failed");
        assert!(matches!(
            entry.event_kind,
            EventKind::WalletMlockFailed { .. }
        ));
        assert!(entry.previous_entry_hash.is_empty());
    }

    #[test]
    fn plugin_invoked_constructor() {
        let entry =
            AuditEntry::new_plugin_invoked("my-plugin", 0, PolicyDecision::Allow, 42, "req-plugin")
                .expect("valid plugin name");
        assert_eq!(entry.tool, "audit.plugin_invoked.my-plugin");
        assert!(matches!(entry.event_kind, EventKind::PluginInvoked { .. }));
        assert!(entry.previous_entry_hash.is_empty());
    }

    #[test]
    fn plugin_invoked_accepts_max_length_name() {
        let plugin_name = "a".repeat(64);
        let entry = AuditEntry::new_plugin_invoked(
            plugin_name.clone(),
            0,
            PolicyDecision::Allow,
            42,
            "req-plugin",
        )
        .expect("64-character plugin name must be accepted");

        assert_eq!(entry.tool, format!("audit.plugin_invoked.{plugin_name}"));
    }

    #[test]
    fn plugin_invoked_rejects_empty_name() {
        let err = AuditEntry::new_plugin_invoked("", 0, PolicyDecision::Allow, 42, "req-plugin")
            .expect_err("empty plugin name must be rejected");

        assert!(matches!(
            err,
            ValidationError::InvalidPluginName { ref reason } if reason == "empty"
        ));
    }

    #[test]
    fn plugin_invoked_rejects_invalid_character() {
        for plugin_name in [
            "bad.name",
            "bad/name",
            "bad\"name",
            "bad\\name",
            "bad\nname",
        ] {
            let err = AuditEntry::new_plugin_invoked(
                plugin_name,
                0,
                PolicyDecision::Allow,
                42,
                "req-plugin",
            )
            .expect_err("invalid plugin character must be rejected");

            assert!(matches!(
                err,
                ValidationError::InvalidPluginName { ref reason } if reason == "invalid_character"
            ));
        }
    }

    #[test]
    fn plugin_invoked_rejects_overlong_name() {
        let plugin_name = "a".repeat(65);
        let err =
            AuditEntry::new_plugin_invoked(plugin_name, 0, PolicyDecision::Allow, 42, "req-plugin")
                .expect_err("65-character plugin name must be rejected");

        assert!(matches!(
            err,
            ValidationError::InvalidPluginName { ref reason } if reason == "too_long"
        ));
    }

    /// `new_sa_raw_invocation` must set `tool = "sa.invocation.<wire_code>"` and
    /// produce a `SaRawInvocation` event kind with all fields plumbed through.
    #[test]
    fn sa_raw_invocation_constructor_shape() {
        let entry = AuditEntry::new_sa_raw_invocation(
            "CDABC...12345",
            "sa.deployment_failed",
            Some("deadbeef".to_owned()),
            3u32,
            SaInvocationResult::PreSubmissionRefused,
            "stellar:testnet",
            "req-sa-001",
        );
        assert_eq!(entry.tool, "sa.invocation.sa.deployment_failed");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-sa-001");
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SaRawInvocation {
            smart_account,
            wire_code,
            auth_digest_prefix,
            context_rule_ids_count,
            result,
        } = &entry.event_kind
        else {
            panic!("expected SaRawInvocation; got: {:?}", entry.event_kind);
        };
        assert_eq!(smart_account, "CDABC...12345");
        assert_eq!(wire_code, "sa.deployment_failed");
        assert_eq!(auth_digest_prefix.as_deref(), Some("deadbeef"));
        assert_eq!(*context_rule_ids_count, 3);
        assert!(matches!(result, SaInvocationResult::PreSubmissionRefused));
    }

    /// `new_smart_account_deployed` must set `tool = "sa.smart_account_deployed"` and
    /// produce a `SmartAccountDeployed` event kind with all fields plumbed through.
    #[test]
    fn smart_account_deployed_constructor_shape() {
        let entry = AuditEntry::new_smart_account_deployed(
            "CDABC...12345",
            "GAAAA...BBBBB",
            "06186e93...a56cb239",
            true,
            "deadbeef...cafebabe",
            100_000u32,
            "stellar:testnet",
            "req-deploy-001",
        );
        assert_eq!(entry.tool, "sa.smart_account_deployed");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-deploy-001");
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SmartAccountDeployed {
            smart_account,
            deployer,
            wasm_hash_prefix,
            wasm_uploaded,
            tx_hash_redacted,
            ledger,
        } = &entry.event_kind
        else {
            panic!("expected SmartAccountDeployed; got: {:?}", entry.event_kind);
        };
        assert_eq!(smart_account, "CDABC...12345");
        assert_eq!(deployer, "GAAAA...BBBBB");
        assert_eq!(wasm_hash_prefix, "06186e93...a56cb239");
        assert!(*wasm_uploaded);
        assert_eq!(tx_hash_redacted, "deadbeef...cafebabe");
        assert_eq!(*ledger, 100_000u32);
    }

    /// `new_passkey_registered` must set `tool = "sa.passkey_registered"`,
    /// produce a `PasskeyRegistered` event kind, and redact the credential ID
    /// to first-5-last-5 base64url form.
    #[test]
    fn passkey_registered_constructor_shape() {
        // A realistic base64url credential_id: 22+ chars (16 raw bytes min).
        let raw_id = "AABBCCDDEEFFGGHHIIJJKK";
        let entry = AuditEntry::new_passkey_registered(
            "my-passkey",
            raw_id,
            "127.0.0.1",
            "registered",
            "req-passkey-001",
        );
        assert_eq!(entry.tool, "sa.passkey_registered");
        assert!(
            entry.chain_id.is_none(),
            "chain_id must be None: {:?}",
            entry.chain_id
        );
        assert_eq!(entry.request_id, "req-passkey-001");
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::PasskeyRegistered {
            credential_name,
            credential_id_redacted,
            rp_id,
            status,
        } = &entry.event_kind
        else {
            panic!("expected PasskeyRegistered; got: {:?}", entry.event_kind);
        };
        assert_eq!(credential_name, "my-passkey");
        assert_eq!(rp_id, "127.0.0.1");
        assert_eq!(status, "registered");
        // Credential ID must be redacted: first-5-last-5 base64url with "..." separator.
        // "AABBCCDDEEFFGGHHIIJJKK" (22 chars): first 5 = "AABBC", last 5 = "IJJKK".
        assert_eq!(
            credential_id_redacted, "AABBC...IJJKK",
            "credential_id_redacted must be first-5...last-5 of raw_id"
        );
        assert!(
            credential_id_redacted.contains("..."),
            "credential_id_redacted must contain '...': {credential_id_redacted}"
        );
        // The full raw ID must NOT appear.
        assert!(
            !credential_id_redacted.contains(raw_id),
            "full credential_id must not appear in audit log: {credential_id_redacted}"
        );
    }

    /// `redact_credential_id_b64url` produces first-5...last-5 for a typical
    /// 22-char base64url credential ID.
    ///
    /// "AABBCCDDEEFFGGHHIIJJKK" (22 chars): first 5 = "AABBC", last 5 = "IJJKK".
    #[test]
    fn redact_credential_id_b64url_typical() {
        let id = "AABBCCDDEEFFGGHHIIJJKK"; // 22 chars
        let redacted = redact_credential_id_b64url(id);
        assert_eq!(redacted, "AABBC...IJJKK");
    }

    /// Short inputs (< 10 chars) are returned unmodified.
    #[test]
    fn redact_credential_id_b64url_short_passthrough() {
        let id = "ABCD"; // 4 chars — below minimum
        let redacted = redact_credential_id_b64url(id);
        assert_eq!(redacted, "ABCD");
    }

    /// `pseudonymize_credential_id` produces a deterministic 8-hex-character
    /// tag and never leaks the raw credential ID substring into its output.
    #[test]
    fn pseudonymize_credential_id_is_deterministic_and_redacted() {
        let id = "enrolled-operator-cred-id";
        let tag1 = pseudonymize_credential_id(id);
        let tag2 = pseudonymize_credential_id(id);
        assert_eq!(tag1, tag2, "same credential ID must produce the same tag");
        assert_eq!(tag1.len(), 8, "tag must be exactly 8 hex characters");
        assert!(
            tag1.chars().all(|c| c.is_ascii_hexdigit()),
            "tag must be lowercase hex: {tag1}"
        );
        assert!(
            !tag1.contains(id),
            "raw credential ID must not appear in its pseudonym"
        );
    }

    /// Distinct credential IDs produce distinct tags (no trivial collision
    /// for adjacent test-fixture-shaped inputs).
    #[test]
    fn pseudonymize_credential_id_differs_across_distinct_ids() {
        let tag_a = pseudonymize_credential_id("operator-credential-a");
        let tag_b = pseudonymize_credential_id("operator-credential-b");
        assert_ne!(tag_a, tag_b, "distinct credential IDs must not collide");
    }

    /// `new_approval_attested_remote` hashes the credential ID into the
    /// redacted pseudonym rather than storing it verbatim, and truncates the
    /// nonce exactly as `new_approval_attested` does.
    #[test]
    fn new_approval_attested_remote_hashes_credential_id() {
        let entry = AuditEntry::new_approval_attested_remote(
            "PaymentSimulated",
            "stellar_pay_commit",
            Some("a".repeat(64)),
            "AAAAAAAAAAAAAAAAAAAAAA",
            "enrolled-operator-cred-id",
            "req-remote-attest-001",
        );
        assert_eq!(entry.tool, "approval.attested");
        let EventKind::ApprovalAttestedRemote {
            nonce_prefix,
            operator_credential_id_redacted,
            ..
        } = &entry.event_kind
        else {
            panic!("expected ApprovalAttestedRemote");
        };
        assert_eq!(nonce_prefix, "AAAAAAAA");
        assert_eq!(
            *operator_credential_id_redacted,
            pseudonymize_credential_id("enrolled-operator-cred-id")
        );
        assert!(!operator_credential_id_redacted.contains("enrolled-operator-cred-id"));
    }

    /// `new_approval_rejected_remote` mirrors the same hashing and
    /// truncation discipline.
    #[test]
    fn new_approval_rejected_remote_hashes_credential_id() {
        let entry = AuditEntry::new_approval_rejected_remote(
            "PaymentSimulated",
            "BBBBBBBBBBBBBBBBBBBBBB",
            "enrolled-operator-cred-id",
            "req-remote-reject-001",
        );
        assert_eq!(entry.tool, "approval.rejected");
        let EventKind::ApprovalRejectedRemote {
            nonce_prefix,
            operator_credential_id_redacted,
            ..
        } = &entry.event_kind
        else {
            panic!("expected ApprovalRejectedRemote");
        };
        assert_eq!(nonce_prefix, "BBBBBBBB");
        assert_eq!(
            *operator_credential_id_redacted,
            pseudonymize_credential_id("enrolled-operator-cred-id")
        );
    }

    /// `new_passkey_registered` with `timeout` status round-trips through
    /// the constructor correctly.
    #[test]
    fn passkey_registered_timeout_constructor() {
        let entry = AuditEntry::new_passkey_registered(
            "test-key",
            "AABBCCDDEEFFGGHHIIJJKK",
            "localhost",
            "timeout",
            "req-timeout-001",
        );
        assert_eq!(entry.tool, "sa.passkey_registered");
        let EventKind::PasskeyRegistered { status, .. } = &entry.event_kind else {
            panic!("expected PasskeyRegistered; got: {:?}", entry.event_kind);
        };
        assert_eq!(status, "timeout");
    }

    /// `new_passkey_assertion` must set `tool = "sa.passkey_assertion"`,
    /// produce a `PasskeyAssertion` event kind, and redact credential ID,
    /// smart_account, and auth digest to first-5-last-5 form.
    #[test]
    fn passkey_assertion_constructor_shape() {
        let raw_id = "AABBCCDDEEFFGGHHIIJJKK";
        // 64-char hex for a 32-byte auth digest.
        let raw_digest_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        // A 56-char C-strkey (typical length for a Soroban contract address).
        let raw_smart_account = "CDEPLOY1ABCDE2FGHIJ3KLMNO4PQRST5UVWXY6ZA7BCDE8FGHIJ9KLMNO";
        let entry = AuditEntry::new_passkey_assertion(
            "my-passkey",
            raw_id,
            "localhost",
            raw_smart_account,
            raw_digest_hex,
            1_747_000_000_000_u64,
            "success",
            "req-assertion-001",
        );
        assert_eq!(entry.tool, "sa.passkey_assertion");
        assert!(entry.chain_id.is_none(), "chain_id must be None");
        assert_eq!(entry.request_id, "req-assertion-001");
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::PasskeyAssertion {
            credential_name,
            credential_id_redacted,
            rp_id,
            smart_account_redacted,
            auth_digest_redacted,
            signed_at_unix_ms,
            result,
        } = &entry.event_kind
        else {
            panic!("expected PasskeyAssertion; got: {:?}", entry.event_kind);
        };
        assert_eq!(credential_name, "my-passkey");
        assert_eq!(rp_id, "localhost");
        assert_eq!(result, "success");
        assert_eq!(*signed_at_unix_ms, 1_747_000_000_000_u64);
        // Credential ID: "AABBCCDDEEFFGGHHIIJJKK" (22 chars): first 5 = "AABBC", last 5 = "IJJKK".
        assert_eq!(
            credential_id_redacted, "AABBC...IJJKK",
            "credential_id_redacted must be first-5...last-5"
        );
        assert!(
            !credential_id_redacted.contains(raw_id),
            "full credential_id must not appear in log"
        );
        // Smart account: first 5 of raw_smart_account and last 5.
        let sa_head = &raw_smart_account[..5];
        let sa_tail = &raw_smart_account[raw_smart_account.len() - 5..];
        assert!(
            smart_account_redacted.starts_with(sa_head),
            "smart_account_redacted must start with {sa_head}: {smart_account_redacted}"
        );
        assert!(
            smart_account_redacted.ends_with(sa_tail),
            "smart_account_redacted must end with {sa_tail}: {smart_account_redacted}"
        );
        assert!(
            !smart_account_redacted.contains(raw_smart_account),
            "full smart_account must not appear in log"
        );
        // Auth digest hex (64 chars): first 5 = "abcde", last 5 = "56789".
        assert_eq!(
            auth_digest_redacted, "abcde...56789",
            "auth_digest_redacted must be first-5...last-5 of hex digest"
        );
        assert!(
            !auth_digest_redacted.contains(raw_digest_hex),
            "full auth digest must not appear in log"
        );
    }

    /// `new_passkey_assertion` with `failure:timeout` result round-trips correctly.
    #[test]
    fn passkey_assertion_failure_timeout_constructor() {
        let entry = AuditEntry::new_passkey_assertion(
            "test-key",
            "AABBCCDDEEFFGGHHIIJJKK",
            "localhost",
            "",
            "",
            1_747_000_000_001_u64,
            "failure:timeout",
            "req-timeout-assert-001",
        );
        assert_eq!(entry.tool, "sa.passkey_assertion");
        let EventKind::PasskeyAssertion { result, .. } = &entry.event_kind else {
            panic!("expected PasskeyAssertion; got: {:?}", entry.event_kind);
        };
        assert_eq!(result, "failure:timeout");
    }

    /// `new_passkey_assertion` round-trips through JSON serialisation.
    #[test]
    fn passkey_assertion_json_round_trip() {
        let entry = AuditEntry::new_passkey_assertion(
            "key-rt",
            "AABBCCDDEEFFGGHHIIJJKK",
            "localhost",
            "CDEPLOY1ABCDE2FGHIJ3KLMNO4PQRST",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            1_747_000_000_002_u64,
            "success",
            "req-rt-001",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(
            json.contains("sa.passkey_assertion"),
            "tool field missing from JSON"
        );
        // EventKind is serialised with serde tag = "kind", rename_all = "snake_case",
        // so the PasskeyAssertion variant appears as `"kind":"passkey_assertion"`.
        assert!(
            json.contains(r#""kind":"passkey_assertion""#),
            "event_kind variant missing from JSON"
        );
        assert!(
            json.contains("smart_account_redacted"),
            "smart_account_redacted field missing from JSON"
        );
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert_eq!(back.tool, "sa.passkey_assertion");
        assert!(matches!(
            back.event_kind,
            EventKind::PasskeyAssertion { .. }
        ));
    }

    /// Legacy `PasskeyAssertion` JSON without `smart_account_redacted` must
    /// deserialise cleanly (field defaults to `""` via `#[serde(default)]`).
    /// Older log entries lack the `smart_account_redacted` key and must load
    /// without error, producing an empty string for that field.
    ///
    /// `EventKind` is `#[serde(flatten)]` + `#[serde(tag = "kind")]` so the
    /// `"kind"` discriminant and all variant fields appear at the top level of
    /// the AuditEntry JSON (not nested under `"event_kind"`).
    #[test]
    fn passkey_assertion_legacy_json_no_smart_account_deserialises() {
        // A legacy JSON string without the smart_account_redacted field.
        // Note: event_kind is #[serde(flatten)] so "kind" + variant fields are
        // top-level keys in the AuditEntry JSON, not nested under "event_kind".
        let legacy_json = r#"{
            "ts": "2026-05-14T12:00:00.000Z",
            "tool": "sa.passkey_assertion",
            "arg_keys": [],
            "truncated": false,
            "policy_decision": "allow",
            "request_id": "legacy-req-001",
            "previous_entry_hash": "",
            "kind": "passkey_assertion",
            "credential_name": "old-key",
            "credential_id_redacted": "AABBC...IJJKK",
            "rp_id": "localhost",
            "auth_digest_redacted": "abcde...56789",
            "signed_at_unix_ms": 1747000000000,
            "result": "success"
        }"#;
        let entry: AuditEntry = serde_json::from_str(legacy_json)
            .expect("legacy PasskeyAssertion must deserialise without smart_account_redacted");
        let EventKind::PasskeyAssertion {
            smart_account_redacted,
            credential_name,
            result,
            ..
        } = &entry.event_kind
        else {
            panic!("expected PasskeyAssertion; got: {:?}", entry.event_kind);
        };
        assert_eq!(
            smart_account_redacted, "",
            "legacy entry must default smart_account_redacted to empty string"
        );
        assert_eq!(credential_name, "old-key");
        assert_eq!(result, "success");
    }

    /// `new_passkey_assertion` must apply first-5-last-5 redaction internally;
    /// callers must NOT pre-redact the `smart_account` argument.
    ///
    /// Passing an already-redacted value (e.g. `"CDEPL...LMNO4"`) must produce
    /// a double-redacted value (e.g. `"CDEPL...MNO4"`), which is incorrect.
    /// This test documents the expected behaviour: the constructor is the single
    /// redaction point.
    #[test]
    fn passkey_assertion_smart_account_redaction_is_applied_internally() {
        let raw_smart_account = "CDEPLOY1ABCDE2FGHIJ3KLMNO4PQRST5UVWXY6ZA";
        let entry = AuditEntry::new_passkey_assertion(
            "key",
            "AABBCCDDEEFFGGHHIIJJKK",
            "localhost",
            raw_smart_account,
            "",
            0,
            "success",
            "req-redact-001",
        );
        let EventKind::PasskeyAssertion {
            smart_account_redacted,
            ..
        } = &entry.event_kind
        else {
            panic!("expected PasskeyAssertion");
        };
        // Redaction must produce first-5...last-5 of the raw input.
        let expected_head = &raw_smart_account[..5];
        let expected_tail = &raw_smart_account[raw_smart_account.len() - 5..];
        assert!(
            smart_account_redacted.starts_with(expected_head),
            "must start with {expected_head}: {smart_account_redacted}"
        );
        assert!(
            smart_account_redacted.ends_with(expected_tail),
            "must end with {expected_tail}: {smart_account_redacted}"
        );
        assert!(
            !smart_account_redacted.contains(raw_smart_account),
            "full smart_account must not appear: {smart_account_redacted}"
        );
    }

    /// `new_sa_verifier_migrated` must set `tool = "sa.verifier_migrated"` and
    /// produce a `SaVerifierMigrated` event kind with all fields plumbed through.
    #[test]
    fn sa_verifier_migrated_constructor_shape() {
        let entry = AuditEntry::new_sa_verifier_migrated(
            3u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "deadbeef",
            "cafebabe",
            "aabb1122...ccdd3344",
            "stellar:testnet",
            "req-migrate-001",
        );
        assert_eq!(entry.tool, "sa.verifier_migrated");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-migrate-001");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SaVerifierMigrated {
            rule_id,
            smart_account_redacted,
            from_hash_first8,
            to_hash_first8,
            tx_hash_redacted,
        } = &entry.event_kind
        else {
            panic!("expected SaVerifierMigrated; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 3u32);
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(from_hash_first8, "deadbeef");
        assert_eq!(to_hash_first8, "cafebabe");
        assert_eq!(tx_hash_redacted, "aabb1122...ccdd3344");
    }

    /// `new_sa_verifier_diversification_override` must set
    /// `tool = "sa.verifier_diversification_override"` and produce a
    /// `SaVerifierDiversificationOverride` event kind with all fields plumbed
    /// through.
    #[test]
    fn sa_verifier_diversification_override_constructor_shape() {
        let entry = AuditEntry::new_sa_verifier_diversification_override(
            7u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "deadbeef",
            100_000_000_000_i64,
            "2026-05-20T12:34:56.000Z",
            "stellar:testnet",
            "req-divover-001",
        );
        assert_eq!(entry.tool, "sa.verifier_diversification_override");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-divover-001");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SaVerifierDiversificationOverride {
            rule_id,
            smart_account_redacted,
            verifier_hash_first8,
            observed_value_threshold_stroops,
            override_acknowledged_at,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaVerifierDiversificationOverride; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(*rule_id, 7u32);
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(verifier_hash_first8, "deadbeef");
        assert_eq!(*observed_value_threshold_stroops, 100_000_000_000_i64);
        assert_eq!(override_acknowledged_at, "2026-05-20T12:34:56.000Z");
    }

    /// `new_sa_verifier_allowlist_advisory` must set
    /// `tool = "sa.verifier_allowlist_advisory"` and produce a
    /// `SaVerifierAllowlistAdvisory` event kind with all fields plumbed through.
    ///
    /// Tests both `Revoked` and `Retired` advisory status values.
    #[test]
    fn sa_verifier_allowlist_advisory_constructor_shape() {
        use crate::audit_log::schema::VerifierAdvisoryKind;

        for (advised_status, expected_display) in &[
            (VerifierAdvisoryKind::Revoked, "revoked"),
            (VerifierAdvisoryKind::Retired, "retired"),
        ] {
            let entry = AuditEntry::new_sa_verifier_allowlist_advisory(
                2u32,
                RedactedStrkey::from_already_redacted("CDABC...12345"),
                "aabbccdd",
                *advised_status,
                "stellar:testnet",
                "req-advisory-001",
            );
            assert_eq!(
                entry.tool, "sa.verifier_allowlist_advisory",
                "tool name for advised_status={expected_display}"
            );
            assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
            assert_eq!(entry.request_id, "req-advisory-001");
            assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
            assert!(entry.previous_entry_hash.is_empty());
            let EventKind::SaVerifierAllowlistAdvisory {
                rule_id,
                smart_account_redacted,
                revoked_hash_first8,
                advised_status: status_field,
            } = &entry.event_kind
            else {
                panic!(
                    "expected SaVerifierAllowlistAdvisory; got: {:?}",
                    entry.event_kind
                );
            };
            assert_eq!(*rule_id, 2u32);
            assert_eq!(smart_account_redacted, "CDABC...12345");
            assert_eq!(revoked_hash_first8, "aabbccdd");
            assert_eq!(status_field, advised_status);
        }
    }

    // ── Sentinel-row fallback unit tests ─────────────────────────────────────

    /// Verify that the normal path (small inputs) produces a non-sentinel entry
    /// within `MAX_ENTRY_BYTES`.
    #[test]
    fn new_sa_multicall_unregistered_force_normal_fits() {
        let entry = AuditEntry::new_sa_multicall_unregistered_force(
            "testnet",
            "CABC12345",
            "abc123def456",
            vec!["warn1".to_owned(), "warn2".to_owned()],
            None::<String>,
            "req-normal-fits",
        );
        let json = serde_json::to_vec(&entry).expect("serialisation must not fail");
        assert!(
            json.len() <= MAX_ENTRY_BYTES,
            "normal entry must fit within MAX_ENTRY_BYTES; got {} bytes",
            json.len()
        );
        assert!(
            !entry.truncated,
            "truncated flag must not be set for normal entry"
        );
        if let EventKind::SaMulticallUnregisteredForce {
            prior_address_raw,
            prior_wasm_sha256_raw,
            ..
        } = &entry.event_kind
        {
            assert_ne!(
                prior_address_raw, "<oversized>",
                "normal entry must not use sentinel for address"
            );
            assert_ne!(
                prior_wasm_sha256_raw, "<oversized>",
                "normal entry must not use sentinel for sha256"
            );
        } else {
            panic!("expected SaMulticallUnregisteredForce event kind");
        }
    }

    /// Verify that an oversized `load_warnings` vector
    /// triggers the sentinel-row fallback — raw fields become `"<oversized>"`,
    /// `truncated` is set, and the serialised entry fits within `MAX_ENTRY_BYTES`.
    #[test]
    fn new_sa_multicall_unregistered_force_oversized_triggers_sentinel() {
        // Build a warning vector that is large enough to push the entry over
        // MAX_ENTRY_BYTES even after the per-field 32-entry cap.
        // Each warning is 256 bytes (the per-entry cap enforced by MulticallRegistry::load).
        // 32 warnings × 256 bytes = 8 192 bytes of warning payload alone — well over
        // the 4 096-byte MAX_ENTRY_BYTES limit.
        let oversized_warnings: Vec<String> = (0..32)
            .map(|i| format!("warning-{i:03}-{}", "x".repeat(240)))
            .collect();
        assert_eq!(oversized_warnings.len(), 32);

        let entry = AuditEntry::new_sa_multicall_unregistered_force(
            "test-sdf-network---september-2015",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD5DA",
            "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4",
            oversized_warnings,
            None::<String>,
            "req-sentinel-row-test",
        );

        // The entry must fit after the fallback.
        let json = serde_json::to_vec(&entry).expect("serialisation must not fail after fallback");
        assert!(
            json.len() <= MAX_ENTRY_BYTES,
            "sentinel entry must fit within MAX_ENTRY_BYTES after fallback; got {} bytes",
            json.len()
        );

        // The outer truncated flag must be set.
        assert!(
            entry.truncated,
            "truncated flag must be set when sentinel-row fallback fires"
        );

        // The raw fields must be replaced by the sentinel string.
        if let EventKind::SaMulticallUnregisteredForce {
            prior_address_raw,
            prior_address_raw_truncated,
            prior_wasm_sha256_raw,
            prior_wasm_sha256_raw_truncated,
            load_warnings_truncated,
            ..
        } = &entry.event_kind
        {
            assert_eq!(
                prior_address_raw, "<oversized>",
                "prior_address_raw must be sentinel after fallback"
            );
            assert!(
                prior_address_raw_truncated,
                "prior_address_raw_truncated must be true after fallback"
            );
            assert_eq!(
                prior_wasm_sha256_raw, "<oversized>",
                "prior_wasm_sha256_raw must be sentinel after fallback"
            );
            assert!(
                prior_wasm_sha256_raw_truncated,
                "prior_wasm_sha256_raw_truncated must be true after fallback"
            );
            assert!(
                *load_warnings_truncated,
                "load_warnings_truncated must be true after warnings were drained"
            );
        } else {
            panic!("expected SaMulticallUnregisteredForce event kind");
        }
    }

    /// `redact_free_text_name` must return first-3-chars + ` len=N`.
    #[test]
    fn redact_free_text_name_basic() {
        assert_eq!(redact_free_text_name("admin-rule"), "adm len=10");
        assert_eq!(redact_free_text_name("go"), "go len=2");
        assert_eq!(redact_free_text_name(""), " len=0");
        assert_eq!(redact_free_text_name("ab"), "ab len=2");
        assert_eq!(redact_free_text_name("abc"), "abc len=3");
    }

    /// `new_sa_context_rule_name_updated` must populate all fields and both
    /// `request_id` slots (outer `AuditEntry` + inner `EventKind` variant).
    #[test]
    fn sa_context_rule_name_updated_constructor_shape() {
        let entry = AuditEntry::new_sa_context_rule_name_updated(
            "CDABC...12345",
            42u32,
            "new-rule",
            "stellar:testnet",
            "req-name-upd-001",
        );
        assert_eq!(entry.tool, "sa.context_rule_name_updated");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-name-upd-001");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SaContextRuleNameUpdated {
            smart_account,
            rule_id,
            new_name_redacted,
            audit_request_id: request_id,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaContextRuleNameUpdated; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(smart_account, "CDABC...12345");
        assert_eq!(*rule_id, 42u32);
        // first 3 chars of "new-rule" (8 chars)
        assert_eq!(new_name_redacted, "new len=8");
        // Inner request_id must match the outer one.
        assert_eq!(request_id, "req-name-upd-001");
    }

    /// `new_sa_context_rule_valid_until_updated` must populate all fields and
    /// both `request_id` slots.
    #[test]
    fn sa_context_rule_valid_until_updated_constructor_shape() {
        let entry = AuditEntry::new_sa_context_rule_valid_until_updated(
            "CDABC...12345",
            7u32,
            None,
            "stellar:testnet",
            "req-vu-upd-002",
        );
        assert_eq!(entry.tool, "sa.context_rule_valid_until_updated");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-vu-upd-002");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SaContextRuleValidUntilUpdated {
            smart_account,
            rule_id,
            new_valid_until,
            audit_request_id: request_id,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaContextRuleValidUntilUpdated; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(smart_account, "CDABC...12345");
        assert_eq!(*rule_id, 7u32);
        assert_eq!(*new_valid_until, None);
        assert_eq!(request_id, "req-vu-upd-002");
    }

    /// Metadata-update rows must survive a JSON round-trip — the log reader
    /// deserialises every line back into `AuditEntry`, so a serde failure
    /// silently drops the row.
    #[test]
    fn sa_context_rule_metadata_rows_json_round_trip() {
        let name_entry = AuditEntry::new_sa_context_rule_name_updated(
            "CDABC...12345",
            7u32,
            "new-rule",
            "stellar:testnet",
            "req-rt-338-1",
        );
        let json = serde_json::to_string(&name_entry).expect("name row must serialise");
        assert!(
            json.contains(r#""kind":"sa_context_rule_name_updated""#),
            "name row kind tag missing: {json}"
        );
        let back: AuditEntry = serde_json::from_str(&json).expect("name row must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaContextRuleNameUpdated { .. }
        ));

        let vu_entry = AuditEntry::new_sa_context_rule_valid_until_updated(
            "CDABC...12345",
            7u32,
            Some(42u32),
            "stellar:testnet",
            "req-rt-338-2",
        );
        let json = serde_json::to_string(&vu_entry).expect("valid-until row must serialise");
        assert!(
            json.contains(r#""kind":"sa_context_rule_valid_until_updated""#),
            "valid-until row kind tag missing: {json}"
        );
        let back: AuditEntry =
            serde_json::from_str(&json).expect("valid-until row must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaContextRuleValidUntilUpdated { .. }
        ));
    }

    /// The `SaTimelockDivergencePostSubmit` variant must survive a JSON
    /// round-trip — the acceptance test log reader deserialises every line back
    /// into `AuditEntry`, so a serde failure would silently drop the row.
    ///
    /// Named `audit_request_id` (not `request_id`) inside the variant to
    /// avoid the serde-flatten collision with the outer `AuditEntry::request_id`
    /// field (same naming pattern as the `SaTimelockScheduled` / `Cancelled` /
    /// `Executed` variants).
    #[test]
    fn sa_timelock_divergence_post_submit_json_round_trip() {
        let entry = AuditEntry::new_sa_timelock_divergence_post_submit(
            crate::observability::RedactedStrkey::from_already_redacted("CDABC...12345"),
            "abcdef12...34567890",
            "aabb1122...ccdd3344",
            "schedule",
            true,
            false,
            "stellar:testnet",
            "00000000-0000-0000-0000-000000000099",
        );
        let json = serde_json::to_string(&entry)
            .expect("SaTimelockDivergencePostSubmit row must serialise");
        assert!(
            json.contains(r#""kind":"sa_timelock_divergence_post_submit""#),
            "kind tag missing in serialised row: {json}"
        );
        // The flat `request_id` on `AuditEntry` and the `audit_request_id` inside
        // the variant must both be present and not collide.
        assert!(
            json.contains(r#""audit_request_id""#),
            "audit_request_id field missing: {json}"
        );
        let back: AuditEntry = serde_json::from_str(&json)
            .expect("SaTimelockDivergencePostSubmit row must deserialise");
        assert!(
            matches!(
                back.event_kind,
                EventKind::SaTimelockDivergencePostSubmit { .. }
            ),
            "round-tripped event_kind does not match SaTimelockDivergencePostSubmit"
        );
    }

    // ── IntoOptionalChainId impls ─────────────────────────────────────────────

    #[test]
    fn into_optional_chain_id_string_owned() {
        let chain_id: Option<String> = "stellar:testnet".to_owned().into_optional_chain_id();
        assert_eq!(chain_id.as_deref(), Some("stellar:testnet"));
    }

    #[test]
    fn into_optional_chain_id_ref_string() {
        let s = "stellar:mainnet".to_owned();
        let chain_id: Option<String> = (&s).into_optional_chain_id();
        assert_eq!(chain_id.as_deref(), Some("stellar:mainnet"));
    }

    #[test]
    fn into_optional_chain_id_option_string_some() {
        let opt: Option<String> = Some("stellar:testnet".to_owned());
        let chain_id = opt.into_optional_chain_id();
        assert_eq!(chain_id.as_deref(), Some("stellar:testnet"));
    }

    #[test]
    fn into_optional_chain_id_option_string_none() {
        let opt: Option<String> = None;
        let chain_id = opt.into_optional_chain_id();
        assert!(chain_id.is_none());
    }

    #[test]
    fn into_optional_chain_id_option_ref_str_some() {
        let chain_id: Option<String> = Some("stellar:testnet").into_optional_chain_id();
        assert_eq!(chain_id.as_deref(), Some("stellar:testnet"));
    }

    #[test]
    fn into_optional_chain_id_option_ref_str_none() {
        let chain_id: Option<String> = None::<&str>.into_optional_chain_id();
        assert!(chain_id.is_none());
    }

    // ── NewToolInvocation builder ─────────────────────────────────────────────

    #[test]
    fn new_tool_invocation_optional_fields_default_to_none() {
        let params = NewToolInvocation::new(
            "my_tool",
            "stellar:testnet",
            vec!["key_a".to_owned()],
            PolicyDecision::Allow,
            "req-defaults",
        );
        assert_eq!(params.tool, "my_tool");
        assert_eq!(params.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(params.arg_keys, vec!["key_a"]);
        assert!(params.envelope_hash.is_none());
        assert!(params.nonce_id.is_none());
        assert_eq!(params.policy_decision, PolicyDecision::Allow);
        assert!(params.decision_reason.is_none());
        assert_eq!(params.request_id, "req-defaults");
    }

    #[test]
    fn new_tool_invocation_clone_and_eq() {
        let params = NewToolInvocation::new(
            "my_tool",
            "stellar:testnet",
            vec!["k".to_owned()],
            PolicyDecision::RequireApproval,
            "req-clone",
        );
        let cloned = params.clone();
        assert_eq!(params, cloned);
    }

    // ── decision_reason accessor and setter ───────────────────────────────────

    #[test]
    fn decision_reason_none_on_construction_without_reason() {
        let entry = make_entry(); // make_entry passes decision_reason: None
        assert!(
            entry.decision_reason().is_none(),
            "decision_reason must be None when not supplied"
        );
    }

    #[test]
    fn decision_reason_set_to_none_clears_field() {
        let mut entry = make_entry();
        entry.set_decision_reason(Some("initial reason".to_owned()));
        assert!(entry.decision_reason().is_some());
        entry.set_decision_reason(None);
        assert!(
            entry.decision_reason().is_none(),
            "set_decision_reason(None) must clear the field"
        );
    }

    #[test]
    fn decision_reason_on_construction_with_reason_is_redacted() {
        // The constructor must apply redact_decision_reason before storing.
        let mut params = NewToolInvocation::new(
            "stellar_pay",
            "stellar:testnet",
            vec![],
            PolicyDecision::Deny("limit_exceeded".to_owned()),
            "req-reason",
        );
        // Embed a full G-strkey — must be redacted by the constructor.
        params.decision_reason = Some(format!("account {} over limit", ACCOUNT));
        let entry = AuditEntry::new_tool_invocation(params);
        let reason = entry
            .decision_reason()
            .expect("decision_reason must be Some");
        assert!(
            !reason.contains(ACCOUNT),
            "full account key must not appear in stored reason: {reason}"
        );
        assert!(
            reason.contains("GA5ZS"),
            "first-5 chars of account must be present: {reason}"
        );
    }

    // ── redact_tx_hashes edge cases ───────────────────────────────────────────

    #[test]
    fn redact_tx_hashes_no_op_for_short_input() {
        // Input shorter than 64 chars → returned as-is.
        let short = "abcdef0123456789abcdef01234567890123456789abcdef0123456789abcde";
        assert_eq!(short.len(), 63);
        let out = redact_decision_reason(short);
        assert_eq!(out, short);
    }

    #[test]
    fn redact_tx_hashes_uppercase_hex_not_redacted() {
        // redact_tx_hashes only matches lowercase hex; uppercase must pass through.
        let upper_hex = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(upper_hex.len(), 64);
        let out = redact_decision_reason(upper_hex);
        assert_eq!(out, upper_hex, "uppercase 64-char hex must NOT be redacted");
    }

    #[test]
    fn redact_tx_hashes_longer_hex_run_not_redacted() {
        // 65-char lowercase hex: should NOT match the 64-char pattern because the
        // 64-char window is followed by another hex char.
        let long_hex = "a".repeat(65);
        let out = redact_decision_reason(&long_hex);
        assert_eq!(
            out, long_hex,
            "65-char lowercase hex run must not be redacted (no isolated 64-char match)"
        );
    }

    #[test]
    fn redact_tx_hashes_exactly_64_chars_isolated() {
        // 64-char lowercase hex surrounded by spaces → must be redacted.
        let hash = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3";
        assert_eq!(hash.len(), 64);
        let reason = format!("tx={hash} done");
        let out = redact_decision_reason(&reason);
        assert!(
            !out.contains(hash),
            "exact 64-char hash must be redacted: {out}"
        );
        assert!(
            out.contains("b2c3d4e5"),
            "first-8 chars must be present: {out}"
        );
        assert!(
            out.contains("f0a1b2c3"),
            "last-8 chars must be present: {out}"
        );
    }

    #[test]
    fn redact_tx_hashes_at_start_of_string() {
        // Hash at position 0: prev_ok = true (pos == 0 condition).
        let hash = "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4";
        assert_eq!(hash.len(), 64);
        // No leading text — hash starts at byte 0.
        let out = redact_decision_reason(hash);
        assert!(
            !out.contains(hash),
            "hash at position 0 must be redacted: {out}"
        );
        assert!(
            out.contains("c3d4e5f6"),
            "first-8 chars must be present: {out}"
        );
    }

    #[test]
    fn redact_tx_hashes_two_separate_hashes_in_one_reason() {
        let hash1 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let hash2 = "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2";
        let reason = format!("from={hash1} to={hash2}");
        let out = redact_decision_reason(&reason);
        assert!(!out.contains(hash1), "first hash must be redacted");
        assert!(!out.contains(hash2), "second hash must be redacted");
        // Each must produce first-8 in the output.
        assert!(out.contains("a1b2c3d4"), "first-8 of hash1: {out}");
        assert!(out.contains("f1e2d3c4"), "first-8 of hash2: {out}");
    }

    // ── validate_plugin_name ──────────────────────────────────────────────────

    #[test]
    fn plugin_name_rejects_uppercase_letters() {
        let err = AuditEntry::new_plugin_invoked("MyPlugin", 0, PolicyDecision::Allow, 0, "req")
            .expect_err("uppercase plugin name must be rejected");
        assert!(
            matches!(err, ValidationError::InvalidPluginName { ref reason } if reason == "invalid_character"),
            "expected invalid_character; got: {err:?}"
        );
    }

    #[test]
    fn plugin_name_accepts_digits_and_hyphens_and_underscores() {
        // All allowed: [a-z0-9_-]
        let entry =
            AuditEntry::new_plugin_invoked("valid-plugin_01", 0, PolicyDecision::Allow, 0, "req")
                .expect("valid plugin name");
        assert_eq!(entry.tool, "audit.plugin_invoked.valid-plugin_01");
    }

    #[test]
    fn plugin_invoked_fields_are_plumbed_through() {
        let entry = AuditEntry::new_plugin_invoked(
            "scoring-v2",
            42,
            PolicyDecision::Deny("plugin_denied".to_owned()),
            1500,
            "req-plugin-fields",
        )
        .expect("valid plugin name");
        assert_eq!(entry.request_id, "req-plugin-fields");
        assert!(
            entry.arg_keys.is_empty(),
            "plugin entry must have empty arg_keys"
        );
        assert!(
            entry.chain_id.is_none(),
            "plugin entry must have no chain_id"
        );
        assert!(entry.envelope_hash.is_none());
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::PluginInvoked {
            plugin_name,
            exit_code,
            decision,
            duration_ms,
        } = &entry.event_kind
        else {
            panic!("expected PluginInvoked; got: {:?}", entry.event_kind);
        };
        assert_eq!(plugin_name, "scoring-v2");
        assert_eq!(*exit_code, 42);
        assert_eq!(*decision, PolicyDecision::Deny("plugin_denied".to_owned()));
        assert_eq!(*duration_ms, 1500);
    }

    // ── sa_verifier_hash_drift / sa_policy_hash_drift constructors ───────────

    #[test]
    fn sa_verifier_hash_drift_constructor_shape() {
        let entry = AuditEntry::new_sa_verifier_hash_drift(
            5u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            RedactedStrkey::from_already_redacted("CXABC...VERIF"),
            "aaaabbbb",
            "ccccdddd",
            "stellar:mainnet",
            "req-vhd-001",
        );
        assert_eq!(entry.tool, "sa.verifier_hash_drift");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:mainnet"));
        assert_eq!(entry.request_id, "req-vhd-001");
        // Policy decision for drift events must be Deny.
        assert!(
            matches!(entry.policy_decision, PolicyDecision::Deny(ref r) if r == "verifier_hash_drift"),
            "verifier hash drift must produce Deny(verifier_hash_drift): {:?}",
            entry.policy_decision
        );
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SaVerifierHashDrift {
            rule_id,
            smart_account_redacted,
            deploy_address_redacted,
            pinned_hash_first8,
            observed_hash_first8,
        } = &entry.event_kind
        else {
            panic!("expected SaVerifierHashDrift; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 5u32);
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(deploy_address_redacted, "CXABC...VERIF");
        assert_eq!(pinned_hash_first8, "aaaabbbb");
        assert_eq!(observed_hash_first8, "ccccdddd");
    }

    #[test]
    fn sa_verifier_hash_drift_json_round_trip() {
        let entry = AuditEntry::new_sa_verifier_hash_drift(
            1u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            RedactedStrkey::from_already_redacted("CXABC...VERIF"),
            "aabb1122",
            "ccdd3344",
            "stellar:testnet",
            "req-vhd-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_verifier_hash_drift""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaVerifierHashDrift { .. }
        ));
    }

    #[test]
    fn sa_policy_hash_drift_constructor_shape() {
        let entry = AuditEntry::new_sa_policy_hash_drift(
            9u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            RedactedStrkey::from_already_redacted("CPOLI...CYCON"),
            "11223344",
            "55667788",
            "stellar:testnet",
            "req-phd-001",
        );
        assert_eq!(entry.tool, "sa.policy_hash_drift");
        assert!(
            matches!(entry.policy_decision, PolicyDecision::Deny(ref r) if r == "policy_hash_drift"),
            "policy hash drift must produce Deny(policy_hash_drift): {:?}",
            entry.policy_decision
        );
        let EventKind::SaPolicyHashDrift {
            rule_id,
            smart_account_redacted,
            deploy_address_redacted,
            pinned_hash_first8,
            observed_hash_first8,
        } = &entry.event_kind
        else {
            panic!("expected SaPolicyHashDrift; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 9u32);
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(deploy_address_redacted, "CPOLI...CYCON");
        assert_eq!(pinned_hash_first8, "11223344");
        assert_eq!(observed_hash_first8, "55667788");
    }

    // ── SaMutableContractOverride / SaUnknownContractOverride ─────────────────

    #[test]
    fn sa_mutable_contract_override_constructor_shape() {
        use crate::audit_log::schema::ContractKind;

        let entry = AuditEntry::new_sa_mutable_contract_override(
            0u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            RedactedStrkey::from_already_redacted("CVER1...VERIF"),
            ContractKind::Verifier,
            "2026-06-20T10:00:00.000Z",
            "stellar:testnet",
            "req-mco-001",
        );
        assert_eq!(entry.tool, "sa.mutable_contract_override");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-mco-001");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        let EventKind::SaMutableContractOverride {
            rule_id,
            smart_account_redacted,
            contract_address_redacted,
            contract_kind,
            override_acknowledged_at,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaMutableContractOverride; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(*rule_id, 0u32);
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(contract_address_redacted, "CVER1...VERIF");
        assert_eq!(*contract_kind, ContractKind::Verifier);
        assert_eq!(override_acknowledged_at, "2026-06-20T10:00:00.000Z");
    }

    #[test]
    fn sa_mutable_contract_override_policy_kind_json_round_trip() {
        use crate::audit_log::schema::ContractKind;

        let entry = AuditEntry::new_sa_mutable_contract_override(
            2u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            RedactedStrkey::from_already_redacted("CPOLI...CYCON"),
            ContractKind::Policy,
            "2026-06-20T11:00:00.000Z",
            "stellar:testnet",
            "req-mco-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_mutable_contract_override""#));
        assert!(json.contains(r#""contract_kind":"policy""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaMutableContractOverride { .. }
        ));
    }

    #[test]
    fn sa_unknown_contract_override_constructor_shape() {
        use crate::audit_log::schema::ContractKind;

        let entry = AuditEntry::new_sa_unknown_contract_override(
            0u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            RedactedStrkey::from_already_redacted("CUNKO...NWASM"),
            ContractKind::Policy,
            "2026-06-20T12:00:00.000Z",
            "aabbccdd",
            "stellar:testnet",
            "req-uco-001",
        );
        assert_eq!(entry.tool, "sa.unknown_contract_override");
        assert_eq!(entry.request_id, "req-uco-001");
        let EventKind::SaUnknownContractOverride {
            rule_id,
            smart_account_redacted,
            contract_address_redacted,
            contract_kind,
            override_acknowledged_at,
            observed_hash_first8,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaUnknownContractOverride; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(*rule_id, 0u32);
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(contract_address_redacted, "CUNKO...NWASM");
        assert_eq!(*contract_kind, ContractKind::Policy);
        assert_eq!(override_acknowledged_at, "2026-06-20T12:00:00.000Z");
        assert_eq!(observed_hash_first8, "aabbccdd");
    }

    // ── SaSignerAdded / Removed / ThresholdChanged / Diverged / Baselined ────

    fn make_observed_signer_set() -> crate::audit_log::signer_set::ObservedSignerSet {
        use crate::audit_log::signer_set::{ObservedSignerSet, SignerPubkey};
        ObservedSignerSet {
            signer_count: 2,
            threshold: 1,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
            ],
        }
    }

    #[test]
    fn sa_signer_added_constructor_shape() {
        let resulting = make_observed_signer_set();
        let entry = AuditEntry::new_sa_signer_added(
            7u32,
            1u32,
            &resulting,
            vec!["0101010101010101".to_owned(), "0202020202020202".to_owned()],
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-signer-add-001",
        );
        assert_eq!(entry.tool, "sa.signer_added");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-signer-add-001");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::SaSignerAdded {
            rule_id,
            signer_id,
            resulting_signer_count,
            resulting_threshold,
            resulting_signer_ids,
            resulting_signer_pubkeys_first8,
            smart_account_redacted,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaSignerAdded; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 7u32);
        assert_eq!(*signer_id, 1u32);
        assert_eq!(*resulting_signer_count, 2);
        assert_eq!(*resulting_threshold, 1);
        assert_eq!(resulting_signer_ids, &vec![0u32, 1u32]);
        assert_eq!(
            resulting_signer_pubkeys_first8,
            &vec!["0101010101010101".to_owned(), "0202020202020202".to_owned()]
        );
        assert_eq!(smart_account_redacted, "CDABC...12345");
    }

    #[test]
    fn sa_signer_added_json_round_trip() {
        let resulting = make_observed_signer_set();
        let entry = AuditEntry::new_sa_signer_added(
            0u32,
            0u32,
            &resulting,
            vec![],
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-add-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_signer_added""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(back.event_kind, EventKind::SaSignerAdded { .. }));
    }

    #[test]
    fn sa_signer_removed_constructor_shape() {
        let resulting = make_observed_signer_set();
        let entry = AuditEntry::new_sa_signer_removed(
            3u32,
            0u32,
            &resulting,
            vec!["0202020202020202".to_owned()],
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-signer-rem-001",
        );
        assert_eq!(entry.tool, "sa.signer_removed");
        let EventKind::SaSignerRemoved {
            rule_id,
            signer_id,
            resulting_signer_count,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaSignerRemoved; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 3u32);
        assert_eq!(*signer_id, 0u32);
        assert_eq!(*resulting_signer_count, 2);
    }

    #[test]
    fn sa_threshold_changed_constructor_shape() {
        let resulting = make_observed_signer_set();
        let entry = AuditEntry::new_sa_threshold_changed(
            4u32,
            1u32,
            2u32,
            &resulting,
            vec![],
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-thresh-001",
        );
        assert_eq!(entry.tool, "sa.threshold_changed");
        let EventKind::SaThresholdChanged {
            rule_id,
            old_threshold,
            new_threshold,
            resulting_threshold,
            resulting_signer_count,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaThresholdChanged; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 4u32);
        assert_eq!(*old_threshold, 1u32);
        assert_eq!(*new_threshold, 2u32);
        assert_eq!(*resulting_threshold, 1u32); // from ObservedSignerSet.threshold
        assert_eq!(*resulting_signer_count, 2u32);
    }

    #[test]
    fn sa_signer_set_diverged_constructor_shape() {
        let entry = AuditEntry::new_sa_signer_set_diverged(
            6u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            2u32,
            3u32,
            1u32,
            2u32,
            "aabb1122...ccdd3344",
            "eeff5566...aabb7788",
            "stellar:testnet",
            "req-diverge-001",
        );
        assert_eq!(entry.tool, "sa.signer_set_diverged");
        let EventKind::SaSignerSetDiverged {
            rule_id,
            expected_signer_count,
            observed_signer_count,
            expected_threshold,
            observed_threshold,
            expected_signer_set_digest,
            observed_signer_set_digest,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaSignerSetDiverged; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 6u32);
        assert_eq!(*expected_signer_count, 2u32);
        assert_eq!(*observed_signer_count, 3u32);
        assert_eq!(*expected_threshold, 1u32);
        assert_eq!(*observed_threshold, 2u32);
        assert_eq!(expected_signer_set_digest, "aabb1122...ccdd3344");
        assert_eq!(observed_signer_set_digest, "eeff5566...aabb7788");
    }

    #[test]
    fn sa_signer_set_baselined_constructor_shape() {
        use crate::audit_log::signer_set::BaselineReason;

        let observed = make_observed_signer_set();
        let prev_chain_tip = [0xABu8; 32];
        let entry = AuditEntry::new_sa_signer_set_baselined(
            8u32,
            &observed,
            vec!["0101010101010101".to_owned()],
            1_700_000_000_000_u64,
            BaselineReason::FirstObservation,
            prev_chain_tip,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-baseline-001",
        );
        assert_eq!(entry.tool, "sa.signer_set_baselined");
        // arg_keys has "rule_id" per the constructor.
        assert_eq!(entry.arg_keys, vec!["rule_id"]);
        let EventKind::SaSignerSetBaselined {
            rule_id,
            observed_signer_count,
            observed_threshold,
            observed_at_unix_ms,
            baseline_reason,
            prev_chain_tip_hash,
            observed_at_ledger_seq,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaSignerSetBaselined; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 8u32);
        assert_eq!(*observed_signer_count, 2u32);
        assert_eq!(*observed_threshold, 1u32);
        assert_eq!(*observed_at_unix_ms, 1_700_000_000_000_u64);
        assert_eq!(*baseline_reason, BaselineReason::FirstObservation);
        assert_eq!(*prev_chain_tip_hash, prev_chain_tip);
        // observed_at_ledger_seq is sentinel 0 because it is not available from view call.
        assert_eq!(*observed_at_ledger_seq, 0u32);
    }

    #[test]
    fn sa_signer_set_baselined_explicit_refresh_json_round_trip() {
        use crate::audit_log::signer_set::BaselineReason;

        let observed = make_observed_signer_set();
        let entry = AuditEntry::new_sa_signer_set_baselined(
            0u32,
            &observed,
            vec![],
            0u64,
            BaselineReason::ExplicitRefresh,
            [0u8; 32],
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-baseline-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_signer_set_baselined""#));
        assert!(json.contains(r#""explicit_refresh""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaSignerSetBaselined { .. }
        ));
    }

    // ── SaPolicyAdded / SaPolicyRemoved ───────────────────────────────────────

    #[test]
    fn sa_policy_added_constructor_shape() {
        let entry = AuditEntry::new_sa_policy_added(
            3u32,
            7u32,
            RedactedStrkey::from_already_redacted("CPOLI...ADDED"),
            "aabb1122...ccdd3344",
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-policy-add-001",
        );
        assert_eq!(entry.tool, "sa.policy_added");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-policy-add-001");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        let EventKind::SaPolicyAdded {
            rule_id,
            policy_id,
            policy_address_redacted,
            transaction_hash_redacted,
            smart_account_redacted,
        } = &entry.event_kind
        else {
            panic!("expected SaPolicyAdded; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 3u32);
        assert_eq!(*policy_id, 7u32);
        assert_eq!(policy_address_redacted, "CPOLI...ADDED");
        assert_eq!(transaction_hash_redacted, "aabb1122...ccdd3344");
        assert_eq!(smart_account_redacted, "CDABC...12345");
    }

    #[test]
    fn sa_policy_added_json_round_trip() {
        let entry = AuditEntry::new_sa_policy_added(
            0u32,
            0u32,
            RedactedStrkey::from_already_redacted("CPOLI...ADDED"),
            "aabb1122...ccdd3344",
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-pa-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_policy_added""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(back.event_kind, EventKind::SaPolicyAdded { .. }));
    }

    #[test]
    fn sa_policy_removed_constructor_shape() {
        let entry = AuditEntry::new_sa_policy_removed(
            5u32,
            2u32,
            "eeff5566...aabb7788",
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "stellar:testnet",
            "req-policy-rem-001",
        );
        assert_eq!(entry.tool, "sa.policy_removed");
        let EventKind::SaPolicyRemoved {
            rule_id,
            policy_id,
            transaction_hash_redacted,
            smart_account_redacted,
        } = &entry.event_kind
        else {
            panic!("expected SaPolicyRemoved; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 5u32);
        assert_eq!(*policy_id, 2u32);
        assert_eq!(transaction_hash_redacted, "eeff5566...aabb7788");
        assert_eq!(smart_account_redacted, "CDABC...12345");
    }

    // ── Multicall constructors ────────────────────────────────────────────────

    #[test]
    fn sa_multicall_bundle_submitted_constructor_shape() {
        let entry = AuditEntry::new_sa_multicall_bundle_submitted(
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            11u32,
            "aabb1122...ccdd3344",
            3u32,
            "stellar:testnet",
            "req-mcb-001",
        );
        assert_eq!(entry.tool, "sa.multicall_bundle_submitted");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        let EventKind::SaMulticallBundleSubmitted {
            smart_account_redacted,
            rule_id,
            bundle_tx_hash_redacted,
            inner_count,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaMulticallBundleSubmitted; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(*rule_id, 11u32);
        assert_eq!(bundle_tx_hash_redacted, "aabb1122...ccdd3344");
        assert_eq!(*inner_count, 3u32);
    }

    #[test]
    fn sa_multicall_bundle_submitted_json_round_trip() {
        let entry = AuditEntry::new_sa_multicall_bundle_submitted(
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            0u32,
            "hash...hash",
            1u32,
            "stellar:testnet",
            "req-mcbs-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_multicall_bundle_submitted""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaMulticallBundleSubmitted { .. }
        ));
    }

    #[test]
    fn sa_multicall_inner_executed_constructor_shape() {
        let entry = AuditEntry::new_sa_multicall_inner_executed(
            "aabb1122...ccdd3344",
            2u32,
            RedactedStrkey::from_already_redacted("CTARG...ETCON"),
            "transfer",
            Some("YWJjZA==".to_owned()),
            "stellar:testnet",
            "req-mcie-001",
        );
        assert_eq!(entry.tool, "sa.multicall_inner_executed");
        let EventKind::SaMulticallInnerExecuted {
            bundle_tx_hash_redacted,
            inner_index,
            target_contract_redacted,
            fn_name,
            return_scval_b64_prefix,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaMulticallInnerExecuted; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(bundle_tx_hash_redacted, "aabb1122...ccdd3344");
        assert_eq!(*inner_index, 2u32);
        assert_eq!(target_contract_redacted, "CTARG...ETCON");
        assert_eq!(fn_name, "transfer");
        assert_eq!(return_scval_b64_prefix.as_deref(), Some("YWJjZA=="));
    }

    #[test]
    fn sa_multicall_inner_executed_none_return_val() {
        let entry = AuditEntry::new_sa_multicall_inner_executed(
            "aabb1122...ccdd3344",
            0u32,
            RedactedStrkey::from_already_redacted("CTARG...ETCON"),
            "no_return",
            None,
            "stellar:testnet",
            "req-void-mcie",
        );
        let EventKind::SaMulticallInnerExecuted {
            return_scval_b64_prefix,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaMulticallInnerExecuted");
        };
        assert!(return_scval_b64_prefix.is_none());
        // The field has no skip_serializing_if, so None serialises as JSON null,
        // consistent with the other optional EventKind fields.
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(
            json.contains("\"return_scval_b64_prefix\":null"),
            "None return value must serialise as null: {json}"
        );
    }

    #[test]
    fn sa_multicall_bundle_denied_constructor_shape() {
        let entry = AuditEntry::new_sa_multicall_bundle_denied(
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            4u32,
            5u32,
            Some(2u32),
            None,
            "multicall.bundle_empty",
            "build",
            None,
            "stellar:testnet",
            "req-mcd-001",
        );
        assert_eq!(entry.tool, "sa.multicall_bundle_denied");
        assert!(
            matches!(entry.policy_decision, PolicyDecision::Deny(ref r) if r == "multicall.bundle_denied"),
            "bundle denied must have Deny(multicall.bundle_denied): {:?}",
            entry.policy_decision
        );
        let EventKind::SaMulticallBundleDenied {
            smart_account_redacted,
            rule_id,
            inner_count,
            denied_inner_index,
            observed_inner_count,
            deny_wire_code,
            refusal_phase,
            bundle_tx_hash_redacted,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaMulticallBundleDenied; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(smart_account_redacted, "CDABC...12345");
        assert_eq!(*rule_id, 4u32);
        assert_eq!(*inner_count, 5u32);
        assert_eq!(*denied_inner_index, Some(2u32));
        assert!(observed_inner_count.is_none());
        assert_eq!(deny_wire_code, "multicall.bundle_empty");
        assert_eq!(refusal_phase, "build");
        assert!(bundle_tx_hash_redacted.is_none());
    }

    #[test]
    fn sa_multicall_registered_constructor_shape() {
        let entry = AuditEntry::new_sa_multicall_registered(
            "test-sdf-network",
            RedactedStrkey::from_already_redacted("CRTRL...OUTER"),
            "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
            "stellar:testnet",
            "req-mcr-001",
        );
        assert_eq!(entry.tool, "sa.multicall_registered");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        let EventKind::SaMulticallRegistered {
            network_safename,
            address_redacted,
            wasm_sha256,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaMulticallRegistered; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(network_safename, "test-sdf-network");
        assert_eq!(address_redacted, "CRTRL...OUTER");
        assert_eq!(
            wasm_sha256,
            "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
        );
    }

    #[test]
    fn sa_multicall_registration_refused_constructor_shape() {
        let entry = AuditEntry::new_sa_multicall_registration_refused(
            "test-net",
            RedactedStrkey::from_already_redacted("CRTRL...OUTER"),
            "wrong_hash_64_chars_here_0000000000000000000000000000000000000000",
            Some("correct_hash_000000000000000000000000000000000000000000000000000".to_owned()),
            "sha256_mismatch",
            "stellar:testnet",
            "req-mcrr-001",
        );
        assert_eq!(entry.tool, "sa.multicall_registration_refused");
        assert!(
            matches!(entry.policy_decision, PolicyDecision::Deny(ref r) if r == "multicall.registration_refused"),
        );
        let EventKind::SaMulticallRegistrationRefused {
            network_safename,
            address_redacted,
            attempted_wasm_sha256,
            existing_wasm_sha256,
            refusal_reason,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaMulticallRegistrationRefused; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(network_safename, "test-net");
        assert_eq!(address_redacted, "CRTRL...OUTER");
        assert_eq!(
            attempted_wasm_sha256,
            "wrong_hash_64_chars_here_0000000000000000000000000000000000000000"
        );
        assert!(existing_wasm_sha256.is_some());
        assert_eq!(refusal_reason, "sha256_mismatch");
    }

    #[test]
    fn sa_multicall_unregistered_constructor_shape() {
        let entry = AuditEntry::new_sa_multicall_unregistered(
            "test-net",
            RedactedStrkey::from_already_redacted("CRTRL...OUTER"),
            "deadbeef000000000000000000000000000000000000000000000000deadbeef",
            "stellar:testnet",
            "req-mcu-001",
        );
        assert_eq!(entry.tool, "sa.multicall_unregistered");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        let EventKind::SaMulticallUnregistered {
            network_safename,
            prior_address_redacted,
            prior_wasm_sha256,
        } = &entry.event_kind
        else {
            panic!(
                "expected SaMulticallUnregistered; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(network_safename, "test-net");
        assert_eq!(prior_address_redacted, "CRTRL...OUTER");
        assert_eq!(
            prior_wasm_sha256,
            "deadbeef000000000000000000000000000000000000000000000000deadbeef"
        );
    }

    // ── new_sa_multicall_unregistered_force per-field truncation ─────────────

    #[test]
    fn sa_multicall_unregistered_force_per_field_truncation_at_64() {
        // Inputs exactly at the 64-char cap must NOT be truncated.
        let addr_exactly_64 = "C".repeat(64);
        let sha_exactly_64 = "a".repeat(64);
        let entry = AuditEntry::new_sa_multicall_unregistered_force(
            "net",
            &addr_exactly_64,
            &sha_exactly_64,
            vec![],
            None::<String>,
            "req-field-cap",
        );
        if let EventKind::SaMulticallUnregisteredForce {
            prior_address_raw,
            prior_address_raw_truncated,
            prior_wasm_sha256_raw,
            prior_wasm_sha256_raw_truncated,
            ..
        } = &entry.event_kind
        {
            assert_eq!(prior_address_raw.len(), 64);
            assert!(
                !prior_address_raw_truncated,
                "64-char input must not be truncated"
            );
            assert_eq!(prior_wasm_sha256_raw.len(), 64);
            assert!(
                !prior_wasm_sha256_raw_truncated,
                "64-char sha must not be truncated"
            );
        } else {
            panic!("expected SaMulticallUnregisteredForce");
        }
        assert!(
            !entry.truncated,
            "64-char inputs must not trigger sentinel fallback"
        );
    }

    #[test]
    fn sa_multicall_unregistered_force_per_field_truncation_over_64() {
        // 65-char inputs: both raw fields must be truncated to 64 chars.
        let addr_65 = "C".repeat(65);
        let sha_65 = "a".repeat(65);
        let entry = AuditEntry::new_sa_multicall_unregistered_force(
            "net",
            &addr_65,
            &sha_65,
            vec![],
            None::<String>,
            "req-over-cap",
        );
        if let EventKind::SaMulticallUnregisteredForce {
            prior_address_raw,
            prior_address_raw_truncated,
            prior_wasm_sha256_raw,
            prior_wasm_sha256_raw_truncated,
            ..
        } = &entry.event_kind
        {
            assert_eq!(
                prior_address_raw.len(),
                64,
                "over-cap address must be truncated to 64"
            );
            assert!(
                prior_address_raw_truncated,
                "address truncation flag must be set"
            );
            assert_eq!(
                prior_wasm_sha256_raw.len(),
                64,
                "over-cap sha must be truncated to 64"
            );
            assert!(
                prior_wasm_sha256_raw_truncated,
                "sha truncation flag must be set"
            );
        } else {
            panic!("expected SaMulticallUnregisteredForce");
        }
        // The entry itself is small enough not to need the sentinel fallback.
        assert!(
            !entry.truncated,
            "small-payload over-cap fields must not trigger sentinel"
        );
    }

    #[test]
    fn sa_multicall_unregistered_force_load_warnings_cap_at_32() {
        // 33 warnings — only the first 32 must be kept.
        let warnings: Vec<String> = (0..33).map(|i| format!("warn-{i}")).collect();
        let entry = AuditEntry::new_sa_multicall_unregistered_force(
            "net",
            "short-addr",
            "short-sha",
            warnings,
            None::<String>,
            "req-warn-cap",
        );
        if let EventKind::SaMulticallUnregisteredForce {
            load_warnings,
            load_warnings_truncated,
            ..
        } = &entry.event_kind
        {
            assert_eq!(load_warnings.len(), 32, "warnings must be capped at 32");
            assert!(
                load_warnings_truncated,
                "truncated flag must be set for 33rd warning"
            );
        } else {
            panic!("expected SaMulticallUnregisteredForce");
        }
    }

    // ── SaTimelockScheduled / Cancelled / Executed ───────────────────────────

    #[test]
    fn sa_timelock_scheduled_constructor_shape() {
        let entry = AuditEntry::new_sa_timelock_scheduled(
            "opid...abcd",
            "00000000aaaaaaaaffffffffaaaaaaaa00000000aaaaaaaaffffffff00000000",
            RedactedStrkey::from_already_redacted("CTIME...CLOCK"),
            RedactedStrkey::from_already_redacted("CTARG...ETCON"),
            "upgrade",
            100u32,
            RedactedStrkey::from_already_redacted("GPROP...OSER1"),
            "sched...tx01",
            "stellar:testnet",
            "req-tls-001",
        );
        assert_eq!(entry.tool, "sa.timelock_scheduled");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(entry.request_id, "req-tls-001");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        let EventKind::SaTimelockScheduled {
            operation_id_redacted,
            delay_ledgers,
            function,
            audit_request_id,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaTimelockScheduled; got: {:?}", entry.event_kind);
        };
        assert_eq!(operation_id_redacted, "opid...abcd");
        assert_eq!(*delay_ledgers, 100u32);
        assert_eq!(function, "upgrade");
        // Inner audit_request_id must match outer request_id.
        assert_eq!(audit_request_id, "req-tls-001");
    }

    #[test]
    fn sa_timelock_scheduled_json_round_trip() {
        let entry = AuditEntry::new_sa_timelock_scheduled(
            "op1...id",
            "fullhex00000000000000000000000000000000000000000000000000000000",
            RedactedStrkey::from_already_redacted("CTIME...LOCK0"),
            RedactedStrkey::from_already_redacted("CTARG...ETCO0"),
            "call",
            10u32,
            RedactedStrkey::from_already_redacted("GAAAA...BBBBB"),
            "tx...hash",
            "stellar:testnet",
            "req-tls-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_timelock_scheduled""#));
        assert!(
            json.contains(r#""audit_request_id""#),
            "audit_request_id missing: {json}"
        );
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaTimelockScheduled { .. }
        ));
    }

    #[test]
    fn sa_timelock_cancelled_constructor_shape() {
        let entry = AuditEntry::new_sa_timelock_cancelled(
            "opid...dcba",
            "00000000bbbbbbbbffffffffbbbbbbbb00000000bbbbbbbbffffffff00000000",
            RedactedStrkey::from_already_redacted("CTIME...CLOCK"),
            RedactedStrkey::from_already_redacted("GCNCE...LLRLR"),
            "cancel...tx02",
            "stellar:testnet",
            "req-tlc-001",
        );
        assert_eq!(entry.tool, "sa.timelock_cancelled");
        assert_eq!(entry.request_id, "req-tlc-001");
        let EventKind::SaTimelockCancelled {
            operation_id_redacted,
            audit_request_id,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaTimelockCancelled; got: {:?}", entry.event_kind);
        };
        assert_eq!(operation_id_redacted, "opid...dcba");
        assert_eq!(audit_request_id, "req-tlc-001");
    }

    #[test]
    fn sa_timelock_cancelled_json_round_trip() {
        let entry = AuditEntry::new_sa_timelock_cancelled(
            "op2...id",
            "hex000000000000000000000000000000000000000000000000000000000000",
            RedactedStrkey::from_already_redacted("CTIME...LOCK0"),
            RedactedStrkey::from_already_redacted("GCNCE...LLRL0"),
            "cancel...hash",
            "stellar:testnet",
            "req-tlc-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_timelock_cancelled""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::SaTimelockCancelled { .. }
        ));
    }

    #[test]
    fn sa_timelock_executed_constructor_shape() {
        let entry = AuditEntry::new_sa_timelock_executed(
            "opid...exec",
            "00000000ccccccccffffffffcccccccc00000000ccccccccffffffff00000000",
            RedactedStrkey::from_already_redacted("CTIME...CLOCK"),
            Some(RedactedStrkey::from_already_redacted("GEXEC...UTOR1")),
            "exec...tx03",
            "stellar:testnet",
            "req-tle-001",
        );
        assert_eq!(entry.tool, "sa.timelock_executed");
        assert_eq!(entry.request_id, "req-tle-001");
        let EventKind::SaTimelockExecuted {
            operation_id_redacted,
            executor_redacted,
            audit_request_id,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaTimelockExecuted; got: {:?}", entry.event_kind);
        };
        assert_eq!(operation_id_redacted, "opid...exec");
        assert!(executor_redacted.is_some());
        assert_eq!(executor_redacted.as_deref(), Some("GEXEC...UTOR1"));
        assert_eq!(audit_request_id, "req-tle-001");
    }

    #[test]
    fn sa_timelock_executed_no_executor_json_round_trip() {
        let entry = AuditEntry::new_sa_timelock_executed(
            "op3...id",
            "hex000000000000000000000000000000000000000000000000000000000000",
            RedactedStrkey::from_already_redacted("CTIME...LOCK0"),
            None, // no executor
            "exec...hash",
            "stellar:testnet",
            "req-tle-rt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"sa_timelock_executed""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        if let EventKind::SaTimelockExecuted {
            executor_redacted, ..
        } = &back.event_kind
        {
            assert!(
                executor_redacted.is_none(),
                "executor_redacted must round-trip as None"
            );
        } else {
            panic!("expected SaTimelockExecuted");
        }
    }

    // ── Channel constructors ──────────────────────────────────────────────────

    #[test]
    fn channel_acquired_constructor_shape() {
        let entry = AuditEntry::new_channel_acquired("GCHAN...EL001", 3u32, "req-ch-acq-001");
        assert_eq!(entry.tool, "pool.channel_acquired");
        assert!(entry.chain_id.is_none(), "channel entries have no chain_id");
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        assert!(entry.previous_entry_hash.is_empty());
        let EventKind::ChannelAcquired {
            channel_redacted,
            index,
        } = &entry.event_kind
        else {
            panic!("expected ChannelAcquired; got: {:?}", entry.event_kind);
        };
        assert_eq!(channel_redacted, "GCHAN...EL001");
        assert_eq!(*index, 3u32);
    }

    #[test]
    fn channel_acquired_json_round_trip() {
        let entry = AuditEntry::new_channel_acquired("GCHAN...EL001", 0u32, "req-ca-rt");
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"channel_acquired""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(back.event_kind, EventKind::ChannelAcquired { .. }));
    }

    #[test]
    fn channel_released_constructor_shape() {
        let entry =
            AuditEntry::new_channel_released("GCHAN...EL001", 3u32, "success", "req-ch-rel-001");
        assert_eq!(entry.tool, "pool.channel_released");
        assert!(entry.chain_id.is_none());
        let EventKind::ChannelReleased {
            channel_redacted,
            index,
            outcome,
        } = &entry.event_kind
        else {
            panic!("expected ChannelReleased; got: {:?}", entry.event_kind);
        };
        assert_eq!(channel_redacted, "GCHAN...EL001");
        assert_eq!(*index, 3u32);
        assert_eq!(outcome, "success");
    }

    #[test]
    fn channel_released_failure_outcome_json_round_trip() {
        let entry =
            AuditEntry::new_channel_released("GCHAN...EL001", 0u32, "tx_bad_seq", "req-cr-rt");
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"channel_released""#));
        assert!(json.contains("tx_bad_seq"));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        if let EventKind::ChannelReleased { outcome, .. } = &back.event_kind {
            assert_eq!(outcome, "tx_bad_seq");
        } else {
            panic!("expected ChannelReleased");
        }
    }

    #[test]
    fn channel_pool_initialised_constructor_shape() {
        let entry = AuditEntry::new_channel_pool_initialised(
            "GFUND...ER001",
            10usize,
            "initpool...tx00",
            12345u32,
            "req-cpi-001",
        );
        assert_eq!(entry.tool, "pool.channel_pool_initialised");
        assert!(entry.chain_id.is_none());
        assert!(matches!(entry.policy_decision, PolicyDecision::Allow));
        let EventKind::ChannelPoolInitialised {
            funder_redacted,
            channel_count,
            tx_hash_redacted,
            ledger,
        } = &entry.event_kind
        else {
            panic!(
                "expected ChannelPoolInitialised; got: {:?}",
                entry.event_kind
            );
        };
        assert_eq!(funder_redacted, "GFUND...ER001");
        assert_eq!(*channel_count, 10usize);
        assert_eq!(tx_hash_redacted, "initpool...tx00");
        assert_eq!(*ledger, 12345u32);
    }

    #[test]
    fn channel_pool_initialised_json_round_trip() {
        let entry = AuditEntry::new_channel_pool_initialised(
            "GFUND...ERXXX",
            5usize,
            "tx...hash",
            100u32,
            "req-cpirt",
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(json.contains(r#""kind":"channel_pool_initialised""#));
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        assert!(matches!(
            back.event_kind,
            EventKind::ChannelPoolInitialised { .. }
        ));
    }

    // ── truncate_arg_keys_if_needed — exact count tracking ───────────────────

    #[test]
    fn truncate_arg_keys_exact_count_over_max() {
        // MAX_ARG_KEYS + 10 keys: exactly 10 must be reported as truncated.
        let total = MAX_ARG_KEYS + 10;
        let mut entry = make_entry();
        entry.arg_keys = (0..total).map(|i| format!("key_{i:03}")).collect();
        entry.truncate_arg_keys_if_needed().unwrap();
        assert_eq!(entry.arg_keys.len(), MAX_ARG_KEYS);
        assert_eq!(
            entry.arg_keys_truncated,
            Some(10),
            "truncated count must be exactly 10; got: {:?}",
            entry.arg_keys_truncated
        );
        assert!(entry.truncated);
    }

    #[test]
    fn truncate_arg_keys_byte_limit_exact_count_tracking() {
        // Build an entry whose arg_keys overflow MAX_ENTRY_BYTES — verify the
        // truncated count accurately reflects the number of dropped keys.
        let big_key = "k".repeat(200);
        let num_keys = 25usize;
        let mut entry = make_entry();
        entry.arg_keys = (0..num_keys).map(|_| big_key.clone()).collect();
        let original_len = entry.arg_keys.len();
        entry.truncate_arg_keys_if_needed().unwrap();
        let remaining = entry.arg_keys.len();
        let dropped = original_len - remaining;
        assert_eq!(
            entry.arg_keys_truncated,
            Some(dropped),
            "truncated count must equal number of dropped keys"
        );
        assert!(entry.truncated);
        let json_size = serde_json::to_vec(&entry).unwrap().len();
        assert!(
            json_size <= MAX_ENTRY_BYTES,
            "entry must fit after truncation; got {json_size} bytes"
        );
    }

    // ── looks_like_rfc3339_timestamp (exercised through debug_assert path) ────

    #[test]
    fn looks_like_rfc3339_timestamp_valid_z_suffix() {
        // The private function is exercised via debug_assert in
        // new_sa_verifier_diversification_override. This test validates the
        // constructor accepts a well-formed RFC 3339 timestamp.
        let entry = AuditEntry::new_sa_verifier_diversification_override(
            0u32,
            RedactedStrkey::from_already_redacted("CDABC...12345"),
            "aabbccdd",
            1_000_000_000_i64,
            "2026-06-20T09:00:00.000Z",
            "stellar:testnet",
            "req-ts-valid",
        );
        let EventKind::SaVerifierDiversificationOverride {
            override_acknowledged_at,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaVerifierDiversificationOverride");
        };
        assert_eq!(override_acknowledged_at, "2026-06-20T09:00:00.000Z");
    }

    // ── Mlock constructor field verification ──────────────────────────────────

    #[test]
    fn mlock_failed_none_errno() {
        let entry = AuditEntry::new_mlock_failed("prod", "EPERM", None, "req-mlock-none-errno");
        assert_eq!(entry.tool, "wallet.mlock_failed");
        let EventKind::WalletMlockFailed {
            profile,
            reason,
            errno,
        } = &entry.event_kind
        else {
            panic!("expected WalletMlockFailed");
        };
        assert_eq!(profile, "prod");
        assert_eq!(reason, "EPERM");
        assert!(errno.is_none(), "errno must be None when not supplied");
        // Verify None errno does not appear in JSON (skip_serializing_if = "Option::is_none").
        let json = serde_json::to_string(&entry).expect("must serialise");
        // Note: the schema uses #[serde(skip_serializing_if = "Option::is_none")] on
        // the outer-entry optional fields, but errno is defined inline in the EventKind
        // variant. Check it can be round-tripped.
        let back: AuditEntry = serde_json::from_str(&json).expect("must deserialise");
        if let EventKind::WalletMlockFailed {
            errno: back_errno, ..
        } = &back.event_kind
        {
            assert!(back_errno.is_none());
        } else {
            panic!("expected WalletMlockFailed after round-trip");
        }
    }

    // ── sa_context_rule_created with overrides present ────────────────────────

    #[test]
    fn sa_context_rule_created_with_all_optional_flags() {
        let entry = AuditEntry::new_sa_context_rule_created(
            "CDABC...12345",
            99u32,
            "default",
            3u32,
            2u32,
            Some(999_000u32),
            "stellar:mainnet",
            "req-crc-flags",
            vec!["deadbeef".to_owned()],
            vec!["cafebabe".to_owned()],
            true, // mutable_override
            true, // unknown_override
        );
        assert_eq!(entry.tool, "sa.context_rule_created");
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:mainnet"));
        let EventKind::SaContextRuleCreated {
            rule_id,
            signers_count,
            policies_count,
            valid_until,
            pinned_verifier_wasm_hashes_first8,
            pinned_policy_wasm_hashes_first8,
            mutable_override,
            unknown_override,
            ..
        } = &entry.event_kind
        else {
            panic!("expected SaContextRuleCreated; got: {:?}", entry.event_kind);
        };
        assert_eq!(*rule_id, 99u32);
        assert_eq!(*signers_count, 3u32);
        assert_eq!(*policies_count, 2u32);
        assert_eq!(*valid_until, Some(999_000u32));
        assert_eq!(
            pinned_verifier_wasm_hashes_first8,
            &vec!["deadbeef".to_owned()]
        );
        assert_eq!(
            pinned_policy_wasm_hashes_first8,
            &vec!["cafebabe".to_owned()]
        );
        assert!(mutable_override);
        assert!(unknown_override);

        // JSON: mutable_override and unknown_override must appear (they are true).
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(
            json.contains(r#""mutable_override":true"#),
            "mutable_override:true must appear in JSON: {json}"
        );
        assert!(
            json.contains(r#""unknown_override":true"#),
            "unknown_override:true must appear in JSON: {json}"
        );
    }

    #[test]
    fn sa_context_rule_created_false_overrides_omitted_from_json() {
        // When both override flags are false they must be omitted from JSON
        // (skip_serializing_if = "std::ops::Not::not").
        let entry = AuditEntry::new_sa_context_rule_created(
            "CDABC...12345",
            1u32,
            "call_contract",
            1u32,
            0u32,
            None,
            "stellar:testnet",
            "req-crc-omit",
            vec![],
            vec![],
            false,
            false,
        );
        let json = serde_json::to_string(&entry).expect("must serialise");
        assert!(
            !json.contains("mutable_override"),
            "false mutable_override must be omitted from JSON: {json}"
        );
        assert!(
            !json.contains("unknown_override"),
            "false unknown_override must be omitted from JSON: {json}"
        );
    }

    // ── redact_free_text_name Unicode support ─────────────────────────────────

    #[test]
    fn redact_free_text_name_unicode_prefix_takes_3_scalar_values() {
        // "éàü" = 3 Unicode scalar values; len() in bytes = 6.
        let name = "éàüfoo-bar";
        let redacted = redact_free_text_name(name);
        // First 3 chars: 'é', 'à', 'ü' — 6 bytes of prefix.
        let expected_prefix: String = name.chars().take(3).collect();
        assert!(
            redacted.starts_with(&expected_prefix),
            "redacted must start with first-3 unicode scalar values: {redacted}"
        );
        assert!(
            redacted.ends_with(&format!("len={}", name.len())),
            "len must be byte length: {redacted}"
        );
    }

    // ── canonical_json_write matches canonical_json_body ─────────────────────

    #[test]
    fn canonical_json_write_output_matches_body_vec() {
        // For every entry kind that has a constructor tested above, verify the
        // streaming writer and the Vec-returning helper agree byte-for-byte.
        let entries = vec![
            make_entry(),
            AuditEntry::new_mlock_failed("p", "E", Some(1), "req"),
            AuditEntry::new_rotation_handoff("file.jsonl.20260101T000000000", "req"),
            AuditEntry::new_plugin_invoked("plug", 0, PolicyDecision::Allow, 0, "req").unwrap(),
            AuditEntry::new_channel_acquired("C...X", 0, "req"),
            AuditEntry::new_channel_released("C...X", 0, "success", "req"),
            AuditEntry::new_channel_pool_initialised("G...F", 1, "t...x", 1, "req"),
        ];
        for entry in &entries {
            let body_vec = entry.canonical_json_body().unwrap();
            let mut body_write = Vec::new();
            entry.canonical_json_write(&mut body_write).unwrap();
            assert_eq!(
                body_vec, body_write,
                "canonical_json_body and canonical_json_write must agree for tool={}",
                entry.tool
            );
        }
    }

    // ── canonical_json_body zeroes previous_entry_hash regardless of value ───

    #[test]
    fn canonical_json_body_zeroes_non_empty_previous_hash() {
        // Simulate the writer having set previous_entry_hash to a real value.
        let mut entry = make_entry();
        entry.previous_entry_hash =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        let body = entry.canonical_json_body().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.get("previous_entry_hash").and_then(|v| v.as_str()),
            Some(""),
            "canonical body must always set previous_entry_hash to empty string"
        );
    }
}

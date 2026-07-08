//! Policy engine trait, no-op implementation, and typed decision surface.
//!
//! This module provides the [`PolicyEngine`] trait that is the binding
//! mechanism for the mainnet MCP write-tools gate, plus the typed
//! [`Decision`], [`DenyReason`], and [`ApprovalRequest`] types.
//!
//! # NoopPolicyEngine behaviour
//!
//! [`crate::policy::NoopPolicyEngine`] is the concrete implementation used when no full policy
//! engine is configured:
//!
//! - **Testnet profiles**: `evaluate()` returns `Ok(Decision::Allow)` for all
//!   tools.
//! - **Mainnet profiles + destructive tools**: `evaluate()` returns
//!   `Err(PolicyError::NotImplemented)`, which the MCP dispatch site propagates
//!   as `policy.engine_required`.
//! - **Mainnet profiles + read-only tools**: `evaluate()` returns
//!   `Ok(Decision::Allow)`.
//!
//! The call site at `tools/call` dispatch is unchanged when a real
//! `PolicyEngine` is substituted — only the concrete type registered at
//! process start changes.  The gate is NOT a feature flag, NOT a `const bool`,
//! NOT a calendar-date check.
//!
//! # Typed decision surface
//!
//! [`Decision::Deny`] carries a structured [`DenyReason`] and
//! [`Decision::RequireApproval`] carries an [`ApprovalRequest`].  The
//! `dispatch_gate` maps the typed deny into the MCP wire error envelope using
//! [`DenyReason::code`].
//!
//! # ToolDescriptor and its relationship to rmcp
//!
//! [`ToolDescriptor`] is the wallet-owned policy-engine descriptor sourced from
//! [`McpToolRegistration`] via `#[mcp_tool_item]` codegen.  It is NOT derived
//! from or identical to `rmcp::model::Tool` — the rmcp library has its own
//! protocol-level tool description type for the MCP wire format; `ToolDescriptor`
//! is the policy-gate-relevant subset used by [`PolicyEngine::evaluate`].
//!
//! The struct is `#[non_exhaustive]` to allow future additions without breaking
//! match-arm exhaustion in consumer code.
//!
//! ## Error placement convention
//!
//! Registry-validation error types live alongside `McpToolRegistration`
//! in this module because `McpToolRegistration` is the input shape they
//! validate (`BuildRegistryError::DuplicateRegistration` is the canonical
//! example). Runtime dispatch errors (e.g. `tools/call` JSON-RPC error
//! responses) live in the consuming crate (`stellar-agent-mcp::server`).
//!
//! # Sub-modules
//!
//! - [`crate::policy::v1`] — `PolicyEngineV1` typed-criteria evaluator.

use crate::{approval::ApprovalError, profile::schema::Profile};

// ─────────────────────────────────────────────────────────────────────────────
// Sub-modules
// ─────────────────────────────────────────────────────────────────────────────

/// `PolicyEngineV1` typed-criteria evaluator.
///
/// Implements [`PolicyEngine`] over the typed schema (per-tx cap, per-period
/// cap, rate limit, counterparty allowlist, minimum-reserve guard, Soroban
/// resource-fee cap).  Replaces [`NoopPolicyEngine`] at runtime when
/// `profile.policy.engine = PolicyEngineKind::V1`.
pub mod v1;

// ─────────────────────────────────────────────────────────────────────────────
// BuildRegistryError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when the tool registry cannot be built at server startup.
///
/// # Security note
///
/// `DuplicateRegistration` is fail-closed: a duplicate `name` in the inventory
/// registry is treated as a fatal startup error.  Silently dropping duplicates
/// (first-registration-wins) would allow a malicious contributor to shadow a
/// `destructive_hint = true` tool with a registration carrying
/// `destructive_hint = false`, bypassing the mainnet write-tools gate.
///
/// The linker order of `inventory::submit!` items is non-deterministic across
/// builds, so the "first registration wins" strategy is also non-deterministic
/// — it cannot be reasoned about defensively.  Fail-closed is the correct shape.
///
/// `UnsupportedEngineKind` is also fail-closed: unknown `PolicyEngineKind`
/// variants encountered at startup produce a hard error rather than silently
/// downgrading to `NoopPolicyEngine`.  Silent downgrade would allow a future
/// engine variant to be ignored, bypassing the operator's intent.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildRegistryError {
    /// Two `McpToolRegistration` values with the same `name` were collected by
    /// the `inventory` registry at link time.
    ///
    /// This is a compile-time authoring error: each tool fn must carry exactly
    /// one `#[mcp_tool_item]` attribute and no two fns may declare the same
    /// `name`.
    #[error(
        "duplicate McpToolRegistration for tool name `{name}`: \
         each tool must be registered exactly once; a duplicate name is a \
         compile-time authoring error"
    )]
    DuplicateRegistration {
        /// The duplicated tool name.
        name: &'static str,
    },

    /// The `NonceMint` could not be constructed from the profile at startup.
    ///
    /// This error should not occur in normal operation; `NonceMint::from_profile`
    /// currently never fails.  The variant exists for forward compatibility when
    /// future versions add reachability probes or keyring validation at construction.
    #[error("nonce mint construction failed at startup: {detail}")]
    NonceMintInit {
        /// Non-secret diagnostic detail.
        detail: String,
    },

    /// The owner keyring entry could not be opened at startup.
    ///
    /// Returned when `keyring_core::Entry::new` fails — typically the keyring
    /// store has not been initialised or the profile name is malformed.
    ///
    /// `detail` is the display output of the upstream keyring error (no key
    /// material; `keyring-core` display output is diagnostic-only).
    #[error("cannot open owner-key keyring entry for profile '{profile}': {detail}")]
    OwnerKeyringEntryUnreadable {
        /// Profile name whose owner-key entry could not be opened.
        profile: String,
        /// Non-secret diagnostic from the keyring library.
        detail: String,
    },

    /// The owner key is absent from the keyring for the given profile.
    ///
    /// Returned when `keyring_core::Entry::get_password` fails — the entry
    /// exists in the store schema but has no value, or the entry was never
    /// written.
    ///
    /// `detail` is the display output of the upstream keyring error (no key
    /// material).
    #[error("owner key not found in keyring for profile '{profile}': {detail}")]
    OwnerKeyAbsent {
        /// Profile name whose owner key is absent.
        profile: String,
        /// Non-secret diagnostic from the keyring library.
        detail: String,
    },

    /// The value stored in the owner keyring entry could not be decoded as
    /// URL-safe base64.
    ///
    /// `detail` is the base64 decode error message (no secret material —
    /// the encoded bytes are not echoed back).
    #[error("owner key for profile '{profile}' is not valid URL-safe base64: {detail}")]
    OwnerKeyDecodeFailed {
        /// Profile name whose owner key failed to decode.
        profile: String,
        /// Non-secret decode error description.
        detail: String,
    },

    /// The decoded owner key has an unexpected byte length.
    ///
    /// Ed25519 public keys are exactly 32 bytes.  A stored key of the wrong
    /// length indicates storage corruption or a wrong key type.
    #[error(
        "owner key for profile '{profile}' has unexpected length \
         {actual_len} (expected {expected_len})"
    )]
    OwnerKeyLengthMismatch {
        /// Profile name whose key has the wrong length.
        profile: String,
        /// Actual decoded byte length.
        actual_len: usize,
        /// Expected byte length (always 32 for ed25519).
        expected_len: usize,
    },

    /// The OS-conventional policy directory could not be resolved.
    ///
    /// Returned by `default_policy_dir()` when `dirs::state_dir()` (Linux) or
    /// `dirs::data_dir()` (macOS/Windows) returns `None`, which happens when
    /// the home directory is not set in the process environment.
    #[error(
        "cannot determine OS-conventional state directory for policy files; \
         ensure HOME (or XDG_STATE_HOME) is set in the process environment"
    )]
    PolicyDirResolutionFailed,

    /// The policy file could not be loaded or its signature verification
    /// failed.
    ///
    /// Wraps the [`crate::policy::PolicyError`] from
    /// `loader::load_signed_policy`.
    #[error("policy file load or verification failed for profile '{profile}': {source}")]
    PolicyFileLoadFailed {
        /// Profile name for which the policy load failed.
        profile: String,
        /// The underlying policy error (file I/O, parse, or signature failure).
        source: crate::policy::PolicyError,
    },

    /// An unknown `PolicyEngineKind` variant was encountered at startup.
    ///
    /// `PolicyEngineKind` is `#[non_exhaustive]`; future variants that are not
    /// recognised by this binary version produce this error rather than silently
    /// falling back to `NoopPolicyEngine`.
    ///
    /// The `kind` field carries the `Debug` representation of the unrecognised
    /// variant so the operator can identify which engine value is in their
    /// profile TOML.
    #[error(
        "unsupported PolicyEngineKind variant '{kind}': \
         upgrade stellar-agent-mcp to a version that supports this engine kind, \
         or reset the profile engine to 'noop'"
    )]
    UnsupportedEngineKind {
        /// `Debug` representation of the unrecognised variant.
        kind: String,
    },

    /// The policy engine could not be constructed at startup for a reason not
    /// covered by the typed variants above.
    ///
    /// This variant is retained as a migration escape hatch and for future
    /// forward-compat.  New call sites should use a typed variant.
    ///
    /// `detail` is a non-secret diagnostic message (no key material).
    #[error("policy engine construction failed at startup: {detail}")]
    PolicyEngineError {
        /// Non-secret diagnostic detail.
        detail: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolValueKind
// ─────────────────────────────────────────────────────────────────────────────

/// The static value shape a tool declares at registration.
///
/// Every tool declares one of these via `#[mcp_tool_item(value_kind = "…")]`
/// so a new tool cannot be added without a conscious classification. The field
/// defaults to [`ToolValueKind::ReadOnly`] when the annotation omits it
/// (back-compatible), which is the correct classification for the large
/// majority of tools (reads, quotes, status, `get_*`, message sign/verify).
///
/// This is a compile-time-declared shape distinct from the per-call
/// [`crate::policy::v1::value::ValueClass`] the dispatch gate derives: a
/// `MovesValue` tool resolves a concrete `ValueClass::Value` at dispatch, an
/// `OpaqueSign` tool resolves `ValueClass::Opaque`, and a `ReadOnly` tool
/// resolves `ValueClass::ReadOnly`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::ToolValueKind;
///
/// assert_eq!(ToolValueKind::default(), ToolValueKind::ReadOnly);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolValueKind {
    /// The tool moves no on-chain value. Default classification.
    #[default]
    ReadOnly,
    /// The tool moves value; the dispatch site resolves the concrete effect(s).
    MovesValue,
    /// The tool signs caller-supplied / opaque material whose value effect the
    /// dispatch site cannot resolve (the SEP-43 transaction / auth-entry sign
    /// tools).
    OpaqueSign,
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// MCP tool descriptor consumed by [`PolicyEngine::evaluate`].
///
/// Carries the full set of tool annotations registered via `#[mcp_tool_item(...)]`.
/// The struct is `#[non_exhaustive]` to allow further additions without breaking
/// match-arm exhaustion.
///
/// # Preferred constructor
///
/// Prefer [`ToolDescriptor::from_registration`] which sources every static
/// field from the `McpToolRegistration` collected by the `#[mcp_tool_item]`
/// attribute at link time — that is the single source of truth.
/// Callers that know the active chain at dispatch time can set `chain_id`
/// directly after construction.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
///
/// let reg = McpToolRegistration {
///     name: "stellar_balances",
///     destructive_hint: false,
///     read_only_hint: true,
///     chain_id_required: true,
///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
/// };
/// let d = ToolDescriptor::from_registration(&reg);
/// assert_eq!(d.name, "stellar_balances");
/// assert!(!d.destructive_hint);
/// assert!(d.read_only_hint);
/// assert!(d.chain_id_required);
/// // chain_id defaults to empty string; dispatch site sets it from call args.
/// assert!(d.chain_id.is_empty());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ToolDescriptor {
    /// The registered MCP tool name (e.g. `"stellar_pay"`).
    pub name: String,
    /// Whether the tool carries `destructiveHint: true` per MCP annotations.
    pub destructive_hint: bool,
    /// Whether the tool carries `readOnlyHint: true` per MCP annotations.
    pub read_only_hint: bool,
    /// Whether the tool requires a CAIP-2 `chain_id` argument.
    ///
    /// When `true`, the per-tool handler body validates `chain_id` directly via
    /// [`crate::profile::validate_chain_id_matches_profile`]
    /// (see `stellar_balances` and `stellar_friendbot` handlers for the pattern).
    /// The `NoopPolicyEngine` does not consult this field — validation happens
    /// at the tool-handler layer before the network call.
    pub chain_id_required: bool,
    /// The active CAIP-2 chain identifier for this call (e.g.
    /// `"stellar:testnet"`, `"stellar:mainnet"`).
    ///
    /// Populated by the dispatch site from the call's `chain_id` arg (when
    /// `chain_id_required = true`) or from the profile's `chain_id` field.
    /// Defaults to the empty string when constructed via
    /// [`ToolDescriptor::from_registration`] — `NoopPolicyEngine` does not use
    /// this field; `PolicyEngineV1` requires it to be set.
    pub chain_id: String,
    /// The tool's declared static value shape, sourced from the
    /// `#[mcp_tool_item(value_kind = "…")]` annotation via
    /// [`McpToolRegistration::value_kind`].
    pub value_kind: ToolValueKind,
}

/// A single MCP tool registration record, collected by `inventory` at link time.
///
/// Each `#[mcp_tool_item(...)]`-annotated fn inside a `#[mcp_tool_router]` impl
/// block emits exactly one of these records via
/// `inventory::submit!{ McpToolRegistration { ... } }`.  `WalletServer::new`
/// iterates `inventory::iter::<McpToolRegistration>()` at startup to build the
/// tool registry.
///
/// All fields are `&'static str` / `bool` — no heap allocation at the
/// registration site.
///
/// # Invariants
///
/// - `name` is the same string that appears in the sibling `#[tool(name = "...")]`
///   attribute.  The `registry_walk` integration test asserts this invariant.
/// - `destructive_hint` and `read_only_hint` mirror the sibling
///   `#[tool(annotations(...))]` attribute.  For `stellar_balances` specifically:
///   `destructive_hint == false` and `read_only_hint == true` (verified by test).
/// - `chain_id_required` gates per-tool body chain_id validation.
///
/// # Examples
///
/// ```rust,ignore
/// use stellar_agent_core::policy::McpToolRegistration;
///
/// for reg in inventory::iter::<McpToolRegistration>() {
///     println!("registered: {} (destructive={})", reg.name, reg.destructive_hint);
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct McpToolRegistration {
    /// The registered MCP tool name (static string from the `#[mcp_tool_item]` argument).
    pub name: &'static str,
    /// Whether the tool carries `destructiveHint: true`.
    pub destructive_hint: bool,
    /// Whether the tool carries `readOnlyHint: true`.
    pub read_only_hint: bool,
    /// Indicates the tool requires an explicit `chain_id` argument.
    ///
    /// When `true`, the per-tool body calls
    /// [`crate::profile::validate_chain_id_matches_profile`]
    /// before the network call (see the `stellar_balances` and
    /// `stellar_friendbot` handlers in `stellar-agent-mcp::server`).
    /// The `NoopPolicyEngine` does not consult this field.
    pub chain_id_required: bool,
    /// The tool's declared static value shape.
    ///
    /// Emitted by the `#[mcp_tool_item]` macro from the optional
    /// `value_kind = "read_only" | "moves_value" | "opaque_sign"` argument;
    /// the annotation defaults to [`ToolValueKind::ReadOnly`] when omitted.
    pub value_kind: ToolValueKind,
}

// Register McpToolRegistration as an inventory-collectable type.
// This enables `inventory::iter::<McpToolRegistration>()` to walk all
// records submitted by `#[mcp_tool_router]` expansions across the binary.
//
// SAFETY: McpToolRegistration contains only &'static str and bool — all
// Copy, all thread-safe.  The `inventory::collect!` macro requires the type
// to be 'static, which is satisfied by the 'static str fields.
inventory::collect!(McpToolRegistration);

impl ToolDescriptor {
    /// Constructs a `ToolDescriptor` from a [`McpToolRegistration`].
    ///
    /// This is the primary constructor; it sources all static fields from the
    /// `#[mcp_tool_item]`-emitted registration record, ensuring no drift
    /// between the compile-time annotation and the runtime policy-engine
    /// dispatch.  `chain_id` defaults to the empty string; the dispatch site
    /// populates it before calling [`PolicyEngine::evaluate`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    ///
    /// let reg = McpToolRegistration {
    ///     name: "stellar_balances",
    ///     destructive_hint: false,
    ///     read_only_hint: true,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// };
    /// let d = ToolDescriptor::from_registration(&reg);
    /// assert_eq!(d.name, "stellar_balances");
    /// assert!(!d.destructive_hint);
    /// assert!(d.read_only_hint);
    /// assert!(d.chain_id_required);
    /// assert!(d.chain_id.is_empty());
    /// ```
    #[must_use]
    pub fn from_registration(reg: &McpToolRegistration) -> Self {
        Self {
            name: reg.name.to_owned(),
            destructive_hint: reg.destructive_hint,
            read_only_hint: reg.read_only_hint,
            chain_id_required: reg.chain_id_required,
            chain_id: String::new(),
            value_kind: reg.value_kind,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision
// ─────────────────────────────────────────────────────────────────────────────

/// The policy engine's allow / deny / require-approval decision.
///
/// [`NoopPolicyEngine`] uses only [`Decision::Allow`] for permitted calls and
/// returns `Err(PolicyError::NotImplemented)` for mainnet destructive tools.
/// [`crate::policy::v1::PolicyEngineV1`] produces all three variants.
/// The `dispatch_gate` maps the typed deny to the MCP wire error envelope using
/// [`DenyReason::code`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::{Decision, DenyReason};
///
/// let d = Decision::Deny(DenyReason::NoMatchingRule);
/// assert!(matches!(d, Decision::Deny(DenyReason::NoMatchingRule)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// The tool call is permitted to proceed.
    Allow,
    /// The tool call is denied with a structured reason.
    ///
    /// The `dispatch_gate` serialises the inner value into the MCP wire error
    /// envelope's `data` field.
    Deny(DenyReason),
    /// The tool call requires interactive approval before proceeding.
    ///
    /// The approval nonce and TTL are carried in the [`ApprovalRequest`] payload;
    /// the operator-tty round-trip is handled at the MCP dispatch layer.
    RequireApproval(ApprovalRequest),
}

// ─────────────────────────────────────────────────────────────────────────────
// DenyReason
// ─────────────────────────────────────────────────────────────────────────────

/// Structured reason accompanying a [`Decision::Deny`] outcome.
///
/// Each variant maps to a snake_case wire code returned by [`DenyReason::code`]
/// and emitted by the `dispatch_gate` in the MCP error envelope.
///
/// ## Secret-material policy
///
/// Account IDs stored in `CounterpartyDenied { value }` are un-redacted here;
/// redaction to `Gxxxxx…xxxxx` happens at the `dispatch_gate` formatter
/// boundary, NOT inside this type.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::DenyReason;
///
/// let r = DenyReason::NoMatchingRule;
/// assert_eq!(r.code(), "no_matching_rule");
///
/// let r2 = DenyReason::PerTxCapExceeded {
///     asset: "XLM".into(),
///     max_stroops: 1_000_000,
///     attempted_stroops: 2_000_000,
/// };
/// assert_eq!(r2.code(), "per_tx_cap_exceeded");
///
/// // Explicit operator deny is distinct from the default-deny fallback.
/// assert_eq!(DenyReason::ExplicitRuleDeny.code(), "explicit_rule_deny");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum DenyReason {
    /// The per-transaction amount cap was exceeded.
    PerTxCapExceeded {
        /// Asset code or canonical identifier (e.g. `"XLM"` or
        /// `"USDC:GA5ZSE…"`).
        asset: String,
        /// The configured maximum in stroops.
        ///
        /// `i128` because a token quantity (e.g. a Soroban SAC transfer) can
        /// exceed `i64::MAX`; serialized as a decimal string at the wire
        /// boundary (`#[serde(with = "crate::wire_stroops::i128")]`) since a
        /// JSON number cannot carry this precision losslessly.
        #[serde(with = "crate::wire_stroops::i128")]
        max_stroops: i128,
        /// The attempted transfer amount in stroops.
        #[serde(with = "crate::wire_stroops::i128")]
        attempted_stroops: i128,
    },
    /// The per-period aggregate cap was exceeded.
    PerPeriodCapExceeded {
        /// Asset code or canonical identifier.
        asset: String,
        /// Human-readable window description (e.g. `"rolling_24h"`).
        window: String,
        /// The configured maximum for the period in stroops.
        ///
        /// `i128` for the same reason as [`DenyReason::PerTxCapExceeded`]'s
        /// `max_stroops`; serialized as a decimal string at the wire boundary.
        #[serde(with = "crate::wire_stroops::i128")]
        max_stroops: i128,
        /// The attempted transfer amount in stroops.
        #[serde(with = "crate::wire_stroops::i128")]
        attempted_stroops: i128,
        /// Accumulated spend in the current window in stroops.
        #[serde(with = "crate::wire_stroops::i128")]
        period_used_stroops: i128,
    },
    /// The rate-limit (calls per window) was exceeded.
    RateLimitExceeded {
        /// Human-readable window description (e.g. `"rolling_1h"`).
        window: String,
        /// The configured maximum calls per window.
        max_calls: u32,
        /// The number of calls observed in the current window.
        calls_in_window: u32,
    },
    /// A counterparty was not on the allowlist.
    ///
    /// `kind` is the counterparty kind tag (`"ADDRESS"`, `"HOME_DOMAIN"`,
    /// `"SEP10_IDENTITY"`, or `"ONE_TIME_ADDRESS"`).  `value` holds the
    /// raw G-strkey or domain — redact at the `dispatch_gate` formatter.
    CounterpartyDenied {
        /// The counterparty kind tag.
        kind: String,
        /// The raw counterparty value (un-redacted; see module-level note).
        value: String,
    },
    /// The operation would leave the account below the Stellar minimum reserve.
    MinimumReserveBreached {
        /// Required reserve in stroops (2 + subentry_count) × base_reserve.
        ///
        /// `i128` because the debit that produced this figure may include an
        /// i128 token quantity; serialized as a decimal string at the wire
        /// boundary since a JSON number cannot carry this precision
        /// losslessly.
        #[serde(with = "crate::wire_stroops::i128")]
        reserve_required_stroops: i128,
        /// Current account balance in stroops.
        #[serde(with = "crate::wire_stroops::i128")]
        balance_stroops: i128,
    },
    /// The owner signature is stale; the key was rotated after the policy
    /// was signed.
    OwnerSignatureStale {
        /// ISO-8601 UTC timestamp of the key rotation event.
        rotated_at: String,
    },
    /// No rule in the resolved scope matched the tool call.
    ///
    /// The engine is default-deny: an unmatched call is denied, not allowed.
    NoMatchingRule,
    /// An operator-authored policy rule with `decision = "deny"` matched the
    /// call.
    ///
    /// Distinct from [`DenyReason::NoMatchingRule`] (the engine's default-deny
    /// fallback when no rule matched).  Use this variant when a rule is present
    /// in the document and its `decision` field is set to `"deny"` — i.e. the
    /// operator explicitly chose to deny this tool call.
    ///
    /// The wire code is `policy.deny.explicit_rule_deny`.
    ///
    /// `loader.rs` returns this variant from `parse_decision("deny")`.
    ExplicitRuleDeny,
    /// The counterparty kind is not supported by this engine version.
    ///
    /// Forward-compat for counterparty kinds not yet handled by the typed
    /// criteria surface (e.g. `SEP10_IDENTITY`, `HOME_DOMAIN`, `ONE_TIME_ADDRESS`).
    CounterpartyKindUnsupported {
        /// The unsupported kind tag.
        kind: String,
    },
    /// The criterion evaluator encountered an internal error.
    ///
    /// Forward-compat variant; used when a criterion hits a path not covered
    /// by the typed surface.
    EvaluationError {
        /// Non-secret diagnostic detail.
        detail: String,
    },

    /// A value criterion in the matched rule cannot size this call's value
    /// effect, so the call is denied fail-closed.
    ///
    /// Produced when a `MovesValue` tool reached a value criterion without the
    /// dispatch site resolving concrete `ValueClass::Value(effects)` (a
    /// forgotten population is denied, never waved through), or when an
    /// `OpaqueSign` tool (`ValueClass::Opaque`) is matched by a broad value
    /// rule that has not opted it out via `allow_opaque_signing`.
    ///
    /// Wire code: `policy.deny.unsizable_value_effect`.
    ///
    /// `detail` is a non-secret diagnostic (tool name and the unsizable reason);
    /// it never carries key material or user-supplied secret input.
    UnsizableValueEffect {
        /// Non-secret diagnostic detail (tool name + reason).
        detail: String,
    },

    // ── Bundle-level criteria ──────────────────────────────────────────────
    /// The number of inner invocations in a multicall bundle exceeded the cap.
    ///
    /// Wire code: `policy.inner_invocation_count_cap_exceeded`.
    InnerInvocationCountCapExceeded {
        /// The configured maximum number of inner invocations.
        max: u32,
        /// The actual number of inner invocations in the bundle.
        attempted: u32,
    },

    /// The aggregate transfer amount across a multicall bundle exceeded the cap.
    ///
    /// Wire code: `policy.bundle_aggregate_cap_exceeded`.
    BundleAggregateCapExceeded {
        /// The asset filter for the cap, or `None` for a cross-asset cap.
        asset: Option<String>,
        /// The configured maximum aggregate amount.
        max: i128,
        /// The actual aggregate sum of matching `TokenTransfer` inners.
        sum: i128,
    },

    /// A multicall bundle contains an inner operation with an unrecognised ABI
    /// shape (`InnerOpDescriptor::Generic`).
    ///
    /// Wire code: `policy.bundle_contains_generic_kind`.
    BundleContainsGenericKind {
        /// The index of the first Generic inner in the bundle.
        inner_index: u32,
    },

    /// An inner operation within a multicall bundle was denied.
    ///
    /// This is the outer-wrapper variant produced by
    /// [`crate::policy::v1::PolicyEngineV1::evaluate_bundle`] when an inner
    /// operation's per-inner evaluation returns a deny.
    ///
    /// Wire code: `policy.bundle_denied`.
    BundleDenied {
        /// The index of the inner that was denied.
        inner_index: u32,
        /// The deny reason produced by the inner's criterion evaluation.
        deny_reason: Box<DenyReason>,
    },

    // ── Quorum-satisfaction criterion ─────────────────────────────────────
    /// The proposed signer set did not satisfy the declared quorum.
    ///
    /// Wire code: `policy.quorum_not_satisfied`.
    ///
    /// Produced by `quorum_satisfied::QuorumSatisfiedCriterion` when
    /// `ctx.quorum.groups_short_by()` returns a non-empty slice.
    QuorumNotSatisfied {
        /// Names of the signer groups whose threshold was not met.
        ///
        /// For `Combinator::And`: the subset of groups that failed.
        /// For `Combinator::Or`: all group names (none was satisfied).
        groups_short_by: Vec<String>,
        /// Human-readable combinator label (`"And"` or `"Or"`).
        combinator: String,
    },

    // ── Home-domain-resolved criterion ────────────────────────────────
    /// The destination account's on-chain `home_domain` has not been
    /// resolved and cached via `stellar-agent counterparty refresh`.
    ///
    /// Wire code: `policy.home_domain_not_resolved`.
    ///
    /// Produced by `home_domain_resolved::HomeDomainResolvedCriterion`
    /// when `ctx.counterparty_cache.has_resolved(home_domain)` returns
    /// `false` for the destination account's on-chain `home_domain`.
    ///
    /// The `home_domain` field carries the raw ASCII home_domain string
    /// from the on-chain `AccountEntry`.  ASCII home_domain strings are
    /// public infrastructure metadata; the full value is acceptable in the
    /// deny payload (no user-secret content).  The `dispatch_gate`
    /// formatter may truncate for display; no redaction is required here.
    HomeDomainNotResolved {
        /// The on-chain `AccountEntry.home_domain` value that was not found
        /// in the counterparty cache.
        home_domain: String,
    },

    // ── SEP-10 session criterion ───────────────────────────────────────
    /// No active SEP-10 session exists for the given account.
    ///
    /// Wire code: `policy.sep10.session_missing`.
    ///
    /// Produced by `sep10_session_active::Sep10SessionActiveCriterion`
    /// when `ctx.sep10_sessions.is_active(account_id, now_unix)` returns
    /// `false`, or when `ctx.sep10_sessions` is `None` (fail-closed).
    ///
    /// The `account_id` field carries the G-strkey of the account whose
    /// session is missing.
    ///
    /// The `dispatch_gate` formatter (`redact_deny_reason` in
    /// `stellar-agent-mcp/src/tools/common.rs`) redacts this field to
    /// first-5-last-5 before it crosses the MCP wire boundary.
    Sep10SessionMissing {
        /// The G-strkey of the account whose SEP-10 session was not found
        /// or has expired. Redacted at the MCP dispatch-gate boundary.
        account_id: String,
    },

    // ── SEP-45 session criterion ───────────────────────────────────────
    /// No active SEP-45 session exists for the given contract account.
    ///
    /// Wire code: `policy.sep45.session_missing`.
    ///
    /// Produced by `sep45_session_active::Sep45SessionActiveCriterion`
    /// when `ctx.sep45_sessions.is_active(contract_id, now_unix)` returns
    /// `false`, or when `ctx.sep45_sessions` is `None` (fail-closed).
    ///
    /// The `contract_id` field carries the C-strkey of the contract account
    /// whose session is missing.
    ///
    /// The `dispatch_gate` formatter (`redact_deny_reason` in
    /// `stellar-agent-mcp/src/tools/common.rs`) redacts this field to
    /// first-5-last-5 before it crosses the MCP wire boundary.
    Sep45SessionMissing {
        /// The C-strkey of the contract account whose SEP-45 session was not
        /// found or has expired. Redacted at the MCP dispatch-gate boundary.
        contract_id: String,
    },
}

impl DenyReason {
    /// Returns the snake_case wire-code suffix used by `dispatch_gate` when
    /// mapping a typed deny to the `policy.deny.<code>` MCP wire response.
    ///
    /// # Prefix convention
    ///
    /// Returns the snake_case suffix only (e.g. `"per_tx_cap_exceeded"`). The
    /// `dispatch_gate` prepends `policy.deny.` to produce the full wire code on
    /// the JSON-RPC envelope (e.g. `policy.deny.per_tx_cap_exceeded`). Do NOT
    /// prepend the prefix here — see [`PolicyError::wire_code`] for the parallel
    /// method that returns the full prefixed wire code (load-time errors are not
    /// routed through `dispatch_gate`).
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::DenyReason;
    ///
    /// assert_eq!(DenyReason::NoMatchingRule.code(), "no_matching_rule");
    /// assert_eq!(
    ///     DenyReason::PerTxCapExceeded {
    ///         asset: "XLM".into(),
    ///         max_stroops: 100,
    ///         attempted_stroops: 200,
    ///     }
    ///     .code(),
    ///     "per_tx_cap_exceeded"
    /// );
    /// ```
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::PerTxCapExceeded { .. } => "per_tx_cap_exceeded",
            Self::PerPeriodCapExceeded { .. } => "per_period_cap_exceeded",
            Self::RateLimitExceeded { .. } => "rate_limit_exceeded",
            Self::CounterpartyDenied { .. } => "counterparty_denied",
            Self::MinimumReserveBreached { .. } => "minimum_reserve_breached",
            Self::OwnerSignatureStale { .. } => "owner_signature_stale",
            Self::NoMatchingRule => "no_matching_rule",
            Self::CounterpartyKindUnsupported { .. } => "counterparty_kind_unsupported",
            Self::EvaluationError { .. } => "evaluation_error",
            Self::UnsizableValueEffect { .. } => "unsizable_value_effect",
            Self::ExplicitRuleDeny => "explicit_rule_deny",
            Self::InnerInvocationCountCapExceeded { .. } => "inner_invocation_count_cap_exceeded",
            Self::BundleAggregateCapExceeded { .. } => "bundle_aggregate_cap_exceeded",
            Self::BundleContainsGenericKind { .. } => "bundle_contains_generic_kind",
            Self::BundleDenied { .. } => "bundle_denied",
            Self::QuorumNotSatisfied { .. } => "quorum_not_satisfied",
            Self::HomeDomainNotResolved { .. } => "home_domain_not_resolved",
            Self::Sep10SessionMissing { .. } => "sep10.session_missing",
            Self::Sep45SessionMissing { .. } => "sep45.session_missing",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApprovalRequest
// ─────────────────────────────────────────────────────────────────────────────

/// Payload carried by [`Decision::RequireApproval`].
///
/// The `nonce` uniquely identifies the pending approval; `ttl_seconds` caps
/// how long the approval window remains open before it expires.  The optional
/// `reason` carries operator-facing rule context only; it is not a trust input.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::ApprovalRequest;
///
/// let req = ApprovalRequest::new("abc-nonce".into(), 300);
/// assert_eq!(req.nonce, "abc-nonce");
/// assert_eq!(req.ttl_seconds, 300);
/// assert!(req.reason.is_none());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequest {
    /// Unique nonce identifying the pending approval.
    pub nonce: String,
    /// Approval window lifetime in seconds.
    pub ttl_seconds: u32,
    /// Optional operator-supplied reason for requiring approval.
    ///
    /// Sourced from the rule TOML's optional `reason` key.  Used for
    /// operator-facing display in the approval prompt; never used as a
    /// trust input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional bridge URL to open in the operator's browser.
    ///
    /// When the policy engine determines that WebAuthn browser-handoff is
    /// required, the bridge sets this field to the approval page URL (e.g.
    /// `http://127.0.0.1:<port>/approve/<nonce>` or
    /// `http://127.0.0.1:<port>/register/<nonce>`).
    ///
    /// `None` for `PaymentSimulated` approvals or when the bridge is not
    /// running.  The CLI agent presents this URL to the operator when non-`None`.
    ///
    /// Serialised with `skip_serializing_if = "Option::is_none"` for backward
    /// compatibility: callers that check only `nonce` and `ttl_seconds` are
    /// unaffected when this field is absent from the wire payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_url: Option<String>,
}

impl ApprovalRequest {
    /// Constructs a new [`ApprovalRequest`] with the given nonce and TTL.
    ///
    /// The `reason` and `approval_url` fields default to `None`; use
    /// [`Self::with_reason`] and [`Self::with_approval_url`] to set them.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::ApprovalRequest;
    ///
    /// let req = ApprovalRequest::new("nonce-1".into(), 60);
    /// assert_eq!(req.ttl_seconds, 60);
    /// assert!(req.reason.is_none());
    /// assert!(req.approval_url.is_none());
    /// ```
    #[must_use]
    pub fn new(nonce: String, ttl_seconds: u32) -> Self {
        Self {
            nonce,
            ttl_seconds,
            reason: None,
            approval_url: None,
        }
    }

    /// Returns `self` with the `reason` field set.
    ///
    /// Builder-style; consumes and returns the struct so callers can chain or
    /// rebind.
    #[must_use]
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Returns `self` with the `approval_url` field set.
    ///
    /// The URL is the full bridge page URL to open in the operator's browser
    /// for the WebAuthn ceremony (e.g.
    /// `http://127.0.0.1:54321/approve/NONCE` or
    /// `http://127.0.0.1:54321/register/NONCE`).
    ///
    /// Builder-style; consumes and returns the struct so callers can chain or
    /// rebind after handling URL validation.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Invalid`] if the URL is not an HTTP URL on
    /// `127.0.0.1` or `localhost`, does not carry an explicit port, or its path
    /// does not start with `/approve/` or `/register/`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::ApprovalRequest;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::ApprovalError> {
    /// let req = ApprovalRequest::new("nonce-1".into(), 60).with_approval_url(
    ///     "http://127.0.0.1:54321/approve/nonce-1".into(),
    /// )?;
    /// assert_eq!(
    ///     req.approval_url.as_deref(),
    ///     Some("http://127.0.0.1:54321/approve/nonce-1"),
    /// );
    /// # Ok(()) }
    /// ```
    pub fn with_approval_url(mut self, url: String) -> Result<Self, ApprovalError> {
        validate_approval_url(&url)?;
        self.approval_url = Some(url);
        Ok(self)
    }
}

fn validate_approval_url(candidate: &str) -> Result<(), ApprovalError> {
    let parsed = url::Url::parse(candidate).map_err(|e| ApprovalError::Invalid {
        reason: format!("approval_url must be a valid URL: {e}"),
    })?;

    if parsed.scheme() != "http" {
        return Err(ApprovalError::Invalid {
            reason: "approval_url scheme must be http".to_owned(),
        });
    }

    let Some(host) = parsed.host_str() else {
        return Err(ApprovalError::Invalid {
            reason: "approval_url host is required".to_owned(),
        });
    };
    if host != "127.0.0.1" && !host.eq_ignore_ascii_case("localhost") {
        return Err(ApprovalError::Invalid {
            reason: "approval_url host must be 127.0.0.1 or localhost".to_owned(),
        });
    }

    if parsed.port().is_none() {
        return Err(ApprovalError::Invalid {
            reason: "approval_url port is required".to_owned(),
        });
    }

    let path = parsed.path();
    if !path.starts_with("/approve/") && !path.starts_with("/register/") {
        return Err(ApprovalError::Invalid {
            reason: "approval_url path must start with /approve/ or /register/".to_owned(),
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by [`PolicyEngine::evaluate`] or by the policy subsystem
/// (loader, signer, evaluator).
///
/// ## Layer placement note
///
/// This `policy::PolicyError` lives at the policy-engine layer.  Do not
/// consolidate it with the `error` module's `WalletError` taxonomy; the two
/// carry different semantic contracts.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The full policy engine is not yet implemented.
    ///
    /// Returned by [`NoopPolicyEngine`] for destructive tools on mainnet
    /// profiles.  The MCP dispatch site propagates this as
    /// `policy.engine_required`.
    ///
    /// Returned by [`NoopPolicyEngine`] when no full policy engine is configured.
    /// Substitute a real `PolicyEngine` implementation to enable mainnet writes.
    #[error(
        "policy engine not implemented for mainnet destructive tools; \
         configure a full policy engine to enable mainnet writes \
         (policy.engine_required)"
    )]
    NotImplemented,

    /// The policy file could not be read from disk.
    ///
    /// `detail` contains the non-secret diagnostic (path, OS error code).
    /// Never include key material or secret paths in `detail`.
    #[error("policy file load failed: {detail}")]
    PolicyFileLoadFailed {
        /// Non-secret diagnostic detail (path and OS error description).
        detail: String,
    },

    /// The policy file could not be deserialized.
    ///
    /// `detail` contains the parse error message (no secret material).
    #[error("policy file parse failed: {detail}")]
    PolicyFileParseFailed {
        /// Non-secret parse error description.
        detail: String,
    },

    /// The owner signature on the policy file is invalid.
    #[error("owner signature invalid for profile {profile}")]
    OwnerSignatureInvalid {
        /// The profile name whose owner key was used for verification.
        profile: String,
    },

    /// The keyring does not contain an owner key for the given profile.
    #[error("missing owner key in keyring for profile {profile}")]
    MissingOwnerKey {
        /// The profile name whose owner key is absent.
        profile: String,
    },

    /// The policy scope could not be resolved for the given profile / project
    /// combination.
    #[error("scope resolution failed: {detail}")]
    ScopeResolutionFailed {
        /// Non-secret diagnostic detail.
        detail: String,
    },

    /// A criterion returned an error during evaluation.
    ///
    /// `detail` contains the non-secret evaluator diagnostic.
    #[error("criterion evaluation failed: {detail}")]
    CriterionEvaluationFailed {
        /// Non-secret evaluator diagnostic.
        detail: String,
    },
}

impl PolicyError {
    /// Returns the semver-stable JSON-RPC wire code for this policy error.
    ///
    /// # Prefix convention
    ///
    /// Returns the full wire code with the `policy.` prefix baked in (e.g.
    /// `"policy.engine_required"`). Unlike [`DenyReason::code`] (which returns a
    /// suffix that the `dispatch_gate` prepends `policy.deny.` to), `PolicyError`
    /// represents load-time failures that are surfaced directly to the operator
    /// without going through `dispatch_gate`, so the prefix is embedded here for
    /// callers' convenience.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::PolicyError;
    ///
    /// assert_eq!(
    ///     PolicyError::NotImplemented.wire_code(),
    ///     "policy.engine_required"
    /// );
    /// assert_eq!(
    ///     PolicyError::MissingOwnerKey {
    ///         profile: "default".to_owned(),
    ///     }
    ///     .wire_code(),
    ///     "policy.missing_owner_key"
    /// );
    /// ```
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::NotImplemented => "policy.engine_required",
            Self::PolicyFileLoadFailed { .. } => "policy.policy_file_load_failed",
            Self::PolicyFileParseFailed { .. } => "policy.policy_file_parse_failed",
            Self::OwnerSignatureInvalid { .. } => "policy.owner_signature_invalid",
            Self::MissingOwnerKey { .. } => "policy.missing_owner_key",
            Self::ScopeResolutionFailed { .. } => "policy.scope_resolution_failed",
            Self::CriterionEvaluationFailed { .. } => "policy.criterion_evaluation_failed",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyEngine trait
// ─────────────────────────────────────────────────────────────────────────────

/// Binding mechanism for the mainnet MCP write-tools gate.
///
/// Every `tools/call` dispatch unconditionally calls
/// `policy_engine.evaluate(tool, args, profile)`.  The registered
/// implementation is swapped at process start — [`NoopPolicyEngine`] is the
/// default when no engine is configured; [`crate::policy::v1::PolicyEngineV1`]
/// is the typed-criteria evaluator.  The call site is unchanged regardless of
/// which implementation is registered.
///
/// Implementations MUST be `Send + Sync` because the `PolicyEngine` is held as
/// `Arc<dyn PolicyEngine>` in the MCP server process.
///
/// # Errors
///
/// Returns [`PolicyError`] when the policy engine denies the tool call.  The
/// caller maps `Err(PolicyError::NotImplemented)` to the `policy.engine_required`
/// wire-format error code.
pub trait PolicyEngine: Send + Sync {
    /// Evaluates whether the given tool call is permitted under the active profile.
    ///
    /// Returns the [`Decision`] ONLY and discards any value descriptor the engine
    /// sizes while deciding. A value-moving dispatch path MUST call
    /// [`Self::evaluate_full`] instead: the value-verb audit row records exactly
    /// the effects the gate sized, and a dispatch that gates through this view
    /// silently loses them. This decision-only view is for callers that record no
    /// value row — read-only gates, criteria-internal checks, and tests.
    ///
    /// # Arguments
    ///
    /// - `tool` — the tool descriptor for the tool being invoked.
    /// - `args` — the raw JSON arguments supplied by the agent.
    /// - `profile` — the currently-active profile.
    /// - `account_view` — optional account reserve view for the minimum-reserve
    ///   criterion.  Pass `None` when the criterion is not active or when account
    ///   state is not available at the call site.
    /// - `identity_view` — optional account identity view for the HOME_DOMAIN
    ///   counterparty criterion.  Pass `None` when the criterion is not active.
    ///   Kept separate from `AccountReservesView` to prevent silent-fail on
    ///   HOME_DOMAIN lookups when only the reserve view is present.
    /// - `counterparty_cache` — optional frozen snapshot of the resolved
    ///   counterparty cache for the `home_domain_resolved` criterion.  Pass
    ///   `None` when the criterion is not active or when no resolver handle is
    ///   available at the dispatch site.
    /// - `sep10_sessions` — optional SEP-10 session view for the
    ///   `sep10_session_active` criterion.  Pass `None` when the criterion is
    ///   not active or when no session store is available at the dispatch site.
    /// - `sep45_sessions` — optional SEP-45 session view for the
    ///   `sep45_session_active` criterion.  Pass `None` when the criterion is
    ///   not active or when no session store is available at the dispatch site.
    ///
    /// # Errors
    ///
    /// - [`PolicyError::NotImplemented`] — the full policy engine is not yet
    ///   available for this tool/profile combination.
    // Each argument represents a distinct injectable view that a downstream
    // criterion type may consume.  Bundling into a builder or struct would
    // obscure the injection points and complicate the `NoopPolicyEngine` impl.
    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &self,
        tool: &ToolDescriptor,
        args: &serde_json::Value,
        profile: &Profile,
        account_view: Option<&dyn crate::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn crate::policy::v1::AccountIdentityView>,
        counterparty_cache: Option<&dyn crate::policy::v1::CounterpartyCacheView>,
        sep10_sessions: Option<&dyn crate::policy::v1::Sep10SessionView>,
        sep45_sessions: Option<&dyn crate::policy::v1::Sep45SessionView>,
    ) -> Result<Decision, PolicyError>;

    /// Evaluates a tool call with the value descriptor supplied explicitly by
    /// the dispatch site.
    ///
    /// For single-shot Soroban tools (DeFi, x402, MPP charge) whose value cannot
    /// appear in the pre-decode `args`, the handler resolves the effects and the
    /// signed operation from ONE decoded value (§2.1 single-decode invariant) and
    /// passes the resolved [`crate::policy::v1::ValueClass`] here.
    ///
    /// The default implementation ignores `value` and delegates to
    /// [`Self::evaluate`], which is correct for engines that do not size value
    /// (e.g. [`NoopPolicyEngine`]). Engines that size value
    /// ([`crate::policy::v1::PolicyEngineV1`]) override it to gate on the supplied
    /// descriptor.
    ///
    /// Returns the [`Decision`] ONLY and discards the sized descriptor. A
    /// value-moving dispatch path MUST call [`Self::evaluate_with_value_full`]
    /// instead so the effects reach the audit row; this decision-only view is for
    /// callers that record no value row.
    ///
    /// # Errors
    ///
    /// Same as [`Self::evaluate`].
    #[allow(clippy::too_many_arguments)]
    fn evaluate_with_value(
        &self,
        tool: &ToolDescriptor,
        args: &serde_json::Value,
        profile: &Profile,
        _value: crate::policy::v1::ValueClass,
        account_view: Option<&dyn crate::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn crate::policy::v1::AccountIdentityView>,
        counterparty_cache: Option<&dyn crate::policy::v1::CounterpartyCacheView>,
        sep10_sessions: Option<&dyn crate::policy::v1::Sep10SessionView>,
        sep45_sessions: Option<&dyn crate::policy::v1::Sep45SessionView>,
    ) -> Result<Decision, PolicyError> {
        self.evaluate(
            tool,
            args,
            profile,
            account_view,
            identity_view,
            counterparty_cache,
            sep10_sessions,
            sep45_sessions,
        )
    }

    /// Evaluates a tool call and additionally surfaces the value descriptor the
    /// engine sized, for callers (e.g. the audit emission path) that must record
    /// exactly what the gate evaluated.
    ///
    /// The default returns the [`Self::evaluate`] decision with
    /// `value_effects = None`, correct for engines that do not size value
    /// ([`NoopPolicyEngine`]). [`crate::policy::v1::PolicyEngineV1`] overrides
    /// this to surface the exact [`ValueEffects`](crate::policy::v1::ValueEffects)
    /// its value criteria sized (single-derivation invariant).
    ///
    /// # Errors
    ///
    /// Same as [`Self::evaluate`].
    #[allow(clippy::too_many_arguments)]
    fn evaluate_full(
        &self,
        tool: &ToolDescriptor,
        args: &serde_json::Value,
        profile: &Profile,
        account_view: Option<&dyn crate::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn crate::policy::v1::AccountIdentityView>,
        counterparty_cache: Option<&dyn crate::policy::v1::CounterpartyCacheView>,
        sep10_sessions: Option<&dyn crate::policy::v1::Sep10SessionView>,
        sep45_sessions: Option<&dyn crate::policy::v1::Sep45SessionView>,
    ) -> Result<Evaluation, PolicyError> {
        let decision = self.evaluate(
            tool,
            args,
            profile,
            account_view,
            identity_view,
            counterparty_cache,
            sep10_sessions,
            sep45_sessions,
        )?;
        Ok(Evaluation {
            decision,
            value_effects: None,
        })
    }

    /// Value-carrying counterpart of [`Self::evaluate_full`].
    ///
    /// The default returns the [`Self::evaluate_with_value`] decision with
    /// `value_effects = None`; value-sizing engines override it to echo the
    /// supplied descriptor's effects back on the allow path.
    ///
    /// # Errors
    ///
    /// Same as [`Self::evaluate_with_value`].
    #[allow(clippy::too_many_arguments)]
    fn evaluate_with_value_full(
        &self,
        tool: &ToolDescriptor,
        args: &serde_json::Value,
        profile: &Profile,
        value: crate::policy::v1::ValueClass,
        account_view: Option<&dyn crate::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn crate::policy::v1::AccountIdentityView>,
        counterparty_cache: Option<&dyn crate::policy::v1::CounterpartyCacheView>,
        sep10_sessions: Option<&dyn crate::policy::v1::Sep10SessionView>,
        sep45_sessions: Option<&dyn crate::policy::v1::Sep45SessionView>,
    ) -> Result<Evaluation, PolicyError> {
        let decision = self.evaluate_with_value(
            tool,
            args,
            profile,
            value,
            account_view,
            identity_view,
            counterparty_cache,
            sep10_sessions,
            sep45_sessions,
        )?;
        Ok(Evaluation {
            decision,
            value_effects: None,
        })
    }
}

/// Outcome of a policy evaluation: the [`Decision`] plus the value descriptor
/// the engine sized on the allow path, when the engine sizes value.
///
/// `value_effects` is `Some` only for a [`Decision::Allow`] from an engine that
/// sizes value ([`crate::policy::v1::PolicyEngineV1`]); it is `None` for
/// read-only/opaque tools, for denials, and for engines that do not size value.
/// It carries the SAME [`ValueEffects`](crate::policy::v1::ValueEffects) the
/// value criteria evaluated, so a caller records exactly what the gate sized
/// (single-derivation invariant) without re-deriving. Not `Serialize`: it
/// crosses only in-process.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Evaluation {
    /// The policy decision.
    pub decision: Decision,
    /// The value descriptor the engine sized on the allow path, or `None`.
    pub value_effects: Option<crate::policy::v1::ValueEffects>,
}

// ─────────────────────────────────────────────────────────────────────────────
// NoopPolicyEngine
// ─────────────────────────────────────────────────────────────────────────────

/// No-op policy engine used when no full engine is configured.
///
/// The evaluation logic is:
///
/// | Profile | Tool | Result |
/// |---------|------|--------|
/// | testnet | any  | `Ok(Decision::Allow)` |
/// | mainnet | read-only (`destructive_hint = false`) | `Ok(Decision::Allow)` |
/// | mainnet | destructive (`destructive_hint = true`) | `Err(PolicyError::NotImplemented)` |
///
/// This acts as the binding gate that prevents mainnet writes when no real
/// `PolicyEngine` is configured.  Substitute [`crate::policy::v1::PolicyEngineV1`]
/// to enable typed-criteria evaluation on mainnet.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::{
///     Decision, McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor,
/// };
/// use stellar_agent_core::profile::schema::Profile;
///
/// let engine = NoopPolicyEngine;
/// let args = serde_json::Value::Null;
///
/// // Testnet: destructive tool is allowed.
/// let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
///     .with_noop_engine()
///     .build();
/// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
///     name: "stellar_pay", destructive_hint: true, read_only_hint: false, chain_id_required: true,
///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
/// });
/// assert_eq!(engine.evaluate(&tool, &args, &profile, None, None, None, None, None).unwrap(), Decision::Allow);
///
/// // Mainnet: read-only tool is allowed.
/// let profile_mainnet = Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
///     .with_noop_engine()
///     .build();
/// let read_tool = ToolDescriptor::from_registration(&McpToolRegistration {
///     name: "stellar_balances", destructive_hint: false, read_only_hint: true, chain_id_required: true,
///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
/// });
/// assert_eq!(engine.evaluate(&read_tool, &args, &profile_mainnet, None, None, None, None, None).unwrap(), Decision::Allow);
///
/// // Mainnet: destructive tool is NOT implemented yet.
/// let write_tool = ToolDescriptor::from_registration(&McpToolRegistration {
///     name: "stellar_pay", destructive_hint: true, read_only_hint: false, chain_id_required: true,
///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
/// });
/// assert!(engine.evaluate(&write_tool, &args, &profile_mainnet, None, None, None, None, None).is_err());
/// ```
pub struct NoopPolicyEngine;

impl PolicyEngine for NoopPolicyEngine {
    fn evaluate(
        &self,
        tool: &ToolDescriptor,
        _args: &serde_json::Value,
        profile: &Profile,
        _account_view: Option<&dyn crate::policy::v1::AccountReservesView>,
        _identity_view: Option<&dyn crate::policy::v1::AccountIdentityView>,
        _counterparty_cache: Option<&dyn crate::policy::v1::CounterpartyCacheView>,
        _sep10_sessions: Option<&dyn crate::policy::v1::Sep10SessionView>,
        _sep45_sessions: Option<&dyn crate::policy::v1::Sep45SessionView>,
    ) -> Result<Decision, PolicyError> {
        // Testnet: all tools allowed.
        if !profile.chain_id.is_mainnet() {
            return Ok(Decision::Allow);
        }

        // Mainnet + read-only: allowed.
        if !tool.destructive_hint {
            return Ok(Decision::Allow);
        }

        // Mainnet + destructive: no engine configured.
        Err(PolicyError::NotImplemented)
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    fn testnet_profile() -> Profile {
        Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build()
    }

    fn mainnet_profile() -> Profile {
        Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build()
    }

    fn destructive_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: false,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn read_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_balances",
            destructive_hint: false,
            read_only_hint: false,
            chain_id_required: false,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    #[test]
    fn testnet_destructive_tool_allowed() {
        let engine = NoopPolicyEngine;
        let result = engine.evaluate(
            &destructive_tool(),
            &serde_json::Value::Null,
            &testnet_profile(),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(result.unwrap(), Decision::Allow);
    }

    #[test]
    fn testnet_read_tool_allowed() {
        let engine = NoopPolicyEngine;
        let result = engine.evaluate(
            &read_tool(),
            &serde_json::Value::Null,
            &testnet_profile(),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(result.unwrap(), Decision::Allow);
    }

    #[test]
    fn mainnet_read_tool_allowed() {
        let engine = NoopPolicyEngine;
        let result = engine.evaluate(
            &read_tool(),
            &serde_json::Value::Null,
            &mainnet_profile(),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(result.unwrap(), Decision::Allow);
    }

    #[test]
    fn mainnet_destructive_tool_not_implemented() {
        let engine = NoopPolicyEngine;
        let result = engine.evaluate(
            &destructive_tool(),
            &serde_json::Value::Null,
            &mainnet_profile(),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            matches!(result, Err(PolicyError::NotImplemented)),
            "expected NotImplemented, got {result:?}"
        );
    }

    #[test]
    fn noop_engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopPolicyEngine>();
    }

    #[test]
    fn policy_error_not_implemented_message_contains_engine_required() {
        let err = PolicyError::NotImplemented;
        let msg = err.to_string();
        assert!(
            msg.contains("policy.engine_required"),
            "error message must reference the wire-format code: {msg}"
        );
    }

    fn representative_policy_errors(detail: &str, profile: &str) -> Vec<PolicyError> {
        // Exhaustiveness guard: forces compile-time verification that every
        // PolicyError variant is represented below. This is belt-and-braces with
        // wire_code(), which already fails compilation on a variant addition; the
        // guard makes the test driver's full-coverage dependency explicit.
        fn _exhaustiveness_guard(e: &PolicyError) {
            match e {
                PolicyError::NotImplemented => {}
                PolicyError::PolicyFileLoadFailed { .. } => {}
                PolicyError::PolicyFileParseFailed { .. } => {}
                PolicyError::OwnerSignatureInvalid { .. } => {}
                PolicyError::MissingOwnerKey { .. } => {}
                PolicyError::ScopeResolutionFailed { .. } => {}
                PolicyError::CriterionEvaluationFailed { .. } => {}
            }
        }

        vec![
            PolicyError::NotImplemented,
            PolicyError::PolicyFileLoadFailed {
                detail: detail.to_owned(),
            },
            PolicyError::PolicyFileParseFailed {
                detail: detail.to_owned(),
            },
            PolicyError::OwnerSignatureInvalid {
                profile: profile.to_owned(),
            },
            PolicyError::MissingOwnerKey {
                profile: profile.to_owned(),
            },
            PolicyError::ScopeResolutionFailed {
                detail: detail.to_owned(),
            },
            PolicyError::CriterionEvaluationFailed {
                detail: detail.to_owned(),
            },
        ]
    }

    fn expected_policy_error_wire_code(err: &PolicyError) -> &'static str {
        match err {
            PolicyError::NotImplemented => "policy.engine_required",
            PolicyError::PolicyFileLoadFailed { .. } => "policy.policy_file_load_failed",
            PolicyError::PolicyFileParseFailed { .. } => "policy.policy_file_parse_failed",
            PolicyError::OwnerSignatureInvalid { .. } => "policy.owner_signature_invalid",
            PolicyError::MissingOwnerKey { .. } => "policy.missing_owner_key",
            PolicyError::ScopeResolutionFailed { .. } => "policy.scope_resolution_failed",
            PolicyError::CriterionEvaluationFailed { .. } => "policy.criterion_evaluation_failed",
        }
    }

    fn is_policy_wire_code(code: &str) -> bool {
        let Some(suffix) = code.strip_prefix("policy.") else {
            return false;
        };
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
    }

    #[test]
    fn policy_error_wire_codes_are_unique_and_stable() {
        let errors = representative_policy_errors("detail", "profile");
        let mut seen = HashSet::new();

        for err in &errors {
            let code = err.wire_code();
            assert_eq!(code, expected_policy_error_wire_code(err));
            assert!(is_policy_wire_code(code), "invalid wire code: {code}");
            assert!(seen.insert(code), "duplicate wire code: {code}");
        }

        assert_eq!(
            seen.len(),
            representative_policy_errors("d", "p").len(),
            "wire codes must be unique across all variants"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn policy_error_wire_codes_do_not_depend_on_payload(
            detail in "[a-z0-9_./:-]{0,64}",
            profile in "[a-z0-9_./:-]{0,64}",
        ) {
            for err in representative_policy_errors(&detail, &profile) {
                prop_assert_eq!(err.wire_code(), expected_policy_error_wire_code(&err));
                prop_assert!(is_policy_wire_code(err.wire_code()));
            }
        }
    }

    // ── DenyReason::code() — one assertion per variant ───────────────────────

    #[test]
    fn deny_reason_code_per_tx_cap_exceeded() {
        let r = DenyReason::PerTxCapExceeded {
            asset: "XLM".into(),
            max_stroops: 100,
            attempted_stroops: 200,
        };
        assert_eq!(r.code(), "per_tx_cap_exceeded");
    }

    #[test]
    fn deny_reason_code_per_period_cap_exceeded() {
        let r = DenyReason::PerPeriodCapExceeded {
            asset: "XLM".into(),
            window: "rolling_24h".into(),
            max_stroops: 100,
            attempted_stroops: 200,
            period_used_stroops: 50,
        };
        assert_eq!(r.code(), "per_period_cap_exceeded");
    }

    #[test]
    fn deny_reason_code_rate_limit_exceeded() {
        let r = DenyReason::RateLimitExceeded {
            window: "rolling_1h".into(),
            max_calls: 10,
            calls_in_window: 11,
        };
        assert_eq!(r.code(), "rate_limit_exceeded");
    }

    #[test]
    fn deny_reason_code_counterparty_denied() {
        let r = DenyReason::CounterpartyDenied {
            kind: "ADDRESS".into(),
            value: "GABC123".into(),
        };
        assert_eq!(r.code(), "counterparty_denied");
    }

    #[test]
    fn deny_reason_code_minimum_reserve_breached() {
        let r = DenyReason::MinimumReserveBreached {
            reserve_required_stroops: 5_000_000,
            balance_stroops: 4_000_000,
        };
        assert_eq!(r.code(), "minimum_reserve_breached");
    }

    // ── i128 stroop-field wire encoding (decimal string, no clamp) ───────────

    /// `PerTxCapExceeded`'s stroop fields carry a value strictly greater than
    /// `i64::MAX` (an i128 token quantity) and must serialize as decimal
    /// STRINGS, not JSON numbers — a JSON number cannot carry this precision
    /// losslessly across a JS/TS MCP client. Asserts the exact full i128
    /// decimal, not merely "is a string".
    #[test]
    fn deny_reason_per_tx_cap_exceeded_i128_beyond_i64_max_serializes_as_decimal_string() {
        let max_stroops: i128 = i128::from(i64::MAX) + 1;
        let attempted_stroops: i128 = i128::from(i64::MAX) + 2;
        let r = DenyReason::PerTxCapExceeded {
            asset: "native".into(),
            max_stroops,
            attempted_stroops,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(
            json["PerTxCapExceeded"]["max_stroops"],
            max_stroops.to_string(),
            "max_stroops beyond i64::MAX must serialize as its full i128 decimal string"
        );
        assert_eq!(
            json["PerTxCapExceeded"]["attempted_stroops"],
            attempted_stroops.to_string(),
            "attempted_stroops beyond i64::MAX must serialize as its full i128 decimal string"
        );
        assert!(
            json["PerTxCapExceeded"]["max_stroops"].is_string()
                && json["PerTxCapExceeded"]["attempted_stroops"].is_string(),
            "both stroop fields must be JSON strings, not numbers: {json}"
        );
    }

    /// Same assertion for `PerPeriodCapExceeded`'s three stroop fields.
    #[test]
    fn deny_reason_per_period_cap_exceeded_i128_beyond_i64_max_serializes_as_decimal_string() {
        let max_stroops: i128 = i128::from(i64::MAX) + 1;
        let attempted_stroops: i128 = i128::from(i64::MAX) + 2;
        let period_used_stroops: i128 = i128::from(i64::MAX) + 3;
        let r = DenyReason::PerPeriodCapExceeded {
            asset: "native".into(),
            window: "1d".into(),
            max_stroops,
            attempted_stroops,
            period_used_stroops,
        };
        let json = serde_json::to_value(&r).unwrap();
        let payload = &json["PerPeriodCapExceeded"];
        assert_eq!(payload["max_stroops"], max_stroops.to_string());
        assert_eq!(payload["attempted_stroops"], attempted_stroops.to_string());
        assert_eq!(
            payload["period_used_stroops"],
            period_used_stroops.to_string()
        );
        assert!(
            payload["max_stroops"].is_string()
                && payload["attempted_stroops"].is_string()
                && payload["period_used_stroops"].is_string(),
            "all three stroop fields must be JSON strings, not numbers: {json}"
        );
    }

    /// Same assertion for `MinimumReserveBreached`'s two stroop fields.
    #[test]
    fn deny_reason_minimum_reserve_breached_i128_beyond_i64_max_serializes_as_decimal_string() {
        let reserve_required_stroops: i128 = i128::from(i64::MAX) + 1;
        let balance_stroops: i128 = i128::from(i64::MAX) + 2;
        let r = DenyReason::MinimumReserveBreached {
            reserve_required_stroops,
            balance_stroops,
        };
        let json = serde_json::to_value(&r).unwrap();
        let payload = &json["MinimumReserveBreached"];
        assert_eq!(
            payload["reserve_required_stroops"],
            reserve_required_stroops.to_string()
        );
        assert_eq!(payload["balance_stroops"], balance_stroops.to_string());
        assert!(
            payload["reserve_required_stroops"].is_string()
                && payload["balance_stroops"].is_string(),
            "both stroop fields must be JSON strings, not numbers: {json}"
        );
    }

    /// `#[serde(with = "crate::wire_stroops::i128")]` round-trips exactly (no
    /// clamp) through the underlying encoder used by every widened
    /// `DenyReason` stroop field — proven directly against the encoder
    /// (`DenyReason` itself is `Serialize`-only; the encoder's own
    /// `Deserialize` half is exercised here, matching the exact `with =`
    /// path each field above uses).
    #[test]
    fn wire_stroops_i128_round_trips_value_beyond_i64_max_with_no_clamp() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Wrapper {
            #[serde(with = "crate::wire_stroops::i128")]
            v: i128,
        }
        let v: i128 = i128::from(i64::MAX) + 12_345;
        let w = Wrapper { v };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], v.to_string());
        let round_tripped: Wrapper = serde_json::from_value(json).unwrap();
        assert_eq!(
            round_tripped.v, v,
            "an i128 value beyond i64::MAX must round-trip exactly, with no saturating clamp"
        );
    }

    #[test]
    fn deny_reason_code_owner_signature_stale() {
        let r = DenyReason::OwnerSignatureStale {
            rotated_at: "2026-04-29T00:00:00Z".into(),
        };
        assert_eq!(r.code(), "owner_signature_stale");
    }

    #[test]
    fn deny_reason_code_no_matching_rule() {
        assert_eq!(DenyReason::NoMatchingRule.code(), "no_matching_rule");
    }

    #[test]
    fn deny_reason_code_counterparty_kind_unsupported() {
        let r = DenyReason::CounterpartyKindUnsupported {
            kind: "SEP10_IDENTITY".into(),
        };
        assert_eq!(r.code(), "counterparty_kind_unsupported");
    }

    #[test]
    fn deny_reason_code_evaluation_error() {
        let r = DenyReason::EvaluationError {
            detail: "internal".into(),
        };
        assert_eq!(r.code(), "evaluation_error");
    }

    #[test]
    fn deny_reason_code_explicit_rule_deny() {
        assert_eq!(DenyReason::ExplicitRuleDeny.code(), "explicit_rule_deny");
    }

    // ── Bundle-level DenyReason variants ─────────────────────────────────────

    #[test]
    fn deny_reason_code_inner_invocation_count_cap_exceeded() {
        let r = DenyReason::InnerInvocationCountCapExceeded {
            max: 50,
            attempted: 51,
        };
        assert_eq!(r.code(), "inner_invocation_count_cap_exceeded");
    }

    #[test]
    fn deny_reason_code_bundle_aggregate_cap_exceeded() {
        let r = DenyReason::BundleAggregateCapExceeded {
            asset: Some("USDC:GISSUER".into()),
            max: 100_000_000_000,
            sum: 120_000_000_000,
        };
        assert_eq!(r.code(), "bundle_aggregate_cap_exceeded");
    }

    #[test]
    fn deny_reason_code_bundle_contains_generic_kind() {
        let r = DenyReason::BundleContainsGenericKind { inner_index: 2 };
        assert_eq!(r.code(), "bundle_contains_generic_kind");
    }

    #[test]
    fn deny_reason_code_bundle_denied() {
        let r = DenyReason::BundleDenied {
            inner_index: 0,
            deny_reason: Box::new(DenyReason::NoMatchingRule),
        };
        assert_eq!(r.code(), "bundle_denied");
    }

    // ── Home-domain DenyReason variant ───────────────────────────────────────

    #[test]
    fn deny_reason_code_home_domain_not_resolved() {
        let r = DenyReason::HomeDomainNotResolved {
            home_domain: "circle.com".into(),
        };
        assert_eq!(r.code(), "home_domain_not_resolved");
    }

    // ── SEP-10 session DenyReason variant ────────────────────────────────────

    #[test]
    fn deny_reason_code_sep10_session_missing() {
        let r = DenyReason::Sep10SessionMissing {
            account_id: "GABC1".into(),
        };
        assert_eq!(r.code(), "sep10.session_missing");
    }

    // ── Decision variants ─────────────────────────────────────────────────────

    #[test]
    fn decision_deny_wraps_deny_reason() {
        let d = Decision::Deny(DenyReason::NoMatchingRule);
        assert!(matches!(d, Decision::Deny(DenyReason::NoMatchingRule)));
    }

    #[test]
    fn decision_require_approval_roundtrip() {
        let req = ApprovalRequest::new("nonce-abc".into(), 120);
        let d = Decision::RequireApproval(req.clone());
        assert!(matches!(d, Decision::RequireApproval(_)));
        if let Decision::RequireApproval(inner) = d {
            assert_eq!(inner, req);
        }
    }

    #[test]
    fn approval_request_accepts_loopback_approve_url() {
        let req = ApprovalRequest::new("nonce-abc".into(), 120)
            .with_approval_url("http://127.0.0.1:54321/approve/abc".into())
            .unwrap();

        assert_eq!(
            req.approval_url.as_deref(),
            Some("http://127.0.0.1:54321/approve/abc")
        );
    }

    #[test]
    fn approval_request_accepts_localhost_register_url() {
        let req = ApprovalRequest::new("nonce-abc".into(), 120)
            .with_approval_url("http://localhost:1234/register/xyz".into())
            .unwrap();

        assert_eq!(
            req.approval_url.as_deref(),
            Some("http://localhost:1234/register/xyz")
        );
    }

    #[test]
    fn approval_request_rejects_https_url() {
        let err = ApprovalRequest::new("nonce-abc".into(), 120)
            .with_approval_url("https://127.0.0.1:54321/approve/abc".into())
            .unwrap_err();

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn approval_request_rejects_external_host() {
        let err = ApprovalRequest::new("nonce-abc".into(), 120)
            .with_approval_url("http://example.com:54321/approve/abc".into())
            .unwrap_err();

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn approval_request_rejects_url_without_port() {
        let err = ApprovalRequest::new("nonce-abc".into(), 120)
            .with_approval_url("http://127.0.0.1/approve/abc".into())
            .unwrap_err();

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn approval_request_rejects_path_outside_allowlist() {
        let err = ApprovalRequest::new("nonce-abc".into(), 120)
            .with_approval_url("http://127.0.0.1:54321/other/abc".into())
            .unwrap_err();

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn approval_request_rejects_non_http_scheme() {
        let err = ApprovalRequest::new("nonce-abc".into(), 120)
            .with_approval_url("ws://127.0.0.1:54321/approve/abc".into())
            .unwrap_err();

        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }
}

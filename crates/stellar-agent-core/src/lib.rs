//! Stellar agent wallet — core library.
//!
//! Primary public API for the synchronous, runtime-free layer of the Stellar
//! agent wallet.  External consumers embed this crate alongside
//! `stellar-agent-network` to sign and submit transactions without spawning
//! the CLI subprocess — see `examples/embed/` for a complete walkthrough.
//!
//! # What this crate does
//!
//! Provides typed amounts ([`StellarAmount`]), the nine-category error taxonomy
//! ([`WalletError`]), the JSON envelope ([`Envelope`]), observability
//! primitives, smart-account auth-digest / context-rule-ID helpers,
//! per-profile configuration ([`profile`]), and the mainnet write-tools policy
//! gate ([`policy`]).
//!
//! All APIs are synchronous except [`wallet::Wallet::unlock`], which is async
//! and must be awaited inside a Tokio runtime (the `time` feature).
//!
//! # Primary consumers
//!
//! - `stellar-agent-cli` — the command-line binary.
//! - `stellar-agent-mcp` — the MCP server binary.
//! - External embedders — pair with `stellar-agent-network`; see
//!   `examples/embed/` for the recommended import pattern.
//!
//! # Non-goals
//!
//! - Network transport, transaction assembly, and signing live in
//!   `stellar-agent-network`.  This crate uses Tokio only for the unlock-TTL
//!   timer in [`wallet::Wallet::unlock`]; it carries no network runtime.
//! - Smart-account transaction submission lives in `stellar-agent-network`.
//!
//! # Related crates
//!
//! - `stellar-agent-network` — async signing, transaction builder, RPC client.
//! - `stellar-agent-cli` — CLI binary; thin dispatch layer over both library crates.
//!
//! See the [research record](https://github.com/christian-rogobete/stellar-cli-wallet-agents-research)
//! for architecture, threat model, and requirements.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Wallet-owned approval spine — storage and cryptographic substrate.
///
/// Provides [`approval::PendingApprovalStore`] (TOML-file-backed, single-writer
/// store with exclusive advisory lock), the HMAC-SHA256 attestation primitive
/// ([`approval::attestation`]), and the platform-stable user identity helper
/// ([`approval::user_id::process_uid_for_attestation`]).
pub mod approval;

/// Hash-chained structured audit log substrate.
///
/// Provides [`audit_log::AuditWriter`] for appending entries, the hash-chain
/// primitives in [`audit_log::chain`], and [`audit_log::verify_log`] for
/// end-to-end chain verification.  The event-kind schema lives in
/// [`audit_log::schema`].
pub mod audit_log;

/// Public, non-secret constants shared by wallet crates.
pub mod constants;

/// Typed Stellar amount value and unit-enforcing parsers.
///
/// The central type is [`amount::StellarAmount`], stored internally as `i64`
/// stroops.  Human-supplied strings require an explicit `XLM` unit label to
/// prevent silent unit confusion.  See the module documentation for full
/// parsing rules.
///
/// [`amount::AnchorAmount`] is the asset-agnostic companion type for SEP-24
/// anchor deposit amounts, which are denominated in the anchor asset's
/// own precision rather than in XLM stroops.
pub mod amount;

/// Shared counterparty identity validators used by policy and network crates.
pub mod counterparty;

/// Nine-category [`WalletError`] taxonomy used by every CLI command, MCP tool,
/// and library API in this crate.  See the module documentation for the full
/// taxonomy overview, wire-format specification, and secret-material policy.
pub mod error;

/// Uniform JSON wire-format envelope for all CLI commands, MCP tools, and
/// library APIs.  Provides [`envelope::Envelope<T>`] (success and error
/// response wrapper), [`envelope::EnvelopeError`] (structured error payload),
/// and [`envelope::OutputFormat`] (the `--output` flag value).
pub mod envelope;

pub mod observability;

/// Policy engine trait, no-op implementation, and typed decision surface.
///
/// The [`policy::PolicyEngine`] trait is the binding mechanism for the mainnet
/// MCP write-tools gate.  The [`policy::NoopPolicyEngine`] concrete
/// implementation returns `Err(PolicyError::NotImplemented)` for every
/// destructive tool on mainnet profiles.  The full engine is
/// [`policy::v1::PolicyEngineV1`]; the call site at `tools/call` dispatch is
/// unchanged between both implementations.
///
/// [`policy::BuildRegistryError`] is returned by the server-side
/// `build_tool_registry()` function when a duplicate `McpToolRegistration`
/// name is detected.  The registry is fail-closed: duplicate names cause a
/// fatal startup error rather than a silent first-registration-wins drop.
pub mod policy;

/// Per-profile wallet configuration.
///
/// Provides the figment-backed [`profile::loader`], the [`profile::schema::Profile`]
/// struct (schema version 2), CAIP-2 chain-ID resolution ([`profile::caip2`]),
/// version-dispatched migration ([`profile::migrate`]), and the profile-local
/// submission receipt store ([`profile::receipt`]).
pub mod profile;

pub mod smart_account;

/// Typed hex-codec helpers (`encode`, `decode_hex32`).
///
/// Canonical hex encoding/decoding used by the deployment module, CLI, and
/// test helpers.
pub mod hex;

/// Canonical Stellar protocol constants (`STROOPS_PER_XLM`, `BASE_RESERVE_STROOPS`,
/// `DEFAULT_CLASSIC_FEE_STROOPS`) colocated for single-source-of-truth imports.
pub mod protocol_consts;

/// Shared timestamp formatting helpers (ISO-8601 UTC, epoch decomposition).
pub mod timefmt;

/// Short-in-memory-unlock window: `mlock`-protected signing seed with RAII dispose.
///
/// Provides [`wallet::Wallet`] (unlock + TTL + RAII dispose),
/// [`wallet::LockedSeed`] (region-backed locked seed buffer),
/// [`wallet::MlockRequired`] (three-posture config enum), and
/// [`wallet::WalletLifecycleError`] (typed lifecycle errors).
///
/// See the module-level documentation for the full locking mechanism and the
/// `mlock(2)` vs `mlock2(MLOCK_ONFAULT)` posture details.
pub mod wallet;

/// Authoritative argument re-derivation from HMAC-bound `envelope_xdr` at
/// `_commit` time.
///
/// Provides [`envelope_decode::decode_authoritative_args`], which decodes the
/// XDR, extracts the single operation, and renders a `serde_json::Value` in
/// the same shape that `dispatch_gate` forwards to `PolicyEngine::evaluate`.
/// Ensures the policy engine sees nonce-bound fields rather than caller-supplied
/// args at the commit step.
pub mod envelope_decode;

pub use amount::{
    ANCHOR_AMOUNT_MAX_DECIMAL_PLACES, ANCHOR_AMOUNT_MAX_LEN, AnchorAmount, AnchorAmountError,
    McpAmountArgument, McpMemoTextArgument, STELLAR_DECIMALS, StellarAmount,
};
pub use approval::{
    ApprovalError, DEFAULT_TTL_MS, EXPECTED_NONCE_LEN, PendingApproval, PendingApprovalStore,
    compute_attestation, envelope_sha256, process_uid_for_attestation, verify_attestation,
};
pub use audit_log::{
    AuditEntry, AuditWriter, AuditWriterRegistry, EventKind, PartialRotationState, PolicyDecision,
    VerifyError, VerifyOk, VerifyWarning, verify_log,
};
pub use counterparty::is_valid_ldh_home_domain;
pub use envelope::{Envelope, EnvelopeError, OutputFormat};
pub use error::{
    AuthError, AuthMismatchReason, ErrorCategory, InternalError, LedgerError, NetworkError,
    PolicyError, ProtocolError, SubmissionError, ValidationError, WalletError, WalletStateError,
};
pub use observability::{
    FormatChoice, InitError, RedactingJsonFormatter, SubscriberConfig, init_subscriber,
    init_subscriber_with, redact_first5_last5,
};
// `STROOPS_PER_XLM` is physically defined in `amount` (compile-time assertion
// ties it to `STELLAR_DECIMALS`) and re-exported from `protocol_consts`.
// `NoopPolicyEngine` is intentionally NOT re-exported flat at the crate root:
// callers import it via the explicit
// `stellar_agent_core::policy::NoopPolicyEngine` path so each construction site
// is individually auditable. A flat re-export here would obscure that.
pub use constants::HIGH_VALUE_THRESHOLD_STROOPS;
pub use policy::{
    ApprovalRequest, BuildRegistryError, Decision, DenyReason, McpToolRegistration, PolicyEngine,
    ToolDescriptor,
};
pub use protocol_consts::{BASE_RESERVE_STROOPS, DEFAULT_CLASSIC_FEE_STROOPS, STROOPS_PER_XLM};
// policy::PolicyError is intentionally excluded from this flat re-export to
// avoid shadowing `error::PolicyError` (the umbrella nine-category variant).
// Callers that need the policy-layer error import `stellar_agent_core::policy::PolicyError`
// directly.  See the layer-placement note in `policy::PolicyError`.
pub use envelope_decode::{EnvelopeDecodeError, decode_authoritative_args, stroops_to_human};
pub use policy::v1::{
    AccountIdentityView, AccountReserveLookupError, AccountReservesView, CounterpartyCacheView,
    Criterion, EvalContext, PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId,
    Sep10SessionView, Sep45SessionView,
};
pub use smart_account::auth_digest::{AuthDigest, compute_auth_digest};
pub use smart_account::rule_id::{
    ContextRuleId, EncodeContextRuleIdsError, encode_context_rule_ids,
};
pub use wallet::{
    DEFAULT_TTL_SECONDS, LockedSeed, MAX_TTL_SECONDS, MlockRequired, Wallet, WalletLifecycleError,
};

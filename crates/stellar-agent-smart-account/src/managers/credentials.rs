//! Credential manager — WebAuthn passkey enrollment, listing, deletion, and
//! show for the Stellar agent wallet.
//!
//! # Overview
//!
//! `CredentialsManager` orchestrates the browser-handoff registration path
//! for WebAuthn passkey enrollment. It does NOT perform
//! signing — only registration.
//!
//! ## Registration flow
//!
//! 1. Insert a `PendingApproval { kind: ApprovalKind::RegisterPasskey { .. } }`
//!    into the approval store (the bridge serves `/register/<nonce>` from this).
//! 2. Report the registration URL back to the caller so the CLI can launch the
//!    browser (or print the URL for manual use).
//! 3. The CLI polls the approval store via [`CredentialsManager::poll_registration`]
//!    at 500 ms intervals until the bridge POST handler calls
//!    `record_passkey_registration` and embeds a `RegistrationInput`, or until
//!    the deadline expires.
//! 4. On success, write a `CredentialMetadata` record to the passkeys registry
//!    TOML file at `<passkeys_dir>/<profile>.toml` (atomic write).
//! 5. Emit a `PasskeyRegistered` audit-log entry via the optional
//!    `AuditWriter` (sourced from the `SignersManager`'s shared writer —
//!    shared `AuditWriter` from `SignersManager`).
//!
//! ## Registry storage
//!
//! Credential metadata is stored in a per-profile TOML file at
//! `<passkeys_dir>/<profile>.toml`. The `CredentialMetadata` records are
//! keyed by human-readable `credential_name`. A name → `credential_id_b64url`
//! index lets `delete <name>` and `show <name>` resolve by name without a
//! full scan.
//!
//! Writes are atomic: a `NamedTempFile` is written in the same parent directory
//! and renamed (on Unix, `persist()` calls `rename(2)` which is atomic).
//!
//! ## First-registration UX
//!
//! [`CredentialsManager::is_empty`] lets the CLI layer detect a first-passkey
//! scenario and display the RP-ID binding warning before calling
//! [`CredentialsManager::prepare_registration`].

use std::{
    collections::HashMap,
    fs,
    io::{self, Write as _},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::managers::signers::SignersManager;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use stellar_agent_core::approval::retry::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::approval::store::{
    ApprovalKind, DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, generate_csrf_token,
};
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::{RedactedStrkey, is_loopback_http_url};
use stellar_agent_core::profile::schema::default_passkeys_dir;
use stellar_agent_core::redact_first5_last5;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::webauthn::passkey_signer::{PasskeyCredentialRecord, PasskeySignHandle};
use stellar_agent_network::signing::Signer as _;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata stored per registered passkey credential.
///
/// Persisted in `<passkeys_dir>/<profile>.toml` as a `[[credentials]]` array.
/// No private-key bytes are ever stored here — only the public metadata
/// returned by the WebAuthn registration ceremony.
///
/// `credential_id_b64url` is stored in full because it is the canonical
/// WebAuthn lookup key (required for signing). It is NEVER written to the
/// audit log; the audit emitter applies first-5-last-5 redaction internally.
///
/// # Field stability policy
///
/// Existing required fields (`credential_name`, `credential_id_b64url`,
/// `rp_id`, `transports`, `registered_at_unix_ms`) are always required for
/// a non-corrupt registry entry — no `#[serde(default)]` on these.
///
/// Additive fields added after the initial schema carry
/// `#[serde(default)]` so that registries written before the field was
/// introduced deserialise successfully. On deserialisation, a missing
/// additive field receives its `Default::default()` value, and the caller
/// should treat an empty additive field as a legacy entry.
///
/// # Debug redaction
///
/// `Debug` is hand-implemented (not derived) to redact `credential_id_b64url`
/// to first-5-last-5 form to prevent sensitive data leaking into logs.
/// The full credential ID is never written to a structured log.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialMetadata {
    /// Human-readable name chosen by the operator at `add-passkey <name>`.
    pub credential_name: String,

    /// Base64url-encoded credential ID (CTAP2 canonical form).
    ///
    /// 16–64 raw bytes → 22–86 base64url characters.
    pub credential_id_b64url: String,

    /// RP-ID used for this registration (e.g. `"localhost"` for local wallets, or
    /// a custom domain such as `"wallet.example.com"` for self-hosted deployments).
    ///
    /// Must be a valid DNS domain string per WebAuthn Level 2 §5.1.2.  IP literals
    /// (e.g. `"127.0.0.1"`) are not valid RP-IDs and will be rejected by browsers.
    pub rp_id: String,

    /// Comma-separated AAGUID-negotiated transport hints
    /// (e.g. `"usb,ble,nfc,internal"`). May be empty if not provided by the
    /// authenticator.
    pub transports: String,

    /// Unix timestamp (ms) of the registration ceremony completion.
    pub registered_at_unix_ms: u64,

    /// Base64url-no-pad encoded uncompressed SEC1 P-256 public key
    /// (`0x04 || X (32 bytes) || Y (32 bytes)`) — exactly 65 raw bytes,
    /// 87 base64url characters.
    ///
    /// Required for WebAuthn assertion verification. Populated at
    /// registration time from `RegistrationInput::public_key_uncompressed_sec1()`.
    ///
    /// Additive field: absent in older registry entries; defaults to empty
    /// string via `#[serde(default)]`. A missing public key means the
    /// credential was registered before this field existed; handled
    /// defensively for forward compatibility.
    #[serde(default)]
    pub public_key_sec1_b64: String,
}

impl std::fmt::Debug for CredentialMetadata {
    /// Redacted `Debug` impl: `credential_id_b64url` is shown as
    /// `"<first5>...<last5>"` to prevent the full credential ID from
    /// appearing in unstructured log output.
    ///
    /// `public_key_sec1_b64` is omitted entirely — it is a public key but
    /// contains sensitive operational data that should not appear in
    /// unstructured log output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialMetadata")
            .field("credential_name", &self.credential_name)
            .field(
                "credential_id_b64url",
                &redact_first5_last5(&self.credential_id_b64url),
            )
            .field("rp_id", &self.rp_id)
            .field("transports", &self.transports)
            .field("registered_at_unix_ms", &self.registered_at_unix_ms)
            .field("public_key_sec1_b64", &"[redacted]")
            .finish()
    }
}

/// Outcome of [`CredentialsManager::prepare_registration`] — the nonce
/// and URL for the registration ceremony.
///
/// Returned to the CLI so it can launch the browser and enter the polling
/// loop separately from the preparation step.
///
/// # Debug redaction
///
/// `Debug` is hand-implemented (not derived) to redact `nonce` to
/// first-5-last-5 form to prevent sensitive data leaking into logs. The `url` field is omitted entirely
/// because it embeds the nonce in the path component.
#[non_exhaustive]
pub struct RegistrationHandle {
    /// The approval nonce identifying this pending registration in the store.
    pub nonce: String,
    /// The full URL to open in the browser for the WebAuthn ceremony.
    ///
    /// Format: `http://localhost:<port>/register/<nonce>` where `<nonce>` is
    /// the base64url-no-pad approval nonce (URL-path-safe by RFC 4648 §5) and
    /// `<port>` is the bound port of the bridge.  The `localhost` origin is
    /// required by WebAuthn Level 2 §5.1.2 (IP literals forbidden as RP-IDs).
    pub url: String,
}

impl std::fmt::Debug for RegistrationHandle {
    /// Redacted `Debug` impl: `nonce` is shown as `"<first5>...<last5>"` to
    /// prevent sensitive data leaking into logs. `url` is omitted because it embeds the nonce in the URL
    /// path — displaying the URL would expose the nonce verbatim.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationHandle")
            .field("nonce", &redact_first5_last5(&self.nonce))
            .field("url", &"[redacted — contains nonce]")
            .finish()
    }
}

/// Outcome of [`CredentialsManager::poll_registration`].
///
/// # Variant triggers
///
/// - [`AddPasskeyOutcome::Registered`] — the bridge POST handler called
///   `record_passkey_registration` and the polling loop observed the completed
///   `RegistrationInput` in the shared approval store.
/// - [`AddPasskeyOutcome::Timeout`] — the polling deadline elapsed before
///   a `RegistrationInput` appeared.
/// - [`AddPasskeyOutcome::UserCanceled`] — the approval store entry exists
///   with kind `RegisterPasskey` but carries an unexpected inner kind or other
///   state indicating the ceremony was aborted on the bridge side (distinct from
///   the nonce simply not being found).
/// - [`AddPasskeyOutcome::EntryMissing`] — the nonce is no longer present in
///   the approval store (cleaned up, TTL-expired before the poll loop started,
///   or the bridge never saw the entry). This is a different condition from a
///   user-driven cancellation.
///
/// # Note on browser-launch failure
///
/// Browser-launch failure is NOT surfaced through `AddPasskeyOutcome`. The
/// CLI layer (`add_passkey.rs`) handles a failed `webbrowser::open` call by
/// printing the URL to stderr and continuing the poll normally. The outcome
/// of the polling loop is one of the variants above regardless of whether the
/// browser was launched.
#[derive(Debug)]
#[non_exhaustive]
pub enum AddPasskeyOutcome {
    /// Registration completed successfully; the credential is stored in the
    /// passkeys registry.
    Registered {
        /// The stored credential metadata.
        metadata: CredentialMetadata,
    },
    /// The polling deadline elapsed before the registration ceremony completed.
    Timeout,
    /// The user cancelled the ceremony in the browser, or the bridge recorded
    /// an unexpected state for the nonce (kind mismatch, etc.).
    UserCanceled,
    /// The approval store entry for the nonce was not found.
    ///
    /// This occurs when the nonce has been cleaned up (TTL-expired) or the
    /// bridge never persisted the entry. Distinct from a user-driven
    /// cancellation — the bridge did not reject the ceremony; the entry simply
    /// does not exist.
    EntryMissing,
}

/// Outcome of [`CredentialsManager::sign_with_passkey_rule`].
///
/// # Variant triggers
///
/// - [`SignWithPasskeyOutcome::Signed`] — the bridge delivered a valid
///   `AssertionInput` and `PasskeySignHandle::sign_webauthn_assertion`
///   returned a `WebAuthnAssertion`.
/// - [`SignWithPasskeyOutcome::Timeout`] — the polling deadline elapsed.
/// - [`SignWithPasskeyOutcome::UserCanceled`] — the approval store entry
///   carries an unexpected inner state (bridge-side abort or kind mismatch).
/// - [`SignWithPasskeyOutcome::EntryMissing`] — the nonce is not in the
///   store (TTL-expired or never persisted).
///
/// # Examples
///
/// ```rust
/// use stellar_agent_smart_account::managers::credentials::SignWithPasskeyOutcome;
///
/// fn handle_outcome(outcome: SignWithPasskeyOutcome) {
///     match outcome {
///         SignWithPasskeyOutcome::Signed { signature_bytes, credential_metadata } => {
///             // `signature_bytes` is the WebAuthn assertion to attach to the
///             // transaction's authorization entry (External-arm signing).
///             // Do NOT log `signature_bytes` — it is a sensitive signing artifact.
///             let _ = (signature_bytes, credential_metadata);
///         }
///         SignWithPasskeyOutcome::Timeout => {
///             eprintln!("signing ceremony timed out; retry");
///         }
///         SignWithPasskeyOutcome::UserCanceled => {
///             eprintln!("user cancelled the WebAuthn ceremony");
///         }
///         SignWithPasskeyOutcome::EntryMissing => {
///             eprintln!("approval entry expired or was never persisted");
///         }
///         // #[non_exhaustive]: match all future variants
///         _ => {}
///     }
/// }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum SignWithPasskeyOutcome {
    /// Signing ceremony completed; `WebAuthnAssertion` is ready.
    Signed {
        /// The compact (64-byte r||s) WebAuthn assertion produced by
        /// `PasskeySignHandle::sign_webauthn_assertion`.
        ///
        /// This is the bytes the caller submits to
        /// `complete_authorization_entry` as the auth-entry signature.
        ///
        /// Do NOT log these bytes at any level — they are a sensitive signing artifact.
        signature_bytes: stellar_agent_network::signing::WebAuthnAssertion,
        /// The credential metadata resolved from the passkeys registry.
        ///
        /// Boxed to reduce enum variant size per `clippy::large_enum_variant`.
        credential_metadata: Box<CredentialMetadata>,
    },
    /// The polling deadline elapsed before the signing ceremony completed.
    Timeout,
    /// The user cancelled the ceremony in the browser, or the bridge
    /// recorded an unexpected state for the nonce.
    UserCanceled,
    /// The approval store entry for the nonce was not found (TTL-expired
    /// or never persisted).
    EntryMissing,
}

/// Typed error for `CredentialsManager` operations.
#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    /// I/O error reading or writing the passkeys registry file.
    #[error("passkeys registry I/O error: {source}")]
    Io {
        /// The underlying I/O error.
        #[from]
        source: io::Error,
    },

    /// TOML deserialisation error on the passkeys registry.
    #[error("passkeys registry TOML parse error: {detail}")]
    RegistryParse {
        /// Human-readable parse error from the TOML deserialiser.
        detail: String,
    },

    /// TOML serialisation error writing the passkeys registry.
    #[error("passkeys registry TOML serialise error: {detail}")]
    RegistrySerialise {
        /// Human-readable serialisation error from the TOML serialiser.
        detail: String,
    },

    /// The platform directory library could not determine the passkeys directory.
    #[error("could not determine passkeys directory for this platform")]
    StateDirUnavailable,

    /// The named credential does not exist in the passkeys registry.
    #[error("credential '{name}' not found")]
    NotFound {
        /// The name that was looked up.
        name: String,
    },

    /// A credential with the given name already exists.
    #[error(
        "credential '{name}' already exists; choose a different name or delete the existing one"
    )]
    DuplicateName {
        /// The name that already exists in the registry.
        name: String,
    },

    /// Credential name fails the naming rules (non-empty, <= 64 chars,
    /// printable ASCII only).
    #[error("invalid credential name '{name}': {reason}")]
    InvalidName {
        /// The name that failed validation.
        name: String,
        /// A human-readable description of why the name is invalid.
        reason: &'static str,
    },

    /// The approval store returned an error during preparation or polling.
    #[error("approval store error: {detail}")]
    ApprovalStore {
        /// Human-readable description of the approval store error.
        detail: String,
    },

    /// The bridge could not be started.
    #[error("bridge start error: {detail}")]
    BridgeStart {
        /// Human-readable description of the bridge start error.
        detail: String,
    },

    /// The bridge could not be shut down cleanly (non-fatal — logged as warning).
    #[error("bridge shutdown error: {detail}")]
    BridgeShutdown {
        /// Human-readable description of the bridge shutdown error.
        detail: String,
    },

    /// An operation that requires an approval store was called on a manager
    /// constructed without one (e.g. via [`CredentialsManager::from_defaults_readonly`]).
    ///
    /// `prepare_registration` and `poll_registration` require `Some(store)`;
    /// construct the manager with [`CredentialsManager::new`] and a shared
    /// `Arc<Mutex<PendingApprovalStore>>` for those operations.
    #[error(
        "this operation requires an approval store; construct the manager with \
         CredentialsManager::new (approval store required for add-passkey)"
    )]
    ApprovalStoreUnavailable,

    /// tempfile + rename failed on atomic write.
    #[error("atomic registry write failed: {detail}")]
    AtomicWrite {
        /// Human-readable description of the atomic write failure.
        detail: String,
    },

    /// The passkey signing primitive returned an error.
    ///
    /// Wraps `WalletError` from `PasskeySignHandle::sign_webauthn_assertion`.
    /// The inner error is reported verbatim in the `CredentialsError::Signing`
    /// variant; no signing-related bytes are included in the message.
    #[error("passkey signing error: {detail}")]
    Signing {
        /// Human-readable description of the signing error (signing-related bytes are omitted).
        detail: String,
    },

    /// The credential `public_key_sec1_b64` field is empty.
    ///
    /// This occurs when a credential was registered before the
    /// `public_key_sec1_b64` field was added to `CredentialMetadata`.
    ///
    /// Resolution: delete the credential and re-register it via
    /// `stellar-agent credentials add-passkey <name>`.
    #[error(
        "credential '{name}' is missing a SEC1 public key (public_key_sec1_b64 is empty); \
         delete and re-register the credential to obtain the public key"
    )]
    MissingPublicKey {
        /// The credential name whose `public_key_sec1_b64` field is empty.
        name: String,
    },

    /// The credential `public_key_sec1_b64` field is present but not a valid
    /// 65-byte SEC1 uncompressed P-256 public key.
    ///
    /// This occurs when the stored value fails base64url decoding, is not
    /// exactly 65 bytes, or does not begin with the `0x04` uncompressed-point
    /// marker byte.
    ///
    /// Resolution: delete the credential and re-register it via
    /// `stellar-agent credentials add-passkey <name>`.
    #[error(
        "credential '{name}' has a malformed SEC1 public key: {reason}; \
         delete and re-register the credential"
    )]
    MalformedPublicKey {
        /// The credential name whose `public_key_sec1_b64` field is malformed.
        name: String,
        /// A stable, non-secret reason string (e.g. `"base64url decode failed"`,
        /// `"expected 65 bytes"`, `"missing 0x04 uncompressed marker"`).
        reason: &'static str,
    },

    /// The per-signing divergence check refused the WebAuthn ceremony.
    ///
    /// Wraps [`crate::SaError`] variants from
    /// `SignersManager::verify_signer_set_against_chain`:
    /// - `SaError::SignerSetDiverged` — on-chain state mismatches audit-log baseline.
    /// - `SaError::SignerSetMissingBaseline` — no audit-log baseline exists for the rule.
    /// - `SaError::NetworkRpcDivergence` — primary and secondary RPC disagree.
    /// - `SaError::AuditLog` — audit-log integrity violation.
    ///
    /// The WebAuthn ceremony is aborted BEFORE any `bridge_local_addr` I/O,
    /// so no browser window is opened and no passkey tap is requested.
    ///
    #[error("signer-set divergence check refused passkey signing: {source}")]
    SignerSetDivergence {
        /// The wrapped `SaError` carrying the typed divergence reason.
        ///
        /// Named `source` so `thiserror` wires `std::error::Error::source()` for
        /// correct error-chain traversal.
        #[source]
        source: Box<crate::SaError>,
    },

    /// The pre-signing verifier or policy wasm-hash drift check detected drift.
    ///
    /// Wraps [`crate::SaError`] variants from
    /// `managers::verifiers::verify_pinned_verifier_against_chain` or
    /// `verify_pinned_policy_against_chain`:
    /// - `SaError::VerifierHashDrift` — live verifier wasm hash differs from pin.
    /// - `SaError::PolicyHashDrift` — live policy wasm hash differs from pin.
    /// - `SaError::NetworkRpcDivergence` — RPCs disagreed before drift check ran.
    /// - `SaError::AuditLog` — audit-log integrity violation during pin read.
    ///
    /// The WebAuthn ceremony is aborted BEFORE any `bridge_local_addr` I/O.
    /// The audit log emits `SaVerifierHashDrift` / `SaPolicyHashDrift` BEFORE
    /// this error is returned and BEFORE the `PasskeyAssertion` result tag row
    /// is written — forensic evidence is preserved even on abort.
    ///
    #[error("wasm hash drift check refused passkey signing: {source}")]
    WasmHashDrift {
        /// The wrapped `SaError` carrying the typed drift reason.
        ///
        /// Named `source` so `thiserror` wires `std::error::Error::source()` for
        /// correct error-chain traversal.
        #[source]
        source: Box<crate::SaError>,
    },

    /// The pre-signing drift-check infrastructure was unavailable.
    ///
    /// Distinct from [`CredentialsError::WasmHashDrift`] (which indicates
    /// actual drift was detected): this variant indicates the drift check could
    /// not run at all — for example, because the on-chain rule was not found or
    /// an RPC error occurred while fetching the rule's verifier/policy addresses.
    ///
    /// The WebAuthn ceremony is aborted (fail-closed) BEFORE any bridge I/O.
    /// No `SaVerifierHashDrift` / `SaPolicyHashDrift` audit row is emitted
    /// (the infrastructure failure is what is being reported, not a hash
    /// mismatch).  The `PasskeyAssertion` result tag is
    /// `"failure:drift_check_unavailable"` (eleventh class).
    ///
    #[error("drift-check infrastructure unavailable; signing refused (fail-closed): {source}")]
    DriftCheckUnavailable {
        /// The wrapped `SaError` carrying the infrastructure failure reason.
        ///
        /// Named `source` so `thiserror` wires `std::error::Error::source()` for
        /// correct error-chain traversal.
        #[source]
        source: Box<crate::SaError>,
    },

    /// The caller supplied an invalid set of context rule IDs.
    #[error("invalid rule_ids: {reason}")]
    InvalidRuleIds {
        /// Stable, non-secret reason suitable for logs and CLI envelopes.
        reason: String,
    },

    /// The diversification enforce-default trigger refused the WebAuthn ceremony.
    ///
    /// Wraps [`crate::SaError::VerifierDiversificationRequired`]: the rule
    /// references a single verifier wasm hash AND the policy criteria indicates
    /// a value above `HIGH_VALUE_THRESHOLD_STROOPS` (or is `Undetermined`,
    /// treated as above-threshold per the fail-CLOSED posture).
    ///
    /// The WebAuthn ceremony is aborted BEFORE any `bridge_local_addr` I/O,
    /// so no browser window is opened and no passkey tap is requested.
    ///
    /// The operator may bypass with `accept_single_verifier = true` (the
    /// `--accept-single-verifier` CLI flag), which emits a
    /// `SaVerifierDiversificationOverride` audit row and proceeds.
    #[error("verifier diversification check refused passkey signing: {source}")]
    DiversificationRequired {
        /// The wrapped `SaError::VerifierDiversificationRequired` carrying the
        /// typed diversification reason.
        ///
        /// Named `source` so `thiserror` wires `std::error::Error::source()` for
        /// correct error-chain traversal.
        #[source]
        source: Box<crate::SaError>,
    },

    /// Shared audit writer mutex was poisoned while emitting a required audit row.
    #[error("audit writer poisoned during {context}")]
    AuditWriterPoisoned {
        /// Static context label for the write that could not be performed.
        context: AuditWriterPoisonContext,
    },
}

/// Discriminator for the [`CredentialsError::AuditWriterPoisoned`] variant.
///
/// Each variant maps to a load-bearing audit-emission site where a poisoned
/// audit-writer mutex was detected. Adding a new site requires extending this
/// enum, so the compiler requires updating every `match` site and avoids the
/// string-match drift pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditWriterPoisonContext {
    /// `SaVerifierDiversificationOverride` emission.
    DiversificationOverrideEmission,
    /// `SaTimelockScheduled` emission in `timelock::emit_scheduled_audit`.
    ///
    /// Surfaces a poisoned audit-writer mutex as a typed fail-CLOSED error
    /// instead of a silent `tracing::warn!` swallow.
    TimelockScheduleEmission,
    /// `SaTimelockCancelled` emission in `timelock::emit_cancelled_audit`.
    ///
    /// Same rationale as [`AuditWriterPoisonContext::TimelockScheduleEmission`].
    TimelockCancelEmission,
    /// `SaTimelockExecuted` emission in `timelock::emit_executed_audit`.
    ///
    /// Same rationale as [`AuditWriterPoisonContext::TimelockScheduleEmission`].
    TimelockExecuteEmission,
}

impl AuditWriterPoisonContext {
    /// Operator-facing label for the wire-code output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DiversificationOverrideEmission => "diversification_override_emission",
            Self::TimelockScheduleEmission => "timelock_schedule_emission",
            Self::TimelockCancelEmission => "timelock_cancel_emission",
            Self::TimelockExecuteEmission => "timelock_execute_emission",
        }
    }
}

impl std::fmt::Display for AuditWriterPoisonContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// On-disk registry schema
// ─────────────────────────────────────────────────────────────────────────────

/// Internal TOML schema for the passkeys registry file.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    credentials: Vec<CredentialMetadata>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CredentialsManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manager for WebAuthn passkey credentials.
///
/// A `CredentialsManager` holds the passkeys registry directory, profile
/// name, RP-ID, and an optional shared handle to the per-process
/// `PendingApprovalStore`. The shared handle is an
/// `Option<Arc<tokio::sync::Mutex<PendingApprovalStore>>>`:
///
/// - `Some(_)` — for the `add-passkey` flow where the manager shares the
///   same `Arc` as the bridge. All approval-store operations acquire the
///   tokio mutex and never re-open the store.
/// - `None` — for read-only subcommands (`list`, `show`, `delete`, `is_empty`)
///   that never touch the approval store. The OS-level advisory file lock is
///   NOT acquired in this mode, so concurrent `add-passkey` invocations are
///   not blocked by background `list`/`show`/`delete` calls.
///
/// # Concurrency
///
/// The CLI opens the `PendingApprovalStore` exactly once per process for
/// `add-passkey`, wraps it in `Arc<Mutex<>>`, and passes clones of that `Arc`
/// to both `start_bridge_register_only` / `start_bridge_with_pubkey_lookup` and `CredentialsManager::new`. All approval-store
/// interactions inside the manager acquire the tokio mutex (`store.lock().await`)
/// and release it before any async sleep. The OS-level advisory file lock is
/// held for the lifetime of the single shared store; intra-process concurrency
/// is mediated by the tokio mutex alone.
///
#[non_exhaustive]
pub struct CredentialsManager {
    /// Directory that holds per-profile passkeys registry TOML files.
    pub passkeys_dir: PathBuf,
    /// Profile name (used as the TOML filename stem and in audit entries).
    pub profile_name: String,
    /// RP-ID to use for new registrations.
    pub rp_id: String,
    /// Shared approval store handle.
    ///
    /// `Some(_)`: shared with the bridge via `Arc::clone`; used by
    /// `prepare_registration` and `poll_registration`.
    ///
    /// `None`: for read-only operations (`list`, `show`, `delete`,
    /// `is_empty`) — the OS-level file lock is not held.
    pub approval_store: Option<Arc<Mutex<PendingApprovalStore>>>,
    /// Polling interval for [`CredentialsManager::poll_registration`].
    pub poll_interval: Duration,
}

impl std::fmt::Debug for CredentialsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialsManager")
            .field("passkeys_dir", &self.passkeys_dir)
            .field("profile_name", &self.profile_name)
            .field("rp_id", &self.rp_id)
            .field(
                "approval_store",
                &if self.approval_store.is_some() {
                    "Some(<store>)"
                } else {
                    "None"
                },
            )
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

impl Clone for CredentialsManager {
    fn clone(&self) -> Self {
        Self {
            passkeys_dir: self.passkeys_dir.clone(),
            profile_name: self.profile_name.clone(),
            rp_id: self.rp_id.clone(),
            approval_store: self.approval_store.clone(),
            poll_interval: self.poll_interval,
        }
    }
}

/// Decode and validate a SEC1-uncompressed P-256 public key from base64url.
///
/// Returns the validated 65-byte array on success. Used by both
/// `public_key_sec1_for_credential_id` (Layer 7 bridge keyring lookup) and
/// `sign_with_passkey_rule` (signer-session approval entry construction);
/// extracting the shared validation keeps both sites in lockstep for any
/// future format tightening (e.g. an explicit point-on-curve check).
///
/// Shared SEC1 validation helper, keeping both call sites in lockstep.
///
/// # Errors
///
/// - [`CredentialsError::MissingPublicKey`] when `b64url` is empty.
/// - [`CredentialsError::MalformedPublicKey`] when the base64url decode
///   fails, the decoded length is not exactly 65 bytes, OR byte 0 is not
///   the SEC1 uncompressed-point marker (`0x04` per ANSI X9.62 §4.3.6).
fn decode_validated_sec1(name: &str, b64url: &str) -> Result<[u8; 65], CredentialsError> {
    if b64url.is_empty() {
        return Err(CredentialsError::MissingPublicKey {
            name: name.to_owned(),
        });
    }
    let pubkey_bytes =
        URL_SAFE_NO_PAD
            .decode(b64url)
            .map_err(|_| CredentialsError::MalformedPublicKey {
                name: name.to_owned(),
                reason: "base64url decode failed",
            })?;
    if pubkey_bytes.len() != 65 {
        return Err(CredentialsError::MalformedPublicKey {
            name: name.to_owned(),
            reason: "expected 65 bytes (SEC1 uncompressed P-256)",
        });
    }
    if pubkey_bytes[0] != 0x04 {
        return Err(CredentialsError::MalformedPublicKey {
            name: name.to_owned(),
            reason: "missing 0x04 uncompressed point marker",
        });
    }
    // len() == 65 is verified above; copy bytes into the fixed-size array.
    // Avoids `try_into().expect()` (which would trip `clippy::expect_used` in
    // non-test code) and removes the unreachable error arm.
    let mut out = [0u8; 65];
    out.copy_from_slice(&pubkey_bytes);
    Ok(out)
}

impl CredentialsManager {
    /// Constructs a `CredentialsManager` with an explicit shared approval store.
    ///
    /// The `approval_store` `Arc` MUST be the same one passed to
    /// `start_bridge_register_only` / `start_bridge_with_pubkey_lookup` — sharing a single in-process store instance avoids
    /// OS-level file-lock contention between the bridge and the manager.
    ///
    /// Pass `None` when the manager will only be used for read-only operations
    /// (`list`, `show`, `delete`, `is_empty`). Pass `Some(arc)` for
    /// `add-passkey` flows that call `prepare_registration` or
    /// `poll_registration`.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn new(
        passkeys_dir: PathBuf,
        profile_name: impl Into<String>,
        rp_id: impl Into<String>,
        approval_store: Option<Arc<Mutex<PendingApprovalStore>>>,
    ) -> Self {
        Self {
            passkeys_dir,
            profile_name: profile_name.into(),
            rp_id: rp_id.into(),
            approval_store,
            poll_interval: Duration::from_millis(500),
        }
    }

    /// Constructs a `CredentialsManager` from OS-conventional directories for
    /// **read-only** operations (`list`, `show`, `delete`, `is_empty`).
    ///
    /// Does NOT open a `PendingApprovalStore` and does NOT acquire the
    /// OS-level advisory file lock. Concurrent `add-passkey` invocations
    /// are unaffected.
    ///
    /// Calling `prepare_registration` or `poll_registration` on a manager
    /// constructed with this method returns
    /// [`CredentialsError::ApprovalStoreUnavailable`].
    ///
    /// # Errors
    ///
    /// - [`CredentialsError::StateDirUnavailable`] — the platform directories
    ///   library cannot determine the OS-conventional passkeys path.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_smart_account::managers::credentials::CredentialsManager;
    ///
    /// let mgr = CredentialsManager::from_defaults_readonly("default", "localhost")
    ///     .expect("must resolve passkeys dir");
    /// let creds = mgr.list().unwrap();
    /// assert!(creds.is_empty());
    /// ```
    pub fn from_defaults_readonly(
        profile_name: impl Into<String>,
        rp_id: impl Into<String>,
    ) -> Result<Self, CredentialsError> {
        let passkeys_dir =
            default_passkeys_dir().map_err(|_| CredentialsError::StateDirUnavailable)?;
        Ok(Self::new(passkeys_dir, profile_name, rp_id, None))
    }

    /// Constructs a `CredentialsManager` from OS-conventional directories,
    /// opening its own `PendingApprovalStore`.
    ///
    /// Intended for use from the `add-passkey` subcommand when a shared store
    /// already exists and the caller wants a self-contained manager. In the
    /// production `add-passkey` flow the CLI opens the store once and passes
    /// the same `Arc` to both `start_bridge_register_only` / `start_bridge_with_pubkey_lookup` and `CredentialsManager::new` —
    /// use that path instead.
    ///
    /// For operations that do not need the approval store (`list`, `show`,
    /// `delete`, `is_empty`) use [`CredentialsManager::from_defaults_readonly`].
    ///
    /// # Errors
    ///
    /// - [`CredentialsError::StateDirUnavailable`] — the platform directories
    ///   library cannot determine the OS-conventional paths.
    /// - [`CredentialsError::ApprovalStore`] — the approval store cannot be
    ///   opened (IO error or advisory lock conflict).
    pub fn from_defaults_for_registration(
        profile_name: impl Into<String>,
        rp_id: impl Into<String>,
    ) -> Result<Self, CredentialsError> {
        let profile_name = profile_name.into();
        let passkeys_dir =
            default_passkeys_dir().map_err(|_| CredentialsError::StateDirUnavailable)?;
        let approval_dir = stellar_agent_core::profile::schema::default_approval_dir()
            .map_err(|_| CredentialsError::StateDirUnavailable)?;
        let approval_path = approval_dir.join(format!("{profile_name}.toml"));
        let store = open_with_retry(
            &approval_path,
            DEFAULT_RETRY_ATTEMPTS,
            DEFAULT_RETRY_BACKOFF,
        )
        .map_err(|e| CredentialsError::ApprovalStore {
            detail: e.to_string(),
        })?;
        Ok(Self::new(
            passkeys_dir,
            &profile_name,
            rp_id,
            Some(Arc::new(Mutex::new(store))),
        ))
    }

    // ─── Registry helpers ────────────────────────────────────────────────────

    /// Returns the path to the per-profile passkeys registry TOML file.
    #[must_use]
    pub fn registry_path(&self) -> PathBuf {
        self.passkeys_dir
            .join(format!("{}.toml", self.profile_name))
    }

    /// Loads the passkeys registry from disk, returning an empty registry if
    /// the file does not exist yet.
    fn load_registry(&self) -> Result<RegistryFile, CredentialsError> {
        let path = self.registry_path();
        if !path.exists() {
            return Ok(RegistryFile::default());
        }
        let content = fs::read_to_string(&path)?;
        toml::from_str(&content).map_err(|e| CredentialsError::RegistryParse {
            detail: e.to_string(),
        })
    }

    /// Atomically writes the passkeys registry to disk.
    ///
    /// Uses a temp-file + rename strategy so partial writes never corrupt the
    /// on-disk file. The parent directory is created with mode 0o700 on Unix.
    fn persist_registry(&self, registry: &RegistryFile) -> Result<(), CredentialsError> {
        let path = self.registry_path();
        let parent = path.parent().ok_or_else(|| CredentialsError::Io {
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "passkeys registry path has no parent directory",
            ),
        })?;

        // Create parent with restricted permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent)?;
        }

        let toml_str =
            toml::to_string(registry).map_err(|e| CredentialsError::RegistrySerialise {
                detail: e.to_string(),
            })?;

        // Write via NamedTempFile + persist (atomic rename).
        let tmp =
            tempfile::NamedTempFile::new_in(parent).map_err(|e| CredentialsError::AtomicWrite {
                detail: format!("tempfile creation failed: {e}"),
            })?;

        // Restrict file permissions to owner-only on Unix (0o600).
        // On non-Unix platforms, setting Unix mode is not meaningful and this
        // block is not compiled.
        //
        // On Unix, failure to set permissions is propagated as
        // `CredentialsError::AtomicWrite` (fail-fast). A registry file that
        // is world-readable could expose credential metadata, so we refuse to
        // proceed rather than silently leaving an over-permissive file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| CredentialsError::AtomicWrite {
                    detail: format!("set_permissions(0o600) failed: {e}"),
                })?;
        }

        let mut file = tmp.as_file().try_clone()?;
        file.write_all(toml_str.as_bytes())?;
        file.flush()?;

        tmp.persist(&path)
            .map_err(|e| CredentialsError::AtomicWrite {
                detail: format!("atomic rename failed: {e}"),
            })?;

        Ok(())
    }

    // ─── Public API ──────────────────────────────────────────────────────────

    /// Returns `true` if no credentials are registered for this profile.
    ///
    /// Used by the CLI first-registration warning.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialsError`] on registry I/O or parse failure.
    pub fn is_empty(&self) -> Result<bool, CredentialsError> {
        let registry = self.load_registry()?;
        Ok(registry.credentials.is_empty())
    }

    /// Returns all registered credentials for this profile.
    ///
    /// `credential_id_b64url` is included verbatim in the
    /// returned metadata; the CLI layer applies redaction before
    /// displaying it to the operator (via `stellar-agent credentials list`).
    ///
    /// # Errors
    ///
    /// Returns [`CredentialsError`] on registry I/O or parse failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_smart_account::managers::credentials::CredentialsManager;
    ///
    /// let mgr = CredentialsManager::from_defaults_readonly("default", "localhost").unwrap();
    /// // An empty registry returns Ok(vec![]).
    /// let creds = mgr.list().unwrap();
    /// assert!(creds.is_empty());
    /// ```
    pub fn list(&self) -> Result<Vec<CredentialMetadata>, CredentialsError> {
        let registry = self.load_registry()?;
        Ok(registry.credentials)
    }

    /// Returns the credential metadata for the named credential.
    ///
    /// # Errors
    ///
    /// - [`CredentialsError::NotFound`] — no credential with `name` exists.
    /// - [`CredentialsError`] variants on I/O or parse failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_smart_account::managers::credentials::{CredentialsManager, CredentialsError};
    ///
    /// let mgr = CredentialsManager::from_defaults_readonly("default", "localhost").unwrap();
    /// let err = mgr.show("nonexistent").unwrap_err();
    /// assert!(matches!(err, CredentialsError::NotFound { .. }));
    /// ```
    pub fn show(&self, name: &str) -> Result<CredentialMetadata, CredentialsError> {
        let registry = self.load_registry()?;
        registry
            .credentials
            .into_iter()
            .find(|c| c.credential_name == name)
            .ok_or_else(|| CredentialsError::NotFound {
                name: name.to_owned(),
            })
    }

    /// Returns the registered SEC1 public key for `credential_id`.
    ///
    /// The lookup scans the per-profile passkeys registry by credential ID and
    /// validates the matched `public_key_sec1_b64` field before returning it.
    /// This is used by the localhost bridge approval POST path so
    /// `pre_verify_assertion` receives the public key from the credential
    /// registry rather than from bridge-session state.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialsError`] when the registry cannot be read or the
    /// matched credential record has an empty or malformed SEC1 public key.
    pub fn public_key_sec1_for_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<[u8; 65]>, CredentialsError> {
        let credential_id_b64url = URL_SAFE_NO_PAD.encode(credential_id);
        let registry = self.load_registry()?;
        let Some(metadata) = registry
            .credentials
            .into_iter()
            .find(|c| c.credential_id_b64url == credential_id_b64url)
        else {
            return Ok(None);
        };

        let pubkey =
            decode_validated_sec1(&metadata.credential_name, &metadata.public_key_sec1_b64)?;
        Ok(Some(pubkey))
    }

    /// Deletes the named credential from the passkeys registry.
    ///
    /// # Errors
    ///
    /// - [`CredentialsError::NotFound`] — no credential with `name` exists.
    /// - [`CredentialsError`] variants on I/O or serialisation failure.
    pub fn delete(&self, name: &str) -> Result<(), CredentialsError> {
        let mut registry = self.load_registry()?;
        let before = registry.credentials.len();
        registry.credentials.retain(|c| c.credential_name != name);
        if registry.credentials.len() == before {
            return Err(CredentialsError::NotFound {
                name: name.to_owned(),
            });
        }
        self.persist_registry(&registry)
    }

    /// Prepares a `RegisterPasskey` approval entry and returns the registration
    /// URL and nonce.
    ///
    /// Acquires the shared `approval_store` tokio mutex, inserts a
    /// `PendingApproval` of kind `RegisterPasskey`, persists, then releases
    /// the mutex immediately. The bridge (which holds an `Arc` clone of the
    /// same mutex) can now observe the pending entry on its next POST handler
    /// invocation.
    ///
    /// The caller (CLI) is responsible for:
    ///
    /// 1. Opening the `PendingApprovalStore` exactly once.
    /// 2. Passing the same `Arc<Mutex<PendingApprovalStore>>` to both
    ///    `start_bridge_register_only` / `start_bridge_with_pubkey_lookup` and [`CredentialsManager::new`].
    /// 3. Launching the browser to the returned `RegistrationHandle::url`.
    /// 4. Calling [`CredentialsManager::poll_registration`] with the nonce.
    ///
    /// The `nominal_smart_account` parameter is an optional display-only
    /// smart-account strkey for UX purposes. When `Some`, it is redacted via
    /// [`redact_first5_last5`] and stored in the approval entry's
    /// `smart_account_redacted` field. When `None`, the placeholder
    /// `"CAAAA...AAAAA"` is retained; passkeys are account-agnostic at
    /// registration time, and the binding to a specific smart account happens
    /// at install-rule time.
    ///
    /// # Errors
    ///
    /// - [`CredentialsError::ApprovalStoreUnavailable`] — the manager was
    ///   constructed without an approval store (e.g. via
    ///   [`CredentialsManager::from_defaults_readonly`]).
    /// - [`CredentialsError::InvalidName`] — `credential_name` fails naming rules.
    /// - [`CredentialsError::DuplicateName`] — a credential with this name already exists.
    /// - [`CredentialsError::ApprovalStore`] — store insert or persist failed.
    pub async fn prepare_registration(
        &self,
        credential_name: &str,
        bridge_addr: SocketAddr,
        nominal_smart_account: Option<&str>,
    ) -> Result<RegistrationHandle, CredentialsError> {
        // Require approval store — read-only managers cannot prepare registrations.
        let approval_store = self
            .approval_store
            .as_ref()
            .ok_or(CredentialsError::ApprovalStoreUnavailable)?;

        // Validate name before touching the store.
        validate_credential_name(credential_name)?;

        // Check for duplicate name.
        let registry = self.load_registry()?;
        if registry
            .credentials
            .iter()
            .any(|c| c.credential_name == credential_name)
        {
            return Err(CredentialsError::DuplicateName {
                name: credential_name.to_owned(),
            });
        }

        // Generate CSRF token + user handle.
        let csrf_token = generate_csrf_token();
        let mut user_handle = [0u8; 32];
        OsRng.fill_bytes(&mut user_handle);

        let process_uid = stellar_agent_core::approval::user_id::process_uid_for_attestation()
            .map_err(|e| CredentialsError::ApprovalStore {
                detail: format!("process_uid: {e}"),
            })?;

        let smart_account_redacted = nominal_smart_account
            .map(redact_first5_last5)
            .unwrap_or_else(|| {
                // No real smart account at registration time: a passkey is
                // account-agnostic at registration; binding to a specific
                // smart account happens at install-rule time. The placeholder
                // satisfies the validator's first-5-last-5 shape.
                "CAAAA...AAAAA".to_owned()
            });

        let entry = PendingApproval::new_register_passkey_pending(
            smart_account_redacted,
            // Sentinel rule_id 0: passkey registration is a pre-deployment
            // ceremony; no context rules exist yet. The non-empty constraint
            // on rule_ids is structural; 0 is used as the registration
            // sentinel and is not meaningful on-chain.
            vec![0],
            csrf_token,
            self.rp_id.clone(),
            user_handle,
            process_uid,
            DEFAULT_TTL_MS,
        )
        .map_err(|e| CredentialsError::ApprovalStore {
            detail: e.to_string(),
        })?;

        let nonce = entry.approval_nonce.clone();

        // Acquire the shared mutex, insert, and release immediately.
        // The lock is held only for this fast synchronous operation.
        {
            let mut guard = approval_store.lock().await;
            guard
                .insert(entry, unix_now_ms())
                .map_err(|e| CredentialsError::ApprovalStore {
                    detail: e.to_string(),
                })?;
        }
        // Guard released here — bridge can now observe the pending entry.

        // Build the registration URL.
        //
        // The approval nonce is already base64url-no-pad (RFC 4648 §5):
        // alphabet `[A-Za-z0-9_-]` is URL-path-safe by construction, so no
        // re-encoding is required. Hex-encoding the ASCII bytes of a
        // URL-safe string would produce a 44-char hex blob that never matches
        // the bridge's exact-string `Path(nonce)` lookup in `register_get`.
        //
        // The hex-encoding defence-in-depth applies to operator-supplied
        // URL components or raw byte arrays — NOT to the approval nonce, which is
        // generated by this process and is URL-path-safe by its base64url
        // construction.
        //
        // Use `localhost:<port>` rather than `127.0.0.1:<port>` so the
        // browser origin matches the RP-ID `"localhost"` per WebAuthn Level 2
        // §5.1.2.  The bridge middleware accepts both Host values; the URL
        // rewrite matters only when a WebAuthn-capable browser drives the page.
        // Direct-HTTP test callers (integration_callbacks.rs) may still use
        // 127.0.0.1 URLs — those tests never involve the browser's WebAuthn API.
        let port = bridge_addr.port();
        let url = format!("http://localhost:{port}/register/{nonce}");
        // Refactor-protection: the format-string literal `"localhost"` makes this
        // assertion structurally true today. The assertion catches a future
        // refactor that swaps the host literal (e.g. to `127.0.0.1` or to `rp_id`)
        // for one that resolves outside the loopback allowlist.
        debug_assert!(
            is_loopback_http_url(&url),
            "constructed URL not loopback-bound: {url}"
        );

        // Diagnostic hint if rp_id does not match "localhost" on a
        // loopback-bound bridge — a real Chromium browser would reject the ceremony
        // with SecurityError (WebAuthn-2 §5.1.2 requires rpId ≡ origin hostname).
        if bridge_addr.ip().is_loopback() && self.rp_id != "localhost" {
            warn!(
                rp_id = %self.rp_id,
                "bridge binds loopback but rp_id is not \"localhost\"; \
                 WebAuthn ceremony will fail in a standards-conforming browser \
                 (WebAuthn-2 §5.1.2)"
            );
        }

        // Redact nonce in log (first-5-last-5) to prevent sensitive data leaking.
        let nonce_redacted = redact_first5_last5(&nonce);
        debug!(
            nonce = %nonce_redacted,
            "passkey registration prepared"
        );

        Ok(RegistrationHandle { nonce, url })
    }

    /// Polls the shared approval store until the bridge delivers a
    /// `RegistrationInput` for the given `nonce`, or until `deadline` is
    /// reached.
    ///
    /// Acquires the shared `approval_store` tokio mutex on each poll cycle,
    /// reads the entry, then immediately releases the mutex before sleeping.
    /// The bridge (which holds an `Arc` clone of the same mutex) can write to
    /// the store between poll cycles without contention.
    ///
    /// On success, writes the credential metadata (including the SEC1 public
    /// key for assertion verification) to the passkeys registry and
    /// optionally emits an audit-log entry.
    ///
    /// # Errors
    ///
    /// - [`CredentialsError::ApprovalStoreUnavailable`] — the manager was
    ///   constructed without an approval store (e.g. via
    ///   [`CredentialsManager::from_defaults_readonly`]).
    /// - [`CredentialsError::DuplicateName`] — (internal; should not occur in
    ///   practice because `prepare_registration` already checked).
    /// - [`CredentialsError`] variants on registry I/O failure.
    pub async fn poll_registration(
        &self,
        credential_name: &str,
        nonce: &str,
        deadline: Instant,
        mut audit_writer: Option<&mut AuditWriter>,
    ) -> Result<AddPasskeyOutcome, CredentialsError> {
        // Require approval store — read-only managers cannot poll registrations.
        let _store_check = self
            .approval_store
            .as_ref()
            .ok_or(CredentialsError::ApprovalStoreUnavailable)?;

        loop {
            // Check deadline before sleeping.
            if Instant::now() >= deadline {
                self.emit_audit(audit_writer.as_deref_mut(), credential_name, "", "timeout");
                return Ok(AddPasskeyOutcome::Timeout);
            }

            if let Some(outcome) = self
                .check_store_for_registration(nonce, credential_name, audit_writer.as_deref_mut())
                .await?
            {
                return Ok(outcome);
            }

            // Wait before next poll, capped by the remaining deadline.
            // The mutex is NOT held across this sleep.
            let remaining = deadline.saturating_duration_since(Instant::now());
            let sleep_for = self.poll_interval.min(remaining);
            if sleep_for.is_zero() {
                self.emit_audit(audit_writer.as_deref_mut(), credential_name, "", "timeout");
                return Ok(AddPasskeyOutcome::Timeout);
            }
            tokio::time::sleep(sleep_for).await;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────

    /// Checks the shared approval store for a completed registration.
    ///
    /// Acquires the tokio mutex, reads the entry for `nonce`, then releases
    /// immediately. Returns `Ok(Some(outcome))` if the nonce is found with a
    /// completed `RegistrationInput`, `Ok(None)` if still pending, or an
    /// error on failure.
    ///
    /// Callers MUST only invoke this method after verifying that
    /// `self.approval_store` is `Some`; `poll_registration` enforces this at
    /// its entry point before entering the loop.
    async fn check_store_for_registration(
        &self,
        nonce: &str,
        credential_name: &str,
        audit_writer: Option<&mut AuditWriter>,
    ) -> Result<Option<AddPasskeyOutcome>, CredentialsError> {
        // Require approval store. This is a private method called only from
        // `poll_registration`, which has already verified `Some(_)` at its
        // entry point. The error path here is a defense-in-depth guard.
        let store = self
            .approval_store
            .as_ref()
            .ok_or(CredentialsError::ApprovalStoreUnavailable)?;

        // Acquire the tokio mutex, clone what we need, and release immediately.
        // We never hold the mutex across I/O (persist_registry) or async sleeps.
        let entry_opt = {
            let guard = store.lock().await;
            guard.get(nonce).cloned()
        };

        let Some(entry) = entry_opt else {
            // Nonce not found — may have been cleaned up (TTL-expired) or the
            // entry was never persisted by the bridge. This is distinct from a
            // user-driven cancellation — the entry simply does not exist.
            let nonce_redacted = redact_first5_last5(nonce);
            warn!(nonce = %nonce_redacted, "registration nonce not found in store");
            self.emit_audit(audit_writer, credential_name, "", "entry_missing");
            return Ok(Some(AddPasskeyOutcome::EntryMissing));
        };

        match &entry.kind {
            ApprovalKind::RegisterPasskey {
                registration_input: Some(reg_input),
                rp_id,
                ..
            } => {
                // Registration completed — write to registry and emit audit.
                let credential_id_bytes = reg_input.credential_id();
                let credential_id_b64url = URL_SAFE_NO_PAD.encode(credential_id_bytes);
                let transports = reg_input.transports().join(",");
                let registered_at_unix_ms = unix_now_ms();

                // Encode the SEC1 public key (65-byte uncompressed P-256 point).
                // Required for assertion verification. The fixture in tests
                // supplies an all-zero key (`[0x04, 0, 0, ...]`) which is not a
                // valid P-256 point but satisfies the 65-byte structural check.
                let public_key_sec1_b64 =
                    URL_SAFE_NO_PAD.encode(reg_input.public_key_uncompressed_sec1());

                let metadata = CredentialMetadata {
                    credential_name: credential_name.to_owned(),
                    credential_id_b64url: credential_id_b64url.clone(),
                    rp_id: rp_id.clone(),
                    transports,
                    registered_at_unix_ms,
                    public_key_sec1_b64,
                };

                // Write to passkeys registry (no mutex held during persist).
                let mut registry = self.load_registry()?;
                // Guard against a concurrent duplicate (defensive).
                if registry
                    .credentials
                    .iter()
                    .any(|c| c.credential_name == credential_name)
                {
                    return Err(CredentialsError::DuplicateName {
                        name: credential_name.to_owned(),
                    });
                }
                registry.credentials.push(metadata.clone());
                self.persist_registry(&registry)?;

                // Emit audit entry.
                self.emit_audit(
                    audit_writer,
                    credential_name,
                    &credential_id_b64url,
                    "registered",
                );

                Ok(Some(AddPasskeyOutcome::Registered { metadata }))
            }
            ApprovalKind::RegisterPasskey {
                registration_input: None,
                ..
            } => {
                // Still pending — release and continue polling.
                Ok(None)
            }
            _ => {
                // Kind mismatch — unexpected; treat as user-cancelled.
                let nonce_redacted = redact_first5_last5(nonce);
                warn!(nonce = %nonce_redacted, "approval store entry has unexpected kind");
                self.emit_audit(audit_writer, credential_name, "", "user_canceled");
                Ok(Some(AddPasskeyOutcome::UserCanceled))
            }
        }
    }

    /// Emits a `PasskeyRegistered` audit entry if `audit_writer` is `Some`.
    ///
    /// `credential_id_b64url` must be provided so the
    /// `AuditEntry` constructor can apply first-5-last-5 redaction internally.
    /// Pass `""` for non-success outcomes where no credential ID is available;
    /// the constructor substitutes a fixed placeholder in that case.
    ///
    /// Audit-log failures are non-fatal — a warn is emitted
    /// and the caller continues normally.
    fn emit_audit(
        &self,
        audit_writer: Option<&mut AuditWriter>,
        credential_name: &str,
        credential_id_b64url: &str,
        status: &str,
    ) {
        let Some(writer) = audit_writer else {
            return;
        };

        // Generate a short request_id (8 random bytes, base64url-encoded).
        let mut raw = [0u8; 8];
        OsRng.fill_bytes(&mut raw);
        let request_id = URL_SAFE_NO_PAD.encode(raw);

        // Use an unambiguous sentinel for empty credential IDs (non-success paths).
        // The sentinel `"<no-credential-id>"` (18 chars) is long enough that
        // `redact_first5_last5` applies, yielding `"<no-c...-id>"`. The `<`
        // and `>` markers are NOT valid base64url characters, so the output
        // is visually distinct from any real credential redaction. Audit-log
        // analysts can unambiguously distinguish "no credential available"
        // from any real credential whose redaction happens to start/end the
        // same way.
        let id_for_audit = if credential_id_b64url.is_empty() {
            "<no-credential-id>".to_owned()
        } else {
            credential_id_b64url.to_owned()
        };

        let entry = AuditEntry::new_passkey_registered(
            credential_name,
            &id_for_audit,
            &self.rp_id,
            status,
            request_id,
        );

        if let Err(e) = writer.write_entry(entry) {
            // Audit-log failures are non-fatal but must be warned.
            warn!(
                error = %e,
                credential_name = %credential_name,
                "failed to write passkey_registered audit entry"
            );
        }
    }

    /// Drives a WebAuthn signing ceremony for the named credential over the
    /// browser-handoff approval spine.
    ///
    /// # Overview
    ///
    /// 1. Resolve `credential_name` → `CredentialMetadata` from the passkeys
    ///    registry (fails with `CredentialsError::NotFound` if absent).
    /// 2. Decode `credential_id` + `public_key_uncompressed` from base64url;
    ///    construct a `PasskeyCredentialRecord`.
    /// 3. Insert a `PendingApproval { kind: ApprovalKind::SignWithPasskey { .. } }`
    ///    into the shared approval store; the bridge serves
    ///    `/approve/<nonce>` from this entry.
    /// 4. Compute the approval URL
    ///    `http://localhost:<port>/approve/<nonce>` (port from
    ///    `bridge_local_addr`; `localhost` origin satisfies WebAuthn-2 §5.1.2
    ///    for RP-ID `"localhost"`).
    /// 5. Call `on_url(&url)` so the caller can launch the browser or print
    ///    the URL.
    /// 6. Poll the shared store at 500 ms intervals until the bridge POST
    ///    handler delivers a `passkey_assertion` (the `AssertionInput`), or
    ///    until the deadline implied by `timeout` elapses.
    /// 7. On success: construct `PasskeySignHandle::new(credential_record,
    ///    assertion_input)` and call
    ///    `handle.sign_webauthn_assertion(auth_digest, credential_id)`.
    /// 8. Emit a `PasskeyAssertion` audit-log entry via the shared audit writer
    ///    (sourced from `signers_manager.audit_writer()`) on **every** terminal
    ///    path (success, timeout, user-canceled, entry-missing,
    ///    credential-not-found, signer-error, or any other early-exit error).
    ///    Early-exit paths (those that return before `poll_signing`) emit with
    ///    `credential_id_b64url = ""` and `rp_id = ""` because those fields are
    ///    only available after `show()` succeeds; `auth_digest_hex` is always
    ///    derived from the caller-supplied `auth_digest` parameter.
    ///
    /// # Parameters
    ///
    /// - `credential_name`: name to look up in the passkeys registry.
    /// - `smart_account`: the C-strkey of the smart account that this signing
    ///   ceremony targets.  Redacted to first-5-last-5 in the approval store
    ///   entry **and** the `PasskeyAssertion` audit-log entry to prevent
    ///   sensitive data leaking into logs.
    ///   The `smart_account_redacted` field in `EventKind::PasskeyAssertion`
    ///   distinguishes ceremonies for different smart accounts in the audit
    ///   trail.
    /// - `auth_digest`: 32-byte Soroban auth digest that the WebAuthn
    ///   ceremony must sign (the `challenge` the bridge encodes for the
    ///   browser).
    /// - `signers_manager`: optional `SignersManager` for the per-signing
    ///   divergence check.  `Some(arc)` enables
    ///   the check; `None` is a test-only escape hatch that skips it with a
    ///   `warn!` log.  Production callers MUST supply `Some(...)`.
    ///   When `Some`, the manager also provides the shared
    ///   `Arc<Mutex<AuditWriter>>` (via `SignersManager::audit_writer()`) that
    ///   carries both the `SaSignerSetDiverged` row and the `PasskeyAssertion`
    ///   row through the same writer instance.  When `None`, no
    ///   `PasskeyAssertion` audit row is emitted.
    /// - `bridge_local_addr`: the bound address of the running bridge
    ///   (`BridgeHandle::local_addr()`); used to construct the approval URL.
    /// - `timeout`: maximum time to wait for the browser ceremony.
    /// - `on_url`: callback invoked exactly once with the full approval URL
    ///   immediately after the store entry is inserted.
    ///
    /// # Errors
    ///
    /// - [`CredentialsError::ApprovalStoreUnavailable`] — the manager was
    ///   constructed without an approval store (read-only path).
    /// - [`CredentialsError::NotFound`] — no credential with `credential_name`.
    /// - [`CredentialsError::MissingPublicKey`] — the credential record has an
    ///   empty `public_key_sec1_b64` field; delete and re-register to obtain
    ///   the public key.
    /// - [`CredentialsError::MalformedPublicKey`] — `public_key_sec1_b64` is
    ///   present but fails base64url decoding, is not 65 bytes, or is missing
    ///   the `0x04` uncompressed-point marker; delete and re-register.
    /// - [`CredentialsError::ApprovalStore`] — store insert failed.
    /// - [`CredentialsError::Signing`] — `sign_webauthn_assertion` returned an
    ///   error; the inner error message is redacted to prevent sensitive data leaking into logs.
    /// - [`CredentialsError::SignerSetDivergence`] — the per-signing divergence
    ///   check fired (on-chain signer-set mismatch, missing baseline, RPC
    ///   disagreement, or audit-log integrity failure); the browser window is
    ///   never opened.
    /// - [`CredentialsError::DiversificationRequired`] — the diversification
    ///   enforce-default trigger fired: the rule references a single verifier
    ///   wasm hash and the policy criteria is high-value or `Undetermined`.
    ///   Pass `accept_single_verifier = true` to bypass; that path emits a
    ///   `SaVerifierDiversificationOverride` audit row and proceeds.
    ///
    /// # Security
    ///
    /// `auth_digest` and all assertion bytes (signature, client_data_json,
    /// authenticator_data) MUST NOT be interpolated into any `tracing::*!`
    /// call. The audit-log entry applies first-5-last-5 redaction on both
    /// `credential_id` and the hex-encoded `auth_digest`.
    ///
    /// # Behavior
    ///
    /// Implements the manager-side WebAuthn signing arm.
    /// The `signers_manager` parameter wires up the per-signing
    /// divergence check before the WebAuthn ceremony.
    /// The `accept_single_verifier` parameter controls the
    /// diversification enforce-default trigger.
    #[allow(
        clippy::too_many_arguments,
        reason = "signing pipeline requires credential, account, digest, signers_manager, \
                  bridge, timeout, URL callback, and accept_single_verifier opt-in; \
                  accept_single_verifier bypasses the diversification enforce-default trigger"
    )]
    pub async fn sign_with_passkey_rule(
        &self,
        credential_name: &str,
        smart_account: &str,
        auth_digest: &[u8; 32],
        rule_ids: Vec<u32>,
        // `signers_manager`: optional SignersManager handle for the per-signing
        // divergence check.
        // `Some(arc)` = production path (divergence check runs before WebAuthn
        // ceremony AND provides the shared AuditWriter for PasskeyAssertion
        // emission via the shared writer-sharing wire-up).
        // `None` = test-only escape hatch (divergence check skipped; no audit
        // emission because there is no writer to source).
        // See `CredentialsError::SignerSetDivergence` for the error types that
        // can be returned when the check fires.
        signers_manager: Option<Arc<SignersManager>>,
        bridge_local_addr: SocketAddr,
        timeout: Duration,
        on_url: impl FnOnce(&str) + Send,
        // `accept_single_verifier`: when `true`, the diversification
        // enforce-default trigger is bypassed.
        // On bypass, a `SaVerifierDiversificationOverride` audit row is emitted
        // before proceeding.  When `false` (default), the trigger refuses
        // signing with `CredentialsError::DiversificationRequired` on all
        // single-verifier high-value or Undetermined-criteria rules.
        //
        // CLI flag: `--accept-single-verifier`.
        accept_single_verifier: bool,
    ) -> Result<SignWithPasskeyOutcome, CredentialsError> {
        // Audit emission must fire on EVERY terminal path,
        // including early-exit errors that propagate before `poll_signing` is
        // called.  Pattern: delegate the signing pipeline to an inner helper that
        // uses `?` freely and always returns `(result, credential_id_b64url,
        // rp_id)` in a tuple regardless of success or failure.  The outer fn
        // captures the tuple, derives the result tag, emits audit unconditionally,
        // then propagates the inner result.
        //
        // On early-exit paths (before `show()` succeeds) `credential_id_b64url`
        // and `rp_id` are unavailable; the inner fn yields `""` for both, which
        // the `AuditEntry::new_passkey_assertion` constructor accepts — the `""`
        // sentinel is the documented convention for non-success paths where the
        // field is unavailable.
        let auth_digest_hex = encode_auth_digest_hex(auth_digest);
        let signed_at_unix_ms = unix_now_ms();

        // Writer-sharing details live in the function rustdoc above; keep the
        // outer assertion row and inner divergence row on the same writer.
        let audit_writer_arc: Option<Arc<std::sync::Mutex<AuditWriter>>> =
            signers_manager.as_ref().map(|sm| sm.audit_writer());

        // The inner fn returns a 4-tuple; the 4th element is the
        // divergence_request_id when the failure is SignerSetDivergence, so
        // emit_signing_audit can share that ID with the SaSignerSetDiverged
        // audit row emitted by verify_signer_set_against_chain (forensic
        // correlation invariant).
        //
        // accept_single_verifier is threaded into the inner fn so
        // the diversification check can emit SaVerifierDiversificationOverride
        // on the opt-in path before proceeding.
        let (inner_result, credential_id_b64url_for_audit, rp_id_for_audit, divergence_request_id) =
            self.sign_with_passkey_rule_inner(
                credential_name,
                smart_account,
                auth_digest,
                rule_ids,
                // Clone preserves signers_manager for emit_signing_audit below
                // Arc clone is O(1).
                signers_manager.clone(),
                bridge_local_addr,
                timeout,
                on_url,
                accept_single_verifier,
            )
            .await;

        // Derive the audit result tag from the full Result, covering all
        // closed-set outcomes enumerated in
        // `audit_log/schema.rs PasskeyAssertion.result` (thirteen classes).
        let result_tag = match &inner_result {
            Ok(SignWithPasskeyOutcome::Signed { .. }) => {
                info!(credential_name, "passkey signing ceremony completed");
                "success"
            }
            Ok(SignWithPasskeyOutcome::Timeout) => "failure:timeout",
            Ok(SignWithPasskeyOutcome::UserCanceled) => "failure:user_canceled",
            Ok(SignWithPasskeyOutcome::EntryMissing) => "failure:entry_missing",
            Err(CredentialsError::NotFound { .. }) => "failure:credential_not_found",
            Err(CredentialsError::Signing { .. }) => "failure:signer_error",
            // Per-signing divergence check fired before the WebAuthn ceremony.
            Err(CredentialsError::SignerSetDivergence { .. }) => "failure:signer_set_diverged",
            // Verifier or policy wasm-hash drift check fired before the WebAuthn ceremony.
            // The result tag distinguishes:
            //   - "failure:verifier_hash_drift" — verifier drift detected
            //     (inner SaError::VerifierHashDrift; paired SaVerifierHashDrift audit row).
            //   - "failure:policy_hash_drift"   — policy drift detected
            //     (inner SaError::PolicyHashDrift; paired SaPolicyHashDrift audit row).
            //   - "failure:drift_check_unavailable" — drift check
            //     infrastructure unavailable (all other inner SaError variants — no
            //     drift audit row was emitted).
            //
            // CredentialsError::WasmHashDrift is only constructed by
            // drift_err_route() when inner is SaError::VerifierHashDrift or
            // SaError::PolicyHashDrift — both cases that emitted a drift audit row.
            // Infrastructure failures are routed to DriftCheckUnavailable by drift_err_route().
            // The `_` catch-all below is defensive for future variants; it should be
            // unreachable given drift_err_route() routing.
            Err(CredentialsError::WasmHashDrift { source }) => match source.as_ref() {
                crate::SaError::PolicyHashDrift { .. } => "failure:policy_hash_drift",
                crate::SaError::VerifierHashDrift { .. } => "failure:verifier_hash_drift",
                // Defensive: should be unreachable after drift_err_route() routing above.
                // If somehow reached, treat as "other" to avoid emitting
                // "failure:verifier_hash_drift" without a paired drift audit row.
                _ => "failure:other",
            },
            Err(CredentialsError::DriftCheckUnavailable { .. }) => {
                "failure:drift_check_unavailable"
            }
            // Diversification enforce-default trigger fired before the WebAuthn ceremony.
            Err(CredentialsError::DiversificationRequired { .. }) => {
                "failure:verifier_diversification_required"
            }
            Err(CredentialsError::InvalidRuleIds { .. }) => "failure:invalid_rule_ids",
            // Audit-writer mutex was poisoned during a load-bearing
            // row emission inside sign_with_passkey_rule_inner.  Routes explicitly
            // rather than falling through to "failure:other" so operator triage
            // can distinguish audit-integrity failures from unclassified ones.
            Err(CredentialsError::AuditWriterPoisoned { .. }) => "failure:audit_writer_poisoned",
            Err(_) => "failure:other",
        };

        // Emit audit unconditionally (best-effort; write failures are non-fatal).
        // This block is reached on ALL terminal paths,
        // including `ApprovalStoreUnavailable`, `NotFound`, `MissingPublicKey`,
        // `MalformedPublicKey`, base64url-decode failures, `process_uid` failure,
        // `new_passkey_pending` validator failure, and store-insert failure —
        // guaranteeing every early-exit path emits an audit row before returning.
        //
        // On the divergence-fail branch, divergence_request_id is Some and
        // is passed as the request_id_override so this row shares the same UUID as
        // the SaSignerSetDiverged row emitted by verify_signer_set_against_chain.
        self.emit_signing_audit(
            audit_writer_arc.as_ref(),
            signers_manager.as_ref(),
            credential_name,
            &credential_id_b64url_for_audit,
            &rp_id_for_audit,
            smart_account,
            &auth_digest_hex,
            signed_at_unix_ms,
            result_tag,
            divergence_request_id.as_deref(),
        );

        inner_result
    }

    /// Inner body of `sign_with_passkey_rule`.
    ///
    /// Returns the signing result plus audit fields so the outer function can
    /// emit `PasskeyAssertion` on every terminal path.
    ///
    /// `credential_id_b64url` and `rp_id` are `""` (empty string) when the
    /// failure occurs before `show()` resolves the credential metadata; they
    /// carry the real values on all paths that reach or pass `show()`.
    #[allow(
        clippy::too_many_arguments,
        reason = "inner pipeline needs the same parameters as the outer public fn \
                  minus audit_writer; no logical grouping eliminates any parameter \
                  (signers_manager and accept_single_verifier mirror the outer fn)"
    )]
    async fn sign_with_passkey_rule_inner(
        &self,
        credential_name: &str,
        smart_account: &str,
        auth_digest: &[u8; 32],
        rule_ids: Vec<u32>,
        signers_manager: Option<Arc<SignersManager>>,
        bridge_local_addr: SocketAddr,
        timeout: Duration,
        on_url: impl FnOnce(&str) + Send,
        accept_single_verifier: bool,
    ) -> (
        Result<SignWithPasskeyOutcome, CredentialsError>,
        String,         // credential_id_b64url for audit (empty if show() not yet called)
        String,         // rp_id for audit (empty if show() not yet called)
        Option<String>, // divergence_request_id override for forensic correlation
    ) {
        if rule_ids.is_empty() {
            return (
                Err(CredentialsError::InvalidRuleIds {
                    reason: "sign_with_passkey_rule requires at least one rule_id".to_owned(),
                }),
                String::new(),
                String::new(),
                None,
            );
        }

        // Per-signing divergence check BEFORE any bridge I/O.
        // Run for EACH rule_id in rule_ids. This fires before show()
        // so that the audit fields are "" on this early-exit path.
        //
        if let Some(ref sm) = signers_manager {
            // Parse smart_account strkey → ScAddress.
            // Reuse parse_c_strkey_to_smart_account from managers::rules
            // instead of inlining stellar_strkey::Contract::from_string +
            // stellar_xdr::ScAddress construction.
            let sc_addr =
                match crate::managers::rules::parse_c_strkey_to_smart_account(smart_account) {
                    Ok(addr) => addr,
                    Err(sa_err) => {
                        // The strkey is not a valid contract address — pre-flight
                        // validation fails before any RPC or bridge I/O.
                        // No divergence_request_id yet (minted below); pass None.
                        return (
                            Err(CredentialsError::SignerSetDivergence {
                                source: Box::new(sa_err),
                            }),
                            String::new(),
                            String::new(),
                            None,
                        );
                    }
                };

            // Generate a per-invocation request_id for divergence audit correlation.
            //
            // This ID is threaded into verify_signer_set_against_chain (so
            // SaSignerSetDiverged audit rows carry it) AND returned as the 4th tuple
            // element so the outer fn can pass it as request_id_override to
            // emit_signing_audit.  Both audit rows thus share the same ID, enabling
            // forensic correlation across the two-row emission set.
            //
            // Uses Uuid::new_v4() to match the request_id convention used by
            // the rest of the module (rules.rs new_request_id, signers.rs new_request_id).
            let divergence_request_id = Uuid::new_v4().to_string();
            let smart_account_redacted = redact_first5_last5(smart_account);

            // Verifier diversification enforce-default trigger.
            //
            // Runs BEFORE the signer-set divergence check and wasm-hash drift checks
            // because it reads only the local audit log (no network I/O) and is the
            // cheapest gate — fail-fast ordering.  For each non-bootstrap rule_id,
            // reads the audit-log-derived pinned-hash record and applies
            // `check_diversification_required`.
            //
            // Criteria ScVal: `ScVal::Void` is passed for all rules. The
            // OpenZeppelin smart-account contract carries no
            // `PerTxCapCriterion` type; `extract_value_threshold(ScVal::Void)`
            // returns `Undetermined`, which is treated as above-threshold (fail-CLOSED).
            // Operators with single-verifier rules must pass `accept_single_verifier = true`.
            //
            // Not yet supported: schema-anticipation for a canonical per-transaction
            // value-cap encoding (the OpenZeppelin contract does not ship a
            // per-transaction value-cap policy).
            {
                if accept_single_verifier && sm.audit_writer().is_poisoned() {
                    warn!("audit-writer mutex poisoned; cannot record diversification override");
                    return (
                        Err(CredentialsError::AuditWriterPoisoned {
                            context: AuditWriterPoisonContext::DiversificationOverrideEmission,
                        }),
                        String::new(),
                        String::new(),
                        Some(divergence_request_id),
                    );
                }
                let audit_reader = stellar_agent_core::audit_log::reader::AuditReader::new(
                    Arc::clone(&sm.audit_writer()),
                    None,
                );

                // This timestamp is intentionally per-invocation, not per-rule,
                // so all override rows emitted by a single signing request share
                // one operator acknowledgement time.
                // request_id correlates the rows in the audit log.
                let override_acknowledged_at = stellar_agent_core::timefmt::current_iso8601_utc();

                for &rule_id in &rule_ids {
                    if rule_id == 0 {
                        // Bootstrap rule has no verifier by definition.
                        continue;
                    }

                    // Read audit-log-derived pinned hashes for this rule.
                    let pinned_hashes = match audit_reader
                        .find_latest_context_rule_pinned_hashes(rule_id, &smart_account_redacted)
                    {
                        Ok(Some(ph)) => ph,
                        Ok(None) => {
                            tracing::info!(
                                rule_id = %rule_id,
                                "no baseline row found; fail-CLOSED via empty pinned-hashes"
                            );
                            // No baseline row → treat as no pinned hashes (fail-CLOSED).
                            stellar_agent_core::audit_log::reader::PinnedHashesRecord::default()
                        }
                        Err(audit_err) => {
                            // Audit-log integrity failure → fail-CLOSED.
                            warn!(
                                rule_id,
                                error = %audit_err,
                                "sign_with_passkey_rule: audit-log read failed during \
                                 diversification check; aborting signing (fail-closed)"
                            );
                            return (
                                Err(CredentialsError::DiversificationRequired {
                                    source: Box::new(
                                        crate::SaError::VerifierDiversificationRequired {
                                            rule_id,
                                            smart_account_redacted:
                                                RedactedStrkey::from_already_redacted(
                                                    smart_account_redacted.clone(),
                                                ),
                                            verifier_hash_first8: String::new(),
                                            observed_value_threshold_stroops:
                                                crate::managers::diversification::DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS,
                                            request_id: divergence_request_id.clone(),
                                        },
                                    ),
                                }),
                                String::new(),
                                String::new(),
                                Some(divergence_request_id),
                            );
                        }
                    };

                    // Criteria: ScVal::Void → Undetermined → fail-CLOSED (see above).
                    let criteria = stellar_xdr::ScVal::Void;

                    match crate::managers::diversification::check_diversification_required(
                        rule_id,
                        &smart_account_redacted,
                        &pinned_hashes,
                        &criteria,
                    ) {
                        crate::managers::diversification::DiversificationCheck::NotRequired => {
                            // Proceed normally.
                        }
                        crate::managers::diversification::DiversificationCheck::Required {
                            rule_id: req_rule_id,
                            smart_account_redacted: ref req_sa,
                            ref verifier_hash_first8,
                            observed_value_threshold_stroops,
                        } => {
                            if accept_single_verifier {
                                // Operator opt-in: emit SaVerifierDiversificationOverride
                                // audit row and proceed.
                                let entry =
                                    stellar_agent_core::audit_log::entry::AuditEntry::new_sa_verifier_diversification_override(
                                        req_rule_id,
                                        RedactedStrkey::from_already_redacted(req_sa.as_str()),
                                        verifier_hash_first8.as_str(),
                                        observed_value_threshold_stroops,
                                        override_acknowledged_at.as_str(),
                                        sm.chain_id(),
                                        divergence_request_id.as_str(),
                                    );
                                match sm.audit_writer().lock() {
                                    Ok(mut writer) => {
                                        if let Err(e) = writer.write_entry(entry) {
                                            warn!(
                                                rule_id = req_rule_id,
                                                error = %e,
                                                "sign_with_passkey_rule: failed to write \
                                                 SaVerifierDiversificationOverride audit row \
                                                 (non-fatal; signing continues)"
                                            );
                                        }
                                    }
                                    Err(_) => {
                                        warn!(
                                            rule_id = req_rule_id,
                                            "audit-writer mutex poisoned; cannot record override"
                                        );
                                        return (
                                            Err(CredentialsError::AuditWriterPoisoned {
                                                context: AuditWriterPoisonContext::DiversificationOverrideEmission,
                                            }),
                                            String::new(),
                                            String::new(),
                                            Some(divergence_request_id),
                                        );
                                    }
                                }
                                // Proceed: do NOT return early.
                            } else {
                                // Refuse with typed error.
                                return (
                                    Err(CredentialsError::DiversificationRequired {
                                        source: Box::new(
                                            crate::SaError::VerifierDiversificationRequired {
                                                rule_id: req_rule_id,
                                                smart_account_redacted:
                                                    RedactedStrkey::from_already_redacted(
                                                        req_sa.clone(),
                                                    ),
                                                verifier_hash_first8: verifier_hash_first8.clone(),
                                                observed_value_threshold_stroops,
                                                request_id: divergence_request_id.clone(),
                                            },
                                        ),
                                    }),
                                    String::new(),
                                    String::new(),
                                    Some(divergence_request_id),
                                );
                            }
                        }
                    }
                }
            }

            for &rule_id in &rule_ids {
                // Bootstrap rule (id == 0) has no threshold-policy by
                // definition; verify_signer_set_against_chain would return
                // SaError::ThresholdPolicyNotInstalled, which would brick all
                // WebAuthn signings against the bootstrap rule.
                // Mirror the skip from rules.rs::check_divergence_for_auth_rule_ids.
                if rule_id == 0 {
                    warn!(
                        rule_id,
                        "sign_with_passkey_rule: auth_rule_id == 0 (bootstrap rule); \
                         divergence check skipped — bootstrap rule has no threshold-policy"
                    );
                    continue;
                }

                match sm
                    .verify_signer_set_against_chain(
                        sc_addr.clone(),
                        rule_id,
                        None,
                        divergence_request_id.clone(),
                    )
                    .await
                {
                    Ok(_frozen) => {
                        // Divergence check passed for this rule_id; continue.
                    }
                    Err(sa_err) => {
                        // Return divergence_request_id as the 4th tuple
                        // element so the outer fn threads it into emit_signing_audit.
                        return (
                            Err(CredentialsError::SignerSetDivergence {
                                source: Box::new(sa_err),
                            }),
                            String::new(),
                            String::new(),
                            Some(divergence_request_id),
                        );
                    }
                }
            }

            // After the signer-set divergence check passes, run per-rule verifier
            // and policy wasm-hash drift detection BEFORE any bridge I/O.
            //
            // Per-call `HashMap<ScAddress-XDR-bytes, [u8;32]>` cache prevents
            // redundant two-RPC fetches when multiple rules reference the same
            // verifier/policy contract.
            //
            // Each verifier/policy call uses `divergence_request_id` so that the
            // `SaVerifierHashDrift` / `SaPolicyHashDrift` audit rows share the same
            // request_id as the eventual `PasskeyAssertion(failure:verifier_hash_drift)`
            // row — forensic correlation.
            let mut wasm_hash_cache: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();

            for &rule_id in &rule_ids {
                if rule_id == 0 {
                    // Bootstrap rule: no verifier/policy contracts to check.
                    continue;
                }

                // Fetch the on-chain rule to learn which verifier/policy addresses
                // are registered.  Read-only `get_context_rule` view call; no auth required.
                let (verifier_addrs, policy_addrs) = match sm
                    .fetch_verifier_and_policy_addresses(sc_addr.clone(), rule_id, None)
                    .await
                {
                    Ok(pair) => pair,
                    Err(sa_err) => {
                        // Rule no longer exists on-chain or RPC error — abort
                        // signing (fail-closed) but use DriftCheckUnavailable, not
                        // WasmHashDrift.  No hash mismatch was detected; the
                        // drift check infrastructure itself could not run.
                        // No SaVerifierHashDrift / SaPolicyHashDrift
                        // audit row is emitted here — a rule-fetch failure is not
                        // the same as a detected drift event.
                        warn!(
                            rule_id,
                            error = %sa_err,
                            "sign_with_passkey_rule: failed to fetch on-chain rule for \
                             drift-detection; aborting signing (fail-closed)"
                        );
                        return (
                            Err(CredentialsError::DriftCheckUnavailable {
                                source: Box::new(sa_err),
                            }),
                            String::new(),
                            String::new(),
                            Some(divergence_request_id),
                        );
                    }
                };

                // Verifier drift-detection — one call per distinct External verifier.
                //
                // Discriminant-route the inner SaError so that only
                // *actual* drift events (SaVerifierHashDrift, SaPolicyHashDrift)
                // produce CredentialsError::WasmHashDrift, which must be paired
                // with a SaVerifier/PolicyHashDrift audit row.  Infrastructure failures
                // (NetworkRpcDivergence, DeploymentFailed, MultiplePinnedHashesUnsupported,
                // AuditLog) route to DriftCheckUnavailable — no drift audit row is
                // emitted for those (none was written by verify_pinned_*).
                for verifier_addr in verifier_addrs {
                    if let Err(sa_err) =
                        crate::managers::verifiers::verify_pinned_verifier_against_chain(
                            sm,
                            verifier_addr,
                            rule_id,
                            &smart_account_redacted,
                            &divergence_request_id,
                            &mut wasm_hash_cache,
                        )
                        .await
                    {
                        let credentials_err = drift_err_route(sa_err);
                        return (
                            Err(credentials_err),
                            String::new(),
                            String::new(),
                            Some(divergence_request_id),
                        );
                    }
                }

                // Policy drift-detection — one call per policy address.
                for policy_addr in policy_addrs {
                    if let Err(sa_err) =
                        crate::managers::verifiers::verify_pinned_policy_against_chain(
                            sm,
                            policy_addr,
                            rule_id,
                            &smart_account_redacted,
                            &divergence_request_id,
                            &mut wasm_hash_cache,
                        )
                        .await
                    {
                        let credentials_err = drift_err_route(sa_err);
                        return (
                            Err(credentials_err),
                            String::new(),
                            String::new(),
                            Some(divergence_request_id),
                        );
                    }
                }
            }
        } else {
            warn!(
                credential_name,
                rule_count = rule_ids.len(),
                "sign_with_passkey_rule: signers_manager is None; \
                 divergence check skipped (test-only escape hatch; \
                 production callers MUST supply Some(signers_manager))"
            );
        }

        // Require approval store — read-only managers cannot drive signing.
        // Early-exit before show(); audit fields are "" on this path.
        let approval_store = match self.approval_store.as_ref() {
            Some(s) => s,
            None => {
                return (
                    Err(CredentialsError::ApprovalStoreUnavailable),
                    String::new(),
                    String::new(),
                    None,
                );
            }
        };

        // 1. Resolve credential metadata.
        // If show() fails (NotFound), we still have "" for the audit fields.
        let metadata = match self.show(credential_name) {
            Ok(m) => m,
            Err(e) => return (Err(e), String::new(), String::new(), None),
        };

        // From this point forward all errors carry real credential_id_b64url and rp_id.
        let credential_id_b64url = metadata.credential_id_b64url.clone();
        let rp_id = metadata.rp_id.clone();

        // Helper macro to return early with real audit fields on error.
        // The 4th element (request_id_override) is None on non-divergence paths.
        macro_rules! early_err {
            ($e:expr) => {
                return (Err($e), credential_id_b64url, rp_id, None)
            };
        }

        // 2. Decode credential_id + public_key.
        let credential_id_bytes = match URL_SAFE_NO_PAD.decode(&metadata.credential_id_b64url) {
            Ok(b) => b,
            Err(_) => early_err!(CredentialsError::ApprovalStore {
                detail: "credential_id_b64url is not valid base64url".to_owned(),
            }),
        };

        // Shared SEC1 validation via `decode_validated_sec1` (defined above the impl
        // block; covers empty / decode-fail / wrong-length / missing-0x04).
        let pubkey_arr: [u8; 65] =
            match decode_validated_sec1(credential_name, &metadata.public_key_sec1_b64) {
                Ok(a) => a,
                Err(e) => early_err!(e),
            };

        let credential_record = PasskeyCredentialRecord::new(
            credential_id_bytes.clone(),
            pubkey_arr,
            metadata.rp_id.clone(),
        );

        // 3. Insert SignWithPasskey approval entry.
        let csrf_token = generate_csrf_token();
        let process_uid = match process_uid_for_attestation() {
            Ok(uid) => uid,
            Err(e) => early_err!(CredentialsError::ApprovalStore {
                detail: format!("process_uid: {e}"),
            }),
        };

        // Redact the caller-supplied smart_account strkey to first-5-last-5
        // so the approval entry and audit log carry a meaningful redacted identifier
        // rather than the indistinguishable "CAAAA...AAAAA" placeholder.  The
        // validator in `new_passkey_pending` accepts the redaction shape; the full
        // strkey is never persisted.
        let smart_account_redacted = redact_first5_last5(smart_account);

        // Pass the credential's stored rp_id so the bridge renders the correct
        // RP-ID in the approval page JS; bridge handlers read rp_id from the entry
        // rather than using a hardcoded "localhost" placeholder.
        let entry = match PendingApproval::new_passkey_pending(
            *auth_digest,
            credential_id_bytes.clone(),
            smart_account_redacted,
            rule_ids,
            csrf_token,
            metadata.rp_id.clone(),
            process_uid,
            DEFAULT_TTL_MS,
        ) {
            Ok(e) => e,
            Err(e) => early_err!(CredentialsError::ApprovalStore {
                detail: e.to_string(),
            }),
        };

        let nonce = entry.approval_nonce.clone();

        {
            let mut guard = approval_store.lock().await;
            if let Err(e) = guard.insert(entry, unix_now_ms()) {
                early_err!(CredentialsError::ApprovalStore {
                    detail: e.to_string(),
                });
            }
        }

        // 4. Build the approval URL and deliver it to the caller.
        //
        // Use `localhost:<port>` rather than `bridge_local_addr` directly
        // so the browser origin (`http://localhost:<port>`) matches the RP-ID
        // `"localhost"` per WebAuthn Level 2 §5.1.2.  Without this rewrite a
        // 127.0.0.1-bound bridge produces URLs with origin
        // `http://127.0.0.1:<port>`, which Chromium (without --disable-web-security)
        // rejects as a SecurityError because "127.0.0.1" is an IP literal, not a
        // registrable domain suffix of the RP-ID "localhost".
        let port = bridge_local_addr.port();
        let url = format!("http://localhost:{port}/approve/{nonce}");
        // Refactor-protection: the format-string literal `"localhost"` makes this
        // assertion structurally true today. The assertion catches a future
        // refactor that swaps the host literal (e.g. to `127.0.0.1` or to `rp_id`)
        // for one that resolves outside the loopback allowlist.
        debug_assert!(
            is_loopback_http_url(&url),
            "constructed URL not loopback-bound: {url}"
        );

        // Diagnostic hint if rp_id does not match "localhost" on a
        // loopback-bound bridge — real Chromium rejects with SecurityError.
        if bridge_local_addr.ip().is_loopback() && metadata.rp_id != "localhost" {
            warn!(
                rp_id = %metadata.rp_id,
                "bridge binds loopback but credential rp_id is not \"localhost\"; \
                 WebAuthn signing ceremony will fail in a standards-conforming browser \
                 (WebAuthn-2 §5.1.2)"
            );
        }

        let nonce_redacted = redact_first5_last5(&nonce);
        debug!(nonce = %nonce_redacted, "passkey signing ceremony prepared");

        // 5. Notify the caller (typically opens the browser or prints the URL).
        on_url(&url);

        // 6. Poll until assertion arrives or deadline elapses.
        let deadline = Instant::now() + timeout;
        let poll_result = self
            .poll_signing(
                &nonce,
                auth_digest,
                credential_record,
                &credential_id_bytes,
                &metadata,
                deadline,
            )
            .await;

        (poll_result, credential_id_b64url, rp_id, None)
    }

    /// Polls the shared approval store until a `passkey_assertion` appears for
    /// `nonce`, drives `PasskeySignHandle::sign_webauthn_assertion`, and
    /// returns the outcome.
    ///
    /// This is a private sub-method of `sign_with_passkey_rule` that handles
    /// the polling loop and signing step.
    #[allow(
        clippy::too_many_arguments,
        reason = "poll_signing mirrors sign_with_passkey_rule's parameter set \
                  minus the callback/audit-writer; no logical grouping is possible"
    )]
    async fn poll_signing(
        &self,
        nonce: &str,
        auth_digest: &[u8; 32],
        credential_record: PasskeyCredentialRecord,
        credential_id_bytes: &[u8],
        metadata: &CredentialMetadata,
        deadline: Instant,
    ) -> Result<SignWithPasskeyOutcome, CredentialsError> {
        let store = self
            .approval_store
            .as_ref()
            .ok_or(CredentialsError::ApprovalStoreUnavailable)?;

        loop {
            if Instant::now() >= deadline {
                return Ok(SignWithPasskeyOutcome::Timeout);
            }

            // Check store for assertion.
            if let Some(result) = self
                .check_store_for_assertion(
                    nonce,
                    auth_digest,
                    credential_record.clone(),
                    credential_id_bytes,
                    metadata,
                    store,
                )
                .await?
            {
                return Ok(result);
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let sleep_for = self.poll_interval.min(remaining);
            if sleep_for.is_zero() {
                return Ok(SignWithPasskeyOutcome::Timeout);
            }
            tokio::time::sleep(sleep_for).await;
        }
    }

    /// Inner poll tick for `poll_signing`: checks the store once and returns
    /// `Ok(Some(outcome))` if terminal, `Ok(None)` if still pending.
    #[allow(
        clippy::too_many_arguments,
        reason = "check_store_for_assertion requires nonce, digest, credential record, \
                  raw bytes, metadata, and store handle; individual parameters cannot \
                  be combined without incurring heap allocation or lifetime complexity"
    )]
    async fn check_store_for_assertion(
        &self,
        nonce: &str,
        auth_digest: &[u8; 32],
        credential_record: PasskeyCredentialRecord,
        credential_id_bytes: &[u8],
        metadata: &CredentialMetadata,
        store: &Arc<Mutex<PendingApprovalStore>>,
    ) -> Result<Option<SignWithPasskeyOutcome>, CredentialsError> {
        let entry_opt = {
            let guard = store.lock().await;
            guard.get(nonce).cloned()
        };

        let Some(entry) = entry_opt else {
            let nonce_redacted = redact_first5_last5(nonce);
            warn!(nonce = %nonce_redacted, "signing nonce not found in store");
            return Ok(Some(SignWithPasskeyOutcome::EntryMissing));
        };

        // Check if the assertion has arrived.
        match &entry.passkey_assertion {
            Some(assertion_input) => {
                // Assertion arrived — drive the signing pipeline.
                let assertion_input = assertion_input.clone();
                let handle = PasskeySignHandle::new(credential_record, assertion_input);
                let webauthn_assertion = handle
                    .sign_webauthn_assertion(auth_digest, credential_id_bytes)
                    .await
                    .map_err(|e| CredentialsError::Signing {
                        detail: format!("sign_webauthn_assertion: {}", e.code()),
                    })?;

                Ok(Some(SignWithPasskeyOutcome::Signed {
                    signature_bytes: webauthn_assertion,
                    credential_metadata: Box::new(metadata.clone()),
                }))
            }
            None => {
                // Assertion not yet available; check entry kind for cancellation.
                match &entry.kind {
                    ApprovalKind::SignWithPasskey { .. } => Ok(None), // still pending
                    _ => {
                        // Kind mismatch — unexpected; treat as user-cancelled.
                        let nonce_redacted = redact_first5_last5(nonce);
                        warn!(nonce = %nonce_redacted, "signing entry has unexpected kind");
                        Ok(Some(SignWithPasskeyOutcome::UserCanceled))
                    }
                }
            }
        }
    }

    /// Emits a `PasskeyAssertion` audit entry if `audit_writer` is `Some`.
    ///
    /// `auth_digest_hex` must be provided so the
    /// `AuditEntry` constructor can apply first-5-last-5 redaction internally.
    /// `smart_account` is the raw C-strkey of the target smart account; the
    /// constructor applies first-5-last-5 redaction before storing.  Pass the
    /// raw (non-pre-redacted) value.
    /// Audit-log failures are non-fatal.
    ///
    /// `signers_manager` is used solely to call
    /// [`SignersManager::mark_audit_writer_degraded`] when the mutex is poisoned
    /// so the session-level flag is set and `wallet audit-log verify` can surface
    /// the gap.  When `None` (test-only escape hatch), the
    /// flag is not set; the drop is still non-fatal.
    ///
    /// # Request-ID override
    ///
    /// When `request_id_override` is `Some(id)`, that ID is used verbatim for the
    /// `PasskeyAssertion` row.  This is set to the `divergence_request_id` on the
    /// `failure:signer_set_diverged` path so both the `SaSignerSetDiverged` row
    /// (emitted by `verify_signer_set_against_chain`) and this `PasskeyAssertion`
    /// row carry the same UUID, enabling forensic correlation.  On all other paths
    /// `request_id_override` is `None` and a fresh UUID is minted here.
    #[allow(
        clippy::too_many_arguments,
        reason = "emit_signing_audit captures all audit-log fields individually; \
                  a single struct parameter would require a pub type exposing internals"
    )]
    fn emit_signing_audit(
        &self,
        audit_writer: Option<&Arc<std::sync::Mutex<AuditWriter>>>,
        signers_manager: Option<&Arc<SignersManager>>,
        credential_name: &str,
        credential_id_b64url: &str,
        rp_id: &str,
        smart_account: &str,
        auth_digest_hex: &str,
        signed_at_unix_ms: u64,
        result: &str,
        request_id_override: Option<&str>,
    ) {
        let Some(arc) = audit_writer else {
            return;
        };

        // Lock the shared Arc<std::sync::Mutex<AuditWriter>>
        // instead of borrowing a caller-owned &mut AuditWriter.  Both the
        // PasskeyAssertion row (emitted here) and the SaSignerSetDiverged row
        // (emitted inside verify_signer_set_against_chain) transit the same
        // Arc, so they land in the same JSONL file — satisfying the cross-row
        // request_id pairing invariant.
        //
        // SignersManager uses std::sync::Mutex (not tokio::sync::Mutex) so that
        // the writer can be locked in both async and sync contexts without .await.
        //
        // Lock discipline: the lock is acquired for the minimum time needed to
        // write the single entry; it is released before the function returns.
        // No caller holds the lock on entry; SaSignerSetDiverged emission
        // inside verify_signer_set_against_chain acquires and releases the same
        // lock separately, so there is no deadlock risk.
        let mut writer = match arc.lock() {
            Ok(g) => g,
            Err(e) => {
                // Wire degraded flag so operator is notified via
                // `wallet audit-log verify` when the PasskeyAssertion row is silently
                // dropped. Only fires if a SignersManager is available (production
                // path); unit-test escape-hatch paths with signers_manager=None remain
                // non-fatal but do not set the flag.
                if let Some(sm) = signers_manager {
                    sm.mark_audit_writer_degraded();
                }
                warn!(
                    credential_name = %credential_name,
                    error = %e,
                    "audit_writer mutex poisoned; PasskeyAssertion entry not written"
                );
                return;
            }
        };

        // Use the caller-supplied override on the divergence-fail path
        // (forensic correlation), or mint a fresh UUID on all other paths.
        let request_id = match request_id_override {
            Some(id) => id.to_owned(),
            None => Uuid::new_v4().to_string(),
        };

        let entry = AuditEntry::new_passkey_assertion(
            credential_name,
            credential_id_b64url,
            rp_id,
            smart_account,
            auth_digest_hex,
            signed_at_unix_ms,
            result,
            request_id,
        );

        if let Err(e) = writer.write_entry(entry) {
            warn!(
                error = %e,
                credential_name = %credential_name,
                "failed to write passkey_assertion audit entry"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn encode_auth_digest_hex(auth_digest: &[u8; 32]) -> String {
    hex::encode(auth_digest)
}

/// Routes a `SaError` from a drift-detection call into the correct
/// `CredentialsError` envelope.
///
/// # Schema invariant
///
/// `CredentialsError::WasmHashDrift` MUST be paired with a
/// `SaVerifierHashDrift` or `SaPolicyHashDrift` audit row carrying the same
/// `request_id`.  `verify_pinned_verifier_against_chain` and
/// `verify_pinned_policy_against_chain` only emit those audit rows when they
/// return `SaError::VerifierHashDrift` or `SaError::PolicyHashDrift`
/// respectively.  All other `SaError` variants from those functions
/// (infrastructure failures: `NetworkRpcDivergence`, `DeploymentFailed`,
/// `MultiplePinnedHashesUnsupported`, `AuditLog`) do NOT emit a drift row,
/// so wrapping them in `WasmHashDrift` would break the result-tag ↔
/// audit-row join that operator tooling relies on.
///
/// This function enforces the invariant at a single call site rather than
/// repeating the match in every loop.
fn drift_err_route(sa_err: crate::SaError) -> CredentialsError {
    match &sa_err {
        // Actual drift detected — paired SaVerifierHashDrift audit row was emitted.
        crate::SaError::VerifierHashDrift { .. } => CredentialsError::WasmHashDrift {
            source: Box::new(sa_err),
        },
        // Actual drift detected — paired SaPolicyHashDrift audit row was emitted.
        crate::SaError::PolicyHashDrift { .. } => CredentialsError::WasmHashDrift {
            source: Box::new(sa_err),
        },
        // Infrastructure failure — no drift audit row was emitted; use DriftCheckUnavailable.
        _ => CredentialsError::DriftCheckUnavailable {
            source: Box::new(sa_err),
        },
    }
}

/// Validates a credential name.
///
/// Rules:
/// - Non-empty.
/// - At most 64 characters.
/// - Only printable ASCII (0x20–0x7E), no control characters.
/// - No `/`, `\`, or `:` (to prevent path-component injection in registry
///   TOML key names and keyring entry names).
pub(crate) fn validate_credential_name(name: &str) -> Result<(), CredentialsError> {
    if name.is_empty() {
        return Err(CredentialsError::InvalidName {
            name: name.to_owned(),
            reason: "must not be empty",
        });
    }
    if name.len() > 64 {
        return Err(CredentialsError::InvalidName {
            name: name.to_owned(),
            reason: "must be at most 64 characters",
        });
    }
    for ch in name.chars() {
        if !ch.is_ascii() || ch.is_ascii_control() {
            return Err(CredentialsError::InvalidName {
                name: name.to_owned(),
                reason: "must contain only printable ASCII characters",
            });
        }
        if matches!(ch, '/' | '\\' | ':') {
            return Err(CredentialsError::InvalidName {
                name: name.to_owned(),
                reason: r"must not contain '/', '\', or ':' characters",
            });
        }
    }
    Ok(())
}

/// Returns the current time as Unix milliseconds, capped at `u64::MAX`.
///
/// Uses `std::time::SystemTime::now()` and saturates on overflow (extremely
/// unlikely before year 584 million).
fn unix_now_ms() -> u64 {
    unix_duration_to_ms(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH))
}

fn unix_duration_to_ms(duration: Result<std::time::Duration, std::time::SystemTimeError>) -> u64 {
    let duration = match duration {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "unix_now_ms: SystemTime::now() before UNIX_EPOCH; falling back to 0ms",
            );
            Duration::ZERO
        }
    };
    duration.as_millis().min(u64::MAX as u128) as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use serde_json::Value as JsonValue;
    use tempfile::TempDir;

    const TEST_RPC_URL: &str = "https://soroban-testnet.stellar.org";

    /// Build a `CredentialsManager` backed by temporary directories.
    ///
    /// Includes an approval store so tests that call `prepare_registration`
    /// and `poll_registration` work. Tests that only need read-only operations
    /// can use `test_manager_readonly` instead.
    fn test_manager(dir: &TempDir) -> CredentialsManager {
        let approval_path = dir.path().join("approvals").join("default.toml");
        std::fs::create_dir_all(approval_path.parent().unwrap()).unwrap();
        let store =
            PendingApprovalStore::open(approval_path).expect("test store must open in tempdir");
        CredentialsManager::new(
            dir.path().join("passkeys"),
            "default",
            "localhost",
            Some(Arc::new(Mutex::new(store))),
        )
    }

    /// Build a read-only `CredentialsManager` (no approval store).
    fn test_manager_readonly(dir: &TempDir) -> CredentialsManager {
        CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None)
    }

    /// A `CredentialMetadata` fixture for testing (includes the new `public_key_sec1_b64`).
    fn make_metadata(name: &str) -> CredentialMetadata {
        let mut pubkey = vec![0u8; 65];
        pubkey[0] = 0x04;
        CredentialMetadata {
            credential_name: name.to_owned(),
            credential_id_b64url: URL_SAFE_NO_PAD.encode(b"test-credential-id-16b"),
            rp_id: "localhost".to_owned(),
            transports: "usb".to_owned(),
            registered_at_unix_ms: 1_700_000_000_000,
            public_key_sec1_b64: URL_SAFE_NO_PAD.encode(&pubkey),
        }
    }

    // ── list ──────────────────────────────────────────────────────────────────

    #[test]
    fn list_returns_empty_when_no_registry_file() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let creds = mgr.list().unwrap();
        assert!(creds.is_empty());
    }

    #[test]
    fn list_returns_persisted_credentials() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let meta = make_metadata("my-key");
        let mut registry = RegistryFile::default();
        registry.credentials.push(meta.clone());
        mgr.persist_registry(&registry).unwrap();

        let creds = mgr.list().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].credential_name, "my-key");
    }

    // ── show ──────────────────────────────────────────────────────────────────

    #[test]
    fn show_returns_not_found_for_missing_name() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let err = mgr.show("ghost").unwrap_err();
        assert!(matches!(err, CredentialsError::NotFound { name } if name == "ghost"));
    }

    #[test]
    fn show_returns_metadata_for_known_name() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let meta = make_metadata("hw-key");
        let mut registry = RegistryFile::default();
        registry.credentials.push(meta.clone());
        mgr.persist_registry(&registry).unwrap();

        let result = mgr.show("hw-key").unwrap();
        assert_eq!(result.credential_id_b64url, meta.credential_id_b64url);
        assert_eq!(result.rp_id, "localhost");
    }

    #[test]
    fn public_key_sec1_for_credential_id_returns_registered_key() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        let meta = make_metadata("approval-key");
        let credential_id = URL_SAFE_NO_PAD.decode(&meta.credential_id_b64url).unwrap();
        let expected_pubkey = URL_SAFE_NO_PAD.decode(&meta.public_key_sec1_b64).unwrap();
        let mut expected = [0u8; 65];
        expected.copy_from_slice(&expected_pubkey);
        let mut registry = RegistryFile::default();
        registry.credentials.push(meta);
        mgr.persist_registry(&registry).unwrap();

        let found = mgr
            .public_key_sec1_for_credential_id(&credential_id)
            .unwrap();

        assert_eq!(found, Some(expected));
    }

    #[test]
    fn public_key_sec1_for_credential_id_returns_none_for_missing_record() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        let meta = make_metadata("approval-key");
        let mut registry = RegistryFile::default();
        registry.credentials.push(meta);
        mgr.persist_registry(&registry).unwrap();

        let found = mgr
            .public_key_sec1_for_credential_id(b"different-credential-id")
            .unwrap();

        assert_eq!(found, None);
    }

    // ── delete ────────────────────────────────────────────────────────────────

    #[test]
    fn delete_removes_named_credential() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let mut registry = RegistryFile::default();
        registry.credentials.push(make_metadata("key-a"));
        registry.credentials.push(make_metadata("key-b"));
        mgr.persist_registry(&registry).unwrap();

        mgr.delete("key-a").unwrap();

        let creds = mgr.list().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].credential_name, "key-b");
    }

    #[test]
    fn delete_returns_not_found_for_missing_name() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let err = mgr.delete("nonexistent").unwrap_err();
        assert!(matches!(err, CredentialsError::NotFound { .. }));
    }

    // ── is_empty ──────────────────────────────────────────────────────────────

    #[test]
    fn is_empty_returns_true_when_no_registry() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        assert!(mgr.is_empty().unwrap());
    }

    #[test]
    fn is_empty_returns_false_after_persist() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let mut registry = RegistryFile::default();
        registry.credentials.push(make_metadata("k"));
        mgr.persist_registry(&registry).unwrap();
        assert!(!mgr.is_empty().unwrap());
    }

    // ── validate_credential_name ──────────────────────────────────────────────

    #[test]
    fn validate_credential_name_accepts_simple_names() {
        assert!(validate_credential_name("my-passkey").is_ok());
        assert!(validate_credential_name("hardware key 1").is_ok());
        assert!(validate_credential_name("a").is_ok());
    }

    #[test]
    fn validate_credential_name_rejects_empty() {
        let err = validate_credential_name("").unwrap_err();
        assert!(
            matches!(err, CredentialsError::InvalidName { reason, .. } if reason.contains("empty"))
        );
    }

    #[test]
    fn validate_credential_name_rejects_over_64_chars() {
        let long = "a".repeat(65);
        let err = validate_credential_name(&long).unwrap_err();
        assert!(
            matches!(err, CredentialsError::InvalidName { reason, .. } if reason.contains("64"))
        );
    }

    #[test]
    fn validate_credential_name_rejects_slash() {
        let err = validate_credential_name("my/key").unwrap_err();
        assert!(
            matches!(err, CredentialsError::InvalidName { reason, .. } if reason.contains('/'))
        );
    }

    #[test]
    fn validate_credential_name_rejects_backslash() {
        let err = validate_credential_name("my\\key").unwrap_err();
        // The displayed reason must show a single backslash, not a doubled one.
        let reason = match err {
            CredentialsError::InvalidName { reason, .. } => reason,
            other => panic!("expected InvalidName, got {other:?}"),
        };
        assert!(
            reason.contains('\\'),
            "reason must mention backslash: {reason}"
        );
        // Must NOT contain a doubled backslash that would display as two.
        assert!(
            !reason.contains("\\\\"),
            "reason must not contain doubled backslash: {reason}"
        );
    }

    #[test]
    fn validate_credential_name_rejects_colon() {
        let err = validate_credential_name("my:key").unwrap_err();
        assert!(
            matches!(err, CredentialsError::InvalidName { reason, .. } if reason.contains(':'))
        );
    }

    #[test]
    fn validate_credential_name_rejects_non_ascii() {
        let err = validate_credential_name("passkey-\u{00e9}").unwrap_err();
        assert!(
            matches!(err, CredentialsError::InvalidName { reason, .. } if reason.contains("ASCII"))
        );
    }

    // ── registry round-trip ───────────────────────────────────────────────────

    #[test]
    fn registry_round_trip_toml() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let meta = make_metadata("usb-key");
        let mut registry = RegistryFile::default();
        registry.credentials.push(meta.clone());
        mgr.persist_registry(&registry).unwrap();

        let loaded = mgr.load_registry().unwrap();
        assert_eq!(loaded.credentials.len(), 1);
        let loaded_meta = &loaded.credentials[0];
        assert_eq!(loaded_meta.credential_name, meta.credential_name);
        assert_eq!(loaded_meta.credential_id_b64url, meta.credential_id_b64url);
        assert_eq!(loaded_meta.rp_id, meta.rp_id);
        assert_eq!(loaded_meta.transports, meta.transports);
        assert_eq!(
            loaded_meta.registered_at_unix_ms,
            meta.registered_at_unix_ms
        );
        assert_eq!(loaded_meta.public_key_sec1_b64, meta.public_key_sec1_b64);
    }

    /// Deserialise a legacy TOML entry that lacks `public_key_sec1_b64`.
    ///
    /// The `#[serde(default)]` attribute on the field must cause deserialisation
    /// to succeed with an empty string (the `Default::default()` for `String`).
    #[test]
    fn deserialise_legacy_entry_without_public_key() {
        let legacy_toml = r#"
[[credentials]]
credential_name = "legacy-key"
credential_id_b64url = "dGVzdC1jcmVkZW50aWFsLWlkLTE2Yg"
rp_id = "127.0.0.1"
transports = "usb"
registered_at_unix_ms = 1700000000000
"#;
        let registry: RegistryFile =
            toml::from_str(legacy_toml).expect("legacy TOML must deserialise");
        assert_eq!(registry.credentials.len(), 1);
        let meta = &registry.credentials[0];
        assert_eq!(meta.credential_name, "legacy-key");
        // public_key_sec1_b64 absent in TOML → empty string (serde(default)).
        assert_eq!(
            meta.public_key_sec1_b64, "",
            "missing public_key_sec1_b64 must deserialise to empty string"
        );
    }

    // ── duplicate detection ────────────────────────────────────────────────────

    #[test]
    fn duplicate_name_detection() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let mut registry = RegistryFile::default();
        registry.credentials.push(make_metadata("existing"));
        mgr.persist_registry(&registry).unwrap();

        // Simulate the duplicate check that prepare_registration does.
        let loaded = mgr.load_registry().unwrap();
        assert!(
            loaded
                .credentials
                .iter()
                .any(|c| c.credential_name == "existing")
        );
    }

    // ── Debug redaction ────────────────────────────────────────────────────────

    #[test]
    fn credential_metadata_debug_does_not_contain_full_credential_id() {
        let meta = make_metadata("hw-key");
        let debug_str = format!("{meta:?}");

        // The credential name must appear (useful for diagnostics).
        assert!(
            debug_str.contains("hw-key"),
            "Debug must include credential_name: {debug_str}"
        );

        // The full credential_id_b64url must NOT appear in Debug output.
        assert!(
            !debug_str.contains(&meta.credential_id_b64url),
            "Debug must redact credential_id_b64url: {debug_str}"
        );

        // The redacted form (first-5...last-5) must appear instead.
        let redacted = redact_first5_last5(&meta.credential_id_b64url);
        assert!(
            debug_str.contains(&redacted),
            "Debug must contain redacted credential_id_b64url '{redacted}': {debug_str}"
        );

        // public_key_sec1_b64 must be completely hidden.
        assert!(
            debug_str.contains("[redacted]"),
            "Debug must show [redacted] for public_key_sec1_b64: {debug_str}"
        );
        assert!(
            !debug_str.contains(&meta.public_key_sec1_b64),
            "Debug must not expose public_key_sec1_b64: {debug_str}"
        );
    }

    // ── readonly manager: concurrent lock contention ───────────────────────────

    #[test]
    fn two_concurrent_readonly_managers_no_lock_contention() {
        // Two from_defaults_readonly-style managers (built via new(..., None))
        // in the SAME directory must both succeed: no approval store is opened
        // so there is no advisory file lock to contend over.
        let dir = TempDir::new().unwrap();
        let mgr1 = test_manager_readonly(&dir);
        let mgr2 = test_manager_readonly(&dir);

        // Both can list without error even though they share the same
        // passkeys directory (no OS lock is held by either).
        let creds1 = mgr1.list().unwrap();
        let creds2 = mgr2.list().unwrap();
        assert!(creds1.is_empty());
        assert!(creds2.is_empty());
    }

    // ── readonly manager: ApprovalStoreUnavailable on store-requiring ops ──────

    #[tokio::test]
    async fn readonly_manager_returns_unavailable_on_prepare_registration() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19877);
        let err = mgr
            .prepare_registration("test-key", addr, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CredentialsError::ApprovalStoreUnavailable),
            "expected ApprovalStoreUnavailable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn prepare_registration_stores_nominal_smart_account_or_placeholder() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use stellar_agent_core::approval::ApprovalKind;

        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let store = Arc::clone(mgr.approval_store.as_ref().unwrap());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19878);
        let smart_account = "CDEPLOY1ABCDE2FGHIJ3KLMNO4PQRST5UVWXY";

        let with_account = mgr
            .prepare_registration("with-account", addr, Some(smart_account))
            .await
            .unwrap();
        let without_account = mgr
            .prepare_registration("without-account", addr, None)
            .await
            .unwrap();

        let guard = store.lock().await;
        let with_entry = guard.get(&with_account.nonce).unwrap();
        let without_entry = guard.get(&without_account.nonce).unwrap();

        let ApprovalKind::RegisterPasskey {
            smart_account_redacted: with_redacted,
            ..
        } = &with_entry.kind
        else {
            panic!("expected RegisterPasskey for nominal smart-account branch");
        };
        assert_eq!(with_redacted, &redact_first5_last5(smart_account));

        let ApprovalKind::RegisterPasskey {
            smart_account_redacted: without_redacted,
            ..
        } = &without_entry.kind
        else {
            panic!("expected RegisterPasskey for placeholder branch");
        };
        assert_eq!(without_redacted, "CAAAA...AAAAA");
    }

    // ── CredentialsManager Debug impl ──────────────────────────────────────────

    #[test]
    fn credentials_manager_debug_does_not_lock_store() {
        // Debug on a manager with Some(store) must not panic and must not
        // expose internal store internals — only "Some(<store>)" indicator.
        let dir = TempDir::new().unwrap();
        let mgr_with_store = test_manager(&dir);
        let debug_with = format!("{mgr_with_store:?}");
        assert!(
            debug_with.contains("Some(<store>)"),
            "Debug with store must show Some indicator: {debug_with}"
        );
        assert!(
            !debug_with.contains("PendingApprovalStore"),
            "Debug must not expose store internals: {debug_with}"
        );

        // Debug on a manager with None must show "None".
        let mgr_readonly = test_manager_readonly(&dir);
        let debug_none = format!("{mgr_readonly:?}");
        assert!(
            debug_none.contains("None"),
            "Debug without store must show None: {debug_none}"
        );
    }

    // ── RegistrationHandle Debug redaction ────────────────────────────────────

    #[test]
    fn registration_handle_debug_does_not_contain_full_nonce() {
        // Construct a nonce long enough for first-5-last-5 redaction.
        let nonce = "AABBCCDDEEFFGGHHIIJJKK".to_owned(); // 22 chars
        let url = format!("http://127.0.0.1:12345/register/{nonce}");
        let handle = RegistrationHandle {
            nonce: nonce.clone(),
            url: url.clone(),
        };
        let debug_str = format!("{handle:?}");

        // The full nonce must NOT appear in Debug output.
        assert!(
            !debug_str.contains(&nonce),
            "Debug must not expose full nonce: {debug_str}"
        );

        // The URL must NOT appear (it embeds the nonce).
        assert!(
            !debug_str.contains(&url),
            "Debug must not expose url (contains nonce): {debug_str}"
        );

        // The redacted nonce form must be present.
        let redacted = redact_first5_last5(&nonce);
        assert!(
            debug_str.contains(&redacted),
            "Debug must contain redacted nonce '{redacted}': {debug_str}"
        );
    }

    // ── audit placeholder sentinel ─────────────────────────────────────────────

    #[test]
    fn audit_placeholder_sentinel_redacts_distinctly_from_real_credential() {
        // The sentinel used by emit_audit on non-success paths.
        let sentinel = "<no-credential-id>";
        let redacted = redact_first5_last5(sentinel);

        // The redacted form MUST contain the `<` marker character — not valid
        // base64url — so analysts can distinguish it from any real credential.
        assert!(
            redacted.contains('<') || redacted.contains('>'),
            "redacted sentinel must contain '<' or '>' (not valid base64url): {redacted}"
        );

        // A typical real credential (base64url chars only) after redaction must
        // NOT contain `<` or `>`.
        let real_cred = "AABBCCDDEEFFGGHHIIJJKK"; // 22 chars, base64url alphabet
        let real_redacted = redact_first5_last5(real_cred);
        assert!(
            !real_redacted.contains('<') && !real_redacted.contains('>'),
            "real credential redacted form must not contain angle brackets: {real_redacted}"
        );
    }

    // ── redact_first5_last5 ───────────────────────────────────────────────────

    #[test]
    fn redact_first5_last5_typical() {
        let id = "AABBCCDDEEFFGGHHIIJJKK"; // 22 chars
        let redacted = redact_first5_last5(id);
        assert_eq!(redacted, "AABBC...IJJKK");
    }

    #[test]
    fn redact_first5_last5_short_passthrough() {
        let short = "ABCDE"; // 5 chars — too short to apply pattern
        assert_eq!(redact_first5_last5(short), "ABCDE");
    }

    #[test]
    fn encode_auth_digest_hex_uses_lowercase_hex() {
        let mut digest = [0u8; 32];
        digest[0] = 0xab;
        digest[1] = 0xcd;

        let encoded = encode_auth_digest_hex(&digest);

        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded, format!("abcd{}", "00".repeat(30)));
    }

    #[test]
    fn unix_duration_to_ms_error_path_returns_zero() {
        let before_epoch =
            std::time::UNIX_EPOCH.duration_since(std::time::UNIX_EPOCH + Duration::from_millis(1));

        assert_eq!(unix_duration_to_ms(before_epoch), 0);
    }

    // ── audit emission on early-exit paths ────────────────────────────────────
    //
    // These tests verify that `sign_with_passkey_rule` emits a `PasskeyAssertion`
    // audit entry on EVERY terminal path, including errors that occur before
    // `poll_signing` is called.  Each test:
    //   1. Triggers a specific early-exit error.
    //   2. Asserts the audit log contains exactly one JSONL line.
    //   3. Asserts the `result` tag matches the expected class.
    //
    // The tests use a file-backed `AuditWriter` written to a temporary file
    // and read back as JSONL to verify the emitted entry.

    /// Helper: open a temporary file-backed `Arc<Mutex<AuditWriter>>` and a
    /// `SignersManager` that shares it.
    ///
    /// `sign_with_passkey_rule` derives the audit writer
    /// from the `SignersManager` reference.  Tests that
    /// verify `PasskeyAssertion` audit emission must supply a `SignersManager`
    /// that wraps an `Arc<std::sync::Mutex<AuditWriter>>` pointing to the temp
    /// audit file.
    ///
    /// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) to match
    /// `SignersManagerConfig`'s field type.
    ///
    /// The `SignersManager` is constructed with a valid testnet RPC URL.
    /// Callers that rely on no network traffic must use `rule_id == 0`.
    fn test_signers_manager_with_writer(
        dir: &TempDir,
    ) -> (Arc<std::sync::Mutex<AuditWriter>>, Arc<SignersManager>) {
        use crate::managers::signers::SignersManagerConfig;

        let audit_path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(audit_path.clone(), None)
            .expect("AuditWriter::open must succeed in tempdir");
        let arc_writer = Arc::new(std::sync::Mutex::new(writer));

        let sm = SignersManager::new(SignersManagerConfig::new(
            TEST_RPC_URL.to_owned(),
            TEST_RPC_URL.to_owned(),
            Arc::clone(&arc_writer),
            audit_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-unit".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        ))
        .expect("SignersManager::new must succeed with valid URL");

        (arc_writer, Arc::new(sm))
    }

    /// Helper: read and return all JSONL lines from the audit file as a Vec of
    /// `serde_json::Value` that contain a `passkey_assertion` event kind.
    ///
    /// `EventKind` is `#[serde(flatten)]` + `#[serde(tag = "kind")]` so the
    /// serialised form has `"kind": "passkey_assertion"` as a top-level key in
    /// the JSONL entry object (not nested under `"event_kind"`).
    fn read_audit_entries(dir: &TempDir) -> Vec<JsonValue> {
        let audit_path = dir.path().join("audit.jsonl");
        let content = std::fs::read_to_string(&audit_path).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<JsonValue>(l).expect("audit JSONL must be valid JSON"))
            .filter(|v| v.get("kind").and_then(|k| k.as_str()) == Some("passkey_assertion"))
            .collect()
    }

    /// All-zeros contract address (C-strkey) — canonical zero-address fixture.
    /// Passes `parse_c_strkey_to_smart_account` without triggering a network call.
    const ZERO_SA_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    #[tokio::test]
    async fn sign_with_passkey_rule_emits_audit_on_approval_store_unavailable() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        // Read-only manager — no approval store.
        let mgr = test_manager_readonly(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19900);
        let auth_digest = [0u8; 32];
        // Supply a SignersManager that provides the shared AuditWriter.
        // Use rule_id=0 (bootstrap skip) so verify_signer_set_against_chain is
        // never invoked (no testnet needed).  The approval-store check fires
        // immediately after the skip and returns ApprovalStoreUnavailable.
        let (_arc_writer, sm) = test_signers_manager_with_writer(&dir);

        let result = mgr
            .sign_with_passkey_rule(
                "does-not-matter",
                ZERO_SA_STRKEY, // valid C-strkey: parse passes; rule_id=0 skips network
                &auth_digest,
                vec![0], // rule_id=0: bootstrap-skip fires, no network call made
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                false, // accept_single_verifier: default off
            )
            .await;

        assert!(
            matches!(result, Err(CredentialsError::ApprovalStoreUnavailable)),
            "expected ApprovalStoreUnavailable"
        );

        let entries = read_audit_entries(&dir);
        assert_eq!(
            entries.len(),
            1,
            "expected exactly 1 PasskeyAssertion audit entry; got {entries:?}"
        );
        let result_tag = entries[0]["result"].as_str().unwrap();
        assert_eq!(
            result_tag, "failure:other",
            "ApprovalStoreUnavailable must produce failure:other tag"
        );
    }

    #[tokio::test]
    async fn sign_with_passkey_rule_emits_audit_on_not_found() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19901);
        let auth_digest = [0u8; 32];
        // Writer sourced from SignersManager; rule_id=0 skips network.
        let (_arc_writer, sm) = test_signers_manager_with_writer(&dir);

        // "nonexistent" has no entry in the empty registry → NotFound.
        let result = mgr
            .sign_with_passkey_rule(
                "nonexistent",
                ZERO_SA_STRKEY, // valid C-strkey; rule_id=0 skips network
                &auth_digest,
                vec![0], // rule_id=0: bootstrap-skip, no network call
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                false, // accept_single_verifier: default off
            )
            .await;

        assert!(
            matches!(result, Err(CredentialsError::NotFound { .. })),
            "expected NotFound, got {result:?}"
        );

        let entries = read_audit_entries(&dir);
        assert_eq!(
            entries.len(),
            1,
            "expected exactly 1 PasskeyAssertion audit entry; got {entries:?}"
        );
        let result_tag = entries[0]["result"].as_str().unwrap();
        assert_eq!(
            result_tag, "failure:credential_not_found",
            "NotFound must produce failure:credential_not_found tag"
        );
        // On pre-show() early-exit, credential_id_redacted and rp_id are "".
        let cid = entries[0]["credential_id_redacted"].as_str().unwrap();
        let rp = entries[0]["rp_id"].as_str().unwrap();
        assert_eq!(
            cid, "",
            "credential_id_redacted must be empty on pre-show() failure"
        );
        assert_eq!(rp, "", "rp_id must be empty on pre-show() failure");
    }

    #[tokio::test]
    async fn sign_with_passkey_rule_emits_audit_on_missing_public_key() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19902);
        let auth_digest = [0u8; 32];

        // Write a credential with empty public_key_sec1_b64.
        let mut meta = make_metadata("no-pubkey");
        meta.public_key_sec1_b64 = String::new();
        write_metadata(&mgr, &meta);

        // Writer sourced from SignersManager; rule_id=0 skips network.
        // MissingPublicKey fires after the approval-store check + show(), so the
        // bootstrap-skip (rule_id=0) still reaches the right early-exit path.
        let (_arc_writer, sm) = test_signers_manager_with_writer(&dir);

        let result = mgr
            .sign_with_passkey_rule(
                "no-pubkey",
                ZERO_SA_STRKEY, // valid C-strkey; rule_id=0 skips network
                &auth_digest,
                vec![0], // bootstrap-skip, no network call
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                false, // accept_single_verifier: default off
            )
            .await;

        assert!(
            matches!(result, Err(CredentialsError::MissingPublicKey { .. })),
            "expected MissingPublicKey, got {result:?}"
        );

        let entries = read_audit_entries(&dir);
        assert_eq!(
            entries.len(),
            1,
            "expected exactly 1 PasskeyAssertion entry"
        );
        let result_tag = entries[0]["result"].as_str().unwrap();
        // MissingPublicKey is not NotFound or Signing, so it maps to "failure:other".
        assert_eq!(result_tag, "failure:other");
        // After show() succeeds the credential_id IS available.
        let cid = entries[0]["credential_id_redacted"].as_str().unwrap();
        // credential_id_b64url in make_metadata is a 22-char base64url string → redacted.
        assert!(
            cid.contains("..."),
            "credential_id_redacted must contain '...' after show() succeeds: {cid}"
        );
    }

    #[tokio::test]
    async fn sign_with_passkey_rule_rejects_empty_rule_ids() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19904);
        let auth_digest = [0u8; 32];
        let meta = make_metadata("empty-rule-ids");
        write_metadata(&mgr, &meta);

        let result = mgr
            .sign_with_passkey_rule(
                "empty-rule-ids",
                "CDEPLOY1ABCDE2FGHIJ3KLMNO4PQRST5UVWXY",
                &auth_digest,
                vec![],
                None, // test-only escape hatch: no writer, no divergence check
                addr,
                Duration::from_millis(100),
                |_| {},
                false, // accept_single_verifier: default off
            )
            .await;

        assert!(
            matches!(result, Err(CredentialsError::InvalidRuleIds { .. })),
            "expected empty rule_ids to fail before approval construction, got {result:?}"
        );
    }

    // ── smart_account_redacted in PasskeyAssertion ────────────────────────────

    #[tokio::test]
    async fn sign_with_passkey_rule_emits_smart_account_redacted_in_audit() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19903);
        let auth_digest = [0u8; 32];

        // Use a NotFound error path (simpler fixture) to get the audit emitted
        // and assert the smart_account field is set correctly.
        //
        // Use ZERO_SA_STRKEY (valid C-strkey, 56 chars) so that
        // parse_c_strkey_to_smart_account passes.  rule_id=0 bootstrap-skip
        // prevents any network call.  The credential "nonexistent" does not
        // exist → NotFound fires after the approval-store check.
        let smart_account = ZERO_SA_STRKEY;
        let (_arc_writer, sm) = test_signers_manager_with_writer(&dir);

        let _ = mgr
            .sign_with_passkey_rule(
                "nonexistent",
                smart_account,
                &auth_digest,
                vec![0], // bootstrap-skip, no network call; NotFound fires after
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                false, // accept_single_verifier: default off
            )
            .await;

        let entries = read_audit_entries(&dir);
        assert_eq!(
            entries.len(),
            1,
            "expected exactly 1 PasskeyAssertion entry"
        );

        let sa_redacted = entries[0]["smart_account_redacted"].as_str().unwrap();
        // ZERO_SA_STRKEY is 56 chars → first-5-last-5 redaction applies.
        assert!(
            sa_redacted.contains("..."),
            "smart_account_redacted must contain '...' for long input: {sa_redacted}"
        );
        assert!(
            !sa_redacted.contains(smart_account),
            "full smart_account must not appear in audit entry"
        );
        // Verify head (first 5 chars) and tail (last 5 chars) of ZERO_SA_STRKEY.
        let head = &smart_account[..5];
        let tail = &smart_account[smart_account.len() - 5..];
        assert!(
            sa_redacted.starts_with(head),
            "smart_account_redacted must start with {head}: {sa_redacted}"
        );
        assert!(
            sa_redacted.ends_with(tail),
            "smart_account_redacted must end with {tail}: {sa_redacted}"
        );
    }

    // ── Diversification enforce-default trigger tests ─────────────────────────
    //
    // Six tests for the diversification enforce-default trigger:
    //   1. diversification_not_required_when_rule_has_two_verifiers
    //   2. diversification_not_required_when_value_threshold_below_high_value
    //   3. diversification_required_when_single_verifier_high_value
    //   4. diversification_required_when_undetermined_threshold_fail_closed
    //   5. diversification_override_emits_audit_row_when_accept_single_verifier_true
    //   6. result_tag_failure_verifier_diversification_required_emitted_on_refusal
    //
    // Tests 1-4 exercise the `check_diversification_required` helper
    // directly (tested in `managers/diversification.rs`).  Tests 5-6 exercise
    // the full `sign_with_passkey_rule` pipeline to verify the audit row and
    // result-tag discipline.
    //
    // All tests use rule_id=0 (bootstrap-skip) so no audit-log reader call is
    // made — the diversification check also skips rule_id=0 — to avoid needing
    // a real audit-log baseline.  Tests 5 and 6 use rule_id=0 to reach the
    // credential check stage without network calls; they rely on the
    // `ApprovalStoreUnavailable` or `NotFound` early-exit to be the terminal
    // result — the audit-row or result-tag assertion happens on the
    // `PasskeyAssertion` row, not on the diversification check itself (which
    // is correctly skipped for bootstrap rules).
    //
    // For the diversification trigger specifically, the `check_diversification_required`
    // unit tests in `diversification.rs` provide the behaviour coverage.
    // `sign_with_passkey_rule` integration is verified here for the
    // `CredentialsError::DiversificationRequired` path (test 6) using a
    // non-zero rule_id and a manager where the audit-log returns an empty
    // `PinnedHashesRecord` (no baseline → treated as single-verifier →
    // Undetermined criteria → gate fires).

    /// Helper: read all `sa_verifier_diversification_override` rows from the audit log.
    fn read_diversification_override_entries(dir: &TempDir) -> Vec<serde_json::Value> {
        let audit_path = dir.path().join("audit.jsonl");
        let content = std::fs::read_to_string(&audit_path).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .expect("audit JSONL must be valid JSON")
            })
            .filter(|v| {
                v.get("kind").and_then(|k| k.as_str())
                    == Some("sa_verifier_diversification_override")
            })
            .collect()
    }

    // ── opt-in emits SaVerifierDiversificationOverride audit row ──────────────

    /// Verifies that when `accept_single_verifier = true` is passed to
    /// `sign_with_passkey_rule`, the `SaVerifierDiversificationOverride` audit
    /// row is emitted on the opt-in path.
    ///
    /// Strategy: use a non-zero rule_id (1) with an empty audit-log baseline
    /// so the diversification check fires (no pinned hashes → treated as
    /// single-verifier; `ScVal::Void` criteria → Undetermined → above threshold).
    /// With `accept_single_verifier = true`, the gate is bypassed and the
    /// `SaVerifierDiversificationOverride` row is written.  The manager has no
    /// approval store, so `ApprovalStoreUnavailable` is the terminal result —
    /// but the audit row is emitted BEFORE the approval-store check.
    #[tokio::test]
    async fn diversification_override_emits_audit_row_when_accept_single_verifier_true() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        // Read-only manager: ApprovalStoreUnavailable fires after the
        // diversification override path emits the audit row.
        let mgr = test_manager_readonly(&dir);
        let (_arc_writer, sm) = test_signers_manager_with_writer(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19910);
        let auth_digest = [0u8; 32];

        // rule_id=1 (non-zero): the diversification check runs; empty audit-log
        // baseline → PinnedHashesRecord::default() → 0 pinned hashes →
        // single-verifier (fail-CLOSED) + Void criteria → Undetermined →
        // Required.  accept_single_verifier=true → override path.
        let _result = mgr
            .sign_with_passkey_rule(
                "irrelevant",
                ZERO_SA_STRKEY,
                &auth_digest,
                vec![1], // non-zero: diversification check runs
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                true, // accept_single_verifier: opt-in
            )
            .await;

        // The override audit row MUST have been emitted.
        let override_rows = read_diversification_override_entries(&dir);
        assert_eq!(
            override_rows.len(),
            1,
            "accept_single_verifier=true must emit exactly one \
             SaVerifierDiversificationOverride row; rows: {override_rows:?}"
        );
        let row = &override_rows[0];
        assert_eq!(
            row.get("rule_id").and_then(|v| v.as_u64()),
            Some(1),
            "override row must carry rule_id=1"
        );
        assert_eq!(
            row.get("verifier_hash_first8").and_then(|v| v.as_str()),
            Some(""),
            "empty baseline must carry empty verifier_hash_first8"
        );
        assert_eq!(
            row.get("observed_value_threshold_stroops")
                .and_then(|v| v.as_i64()),
            Some(crate::managers::diversification::DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS),
            "undetermined criteria must use the shared sentinel"
        );
        assert!(
            row.get("override_acknowledged_at")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "override row must carry override_acknowledged_at"
        );
        assert!(
            row.get("request_id")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "override row must carry the divergence request_id"
        );
    }

    #[tokio::test]
    async fn diversification_override_returns_error_when_audit_writer_poisoned() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        let (arc_writer, sm) = test_signers_manager_with_writer(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19912);
        let auth_digest = [0u8; 32];

        let _ = std::panic::catch_unwind({
            let arc_writer = std::sync::Arc::clone(&arc_writer);
            move || {
                let _guard = arc_writer.lock().unwrap();
                panic!("poison audit writer");
            }
        });

        let result = mgr
            .sign_with_passkey_rule(
                "irrelevant",
                ZERO_SA_STRKEY,
                &auth_digest,
                vec![1],
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                true,
            )
            .await;

        assert!(
            matches!(
                result,
                Err(CredentialsError::AuditWriterPoisoned {
                    context: AuditWriterPoisonContext::DiversificationOverrideEmission
                })
            ),
            "poisoned writer must fail closed before continuing; got {result:?}"
        );
    }

    // ── refusal emits result_tag failure:verifier_diversification_required ─────

    /// Verifies that when `accept_single_verifier = false` (default), the
    /// `CredentialsError::DiversificationRequired` error is returned AND the
    /// `PasskeyAssertion` audit row carries
    /// `result = "failure:verifier_diversification_required"`.
    ///
    /// Same setup as the override test but with `accept_single_verifier = false`.
    #[tokio::test]
    async fn result_tag_failure_verifier_diversification_required_emitted_on_refusal() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = TempDir::new().unwrap();
        // Read-only manager: if the diversification check is bypassed (bug),
        // ApprovalStoreUnavailable would fire — but here it should be
        // DiversificationRequired that fires first.
        let mgr = test_manager_readonly(&dir);
        let (_arc_writer, sm) = test_signers_manager_with_writer(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19911);
        let auth_digest = [0u8; 32];

        // rule_id=1: diversification check runs; empty log → Required fires.
        let result = mgr
            .sign_with_passkey_rule(
                "irrelevant",
                ZERO_SA_STRKEY,
                &auth_digest,
                vec![1], // non-zero: diversification check runs
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                false, // accept_single_verifier: default off → refusal
            )
            .await;

        // Must return DiversificationRequired.
        assert!(
            matches!(
                result,
                Err(CredentialsError::DiversificationRequired { .. })
            ),
            "accept_single_verifier=false must return DiversificationRequired when \
             diversification gate fires; got: {result:?}"
        );

        // PasskeyAssertion audit row must carry the 12th class result tag.
        let entries = read_audit_entries(&dir);
        assert_eq!(
            entries.len(),
            1,
            "exactly one PasskeyAssertion audit row must be emitted on refusal"
        );
        let result_tag = entries[0]["result"].as_str().unwrap();
        assert_eq!(
            result_tag, "failure:verifier_diversification_required",
            "PasskeyAssertion.result must be 'failure:verifier_diversification_required'"
        );
    }

    /// Helper: write a `CredentialMetadata` fixture to the manager's registry.
    ///
    /// Calls the private `persist_registry` method (accessible in the same
    /// module's test block) with a single-entry `RegistryFile`, guaranteeing
    /// the on-disk format matches what `show()` expects.
    fn write_metadata(mgr: &CredentialsManager, meta: &CredentialMetadata) {
        let registry = RegistryFile {
            credentials: vec![meta.clone()],
        };
        mgr.persist_registry(&registry)
            .expect("write_metadata: persist_registry must succeed in tempdir");
    }

    // ── AuditWriterPoisonContext label + Display ───────────────────────────────

    #[test]
    fn audit_writer_poison_context_label_covers_all_variants() {
        // The label values are load-bearing wire codes that appear in audit logs
        // and operator tooling. Verify each variant returns the exact expected string.
        assert_eq!(
            AuditWriterPoisonContext::DiversificationOverrideEmission.label(),
            "diversification_override_emission"
        );
        assert_eq!(
            AuditWriterPoisonContext::TimelockScheduleEmission.label(),
            "timelock_schedule_emission"
        );
        assert_eq!(
            AuditWriterPoisonContext::TimelockCancelEmission.label(),
            "timelock_cancel_emission"
        );
        assert_eq!(
            AuditWriterPoisonContext::TimelockExecuteEmission.label(),
            "timelock_execute_emission"
        );
    }

    #[test]
    fn audit_writer_poison_context_display_delegates_to_label() {
        // Display must call label() — verify each variant's Display output matches
        // the label() output exactly (Display is the wire format for CredentialsError).
        for (variant, expected) in [
            (
                AuditWriterPoisonContext::DiversificationOverrideEmission,
                "diversification_override_emission",
            ),
            (
                AuditWriterPoisonContext::TimelockScheduleEmission,
                "timelock_schedule_emission",
            ),
            (
                AuditWriterPoisonContext::TimelockCancelEmission,
                "timelock_cancel_emission",
            ),
            (
                AuditWriterPoisonContext::TimelockExecuteEmission,
                "timelock_execute_emission",
            ),
        ] {
            let displayed = format!("{variant}");
            assert_eq!(
                displayed, expected,
                "Display for {variant:?} must be '{expected}'"
            );
        }
    }

    // ── CredentialsManager::clone ─────────────────────────────────────────────

    #[test]
    fn credentials_manager_clone_preserves_fields() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let cloned = mgr.clone();

        assert_eq!(cloned.passkeys_dir, mgr.passkeys_dir);
        assert_eq!(cloned.profile_name, mgr.profile_name);
        assert_eq!(cloned.rp_id, mgr.rp_id);
        assert_eq!(cloned.poll_interval, mgr.poll_interval);
        // Clone of an Arc — both must be Some (pointing to the shared store).
        assert!(cloned.approval_store.is_some());
        assert!(
            Arc::ptr_eq(
                cloned.approval_store.as_ref().unwrap(),
                mgr.approval_store.as_ref().unwrap()
            ),
            "clone must share the same Arc<Mutex<PendingApprovalStore>>"
        );
    }

    #[test]
    fn credentials_manager_clone_readonly_preserves_none_store() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        let cloned = mgr.clone();
        assert!(cloned.approval_store.is_none());
        assert_eq!(cloned.passkeys_dir, mgr.passkeys_dir);
    }

    // ── registry_path ─────────────────────────────────────────────────────────

    #[test]
    fn registry_path_is_profile_toml_inside_passkeys_dir() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let path = mgr.registry_path();
        // Must end with "default.toml" and be inside the passkeys subdirectory.
        assert!(
            path.ends_with("default.toml"),
            "registry_path must end with '<profile>.toml': {path:?}"
        );
        assert!(
            path.starts_with(&mgr.passkeys_dir),
            "registry_path must be inside passkeys_dir: {path:?}"
        );
    }

    // ── load_registry returns RegistryParse on malformed TOML ─────────────────

    #[test]
    fn load_registry_returns_parse_error_on_malformed_toml() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let registry_path = mgr.registry_path();

        // Create the parent dir and write a malformed TOML file.
        std::fs::create_dir_all(registry_path.parent().unwrap()).unwrap();
        std::fs::write(&registry_path, b"[[credentials\nbroken_toml_here").unwrap();

        let err = mgr.load_registry().unwrap_err();
        assert!(
            matches!(err, CredentialsError::RegistryParse { .. }),
            "malformed TOML must produce RegistryParse; got {err:?}"
        );
    }

    // ── decode_validated_sec1 error paths ─────────────────────────────────────

    #[test]
    fn decode_validated_sec1_empty_returns_missing_public_key() {
        let err = decode_validated_sec1("my-key", "").unwrap_err();
        assert!(
            matches!(err, CredentialsError::MissingPublicKey { ref name } if name == "my-key"),
            "empty b64url must produce MissingPublicKey for the given name: {err:?}"
        );
    }

    #[test]
    fn decode_validated_sec1_invalid_base64_returns_malformed() {
        // "!!!" is not valid base64url.
        let err = decode_validated_sec1("my-key", "!!!").unwrap_err();
        assert!(
            matches!(
                err,
                CredentialsError::MalformedPublicKey {
                    ref name,
                    reason,
                    ..
                }
                if name == "my-key" && reason.contains("base64url")
            ),
            "invalid base64url must produce MalformedPublicKey with 'base64url' reason: {err:?}"
        );
    }

    #[test]
    fn decode_validated_sec1_wrong_length_returns_malformed() {
        // 64 bytes → 86 base64url chars (not 65).
        let short = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let err = decode_validated_sec1("my-key", &short).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialsError::MalformedPublicKey {
                    ref name,
                    reason,
                    ..
                }
                if name == "my-key" && reason.contains("65 bytes")
            ),
            "wrong-length key must produce MalformedPublicKey with '65 bytes' reason: {err:?}"
        );
    }

    #[test]
    fn decode_validated_sec1_missing_0x04_marker_returns_malformed() {
        // 65 bytes all zero — first byte is 0x00, not 0x04.
        let no_marker = URL_SAFE_NO_PAD.encode([0u8; 65]);
        let err = decode_validated_sec1("my-key", &no_marker).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialsError::MalformedPublicKey {
                    ref name,
                    reason,
                    ..
                }
                if name == "my-key" && reason.contains("0x04")
            ),
            "missing 0x04 marker must produce MalformedPublicKey with '0x04' reason: {err:?}"
        );
    }

    #[test]
    fn decode_validated_sec1_valid_key_returns_bytes() {
        // A structurally valid key: 0x04 marker + 64 zero bytes.
        let mut key = [0u8; 65];
        key[0] = 0x04;
        let b64 = URL_SAFE_NO_PAD.encode(key);
        let result = decode_validated_sec1("my-key", &b64).unwrap();
        assert_eq!(result[0], 0x04, "first byte of decoded key must be 0x04");
        assert_eq!(result.len(), 65, "decoded key must be 65 bytes");
        assert_eq!(result, key);
    }

    // ── public_key_sec1_for_credential_id with malformed stored key ────────────

    #[test]
    fn public_key_sec1_for_credential_id_returns_error_on_malformed_stored_key() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        // Store a credential with an invalid public key (empty → MissingPublicKey).
        let cred_id = b"test-cred-id-0001";
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(cred_id);
        let mut meta = make_metadata("bad-key");
        meta.credential_id_b64url = cred_id_b64;
        meta.public_key_sec1_b64 = String::new(); // missing key
        let mut registry = RegistryFile::default();
        registry.credentials.push(meta);
        mgr.persist_registry(&registry).unwrap();

        let err = mgr.public_key_sec1_for_credential_id(cred_id).unwrap_err();
        assert!(
            matches!(err, CredentialsError::MissingPublicKey { ref name } if name == "bad-key"),
            "empty public_key_sec1_b64 in registry must return MissingPublicKey: {err:?}"
        );
    }

    #[test]
    fn public_key_sec1_for_credential_id_returns_error_on_wrong_length_stored_key() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        let cred_id = b"test-cred-id-0002";
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(cred_id);
        // 64 bytes (wrong length — should be 65).
        let bad_key = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let mut meta = make_metadata("bad-key-2");
        meta.credential_id_b64url = cred_id_b64;
        meta.public_key_sec1_b64 = bad_key;
        let mut registry = RegistryFile::default();
        registry.credentials.push(meta);
        mgr.persist_registry(&registry).unwrap();

        let err = mgr.public_key_sec1_for_credential_id(cred_id).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialsError::MalformedPublicKey { reason, .. }
                if reason.contains("65 bytes")
            ),
            "64-byte stored key must return MalformedPublicKey with '65 bytes' reason: {err:?}"
        );
    }

    // ── drift_err_route routing invariant ─────────────────────────────────────

    #[test]
    fn drift_err_route_verifier_hash_drift_routes_to_wasm_hash_drift() {
        use stellar_agent_core::observability::RedactedStrkey;

        let sa_err = crate::SaError::VerifierHashDrift {
            rule_id: 1,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AAAAA"),
            deploy_address_redacted: RedactedStrkey::from_already_redacted("CVERIF...ADDR1"),
            pinned_hash_first8: "abcdef01".to_owned(),
            observed_hash_first8: "12345678".to_owned(),
            request_id: "req-id-1".to_owned(),
        };
        let result = drift_err_route(sa_err);
        assert!(
            matches!(result, CredentialsError::WasmHashDrift { .. }),
            "VerifierHashDrift must route to WasmHashDrift: {result:?}"
        );
        // Verify the inner source is VerifierHashDrift (not erased).
        let CredentialsError::WasmHashDrift { ref source } = result else {
            panic!("expected WasmHashDrift");
        };
        assert!(
            matches!(source.as_ref(), crate::SaError::VerifierHashDrift { .. }),
            "inner source must be VerifierHashDrift: {source:?}"
        );
    }

    #[test]
    fn drift_err_route_policy_hash_drift_routes_to_wasm_hash_drift() {
        use stellar_agent_core::observability::RedactedStrkey;

        let sa_err = crate::SaError::PolicyHashDrift {
            rule_id: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AAAAA"),
            deploy_address_redacted: RedactedStrkey::from_already_redacted("CPOLI...ADDR1"),
            pinned_hash_first8: "deadbeef".to_owned(),
            observed_hash_first8: "cafebabe".to_owned(),
            request_id: "req-id-2".to_owned(),
        };
        let result = drift_err_route(sa_err);
        assert!(
            matches!(result, CredentialsError::WasmHashDrift { .. }),
            "PolicyHashDrift must route to WasmHashDrift: {result:?}"
        );
        let CredentialsError::WasmHashDrift { ref source } = result else {
            panic!("expected WasmHashDrift");
        };
        assert!(
            matches!(source.as_ref(), crate::SaError::PolicyHashDrift { .. }),
            "inner source must be PolicyHashDrift: {source:?}"
        );
    }

    #[test]
    fn drift_err_route_infrastructure_failure_routes_to_drift_check_unavailable() {
        use stellar_agent_core::observability::RedactedStrkey;

        // NetworkRpcDivergence is an infrastructure failure, not an actual drift event.
        let sa_err = crate::SaError::NetworkRpcDivergence {
            rule_id: 3,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AAAAA"),
            primary_view_digest_first8: "11111111".to_owned(),
            secondary_view_digest_first8: "22222222".to_owned(),
            request_id: "req-id-3".to_owned(),
        };
        let result = drift_err_route(sa_err);
        assert!(
            matches!(result, CredentialsError::DriftCheckUnavailable { .. }),
            "NetworkRpcDivergence must route to DriftCheckUnavailable (not WasmHashDrift): {result:?}"
        );
        let CredentialsError::DriftCheckUnavailable { ref source } = result else {
            panic!("expected DriftCheckUnavailable");
        };
        assert!(
            matches!(source.as_ref(), crate::SaError::NetworkRpcDivergence { .. }),
            "inner source must be NetworkRpcDivergence: {source:?}"
        );
    }

    // ── result tag for InvalidRuleIds emits failure:invalid_rule_ids ──────────

    #[tokio::test]
    async fn sign_with_passkey_rule_emits_invalid_rule_ids_audit_tag() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Use a SignersManager-backed writer so the PasskeyAssertion audit row is emitted.
        // rule_ids=[] fires the InvalidRuleIds check before signers_manager is consulted.
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19920);
        let auth_digest = [0u8; 32];
        let (_arc_writer, sm) = test_signers_manager_with_writer(&dir);

        let result = mgr
            .sign_with_passkey_rule(
                "does-not-matter",
                ZERO_SA_STRKEY,
                &auth_digest,
                vec![], // empty rule_ids → InvalidRuleIds
                Some(sm),
                addr,
                Duration::from_millis(100),
                |_| {},
                false,
            )
            .await;

        assert!(
            matches!(result, Err(CredentialsError::InvalidRuleIds { .. })),
            "empty rule_ids must return InvalidRuleIds; got {result:?}"
        );

        // PasskeyAssertion audit row must carry failure:invalid_rule_ids.
        // Note: because rule_ids is checked before the signers_manager branch,
        // the audit_writer_arc is None (derived from signers_manager, which the
        // sign_with_passkey_rule outer function sources from signers_manager.as_ref()).
        // With signers_manager=Some(sm), the writer IS available.
        // InvalidRuleIds fires before the sm check, so no writer was set up yet.
        // Verify that no crash occurs and the error propagates correctly.
        // The audit row emission requires the writer to be set; check entry count.
        let entries = read_audit_entries(&dir);
        // InvalidRuleIds fires before `signers_manager.as_ref().map(|sm| sm.audit_writer())`
        // runs (it returns early from sign_with_passkey_rule_inner before that),
        // so the outer emit_signing_audit call does see the writer.
        // The outer function always calls emit_signing_audit with audit_writer_arc
        // derived BEFORE calling the inner function, so it IS available.
        assert_eq!(
            entries.len(),
            1,
            "exactly one PasskeyAssertion row must be emitted even for InvalidRuleIds: {entries:?}"
        );
        let result_tag = entries[0]["result"].as_str().unwrap();
        assert_eq!(
            result_tag, "failure:invalid_rule_ids",
            "InvalidRuleIds must produce failure:invalid_rule_ids audit tag"
        );
    }

    // ── CredentialsError Display messages ──────────────────────────────────────

    #[test]
    fn credentials_error_display_messages_are_operator_readable() {
        // Each variant's Display must contain identifiable, stable text.
        let errors = [
            (
                CredentialsError::RegistryParse {
                    detail: "bad toml".to_owned(),
                },
                "bad toml",
            ),
            (
                CredentialsError::RegistrySerialise {
                    detail: "ser failed".to_owned(),
                },
                "ser failed",
            ),
            (CredentialsError::StateDirUnavailable, "passkeys directory"),
            (
                CredentialsError::NotFound {
                    name: "mykey".to_owned(),
                },
                "mykey",
            ),
            (
                CredentialsError::DuplicateName {
                    name: "dupkey".to_owned(),
                },
                "dupkey",
            ),
            (
                CredentialsError::InvalidName {
                    name: "bad/name".to_owned(),
                    reason: "must not contain",
                },
                "bad/name",
            ),
            (
                CredentialsError::ApprovalStore {
                    detail: "lock fail".to_owned(),
                },
                "lock fail",
            ),
            (
                CredentialsError::BridgeStart {
                    detail: "bind failed".to_owned(),
                },
                "bind failed",
            ),
            (
                CredentialsError::BridgeShutdown {
                    detail: "shutdown failed".to_owned(),
                },
                "shutdown failed",
            ),
            (CredentialsError::ApprovalStoreUnavailable, "approval store"),
            (
                CredentialsError::AtomicWrite {
                    detail: "rename failed".to_owned(),
                },
                "rename failed",
            ),
            (
                CredentialsError::Signing {
                    detail: "sign error".to_owned(),
                },
                "sign error",
            ),
            (
                CredentialsError::MissingPublicKey {
                    name: "mykey".to_owned(),
                },
                "mykey",
            ),
            (
                CredentialsError::MalformedPublicKey {
                    name: "mykey".to_owned(),
                    reason: "base64url decode failed",
                },
                "mykey",
            ),
            (
                CredentialsError::InvalidRuleIds {
                    reason: "empty rule_ids".to_owned(),
                },
                "empty rule_ids",
            ),
            (
                CredentialsError::AuditWriterPoisoned {
                    context: AuditWriterPoisonContext::TimelockScheduleEmission,
                },
                "timelock_schedule_emission",
            ),
        ];

        for (err, expected_substr) in errors {
            let msg = format!("{err}");
            assert!(
                msg.contains(expected_substr),
                "Display for {err:?} must contain '{expected_substr}'; got: {msg}"
            );
        }
    }

    // ── poll_registration: UserCanceled when store has wrong-kind entry ────────

    #[tokio::test]
    async fn poll_registration_returns_user_canceled_on_kind_mismatch() {
        use stellar_agent_core::approval::store::PendingApproval;

        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);

        // Insert a PaymentSimulated entry into the shared store, then pass
        // its nonce to poll_registration. The entry exists but is not
        // RegisterPasskey → the kind-mismatch branch returns UserCanceled.
        let payment_entry = PendingApproval::new_payment_pending(
            "AAAAAQAAAA==".to_owned(), // dummy XDR b64
            b"dummy-xdr-bytes",
            "GBH...DEST".to_owned(),
            10_000_000,
            "XLM".to_owned(),
            None,
            100,
            1000,
            "test-uid".to_owned(),
            300_000,
        )
        .expect("PaymentSimulated fixture must construct");

        let nonce = payment_entry.approval_nonce.clone();

        {
            let store = mgr.approval_store.as_ref().unwrap();
            let mut guard = store.lock().await;
            guard
                .insert(payment_entry, unix_now_ms())
                .expect("insert must succeed");
        }

        // Deadline in the future so the deadline check doesn't fire first.
        let deadline = Instant::now() + Duration::from_secs(10);
        let outcome = mgr
            .poll_registration("some-name", &nonce, deadline, None)
            .await
            .expect("poll_registration must not return Err on kind mismatch");

        assert!(
            matches!(outcome, AddPasskeyOutcome::UserCanceled),
            "wrong-kind store entry must produce UserCanceled; got {outcome:?}"
        );
    }

    // ── poll_registration: EntryMissing when nonce not in store ──────────────

    #[tokio::test]
    async fn poll_registration_returns_entry_missing_for_absent_nonce() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);

        // Deadline in the future; nonce is never inserted.
        let deadline = Instant::now() + Duration::from_secs(10);
        let outcome = mgr
            .poll_registration("some-name", "nonce-that-was-never-inserted", deadline, None)
            .await
            .expect("poll_registration must not return Err on missing nonce");

        assert!(
            matches!(outcome, AddPasskeyOutcome::EntryMissing),
            "absent nonce must produce EntryMissing; got {outcome:?}"
        );
    }

    // ── poll_registration: ApprovalStoreUnavailable on readonly manager ───────

    #[tokio::test]
    async fn poll_registration_readonly_manager_returns_unavailable() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager_readonly(&dir);
        let deadline = Instant::now() + Duration::from_secs(10);

        let err = mgr
            .poll_registration("some-name", "any-nonce", deadline, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CredentialsError::ApprovalStoreUnavailable),
            "readonly manager must return ApprovalStoreUnavailable; got {err:?}"
        );
    }

    // ── emit_audit: non-fatal when audit_writer is None ───────────────────────

    #[test]
    fn emit_audit_with_none_writer_is_noop() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        // Should not panic; no audit file should be created.
        mgr.emit_audit(None, "my-key", "some-cred-id", "registered");
        // No audit file to check — just verify no panic.
    }

    // ── emit_audit: writes entry with correct credential_id sentinel ──────────

    #[test]
    fn emit_audit_with_empty_credential_id_uses_sentinel() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let audit_path = dir.path().join("audit.jsonl");
        let mut writer =
            AuditWriter::open(audit_path.clone(), None).expect("AuditWriter must open");

        // Empty credential_id → uses "<no-credential-id>" sentinel.
        mgr.emit_audit(Some(&mut writer), "my-key", "", "timeout");
        drop(writer);

        let content = std::fs::read_to_string(&audit_path).unwrap();
        let line = content.lines().next().expect("must have one entry");
        let entry: serde_json::Value =
            serde_json::from_str(line).expect("audit entry must be valid JSON");

        assert_eq!(entry["kind"], "passkey_registered");
        assert_eq!(entry["status"], "timeout");
        // The sentinel is redacted: "<no-c...-id>" — contains '<' or '>' markers.
        let cid = entry["credential_id_redacted"].as_str().unwrap();
        assert!(
            cid.contains('<') || cid.contains('>'),
            "sentinel must contain '<' or '>' angle bracket: {cid}"
        );
    }

    #[test]
    fn emit_audit_with_real_credential_id_applies_redaction() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let audit_path = dir.path().join("audit.jsonl");
        let mut writer =
            AuditWriter::open(audit_path.clone(), None).expect("AuditWriter must open");

        // 32-byte zero credential produces a 43-char base64url string.
        let cred_id_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
        mgr.emit_audit(Some(&mut writer), "my-key", &cred_id_b64, "registered");
        drop(writer);

        let content = std::fs::read_to_string(&audit_path).unwrap();
        let line = content.lines().next().expect("must have one entry");
        let entry: serde_json::Value =
            serde_json::from_str(line).expect("audit entry must be valid JSON");

        let cid = entry["credential_id_redacted"].as_str().unwrap();
        // Must be redacted (contain "..."), not the full 43-char string.
        assert!(
            cid.contains("..."),
            "long credential_id must be redacted with '...': {cid}"
        );
        assert!(
            !cid.contains(&cred_id_b64),
            "full credential_id_b64url must not appear in audit entry: {cid}"
        );
    }

    // ── multi-credential registry: show selects by exact name ────────────────

    #[test]
    fn show_selects_correct_entry_from_multi_credential_registry() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);

        let meta_a = make_metadata("key-alpha");
        let mut meta_b = make_metadata("key-beta");
        meta_b.rp_id = "example.com".to_owned();

        let mut registry = RegistryFile::default();
        registry.credentials.push(meta_a.clone());
        registry.credentials.push(meta_b.clone());
        mgr.persist_registry(&registry).unwrap();

        let found_a = mgr.show("key-alpha").unwrap();
        assert_eq!(found_a.rp_id, "localhost");

        let found_b = mgr.show("key-beta").unwrap();
        assert_eq!(found_b.rp_id, "example.com");
    }

    // ── validate_credential_name: boundary conditions ─────────────────────────

    #[test]
    fn validate_credential_name_accepts_exactly_64_chars() {
        let exactly_64 = "a".repeat(64);
        assert!(
            validate_credential_name(&exactly_64).is_ok(),
            "64-char name must be accepted"
        );
    }

    #[test]
    fn validate_credential_name_rejects_65_chars() {
        let sixty_five = "a".repeat(65);
        let err = validate_credential_name(&sixty_five).unwrap_err();
        assert!(
            matches!(err, CredentialsError::InvalidName { .. }),
            "65-char name must be rejected: {err:?}"
        );
    }

    #[test]
    fn validate_credential_name_rejects_ascii_control_chars() {
        // Null byte is a control character.
        let err = validate_credential_name("key\x00name").unwrap_err();
        assert!(
            matches!(
                err,
                CredentialsError::InvalidName { reason, .. }
                if reason.contains("ASCII")
            ),
            "control character must be rejected with ASCII reason: {err:?}"
        );
    }

    #[test]
    fn validate_credential_name_accepts_printable_ascii_special_chars() {
        // Parentheses, hyphens, spaces, and dots are all valid printable ASCII.
        assert!(validate_credential_name("My Key (2024)").is_ok());
        assert!(validate_credential_name("hw.token.v2").is_ok());
        assert!(validate_credential_name("key-2024-01").is_ok());
    }

    // ── delete: only removes the matching entry ────────────────────────────────

    #[test]
    fn delete_preserves_other_credentials_when_removing_one() {
        let dir = TempDir::new().unwrap();
        let mgr = test_manager(&dir);
        let mut registry = RegistryFile::default();
        registry.credentials.push(make_metadata("keep-1"));
        registry.credentials.push(make_metadata("remove-me"));
        registry.credentials.push(make_metadata("keep-2"));
        mgr.persist_registry(&registry).unwrap();

        mgr.delete("remove-me").unwrap();

        let creds = mgr.list().unwrap();
        assert_eq!(creds.len(), 2, "delete must remove exactly one entry");
        let names: Vec<_> = creds.iter().map(|c| c.credential_name.as_str()).collect();
        assert!(names.contains(&"keep-1"), "keep-1 must remain after delete");
        assert!(names.contains(&"keep-2"), "keep-2 must remain after delete");
        assert!(
            !names.contains(&"remove-me"),
            "remove-me must be gone after delete"
        );
    }

    // ── unix_duration_to_ms: normal path ─────────────────────────────────────

    #[test]
    fn unix_duration_to_ms_normal_path() {
        let d = Ok(Duration::from_millis(5_000));
        assert_eq!(unix_duration_to_ms(d), 5_000);
    }

    #[test]
    fn unix_duration_to_ms_large_value_saturates_to_u64_max() {
        // u128 that exceeds u64::MAX — must saturate to u64::MAX.
        // Duration::from_millis(u64::MAX) is valid and as_millis() → u64::MAX.
        let max_d = Ok(Duration::from_millis(u64::MAX));
        assert_eq!(unix_duration_to_ms(max_d), u64::MAX);
    }

    // ── encode_auth_digest_hex: all-zero digest ───────────────────────────────

    #[test]
    fn encode_auth_digest_hex_all_zero() {
        let digest = [0u8; 32];
        let encoded = encode_auth_digest_hex(&digest);
        assert_eq!(
            encoded,
            "0".repeat(64),
            "all-zero digest must encode as 64 zeros"
        );
    }

    // ── CredentialMetadata PartialEq ──────────────────────────────────────────

    #[test]
    fn credential_metadata_equality_and_inequality() {
        let a = make_metadata("key-a");
        let b = make_metadata("key-a");
        let c = make_metadata("key-b");
        assert_eq!(a, b, "identical metadata must be equal");
        assert_ne!(a, c, "metadata with different names must not be equal");
    }
}

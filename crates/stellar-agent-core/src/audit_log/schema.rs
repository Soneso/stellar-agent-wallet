//! Audit-log event schema — event kinds and field types.
//!
//! Enumerates every known event kind so [`super::verify`] can exhaustively
//! match them. All variants are defined up-front to prevent retroactive schema
//! changes in a hash-chained log: adding a variant with `#[non_exhaustive]` is
//! safe; changing or removing one is not.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::signer_set::{BaselineReason, SignerPubkey};
use crate::observability::RedactedStrkey;

// ── PolicyDecision ────────────────────────────────────────────────────────────

/// The outcome of a policy-engine evaluation, serialised into each audit entry.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::schema::PolicyDecision;
///
/// let d = PolicyDecision::Allow;
/// let s = serde_json::to_string(&d).unwrap();
/// assert_eq!(s, r#""allow""#);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyDecision {
    /// The policy engine allowed the operation.
    Allow,
    /// The policy engine denied the operation; includes the typed reason code.
    #[serde(rename = "deny")]
    Deny(String),
    /// The policy engine requires explicit user approval.
    RequireApproval,
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny(reason) => write!(f, "deny:{reason}"),
            Self::RequireApproval => write!(f, "require_approval"),
        }
    }
}

// ── ContractKind ─────────────────────────────────────────────────────────────

/// Which contract kind triggered an override or drift event.
///
/// Closed two-value set, mirrors the `contract_kind` field on
/// [`EventKind::SaMutableContractOverride`] and
/// [`EventKind::SaUnknownContractOverride`].
///
/// # Schema additivity
///
/// `#[non_exhaustive]` posture allows future kinds to be added without breaking
/// existing `match` arms in downstream consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContractKind {
    /// WebAuthn / signature verifier contract.
    Verifier,
    /// Threshold-policy contract.
    Policy,
}

impl fmt::Display for ContractKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verifier => f.write_str("verifier"),
            Self::Policy => f.write_str("policy"),
        }
    }
}

// ── VerifierAdvisoryKind ──────────────────────────────────────────────────────

/// Classification of the allowlist-advisory status for a verifier wasm hash.
///
/// Closed two-value set, carried by [`EventKind::SaVerifierAllowlistAdvisory`].
/// A typed enum rather than a `&'static str` discriminator so exhaustiveness is
/// compiler-enforced and serde round-trips are schema-stable.
///
/// # Schema additivity
///
/// `#[non_exhaustive]` allows future advisory classes to be added without
/// breaking existing `match` arms in downstream consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerifierAdvisoryKind {
    /// The verifier wasm hash has `VerifierAuditStatus::Revoked`.
    Revoked,
    /// The verifier wasm hash has `VerifierAuditStatus::Retired` (24-month
    /// rotation past `Revoked`; still an unconditional advisory trigger).
    Retired,
}

impl fmt::Display for VerifierAdvisoryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked => f.write_str("revoked"),
            Self::Retired => f.write_str("retired"),
        }
    }
}

// ── SaInvocationResult ────────────────────────────────────────────────────────

/// Outcome tag for [`EventKind::SaRawInvocation`].
///
/// `#[non_exhaustive]` ensures adding a new outcome variant is non-breaking for
/// downstream `match` arms.
///
/// # Variant taxonomy
///
/// | Variant | When emitted | Example `SaError` |
/// |---|---|---|
/// | `Success` | on-chain confirmed | — |
/// | `PreSubmissionRefused` | before tx signed/sent | `SimulationFailed`, `AuditWriterPoisoned` |
/// | `OnChainRejected` | on-chain `__check_auth` reject | `Unauthorized`, `InvalidOperationState` |
/// | `PostSubmitVerificationFailed` | tx confirmed; post-submit check failed | `EventConfirmationMissing` |
///
/// `PostSubmitVerificationFailed` distinguishes the case where the transaction
/// was submitted and confirmed on-chain, but a subsequent integrity check (e.g.
/// OZ contract event-emission confirmation) did not find the expected evidence
/// in the transaction meta. This is observationally distinct from both a
/// pre-submission refusal (no tx sent) and an on-chain rejection (`__check_auth`
/// returned an error): the op MAY have executed on-chain, but the wallet cannot
/// verify it.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::schema::SaInvocationResult;
///
/// let r = SaInvocationResult::Success;
/// let s = serde_json::to_string(&r).unwrap();
/// assert_eq!(s, r#""success""#);
///
/// let r = SaInvocationResult::PostSubmitVerificationFailed;
/// let s = serde_json::to_string(&r).unwrap();
/// assert_eq!(s, r#""post_submit_verification_failed""#);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SaInvocationResult {
    /// On-chain submission succeeded; auth-digest verified.
    Success,
    /// Pre-submission gate refused (matched `SaError` variant carried
    /// in the parent's `wire_code` field).
    PreSubmissionRefused,
    /// On-chain `__check_auth` rejected (`auth_digest_mismatch` class).
    OnChainRejected,
    /// Transaction submitted and confirmed on-chain, but a required post-submit
    /// integrity check failed (e.g. expected OZ contract event absent from tx
    /// meta).
    ///
    /// Wire form: `"post_submit_verification_failed"`.
    PostSubmitVerificationFailed,
}

// ── EventKind ────────────────────────────────────────────────────────────────

/// All known audit-log event kinds.
///
/// The `audit verify` command matches exhaustively against this enum. All
/// variants are defined in a single location to prevent retroactive schema
/// changes in the hash-chained log.
///
/// # Stability
///
/// `#[non_exhaustive]` because future releases may add more event kinds.
/// Callers that match on this enum in `audit verify` must include a wildcard
/// arm to handle unknown future kinds gracefully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// Standard per-tool audit entry (the common case).
    ///
    /// Produced by every signing tool invocation — simulate, commit, approve.
    ToolInvocation,

    /// A fail-closed executable policy plugin was invoked.
    ///
    /// `audit verify` recognises this kind regardless of whether the local
    /// binary shipped with plugin support active.
    PluginInvoked {
        /// Name of the plugin subprocess that was invoked.
        plugin_name: String,
        /// Exit code returned by the plugin process.
        exit_code: i32,
        /// The plugin's policy decision.
        decision: PolicyDecision,
        /// Wall-clock duration of the plugin invocation in milliseconds.
        duration_ms: u64,
    },

    /// Memory-lock failure during the short-in-memory-unlock window.
    ///
    /// Emitted when `mlock` fails and `wallet.mlock_required = "warn"` is
    /// set.  The hash-chained log records every degradation event so the
    /// forensic record is complete.
    WalletMlockFailed {
        /// Profile name that experienced the failure.
        profile: String,
        /// Human-readable reason for the failure.
        reason: String,
        /// `errno` value from the failed `mlock` syscall, if available.
        errno: Option<i32>,
    },

    /// Smart-account raw invocation boundary event.
    ///
    /// Emitted at the on-chain auth boundary. The full field set is defined
    /// up-front because the hash-chained log forbids silent field additions to
    /// an existing variant; only NEW variants can land additively due to
    /// `#[non_exhaustive]`.
    ///
    SaRawInvocation {
        /// Smart-account C-strkey, redacted first-5-last-5
        /// (`stellar_agent_core::observability::redact_strkey_first5_last5`).
        smart_account: String,
        /// `SaError::wire_code()` of the operation outcome (`"sa.ok"` for
        /// success). Stored as `String` (not `&'static str`) because the parent
        /// enum derives `Deserialize` and serde-roundtripping a borrowed string
        /// would require lifetime parameters that propagate through every
        /// consumer's match arm.
        wire_code: String,
        /// First-8 hex chars of the auth-digest the wallet computed for this
        /// invocation. Truncation rationale: the audit log is not a cryptographic
        /// integrity store for the digest itself (the on-chain ledger is); the
        /// prefix is sufficient for forensic correlation across log entries
        /// without leaking the full preimage commitment.
        ///
        /// `None` for operations that do not compute a smart-account auth-digest
        /// (e.g. deployment ops where the deployer's source-account signature is
        /// the auth; no `compute_auth_digest` invocation is in scope). Auth-
        /// bearing invocations set `Some("16-char-hex-prefix")`.
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_digest_prefix: Option<String>,
        /// Length of the `context_rule_ids` vector at signing time. A divergence
        /// between this count and the on-chain rule-set count indicates a
        /// `simulation.divergence.context_rule_ids` failure.
        context_rule_ids_count: u32,
        /// Operation outcome (success vs. typed-error class). Allows
        /// `audit verify` to filter for failures across the SA boundary
        /// without parsing wire-code strings.
        result: SaInvocationResult,
    },

    /// Smart-account deployment event.
    ///
    /// Emitted by `deployment::deploy_smart_account` on every successful
    /// deployment. Includes both the deployer (G-strkey) and the deployed
    /// smart-account (C-strkey); both redacted per the audit-log redaction policy.
    ///
    /// # Schema additivity
    ///
    /// The `#[non_exhaustive]` posture on `EventKind` guarantees no existing
    /// match arm breaks when a new variant is added.
    SmartAccountDeployed {
        /// Smart-account C-strkey, redacted first-5-last-5.
        smart_account: String,
        /// Deployer G-strkey, redacted first-5-last-5.
        deployer: String,
        /// Redacted form of the deployed WASM SHA-256: first-8-last-8 hex chars
        /// in the `"abcd1234...wxyz5678"` shape (19 chars total).
        ///
        /// Field name `wasm_hash_prefix` encodes first-8-last-8 hex, matching
        /// the `tx_hash_redacted` discipline.
        wasm_hash_prefix: String,
        /// Whether the WASM was uploaded by THIS transaction (`true`) or was
        /// already on-chain at pre-flight time.
        wasm_uploaded: bool,
        /// Transaction hash, redacted first-8-last-8.
        tx_hash_redacted: String,
        /// Network ledger sequence at confirmation.
        ledger: u32,
    },

    /// Smart-account context-rule installation event.
    ///
    /// Emitted by `ContextRuleManager::install_rule` after a successful on-chain
    /// `add_context_rule` invocation.
    ///
    /// # Schema additivity
    ///
    /// The `#[non_exhaustive]` posture on `EventKind` guarantees additive
    /// landing — existing match-with-wildcard arms in `audit verify` continue
    /// to compile.
    ///
    /// # Field redaction
    ///
    /// `smart_account` is the C-strkey form, redacted first-5-last-5.
    /// `rule_id`, `signers_count`, `policies_count`, and `valid_until` are
    /// non-sensitive: rule IDs are public on-chain identifiers, and
    /// signer/policy counts are signer-set composition metadata held only in
    /// the wallet operator's local audit log.
    ///
    SaContextRuleCreated {
        /// Smart-account C-strkey, redacted first-5-last-5.
        smart_account: String,
        /// Public on-chain rule identifier (non-sensitive — visible to any
        /// RPC observer; redaction would be performative).
        rule_id: u32,
        /// Stable label of the rule's `ContextRuleType` variant. Closed set:
        /// `"default"`, `"call_contract"`, `"create_contract"`. The variant
        /// payload (Address / WASM hash) is not carried by this row to keep
        /// the audit-log surface free of strkeys/hashes that the row's
        /// `smart_account` field already establishes.
        context_type: String,
        /// Number of signer entries the rule was installed with. Operator-
        /// facing forensic correlation field; non-sensitive per the audit-log
        /// access trust model.
        signers_count: u32,
        /// Number of policy entries the rule was installed with.
        policies_count: u32,
        /// Optional ledger sequence at which the rule expires. `None` means
        /// the rule is permanent (no `valid_until` set).
        #[serde(skip_serializing_if = "Option::is_none")]
        valid_until: Option<u32>,
        /// First-8-hex projections of wasm hashes pinned at install time for
        /// each referenced verifier contract.
        ///
        /// Empty if the rule has no `External` signers. `#[serde(default)]`
        /// provides backward-compatibility with older log entries that predate
        /// this field (appropriate for extensions to an existing variant; new
        /// variants require all fields to be present).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pinned_verifier_wasm_hashes_first8: Vec<String>,
        /// First-8-hex projections of wasm hashes pinned at install time for
        /// each referenced policy contract.
        ///
        /// Empty if the rule has no policies. Same `#[serde(default)]`
        /// rationale as `pinned_verifier_wasm_hashes_first8`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pinned_policy_wasm_hashes_first8: Vec<String>,
        /// `true` if `--accept-mutable-verifier` was set at install.
        ///
        /// `#[serde(default)]` for backward-compat: older entries without this
        /// field read as `false` (no override was present).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        mutable_override: bool,
        /// `true` if `--accept-unknown-verifier` was set at install.
        ///
        /// `#[serde(default)]` for backward-compat: older entries without this
        /// field read as `false`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        unknown_override: bool,
    },

    /// Smart-account context-rule deletion event.
    ///
    /// Emitted by `ContextRuleManager::delete_rule` after a successful on-chain
    /// `delete_context_rule` invocation.
    ///
    SaContextRuleDeleted {
        /// Smart-account C-strkey, redacted first-5-last-5.
        smart_account: String,
        /// Public on-chain rule identifier (non-sensitive).
        rule_id: u32,
    },

    /// Smart-account context-rule name-update event.
    ///
    /// Emitted by `ContextRuleManager::update_name` on each successful
    /// `update_context_rule_name` invocation, in addition to the
    /// `SaRawInvocation(sa.ok)` row that records the on-chain result.
    ///
    /// # Redaction
    ///
    /// `smart_account` is the C-strkey form redacted first-5-last-5.
    /// `new_name_redacted` carries the first 3 chars of the name followed by
    /// `len=N` (e.g. `"foo len=8"`) to prevent free-text rule names from
    /// leaking user-identifying content into the audit log.
    ///
    /// # Schema additivity
    ///
    /// The `#[non_exhaustive]` posture on `EventKind` guarantees additive
    /// landing — existing match-with-wildcard arms in `audit verify` continue
    /// to compile.
    ///
    #[non_exhaustive]
    SaContextRuleNameUpdated {
        /// Smart-account C-strkey, redacted first-5-last-5.
        smart_account: String,
        /// Public on-chain rule identifier (non-sensitive).
        rule_id: u32,
        /// New rule name, redacted to first-3-chars + `" len=N"`.
        ///
        /// The previous name is intentionally NOT recorded: the update flow
        /// never fetches it, and a fabricated "old" value would corrupt the
        /// forensic record.  The prior name is recoverable from the preceding
        /// rule-install row or from chain history.
        new_name_redacted: String,
        /// Request-id for forensic correlation with the `SaRawInvocation` row.
        ///
        /// Named `audit_request_id` to avoid the serde-flatten collision with
        /// the outer `AuditEntry::request_id` field.
        audit_request_id: String,
    },

    /// Smart-account context-rule valid-until update event.
    ///
    /// Emitted by `ContextRuleManager::update_valid_until` on each successful
    /// `update_context_rule_valid_until` invocation, in addition to the
    /// `SaRawInvocation(sa.ok)` row.
    ///
    /// # Redaction
    ///
    /// `smart_account` is redacted first-5-last-5. `new_valid_until` is a
    /// ledger sequence (non-sensitive public value).
    ///
    /// # Schema additivity
    ///
    /// The `#[non_exhaustive]` posture on `EventKind` guarantees additive
    /// landing.
    ///
    #[non_exhaustive]
    SaContextRuleValidUntilUpdated {
        /// Smart-account C-strkey, redacted first-5-last-5.
        smart_account: String,
        /// Public on-chain rule identifier (non-sensitive).
        rule_id: u32,
        /// New expiry ledger, `None` when expiry was cleared (permanent rule).
        ///
        /// The previous expiry is intentionally NOT recorded: the update flow
        /// never fetches it, and `None` would be indistinguishable from
        /// "was permanent".  The prior value is recoverable from the preceding
        /// rule-install or valid-until row or from chain history.
        new_valid_until: Option<u32>,
        /// Request-id for forensic correlation with the `SaRawInvocation` row.
        ///
        /// Named `audit_request_id` to avoid the serde-flatten collision with
        /// the outer `AuditEntry::request_id` field.
        audit_request_id: String,
    },

    /// Passkey registration event.
    ///
    /// Emitted by `CredentialsManager::add_passkey` when a WebAuthn registration
    /// ceremony completes (status `registered`) or is attempted but fails
    /// (status `timeout`, `user_canceled`, `entry_missing`).
    ///
    /// # Redaction
    ///
    /// `credential_id_redacted` carries only the first-5-last-5 base64url
    /// characters (`<head>...<tail>` with literal `...`).  The full `credential_id`
    /// and all public-key bytes are never written to the audit log.
    ///
    /// `rp_id` is not secret and is logged unredacted to support incident
    /// correlation across log entries.
    ///
    /// # Schema additivity
    ///
    /// The `#[non_exhaustive]` posture on `EventKind` guarantees additive
    /// landing — existing match-with-wildcard arms in `audit verify` continue
    /// to compile.
    ///
    PasskeyRegistered {
        /// Credential name chosen by the operator (verbatim, non-sensitive).
        credential_name: String,

        /// Credential-ID, redacted to first-5-last-5 base64url characters.
        ///
        /// Format: `"<head>...<tail>"` where `<head>` is the first 5 base64url
        /// chars and `<tail>` is the last 5. The literal `...` separates them.
        /// Analogous to strkey first-5-last-5 redaction.
        credential_id_redacted: String,

        /// RP-ID used for this registration (e.g. `"127.0.0.1"` or a custom
        /// domain when self-hosted). Non-sensitive: the RP-ID is a public
        /// hostname/domain by construction.
        rp_id: String,

        /// Registration outcome. One of `"registered"`, `"timeout"`,
        /// `"user_canceled"`, or `"entry_missing"`.
        ///
        /// - `"registered"` — ceremony completed; credential stored in registry.
        /// - `"timeout"` — polling deadline elapsed before completion.
        /// - `"user_canceled"` — store entry has unexpected kind (bridge-side abort).
        /// - `"entry_missing"` — nonce not found in store (TTL-expired or never
        ///   persisted); distinct from a user-driven cancellation.
        status: String,
    },

    /// A WebAuthn passkey signing ceremony was completed (or failed).
    ///
    /// Emitted by `CredentialsManager::sign_with_passkey_rule` after the
    /// bridge POST handler delivers `AssertionInput` and
    /// `PasskeySignHandle::sign_webauthn_assertion` returns (or on any
    /// earlier failure — see `result` field).
    ///
    /// # Redaction
    ///
    /// `credential_id_redacted` carries only the first-5-last-5 base64url
    /// characters.  `auth_digest_redacted` carries only the first-5-last-5 hex
    /// characters of the 32-byte auth digest.  `smart_account_redacted` carries
    /// only the first-5-last-5 characters of the target smart account C-strkey.
    /// Neither the full credential ID, any signature bytes, nor the full
    /// smart account strkey appear in the log.
    ///
    /// `rp_id` is non-sensitive (a public hostname/domain) and is logged
    /// unredacted to support incident correlation across entries.
    ///
    /// # Schema additivity
    ///
    /// The `#[non_exhaustive]` posture on `EventKind` guarantees additive
    /// landing — existing match-with-wildcard arms in `audit verify` continue
    /// to compile.  Older entries without `smart_account_redacted` deserialise
    /// to the default (empty string) via `#[serde(default)]`.
    ///
    PasskeyAssertion {
        /// Credential name from the passkeys registry (verbatim, non-sensitive).
        credential_name: String,

        /// Credential-ID, redacted to first-5-last-5 base64url characters.
        ///
        /// Format: `"<head>...<tail>"`.
        credential_id_redacted: String,

        /// RP-ID used for this assertion (e.g. `"localhost"` for local
        /// topology, or a custom domain when self-hosted).  Empty string `""`
        /// on early-exit paths where the credential metadata was never resolved.
        rp_id: String,

        /// Target smart account C-strkey, redacted to first-5-last-5.
        ///
        /// Distinguishes signing ceremonies targeting different smart accounts in
        /// the audit trail.  The full strkey is never stored.
        ///
        /// Empty string `""` on early-exit paths that occur before the caller
        /// supplies the smart account argument (should not occur in practice since
        /// `smart_account` is a required function parameter, but the `""` sentinel
        /// is safe on pre-`show()` failures).
        ///
        /// `#[serde(default)]` enables older entries without this field to
        /// deserialise without error.
        #[serde(default)]
        smart_account_redacted: RedactedStrkey,

        /// Auth digest (SHA-256 Soroban auth payload), redacted to
        /// first-5-last-5 of its hex representation.
        ///
        /// Provides correlation across entries for a single auth cycle without
        /// exposing the full digest in unstructured log output.
        auth_digest_redacted: String,

        /// Unix timestamp (ms) of the signing ceremony completion.
        signed_at_unix_ms: u64,

        /// Invocation result: `"success"` or `"failure:<reason_class>"` (never
        /// exposes raw error or signature bytes).
        ///
        /// Reason classes:
        /// - `"success"` — assertion accepted; auth-entry signed.
        /// - `"failure:timeout"` — polling deadline elapsed.
        /// - `"failure:user_canceled"` — ceremony aborted on bridge side.
        /// - `"failure:entry_missing"` — nonce not found in store.
        /// - `"failure:credential_not_found"` — credential name not in registry
        ///   (`CredentialsError::NotFound`); emitted on the early-exit path when
        ///   `show()` fails before the approval entry is created.
        /// - `"failure:signer_error"` — `PasskeySignHandle::sign_webauthn_assertion`
        ///   returned an error (`CredentialsError::Signing`).
        /// - `"failure:signer_set_diverged"` — the per-signing divergence check
        ///   fired before the WebAuthn ceremony was opened; the on-chain signer-set
        ///   did not match the audit-log baseline, the primary and secondary RPC
        ///   disagreed, the baseline was missing, or the audit-log integrity check
        ///   failed (`CredentialsError::SignerSetDivergence`).  The browser window
        ///   is never opened on this path.
        /// - `"failure:verifier_hash_drift"` — the pre-signing verifier wasm-hash
        ///   drift check detected that the live on-chain wasm hash differs from the
        ///   verifier hash pinned at rule-install time
        ///   (`CredentialsError::WasmHashDrift` wrapping `SaError::VerifierHashDrift`).
        ///   The browser window is never opened on this path.  Both
        ///   `SaVerifierHashDrift` AND this `PasskeyAssertion` audit row are emitted
        ///   with the same `request_id` for forensic correlation.
        /// - `"failure:policy_hash_drift"` — the pre-signing policy wasm-hash
        ///   drift check detected that the live on-chain wasm hash differs from the
        ///   policy hash pinned at rule-install time
        ///   (`CredentialsError::WasmHashDrift` wrapping `SaError::PolicyHashDrift`).
        ///   Both `SaPolicyHashDrift` AND this `PasskeyAssertion` audit row share
        ///   the same `request_id`.
        /// - `"failure:drift_check_unavailable"` — the drift-check infrastructure
        ///   could not run (RPC error, rule not found on-chain, etc.)
        ///   (`CredentialsError::DriftCheckUnavailable`).
        ///   Signing is refused fail-closed.  No `SaVerifierHashDrift` /
        ///   `SaPolicyHashDrift` row is emitted (no hash mismatch was detected).
        /// - `"failure:verifier_diversification_required"` — the diversification
        ///   enforce-default trigger fired because the rule references a single
        ///   verifier wasm hash on a high-value account AND the operator did not
        ///   pass `--accept-single-verifier`.
        /// - `"failure:invalid_rule_ids"` — caller supplied an empty or otherwise
        ///   invalid context-rule ID set (`CredentialsError::InvalidRuleIds`).
        /// - `"failure:audit_writer_poisoned"` — the shared audit-writer mutex
        ///   was poisoned while emitting a load-bearing audit row; the operation
        ///   fails closed (`CredentialsError::AuditWriterPoisoned`).
        /// - `"failure:other"` — catch-all for any other `CredentialsError`
        ///   variant (e.g. `ApprovalStoreUnavailable`, base64url decode failure,
        ///   `MissingPublicKey`, `MalformedPublicKey`, `process_uid` failure,
        ///   `new_passkey_pending` validator failure, or store-insert failure).
        ///
        /// All reason classes are emitted unconditionally by
        /// `CredentialsManager::sign_with_passkey_rule` on **every** terminal
        /// path — including early-exit errors that occur before `poll_signing` is
        /// called.  Early-exit entries carry `credential_id_redacted = ""` and
        /// `rp_id = ""` because those fields are unavailable when `show()` has
        /// not yet succeeded.
        result: String,
    },

    /// A signer was added to a context rule.
    ///
    /// Emitted by `SignersManager::add_signer` after a successful on-chain
    /// `add_signer` invocation. Carries the full post-operation signer set in
    /// `resulting_signer_pubkeys` for audit-log baseline reconstruction.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` carries first-5-last-5 of the C-strkey.
    /// `resulting_signer_pubkeys_first8` carries info-level redacted pubkey
    /// summaries; `resulting_signer_pubkeys` carries the full set for
    /// reconstruction (written only to the local audit log, never to a network
    /// endpoint).
    ///
    /// # Schema additivity
    ///
    /// The `#[non_exhaustive]` posture on `EventKind` guarantees additive
    /// landing — existing wildcard-match arms in `audit verify` continue to
    /// compile.
    ///
    SaSignerAdded {
        /// Context rule ID this signer was added to (non-sensitive on-chain ID).
        rule_id: u32,
        /// On-chain signer ID assigned by the smart-account contract.
        signer_id: u32,
        /// Signer count in the rule after the operation.
        resulting_signer_count: u32,
        /// Threshold of the rule after the operation.
        resulting_threshold: u32,
        /// Signer IDs in the rule after the operation (parallel to pubkeys).
        resulting_signer_ids: Vec<u32>,
        /// Full public-key envelopes for baseline reconstruction.
        ///
        /// The post-state vector carries the new entry at the index corresponding
        /// to the assigned `signer_id`.
        resulting_signer_pubkeys: Vec<SignerPubkey>,
        /// Info-level redacted first-8-hex summaries of resulting pubkeys.
        resulting_signer_pubkeys_first8: Vec<String>,
        /// Smart-account C-strkey, redacted first-5-last-5.
        ///
        /// Per-invocation request correlation ID is carried by the top-level
        /// `AuditEntry::request_id` field (common to all event kinds).
        smart_account_redacted: RedactedStrkey,
    },

    /// A signer was removed from a context rule.
    ///
    /// Emitted by `SignersManager::remove_signer` after a successful on-chain
    /// `remove_signer` invocation. Carries the full post-operation signer set.
    ///
    /// # Redaction
    ///
    /// See `SaSignerAdded` redaction notes — same discipline applies.
    ///
    SaSignerRemoved {
        /// Context rule ID the signer was removed from.
        rule_id: u32,
        /// On-chain signer ID that was removed.
        signer_id: u32,
        /// Signer count after the removal.
        resulting_signer_count: u32,
        /// Threshold after the removal.
        resulting_threshold: u32,
        /// Signer IDs after the removal.
        resulting_signer_ids: Vec<u32>,
        /// Full public-key envelopes for baseline reconstruction.
        resulting_signer_pubkeys: Vec<SignerPubkey>,
        /// Info-level redacted first-8-hex summaries.
        resulting_signer_pubkeys_first8: Vec<String>,
        /// Smart-account C-strkey, redacted first-5-last-5.
        ///
        /// Per-invocation request correlation ID is carried by the top-level
        /// `AuditEntry::request_id` field (common to all event kinds).
        smart_account_redacted: RedactedStrkey,
    },

    /// The threshold of a context rule was changed.
    ///
    /// Emitted by `SignersManager::set_threshold` after a successful on-chain
    /// `set_threshold` invocation. Carries both old and new threshold values for
    /// forensic correlation.
    ///
    /// # Redaction
    ///
    /// See `SaSignerAdded` redaction notes — same discipline applies.
    ///
    SaThresholdChanged {
        /// Context rule ID whose threshold was changed.
        rule_id: u32,
        /// Threshold before the change.
        old_threshold: u32,
        /// Threshold requested by the caller.
        new_threshold: u32,
        /// Resulting threshold (equals `new_threshold`; symmetric naming for
        /// consistency with `SaSignerAdded.resulting_threshold`).
        resulting_threshold: u32,
        /// Resulting signer count (unchanged by this operation).
        resulting_signer_count: u32,
        /// Resulting signer IDs (unchanged by this operation).
        resulting_signer_ids: Vec<u32>,
        /// Full public-key envelopes for baseline reconstruction.
        resulting_signer_pubkeys: Vec<SignerPubkey>,
        /// Info-level redacted first-8-hex summaries.
        resulting_signer_pubkeys_first8: Vec<String>,
        /// Smart-account C-strkey, redacted first-5-last-5.
        ///
        /// Per-invocation request correlation ID is carried by the top-level
        /// `AuditEntry::request_id` field (common to all event kinds).
        smart_account_redacted: RedactedStrkey,
    },

    /// A signer-set divergence was detected.
    ///
    /// Emitted by `SignersManager::verify_signer_set_against_chain` when the
    /// on-chain signer set does not match the audit-log baseline.
    ///
    /// # Digest fields
    ///
    /// `expected_signer_set_digest` and `observed_signer_set_digest` carry
    /// first-8-last-8 hex representations of the domain-tagged SHA-256 of the
    /// respective signer sets (computed by
    /// `signer_set::compute_signer_set_digest`). The 19-char format matches the
    /// `wasm_hash_prefix` / `tx_hash_redacted` discipline.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` first-5-last-5. Signer counts and thresholds are
    /// non-sensitive (public on-chain state). The full signer sets are NOT
    /// logged in this variant (use the baseline row for reconstruction).
    ///
    SaSignerSetDiverged {
        /// Context rule ID where divergence was detected.
        rule_id: u32,
        /// Smart-account C-strkey, redacted first-5-last-5.
        ///
        /// Per-invocation request correlation ID is carried by the top-level
        /// `AuditEntry::request_id` field (common to all event kinds).
        smart_account_redacted: RedactedStrkey,
        /// Signer count from the audit-log baseline.
        expected_signer_count: u32,
        /// Signer count observed on-chain.
        observed_signer_count: u32,
        /// Threshold from the audit-log baseline.
        expected_threshold: u32,
        /// Threshold observed on-chain.
        observed_threshold: u32,
        /// First-8-last-8 hex of the domain-tagged SHA-256 of the expected
        /// signer set (`(signer_ids, signer_pubkeys, threshold)`).
        expected_signer_set_digest: String,
        /// First-8-last-8 hex of the domain-tagged SHA-256 of the observed
        /// signer set.
        observed_signer_set_digest: String,
    },

    /// The signer-set baseline was recorded for a context rule.
    ///
    /// Emitted ONLY by `SignersManager::refresh_signer_baseline` (always) and
    /// `SignersManager::list_signers` (first-observation only). A repo-gate
    /// enforces this single-caller invariant.
    ///
    /// # TOCTOU anchor (`prev_chain_tip_hash`)
    ///
    /// `prev_chain_tip_hash` MUST be sourced from
    /// `AuditWriter::current_chain_tip()` inside the same write critical section,
    /// never re-read from disk after lock release, to prevent replay attacks.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` first-5-last-5. Full signer pubkeys are stored
    /// for reconstruction (`observed_signer_pubkeys`); info-level display uses
    /// `observed_signer_pubkeys_first8`.
    ///
    SaSignerSetBaselined {
        /// Context rule ID being baselined.
        rule_id: u32,
        /// Signer count at observation time.
        observed_signer_count: u32,
        /// Threshold at observation time.
        observed_threshold: u32,
        /// Signer IDs at observation time (parallel to pubkeys).
        observed_signer_ids: Vec<u32>,
        /// Full public-key envelopes for reconstruction.
        ///
        /// Stored locally in the audit log for baseline reconstruction by
        /// `AuditReader::find_latest_signer_set_state`.
        observed_signer_pubkeys: Vec<SignerPubkey>,
        /// Info-level redacted first-8-hex summaries.
        observed_signer_pubkeys_first8: Vec<String>,
        /// Ledger sequence number at which the on-chain state was read.
        ///
        /// Binds the baseline to a specific ledger slot for forensic correlation.
        observed_at_ledger_seq: u32,
        /// Unix timestamp (milliseconds) when the observation was made.
        observed_at_unix_ms: u64,
        /// Reason this baseline was recorded.
        baseline_reason: BaselineReason,
        /// SHA-256 of the most-recently-written audit entry at time of emission.
        ///
        /// Sourced from `AuditWriter::current_chain_tip()` inside the write
        /// critical section. Binds the baseline to a specific chain-tip so a
        /// replay attack cannot re-order a stale baseline ahead of newer
        /// signer-set mutations.
        prev_chain_tip_hash: [u8; 32],
        /// Smart-account C-strkey, redacted first-5-last-5.
        ///
        /// Per-invocation request correlation ID is carried by the top-level
        /// `AuditEntry::request_id` field (common to all event kinds).
        ///
        /// No `#[serde(default)]` here: this variant has no legacy entries that
        /// predate it. Allowing default deserialisation would let malformed wire
        /// input (missing field) silently produce `smart_account_redacted = ""`
        /// so audit queries with `smart_account_redacted=""` would match all
        /// entries — a silent data-integrity hole.
        smart_account_redacted: RedactedStrkey,
    },

    /// Verifier wasm-hash drift was detected during a signing path re-fetch.
    ///
    /// Emitted by `VerifiersManager::verify_pinned_verifier_against_chain` when the
    /// live two-RPC wasm-hash re-fetch disagrees with the hash pinned at rule-install
    /// time.  The signing operation is aborted before any signature bytes are
    /// produced.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `deploy_address_redacted` are first-5-last-5
    /// C-strkey.  `pinned_hash_first8` and `observed_hash_first8` are the first-8
    /// hex characters of the respective 32-byte wasm hashes — sufficient for
    /// forensic correlation without leaking the full hash preimage.
    ///
    /// Per-invocation request correlation ID is carried by the top-level
    /// `AuditEntry::request_id` field (common to all event kinds).
    ///
    /// # Backward compatibility
    ///
    /// No `#[serde(default)]` on fields — this variant has no legacy entries that
    /// predate it. Allowing default deserialisation would let malformed wire input
    /// (missing field) silently produce empty strings, a silent data-integrity
    /// hole. The `#[non_exhaustive]` attribute on `EventKind` (not per-field
    /// defaults) provides the schema-additivity guarantee.
    ///
    SaVerifierHashDrift {
        /// Context-rule identifier for which drift was detected (non-sensitive on-chain ID).
        rule_id: u32,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// Redacted deploy address of the drifted verifier contract, first-5-last-5 C-strkey.
        deploy_address_redacted: RedactedStrkey,
        /// First-8 hex chars of the wasm hash pinned at rule-install time.
        pinned_hash_first8: String,
        /// First-8 hex chars of the wasm hash observed via two-RPC re-fetch.
        observed_hash_first8: String,
    },

    /// Policy wasm-hash drift was detected during a signing path re-fetch.
    ///
    /// Parallel to [`EventKind::SaVerifierHashDrift`] for the threshold-policy
    /// contract path.  Emitted by
    /// `VerifiersManager::verify_pinned_policy_against_chain` when the live
    /// two-RPC wasm-hash re-fetch disagrees with the hash pinned at rule-install
    /// time.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `deploy_address_redacted` are first-5-last-5
    /// C-strkey.  `pinned_hash_first8` and `observed_hash_first8` are first-8
    /// hex chars of the respective 32-byte wasm hashes.
    ///
    /// Per-invocation request correlation ID is carried by the top-level
    /// `AuditEntry::request_id` field (common to all event kinds).
    ///
    /// # Backward compatibility
    ///
    /// No `#[serde(default)]` on fields — this variant has no legacy entries that
    /// predate it. Tampered or malformed wire input (missing field) MUST fail
    /// deserialisation, not silently default.
    ///
    SaPolicyHashDrift {
        /// Context-rule identifier for which drift was detected.
        rule_id: u32,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// Redacted deploy address of the drifted policy contract, first-5-last-5 C-strkey.
        deploy_address_redacted: RedactedStrkey,
        /// First-8 hex chars of the pinned wasm hash.
        pinned_hash_first8: String,
        /// First-8 hex chars of the observed wasm hash.
        observed_hash_first8: String,
    },

    /// A mutable-contract override was acknowledged at rule-install time.
    ///
    /// Emitted when `ContextRuleManager::install_rule` detects that a referenced
    /// verifier or policy contract has a non-zero `Admin` or `Owner` storage key,
    /// AND the operator has passed `--accept-mutable-verifier`.  The audit row
    /// records the acknowledgement with an ISO-8601 timestamp so the forensic
    /// trail is complete.
    ///
    /// # Fields
    ///
    /// - `contract_kind`: typed closed set identifying verifier vs policy
    ///   contract.
    /// - `override_acknowledged_at`: ISO-8601 UTC timestamp (RFC 3339 format)
    ///   of when the CLI flag was processed.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `contract_address_redacted` are
    /// first-5-last-5 C-strkey.  The `contract_kind` and timestamp are not secret.
    ///
    /// Per-invocation request correlation ID is carried by the top-level
    /// `AuditEntry::request_id` field (common to all event kinds).
    ///
    /// **Note:** `rule_id = 0` is a placeholder because this row is emitted
    /// by `pin_referenced_contracts` pre-install (no on-chain rule_id assigned
    /// yet). Correlate with the post-install `SaContextRuleCreated` row via the
    /// shared `request_id` UUID.
    ///
    /// # Backward compatibility
    ///
    /// No `#[serde(default)]` on fields — this variant has no legacy entries that
    /// predate it. Tampered or malformed wire input (missing field) MUST fail
    /// deserialisation, not silently default.
    ///
    SaMutableContractOverride {
        /// Context-rule identifier to which the overridden contract belongs.
        rule_id: u32,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// Redacted address of the mutable contract, first-5-last-5 C-strkey.
        contract_address_redacted: RedactedStrkey,
        /// Which contract kind triggered the override.
        ///
        /// Typed closed set; serialises as `"verifier"` or `"policy"`.
        /// Named `contract_kind` (not `kind`) to avoid colliding with the serde
        /// `#[serde(tag = "kind")]` internal-tag field on `EventKind`.
        contract_kind: ContractKind,
        /// ISO-8601 UTC timestamp (RFC 3339) of when the override was acknowledged.
        override_acknowledged_at: String,
    },

    /// An unknown-wasm-hash override was acknowledged at rule-install time.
    ///
    /// Emitted when `ContextRuleManager::install_rule` detects that a referenced
    /// verifier or policy contract's wasm hash is NOT in the compile-time
    /// allowlist (`VERIFIER_ALLOWLIST` / `THRESHOLD_POLICY_WASM_HASHES`),
    /// AND the operator has passed `--accept-unknown-verifier` (fail-closed by
    /// default with opt-in).  The audit row records the acknowledgement and the
    /// `observed_hash_first8` for forensic correlation.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` and `contract_address_redacted` are
    /// first-5-last-5 C-strkey.  `observed_hash_first8` carries the first-8
    /// hex chars of the unrecognised wasm hash (not secret — it's an on-chain
    /// identifier).
    ///
    /// Per-invocation request correlation ID is carried by the top-level
    /// `AuditEntry::request_id` field (common to all event kinds).
    ///
    /// **Note:** `rule_id = 0` is a placeholder because this row is emitted
    /// by `pin_referenced_contracts` pre-install (no on-chain rule_id assigned
    /// yet). Correlate with the post-install `SaContextRuleCreated` row via the
    /// shared `request_id` UUID.
    ///
    /// # Backward compatibility
    ///
    /// No `#[serde(default)]` on fields — this variant has no legacy entries that
    /// predate it. Tampered or malformed wire input (missing field) MUST fail
    /// deserialisation, not silently default.
    ///
    SaUnknownContractOverride {
        /// Context-rule identifier to which the overridden contract belongs.
        rule_id: u32,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// Redacted address of the contract with the unknown wasm hash,
        /// first-5-last-5 C-strkey.
        contract_address_redacted: RedactedStrkey,
        /// Which contract kind triggered the override.
        ///
        /// Typed closed set; serialises as `"verifier"` or `"policy"`.
        /// Named `contract_kind` (not `kind`) to avoid colliding with the serde
        /// `#[serde(tag = "kind")]` internal-tag field on `EventKind`.
        contract_kind: ContractKind,
        /// ISO-8601 UTC timestamp (RFC 3339) of when the override was acknowledged.
        override_acknowledged_at: String,
        /// First-8 hex chars of the unrecognised wasm hash for forensic correlation.
        ///
        /// Not secret — it is an on-chain identifier (the hash is public on the
        /// ledger).  Included to allow operators to identify the exact contract
        /// binary that was accepted under the unknown-wasm override.
        observed_hash_first8: String,
    },

    /// Rotation manifest entry written as the last entry in a rotated file.
    ///
    /// Written as the final entry into the outgoing (soon-to-be-archived) log
    /// file before [`AuditWriter`](crate::audit_log::writer::AuditWriter) calls
    /// `fs::rename`.  After rename, the file at `<stem>.<compact-ts>` IS this
    /// file.
    ///
    /// `audit verify` uses `next_file_name` to detect substitution attacks: it
    /// compares the field value against the actual basename of the file it is
    /// reading and rejects any mismatch as a `RotationGap` error.
    AuditRotationHandoff {
        /// The **archive filename** that THIS file was / is being renamed to
        /// during rotation (e.g. `default.jsonl.20260429T123456789`, basename
        /// only — no path components).
        ///
        /// Used by `audit verify` to detect substitution attacks where an
        /// attacker renames a rotated file to a different timestamp slot.
        /// The field's value MUST match the basename of THIS file's rotated
        /// archive after `fs::rename` completes.
        ///
        /// # Wire-format invariant
        ///
        /// The basename MUST match `<stem>.<YYYYMMDDTHHMMSS[mmm]>` exactly
        /// (the compact-timestamp format produced by `writer::compact_timestamp()`).
        /// Renaming or moving the archive file after rotation will cause
        /// `audit verify` to report `RotationGap`.
        next_file_name: String,
    },

    /// Verifier wasm hash on a context rule was migrated from one hash to
    /// another via `wallet sa migrate-verifier`.
    ///
    /// Emitted per affected rule after on-chain submission of the migration
    /// transaction. The per-rule emission allows operator triage to enumerate
    /// exactly which rules were rewritten in a multi-rule migration batch.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` is first-5-last-5 C-strkey.
    /// `from_hash_first8` and `to_hash_first8` are the first-8 hex chars of
    /// the respective 32-byte wasm hashes (not secret — on-chain identifiers).
    /// `tx_hash_redacted` is first-8-last-8 of the Stellar transaction hash,
    /// matching the `wasm_hash_prefix` / `tx_hash_redacted` discipline.
    ///
    /// # Backward compatibility
    ///
    /// No `#[serde(default)]` on fields — this variant has no legacy entries that
    /// predate it. Tampered or malformed wire input (missing field) MUST fail
    /// deserialisation, not silently default.
    SaVerifierMigrated {
        /// Context-rule identifier that was migrated (non-sensitive on-chain ID).
        rule_id: u32,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the pre-migration verifier wasm hash.
        from_hash_first8: String,
        /// First-8 hex chars of the post-migration verifier wasm hash.
        to_hash_first8: String,
        /// Stellar transaction hash of the migration submission.
        ///
        /// Redacted first-8-last-8 (matching `tx_hash_redacted`
        /// discipline for `SmartAccountDeployed`).
        tx_hash_redacted: String,
    },

    /// Operator explicitly accepted single-verifier signing on a high-value
    /// account via `--accept-single-verifier`.
    ///
    /// Emitted when the diversification enforce-default trigger would have fired
    /// (`SaError::VerifierDiversificationRequired`) but the operator passes
    /// `--accept-single-verifier`.  The audit row is the forensic record — the
    /// operator's explicit acknowledgement of reduced diversification is persisted
    /// regardless of the signing outcome.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` is first-5-last-5 C-strkey.
    /// `verifier_hash_first8` is the first-8 hex chars of the single verifier
    /// wasm hash (not secret).  `observed_value_threshold_stroops` is a
    /// numeric policy-criteria value (not secret).
    ///
    /// # Backward compatibility
    ///
    /// No `#[serde(default)]` on fields — this variant has no legacy entries that
    /// predate it. Tampered or malformed wire input MUST fail deserialisation.
    SaVerifierDiversificationOverride {
        /// Context-rule identifier for which the opt-in was acknowledged.
        rule_id: u32,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the single verifier wasm hash the rule
        /// references (not secret — on-chain identifier).
        verifier_hash_first8: String,
        /// Observed `value_threshold` from the active policy criteria (stroops).
        ///
        /// The raw stroop value from the active policy criteria; USD conversion
        /// happens at the policy-engine layer.
        observed_value_threshold_stroops: i64,
        /// ISO-8601 UTC timestamp (RFC 3339) when the operator opt-in was
        /// acknowledged.
        override_acknowledged_at: String,
    },

    /// Startup-advisory emitted when a context rule references a revoked or
    /// retired verifier wasm hash.
    ///
    /// Emitted by `run_startup_advisory` per affected rule. Provides a durable
    /// audit-log record of advisory emissions independent of stderr capture,
    /// allowing operators to query the log for historical advisories.
    ///
    /// `run_startup_advisory` emits this row using the local audit-log path
    /// only; no network call is involved.
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` is first-5-last-5 C-strkey.
    /// `revoked_hash_first8` is the first-8 hex chars of the advisory hash
    /// (not secret — on-chain identifier).  `advised_status` is a typed closed
    /// set.
    ///
    /// Per-invocation request correlation ID is carried by the top-level
    /// [`AuditEntry::request_id`](super::entry::AuditEntry::request_id) field
    /// (common to all event kinds).
    ///
    /// # Backward compatibility
    ///
    /// No `#[serde(default)]` on fields — this variant has no legacy entries that
    /// predate it. Tampered or malformed wire input MUST fail deserialisation.
    SaVerifierAllowlistAdvisory {
        /// Context-rule identifier referencing the revoked or retired verifier.
        rule_id: u32,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the revoked or retired verifier wasm hash.
        revoked_hash_first8: String,
        /// Closed-set classification of the offending allowlist status.
        ///
        /// Typed closed set: `Revoked` or `Retired`.  Serialises as
        /// `"revoked"` or `"retired"` via `#[serde(rename_all = "snake_case")]`.
        advised_status: VerifierAdvisoryKind,
    },

    /// A policy was added to a context rule via `wallet rules add-policy`.
    ///
    /// Emitted by `ContextRuleManager::add_policy` after a successful on-chain
    /// `add_policy(context_rule_id, policy, install_param) -> u32` invocation.
    ///
    /// # Field redaction
    ///
    /// `smart_account_redacted` is the C-strkey redacted first-5-last-5.
    /// `policy_address_redacted` is the policy contract C-strkey redacted
    /// first-5-last-5.  `transaction_hash_redacted` is first-8-last-8 of the
    /// Stellar transaction hash.
    ///
    /// `rule_id` and `policy_id` are on-chain public identifiers —
    /// redaction would be performative (they are visible to any RPC observer).
    ///
    /// Per-invocation request correlation ID is carried by the top-level
    /// [`AuditEntry::request_id`](super::entry::AuditEntry::request_id) field.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; existing wildcard-match arms in
    /// `audit verify` continue to compile. Hash-chain integrity is preserved.
    SaPolicyAdded {
        /// On-chain context rule ID the policy was added to (non-sensitive).
        rule_id: u32,
        /// On-chain policy ID assigned by the smart-account registry.
        ///
        /// Returned by `add_policy` as its `u32` return value.
        policy_id: u32,
        /// Policy contract C-strkey, redacted first-5-last-5.
        policy_address_redacted: RedactedStrkey,
        /// Stellar transaction hash, redacted first-8-last-8.
        transaction_hash_redacted: String,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
    },

    /// A policy was removed from a context rule via `wallet rules remove-policy`.
    ///
    /// Emitted by `ContextRuleManager::remove_policy` after a successful
    /// on-chain `remove_policy(context_rule_id, policy_id)` invocation.
    ///
    /// # Field redaction
    ///
    /// `smart_account_redacted` is the C-strkey redacted first-5-last-5.
    /// `transaction_hash_redacted` is first-8-last-8 of the Stellar transaction
    /// hash.
    ///
    /// `rule_id` and `policy_id` are on-chain public identifiers.
    ///
    /// Per-invocation request correlation ID is carried by the top-level
    /// [`AuditEntry::request_id`](super::entry::AuditEntry::request_id) field.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; hash-chain integrity preserved.
    SaPolicyRemoved {
        /// On-chain context rule ID the policy was removed from (non-sensitive).
        rule_id: u32,
        /// On-chain policy ID that was removed.
        policy_id: u32,
        /// Stellar transaction hash, redacted first-8-last-8.
        transaction_hash_redacted: String,
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
    },

    /// A multicall bundle was successfully submitted and confirmed on-chain.
    ///
    /// Emitted by `multicall::submit_multicall_bundle` after a successful
    /// `submit_signed_invoke` + on-chain confirmation cycle.
    ///
    /// Per-inner execution rows are emitted as separate
    /// [`EventKind::SaMulticallInnerExecuted`] rows, one per inner invocation,
    /// immediately following this parent row.
    ///
    /// # Field redaction
    ///
    /// - `smart_account_redacted` — C-strkey, first-5-last-5.
    /// - `bundle_tx_hash_redacted` — transaction hash, first-8-last-8.
    ///
    /// `rule_id` and `inner_count` are non-sensitive on-chain identifiers.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; hash-chain integrity preserved.
    SaMulticallBundleSubmitted {
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// On-chain context rule ID under which the multicall was authorised.
        rule_id: u32,
        /// Transaction hash of the confirmed bundle, redacted first-8-last-8.
        bundle_tx_hash_redacted: String,
        /// Number of inner invocations in the bundle.
        inner_count: u32,
    },

    /// A single inner invocation within a confirmed multicall bundle was executed.
    ///
    /// Emitted once per inner invocation, immediately after
    /// [`EventKind::SaMulticallBundleSubmitted`], in bundle order (inner_index
    /// 0, 1, ..., N-1).
    ///
    /// # Field redaction
    ///
    /// - `bundle_tx_hash_redacted` — first-8-last-8 of the transaction hash.
    /// - `target_contract_redacted` — C-strkey of the target contract, first-5-last-5.
    /// - `return_scval_b64_prefix` — first 32 chars of the base64-encoded return
    ///   `ScVal` (truncated to avoid log bloat; `None` when return is `Void`).
    ///
    /// `inner_index`, `fn_name` are non-sensitive identifiers.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`.
    SaMulticallInnerExecuted {
        /// Transaction hash of the parent bundle, redacted first-8-last-8.
        bundle_tx_hash_redacted: String,
        /// Zero-based index of this inner within the bundle.
        inner_index: u32,
        /// C-strkey of the target contract, redacted first-5-last-5.
        target_contract_redacted: RedactedStrkey,
        /// Soroban function name that was called.
        fn_name: String,
        /// First 32 base64 chars of the `ScVal` return value, or `None` for `Void`.
        return_scval_b64_prefix: Option<String>,
    },

    /// A multicall bundle was denied before or during submission.
    ///
    /// Emitted by `multicall::submit_multicall_bundle` when the bundle is
    /// refused at any phase: `build` validation, `policy_gate` denial,
    /// `rpc_divergence` trust-anchor failure, `simulate` error, `sign` error,
    /// `submit` error, or `post_submit_verification` mismatch.
    ///
    /// `denied_inner_index` is `Some(N)` when the denial was triggered by a
    /// specific inner invocation (e.g. policy per-inner deny); `None` for
    /// aggregate/whole-bundle denials.
    ///
    /// # Field redaction
    ///
    /// - `smart_account_redacted` — C-strkey, first-5-last-5.
    /// - `bundle_tx_hash_redacted` — transaction hash, first-8-last-8, `None`
    ///   when the bundle was denied before submission.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`.
    SaMulticallBundleDenied {
        /// Target smart-account C-strkey, redacted first-5-last-5.
        smart_account_redacted: RedactedStrkey,
        /// On-chain context rule ID under which the multicall was attempted.
        rule_id: u32,
        /// Number of inner invocations in the attempted bundle.
        inner_count: u32,
        /// Zero-based index of the inner invocation that triggered the denial, if any.
        denied_inner_index: Option<u32>,
        /// Observed inner count if the post-submit count mismatch triggered the denial.
        observed_inner_count: Option<u32>,
        /// Denial wire code (e.g. `"multicall.bundle_empty"`,
        /// `"multicall.sa.deployment_failed"`).
        deny_wire_code: String,
        /// Phase from the closed 7-value set at which the bundle was denied.
        ///
        /// One of: `"build"`, `"policy_gate"`, `"rpc_divergence"`, `"simulate"`,
        /// `"sign"`, `"submit"`, `"post_submit_verification"`.
        refusal_phase: String,
        /// Transaction hash of the submission attempt if denial occurred post-submit,
        /// redacted first-8-last-8. `None` for pre-submission denials.
        bundle_tx_hash_redacted: Option<String>,
    },

    /// A multicall router was successfully registered in the local registry.
    ///
    /// Emitted by `wallet sa register-multicall` on success, after
    /// `MulticallRegistry::register` writes the entry to disk.
    ///
    /// # Field redaction
    ///
    /// - `address_redacted` — C-strkey of the registered router, first-5-last-5.
    ///
    /// `network_safename` and `wasm_sha256` are non-sensitive configuration identifiers.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; hash-chain integrity preserved.
    SaMulticallRegistered {
        /// Network safename (TOML section key; e.g. `"test-sdf-network---september-2015"`).
        network_safename: String,
        /// Registered multicall router C-strkey, redacted first-5-last-5.
        address_redacted: RedactedStrkey,
        /// SHA-256 of the vendored multicall WASM, as 64-char lowercase hex.
        wasm_sha256: String,
    },

    /// A multicall router registration was refused due to a WASM SHA-256 mismatch.
    ///
    /// Emitted by `wallet sa register-multicall` when the supplied `--wasm-sha256`
    /// does not equal `MULTICALL_WASM_SHA256`, or when an existing entry has a
    /// different SHA (re-register drift guard).
    ///
    /// # Field redaction
    ///
    /// - `address_redacted` — C-strkey of the refused router, first-5-last-5.
    ///
    /// `attempted_wasm_sha256`, `existing_wasm_sha256`, and `refusal_reason` are
    /// non-sensitive configuration identifiers.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; hash-chain integrity preserved.
    SaMulticallRegistrationRefused {
        /// Network safename (TOML section key).
        network_safename: String,
        /// Refused router C-strkey, redacted first-5-last-5.
        address_redacted: RedactedStrkey,
        /// The `wasm_sha256` value the caller attempted to register (64-char hex).
        attempted_wasm_sha256: String,
        /// The `wasm_sha256` value in the existing registry entry, if any.
        existing_wasm_sha256: Option<String>,
        /// Short human-readable refusal reason (e.g. `"sha256_mismatch"`,
        /// `"cli_sha256_check_failed"`).
        refusal_reason: String,
    },

    /// A multicall router was successfully unregistered from the local registry.
    ///
    /// Emitted by `wallet sa unregister-multicall` (normal path, not `--force`)
    /// on success, after `MulticallRegistry::unregister` removes the entry.
    ///
    /// # Field redaction
    ///
    /// - `prior_address_redacted` — C-strkey of the removed router, first-5-last-5.
    ///
    /// `network_safename` and `prior_wasm_sha256` are non-sensitive configuration identifiers.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; hash-chain integrity preserved.
    SaMulticallUnregistered {
        /// Network safename (TOML section key).
        network_safename: String,
        /// Prior router C-strkey, redacted first-5-last-5.
        prior_address_redacted: RedactedStrkey,
        /// Prior WASM SHA-256 (64-char lowercase hex).
        prior_wasm_sha256: String,
    },

    /// A multicall router was forcibly removed from the local registry via
    /// `wallet sa unregister-multicall --force`.
    ///
    /// This is the corruption-recovery path. The raw string values from the TOML
    /// file are included without validation — they may be invalid strkeys or hex
    /// strings. Each raw field is truncated to 64 characters if longer; if the
    /// full entry still exceeds `MAX_ENTRY_BYTES` after truncation, sentinel
    /// `"<oversized>"` placeholders replace the raw fields.
    ///
    /// # Audit-row emission discipline
    ///
    /// The audit row is emitted BEFORE any file mutation. If emission fails, the
    /// file is NOT mutated: the row says "tried"; the registry retains the entry;
    /// the operator retries after resolving the emission failure.
    ///
    /// # Field truncation
    ///
    /// - `prior_address_raw` — truncated to 64 characters; `prior_address_raw_truncated = true`
    ///   when the raw value was longer.
    /// - `prior_wasm_sha256_raw` — truncated to 64 characters; `prior_wasm_sha256_raw_truncated = true`.
    /// - `load_warnings` — capped at 32 entries; `load_warnings_truncated = true` when more.
    ///   Each warning string is already capped at 256 bytes by `MulticallRegistry::load`.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; hash-chain integrity preserved.
    SaMulticallUnregisteredForce {
        /// Network safename (TOML section key).
        network_safename: String,
        /// Raw address string from TOML (possibly invalid strkey); truncated to 64 chars.
        prior_address_raw: String,
        /// `true` when `prior_address_raw` was longer than 64 chars and was truncated.
        prior_address_raw_truncated: bool,
        /// Raw wasm_sha256 string from TOML (possibly invalid hex); truncated to 64 chars.
        prior_wasm_sha256_raw: String,
        /// `true` when `prior_wasm_sha256_raw` was longer than 64 chars and was truncated.
        prior_wasm_sha256_raw_truncated: bool,
        /// Load warnings accumulated during `MulticallRegistry::load` for this network;
        /// capped at 32 entries.
        load_warnings: Vec<String>,
        /// `true` when more than 32 load warnings were present and the list was capped.
        load_warnings_truncated: bool,
    },

    /// A timelock operation was successfully scheduled on-chain.
    ///
    /// Emitted by `stellar_agent_smart_account::timelock::schedule_upgrade` after
    /// the `Timelock::schedule` transaction is confirmed. The `operation_id_full_hex`
    /// field (64 hex chars) is the canonical cross-reference for `cancel` and
    /// `execute` audit rows; `operation_id_redacted` (first-8-last-8 hex) is
    /// the forensic-log form.
    SaTimelockScheduled {
        /// Redacted operation identifier (first-8-last-8 hex, 19 chars).
        operation_id_redacted: String,
        /// Full 64-character lowercase hex operation identifier.
        ///
        /// Used in `cancel` and `execute` audit rows for cross-referencing.
        /// Operation IDs are public on-chain; no PII is present.
        operation_id_full_hex: String,
        /// Redacted timelock contract address (first-5-last-5 C-strkey).
        timelock_contract_redacted: crate::observability::RedactedStrkey,
        /// Redacted target contract address for the scheduled operation.
        target_redacted: crate::observability::RedactedStrkey,
        /// Name of the function on the target contract that will be called on execute.
        function: String,
        /// Minimum ledger delay before the operation can be executed.
        delay_ledgers: u32,
        /// Redacted G-strkey of the proposer who signed the `schedule` call.
        proposer_redacted: crate::observability::RedactedStrkey,
        /// Redacted transaction hash (first-8-last-8 hex, 19 chars).
        schedule_tx_hash_redacted: String,
        /// Per-request correlation identifier from the originating `schedule_upgrade` call.
        audit_request_id: String,
    },

    /// A pending timelock operation was cancelled.
    ///
    /// Emitted by `stellar_agent_smart_account::timelock::cancel` after the
    /// `Timelock::cancel` transaction is confirmed.
    SaTimelockCancelled {
        /// Redacted operation identifier (first-8-last-8 hex, 19 chars).
        operation_id_redacted: String,
        /// Full 64-character lowercase hex operation identifier.
        ///
        /// Allows `find_pending_timelock_operations` to match by exact
        /// `operation_id_full_hex` rather than the 64-bit collision surface of the
        /// redacted first-8-last-8 form. Operation IDs are public on-chain; no PII
        /// is present.
        operation_id_full_hex: String,
        /// Redacted timelock contract address (first-5-last-5 C-strkey).
        timelock_contract_redacted: crate::observability::RedactedStrkey,
        /// Redacted G-strkey of the canceller who signed the `cancel` call.
        canceller_redacted: crate::observability::RedactedStrkey,
        /// Redacted transaction hash (first-8-last-8 hex, 19 chars).
        cancel_tx_hash_redacted: String,
        /// Per-request correlation identifier from the originating `cancel` call.
        audit_request_id: String,
    },

    /// A ready timelock operation was executed.
    ///
    /// Emitted by `stellar_agent_smart_account::timelock::execute` after the
    /// `Timelock::execute` transaction is confirmed.
    SaTimelockExecuted {
        /// Redacted operation identifier (first-8-last-8 hex, 19 chars).
        operation_id_redacted: String,
        /// Full 64-character lowercase hex operation identifier.
        ///
        /// Allows `find_pending_timelock_operations` to match by exact
        /// `operation_id_full_hex` rather than the 64-bit collision surface of the
        /// redacted first-8-last-8 form. Operation IDs are public on-chain; no PII
        /// is present.
        operation_id_full_hex: String,
        /// Redacted timelock contract address (first-5-last-5 C-strkey).
        timelock_contract_redacted: crate::observability::RedactedStrkey,
        /// Redacted G-strkey of the executor who signed the `execute` call.
        ///
        /// `None` when open-execution mode is used (no configured EXECUTOR_ROLE).
        executor_redacted: Option<crate::observability::RedactedStrkey>,
        /// Redacted transaction hash (first-8-last-8 hex, 19 chars).
        execute_tx_hash_redacted: String,
        /// Per-request correlation identifier from the originating `execute` call.
        audit_request_id: String,
    },

    /// A `cross_confirm_event` call returned `Divergence` on a timelock path.
    ///
    /// Emitted immediately before the divergence error is propagated on the
    /// `schedule`, `cancel`, or `execute` paths so that an on-chain op that
    /// landed (but whose event was not confirmed on both RPCs) leaves a forensic
    /// trail in the audit log.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; existing match-with-wildcard arms compile.
    ///
    /// # Field redaction
    ///
    /// `smart_account_redacted`: C-strkey first-5-last-5.
    /// `operation_id_redacted`: first-8-last-8 hex.
    /// `tx_hash_redacted`: first-8-last-8 hex.
    SaTimelockDivergencePostSubmit {
        /// Redacted C-strkey of the smart account (first-5-last-5).
        smart_account_redacted: crate::observability::RedactedStrkey,
        /// Redacted timelock operation id (first-8-last-8 hex, 19 chars).
        operation_id_redacted: String,
        /// Redacted transaction hash (first-8-last-8 hex, 19 chars).
        tx_hash_redacted: String,
        /// Which timelock path produced the divergence: `"schedule"`, `"cancel"`,
        /// or `"execute"`.
        path: String,
        /// Whether the event was present on the primary RPC.
        primary_present: bool,
        /// Whether the event was present on the secondary RPC.
        secondary_present: bool,
        /// Per-request correlation identifier.
        ///
        /// Named `audit_request_id` to avoid the serde-flatten collision with
        /// the outer `AuditEntry::request_id` field (same serde-flatten convention
        /// used by all SaTimelock* variants).
        audit_request_id: String,
    },

    /// Channel-account pool was initialised on-chain.
    ///
    /// Emitted by `stellar_agent_pool::init::init_pool` after the CAP-33
    /// sponsored-reserve sandwich is confirmed on-chain.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; existing match-with-wildcard arms compile.
    ///
    /// # Field redaction
    ///
    /// `funder_redacted`: G-strkey first-5-last-5.
    /// `tx_hash_redacted`: first-8-last-8 hex.
    ChannelPoolInitialised {
        /// Redacted G-strkey of the funder (transaction source + sponsor),
        /// first-5-last-5 form.
        funder_redacted: String,
        /// Number of channels created in this sandwich.
        channel_count: usize,
        /// Redacted transaction hash (first-8-last-8 hex, 19 chars).
        tx_hash_redacted: String,
        /// Network ledger sequence at confirmation.
        ledger: u32,
    },

    /// A pool channel was acquired (allocated to an in-flight submission).
    ///
    /// Schema variant defined ahead of its emitter so that the hash-chained log
    /// can recognise it without a retroactive schema change once the concurrent
    /// allocator is live.
    ///
    /// # Field redaction
    ///
    /// `channel_redacted`: G-strkey first-5-last-5.
    ChannelAcquired {
        /// Redacted G-strkey of the acquired channel, first-5-last-5 form.
        channel_redacted: String,
        /// BIP-44 derivation index of the acquired channel.
        ///
        /// Non-sensitive: it is a position counter, not a secret.
        index: u32,
    },

    /// A pool channel was released back to the free pool.
    ///
    /// Schema variant defined ahead of its emitter so that the hash-chained log
    /// can recognise it without a retroactive schema change once the concurrent
    /// allocator is live.
    ///
    /// # Field redaction
    ///
    /// `channel_redacted`: G-strkey first-5-last-5.
    ChannelReleased {
        /// Redacted G-strkey of the released channel, first-5-last-5 form.
        channel_redacted: String,
        /// BIP-44 derivation index of the released channel.
        index: u32,
        /// The terminal outcome that caused the release.
        ///
        /// String-serialised: `"success"`, `"tx_bad_seq"`, or `"failed"`.
        outcome: String,
    },

    /// A Soroban auth-entry fingerprint check detected a mismatch before
    /// submission.
    ///
    /// The in-process tripwire in `submit_signed_invoke` surfaces a mismatch as
    /// `SaError::AuthMismatch` (→ `SaInvocationResult::PreSubmissionRefused` in
    /// the caller's invocation-result audit row). This dedicated event variant is
    /// defined here for the external-submit boundary; `submit_signed_invoke` is
    /// explicitly audit-silent by design (see module doc of
    /// `stellar_agent_smart_account::submit`).
    ///
    /// No pass-event is emitted: the pass case (auth entries unchanged) is the
    /// overwhelming common path; a per-submit "audited OK" row would add
    /// audit-volume noise with no forensic value.
    ///
    /// # Field redaction
    ///
    /// - `smart_account` — C-strkey redacted first-5-last-5.
    /// - `expected_count` / `actual_count` — entry counts, non-sensitive
    ///   (integer metadata; no entry bytes).
    /// - `reason` — the [`crate::error::AuthMismatchReason`] label string, a fixed
    ///   secret-free enum discriminant.
    ///
    /// No entry XDR bytes, no signature bytes, and no full strkeys appear
    /// in this event.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; existing wildcard-match arms in
    /// `audit verify` continue to compile.
    SubmissionAuthMismatch {
        /// Smart-account C-strkey, redacted first-5-last-5.
        ///
        /// Empty string `""` when the mismatch is detected outside the smart-
        /// account submit path (e.g. external-submit entry point with no smart
        /// account context; reserved for future wiring).
        smart_account: String,
        /// Number of auth entries in the expected fingerprint (captured at
        /// sign time).
        expected_count: u32,
        /// Number of auth entries in the actual (about-to-be-submitted)
        /// envelope.
        actual_count: u32,
        /// The closed-set [`crate::error::AuthMismatchReason`] label (e.g. `"entry_mutated"`).
        ///
        /// Always one of the six fixed labels from `AuthMismatchReason::label()`.
        /// No secret content.
        reason: String,
    },

    /// A pending approval was attested (approved) by the operator.
    ///
    /// Emitted from the shared `stellar_agent_core::approval::attest` path
    /// after the entry's HMAC attestation (`PaymentSimulated` /
    /// `ClaimSimulated` / `TrustlineClawbackOptIn`) or recorded consent
    /// (`ToolsetFirstInvokeGate`) is durably persisted to the pending-approval
    /// store — both the `stellar-agent approve --id <nonce>` CLI path and any
    /// future server-driven approve surface emit this same event. Emission is
    /// non-fatal: a failure to write this row never unwinds a successful
    /// attestation.
    ///
    /// # Field redaction
    ///
    /// `nonce_prefix` carries only the first 8 characters of the approval
    /// nonce (same truncation discipline as `SaRawInvocation.auth_digest_prefix`).
    /// `envelope_sha256_hex` is a SHA-256 digest — no user data — and is
    /// carried in full; it is `None` for kinds with no signed transaction
    /// envelope (`ToolsetFirstInvokeGate`, `TrustlineClawbackOptIn`).
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; existing wildcard-match arms in
    /// `audit verify` continue to compile.
    ApprovalAttested {
        /// `ApprovalKind::kind_name()` of the attested entry (e.g.
        /// `"PaymentSimulated"`).
        approval_kind: String,
        /// MCP tool this approval gates (e.g. `"stellar_pay_commit"`).
        ///
        /// Named distinctly from the outer `AuditEntry::tool` field — which
        /// carries the fixed event name for this row — to avoid the
        /// `#[serde(flatten)]` collision the `audit_request_id` convention
        /// guards against (see `SaContextRuleNameUpdated`).
        gated_tool: String,
        /// Hex-encoded SHA-256 of the envelope XDR bytes, for
        /// `PaymentSimulated` and `ClaimSimulated` entries.
        #[serde(skip_serializing_if = "Option::is_none")]
        envelope_sha256_hex: Option<String>,
        /// First 8 characters of the approval nonce.
        nonce_prefix: String,
        /// Which origin attested the entry: `"cli"` or `"serve"`.
        origin: String,
    },

    /// A pending approval was rejected by the operator.
    ///
    /// Emitted after the entry is replaced by a short-TTL
    /// `ApprovalKind::Rejected` tombstone (`crate::approval::store`).
    /// Additive schema: the field set mirrors `ApprovalAttested` minus the
    /// attestation-specific fields, defined up front alongside it because the
    /// hash-chained log forbids adding fields to an existing variant later.
    ///
    /// # Schema additivity
    ///
    /// Additive under `#[non_exhaustive]`; existing wildcard-match arms in
    /// `audit verify` continue to compile.
    ApprovalRejected {
        /// `ApprovalKind::kind_name()` of the rejected entry.
        approval_kind: String,
        /// First 8 characters of the approval nonce.
        nonce_prefix: String,
        /// Which origin rejected the entry: `"cli"` or `"serve"`.
        origin: String,
    },
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;

    #[test]
    fn policy_decision_allow_serialises() {
        let d = PolicyDecision::Allow;
        assert_eq!(serde_json::to_string(&d).unwrap(), r#""allow""#);
    }

    #[test]
    fn policy_decision_deny_serialises() {
        let d = PolicyDecision::Deny("per_tx_cap_exceeded".to_owned());
        let s = serde_json::to_string(&d).unwrap();
        assert!(s.contains("deny"), "deny must appear: {s}");
    }

    #[test]
    fn policy_decision_require_approval_serialises() {
        let d = PolicyDecision::RequireApproval;
        assert_eq!(serde_json::to_string(&d).unwrap(), r#""require_approval""#);
    }

    #[test]
    fn policy_decision_display() {
        assert_eq!(format!("{}", PolicyDecision::Allow), "allow");
        assert_eq!(
            format!("{}", PolicyDecision::Deny("x".to_owned())),
            "deny:x"
        );
        assert_eq!(
            format!("{}", PolicyDecision::RequireApproval),
            "require_approval"
        );
    }

    #[test]
    fn event_kind_tool_invocation_round_trip() {
        let ev = EventKind::ToolInvocation;
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn event_kind_plugin_invoked_round_trip() {
        let ev = EventKind::PluginInvoked {
            plugin_name: "my-plugin".to_owned(),
            exit_code: 0,
            decision: PolicyDecision::Allow,
            duration_ms: 42,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn event_kind_mlock_failed_round_trip() {
        let ev = EventKind::WalletMlockFailed {
            profile: "default".to_owned(),
            reason: "ENOMEM".to_owned(),
            errno: Some(12),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn event_kind_rotation_handoff_round_trip() {
        let ev = EventKind::AuditRotationHandoff {
            next_file_name: "default.jsonl.20260428T123456".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    /// Asserts that `next_file_name` in a handoff entry is an archive basename,
    /// not the new active file name.  The value must match the pattern used by
    /// `writer::compact_timestamp()` — `<stem>.<YYYYMMDDTHHMMSS[mmm]>`.
    ///
    /// Pins the semantic contract: `next_file_name` is the archive basename of
    /// THIS file, NOT the next active log file.
    #[test]
    fn rotation_handoff_next_file_name_is_archive_basename() {
        use crate::audit_log::writer::is_rotated_sibling;
        // Construct a handoff with a realistic archive basename.
        let archive_name = "default.jsonl.20260429T123456789";
        let ev = EventKind::AuditRotationHandoff {
            next_file_name: archive_name.to_owned(),
        };
        // Verify that next_file_name matches the rotated-sibling pattern.
        assert!(
            is_rotated_sibling("default.jsonl", archive_name),
            "next_file_name must match rotated-sibling pattern: {archive_name}"
        );
        // Verify the serialised field name and value round-trip.
        let s = serde_json::to_string(&ev).unwrap();
        assert!(
            s.contains("next_file_name"),
            "serialised handoff must contain 'next_file_name': {s}"
        );
        assert!(
            s.contains(archive_name),
            "serialised handoff must preserve the archive basename: {s}"
        );
        // Deserialise and confirm field value.
        let back: EventKind = serde_json::from_str(&s).unwrap();
        if let EventKind::AuditRotationHandoff {
            next_file_name: ref n,
        } = back
        {
            assert_eq!(
                n, archive_name,
                "deserialised next_file_name must equal archive_name"
            );
        } else {
            unreachable!("expected AuditRotationHandoff, got: {back:?}");
        }
    }

    #[test]
    fn sa_invocation_result_success_serialises() {
        let r = SaInvocationResult::Success;
        assert_eq!(serde_json::to_string(&r).unwrap(), r#""success""#);
    }

    #[test]
    fn sa_invocation_result_pre_submission_refused_serialises() {
        let r = SaInvocationResult::PreSubmissionRefused;
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#""pre_submission_refused""#
        );
    }

    #[test]
    fn sa_invocation_result_on_chain_rejected_serialises() {
        let r = SaInvocationResult::OnChainRejected;
        assert_eq!(serde_json::to_string(&r).unwrap(), r#""on_chain_rejected""#);
    }

    /// `PostSubmitVerificationFailed` serialises to
    /// `"post_submit_verification_failed"` and round-trips correctly.
    #[test]
    fn sa_invocation_result_post_submit_verification_failed_serialises() {
        let r = SaInvocationResult::PostSubmitVerificationFailed;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#""post_submit_verification_failed""#);
        let back: SaInvocationResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back, SaInvocationResult::PostSubmitVerificationFailed);
    }

    /// Round-trip with `auth_digest_prefix: Some(...)`.
    #[test]
    fn event_kind_sa_raw_invocation_round_trip_with_some_auth_digest_prefix() {
        let ev = EventKind::SaRawInvocation {
            smart_account: "CAAAA...ZZZZZ".to_owned(),
            wire_code: "sa.ok".to_owned(),
            auth_digest_prefix: Some("aabb1122ccdd3344".to_owned()),
            context_rule_ids_count: 3,
            result: SaInvocationResult::Success,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        // Field MUST appear in wire form when Some.
        assert!(
            s.contains("auth_digest_prefix"),
            "auth_digest_prefix field must be present when Some: {s}"
        );
        assert!(
            s.contains("aabb1122ccdd3344"),
            "auth_digest_prefix value must appear: {s}"
        );
    }

    /// Round-trip with `auth_digest_prefix: None` — the deployment-op shape.
    ///
    /// With `#[serde(skip_serializing_if = "Option::is_none")]` the field is
    /// omitted from the wire form; deserialisation MUST recover `None`.
    #[test]
    fn event_kind_sa_raw_invocation_round_trip_with_none_auth_digest_prefix() {
        let ev = EventKind::SaRawInvocation {
            smart_account: "CAAAA...ZZZZZ".to_owned(),
            wire_code: "sa.deployment_failed".to_owned(),
            auth_digest_prefix: None,
            context_rule_ids_count: 0,
            result: SaInvocationResult::PreSubmissionRefused,
        };
        let s = serde_json::to_string(&ev).unwrap();
        // The field MUST be absent (not "null") in the wire form.
        assert!(
            !s.contains("auth_digest_prefix"),
            "auth_digest_prefix field must be absent when None (skip_serializing_if): {s}"
        );
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn event_kind_sa_raw_invocation_serialised_fields_present() {
        let ev = EventKind::SaRawInvocation {
            smart_account: "CTEST1...TEST2".to_owned(),
            wire_code: "sa.threshold_unreachable".to_owned(),
            auth_digest_prefix: Some("deadbeef12345678".to_owned()),
            context_rule_ids_count: 2,
            result: SaInvocationResult::PreSubmissionRefused,
        };
        let s = serde_json::to_string(&ev).unwrap();
        // Verify field names are present in the wire format.
        assert!(s.contains("smart_account"), "smart_account field: {s}");
        assert!(s.contains("wire_code"), "wire_code field: {s}");
        assert!(
            s.contains("auth_digest_prefix"),
            "auth_digest_prefix field: {s}"
        );
        assert!(
            s.contains("context_rule_ids_count"),
            "context_rule_ids_count field: {s}"
        );
        assert!(s.contains("result"), "result field: {s}");
        assert!(
            s.contains("sa.threshold_unreachable"),
            "wire_code value: {s}"
        );
        assert!(s.contains("pre_submission_refused"), "result value: {s}");
    }

    /// Round-trip for the `SmartAccountDeployed` variant.
    #[test]
    fn event_kind_smart_account_deployed_round_trip() {
        let ev = EventKind::SmartAccountDeployed {
            smart_account: "CDABC...XYZ12".to_owned(),
            deployer: "GAQAA...5ABVQ".to_owned(),
            wasm_hash_prefix: "06186e93...a56cb239".to_owned(),
            wasm_uploaded: true,
            tx_hash_redacted: "deadbeef...cafebabe".to_owned(),
            ledger: 42_000,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        // Verify required field names are present.
        assert!(s.contains("smart_account"), "smart_account field: {s}");
        assert!(s.contains("deployer"), "deployer field: {s}");
        assert!(
            s.contains("wasm_hash_prefix"),
            "wasm_hash_prefix field: {s}"
        );
        assert!(s.contains("wasm_uploaded"), "wasm_uploaded field: {s}");
        assert!(
            s.contains("tx_hash_redacted"),
            "tx_hash_redacted field: {s}"
        );
        assert!(s.contains("ledger"), "ledger field: {s}");
        // kind discriminant.
        assert!(
            s.contains("smart_account_deployed"),
            "kind discriminant must be snake_case: {s}"
        );
    }

    /// Round-trip for `SaContextRuleCreated` with `valid_until: Some(...)`.
    #[test]
    fn event_kind_sa_context_rule_created_round_trip_with_valid_until() {
        let ev = EventKind::SaContextRuleCreated {
            smart_account: "CDABC...XYZ12".to_owned(),
            rule_id: 42,
            context_type: "default".to_owned(),
            signers_count: 3,
            policies_count: 1,
            valid_until: Some(123_456),
            pinned_verifier_wasm_hashes_first8: vec![],
            pinned_policy_wasm_hashes_first8: vec![],
            mutable_override: false,
            unknown_override: false,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(s.contains("smart_account"), "smart_account field: {s}");
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        assert!(s.contains("context_type"), "context_type field: {s}");
        assert!(s.contains("signers_count"), "signers_count field: {s}");
        assert!(s.contains("policies_count"), "policies_count field: {s}");
        assert!(s.contains("valid_until"), "valid_until field: {s}");
        assert!(
            s.contains("sa_context_rule_created"),
            "kind discriminant must be snake_case: {s}"
        );
        // New pin fields MUST be absent when empty/false (skip_serializing_if).
        assert!(
            !s.contains("pinned_verifier_wasm_hashes_first8"),
            "empty verifier pin field must be skipped: {s}"
        );
        assert!(
            !s.contains("mutable_override"),
            "false mutable_override must be skipped: {s}"
        );
    }

    /// Round-trip with `valid_until: None` — the rule is permanent.
    #[test]
    fn event_kind_sa_context_rule_created_round_trip_with_none_valid_until() {
        let ev = EventKind::SaContextRuleCreated {
            smart_account: "CDABC...XYZ12".to_owned(),
            rule_id: 7,
            context_type: "call_contract".to_owned(),
            signers_count: 1,
            policies_count: 0,
            valid_until: None,
            pinned_verifier_wasm_hashes_first8: vec![],
            pinned_policy_wasm_hashes_first8: vec![],
            mutable_override: false,
            unknown_override: false,
        };
        let s = serde_json::to_string(&ev).unwrap();
        // valid_until field MUST be absent (skip_serializing_if).
        assert!(
            !s.contains("valid_until"),
            "valid_until field must be absent when None: {s}"
        );
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    /// Backward-compat: a `SaContextRuleCreated` entry without pin fields
    /// deserialises correctly with `#[serde(default)]` filling in empty/false.
    #[test]
    fn event_kind_sa_context_rule_created_backward_compat_missing_pin_fields() {
        // Simulate a legacy JSON entry without the pin fields.
        let legacy_json = r#"{"kind":"sa_context_rule_created","smart_account":"CDABC...XYZ12","rule_id":1,"context_type":"default","signers_count":2,"policies_count":1,"valid_until":99999}"#;
        let back: EventKind = serde_json::from_str(legacy_json).unwrap();
        match back {
            EventKind::SaContextRuleCreated {
                rule_id,
                pinned_verifier_wasm_hashes_first8,
                pinned_policy_wasm_hashes_first8,
                mutable_override,
                unknown_override,
                ..
            } => {
                assert_eq!(rule_id, 1, "rule_id must round-trip");
                assert!(
                    pinned_verifier_wasm_hashes_first8.is_empty(),
                    "missing pin field must default to empty"
                );
                assert!(
                    pinned_policy_wasm_hashes_first8.is_empty(),
                    "missing policy pin field must default to empty"
                );
                assert!(
                    !mutable_override,
                    "missing mutable_override must default to false"
                );
                assert!(
                    !unknown_override,
                    "missing unknown_override must default to false"
                );
            }
            other => panic!("expected SaContextRuleCreated, got {other:?}"),
        }
    }

    /// Round-trip: `SaContextRuleCreated` with non-empty pin fields.
    #[test]
    fn event_kind_sa_context_rule_created_round_trip_with_pin_fields() {
        let ev = EventKind::SaContextRuleCreated {
            smart_account: "CDABC...XYZ12".to_owned(),
            rule_id: 5,
            context_type: "default".to_owned(),
            signers_count: 1,
            policies_count: 1,
            valid_until: None,
            pinned_verifier_wasm_hashes_first8: vec!["aabbccdd".to_owned()],
            pinned_policy_wasm_hashes_first8: vec!["11223344".to_owned()],
            mutable_override: false,
            unknown_override: true,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("pinned_verifier_wasm_hashes_first8"),
            "non-empty verifier pin field must be serialised: {s}"
        );
        assert!(
            s.contains("pinned_policy_wasm_hashes_first8"),
            "non-empty policy pin field must be serialised: {s}"
        );
        // unknown_override = true MUST be serialised.
        assert!(
            s.contains("unknown_override"),
            "true unknown_override must be serialised: {s}"
        );
        // mutable_override = false MUST be skipped.
        assert!(
            !s.contains("mutable_override"),
            "false mutable_override must be skipped: {s}"
        );
    }

    /// Round-trip for `SaSignerAdded`.
    #[test]
    fn event_kind_sa_signer_added_round_trip() {
        let ev = EventKind::SaSignerAdded {
            rule_id: 1,
            signer_id: 0,
            resulting_signer_count: 1,
            resulting_threshold: 1,
            resulting_signer_ids: vec![0],
            resulting_signer_pubkeys: vec![SignerPubkey::Ed25519 {
                pubkey: [0xabu8; 32],
            }],
            resulting_signer_pubkeys_first8: vec!["abababab".to_owned()],
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_signer_added"),
            "kind discriminant must be sa_signer_added: {s}"
        );
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        assert!(s.contains("signer_id"), "signer_id field: {s}");
        assert!(
            s.contains("resulting_signer_count"),
            "resulting_signer_count: {s}"
        );
    }

    /// Round-trip for `SaSignerRemoved`.
    #[test]
    fn event_kind_sa_signer_removed_round_trip() {
        use crate::audit_log::signer_set::SignerPubkey;
        let ev = EventKind::SaSignerRemoved {
            rule_id: 2,
            signer_id: 1,
            resulting_signer_count: 1,
            resulting_threshold: 1,
            resulting_signer_ids: vec![0],
            resulting_signer_pubkeys: vec![SignerPubkey::Ed25519 {
                pubkey: [0x01u8; 32],
            }],
            resulting_signer_pubkeys_first8: vec!["01010101".to_owned()],
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...67890"),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(s.contains("sa_signer_removed"), "kind discriminant: {s}");
    }

    /// Round-trip for `SaThresholdChanged`.
    #[test]
    fn event_kind_sa_threshold_changed_round_trip() {
        use crate::audit_log::signer_set::SignerPubkey;
        let ev = EventKind::SaThresholdChanged {
            rule_id: 3,
            old_threshold: 1,
            new_threshold: 2,
            resulting_threshold: 2,
            resulting_signer_count: 2,
            resulting_signer_ids: vec![0, 1],
            resulting_signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [0u8; 32] },
                SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
            ],
            resulting_signer_pubkeys_first8: vec!["00000000".to_owned(), "01010101".to_owned()],
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...11111"),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(s.contains("sa_threshold_changed"), "kind discriminant: {s}");
        assert!(s.contains("old_threshold"), "old_threshold field: {s}");
        assert!(s.contains("new_threshold"), "new_threshold field: {s}");
    }

    /// Round-trip for `SaSignerSetDiverged`.
    #[test]
    fn event_kind_sa_signer_set_diverged_round_trip() {
        let ev = EventKind::SaSignerSetDiverged {
            rule_id: 1,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...22222"),
            expected_signer_count: 3,
            observed_signer_count: 2,
            expected_threshold: 3,
            observed_threshold: 3,
            expected_signer_set_digest: "abcdef12...90abcdef".to_owned(),
            observed_signer_set_digest: "12345678...fedcba90".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_signer_set_diverged"),
            "kind discriminant: {s}"
        );
        assert!(
            s.contains("expected_signer_count"),
            "expected_signer_count: {s}"
        );
        assert!(
            s.contains("observed_signer_count"),
            "observed_signer_count: {s}"
        );
    }

    /// Round-trip for `SaSignerSetBaselined`.
    #[test]
    fn event_kind_sa_signer_set_baselined_round_trip() {
        use crate::audit_log::signer_set::{BaselineReason, SignerPubkey};
        let ev = EventKind::SaSignerSetBaselined {
            rule_id: 1,
            observed_signer_count: 2,
            observed_threshold: 2,
            observed_signer_ids: vec![0, 1],
            observed_signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [0u8; 32] },
                SignerPubkey::WebAuthn {
                    credential_id_first16: [0xccu8; 16],
                },
            ],
            observed_signer_pubkeys_first8: vec!["00000000".to_owned(), "cccccccc".to_owned()],
            observed_at_ledger_seq: 1_234_567,
            observed_at_unix_ms: 1_700_000_000_123,
            baseline_reason: BaselineReason::ExplicitRefresh,
            prev_chain_tip_hash: [0xddu8; 32],
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...33333"),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_signer_set_baselined"),
            "kind discriminant: {s}"
        );
        assert!(
            s.contains("observed_at_ledger_seq"),
            "observed_at_ledger_seq: {s}"
        );
        assert!(s.contains("baseline_reason"), "baseline_reason: {s}");
        assert!(
            s.contains("prev_chain_tip_hash"),
            "prev_chain_tip_hash: {s}"
        );
    }

    /// `SaSignerSetBaselined` with absent `smart_account_redacted` must fail
    /// deserialisation: the field is required (no `#[serde(default)]`), so a
    /// missing field is always a schema violation.
    #[test]
    fn event_kind_sa_signer_set_baselined_missing_smart_account_fails_deserialise() {
        use crate::audit_log::signer_set::{BaselineReason, SignerPubkey};
        let ev = EventKind::SaSignerSetBaselined {
            rule_id: 1,
            observed_signer_count: 1,
            observed_threshold: 1,
            observed_signer_ids: vec![0],
            observed_signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0u8; 32] }],
            observed_signer_pubkeys_first8: vec!["00000000".to_owned()],
            observed_at_ledger_seq: 1,
            observed_at_unix_ms: 1,
            baseline_reason: BaselineReason::FirstObservation,
            prev_chain_tip_hash: [0u8; 32],
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
        };
        // Serialise, then manually remove the required `smart_account_redacted` field.
        // Since #[serde(tag = "kind")] + #[serde(flatten)] places fields at the top
        // level, we manipulate the JSON map directly.
        let s = serde_json::to_string(&ev).unwrap();
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        let s_without = {
            let mut obj: serde_json::Map<String, serde_json::Value> =
                serde_json::from_value(json).unwrap();
            obj.remove("smart_account_redacted");
            serde_json::to_string(&obj).unwrap()
        };
        // Deserialisation must fail: `smart_account_redacted` is required.
        let result: Result<EventKind, _> = serde_json::from_str(&s_without);
        assert!(
            result.is_err(),
            "deserialising SaSignerSetBaselined without smart_account_redacted must fail; \
             got: {result:?}"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("smart_account_redacted"),
            "error message must name the missing field; got: {err_msg}"
        );
    }

    /// Round-trip for the `PasskeyRegistered` variant.
    #[test]
    fn event_kind_passkey_registered_round_trip() {
        let ev = EventKind::PasskeyRegistered {
            credential_name: "my-passkey".to_owned(),
            credential_id_redacted: "AABBCC...XXYYZZ".to_owned(),
            rp_id: "127.0.0.1".to_owned(),
            status: "registered".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        // Verify kind discriminant.
        assert!(
            s.contains("passkey_registered"),
            "kind discriminant must be passkey_registered: {s}"
        );
        // Verify required field names.
        assert!(s.contains("credential_name"), "credential_name field: {s}");
        assert!(
            s.contains("credential_id_redacted"),
            "credential_id_redacted field: {s}"
        );
        assert!(s.contains("rp_id"), "rp_id field: {s}");
        assert!(s.contains("status"), "status field: {s}");
    }

    /// Timeout status round-trips correctly via the `PasskeyRegistered` variant.
    #[test]
    fn event_kind_passkey_registered_timeout_round_trip() {
        let ev = EventKind::PasskeyRegistered {
            credential_name: "test".to_owned(),
            credential_id_redacted: "AAAAA...BBBBB".to_owned(),
            rp_id: "localhost".to_owned(),
            status: "timeout".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(s.contains("timeout"), "status value must appear: {s}");
    }

    /// Round-trip for the `SaContextRuleDeleted` variant.
    #[test]
    fn event_kind_sa_context_rule_deleted_round_trip() {
        let ev = EventKind::SaContextRuleDeleted {
            smart_account: "CDABC...XYZ12".to_owned(),
            rule_id: 42,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(s.contains("smart_account"), "smart_account field: {s}");
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        assert!(
            s.contains("sa_context_rule_deleted"),
            "kind discriminant must be snake_case: {s}"
        );
    }

    /// Round-trip for `SaVerifierHashDrift`.
    #[test]
    fn event_kind_sa_verifier_hash_drift_round_trip() {
        let ev = EventKind::SaVerifierHashDrift {
            rule_id: 7,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
            pinned_hash_first8: "aabbccdd".to_owned(),
            observed_hash_first8: "11223344".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_verifier_hash_drift"),
            "kind discriminant must be sa_verifier_hash_drift: {s}"
        );
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        assert!(
            s.contains("smart_account_redacted"),
            "smart_account_redacted field: {s}"
        );
        assert!(
            s.contains("deploy_address_redacted"),
            "deploy_address_redacted field: {s}"
        );
        assert!(
            s.contains("pinned_hash_first8"),
            "pinned_hash_first8 field: {s}"
        );
        assert!(
            s.contains("observed_hash_first8"),
            "observed_hash_first8 field: {s}"
        );
        // request_id is NOT a variant field — it is delegated to AuditEntry::request_id
        // (top-level field common to all event kinds).
        assert!(
            !s.contains("request_id"),
            "request_id must NOT appear as a variant field: {s}"
        );
    }

    /// `SaVerifierHashDrift` with missing fields MUST fail to deserialise.
    ///
    /// No `#[serde(default)]` on fields — serde defaults open silent data-integrity holes.
    #[test]
    fn event_kind_sa_verifier_hash_drift_missing_fields_fail() {
        // Omit all payload fields — must fail because fields have no defaults.
        let json = r#"{"kind":"sa_verifier_hash_drift"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaVerifierHashDrift"
        );
    }

    /// Round-trip for `SaPolicyHashDrift`.
    #[test]
    fn event_kind_sa_policy_hash_drift_round_trip() {
        let ev = EventKind::SaPolicyHashDrift {
            rule_id: 8,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            deploy_address_redacted: RedactedStrkey::from_already_redacted("CCCCC...DDDDD"),
            pinned_hash_first8: "eeff0011".to_owned(),
            observed_hash_first8: "22334455".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_policy_hash_drift"),
            "kind discriminant must be sa_policy_hash_drift: {s}"
        );
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        // request_id is NOT a variant field — delegated to AuditEntry::request_id.
        assert!(
            !s.contains("request_id"),
            "request_id must NOT appear as a variant field: {s}"
        );
    }

    /// `SaPolicyHashDrift` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_policy_hash_drift_missing_fields_fail() {
        let json = r#"{"kind":"sa_policy_hash_drift"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaPolicyHashDrift"
        );
    }

    /// Round-trip for `SaMutableContractOverride`.
    #[test]
    fn event_kind_sa_mutable_contract_override_round_trip() {
        let ev = EventKind::SaMutableContractOverride {
            rule_id: 9,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            contract_address_redacted: RedactedStrkey::from_already_redacted("CEFFE...11111"),
            contract_kind: ContractKind::Verifier,
            override_acknowledged_at: "2026-05-19T10:00:00Z".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_mutable_contract_override"),
            "kind discriminant must be sa_mutable_contract_override: {s}"
        );
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        assert!(
            s.contains("contract_address_redacted"),
            "contract_address_redacted field: {s}"
        );
        assert!(
            s.contains("verifier"),
            "contract_kind value must appear: {s}"
        );
        assert!(
            s.contains("override_acknowledged_at"),
            "override_acknowledged_at field: {s}"
        );
        assert!(s.contains("contract_kind"), "contract_kind field: {s}");
        // request_id is NOT a variant field — delegated to AuditEntry::request_id.
        assert!(
            !s.contains("request_id"),
            "request_id must NOT appear as a variant field: {s}"
        );
    }

    /// `SaMutableContractOverride` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_mutable_contract_override_missing_fields_fail() {
        let json = r#"{"kind":"sa_mutable_contract_override"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaMutableContractOverride"
        );
    }

    /// Round-trip for `SaUnknownContractOverride`.
    #[test]
    fn event_kind_sa_unknown_contract_override_round_trip() {
        let ev = EventKind::SaUnknownContractOverride {
            rule_id: 10,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            contract_address_redacted: RedactedStrkey::from_already_redacted("CFFFF...22222"),
            contract_kind: ContractKind::Policy,
            override_acknowledged_at: "2026-05-19T11:00:00Z".to_owned(),
            observed_hash_first8: "deadbeef".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_unknown_contract_override"),
            "kind discriminant must be sa_unknown_contract_override: {s}"
        );
        assert!(s.contains("policy"), "contract_kind value must appear: {s}");
        assert!(s.contains("contract_kind"), "contract_kind field: {s}");
        assert!(
            s.contains("observed_hash_first8"),
            "observed_hash_first8 must be present: {s}"
        );
        assert!(
            s.contains("deadbeef"),
            "observed_hash_first8 value must appear: {s}"
        );
        // request_id is NOT a variant field — delegated to AuditEntry::request_id.
        assert!(
            !s.contains("request_id"),
            "request_id must NOT appear as a variant field: {s}"
        );
    }

    /// `SaUnknownContractOverride` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_unknown_contract_override_missing_fields_fail() {
        let json = r#"{"kind":"sa_unknown_contract_override"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaUnknownContractOverride"
        );
    }

    /// `VerifierAdvisoryKind` Display and serde closed-set test.
    ///
    /// Verifies the two-value closed set serialises as snake_case strings and
    /// that Display matches the wire form.
    #[test]
    fn verifier_advisory_kind_closed_set_and_display() {
        let kinds = [VerifierAdvisoryKind::Revoked, VerifierAdvisoryKind::Retired];
        let expected_wire = ["\"revoked\"", "\"retired\""];
        let expected_display = ["revoked", "retired"];

        for ((kind, wire), display) in kinds
            .iter()
            .zip(expected_wire.iter())
            .zip(expected_display.iter())
        {
            let s = serde_json::to_string(kind).unwrap();
            assert_eq!(
                s, *wire,
                "VerifierAdvisoryKind::{kind:?} wire form must be {wire}"
            );
            assert_eq!(
                format!("{kind}"),
                *display,
                "VerifierAdvisoryKind::{kind:?} Display must be {display}"
            );
        }

        // Round-trip.
        for kind in &kinds {
            let s = serde_json::to_string(kind).unwrap();
            let back: VerifierAdvisoryKind = serde_json::from_str(&s).unwrap();
            assert_eq!(*kind, back, "VerifierAdvisoryKind must round-trip: {s}");
        }
    }

    #[test]
    fn verifier_advisory_kind_rejects_unknown_wire_string() {
        let result = serde_json::from_str::<VerifierAdvisoryKind>("\"deprecated\"");
        assert!(
            result.is_err(),
            "unknown VerifierAdvisoryKind strings must fail deserialisation"
        );
    }

    /// `SaVerifierMigrated` round-trip test.
    #[test]
    fn event_kind_sa_verifier_migrated_round_trip() {
        let ev = EventKind::SaVerifierMigrated {
            rule_id: 4,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            from_hash_first8: "deadbeef".to_owned(),
            to_hash_first8: "cafebabe".to_owned(),
            tx_hash_redacted: "aabb1122...ccdd3344".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(s.contains("sa_verifier_migrated"), "kind discriminant: {s}");
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        assert!(
            s.contains("smart_account_redacted"),
            "smart_account_redacted field: {s}"
        );
        assert!(
            s.contains("from_hash_first8"),
            "from_hash_first8 field: {s}"
        );
        assert!(s.contains("to_hash_first8"), "to_hash_first8 field: {s}");
        assert!(
            s.contains("tx_hash_redacted"),
            "tx_hash_redacted field: {s}"
        );
    }

    /// `SaVerifierMigrated` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_verifier_migrated_missing_fields_fail() {
        let json = r#"{"kind":"sa_verifier_migrated"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaVerifierMigrated"
        );
    }

    /// `SaVerifierDiversificationOverride` round-trip test.
    #[test]
    fn event_kind_sa_verifier_diversification_override_round_trip() {
        let ev = EventKind::SaVerifierDiversificationOverride {
            rule_id: 7,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
            verifier_hash_first8: "deadbeef".to_owned(),
            observed_value_threshold_stroops: 100_000_000_000_i64,
            override_acknowledged_at: "2026-05-20T12:34:56.000Z".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            s.contains("sa_verifier_diversification_override"),
            "kind discriminant: {s}"
        );
        assert!(s.contains("rule_id"), "rule_id field: {s}");
        assert!(
            s.contains("verifier_hash_first8"),
            "verifier_hash_first8 field: {s}"
        );
        assert!(
            s.contains("observed_value_threshold_stroops"),
            "observed_value_threshold_stroops field: {s}"
        );
        assert!(
            s.contains("override_acknowledged_at"),
            "override_acknowledged_at field: {s}"
        );
    }

    /// `SaVerifierDiversificationOverride` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_verifier_diversification_override_missing_fields_fail() {
        let json = r#"{"kind":"sa_verifier_diversification_override"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaVerifierDiversificationOverride"
        );
    }

    /// `SaVerifierAllowlistAdvisory` round-trip test.
    ///
    /// Tests both `Revoked` and `Retired` advisory status values.
    #[test]
    fn event_kind_sa_verifier_allowlist_advisory_round_trip() {
        for (advised_status, expected_wire) in &[
            (VerifierAdvisoryKind::Revoked, "revoked"),
            (VerifierAdvisoryKind::Retired, "retired"),
        ] {
            let ev = EventKind::SaVerifierAllowlistAdvisory {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CDABC...12345"),
                revoked_hash_first8: "aabbccdd".to_owned(),
                advised_status: *advised_status,
            };
            let s = serde_json::to_string(&ev).unwrap();
            let back: EventKind = serde_json::from_str(&s).unwrap();
            assert_eq!(
                ev, back,
                "round-trip failed for advised_status={expected_wire}"
            );
            assert!(
                s.contains("sa_verifier_allowlist_advisory"),
                "kind discriminant: {s}"
            );
            assert!(s.contains("rule_id"), "rule_id field: {s}");
            assert!(
                s.contains("revoked_hash_first8"),
                "revoked_hash_first8 field: {s}"
            );
            assert!(
                s.contains(expected_wire),
                "advised_status wire form '{expected_wire}' must appear: {s}"
            );
        }
    }

    /// `SaVerifierAllowlistAdvisory` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_verifier_allowlist_advisory_missing_fields_fail() {
        let json = r#"{"kind":"sa_verifier_allowlist_advisory"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaVerifierAllowlistAdvisory"
        );
    }

    /// Asserts `SaPolicyAdded` serialises with the correct wire discriminant
    /// and all required fields, and round-trips cleanly.
    #[test]
    fn event_kind_sa_policy_added_round_trip() {
        let ev = EventKind::SaPolicyAdded {
            rule_id: 3,
            policy_id: 7,
            policy_address_redacted: RedactedStrkey::from_already_redacted("CAABB...ZZXYY"),
            transaction_hash_redacted: "abcd1234...ef567890".to_owned(),
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...BBBBB"),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back, "SaPolicyAdded must round-trip cleanly");
        assert!(
            s.contains("\"sa_policy_added\""),
            "wire discriminant must be 'sa_policy_added': {s}"
        );
        assert!(
            s.contains("\"rule_id\""),
            "rule_id field must be present: {s}"
        );
        assert!(
            s.contains("\"policy_id\""),
            "policy_id field must be present: {s}"
        );
        assert!(
            s.contains("\"policy_address_redacted\""),
            "policy_address_redacted field must be present: {s}"
        );
        assert!(
            s.contains("\"transaction_hash_redacted\""),
            "transaction_hash_redacted field must be present: {s}"
        );
        assert!(
            s.contains("\"smart_account_redacted\""),
            "smart_account_redacted field must be present: {s}"
        );
    }

    /// `SaPolicyAdded` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_policy_added_missing_fields_fail() {
        let json = r#"{"kind":"sa_policy_added"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaPolicyAdded"
        );
    }

    /// Asserts `SaPolicyRemoved` serialises with the correct wire discriminant
    /// and all required fields, and round-trips cleanly.
    #[test]
    fn event_kind_sa_policy_removed_round_trip() {
        let ev = EventKind::SaPolicyRemoved {
            rule_id: 1,
            policy_id: 2,
            transaction_hash_redacted: "11223344...55667788".to_owned(),
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...BBBBB"),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back, "SaPolicyRemoved must round-trip cleanly");
        assert!(
            s.contains("\"sa_policy_removed\""),
            "wire discriminant must be 'sa_policy_removed': {s}"
        );
        assert!(
            s.contains("\"rule_id\""),
            "rule_id field must be present: {s}"
        );
        assert!(
            s.contains("\"policy_id\""),
            "policy_id field must be present: {s}"
        );
        assert!(
            s.contains("\"transaction_hash_redacted\""),
            "transaction_hash_redacted field must be present: {s}"
        );
        assert!(
            s.contains("\"smart_account_redacted\""),
            "smart_account_redacted field must be present: {s}"
        );
    }

    /// `SaPolicyRemoved` with missing fields MUST fail to deserialise.
    #[test]
    fn event_kind_sa_policy_removed_missing_fields_fail() {
        let json = r#"{"kind":"sa_policy_removed"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for SaPolicyRemoved"
        );
    }

    /// Asserts `ApprovalAttested` serialises with the correct wire discriminant
    /// and all required fields, and round-trips cleanly.
    #[test]
    fn event_kind_approval_attested_round_trip() {
        let ev = EventKind::ApprovalAttested {
            approval_kind: "PaymentSimulated".to_owned(),
            gated_tool: "stellar_pay_commit".to_owned(),
            envelope_sha256_hex: Some("a".repeat(64)),
            nonce_prefix: "AAAAAAAA".to_owned(),
            origin: "cli".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back, "ApprovalAttested must round-trip cleanly");
        assert!(
            s.contains("\"approval_attested\""),
            "wire discriminant must be 'approval_attested': {s}"
        );
        assert!(s.contains("\"approval_kind\""), "approval_kind field: {s}");
        assert!(s.contains("\"gated_tool\""), "gated_tool field: {s}");
        assert!(
            s.contains("\"envelope_sha256_hex\""),
            "envelope_sha256_hex field: {s}"
        );
        assert!(s.contains("\"nonce_prefix\""), "nonce_prefix field: {s}");
        assert!(s.contains("\"origin\""), "origin field: {s}");
    }

    /// `envelope_sha256_hex` is sparse: absent for kinds with no signed
    /// envelope (`ToolsetFirstInvokeGate`, `TrustlineClawbackOptIn`).
    #[test]
    fn event_kind_approval_attested_omits_absent_envelope_hash() {
        let ev = EventKind::ApprovalAttested {
            approval_kind: "ToolsetFirstInvokeGate".to_owned(),
            gated_tool: "toolset:my-toolset:sign-payment".to_owned(),
            envelope_sha256_hex: None,
            nonce_prefix: "AAAAAAAA".to_owned(),
            origin: "cli".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(
            !s.contains("envelope_sha256_hex"),
            "absent envelope_sha256_hex must be skipped, not null: {s}"
        );
    }

    /// `ApprovalAttested` with missing required fields MUST fail to deserialise.
    #[test]
    fn event_kind_approval_attested_missing_fields_fail() {
        let json = r#"{"kind":"approval_attested"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for ApprovalAttested"
        );
    }

    /// Asserts `ApprovalRejected` serialises with the correct wire discriminant
    /// and all required fields, and round-trips cleanly.
    #[test]
    fn event_kind_approval_rejected_round_trip() {
        let ev = EventKind::ApprovalRejected {
            approval_kind: "PaymentSimulated".to_owned(),
            nonce_prefix: "BBBBBBBB".to_owned(),
            origin: "serve".to_owned(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: EventKind = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back, "ApprovalRejected must round-trip cleanly");
        assert!(
            s.contains("\"approval_rejected\""),
            "wire discriminant must be 'approval_rejected': {s}"
        );
        assert!(s.contains("\"approval_kind\""), "approval_kind field: {s}");
        assert!(s.contains("\"nonce_prefix\""), "nonce_prefix field: {s}");
        assert!(s.contains("\"origin\""), "origin field: {s}");
    }

    /// `ApprovalRejected` with missing required fields MUST fail to deserialise.
    #[test]
    fn event_kind_approval_rejected_missing_fields_fail() {
        let json = r#"{"kind":"approval_rejected"}"#;
        let result: Result<EventKind, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing-field deserialisation must fail for ApprovalRejected"
        );
    }

    /// Neither new variant's fields collide with the flattened outer
    /// `AuditEntry::request_id` — a full `AuditEntry` round-trip must produce
    /// exactly one `request_id` key and deserialise back cleanly (the
    /// serde-flatten collision class documented on `SaContextRuleNameUpdated`).
    #[test]
    fn approval_attested_and_rejected_do_not_collide_with_outer_request_id() {
        use crate::audit_log::entry::AuditEntry;

        let attested = AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            Some("a".repeat(64)),
            "AAAAAAAAAAAAAAAAAAAAAA",
            "cli",
            "00000000-0000-0000-0000-0000000000a1",
        );
        let s = serde_json::to_string(&attested).unwrap();
        assert_eq!(
            s.matches("\"request_id\"").count(),
            1,
            "exactly one request_id key must appear: {s}"
        );
        let back: AuditEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.request_id, attested.request_id);

        let rejected = AuditEntry::new_approval_rejected(
            "PaymentSimulated",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "cli",
            "00000000-0000-0000-0000-0000000000a2",
        );
        let s = serde_json::to_string(&rejected).unwrap();
        assert_eq!(
            s.matches("\"request_id\"").count(),
            1,
            "exactly one request_id key must appear: {s}"
        );
        let back: AuditEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.request_id, rejected.request_id);
    }
}

//! Shared attest path for a pending approval.
//!
//! The `stellar-agent approve --id <nonce> --profile <name>` CLI command and
//! server-driven approval surfaces share this canonical path.
//! [`load_and_validate_entry`] checks the nonce, expiry, attestation state, and
//! process UID. [`attest_and_persist`] dispatches each kind to its HMAC and
//! persistence path. The CLI crate owns the tty prompt, exit-code mapping,
//! and JSON rendering.
//!
//! # Layering note: the `ToolsetFirstInvokeGate` grant step
//!
//! `stellar-agent-toolsets-runtime` (which owns `record_first_invoke_grant`,
//! the durable-grant persistence path) depends on `stellar-agent-core`, not
//! the reverse — core calling into it directly would be an illegal dependency
//! cycle. [`attest_and_persist`] therefore takes the grant-persistence step as
//! an injected closure (`persist_toolset_grant`). Core owns the validation,
//! the per-kind dispatch, the sequencing (write the consent row, persist the
//! grant, then consume the pending entry), and the audit emission. Only the
//! literal `record_first_invoke_grant` call is supplied by the caller, which
//! already depends on `stellar-agent-toolsets-runtime`.
//!
//! # Consent row before the approval
//!
//! [`attest_and_persist`] writes the consent row through a required
//! [`ConsentAudit`] sink before it persists anything. A sink that refuses
//! refuses the approval with nothing persisted.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use zeroize::Zeroizing;

use crate::audit_log::entry::AuditEntry;
use crate::audit_log::outbox::AuditOutbox;
use crate::audit_log::writer::{AuditWriter, WriterError, audit_writer_refusal};
use crate::error::{InternalError, WalletError};
use crate::keyring_errors::map_keyring_error;
use crate::profile::schema::KeyringEntryRef;
use crate::timefmt;

use super::attestation::{compute_attestation, compute_trustline_clawback_opt_in_digest};
use super::error::ApprovalError;
use super::store::{ApprovalKind, PendingApproval, PendingApprovalStore};
use super::user_id::ApproverIdentity;

// ─────────────────────────────────────────────────────────────────────────────
// Surface
// ─────────────────────────────────────────────────────────────────────────────

/// Which UI surface drove an attest or reject action.
///
/// Carried into the `ApprovalAttested` / `ApprovalRejected` audit events so
/// the forensic record distinguishes the interactive CLI path from a
/// server-driven approve surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Surface {
    /// The `stellar-agent approve --id <nonce> --profile <name>` CLI command.
    Cli,
    /// A resident, server-driven approve surface bound to loopback.
    Serve,
    /// A resident, server-driven approve surface reachable from beyond
    /// loopback, authenticated by a passkey-authenticated
    /// [`super::user_id::ApproverIdentity::PasskeyCredential`] identity
    /// rather than the OS process boundary.
    ServeRemote,
}

impl Surface {
    /// Returns the wire string for this surface (`"cli"`, `"serve"`, or
    /// `"serve-remote"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Serve => "serve",
            Self::ServeRemote => "serve-remote",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolsetGrantRequest — injected-closure parameters for the grant step
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for the caller-supplied `persist_toolset_grant` closure passed
/// to [`attest_and_persist`].
///
/// The caller forwards all fields, including `binding`, `process_uid`,
/// `now_unix_ms`, and the attestation key into
/// `stellar_agent_toolsets_runtime::record_first_invoke_grant`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ToolsetGrantRequest<'a> {
    /// Profile and chain binding forwarded to the grant attester.
    pub binding: &'a super::AttestationBinding<'a>,
    /// Name of the toolset requesting signing-adjacent capability access.
    pub toolset_name: &'a str,
    /// The signing-adjacent capability token being requested.
    pub capability: &'a str,
    /// Canonical G-strkey destination address from the authoritative envelope.
    pub destination: &'a str,
    /// Full asset identifier (`"XLM"` or `"<code>:<G-strkey>"`).
    pub asset: &'a str,
    /// Minimum amount bound in stroops for this grant bucket.
    pub amount_min_stroops: i64,
    /// Maximum amount bound in stroops for this grant bucket.
    pub amount_max_stroops: i64,
    /// Platform-stable user identity bound into the grant.
    pub process_uid: &'a str,
    /// Current time, read once by [`attest_and_persist`] so the grant and any
    /// subsequent store mutation share a single clock read.
    pub now_unix_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// load_and_validate_entry
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the pending approval entry for `nonce`, validating expiry,
/// already-attested state, and the caller's identity binding.
///
/// `identity` is an [`ApproverIdentity`] rather than a raw `process_uid: &str`
/// so a remote-approval mode can bind a different identity kind without
/// changing this signature. For [`ApproverIdentity::OsUid`],
/// [`ApproverIdentity::is_authorized_for_entry`] compares against the stored
/// entry's `process_uid` exactly as the pre-abstraction `process_uid: &str`
/// parameter was — byte-identical wire behaviour, and `allowed_credentials`
/// is not consulted. For [`ApproverIdentity::PasskeyCredential`], the check
/// instead requires the identity's credential ID to be non-empty and present
/// in `allowed_credentials` — the profile's operator-approval allowlist —
/// AND the identity's verified-assertion witness to be bound to this exact
/// entry's nonce, regardless of the entry's stored `process_uid`. The
/// nonce-binding check is what prevents a witness verified for one pending
/// entry's per-action challenge from ever authorizing a different entry.
/// Passing an empty `allowed_credentials` slice is the correct call for any
/// surface that only ever constructs `OsUid` identities (the CLI and the
/// loopback serve surface today): the slice is simply never read on that
/// path.
///
/// # Errors
///
/// Returns a [`WalletError`] (all `Internal(UnexpectedState)` with a
/// `approval.*` detail prefix) when: the nonce is unknown
/// (`approval.not_found`); the entry has expired (`approval.expired`); the
/// entry is already attested (`approval.already_attested`); or the
/// caller's identity is not authorized against the entry
/// (`approval.user_mismatch`).
pub fn load_and_validate_entry(
    store: &PendingApprovalStore,
    nonce: &str,
    identity: &ApproverIdentity,
    allowed_credentials: &[String],
) -> Result<PendingApproval, WalletError> {
    let entry = store.get(nonce).cloned().ok_or_else(|| {
        // Distinguishable UX error: indistinguishability is required for the
        // MCP commit path, not for this wallet-controlled attest path.
        WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.not_found: no pending approval with that nonce".to_owned(),
        })
    })?;

    let now_ms = timefmt::now_unix_ms().map_err(|e| map_clock_error(&e))?;
    if entry.is_expired(now_ms) {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.expired: this pending approval has expired".to_owned(),
        }));
    }

    if entry.attestation_blob_b64.is_some() {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.already_attested: this pending approval has already been attested"
                .to_owned(),
        }));
    }

    if !identity.is_authorized_for_entry(
        &entry.process_uid,
        &entry.approval_nonce,
        allowed_credentials,
    ) {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.user_mismatch: this pending approval was created by a different \
                     local user (process_uid mismatch), or the presented passkey credential is \
                     not authorized for this profile; this caller cannot attest it"
                .to_owned(),
        }));
    }

    Ok(entry)
}

fn map_clock_error(err: &crate::wallet::WalletLifecycleError) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: format!("approval.clock_error: system clock error: {err}"),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_sha256_hex
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a lowercase-hex SHA-256 string into a `[u8; 32]`.
///
/// # Errors
///
/// Returns `approval.sha256_hex_error` if `hex` is not exactly 64 characters
/// or contains non-hex-digit bytes.
pub fn decode_sha256_hex(hex: &str) -> Result<[u8; 32], WalletError> {
    if hex.len() != 64 {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "approval.sha256_hex_error: expected 64 hex chars, got {}",
                hex.len()
            ),
        }));
    }

    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|_| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.sha256_hex_error: non-UTF8 in hex string".to_owned(),
            })
        })?;
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|_| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approval.sha256_hex_error: invalid hex byte '{byte_str}'"),
            })
        })?;
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// load_attestation_key
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the attestation HMAC key from the platform keyring.
///
/// The platform keyring store must already be initialised (via
/// `stellar_agent_network::keyring::init_platform_keyring_store` or
/// equivalent) before calling this function — that bootstrap step stays with
/// the caller, since it is a process-wide, one-time registration rather than
/// part of the per-approval attest path.
///
/// A coordinate in the owner key namespace is refused before any keyring read,
/// and a loaded key equal to the owner public key at a coordinate of `owner`
/// is refused after decoding. Both refusals are
/// [`crate::error::ValidationError::KeyMatchesOwnerPublicKey`] for
/// `attestation_key_id`.
///
/// # Errors
///
/// Returns a [`WalletError`] when the keyring entry is missing or contains
/// invalid base64/wrong-length data, when the key is or may be the owner
/// public key, or when an owner entry cannot be read.
pub fn load_attestation_key(
    entry_ref: &KeyringEntryRef,
    owner: &crate::profile::owner_key::OwnerKeyContext,
) -> Result<Zeroizing<Vec<u8>>, WalletError> {
    crate::profile::owner_key::refuse_owner_key_coordinate(entry_ref, ATTESTATION_KEY_FIELD)?;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "keyring Entry::new failed for attestation key"
        );
        map_keyring_error(&e, &entry_ref.service)
    })?;

    let secret_b64 = Zeroizing::new(entry.get_password().map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "get_password failed for attestation key"
        );
        map_keyring_error(&e, &entry_ref.service)
    })?);

    let key_bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret_b64.as_bytes()).map_err(|e| {
        tracing::debug!(error = %e, "attestation key base64 decode failed");
        WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.key_decode_failed: attestation key is not valid base64".to_owned(),
        })
    })?);

    if key_bytes.len() != 32 {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "approval.key_length_error: attestation key must be 32 bytes, got {}",
                key_bytes.len()
            ),
        }));
    }

    crate::profile::owner_key::refuse_owner_public_key(&key_bytes, owner, ATTESTATION_KEY_FIELD)?;
    Ok(key_bytes)
}

/// The profile field an attestation-key refusal names.
pub const ATTESTATION_KEY_FIELD: &str = "attestation_key_id";

// ─────────────────────────────────────────────────────────────────────────────
// ConsentAudit
// ─────────────────────────────────────────────────────────────────────────────

/// Where [`attest_and_persist`] writes the consent row.
///
/// The row is durable in the log or in the log's outbox before the approval
/// takes effect, and a sink that refuses refuses the approval.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConsentAudit<'a> {
    /// Append the row through the audit writer this process holds. A
    /// draining writer drains the outbox before the row.
    Writer(&'a mut AuditWriter),
    /// Queue the row in the audit outbox, for the draining writer in another
    /// process that holds the log. That writer appends it before any process
    /// loads a signing key for the approved action.
    Outbox(&'a AuditOutbox),
}

impl ConsentAudit<'_> {
    fn write(&mut self, entry: AuditEntry) -> Result<(), WriterError> {
        match self {
            Self::Writer(writer) => writer.write_entry(entry),
            Self::Outbox(outbox) => outbox.append(&entry),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// attest_and_persist
// ─────────────────────────────────────────────────────────────────────────────

/// Computes and persists the operator's attestation (or recorded consent) for
/// a pending approval, dispatching on [`ApprovalKind`].
///
/// Returns `Some(base64url_blob)` for `PaymentSimulated`, `ClaimSimulated`,
/// `RuleProposalSimulated`, and `MppChargeSimulated`: the attestation the agent
/// surface presents as `approval_attestation` to the matching `*_commit` tool,
/// or that the MPP gate reads from the store. Returns `None` for
/// `ToolsetFirstInvokeGate` and `TrustlineClawbackOptIn`, whose gates read the
/// recorded consent from the store directly and take no attestation argument.
///
/// Every arm runs in the same order:
///
/// 1. Re-read the entry from the locked `store` and refuse unless it is the
///    same pending entry the caller validated, with the code the store would
///    give for the same condition. One clock read serves this check and the
///    store's own expiry check.
/// 2. Write the consent row through `audit`: `ApprovalAttested`, or
///    `ApprovalAttestedRemote` with the operator's redacted credential
///    pseudonym when `operator_credential_id_b64url` is `Some`. The row is
///    fatal: when the sink refuses, nothing is persisted and the sink's error
///    is returned.
/// 3. Persist the attestation, the grant, or the consent. A persist failure
///    after the row returns that failure, and the row then records a consent
///    that did not take effect.
///
/// # Errors
///
/// Returns a [`WalletError`] in each of these cases:
///
/// - Validation: a key-length mismatch, a hash-decode failure, a binding
///   mismatch, or an `entry.kind` that is not one of the attestable kinds.
///   `ApprovalKind::Rejected` and `ApprovalKind::Consumed` are tombstones and
///   can never be attested.
/// - An entry that changed since validation: `approval.not_found`,
///   `approval.expired`, `approval.already_attested`, `approval.rejected`,
///   `approval.consumed`, or `approval.wrong_kind`.
/// - A refused consent row, with the `audit.*` code of the refusal.
/// - A store or `persist_toolset_grant` failure after the row.
#[allow(
    clippy::too_many_arguments,
    reason = "every attester passes the store, the entry, the key, the binding and the surface explicitly"
)]
#[allow(
    clippy::too_many_lines,
    reason = "one arm per attestable kind, each in the re-read, row, persist order"
)]
pub fn attest_and_persist(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &[u8],
    binding: &super::AttestationBinding<'_>,
    surface: Surface,
    mut audit: ConsentAudit<'_>,
    operator_credential_id_b64url: Option<&str>,
    persist_toolset_grant: impl FnOnce(&ToolsetGrantRequest<'_>, &[u8; 32]) -> Result<(), String>,
) -> Result<Option<String>, WalletError> {
    let binding_matches = match &entry.kind {
        ApprovalKind::RuleProposalSimulated { chain_id, .. } => chain_id == binding.chain_id,
        ApprovalKind::MppChargeSimulated {
            profile, chain_id, ..
        } => profile == binding.profile_name && chain_id == binding.chain_id,
        _ => true,
    };
    if !binding_matches {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.binding_mismatch: this request belongs to another profile or network"
                .to_owned(),
        }));
    }
    let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "approval.key_length_error: attestation key must be 32 bytes, got {}",
                key_bytes.len()
            ),
        })
    })?;

    // One clock read serves the re-read's expiry check and the store's own.
    let now_ms = timefmt::now_unix_ms().map_err(|e| map_clock_error(&e))?;
    refuse_unless_still_pending(store, entry, now_ms)?;
    let profile = binding.profile_name;

    // `Some(blob)` is the attestation the agent surface must present to the
    // matching `*_commit` tool; `None` for approval kinds whose gate reads the
    // recorded consent from the store and takes no attestation argument.
    //
    // Every arm writes the consent row before it persists anything, so an
    // approval never takes effect without its row.
    let surfaced_attestation: Option<String> = match &entry.kind {
        ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } => {
            let presented_sha256 = decode_sha256_hex(envelope_sha256_hex)?;
            let attestation_blob = compute_attestation(
                &key_arr,
                binding,
                &entry.approval_nonce,
                &presented_sha256,
                &entry.process_uid,
            );
            emit_attested_audit(
                &mut audit,
                profile,
                "PaymentSimulated",
                "stellar_pay_commit",
                Some(envelope_sha256_hex.clone()),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            record_attestation_on_store(store, &entry.approval_nonce, attestation_blob, now_ms)?;
            Some(URL_SAFE_NO_PAD.encode(attestation_blob))
        }
        ApprovalKind::ClaimSimulated {
            envelope_sha256_hex,
            ..
        } => {
            // ClaimSimulated shares the envelope-hash HMAC attestation path with
            // PaymentSimulated: the blob binds the envelope SHA-256, the nonce,
            // and the process UID, and is surfaced to `stellar_claim_commit`.
            let presented_sha256 = decode_sha256_hex(envelope_sha256_hex)?;
            let attestation_blob = compute_attestation(
                &key_arr,
                binding,
                &entry.approval_nonce,
                &presented_sha256,
                &entry.process_uid,
            );
            emit_attested_audit(
                &mut audit,
                profile,
                "ClaimSimulated",
                "stellar_claim_commit",
                Some(envelope_sha256_hex.clone()),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            record_attestation_on_store(store, &entry.approval_nonce, attestation_blob, now_ms)?;
            Some(URL_SAFE_NO_PAD.encode(attestation_blob))
        }
        ApprovalKind::ToolsetFirstInvokeGate {
            toolset_name,
            capability,
            destination,
            asset,
            amount_min_stroops,
            amount_max_stroops,
        } => {
            // A `ToolsetFirstInvokeGate` entry MUST NOT use `record_attestation_on_store`
            // (which calls `store.record_attestation` — PaymentSimulated/ClaimSimulated-only,
            // returns `WrongKind` for this variant) and MUST NOT set
            // `attestation_blob_b64` on the entry (the ToolsetFirstInvokeGate
            // deserialiser rejects it as cross-kind contamination on the next
            // store reload).
            //
            // Correct flow for ToolsetFirstInvokeGate approval:
            //   1. Write the consent row.
            //   2. Build and persist the ToolsetGrant via the caller-injected
            //      `persist_toolset_grant` closure (see module docs for why this
            //      step cannot be a direct core-internal call).
            //   3. CONSUME (remove) the pending entry so it cannot be re-used.
            let request = ToolsetGrantRequest {
                binding,
                toolset_name,
                capability,
                destination,
                asset,
                amount_min_stroops: *amount_min_stroops,
                amount_max_stroops: *amount_max_stroops,
                process_uid: &entry.process_uid,
                now_unix_ms: now_ms,
            };
            emit_attested_audit(
                &mut audit,
                profile,
                "ToolsetFirstInvokeGate",
                &format!("toolset:{toolset_name}:{capability}"),
                None,
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            persist_toolset_grant(&request, &key_arr).map_err(|e| {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: format!("approval.grant_persist: {e}"),
                })
            })?;

            // Step 3: CONSUME the pending entry so it cannot be replayed.
            // A failure to remove is best-effort (the grant is already persisted).
            // Log a warning; the entry will expire via gc regardless.
            if let Err(e) = store.remove(&entry.approval_nonce) {
                tracing::warn!(
                    nonce = %entry.approval_nonce,
                    error = %e,
                    "ToolsetFirstInvokeGate: pending entry remove failed after grant persist; \
                     entry will expire via gc"
                );
            }

            tracing::debug!(
                toolset = %toolset_name,
                capability = %capability,
                "ToolsetFirstInvokeGate: grant persisted; pending entry consumed"
            );

            // The first-invoke gate reads the persisted grant from the grant
            // store at re-invoke time; the agent presents no attestation here.
            None
        }
        ApprovalKind::TrustlineClawbackOptIn {
            network,
            code,
            issuer,
        } => {
            // The commitment is the domain-separated SHA-256 of the
            // (network, code, issuer) triple — same domain-tag discipline as
            // ToolsetFirstInvokeGate.  The HMAC blob is written to
            // `attestation_blob_b64` on the pending entry; the trustline gate
            // clears only when `verify_attested_trustline_clawback_opt_in`
            // recomputes the digest and verifies this blob against the keyring key.
            let digest = compute_trustline_clawback_opt_in_digest(network, code, issuer);
            let attestation_blob = compute_attestation(
                &key_arr,
                binding,
                &entry.approval_nonce,
                &digest,
                &entry.process_uid,
            );
            emit_attested_audit(
                &mut audit,
                profile,
                "TrustlineClawbackOptIn",
                "stellar_trustline_commit",
                None,
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            store
                .record_trustline_clawback_opt_in_attestation_at(
                    &entry.approval_nonce,
                    attestation_blob,
                    now_ms,
                )
                .map_err(|e| record_error(&e))?;

            // The trustline clawback opt-in gate recomputes the digest and
            // verifies the stored blob; the agent presents no attestation here.
            None
        }
        ApprovalKind::RuleProposalSimulated {
            proposal_sha256, ..
        } => {
            // RuleProposalSimulated shares the digest-HMAC attestation path
            // with PaymentSimulated/ClaimSimulated: the blob binds
            // `proposal_sha256`, the nonce, and the process UID, and is
            // surfaced to `stellar_rule_create_commit`.
            let attestation_blob = compute_attestation(
                &key_arr,
                binding,
                &entry.approval_nonce,
                proposal_sha256,
                &entry.process_uid,
            );
            let proposal_sha256_hex = proposal_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            emit_attested_audit(
                &mut audit,
                profile,
                "RuleProposalSimulated",
                "stellar_rule_create_commit",
                Some(proposal_sha256_hex),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            store
                .record_rule_proposal_attestation_at(
                    &entry.approval_nonce,
                    attestation_blob,
                    now_ms,
                )
                .map_err(|e| record_error(&e))?;
            Some(URL_SAFE_NO_PAD.encode(attestation_blob))
        }
        ApprovalKind::MppChargeSimulated {
            prepared_artifact_hash,
            ..
        } => {
            let attestation_blob = compute_attestation(
                &key_arr,
                binding,
                &entry.approval_nonce,
                prepared_artifact_hash,
                &entry.process_uid,
            );
            emit_attested_audit(
                &mut audit,
                profile,
                "MppChargeSimulated",
                "stellar_mpp_charge_commit",
                Some(
                    prepared_artifact_hash
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                ),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            record_attestation_on_store(store, &entry.approval_nonce, attestation_blob, now_ms)?;
            Some(URL_SAFE_NO_PAD.encode(attestation_blob))
        }
        ApprovalKind::Rejected { .. } => {
            return Err(rejected_error());
        }
        ApprovalKind::Consumed { .. } => {
            return Err(consumed_error());
        }
        other => {
            return Err(WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "approval.wrong_kind: attest_and_persist does not support {}, \
                     expected PaymentSimulated, ClaimSimulated, MppChargeSimulated, \
                     ToolsetFirstInvokeGate, TrustlineClawbackOptIn, or RuleProposalSimulated",
                    other.kind_name()
                ),
            }));
        }
    };

    Ok(surfaced_attestation)
}

fn rejected_error() -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: "approval.rejected: this pending approval was rejected by the operator \
                 and cannot be attested"
            .to_owned(),
    })
}

fn consumed_error() -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: "approval.consumed: this pending approval was already spent on a \
                 submission and cannot be attested"
            .to_owned(),
    })
}

/// Refuses unless the locked `store` still holds the pending entry the caller
/// validated.
///
/// The caller validated `validated` earlier, possibly through another store
/// handle, and another process may have attested, rejected, consumed, or
/// replaced it since. The same pending entry means the whole `kind` value and
/// the `process_uid` are equal. Each refusal carries the code
/// [`record_attestation_on_store`] gives for the same condition, so a caller
/// maps both the same way. No row is written for a refused entry.
fn refuse_unless_still_pending(
    store: &PendingApprovalStore,
    validated: &PendingApproval,
    now_ms: u64,
) -> Result<(), WalletError> {
    let Some(current) = store.get(&validated.approval_nonce) else {
        return Err(record_error(&ApprovalError::NotFound));
    };
    if current.kind != validated.kind || current.process_uid != validated.process_uid {
        return Err(match current.kind {
            ApprovalKind::Rejected { .. } => rejected_error(),
            ApprovalKind::Consumed { .. } => consumed_error(),
            _ => WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.wrong_kind: the pending approval changed between validation \
                         and the attest"
                    .to_owned(),
            }),
        });
    }
    if current.is_expired(now_ms) {
        return Err(record_error(&ApprovalError::Expired));
    }
    if current.attestation_blob_b64.is_some() {
        return Err(record_error(&ApprovalError::AlreadyAttested));
    }
    Ok(())
}

/// Maps a store record failure to its `approval.*` refusal.
fn record_error(e: &ApprovalError) -> WalletError {
    match e {
        ApprovalError::NotFound => WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.not_found: entry disappeared between lookup and record".to_owned(),
        }),
        ApprovalError::Expired => WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.expired: entry expired between check and record".to_owned(),
        }),
        ApprovalError::AlreadyAttested => WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.already_attested: entry was attested by a concurrent process"
                .to_owned(),
        }),
        other => WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("approval.record_failed: {other}"),
        }),
    }
}

/// Helper: records an HMAC attestation blob on the store entry.
fn record_attestation_on_store(
    store: &mut PendingApprovalStore,
    approval_nonce: &str,
    attestation_blob: [u8; 32],
    now_ms: u64,
) -> Result<(), WalletError> {
    store
        .record_attestation_at(approval_nonce, attestation_blob, now_ms)
        .map_err(|e| record_error(&e))
}

/// Writes the consent row through `audit`, fatally.
///
/// A refusal is returned as the [`WalletError`] that names the condition. It
/// uses the variants and wire codes of the value verbs' audit pre-flight: a
/// tip-anchor mismatch, a condition about the log led by its `audit.*`
/// sub-code, or an open failure. The caller then persists nothing.
#[allow(
    clippy::too_many_arguments,
    reason = "flat row fields mirror the ApprovalAttested event schema"
)]
fn emit_attested_audit(
    audit: &mut ConsentAudit<'_>,
    profile: &str,
    approval_kind: &str,
    gated_tool: &str,
    envelope_sha256_hex: Option<String>,
    approval_nonce: &str,
    surface: Surface,
    operator_credential_id_b64url: Option<&str>,
) -> Result<(), WalletError> {
    let entry = match operator_credential_id_b64url {
        Some(cred_id) => AuditEntry::new_approval_attested_remote(
            approval_kind,
            gated_tool,
            envelope_sha256_hex,
            approval_nonce,
            cred_id,
            uuid::Uuid::new_v4().to_string(),
        ),
        None => AuditEntry::new_approval_attested(
            approval_kind,
            gated_tool,
            envelope_sha256_hex,
            approval_nonce,
            surface.as_str(),
            uuid::Uuid::new_v4().to_string(),
        ),
    };
    audit.write(entry).map_err(|e| {
        tracing::warn!(
            error = %e,
            approval_kind,
            "approval attest: the consent row was not written; nothing is persisted"
        );
        audit_writer_refusal(profile, &e)
    })
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
    use crate::approval::store::DEFAULT_TTL_MS;
    use crate::approval::user_id::process_uid_for_attestation;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    fn seed_key_32(service: &str, account: &str) -> [u8; 32] {
        let key = [0xABu8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(key);
        let entry = KeyringEntry::new(service, account).unwrap();
        entry.set_password(&encoded).unwrap();
        key
    }

    fn make_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            None,
            100,
            1_234_567,
            process_uid_for_attestation().expect("UID available on test host"),
            ttl_ms,
        )
        .unwrap()
    }

    /// Opens an unkeyed audit writer on a log inside `dir`.
    fn test_audit_writer(dir: &TempDir) -> AuditWriter {
        AuditWriter::open(dir.path().join("audit").join("audit.jsonl"), None).unwrap()
    }

    #[test]
    fn decode_sha256_hex_valid() {
        let hex = "a".repeat(64);
        assert!(decode_sha256_hex(&hex).is_ok());
    }

    #[test]
    fn decode_sha256_hex_wrong_length_fails() {
        let err = decode_sha256_hex("abcd").unwrap_err();
        assert!(err.to_string().contains("64"));
    }

    /// The owner context of the profile these loader tests name.
    fn test_owner() -> crate::profile::owner_key::OwnerKeyContext {
        crate::profile::owner_key::OwnerKeyContext::for_profile_name("core-test")
    }

    #[test]
    #[serial_test::serial]
    fn load_attestation_key_success() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-load";
        seed_key_32(svc, "default");
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let key = load_attestation_key(&entry_ref, &test_owner()).unwrap();
        assert_eq!(key.len(), 32);
    }

    /// An attestation key equal to the profile's owner public key in the older
    /// form refuses after decoding.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_refuses_the_owner_public_key() {
        use base64::Engine as _;
        keyring_mock::install().unwrap();
        let owner_bytes = [0x2b_u8; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(owner_bytes);
        let owner = KeyringEntryRef::default_owner_key("core-test");
        let attestation = KeyringEntryRef::new("stellar-agent-attestation-core-test", "default");
        for coordinate in [&owner, &attestation] {
            keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                .unwrap()
                .set_password(&encoded)
                .unwrap();
        }
        let Err(err) = load_attestation_key(&attestation, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(err.to_string().contains("attestation_key_id"));
    }

    /// A G-strkey owner value at the attestation coordinate decodes to 42
    /// bytes and is refused by the length rule.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_refuses_a_g_strkey_owner_value() {
        keyring_mock::install().unwrap();
        let attestation = KeyringEntryRef::new("stellar-agent-attestation-core-strkey", "default");
        keyring_core::Entry::new(&attestation.service, &attestation.account)
            .unwrap()
            .set_password(&crate::profile::owner_key::encode_owner_public_key(
                &[0x2b; 32],
            ))
            .unwrap();
        let Err(err) = load_attestation_key(&attestation, &test_owner()) else {
            panic!("the load refuses");
        };
        assert!(
            err.to_string()
                .contains("attestation key must be 32 bytes, got 42"),
            "{err}"
        );
    }

    /// A profile whose `policy_owner_key_id.account` is not `default` still
    /// compares against the owner entry the engine reads,
    /// `default_owner_key(name)`.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_compares_the_engine_coordinate_for_a_non_default_account() {
        use base64::Engine as _;
        keyring_mock::install().unwrap();
        let mut profile = crate::profile::schema::Profile::builder_testnet_named(
            "core-owner-acct",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        profile.policy_owner_key_id =
            KeyringEntryRef::new("stellar-agent-owner-core-owner-acct", "operator");
        let owner =
            crate::profile::owner_key::OwnerKeyContext::for_profile("core-owner-acct", &profile);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x3c_u8; 32]);
        let engine_coordinate = KeyringEntryRef::default_owner_key("core-owner-acct");
        let attestation =
            KeyringEntryRef::new("stellar-agent-attestation-core-owner-acct", "default");
        for coordinate in [&engine_coordinate, &attestation] {
            keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                .unwrap()
                .set_password(&encoded)
                .unwrap();
        }
        let Err(err) = load_attestation_key(&attestation, &owner) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
    }

    /// An attestation coordinate in another profile's owner namespace refuses
    /// before any keyring read: an error planted there is still pending.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_refuses_an_owner_coordinate_without_a_read() {
        keyring_mock::install().unwrap();
        let other_owner = KeyringEntryRef::new("stellar-agent-owner-B", "default");
        keyring_mock::inject_error(
            &other_owner.service,
            &other_owner.account,
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("planted"))),
        )
        .unwrap();
        let Err(err) = load_attestation_key(&other_owner, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        let pending = keyring_core::Entry::new(&other_owner.service, &other_owner.account)
            .unwrap()
            .get_password()
            .unwrap_err();
        assert!(
            matches!(pending, keyring_core::Error::PlatformFailure(_)),
            "the planted error is still pending, so no read happened: {pending:?}"
        );
    }

    /// A non-interactive Windows session (the `ERROR_NO_SUCH_LOGON_SESSION`
    /// shape injected at the attestation-key coordinates) must surface as
    /// `auth.keyring_interactive_session_required`, not `auth.keyring_not_found`.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_surfaces_interactive_session_required() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-no-logon";
        keyring_mock::inject_no_logon_session(svc, "default").unwrap();
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let Err(err) = load_attestation_key(&entry_ref, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "auth.keyring_interactive_session_required");
    }

    /// A platform-store failure at the attestation-key coordinates must surface
    /// as `auth.keyring_platform_error`, not `auth.keyring_not_found`.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_surfaces_platform_error() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-platform-err";
        keyring_mock::inject_error(
            svc,
            "default",
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(
                "simulated platform failure",
            ))),
        )
        .unwrap();
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let Err(err) = load_attestation_key(&entry_ref, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }

    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_success() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let uid = entry.process_uid.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let validated =
            load_and_validate_entry(&store, &nonce, &ApproverIdentity::OsUid(uid), &[]).unwrap();
        assert_eq!(validated.approval_nonce, nonce);
    }

    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_user_mismatch_fails() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let err = load_and_validate_entry(
            &store,
            &nonce,
            &ApproverIdentity::OsUid("different-uid".to_owned()),
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("approval.user_mismatch"));
    }

    /// GATE-IS-REAL: a `PasskeyCredential` identity reaching
    /// `load_and_validate_entry` — the single production gate every approve
    /// surface funnels through — is refused when its credential ID is not in
    /// `allowed_credentials`, even though the entry itself is otherwise valid
    /// (unexpired, unattested) and the identity carries a verified-assertion
    /// witness. This pins the fix for the fail-open risk of an always-true
    /// gate arm: a future regression that stops threading the allowlist (or
    /// reintroduces an unconditional pass) fails this test.
    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_refuses_non_allowlisted_passkey_credential() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "attacker-controlled-cred-id",
            crate::approval::user_id::VerifiedPasskeyAssertion::new_for_test(&nonce),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        let err = load_and_validate_entry(&store, &nonce, &identity, &allowed).unwrap_err();
        assert!(
            err.to_string().contains("approval.user_mismatch"),
            "unexpected error: {err}"
        );
    }

    /// GATE-IS-REAL, positive case: the same gate authorizes a
    /// `PasskeyCredential` identity whose credential ID IS present in
    /// `allowed_credentials`, proving the check is a genuine membership test
    /// rather than always refusing (which would make the earlier test
    /// vacuous).
    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_accepts_allowlisted_passkey_credential() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "enrolled-operator-cred-id",
            crate::approval::user_id::VerifiedPasskeyAssertion::new_for_test(&nonce),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        let validated = load_and_validate_entry(&store, &nonce, &identity, &allowed).unwrap();
        assert_eq!(validated.approval_nonce, nonce);
    }

    /// ENTRY-BINDING at the `load_and_validate_entry` layer: an allowlisted
    /// `PasskeyCredential` identity whose witness is bound to a DIFFERENT
    /// nonce than the entry being loaded is refused, even though the
    /// credential itself is allowlisted. Proves cross-entry replay is
    /// impossible through the production gate, not just through the
    /// `ApproverIdentity` unit tests in `user_id.rs`.
    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_refuses_witness_bound_to_different_entry() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "enrolled-operator-cred-id",
            // Bound to a different (well-formed but unrelated) nonce, not `nonce`.
            crate::approval::user_id::VerifiedPasskeyAssertion::new_for_test(
                "ZZZZZZZZZZZZZZZZZZZZZZ",
            ),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        let err = load_and_validate_entry(&store, &nonce, &identity, &allowed).unwrap_err();
        assert!(
            err.to_string().contains("approval.user_mismatch"),
            "unexpected error: {err}"
        );
    }

    fn assert_cross_bindings_refused(
        key: &[u8; 32],
        nonce: &str,
        digest: &[u8; 32],
        uid: &str,
        blob: &[u8; 32],
    ) {
        for binding in [
            crate::approval::AttestationBinding::new("b", "stellar:testnet"),
            crate::approval::AttestationBinding::new("a", "stellar:mainnet"),
        ] {
            assert!(!crate::approval::verify_attestation(
                key, &binding, nonce, digest, uid, blob
            ));
        }
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_payment_records_hmac_and_surfaces_blob() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-payment";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let path = dir.path().join("default.toml");
        let mut store = PendingApprovalStore::open(path).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();

        let envelope_sha256_hex = if let ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } = &entry.kind
        {
            envelope_sha256_hex.clone()
        } else {
            unreachable!("make_entry always produces PaymentSimulated")
        };

        store
            .insert(entry.clone(), timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let surfaced = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |_req, _key| Err("must not be called for PaymentSimulated".to_owned()),
        )
        .unwrap();
        let surfaced_blob = surfaced.expect("PaymentSimulated must surface its attestation blob");

        let final_entry = store.get(&nonce).unwrap();
        let blob_b64 = final_entry.attestation_blob_b64.as_ref().unwrap();
        assert_eq!(surfaced_blob, *blob_b64);

        let sha256_bytes = decode_sha256_hex(&envelope_sha256_hex).unwrap();
        let expected = compute_attestation(
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            &nonce,
            &sha256_bytes,
            &process_uid,
        );
        let persisted_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(persisted_bytes, expected);
        assert_cross_bindings_refused(
            &raw_key,
            &nonce,
            &sha256_bytes,
            &process_uid,
            &persisted_bytes,
        );
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rejected_tombstone_fails_closed() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rejected";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry, now_ms).unwrap();
        store.reject(&nonce, now_ms, 60_000).unwrap();

        let rejected_entry = store.get(&nonce).unwrap().clone();
        let err = attest_and_persist(
            &mut store,
            &rejected_entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |_req, _key| Err("must not be called".to_owned()),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("approval.rejected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_toolset_gate_invokes_closure_and_consumes_entry() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-toolset";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let uid = process_uid_for_attestation().unwrap();
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "XLM".to_owned(),
            0,
            1_000_000,
            uid,
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry.clone(), now_ms).unwrap();

        let surfaced = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |req, _key| {
                assert_eq!(req.toolset_name, "my-toolset");
                assert_eq!(req.capability, "sign-payment");
                Ok(())
            },
        );
        assert!(
            surfaced.unwrap().is_none(),
            "ToolsetFirstInvokeGate surfaces no attestation"
        );
        assert!(
            store.get(&nonce).is_none(),
            "ToolsetFirstInvokeGate entry must be consumed after grant persist"
        );
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_toolset_gate_closure_failure_propagates_and_keeps_entry() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-toolset-fail";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let uid = process_uid_for_attestation().unwrap();
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "XLM".to_owned(),
            0,
            1_000_000,
            uid,
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry.clone(), now_ms).unwrap();

        let err = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |_req, _key| Err("grant store unavailable".to_owned()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("approval.grant_persist"));
        assert!(
            store.get(&nonce).is_some(),
            "entry must survive a failed grant persist"
        );
    }

    fn make_rule_proposal_entry(ttl_ms: u64) -> PendingApproval {
        use crate::approval::rule_proposal::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };

        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        PendingApproval::new_rule_proposal_pending(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            "stellar:testnet".to_owned(),
            definition,
            [0x77u8; 32],
            "CallContract rule \"spend-daily\"".to_owned(),
            process_uid_for_attestation().expect("UID available on test host"),
            ttl_ms,
        )
        .unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rule_proposal_records_hmac_and_surfaces_blob() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rule-proposal";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let path = dir.path().join("default.toml");
        let mut store = PendingApprovalStore::open(path).unwrap();
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();

        let proposal_sha256 = if let ApprovalKind::RuleProposalSimulated {
            proposal_sha256, ..
        } = &entry.kind
        {
            *proposal_sha256
        } else {
            unreachable!("make_rule_proposal_entry always produces RuleProposalSimulated")
        };

        store
            .insert(entry.clone(), timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let surfaced = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |_req, _key| Err("must not be called for RuleProposalSimulated".to_owned()),
        )
        .unwrap();
        let surfaced_blob =
            surfaced.expect("RuleProposalSimulated must surface its attestation blob");

        let final_entry = store.get(&nonce).unwrap();
        let blob_b64 = final_entry.attestation_blob_b64.as_ref().unwrap();
        assert_eq!(surfaced_blob, *blob_b64);

        let expected = compute_attestation(
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            &nonce,
            &proposal_sha256,
            &process_uid,
        );
        let persisted_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(persisted_bytes, expected);
        assert_cross_bindings_refused(
            &raw_key,
            &nonce,
            &proposal_sha256,
            &process_uid,
            &persisted_bytes,
        );
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rule_proposal_rejected_tombstone_fails_closed() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rule-proposal-rejected";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry, now_ms).unwrap();
        store.reject(&nonce, now_ms, 60_000).unwrap();

        let rejected_entry = store.get(&nonce).unwrap().clone();
        let err = attest_and_persist(
            &mut store,
            &rejected_entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |_req, _key| Err("must not be called".to_owned()),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("approval.rejected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn attest_rule_refuses_stored_chain_mismatch() {
        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        store
            .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
            .unwrap();
        let error = attest_and_persist(
            &mut store,
            &entry,
            &[0x42; 32],
            &crate::approval::AttestationBinding::new("a", "stellar:mainnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("approval.binding_mismatch"));
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
    }

    #[test]
    fn attest_mpp_refuses_stored_profile_and_chain_mismatch() {
        for mismatch_profile in [true, false] {
            let dir = TempDir::new().unwrap();
            let mut audit_writer = test_audit_writer(&dir);
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            let now = timefmt::now_unix_ms().unwrap();
            let mut entry = PendingApproval::new_mpp_charge_pending(
                [0x11; 32],
                [0x22; 32],
                if mismatch_profile { "other" } else { "a" }.to_owned(),
                "stellar:testnet".to_owned(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                "mcp".to_owned(),
                "merchant".to_owned(),
                "tools/charge".to_owned(),
                "1000000".to_owned(),
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                now / 1_000 + 3_600,
                1_100,
                "1000".to_owned(),
                DEFAULT_TTL_MS,
            )
            .unwrap();
            store.insert(entry.clone(), now).unwrap();
            if !mismatch_profile
                && let ApprovalKind::MppChargeSimulated { chain_id, .. } = &mut entry.kind
            {
                *chain_id = "stellar:mainnet".to_owned();
            }
            let error = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
                Surface::Cli,
                ConsentAudit::Writer(&mut audit_writer),
                None,
                |_, _| Ok(()),
            )
            .unwrap_err();
            assert!(error.to_string().contains("approval.binding_mismatch"));
            assert!(
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .attestation_blob_b64
                    .is_none()
            );
        }
    }

    // ── The consent row before the persist, per kind ─────────────────────────

    const BINDING_PROFILE: &str = "a";

    fn binding() -> crate::approval::AttestationBinding<'static> {
        crate::approval::AttestationBinding::new(BINDING_PROFILE, "stellar:testnet")
    }

    /// One pending entry of every attestable kind, labelled.
    fn every_attestable_kind() -> Vec<(&'static str, PendingApproval)> {
        let uid = process_uid_for_attestation().unwrap();
        let now = timefmt::now_unix_ms().unwrap();
        vec![
            ("PaymentSimulated", make_entry(DEFAULT_TTL_MS)),
            (
                "ClaimSimulated",
                PendingApproval::new_claim_pending(
                    "b64xdr".to_owned(),
                    b"fake-xdr",
                    "a".repeat(72),
                    "B".to_owned() + &"A".repeat(57),
                    "XLM".to_owned(),
                    500,
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    100,
                    1,
                    uid.clone(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
            (
                "ToolsetFirstInvokeGate",
                PendingApproval::new_toolset_first_invoke_gate_pending(
                    "my-toolset".to_owned(),
                    "sign-payment".to_owned(),
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    "XLM".to_owned(),
                    0,
                    1_000_000,
                    uid.clone(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
            (
                "TrustlineClawbackOptIn",
                PendingApproval::new_trustline_clawback_opt_in_pending(
                    "stellar:testnet".to_owned(),
                    "USDC".to_owned(),
                    "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
                    uid,
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
            (
                "RuleProposalSimulated",
                make_rule_proposal_entry(DEFAULT_TTL_MS),
            ),
            (
                "MppChargeSimulated",
                PendingApproval::new_mpp_charge_pending(
                    [0x11; 32],
                    [0x22; 32],
                    BINDING_PROFILE.to_owned(),
                    "stellar:testnet".to_owned(),
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    "mcp".to_owned(),
                    "merchant".to_owned(),
                    "tools/charge".to_owned(),
                    "1000000".to_owned(),
                    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    now / 1_000 + 3_600,
                    1_100,
                    "1000".to_owned(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
        ]
    }

    /// Whether the store at `path`, read back from disk, still holds `nonce`
    /// as an unattested pending entry.
    fn still_pending(path: &std::path::Path, nonce: &str) -> bool {
        let store = PendingApprovalStore::open(path.to_path_buf()).unwrap();
        store
            .get(nonce)
            .is_some_and(|entry| entry.attestation_blob_b64.is_none())
    }

    fn consent_rows(dir: &TempDir) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.path().join("audit").join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "approval_attested")
            .collect()
    }

    #[test]
    fn a_refusing_writer_sink_persists_nothing_for_any_kind() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_path = dir.path().join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            let nonce = entry.approval_nonce.clone();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let mut writer = test_audit_writer(&dir);
            writer.set_appends_before_fault(Some(0));
            let mut grant_persisted = false;
            let err = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut writer),
                None,
                |_, _| {
                    grant_persisted = true;
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(err.code(), "audit.chain_key_unavailable", "{kind}: {err}");
            assert!(err.to_string().contains("audit.io_error"), "{kind}: {err}");
            drop(store);
            assert!(
                still_pending(&store_path, &nonce),
                "{kind}: nothing persisted"
            );
            assert!(!grant_persisted, "{kind}: no grant persisted");
            assert!(consent_rows(&dir).is_empty(), "{kind}");
        }
    }

    #[test]
    fn a_failing_outbox_sink_persists_nothing_for_any_kind() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_path = dir.path().join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            let nonce = entry.approval_nonce.clone();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let outbox = AuditOutbox::for_log(&dir.path().join("audit").join("audit.jsonl"));
            crate::audit_log::outbox::test_seam::arm_partial_write(outbox.path(), 9);
            let mut grant_persisted = false;
            let result = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Outbox(&outbox),
                None,
                |_, _| {
                    grant_persisted = true;
                    Ok(())
                },
            );
            crate::audit_log::outbox::test_seam::disarm(outbox.path());
            let err = result.unwrap_err();
            assert_eq!(err.code(), "audit.chain_key_unavailable", "{kind}: {err}");
            drop(store);
            assert!(
                still_pending(&store_path, &nonce),
                "{kind}: nothing persisted"
            );
            assert!(!grant_persisted, "{kind}: no grant persisted");
            assert_eq!(
                std::fs::read(outbox.path()).unwrap_or_default(),
                Vec::<u8>::new(),
                "{kind}: the refused append leaves no line"
            );
        }
    }

    /// The row is durable before the persist runs: a persist that fails after
    /// it leaves the row and returns the failure.
    #[cfg(unix)]
    #[test]
    fn the_consent_row_precedes_the_persist_for_every_kind() {
        use std::os::unix::fs::PermissionsExt as _;

        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_dir = dir.path().join("store");
            std::fs::create_dir(&store_dir).unwrap();
            let store_path = store_dir.join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let mut writer = test_audit_writer(&dir);
            let audit_path = dir.path().join("audit").join("audit.jsonl");
            // The store cannot persist; the grant closure observes the log.
            std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let mut row_before_grant = None;
            let result = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut writer),
                None,
                |_, _| {
                    row_before_grant = Some(
                        std::fs::read_to_string(&audit_path)
                            .unwrap_or_default()
                            .contains(r#""kind":"approval_attested""#),
                    );
                    Err("grant store unavailable".to_owned())
                },
            );
            std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(result.is_err(), "{kind}: the persist failure is returned");
            let rows = consent_rows(&dir);
            assert_eq!(rows.len(), 1, "{kind}: the row was written first");
            assert_eq!(rows[0]["approval_kind"], kind);
            if kind == "ToolsetFirstInvokeGate" {
                assert_eq!(row_before_grant, Some(true), "the row precedes the grant");
            }
        }
    }

    /// The store resolves the entry after the caller validated its copy. The
    /// mutation goes through the same locked handle `attest_and_persist`
    /// receives, which holds exactly what a fresh handle would read after
    /// another process wrote it.
    #[test]
    fn an_entry_attested_by_another_handle_since_validation_refuses_with_no_row() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            // `entry` is the validated copy. The store then resolves it.
            let expected_code = match kind {
                "TrustlineClawbackOptIn" => {
                    store
                        .record_trustline_clawback_opt_in_attestation(
                            &entry.approval_nonce,
                            [0x01; 32],
                        )
                        .unwrap();
                    "approval.already_attested"
                }
                "RuleProposalSimulated" => {
                    store
                        .record_rule_proposal_attestation(&entry.approval_nonce, [0x01; 32])
                        .unwrap();
                    "approval.already_attested"
                }
                "ToolsetFirstInvokeGate" => {
                    store.remove(&entry.approval_nonce).unwrap();
                    "approval.not_found"
                }
                _ => {
                    store
                        .record_attestation(&entry.approval_nonce, [0x01; 32])
                        .unwrap();
                    "approval.already_attested"
                }
            };
            let mut writer = test_audit_writer(&dir);
            let mut grant_persisted = false;
            let err = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut writer),
                None,
                |_, _| {
                    grant_persisted = true;
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(
                err.to_string().contains(&format!("{expected_code}: ")),
                "{kind}: {err}"
            );
            assert!(consent_rows(&dir).is_empty(), "{kind}: no row is written");
            assert!(!grant_persisted, "{kind}");
        }
    }

    /// Calls `attest_and_persist` with the validated copy `entry` against
    /// `store`, which already holds whatever another handle left there, and
    /// returns the refusal. A grant persisted on the way fails the test.
    fn attest_validated_copy(
        dir: &TempDir,
        store: &mut PendingApprovalStore,
        entry: &PendingApproval,
    ) -> WalletError {
        let mut writer = test_audit_writer(dir);
        let mut grant_persisted = false;
        let err = attest_and_persist(
            store,
            entry,
            &[0x42; 32],
            &binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut writer),
            None,
            |_, _| {
                grant_persisted = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!grant_persisted, "no grant is persisted");
        err
    }

    /// The stored entry expired after the caller validated its copy. The
    /// re-read refuses before the row, so no row records a consent the store
    /// then refuses.
    #[test]
    fn an_entry_that_expired_since_validation_refuses_with_no_row() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_path = dir.path().join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            // The stored entry is the validated one with its expiry passed.
            let mut stored = entry.clone();
            stored.expires_at_unix_ms = stored.created_at_unix_ms;
            store
                .insert(stored, entry.created_at_unix_ms.saturating_sub(1))
                .unwrap();
            assert!(!entry.is_expired(timefmt::now_unix_ms().unwrap()));

            let err = attest_validated_copy(&dir, &mut store, &entry);
            assert!(
                err.to_string().contains("approval.expired: "),
                "{kind}: {err}"
            );
            assert!(consent_rows(&dir).is_empty(), "{kind}: no row is written");
            drop(store);
            let reopened = PendingApprovalStore::open(store_path).unwrap();
            let left = reopened.get(&entry.approval_nonce);
            assert!(
                left.is_some_and(|e| e.attestation_blob_b64.is_none()),
                "{kind}: nothing is persisted"
            );
        }
    }

    /// Another process replaced the entry under the same nonce with one bound
    /// to another user. The re-read compares the `process_uid` as well as the
    /// kind, and refuses before the row.
    #[test]
    fn an_entry_whose_process_uid_changed_since_validation_refuses_with_no_row() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            let mut stored = entry.clone();
            stored.process_uid = "4242424242".to_owned();
            assert_ne!(stored.process_uid, entry.process_uid);
            store
                .insert(stored, timefmt::now_unix_ms().unwrap())
                .unwrap();

            let err = attest_validated_copy(&dir, &mut store, &entry);
            assert!(
                err.to_string().contains("approval.wrong_kind: "),
                "{kind}: {err}"
            );
            assert!(consent_rows(&dir).is_empty(), "{kind}: no row is written");
            let left = store.get(&entry.approval_nonce).unwrap();
            assert!(left.attestation_blob_b64.is_none(), "{kind}");
        }
    }

    #[test]
    fn a_rejected_entry_since_validation_refuses_with_its_own_code() {
        let entry = make_entry(DEFAULT_TTL_MS);
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
        store
            .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
            .unwrap();
        store
            .reject(
                &entry.approval_nonce,
                timefmt::now_unix_ms().unwrap(),
                60_000,
            )
            .unwrap();
        let err = attest_validated_copy(&dir, &mut store, &entry);
        assert!(err.to_string().contains("approval.rejected: "), "{err}");
        assert!(consent_rows(&dir).is_empty());
    }

    /// Another handle attested the entry and a commit spent it after the
    /// caller validated its unattested copy.
    #[test]
    fn a_consumed_entry_since_validation_refuses_with_its_own_code() {
        let entry = make_entry(DEFAULT_TTL_MS);
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
        store
            .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
            .unwrap();
        store
            .record_attestation(&entry.approval_nonce, [0x01; 32])
            .unwrap();
        store
            .consume(
                &entry.approval_nonce,
                &"ab".repeat(32),
                crate::approval::ConsumedOutcome::Confirmed,
            )
            .unwrap();
        let err = attest_validated_copy(&dir, &mut store, &entry);
        assert!(err.to_string().contains("approval.consumed: "), "{err}");
        assert!(consent_rows(&dir).is_empty());
    }
}

//! Shared attest path for a pending approval.
//!
//! The `stellar-agent approve --id <nonce>` CLI command and any future
//! server-driven approve surface call this single canonical path so both
//! render the identical wallet-controlled attestation semantics: the same
//! nonce/expiry/already-attested/process-uid validation
//! ([`load_and_validate_entry`]), and the same per-kind HMAC-attest-and-persist
//! dispatch ([`attest_and_persist`]).  The CLI's tty prompt, exit-code
//! mapping, and JSON rendering stay in the CLI crate — this module has no
//! concept of a terminal or a process exit code.
//!
//! # Layering note: the `ToolsetFirstInvokeGate` grant step
//!
//! `stellar-agent-toolsets-runtime` (which owns `record_first_invoke_grant`,
//! the durable-grant persistence path) depends on `stellar-agent-core`, not
//! the reverse — core calling into it directly would be an illegal dependency
//! cycle. [`attest_and_persist`] therefore takes the grant-persistence step as
//! an injected closure (`persist_toolset_grant`): core owns the validation,
//! the per-kind dispatch, the sequencing (persist grant, then consume the
//! pending entry), and the audit emission; only the literal
//! `record_first_invoke_grant` call is supplied by the caller, which already
//! depends on `stellar-agent-toolsets-runtime`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use zeroize::Zeroizing;

use crate::audit_log::entry::AuditEntry;
use crate::audit_log::writer::AuditWriter;
use crate::error::{AuthError, InternalError, WalletError};
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
    /// The `stellar-agent approve --id <nonce>` CLI command.
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
/// The caller is expected to forward these fields, `process_uid`,
/// `now_unix_ms`, and the attestation key into
/// `stellar_agent_toolsets_runtime::record_first_invoke_grant`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ToolsetGrantRequest<'a> {
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
/// # Errors
///
/// Returns a [`WalletError`] when the keyring entry is missing or contains
/// invalid base64/wrong-length data.
pub fn load_attestation_key(
    entry_ref: &KeyringEntryRef,
) -> Result<Zeroizing<Vec<u8>>, WalletError> {
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "keyring Entry::new failed for attestation key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
    })?;

    let secret_b64 = Zeroizing::new(entry.get_password().map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "get_password failed for attestation key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
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

    Ok(key_bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// attest_and_persist
// ─────────────────────────────────────────────────────────────────────────────

/// Computes and persists the operator's attestation (or recorded consent) for
/// a pending approval, dispatching on [`ApprovalKind`].
///
/// Returns `Some(base64url_blob)` for `PaymentSimulated` / `ClaimSimulated` /
/// `RuleProposalSimulated` — the attestation the agent surface must present
/// as `approval_attestation` to the matching `*_commit` tool. Returns `None`
/// for `ToolsetFirstInvokeGate` and `TrustlineClawbackOptIn`, whose gates
/// read the recorded consent from the store directly and take no attestation
/// argument.
///
/// On success, emits an audit event through `audit` (if supplied) after the
/// persist step: `ApprovalAttested` when `operator_credential_id_b64url` is
/// `None` (the loopback CLI and serve surfaces), or `ApprovalAttestedRemote`
/// — carrying the operator's redacted credential pseudonym — when it is
/// `Some` (the remote-approval surface). Audit emission is non-fatal: a
/// failure to write the event is logged (`tracing::warn!`) and does not
/// affect the return value — a failed attestation write must never be
/// reported as a successful attest, but a failed *audit* write must never
/// undo one.
///
/// # Errors
///
/// Returns a [`WalletError`] on key-length mismatch, hash-decode failure, a
/// store-level `NotFound` / `Expired` / `AlreadyAttested` race, a
/// `persist_toolset_grant` failure, or when `entry.kind` is not one of the
/// five attestable kinds (including `ApprovalKind::Rejected`, which can never
/// be attested).
pub fn attest_and_persist(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &[u8],
    surface: Surface,
    mut audit: Option<&mut AuditWriter>,
    operator_credential_id_b64url: Option<&str>,
    persist_toolset_grant: impl FnOnce(&ToolsetGrantRequest<'_>, &[u8; 32]) -> Result<(), String>,
) -> Result<Option<String>, WalletError> {
    let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "approval.key_length_error: attestation key must be 32 bytes, got {}",
                key_bytes.len()
            ),
        })
    })?;

    // `Some(blob)` is the attestation the agent surface must present to the
    // matching `*_commit` tool; `None` for approval kinds whose gate reads the
    // recorded consent from the store and takes no attestation argument.
    let surfaced_attestation: Option<String> = match &entry.kind {
        ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } => {
            let presented_sha256 = decode_sha256_hex(envelope_sha256_hex)?;
            let attestation_blob = compute_attestation(
                &key_arr,
                &entry.approval_nonce,
                &presented_sha256,
                &entry.process_uid,
            );
            record_attestation_on_store(store, &entry.approval_nonce, attestation_blob)?;
            let blob_b64 = URL_SAFE_NO_PAD.encode(attestation_blob);
            emit_attested_audit(
                &mut audit,
                "PaymentSimulated",
                "stellar_pay_commit",
                Some(envelope_sha256_hex.clone()),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            );
            Some(blob_b64)
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
                &entry.approval_nonce,
                &presented_sha256,
                &entry.process_uid,
            );
            record_attestation_on_store(store, &entry.approval_nonce, attestation_blob)?;
            let blob_b64 = URL_SAFE_NO_PAD.encode(attestation_blob);
            emit_attested_audit(
                &mut audit,
                "ClaimSimulated",
                "stellar_claim_commit",
                Some(envelope_sha256_hex.clone()),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            );
            Some(blob_b64)
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
            //   1. Build and persist the ToolsetGrant via the caller-injected
            //      `persist_toolset_grant` closure (see module docs for why this
            //      step cannot be a direct core-internal call).
            //   2. CONSUME (remove) the pending entry so it cannot be re-used.
            let now_ms = timefmt::now_unix_ms().map_err(|e| map_clock_error(&e))?;

            let request = ToolsetGrantRequest {
                toolset_name,
                capability,
                destination,
                asset,
                amount_min_stroops: *amount_min_stroops,
                amount_max_stroops: *amount_max_stroops,
                process_uid: &entry.process_uid,
                now_unix_ms: now_ms,
            };
            persist_toolset_grant(&request, &key_arr).map_err(|e| {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: format!("approval.grant_persist: {e}"),
                })
            })?;

            // Step 2: CONSUME the pending entry so it cannot be replayed.
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

            emit_attested_audit(
                &mut audit,
                "ToolsetFirstInvokeGate",
                &format!("toolset:{toolset_name}:{capability}"),
                None,
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
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
            let attestation_blob =
                compute_attestation(&key_arr, &entry.approval_nonce, &digest, &entry.process_uid);

            store
                .record_trustline_clawback_opt_in_attestation(
                    &entry.approval_nonce,
                    attestation_blob,
                )
                .map_err(|e| match e {
                    ApprovalError::NotFound => {
                        WalletError::Internal(InternalError::UnexpectedState {
                            detail: "approval.not_found: entry disappeared between lookup \
                                     and record"
                                .to_owned(),
                        })
                    }
                    ApprovalError::Expired => {
                        WalletError::Internal(InternalError::UnexpectedState {
                            detail: "approval.expired: entry expired between check and record"
                                .to_owned(),
                        })
                    }
                    ApprovalError::AlreadyAttested => {
                        WalletError::Internal(InternalError::UnexpectedState {
                            detail: "approval.already_attested: entry was attested by a \
                                     concurrent process"
                                .to_owned(),
                        })
                    }
                    other => WalletError::Internal(InternalError::UnexpectedState {
                        detail: format!("approval.record_failed: {other}"),
                    }),
                })?;

            emit_attested_audit(
                &mut audit,
                "TrustlineClawbackOptIn",
                "stellar_trustline_commit",
                None,
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            );

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
                &entry.approval_nonce,
                proposal_sha256,
                &entry.process_uid,
            );
            store
                .record_rule_proposal_attestation(&entry.approval_nonce, attestation_blob)
                .map_err(|e| match e {
                    ApprovalError::NotFound => {
                        WalletError::Internal(InternalError::UnexpectedState {
                            detail: "approval.not_found: entry disappeared between lookup \
                                     and record"
                                .to_owned(),
                        })
                    }
                    ApprovalError::Expired => {
                        WalletError::Internal(InternalError::UnexpectedState {
                            detail: "approval.expired: entry expired between check and record"
                                .to_owned(),
                        })
                    }
                    ApprovalError::AlreadyAttested => {
                        WalletError::Internal(InternalError::UnexpectedState {
                            detail: "approval.already_attested: entry was attested by a \
                                     concurrent process"
                                .to_owned(),
                        })
                    }
                    other => WalletError::Internal(InternalError::UnexpectedState {
                        detail: format!("approval.record_failed: {other}"),
                    }),
                })?;
            let blob_b64 = URL_SAFE_NO_PAD.encode(attestation_blob);
            let proposal_sha256_hex = proposal_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            emit_attested_audit(
                &mut audit,
                "RuleProposalSimulated",
                "stellar_rule_create_commit",
                Some(proposal_sha256_hex),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            );
            Some(blob_b64)
        }
        ApprovalKind::Rejected { .. } => {
            return Err(WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.rejected: this pending approval was rejected by the operator \
                         and cannot be attested"
                    .to_owned(),
            }));
        }
        other => {
            return Err(WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "approval.wrong_kind: attest_and_persist does not support {}, \
                     expected PaymentSimulated, ClaimSimulated, ToolsetFirstInvokeGate, \
                     TrustlineClawbackOptIn, or RuleProposalSimulated",
                    other.kind_name()
                ),
            }));
        }
    };

    Ok(surfaced_attestation)
}

/// Helper: records an HMAC attestation blob on the store entry.
fn record_attestation_on_store(
    store: &mut PendingApprovalStore,
    approval_nonce: &str,
    attestation_blob: [u8; 32],
) -> Result<(), WalletError> {
    store
        .record_attestation(approval_nonce, attestation_blob)
        .map_err(|e| match e {
            ApprovalError::NotFound => WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.not_found: entry disappeared between lookup and record"
                    .to_owned(),
            }),
            ApprovalError::Expired => WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.expired: entry expired between check and record".to_owned(),
            }),
            ApprovalError::AlreadyAttested => {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: "approval.already_attested: entry was attested by a concurrent process"
                        .to_owned(),
                })
            }
            other => WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approval.record_failed: {other}"),
            }),
        })
}

/// Emits an `ApprovalAttested` audit event, non-fatally.
///
/// A failure to write the event is logged and otherwise ignored: the
/// attestation is already durably persisted by the time this is called, and
/// an audit-log hiccup must not be reported as an attest failure.
fn emit_attested_audit(
    audit: &mut Option<&mut AuditWriter>,
    approval_kind: &str,
    gated_tool: &str,
    envelope_sha256_hex: Option<String>,
    approval_nonce: &str,
    surface: Surface,
    operator_credential_id_b64url: Option<&str>,
) {
    let Some(writer) = audit.as_deref_mut() else {
        return;
    };
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
    if let Err(e) = writer.write_entry(entry) {
        tracing::warn!(
            error = %e,
            approval_kind,
            "approval attest: audit write failed; attestation already persisted, continuing"
        );
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

    #[test]
    #[serial_test::serial]
    fn load_attestation_key_success() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-load";
        seed_key_32(svc, "default");
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let key = load_attestation_key(&entry_ref).unwrap();
        assert_eq!(key.len(), 32);
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

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_payment_records_hmac_and_surfaces_blob() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-payment";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
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
            Surface::Cli,
            None,
            None,
            |_req, _key| Err("must not be called for PaymentSimulated".to_owned()),
        )
        .unwrap();
        let surfaced_blob = surfaced.expect("PaymentSimulated must surface its attestation blob");

        let final_entry = store.get(&nonce).unwrap();
        let blob_b64 = final_entry.attestation_blob_b64.as_ref().unwrap();
        assert_eq!(surfaced_blob, *blob_b64);

        let sha256_bytes = decode_sha256_hex(&envelope_sha256_hex).unwrap();
        let expected = compute_attestation(&raw_key, &nonce, &sha256_bytes, &process_uid);
        let persisted_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(persisted_bytes, expected);
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rejected_tombstone_fails_closed() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rejected";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
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
            Surface::Cli,
            None,
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
            Surface::Cli,
            None,
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
            Surface::Cli,
            None,
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
            Surface::Cli,
            None,
            None,
            |_req, _key| Err("must not be called for RuleProposalSimulated".to_owned()),
        )
        .unwrap();
        let surfaced_blob =
            surfaced.expect("RuleProposalSimulated must surface its attestation blob");

        let final_entry = store.get(&nonce).unwrap();
        let blob_b64 = final_entry.attestation_blob_b64.as_ref().unwrap();
        assert_eq!(surfaced_blob, *blob_b64);

        let expected = compute_attestation(&raw_key, &nonce, &proposal_sha256, &process_uid);
        let persisted_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(persisted_bytes, expected);
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rule_proposal_rejected_tombstone_fails_closed() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rule-proposal-rejected";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
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
            Surface::Cli,
            None,
            None,
            |_req, _key| Err("must not be called".to_owned()),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("approval.rejected"),
            "unexpected error: {err}"
        );
    }
}

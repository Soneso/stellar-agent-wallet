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
    /// A resident, server-driven approve surface.
    Serve,
}

impl Surface {
    /// Returns the wire string for this surface (`"cli"` or `"serve"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Serve => "serve",
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
/// so a future remote-approval mode can bind a different identity kind
/// without changing this signature. For the current [`ApproverIdentity::OsUid`]
/// variant, [`ApproverIdentity::matches_entry_process_uid`] compares against
/// the stored entry's `process_uid` exactly as the pre-abstraction
/// `process_uid: &str` parameter was — byte-identical wire behaviour.
///
/// # Errors
///
/// Returns a [`WalletError`] (all `Internal(UnexpectedState)` with a
/// `approval.*` detail prefix) when: the nonce is unknown
/// (`approval.not_found`); the entry has expired (`approval.expired`); the
/// entry is already attested (`approval.already_attested`); or the
/// caller's identity does not match the entry's (`approval.user_mismatch`).
pub fn load_and_validate_entry(
    store: &PendingApprovalStore,
    nonce: &str,
    identity: &ApproverIdentity,
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

    if !identity.matches_entry_process_uid(&entry.process_uid) {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.user_mismatch: this pending approval was created by a different \
                     local user (process_uid mismatch); a different user cannot attest it"
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
/// Returns `Some(base64url_blob)` for `PaymentSimulated` / `ClaimSimulated` —
/// the attestation the agent surface must present as `approval_attestation`
/// to the matching `*_commit` tool. Returns `None` for
/// `ToolsetFirstInvokeGate` and `TrustlineClawbackOptIn`, whose gates read the
/// recorded consent from the store directly and take no attestation
/// argument.
///
/// On success, emits an `ApprovalAttested` audit event through `audit` (if
/// supplied) after the persist step. Audit emission is non-fatal: a failure
/// to write the event is logged (`tracing::warn!`) and does not affect the
/// return value — a failed attestation write must never be reported as a
/// successful attest, but a failed *audit* write must never undo one.
///
/// # Errors
///
/// Returns a [`WalletError`] on key-length mismatch, hash-decode failure, a
/// store-level `NotFound` / `Expired` / `AlreadyAttested` race, a
/// `persist_toolset_grant` failure, or when `entry.kind` is not one of the
/// four attestable kinds (including `ApprovalKind::Rejected`, which can never
/// be attested).
pub fn attest_and_persist(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &[u8],
    surface: Surface,
    mut audit: Option<&mut AuditWriter>,
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
            );

            // The trustline clawback opt-in gate recomputes the digest and
            // verifies the stored blob; the agent presents no attestation here.
            None
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
                     or TrustlineClawbackOptIn",
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
) {
    let Some(writer) = audit.as_deref_mut() else {
        return;
    };
    let entry = AuditEntry::new_approval_attested(
        approval_kind,
        gated_tool,
        envelope_sha256_hex,
        approval_nonce,
        surface.as_str(),
        uuid::Uuid::new_v4().to_string(),
    );
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
            load_and_validate_entry(&store, &nonce, &ApproverIdentity::OsUid(uid)).unwrap();
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
        )
        .unwrap_err();
        assert!(err.to_string().contains("approval.user_mismatch"));
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
            |_req, _key| Err("grant store unavailable".to_owned()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("approval.grant_persist"));
        assert!(
            store.get(&nonce).is_some(),
            "entry must survive a failed grant persist"
        );
    }
}

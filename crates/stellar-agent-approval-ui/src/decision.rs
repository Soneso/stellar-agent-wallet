//! The approve/reject decision seam.
//!
//! [`apply_decision`] is the single, authentication-agnostic entry point every
//! HTTP action handler funnels through. The caller (the HTTP layer) is
//! responsible for having already authenticated the request (session cookie)
//! and CSRF-checked it; this function performs no auth of its own. Keeping the
//! seam this narrow lets a future authenticator slot in front of the HTTP
//! handlers without reshaping the store/attest logic.
//!
//! # Concurrency model
//!
//! The server never holds a resident
//! [`PendingApprovalStore`].
//! Every call here opens the store via [`open_with_retry`], performs the one
//! action, and lets the store drop — releasing the advisory file lock — before
//! returning. Lock contention that survives the bounded retry surfaces as
//! [`Outcome::Busy`] rather than an error or a panic.
//!
//! # Audit rows
//!
//! An approve or a reject takes effect only after its row is durable. The row
//! is written through [`DecisionContext::audit_writer`] first. A refused row,
//! or a poisoned writer mutex, answers [`Outcome::Unavailable`] with the store
//! unchanged. A poisoned mutex keeps refusing every decision until the
//! inbox restarts.
//!
//! # Remote authorization
//!
//! A [`RequestIdentity::Remote`] decision reads the profile's current
//! remote-approval authorization from disk through its
//! [`RemoteApprovalAuthority`]: once when the request is resolved, and an
//! approve again after the attestation key is loaded, immediately before its
//! consent row and attestation are persisted, so a credential removed while
//! the keyring prompt waits cannot approve. A credential the current files do
//! not admit answers [`Outcome::Unauthorized`] with the store unchanged.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::{
    ApprovalKind, ApproverIdentity, AttestedApprover, ConsentAudit, DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_BACKOFF, PendingApprovalStore, RemoteApprovalAuthority, Surface,
    attest_and_persist, load_and_validate_entry, load_attestation_key, open_with_retry,
    process_uid_for_attestation,
};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::owner_key::OwnerKeyContext;
use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_core::timefmt;

/// TTL applied to a `Rejected` tombstone written by the approval-inbox server.
///
/// One hour: long enough that a re-issued or replayed nonce resolves to the
/// tombstone (idempotent reject) rather than reappearing as pending, short
/// enough to be swept by the normal expiry/gc path.
pub const REJECT_TOMBSTONE_TTL_MS: u64 = 3_600_000;

/// The authenticated identity behind a decision, supplied by the HTTP layer
/// that already performed authentication.
///
/// [`apply_decision`] is authentication-agnostic per the module docs; this
/// type is the narrow seam a caller uses to say WHO is deciding, without
/// `apply_decision` itself knowing how that identity was established.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RequestIdentity {
    /// The loopback approval-inbox server: derive
    /// `ApproverIdentity::OsUid(process_uid_for_attestation())` internally.
    /// The remote-approval allowlist is never consulted, and the attestation
    /// names [`AttestedApprover::Local`].
    Local,
    /// A passkey-authenticated identity from the remote-approval HTTP
    /// surface, already verified by the caller (see
    /// `ApproverIdentity::from_verified_passkey_assertion`), plus where the
    /// profile's current authorization lives.
    ///
    /// The identity must be an `ApproverIdentity::PasskeyCredential`; any
    /// other identity answers [`Outcome::Unauthorized`]. The attestation
    /// names [`AttestedApprover::Remote`] with its credential ID.
    Remote {
        /// The verified `PasskeyCredential` identity.
        identity: ApproverIdentity,
        /// The serving profile's remote-approval authority, read again at
        /// every check.
        authority: Arc<RemoteApprovalAuthority>,
        /// The chain the listener serves.
        chain: Caip2,
        /// The relying-party ID the listener verifies assertions for.
        rp_id: String,
    },
}

/// A single operator decision on one pending approval.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Decision {
    /// Approve (attest / record consent) the approval with this nonce.
    Approve {
        /// The approval nonce from the URL path.
        nonce: String,
    },
    /// Reject the approval with this nonce (write a tombstone).
    Reject {
        /// The approval nonce from the URL path.
        nonce: String,
    },
}

/// The immutable inputs [`apply_decision`] needs to act on the store.
///
/// The keyring store must already be initialised process-wide (via
/// `stellar_agent_network::keyring::init_platform_keyring_store` or the test
/// mock) before the first [`apply_decision`] call.
#[non_exhaustive]
pub struct DecisionContext {
    /// Serving profile context: the store name, the chain id, the endpoint host and
    /// the enrolled signer; its binding enters every attestation.
    pub context: stellar_agent_core::approval::ApprovalContext,
    /// Path to the profile's pending-approval store file.
    pub store_path: PathBuf,
    /// Keyring reference for the profile's attestation HMAC key.
    pub attestation_key_entry_ref: KeyringEntryRef,
    /// The profile's owner coordinates. The attestation key load refuses a
    /// key equal to the owner public key at any of them.
    pub owner: OwnerKeyContext,
    /// Shared audit-log writer for the profile.
    ///
    /// Every approve and reject writes its row through this writer before the
    /// decision is persisted, and a refused row refuses the decision with
    /// [`Outcome::Unavailable`]. A poisoned mutex is never recovered: every
    /// later decision refuses until the inbox restarts.
    pub audit_writer: Arc<Mutex<AuditWriter>>,
    /// Optional grant-store path override for the `ToolsetFirstInvokeGate`
    /// branch. Production passes `None` (the path is resolved from the profile
    /// name); integration tests pass `Some(temp_dir_path)` for isolation.
    pub grant_store_path_override: Option<PathBuf>,
}

impl DecisionContext {
    /// Construct a decision context. Production callers pass `None` for
    /// `grant_store_path_override`, and build `owner` with
    /// [`OwnerKeyContext::for_profile`] from the serving profile and its name.
    #[must_use]
    pub fn new(
        context: stellar_agent_core::approval::ApprovalContext,
        store_path: PathBuf,
        attestation_key_entry_ref: KeyringEntryRef,
        owner: OwnerKeyContext,
        audit_writer: Arc<Mutex<AuditWriter>>,
        grant_store_path_override: Option<PathBuf>,
    ) -> Self {
        Self {
            context,
            store_path,
            attestation_key_entry_ref,
            owner,
            audit_writer,
            grant_store_path_override,
        }
    }
}

/// The outcome of an [`apply_decision`] call.
///
/// All variants are terminal, non-secret status values the HTTP layer maps onto
/// a JSON response. No raw error strings from the core approval layer are
/// propagated to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The approval was attested (or, for gate/consent kinds, consent was
    /// recorded). `attestation` is `Some` for payment-style kinds and `None`
    /// for `ToolsetFirstInvokeGate` / `TrustlineClawbackOptIn`.
    Attested {
        /// The base64url attestation blob to surface to the agent, when any.
        attestation: Option<String>,
        /// Unix-ms expiry of the approved entry.
        expires_at_unix_ms: u64,
    },
    /// A reject wrote (or confirmed) a tombstone for the nonce.
    Rejected,
    /// The nonce was already resolved: attested, rejected, or absent. Carries
    /// the previously-stored attestation blob when one exists, so a lost
    /// success response can be re-shown without re-attesting.
    AlreadyResolved {
        /// The already-stored attestation blob, when present.
        attestation: Option<String>,
    },
    /// The entry has expired and can no longer be approved.
    Expired,
    /// The store is locked by another writer after the bounded retry window.
    Busy,
    /// The store or a dependency could not be reached (I/O, keyring, clock).
    Unavailable,
    /// The entry was created by a different OS user than the caller.
    UserMismatch,
    /// This request belongs to another profile or network.
    BindingMismatch,
    /// No entry with this nonce exists.
    NotFound,
    /// The entry's kind is not one the attest path supports (for example a
    /// passkey kind, whose interactive flow lives in the WebAuthn bridge).
    WrongKind,
    /// The entry's stored digest is not the digest of its stored envelope, or
    /// that envelope does not decode, so no surface can show what an
    /// attestation would approve. Nothing was attested and no row written.
    Inconsistent,
    /// A remote requester the profile's current authorization does not
    /// admit: its credential is absent from `allowed_credentials` or from the
    /// operator-credential store, remote approval is disabled, or the
    /// authorization cannot be read. Nothing was attested and no row written.
    Unauthorized,
}

/// Apply one operator [`Decision`] against the profile's approval store, on
/// behalf of `requester`.
///
/// This is synchronous file/keyring I/O plus at most one audit write — no
/// network — matching the CLI `approve` command's in-async-fn synchronous
/// house style. All authentication and CSRF checks happen at the HTTP boundary
/// before this is called; `requester` says WHO is deciding, not whether they
/// were authenticated.
///
/// # Panics
///
/// Never panics.
#[must_use]
pub fn apply_decision(
    ctx: &DecisionContext,
    decision: Decision,
    requester: &RequestIdentity,
) -> Outcome {
    match decision {
        Decision::Approve { nonce } => apply_approve(ctx, &nonce, requester),
        Decision::Reject { nonce } => apply_reject(ctx, &nonce, requester),
    }
}

/// A requester resolved against the current authorization.
struct Resolved {
    /// The identity the entry binding is checked against.
    identity: ApproverIdentity,
    /// The allowlist as read for this decision; empty for a local requester.
    allowed_credentials: Vec<String>,
    /// The surface the decision is attributed to.
    surface: Surface,
    /// The approver the attestation authenticates.
    approver: AttestedApprover,
}

impl Resolved {
    /// The operator credential ID the audit row redacts, for a remote
    /// requester.
    fn operator_credential_id(&self) -> Option<&str> {
        match &self.approver {
            AttestedApprover::Remote {
                credential_id_b64url,
            } => Some(credential_id_b64url),
            _ => None,
        }
    }
}

/// Resolves `requester` into the identity and allowlist to gate with, the
/// surface to attribute the action to, and the approver to attest.
///
/// For [`RequestIdentity::Local`] this derives
/// `ApproverIdentity::OsUid(process_uid_for_attestation())`. For
/// [`RequestIdentity::Remote`] it reads the current authorization through
/// [`authorize_remote`].
///
/// # Errors
///
/// Returns `Err(Outcome::Unavailable)` if process-UID derivation fails for
/// `RequestIdentity::Local`, and `Err(Outcome::Unauthorized)` for a remote
/// requester the current authorization does not admit.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return Outcome for a derivation failure"
)]
fn resolve_requester(requester: &RequestIdentity) -> Result<Resolved, Outcome> {
    match requester {
        RequestIdentity::Local => {
            let uid = process_uid_for_attestation().map_err(|e| {
                tracing::warn!(error = %e, "decision: process uid derivation failed");
                Outcome::Unavailable
            })?;
            Ok(Resolved {
                identity: ApproverIdentity::OsUid(uid),
                allowed_credentials: Vec::new(),
                surface: Surface::Serve,
                approver: AttestedApprover::Local,
            })
        }
        RequestIdentity::Remote { identity, .. } => {
            let (credential_id, allowed_credentials) = authorize_remote(requester)?;
            Ok(Resolved {
                identity: identity.clone(),
                allowed_credentials,
                surface: Surface::ServeRemote,
                approver: AttestedApprover::Remote {
                    credential_id_b64url: credential_id,
                },
            })
        }
    }
}

/// Reads a remote requester's authorization from disk now and returns its
/// credential ID and the current allowlist. A local requester needs none and
/// returns an empty ID and list.
///
/// # Errors
///
/// `Err(Outcome::Unauthorized)` when the identity is not a passkey
/// credential, or when the current profile and operator-credential store do
/// not admit it for the listener's chain and relying-party ID.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return Outcome"
)]
fn authorize_remote(requester: &RequestIdentity) -> Result<(String, Vec<String>), Outcome> {
    let RequestIdentity::Remote {
        identity,
        authority,
        chain,
        rp_id,
    } = requester
    else {
        return Ok((String::new(), Vec::new()));
    };
    let ApproverIdentity::PasskeyCredential {
        credential_id_b64url,
        ..
    } = identity
    else {
        tracing::warn!("decision: a remote requester carries no passkey identity");
        return Err(Outcome::Unauthorized);
    };
    let authorization = authority
        .require_credential(credential_id_b64url, *chain, Some(rp_id))
        .map_err(|e| {
            tracing::warn!(code = %e.code(), "decision: remote requester is not authorized");
            Outcome::Unauthorized
        })?;
    Ok((
        credential_id_b64url.clone(),
        authorization.allowed_credentials().to_vec(),
    ))
}

#[cfg(test)]
pub(crate) mod wait_hook {
    //! Runs a test action where a decision waits: right after approve's
    //! attestation key loads, standing in for an interactive keyring prompt,
    //! and right after reject takes the audit-writer lock, before its final
    //! authorization read, standing in for a revocation while another
    //! decision held the writer.

    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Installs `action` for the next decision wait on this thread.
    pub(crate) fn install(action: impl FnOnce() + 'static) {
        HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(action)));
    }

    pub(super) fn fire() {
        if let Some(action) = HOOK.with(|hook| hook.borrow_mut().take()) {
            action();
        }
    }
}

/// Opens the profile's approval store, mapping [`ApprovalError::WriterLocked`]
/// and any other open failure directly onto a terminal [`Outcome`].
///
/// Every store open in this module goes through this helper so the two
/// action paths share one lock-contention / unavailable mapping.
fn open_store(ctx: &DecisionContext, op: &'static str) -> Result<PendingApprovalStore, Outcome> {
    open_with_retry(
        &ctx.store_path,
        DEFAULT_RETRY_ATTEMPTS,
        DEFAULT_RETRY_BACKOFF,
    )
    .map_err(|e| match e {
        ApprovalError::WriterLocked => Outcome::Busy,
        other => {
            tracing::warn!(error = %other, op, "approval store open failed");
            Outcome::Unavailable
        }
    })
}

/// Compares the structured approval code independently of operator-facing text.
fn approval_code_is(err: &WalletError, code: &str) -> bool {
    err.code() == code
}

fn apply_approve(ctx: &DecisionContext, nonce: &str, requester: &RequestIdentity) -> Outcome {
    let store = match open_store(ctx, "approve") {
        Ok(s) => s,
        Err(outcome) => return outcome,
    };

    let resolved = match resolve_requester(requester) {
        Ok(resolved) => resolved,
        Err(outcome) => return outcome,
    };

    let entry = match load_and_validate_entry(
        &store,
        nonce,
        &resolved.identity,
        &resolved.allowed_credentials,
    ) {
        Ok(e) => e,
        Err(e) => {
            if approval_code_is(&e, "approval.user_mismatch") {
                return Outcome::UserMismatch;
            }
            if approval_code_is(&e, "approval.expired") {
                return Outcome::Expired;
            }
            if approval_code_is(&e, "approval.not_found") {
                return Outcome::NotFound;
            }
            if approval_code_is(&e, "approval.already_attested") {
                // Recoverable lost-response re-show: return the already-stored
                // blob without re-attesting.
                let attestation = store
                    .get(nonce)
                    .and_then(|e| e.attestation_blob_b64.clone());
                return Outcome::AlreadyResolved { attestation };
            }
            tracing::warn!(error = %e, "approve: entry validation failed");
            return Outcome::Unavailable;
        }
    };

    // Release the store lock BEFORE the keyring read: `load_attestation_key`
    // can block on an interactive platform-keychain prompt, and holding the
    // advisory file lock across that wait would starve the agent's own
    // simulate/insert calls on this profile's store for the prompt's
    // duration. The entry is already validated and cloned above; a
    // concurrent mutation of this exact nonce between here and the re-open
    // below (attest, reject, or removal by another process) is caught by
    // `attest_and_persist`'s own store-level re-check, never silently
    // overwritten.
    drop(store);

    let key = match load_attestation_key(&ctx.attestation_key_entry_ref, &ctx.owner) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                code = %e.code(),
                error = %e,
                "approve: attestation key load failed"
            );
            return Outcome::Unavailable;
        }
    };
    #[cfg(test)]
    wait_hook::fire();

    let mut store = match open_store(ctx, "approve-persist") {
        Ok(s) => s,
        Err(outcome) => return outcome,
    };

    // The consent row is written before the attestation is persisted, so a
    // writer that cannot be used refuses the decision. A poisoned mutex may
    // guard a writer left mid-append; it is never recovered, and every later
    // decision refuses until the inbox restarts.
    let Ok(mut writer) = ctx.audit_writer.lock() else {
        tracing::error!(
            event_kind = audit_event_kind(resolved.operator_credential_id(), true),
            "approve: audit writer mutex poisoned; refusing the decision until the inbox \
             restarts"
        );
        return Outcome::Unavailable;
    };

    // The key load above may have waited on a keyring prompt, and the writer
    // lock on other decisions: read the authorization again, immediately
    // before the row and the attestation are persisted.
    if let Err(outcome) = authorize_remote(requester) {
        return outcome;
    }

    let grant_override = ctx.grant_store_path_override.clone();
    let profile_name = ctx.context.profile_name.as_str();
    let result = attest_and_persist(
        &mut store,
        &entry,
        &key,
        &ctx.context.binding(),
        resolved.surface,
        ConsentAudit::Writer(&mut writer),
        &resolved.approver,
        |req, grant_key| {
            stellar_agent_toolsets_runtime::record_first_invoke_grant(
                profile_name,
                req.toolset_name,
                req.capability,
                req.destination,
                req.asset,
                req.amount_min_stroops,
                req.amount_max_stroops,
                req.process_uid,
                req.now_unix_ms,
                grant_key,
                req.binding,
                grant_override.clone(),
            )
            .map(|_grant| ())
            .map_err(|e| e.to_string())
        },
    );

    match result {
        Ok(attestation) => Outcome::Attested {
            attestation,
            expires_at_unix_ms: entry.expires_at_unix_ms,
        },
        Err(e) => {
            if approval_code_is(&e, "approval.binding_mismatch") {
                return Outcome::BindingMismatch;
            }
            if approval_code_is(&e, "approval.wrong_kind") {
                return Outcome::WrongKind;
            }
            if approval_code_is(&e, "approval.entry_inconsistent") {
                return Outcome::Inconsistent;
            }
            if approval_code_is(&e, "approval.not_found") {
                return Outcome::NotFound;
            }
            if approval_code_is(&e, "approval.expired") {
                return Outcome::Expired;
            }
            if approval_code_is(&e, "approval.rejected")
                || approval_code_is(&e, "approval.consumed")
            {
                // A rejected or spent tombstone is already resolved, and its
                // attestation is not handed back.
                return Outcome::AlreadyResolved { attestation: None };
            }
            if approval_code_is(&e, "approval.already_attested") {
                // Another handle attested this entry since it was validated:
                // no row was written here, and the stored attestation is the
                // one to re-show.
                let attestation = store
                    .get(nonce)
                    .and_then(|e| e.attestation_blob_b64.clone());
                return Outcome::AlreadyResolved { attestation };
            }
            // A refused consent row lands here: nothing was persisted.
            tracing::warn!(error = %e, "approve: attest_and_persist failed");
            Outcome::Unavailable
        }
    }
}

/// The audit event kind a decision writes, for the `error` log of a decision
/// refused before its row.
fn audit_event_kind(operator_credential_id: Option<&str>, approve: bool) -> &'static str {
    match (operator_credential_id.is_some(), approve) {
        (false, true) => "approval_attested",
        (true, true) => "approval_attested_remote",
        (false, false) => "approval_rejected",
        (true, false) => "approval_rejected_remote",
    }
}

fn apply_reject(ctx: &DecisionContext, nonce: &str, requester: &RequestIdentity) -> Outcome {
    let mut store = match open_store(ctx, "reject") {
        Ok(s) => s,
        Err(outcome) => return outcome,
    };

    // Idempotency + capture-before-mutate: read what we need, then mutate.
    // The full entry is cloned (not just its fields) because the
    // ApproverIdentity check below needs `process_uid` and `approval_nonce`.
    let entry = store.get(nonce).cloned();
    let (already_resolved, resolved_attestation, original_kind_name) = match &entry {
        None => (true, None, None),
        Some(e) => match &e.kind {
            ApprovalKind::Rejected { .. } => (true, None, None),
            // A spent approval is resolved, and its attestation is not handed
            // back: the blob is retained so the commit gate can tell a retry
            // from a first attempt, not so a second flow can present it again.
            ApprovalKind::Consumed { .. } => (true, None, None),
            _ if e.attestation_blob_b64.is_some() => (true, e.attestation_blob_b64.clone(), None),
            _ => (false, None, Some(e.kind.kind_name().to_owned())),
        },
    };

    if already_resolved {
        return Outcome::AlreadyResolved {
            attestation: resolved_attestation,
        };
    }

    // Same ApproverIdentity gate `apply_approve` enforces via
    // `load_and_validate_entry`: without it, a caller reachable over HTTP but
    // not authorized for this entry could inject a terminal "no" the
    // operator never gave — reject is not exempt from the identity binding
    // just because it carries no attestation. Threaded symmetrically with
    // `apply_approve` via `is_authorized_for_entry`, so a `RequestIdentity::Remote`
    // reject is gated by the same allowlist + entry-binding checks as an
    // approve. A remote requester's authorization is read here, after the
    // store lock is held, and again once the audit-writer lock is held.
    let resolved = match resolve_requester(requester) {
        Ok(resolved) => resolved,
        Err(outcome) => return outcome,
    };
    // `entry` is `Some` here: `already_resolved` is `true` for every arm
    // above where it is `None`.
    let Some(entry) = entry else {
        tracing::warn!("reject: entry unexpectedly absent after not-already-resolved check");
        return Outcome::Unavailable;
    };
    if !resolved.identity.is_authorized_for_entry(
        &entry.process_uid,
        &entry.approval_nonce,
        &resolved.allowed_credentials,
    ) {
        return Outcome::UserMismatch;
    }

    let now_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "reject: system clock read failed");
            return Outcome::Unavailable;
        }
    };

    // The rejection row is written before the rejection is persisted, so a
    // rejection never takes effect without its row. The entry was read above
    // from this store, which holds its lock until it drops, so it is still the
    // entry being rejected. A poisoned mutex is never recovered: every later
    // decision refuses until the inbox restarts.
    let operator_credential_id = resolved.operator_credential_id();
    let event_kind = audit_event_kind(operator_credential_id, false);
    let Ok(mut writer) = ctx.audit_writer.lock() else {
        tracing::error!(
            event_kind,
            "reject: audit writer mutex poisoned; refusing the decision until the inbox restarts"
        );
        return Outcome::Unavailable;
    };

    // The writer lock may have waited on other decisions: read the
    // authorization again before the rejection row. `write_entry` may still
    // drain queued rows, repair the anchor or rotate the log before the row
    // lands, so a revocation during that work does not stop this rejection;
    // a rejection only denies the pending action.
    #[cfg(test)]
    wait_hook::fire();
    if let Err(outcome) = authorize_remote(requester) {
        return outcome;
    }
    let kind_name = original_kind_name.unwrap_or_else(|| "unknown".to_owned());
    let audit_entry = match operator_credential_id {
        Some(cred_id) => AuditEntry::new_approval_rejected_remote(
            kind_name,
            nonce,
            cred_id,
            uuid::Uuid::new_v4().to_string(),
        ),
        None => AuditEntry::new_approval_rejected(
            kind_name,
            nonce,
            resolved.surface.as_str(),
            uuid::Uuid::new_v4().to_string(),
        ),
    };
    if let Err(e) = writer.write_entry(audit_entry) {
        tracing::warn!(
            error = %e,
            event_kind,
            "reject: the rejection row was not written; the entry stays pending"
        );
        return Outcome::Unavailable;
    }
    drop(writer);

    // A persist failure here leaves a row recording a rejection that did not
    // take effect; the entry stays pending.
    match store.reject(nonce, now_ms, REJECT_TOMBSTONE_TTL_MS) {
        Ok(true) => Outcome::Rejected,
        Ok(false) => {
            // The store lock keeps the validated entry present through this call.
            Outcome::AlreadyResolved { attestation: None }
        }
        Err(e) => {
            tracing::warn!(error = %e, "reject: store reject failed after the rejection row");
            Outcome::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_core::approval::attestation::{compute_attestation_v4, verify_attestation};
    use stellar_agent_core::approval::operator_credentials::{
        OperatorApprovalCredential, OperatorApprovalCredentialStore,
    };
    use stellar_agent_core::approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, decode_sha256_hex, fixtures,
        process_uid_for_attestation,
    };
    use tempfile::TempDir;

    const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

    struct Fixture {
        _dir: TempDir,
        ctx: DecisionContext,
        raw_key: [u8; 32],
    }

    fn seed_key(service: &str) -> [u8; 32] {
        let key = [0xABu8; 32];
        let entry = KeyringEntry::new(service, "default").unwrap();
        entry.set_password(&URL_SAFE_NO_PAD.encode(key)).unwrap();
        key
    }

    fn fixture(tag: &str) -> Fixture {
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("default.toml");
        let audit_path = dir.path().join("audit.log");
        let grant_path = dir.path().join("grants.toml");
        let svc = format!("stellar-agent-attestation-ui-{tag}");
        let raw_key = seed_key(&svc);
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_path, None).expect("open audit writer"),
        ));
        let ctx = DecisionContext::new(
            stellar_agent_core::approval::ApprovalContext::from_profile(
                "ui-test",
                &stellar_agent_core::profile::schema::Profile::builder_testnet(
                    "svc", "default", "nonce", "default",
                )
                .build(),
            ),
            store_path,
            KeyringEntryRef::new(svc, "default"),
            stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("ui-test"),
            audit_writer,
            Some(grant_path),
        );
        Fixture {
            _dir: dir,
            ctx,
            raw_key,
        }
    }

    fn uid() -> String {
        process_uid_for_attestation().expect("uid available on test host")
    }

    fn insert(ctx: &DecisionContext, entry: PendingApproval) -> String {
        let nonce = entry.approval_nonce.clone();
        let mut store = PendingApprovalStore::open(ctx.store_path.clone()).unwrap();
        store
            .insert(entry, timefmt::now_unix_ms().unwrap())
            .unwrap();
        nonce
    }

    fn payment_entry(ttl_ms: u64) -> PendingApproval {
        fixtures::payment_pending(
            SOURCE_G,
            DEST_G,
            "XLM",
            2_500_000,
            None,
            100,
            1_234_567,
            uid(),
            ttl_ms,
        )
    }

    /// A payment entry stamped with a `process_uid` that can never equal the
    /// test host's real uid, simulating an entry parked by a different OS
    /// user's agent process.
    fn foreign_payment_entry(ttl_ms: u64) -> PendingApproval {
        fixtures::payment_pending(
            SOURCE_G,
            DEST_G,
            "XLM",
            2_500_000,
            None,
            100,
            1_234_567,
            "99999999".to_owned(),
            ttl_ms,
        )
    }

    #[test]
    fn approval_classifications_use_wire_codes() {
        use stellar_agent_core::ApprovalFailure;
        let cases = [
            (
                ApprovalFailure::UserMismatch {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.user_mismatch",
            ),
            (
                ApprovalFailure::Expired {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.expired",
            ),
            (
                ApprovalFailure::NotFound {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.not_found",
            ),
            (
                ApprovalFailure::AlreadyAttested {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.already_attested",
            ),
            (
                ApprovalFailure::BindingMismatch {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.binding_mismatch",
            ),
            (
                ApprovalFailure::WrongKind {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.wrong_kind",
            ),
            (
                ApprovalFailure::Rejected {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.rejected",
            ),
            (
                ApprovalFailure::Consumed {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.consumed",
            ),
            (
                ApprovalFailure::EntryInconsistent {
                    detail: "plain diagnostic".to_owned(),
                },
                "approval.entry_inconsistent",
            ),
        ];
        for (failure, code) in cases {
            let error = WalletError::Approval(failure);
            assert_eq!(error.message(), "plain diagnostic");
            assert!(approval_code_is(&error, code));
        }
    }

    #[test]
    fn approval_classifications_ignore_message_tokens() {
        for code in [
            "approval.user_mismatch",
            "approval.expired",
            "approval.not_found",
            "approval.already_attested",
            "approval.binding_mismatch",
            "approval.wrong_kind",
            "approval.rejected",
            "approval.consumed",
            "approval.entry_inconsistent",
        ] {
            let unrelated =
                WalletError::Internal(stellar_agent_core::InternalError::UnexpectedState {
                    detail: format!("unrelated diagnostic contains {code}: quoted text"),
                });
            assert!(!approval_code_is(&unrelated, code));
        }
    }

    /// An entry whose stored digest is not its envelope's is refused as
    /// inconsistent: nothing is attested and the entry stays pending.
    #[test]
    #[serial]
    fn approve_inconsistent_entry_is_refused() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("inconsistent");
        let mut entry = payment_entry(DEFAULT_TTL_MS);
        let ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        *envelope_xdr_b64 = fixtures::payment_envelope(SOURCE_G, SOURCE_G, "XLM", 9, None, 100, 1);
        let nonce = insert(&fx.ctx, entry);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Inconsistent);
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        assert!(store.get(&nonce).unwrap().attestation_blob_b64.is_none());
    }

    #[test]
    #[serial]
    fn approve_payment_mints_verifiable_attestation() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("payment");
        let entry = payment_entry(DEFAULT_TTL_MS);
        let process_uid = entry.process_uid.clone();
        let envelope_sha256_hex = match &entry.kind {
            ApprovalKind::PaymentSimulated {
                envelope_sha256_hex,
                ..
            } => envelope_sha256_hex.clone(),
            _ => unreachable!(),
        };
        let attested = entry.clone();
        let nonce = insert(&fx.ctx, entry);

        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        let attestation = match outcome {
            Outcome::Attested { attestation, .. } => attestation.expect("payment surfaces a blob"),
            other => panic!("expected Attested, got {other:?}"),
        };

        // Independently verify the surfaced blob against the attestation key.
        let sha = decode_sha256_hex(&envelope_sha256_hex).unwrap();
        let expected = compute_attestation_v4(
            &fx.raw_key,
            &fx.ctx.context.binding(),
            &nonce,
            &sha,
            &process_uid,
            &attested.attested_lifetime(),
            &AttestedApprover::Local,
        );
        let blob: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&attestation)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(blob, expected);
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let persisted = store.get(&nonce).unwrap();
        assert!(persisted.attested_approver == Some(AttestedApprover::Local));
        assert!(verify_attestation(
            &fx.raw_key,
            &fx.ctx.context.binding(),
            &nonce,
            &sha,
            &process_uid,
            &persisted.attestation_scope().unwrap(),
            &blob
        ));
    }

    /// An attestation key equal to the profile's owner public key in the
    /// older form is refused. The decision is unavailable, nothing is
    /// attested, and the `warn` line carries the owner code without the raw
    /// value.
    #[test]
    #[serial]
    fn approve_refuses_an_attestation_key_equal_to_the_owner_key() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("owner");
        let owner = KeyringEntryRef::default_owner_key("ui-test");
        let older_form = URL_SAFE_NO_PAD.encode(fx.raw_key);
        KeyringEntry::new(&owner.service, &owner.account)
            .unwrap()
            .set_password(&older_form)
            .unwrap();
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));

        let mut outcome = None;
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            outcome = Some(apply_decision(
                &fx.ctx,
                Decision::Approve {
                    nonce: nonce.clone(),
                },
                &RequestIdentity::Local,
            ));
        });
        assert!(
            matches!(outcome, Some(Outcome::Unavailable)),
            "expected Unavailable, got {outcome:?}"
        );
        assert!(!logs.contains(&older_form), "the raw value is never logged");
        assert!(logs.contains("WARN"), "{logs}");
        assert!(
            logs.contains("validation.key_matches_owner_public_key"),
            "{logs}"
        );
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let entry = store.get(&nonce).expect("the entry stays");
        assert!(entry.attestation_blob_b64.is_none(), "nothing is attested");
    }

    #[test]
    #[serial]
    fn approve_payment_mainnet_mints_verifiable_attestation() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut fx = fixture("payment-mainnet");
        fx.ctx.context.chain_id = "stellar:mainnet".to_owned();
        let entry = payment_entry(DEFAULT_TTL_MS);
        let process_uid = entry.process_uid.clone();
        let envelope_sha256_hex = match &entry.kind {
            ApprovalKind::PaymentSimulated {
                envelope_sha256_hex,
                ..
            } => envelope_sha256_hex.clone(),
            _ => unreachable!(),
        };
        let attested = entry.clone();
        let nonce = insert(&fx.ctx, entry);

        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        let attestation = match outcome {
            Outcome::Attested { attestation, .. } => attestation.expect("payment surfaces a blob"),
            other => panic!("expected Attested, got {other:?}"),
        };

        // Independently verify the surfaced blob against the attestation key.
        let sha = decode_sha256_hex(&envelope_sha256_hex).unwrap();
        let expected = compute_attestation_v4(
            &fx.raw_key,
            &fx.ctx.context.binding(),
            &nonce,
            &sha,
            &process_uid,
            &attested.attested_lifetime(),
            &AttestedApprover::Local,
        );
        let blob: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&attestation)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(blob, expected);
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let persisted = store.get(&nonce).unwrap();
        assert!(persisted.attested_approver == Some(AttestedApprover::Local));
        assert!(verify_attestation(
            &fx.raw_key,
            &fx.ctx.context.binding(),
            &nonce,
            &sha,
            &process_uid,
            &persisted.attestation_scope().unwrap(),
            &blob
        ));
    }

    #[test]
    #[serial]
    fn approve_claim_mints_attestation() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("claim");
        let entry = fixtures::claim_pending(
            SOURCE_G,
            [0x0a; 32],
            Some(("XLM", 500)),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        );
        let nonce = insert(&fx.ctx, entry);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        assert!(matches!(
            outcome,
            Outcome::Attested {
                attestation: Some(_),
                ..
            }
        ));
    }

    #[test]
    #[serial]
    fn approve_toolset_gate_consumes_entry_and_surfaces_no_blob() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("toolset");
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "XLM".to_owned(),
            0,
            1_000_000,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = insert(&fx.ctx, entry);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert!(matches!(
            outcome,
            Outcome::Attested {
                attestation: None,
                ..
            }
        ));
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        assert!(store.get(&nonce).is_none(), "gate entry must be consumed");
    }

    #[test]
    #[serial]
    fn approve_trustline_clawback_opt_in_attests_without_blob() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("trustline");
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            "Test SDF Network ; September 2015".to_owned(),
            "USDC".to_owned(),
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = insert(&fx.ctx, entry);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        assert!(matches!(
            outcome,
            Outcome::Attested {
                attestation: None,
                ..
            }
        ));
    }

    #[test]
    #[serial]
    fn approve_sign_with_passkey_is_wrong_kind() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("passkey");
        let entry = PendingApproval::new_passkey_pending(
            [0x01u8; 32],
            vec![0u8; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![0],
            [0x02u8; 32],
            "localhost".to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = insert(&fx.ctx, entry);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::WrongKind);
    }

    #[test]
    #[serial]
    fn approve_expired_entry_refuses() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("expired");
        let entry = payment_entry(1);
        let nonce = insert(&fx.ctx, entry);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Expired);
    }

    #[test]
    #[serial]
    fn approve_unknown_nonce_is_not_found() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("missing");
        // Open once so the store file exists but is empty.
        let _ = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::NotFound);
    }

    #[test]
    #[serial]
    fn approve_already_attested_reshows_blob() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("reshow");
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        let first = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        let first_blob = match first {
            Outcome::Attested {
                attestation: Some(b),
                ..
            } => b,
            other => panic!("expected Attested, got {other:?}"),
        };
        let second = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        match second {
            Outcome::AlreadyResolved {
                attestation: Some(b),
            } => assert_eq!(b, first_blob),
            other => panic!("expected AlreadyResolved with blob, got {other:?}"),
        }
    }

    #[test]
    #[serial]
    fn reject_creates_tombstone_and_is_idempotent() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("reject");
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Reject {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Rejected);

        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let entry = store.get(&nonce).expect("tombstone present");
        assert!(matches!(entry.kind, ApprovalKind::Rejected { .. }));
        drop(store);

        // Second reject is idempotent.
        let again = apply_decision(&fx.ctx, Decision::Reject { nonce }, &RequestIdentity::Local);
        assert_eq!(again, Outcome::AlreadyResolved { attestation: None });
    }

    #[test]
    #[serial]
    fn approve_rejected_tombstone_is_already_resolved_not_panic() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("reject-then-approve");
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        assert_eq!(
            apply_decision(
                &fx.ctx,
                Decision::Reject {
                    nonce: nonce.clone()
                },
                &RequestIdentity::Local
            ),
            Outcome::Rejected
        );
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::AlreadyResolved { attestation: None });
    }

    #[test]
    #[serial]
    fn reject_unknown_nonce_is_already_resolved() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("reject-missing");
        let _ = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Reject {
                nonce: "BBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::AlreadyResolved { attestation: None });
    }

    #[test]
    #[serial]
    fn approve_foreign_process_uid_is_user_mismatch() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("approve-mismatch");
        let nonce = insert(&fx.ctx, foreign_payment_entry(DEFAULT_TTL_MS));
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::UserMismatch);

        // The entry must be untouched: no attestation was minted for a caller
        // whose OS identity does not match the entry's.
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        assert!(store.get(&nonce).unwrap().attestation_blob_b64.is_none());
    }

    #[test]
    #[serial]
    fn reject_foreign_process_uid_is_user_mismatch() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("reject-mismatch");
        let nonce = insert(&fx.ctx, foreign_payment_entry(DEFAULT_TTL_MS));
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Reject {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::UserMismatch);

        // Without the ApproverIdentity gate, a cross-user caller could inject
        // a terminal "no" the operator never gave: assert the entry was NOT
        // turned into a `Rejected` tombstone.
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let entry = store.get(&nonce).unwrap();
        assert!(
            !matches!(entry.kind, ApprovalKind::Rejected { .. }),
            "a foreign-uid caller must not be able to reject this entry"
        );
    }

    /// `open_store`'s non-`WriterLocked` error arm (a genuinely corrupt store
    /// file, not lock contention) maps to `Outcome::Unavailable` — distinct
    /// from the `WriterLocked` -> `Outcome::Busy` path exercised elsewhere.
    #[test]
    #[serial]
    fn approve_with_corrupt_store_file_is_unavailable_not_busy() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("corrupt-store");
        std::fs::write(&fx.ctx.store_path, b"this is not valid toml {{{").unwrap();
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Unavailable);
    }

    #[test]
    #[serial]
    fn reject_with_corrupt_store_file_is_unavailable_not_busy() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("corrupt-store-reject");
        std::fs::write(&fx.ctx.store_path, b"this is not valid toml {{{").unwrap();
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Reject {
                nonce: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Unavailable);
    }
    #[test]
    #[serial]
    fn approve_refuses_another_chain_with_binding_mismatch() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("binding-mismatch");
        let definition = stellar_agent_core::approval::ContextRuleProposalSnapshot::new(
            stellar_agent_core::approval::RuleProposalContextType::Default,
            "rule".to_owned(),
            None,
            vec![stellar_agent_core::approval::RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let entry = stellar_agent_core::approval::PendingApproval::new_rule_proposal_pending(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "Public Global Stellar Network ; September 2015".to_owned(),
            "stellar:mainnet".to_owned(),
            definition,
            [1; 32],
            "rule".to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = insert(&fx.ctx, entry);
        assert_eq!(
            apply_decision(
                &fx.ctx,
                Decision::Approve {
                    nonce: nonce.clone()
                },
                &RequestIdentity::Local
            ),
            Outcome::BindingMismatch
        );
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        assert!(store.get(&nonce).unwrap().attestation_blob_b64.is_none());
    }

    // ── Decisions take effect only after their rows ──────────────────────────

    use stellar_agent_core::audit_log::{TipAnchor, TipAnchorStore, TipAnchorStoreError};

    /// An in-process anchor store, so a test writer refuses an append on a log
    /// rolled back underneath it.
    #[derive(Debug, Default)]
    struct MemAnchor(
        Mutex<(
            Option<TipAnchor>,
            u64,
            Option<stellar_agent_core::audit_log::OutboxState>,
        )>,
    );

    impl TipAnchorStore for MemAnchor {
        fn load_outbox_state(
            &self,
        ) -> Result<Option<stellar_agent_core::audit_log::OutboxState>, TipAnchorStoreError>
        {
            Ok(self.0.lock().unwrap().2.clone())
        }
        fn store_outbox_state(
            &self,
            state: &stellar_agent_core::audit_log::OutboxState,
        ) -> Result<(), TipAnchorStoreError> {
            self.0.lock().unwrap().2 = Some(state.clone());
            Ok(())
        }

        fn load_anchor(&self) -> Result<Option<TipAnchor>, TipAnchorStoreError> {
            Ok(self.0.lock().unwrap().0.clone())
        }

        fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .0
                .as_ref()
                .map(TipAnchor::to_keyring_value))
        }

        fn store_anchor(&self, anchor: &TipAnchor) -> Result<(), TipAnchorStoreError> {
            self.0.lock().unwrap().0 = Some(anchor.clone());
            Ok(())
        }

        fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError> {
            let mut state = self.0.lock().unwrap();
            state.1 += 1;
            Ok(state.1)
        }

        fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError> {
            Ok(Some(self.0.lock().unwrap().1))
        }
    }

    fn audit_path(fx: &Fixture) -> std::path::PathBuf {
        fx.ctx.store_path.parent().unwrap().join("audit.log")
    }

    fn rows_of_kind(path: &std::path::Path, kind: &str) -> usize {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains(&format!(r#""kind":"{kind}""#)))
            .count()
    }

    fn poison(writer: &Arc<Mutex<AuditWriter>>) {
        let held = Arc::clone(writer);
        let _ = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            panic!("poison the audit writer mutex");
        })
        .join();
        assert!(writer_is_poisoned(writer));
    }

    fn writer_is_poisoned(writer: &Arc<Mutex<AuditWriter>>) -> bool {
        writer.lock().is_err()
    }

    /// Replaces the fixture's writer with an anchored one over a log that is
    /// then rolled back, so every append refuses.
    fn refusing_writer(fx: &mut Fixture) {
        let path = fx.ctx.store_path.parent().unwrap().join("anchored.log");
        let mut writer = AuditWriter::open_with_tip_anchor(
            path.clone(),
            None,
            Arc::new(MemAnchor::default()) as Arc<dyn TipAnchorStore>,
            stellar_agent_core::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        writer
            .write_entry(AuditEntry::new_approval_rejected(
                "PaymentSimulated",
                "AAAAAAAAAAAAAAAAAAAAAA",
                "serve",
                "seed-row",
            ))
            .unwrap();
        std::fs::write(&path, b"").unwrap();
        fx.ctx.audit_writer = Arc::new(Mutex::new(writer));
    }

    fn still_pending(fx: &Fixture, nonce: &str) -> bool {
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let entry = store.get(nonce).expect("the entry stays");
        matches!(entry.kind, ApprovalKind::PaymentSimulated { .. })
            && entry.attestation_blob_b64.is_none()
    }

    /// Another handle attests the entry after the inbox validated it and
    /// before it attests: the inbox answers with the stored attestation and
    /// writes no row.
    #[test]
    #[serial]
    fn approving_an_entry_attested_by_another_handle_reshows_the_stored_blob_with_no_row() {
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let store_path = Arc::new(Mutex::new(None::<std::path::PathBuf>));
        let nonce_slot = Arc::new(Mutex::new(None::<String>));
        let hook = {
            let fired = Arc::clone(&fired);
            let store_path = Arc::clone(&store_path);
            let nonce_slot = Arc::clone(&nonce_slot);
            Arc::new(move || {
                let (Some(path), Some(nonce)) = (
                    store_path.lock().unwrap().clone(),
                    nonce_slot.lock().unwrap().clone(),
                ) else {
                    return;
                };
                if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let mut other = PendingApprovalStore::open(path).unwrap();
                other
                    .record_attestation(&nonce, [0x01; 32], AttestedApprover::Local)
                    .unwrap();
            }) as Arc<dyn Fn() + Send + Sync>
        };
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                "stellar-agent-attestation-ui-raced",
                "default",
                hook,
            ),
        ])
        .unwrap();
        let fx = fixture("raced");
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        *store_path.lock().unwrap() = Some(fx.ctx.store_path.clone());
        *nonce_slot.lock().unwrap() = Some(nonce.clone());

        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the other handle attested between validation and the attest"
        );
        assert_eq!(
            outcome,
            Outcome::AlreadyResolved {
                attestation: Some(URL_SAFE_NO_PAD.encode([0x01; 32])),
            }
        );
        assert_eq!(rows_of_kind(&audit_path(&fx), "approval_attested"), 0);
    }

    /// Approves a payment entry that another handle resolves with `resolve`
    /// after the inbox validated it and before it attests. A read hook at the
    /// attestation key runs `resolve` once; the inbox has released the store
    /// lock by then.
    fn approve_an_entry_resolved_by_another_handle(
        tag: &str,
        resolve: fn(&mut PendingApprovalStore, &str),
    ) -> (Fixture, Outcome) {
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target = Arc::new(Mutex::new(None::<(std::path::PathBuf, String)>));
        let hook = {
            let fired = Arc::clone(&fired);
            let target = Arc::clone(&target);
            Arc::new(move || {
                let Some((path, nonce)) = target.lock().unwrap().clone() else {
                    return;
                };
                if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let mut other = PendingApprovalStore::open(path).unwrap();
                resolve(&mut other, &nonce);
            }) as Arc<dyn Fn() + Send + Sync>
        };
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                &format!("stellar-agent-attestation-ui-{tag}"),
                "default",
                hook,
            ),
        ])
        .unwrap();
        let fx = fixture(tag);
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        *target.lock().unwrap() = Some((fx.ctx.store_path.clone(), nonce.clone()));

        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve { nonce },
            &RequestIdentity::Local,
        );
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the other handle resolved the entry between validation and the attest"
        );
        (fx, outcome)
    }

    /// A commit spends the entry after the inbox validated it: the decision is
    /// already resolved, no attestation is handed back, and no row is written.
    #[test]
    #[serial]
    fn approving_an_entry_consumed_since_validation_is_already_resolved_with_no_row() {
        let (fx, outcome) =
            approve_an_entry_resolved_by_another_handle("raced-consumed", |store, nonce| {
                store
                    .record_attestation(nonce, [0x01; 32], AttestedApprover::Local)
                    .unwrap();
                store
                    .consume(
                        nonce,
                        &"ab".repeat(32),
                        stellar_agent_core::approval::ConsumedOutcome::Confirmed,
                    )
                    .unwrap();
            });
        assert_eq!(outcome, Outcome::AlreadyResolved { attestation: None });
        assert_eq!(rows_of_kind(&audit_path(&fx), "approval_attested"), 0);
    }

    /// The operator rejects the entry from another surface after the inbox
    /// validated it.
    #[test]
    #[serial]
    fn approving_an_entry_rejected_since_validation_is_already_resolved_with_no_row() {
        let (fx, outcome) =
            approve_an_entry_resolved_by_another_handle("raced-rejected", |store, nonce| {
                store
                    .reject(nonce, timefmt::now_unix_ms().unwrap(), DEFAULT_TTL_MS)
                    .unwrap();
            });
        assert_eq!(outcome, Outcome::AlreadyResolved { attestation: None });
        assert_eq!(rows_of_kind(&audit_path(&fx), "approval_attested"), 0);
    }

    #[test]
    #[serial]
    fn approve_with_a_poisoned_writer_mutex_is_unavailable_and_changes_no_store() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("poison-approve");
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        poison(&fx.ctx.audit_writer);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Unavailable);
        assert!(still_pending(&fx, &nonce));
        // A poisoned mutex keeps refusing until the inbox restarts.
        let again = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(again, Outcome::Unavailable);
        assert!(still_pending(&fx, &nonce));
    }

    #[test]
    #[serial]
    fn reject_with_a_poisoned_writer_mutex_is_unavailable_and_changes_no_store() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("poison-reject");
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        poison(&fx.ctx.audit_writer);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Reject {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Unavailable);
        assert!(still_pending(&fx, &nonce));
    }

    #[test]
    #[serial]
    fn a_reject_whose_row_cannot_be_written_leaves_the_entry_pending() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut fx = fixture("reject-row-refused");
        refusing_writer(&mut fx);
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Reject {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Unavailable);
        assert!(
            still_pending(&fx, &nonce),
            "the rejection did not take effect"
        );
    }

    #[test]
    #[serial]
    fn an_approve_whose_row_cannot_be_written_persists_nothing() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut fx = fixture("approve-row-refused");
        refusing_writer(&mut fx);
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &RequestIdentity::Local,
        );
        assert_eq!(outcome, Outcome::Unavailable);
        assert!(
            still_pending(&fx, &nonce),
            "the approval did not take effect"
        );
    }

    #[test]
    #[serial]
    fn approve_and_reject_write_their_rows() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("rows");
        let approved = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        let rejected = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        assert!(matches!(
            apply_decision(
                &fx.ctx,
                Decision::Approve { nonce: approved },
                &RequestIdentity::Local
            ),
            Outcome::Attested { .. }
        ));
        assert_eq!(
            apply_decision(
                &fx.ctx,
                Decision::Reject { nonce: rejected },
                &RequestIdentity::Local
            ),
            Outcome::Rejected
        );
        assert_eq!(rows_of_kind(&audit_path(&fx), "approval_attested"), 1);
        assert_eq!(rows_of_kind(&audit_path(&fx), "approval_rejected"), 1);
    }

    const RP_ID: &str = "wallet.test.internal";

    fn credential_id(seed: u8) -> String {
        URL_SAFE_NO_PAD.encode([seed; 16])
    }

    fn profile_dir(fx: &Fixture) -> std::path::PathBuf {
        fx.ctx.store_path.parent().unwrap().join("profiles")
    }

    fn credentials_path(fx: &Fixture) -> std::path::PathBuf {
        fx.ctx
            .store_path
            .parent()
            .unwrap()
            .join("operator-credentials.toml")
    }

    /// Writes the fixture's profile to disk with remote approval enabled for
    /// `ids`.
    fn allow(fx: &Fixture, ids: &[String]) {
        let mut profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
            "svc", "default", "nonce", "default",
        )
        .build();
        profile.remote_approval = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "bind": "127.0.0.1:8443",
                "rp_id": RP_ID,
                "allowed_credentials": ids,
            }))
            .unwrap(),
        );
        stellar_agent_core::profile::loader::save_to_dir("ui-test", &profile, &profile_dir(fx))
            .unwrap();
    }

    fn enroll(fx: &Fixture, id: &str) {
        let mut key = vec![0x04u8; 65];
        key[1] = 7;
        OperatorApprovalCredentialStore::new(credentials_path(fx))
            .enroll(OperatorApprovalCredential {
                credential_id_b64url: id.to_owned(),
                public_key_sec1_b64: URL_SAFE_NO_PAD.encode(key),
                rp_id: RP_ID.to_owned(),
                label: "device".to_owned(),
                registered_at_unix_ms: 1,
                sign_count: None,
            })
            .unwrap();
    }

    /// A remote requester whose assertion for `nonce` was verified for the
    /// credential `id`, reading its authorization from the fixture's files.
    fn remote_requester(fx: &Fixture, id: &str, nonce: &str) -> RequestIdentity {
        let witness = stellar_agent_core::approval::VerifiedPasskeyAssertion::new_verified(
            nonce,
            Ok::<(), ()>(()),
        )
        .unwrap();
        RequestIdentity::Remote {
            identity: ApproverIdentity::from_verified_passkey_assertion(id, witness),
            authority: Arc::new(
                RemoteApprovalAuthority::from_paths(
                    "ui-test".to_owned(),
                    profile_dir(fx),
                    credentials_path(fx),
                )
                .unwrap(),
            ),
            chain: Caip2::Testnet,
            rp_id: RP_ID.to_owned(),
        }
    }

    /// An authorized remote approval persists a version 4 attestation that
    /// names the verified credential and writes the remote consent row.
    #[test]
    #[serial]
    fn remote_approve_attests_the_verified_credential() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("remote-approve");
        allow(&fx, &[credential_id(1)]);
        enroll(&fx, &credential_id(1));
        let entry = payment_entry(DEFAULT_TTL_MS);
        let nonce = insert(&fx.ctx, entry);
        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
            &remote_requester(&fx, &credential_id(1), &nonce),
        );
        assert!(matches!(outcome, Outcome::Attested { .. }), "{outcome:?}");
        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let record = store.get(&nonce).unwrap();
        assert_eq!(record.attestation_version, 4);
        assert!(
            record.attested_approver
                == Some(AttestedApprover::Remote {
                    credential_id_b64url: credential_id(1),
                })
        );
        assert_eq!(
            rows_of_kind(&audit_path(&fx), "approval_attested_remote"),
            1
        );
    }

    /// The credential is removed from the allowlist while the attestation key
    /// loads: the approval refuses after the wait, and neither the
    /// attestation nor the consent row is persisted. Removing the enrollment
    /// instead refuses the same way.
    #[test]
    #[serial]
    fn revocation_during_keyring_wait_refuses() {
        for revoke in ["allowlist", "enrollment"] {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let fx = fixture(&format!("remote-wait-{revoke}"));
            allow(&fx, &[credential_id(1), credential_id(2)]);
            enroll(&fx, &credential_id(1));
            enroll(&fx, &credential_id(2));
            let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
            let profiles = profile_dir(&fx);
            let credentials = credentials_path(&fx);
            let fired = std::rc::Rc::new(std::cell::Cell::new(false));
            let hook_fired = std::rc::Rc::clone(&fired);
            wait_hook::install(move || {
                hook_fired.set(true);
                revoke_first_credential(&profiles, &credentials, revoke);
            });
            let outcome = apply_decision(
                &fx.ctx,
                Decision::Approve {
                    nonce: nonce.clone(),
                },
                &remote_requester(&fx, &credential_id(1), &nonce),
            );
            assert!(fired.get());
            assert_eq!(outcome, Outcome::Unauthorized);
            assert!(still_pending(&fx, &nonce));
            assert_eq!(
                rows_of_kind(&audit_path(&fx), "approval_attested_remote"),
                0
            );

            // The credential the edit left authorized still approves.
            let outcome = apply_decision(
                &fx.ctx,
                Decision::Approve {
                    nonce: nonce.clone(),
                },
                &remote_requester(&fx, &credential_id(2), &nonce),
            );
            assert!(matches!(outcome, Outcome::Attested { .. }), "{outcome:?}");
        }
    }

    /// Revokes `credential_id(1)` the way `revoke` names: by editing the
    /// profile's allowlist or by removing its enrollment.
    fn revoke_first_credential(
        profiles: &std::path::Path,
        credentials: &std::path::Path,
        revoke: &str,
    ) {
        if revoke == "allowlist" {
            let mut profile = stellar_agent_core::profile::loader::load_from_dir_without_overlays(
                "ui-test", profiles, None,
            )
            .unwrap();
            profile
                .remote_approval
                .as_mut()
                .unwrap()
                .allowed_credentials
                .retain(|id| *id != credential_id(1));
            stellar_agent_core::profile::loader::save_to_dir("ui-test", &profile, profiles)
                .unwrap();
        } else {
            assert!(
                OperatorApprovalCredentialStore::new(credentials.to_path_buf())
                    .remove(&credential_id(1))
                    .unwrap()
            );
        }
    }

    /// The credential is revoked while the reject waits for the audit-writer
    /// lock: the rejection refuses after the wait, and neither the rejection
    /// row nor the tombstone is written. The credential the edit left
    /// authorized still rejects.
    #[test]
    #[serial]
    fn revocation_while_reject_waits_for_the_writer_refuses() {
        for revoke in ["allowlist", "enrollment"] {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let fx = fixture(&format!("remote-reject-wait-{revoke}"));
            allow(&fx, &[credential_id(1), credential_id(2)]);
            enroll(&fx, &credential_id(1));
            enroll(&fx, &credential_id(2));
            let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
            let profiles = profile_dir(&fx);
            let credentials = credentials_path(&fx);
            let fired = std::rc::Rc::new(std::cell::Cell::new(false));
            let hook_fired = std::rc::Rc::clone(&fired);
            wait_hook::install(move || {
                hook_fired.set(true);
                revoke_first_credential(&profiles, &credentials, revoke);
            });
            let outcome = apply_decision(
                &fx.ctx,
                Decision::Reject {
                    nonce: nonce.clone(),
                },
                &remote_requester(&fx, &credential_id(1), &nonce),
            );
            assert!(fired.get(), "{revoke}");
            assert_eq!(outcome, Outcome::Unauthorized, "{revoke}");
            assert!(still_pending(&fx, &nonce), "{revoke}");
            assert_eq!(
                rows_of_kind(&audit_path(&fx), "approval_rejected_remote"),
                0
            );

            let outcome = apply_decision(
                &fx.ctx,
                Decision::Reject {
                    nonce: nonce.clone(),
                },
                &remote_requester(&fx, &credential_id(2), &nonce),
            );
            assert_eq!(outcome, Outcome::Rejected, "{revoke}");
            assert_eq!(
                rows_of_kind(&audit_path(&fx), "approval_rejected_remote"),
                1
            );
            let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
            assert!(matches!(
                store.get(&nonce).unwrap().kind,
                ApprovalKind::Rejected { .. }
            ));
        }
    }

    /// A remote requester the current files do not admit can neither approve
    /// nor reject, and a remote requester without a passkey identity is
    /// refused the same way; nothing is persisted and no row is written.
    #[test]
    #[serial]
    fn unauthorized_remote_requester_decides_nothing() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("remote-unauthorized");
        allow(&fx, &[credential_id(2)]);
        enroll(&fx, &credential_id(1));
        enroll(&fx, &credential_id(2));
        let nonce = insert(&fx.ctx, payment_entry(DEFAULT_TTL_MS));
        for decision in [
            Decision::Approve {
                nonce: nonce.clone(),
            },
            Decision::Reject {
                nonce: nonce.clone(),
            },
        ] {
            assert_eq!(
                apply_decision(
                    &fx.ctx,
                    decision,
                    &remote_requester(&fx, &credential_id(1), &nonce)
                ),
                Outcome::Unauthorized
            );
        }
        let RequestIdentity::Remote {
            authority,
            chain,
            rp_id,
            ..
        } = remote_requester(&fx, &credential_id(2), &nonce)
        else {
            unreachable!()
        };
        let os_identity = RequestIdentity::Remote {
            identity: ApproverIdentity::OsUid(uid()),
            authority,
            chain,
            rp_id,
        };
        for decision in [
            Decision::Approve {
                nonce: nonce.clone(),
            },
            Decision::Reject {
                nonce: nonce.clone(),
            },
        ] {
            assert_eq!(
                apply_decision(&fx.ctx, decision, &os_identity),
                Outcome::Unauthorized
            );
        }
        assert!(still_pending(&fx, &nonce));
        let log = std::fs::read_to_string(audit_path(&fx)).unwrap_or_default();
        assert!(!log.contains("approval_"), "{log}");
    }
}

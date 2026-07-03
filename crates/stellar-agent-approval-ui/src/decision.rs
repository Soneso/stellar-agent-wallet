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

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::{
    ApprovalKind, ApproverIdentity, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF,
    PendingApprovalStore, Surface, attest_and_persist, load_and_validate_entry,
    load_attestation_key, open_with_retry, process_uid_for_attestation,
};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_core::timefmt;

/// TTL applied to a `Rejected` tombstone written by the approval-inbox server.
///
/// One hour: long enough that a re-issued or replayed nonce resolves to the
/// tombstone (idempotent reject) rather than reappearing as pending, short
/// enough to be swept by the normal expiry/gc path.
pub const REJECT_TOMBSTONE_TTL_MS: u64 = 3_600_000;

/// Origin string recorded in the `ApprovalAttested` / `ApprovalRejected` audit
/// events for actions driven by the approval-inbox server.
const SERVE_ORIGIN: &str = "serve";

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
    /// Profile whose approval store and grant store are acted upon.
    pub profile_name: String,
    /// Path to the profile's pending-approval store file.
    pub store_path: PathBuf,
    /// Keyring reference for the profile's attestation HMAC key.
    pub attestation_key_entry_ref: KeyringEntryRef,
    /// Shared audit-log writer for the profile.
    pub audit_writer: Arc<Mutex<AuditWriter>>,
    /// Optional grant-store path override for the `ToolsetFirstInvokeGate`
    /// branch. Production passes `None` (the path is resolved from the profile
    /// name); integration tests pass `Some(temp_dir_path)` for isolation.
    pub grant_store_path_override: Option<PathBuf>,
}

impl DecisionContext {
    /// Construct a decision context. Production callers pass `None` for
    /// `grant_store_path_override`.
    #[must_use]
    pub fn new(
        profile_name: String,
        store_path: PathBuf,
        attestation_key_entry_ref: KeyringEntryRef,
        audit_writer: Arc<Mutex<AuditWriter>>,
        grant_store_path_override: Option<PathBuf>,
    ) -> Self {
        Self {
            profile_name,
            store_path,
            attestation_key_entry_ref,
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
    /// No entry with this nonce exists.
    NotFound,
    /// The entry's kind is not one the attest path supports (for example a
    /// passkey kind, whose interactive flow lives in the WebAuthn bridge).
    WrongKind,
}

/// Apply one operator [`Decision`] against the profile's approval store.
///
/// This is synchronous file/keyring I/O plus at most one audit write — no
/// network — matching the CLI `approve` command's in-async-fn synchronous
/// house style. All authentication and CSRF checks happen at the HTTP boundary
/// before this is called.
///
/// # Panics
///
/// Never panics.
#[must_use]
pub fn apply_decision(ctx: &DecisionContext, decision: Decision) -> Outcome {
    match decision {
        Decision::Approve { nonce } => apply_approve(ctx, &nonce),
        Decision::Reject { nonce } => apply_reject(ctx, &nonce),
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

/// Returns `true` iff `err` carries the `approval.*` detail code `code`.
///
/// [`load_and_validate_entry`] and [`attest_and_persist`] document their
/// [`WalletError::Internal`] values as carrying an `approval.*` detail
/// PREFIX (`"<code>: <message>"`) — that prefix is the stable contract those
/// two functions commit to, even though `WalletError::code()` itself
/// collapses every one of these paths to the coarse
/// `"internal.unexpected_state"`. Matching is anchored on the `"<code>: "`
/// token rather than a bare substring scan of the full human-readable
/// message, so unrelated prose elsewhere in the message can never produce a
/// false match.
fn approval_detail_code_is(err: &WalletError, code: &str) -> bool {
    err.to_string().contains(&format!("{code}: "))
}

fn apply_approve(ctx: &DecisionContext, nonce: &str) -> Outcome {
    let store = match open_store(ctx, "approve") {
        Ok(s) => s,
        Err(outcome) => return outcome,
    };

    let uid = match process_uid_for_attestation() {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "approve: process uid derivation failed");
            return Outcome::Unavailable;
        }
    };
    let identity = ApproverIdentity::OsUid(uid);

    let entry = match load_and_validate_entry(&store, nonce, &identity) {
        Ok(e) => e,
        Err(e) => {
            if approval_detail_code_is(&e, "approval.user_mismatch") {
                return Outcome::UserMismatch;
            }
            if approval_detail_code_is(&e, "approval.expired") {
                return Outcome::Expired;
            }
            if approval_detail_code_is(&e, "approval.not_found") {
                return Outcome::NotFound;
            }
            if approval_detail_code_is(&e, "approval.already_attested") {
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

    let key = match load_attestation_key(&ctx.attestation_key_entry_ref) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "approve: attestation key load failed");
            return Outcome::Unavailable;
        }
    };

    let mut store = match open_store(ctx, "approve-persist") {
        Ok(s) => s,
        Err(outcome) => return outcome,
    };

    let mut audit_guard = ctx.audit_writer.lock().ok();
    let audit_ref: Option<&mut AuditWriter> = audit_guard.as_deref_mut().map(|w| &mut *w);

    let grant_override = ctx.grant_store_path_override.clone();
    let profile_name = ctx.profile_name.as_str();
    let result = attest_and_persist(
        &mut store,
        &entry,
        &key,
        Surface::Serve,
        audit_ref,
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
            if approval_detail_code_is(&e, "approval.wrong_kind") {
                return Outcome::WrongKind;
            }
            if approval_detail_code_is(&e, "approval.rejected") {
                // A rejected tombstone is already resolved; never a panic.
                return Outcome::AlreadyResolved { attestation: None };
            }
            if approval_detail_code_is(&e, "approval.already_attested") {
                let attestation = store
                    .get(nonce)
                    .and_then(|e| e.attestation_blob_b64.clone());
                return Outcome::AlreadyResolved { attestation };
            }
            tracing::warn!(error = %e, "approve: attest_and_persist failed");
            Outcome::Unavailable
        }
    }
}

fn apply_reject(ctx: &DecisionContext, nonce: &str) -> Outcome {
    let mut store = match open_store(ctx, "reject") {
        Ok(s) => s,
        Err(outcome) => return outcome,
    };

    // Idempotency + capture-before-mutate: read what we need, then mutate.
    // The full entry is cloned (not just its fields) because the
    // ApproverIdentity check below needs `process_uid`.
    let entry = store.get(nonce).cloned();
    let (already_resolved, resolved_attestation, original_kind_name) = match &entry {
        None => (true, None, None),
        Some(e) => match &e.kind {
            ApprovalKind::Rejected { .. } => (true, None, None),
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
    // running as a different OS user than the one that parked this entry
    // could inject a terminal "no" the operator never gave — reject is not
    // exempt from the cross-user binding just because it carries no
    // attestation.
    let uid = match process_uid_for_attestation() {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "reject: process uid derivation failed");
            return Outcome::Unavailable;
        }
    };
    let identity = ApproverIdentity::OsUid(uid);
    // `entry` is `Some` here: `already_resolved` is `true` for every arm
    // above where it is `None`.
    let Some(entry) = entry else {
        tracing::warn!("reject: entry unexpectedly absent after not-already-resolved check");
        return Outcome::Unavailable;
    };
    if !identity.matches_entry_process_uid(&entry.process_uid) {
        return Outcome::UserMismatch;
    }

    let now_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "reject: system clock read failed");
            return Outcome::Unavailable;
        }
    };

    match store.reject(nonce, now_ms, REJECT_TOMBSTONE_TTL_MS) {
        Ok(true) => {}
        Ok(false) => {
            // The entry vanished between the read and the reject — idempotent.
            return Outcome::AlreadyResolved { attestation: None };
        }
        Err(e) => {
            tracing::warn!(error = %e, "reject: store reject failed");
            return Outcome::Unavailable;
        }
    }

    // Audit is best-effort: a rejection is already durable by this point, and
    // an audit hiccup must never undo it.
    let kind_name = original_kind_name.unwrap_or_else(|| "unknown".to_owned());
    if let Ok(mut writer) = ctx.audit_writer.lock() {
        let audit_entry = AuditEntry::new_approval_rejected(
            kind_name,
            nonce,
            SERVE_ORIGIN,
            uuid::Uuid::new_v4().to_string(),
        );
        if let Err(e) = writer.write_entry(audit_entry) {
            tracing::warn!(error = %e, "reject: audit write failed; rejection already persisted");
        }
    }

    Outcome::Rejected
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
    use stellar_agent_core::approval::attestation::{compute_attestation, verify_attestation};
    use stellar_agent_core::approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, decode_sha256_hex,
        process_uid_for_attestation,
    };
    use tempfile::TempDir;

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
            "ui-test".to_owned(),
            store_path,
            KeyringEntryRef::new(svc, "default"),
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
        PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            None,
            100,
            1_234_567,
            uid(),
            ttl_ms,
        )
        .unwrap()
    }

    /// A payment entry stamped with a `process_uid` that can never equal the
    /// test host's real uid, simulating an entry parked by a different OS
    /// user's agent process.
    fn foreign_payment_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            None,
            100,
            1_234_567,
            "99999999".to_owned(),
            ttl_ms,
        )
        .unwrap()
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
        let nonce = insert(&fx.ctx, entry);

        let outcome = apply_decision(
            &fx.ctx,
            Decision::Approve {
                nonce: nonce.clone(),
            },
        );
        let attestation = match outcome {
            Outcome::Attested { attestation, .. } => attestation.expect("payment surfaces a blob"),
            other => panic!("expected Attested, got {other:?}"),
        };

        // Independently verify the surfaced blob against the attestation key.
        let sha = decode_sha256_hex(&envelope_sha256_hex).unwrap();
        let expected = compute_attestation(&fx.raw_key, &nonce, &sha, &process_uid);
        let blob: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&attestation)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(blob, expected);
        assert!(verify_attestation(
            &fx.raw_key,
            &nonce,
            &sha,
            &process_uid,
            &blob
        ));
    }

    #[test]
    #[serial]
    fn approve_claim_mints_attestation() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fx = fixture("claim");
        let entry = PendingApproval::new_claim_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "a".repeat(72),
            "B".to_owned() + &"A".repeat(57),
            "XLM".to_owned(),
            500,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = insert(&fx.ctx, entry);
        let outcome = apply_decision(&fx.ctx, Decision::Approve { nonce });
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
        let outcome = apply_decision(&fx.ctx, Decision::Approve { nonce });
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
        let outcome = apply_decision(&fx.ctx, Decision::Approve { nonce });
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
        let outcome = apply_decision(&fx.ctx, Decision::Approve { nonce });
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
        );
        let first_blob = match first {
            Outcome::Attested {
                attestation: Some(b),
                ..
            } => b,
            other => panic!("expected Attested, got {other:?}"),
        };
        let second = apply_decision(&fx.ctx, Decision::Approve { nonce });
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
        );
        assert_eq!(outcome, Outcome::Rejected);

        let store = PendingApprovalStore::open(fx.ctx.store_path.clone()).unwrap();
        let entry = store.get(&nonce).expect("tombstone present");
        assert!(matches!(entry.kind, ApprovalKind::Rejected { .. }));
        drop(store);

        // Second reject is idempotent.
        let again = apply_decision(&fx.ctx, Decision::Reject { nonce });
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
                }
            ),
            Outcome::Rejected
        );
        let outcome = apply_decision(&fx.ctx, Decision::Approve { nonce });
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
        );
        assert_eq!(outcome, Outcome::Unavailable);
    }
}

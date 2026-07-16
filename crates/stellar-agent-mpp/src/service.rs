//! Shared durable orchestration used by the CLI and MCP host boundaries.

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::approval::store::{PendingApproval, PendingApprovalStore};
use stellar_agent_core::policy::v1::ValueEffects;
use stellar_agent_network::signing::Signer;

use crate::{
    AuthorizationRecord, AuthorizationStatus, MppAuthorizationStore, MppError,
    PreparedSponsoredCharge, RequestContext,
};

/// Policy result that controls whether a prepared authorization is immediately
/// committable or must enter the wallet-owned approval spine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDisposition {
    /// Policy allowed the exact validated value effect.
    Allow,
    /// Policy requires explicit operator approval.
    RequireApproval,
}

/// Non-secret prepare result shared by CLI and MCP.
#[derive(Clone, Debug, Serialize)]
pub struct AuthorizationPreview {
    /// Opaque durable authorization identifier.
    pub authorization_id: String,
    /// Current lifecycle status.
    pub status: AuthorizationStatus,
    /// Authorization fingerprint in lowercase hex.
    pub authorization_fingerprint: String,
    /// Prepared artifact digest in lowercase hex.
    pub prepared_artifact_hash: String,
    /// Canonical positive token amount.
    pub amount: String,
    /// Asset-contract C-strkey.
    pub currency: String,
    /// Recipient G- or C-strkey.
    pub recipient: String,
    /// Payer G-strkey.
    pub payer: String,
    /// Bound transport name.
    pub transport: String,
    /// Bound authority shown to the operator.
    pub authority: String,
    /// Bound target shown to the operator.
    pub target: String,
    /// Effective challenge expiry as Unix seconds.
    pub expires_at_unix: i64,
    /// Bounded total simulated fee in stroops.
    pub simulated_fee_stroops: u32,
    /// Approval identifier when operator consent is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

/// Redacted durable status. It never exposes challenge, XDR, credential,
/// receipt value, or transaction reference.
#[derive(Clone, Debug, Serialize)]
pub struct AuthorizationStatusView {
    /// Opaque durable authorization identifier.
    pub authorization_id: String,
    /// Current lifecycle status.
    pub status: AuthorizationStatus,
    /// Last state update as Unix seconds.
    pub updated_at_unix: i64,
    /// Effective challenge expiry as Unix seconds.
    pub expires_at_unix: i64,
    /// Whether policy-window usage was durably accounted.
    pub policy_accounted: bool,
    /// Whether an approval is attached, without exposing the approval value.
    pub approval_required: bool,
    /// Whether a credential was constructed, without exposing it.
    pub credential_constructed: bool,
    /// Whether the trusted host reported a receipt.
    pub receipt_observed: bool,
    /// Independently verified ledger outcome.
    pub ledger_outcome: crate::LedgerOutcome,
}

/// Non-secret data passed to the mandatory pre-delivery audit gate.
pub struct AuthorizedCharge<'a> {
    /// Durable authorization record at delivery-pending state.
    pub record: &'a AuthorizationRecord,
    /// Validated payer account.
    pub payer: &'a str,
    /// Exact value effects used at policy evaluation and accounting.
    pub value_effects: &'a ValueEffects,
}

/// Non-secret context for a best-effort withheld-authorization audit event.
pub struct WithheldCharge<'a> {
    /// Durable record after the safest available terminal transition.
    pub record: &'a AuthorizationRecord,
    /// Closed, wallet-owned failure stage label.
    pub failure_stage: &'static str,
    /// Whether secret-key access may have begun.
    pub key_access_began: bool,
    /// Whether policy budget is conservatively treated as consumed.
    pub policy_budget_consumed: bool,
}

impl std::fmt::Debug for AuthorizedCharge<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedCharge")
            .field("authorization_id", &self.record.authorization_id())
            .field("payer", &"[redacted]")
            .field("value_effects", &self.value_effects)
            .finish()
    }
}

/// Persists a successfully simulated sponsored charge and, when required,
/// creates its dedicated approval entry.
///
/// The caller must evaluate policy from [`crate::mpp_value_effects`] before
/// invoking this function. Mainnet refusal and challenge validation occur
/// before this persistence boundary.
///
/// # Errors
///
/// Fails closed on approval validation/persistence or MPP state integrity and
/// I/O errors.
#[allow(
    clippy::too_many_arguments,
    reason = "the persistence boundary keeps each security-relevant input explicit"
)]
pub fn persist_prepared_authorization(
    profile_name: &str,
    network_passphrase: &str,
    prepared: &PreparedSponsoredCharge,
    disposition: ApprovalDisposition,
    process_uid: &str,
    now_unix: i64,
    state_store: &MppAuthorizationStore,
    mut approval_store: Option<&mut PendingApprovalStore>,
) -> Result<AuthorizationPreview, MppError> {
    let mut record =
        AuthorizationRecord::new(profile_name, network_passphrase, prepared, now_unix)?;

    if let Ok(existing) = state_store.load(record.authorization_id()) {
        if disposition == ApprovalDisposition::RequireApproval
            && existing.approval_nonce().is_none()
        {
            if existing.status() != AuthorizationStatus::Ready {
                return Err(state_error());
            }
            let store = approval_store.take().ok_or_else(state_error)?;
            let pending =
                new_pending_approval(&existing, prepared, profile_name, process_uid, now_unix)?;
            let approval_nonce = pending.approval_nonce.clone();
            let now_ms = u64::try_from(now_unix).unwrap_or(0).saturating_mul(1_000);
            store
                .insert(pending, now_ms)
                .map_err(|_error| state_error())?;
            let pending_record = state_store.mark_approval_pending(
                existing.authorization_id(),
                approval_nonce,
                now_unix,
            )?;
            return preview(&pending_record);
        }
        return preview(&existing);
    }

    match disposition {
        ApprovalDisposition::Allow => record.allow_commit(now_unix)?,
        ApprovalDisposition::RequireApproval => {
            let store = approval_store.take().ok_or_else(state_error)?;
            let pending =
                new_pending_approval(&record, prepared, profile_name, process_uid, now_unix)?;
            let approval_nonce = pending.approval_nonce.clone();
            let now_ms = u64::try_from(now_unix).unwrap_or(0).saturating_mul(1_000);
            store
                .insert(pending, now_ms)
                .map_err(|_error| state_error())?;
            record.require_approval(approval_nonce, now_unix)?;
        }
    }

    let persisted = state_store.insert_prepared(record, now_unix)?;
    preview(&persisted)
}

fn new_pending_approval(
    record: &AuthorizationRecord,
    prepared: &PreparedSponsoredCharge,
    profile_name: &str,
    process_uid: &str,
    now_unix: i64,
) -> Result<PendingApproval, MppError> {
    let (transport, authority, target) = context_terms(prepared.selected().context());
    let challenge_expiry = u64::try_from(prepared.selected().effective_expires_at())
        .map_err(|_error| state_error())?;
    let now_ms = u64::try_from(now_unix)
        .map_err(|_error| state_error())?
        .saturating_mul(1_000);
    PendingApproval::new_mpp_charge_pending_at(
        *record.fingerprint(),
        *prepared.artifact_hash(),
        profile_name.to_owned(),
        crate::TESTNET_NETWORK.to_owned(),
        prepared.payer().to_owned(),
        transport,
        authority,
        target,
        prepared.selected().request().amount_decimal().to_owned(),
        prepared.selected().request().currency().to_owned(),
        prepared.selected().request().recipient().to_owned(),
        challenge_expiry,
        prepared.simulated_fee_stroops(),
        process_uid.to_owned(),
        stellar_agent_core::approval::store::MPP_APPROVAL_MAX_TTL_MS,
        now_ms,
    )
    .map_err(|_error| state_error())
}

/// Loads a redacted durable status view. Expiry is derived from the caller's
/// captured clock without mutating state; only the explicit prune operation
/// persists and removes expired replay markers.
///
/// # Errors
///
/// Returns `mpp.state_unavailable` for an unknown or unverifiable record.
pub fn authorization_status(
    state_store: &MppAuthorizationStore,
    authorization_id: &str,
    now_unix: i64,
) -> Result<AuthorizationStatusView, MppError> {
    let record = state_store.load(authorization_id)?;
    let status = if record.expires_at() <= now_unix
        && matches!(
            record.status(),
            AuthorizationStatus::Prepared
                | AuthorizationStatus::ApprovalPending
                | AuthorizationStatus::Ready
                | AuthorizationStatus::Authorized
                | AuthorizationStatus::ReceiptObserved
        ) {
        AuthorizationStatus::ExpiredUnresolved
    } else {
        record.status()
    };
    Ok(AuthorizationStatusView {
        authorization_id: record.authorization_id().to_owned(),
        status,
        updated_at_unix: record.updated_at(),
        expires_at_unix: record.expires_at(),
        policy_accounted: record.policy_accounted(),
        approval_required: record.approval_nonce().is_some(),
        credential_constructed: record.credential_constructed(),
        receipt_observed: record.host_observation().is_some(),
        ledger_outcome: record.ledger_outcome().clone(),
    })
}

/// Claims, accounts, signs, audits, and releases one credential.
///
/// `before_sign` must re-evaluate policy and durably record window usage for
/// the supplied exact `ValueEffects`. `before_delivery` is the mandatory audit
/// gate; its failure withholds the already-built credential.
///
/// # Errors
///
/// Fails closed on missing/invalid approval, replay, policy/accounting gate,
/// signing/re-simulation, state persistence, or delivery-audit failure.
#[allow(
    clippy::too_many_arguments,
    reason = "security gates are explicit injected boundaries"
)]
pub async fn commit_authorization<BeforeSign, BeforeDelivery, OnWithheld>(
    state_store: &MppAuthorizationStore,
    approval_store: Option<&PendingApprovalStore>,
    approval_key: Option<&[u8; 32]>,
    authorization_id: &str,
    now_unix: i64,
    network_passphrase: &str,
    signer: &(dyn Signer + Send + Sync),
    rpc: &(dyn crate::SponsoredRpc + Send + Sync),
    before_sign: BeforeSign,
    before_delivery: BeforeDelivery,
    mut on_withheld: OnWithheld,
) -> Result<crate::CredentialOutput, MppError>
where
    BeforeSign: FnOnce(
        &AuthorizationRecord,
        &PreparedSponsoredCharge,
        &ValueEffects,
    ) -> Result<(), MppError>,
    BeforeDelivery: FnOnce(&AuthorizedCharge<'_>) -> Result<(), MppError>,
    OnWithheld: FnMut(&WithheldCharge<'_>),
{
    let mut record = state_store.load(authorization_id)?;
    if record.status() == AuthorizationStatus::ApprovalPending {
        let nonce = record.approval_nonce().ok_or_else(approval_error)?;
        let approvals = approval_store.ok_or_else(approval_error)?;
        let key = approval_key.ok_or_else(approval_error)?;
        let prepared = record.prepared_charge()?;
        let now_ms = u64::try_from(now_unix).unwrap_or(0).saturating_mul(1_000);
        if !approvals.verify_mpp_charge_attestation(
            key,
            nonce,
            record.fingerprint(),
            prepared.artifact_hash(),
            now_ms,
        ) {
            return Err(approval_error());
        }
        record = state_store.mark_ready(authorization_id, now_unix)?;
    }
    if record.status() != AuthorizationStatus::Ready {
        return Err(replay_error());
    }

    record = state_store.claim_ready(authorization_id, now_unix)?;
    let prepared = record.prepared_charge()?;
    let effects = crate::mpp_value_effects(prepared.selected());
    if let Err(error) = before_sign(&record, &prepared, &effects) {
        notify_withheld(
            state_store,
            authorization_id,
            now_unix,
            "policy_accounting",
            false,
            true,
            &mut on_withheld,
        );
        return Err(error);
    }
    if let Err(error) = state_store.mark_policy_accounted(authorization_id) {
        notify_withheld(
            state_store,
            authorization_id,
            now_unix,
            "policy_state",
            false,
            true,
            &mut on_withheld,
        );
        return Err(error);
    }

    let credential =
        match crate::commit_sponsored(prepared, now_unix, network_passphrase, signer, rpc).await {
            Ok(credential) => credential,
            Err(error) => {
                notify_withheld(
                    state_store,
                    authorization_id,
                    now_unix,
                    "sign_or_resimulation",
                    true,
                    true,
                    &mut on_withheld,
                );
                return Err(error);
            }
        };
    let credential_bytes = match serde_json::to_vec(&credential) {
        Ok(bytes) => bytes,
        Err(_error) => {
            notify_withheld(
                state_store,
                authorization_id,
                now_unix,
                "credential_encoding",
                true,
                true,
                &mut on_withheld,
            );
            return Err(state_error());
        }
    };
    let digest: [u8; 32] = Sha256::digest(&credential_bytes).into();
    drop(credential_bytes);
    record = match state_store.mark_delivery_pending(authorization_id, digest, now_unix) {
        Ok(record) => record,
        Err(error) => {
            notify_withheld(
                state_store,
                authorization_id,
                now_unix,
                "delivery_state",
                true,
                true,
                &mut on_withheld,
            );
            return Err(error);
        }
    };

    if let Err(error) = before_delivery(&AuthorizedCharge {
        record: &record,
        payer: record.prepared_charge()?.payer(),
        value_effects: &effects,
    }) {
        let _ = state_store.mark_authorized_withheld(authorization_id, now_unix);
        if let Ok(withheld) = state_store.load(authorization_id) {
            on_withheld(&WithheldCharge {
                record: &withheld,
                failure_stage: "authorization_audit",
                key_access_began: true,
                policy_budget_consumed: true,
            });
        }
        return Err(error);
    }
    if let Err(error) = state_store.mark_authorized(authorization_id, now_unix) {
        let _ = state_store.mark_authorized_withheld(authorization_id, now_unix);
        if let Ok(withheld) = state_store.load(authorization_id) {
            on_withheld(&WithheldCharge {
                record: &withheld,
                failure_stage: "final_state",
                key_access_began: true,
                policy_budget_consumed: true,
            });
        }
        return Err(error);
    }
    Ok(credential)
}

fn notify_withheld<OnWithheld>(
    state_store: &MppAuthorizationStore,
    authorization_id: &str,
    now_unix: i64,
    failure_stage: &'static str,
    key_access_began: bool,
    policy_budget_consumed: bool,
    on_withheld: &mut OnWithheld,
) where
    OnWithheld: FnMut(&WithheldCharge<'_>),
{
    let _ = state_store.mark_indeterminate(authorization_id, now_unix);
    if let Ok(record) = state_store.load(authorization_id) {
        on_withheld(&WithheldCharge {
            record: &record,
            failure_stage,
            key_access_began,
            policy_budget_consumed,
        });
    }
}

/// Verifies a required dedicated approval and moves the authorization to
/// ready before signer-key access. Ready authorizations are idempotently
/// accepted.
///
/// # Errors
///
/// Returns an indistinguishable approval error or replay/state error.
pub fn verify_pending_approval(
    state_store: &MppAuthorizationStore,
    approval_store: Option<&PendingApprovalStore>,
    approval_key: Option<&[u8; 32]>,
    authorization_id: &str,
    now_unix: i64,
) -> Result<AuthorizationRecord, MppError> {
    let record = state_store.load(authorization_id)?;
    if record.status() == AuthorizationStatus::Ready {
        return Ok(record);
    }
    if record.status() != AuthorizationStatus::ApprovalPending {
        return Err(replay_error());
    }
    let nonce = record.approval_nonce().ok_or_else(approval_error)?;
    let approvals = approval_store.ok_or_else(approval_error)?;
    let key = approval_key.ok_or_else(approval_error)?;
    let prepared = record.prepared_charge()?;
    let now_ms = u64::try_from(now_unix).unwrap_or(0).saturating_mul(1_000);
    if !approvals.verify_mpp_charge_attestation(
        key,
        nonce,
        record.fingerprint(),
        prepared.artifact_hash(),
        now_ms,
    ) {
        return Err(approval_error());
    }
    state_store.mark_ready(authorization_id, now_unix)
}

fn preview(record: &AuthorizationRecord) -> Result<AuthorizationPreview, MppError> {
    let prepared = record.prepared_charge()?;
    let (transport, authority, target) = context_terms(prepared.selected().context());
    Ok(AuthorizationPreview {
        authorization_id: record.authorization_id().to_owned(),
        status: record.status(),
        authorization_fingerprint: hex::encode(record.fingerprint()),
        prepared_artifact_hash: hex::encode(prepared.artifact_hash()),
        amount: prepared.selected().request().amount_decimal().to_owned(),
        currency: prepared.selected().request().currency().to_owned(),
        recipient: prepared.selected().request().recipient().to_owned(),
        payer: prepared.payer().to_owned(),
        transport,
        authority,
        target,
        expires_at_unix: record.expires_at(),
        simulated_fee_stroops: prepared.simulated_fee_stroops(),
        approval_id: record.approval_nonce().map(ToOwned::to_owned),
    })
}

fn context_terms(context: &RequestContext) -> (String, String, String) {
    match context {
        // The displayed target strips the query and fragment: query values may
        // carry sensitive request data and must not reach approval summaries
        // or previews. Replay binding is unaffected — the full canonical
        // resource stays in the context digest and fingerprint.
        RequestContext::Http(http) => (
            "http".to_owned(),
            http.origin().to_owned(),
            http.display_resource(),
        ),
        RequestContext::Mcp(mcp) => (
            "mcp".to_owned(),
            mcp.server_identity().to_owned(),
            mcp.target().to_owned(),
        ),
    }
}

fn state_error() -> MppError {
    MppError::new(
        crate::MppErrorCode::StateUnavailable,
        "MPP authorization state is unavailable",
    )
}

fn approval_error() -> MppError {
    MppError::new(
        crate::MppErrorCode::ApprovalInvalid,
        "MPP approval is missing, invalid, or expired",
    )
}

fn replay_error() -> MppError {
    MppError::new(
        crate::MppErrorCode::AuthorizationReplayed,
        "MPP authorization has already been consumed",
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use std::sync::{Arc, Barrier};

    use serde_json::json;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use tempfile::TempDir;

    use super::*;
    use crate::{ReceiptInput, parse_receipt, sponsored::tests::prepared_fixture};

    const NOW: i64 = 1_700_000_000;

    fn store(directory: &TempDir) -> MppAuthorizationStore {
        MppAuthorizationStore::at_path(directory.path().join("mpp.state"), [7; 32])
    }

    #[tokio::test]
    async fn repeated_prepare_promotes_ready_record_when_policy_now_requires_approval() {
        let directory = TempDir::new().expect("tempdir");
        let state = store(&directory);
        let (prepared, _signer, _rpc) = prepared_fixture(NOW).await;
        let ready = persist_prepared_authorization(
            "policy-change",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::Allow,
            "424242",
            NOW,
            &state,
            None,
        )
        .expect("persist ready");
        assert_eq!(ready.status, AuthorizationStatus::Ready);

        let mut approvals = PendingApprovalStore::open(directory.path().join("approvals.toml"))
            .expect("approval store");
        let promoted = persist_prepared_authorization(
            "policy-change",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::RequireApproval,
            "424242",
            NOW + 1,
            &state,
            Some(&mut approvals),
        )
        .expect("promote to approval");
        assert_eq!(promoted.authorization_id, ready.authorization_id);
        assert_eq!(promoted.status, AuthorizationStatus::ApprovalPending);
        assert!(promoted.approval_id.is_some());
        assert_eq!(approvals.len(), 1);
    }

    #[tokio::test]
    async fn preview_and_approval_target_never_carry_query_values() {
        use crate::sponsored::tests::prepared_fixture_for_resource;

        let directory = TempDir::new().expect("tempdir");
        let state = store(&directory);
        let (prepared, _signer, _rpc) = prepared_fixture_for_resource(
            NOW,
            "https://merchant.example/checkout?order=42&customer=alice",
        )
        .await;
        let mut approvals = PendingApprovalStore::open(directory.path().join("approvals.toml"))
            .expect("approval store");
        let preview = persist_prepared_authorization(
            "query-redaction",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::RequireApproval,
            "424242",
            NOW,
            &state,
            Some(&mut approvals),
        )
        .expect("persist");
        assert_eq!(preview.target, "https://merchant.example/checkout");
        assert!(!preview.target.contains('?'));

        let nonce = preview.approval_id.expect("approval required");
        let entry = approvals.get(&nonce).expect("pending entry");
        let summary = format!("{:?}", entry.kind);
        assert!(!summary.contains("order=42"), "approval kind leaks query");
        assert!(
            !summary.contains("alice"),
            "approval kind leaks query value"
        );
        // Replay binding still uses the full resource: an identical challenge
        // bound to a different query yields a different fingerprint.
        let (other, _signer, _rpc) = prepared_fixture_for_resource(
            NOW,
            "https://merchant.example/checkout?order=43&customer=alice",
        )
        .await;
        assert_ne!(
            crate::authorization_fingerprint(
                "query-redaction",
                TESTNET_PASSPHRASE,
                prepared.payer(),
                prepared.selected(),
            )
            .expect("fingerprint"),
            crate::authorization_fingerprint(
                "query-redaction",
                TESTNET_PASSPHRASE,
                other.payer(),
                other.selected(),
            )
            .expect("other fingerprint"),
        );
    }

    #[tokio::test]
    async fn status_derives_expiry_without_mutating_replay_state() {
        let directory = TempDir::new().expect("tempdir");
        let state = store(&directory);
        let (prepared, _signer, _rpc) = prepared_fixture(NOW).await;
        let preview = persist_prepared_authorization(
            "expiry-status",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::Allow,
            "424242",
            NOW,
            &state,
            None,
        )
        .expect("persist ready");
        let view =
            authorization_status(&state, &preview.authorization_id, NOW + 301).expect("status");
        assert_eq!(view.status, AuthorizationStatus::ExpiredUnresolved);
        assert_eq!(
            state
                .load(&preview.authorization_id)
                .expect("durable record")
                .status(),
            AuthorizationStatus::Ready
        );
    }

    #[tokio::test]
    async fn commit_is_one_shot_and_receipts_are_idempotent() {
        let directory = TempDir::new().expect("tempdir");
        let state = store(&directory);
        let (prepared, signer, rpc) = prepared_fixture(NOW).await;
        let preview = persist_prepared_authorization(
            "default",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::Allow,
            "424242",
            NOW,
            &state,
            None,
        )
        .expect("persist");
        let mut withheld = Vec::new();
        let credential = commit_authorization(
            &state,
            None,
            None,
            &preview.authorization_id,
            NOW + 1,
            TESTNET_PASSPHRASE,
            &signer,
            &rpc,
            |_record, _prepared, effects| {
                assert_eq!(effects.legs().len(), 1);
                Ok(())
            },
            |_authorized| Ok(()),
            |event| withheld.push(event.failure_stage),
        )
        .await
        .expect("commit");
        assert!(serde_json::to_vec(&credential).expect("JSON").len() > 100);
        assert!(withheld.is_empty());
        assert_eq!(rpc.call_count(), 2);
        assert_eq!(
            state
                .load(&preview.authorization_id)
                .expect("state")
                .status(),
            AuthorizationStatus::Authorized
        );

        let mismatched = parse_receipt(&ReceiptInput::Mcp {
            receipt: json!({
                "method": "stellar",
                "reference": "c".repeat(64),
                "status": "success",
                "timestamp": "2026-07-16T12:00:00Z",
                "challengeId": "another-challenge"
            }),
        })
        .expect("receipt");
        let mismatch = state
            .record_receipt(&preview.authorization_id, &mismatched, NOW + 2)
            .expect_err("challenge ID must correlate");
        assert_eq!(mismatch.code(), "mpp.receipt_conflict");

        let replay = commit_authorization(
            &state,
            None,
            None,
            &preview.authorization_id,
            NOW + 2,
            TESTNET_PASSPHRASE,
            &signer,
            &rpc,
            |_record, _prepared, _effects| Ok(()),
            |_authorized| Ok(()),
            |_event| {},
        )
        .await
        .expect_err("credential must never be returned twice");
        assert_eq!(replay.code(), "mpp.authorization_replayed");
        assert_eq!(rpc.call_count(), 2);

        let first = parse_receipt(&ReceiptInput::Mcp {
            receipt: json!({
                "method": "stellar",
                "reference": "a".repeat(64),
                "status": "success",
                "timestamp": "2026-07-16T12:00:00Z"
            }),
        })
        .expect("receipt");
        state
            .record_receipt(&preview.authorization_id, &first, NOW + 3)
            .expect("first observation");
        state
            .record_receipt(&preview.authorization_id, &first, NOW + 4)
            .expect("identical replay");
        let conflicting = parse_receipt(&ReceiptInput::Mcp {
            receipt: json!({
                "method": "stellar",
                "reference": "b".repeat(64),
                "status": "success",
                "timestamp": "2026-07-16T12:00:00Z"
            }),
        })
        .expect("receipt");
        let error = state
            .record_receipt(&preview.authorization_id, &conflicting, NOW + 5)
            .expect_err("different receipt must conflict");
        assert_eq!(error.code(), "mpp.receipt_conflict");
    }

    #[tokio::test]
    async fn delivery_audit_failure_withholds_without_retrying_signature() {
        let directory = TempDir::new().expect("tempdir");
        let state = store(&directory);
        let (prepared, signer, rpc) = prepared_fixture(NOW).await;
        let preview = persist_prepared_authorization(
            "audit-failure",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::Allow,
            "424242",
            NOW,
            &state,
            None,
        )
        .expect("persist");
        let mut events = Vec::new();
        let error = commit_authorization(
            &state,
            None,
            None,
            &preview.authorization_id,
            NOW + 1,
            TESTNET_PASSPHRASE,
            &signer,
            &rpc,
            |_record, _prepared, _effects| Ok(()),
            |_authorized| Err(state_error()),
            |event| {
                events.push((
                    event.failure_stage,
                    event.key_access_began,
                    event.policy_budget_consumed,
                ));
            },
        )
        .await
        .expect_err("audit failure must withhold");
        assert_eq!(error.code(), "mpp.state_unavailable");
        assert_eq!(
            state
                .load(&preview.authorization_id)
                .expect("state")
                .status(),
            AuthorizationStatus::AuthorizedWithheld
        );
        assert_eq!(events, vec![("authorization_audit", true, true)]);
        assert_eq!(rpc.call_count(), 2);

        let replay = commit_authorization(
            &state,
            None,
            None,
            &preview.authorization_id,
            NOW + 2,
            TESTNET_PASSPHRASE,
            &signer,
            &rpc,
            |_record, _prepared, _effects| Ok(()),
            |_authorized| Ok(()),
            |_event| {},
        )
        .await
        .expect_err("withheld authorization is terminal");
        assert_eq!(replay.code(), "mpp.authorization_replayed");
        assert_eq!(rpc.call_count(), 2);
    }

    #[tokio::test]
    async fn ambiguous_policy_accounting_fails_before_signing() {
        let directory = TempDir::new().expect("tempdir");
        let state = store(&directory);
        let (prepared, signer, rpc) = prepared_fixture(NOW).await;
        let preview = persist_prepared_authorization(
            "policy-failure",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::Allow,
            "424242",
            NOW,
            &state,
            None,
        )
        .expect("persist");
        let mut event = None;
        commit_authorization(
            &state,
            None,
            None,
            &preview.authorization_id,
            NOW + 1,
            TESTNET_PASSPHRASE,
            &signer,
            &rpc,
            |_record, _prepared, _effects| Err(state_error()),
            |_authorized| Ok(()),
            |withheld| {
                event = Some((withheld.failure_stage, withheld.key_access_began));
            },
        )
        .await
        .expect_err("accounting ambiguity must fail closed");
        assert_eq!(rpc.call_count(), 1, "only prepare simulation is allowed");
        assert_eq!(event, Some(("policy_accounting", false)));
        assert_eq!(
            state
                .load(&preview.authorization_id)
                .expect("state")
                .status(),
            AuthorizationStatus::Indeterminate
        );
        assert_eq!(state.prune(NOW + 90 * 24 * 60 * 60).expect("prune"), 0);
        assert_eq!(
            state
                .load(&preview.authorization_id)
                .expect("indeterminate retained")
                .status(),
            AuthorizationStatus::Indeterminate
        );
    }

    #[tokio::test]
    async fn concurrent_claim_has_exactly_one_winner() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("mpp.state");
        let state = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
        let (prepared, _signer, _rpc) = prepared_fixture(NOW).await;
        let preview = persist_prepared_authorization(
            "concurrent",
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::Allow,
            "424242",
            NOW,
            &state,
            None,
        )
        .expect("persist");
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let store = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
            let id = preview.authorization_id.clone();
            let ready = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                ready.wait();
                store.claim_ready(&id, NOW + 1).is_ok()
            }));
        }
        let winners = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
        assert_eq!(
            state
                .load(&preview.authorization_id)
                .expect("state")
                .status(),
            AuthorizationStatus::Authorizing
        );
    }
}

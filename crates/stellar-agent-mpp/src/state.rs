//! Durable MPP authorization record and state machine.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    SelectedChallenge,
    error::{MppError, MppErrorCode},
    sponsored::{PreparedSponsoredCharge, StoredPreparedCharge},
};

/// Durable authorization lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    /// Prepared and awaiting policy or approval resolution.
    Prepared,
    /// A dedicated approval is pending.
    ApprovalPending,
    /// All pre-signing gates passed and commit may claim the record.
    Ready,
    /// Commit has exclusively claimed the record.
    Authorizing,
    /// Credential was built but final delivery gates have not cleared.
    DeliveryPending,
    /// Credential delivery gates cleared and one-shot return was attempted.
    Authorized,
    /// A delivery gate failed after credential construction.
    AuthorizedWithheld,
    /// A receipt was reported by the trusted host.
    ReceiptObserved,
    /// Ledger reconciliation verified successful settlement.
    Settled,
    /// Ledger reconciliation verified failure.
    Failed,
    /// Authorization expired without a verified outcome.
    ExpiredUnresolved,
    /// Key access began and the result cannot safely be retried.
    Indeterminate,
}

impl AuthorizationStatus {
    /// Returns whether this state is terminal for retention and pruning.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled
                | Self::Failed
                | Self::ExpiredUnresolved
                | Self::AuthorizedWithheld
                | Self::Indeterminate
        )
    }

    pub(crate) const fn allows(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::ApprovalPending | Self::Ready)
                | (Self::Ready, Self::ApprovalPending)
                | (
                    Self::Prepared | Self::ApprovalPending | Self::Ready,
                    Self::ExpiredUnresolved
                )
                | (Self::ApprovalPending, Self::Ready)
                | (Self::Ready, Self::Authorizing)
                | (
                    Self::Authorizing,
                    Self::DeliveryPending | Self::Failed | Self::Indeterminate
                )
                | (
                    Self::DeliveryPending,
                    Self::Authorized | Self::AuthorizedWithheld
                )
                | (
                    Self::Authorized,
                    Self::ReceiptObserved | Self::Settled | Self::Failed
                )
                | (
                    Self::ReceiptObserved,
                    Self::Settled | Self::Failed | Self::ExpiredUnresolved
                )
                | (Self::Authorized, Self::ExpiredUnresolved)
        )
    }
}

/// Host-reported receipt observation, separate from ledger proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostObservation {
    /// Canonical receipt SHA-256 digest.
    pub receipt_digest: [u8; 32],
    /// SHA-256 digest of the transaction reference.
    pub reference_digest: [u8; 32],
    /// Observation Unix timestamp.
    pub observed_at: i64,
}

/// Ledger reconciliation axis, independent of host receipt state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LedgerOutcome {
    /// No verified ledger result is available.
    Unknown,
    /// Exact payment was verified successful in a ledger.
    Settled {
        /// Confirming ledger sequence.
        ledger: u32,
        /// Reconciliation Unix timestamp.
        reconciled_at: i64,
    },
    /// Exact transaction was verified failed.
    Failed {
        /// Final ledger sequence.
        ledger: u32,
        /// Reconciliation Unix timestamp.
        reconciled_at: i64,
    },
}

/// HMAC-protected durable authorization record.
#[derive(Clone, Deserialize, Serialize)]
pub struct AuthorizationRecord {
    authorization_id: String,
    fingerprint: [u8; 32],
    status: AuthorizationStatus,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    prepared: StoredPreparedCharge,
    #[serde(default)]
    approval_nonce: Option<String>,
    credential_digest: Option<[u8; 32]>,
    host_observation: Option<HostObservation>,
    ledger_outcome: LedgerOutcome,
    policy_accounted: bool,
}

impl AuthorizationRecord {
    /// Creates the initial prepared record from a validated transaction artifact.
    ///
    /// # Errors
    ///
    /// Returns a stable state or simulation error if fingerprinting or artifact
    /// serialization fails.
    pub fn new(
        profile_name: &str,
        network_passphrase: &str,
        prepared: &PreparedSponsoredCharge,
        now_unix: i64,
    ) -> Result<Self, MppError> {
        let fingerprint = authorization_fingerprint(
            profile_name,
            network_passphrase,
            prepared.payer(),
            prepared.selected(),
        )?;
        let authorization_id = format!("mpp_{}", &hex::encode(fingerprint)[..32]);
        Ok(Self {
            authorization_id,
            fingerprint,
            status: AuthorizationStatus::Prepared,
            created_at: now_unix,
            updated_at: now_unix,
            expires_at: prepared.selected().effective_expires_at(),
            prepared: prepared.to_stored()?,
            approval_nonce: None,
            credential_digest: None,
            host_observation: None,
            ledger_outcome: LedgerOutcome::Unknown,
            policy_accounted: false,
        })
    }

    /// Returns the opaque authorization identifier.
    #[must_use]
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }

    /// Returns the authorization fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn status(&self) -> AuthorizationStatus {
        self.status
    }

    /// Returns the effective challenge expiry.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the dedicated approval nonce when policy required consent.
    #[must_use]
    pub fn approval_nonce(&self) -> Option<&str> {
        self.approval_nonce.as_deref()
    }

    /// Returns the last state update timestamp.
    #[must_use]
    pub const fn updated_at(&self) -> i64 {
        self.updated_at
    }

    /// Returns whether a credential was constructed, without exposing it.
    #[must_use]
    pub const fn credential_constructed(&self) -> bool {
        self.credential_digest.is_some()
    }

    /// Returns whether value-policy window usage was durably accounted.
    #[must_use]
    pub const fn policy_accounted(&self) -> bool {
        self.policy_accounted
    }

    /// Returns the host receipt axis.
    #[must_use]
    pub const fn host_observation(&self) -> Option<&HostObservation> {
        self.host_observation.as_ref()
    }

    /// Returns the ledger reconciliation axis.
    #[must_use]
    pub const fn ledger_outcome(&self) -> &LedgerOutcome {
        &self.ledger_outcome
    }

    /// Reconstructs and revalidates the prepared transaction artifact.
    ///
    /// # Errors
    ///
    /// Returns `mpp.state_unavailable` if persisted artifact validation fails.
    pub fn prepared_charge(&self) -> Result<PreparedSponsoredCharge, MppError> {
        PreparedSponsoredCharge::from_stored(self.prepared.clone()).map_err(|_error| {
            MppError::new(
                MppErrorCode::StateUnavailable,
                "stored MPP authorization failed validation",
            )
        })
    }

    pub(crate) fn validate(&self) -> Result<(), MppError> {
        let expected_id = format!("mpp_{}", &hex::encode(self.fingerprint)[..32]);
        if self.authorization_id != expected_id
            || self.updated_at < self.created_at
            || self.expires_at < self.created_at
        {
            return Err(state_error());
        }
        if let Some(nonce) = self.approval_nonce.as_deref()
            && (nonce.len() != 22
                || !nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        {
            return Err(state_error());
        }
        if self.status == AuthorizationStatus::ApprovalPending && self.approval_nonce.is_none() {
            return Err(state_error());
        }
        if self.status == AuthorizationStatus::Prepared && self.approval_nonce.is_some() {
            return Err(state_error());
        }
        if self.policy_accounted
            && matches!(
                self.status,
                AuthorizationStatus::Prepared
                    | AuthorizationStatus::ApprovalPending
                    | AuthorizationStatus::Ready
            )
        {
            return Err(state_error());
        }
        if self.credential_digest.is_some()
            && matches!(
                self.status,
                AuthorizationStatus::Prepared
                    | AuthorizationStatus::ApprovalPending
                    | AuthorizationStatus::Ready
                    | AuthorizationStatus::Authorizing
            )
        {
            return Err(state_error());
        }
        if matches!(
            self.status,
            AuthorizationStatus::DeliveryPending
                | AuthorizationStatus::Authorized
                | AuthorizationStatus::AuthorizedWithheld
                | AuthorizationStatus::ReceiptObserved
                | AuthorizationStatus::Settled
        ) && self.credential_digest.is_none()
        {
            return Err(state_error());
        }
        if self.host_observation.is_some()
            && (!matches!(
                self.status,
                AuthorizationStatus::ReceiptObserved
                    | AuthorizationStatus::Settled
                    | AuthorizationStatus::Failed
                    | AuthorizationStatus::ExpiredUnresolved
            ) || self.credential_digest.is_none())
        {
            return Err(state_error());
        }
        match (&self.ledger_outcome, self.status) {
            (LedgerOutcome::Settled { ledger, .. }, AuthorizationStatus::Settled)
            | (LedgerOutcome::Failed { ledger, .. }, AuthorizationStatus::Failed)
                if *ledger > 0 => {}
            (LedgerOutcome::Unknown, AuthorizationStatus::Settled) => return Err(state_error()),
            (LedgerOutcome::Settled { .. }, _) | (LedgerOutcome::Failed { .. }, _) => {
                return Err(state_error());
            }
            (LedgerOutcome::Unknown, _) => {}
        }
        let prepared = self.prepared_charge()?;
        if prepared.selected().effective_expires_at() != self.expires_at {
            return Err(state_error());
        }
        Ok(())
    }

    pub(crate) fn transition(
        &mut self,
        next: AuthorizationStatus,
        now_unix: i64,
    ) -> Result<(), MppError> {
        if !self.status.allows(next) {
            return Err(MppError::new(
                MppErrorCode::AuthorizationReplayed,
                "MPP authorization cannot transition from its current state",
            ));
        }
        self.status = next;
        self.updated_at = now_unix;
        Ok(())
    }

    pub(crate) fn require_approval(
        &mut self,
        nonce: String,
        now_unix: i64,
    ) -> Result<(), MppError> {
        self.set_approval_nonce(nonce);
        self.transition(AuthorizationStatus::ApprovalPending, now_unix)
    }

    pub(crate) fn allow_commit(&mut self, now_unix: i64) -> Result<(), MppError> {
        self.transition(AuthorizationStatus::Ready, now_unix)
    }

    pub(crate) const fn set_policy_accounted(&mut self) {
        self.policy_accounted = true;
    }

    pub(crate) fn set_approval_nonce(&mut self, nonce: String) {
        self.approval_nonce = Some(nonce);
    }

    pub(crate) const fn set_credential_digest(&mut self, digest: [u8; 32]) {
        self.credential_digest = Some(digest);
    }

    pub(crate) const fn set_host_observation(&mut self, observation: HostObservation) {
        self.host_observation = Some(observation);
    }

    pub(crate) fn set_ledger_outcome(&mut self, outcome: LedgerOutcome) {
        self.ledger_outcome = outcome;
    }
}

impl fmt::Debug for AuthorizationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRecord")
            .field("authorization_id", &self.authorization_id)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("expires_at", &self.expires_at)
            .field("prepared", &"[redacted]")
            .field("approval_nonce", &self.approval_nonce)
            .field(
                "credential_digest",
                &self.credential_digest.map(hex::encode),
            )
            .field("host_observation", &self.host_observation)
            .field("ledger_outcome", &self.ledger_outcome)
            .field("policy_accounted", &self.policy_accounted)
            .finish()
    }
}

/// Computes the versioned authorization fingerprint that binds profile,
/// network, payer, transport context, exact challenge, terms, and expiry.
///
/// # Errors
///
/// Returns a redacted challenge error if context serialization fails.
pub fn authorization_fingerprint(
    profile_name: &str,
    network_passphrase: &str,
    payer: &str,
    selected: &SelectedChallenge,
) -> Result<[u8; 32], MppError> {
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent-mpp-authorization:v1\0");
    update(&mut hash, profile_name.as_bytes());
    update(&mut hash, &Sha256::digest(network_passphrase.as_bytes()));
    update(&mut hash, payer.as_bytes());
    update(&mut hash, &selected.context().digest()?);
    update(&mut hash, selected.challenge_digest());
    update(&mut hash, b"stellar");
    update(&mut hash, b"charge");
    update(&mut hash, b"sponsored_pull");
    update(&mut hash, selected.request().amount_decimal().as_bytes());
    update(&mut hash, selected.request().currency().as_bytes());
    update(&mut hash, selected.request().recipient().as_bytes());
    update(&mut hash, &selected.effective_expires_at().to_be_bytes());
    Ok(hash.finalize().into())
}

fn update(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

const fn state_error() -> MppError {
    MppError::new(
        MppErrorCode::StateUnavailable,
        "MPP authorization state is unavailable",
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use proptest::prelude::*;
    use serde_json::Value;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;

    use super::*;
    use crate::sponsored::tests::prepared_fixture;

    fn status(index: u8) -> AuthorizationStatus {
        match index % 12 {
            0 => AuthorizationStatus::Prepared,
            1 => AuthorizationStatus::ApprovalPending,
            2 => AuthorizationStatus::Ready,
            3 => AuthorizationStatus::Authorizing,
            4 => AuthorizationStatus::DeliveryPending,
            5 => AuthorizationStatus::Authorized,
            6 => AuthorizationStatus::AuthorizedWithheld,
            7 => AuthorizationStatus::ReceiptObserved,
            8 => AuthorizationStatus::Settled,
            9 => AuthorizationStatus::Failed,
            10 => AuthorizationStatus::ExpiredUnresolved,
            _ => AuthorizationStatus::Indeterminate,
        }
    }

    fn expected_transition(current: AuthorizationStatus, next: AuthorizationStatus) -> bool {
        use AuthorizationStatus as S;
        matches!(
            (current, next),
            (
                S::Prepared,
                S::ApprovalPending | S::Ready | S::ExpiredUnresolved
            ) | (S::ApprovalPending, S::Ready | S::ExpiredUnresolved)
                | (
                    S::Ready,
                    S::ApprovalPending | S::Authorizing | S::ExpiredUnresolved
                )
                | (
                    S::Authorizing,
                    S::DeliveryPending | S::Failed | S::Indeterminate
                )
                | (S::DeliveryPending, S::Authorized | S::AuthorizedWithheld)
                | (
                    S::Authorized,
                    S::ReceiptObserved | S::Settled | S::Failed | S::ExpiredUnresolved
                )
                | (
                    S::ReceiptObserved,
                    S::Settled | S::Failed | S::ExpiredUnresolved
                )
        )
    }

    proptest! {
        #[test]
        fn transition_graph_matches_the_closed_lifecycle(sequence in prop::collection::vec(any::<u8>(), 0..128)) {
            let mut current = AuthorizationStatus::Prepared;
            for candidate in sequence.into_iter().map(status) {
                let expected = expected_transition(current, candidate);
                prop_assert_eq!(current.allows(candidate), expected);
                if expected {
                    current = candidate;
                }
                if current.is_terminal() {
                    prop_assert!(!(0_u8..12).map(status).any(|next| current.allows(next)));
                }
            }
        }
    }

    #[tokio::test]
    async fn record_lifecycle_preserves_independent_receipt_and_ledger_axes() {
        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let mut record = AuthorizationRecord::new("default", TESTNET_PASSPHRASE, &prepared, now)
            .expect("record");

        assert!(record.authorization_id().starts_with("mpp_"));
        assert_eq!(record.status(), AuthorizationStatus::Prepared);
        assert_eq!(record.expires_at(), now + 300);
        assert_eq!(record.updated_at(), now);
        assert_eq!(record.approval_nonce(), None);
        assert!(!record.credential_constructed());
        assert!(!record.policy_accounted());
        assert!(record.host_observation().is_none());
        assert_eq!(record.ledger_outcome(), &LedgerOutcome::Unknown);
        assert_eq!(
            record.prepared_charge().expect("prepared").payer(),
            prepared.payer()
        );
        assert!(format!("{record:?}").contains("prepared: \"[redacted]\""));
        record.validate().expect("initial record");

        let nonce = "approval_nonce_value12".to_owned();
        assert_eq!(nonce.len(), 22);
        record
            .require_approval(nonce.clone(), now + 1)
            .expect("pending");
        assert_eq!(record.approval_nonce(), Some(nonce.as_str()));
        record.validate().expect("pending record");
        record.allow_commit(now + 2).expect("ready");
        record
            .transition(AuthorizationStatus::Authorizing, now + 3)
            .expect("claim");
        record.set_policy_accounted();
        record.set_credential_digest([3; 32]);
        record
            .transition(AuthorizationStatus::DeliveryPending, now + 4)
            .expect("delivery pending");
        record
            .transition(AuthorizationStatus::Authorized, now + 5)
            .expect("authorized");
        record.validate().expect("authorized record");

        let observation = HostObservation {
            receipt_digest: [4; 32],
            reference_digest: [5; 32],
            observed_at: now + 6,
        };
        record.set_host_observation(observation.clone());
        record
            .transition(AuthorizationStatus::ReceiptObserved, now + 6)
            .expect("receipt observed");
        assert_eq!(record.host_observation(), Some(&observation));
        record.validate().expect("receipt record");

        let outcome = LedgerOutcome::Settled {
            ledger: 123,
            reconciled_at: now + 7,
        };
        record.set_ledger_outcome(outcome.clone());
        record
            .transition(AuthorizationStatus::Settled, now + 7)
            .expect("settled");
        assert_eq!(record.ledger_outcome(), &outcome);
        assert!(record.status().is_terminal());
        record.validate().expect("settled record");

        assert_eq!(
            record
                .transition(AuthorizationStatus::Failed, now + 8)
                .expect_err("terminal transition")
                .code(),
            "mpp.authorization_replayed"
        );
    }

    #[tokio::test]
    async fn record_validation_rejects_corrupt_or_incoherent_state() {
        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let base = AuthorizationRecord::new("default", TESTNET_PASSPHRASE, &prepared, now)
            .expect("record");
        let assert_invalid = |record: &AuthorizationRecord| {
            assert_eq!(
                record.validate().expect_err("invalid record").code(),
                "mpp.state_unavailable"
            );
        };

        let mut record = base.clone();
        record.authorization_id = "mpp_00000000000000000000000000000000".to_owned();
        assert_invalid(&record);
        let mut record = base.clone();
        record.updated_at = now - 1;
        assert_invalid(&record);
        let mut record = base.clone();
        record.expires_at = now - 1;
        assert_invalid(&record);
        let mut record = base.clone();
        record.approval_nonce = Some("short".to_owned());
        record.status = AuthorizationStatus::ApprovalPending;
        assert_invalid(&record);
        let mut record = base.clone();
        record.approval_nonce = Some("invalid+nonce_value_12".to_owned());
        record.status = AuthorizationStatus::ApprovalPending;
        assert_invalid(&record);
        let mut record = base.clone();
        record.status = AuthorizationStatus::ApprovalPending;
        assert_invalid(&record);
        let mut record = base.clone();
        record.approval_nonce = Some("approval_nonce_value12".to_owned());
        assert_invalid(&record);
        let mut record = base.clone();
        record.policy_accounted = true;
        assert_invalid(&record);
        let mut record = base.clone();
        record.credential_digest = Some([1; 32]);
        assert_invalid(&record);
        let mut record = base.clone();
        record.status = AuthorizationStatus::DeliveryPending;
        assert_invalid(&record);

        let mut record = base.clone();
        record.status = AuthorizationStatus::Authorized;
        record.credential_digest = Some([1; 32]);
        record.host_observation = Some(HostObservation {
            receipt_digest: [2; 32],
            reference_digest: [3; 32],
            observed_at: now,
        });
        assert_invalid(&record);
        let mut record = base.clone();
        record.status = AuthorizationStatus::Settled;
        record.credential_digest = Some([1; 32]);
        assert_invalid(&record);
        let mut record = base.clone();
        record.ledger_outcome = LedgerOutcome::Settled {
            ledger: 1,
            reconciled_at: now,
        };
        assert_invalid(&record);
        let mut record = base.clone();
        record.status = AuthorizationStatus::Settled;
        record.credential_digest = Some([1; 32]);
        record.ledger_outcome = LedgerOutcome::Settled {
            ledger: 0,
            reconciled_at: now,
        };
        assert_invalid(&record);
        let mut record = base.clone();
        record.expires_at += 1;
        assert_invalid(&record);

        let mut serialized = serde_json::to_value(&base).expect("serialize record");
        serialized["prepared"]["payer"] = Value::String("invalid".to_owned());
        let corrupt: AuthorizationRecord =
            serde_json::from_value(serialized).expect("structural record");
        assert_eq!(
            corrupt
                .prepared_charge()
                .expect_err("corrupt artifact")
                .code(),
            "mpp.state_unavailable"
        );
    }

    #[tokio::test]
    async fn fingerprints_bind_every_authority_dimension() {
        use serde_json::{Value, json};

        use crate::{ChallengeInput, McpOperationKind, McpRequestContext, select_and_validate};

        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let selected = prepared.selected();
        let baseline =
            authorization_fingerprint("default", TESTNET_PASSPHRASE, prepared.payer(), selected)
                .expect("fingerprint");
        for changed in [
            authorization_fingerprint(
                "other-profile",
                TESTNET_PASSPHRASE,
                prepared.payer(),
                selected,
            )
            .expect("profile fingerprint"),
            authorization_fingerprint("default", "other-network", prepared.payer(), selected)
                .expect("network fingerprint"),
            authorization_fingerprint("default", TESTNET_PASSPHRASE, "other-payer", selected)
                .expect("payer fingerprint"),
        ] {
            assert_ne!(baseline, changed);
        }

        // The remaining preimage dimensions flow through the selected
        // challenge: transport context, exact challenge echo, amount,
        // currency, recipient, and effective expiry. Each perturbation must
        // change the fingerprint.
        const OTHER_CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
        const OTHER_ACCOUNT: &str = "GAJZR5RMNUNEK7CRXJVEWXZ5XUXWT7FJGILCDDOITF7EC26RPWJ4UVOE";
        let request_with = |mutate: &dyn Fn(&mut Value)| {
            let mut request = json!({
                "amount": "10000000",
                "currency": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
                "methodDetails": {"feePayer": true, "network": "stellar:testnet"},
                "recipient": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
            });
            mutate(&mut request);
            request
        };
        let selected_with =
            |request: Value, challenge_mutate: &dyn Fn(&mut Value), target: &str| {
                let mut challenge = json!({
                    "id": "challenge-1",
                    "realm": "server",
                    "method": "stellar",
                    "intent": "charge",
                    "request": request
                });
                challenge_mutate(&mut challenge);
                let context =
                    McpRequestContext::from_params("server", McpOperationKind::Tool, target, None)
                        .expect("context");
                select_and_validate(
                    &ChallengeInput::Mcp {
                        challenges: vec![challenge],
                        selected_challenge_id: None,
                        context,
                    },
                    now,
                )
                .expect("variant challenge")
            };
        let dimension_selected = selected_with(request_with(&|_| {}), &|_| {}, "charge");
        let dimension_baseline = authorization_fingerprint(
            "default",
            TESTNET_PASSPHRASE,
            prepared.payer(),
            &dimension_selected,
        )
        .expect("dimension baseline");
        let variants: Vec<(&str, crate::SelectedChallenge)> = vec![
            (
                "context target",
                selected_with(request_with(&|_| {}), &|_| {}, "other-tool"),
            ),
            (
                "challenge echo",
                selected_with(
                    request_with(&|_| {}),
                    &|challenge| {
                        challenge["opaque"] = Value::String("distinct".to_owned());
                    },
                    "charge",
                ),
            ),
            (
                "amount",
                selected_with(
                    request_with(&|request| {
                        request["amount"] = Value::String("10000001".to_owned());
                    }),
                    &|_| {},
                    "charge",
                ),
            ),
            (
                "currency",
                selected_with(
                    request_with(&|request| {
                        request["currency"] = Value::String(OTHER_CONTRACT.to_owned());
                    }),
                    &|_| {},
                    "charge",
                ),
            ),
            (
                "recipient",
                selected_with(
                    request_with(&|request| {
                        request["recipient"] = Value::String(OTHER_ACCOUNT.to_owned());
                    }),
                    &|_| {},
                    "charge",
                ),
            ),
            (
                "effective expiry",
                selected_with(
                    request_with(&|_| {}),
                    &|challenge| {
                        challenge["expires"] = Value::String("2023-11-14T22:15:00Z".to_owned());
                    },
                    "charge",
                ),
            ),
        ];
        for (dimension, variant) in variants {
            let fingerprint = authorization_fingerprint(
                "default",
                TESTNET_PASSPHRASE,
                prepared.payer(),
                &variant,
            )
            .expect("variant fingerprint");
            assert_ne!(
                dimension_baseline, fingerprint,
                "fingerprint must bind dimension: {dimension}"
            );
        }
    }
}

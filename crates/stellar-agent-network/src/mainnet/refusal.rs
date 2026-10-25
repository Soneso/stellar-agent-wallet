//! The refusals of mainnet authorization: the closed set of preconditions a
//! check or a ledger transition can find broken, and the one error that
//! carries them.
//!
//! Every refusal reaches an agent as `network.mainnet_authorization_refused`
//! with a generic text; the precondition is for the operator's log and for
//! tests. A build without mainnet writes reports
//! `network.mainnet_write_forbidden` instead.

use stellar_agent_core::error::{NetworkError, WalletError};

/// One precondition a mainnet authorization check or ledger transition found
/// broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MainnetPrecondition {
    /// The profile differs.
    ProfileMismatch,
    /// A chain is not mainnet.
    ChainNotMainnet,
    /// The chains differ.
    ChainMismatch,
    /// The consuming verb differs.
    ConsumerMismatch,
    /// The signer's public key differs.
    SignerKeyMismatch,
    /// The signer's role differs.
    SignerRoleMismatch,
    /// An endpoint binding is present on one side only.
    EndpointPresence,
    /// The endpoint authority differs.
    EndpointAuthority,
    /// The endpoint's client differs.
    EndpointClient,
    /// The policy sequence differs.
    PolicySequence,
    /// The policy digest differs.
    PolicyDigest,
    /// The enablement nonce digest differs.
    EnablementMismatch,
    /// The approval nonce differs.
    ApprovalNonce,
    /// The approval expiry differs.
    ApprovalExpiry,
    /// The window reservation differs, or is present on one side only.
    ReservationMismatch,
    /// The witness subject differs, or is present on one side only.
    WitnessSubject,
    /// The audit log path digest differs.
    AuditLogPath,
    /// The writer's keyring provenance or active path changed.
    AuditProvenance,
    /// The active audit segment differs from the recorded segment.
    AuditSegment,
    /// The audit log holds fewer anchored entries than the authorization
    /// recorded.
    AuditCount,
    /// The time precedes the authorization's issue time.
    NotYetValid,
    /// The authorization has expired.
    Expired,
    /// The lifetime is zero, overflows, or the approval has already expired.
    LifetimeInvalid,
    /// The unsigned envelope digest differs.
    UnsignedEnvelope,
    /// The transaction hash differs.
    TxHash,
    /// The source account differs.
    SourceAccount,
    /// The sequence number differs.
    Sequence,
    /// The Soroban intent digest differs.
    IntentDigest,
    /// The parent intent record differs or does not qualify.
    IntentRecordMismatch,
    /// The final envelope digest differs.
    FinalEnvelope,
    /// The root invocation digest differs.
    RootInvocation,
    /// The inner transaction hash differs.
    InnerTxHash,
    /// No outer transaction hash is bound.
    OuterTxHashAbsent,
    /// The outer transaction hash differs.
    OuterTxHash,
    /// The fee source differs.
    FeeSource,
    /// The bound fee differs.
    MaxFee,
    /// The message's home domain differs.
    MessageHomeDomain,
    /// The message's web authentication domain differs.
    MessageWebAuthDomain,
    /// The message's server key differs.
    MessageServerKey,
    /// The message content digest differs.
    MessageContent,
    /// The domain differs.
    DomainMismatch,
    /// The bound domain facts differ, or the consumption binding does not
    /// fit the domain.
    BindingMismatch,
    /// The content digest differs.
    ContentDigest,
    /// The holds digest differs.
    EntriesDigest,
    /// The aggregate bindings digest differs.
    BindingsDigest,
    /// The domain carries holds it must not, or lacks ones it needs.
    HoldsMismatch,
    /// An open authorization already names this domain and content.
    DuplicateOpen,
    /// The profile already holds the most open authorizations it may.
    TooManyOpen,
    /// A record within retention already carries the approval nonce.
    ApprovalNonceReused,
    /// No policy pin is recorded.
    PolicyPinAbsent,
    /// The recorded policy pin is malformed.
    PolicyPinMalformed,
    /// The recorded policy pin differs from the authorization's policy.
    PolicyPinMismatch,
    /// No authorization has the identity.
    UnknownAuthorization,
    /// The authorization is used, expired, or invalidated.
    NotOpen,
    /// The audit anchor does not cover the log's tip.
    AuditNotAnchored,
    /// A signature does not verify under the bound signer's key.
    SignatureInvalid,
}

impl MainnetPrecondition {
    /// The stable snake-case label the operator's log names.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ProfileMismatch => "profile_mismatch",
            Self::ChainNotMainnet => "chain_not_mainnet",
            Self::ChainMismatch => "chain_mismatch",
            Self::ConsumerMismatch => "consumer_mismatch",
            Self::SignerKeyMismatch => "signer_key_mismatch",
            Self::SignerRoleMismatch => "signer_role_mismatch",
            Self::EndpointPresence => "endpoint_presence",
            Self::EndpointAuthority => "endpoint_authority",
            Self::EndpointClient => "endpoint_client",
            Self::PolicySequence => "policy_sequence",
            Self::PolicyDigest => "policy_digest",
            Self::EnablementMismatch => "enablement_mismatch",
            Self::ApprovalNonce => "approval_nonce",
            Self::ApprovalExpiry => "approval_expiry",
            Self::ReservationMismatch => "reservation_mismatch",
            Self::WitnessSubject => "witness_subject",
            Self::AuditLogPath => "audit_log_path",
            Self::AuditProvenance => "audit_provenance",
            Self::AuditSegment => "audit_segment",
            Self::AuditCount => "audit_count",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::LifetimeInvalid => "lifetime_invalid",
            Self::UnsignedEnvelope => "unsigned_envelope",
            Self::TxHash => "tx_hash",
            Self::SourceAccount => "source_account",
            Self::Sequence => "sequence",
            Self::IntentDigest => "intent_digest",
            Self::IntentRecordMismatch => "intent_record_mismatch",
            Self::FinalEnvelope => "final_envelope",
            Self::RootInvocation => "root_invocation",
            Self::InnerTxHash => "inner_tx_hash",
            Self::OuterTxHashAbsent => "outer_tx_hash_absent",
            Self::OuterTxHash => "outer_tx_hash",
            Self::FeeSource => "fee_source",
            Self::MaxFee => "max_fee",
            Self::MessageHomeDomain => "message_home_domain",
            Self::MessageWebAuthDomain => "message_web_auth_domain",
            Self::MessageServerKey => "message_server_key",
            Self::MessageContent => "message_content",
            Self::DomainMismatch => "domain_mismatch",
            Self::BindingMismatch => "binding_mismatch",
            Self::ContentDigest => "content_digest",
            Self::EntriesDigest => "entries_digest",
            Self::BindingsDigest => "bindings_digest",
            Self::HoldsMismatch => "holds_mismatch",
            Self::DuplicateOpen => "duplicate_open",
            Self::TooManyOpen => "too_many_open",
            Self::ApprovalNonceReused => "approval_nonce_reused",
            Self::PolicyPinAbsent => "policy_pin_absent",
            Self::PolicyPinMalformed => "policy_pin_malformed",
            Self::PolicyPinMismatch => "policy_pin_mismatch",
            Self::UnknownAuthorization => "unknown_authorization",
            Self::NotOpen => "not_open",
            Self::AuditNotAnchored => "audit_not_anchored",
            Self::SignatureInvalid => "signature_invalid",
        }
    }
}

impl std::fmt::Display for MainnetPrecondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A mainnet authorization refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MainnetAuthorizationError {
    /// This build has no mainnet writes.
    #[error("this build has no mainnet writes")]
    FeatureDisabled,
    /// A precondition does not hold.
    #[error("mainnet authorization refused: {0}")]
    Refused(MainnetPrecondition),
}

impl MainnetAuthorizationError {
    /// The agent-facing error, as the [`WalletError`] conversion gives it,
    /// after a refused precondition is logged under `path` with its label.
    ///
    /// For a signing point outside this crate: the precondition never
    /// crosses into the error, so the path that refuses logs it here.
    #[must_use]
    pub fn report(self, path: &'static str) -> WalletError {
        AuthorizedPathError::from(self).report(path)
    }
}

impl From<MainnetAuthorizationError> for WalletError {
    /// The agent-facing error: `network.mainnet_write_forbidden` for a build
    /// without mainnet writes, `network.mainnet_authorization_refused` for
    /// every refused precondition. The precondition does not cross into the
    /// error: the caller logs it.
    fn from(error: MainnetAuthorizationError) -> Self {
        match error {
            MainnetAuthorizationError::FeatureDisabled => {
                WalletError::Network(NetworkError::MainnetWriteForbidden)
            }
            MainnetAuthorizationError::Refused(_) => {
                WalletError::Network(NetworkError::MainnetAuthorizationRefused)
            }
        }
    }
}

/// The failure of an authorized signing or submit path: a broken
/// precondition, which the path logs before it reports the generic refusal,
/// or an error of the path itself, which passes through unchanged.
#[derive(Debug)]
pub(crate) enum AuthorizedPathError {
    /// A precondition does not hold.
    Refused(MainnetPrecondition),
    /// The path failed for a reason of its own.
    Wallet(WalletError),
}

impl AuthorizedPathError {
    /// The agent-facing error. A refusal is logged under `path` with its
    /// precondition's label and becomes `network.mainnet_authorization_refused`.
    pub(crate) fn report(self, path: &'static str) -> WalletError {
        match self {
            Self::Refused(precondition) => {
                tracing::warn!(
                    path,
                    precondition = precondition.label(),
                    "mainnet authorization refused"
                );
                WalletError::Network(NetworkError::MainnetAuthorizationRefused)
            }
            Self::Wallet(error) => error,
        }
    }
}

impl From<MainnetAuthorizationError> for AuthorizedPathError {
    fn from(error: MainnetAuthorizationError) -> Self {
        match error {
            MainnetAuthorizationError::Refused(precondition) => Self::Refused(precondition),
            MainnetAuthorizationError::FeatureDisabled => {
                Self::Wallet(WalletError::Network(NetworkError::MainnetWriteForbidden))
            }
        }
    }
}

impl From<WalletError> for AuthorizedPathError {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}

/// Returns `Ok(())` when `holds`, else the refusal of `precondition`.
pub(crate) fn require(
    holds: bool,
    precondition: MainnetPrecondition,
) -> Result<(), MainnetAuthorizationError> {
    if holds {
        Ok(())
    } else {
        Err(MainnetAuthorizationError::Refused(precondition))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every precondition, through an exhaustive match so a new variant fails
    /// to compile here until it is listed.
    fn every_precondition() -> Vec<MainnetPrecondition> {
        use MainnetPrecondition as P;
        let all = [
            P::ProfileMismatch,
            P::ChainNotMainnet,
            P::ChainMismatch,
            P::ConsumerMismatch,
            P::SignerKeyMismatch,
            P::SignerRoleMismatch,
            P::EndpointPresence,
            P::EndpointAuthority,
            P::EndpointClient,
            P::PolicySequence,
            P::PolicyDigest,
            P::EnablementMismatch,
            P::ApprovalNonce,
            P::ApprovalExpiry,
            P::ReservationMismatch,
            P::WitnessSubject,
            P::AuditLogPath,
            P::AuditProvenance,
            P::AuditSegment,
            P::AuditCount,
            P::NotYetValid,
            P::Expired,
            P::LifetimeInvalid,
            P::UnsignedEnvelope,
            P::TxHash,
            P::SourceAccount,
            P::Sequence,
            P::IntentDigest,
            P::IntentRecordMismatch,
            P::FinalEnvelope,
            P::RootInvocation,
            P::InnerTxHash,
            P::OuterTxHashAbsent,
            P::OuterTxHash,
            P::FeeSource,
            P::MaxFee,
            P::MessageHomeDomain,
            P::MessageWebAuthDomain,
            P::MessageServerKey,
            P::MessageContent,
            P::DomainMismatch,
            P::BindingMismatch,
            P::ContentDigest,
            P::EntriesDigest,
            P::BindingsDigest,
            P::HoldsMismatch,
            P::DuplicateOpen,
            P::TooManyOpen,
            P::ApprovalNonceReused,
            P::PolicyPinAbsent,
            P::PolicyPinMalformed,
            P::PolicyPinMismatch,
            P::UnknownAuthorization,
            P::NotOpen,
            P::AuditNotAnchored,
            P::SignatureInvalid,
        ];
        for precondition in all {
            match precondition {
                P::ProfileMismatch
                | P::ChainNotMainnet
                | P::ChainMismatch
                | P::ConsumerMismatch
                | P::SignerKeyMismatch
                | P::SignerRoleMismatch
                | P::EndpointPresence
                | P::EndpointAuthority
                | P::EndpointClient
                | P::PolicySequence
                | P::PolicyDigest
                | P::EnablementMismatch
                | P::ApprovalNonce
                | P::ApprovalExpiry
                | P::ReservationMismatch
                | P::WitnessSubject
                | P::AuditProvenance
                | P::AuditSegment
                | P::AuditLogPath
                | P::AuditCount
                | P::NotYetValid
                | P::Expired
                | P::LifetimeInvalid
                | P::UnsignedEnvelope
                | P::TxHash
                | P::SourceAccount
                | P::Sequence
                | P::IntentDigest
                | P::IntentRecordMismatch
                | P::FinalEnvelope
                | P::RootInvocation
                | P::InnerTxHash
                | P::OuterTxHashAbsent
                | P::OuterTxHash
                | P::FeeSource
                | P::MaxFee
                | P::MessageHomeDomain
                | P::MessageWebAuthDomain
                | P::MessageServerKey
                | P::MessageContent
                | P::DomainMismatch
                | P::BindingMismatch
                | P::ContentDigest
                | P::EntriesDigest
                | P::BindingsDigest
                | P::HoldsMismatch
                | P::DuplicateOpen
                | P::TooManyOpen
                | P::ApprovalNonceReused
                | P::PolicyPinAbsent
                | P::PolicyPinMalformed
                | P::PolicyPinMismatch
                | P::UnknownAuthorization
                | P::NotOpen
                | P::AuditNotAnchored
                | P::SignatureInvalid => {}
            }
        }
        all.to_vec()
    }

    /// Every refused precondition maps to the one agent-facing code, whose
    /// text names no precondition; a disabled build maps to the write
    /// refusal.
    #[test]
    fn every_refusal_maps_to_the_one_generic_code() {
        let all = every_precondition();
        let mut labels: Vec<_> = all.iter().map(|p| p.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len(), "labels are distinct");
        for precondition in all {
            let error = WalletError::from(MainnetAuthorizationError::Refused(precondition));
            assert_eq!(error.code(), "network.mainnet_authorization_refused");
            let text = error.to_string();
            assert!(!text.contains(precondition.label()), "{text}");
            assert!(
                MainnetAuthorizationError::Refused(precondition)
                    .to_string()
                    .contains(precondition.label())
            );
        }
        assert_eq!(
            WalletError::from(MainnetAuthorizationError::FeatureDisabled).code(),
            "network.mainnet_write_forbidden"
        );
    }

    /// The logging report gives the agent-facing error of the conversion.
    #[test]
    fn report_gives_the_converted_error() {
        for precondition in every_precondition() {
            let error = MainnetAuthorizationError::Refused(precondition);
            assert_eq!(
                error.report("test").code(),
                WalletError::from(error).code(),
                "{precondition}"
            );
        }
        assert_eq!(
            MainnetAuthorizationError::FeatureDisabled
                .report("test")
                .code(),
            "network.mainnet_write_forbidden"
        );
    }

    #[test]
    fn require_refuses_with_its_precondition() {
        assert_eq!(require(true, MainnetPrecondition::TxHash), Ok(()));
        assert_eq!(
            require(false, MainnetPrecondition::TxHash),
            Err(MainnetAuthorizationError::Refused(
                MainnetPrecondition::TxHash
            ))
        );
    }
}

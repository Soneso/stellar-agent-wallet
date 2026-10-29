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
    /// The profile name was not selected by a flag.
    NameSourceNotFlag,
    /// The default profile cannot authorize mainnet writes.
    DefaultProfile,
    /// An endpoint override is forbidden.
    EndpointFlagRefused,
    /// The stored owner coordinate derives another profile name.
    DerivedNameMismatch,
    /// The merged chain or endpoint differs from disk.
    DiskViewMismatch,
    /// The authorization clock is unavailable.
    ClockUnavailable,
    /// The signed policy has no mainnet body.
    PolicyNotMainnet,
    /// The enablement names another policy sequence.
    EnablementSequenceMismatch,
    /// The endpoint identity cannot be established.
    EndpointUnavailable,
    /// The endpoint protocol is unsupported.
    EndpointProtocolUnsupported,
    /// The endpoint does not report mainnet.
    EndpointNotMainnet,
    /// The enabled endpoint host differs.
    EnablementHostMismatch,
    /// Fee bump resolution is forbidden.
    FeeBumpRefused,
    /// The envelope has an unsupported shape.
    EnvelopeShape,
    /// The envelope already carries signatures.
    EnvelopePreSigned,
    /// The envelope fee exceeds its effective cap.
    FeeAboveCap,
    /// The source account cannot be read.
    AccountUnavailable,
    /// Policy evaluation or sizing failed.
    PolicyEvaluationFailed,
    /// The signed and stored thresholds name no threshold for the asset.
    WitnessThresholdMissing,
    /// The profile has no oracle.
    WitnessOracleMissing,
    /// The required cross-check witness is absent.
    WitnessRequired,
    /// The witness shares the primary endpoint host.
    WitnessSameHost,
    /// The witness does not name the stored oracle host.
    WitnessOracleUnbound,
    /// The approval names another profile.
    ApprovalProfileMismatch,
    /// The approval names another chain.
    ApprovalChainMismatch,
    /// The approval names another subject.
    ApprovalSubjectMismatch,
    /// The approval has another kind.
    ApprovalKindMismatch,
    /// The approval has expired.
    ApprovalExpired,
    /// The approval lifetime exceeds the governing rule.
    ApprovalTtlExceedsRule,
    /// The audit lease names another profile.
    AuditProfileMismatch,
    /// The audit readiness proof is stale.
    AuditStale,
    /// The signer coordinate differs from the stored profile.
    SignerCoordinateMismatch,
    /// The authorization store is unavailable.
    StoreUnavailable,
    /// The intent has an unsupported invocation shape.
    IntentShape,
    /// The intent names another network.
    IntentNetworkMismatch,
    /// The intent payer differs from the signer.
    IntentPayerMismatch,
    /// The final envelope does not derive from the consumed intent.
    DerivationMismatch,
    /// The final envelope carries different authorization entries.
    AuthEntriesMismatch,

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
    /// The time precedes the authorization's issue time or the approval's creation time.
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
    /// The authorization entry's nonce differs from the bound one.
    EntryNonce,
    /// The authorization entry's signature expiration ledger differs from
    /// the bound one.
    EntryExpiration,
    /// A type 10 Soroban preimage is bound to another address than the
    /// account of the authorization's signer.
    PreimageAddress,
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
    /// A message receipt's bound content digest or ephemeral key differs
    /// from the message about to be signed.
    MessageUseMismatch,
    /// A SEP-10 challenge's client account is not the ephemeral account
    /// that signs it.
    MessageClientAccount,
}

impl MainnetPrecondition {
    /// The stable snake-case label the operator's log names.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NameSourceNotFlag => "name_source_not_flag",
            Self::DefaultProfile => "default_profile",
            Self::EndpointFlagRefused => "endpoint_flag_refused",
            Self::DerivedNameMismatch => "derived_name_mismatch",
            Self::DiskViewMismatch => "disk_view_mismatch",
            Self::ClockUnavailable => "clock_unavailable",
            Self::PolicyNotMainnet => "policy_not_mainnet",
            Self::EnablementSequenceMismatch => "enablement_sequence_mismatch",
            Self::EndpointUnavailable => "endpoint_unavailable",
            Self::EndpointProtocolUnsupported => "endpoint_protocol_unsupported",
            Self::EndpointNotMainnet => "endpoint_not_mainnet",
            Self::EnablementHostMismatch => "enablement_host_mismatch",
            Self::FeeBumpRefused => "fee_bump_refused",
            Self::EnvelopeShape => "envelope_shape",
            Self::EnvelopePreSigned => "envelope_pre_signed",
            Self::FeeAboveCap => "fee_above_cap",
            Self::AccountUnavailable => "account_unavailable",
            Self::PolicyEvaluationFailed => "policy_evaluation_failed",
            Self::WitnessThresholdMissing => "witness_threshold_missing",
            Self::WitnessOracleMissing => "witness_oracle_missing",
            Self::WitnessRequired => "witness_required",
            Self::WitnessSameHost => "witness_same_host",
            Self::WitnessOracleUnbound => "witness_oracle_unbound",
            Self::ApprovalProfileMismatch => "approval_profile_mismatch",
            Self::ApprovalChainMismatch => "approval_chain_mismatch",
            Self::ApprovalSubjectMismatch => "approval_subject_mismatch",
            Self::ApprovalKindMismatch => "approval_kind_mismatch",
            Self::ApprovalExpired => "approval_expired",
            Self::ApprovalTtlExceedsRule => "approval_ttl_exceeds_rule",
            Self::AuditProfileMismatch => "audit_profile_mismatch",
            Self::AuditStale => "audit_stale",
            Self::SignerCoordinateMismatch => "signer_coordinate_mismatch",
            Self::StoreUnavailable => "store_unavailable",
            Self::IntentShape => "intent_shape",
            Self::IntentNetworkMismatch => "intent_network_mismatch",
            Self::IntentPayerMismatch => "intent_payer_mismatch",
            Self::DerivationMismatch => "derivation_mismatch",
            Self::AuthEntriesMismatch => "auth_entries_mismatch",

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
            Self::EntryNonce => "entry_nonce",
            Self::EntryExpiration => "entry_expiration",
            Self::PreimageAddress => "preimage_address",
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
            Self::MessageUseMismatch => "message_use_mismatch",
            Self::MessageClientAccount => "message_client_account",
        }
    }
}

impl std::fmt::Display for MainnetPrecondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A mainnet authorization refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MainnetAuthorizationError {
    /// The policy denies evaluation or admission.
    #[error("mainnet policy denied")]
    PolicyDenied(Box<stellar_agent_core::policy::DenyReason>),
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
    /// The agent-facing error: the policy's `policy.deny.*` code for a
    /// denial, `network.mainnet_write_forbidden` for a build without mainnet
    /// writes, and `network.mainnet_authorization_refused` for every refused
    /// precondition. The precondition does not cross into the error: the
    /// caller logs it.
    fn from(error: MainnetAuthorizationError) -> Self {
        match error {
            MainnetAuthorizationError::PolicyDenied(reason) => WalletError::PolicyDenied { reason },
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
            MainnetAuthorizationError::PolicyDenied(reason) => {
                Self::Wallet(WalletError::PolicyDenied { reason })
            }
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
            P::NameSourceNotFlag,
            P::DefaultProfile,
            P::EndpointFlagRefused,
            P::DerivedNameMismatch,
            P::DiskViewMismatch,
            P::ClockUnavailable,
            P::PolicyNotMainnet,
            P::EnablementSequenceMismatch,
            P::EndpointUnavailable,
            P::EndpointProtocolUnsupported,
            P::EndpointNotMainnet,
            P::EnablementHostMismatch,
            P::FeeBumpRefused,
            P::EnvelopeShape,
            P::EnvelopePreSigned,
            P::FeeAboveCap,
            P::AccountUnavailable,
            P::PolicyEvaluationFailed,
            P::WitnessThresholdMissing,
            P::WitnessOracleMissing,
            P::WitnessRequired,
            P::WitnessSameHost,
            P::WitnessOracleUnbound,
            P::ApprovalProfileMismatch,
            P::ApprovalChainMismatch,
            P::ApprovalSubjectMismatch,
            P::ApprovalKindMismatch,
            P::ApprovalExpired,
            P::ApprovalTtlExceedsRule,
            P::AuditProfileMismatch,
            P::AuditStale,
            P::SignerCoordinateMismatch,
            P::StoreUnavailable,
            P::IntentShape,
            P::IntentNetworkMismatch,
            P::IntentPayerMismatch,
            P::DerivationMismatch,
            P::AuthEntriesMismatch,
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
            P::EntryNonce,
            P::EntryExpiration,
            P::PreimageAddress,
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
            P::MessageUseMismatch,
            P::MessageClientAccount,
        ];
        for precondition in all {
            match precondition {
                P::NameSourceNotFlag
                | P::DefaultProfile
                | P::EndpointFlagRefused
                | P::DerivedNameMismatch
                | P::DiskViewMismatch
                | P::ClockUnavailable
                | P::PolicyNotMainnet
                | P::EnablementSequenceMismatch
                | P::EndpointUnavailable
                | P::EndpointProtocolUnsupported
                | P::EndpointNotMainnet
                | P::EnablementHostMismatch
                | P::FeeBumpRefused
                | P::EnvelopeShape
                | P::EnvelopePreSigned
                | P::FeeAboveCap
                | P::AccountUnavailable
                | P::PolicyEvaluationFailed
                | P::WitnessThresholdMissing
                | P::WitnessOracleMissing
                | P::WitnessRequired
                | P::WitnessSameHost
                | P::WitnessOracleUnbound
                | P::ApprovalProfileMismatch
                | P::ApprovalChainMismatch
                | P::ApprovalSubjectMismatch
                | P::ApprovalKindMismatch
                | P::ApprovalExpired
                | P::ApprovalTtlExceedsRule
                | P::AuditProfileMismatch
                | P::AuditStale
                | P::SignerCoordinateMismatch
                | P::StoreUnavailable
                | P::IntentShape
                | P::IntentNetworkMismatch
                | P::IntentPayerMismatch
                | P::DerivationMismatch
                | P::AuthEntriesMismatch
                | P::ProfileMismatch
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
                | P::EntryNonce
                | P::EntryExpiration
                | P::PreimageAddress
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
                | P::SignatureInvalid
                | P::MessageUseMismatch
                | P::MessageClientAccount => {}
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
        let expected = [
            "name_source_not_flag",
            "default_profile",
            "endpoint_flag_refused",
            "derived_name_mismatch",
            "disk_view_mismatch",
            "clock_unavailable",
            "policy_not_mainnet",
            "enablement_sequence_mismatch",
            "endpoint_unavailable",
            "endpoint_protocol_unsupported",
            "endpoint_not_mainnet",
            "enablement_host_mismatch",
            "fee_bump_refused",
            "envelope_shape",
            "envelope_pre_signed",
            "fee_above_cap",
            "account_unavailable",
            "policy_evaluation_failed",
            "witness_threshold_missing",
            "witness_oracle_missing",
            "witness_required",
            "witness_same_host",
            "witness_oracle_unbound",
            "approval_profile_mismatch",
            "approval_chain_mismatch",
            "approval_subject_mismatch",
            "approval_kind_mismatch",
            "approval_expired",
            "approval_ttl_exceeds_rule",
            "audit_profile_mismatch",
            "audit_stale",
            "signer_coordinate_mismatch",
            "store_unavailable",
            "intent_shape",
            "intent_network_mismatch",
            "intent_payer_mismatch",
            "derivation_mismatch",
            "auth_entries_mismatch",
            "profile_mismatch",
            "chain_not_mainnet",
            "chain_mismatch",
            "consumer_mismatch",
            "signer_key_mismatch",
            "signer_role_mismatch",
            "endpoint_presence",
            "endpoint_authority",
            "endpoint_client",
            "policy_sequence",
            "policy_digest",
            "enablement_mismatch",
            "approval_nonce",
            "approval_expiry",
            "reservation_mismatch",
            "witness_subject",
            "audit_log_path",
            "audit_provenance",
            "audit_segment",
            "audit_count",
            "not_yet_valid",
            "expired",
            "lifetime_invalid",
            "unsigned_envelope",
            "tx_hash",
            "source_account",
            "sequence",
            "intent_digest",
            "entry_nonce",
            "entry_expiration",
            "preimage_address",
            "intent_record_mismatch",
            "final_envelope",
            "root_invocation",
            "inner_tx_hash",
            "outer_tx_hash_absent",
            "outer_tx_hash",
            "fee_source",
            "max_fee",
            "message_home_domain",
            "message_web_auth_domain",
            "message_server_key",
            "message_content",
            "domain_mismatch",
            "binding_mismatch",
            "content_digest",
            "entries_digest",
            "bindings_digest",
            "holds_mismatch",
            "duplicate_open",
            "too_many_open",
            "approval_nonce_reused",
            "policy_pin_absent",
            "policy_pin_malformed",
            "policy_pin_mismatch",
            "unknown_authorization",
            "not_open",
            "audit_not_anchored",
            "signature_invalid",
            "message_use_mismatch",
            "message_client_account",
        ];
        assert_eq!(all.iter().map(|p| p.label()).collect::<Vec<_>>(), expected);
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
                error.clone().report("test").code(),
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
    #[test]
    fn policy_denied_maps_to_policy_code() {
        let reason = stellar_agent_core::policy::DenyReason::AssetNotAllowlisted;
        let expected = reason.wire_code();
        let error: WalletError = MainnetAuthorizationError::PolicyDenied(Box::new(reason)).into();
        assert!(matches!(error, WalletError::PolicyDenied { .. }));
        assert_eq!(error.code(), expected);
    }
}

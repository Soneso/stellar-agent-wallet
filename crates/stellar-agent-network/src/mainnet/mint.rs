//! Sealed composition of checked proofs and durable authorization records.

use super::{MainnetAuthorizationError, MainnetPrecondition};
use crate::policy_state::WindowStoreError;

pub(crate) fn store_error(error: WindowStoreError) -> MainnetAuthorizationError {
    match error {
        WindowStoreError::AuthorizationRefused { precondition } => {
            MainnetAuthorizationError::Refused(precondition)
        }
        WindowStoreError::PolicyDenied { reason } => {
            MainnetAuthorizationError::PolicyDenied(reason)
        }
        _ => MainnetAuthorizationError::Refused(MainnetPrecondition::StoreUnavailable),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the header binds every independently checked proof"
)]
pub(crate) fn header(
    context: &crate::MainnetWriteContext,
    request: &crate::policy_state::MintRequest,
    minted: crate::policy_state::MintedRecord,
    endpoint: &crate::endpoint_identity::EndpointIdentity,
    signer: &crate::keyring::EnrolledSigner,
    enablement: &stellar_agent_core::mainnet::enablement::EnablementRecord,
    approval: &stellar_agent_core::approval::witness::ApprovalWitness,
    witness: Option<&crate::cross_check::CrossCheckWitness>,
    audit: super::audit_readiness::AuditReadiness,
) -> super::authorization::Header {
    use super::authorization::{
        ApprovalBinding, EndpointBinding, Header, PolicyBinding, SignerBinding,
    };
    Header {
        id: minted.id,
        profile: context.profile_name().to_owned(),
        chain: context.chain(),
        domain: request.binding.domain(),
        consumer: request.consumer,
        endpoint: Some(EndpointBinding {
            authority: endpoint.authority().to_owned(),
            client_id: endpoint.client_id(),
        }),
        signer: SignerBinding {
            public_key: signer.public_key(),
            role: super::SignerRole::AgentSigner,
        },
        policy: PolicyBinding {
            sequence: request.policy_sequence,
            digest: request.policy_digest,
        },
        enablement_nonce_digest: *enablement.nonce_digest(),
        approval: ApprovalBinding {
            nonce: approval.nonce().to_owned(),
            expires_at_ms: approval.expires_at_ms(),
        },
        reservation: minted.reservation,
        witness_subject: witness.and_then(|w| w.subject()),
        audit,
        issued_at_ms: minted.issued_at_ms,
        expires_at_ms: minted.expires_at_ms,
        bindings_digest: minted.bindings_digest,
    }
}

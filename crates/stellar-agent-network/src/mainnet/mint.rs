//! Sealed composition of checked proofs and durable authorization records.

use super::authorization::{
    ApprovalBinding, EndpointBinding, Header, MainnetMessageSignAuthorization, MessageSignInner,
    PolicyBinding, SignerBinding,
};
use super::{MainnetAuthorizationError, MainnetPrecondition, SignerRole};
use crate::policy_state::{MintRequest, MintedRecord, WindowStoreError};
use stellar_agent_core::approval::witness::ApprovalWitness;
use stellar_agent_core::mainnet::enablement::EnablementRecord;

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

/// The header of an authorization the enrolled agent signer acts under,
/// bound to the endpoint identity the resolver established.
#[allow(
    clippy::too_many_arguments,
    reason = "the header binds every independently checked proof"
)]
pub(crate) fn header(
    context: &crate::MainnetWriteContext,
    request: &MintRequest,
    minted: MintedRecord,
    endpoint: &crate::endpoint_identity::EndpointIdentity,
    signer: &crate::keyring::EnrolledSigner,
    enablement: &EnablementRecord,
    approval: &ApprovalWitness,
    witness: Option<&crate::cross_check::CrossCheckWitness>,
    audit: super::audit_readiness::AuditReadiness,
) -> Header {
    assemble(
        context,
        request,
        minted,
        Some(EndpointBinding {
            authority: endpoint.authority().to_owned(),
            client_id: endpoint.client_id(),
        }),
        SignerBinding {
            public_key: signer.public_key(),
            role: SignerRole::AgentSigner,
        },
        enablement,
        approval,
        witness.and_then(|w| w.subject()),
        audit,
    )
}

/// The Message arm: the authorization of a minted zero-value message record.
///
/// The record binds no endpoint, because a message signing reaches no RPC
/// endpoint, and its signer is the SEP-10 ephemeral key in the
/// [`SignerRole::Sep10Ephemeral`] role, not an enrolled signer. It binds no
/// witness subject. The binding moves out of `request` into the
/// authorization.
pub(crate) fn message(
    context: &crate::MainnetWriteContext,
    request: MintRequest,
    minted: MintedRecord,
    ephemeral_public_key: [u8; 32],
    enablement: &EnablementRecord,
    approval: &ApprovalWitness,
    audit: super::audit_readiness::AuditReadiness,
) -> MainnetMessageSignAuthorization {
    let header = assemble(
        context,
        &request,
        minted,
        None,
        SignerBinding {
            public_key: ephemeral_public_key,
            role: SignerRole::Sep10Ephemeral,
        },
        enablement,
        approval,
        None,
        audit,
    );
    MainnetMessageSignAuthorization::from_inner(MessageSignInner {
        header,
        binding: request.binding,
    })
}

/// The one assembly of every header: the minted record's identity, lifetime,
/// reservation, and bindings digest; the context's profile name and chain;
/// the request's domain, consumer, and policy; the enablement nonce digest;
/// the approval's nonce and expiry; and the endpoint, signer, witness subject,
/// and audit lease the caller supplies.
#[allow(
    clippy::too_many_arguments,
    reason = "the header binds every independently checked proof"
)]
fn assemble(
    context: &crate::MainnetWriteContext,
    request: &MintRequest,
    minted: MintedRecord,
    endpoint: Option<EndpointBinding>,
    signer: SignerBinding,
    enablement: &EnablementRecord,
    approval: &ApprovalWitness,
    witness_subject: Option<[u8; 32]>,
    audit: super::audit_readiness::AuditReadiness,
) -> Header {
    Header {
        id: minted.id,
        profile: context.profile_name().to_owned(),
        chain: context.chain(),
        domain: request.binding.domain(),
        consumer: request.consumer,
        endpoint,
        signer,
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
        witness_subject,
        audit,
        issued_at_ms: minted.issued_at_ms,
        expires_at_ms: minted.expires_at_ms,
        bindings_digest: minted.bindings_digest,
    }
}

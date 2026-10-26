//! The five mainnet authorization types.
//!
//! A mainnet authorization is the signing authority one action receives once
//! every proof it needs holds: the endpoint identity, the enrolled signer,
//! the verified policy and the enablement record, the cross-check witness
//! when one is required, the window reservation when the action holds
//! entries, the approval witness, and the audit readiness. The facts of each
//! proof, and the aggregate digest over their fact digests, are bound into
//! one header together with the record the authorization ledger minted.
//!
//! | Type | Domain |
//! |---|---|
//! | [`MainnetTxSignAuthorization`] | signing a classic transaction |
//! | [`MainnetSorobanIntentAuthorization`] | signing a Soroban authorization for an x402 intent |
//! | [`MainnetSubmitAuthorization`] | releasing a signed x402 payload |
//! | [`MainnetFeeBumpAuthorization`] | a fee-bump phase: [`Inner`], [`Outer`], [`Submit`] |
//! | [`MainnetMessageSignAuthorization`] | signing a message |
//!
//! # The sealing boundary
//!
//! The window store's transitions are public and yield ledger results and
//! reservation proofs, never signing authority. Only this crate's
//! crate-private header assembles an authorization, so no code outside the
//! crate holds one it did not receive from the crate's resolvers. Each type
//! is a tuple struct over a private inner type: no literal, no constructor,
//! and no trait builds or copies one.
//!
//! An authorization exposes its identity, its expiry, its signer, and its
//! endpoint, and otherwise only checks: each compares one candidate fact a
//! consumer holds with the bound one and returns `Ok(())` or
//! [`MainnetAuthorizationError::Refused`] naming the precondition.
//! `consume_expect` combines the bound facts with the consumer's recomputed
//! ones into the expectation the ledger compares at consumption; the bound
//! facts never leave the type.
//!
//! # Without mainnet writes
//!
//! In a build without the `mainnet-write` feature every inner type holds an
//! uninhabited value, so no authorization exists, and every method is the
//! empty match that proves it. The fee-bump role parameter is kept in both
//! builds.
//!
//! # Compile-time contract
//!
//! No authorization can be constructed outside the crate:
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization as A;
//! fn main() { let _ = A(loop {}); }
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::mainnet::authorization::MainnetSorobanIntentAuthorization as A;
//! fn main() { let _ = A(loop {}); }
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::mainnet::authorization::MainnetSubmitAuthorization as A;
//! fn main() { let _ = A(loop {}); }
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Inner};
//! fn main() { let _ = MainnetFeeBumpAuthorization::<Inner>(loop {}); }
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Outer};
//! fn main() { let _ = MainnetFeeBumpAuthorization::<Outer>(loop {}); }
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Submit};
//! fn main() { let _ = MainnetFeeBumpAuthorization::<Submit>(loop {}); }
//! ```
//!
//! ```compile_fail,E0423
//! use stellar_agent_network::mainnet::authorization::MainnetMessageSignAuthorization as A;
//! fn main() { let _ = A(loop {}); }
//! ```
//!
//! The inner types are private in both builds:
//!
//! ```compile_fail,E0603
//! use stellar_agent_network::mainnet::authorization::TxSignInner;
//! ```
//!
//! ```compile_fail,E0603
//! use stellar_agent_network::mainnet::authorization::SorobanIntentInner;
//! ```
//!
//! ```compile_fail,E0603
//! use stellar_agent_network::mainnet::authorization::SubmitInner;
//! ```
//!
//! ```compile_fail,E0603
//! use stellar_agent_network::mainnet::authorization::FeeBumpInner;
//! ```
//!
//! ```compile_fail,E0603
//! use stellar_agent_network::mainnet::authorization::MessageSignInner;
//! ```
//!
//! The public names resolve, so each snippet above fails on the barrier it
//! names and not on the path:
//!
//! ```
//! use stellar_agent_network::mainnet::AuthorizationId;
//! use stellar_agent_network::mainnet::authorization::{
//!     FeeBumpRole, Inner, MainnetFeeBumpAuthorization, MainnetMessageSignAuthorization,
//!     MainnetSorobanIntentAuthorization, MainnetSubmitAuthorization,
//!     MainnetTxSignAuthorization, Outer, Submit,
//! };
//! fn ids(
//!     a: &MainnetTxSignAuthorization,
//!     b: &MainnetSorobanIntentAuthorization,
//!     c: &MainnetSubmitAuthorization,
//!     d: &MainnetFeeBumpAuthorization<Inner>,
//!     e: &MainnetFeeBumpAuthorization<Outer>,
//!     f: &MainnetFeeBumpAuthorization<Submit>,
//!     g: &MainnetMessageSignAuthorization,
//! ) -> [AuthorizationId; 7] {
//!     [a.id(), b.id(), c.id(), d.id(), e.id(), f.id(), g.id()]
//! }
//! fn role<R: FeeBumpRole>() {}
//! role::<Inner>();
//! let _ = ids;
//! ```
//!
//! No authorization implements `Serialize`, `Deserialize`, `Default`,
//! `Clone`, or `Copy`:
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
//! fn need<T: serde::Serialize>() {}
//! need::<MainnetTxSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<MainnetTxSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
//! fn need<T: Default>() {}
//! need::<MainnetTxSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
//! fn need<T: Clone>() {}
//! need::<MainnetTxSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
//! fn need<T: Copy>() {}
//! need::<MainnetTxSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSorobanIntentAuthorization;
//! fn need<T: serde::Serialize>() {}
//! need::<MainnetSorobanIntentAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSorobanIntentAuthorization;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<MainnetSorobanIntentAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSorobanIntentAuthorization;
//! fn need<T: Default>() {}
//! need::<MainnetSorobanIntentAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSorobanIntentAuthorization;
//! fn need<T: Clone>() {}
//! need::<MainnetSorobanIntentAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSorobanIntentAuthorization;
//! fn need<T: Copy>() {}
//! need::<MainnetSorobanIntentAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSubmitAuthorization;
//! fn need<T: serde::Serialize>() {}
//! need::<MainnetSubmitAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSubmitAuthorization;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<MainnetSubmitAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSubmitAuthorization;
//! fn need<T: Default>() {}
//! need::<MainnetSubmitAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSubmitAuthorization;
//! fn need<T: Clone>() {}
//! need::<MainnetSubmitAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetSubmitAuthorization;
//! fn need<T: Copy>() {}
//! need::<MainnetSubmitAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Inner};
//! fn need<T: serde::Serialize>() {}
//! need::<MainnetFeeBumpAuthorization<Inner>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Inner};
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<MainnetFeeBumpAuthorization<Inner>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Inner};
//! fn need<T: Default>() {}
//! need::<MainnetFeeBumpAuthorization<Inner>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Inner};
//! fn need<T: Clone>() {}
//! need::<MainnetFeeBumpAuthorization<Inner>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Inner};
//! fn need<T: Copy>() {}
//! need::<MainnetFeeBumpAuthorization<Inner>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Outer};
//! fn need<T: serde::Serialize>() {}
//! need::<MainnetFeeBumpAuthorization<Outer>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Outer};
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<MainnetFeeBumpAuthorization<Outer>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Outer};
//! fn need<T: Default>() {}
//! need::<MainnetFeeBumpAuthorization<Outer>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Outer};
//! fn need<T: Clone>() {}
//! need::<MainnetFeeBumpAuthorization<Outer>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Outer};
//! fn need<T: Copy>() {}
//! need::<MainnetFeeBumpAuthorization<Outer>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Submit};
//! fn need<T: serde::Serialize>() {}
//! need::<MainnetFeeBumpAuthorization<Submit>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Submit};
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<MainnetFeeBumpAuthorization<Submit>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Submit};
//! fn need<T: Default>() {}
//! need::<MainnetFeeBumpAuthorization<Submit>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Submit};
//! fn need<T: Clone>() {}
//! need::<MainnetFeeBumpAuthorization<Submit>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::{MainnetFeeBumpAuthorization, Submit};
//! fn need<T: Copy>() {}
//! need::<MainnetFeeBumpAuthorization<Submit>>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetMessageSignAuthorization;
//! fn need<T: serde::Serialize>() {}
//! need::<MainnetMessageSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetMessageSignAuthorization;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<MainnetMessageSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetMessageSignAuthorization;
//! fn need<T: Default>() {}
//! need::<MainnetMessageSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetMessageSignAuthorization;
//! fn need<T: Clone>() {}
//! need::<MainnetMessageSignAuthorization>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::authorization::MainnetMessageSignAuthorization;
//! fn need<T: Copy>() {}
//! need::<MainnetMessageSignAuthorization>();
//! ```
//!
#![cfg_attr(
    feature = "mainnet-write",
    doc = "The header that assembles an authorization is private as well:\n\n```compile_fail,E0603\nuse stellar_agent_network::mainnet::authorization::Header;\n```"
)]

use std::marker::PhantomData;

#[cfg(feature = "mainnet-write")]
use stellar_agent_core::profile::caip2::Caip2;

use super::refusal::MainnetAuthorizationError;
#[cfg(feature = "mainnet-write")]
use super::refusal::{MainnetPrecondition as P, require};
use super::types::{
    AuthorizationDomain, AuthorizationId, MainnetConsumer, MessageDomain, RecomputedFacts,
    SignerRole,
};
use crate::policy_state::ConsumeExpect;
#[cfg(feature = "mainnet-write")]
use crate::policy_state::{DomainBinding, WindowReservation};

#[cfg(feature = "mainnet-write")]
use super::audit_readiness::AuditReadiness;
#[cfg(feature = "mainnet-write")]
use super::types::AuditFacts;

mod sealed {
    /// Keeps the fee-bump roles to the three this module defines.
    pub trait Sealed {}
}

/// A fee-bump phase: [`Inner`], [`Outer`], or [`Submit`].
///
/// Sealed: no other role exists.
pub trait FeeBumpRole: sealed::Sealed {
    /// The ledger domain of an authorization of this phase.
    const DOMAIN: AuthorizationDomain;
}

/// The inner-transaction phase of a fee bump, signed by the agent signer.
#[derive(Debug)]
pub struct Inner;

/// The outer fee-bump phase, signed by the fee payer.
#[derive(Debug)]
pub struct Outer;

/// The submission phase of a signed fee bump.
#[derive(Debug)]
pub struct Submit;

impl sealed::Sealed for Inner {}
impl sealed::Sealed for Outer {}
impl sealed::Sealed for Submit {}

impl FeeBumpRole for Inner {
    const DOMAIN: AuthorizationDomain = AuthorizationDomain::FeeBumpInner;
}

impl FeeBumpRole for Outer {
    const DOMAIN: AuthorizationDomain = AuthorizationDomain::FeeBumpOuter;
}

impl FeeBumpRole for Submit {
    const DOMAIN: AuthorizationDomain = AuthorizationDomain::FeeBumpSubmit;
}

// ─────────────────────────────────────────────────────────────────────────────
// The header
// ─────────────────────────────────────────────────────────────────────────────

/// The endpoint an authorization binds: the authority and the client its
/// identity was established through.
#[cfg(feature = "mainnet-write")]
pub(crate) struct EndpointBinding {
    pub(crate) authority: String,
    pub(crate) client_id: u64,
}

/// The signer an authorization binds.
#[cfg(feature = "mainnet-write")]
pub(crate) struct SignerBinding {
    pub(crate) public_key: [u8; 32],
    pub(crate) role: SignerRole,
}

/// The verified policy an authorization binds.
#[cfg(feature = "mainnet-write")]
pub(crate) struct PolicyBinding {
    pub(crate) sequence: i64,
    pub(crate) digest: [u8; 32],
}

/// The approval an authorization binds, with its effective expiry in Unix
/// milliseconds.
#[cfg(feature = "mainnet-write")]
pub(crate) struct ApprovalBinding {
    pub(crate) nonce: String,
    pub(crate) expires_at_ms: u64,
}

/// The facts every mainnet authorization binds.
///
/// Assembled only by this crate's resolvers. `expires_at_ms` is the earlier
/// of the issue time plus the authorization lifetime and the approval's
/// expiry; `bindings_digest` is
/// [`crate::mainnet::digest::bindings_digest`] over the proofs' fact
/// digests. The audit proof keeps the audit writer alive while the
/// authorization lives.
#[cfg(feature = "mainnet-write")]
pub(crate) struct Header {
    pub(crate) id: AuthorizationId,
    pub(crate) profile: String,
    pub(crate) chain: Caip2,
    pub(crate) domain: AuthorizationDomain,
    pub(crate) consumer: MainnetConsumer,
    pub(crate) endpoint: Option<EndpointBinding>,
    pub(crate) signer: SignerBinding,
    pub(crate) policy: PolicyBinding,
    pub(crate) enablement_nonce_digest: [u8; 32],
    pub(crate) approval: ApprovalBinding,
    pub(crate) reservation: Option<WindowReservation>,
    pub(crate) witness_subject: Option<[u8; 32]>,
    pub(crate) audit: AuditReadiness,
    pub(crate) issued_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) bindings_digest: [u8; 32],
}

#[cfg(feature = "mainnet-write")]
impl Header {
    fn check_profile(&self, profile: &str) -> Result<(), MainnetAuthorizationError> {
        require(self.profile == profile, P::ProfileMismatch)
    }

    fn check_chain(&self, chain: Caip2) -> Result<(), MainnetAuthorizationError> {
        require(
            chain.is_mainnet() && self.chain.is_mainnet(),
            P::ChainNotMainnet,
        )?;
        require(chain == self.chain, P::ChainMismatch)
    }

    fn check_consumer(&self, consumer: MainnetConsumer) -> Result<(), MainnetAuthorizationError> {
        require(consumer == self.consumer, P::ConsumerMismatch)?;
        require(
            self.domain != AuthorizationDomain::Soroban
                || matches!(
                    consumer,
                    MainnetConsumer::X402Create | MainnetConsumer::X402Authenticated
                ),
            P::ConsumerMismatch,
        )
    }

    fn check_signer(
        &self,
        public_key: &[u8; 32],
        role: SignerRole,
    ) -> Result<(), MainnetAuthorizationError> {
        require(*public_key == self.signer.public_key, P::SignerKeyMismatch)?;
        require(role == self.signer.role, P::SignerRoleMismatch)
    }

    fn check_endpoint(
        &self,
        candidate: Option<(&str, u64)>,
    ) -> Result<(), MainnetAuthorizationError> {
        match (&self.endpoint, candidate) {
            (None, None) => Ok(()),
            (Some(bound), Some((authority, client_id))) => {
                require(bound.authority == authority, P::EndpointAuthority)?;
                require(bound.client_id == client_id, P::EndpointClient)
            }
            _ => Err(MainnetAuthorizationError::Refused(P::EndpointPresence)),
        }
    }

    fn check_policy(
        &self,
        sequence: i64,
        digest: &[u8; 32],
    ) -> Result<(), MainnetAuthorizationError> {
        require(sequence == self.policy.sequence, P::PolicySequence)?;
        require(*digest == self.policy.digest, P::PolicyDigest)
    }

    fn check_enablement(&self, nonce_digest: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
        require(
            *nonce_digest == self.enablement_nonce_digest,
            P::EnablementMismatch,
        )
    }

    fn check_approval(&self, nonce: &str) -> Result<(), MainnetAuthorizationError> {
        require(nonce == self.approval.nonce, P::ApprovalNonce)
    }

    fn check_reservation(
        &self,
        candidate: Option<AuthorizationId>,
    ) -> Result<(), MainnetAuthorizationError> {
        require(
            candidate == self.reservation.as_ref().map(WindowReservation::id),
            P::ReservationMismatch,
        )
    }

    fn check_witness_subject(
        &self,
        candidate: Option<[u8; 32]>,
    ) -> Result<(), MainnetAuthorizationError> {
        require(candidate == self.witness_subject, P::WitnessSubject)
    }

    fn check_audit(
        &self,
        log_path_digest: &[u8; 32],
        anchored_count: u64,
        segment: &[u8; 32],
    ) -> Result<(), MainnetAuthorizationError> {
        require(
            *log_path_digest == self.audit.log_path_digest(),
            P::AuditLogPath,
        )?;
        require(*segment == self.audit.segment(), P::AuditSegment)?;
        require(anchored_count >= self.audit.anchored_count(), P::AuditCount)
    }

    fn check_not_expired(&self, now_ms: u64) -> Result<(), MainnetAuthorizationError> {
        require(
            self.expires_at_ms <= self.approval.expires_at_ms,
            P::LifetimeInvalid,
        )?;
        require(self.issued_at_ms <= now_ms, P::NotYetValid)?;
        require(now_ms < self.expires_at_ms, P::Expired)
    }

    fn endpoint(&self) -> Option<(&str, u64)> {
        self.endpoint
            .as_ref()
            .map(|bound| (bound.authority.as_str(), bound.client_id))
    }

    fn consume_expect(
        &self,
        binding: DomainBinding,
        recomputed: &RecomputedFacts,
    ) -> ConsumeExpect {
        ConsumeExpect::new(
            self.profile.clone(),
            self.chain,
            self.consumer,
            binding,
            self.policy.sequence,
            self.policy.digest,
            self.approval.nonce.clone(),
            self.approval.expires_at_ms,
            self.reservation.as_ref().map(WindowReservation::id),
            self.bindings_digest,
            AuditFacts {
                segment: self.audit.segment(),
                log_path_digest: self.audit.log_path_digest(),
                anchored_count: self.audit.anchored_count(),
            },
            recomputed,
        )
    }

    fn debug(&self, f: &mut std::fmt::Formatter<'_>, name: &str) -> std::fmt::Result {
        f.debug_struct(name)
            .field("domain", &self.domain)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Inner types
// ─────────────────────────────────────────────────────────────────────────────

/// The uninhabited value every inner type holds without mainnet writes.
#[cfg(not(feature = "mainnet-write"))]
enum Never {}

/// A transaction signing: the header and its transaction facts.
#[cfg(feature = "mainnet-write")]
pub(crate) struct TxSignInner {
    pub(crate) entries: Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
    pub(crate) header: Header,
    pub(crate) binding: DomainBinding,
}

/// A Soroban intent signing: the header and its intent facts.
#[cfg(feature = "mainnet-write")]
pub(crate) struct SorobanIntentInner {
    pub(crate) entries: Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
    pub(crate) facts: crate::mainnet::digest::BindingFacts,
    pub(crate) authorization_ttl_ms: u64,
    pub(crate) header: Header,
    pub(crate) binding: DomainBinding,
}

/// An x402 payload release: the header, its submission facts, and the used
/// intent it continues.
#[cfg(feature = "mainnet-write")]
pub(crate) struct SubmitInner {
    pub(crate) header: Header,
    pub(crate) binding: DomainBinding,
    pub(crate) intent_record: AuthorizationId,
}

/// One fee-bump phase: the header and the phase's facts.
#[cfg(feature = "mainnet-write")]
pub(crate) struct FeeBumpInner<R: FeeBumpRole> {
    pub(crate) header: Header,
    pub(crate) binding: DomainBinding,
    pub(crate) role: PhantomData<R>,
}

/// A message signing: the header and the message facts.
#[cfg(feature = "mainnet-write")]
pub(crate) struct MessageSignInner {
    pub(crate) header: Header,
    pub(crate) binding: DomainBinding,
}

/// A transaction signing; uninhabited without mainnet writes.
#[cfg(not(feature = "mainnet-write"))]
pub(crate) struct TxSignInner {
    never: Never,
}

/// A Soroban intent signing; uninhabited without mainnet writes.
#[cfg(not(feature = "mainnet-write"))]
pub(crate) struct SorobanIntentInner {
    never: Never,
}

/// An x402 payload release; uninhabited without mainnet writes.
#[cfg(not(feature = "mainnet-write"))]
pub(crate) struct SubmitInner {
    never: Never,
}

/// One fee-bump phase; uninhabited without mainnet writes.
#[cfg(not(feature = "mainnet-write"))]
pub(crate) struct FeeBumpInner<R: FeeBumpRole> {
    never: Never,
    role: PhantomData<R>,
}

/// A message signing; uninhabited without mainnet writes.
#[cfg(not(feature = "mainnet-write"))]
pub(crate) struct MessageSignInner {
    never: Never,
}

// ─────────────────────────────────────────────────────────────────────────────
// The authorization types
// ─────────────────────────────────────────────────────────────────────────────

/// Authority to sign one classic transaction on mainnet.
pub struct MainnetTxSignAuthorization(pub(crate) TxSignInner);

/// Authority to sign one Soroban authorization for an x402 payment intent on
/// mainnet.
pub struct MainnetSorobanIntentAuthorization(pub(crate) SorobanIntentInner);

/// Authority to release one signed x402 payment payload on mainnet.
pub struct MainnetSubmitAuthorization(pub(crate) SubmitInner);

/// Authority for one phase `R` of a fee bump on mainnet.
pub struct MainnetFeeBumpAuthorization<R: FeeBumpRole>(FeeBumpInner<R>);

/// Authority to sign one message for a mainnet action.
pub struct MainnetMessageSignAuthorization(MessageSignInner);

/// Emits a method in both builds: with its body under mainnet writes, and as
/// the empty match over the uninhabited inner value without them.
macro_rules! gated_method {
    ($(#[$meta:meta])* fn $name:ident(&$self:ident $(, $arg:ident : $ty:ty)* $(,)?) -> $ret:ty $body:block) => {
        $(#[$meta])*
        #[cfg(feature = "mainnet-write")]
        pub fn $name(&$self $(, $arg: $ty)*) -> $ret $body

        $(#[$meta])*
        #[cfg(not(feature = "mainnet-write"))]
        pub fn $name(&$self $(, $arg: $ty)*) -> $ret {
            $(let _ = $arg;)*
            match $self.0.never {}
        }
    };
}

/// Emits the methods every authorization shares.
macro_rules! shared_methods {
    () => {
        gated_method! {
            /// The authorization's identity: its ledger record's.
            #[must_use]
            fn id(&self) -> AuthorizationId { self.0.header.id }
        }

        gated_method! {
            /// When the authorization expires, in Unix milliseconds.
            #[must_use]
            fn expires_at_ms(&self) -> u64 { self.0.header.expires_at_ms }
        }

        gated_method! {
            /// The public key of the signer the authorization binds.
            #[must_use]
            fn signer_public_key(&self) -> [u8; 32] { self.0.header.signer.public_key }
        }

        gated_method! {
            /// The role of the signer the authorization binds.
            #[must_use]
            fn signer_role(&self) -> SignerRole { self.0.header.signer.role }
        }

        gated_method! {
            /// The endpoint authority and client the authorization binds;
            /// `None` for a message.
            #[must_use]
            fn endpoint(&self) -> Option<(&str, u64)> { self.0.header.endpoint() }
        }

        gated_method! {
            /// Requires `profile` to be the bound profile.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_profile(&self, profile: &str) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_profile(profile)
            }
        }

        gated_method! {
            /// Requires `chain` and the bound chain to be mainnet and equal.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_chain(&self, chain: stellar_agent_core::profile::caip2::Caip2) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_chain(chain)
            }
        }

        gated_method! {
            /// Requires `consumer` to be the bound consuming verb.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_consumer(&self, consumer: MainnetConsumer) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_consumer(consumer)
            }
        }

        gated_method! {
            /// Requires `public_key` and `role` to be the bound signer's, each
            /// on its own.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_signer(&self, public_key: &[u8; 32], role: SignerRole) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_signer(public_key, role)
            }
        }

        gated_method! {
            /// Requires the candidate endpoint to equal the bound one:
            /// presence, authority, and client, each on its own. `None` is
            /// compared, never skipped.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_endpoint(&self, candidate: Option<(&str, u64)>) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_endpoint(candidate)
            }
        }

        gated_method! {
            /// Requires `sequence` and `digest` to be the bound policy's, each
            /// on its own.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_policy(&self, sequence: i64, digest: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_policy(sequence, digest)
            }
        }

        gated_method! {
            /// Requires `nonce_digest` to be the bound enablement nonce digest.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_enablement(&self, nonce_digest: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_enablement(nonce_digest)
            }
        }

        gated_method! {
            /// Requires `nonce` to be the bound approval's. Freshness is the
            /// authorization's own expiry.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_approval(&self, nonce: &str) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_approval(nonce)
            }
        }

        gated_method! {
            /// Requires the candidate reservation identity to equal the bound
            /// reservation's, absence included.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_reservation(&self, candidate: Option<AuthorizationId>) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_reservation(candidate)
            }
        }

        gated_method! {
            /// Requires the candidate witness subject to equal the bound one,
            /// absence included.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_witness_subject(&self, candidate: Option<[u8; 32]>) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_witness_subject(candidate)
            }
        }

        gated_method! {
            /// Requires the fresh audit facts a consumer read at use time to
            /// name the bound log path exactly and to hold at least the bound
            /// anchored count. Other tasks append to the shared writer, so a
            /// larger count passes; a rotation changes the count's file and the
            /// authorization is minted again.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
            fn check_audit(&self, log_path_digest: &[u8; 32], anchored_count: u64, segment: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_audit(log_path_digest, anchored_count, segment)
            }
        }

        gated_method! {
            /// Requires `issued_at <= now_ms < expires_at`; the expiry itself
            /// is expired. An expiry beyond the approval's refuses as
            /// inconsistent.
            ///
            /// # Errors
            ///
            /// [`MainnetAuthorizationError::Refused`] naming the condition.
            fn check_not_expired(&self, now_ms: u64) -> Result<(), MainnetAuthorizationError> {
                self.0.header.check_not_expired(now_ms)
            }
        }

        gated_method! {
            /// The expectation the ledger compares at consumption: the bound
            /// facts with the consumer's recomputed digests and fresh audit
            /// facts.
            #[must_use]
            fn consume_expect(&self, recomputed: &RecomputedFacts) -> ConsumeExpect {
                self.0.header.consume_expect(self.0.binding.clone(), recomputed)
            }
        }
    };
}

/// Emits the manual `Debug`: the domain and an identity prefix, nothing else.
macro_rules! debug_impl {
    ($ty:ty, $name:literal $(, $generic:ident)?) => {
        impl$(<$generic: FeeBumpRole>)? std::fmt::Debug for $ty {
            #[cfg(feature = "mainnet-write")]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.header.debug(f, $name)
            }

            #[cfg(not(feature = "mainnet-write"))]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let _ = f;
                match self.0.never {}
            }
        }
    };
}

debug_impl!(MainnetTxSignAuthorization, "MainnetTxSignAuthorization");
debug_impl!(
    MainnetSorobanIntentAuthorization,
    "MainnetSorobanIntentAuthorization"
);
debug_impl!(MainnetSubmitAuthorization, "MainnetSubmitAuthorization");
debug_impl!(
    MainnetFeeBumpAuthorization<R>,
    "MainnetFeeBumpAuthorization",
    R
);
debug_impl!(
    MainnetMessageSignAuthorization,
    "MainnetMessageSignAuthorization"
);

impl MainnetTxSignAuthorization {
    pub(crate) fn entries(
        &self,
    ) -> &[stellar_agent_core::policy::v1::criteria::state_store::WindowEntry] {
        #[cfg(feature = "mainnet-write")]
        {
            &self.0.entries
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            match self.0.never {}
        }
    }

    shared_methods!();

    /// An authorization over directly assembled facts, for this crate's tests
    /// of the paths that consume one.
    #[cfg(all(test, feature = "mainnet-write"))]
    pub(crate) fn for_crate_tests(inner: TxSignInner) -> Self {
        Self(inner)
    }

    gated_method! {
        /// Requires `sha256` to be the bound unsigned envelope digest.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_unsigned_envelope(&self, sha256: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::Transaction { unsigned_envelope_sha256, .. } => {
                    require(sha256 == unsigned_envelope_sha256, P::UnsignedEnvelope)
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }

    gated_method! {
        /// Requires `hash` to be the bound network transaction hash.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_tx_hash(&self, hash: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::Transaction { tx_hash, .. } => require(hash == tx_hash, P::TxHash),
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }

    gated_method! {
        /// Requires `source` and `sequence` to be the bound ones, each on its
        /// own.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_source_sequence(&self, source: &str, sequence: i64) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::Transaction { source: bound_source, sequence: bound_sequence, .. } => {
                    require(source == bound_source, P::SourceAccount)?;
                    require(sequence == *bound_sequence, P::Sequence)
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }
}

impl MainnetSorobanIntentAuthorization {
    #[cfg_attr(
        not(feature = "mainnet-write"),
        expect(dead_code, reason = "uninhabited without mainnet writes")
    )]
    pub(crate) fn entries(
        &self,
    ) -> &[stellar_agent_core::policy::v1::criteria::state_store::WindowEntry] {
        #[cfg(feature = "mainnet-write")]
        {
            &self.0.entries
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            match self.0.never {}
        }
    }

    shared_methods!();

    /// An authorization over directly assembled facts, for this crate's tests
    /// of the paths that consume one.
    #[cfg(all(test, feature = "mainnet-write"))]
    pub(crate) fn for_crate_tests(inner: SorobanIntentInner) -> Self {
        Self(inner)
    }

    gated_method! {
        /// Requires `digest` to be the bound Soroban intent digest.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_intent_digest(&self, digest: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::Soroban { intent_digest } => require(digest == intent_digest, P::IntentDigest),
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }
}

impl MainnetSubmitAuthorization {
    shared_methods!();

    gated_method! {
        /// Requires `id` to be the used intent the release continues.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_intent_record(&self, id: AuthorizationId) -> Result<(), MainnetAuthorizationError> {
            require(id == self.0.intent_record, P::IntentRecordMismatch)
        }
    }

    gated_method! {
        /// Requires `sha256` to be the bound final envelope identity.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_final_envelope(&self, sha256: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::X402Submit { final_envelope_sha256, .. } => {
                    require(sha256 == final_envelope_sha256, P::FinalEnvelope)
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }

    gated_method! {
        /// Requires `digest` to be the bound root invocation digest.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_root_invocation(&self, digest: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::X402Submit { root_invocation_digest, .. } => {
                    require(digest == root_invocation_digest, P::RootInvocation)
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }
}

impl<R: FeeBumpRole> MainnetFeeBumpAuthorization<R> {
    shared_methods!();

    gated_method! {
        /// Requires `hash` to be the bound inner transaction hash.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_inner_tx_hash(&self, hash: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::FeeBumpInner { inner_tx_hash, .. }
                | DomainBinding::FeeBumpOuter { inner_tx_hash, .. }
                | DomainBinding::FeeBumpSubmit { inner_tx_hash, .. } => {
                    require(hash == inner_tx_hash, P::InnerTxHash)
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }

    gated_method! {
        /// Requires `hash` to be the bound outer transaction hash. The inner
        /// phase binds none, and checking it refuses.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch or the
        /// absent outer hash.
        fn check_outer_tx_hash(&self, hash: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::FeeBumpOuter { outer_tx_hash, .. }
                | DomainBinding::FeeBumpSubmit { outer_tx_hash, .. } => {
                    require(hash == outer_tx_hash, P::OuterTxHash)
                }
                DomainBinding::FeeBumpInner { .. } => {
                    Err(MainnetAuthorizationError::Refused(P::OuterTxHashAbsent))
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }

    gated_method! {
        /// Requires `source` and `max_fee` to be the bound fee source and fee,
        /// each on its own.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_fee(&self, source: &str, max_fee: i64) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::FeeBumpInner { fee_source, max_fee: bound, .. }
                | DomainBinding::FeeBumpOuter { fee_source, max_fee: bound, .. }
                | DomainBinding::FeeBumpSubmit { fee_source, max_fee: bound, .. } => {
                    require(source == fee_source, P::FeeSource)?;
                    require(max_fee == *bound, P::MaxFee)
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
    }
}

impl MainnetMessageSignAuthorization {
    shared_methods!();

    gated_method! {
        /// Requires every component of `domain` and the content digest to be
        /// the bound ones, each on its own.
        ///
        /// # Errors
        ///
        /// [`MainnetAuthorizationError::Refused`] naming the mismatch.
        fn check_message(&self, domain: &MessageDomain, content_digest: &[u8; 32]) -> Result<(), MainnetAuthorizationError> {
            match &self.0.binding {
                DomainBinding::Message { domain: bound, content_digest: bound_content, .. } => {
                    require(domain.home_domain == bound.home_domain, P::MessageHomeDomain)?;
                    require(domain.web_auth_domain == bound.web_auth_domain, P::MessageWebAuthDomain)?;
                    require(domain.server_key == bound.server_key, P::MessageServerKey)?;
                    require(content_digest == bound_content, P::MessageContent)
                }
                _ => Err(MainnetAuthorizationError::Refused(P::BindingMismatch)),
            }
        }
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
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn each_fee_bump_role_names_its_domain() {
        assert_eq!(Inner::DOMAIN, AuthorizationDomain::FeeBumpInner);
        assert_eq!(Outer::DOMAIN, AuthorizationDomain::FeeBumpOuter);
        assert_eq!(Submit::DOMAIN, AuthorizationDomain::FeeBumpSubmit);
    }

    #[cfg(feature = "mainnet-write")]
    mod mainnet {
        use std::sync::{Arc, Mutex};

        use serial_test::serial;
        use stellar_agent_core::audit_log::AuditWriter;
        use stellar_agent_core::audit_log::writer::VerifiedTipFacts;
        use stellar_agent_core::policy::pin::{self, Pin, PinScope};
        use stellar_agent_core::policy::state_lock::WindowStoreLock;
        use stellar_agent_core::profile::caip2::Caip2;
        use stellar_agent_core::profile::schema::Profile;
        use stellar_agent_test_support::keyring_mock;
        use tempfile::TempDir;

        use super::super::*;
        use crate::mainnet::MainnetPrecondition as P;
        use crate::mainnet::clock::set_now_ms_for_test;
        use crate::mainnet::digest::entries_digest;
        use crate::policy_state::{ConsumptionBinding, MintRequest, PersistedWindowStore};

        const ID: [u8; 32] = [0xab; 32];
        const SOURCE: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM";
        const FEE_SOURCE: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGN";

        fn refused(result: Result<(), MainnetAuthorizationError>) -> P {
            match result {
                Err(MainnetAuthorizationError::Refused(precondition)) => precondition,
                other => panic!("expected a refusal, got {other:?}"),
            }
        }

        struct Fixture {
            _dir: TempDir,
            writer: crate::submission_record::AuditWriterHandle,
        }

        impl Fixture {
            fn new() -> Self {
                let dir = TempDir::new().unwrap();
                let writer = Arc::new(Mutex::new(
                    AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
                ));
                Self { _dir: dir, writer }
            }

            fn header(&self, domain: AuthorizationDomain, endpoint: bool) -> Header {
                let id = AuthorizationId::from_bytes(ID);
                Header {
                    id,
                    profile: "mainnet-profile".to_owned(),
                    chain: Caip2::Mainnet,
                    domain,
                    consumer: MainnetConsumer::CliPay,
                    endpoint: endpoint.then(|| EndpointBinding {
                        authority: "rpc.example:443".to_owned(),
                        client_id: 3,
                    }),
                    signer: SignerBinding {
                        public_key: [1; 32],
                        role: SignerRole::AgentSigner,
                    },
                    policy: PolicyBinding {
                        sequence: 7,
                        digest: [7; 32],
                    },
                    enablement_nonce_digest: [8; 32],
                    approval: ApprovalBinding {
                        nonce: "nonce-secret-1".to_owned(),
                        expires_at_ms: 2_000,
                    },
                    reservation: Some(WindowReservation::for_crate_tests(id, "mainnet-profile")),
                    witness_subject: Some([4; 32]),
                    audit: AuditReadiness::for_crate_tests(
                        "mainnet-profile",
                        VerifiedTipFacts {
                            segment_start_hash: [0; 32],
                            entry_count: 10,
                            tip_hash: [6; 32],
                            log_path_sha256: [5; 32],
                            anchor_covers_tip: true,
                        },
                        900,
                        Arc::clone(&self.writer),
                    ),
                    issued_at_ms: 1_000,
                    expires_at_ms: 1_500,
                    bindings_digest: crate::mainnet::digest::bindings_digest(
                        &crate::mainnet::digest::BindingFacts {
                            endpoint: None,
                            signer: [2; 32],
                            policy: [3; 32],
                            enablement: [4; 32],
                            witness: None,
                            reservation: None,
                            approval: [7; 32],
                            audit: [8; 32],
                        },
                    ),
                }
            }

            fn tx(&self) -> MainnetTxSignAuthorization {
                MainnetTxSignAuthorization(TxSignInner {
                    entries: vec![],
                    header: self.header(AuthorizationDomain::Transaction, true),
                    binding: DomainBinding::Transaction {
                        unsigned_envelope_sha256: [0x11; 32],
                        tx_hash: [0x22; 32],
                        source: SOURCE.to_owned(),
                        sequence: 42,
                    },
                })
            }

            fn message(&self) -> MainnetMessageSignAuthorization {
                let mut header = self.header(AuthorizationDomain::Message, false);
                header.reservation = None;
                header.witness_subject = None;
                header.signer.role = SignerRole::Sep10Ephemeral;
                MainnetMessageSignAuthorization(MessageSignInner {
                    header,
                    binding: DomainBinding::Message {
                        domain: message_domain(),
                        content_digest: [0x33; 32],
                        ephemeral_public_key: [1; 32],
                    },
                })
            }

            fn fee_bump<R: FeeBumpRole>(
                &self,
                binding: DomainBinding,
            ) -> MainnetFeeBumpAuthorization<R> {
                MainnetFeeBumpAuthorization(FeeBumpInner {
                    header: self.header(R::DOMAIN, true),
                    binding,
                    role: PhantomData,
                })
            }
        }

        fn message_domain() -> MessageDomain {
            MessageDomain {
                home_domain: "example.com".to_owned(),
                web_auth_domain: "auth.example.com".to_owned(),
                server_key: [3; 32],
            }
        }

        #[test]
        fn every_header_check_accepts_the_bound_fact_and_refuses_another() {
            let f = Fixture::new();
            let a = f.tx();
            a.check_profile("mainnet-profile").unwrap();
            assert_eq!(refused(a.check_profile("other")), P::ProfileMismatch);

            a.check_chain(Caip2::Mainnet).unwrap();
            assert_eq!(refused(a.check_chain(Caip2::Testnet)), P::ChainNotMainnet);

            a.check_consumer(MainnetConsumer::CliPay).unwrap();
            assert_eq!(
                refused(a.check_consumer(MainnetConsumer::McpPay)),
                P::ConsumerMismatch
            );

            a.check_signer(&[1; 32], SignerRole::AgentSigner).unwrap();
            assert_eq!(
                refused(a.check_signer(&[2; 32], SignerRole::AgentSigner)),
                P::SignerKeyMismatch
            );
            assert_eq!(
                refused(a.check_signer(&[1; 32], SignerRole::FeePayer)),
                P::SignerRoleMismatch
            );

            a.check_endpoint(Some(("rpc.example:443", 3))).unwrap();
            assert_eq!(refused(a.check_endpoint(None)), P::EndpointPresence);
            assert_eq!(
                refused(a.check_endpoint(Some(("other.example:443", 3)))),
                P::EndpointAuthority
            );
            assert_eq!(
                refused(a.check_endpoint(Some(("rpc.example:443", 4)))),
                P::EndpointClient
            );

            a.check_policy(7, &[7; 32]).unwrap();
            assert_eq!(refused(a.check_policy(8, &[7; 32])), P::PolicySequence);
            assert_eq!(refused(a.check_policy(7, &[8; 32])), P::PolicyDigest);

            a.check_enablement(&[8; 32]).unwrap();
            assert_eq!(refused(a.check_enablement(&[9; 32])), P::EnablementMismatch);

            a.check_approval("nonce-secret-1").unwrap();
            assert_eq!(refused(a.check_approval("nonce-2")), P::ApprovalNonce);

            let id = AuthorizationId::from_bytes(ID);
            a.check_reservation(Some(id)).unwrap();
            assert_eq!(refused(a.check_reservation(None)), P::ReservationMismatch);
            assert_eq!(
                refused(a.check_reservation(Some(AuthorizationId::from_bytes([0; 32])))),
                P::ReservationMismatch
            );

            a.check_witness_subject(Some([4; 32])).unwrap();
            assert_eq!(refused(a.check_witness_subject(None)), P::WitnessSubject);
            assert_eq!(
                refused(a.check_witness_subject(Some([0; 32]))),
                P::WitnessSubject
            );

            a.check_audit(&[5; 32], 10, &[0; 32]).unwrap();
            a.check_audit(&[5; 32], 11, &[0; 32]).unwrap();
            assert_eq!(refused(a.check_audit(&[5; 32], 9, &[0; 32])), P::AuditCount);
            assert_eq!(
                refused(a.check_audit(&[0; 32], 10, &[0; 32])),
                P::AuditLogPath
            );

            a.check_not_expired(1_000).unwrap();
            a.check_not_expired(1_499).unwrap();
            assert_eq!(refused(a.check_not_expired(1_500)), P::Expired);
            assert_eq!(refused(a.check_not_expired(999)), P::NotYetValid);

            assert_eq!(a.id(), id);
            assert_eq!(a.expires_at_ms(), 1_500);
            assert_eq!(a.signer_public_key(), [1; 32]);
            assert_eq!(a.signer_role(), SignerRole::AgentSigner);
            assert_eq!(a.endpoint(), Some(("rpc.example:443", 3)));
        }

        #[test]
        fn absence_is_compared_never_skipped() {
            let f = Fixture::new();
            let m = f.message();
            m.check_endpoint(None).unwrap();
            assert_eq!(
                refused(m.check_endpoint(Some(("rpc.example:443", 3)))),
                P::EndpointPresence
            );
            m.check_reservation(None).unwrap();
            assert_eq!(
                refused(m.check_reservation(Some(AuthorizationId::from_bytes(ID)))),
                P::ReservationMismatch
            );
            m.check_witness_subject(None).unwrap();
            assert_eq!(
                refused(m.check_witness_subject(Some([4; 32]))),
                P::WitnessSubject
            );
            assert_eq!(m.endpoint(), None);
            assert_eq!(m.signer_role(), SignerRole::Sep10Ephemeral);
        }

        #[test]
        fn an_inconsistent_header_refuses_its_own_checks() {
            let f = Fixture::new();
            let mut header = f.header(AuthorizationDomain::Transaction, true);
            header.chain = Caip2::Testnet;
            header.expires_at_ms = 2_500;
            let a = MainnetTxSignAuthorization(TxSignInner {
                entries: vec![],
                header,
                binding: DomainBinding::Transaction {
                    unsigned_envelope_sha256: [0x11; 32],
                    tx_hash: [0x22; 32],
                    source: SOURCE.to_owned(),
                    sequence: 42,
                },
            });
            assert_eq!(refused(a.check_chain(Caip2::Mainnet)), P::ChainNotMainnet);
            assert_eq!(
                refused(a.check_not_expired(1_200)),
                P::LifetimeInvalid,
                "an expiry beyond the approval's is inconsistent"
            );
        }

        #[test]
        fn the_transaction_checks_compare_each_fact() {
            let f = Fixture::new();
            let a = f.tx();
            a.check_unsigned_envelope(&[0x11; 32]).unwrap();
            assert_eq!(
                refused(a.check_unsigned_envelope(&[0x22; 32])),
                P::UnsignedEnvelope
            );
            a.check_tx_hash(&[0x22; 32]).unwrap();
            assert_eq!(refused(a.check_tx_hash(&[0x11; 32])), P::TxHash);
            a.check_source_sequence(SOURCE, 42).unwrap();
            assert_eq!(
                refused(a.check_source_sequence(FEE_SOURCE, 42)),
                P::SourceAccount
            );
            assert_eq!(refused(a.check_source_sequence(SOURCE, 43)), P::Sequence);
        }

        #[test]
        fn the_soroban_and_submit_checks_compare_each_fact() {
            let f = Fixture::new();
            let intent = MainnetSorobanIntentAuthorization(SorobanIntentInner {
                entries: vec![],
                facts: crate::mainnet::digest::BindingFacts {
                    endpoint: None,
                    signer: [0; 32],
                    policy: [0; 32],
                    enablement: [0; 32],
                    witness: None,
                    reservation: None,
                    approval: [0; 32],
                    audit: [0; 32],
                },
                authorization_ttl_ms: 120_000,
                header: f.header(AuthorizationDomain::Soroban, true),
                binding: DomainBinding::Soroban {
                    intent_digest: [0x44; 32],
                },
            });
            intent.check_intent_digest(&[0x44; 32]).unwrap();
            assert_eq!(
                refused(intent.check_intent_digest(&[0x45; 32])),
                P::IntentDigest
            );

            let parent = AuthorizationId::from_bytes([0x55; 32]);
            let mut header = f.header(AuthorizationDomain::X402Submit, true);
            header.reservation = None;
            let submit = MainnetSubmitAuthorization(SubmitInner {
                header,
                binding: DomainBinding::X402Submit {
                    final_envelope_sha256: [0x66; 32],
                    root_invocation_digest: [0x77; 32],
                },
                intent_record: parent,
            });
            submit.check_intent_record(parent).unwrap();
            assert_eq!(
                refused(submit.check_intent_record(AuthorizationId::from_bytes(ID))),
                P::IntentRecordMismatch
            );
            submit.check_final_envelope(&[0x66; 32]).unwrap();
            assert_eq!(
                refused(submit.check_final_envelope(&[0x67; 32])),
                P::FinalEnvelope
            );
            submit.check_root_invocation(&[0x77; 32]).unwrap();
            assert_eq!(
                refused(submit.check_root_invocation(&[0x78; 32])),
                P::RootInvocation
            );
        }

        #[test]
        fn the_fee_bump_checks_follow_the_phase() {
            let f = Fixture::new();
            let inner: MainnetFeeBumpAuthorization<Inner> =
                f.fee_bump(DomainBinding::FeeBumpInner {
                    inner_tx_hash: [0x10; 32],
                    inner_source: SOURCE.to_owned(),
                    inner_sequence: 300,
                    fee_source: FEE_SOURCE.to_owned(),
                    max_fee: 1_000,
                });
            inner.check_inner_tx_hash(&[0x10; 32]).unwrap();
            assert_eq!(
                refused(inner.check_inner_tx_hash(&[0x11; 32])),
                P::InnerTxHash
            );
            assert_eq!(
                refused(inner.check_outer_tx_hash(&[0x30; 32])),
                P::OuterTxHashAbsent
            );
            inner.check_fee(FEE_SOURCE, 1_000).unwrap();
            assert_eq!(refused(inner.check_fee(SOURCE, 1_000)), P::FeeSource);
            assert_eq!(refused(inner.check_fee(FEE_SOURCE, 1_001)), P::MaxFee);

            let outer: MainnetFeeBumpAuthorization<Outer> =
                f.fee_bump(DomainBinding::FeeBumpOuter {
                    inner_tx_hash: [0x10; 32],
                    outer_tx_hash: [0x30; 32],
                    inner_source: SOURCE.to_owned(),
                    inner_sequence: 300,
                    fee_source: FEE_SOURCE.to_owned(),
                    max_fee: 1_000,
                });
            outer.check_outer_tx_hash(&[0x30; 32]).unwrap();
            assert_eq!(
                refused(outer.check_outer_tx_hash(&[0x31; 32])),
                P::OuterTxHash
            );
            outer.check_inner_tx_hash(&[0x10; 32]).unwrap();
            outer.check_fee(FEE_SOURCE, 1_000).unwrap();

            let submit: MainnetFeeBumpAuthorization<Submit> =
                f.fee_bump(DomainBinding::FeeBumpSubmit {
                    inner_tx_hash: [0x10; 32],
                    outer_tx_hash: [0x30; 32],
                    inner_source: SOURCE.to_owned(),
                    inner_sequence: 300,
                    fee_source: FEE_SOURCE.to_owned(),
                    max_fee: 1_000,
                    final_envelope_sha256: [0x50; 32],
                });
            submit.check_outer_tx_hash(&[0x30; 32]).unwrap();
            assert_eq!(
                refused(submit.check_outer_tx_hash(&[0x31; 32])),
                P::OuterTxHash
            );
            assert_eq!(
                refused(submit.check_inner_tx_hash(&[0x11; 32])),
                P::InnerTxHash
            );
            assert_eq!(refused(submit.check_fee(FEE_SOURCE, 999)), P::MaxFee);
        }

        #[test]
        fn the_message_check_compares_every_component() {
            let f = Fixture::new();
            let m = f.message();
            m.check_message(&message_domain(), &[0x33; 32]).unwrap();
            let cases = [
                (
                    MessageDomain {
                        home_domain: "other.com".to_owned(),
                        ..message_domain()
                    },
                    [0x33; 32],
                    P::MessageHomeDomain,
                ),
                (
                    MessageDomain {
                        web_auth_domain: "other.example.com".to_owned(),
                        ..message_domain()
                    },
                    [0x33; 32],
                    P::MessageWebAuthDomain,
                ),
                (
                    MessageDomain {
                        server_key: [0; 32],
                        ..message_domain()
                    },
                    [0x33; 32],
                    P::MessageServerKey,
                ),
                (message_domain(), [0x34; 32], P::MessageContent),
            ];
            for (domain, content, precondition) in cases {
                assert_eq!(refused(m.check_message(&domain, &content)), precondition);
            }
        }

        #[test]
        fn debug_shows_the_domain_and_an_identity_prefix_only() {
            let f = Fixture::new();
            let rendered = format!("{:?}", f.tx());
            assert_eq!(
                rendered,
                "MainnetTxSignAuthorization { domain: Transaction, id: AuthorizationId(abababab…), .. }"
            );
            for secret in ["nonce-secret-1", "rpc.example", "mainnet-profile", SOURCE] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
            let fee: MainnetFeeBumpAuthorization<Inner> = f.fee_bump(DomainBinding::FeeBumpInner {
                inner_tx_hash: [0x10; 32],
                inner_source: SOURCE.to_owned(),
                inner_sequence: 300,
                fee_source: FEE_SOURCE.to_owned(),
                max_fee: 1_000,
            });
            assert!(
                format!("{fee:?}")
                    .starts_with("MainnetFeeBumpAuthorization { domain: FeeBumpInner")
            );
        }

        async fn proof_composition(
            domain: AuthorizationDomain,
            holds_entries: bool,
            rotation: Option<u64>,
        ) {
            use crate::mainnet::digest::{BindingFacts, approval_subject_classic, bindings_digest};
            use crate::policy_state::{FeeBumpFacts, SubmissionBinding};
            use crate::signing::{Signer, SoftwareSigningKey};
            use base64::Engine as _;
            use stellar_agent_core::approval::store::{PendingApproval, PendingApprovalStore};
            use stellar_agent_core::approval::witness::{
                ApprovalExpectation, ApprovedKind, verify_approval,
            };
            use stellar_agent_core::approval::{AttestationBinding, compute_attestation};
            use stellar_agent_core::mainnet::fact::{
                FACT_LABEL_ENABLEMENT, FACT_LABEL_POLICY, FactDigest,
            };
            use stellar_agent_core::policy::v1::criteria::state_store::{
                StateKey, WindowEntry, WindowLimit,
            };
            use stellar_agent_core::profile::{
                loader::save_to_dir, schema::signer_identity_entry_ref,
            };
            use stellar_agent_test_support::signed_envelope::SignedTestEnvelope;
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let name = format!(
                "composition-{}-{}",
                domain.tag(),
                rotation.map_or("plain".to_owned(), |count| count.to_string())
            );
            let signer = SoftwareSigningKey::new_from_bytes([1; 32]);
            let public = signer.public_key().await.unwrap();
            let source = public.to_string().to_string();
            let mut profile = Profile::builder_mainnet_named(
                &name,
                "https://rpc.example",
                "composition-signer",
                &source,
                "composition-nonce",
                "nonce",
            )
            .build();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            save_to_dir(&name, &profile, dir.path()).unwrap();
            crate::keyring::write_keyring_string(
                &signer_identity_entry_ref(&profile.mcp_signer_default),
                &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::agent(
                    public.0,
                )
                .render(),
            )
            .unwrap();
            let enrolled = crate::keyring::enrolled_signer(
                &name,
                dir.path(),
                &profile,
                crate::keyring::EnrolledRole::Agent,
                &public.0,
            )
            .unwrap();
            let client = crate::StellarRpcClient::new("https://rpc.example").unwrap();
            let endpoint = crate::EndpointIdentity::checked(
                Some(Caip2::Mainnet),
                29,
                "rpc.example".to_owned(),
                client.id(),
            );
            // The verified policy and the enablement record enter the
            // authorization as their facts and fact digests, computed here in
            // the layouts `VerifiedPolicy::fact_digest` and
            // `EnablementRecord::fact_digest` document.
            let (policy_sequence, policy_digest, policy_owner) = (7_i64, [0x71; 32], [1; 32]);
            let nonce_digest = [3; 32];
            let mut policy_fact = FactDigest::new(FACT_LABEL_POLICY);
            policy_fact
                .i64(policy_sequence)
                .fixed(&policy_digest)
                .fixed(&policy_owner)
                .present(true)
                .bytes(name.as_bytes())
                .bytes(b"rpc.example")
                .fixed(&nonce_digest)
                .u32(1000)
                .opt_u32(Some(60))
                .thresholds(None);
            let mut enablement_fact = FactDigest::new(FACT_LABEL_ENABLEMENT);
            enablement_fact
                .bytes(name.as_bytes())
                .bytes(b"rpc.example")
                .fixed(&nonce_digest)
                .i64(policy_sequence)
                .u32(1000)
                .opt_u32(Some(60))
                .thresholds(None);
            let envelope = SignedTestEnvelope::builder([1; 32])
                .network_passphrase(&profile.network_passphrase)
                .sequence(42)
                .build();
            let envelope_text = envelope.envelope_xdr().to_owned();
            let tx_hash = stellar_agent_core::hex::decode_hex32(envelope.tx_hash_hex()).unwrap();
            let witness = crate::cross_check::CrossCheckWitness::for_crate_tests(
                "https://oracle.example",
                42,
                tx_hash,
                vec![],
            )
            .bound_for_crate_tests(tx_hash);
            let approval_record = PendingApproval::new_payment_pending(
                envelope_text.clone(),
                envelope_text.as_bytes(),
                source.clone(),
                1,
                "XLM".to_owned(),
                None,
                100,
                42,
                "1000".to_owned(),
                600_000,
            )
            .unwrap();
            let now = approval_record.created_at_unix_ms;
            let _clock = set_now_ms_for_test(now);
            let nonce = approval_record.approval_nonce.clone();
            let key = [0x51; 32];
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
            crate::keyring::write_keyring_string(&profile.attestation_key_id, &encoded).unwrap();
            let subject = approval_subject_classic(&envelope_text);
            let blob = compute_attestation(
                &key,
                &AttestationBinding::new(&name, "stellar:mainnet"),
                &nonce,
                &subject,
                "1000",
                &approval_record.attested_lifetime(),
            );
            let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
            pending.insert(approval_record, now).unwrap();
            pending.record_attestation(&nonce, blob).unwrap();
            let approval = verify_approval(
                &pending,
                &profile,
                &name,
                &nonce,
                &blob,
                &ApprovalExpectation {
                    kind: ApprovedKind::Payment,
                    subject,
                },
                now,
            )
            .unwrap();
            crate::keyring::rotate_keyring_secret_32(
                &profile.audit_log_hash_chain_key_id.service,
                &profile.audit_log_hash_chain_key_id.account,
            )
            .unwrap();
            let row = || {
                stellar_agent_core::audit_log::AuditEntry::new_approval_attested(
                    "PaymentSimulated",
                    "test",
                    None,
                    "ABCDEFGHIJKLMNOPQRSTUV",
                    "cli",
                    "row",
                )
            };
            let audit = crate::mainnet::audit_readiness::audit_readiness(&profile, &name).unwrap();
            if let Some(count) = rotation {
                for _ in 0..count {
                    audit.writer().lock().unwrap().write_entry(row()).unwrap();
                }
            }
            let audit = crate::mainnet::audit_readiness::audit_readiness(&profile, &name).unwrap();
            let mut facts = BindingFacts {
                endpoint: Some(endpoint.fact_digest()),
                signer: enrolled.fact_digest(),
                policy: policy_fact.finish(),
                enablement: enablement_fact.finish(),
                witness: Some(witness.fact_digest()),
                reservation: None,
                approval: approval.fact_digest(),
                audit: audit.fact_digest(),
            };
            let binding = match domain {
                AuthorizationDomain::Transaction => DomainBinding::Transaction {
                    unsigned_envelope_sha256: subject,
                    tx_hash,
                    source: source.clone(),
                    sequence: 42,
                },
                AuthorizationDomain::FeeBumpInner => DomainBinding::FeeBumpInner {
                    inner_tx_hash: tx_hash,
                    inner_source: source.clone(),
                    inner_sequence: 42,
                    fee_source: source.clone(),
                    max_fee: 1000,
                },
                AuthorizationDomain::FeeBumpOuter => DomainBinding::FeeBumpOuter {
                    inner_tx_hash: tx_hash,
                    outer_tx_hash: [8; 32],
                    inner_source: source.clone(),
                    inner_sequence: 42,
                    fee_source: source.clone(),
                    max_fee: 1000,
                },
                AuthorizationDomain::FeeBumpSubmit => DomainBinding::FeeBumpSubmit {
                    inner_tx_hash: tx_hash,
                    outer_tx_hash: [8; 32],
                    inner_source: source.clone(),
                    inner_sequence: 42,
                    fee_source: source.clone(),
                    max_fee: 1000,
                    final_envelope_sha256: subject,
                },
                AuthorizationDomain::Soroban => DomainBinding::Soroban {
                    intent_digest: tx_hash,
                },
                AuthorizationDomain::X402Submit => DomainBinding::X402Submit {
                    final_envelope_sha256: subject,
                    root_invocation_digest: tx_hash,
                },
                AuthorizationDomain::Message => DomainBinding::Message {
                    domain: MessageDomain {
                        home_domain: "example.org".to_owned(),
                        web_auth_domain: "auth.example.org".to_owned(),
                        server_key: public.0,
                    },
                    content_digest: subject,
                    ephemeral_public_key: public.0,
                },
            };
            let holds = if holds_entries {
                vec![WindowEntry::new(
                    StateKey::new(&name, 1, "native", 86400),
                    now,
                    1,
                    WindowLimit::Amount {
                        asset: "native".to_owned(),
                        window: "1d".to_owned(),
                        max_stroops: 100,
                    },
                )]
            } else {
                vec![]
            };
            let store = PersistedWindowStore::at_path(dir.path().join("state.window"));
            {
                let lock = WindowStoreLock::acquire_for(
                    &dir.path().join("state.window"),
                    &profile.policy_window_state_key_id,
                )
                .unwrap();
                pin::write(
                    &lock,
                    &PinScope::for_profile(&dir.path().join("state.window"), &profile),
                    &Pin::new(policy_sequence, policy_digest, policy_owner).unwrap(),
                )
                .unwrap();
            }
            let request = MintRequest {
                chain: Caip2::Mainnet,
                binding: binding.clone(),
                consumer: MainnetConsumer::X402Create,
                policy_sequence,
                policy_digest,
                approval_nonce: approval.nonce().to_owned(),
                approval_expires_at_ms: approval.expires_at_ms(),
                authorization_ttl_ms: 60_000,
                bindings: facts,
                holds: holds.clone(),
                parent: None,
            };
            let minted = store.mint_authorization(&profile, &request).unwrap();
            facts.reservation = minted
                .reservation
                .as_ref()
                .map(WindowReservation::fact_digest);
            assert_eq!(minted.bindings_digest, bindings_digest(&facts));
            let header = Header {
                id: minted.id,
                profile: name,
                chain: Caip2::Mainnet,
                domain,
                consumer: request.consumer,
                endpoint: Some(EndpointBinding {
                    authority: "rpc.example".to_owned(),
                    client_id: client.id(),
                }),
                signer: SignerBinding {
                    public_key: enrolled.public_key(),
                    role: SignerRole::AgentSigner,
                },
                policy: PolicyBinding {
                    sequence: policy_sequence,
                    digest: policy_digest,
                },
                enablement_nonce_digest: nonce_digest,
                approval: ApprovalBinding {
                    nonce,
                    expires_at_ms: approval.expires_at_ms(),
                },
                reservation: minted.reservation,
                witness_subject: witness.subject(),
                audit,
                issued_at_ms: minted.issued_at_ms,
                expires_at_ms: minted.expires_at_ms,
                bindings_digest: minted.bindings_digest,
            };
            let recomputed = RecomputedFacts {
                content_digest: binding.content_digest(),
                entries_digest: entries_digest(&holds),
                audit: header.audit.fresh_facts().unwrap(),
            };
            let consumption = match binding.clone() {
                DomainBinding::Transaction { tx_hash, .. } => {
                    ConsumptionBinding::Transaction(SubmissionBinding {
                        fee_bump: None,
                        envelope_hash: subject,
                        tx_hash,
                        source,
                        sequence: 42,
                        max_time: 0,
                        pending_since_ms: now,
                        submission_ledger: 42,
                    })
                }
                DomainBinding::FeeBumpInner { .. } | DomainBinding::FeeBumpOuter { .. } => {
                    ConsumptionBinding::Transaction(SubmissionBinding {
                        fee_bump: Some(FeeBumpFacts {
                            inner_tx_hash: tx_hash,
                            fee_source: source.clone(),
                            max_fee: 1000,
                        }),
                        envelope_hash: subject,
                        tx_hash: [8; 32],
                        source,
                        sequence: 42,
                        max_time: 0,
                        pending_since_ms: now,
                        submission_ledger: 42,
                    })
                }
                DomainBinding::Soroban { intent_digest } => {
                    ConsumptionBinding::RetainedIntent { intent_digest }
                }
                DomainBinding::Message {
                    domain,
                    content_digest,
                    ephemeral_public_key,
                } => ConsumptionBinding::Message {
                    domain,
                    content_digest,
                    ephemeral_public_key,
                },
                DomainBinding::FeeBumpSubmit { .. } => ConsumptionBinding::PayloadRelease {
                    intent_record: None,
                    final_envelope_sha256: subject,
                    root_invocation_digest: None,
                },
                DomainBinding::X402Submit { .. } => unreachable!(),
            };
            if rotation.is_some() {
                header
                    .audit
                    .writer()
                    .lock()
                    .unwrap()
                    .write_entry(row())
                    .unwrap();
                let threshold =
                    stellar_agent_core::audit_log::rotation::test_seam::set_rotation_threshold(
                        &profile.audit_log_path,
                        1,
                    );
                header
                    .audit
                    .writer()
                    .lock()
                    .unwrap()
                    .write_entry(row())
                    .unwrap();
                drop(threshold);
                let fresh = header.audit.fresh_facts().unwrap();
                assert!(fresh.anchored_count >= header.audit.anchored_count());
                assert_eq!(
                    refused(header.check_audit(
                        &fresh.log_path_digest,
                        fresh.anchored_count,
                        &fresh.segment
                    )),
                    P::AuditSegment
                );
                let before = std::fs::read(dir.path().join("state.window")).unwrap();
                let changed = RecomputedFacts {
                    audit: fresh,
                    ..recomputed
                };
                assert!(matches!(
                    store.consume_authorization(
                        &profile,
                        minted.id,
                        &header.consume_expect(binding, &changed),
                        &consumption
                    ),
                    Err(
                        crate::policy_state::WindowStoreError::AuthorizationRefused {
                            precondition: P::AuditSegment
                        }
                    )
                ));
                assert_eq!(
                    std::fs::read(dir.path().join("state.window")).unwrap(),
                    before
                );
                return;
            }
            store
                .consume_authorization(
                    &profile,
                    minted.id,
                    &header.consume_expect(binding, &recomputed),
                    &consumption,
                )
                .unwrap();
        }

        #[tokio::test]
        #[serial]
        async fn consume_expect_matches_the_minted_record() {
            proof_composition(AuthorizationDomain::Transaction, true, None).await;
        }

        #[tokio::test]
        #[serial]
        async fn real_proofs_compose_with_inner_holds() {
            proof_composition(AuthorizationDomain::FeeBumpInner, true, None).await;
        }

        #[tokio::test]
        #[serial]
        async fn real_proofs_compose_with_outer_holds() {
            proof_composition(AuthorizationDomain::FeeBumpOuter, true, None).await;
        }

        #[tokio::test]
        #[serial]
        async fn real_proofs_compose_with_intent_holds() {
            proof_composition(AuthorizationDomain::Soroban, true, None).await;
        }

        #[tokio::test]
        #[serial]
        async fn real_proofs_compose_without_holds() {
            proof_composition(AuthorizationDomain::Message, false, None).await;
        }

        #[test]
        fn soroban_consumer_checks_equality_and_family() {
            let f = Fixture::new();
            for consumer in [
                MainnetConsumer::X402Create,
                MainnetConsumer::X402Authenticated,
            ] {
                let mut header = f.header(AuthorizationDomain::Soroban, true);
                header.consumer = consumer;
                header.check_consumer(consumer).unwrap();
                let other = match consumer {
                    MainnetConsumer::X402Create => MainnetConsumer::X402Authenticated,
                    _ => MainnetConsumer::X402Create,
                };
                assert_eq!(refused(header.check_consumer(other)), P::ConsumerMismatch);
                assert_eq!(
                    refused(header.check_consumer(MainnetConsumer::CliPay)),
                    P::ConsumerMismatch
                );
                header.consumer = MainnetConsumer::CliPay;
                assert_eq!(
                    refused(header.check_consumer(MainnetConsumer::CliPay)),
                    P::ConsumerMismatch
                );
            }
        }

        #[test]
        fn audit_checks_the_segment_at_zero_and_after_count_recovery() {
            let f = Fixture::new();
            let header = f.header(AuthorizationDomain::Transaction, true);
            assert_eq!(
                refused(header.check_audit(&[5; 32], 11, &[1; 32])),
                P::AuditSegment
            );
            header.check_audit(&[5; 32], 11, &[0; 32]).unwrap();
        }

        #[tokio::test]
        #[serial]
        async fn rotation_refuses_authority_recorded_at_zero_or_one() {
            for count in [0, 1] {
                proof_composition(AuthorizationDomain::Transaction, true, Some(count)).await;
            }
        }
    }
}

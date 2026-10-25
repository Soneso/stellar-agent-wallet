//! The proof that a submission consumed its mainnet authorization.
//!
//! A mainnet send depends on this proof. Only this crate constructs it, in the
//! wallet recorder after the authorization ledger committed the consumption,
//! so a recorder implemented elsewhere cannot report a consumption that did
//! not happen: the trait's default refuses instead.

use super::AuthorizationId;

/// What a recorder returns once it consumed a mainnet authorization for a
/// submission.
///
/// Its fields are private, it has no `Clone`, `Default`, or serde
/// implementation, and its constructor is crate-private: a proof is used once,
/// by move, and the submit compares its envelope hash, content digest, and
/// authorization identity with its own before the send.
#[derive(Debug)]
pub struct AuthorizationConsumed {
    envelope_hash: [u8; 32],
    content_digest: [u8; 32],
    authorization_id: AuthorizationId,
}

impl AuthorizationConsumed {
    /// The proof of the consumption of `authorization_id` for the envelope
    /// with `envelope_hash`, whose transaction content digest is
    /// `content_digest`.
    pub(crate) fn new(
        envelope_hash: [u8; 32],
        content_digest: [u8; 32],
        authorization_id: AuthorizationId,
    ) -> Self {
        Self {
            envelope_hash,
            content_digest,
            authorization_id,
        }
    }

    /// The envelope hash of the submission the consumption recorded.
    pub(crate) fn envelope_hash(&self) -> &[u8; 32] {
        &self.envelope_hash
    }

    /// The domain-tagged content digest of the consumed transaction.
    pub(crate) fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// The consumed authorization.
    pub(crate) fn authorization_id(&self) -> AuthorizationId {
        self.authorization_id
    }
}

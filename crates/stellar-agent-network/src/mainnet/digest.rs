//! The digests mainnet authorization shares, by the names its consumers use.
//!
//! - [`soroban_intent_digest`] and [`root_invocation_digest`]: the Soroban
//!   intent and root digests, defined in core beside the approval subjects.
//! - [`approval_subject_classic`], [`approval_subject_x402`], and
//!   [`approval_subject_x402_authenticated`]: the approval subjects.
//! - [`envelope_hash_hex`]: the submission envelope identity, SHA-256 of the
//!   envelope's base64 text bytes, never of the decoded XDR.
//! - [`content_digest`]: the domain-tagged content digest of an authorization
//!   record, which keys the duplicate-open rule.
//! - [`entries_digest`]: the digest of the window entries an authorization
//!   holds, in order.
//! - [`bindings_digest`]: the aggregate digest over the proofs' fact digests.
//! - The fact-digest labels of the eight proofs, from
//!   [`stellar_agent_core::mainnet::fact`].
//!
//! # Content digest
//!
//! ```text
//! SHA256("stellar-agent-authz-content:v1" || domain tag || u32be(len(subject)) || subject)
//! ```
//!
//! with the domain tags of [`AuthorizationDomain`]; the subject each domain
//! names is [`AuthorizationDomain::subject`].
//!
//! # Entries digest
//!
//! ```text
//! SHA256("stellar-agent-authz-holds:v1" || for each entry, in order:
//!     u32be(ordinal) || lp(scope) || lp(bucket) || lp(window) || i128be(amount))
//! ```
//!
//! where `ordinal` is the entry's index, `lp(x)` is `u32be(len(x)) || x`,
//! `scope` is the one-byte scope specificity, `bucket` the bucket name's
//! UTF-8 bytes, and `window` the window length in seconds as eight big-endian
//! bytes. The timestamp and the limit do not enter the digest.
//!
//! # Bindings digest
//!
//! ```text
//! SHA256("stellar-agent-authz-bindings:v1"
//!     || opt(endpoint) || signer || policy || enablement
//!     || opt(witness) || opt(reservation) || approval || audit)
//! ```
//!
//! over the proofs' 32-byte fact digests in that fixed order, where
//! `opt(x)` is `0x00` for an absent proof or `0x01 || x`.

use sha2::{Digest as _, Sha256};
use stellar_agent_core::policy::v1::criteria::state_store::WindowEntry;

pub use crate::submit::envelope_hash_hex;
pub use stellar_agent_core::approval::subject::{
    SOROBAN_INTENT_LABEL, SOROBAN_ROOT_LABEL, X402_AUTHENTICATED_INTENT_LABEL, X402_INTENT_LABEL,
    approval_subject_classic, approval_subject_x402, approval_subject_x402_authenticated,
    root_invocation_digest, soroban_intent_digest,
};
pub use stellar_agent_core::mainnet::fact::{
    FACT_LABEL_APPROVAL, FACT_LABEL_AUDIT, FACT_LABEL_ENABLEMENT, FACT_LABEL_ENDPOINT,
    FACT_LABEL_POLICY, FACT_LABEL_RESERVATION, FACT_LABEL_SIGNER, FACT_LABEL_WITNESS, FactDigest,
};

use super::types::AuthorizationDomain;

/// Label of the content digest.
pub const CONTENT_LABEL: &[u8] = b"stellar-agent-authz-content:v1";

/// Label of the entries digest.
pub const ENTRIES_LABEL: &[u8] = b"stellar-agent-authz-holds:v1";

/// Label of the bindings digest.
pub const BINDINGS_LABEL: &[u8] = b"stellar-agent-authz-bindings:v1";

use stellar_agent_core::approval::subject::length_prefixed;

/// The content digest of an authorization of `domain` over `subject`.
#[must_use]
pub fn content_digest(domain: AuthorizationDomain, subject: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_LABEL);
    hasher.update([domain.tag()]);
    length_prefixed(&mut hasher, subject);
    hasher.finalize().into()
}

/// The digest of the window entries an authorization holds, in order.
#[must_use]
pub fn entries_digest(entries: &[WindowEntry]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ENTRIES_LABEL);
    for (ordinal, entry) in entries.iter().enumerate() {
        let key = entry.key();
        hasher.update(u32::try_from(ordinal).unwrap_or(u32::MAX).to_be_bytes());
        length_prefixed(&mut hasher, &[key.scope_specificity()]);
        length_prefixed(&mut hasher, key.bucket().as_bytes());
        length_prefixed(&mut hasher, &key.window_secs().to_be_bytes());
        hasher.update(entry.amount().to_be_bytes());
    }
    hasher.finalize().into()
}

/// The fact digests [`bindings_digest`] aggregates, one per proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingFacts {
    /// The endpoint identity's fact digest; absent for a message.
    pub endpoint: Option<[u8; 32]>,
    /// The signer's fact digest.
    pub signer: [u8; 32],
    /// The verified policy's fact digest.
    pub policy: [u8; 32],
    /// The enablement record's fact digest.
    pub enablement: [u8; 32],
    /// The cross-check witness's fact digest, when one was required.
    pub witness: Option<[u8; 32]>,
    /// The window reservation's fact digest, when the record holds entries.
    pub reservation: Option<[u8; 32]>,
    /// The approval witness's fact digest.
    pub approval: [u8; 32],
    /// The audit readiness's fact digest.
    pub audit: [u8; 32],
}

/// The aggregate digest over the proofs' fact digests, in the fixed order
/// endpoint, signer, policy, enablement, witness, reservation, approval,
/// audit.
#[must_use]
pub fn bindings_digest(facts: &BindingFacts) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BINDINGS_LABEL);
    let optional = |hasher: &mut Sha256, value: Option<&[u8; 32]>| match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value);
        }
        None => hasher.update([0]),
    };
    optional(&mut hasher, facts.endpoint.as_ref());
    hasher.update(facts.signer);
    hasher.update(facts.policy);
    hasher.update(facts.enablement);
    optional(&mut hasher, facts.witness.as_ref());
    optional(&mut hasher, facts.reservation.as_ref());
    hasher.update(facts.approval);
    hasher.update(facts.audit);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowLimit};

    fn hex(bytes: &[u8; 32]) -> String {
        stellar_agent_core::hex::encode(bytes)
    }

    /// The content digest of every domain over one subject, against vectors
    /// computed independently from the documented layout.
    #[test]
    fn content_digests_follow_the_layout() {
        let subject = [0x44; 32];
        let expected = [
            "f56bd6d902bcb590d2d15a6872f50cc59a584479ee25e67d6440e925338a2040",
            "95262e13cabf8b1eaa4e4f3a0d1b056670174c516a0fe077ff53c8ced1ebd091",
            "23708834f7cce24b2e0199ceb991d3903f45455e50a5c7868c6d4dc9f0f40e0d",
            "ad428f83ad5aa9be62971ba1fc0d98828548c1173e366d741eca8a5434a7ab88",
            "ea6275f70a7ef0834111911513e767802ed9e25d4de42554ca12253ae3fc349c",
            "900fdedc99bcd4071ea01a4b96085c029e211e07d5f3cd586b0589d2cfad5041",
            "35dd8e5dbd48d1bc6a95969462eabccdcc70114bde881facc332cec4d8eff120",
        ];
        for (domain, vector) in AuthorizationDomain::ALL.iter().zip(expected) {
            assert_eq!(
                hex(&content_digest(*domain, &subject)),
                vector,
                "{domain:?}"
            );
        }
    }

    /// The entries digest covers ordinal, scope, bucket, window, and amount in
    /// order, and ignores the timestamp and the limit.
    #[test]
    fn entries_digest_follows_the_layout() {
        let entries = [
            WindowEntry::new(
                StateKey::new("p", 2, "native", 86_400),
                111,
                -5,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 10,
                },
            ),
            WindowEntry::new(
                StateKey::new("p", 1, "rate_limit", 60),
                222,
                1,
                WindowLimit::Count {
                    window: "1m".to_owned(),
                    max_calls: 3,
                },
            ),
        ];
        assert_eq!(
            hex(&entries_digest(&entries)),
            "80de786a81393823d146c61f6ae49c2427522de186bd0af5e3430e5b41037069"
        );
        let mut retimed = entries.clone();
        retimed[0] = WindowEntry::new(
            StateKey::new("other-profile", 2, "native", 86_400),
            999,
            -5,
            WindowLimit::Count {
                window: "1d".to_owned(),
                max_calls: 1,
            },
        );
        assert_eq!(entries_digest(&retimed), entries_digest(&entries));
        let swapped = [entries[1].clone(), entries[0].clone()];
        assert_ne!(entries_digest(&swapped), entries_digest(&entries));
        assert_eq!(
            hex(&entries_digest(&[])),
            "7f5c3895b5a03f8439bd58a8878102768b3fc053bb9b0c9aa110c84e1b1823e2"
        );
    }

    /// The bindings digest follows the fixed order and marks every optional
    /// proof.
    #[test]
    fn bindings_digest_follows_the_layout() {
        let facts = BindingFacts {
            endpoint: Some([1; 32]),
            signer: [2; 32],
            policy: [3; 32],
            enablement: [4; 32],
            witness: None,
            reservation: Some([6; 32]),
            approval: [7; 32],
            audit: [8; 32],
        };
        assert_eq!(
            hex(&bindings_digest(&facts)),
            "9d918e1e1855fd58664f4e9944871ad629dbfb2c1f038ff9266e51498ff2bcc2"
        );
        let without_endpoint = BindingFacts {
            endpoint: None,
            ..facts
        };
        assert_ne!(bindings_digest(&without_endpoint), bindings_digest(&facts));
    }

    #[test]
    fn bindings_digest_covers_a_present_witness() {
        let facts = BindingFacts {
            endpoint: Some([1; 32]),
            signer: [2; 32],
            policy: [3; 32],
            enablement: [4; 32],
            witness: Some([5; 32]),
            reservation: Some([6; 32]),
            approval: [7; 32],
            audit: [8; 32],
        };
        assert_eq!(
            hex(&bindings_digest(&facts)),
            "20d70736524ada8f1beb54f911c7f3c97bafdf812843deb1ffbe65fdc9fd88b9"
        );
    }
}

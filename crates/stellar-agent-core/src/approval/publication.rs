//! The authenticated sink handoff of a strict mainnet consent.
//!
//! The inbox file is editable, so a stored attestation cannot vouch for an
//! edited sink. The strict mainnet attester therefore seals the successful
//! sink, and for a queued row its full reference, under the attestation key
//! with its own domain. It stores the seal in the same inbox replacement as
//! the blob and the receipt. Recovery reads the sink only through
//! [`verify_consent_publication`].

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::attestation::AttestationBinding;
use super::store::PendingApproval;
use super::subject::SubjectKind;
use crate::audit_log::OutboxRowRef;
use crate::error::{ApprovalFailure, WalletError};

/// The MAC domain of a consent publication handoff.
pub const CONSENT_PUBLICATION_DOMAIN: &[u8] = b"stellar-agent-consent-publication:v1";

/// The sink that accepted a strict consent row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PublicationSink {
    /// The direct writer anchored the row.
    DirectAnchored,
    /// The keyed outbox queued the row under the handoff's reference.
    Queued,
}

/// The stored handoff of one inbox entry, authenticated by its tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPublicationV1 {
    #[serde(deserialize_with = "publication_version")]
    v: u8,
    sink: PublicationSink,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outbox_row: Option<OutboxRowRef>,
    #[serde(with = "hex32")]
    subject: [u8; 32],
    #[serde(with = "hex32")]
    tag: [u8; 32],
}

fn publication_version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let version = u8::deserialize(d)?;
    if version != 1 {
        return Err(serde::de::Error::custom(
            "unsupported consent publication version",
        ));
    }
    Ok(version)
}

mod hex32 {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(serde::de::Error::custom(
                "a publication digest is 64 lowercase hex characters",
            ));
        }
        crate::hex::decode_hex32(&text).map_err(serde::de::Error::custom)
    }
}

/// The signed entry facts a handoff binds, beside its sink.
pub(crate) struct PublicationFacts<'a> {
    pub(crate) binding: &'a AttestationBinding<'a>,
    pub(crate) entry: &'a PendingApproval,
    pub(crate) subject: [u8; 32],
    pub(crate) attestation: [u8; 32],
    pub(crate) receipt: [u8; 32],
}

/// The canonical MAC input: the domain, version 1, then the profile, chain,
/// nonce, kind name and process UID each after a big-endian `u32` length.
/// Fixed-width fields follow the signed entry order, and the sink ends it:
/// byte 1 for a direct anchor, or byte 2 and the full queued reference.
pub(crate) fn publication_input(
    facts: &PublicationFacts<'_>,
    sink: PublicationSink,
    outbox_row: Option<&OutboxRowRef>,
) -> Vec<u8> {
    let mut input = CONSENT_PUBLICATION_DOMAIN.to_vec();
    let prefixed = |input: &mut Vec<u8>, bytes: &[u8]| {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        input.extend_from_slice(&len.to_be_bytes());
        input.extend_from_slice(bytes);
    };
    input.push(1);
    let entry = facts.entry;
    prefixed(&mut input, facts.binding.profile_name.as_bytes());
    prefixed(&mut input, facts.binding.chain_id.as_bytes());
    prefixed(&mut input, entry.approval_nonce.as_bytes());
    prefixed(&mut input, entry.kind.kind_name().as_bytes());
    input.push(match entry.subject_kind {
        SubjectKind::EnvelopeText => 1,
        SubjectKind::IntentDigest => 2,
    });
    input.extend_from_slice(&facts.subject);
    input.extend_from_slice(&entry.created_at_unix_ms.to_be_bytes());
    input.extend_from_slice(&entry.expires_at_unix_ms.to_be_bytes());
    prefixed(&mut input, entry.process_uid.as_bytes());
    input.extend_from_slice(&Sha256::digest(facts.attestation));
    input.extend_from_slice(&facts.receipt);
    match (sink, outbox_row) {
        (PublicationSink::Queued, Some(row)) => {
            input.push(2);
            input.extend_from_slice(&row.generation().to_be_bytes());
            input.extend_from_slice(&row.sequence().to_be_bytes());
            input.extend_from_slice(row.digest());
        }
        _ => input.push(1),
    }
    input
}

fn publication_mac(key: &[u8; 32], input: &[u8]) -> Hmac<Sha256> {
    #[allow(
        clippy::expect_used,
        reason = "new_from_slice fails only for zero-length keys; &[u8; 32] is always 32 bytes"
    )]
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .expect("HmacSha256 key initialisation with 32-byte array is infallible");
    mac.update(input);
    mac
}

impl ConsentPublicationV1 {
    /// Seals `sink` and its queued reference over `facts`.
    pub(crate) fn seal(
        key: &[u8; 32],
        facts: &PublicationFacts<'_>,
        sink: PublicationSink,
        outbox_row: Option<OutboxRowRef>,
    ) -> Self {
        let input = publication_input(facts, sink, outbox_row.as_ref());
        Self {
            v: 1,
            sink,
            outbox_row,
            subject: facts.subject,
            tag: publication_mac(key, &input).finalize().into_bytes().into(),
        }
    }
}

/// A handoff whose tag verified over its inbox entry.
///
/// Only [`verify_consent_publication`] creates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedConsentPublication {
    outbox_row: Option<OutboxRowRef>,
    subject: [u8; 32],
}

impl VerifiedConsentPublication {
    /// The queued reference, absent for a direct anchor.
    #[must_use]
    pub fn outbox_row(&self) -> Option<&OutboxRowRef> {
        self.outbox_row.as_ref()
    }

    /// Whether the direct writer anchored the row.
    #[must_use]
    pub fn is_direct_anchored(&self) -> bool {
        self.outbox_row.is_none()
    }

    /// The signed subject the handoff binds.
    #[must_use]
    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }
}

/// Verifies the handoff of the attested `entry` under `key_bytes` and
/// `binding`.
///
/// # Errors
///
/// `approval.attestation_invalid` for a missing handoff, blob or receipt, a
/// key that is not 32 bytes, a queued sink without its reference or a direct
/// sink with one, and a tag that does not verify.
pub fn verify_consent_publication(
    entry: &PendingApproval,
    key_bytes: &[u8],
    binding: &AttestationBinding<'_>,
) -> Result<VerifiedConsentPublication, WalletError> {
    let invalid = |detail: &str| {
        WalletError::Approval(ApprovalFailure::AttestationInvalid {
            detail: detail.to_owned(),
        })
    };
    let publication = entry
        .consent_publication
        .as_ref()
        .ok_or_else(|| invalid("the consent publication is missing"))?;
    let key: &[u8; 32] = key_bytes
        .try_into()
        .map_err(|_| invalid("the attestation key is not 32 bytes"))?;
    let attestation = entry
        .attestation_blob_b64
        .as_deref()
        .and_then(|blob| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(blob)
                .ok()
        })
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| invalid("the consent publication has no attestation"))?;
    let receipt = entry
        .mainnet_presence
        .as_ref()
        .and_then(super::presence::MainnetPresenceReceipt::digest)
        .ok_or_else(|| invalid("the consent publication has no receipt"))?;
    if (publication.sink == PublicationSink::Queued) != publication.outbox_row.is_some() {
        return Err(invalid(
            "the consent publication sink and reference disagree",
        ));
    }
    let facts = PublicationFacts {
        binding,
        entry,
        subject: publication.subject,
        attestation,
        receipt,
    };
    let input = publication_input(&facts, publication.sink, publication.outbox_row.as_ref());
    publication_mac(key, &input)
        .verify_slice(&publication.tag)
        .map_err(|_| invalid("the consent publication does not verify"))?;
    Ok(VerifiedConsentPublication {
        outbox_row: publication.outbox_row,
        subject: publication.subject,
    })
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;

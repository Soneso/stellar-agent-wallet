//! The fact digests of the mainnet proofs.
//!
//! Every proof a mainnet authorization binds (the endpoint identity, the
//! enrolled signer, the verified policy, the enablement record, the
//! cross-check witness, the window reservation, the approval witness, and the
//! audit readiness) reports one SHA-256 fact digest. The authorization's
//! aggregate bindings digest is computed over these, so the layout of each is
//! frozen.
//!
//! # Layout
//!
//! A fact digest is SHA-256 over the proof's label, then its fields in the
//! order the proof's `fact_digest` documents:
//!
//! - a fixed-width integer as its big-endian bytes;
//! - a fixed-length byte array as its raw bytes;
//! - a variable-length byte string as `u32be(len) || bytes`;
//! - an enum as its one-byte tag;
//! - an optional value as `0x00` when absent, or `0x01` followed by the value;
//! - a threshold table as `u32be(count)` followed, in ascending key order, by
//!   `u32be(len(key)) || key || i128be(value)` per entry.
//!
//! Labels are ASCII and carry no length prefix or terminator; each names one
//! proof and a version, so no two proofs' digests collide.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

/// Label of the endpoint identity's fact digest.
pub const FACT_LABEL_ENDPOINT: &[u8] = b"stellar-agent-authz-fact:endpoint:v1";
/// Label of the enrolled signer's fact digest.
pub const FACT_LABEL_SIGNER: &[u8] = b"stellar-agent-authz-fact:signer:v1";
/// Label of the verified policy's fact digest.
pub const FACT_LABEL_POLICY: &[u8] = b"stellar-agent-authz-fact:policy:v1";
/// Label of the enablement record's fact digest.
pub const FACT_LABEL_ENABLEMENT: &[u8] = b"stellar-agent-authz-fact:enablement:v1";
/// Label of the cross-check witness's fact digest.
pub const FACT_LABEL_WITNESS: &[u8] = b"stellar-agent-authz-fact:witness:v1";
/// Label of the window reservation's fact digest.
pub const FACT_LABEL_RESERVATION: &[u8] = b"stellar-agent-authz-fact:reservation:v1";
/// Label of the approval witness's fact digest.
pub const FACT_LABEL_APPROVAL: &[u8] = b"stellar-agent-authz-fact:approval:v1";
/// Label of the audit readiness's fact digest.
pub const FACT_LABEL_AUDIT: &[u8] = b"stellar-agent-authz-fact:audit:v1";

/// An incremental fact digest in the layout the module documents.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::mainnet::fact::{FACT_LABEL_RESERVATION, FactDigest};
///
/// let mut digest = FactDigest::new(FACT_LABEL_RESERVATION);
/// digest.bytes(b"main").fixed(&[0x11; 32]);
/// assert_eq!(digest.finish().len(), 32);
/// ```
#[derive(Debug, Clone)]
pub struct FactDigest {
    hasher: Sha256,
}

impl FactDigest {
    /// Starts a digest under `label`.
    #[must_use]
    pub fn new(label: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(label);
        Self { hasher }
    }

    /// Appends a fixed-length byte array as its raw bytes.
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.hasher.update(bytes);
        self
    }

    /// Appends a variable-length byte string with its `u32` big-endian length.
    ///
    /// A length beyond `u32::MAX` saturates; no proof field approaches it.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.hasher.update(len.to_be_bytes());
        self.hasher.update(bytes);
        self
    }

    /// Appends a one-byte enum tag.
    pub fn tag(&mut self, tag: u8) -> &mut Self {
        self.hasher.update([tag]);
        self
    }

    /// Appends the presence byte of an optional value: `0x01` when present.
    pub fn present(&mut self, present: bool) -> &mut Self {
        self.hasher.update([u8::from(present)]);
        self
    }

    /// Appends a `u32` big-endian.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.hasher.update(value.to_be_bytes());
        self
    }

    /// Appends a `u64` big-endian.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.hasher.update(value.to_be_bytes());
        self
    }

    /// Appends an `i64` big-endian.
    pub fn i64(&mut self, value: i64) -> &mut Self {
        self.hasher.update(value.to_be_bytes());
        self
    }

    /// Appends an optional `u32`: the presence byte, then the value.
    pub fn opt_u32(&mut self, value: Option<u32>) -> &mut Self {
        self.present(value.is_some());
        if let Some(value) = value {
            self.u32(value);
        }
        self
    }

    /// Appends an optional 32-byte array: the presence byte, then the bytes.
    pub fn opt_fixed32(&mut self, value: Option<&[u8; 32]>) -> &mut Self {
        self.present(value.is_some());
        if let Some(value) = value {
            self.fixed(value);
        }
        self
    }

    /// Appends an optional threshold table: the presence byte, then
    /// `u32be(count)` and each entry in ascending key order.
    pub fn thresholds(&mut self, table: Option<&BTreeMap<String, i128>>) -> &mut Self {
        self.present(table.is_some());
        if let Some(table) = table {
            self.u32(u32::try_from(table.len()).unwrap_or(u32::MAX));
            for (key, value) in table {
                self.bytes(key.as_bytes());
                self.hasher.update(value.to_be_bytes());
            }
        }
        self
    }

    /// Returns the digest.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoder produces exactly the documented preimage, checked against a
    /// hand-assembled byte string and a frozen digest.
    #[test]
    fn the_encoder_matches_the_documented_layout() {
        let mut table = BTreeMap::new();
        table.insert("b".to_owned(), -2_i128);
        table.insert("a".to_owned(), 1_i128);
        let mut digest = FactDigest::new(b"label");
        digest
            .fixed(&[0xaa, 0xbb])
            .bytes(b"xyz")
            .tag(5)
            .u32(7)
            .u64(8)
            .i64(-9)
            .opt_u32(None)
            .opt_u32(Some(10))
            .opt_fixed32(Some(&[0x01; 32]))
            .thresholds(Some(&table))
            .thresholds(None);
        let mut expected = b"label".to_vec();
        expected.extend([0xaa, 0xbb]);
        expected.extend([0, 0, 0, 3]);
        expected.extend(b"xyz");
        expected.push(5);
        expected.extend(7_u32.to_be_bytes());
        expected.extend(8_u64.to_be_bytes());
        expected.extend((-9_i64).to_be_bytes());
        expected.push(0);
        expected.push(1);
        expected.extend(10_u32.to_be_bytes());
        expected.push(1);
        expected.extend([0x01; 32]);
        expected.push(1);
        expected.extend(2_u32.to_be_bytes());
        expected.extend([0, 0, 0, 1]);
        expected.push(b'a');
        expected.extend(1_i128.to_be_bytes());
        expected.extend([0, 0, 0, 1]);
        expected.push(b'b');
        expected.extend((-2_i128).to_be_bytes());
        expected.push(0);
        let independent: [u8; 32] = Sha256::digest(&expected).into();
        let produced = digest.finish();
        assert_eq!(produced, independent);
        assert_eq!(
            crate::hex::encode(&produced),
            "aade98f8792f13aaef63956e58e1cd326b36dce3ebf64136ad8c3ba17d84fd6d"
        );
    }

    /// The eight labels are distinct and name their proof.
    #[test]
    fn the_labels_are_distinct_and_frozen() {
        let labels = [
            (FACT_LABEL_ENDPOINT, "stellar-agent-authz-fact:endpoint:v1"),
            (FACT_LABEL_SIGNER, "stellar-agent-authz-fact:signer:v1"),
            (FACT_LABEL_POLICY, "stellar-agent-authz-fact:policy:v1"),
            (
                FACT_LABEL_ENABLEMENT,
                "stellar-agent-authz-fact:enablement:v1",
            ),
            (FACT_LABEL_WITNESS, "stellar-agent-authz-fact:witness:v1"),
            (
                FACT_LABEL_RESERVATION,
                "stellar-agent-authz-fact:reservation:v1",
            ),
            (FACT_LABEL_APPROVAL, "stellar-agent-authz-fact:approval:v1"),
            (FACT_LABEL_AUDIT, "stellar-agent-authz-fact:audit:v1"),
        ];
        for (label, text) in labels {
            assert_eq!(label, text.as_bytes());
        }
        let mut sorted: Vec<_> = labels.iter().map(|(l, _)| *l).collect();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 8);
    }
}

//! Protected records of spent rule approvals, independent of the pending file.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

/// Maximum live records per profile. The time floor and sixteen records encode
/// to 867 characters, keeping the UTF-16 value inside Windows Credential
/// Manager's 2560-byte limit.
pub const MAX_SPENT_RULE_APPROVALS: usize = 16;

/// Binds a spent approval to its profile, chain, nonce and proposal digest.
#[must_use]
pub fn rule_approval_spent_marker(
    profile: &str,
    chain_id: &str,
    approval_nonce: &str,
    proposal_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent-rule-approval-spent:v1\0");
    for value in [
        profile.as_bytes(),
        chain_id.as_bytes(),
        approval_nonce.as_bytes(),
        proposal_sha256,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.finalize().into()
}

/// A spent record cannot be used or persisted. Diagnostics contain no stored value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpentSetError {
    /// The value is not a versioned sequence of complete records.
    #[error("spent rule approval record does not parse")]
    Malformed,
    /// The set has no room until an approval expires.
    #[error("spent rule approval record is full")]
    Full,
    /// The backend refuses an operation, identified only by its error code.
    #[error("spent rule approval record unavailable ({code})")]
    Unavailable {
        /// The backend's fixed error code.
        code: &'static str,
    },
}

/// Marker and expiry pairs stored together beside the attestation key, with
/// the latest clock reading a stored insert saw.
///
/// Pruning and [`Self::lapsed`] both read that floor, which never moves back,
/// so a pruned record's approval stays refused after the clock moves back
/// before its expiry.
#[derive(Default)]
pub struct SpentSet {
    floor_unix_ms: u64,
    records: Vec<([u8; 32], u64)>,
}

impl SpentSet {
    /// Reads a versioned record; absence is the empty set.
    ///
    /// # Errors
    /// Returns [`SpentSetError::Malformed`] for any other encoding.
    pub fn parse(value: Option<&str>) -> Result<Self, SpentSetError> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let payload = value.strip_prefix("v1.").ok_or(SpentSetError::Malformed)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| SpentSetError::Malformed)?;
        let (floor, records) = bytes
            .split_first_chunk::<8>()
            .ok_or(SpentSetError::Malformed)?;
        let (records, remainder) = records.as_chunks::<40>();
        if !remainder.is_empty() {
            return Err(SpentSetError::Malformed);
        }
        let records = records
            .iter()
            .map(|record| {
                let mut marker = [0; 32];
                marker.copy_from_slice(&record[..32]);
                let mut expiry = [0; 8];
                expiry.copy_from_slice(&record[32..]);
                (marker, u64::from_be_bytes(expiry))
            })
            .collect();
        Ok(Self {
            floor_unix_ms: u64::from_be_bytes(*floor),
            records,
        })
    }

    /// Whether the record holds this marker.
    #[must_use]
    pub fn contains(&self, marker: &[u8; 32]) -> bool {
        self.records.iter().any(|(stored, _)| stored == marker)
    }

    /// Whether an approval with this expiry lies at or below the time floor,
    /// where its record may already be pruned.
    #[must_use]
    pub fn lapsed(&self, expires_at_unix_ms: u64) -> bool {
        expires_at_unix_ms <= self.floor_unix_ms
    }

    /// Raises the time floor to `now_unix_ms`, prunes the records below it,
    /// then inserts a marker with its attested expiry. The floor and the
    /// pruning reach the store in the one encoded value.
    ///
    /// # Errors
    /// Returns [`SpentSetError::Full`] when the live records reach the bound.
    pub fn insert(
        &mut self,
        marker: [u8; 32],
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), SpentSetError> {
        self.floor_unix_ms = self.floor_unix_ms.max(now_unix_ms);
        self.records
            .retain(|(_, expiry)| *expiry >= self.floor_unix_ms);
        if self.records.len() >= MAX_SPENT_RULE_APPROVALS {
            return Err(SpentSetError::Full);
        }
        self.records.push((marker, expires_at_unix_ms));
        Ok(())
    }

    /// Encodes the floor and the records as URL-safe base64 without padding,
    /// prefixed by `v1.`.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(8 + self.records.len() * 40);
        bytes.extend_from_slice(&self.floor_unix_ms.to_be_bytes());
        for (marker, expiry) in &self.records {
            bytes.extend_from_slice(marker);
            bytes.extend_from_slice(&expiry.to_be_bytes());
        }
        format!("v1.{}", URL_SAFE_NO_PAD.encode(bytes))
    }
}

/// Protected storage accessed while the lock of its keyring entry is held.
pub trait RuleApprovalSpentStore: Send + Sync {
    /// Reads the record, returning `None` only for an absent entry.
    ///
    /// # Errors
    /// Returns [`SpentSetError::Unavailable`] when the backend cannot be read.
    fn load(&self) -> Result<Option<String>, SpentSetError>;
    /// Persists the record before the approval is consumed or installed.
    ///
    /// # Errors
    /// Returns [`SpentSetError::Unavailable`] when the backend cannot be
    /// written. A backend can replace the value and then fail, so an error
    /// leaves the stored value unknown.
    fn store(&self, value: &str) -> Result<(), SpentSetError>;
}

/// In-memory spent record with independent read and write failure switches,
/// and a switch for a write that stores the value and then fails.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Default)]
pub struct InMemoryRuleApprovalSpentStore {
    value: std::sync::Mutex<Option<String>>,
    /// Refuses reads while set.
    pub fail_read: std::sync::atomic::AtomicBool,
    /// Refuses writes while set.
    pub fail_write: std::sync::atomic::AtomicBool,
    /// Stores each write, then reports its failure, while set.
    pub fail_after_write: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "test-helpers"))]
impl RuleApprovalSpentStore for InMemoryRuleApprovalSpentStore {
    fn load(&self) -> Result<Option<String>, SpentSetError> {
        if self.fail_read.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SpentSetError::Unavailable { code: "test.read" });
        }
        self.value
            .lock()
            .map(|value| value.clone())
            .map_err(|_| SpentSetError::Unavailable { code: "test.lock" })
    }

    fn store(&self, value: &str) -> Result<(), SpentSetError> {
        if self.fail_write.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SpentSetError::Unavailable { code: "test.write" });
        }
        *self
            .value
            .lock()
            .map_err(|_| SpentSetError::Unavailable { code: "test.lock" })? =
            Some(value.to_owned());
        if self
            .fail_after_write
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(SpentSetError::Unavailable {
                code: "test.after_write",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_covers_every_input() {
        let marker = rule_approval_spent_marker("unit", "stellar:testnet", "nonce", &[7; 32]);
        assert_eq!(
            crate::hex::encode(&marker),
            "3d109ff90c291a422e7128d744ee5fe8ca30adc6e167c70866105807e406cef8"
        );
        assert_ne!(
            marker,
            rule_approval_spent_marker("other", "stellar:testnet", "nonce", &[7; 32])
        );
        assert_ne!(
            marker,
            rule_approval_spent_marker("unit", "stellar:other", "nonce", &[7; 32])
        );
        assert_ne!(
            marker,
            rule_approval_spent_marker("unit", "stellar:testnet", "other", &[7; 32])
        );
        for i in 0..32 {
            let mut digest = [7; 32];
            digest[i] ^= 1;
            assert_ne!(
                marker,
                rule_approval_spent_marker("unit", "stellar:testnet", "nonce", &digest)
            );
        }
        assert_ne!(
            rule_approval_spent_marker("ab", "c", "nonce", &[7; 32]),
            rule_approval_spent_marker("a", "bc", "nonce", &[7; 32])
        );
    }

    #[test]
    fn a_set_round_trips_and_prunes_expired_records() {
        let mut set = SpentSet::parse(None).unwrap();
        assert_eq!(set.encode(), "v1.AAAAAAAAAAA");
        set.insert([1; 32], 9, 0).unwrap();
        set.insert([2; 32], 10, 0).unwrap();
        let mut restored = SpentSet::parse(Some(&set.encode())).unwrap();
        assert!(restored.contains(&[1; 32]));
        restored.insert([3; 32], 20, 10).unwrap();
        assert!(!restored.contains(&[1; 32]));
        assert!(restored.contains(&[2; 32]));
        assert!(restored.contains(&[3; 32]));
        assert_eq!(
            SpentSet::parse(Some(&restored.encode())).unwrap().encode(),
            restored.encode()
        );
    }

    #[test]
    fn a_full_set_refuses_an_insert() {
        let mut set = SpentSet::default();
        for i in 0..MAX_SPENT_RULE_APPROVALS {
            set.insert([i as u8; 32], 10, 0).unwrap();
        }
        assert_eq!(set.encode().len(), 867);
        assert!(set.encode().encode_utf16().count() * 2 < 2560);
        assert_eq!(set.insert([99; 32], 20, 10), Err(SpentSetError::Full));
        assert!(!set.contains(&[99; 32]));
        set.insert([99; 32], 20, 11).unwrap();
        assert!(set.contains(&[99; 32]));
    }

    #[test]
    fn a_malformed_value_is_not_an_empty_set() {
        let short_record = format!("v1.{}", URL_SAFE_NO_PAD.encode([0; 47]));
        for value in [
            "",
            "v2.",
            "v1.",
            "v1.!!!",
            "v1.AA",
            "v1.AA==",
            short_record.as_str(),
        ] {
            assert!(matches!(
                SpentSet::parse(Some(value)),
                Err(SpentSetError::Malformed)
            ));
        }
    }

    #[test]
    fn the_time_floor_outlives_a_pruned_record_and_never_moves_back() {
        let mut set = SpentSet::default();
        set.insert([1; 32], 100, 10).unwrap();
        assert!(!set.lapsed(100));
        set.insert([2; 32], 500, 101).unwrap();
        let mut restored = SpentSet::parse(Some(&set.encode())).unwrap();
        assert!(!restored.contains(&[1; 32]));
        assert!(restored.lapsed(100));
        assert!(restored.lapsed(101));
        assert!(!restored.lapsed(102));
        restored.insert([3; 32], 600, 50).unwrap();
        assert!(restored.lapsed(101));
        assert!(restored.contains(&[2; 32]));
    }
}

//! Authenticated consent evidence snapshots beside the audit outbox.
//!
//! # Files
//!
//! Two fixed files sit beside the log: `<log>.outbox.evidence.0` and
//! `<log>.outbox.evidence.1`. Each holds one complete snapshot of exactly
//! [`SLOT_BYTES`] bytes. The owner value commits the evidence generation and
//! the head of one of them; no row ever supplies a file name.
//!
//! # Layout
//!
//! A slot holds a 124-byte header, `count` records of 89 bytes, and zero
//! padding through [`MAX_EVIDENCE_ENTRIES`] records. The header holds
//! `SAEV0001`, the scope digest, the evidence generation, the time floor in
//! milliseconds, the record count, the predecessor head, and the tag. A record
//! holds the approval identity, the row digest, the conservative expiry, the
//! queue generation, the sequence, and one state byte. Integers are
//! big-endian.
//!
//! Records sort strictly by identity. The states are Reserved, Queued,
//! Delivered, and LegacyPin. A LegacyPin carries a digest the v1 owner kept
//! as recent evidence; its identity derives from that digest.
//!
//! # Authentication
//!
//! The tag is HMAC-SHA256 under the audit key over
//! `stellar-agent-consent-evidence-tag:v1` and the whole slot with its own
//! 32 tag bytes zeroed. The head is SHA-256 over
//! `stellar-agent-consent-evidence:v1` and the whole tagged slot. A read
//! checks length, then the tag, then the layout.
//!
//! # Selection
//!
//! Any tag-valid image of the owner's scope above the committed generation
//! proves an older owner entry. Selection takes the highest such generation
//! and the caller recommits the owner to it. Two distinct images of that
//! generation refuse with `owner rollback`. Without a newer image, the image
//! matching the committed generation and head is the evidence; an older image
//! never stands in for it.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::outbox::OutboxRowRef;

/// The most records one owner scope holds: reservations, queued and
/// delivered records, and migration pins together.
pub const MAX_EVIDENCE_ENTRIES: usize = 4096;

/// A retained slot for an authenticated approval identity and immutable expiry.
/// Only the owning outbox can create this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReservation {
    scope: [u8; 32],
    identity: [u8; 32],
    expires_at_ms: u64,
}

impl EvidenceReservation {
    pub(super) fn new(scope: [u8; 32], identity: [u8; 32], expires_at_ms: u64) -> Self {
        Self {
            scope,
            identity,
            expires_at_ms,
        }
    }

    pub(super) fn facts(&self) -> ([u8; 32], [u8; 32], u64) {
        (self.scope, self.identity, self.expires_at_ms)
    }

    /// Computes retention through waiting expiry and the bounded execution window.
    /// Callers supply authenticated waiting expiry and rule duration.
    ///
    /// # Errors
    /// Refuses a deadline that overflows milliseconds.
    pub fn deadline(
        waiting_expires_at_ms: u64,
        rule_ttl_ms: u64,
    ) -> Result<u64, super::WriterError> {
        waiting_expires_at_ms
            .checked_add(rule_ttl_ms.min(900_000))
            .ok_or(super::WriterError::OutboxEvidenceUnusable {
                reason: "expiry overflow",
            })
    }
}

const HEADER_BYTES: usize = 124;
const RECORD_BYTES: usize = 89;
const MAGIC: &[u8; 8] = b"SAEV0001";
const TAG_START: usize = 92;

/// The exact size of one evidence slot.
pub(crate) const SLOT_BYTES: usize = HEADER_BYTES + RECORD_BYTES * MAX_EVIDENCE_ENTRIES;

/// The lifecycle state of one evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordState {
    Reserved = 0,
    Queued = 1,
    Delivered = 2,
    LegacyPin = 3,
}

/// One approval's evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceRecord {
    pub(crate) identity: [u8; 32],
    pub(crate) digest: [u8; 32],
    pub(crate) expires_at_ms: u64,
    pub(crate) generation: u64,
    pub(crate) sequence: u64,
    pub(crate) state: RecordState,
}

impl EvidenceRecord {
    /// The pin of a digest a v1 owner kept as recent evidence.
    pub(crate) fn legacy_pin(digest: [u8; 32]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"stellar-agent-evidence-legacy:v1");
        hash.update(digest);
        Self {
            identity: hash.finalize().into(),
            digest,
            expires_at_ms: u64::MAX,
            generation: 0,
            sequence: 0,
            state: RecordState::LegacyPin,
        }
    }
}

/// The facts of one decoded snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceImage {
    pub(crate) scope: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) floor_ms: u64,
    pub(crate) predecessor: [u8; 32],
    pub(crate) records: Vec<EvidenceRecord>,
}

impl EvidenceImage {
    /// Advances the persistent clock and removes only expired live records.
    pub(super) fn advance_floor(&mut self, now_ms: u64) {
        self.floor_ms = self.floor_ms.max(now_ms);
        self.records.retain(|record| {
            record.state == RecordState::LegacyPin || record.expires_at_ms > self.floor_ms
        });
    }

    /// The first image of a scope: generation one, zero predecessor, floor
    /// zero, and `records` sorted by identity with duplicates merged.
    pub(crate) fn initial(scope: [u8; 32], mut records: Vec<EvidenceRecord>) -> Self {
        records.sort_by_key(|record| record.identity);
        records.dedup_by(|a, b| a.identity == b.identity);
        Self {
            scope,
            generation: 1,
            floor_ms: 0,
            predecessor: [0; 32],
            records,
        }
    }

    /// The complete tagged slot bytes under `key`.
    pub(crate) fn seal(&self, key: &[u8; 32]) -> Vec<u8> {
        let mut slot = vec![0; SLOT_BYTES];
        slot[..8].copy_from_slice(MAGIC);
        slot[8..40].copy_from_slice(&self.scope);
        slot[40..48].copy_from_slice(&self.generation.to_be_bytes());
        slot[48..56].copy_from_slice(&self.floor_ms.to_be_bytes());
        let count = u32::try_from(self.records.len()).unwrap_or(u32::MAX);
        slot[56..60].copy_from_slice(&count.to_be_bytes());
        slot[60..TAG_START].copy_from_slice(&self.predecessor);
        for (index, record) in self.records.iter().take(MAX_EVIDENCE_ENTRIES).enumerate() {
            let at = HEADER_BYTES + index * RECORD_BYTES;
            slot[at..at + 32].copy_from_slice(&record.identity);
            slot[at + 32..at + 64].copy_from_slice(&record.digest);
            slot[at + 64..at + 72].copy_from_slice(&record.expires_at_ms.to_be_bytes());
            slot[at + 72..at + 80].copy_from_slice(&record.generation.to_be_bytes());
            slot[at + 80..at + 88].copy_from_slice(&record.sequence.to_be_bytes());
            slot[at + 88] = record.state as u8;
        }
        apply_tag(&mut slot, key);
        slot
    }
}

/// Writes the tag of `slot` under `key` into its tag field.
pub(crate) fn apply_tag(slot: &mut [u8], key: &[u8; 32]) {
    let tag = slot_mac(slot, key).finalize().into_bytes();
    slot[TAG_START..HEADER_BYTES].copy_from_slice(&tag);
}

/// The MAC over the domain and the slot with its tag field zeroed.
fn slot_mac(slot: &[u8], key: &[u8; 32]) -> Hmac<Sha256> {
    #[allow(clippy::expect_used, reason = "HMAC accepts every key length")]
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(b"stellar-agent-consent-evidence-tag:v1");
    mac.update(&slot[..TAG_START]);
    mac.update(&[0; 32]);
    mac.update(&slot[HEADER_BYTES..]);
    mac
}

/// The head that the owner value commits: SHA-256 over the domain and the
/// whole tagged slot.
pub(crate) fn head(slot: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent-consent-evidence:v1");
    hash.update(slot);
    hash.finalize().into()
}

/// Whether the tag of `slot` verifies under `key`. The caller has checked
/// that the slot holds a complete header.
pub(crate) fn tag_verifies(slot: &[u8], key: &[u8; 32]) -> bool {
    slot_mac(slot, key)
        .verify_slice(&slot[TAG_START..HEADER_BYTES])
        .is_ok()
}

fn be64(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(bytes);
    u64::from_be_bytes(word)
}

fn hash32(bytes: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    hash.copy_from_slice(bytes);
    hash
}

/// Decodes one slot: length, then tag, then layout.
///
/// # Errors
///
/// The static reason `length`, `tag`, or `layout`.
pub(crate) fn decode(slot: &[u8], key: &[u8; 32]) -> Result<EvidenceImage, &'static str> {
    if slot.len() != SLOT_BYTES {
        return Err("length");
    }
    if !tag_verifies(slot, key) {
        return Err("tag");
    }
    decode_layout(slot)
}

/// Checks the complete layout of bytes authenticated by a committed head.
pub(crate) fn decode_layout(slot: &[u8]) -> Result<EvidenceImage, &'static str> {
    if slot.len() != SLOT_BYTES {
        return Err("length");
    }
    let layout = "layout";
    if &slot[..8] != MAGIC {
        return Err(layout);
    }
    let count = u32::from_be_bytes([slot[56], slot[57], slot[58], slot[59]]) as usize;
    if count > MAX_EVIDENCE_ENTRIES {
        return Err(layout);
    }
    let end = HEADER_BYTES + count * RECORD_BYTES;
    if slot[end..].iter().any(|byte| *byte != 0) {
        return Err(layout);
    }
    let mut records: Vec<EvidenceRecord> = Vec::with_capacity(count);
    let mut digests = HashSet::with_capacity(count);
    for at in (HEADER_BYTES..end).step_by(RECORD_BYTES) {
        let record = EvidenceRecord {
            identity: hash32(&slot[at..at + 32]),
            digest: hash32(&slot[at + 32..at + 64]),
            expires_at_ms: be64(&slot[at + 64..at + 72]),
            generation: be64(&slot[at + 72..at + 80]),
            sequence: be64(&slot[at + 80..at + 88]),
            state: match slot[at + 88] {
                0 => RecordState::Reserved,
                1 => RecordState::Queued,
                2 => RecordState::Delivered,
                3 => RecordState::LegacyPin,
                _ => return Err(layout),
            },
        };
        if let Some(previous) = records.last() {
            if previous.identity == record.identity {
                return Err(layout);
            }
            if previous.identity > record.identity {
                return Err(layout);
            }
        }
        let coordinates_valid = match record.state {
            RecordState::Reserved => {
                record.digest == [0; 32] && record.generation == 0 && record.sequence == 0
            }
            RecordState::Queued | RecordState::Delivered => {
                record.digest != [0; 32] && record.sequence > 0
            }
            RecordState::LegacyPin => {
                record == EvidenceRecord::legacy_pin(record.digest) && record.digest != [0; 32]
            }
        };
        if !coordinates_valid || (record.digest != [0; 32] && !digests.insert(record.digest)) {
            return Err(layout);
        }
        records.push(record);
    }
    Ok(EvidenceImage {
        scope: hash32(&slot[8..40]),
        generation: be64(&slot[40..48]),
        floor_ms: be64(&slot[48..56]),
        predecessor: hash32(&slot[60..TAG_START]),
        records,
    })
}

/// The evidence scope of one owner coordinate, a keyring service and account.
///
/// SHA-256 over `stellar-agent-evidence-scope:v1`, then each string after
/// its big-endian 64-bit length.
#[must_use]
pub fn evidence_scope(service: &str, account: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent-evidence-scope:v1");
    for part in [service, account] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}

/// The two slot paths of the log at `log_path`.
pub(crate) fn slot_paths(log_path: &Path) -> [PathBuf; 2] {
    let outbox = super::outbox::outbox_path(log_path);
    [".evidence.0", ".evidence.1"].map(|suffix| {
        let mut name = outbox.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    })
}

/// Reads at most one byte more than a slot holds. A missing file reads as
/// `None`.
pub(crate) fn read_slot(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(SLOT_BYTES as u64 + 1).read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether either slot of the log at `log_path` exists.
pub(crate) fn any_slot_exists(log_path: &Path) -> io::Result<bool> {
    for path in slot_paths(log_path) {
        if path.try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The outcome of an authenticated selection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Selected {
    /// The image the owner commits.
    Current(EvidenceImage),
    /// A newer authenticated image, with its head, for the owner to commit.
    Newer {
        image: EvidenceImage,
        head: [u8; 32],
    },
}

/// Selects the evidence of an owner that commits generation `generation`
/// and head `committed`, from both slots as read.
///
/// # Errors
///
/// The static reason: `owner rollback` for two distinct newest images,
/// `scope` for a committed image of another scope, `head` when tag-valid
/// images exist but none is committed, the first slot's own reason, or
/// `missing image`.
pub(crate) fn select(
    slots: &[Option<Vec<u8>>; 2],
    generation: u64,
    committed: &[u8; 32],
    scope: &[u8; 32],
    key: &[u8; 32],
) -> Result<Selected, &'static str> {
    let decoded = slots.each_ref().map(|slot| match slot {
        None => Err("missing image"),
        Some(bytes) => decode(bytes, key).map(|image| (image, head(bytes))),
    });
    let valid: Vec<&(EvidenceImage, [u8; 32])> = decoded.iter().flatten().collect();
    let newer: Vec<&&(EvidenceImage, [u8; 32])> = valid
        .iter()
        .filter(|(image, _)| image.scope == *scope && image.generation > generation)
        .collect();
    if let Some((top, top_head)) = newer
        .iter()
        .copied()
        .copied()
        .max_by_key(|(image, _)| image.generation)
    {
        if newer
            .iter()
            .any(|(image, image_head)| image.generation == top.generation && image_head != top_head)
        {
            return Err("owner rollback");
        }
        return Ok(Selected::Newer {
            image: top.clone(),
            head: *top_head,
        });
    }
    for (image, image_head) in &valid {
        if image_head == committed && image.generation == generation {
            if image.scope != *scope {
                return Err("scope");
            }
            return Ok(Selected::Current(image.clone()));
        }
    }
    if !valid.is_empty() {
        return Err("head");
    }
    Err(decoded
        .iter()
        .find_map(|slot| {
            slot.as_ref()
                .err()
                .copied()
                .filter(|reason| *reason != "missing image")
        })
        .unwrap_or("missing image"))
}

/// The authenticated consent evidence an owner commits.
///
/// It is the complete selected image, never an uncommitted candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEvidence {
    records: Vec<EvidenceRecord>,
    floor_ms: u64,
}

impl From<EvidenceImage> for OutboxEvidence {
    fn from(image: EvidenceImage) -> Self {
        Self {
            records: image.records,
            floor_ms: image.floor_ms,
        }
    }
}

impl OutboxEvidence {
    /// Whether the record of `identity` is Delivered with the full digest of
    /// `reference`. Coordinates never substitute for the digest.
    #[must_use]
    pub fn contains_delivered(&self, identity: &[u8; 32], reference: &OutboxRowRef) -> bool {
        self.records
            .binary_search_by(|record| record.identity.cmp(identity))
            .ok()
            .and_then(|index| self.records.get(index))
            .is_some_and(|record| {
                record.state == RecordState::Delivered && record.digest == *reference.digest()
            })
    }

    /// The persistent time floor in milliseconds.
    #[must_use]
    pub fn time_floor_ms(&self) -> u64 {
        self.floor_ms
    }

    #[cfg(test)]
    pub(crate) fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;

    pub(crate) const KEY: [u8; 32] = [0x42; 32];
    const SCOPE: [u8; 32] = [0x5c; 32];

    /// A Delivered record whose identity and digest derive from `n`.
    pub(crate) fn delivered(n: u32) -> EvidenceRecord {
        let mut identity = [0; 32];
        identity[..4].copy_from_slice(&n.to_be_bytes());
        let mut digest = [0xd0; 32];
        digest[..4].copy_from_slice(&n.to_be_bytes());
        EvidenceRecord {
            identity,
            digest,
            expires_at_ms: 9_000,
            generation: 2,
            sequence: u64::from(n) + 1,
            state: RecordState::Delivered,
        }
    }

    fn image(generation: u64, records: Vec<EvidenceRecord>) -> EvidenceImage {
        EvidenceImage {
            scope: SCOPE,
            generation,
            floor_ms: 7,
            predecessor: [0x11; 32],
            records,
        }
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the slots in place"
    )]
    fn select_from(
        slots: [Option<Vec<u8>>; 2],
        generation: u64,
        committed: [u8; 32],
    ) -> Result<Selected, &'static str> {
        select(&slots, generation, &committed, &SCOPE, &KEY)
    }

    #[test]
    fn snapshot_wire_vector() {
        let pin = EvidenceRecord::legacy_pin([0xab; 32]);
        let mut records = vec![delivered(1), pin.clone()];
        records.sort_by_key(|record| record.identity);
        let image = image(3, records.clone());
        let slot = image.seal(&KEY);
        assert_eq!(slot.len(), 364_668);
        assert_eq!(&slot[..8], b"SAEV0001");
        assert_eq!(&slot[8..40], &SCOPE);
        assert_eq!(&slot[40..48], &3_u64.to_be_bytes());
        assert_eq!(&slot[48..56], &7_u64.to_be_bytes());
        assert_eq!(&slot[56..60], &2_u32.to_be_bytes());
        assert_eq!(&slot[60..92], &[0x11; 32]);
        let first = &slot[124..213];
        assert_eq!(&first[..32], &records[0].identity);
        assert_eq!(&first[32..64], &records[0].digest);
        assert_eq!(&first[64..72], &records[0].expires_at_ms.to_be_bytes());
        assert_eq!(&first[72..80], &records[0].generation.to_be_bytes());
        assert_eq!(&first[80..88], &records[0].sequence.to_be_bytes());
        assert_eq!(first[88], records[0].state as u8);
        assert!(slot[124 + 2 * 89..].iter().all(|byte| *byte == 0));
        let mut legacy = Sha256::new();
        legacy.update(b"stellar-agent-evidence-legacy:v1");
        legacy.update([0xab; 32]);
        assert_eq!(pin.identity, <[u8; 32]>::from(legacy.finalize()));
        let mut zeroed = slot.clone();
        zeroed[92..124].fill(0);
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(b"stellar-agent-consent-evidence-tag:v1");
        mac.update(&zeroed);
        assert_eq!(&slot[92..124], mac.finalize().into_bytes().as_slice());
        let mut expected = Sha256::new();
        expected.update(b"stellar-agent-consent-evidence:v1");
        expected.update(&slot);
        assert_eq!(head(&slot), <[u8; 32]>::from(expected.finalize()));
        assert_eq!(decode(&slot, &KEY).unwrap(), image);
        assert_eq!(
            crate::hex::encode(&evidence_scope("svc", "acct")),
            crate::hex::encode(&{
                let mut scope = Sha256::new();
                scope.update(b"stellar-agent-evidence-scope:v1");
                scope.update(3_u64.to_be_bytes());
                scope.update(b"svc");
                scope.update(4_u64.to_be_bytes());
                scope.update(b"acct");
                <[u8; 32]>::from(scope.finalize())
            })
        );
    }

    #[test]
    fn documented_domains_reproduce_snapshot_vector() {
        const DOC: &str = include_str!("../../../../docs/maintainers/audit-log-recovery.md");
        let tag_rule = "The tag is HMAC-SHA256 under the audit key over ASCII `stellar-agent-consent-evidence-tag:v1`, followed by the whole file with bytes 92 through 123 zeroed.";
        let head_rule = "The head is SHA-256 over ASCII `stellar-agent-consent-evidence:v1`, followed by the whole tagged file.";
        assert!(DOC.contains(tag_rule), "documented tag domain and order");
        assert!(DOC.contains(head_rule), "documented head domain and order");
        let mut records = vec![delivered(1), EvidenceRecord::legacy_pin([0xab; 32])];
        records.sort_by_key(|record| record.identity);
        let slot = image(3, records).seal(&KEY);
        let mut zeroed = slot.clone();
        zeroed[92..124].fill(0);
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(tag_rule.split('`').nth(1).unwrap().as_bytes());
        mac.update(&zeroed);
        assert_eq!(&slot[92..124], mac.finalize().into_bytes().as_slice());
        let mut hash = Sha256::new();
        hash.update(head_rule.split('`').nth(1).unwrap().as_bytes());
        hash.update(&slot);
        assert_eq!(head(&slot), <[u8; 32]>::from(hash.finalize()));
    }

    #[test]
    fn snapshot_refuses_bad_layout() {
        let mut twin = delivered(1);
        twin.digest = [0xee; 32];
        let duplicate = image(1, vec![delivered(1), twin]).seal(&KEY);
        assert!(tag_verifies(&duplicate, &KEY));
        assert_eq!(decode(&duplicate, &KEY), Err("layout"));
        let descending = image(1, vec![delivered(2), delivered(1)]).seal(&KEY);
        assert_eq!(decode(&descending, &KEY), Err("layout"));
        let mut same_digest = delivered(2);
        same_digest.digest = delivered(1).digest;
        let shared = image(1, vec![delivered(1), same_digest]).seal(&KEY);
        assert_eq!(decode(&shared, &KEY), Err("layout"));
        let mut unsequenced = delivered(1);
        unsequenced.sequence = 0;
        assert_eq!(
            decode(&image(1, vec![unsequenced]).seal(&KEY), &KEY),
            Err("layout")
        );
        let mut state = image(1, vec![delivered(1)]).seal(&KEY);
        state[124 + 88] = 4;
        apply_tag(&mut state, &KEY);
        assert_eq!(decode(&state, &KEY), Err("layout"));
        let mut padding = image(1, vec![delivered(1)]).seal(&KEY);
        padding[124 + 89] = 1;
        apply_tag(&mut padding, &KEY);
        assert_eq!(decode(&padding, &KEY), Err("layout"));
    }

    #[test]
    fn snapshot_reads_are_bounded() {
        let dir = tempfile::TempDir::new().unwrap();
        let slot = image(1, vec![delivered(1)]).seal(&KEY);
        let mut long = slot.clone();
        long.push(0);
        apply_tag(&mut long, &KEY);
        assert!(
            tag_verifies(&long, &KEY),
            "the fixture tag covers the extra byte"
        );
        let path = dir.path().join("slot");
        let mut oversized = long.clone();
        oversized.extend_from_slice(&[0; 4096]);
        std::fs::write(&path, &oversized).unwrap();
        let read = read_slot(&path).unwrap().unwrap();
        assert_eq!(read.len(), SLOT_BYTES + 1);
        assert_eq!(read, long);
        assert_eq!(decode(&read, &KEY), Err("length"));
        assert_eq!(decode(&slot[..SLOT_BYTES - 1], &KEY), Err("length"));
        assert_eq!(read_slot(&dir.path().join("absent")).unwrap(), None);
        assert_eq!(decode(&slot, &KEY).unwrap().records, vec![delivered(1)]);
    }

    #[test]
    fn snapshot_tag_covers_predecessor_and_padding() {
        let slot = image(1, vec![delivered(1)]).seal(&KEY);
        assert!(tag_verifies(&slot, &KEY));
        let mut predecessor = slot.clone();
        predecessor[60] ^= 1;
        assert!(!tag_verifies(&predecessor, &KEY));
        let mut padding = slot.clone();
        padding[SLOT_BYTES - 1] = 1;
        assert!(
            !tag_verifies(&padding, &KEY),
            "the tag covers the final padding byte"
        );
        assert_eq!(decode(&padding, &KEY), Err("tag"));
        assert!(!tag_verifies(&slot, &[0x43; 32]));
    }

    #[test]
    fn evidence_limits_are_exact() {
        let full: Vec<EvidenceRecord> = (0..4096).map(delivered).collect();
        let slot = image(u64::MAX, full).seal(&KEY);
        assert_eq!(
            decode(&slot, &KEY).unwrap().records.len(),
            MAX_EVIDENCE_ENTRIES
        );
        let committed = head(&slot);
        assert!(matches!(
            select_from([Some(slot.clone()), Some(slot)], u64::MAX, committed),
            Ok(Selected::Current(image)) if image.generation == u64::MAX
        ));
        let over: Vec<EvidenceRecord> = (0..4097).map(delivered).collect();
        let over = image(1, over).seal(&KEY);
        assert_eq!(&over[56..60], &4097_u32.to_be_bytes());
        assert_eq!(decode(&over, &KEY), Err("layout"));
    }

    #[test]
    fn selection_uses_the_committed_head() {
        let current = image(1, vec![delivered(1)]).seal(&KEY);
        let forged = image(5, vec![delivered(2)]).seal(&[0x43; 32]);
        let selected = select_from([Some(forged), Some(current.clone())], 1, head(&current));
        assert_eq!(
            selected,
            Ok(Selected::Current(decode(&current, &KEY).unwrap()))
        );
    }

    #[test]
    fn selection_refuses_foreign_scope() {
        let mut foreign = image(1, vec![delivered(1)]);
        foreign.scope = [0x77; 32];
        let foreign = foreign.seal(&KEY);
        assert_eq!(
            select_from([Some(foreign.clone()), None], 1, head(&foreign)),
            Err("scope")
        );
        let current = image(1, vec![delivered(1)]).seal(&KEY);
        let mut newer = image(4, vec![delivered(3)]);
        newer.scope = [0x77; 32];
        assert!(matches!(
            select_from(
                [Some(newer.seal(&KEY)), Some(current.clone())],
                1,
                head(&current)
            ),
            Ok(Selected::Current(_))
        ));
    }

    #[test]
    fn selection_rejects_file_rollback() {
        let first = image(1, vec![delivered(1)]).seal(&KEY);
        let second = image(2, vec![delivered(2)]).seal(&KEY);
        let committed = image(3, vec![delivered(3)]).seal(&KEY);
        assert_eq!(
            select_from([Some(first), Some(second.clone())], 3, head(&committed)),
            Err("head")
        );
        assert_eq!(
            select_from([None, None], 3, head(&committed)),
            Err("missing image")
        );
        let torn = second[..100].to_vec();
        assert_eq!(
            select_from([None, Some(torn)], 3, head(&committed)),
            Err("length")
        );
    }

    #[test]
    fn selection_takes_the_newest_authenticated_image() {
        let committed = image(1, vec![delivered(1)]).seal(&KEY);
        let third = image(3, vec![delivered(3)]).seal(&KEY);
        let fourth = image(4, vec![delivered(4)]).seal(&KEY);
        for slots in [
            [Some(third.clone()), Some(fourth.clone())],
            [Some(fourth.clone()), Some(third.clone())],
        ] {
            assert_eq!(
                select_from(slots, 1, head(&committed)),
                Ok(Selected::Newer {
                    image: decode(&fourth, &KEY).unwrap(),
                    head: head(&fourth),
                })
            );
        }
    }

    #[test]
    fn distinct_newest_images_refuse_owner_rollback() {
        let committed = image(1, vec![delivered(1)]).seal(&KEY);
        let left = image(3, vec![delivered(3)]).seal(&KEY);
        let right = image(3, vec![delivered(4)]).seal(&KEY);
        assert_eq!(
            select_from([Some(left.clone()), Some(right)], 1, head(&committed)),
            Err("owner rollback")
        );
        assert!(matches!(
            select_from([Some(left.clone()), Some(left)], 1, head(&committed)),
            Ok(Selected::Newer { image, .. }) if image.generation == 3
        ));
    }
}

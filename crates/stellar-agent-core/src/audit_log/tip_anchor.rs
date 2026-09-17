//! Keyring-held high-water mark of one audit-log file.
//!
//! The hash chain in [`super::writer`] links every entry to its predecessor,
//! and the per-file `.root_hmac` sidecar signs each file's FIRST entry. Neither
//! pins the chain's TIP: restoring an older copy of the active file, or
//! truncating it, leaves a prefix whose linkage and root signature both still
//! verify. The tip anchor closes that gap by keeping the tip's coordinates
//! outside the file, in the platform keyring, where an attacker holding only
//! filesystem access cannot rewind them.
//!
//! # What the anchor is
//!
//! [`TipAnchor`] records three numbers about ONE log file:
//!
//! - `entry_count` — entries in that file.
//! - `tip_hash` — the SHA-256 entry hash of its last entry.
//! - `end_offset` — the byte offset just past that entry's trailing newline,
//!   which equals the file length when the file ends on an entry boundary.
//!
//! The writer advances all three under its sidecar lock on every append, so the
//! anchor is always either exactly current or behind by the appends that
//! happened after the last successful anchor write.
//!
//! # Check semantics
//!
//! Given an anchor and the file it names:
//!
//! - File length equals `end_offset` and the entry ending there hashes to
//!   `tip_hash`: current, accept.
//! - File length exceeds `end_offset` and the anchored entry is intact: the
//!   file moved forward (an unkeyed writer appended, or a crash landed between
//!   the entry fsync and the anchor write). Accept, replay from `end_offset`,
//!   and re-anchor to the new tip.
//! - File length is below `end_offset`, or the entry ending at `end_offset` does
//!   not hash to `tip_hash`: the file was rolled back, truncated, or replaced.
//!   Refuse.
//!
//! An absent anchor is adopted: the chain is verified, the current tip is
//! written as the anchor, and an `audit_tip_anchored` row records the adoption.
//! This is what an audit log written before the anchor existed does on its first
//! keyed use, with no operator action.
//!
//! # Only a file with entries is ever anchored
//!
//! There is no anchor value meaning "this file is empty". Offset 0 is a prefix
//! of every file, so such an anchor would classify every file at the path as
//! ahead of it, and a rollback would be absorbed instead of refused — the exact
//! outcome the anchor exists to prevent. An absent anchor says the same thing
//! honestly: no entry has ever been anchored at this path, which the adoption
//! rule already handles.
//!
//! A file a rotation created therefore keeps the anchor its outgoing generation
//! ended on — the handoff entry — until its own first append advances it. The
//! writer recognises that state by hash and treats it as a completed rotation
//! rather than a rollback.
//!
//! # What the anchor is not
//!
//! The anchor detects rollback and truncation. It does not detect forgery: the
//! chain hash is unkeyed, so an attacker who can write the file can append
//! well-formed entries and move the tip forward legitimately. Detecting that
//! requires a per-entry keyed tag, which this substrate does not have. See
//! `docs/maintainers/security-internals.md`.
//!
//! # Scope: one path inside one profile's keyring namespace
//!
//! The anchor's keyring SERVICE is the profile's own audit-key service and its
//! ACCOUNT is derived from the lexically normalized log path, so pointing a
//! profile's `audit_log_path` at a different file starts a fresh anchor, which
//! then adopts that file's tip. Normalization is lexical rather than
//! [`std::fs::canonicalize`] because the log file may not exist yet at the
//! moment the coordinate is derived.
//!
//! Two profiles pointed at ONE log path therefore hold TWO anchors rather than
//! sharing one, each advancing only on its own appends, and a rollback to the
//! lagging one is absorbed there while the other refuses it. That configuration
//! is unsupported; see `docs/maintainers/audit-log-recovery.md`.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Number of hex characters of the path digest carried in the anchor's keyring
/// account name.
///
/// 16 hex characters are 64 bits of the SHA-256 of the normalized path. The
/// account name is a cache coordinate, not a security boundary — a collision
/// would make two log paths share an anchor, which the tip check then reports as
/// a mismatch rather than silently accepting. 64 bits keeps accidental
/// collisions out of reach while leaving the account name short enough for every
/// platform keyring backend.
const PATH_DIGEST_HEX_LEN: usize = 16;

/// Length in hex characters of a SHA-256 digest.
const SHA256_HEX_LEN: usize = 64;

// ── TipAnchor ────────────────────────────────────────────────────────────────

/// The anchored tip of one audit-log file.
///
/// Serialised for the keyring as `<entry count>:<tip hash hex>:<end offset>`,
/// where the tip hash is the bare 64-character lowercase hex digest without the
/// `sha256:` prefix the log itself carries (the prefix contains the field
/// separator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipAnchor {
    /// Number of entries in the anchored file.
    pub entry_count: u64,
    /// SHA-256 entry hash of the anchored file's last entry, in the
    /// `sha256:<hex>` form the log uses.
    pub tip_hash: String,
    /// Byte offset just past the anchored entry's trailing newline.
    pub end_offset: u64,
}

impl TipAnchor {
    /// Constructs an anchor from a replay result.
    ///
    /// # Panics
    ///
    /// Debug builds assert `entry_count >= 1`. An anchor for a file with no
    /// entries is not a representable value — see the module docs — and every
    /// construction site guards on the count before calling this.
    #[must_use]
    pub fn new(entry_count: u64, tip_hash: impl Into<String>, end_offset: u64) -> Self {
        debug_assert!(
            entry_count >= 1,
            "a tip anchor names an entry; a file with none is left unanchored"
        );
        Self {
            entry_count,
            tip_hash: tip_hash.into(),
            end_offset,
        }
    }

    /// Parses the keyring representation `<count>:<tip hash hex>:<offset>`.
    ///
    /// Strict: exactly three colon-separated fields, both counters decimal
    /// digits only (no sign, no whitespace, no radix prefix), and the digest
    /// exactly 64 lowercase hex characters. A value that does not parse is an
    /// unusable anchor, never a silently-ignored one — the caller refuses.
    ///
    /// # Errors
    ///
    /// [`TipAnchorParseError`] describing which field is malformed. The error
    /// never echoes the value.
    pub fn parse(value: &str) -> Result<Self, TipAnchorParseError> {
        let mut fields = value.split(':');
        let (Some(count), Some(hash), Some(offset), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(TipAnchorParseError::FieldCount);
        };

        let entry_count = parse_decimal_u64(count).ok_or(TipAnchorParseError::EntryCount)?;
        if entry_count == 0 {
            return Err(TipAnchorParseError::EmptyAnchor);
        }
        if hash.len() != SHA256_HEX_LEN
            || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(TipAnchorParseError::TipHash);
        }
        let end_offset = parse_decimal_u64(offset).ok_or(TipAnchorParseError::EndOffset)?;

        Ok(Self {
            entry_count,
            tip_hash: format!("sha256:{hash}"),
            end_offset,
        })
    }

    /// Renders the keyring representation.
    ///
    /// Inverse of [`TipAnchor::parse`].
    #[must_use]
    pub fn to_keyring_value(&self) -> String {
        let hex = self
            .tip_hash
            .strip_prefix("sha256:")
            .unwrap_or(&self.tip_hash);
        format!("{}:{hex}:{}", self.entry_count, self.end_offset)
    }

    /// Returns `true` when this anchor describes exactly the supplied replay
    /// result.
    #[must_use]
    pub fn matches_tip(&self, entry_count: u64, tip_hash: &str, end_offset: u64) -> bool {
        self.entry_count == entry_count
            && self.end_offset == end_offset
            && self.tip_hash == tip_hash
    }

    /// Renders `<count>:<offset>` — the anchor coordinates without the digest.
    ///
    /// Used for the `previous_anchor` field of the `audit_tip_anchored` row and
    /// for operator-visible refusals, neither of which may carry a full hash.
    #[must_use]
    pub fn coordinates(&self) -> String {
        format!("{}:{}", self.entry_count, self.end_offset)
    }
}

/// Parses a decimal `u64` with no sign, whitespace, radix prefix, or leading
/// zero padding beyond a bare `0`.
fn parse_decimal_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse::<u64>().ok()
}

/// The field of a keyring anchor value that failed to parse.
///
/// Carries no part of the value: an unparseable anchor is reported by field
/// name only, so a corrupted or attacker-planted value never reaches an
/// operator-visible message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TipAnchorParseError {
    /// The value did not consist of exactly three colon-separated fields.
    #[error("audit tip anchor: expected three colon-separated fields")]
    FieldCount,
    /// The entry-count field was not a bare decimal integer.
    #[error("audit tip anchor: entry count is not a decimal integer")]
    EntryCount,
    /// The tip-hash field was not 64 lowercase hex characters.
    #[error("audit tip anchor: tip hash is not a 64-character lowercase hex digest")]
    TipHash,
    /// The end-offset field was not a bare decimal integer.
    #[error("audit tip anchor: end offset is not a decimal integer")]
    EndOffset,
    /// The value claimed an entry count of zero.
    ///
    /// An anchor names an entry; a file with none is left unanchored. A stored
    /// zero is a corrupted or foreign value, and reading it as "nothing is
    /// anchored" would turn a corrupted anchor into a silently disarmed guard.
    #[error("audit tip anchor: entry count is zero; a file with no entries is not anchored")]
    EmptyAnchor,
}

// ── Store ────────────────────────────────────────────────────────────────────

/// Failure reading or writing the anchor's backing store.
///
/// The concrete backend lives outside this crate (the platform keyring), so the
/// error carries a human-readable detail rather than a typed backend cause. The
/// detail names the operation and the backend's own message; it never carries
/// key material, since the anchor is not secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("audit tip anchor store: {detail}")]
pub struct TipAnchorStoreError {
    /// What failed, and the backend's message.
    pub detail: String,
}

impl TipAnchorStoreError {
    /// Constructs a store error from an operation label and a cause.
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// Read/write access to one log path's anchor and its re-anchor counter.
///
/// Implemented over the platform keyring in `stellar-agent-network`; this crate
/// owns the writer and the check semantics, and never links a keyring backend of
/// its own. Every method is called with the writer's sidecar lock already held,
/// so implementations need no locking beyond what the backend provides.
pub trait TipAnchorStore: std::fmt::Debug + Send + Sync {
    /// Reads the anchor. `Ok(None)` means no anchor has ever been written for
    /// this path — the adoption path.
    ///
    /// # Errors
    ///
    /// [`TipAnchorStoreError`] when the backend is unavailable or the stored
    /// value does not parse. A value that does not parse is an error rather than
    /// `Ok(None)`: adopting over an unreadable anchor would let a corrupted
    /// value erase the rollback guard.
    fn load_anchor(&self) -> Result<Option<TipAnchor>, TipAnchorStoreError>;

    /// Reads the stored value without parsing it.
    ///
    /// [`TipAnchorStore::load_anchor`] refuses an unparseable value, which is
    /// what keeps a corrupted anchor from reading as "nothing anchored" and
    /// silently disarming the guard. The repair verb needs to see such a value
    /// to report and replace it, and this is the only way to reach it.
    ///
    /// # Errors
    ///
    /// [`TipAnchorStoreError`] when the backend is unavailable.
    fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError>;

    /// Writes `anchor`, replacing any previous value.
    ///
    /// # Errors
    ///
    /// [`TipAnchorStoreError`] when the backend rejects the write.
    fn store_anchor(&self, anchor: &TipAnchor) -> Result<(), TipAnchorStoreError>;

    /// Increments the re-anchor counter and returns the new value.
    ///
    /// The counter is monotonic per path and never reset; an absent counter
    /// reads as zero, so the first increment returns 1.
    ///
    /// # Errors
    ///
    /// [`TipAnchorStoreError`] when the backend is unavailable or the stored
    /// counter does not parse.
    fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError>;

    /// Reads the re-anchor counter. `Ok(None)` means no acknowledged rollback
    /// has ever been recorded for this path.
    ///
    /// # Errors
    ///
    /// [`TipAnchorStoreError`] when the backend is unavailable or the stored
    /// counter does not parse.
    fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError>;
}

// ── Keyed access ─────────────────────────────────────────────────────────────

/// The pair a KEYED audit-writer open needs: the chain-root HMAC key and the
/// anchor store for the log path.
///
/// Exists so the two cannot be separated. A keyed writer's rows are the ones
/// `audit verify` covers and the ones an attacker most wants to remove, so every
/// keyed open must advance the anchor; an API that took the key alone made
/// forgetting the anchor the default. Both registry and direct keyed opens take
/// this type, and it can only be built with both halves present.
///
/// Constructed by the surface that loads the key — the key and the anchor
/// coordinate are both derived from the profile's audit keyring entry, so one
/// helper produces both.
pub struct KeyedAuditAccess {
    hmac_key: Zeroizing<[u8; 32]>,
    tip_anchor: Arc<dyn TipAnchorStore>,
}

impl std::fmt::Debug for KeyedAuditAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key never reaches Debug output.
        f.debug_struct("KeyedAuditAccess")
            .field("tip_anchor", &self.tip_anchor)
            .finish_non_exhaustive()
    }
}

impl KeyedAuditAccess {
    /// Pairs a chain-root key with the anchor store for the log it will write.
    #[must_use]
    pub fn new(hmac_key: Zeroizing<[u8; 32]>, tip_anchor: Arc<dyn TipAnchorStore>) -> Self {
        Self {
            hmac_key,
            tip_anchor,
        }
    }

    /// Borrows the anchor store, for callers that attach it to a writer they
    /// already hold.
    #[must_use]
    pub fn tip_anchor(&self) -> &Arc<dyn TipAnchorStore> {
        &self.tip_anchor
    }

    /// Splits the pair for the writer constructors.
    #[must_use]
    pub fn into_parts(self) -> (Zeroizing<[u8; 32]>, Arc<dyn TipAnchorStore>) {
        (self.hmac_key, self.tip_anchor)
    }

    /// SHA-256 of the chain-root key.
    ///
    /// The writer registry pins one key per profile name for the process
    /// lifetime and refuses a later acquisition presenting a different one. It
    /// compares fingerprints rather than keys so nothing outside this type ever
    /// holds the key material, and so the registry entry that outlives the
    /// acquisition carries no secret.
    ///
    /// Crate-visible: the registry is its only caller, and the audit log's
    /// published API commits to nothing here.
    #[must_use]
    pub(crate) fn key_fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.hmac_key.as_ref());
        hasher.finalize().into()
    }
}

// ── Path-scoped coordinate derivation ────────────────────────────────────────

/// Normalizes `path` lexically: resolves `.` and `..` textually without
/// touching the filesystem.
///
/// [`std::fs::canonicalize`] cannot be used here — the coordinate must be
/// derivable before the log file exists, and canonicalize fails on a
/// not-yet-created path. Lexical normalization makes `audit/./default.jsonl`
/// and `audit/x/../default.jsonl` share an anchor with `audit/default.jsonl`;
/// it deliberately does not resolve symlinks, so two paths that differ only
/// through a link get separate anchors, each of which adopts.
#[must_use]
pub fn normalize_path_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                // Ascend one real directory.
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // A root or drive prefix is the top: `/..` is `/`.
                Some(Component::Prefix(_) | Component::RootDir) => {}
                // Nothing to ascend from on a relative path; keep the `..`.
                _ => out.push(".."),
            },
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// Derives the keyring account name that holds the anchor for `log_path`,
/// given the profile's audit-key account as the base.
///
/// The suffix is the first `PATH_DIGEST_HEX_LEN` hex characters of the
/// SHA-256 of the lexically normalized path, so the anchor follows the FILE the
/// profile points at: repointing `audit_log_path` starts a fresh anchor, which
/// adopts the new file's tip.
#[must_use]
pub fn tip_anchor_account(base_account: &str, log_path: &Path) -> String {
    let normalized = normalize_path_lexically(log_path);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_os_str().as_encoded_bytes());
    let digest = crate::hex::encode(&hasher.finalize());
    let suffix = digest.get(..PATH_DIGEST_HEX_LEN).unwrap_or(digest.as_str());
    format!("{base_account}-tip-{suffix}")
}

/// Derives the keyring account name holding the re-anchor counter that sits
/// beside the anchor for `log_path`.
#[must_use]
pub fn reanchor_count_account(base_account: &str, log_path: &Path) -> String {
    format!("{}-reanchors", tip_anchor_account(base_account, log_path))
}

// ── In-memory store for tests ────────────────────────────────────────────────

/// An in-process [`TipAnchorStore`] for tests that exercise the writer's anchor
/// semantics without a platform keyring.
///
/// Feature-gated: it is a test seam, never reachable from a shipped binary.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Default)]
pub struct InMemoryTipAnchorStore {
    state: std::sync::Mutex<InMemoryAnchorState>,
}

/// Backing state of [`InMemoryTipAnchorStore`].
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Default)]
struct InMemoryAnchorState {
    anchor: Option<TipAnchor>,
    reanchors: u64,
    fail: bool,
    writes: Vec<TipAnchor>,
    /// A raw value planted by a test, so the repair path can be exercised
    /// against something `load_anchor` refuses.
    raw: Option<String>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl InMemoryTipAnchorStore {
    /// Constructs an empty store (no anchor, no re-anchors recorded).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the currently stored anchor, if any.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned, which can only happen if a
    /// test panicked while holding it.
    #[must_use]
    pub fn peek(&self) -> Option<TipAnchor> {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        self.state
            .lock()
            .expect("in-memory anchor store mutex")
            .anchor
            .clone()
    }

    /// Overwrites the stored anchor, bypassing the writer.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn set(&self, anchor: Option<TipAnchor>) {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let mut state = self.state.lock().expect("in-memory anchor store mutex");
        state.anchor = anchor;
    }

    /// Returns every anchor value this store has successfully recorded, in
    /// order.
    ///
    /// Lets a test assert on the SEQUENCE of writes rather than only the final
    /// value, which is what discriminates a repair write from the write the
    /// next append would have made anyway.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn writes(&self) -> Vec<TipAnchor> {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        self.state
            .lock()
            .expect("in-memory anchor store mutex")
            .writes
            .clone()
    }

    /// Plants a raw stored value that [`TipAnchorStore::load_anchor`] will
    /// refuse, for exercising the repair path.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn set_raw(&self, raw: &str) {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let mut state = self.state.lock().expect("in-memory anchor store mutex");
        state.raw = Some(raw.to_owned());
        state.anchor = None;
    }

    /// Makes every subsequent operation fail, simulating an unavailable
    /// backend.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn set_failing(&self, failing: bool) {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let mut state = self.state.lock().expect("in-memory anchor store mutex");
        state.fail = failing;
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl TipAnchorStore for InMemoryTipAnchorStore {
    fn load_anchor(&self) -> Result<Option<TipAnchor>, TipAnchorStoreError> {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let state = self.state.lock().expect("in-memory anchor store mutex");
        if state.fail {
            return Err(TipAnchorStoreError::new("in-memory store set to fail"));
        }
        if let Some(raw) = state.raw.as_deref() {
            return TipAnchor::parse(raw.trim())
                .map(Some)
                .map_err(|e| TipAnchorStoreError::new(format!("anchor value is unusable: {e}")));
        }
        Ok(state.anchor.clone())
    }

    fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError> {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let state = self.state.lock().expect("in-memory anchor store mutex");
        if state.fail {
            return Err(TipAnchorStoreError::new("in-memory store set to fail"));
        }
        Ok(state
            .raw
            .clone()
            .or_else(|| state.anchor.as_ref().map(TipAnchor::to_keyring_value)))
    }

    fn store_anchor(&self, anchor: &TipAnchor) -> Result<(), TipAnchorStoreError> {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let mut state = self.state.lock().expect("in-memory anchor store mutex");
        if state.fail {
            return Err(TipAnchorStoreError::new("in-memory store set to fail"));
        }
        state.anchor = Some(anchor.clone());
        state.raw = None;
        state.writes.push(anchor.clone());
        Ok(())
    }

    fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError> {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let mut state = self.state.lock().expect("in-memory anchor store mutex");
        if state.fail {
            return Err(TipAnchorStoreError::new("in-memory store set to fail"));
        }
        state.reanchors += 1;
        Ok(state.reanchors)
    }

    fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError> {
        #[allow(clippy::expect_used, reason = "test seam; poison means a failed test")]
        let state = self.state.lock().expect("in-memory anchor store mutex");
        if state.fail {
            return Err(TipAnchorStoreError::new("in-memory store set to fail"));
        }
        Ok((state.reanchors > 0).then_some(state.reanchors))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn round_trips_through_the_keyring_representation() {
        let anchor = TipAnchor::new(7, format!("sha256:{DIGEST}"), 4096);
        let value = anchor.to_keyring_value();
        assert_eq!(value, format!("7:{DIGEST}:4096"));
        assert_eq!(TipAnchor::parse(&value).unwrap(), anchor);
    }

    #[test]
    fn an_anchor_always_names_an_entry() {
        // There is no representable "this file is empty" anchor: a zero count is
        // rejected on the way in, so a corrupted or foreign value cannot read as
        // a silently disarmed guard.
        assert_eq!(
            TipAnchor::parse(&format!("0:{DIGEST}:0")).unwrap_err(),
            TipAnchorParseError::EmptyAnchor
        );
        assert_eq!(
            TipAnchor::parse(&format!("0:{DIGEST}:512")).unwrap_err(),
            TipAnchorParseError::EmptyAnchor
        );
    }

    #[test]
    fn parse_rejects_malformed_values() {
        for (value, expected) in [
            (format!("7:{DIGEST}"), TipAnchorParseError::FieldCount),
            (
                format!("7:{DIGEST}:4096:9"),
                TipAnchorParseError::FieldCount,
            ),
            (format!("-1:{DIGEST}:0"), TipAnchorParseError::EntryCount),
            (format!(" 7:{DIGEST}:0"), TipAnchorParseError::EntryCount),
            (format!("07:{DIGEST}:0"), TipAnchorParseError::EntryCount),
            ("7::0".to_owned(), TipAnchorParseError::TipHash),
            (
                format!("7:{}:0", DIGEST.to_uppercase()),
                TipAnchorParseError::TipHash,
            ),
            (format!("7:{DIGEST}x:0"), TipAnchorParseError::TipHash),
            (format!("7:{DIGEST}:0x10"), TipAnchorParseError::EndOffset),
            (format!("0:{DIGEST}:0"), TipAnchorParseError::EmptyAnchor),
        ] {
            assert_eq!(
                TipAnchor::parse(&value).unwrap_err(),
                expected,
                "value {value} must be rejected as {expected:?}"
            );
        }
    }

    #[test]
    fn matches_tip_compares_all_three_fields() {
        let anchor = TipAnchor::new(2, format!("sha256:{DIGEST}"), 300);
        assert!(anchor.matches_tip(2, &format!("sha256:{DIGEST}"), 300));
        assert!(!anchor.matches_tip(2, "sha256:other", 300));
        assert!(!anchor.matches_tip(3, &format!("sha256:{DIGEST}"), 300));
        assert!(!anchor.matches_tip(2, &format!("sha256:{DIGEST}"), 301));
    }

    #[test]
    fn coordinates_exclude_the_digest() {
        let anchor = TipAnchor::new(9, format!("sha256:{DIGEST}"), 1234);
        let coords = anchor.coordinates();
        assert_eq!(coords, "9:1234");
        assert!(
            !coords.contains(DIGEST),
            "coordinates must not carry the digest: {coords}"
        );
    }

    #[test]
    fn lexical_normalization_folds_dot_and_dotdot() {
        assert_eq!(
            normalize_path_lexically(Path::new("/a/./b/../c/audit.jsonl")),
            PathBuf::from("/a/c/audit.jsonl")
        );
        assert_eq!(
            normalize_path_lexically(Path::new("a/b/../../../c")),
            PathBuf::from("../c")
        );
        assert_eq!(
            normalize_path_lexically(Path::new("/../a")),
            PathBuf::from("/a")
        );
    }

    #[test]
    fn account_follows_the_path_not_the_profile() {
        let one = tip_anchor_account("default", Path::new("/data/audit/default.jsonl"));
        let same = tip_anchor_account("default", Path::new("/data/audit/./default.jsonl"));
        let other = tip_anchor_account("default", Path::new("/data/audit/other.jsonl"));

        assert_eq!(one, same, "lexically equal paths share an anchor");
        assert_ne!(one, other, "a different path gets a different anchor");
        assert!(one.starts_with("default-tip-"), "account shape: {one}");
        assert_eq!(
            one.len(),
            "default-tip-".len() + PATH_DIGEST_HEX_LEN,
            "account carries exactly the truncated digest: {one}"
        );
    }

    #[test]
    fn reanchor_counter_account_sits_beside_the_anchor() {
        let path = Path::new("/data/audit/default.jsonl");
        assert_eq!(
            reanchor_count_account("default", path),
            format!("{}-reanchors", tip_anchor_account("default", path))
        );
    }

    #[test]
    fn in_memory_store_records_anchor_and_counter() {
        let store = InMemoryTipAnchorStore::new();
        assert_eq!(store.load_anchor().unwrap(), None);
        assert_eq!(store.reanchor_count().unwrap(), None);

        let anchor = TipAnchor::new(1, format!("sha256:{DIGEST}"), 120);
        store.store_anchor(&anchor).unwrap();
        assert_eq!(store.load_anchor().unwrap(), Some(anchor));

        assert_eq!(store.bump_reanchor_count().unwrap(), 1);
        assert_eq!(store.bump_reanchor_count().unwrap(), 2);
        assert_eq!(store.reanchor_count().unwrap(), Some(2));

        store.set_failing(true);
        assert!(store.load_anchor().is_err());
    }
}

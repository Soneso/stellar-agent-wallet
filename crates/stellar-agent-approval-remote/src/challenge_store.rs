//! Bounded, memory-only, single-use challenge stores for the two WebAuthn
//! ceremonies the remote-approval listener runs.
//!
//! Both stores are capped so a network-exposed, pre-authentication mint
//! endpoint cannot be used to exhaust process memory: the 16 KiB request-body
//! limit bounds a single request's cost, but does not bound how many
//! outstanding challenges accumulate across many requests. Neither store is
//! ever persisted to disk — a process restart invalidates every outstanding
//! challenge, which is the correct fail-safe (an in-flight ceremony simply
//! restarts).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore as _};

/// Hard cap on outstanding login challenges (pre-authentication, so this
/// bounds the network-exposed mint endpoint's memory cost). When full, minting
/// a new login challenge fails closed — the pre-auth path has no session
/// context to evict by, so evict-oldest would let an attacker keep evicting a
/// legitimate operator's in-flight challenge by flooding mint requests.
pub const LOGIN_CHALLENGE_STORE_CAP: usize = 256;

/// Hard cap on outstanding per-action challenges. These are minted only after
/// a successful login (session-scoped), so when full the oldest entry is
/// evicted rather than failing closed — a legitimate, already-authenticated
/// session should not be locked out by its own past activity.
pub const ACTION_CHALLENGE_STORE_CAP: usize = 256;

/// Time-to-live for a minted challenge before it is treated as expired.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// One outstanding login challenge: the 32 random bytes handed to the
/// browser as the WebAuthn `challenge`, plus its mint time.
struct LoginChallengeEntry {
    challenge: [u8; 32],
    minted_at: Instant,
}

/// Memory-only, single-use, capped store of outstanding login challenges.
///
/// # Fail-closed capacity
///
/// [`Self::mint`] returns `None` when the store is already at
/// [`LOGIN_CHALLENGE_STORE_CAP`] non-expired entries — the pre-authentication
/// mint endpoint is network-exposed, so a hard cap with fail-closed behaviour
/// (rather than silent unbounded growth) is required, not optional.
#[derive(Default)]
pub struct LoginChallengeStore {
    entries: VecDeque<LoginChallengeEntry>,
}

impl LoginChallengeStore {
    /// Constructs an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prunes expired entries, then mints and stores a fresh 32-byte
    /// challenge, returning it.
    ///
    /// Returns `None` if the store is at capacity after pruning — the caller
    /// must reject the mint request (fail closed) rather than mint anyway.
    pub fn mint(&mut self) -> Option<[u8; 32]> {
        self.prune();
        if self.entries.len() >= LOGIN_CHALLENGE_STORE_CAP {
            return None;
        }
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        self.entries.push_back(LoginChallengeEntry {
            challenge,
            minted_at: Instant::now(),
        });
        Some(challenge)
    }

    /// Consumes (removes) `challenge` if it is present and not expired.
    ///
    /// Returns `true` iff the challenge was found and unexpired — this is
    /// the single-use check: a second call with the same bytes always
    /// returns `false`.
    pub fn consume(&mut self, challenge: &[u8; 32]) -> bool {
        self.prune();
        if let Some(pos) = self.entries.iter().position(|e| &e.challenge == challenge) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes entries older than [`CHALLENGE_TTL`].
    fn prune(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|e| now.duration_since(e.minted_at) < CHALLENGE_TTL);
    }

    /// Current number of outstanding (not-yet-pruned) entries. Test/metrics use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries are outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One outstanding per-action challenge: the full derived 32-byte challenge,
/// the approval nonce it is bound to (for a defence-in-depth cross-check at
/// consume time), and its mint time.
struct ActionChallengeEntry {
    challenge: [u8; 32],
    approval_nonce: String,
    minted_at: Instant,
}

/// Memory-only, single-use, capped store of outstanding per-action approve/
/// reject challenges.
///
/// Each entry binds `challenge = SHA-256(rand32 || envelope_sha256 ||
/// approval_nonce)` (computed by the caller; this store only holds the
/// result plus its own bookkeeping) to the specific approval nonce it was
/// minted for. [`Self::consume`] requires the caller to also pass the
/// nonce it expects, so a challenge minted for entry A can never be
/// consumed as if it were valid for entry B even if the raw challenge bytes
/// were somehow replayed against the wrong nonce parameter.
///
/// # Bounded capacity
///
/// Session-scoped (minted only after login), so [`Self::mint`] evicts the
/// oldest entry when at [`ACTION_CHALLENGE_STORE_CAP`] rather than failing
/// closed — an authenticated operator's own activity should not lock them
/// out.
#[derive(Default)]
pub struct ActionChallengeStore {
    entries: VecDeque<ActionChallengeEntry>,
}

impl ActionChallengeStore {
    /// Constructs an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prunes expired entries, evicts the oldest if at capacity, then stores
    /// `challenge` bound to `approval_nonce`.
    pub fn mint(&mut self, challenge: [u8; 32], approval_nonce: impl Into<String>) {
        self.prune();
        if self.entries.len() >= ACTION_CHALLENGE_STORE_CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(ActionChallengeEntry {
            challenge,
            approval_nonce: approval_nonce.into(),
            minted_at: Instant::now(),
        });
    }

    /// Consumes (removes) the entry matching BOTH `challenge` and
    /// `approval_nonce`, if present and unexpired.
    ///
    /// Returns `true` iff such an entry existed. A challenge minted for a
    /// different nonce than the one presented here never matches, even if
    /// the raw 32 bytes happened to collide (astronomically unlikely, but
    /// the nonce check makes the store's cross-entry binding independent of
    /// that assumption).
    pub fn consume(&mut self, challenge: &[u8; 32], approval_nonce: &str) -> bool {
        self.prune();
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| &e.challenge == challenge && e.approval_nonce == approval_nonce)
        {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes entries older than [`CHALLENGE_TTL`].
    fn prune(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|e| now.duration_since(e.minted_at) < CHALLENGE_TTL);
    }

    /// Current number of outstanding (not-yet-pruned) entries. Test/metrics use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries are outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Derives the per-action challenge: `SHA-256(rand32 || envelope_sha256 ||
/// approval_nonce)`.
///
/// `envelope_sha256` MUST be server-derived from the parked
/// `PendingApproval` entry, never taken from request input — see the
/// module docs on the per-action ceremony design.
#[must_use]
pub fn derive_action_challenge(
    rand32: &[u8; 32],
    envelope_sha256: &[u8; 32],
    approval_nonce: &str,
) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(rand32);
    hasher.update(envelope_sha256);
    hasher.update(approval_nonce.as_bytes());
    hasher.finalize().into()
}

/// Generates a fresh 32-byte random value for [`derive_action_challenge`]'s
/// `rand32` input.
#[must_use]
pub fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;

    #[test]
    fn login_challenge_mint_and_consume_once() {
        let mut store = LoginChallengeStore::new();
        let challenge = store.mint().unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.consume(&challenge));
        assert!(store.is_empty());
    }

    #[test]
    fn login_challenge_consume_is_single_use() {
        let mut store = LoginChallengeStore::new();
        let challenge = store.mint().unwrap();
        assert!(store.consume(&challenge));
        assert!(
            !store.consume(&challenge),
            "a second consume of the same challenge must fail — replay must be refused"
        );
    }

    #[test]
    fn login_challenge_unknown_value_is_refused() {
        let mut store = LoginChallengeStore::new();
        assert!(!store.consume(&[0xAB; 32]));
    }

    #[test]
    fn login_challenge_store_fails_closed_at_capacity() {
        let mut store = LoginChallengeStore::new();
        for _ in 0..LOGIN_CHALLENGE_STORE_CAP {
            assert!(store.mint().is_some());
        }
        assert!(
            store.mint().is_none(),
            "minting past the cap must fail closed, not evict"
        );
        assert_eq!(store.len(), LOGIN_CHALLENGE_STORE_CAP);
    }

    #[test]
    fn action_challenge_mint_and_consume_bound_to_nonce() {
        let mut store = ActionChallengeStore::new();
        let challenge = derive_action_challenge(&random_32(), &[0x11; 32], "nonce-a");
        store.mint(challenge, "nonce-a");
        assert!(
            !store.consume(&challenge, "nonce-b"),
            "a challenge minted for nonce-a must not consume as nonce-b"
        );
        assert!(
            store.consume(&challenge, "nonce-a"),
            "consuming with the correct nonce must succeed"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn action_challenge_consume_is_single_use() {
        let mut store = ActionChallengeStore::new();
        let challenge = derive_action_challenge(&random_32(), &[0x22; 32], "nonce-x");
        store.mint(challenge, "nonce-x");
        assert!(store.consume(&challenge, "nonce-x"));
        assert!(!store.consume(&challenge, "nonce-x"));
    }

    /// WYSIWYS: a challenge derived from entry A's envelope hash differs from
    /// one derived from entry B's, even with the same nonce and rand32 —
    /// proving the challenge is not solely nonce-bound but genuinely
    /// envelope-bound.
    #[test]
    fn wysiwys_challenge_differs_by_envelope_hash() {
        let rand32 = random_32();
        let challenge_a = derive_action_challenge(&rand32, &[0xAA; 32], "same-nonce");
        let challenge_b = derive_action_challenge(&rand32, &[0xBB; 32], "same-nonce");
        assert_ne!(
            challenge_a, challenge_b,
            "distinct envelope hashes must produce distinct challenges"
        );
    }

    #[test]
    fn action_challenge_store_evicts_oldest_at_capacity() {
        let mut store = ActionChallengeStore::new();
        let first = derive_action_challenge(&random_32(), &[0x01; 32], "nonce-0");
        store.mint(first, "nonce-0");
        for i in 1..ACTION_CHALLENGE_STORE_CAP {
            let c = derive_action_challenge(&random_32(), &[i as u8; 32], &format!("nonce-{i}"));
            store.mint(c, format!("nonce-{i}"));
        }
        assert_eq!(store.len(), ACTION_CHALLENGE_STORE_CAP);
        // Minting one more evicts the oldest (`first` / "nonce-0").
        let extra = derive_action_challenge(&random_32(), &[0xFF; 32], "nonce-extra");
        store.mint(extra, "nonce-extra");
        assert_eq!(store.len(), ACTION_CHALLENGE_STORE_CAP);
        assert!(
            !store.consume(&first, "nonce-0"),
            "the oldest entry must have been evicted"
        );
    }

    #[test]
    fn derive_action_challenge_is_deterministic() {
        let rand32 = [0x42u8; 32];
        let env_hash = [0x99u8; 32];
        let a = derive_action_challenge(&rand32, &env_hash, "nonce-z");
        let b = derive_action_challenge(&rand32, &env_hash, "nonce-z");
        assert_eq!(a, b);
    }
}

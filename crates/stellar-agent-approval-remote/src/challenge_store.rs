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
        self.mint_at(Instant::now())
    }

    fn mint_at(&mut self, now: Instant) -> Option<[u8; 32]> {
        self.prune_at(now);
        if self.entries.len() >= LOGIN_CHALLENGE_STORE_CAP {
            return None;
        }
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        self.entries.push_back(LoginChallengeEntry {
            challenge,
            minted_at: now,
        });
        Some(challenge)
    }

    /// Consumes (removes) `challenge` if it is present and not expired.
    ///
    /// Returns `true` iff the challenge was found and unexpired — this is
    /// the single-use check: a second call with the same bytes always
    /// returns `false`.
    pub fn consume(&mut self, challenge: &[u8; 32]) -> bool {
        self.consume_at(challenge, Instant::now())
    }

    fn consume_at(&mut self, challenge: &[u8; 32], now: Instant) -> bool {
        self.prune_at(now);
        if let Some(pos) = self.entries.iter().position(|e| &e.challenge == challenge) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes entries older than [`CHALLENGE_TTL`].
    fn prune_at(&mut self, now: Instant) {
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
/// consume time), the view digest it was minted over, and its mint time.
struct ActionChallengeEntry {
    challenge: [u8; 32],
    approval_nonce: String,
    shown_view_digest: Option<[u8; 32]>,
    minted_at: Instant,
}

/// What consuming a per-action challenge yields: the view digest of the
/// page that requested it, which an approve compares with the entry it
/// attests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumedActionChallenge {
    /// The view digest the challenge was minted over; `None` for a challenge
    /// minted without one, which can reject but not approve.
    pub shown_view_digest: Option<[u8; 32]>,
}

/// Memory-only, single-use, capped store of outstanding per-action approve/
/// reject challenges.
///
/// Each entry binds `challenge = SHA-256(rand32 || view_digest ||
/// approval_nonce)` (computed by the caller with
/// [`derive_action_challenge`]; this store only holds the result plus its
/// own bookkeeping) to the specific approval nonce it was minted for and to
/// the view digest it was derived from. [`Self::consume`] requires the
/// caller to also pass the nonce it expects, so a challenge minted for
/// entry A can never be consumed as if it were valid for entry B even if
/// the raw challenge bytes were somehow replayed against the wrong nonce
/// parameter, and returns the view digest, so the passkey assertion over
/// the challenge fixes the digest the decision compares.
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
    /// `challenge` bound to `approval_nonce` and to the view digest it was
    /// derived from (`None` for a challenge derived without one).
    pub fn mint(
        &mut self,
        challenge: [u8; 32],
        approval_nonce: impl Into<String>,
        shown_view_digest: Option<[u8; 32]>,
    ) {
        self.mint_at(challenge, approval_nonce, shown_view_digest, Instant::now());
    }

    fn mint_at(
        &mut self,
        challenge: [u8; 32],
        approval_nonce: impl Into<String>,
        shown_view_digest: Option<[u8; 32]>,
        now: Instant,
    ) {
        self.prune_at(now);
        if self.entries.len() >= ACTION_CHALLENGE_STORE_CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(ActionChallengeEntry {
            challenge,
            approval_nonce: approval_nonce.into(),
            shown_view_digest,
            minted_at: now,
        });
    }

    /// Consumes (removes) the entry matching BOTH `challenge` and
    /// `approval_nonce`, if present and unexpired, and returns the view
    /// digest it was minted over.
    ///
    /// Returns `None` iff no such entry existed. A challenge minted for a
    /// different nonce than the one presented here never matches, even if
    /// the raw 32 bytes happened to collide (astronomically unlikely, but
    /// the nonce check makes the store's cross-entry binding independent of
    /// that assumption).
    pub fn consume(
        &mut self,
        challenge: &[u8; 32],
        approval_nonce: &str,
    ) -> Option<ConsumedActionChallenge> {
        self.consume_at(challenge, approval_nonce, Instant::now())
    }

    fn consume_at(
        &mut self,
        challenge: &[u8; 32],
        approval_nonce: &str,
        now: Instant,
    ) -> Option<ConsumedActionChallenge> {
        self.prune_at(now);
        let pos = self
            .entries
            .iter()
            .position(|e| &e.challenge == challenge && e.approval_nonce == approval_nonce)?;
        self.entries
            .remove(pos)
            .map(|entry| ConsumedActionChallenge {
                shown_view_digest: entry.shown_view_digest,
            })
    }

    /// Removes entries older than [`CHALLENGE_TTL`].
    fn prune_at(&mut self, now: Instant) {
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

/// Derives the per-action challenge: `SHA-256(rand32 || view_digest ||
/// approval_nonce)`.
///
/// `view_digest` is the view digest the requesting page rendered, after the
/// caller checked that it is the digest of the current entry, or 32 zero
/// bytes for a challenge minted without one. A passkey assertion over the
/// challenge therefore commits to the terms the page showed.
#[must_use]
pub fn derive_action_challenge(
    rand32: &[u8; 32],
    view_digest: &[u8; 32],
    approval_nonce: &str,
) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(rand32);
    hasher.update(view_digest);
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
        let now = Instant::now();
        let mut store = LoginChallengeStore::new();
        let challenge = store.mint_at(now).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.consume_at(&challenge, now));
        assert!(store.is_empty());
    }

    #[test]
    fn login_challenge_consume_is_single_use() {
        let now = Instant::now();
        let mut store = LoginChallengeStore::new();
        let challenge = store.mint_at(now).unwrap();
        assert!(store.consume_at(&challenge, now));
        assert!(
            !store.consume_at(&challenge, now),
            "a second consume of the same challenge must fail — replay must be refused"
        );
    }

    #[test]
    fn login_challenge_unknown_value_is_refused() {
        let mut store = LoginChallengeStore::new();
        assert!(!store.consume(&[0xAB; 32]));
    }

    #[test]
    fn login_challenge_expires_at_ttl() {
        let now = Instant::now();
        let mut store = LoginChallengeStore::new();
        let first = store.mint_at(now).unwrap();
        let second = store.mint_at(now).unwrap();
        assert!(store.consume_at(&first, now + CHALLENGE_TTL - Duration::from_nanos(1)));
        assert!(!store.consume_at(&second, now + CHALLENGE_TTL));
        assert!(store.is_empty());
    }

    #[test]
    fn login_challenge_store_fails_closed_at_capacity() {
        let now = Instant::now();
        let mut store = LoginChallengeStore::new();
        for _ in 0..LOGIN_CHALLENGE_STORE_CAP {
            assert!(store.mint_at(now).is_some());
        }
        assert!(
            store.mint_at(now).is_none(),
            "minting past the cap must fail closed, not evict"
        );
        assert_eq!(store.len(), LOGIN_CHALLENGE_STORE_CAP);
    }

    #[test]
    fn action_challenge_mint_and_consume_bound_to_nonce() {
        let now = Instant::now();
        let mut store = ActionChallengeStore::new();
        let challenge = derive_action_challenge(&random_32(), &[0x11; 32], "nonce-a");
        store.mint_at(challenge, "nonce-a", None, now);
        assert!(
            store.consume_at(&challenge, "nonce-b", now).is_none(),
            "a challenge minted for nonce-a must not consume as nonce-b"
        );
        assert!(
            store.consume_at(&challenge, "nonce-a", now).is_some(),
            "consuming with the correct nonce must succeed"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn action_challenge_consume_is_single_use() {
        let now = Instant::now();
        let mut store = ActionChallengeStore::new();
        let challenge = derive_action_challenge(&random_32(), &[0x22; 32], "nonce-x");
        store.mint_at(challenge, "nonce-x", None, now);
        assert!(store.consume_at(&challenge, "nonce-x", now).is_some());
        assert!(store.consume_at(&challenge, "nonce-x", now).is_none());
    }

    #[test]
    fn action_challenge_expires_at_ttl() {
        let now = Instant::now();
        let mut store = ActionChallengeStore::new();
        store.mint_at([0x11; 32], "nonce-a", None, now);
        store.mint_at([0x22; 32], "nonce-b", None, now);
        assert!(
            store
                .consume_at(
                    &[0x11; 32],
                    "nonce-a",
                    now + CHALLENGE_TTL - Duration::from_nanos(1)
                )
                .is_some()
        );
        assert!(
            store
                .consume_at(&[0x22; 32], "nonce-b", now + CHALLENGE_TTL)
                .is_none()
        );
        assert!(store.is_empty());
    }

    /// WYSIWYS: a challenge derived from one view digest differs from one
    /// derived from another, even with the same nonce and rand32, so the
    /// challenge is bound to the terms the page showed and not only to the
    /// nonce.
    #[test]
    fn wysiwys_challenge_differs_by_view_digest() {
        let rand32 = random_32();
        let challenge_a = derive_action_challenge(&rand32, &[0xAA; 32], "same-nonce");
        let challenge_b = derive_action_challenge(&rand32, &[0xBB; 32], "same-nonce");
        assert_ne!(
            challenge_a, challenge_b,
            "distinct view digests must produce distinct challenges"
        );
    }

    #[test]
    fn action_challenge_store_evicts_oldest_at_capacity() {
        let now = Instant::now();
        let mut store = ActionChallengeStore::new();
        let first = derive_action_challenge(&random_32(), &[0x01; 32], "nonce-0");
        store.mint_at(first, "nonce-0", None, now);
        for i in 1..ACTION_CHALLENGE_STORE_CAP {
            let c = derive_action_challenge(&random_32(), &[i as u8; 32], &format!("nonce-{i}"));
            store.mint_at(c, format!("nonce-{i}"), None, now);
        }
        assert_eq!(store.len(), ACTION_CHALLENGE_STORE_CAP);
        // Minting one more evicts the oldest (`first` / "nonce-0").
        let extra = derive_action_challenge(&random_32(), &[0xFF; 32], "nonce-extra");
        store.mint_at(extra, "nonce-extra", None, now);
        assert_eq!(store.len(), ACTION_CHALLENGE_STORE_CAP);
        assert!(
            store.consume_at(&first, "nonce-0", now).is_none(),
            "the oldest entry must have been evicted"
        );
    }

    #[test]
    fn consuming_a_challenge_returns_its_shown_digest() {
        let now = Instant::now();
        let mut store = ActionChallengeStore::new();
        let shown = [0x5A; 32];
        let approve = derive_action_challenge(&random_32(), &shown, "nonce-a");
        let reject = derive_action_challenge(&random_32(), &[0; 32], "nonce-a");
        store.mint_at(approve, "nonce-a", Some(shown), now);
        store.mint_at(reject, "nonce-a", None, now);
        assert_eq!(
            store.consume_at(&reject, "nonce-a", now),
            Some(ConsumedActionChallenge {
                shown_view_digest: None
            }),
            "a challenge minted without a digest yields none"
        );
        assert_eq!(
            store.consume_at(&approve, "nonce-a", now),
            Some(ConsumedActionChallenge {
                shown_view_digest: Some(shown)
            }),
            "a challenge yields the digest it was minted over"
        );
        assert!(store.is_empty());
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

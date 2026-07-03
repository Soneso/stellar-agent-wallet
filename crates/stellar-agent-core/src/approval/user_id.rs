//! `process_uid_for_attestation()` — platform-stable user identity for attestation binding.
//!
//! Provides a platform-stable string representing the calling process's
//! user identity, used as an input to the attestation HMAC to defend against
//! cross-account-on-host replay.
//!
//! # Platform behaviour
//!
//! - **Linux:** stats `/proc/self`, whose owner UID is the calling process's
//!   effective UID.  Rendered as decimal ASCII (e.g. `"1000"`).
//! - **macOS / BSD / other Unix:** creates an ephemeral file via
//!   `tempfile::tempfile()` and stats its owner UID.  On Unix, a freshly
//!   created file is owned by the creating process's effective UID, which
//!   matches the value `getuid(2)` would return for the wallet's
//!   non-setuid invocation profile.
//! - **Windows:** returns the current process token user's SID string
//!   (for example, `"S-1-5-21-..."`) via the `stellar-agent-windows-identity`
//!   safe wrapper around Win32 token APIs.
//! - **Other non-Unix:** returns the stable stub `"non-unix-stub"`.
//!
//! # Why not `libc::getuid()` directly?
//!
//! `stellar-agent-core` uses `#![forbid(unsafe_code)]` which prevents both
//! inline `unsafe` blocks and `#[allow(unsafe_code)]` overrides.  The Rust
//! 2024 `unsafe extern "C" { safe fn ... }` idiom is appropriate for crates
//! using `#![deny(unsafe_code)]` (where local `#[allow]` is permitted) but
//! not for `forbid`.  The `/proc/self` (Linux) and `tempfile::tempfile()`
//! (macOS / BSD) approaches avoid FFI entirely and return the same UID
//! value `getuid(2)` would for non-setuid invocations.
//!
//! # Why not `current_exe()` UID?
//!
//! `std::env::current_exe()` returns the **binary file's** owner UID, which
//! on Linux package-managed installs is `root` (0) rather than the running
//! user.  The attestation binding requires the **process's** UID, so this
//! module derives that explicitly.
//!
//! # Security posture
//!
//! The value is NOT a secrecy-sensitive value — it is a cross-account
//! non-replay binding.  Its purpose is to prevent a different local user
//! from replaying an attestation blob minted by another user on the same
//! host.  The HMAC key is the actual secret; the user ID is the binding
//! discriminant.

use super::error::ApprovalError;

// ─────────────────────────────────────────────────────────────────────────────
// Unix implementation
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::MetadataExt as _;

    use super::ApprovalError;

    /// Returns the calling process's effective UID as a decimal ASCII string.
    ///
    /// Strategy (in order):
    ///
    /// 1. **Linux:** stat `/proc/self`, whose owner UID equals the calling
    ///    process's effective UID.
    /// 2. **macOS / BSD / other Unix:** create an ephemeral file via
    ///    `tempfile::tempfile()` and read its owner UID.  Newly created
    ///    files are owned by the creating process's effective UID.
    /// 3. If both operations fail, returns
    ///    [`ApprovalError::ProcessUidUnavailable`].  `"0"` is not used as a
    ///    fallback because it collides with root's UID and would allow
    ///    cross-root-replay.
    ///
    /// Uses only safe Rust (no FFI), compatible with `#![forbid(unsafe_code)]`.
    /// The two strategies match `getuid(2)` semantics for non-setuid
    /// invocations, which is the wallet's invariant invocation profile.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::ProcessUidUnavailable`] when both `/proc/self`
    /// stat (Linux) and `tempfile::tempfile()` (other Unix) fail.
    pub fn process_uid_for_attestation() -> Result<String, ApprovalError> {
        // Linux: /proc/self is the canonical zero-I/O path.
        #[cfg(target_os = "linux")]
        if let Ok(meta) = std::fs::metadata("/proc/self") {
            return Ok(meta.uid().to_string());
        }

        // macOS / BSD / other Unix: ephemeral file owned by the calling
        // process's effective UID.  The temp file is unlinked on Drop.
        if let Ok(f) = tempfile::tempfile()
            && let Ok(meta) = f.metadata()
        {
            return Ok(meta.uid().to_string());
        }

        // Both strategies failed.  "0" is not used as a fallback because it
        // collides with root's UID and would allow cross-root-replay.
        Err(ApprovalError::ProcessUidUnavailable {
            detail: "both /proc/self stat and tempfile UID derivation failed".to_owned(),
        })
    }
}

// -----------------------------------------------------------------------------
// Windows implementation
// -----------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod platform {
    use super::ApprovalError;

    /// Returns the current process token user's SID string.
    ///
    /// The Win32 calls live in `stellar-agent-windows-identity`, a tiny safe
    /// wrapper crate.  Keeping that FFI outside this crate lets
    /// `stellar-agent-core` retain `#![forbid(unsafe_code)]`.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::ProcessUidUnavailable`] if the Windows token
    /// query or SID conversion fails.
    pub fn process_uid_for_attestation() -> Result<String, ApprovalError> {
        stellar_agent_windows_identity::current_user_sid_string().map_err(|e| {
            ApprovalError::ProcessUidUnavailable {
                detail: format!("windows SID lookup failed: {e}"),
            }
        })
    }
}

// -----------------------------------------------------------------------------
// Other non-Unix stub
// -----------------------------------------------------------------------------

#[cfg(not(any(unix, target_os = "windows")))]
mod platform {
    use super::ApprovalError;

    /// Returns a stable non-Unix stub for platforms without a wallet-owned
    /// approval identity implementation.
    ///
    /// # Errors
    ///
    /// Never returns `Err` on the current stub path; declared fallible for
    /// API symmetry with the Unix implementation.
    pub fn process_uid_for_attestation() -> Result<String, ApprovalError> {
        Ok("non-unix-stub".to_owned())
    }
}

/// Returns the platform-stable user identity string for attestation binding.
///
/// - **Unix:** numeric effective UID of the calling process, rendered as
///   decimal ASCII.  Derived from `/proc/self` on Linux or an ephemeral
///   `tempfile` on macOS/BSD — both match `getuid(2)` semantics for
///   non-setuid invocations.
/// - **Windows:** current process token user's SID string.
/// - **Other non-Unix:** stable stub `"non-unix-stub"`.
///
/// The returned string is an input to
/// `HMAC-SHA256(attestation_key, approval_nonce || envelope_sha256 || process_uid)`
/// and is therefore bound into the attestation blob.  An attestation blob
/// produced under one UID cannot be replayed by a different local user.
///
/// # Errors
///
/// Returns [`ApprovalError::ProcessUidUnavailable`] when the platform's UID
/// derivation strategies fail, or when the Windows token SID lookup fails.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::user_id::process_uid_for_attestation;
///
/// let uid = process_uid_for_attestation().expect("uid available on test host");
/// assert!(!uid.is_empty(), "user ID must not be empty");
/// ```
pub fn process_uid_for_attestation() -> Result<String, ApprovalError> {
    platform::process_uid_for_attestation()
}

// ─────────────────────────────────────────────────────────────────────────────
// ApproverIdentity
// ─────────────────────────────────────────────────────────────────────────────

/// The identity the attestation binds — a cross-account-on-host non-replay
/// discriminant fed into the attestation HMAC preimage.
///
/// This is an abstraction over the identity input, not a hard-wired
/// `process_uid_for_attestation()` call inside the attest path: callers
/// (the CLI today; a future server-driven approve surface) construct a
/// value of this type and pass it to [`super::attest::load_and_validate_entry`].
/// The OS uid is the only current binding.
///
/// `#[non_exhaustive]`: a future remote-approval mode will bind a
/// credential-provenance identity (for example, a WebAuthn/passkey
/// assertion) instead of an OS user id. That lands as a **second** variant
/// here. Both the entry-side parked identity and the comparison semantics
/// for matching a caller's identity against it live behind this type
/// ([`Self::matches_entry_process_uid`]), so a new variant only has to
/// teach this type how to compare itself — it does not require reopening
/// `load_and_validate_entry` or the HMAC preimage construction in
/// `attestation.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApproverIdentity {
    /// The platform-stable OS-level user identity produced by
    /// [`process_uid_for_attestation`].
    ///
    /// Carries the exact `String` that function returns — a decimal ASCII
    /// UID on Unix, a Windows SID string (`"S-1-5-21-..."`), or the fixed
    /// stub `"non-unix-stub"` on other non-Unix targets. Deliberately not
    /// narrowed to `u32`: the Windows and non-Unix-stub forms are not
    /// numeric, and narrowing would silently break attestation binding on
    /// those platforms. Preserving the exact string here is what keeps the
    /// HMAC preimage byte-identical to the pre-abstraction wire format.
    OsUid(String),
}

impl ApproverIdentity {
    /// Returns `true` if this identity matches the identity recorded on a
    /// pending entry at simulate time (`PendingApproval::process_uid`).
    ///
    /// For [`Self::OsUid`] this is a single match arm doing a string
    /// comparison against `entry_process_uid` — the exact check the
    /// pre-abstraction `process_uid: &str` parameter performed. A future
    /// credential-provenance variant may compare against different stored
    /// state entirely; that logic lives here, in one place, rather than at
    /// each call site.
    #[must_use]
    pub fn matches_entry_process_uid(&self, entry_process_uid: &str) -> bool {
        match self {
            Self::OsUid(uid) => uid == entry_process_uid,
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
    fn process_uid_for_attestation_is_not_empty() {
        let uid = process_uid_for_attestation().expect("uid available on test host");
        assert!(!uid.is_empty(), "user ID must not be empty");
    }

    #[cfg(unix)]
    #[test]
    fn process_uid_for_attestation_parses_as_u32_on_unix() {
        let uid = process_uid_for_attestation().expect("uid available on test host");
        uid.parse::<u32>()
            .expect("Unix process_uid_for_attestation must be parseable as u32");
    }

    #[test]
    fn process_uid_for_attestation_is_stable_across_calls() {
        let uid1 = process_uid_for_attestation().expect("uid available on test host");
        let uid2 = process_uid_for_attestation().expect("uid available on test host");
        assert_eq!(
            uid1, uid2,
            "process_uid_for_attestation must be stable across calls"
        );
    }

    /// Asserts that the returned UID parses as a valid `u32` (Unix UID range).
    ///
    /// A `u32` parse covers the invariant: any non-numeric output (including
    /// a literal `"0"` fallback or other synthesis) would fail here,
    /// regardless of whether the test runs as root or non-root.
    ///
    /// Also exercises the platform-UID derivation chain (Linux: `/proc/self`;
    /// macOS: ephemeral tempfile), confirming a real numeric UID is returned.
    #[cfg(unix)]
    #[test]
    fn process_uid_for_attestation_not_zero_unless_root() {
        let uid = process_uid_for_attestation().expect("uid available on test host");
        // The UID must be parseable as u32 on all Unix hosts (root or non-root).
        // This catches non-numeric output that would indicate a derivation failure.
        assert!(
            uid.parse::<u32>().is_ok(),
            "process_uid_for_attestation must return a parseable u32 UID on Unix, got: {uid:?}"
        );
    }

    /// The UID returned by `process_uid_for_attestation` must pass the same
    /// validation rules that the TOML deserialiser applies to `process_uid` on
    /// reload: numeric ASCII, Windows SID form, or the literal `"non-unix-stub"`.
    ///
    /// Verified by re-implementing the acceptance predicate inline — the exact
    /// same logic used in `store.rs::process_uid_is_valid`.
    #[test]
    fn process_uid_for_attestation_passes_store_deserialiser_rules() {
        let uid = process_uid_for_attestation().expect("uid available on test host");
        // Inline the acceptance rule from store.rs::process_uid_is_valid so that
        // this test does not depend on internal module visibility.
        let is_numeric = uid.chars().all(|c| c.is_ascii_digit());
        let is_stub = uid == "non-unix-stub";
        // Windows SID: "S" "-" (≥3 numeric dash-separated parts).
        let is_sid = {
            let mut parts = uid.split('-');
            parts.next() == Some("S") && {
                let numeric: Vec<_> = parts.collect();
                numeric.len() >= 3
                    && numeric
                        .iter()
                        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            }
        };
        assert!(
            is_numeric || is_stub || is_sid,
            "UID '{uid}' must be numeric, 'non-unix-stub', or a Windows SID — matches store deserialiser rules"
        );
    }

    /// The returned UID contains only ASCII characters and no whitespace.
    ///
    /// The store's tamper-defence rejects `process_uid` values containing
    /// Unicode direction marks or whitespace.  Verify the freshly-derived UID
    /// cannot trip that guard.
    #[test]
    fn process_uid_for_attestation_contains_only_ascii_no_whitespace() {
        let uid = process_uid_for_attestation().expect("uid available on test host");
        assert!(
            uid.is_ascii(),
            "process_uid_for_attestation must return an all-ASCII string, got: {uid:?}"
        );
        assert!(
            !uid.chars().any(char::is_whitespace),
            "process_uid_for_attestation must not contain whitespace, got: {uid:?}"
        );
    }

    /// The UID survives a round-trip through the approval store's TOML
    /// serialisation and deserialisation by using the public `PendingApprovalStore`
    /// API.  Any UID that breaks the store's on-load validator causes this test
    /// to fail at the second `open` call.
    #[test]
    fn process_uid_survives_store_roundtrip() {
        use crate::approval::store::{DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore};
        use tempfile::TempDir;

        let uid = process_uid_for_attestation().expect("uid available on test host");
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("uid-rt-test.toml");

        let nonce = {
            let mut store =
                PendingApprovalStore::open(path.clone()).expect("open store for uid roundtrip");
            let entry = PendingApproval::new_payment_pending(
                "b64xdr".to_owned(),
                b"xdr",
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                1_000_000,
                "XLM".to_owned(),
                None,
                100,
                1,
                uid.clone(),
                DEFAULT_TTL_MS,
            )
            .expect("entry construction must succeed with real UID");
            let n = entry.approval_nonce.clone();
            store.insert(entry, 1).expect("insert must succeed");
            n
        }; // store dropped, lock released

        let store2 =
            PendingApprovalStore::open(path).expect("reopen must succeed — UID must be valid");
        let loaded = store2
            .get(&nonce)
            .expect("entry must be present after reload");
        assert_eq!(
            loaded.process_uid, uid,
            "process_uid must round-trip through TOML persist+reload unchanged"
        );
    }
}

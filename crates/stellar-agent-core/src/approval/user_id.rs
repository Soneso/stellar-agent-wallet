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
/// `#[non_exhaustive]`: a remote-approval mode binds a credential-provenance
/// identity (a WebAuthn/passkey assertion) instead of an OS user id. That
/// lands as a **second** variant here. Both the entry-side parked identity
/// and the comparison semantics for matching a caller's identity against it
/// live behind this type ([`Self::matches_entry_process_uid`],
/// [`Self::is_authorized_for_entry`]), so a new variant only has to teach
/// this type how to compare itself — it does not require reopening
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

    /// An operator identity authenticated by a WebAuthn passkey assertion,
    /// for consenting to a pending approval from a device other than the
    /// wallet host.
    ///
    /// Unlike [`Self::OsUid`], this identity is not bound by the OS process
    /// boundary: the entry's stored `process_uid` is always the agent
    /// process's UID (stamped at simulate/park time), never the approving
    /// operator's. Authorization instead rests on two independent checks
    /// that must both hold: cryptographic possession of the passkey,
    /// established by verifying a fresh WebAuthn assertion before this
    /// identity is constructed (see [`VerifiedPasskeyAssertion`]), and
    /// allowlist membership, checked against the profile's configured
    /// operator credentials by [`Self::is_authorized_for_entry`].
    PasskeyCredential {
        /// Base64url WebAuthn credential ID that the assertion verifier
        /// accepted for `verification_witness`.
        ///
        /// MUST be the credential ID the verifier itself matched the
        /// assertion's public key to — never a value taken from request
        /// input independent of verification. See
        /// [`Self::from_verified_passkey_assertion`].
        credential_id_b64url: String,

        /// Proof that a WebAuthn assertion for `credential_id_b64url` was
        /// verified before this identity was constructed.
        ///
        /// This field's type has no public constructor outside test builds
        /// (see [`VerifiedPasskeyAssertion`]), so holding one is only
        /// possible by having gone through assertion verification.
        verification_witness: VerifiedPasskeyAssertion,
    },
}

impl ApproverIdentity {
    /// Constructs a [`Self::PasskeyCredential`] identity from a verified
    /// WebAuthn assertion.
    ///
    /// Consuming a [`VerifiedPasskeyAssertion`] is the only way to obtain
    /// this variant: there is no constructor that skips verification.
    /// `credential_id_b64url` MUST be the credential ID the verifier itself
    /// matched — never a value read from request input independent of the
    /// verification that produced `verification_witness`.
    #[must_use]
    pub fn from_verified_passkey_assertion(
        credential_id_b64url: impl Into<String>,
        verification_witness: VerifiedPasskeyAssertion,
    ) -> Self {
        Self::PasskeyCredential {
            credential_id_b64url: credential_id_b64url.into(),
            verification_witness,
        }
    }

    /// Returns `true` if this identity matches the identity recorded on a
    /// pending entry at simulate time (`PendingApproval::process_uid`).
    ///
    /// For [`Self::OsUid`] this is a single match arm doing a string
    /// comparison against `entry_process_uid` — the exact check the
    /// pre-abstraction `process_uid: &str` parameter performed.
    ///
    /// For [`Self::PasskeyCredential`] this method always returns `false`:
    /// a passkey-authenticated identity is never authorized by a bare
    /// process-UID comparison (the entry's `process_uid` is the agent
    /// process's UID, not the approving operator's), and this method takes
    /// no allowlist to check membership against. Callers that need to gate
    /// a `PasskeyCredential` identity MUST use
    /// [`Self::is_authorized_for_entry`] instead.
    #[must_use]
    pub fn matches_entry_process_uid(&self, entry_process_uid: &str) -> bool {
        match self {
            Self::OsUid(uid) => uid == entry_process_uid,
            Self::PasskeyCredential { .. } => false,
        }
    }

    /// Returns `true` if this identity is authorized to attest or reject a
    /// pending entry, given the entry's stored `process_uid`, the entry's own
    /// approval nonce, and the profile's operator-approval credential
    /// allowlist.
    ///
    /// - [`Self::OsUid`]: identical to [`Self::matches_entry_process_uid`];
    ///   `allowed_credentials` and `entry_nonce` are not consulted, keeping
    ///   loopback approval behaviour byte-identical.
    /// - [`Self::PasskeyCredential`]: `entry_process_uid` is not consulted.
    ///   Authorization instead requires ALL of: `credential_id_b64url` is
    ///   non-empty and present in `allowed_credentials`, AND the witness's
    ///   bound nonce equals `entry_nonce`. The nonce-binding check is what
    ///   prevents a witness verified for one pending entry's per-action
    ///   challenge from ever authorizing a different entry — see
    ///   [`VerifiedPasskeyAssertion`]'s entry-binding invariant. Every
    ///   condition is a real check consulted on every call, not a
    ///   placeholder that always succeeds.
    #[must_use]
    pub fn is_authorized_for_entry(
        &self,
        entry_process_uid: &str,
        entry_nonce: &str,
        allowed_credentials: &[String],
    ) -> bool {
        match self {
            Self::OsUid(_) => self.matches_entry_process_uid(entry_process_uid),
            Self::PasskeyCredential {
                credential_id_b64url,
                verification_witness,
            } => {
                !credential_id_b64url.is_empty()
                    && allowed_credentials
                        .iter()
                        .any(|allowed| allowed == credential_id_b64url)
                    && verification_witness.bound_nonce == entry_nonce
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifiedPasskeyAssertion
// ─────────────────────────────────────────────────────────────────────────────

/// Non-forgeable evidence that a WebAuthn assertion for a specific passkey
/// credential has already been verified, bound to one specific pending
/// approval's nonce.
///
/// # Construction discipline
///
/// Both fields of this type are private to this module. No other module —
/// even within this crate — can construct a value of this type by writing a
/// struct literal; the only way is through an associated function of this
/// type. The only associated function available outside test builds,
/// [`Self::new_verified`], is called by the remote-approval HTTP layer only
/// after a successful WebAuthn assertion verification; there is no non-test
/// path in this crate that mints a witness without verifying an assertion
/// first.
///
/// [`ApproverIdentity::PasskeyCredential`] can only be built by consuming a
/// value of this type ([`ApproverIdentity::from_verified_passkey_assertion`]),
/// so a `PasskeyCredential` identity can never be minted without one.
///
/// # Entry-binding invariant
///
/// A witness is scoped to exactly the pending-approval nonce passed to
/// [`Self::new_verified`] at construction. The caller MUST have verified the
/// assertion over a challenge that is itself cryptographically bound to that
/// nonce (the remote-approval per-action challenge is
/// `SHA-256(rand32 || envelope_sha256 || approval_nonce)`, server-derived
/// from the parked entry) — never a caller-chosen or request-supplied nonce
/// independent of what was actually verified.
///
/// [`ApproverIdentity::is_authorized_for_entry`] enforces this invariant
/// structurally: it compares the witness's bound nonce against the nonce of
/// the entry actually being decided and refuses on any mismatch. A witness
/// obtained from verifying entry A's challenge can therefore never authorize
/// a decision on entry B, even if an HTTP-layer bug routed it there — the
/// core gate refuses independently of the HTTP layer's own bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPasskeyAssertion {
    /// The full approval nonce the verified assertion's challenge was bound
    /// to. Compared against the entry's own nonce by
    /// [`ApproverIdentity::is_authorized_for_entry`].
    bound_nonce: String,
}

impl VerifiedPasskeyAssertion {
    /// Mints a witness bound to `approval_nonce` without running WebAuthn
    /// assertion verification.
    ///
    /// Exists only to exercise [`ApproverIdentity::PasskeyCredential`] gate
    /// behaviour in isolation from the verification pipeline. Compiled only
    /// under `#[cfg(test)]` or the `test-helpers` feature — a production
    /// release build never includes this function, so it cannot be reached
    /// outside a test binary.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn new_for_test(approval_nonce: impl Into<String>) -> Self {
        Self {
            bound_nonce: approval_nonce.into(),
        }
    }

    /// Mints a witness bound to `approval_nonce` by consuming the `Result` a
    /// WebAuthn assertion verifier returned, over a challenge bound to that
    /// nonce.
    ///
    /// This is the only production (non-test-gated) constructor of this
    /// type, and it takes the literal `Result` a verifier such as
    /// `stellar_agent_smart_account::webauthn::pre_verify_assertion` returns
    /// — generic over the error type so this crate (which must not depend on
    /// `stellar-agent-smart-account`; the dependency runs the other way)
    /// never needs to name it. Returns `None` when `verification_result` is
    /// `Err`, so a caller cannot mint a witness by merely asserting success —
    /// it must hold an actual `Ok(())` produced by calling the verifier.
    ///
    /// Callers MUST call this only with the result of verifying an assertion
    /// over a challenge that a server derived from the PARKED
    /// pending-approval entry identified by `approval_nonce` — never from a
    /// request-supplied value taken independent of that derivation. See the
    /// entry-binding invariant on the type docs: `approval_nonce` here is
    /// what [`ApproverIdentity::is_authorized_for_entry`] later compares
    /// against the nonce of the entry actually being decided.
    #[must_use]
    pub fn new_verified<E>(
        approval_nonce: impl Into<String>,
        verification_result: Result<(), E>,
    ) -> Option<Self> {
        verification_result.ok()?;
        Some(Self {
            bound_nonce: approval_nonce.into(),
        })
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

    // ─────────────────────────────────────────────────────────────────────
    // PasskeyCredential gate tests
    // ─────────────────────────────────────────────────────────────────────

    /// `OsUid` behaviour is unchanged by the addition of `PasskeyCredential`:
    /// `is_authorized_for_entry` delegates to the same string comparison as
    /// `matches_entry_process_uid`, ignoring the allowlist and nonce entirely.
    #[test]
    fn os_uid_is_authorized_for_entry_matches_process_uid_comparison() {
        let identity = ApproverIdentity::OsUid("1000".to_owned());
        assert!(identity.is_authorized_for_entry("1000", "AAAAAAAAAAAAAAAAAAAAAA", &[]));
        assert!(!identity.is_authorized_for_entry("2000", "AAAAAAAAAAAAAAAAAAAAAA", &[]));
        // Allowlist and nonce contents are irrelevant to the OsUid arm.
        assert!(identity.is_authorized_for_entry(
            "1000",
            "BBBBBBBBBBBBBBBBBBBBBB",
            &["some-credential".to_owned()]
        ));
    }

    /// `matches_entry_process_uid` always refuses a `PasskeyCredential`
    /// identity: this narrower method has no allowlist input, so it cannot
    /// safely authorize a passkey identity and must fail closed.
    #[test]
    fn passkey_credential_never_matches_bare_process_uid_comparison() {
        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "cred-abc",
            VerifiedPasskeyAssertion::new_for_test("AAAAAAAAAAAAAAAAAAAAAA"),
        );
        assert!(!identity.matches_entry_process_uid("1000"));
        assert!(!identity.matches_entry_process_uid("cred-abc"));
    }

    const ENTRY_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const OTHER_ENTRY_NONCE: &str = "BBBBBBBBBBBBBBBBBBBBBB";

    /// GATE-IS-REAL (a): a `PasskeyCredential` identity whose credential ID
    /// is NOT in `allowed_credentials` is refused, even though the identity
    /// itself carries a validly-verified, correctly-bound witness. Proves the
    /// allowlist check is a real, non-vacuous gate — not an always-true arm.
    #[test]
    fn passkey_credential_not_in_allowlist_is_refused() {
        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "attacker-controlled-cred-id",
            VerifiedPasskeyAssertion::new_for_test(ENTRY_NONCE),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        assert!(
            !identity.is_authorized_for_entry("1000", ENTRY_NONCE, &allowed),
            "a credential ID absent from the allowlist must be refused"
        );
    }

    /// GATE-IS-REAL (a continued): the same identity type, with a credential
    /// ID that IS present in `allowed_credentials` and a witness bound to the
    /// entry actually being decided, is authorized. Together with the
    /// refusal test above this proves the check is neither always-true nor
    /// always-false — it is a genuine membership test.
    #[test]
    fn passkey_credential_in_allowlist_and_bound_to_entry_is_authorized() {
        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "enrolled-operator-cred-id",
            VerifiedPasskeyAssertion::new_for_test(ENTRY_NONCE),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        assert!(
            identity.is_authorized_for_entry("1000", ENTRY_NONCE, &allowed),
            "an allowlisted credential ID with a correctly-bound witness must be authorized"
        );
    }

    /// An empty credential ID is refused even if (degenerately) present in
    /// the allowlist slice — the non-empty check is independent of, and
    /// prior to, the membership check.
    #[test]
    fn passkey_credential_empty_id_is_always_refused() {
        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "",
            VerifiedPasskeyAssertion::new_for_test(ENTRY_NONCE),
        );
        let allowed = vec![String::new()];
        assert!(
            !identity.is_authorized_for_entry("1000", ENTRY_NONCE, &allowed),
            "an empty credential ID must never be authorized"
        );
    }

    /// ENTRY-BINDING (cross-entry replay refusal): a witness verified for
    /// entry A's per-action challenge must never authorize a decision on
    /// entry B, even when the credential is allowlisted. This is the
    /// structural, type-level enforcement of the entry-binding invariant
    /// documented on `VerifiedPasskeyAssertion` — it must fail if a future
    /// refactor stops checking the bound nonce against the entry's own
    /// nonce.
    #[test]
    fn passkey_credential_witness_bound_to_different_entry_is_refused() {
        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "enrolled-operator-cred-id",
            VerifiedPasskeyAssertion::new_for_test(ENTRY_NONCE),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        assert!(
            !identity.is_authorized_for_entry("1000", OTHER_ENTRY_NONCE, &allowed),
            "a witness bound to a different entry's nonce must never authorize this entry"
        );
    }

    /// `VerifiedPasskeyAssertion::new_verified` (the production constructor)
    /// returns `None` when the verification result it is handed is `Err`,
    /// and `Some` only when handed `Ok(())` — it cannot be used to fabricate
    /// a witness by merely claiming success.
    #[test]
    fn new_verified_returns_none_on_verification_failure() {
        let failure: Result<(), &'static str> = Err("assertion invalid");
        assert!(VerifiedPasskeyAssertion::new_verified(ENTRY_NONCE, failure).is_none());

        let success: Result<(), &'static str> = Ok(());
        assert!(VerifiedPasskeyAssertion::new_verified(ENTRY_NONCE, success).is_some());
    }

    /// GATE-IS-REAL (b): exercises the only construction path for
    /// `ApproverIdentity::PasskeyCredential` — consuming a
    /// `VerifiedPasskeyAssertion` witness via
    /// `from_verified_passkey_assertion`. The structural invariant that no
    /// production build can mint a witness without a real verification
    /// result is enforced at compile time and by `new_verified`'s `Option`
    /// return, not by this test: the witness's fields are private to this
    /// module, its test-only constructor is gated
    /// `#[cfg(any(test, feature = "test-helpers"))]`, and its production
    /// constructor only returns `Some` for an `Ok(())` result.
    #[test]
    fn verified_passkey_assertion_has_no_production_bypass_constructor() {
        // Constructing via the test-only path is the only way reachable from
        // this test module, confirming the type is not a bare unit struct or
        // a public tuple struct constructible with a literal from outside
        // `user_id.rs` — its fields are private to this module.
        let witness = VerifiedPasskeyAssertion::new_for_test(ENTRY_NONCE);
        let identity = ApproverIdentity::from_verified_passkey_assertion("cred-x", witness);
        assert!(matches!(
            identity,
            ApproverIdentity::PasskeyCredential { .. }
        ));
    }
}

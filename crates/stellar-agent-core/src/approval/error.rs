//! `ApprovalError` taxonomy for the wallet-owned approval spine.
//!
//! All error variants redact secret material.  The `attestation_blob_b64`
//! field MUST NOT appear in any error message.  `approval_nonce` values are
//! redacted to first-5-last-5 characters when the nonce length exceeds 10
//! characters.

/// Errors produced by the wallet-owned approval spine.
///
/// `#[non_exhaustive]` ensures callers cannot exhaustively match all variants
/// without a wildcard arm, permitting future additions without breaking changes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// An I/O error occurred.
    ///
    /// Display exposes only [`std::io::ErrorKind`] so user paths embedded in
    /// platform I/O error strings do not leak through user-facing errors.
    #[error("approval I/O error: {kind:?}")]
    Io {
        /// The I/O error kind, safe to display without path details.
        kind: std::io::ErrorKind,
        /// The original source error, retained for error chaining but not shown in Display.
        #[source]
        source: std::io::Error,
    },

    /// A TOML parse or serialise error occurred.
    ///
    /// `detail` is a non-secret diagnostic string derived from the TOML error.
    #[error("approval TOML error: {detail}")]
    Toml {
        /// Non-secret diagnostic detail string.
        detail: String,
    },

    /// The approval store file is locked by another writer.
    ///
    /// Only one `PendingApprovalStore` per store file is permitted across all
    /// processes.  The caller should retry after a short delay or surface
    /// `approval.writer_locked` to the user.
    #[error("approval store is locked by another writer (approval.writer_locked)")]
    WriterLocked,

    /// An entry with the same `approval_nonce` already exists in the store.
    ///
    /// The `approval_nonce_redacted` field shows first-5-last-5 characters of
    /// the nonce to aid forensic correlation without leaking the full value.
    #[error("duplicate approval nonce: {approval_nonce_redacted}")]
    DuplicateNonce {
        /// Redacted nonce (first-5-last-5 characters, or the full nonce if
        /// length ≤ 10).
        approval_nonce_redacted: String,
    },

    /// No entry with the given `approval_nonce` was found.
    #[error("approval entry not found")]
    NotFound,

    /// The approval entry has expired.
    ///
    /// Expired entries are distinct from absent entries at this internal layer.
    /// The MCP commit path collapses both to `policy.approval_required`
    /// (indistinguishability invariant).
    #[error("approval entry has expired")]
    Expired,

    /// The attestation blob has already been set on this entry.
    ///
    /// `record_attestation` is one-shot; calling it again returns this error.
    #[error("attestation already set on this approval entry")]
    AlreadyAttested,

    /// A filesystem permission error occurred.
    ///
    /// Raised when the store directory or file cannot be created with the
    /// required permissions (`0o700` for directory, `0o600` for file).
    #[error("approval permission error: {detail}")]
    Permission {
        /// Non-secret diagnostic detail string.
        detail: String,
    },

    /// The nonce length did not match expectations.
    ///
    /// The approval nonce must be exactly 22 characters (16 bytes encoded as
    /// URL-safe base64 no-pad).
    #[error("invalid approval nonce length: expected {expected} characters, got {actual}")]
    InvalidNonceLength {
        /// Expected length in characters.
        expected: usize,
        /// Actual length in characters.
        actual: usize,
    },

    /// The platform UID derivation failed.
    ///
    /// On Unix, this means both `/proc/self` stat (Linux) and the ephemeral
    /// `tempfile` UID strategy (macOS/BSD) failed.  The `"0"` silent fallback
    /// is deliberately absent: `0` collides with root's UID and would create a
    /// cross-root-replay vector.
    ///
    /// Callers MUST propagate this error and not fall back to a static string.
    #[error("process UID unavailable for attestation binding: {detail}")]
    ProcessUidUnavailable {
        /// Non-secret diagnostic detail string.
        detail: String,
    },

    /// A store entry failed validation on `PendingApprovalStore::open`.
    ///
    /// Raised when a deserialised `PendingApproval` entry contains a field
    /// that fails the format invariants (nonce not base64url no-pad 22 chars,
    /// process_uid containing non-numeric-or-stub content, etc.).
    #[error("invalid approval store entry: {detail}")]
    InvalidEntry {
        /// Non-secret diagnostic detail string.
        detail: String,
    },

    /// A kind-guarded operation was called on an entry of the wrong
    /// [`super::store::ApprovalKind`].
    ///
    /// `record_attestation` requires `PaymentSimulated`; `record_passkey_assertion`
    /// requires `SignWithPasskey`. Calling either method on the other kind returns
    /// this error.
    ///
    /// Wire codes carried in `expected` and `actual` are one of:
    /// `"PaymentSimulated"` or `"SignWithPasskey"`.
    #[error(
        "approval kind mismatch: expected {expected}, actual {actual} \
         (approval.wrong_kind)"
    )]
    WrongKind {
        /// The kind that the called method operates on.
        expected: &'static str,
        /// The kind that the entry actually holds.
        actual: &'static str,
    },

    /// A field value supplied to a `PendingApproval` constructor or a
    /// validator failed an invariant check.
    ///
    /// `reason` is a non-secret human-readable diagnostic string.
    ///
    /// Raised for:
    /// - Empty or oversized `credential_id` (CTAP2 range: 16–64 bytes).
    /// - Empty or oversized `rule_ids` (max 8 entries per OZ context-rule limits).
    /// - `smart_account_redacted` that does not match the
    ///   `^C[A-Z2-7]{4}\.\.\.[A-Z2-7]{5}$` first-5-last-5 redaction shape.
    #[error("invalid approval field: {reason}")]
    Invalid {
        /// Non-secret diagnostic detail string.
        reason: String,
    },

    /// The pending approval store has reached its maximum capacity.
    ///
    /// Expired entries are pruned on `insert`, so this error is returned only
    /// when the store already holds `max` non-expired entries.  The caller
    /// should surface this as a transient resource-limit condition; no auth
    /// bypass is implied.
    #[error("pending approval store full: maximum {max} entries reached")]
    PendingStoreFull {
        /// The hard cap enforced by the store.
        max: usize,
    },

    /// An operator-approval credential enrollment named a `credential_id_b64url`
    /// already present in the store.
    ///
    /// `enroll` refuses silent overwrite: replacing an already-enrolled
    /// operator's public key without an explicit prior removal could let a
    /// compromised enrollment path substitute an attacker-controlled key
    /// under a credential ID the operator still recognises.
    #[error("operator-approval credential already enrolled: {credential_id_redacted}")]
    DuplicateCredentialId {
        /// Redacted credential ID (first-5-last-5 characters, or the full
        /// value if length ≤ 10).
        credential_id_redacted: String,
    },

    /// A WebAuthn sign-counter update presented a counter that did not
    /// advance past the stored counter, for a credential where both are
    /// non-zero.
    ///
    /// Per WebAuthn Level 2, a non-advancing counter across two verified
    /// assertions from the same credential is a cloned-authenticator signal:
    /// the presented value is refused and the stored counter is left
    /// unchanged.  A presented or stored counter of `0` means the
    /// authenticator does not report counters and is exempt from this check.
    #[error(
        "sign counter did not advance for {credential_id_redacted}: presented {presented}, \
         stored {stored} (possible cloned authenticator)"
    )]
    SignCounterRegression {
        /// Redacted credential ID (first-5-last-5 characters, or the full
        /// value if length ≤ 10).
        credential_id_redacted: String,
        /// The counter value presented by the verified assertion.
        presented: u32,
        /// The counter value previously stored for this credential.
        stored: u32,
    },
}

impl ApprovalError {
    /// Constructs an [`ApprovalError::Io`] from an `io::Error`.
    ///
    /// Takes by value so the error can be used as a `map_err` function pointer.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taken by value to serve as `map_err(ApprovalError::from_io)` function pointer"
    )]
    pub(crate) fn from_io(e: std::io::Error) -> Self {
        let kind = e.kind();
        Self::Io { kind, source: e }
    }

    /// Constructs an [`ApprovalError::Io`] for synthetic I/O-shaped failures.
    pub(crate) fn from_io_detail(kind: std::io::ErrorKind, detail: impl Into<String>) -> Self {
        Self::Io {
            kind,
            source: std::io::Error::new(kind, detail.into()),
        }
    }

    /// Constructs a [`ApprovalError::DuplicateNonce`] with the nonce redacted.
    ///
    /// Redaction rule: if `nonce.len() > 10`, keeps first 5 and last 5
    /// characters separated by `"..."`.  Otherwise uses the full nonce.
    pub(crate) fn duplicate_nonce(nonce: &str) -> Self {
        Self::DuplicateNonce {
            approval_nonce_redacted: redact_nonce(nonce),
        }
    }

    /// Constructs an [`ApprovalError::PendingStoreFull`] with the cap value.
    pub(crate) fn pending_store_full(max: usize) -> Self {
        Self::PendingStoreFull { max }
    }

    /// Constructs a [`ApprovalError::DuplicateCredentialId`] with the
    /// credential ID redacted.
    pub(crate) fn duplicate_credential_id(credential_id_b64url: &str) -> Self {
        Self::DuplicateCredentialId {
            credential_id_redacted: redact_nonce(credential_id_b64url),
        }
    }

    /// Constructs a [`ApprovalError::SignCounterRegression`] with the
    /// credential ID redacted.
    pub(crate) fn sign_counter_regression(
        credential_id_b64url: &str,
        presented: u32,
        stored: u32,
    ) -> Self {
        Self::SignCounterRegression {
            credential_id_redacted: redact_nonce(credential_id_b64url),
            presented,
            stored,
        }
    }
}

/// Redacts a nonce for use in error messages.
///
/// Returns first-5-last-5 characters separated by `"..."` if the nonce is
/// longer than 10 characters; otherwise returns the full nonce unchanged.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::error::redact_nonce;
///
/// assert_eq!(redact_nonce("abc"), "abc");
/// assert_eq!(redact_nonce("abcdefghijk"), "abcde...ghijk");
/// ```
pub fn redact_nonce(nonce: &str) -> String {
    if nonce.len() > 10 {
        let (head, tail) = (&nonce[..5], &nonce[nonce.len() - 5..]);
        format!("{head}...{tail}")
    } else {
        nonce.to_owned()
    }
}

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
    fn redact_nonce_short_passes_through() {
        assert_eq!(redact_nonce("abc"), "abc");
        assert_eq!(redact_nonce("1234567890"), "1234567890");
    }

    #[test]
    fn redact_nonce_long_redacts() {
        let nonce = "abcdefghijk"; // len 11
        assert_eq!(redact_nonce(nonce), "abcde...ghijk");
    }

    #[test]
    fn redact_nonce_22_chars() {
        let nonce = "AAAAAAAAAAAABBBBBBBBBBBB"; // typical 22-char nonce
        let redacted = redact_nonce(nonce);
        assert!(redacted.contains("..."));
        assert_eq!(&redacted[..5], "AAAAA");
        assert_eq!(&redacted[redacted.len() - 5..], "BBBBB");
    }

    #[test]
    fn duplicate_nonce_error_redacts() {
        let err = ApprovalError::duplicate_nonce("abcdefghijklmn");
        match err {
            ApprovalError::DuplicateNonce {
                approval_nonce_redacted,
            } => {
                assert!(approval_nonce_redacted.contains("..."));
                assert!(!approval_nonce_redacted.contains("abcdefghijklmn"));
            }
            _ => panic!("expected DuplicateNonce"),
        }
    }

    #[test]
    fn io_error_display_does_not_contain_secret() {
        let err = ApprovalError::from_io(std::io::Error::other("disk full"));
        let msg = err.to_string();
        assert!(msg.contains("Other"));
        // Ensure the word "attestation_blob" never appears
        assert!(!msg.contains("attestation_blob"));
    }

    #[test]
    fn from_io_display_omits_embedded_path() {
        let path = "/home/alice/.local/share/stellar-agent/approvals/default.toml";
        let source = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("open(\"{path}\"): permission denied"),
        );

        let err = ApprovalError::from_io(source);
        let msg = err.to_string();

        assert!(msg.contains("PermissionDenied"));
        assert!(
            !msg.contains(path),
            "ApprovalError::Io display must not leak user paths"
        );
        assert!(
            !msg.contains("/home/alice"),
            "ApprovalError::Io display must not leak user home directories"
        );
    }

    #[test]
    fn writer_locked_display() {
        let err = ApprovalError::WriterLocked;
        assert!(err.to_string().contains("writer"));
    }

    #[test]
    fn not_found_display() {
        let err = ApprovalError::NotFound;
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn expired_display() {
        let err = ApprovalError::Expired;
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn already_attested_display() {
        let err = ApprovalError::AlreadyAttested;
        assert!(err.to_string().contains("already"));
    }

    #[test]
    fn invalid_nonce_length_display() {
        let err = ApprovalError::InvalidNonceLength {
            expected: 22,
            actual: 10,
        };
        assert!(err.to_string().contains("22"));
        assert!(err.to_string().contains("10"));
    }

    #[test]
    fn pending_store_full_display_contains_max() {
        let err = ApprovalError::pending_store_full(4096);
        let msg = err.to_string();
        assert!(msg.contains("4096"), "display must include the cap: {msg}");
        assert!(
            !msg.contains("secret") && !msg.contains("attestation_blob"),
            "display must not leak secret material: {msg}"
        );
    }

    #[test]
    fn duplicate_credential_id_error_redacts() {
        let err = ApprovalError::duplicate_credential_id("enrolled-operator-credential-id");
        match err {
            ApprovalError::DuplicateCredentialId {
                credential_id_redacted,
            } => {
                assert!(credential_id_redacted.contains("..."));
                assert!(!credential_id_redacted.contains("enrolled-operator-credential-id"));
            }
            _ => panic!("expected DuplicateCredentialId"),
        }
    }

    #[test]
    fn sign_counter_regression_display_contains_values_not_full_id() {
        let err = ApprovalError::sign_counter_regression("enrolled-operator-credential-id", 3, 5);
        let msg = err.to_string();
        assert!(msg.contains('3'), "presented value must appear: {msg}");
        assert!(msg.contains('5'), "stored value must appear: {msg}");
        assert!(
            !msg.contains("enrolled-operator-credential-id"),
            "full credential ID must not appear: {msg}"
        );
    }
}

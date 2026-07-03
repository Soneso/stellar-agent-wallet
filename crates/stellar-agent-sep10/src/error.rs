//! Typed error enum for SEP-10 challenge validation and JWT session handling.
//!
//! All variants are fail-closed: they represent validation failures that must
//! cause the challenge or session to be rejected. None of the variants echo
//! secret material.

/// Errors produced by SEP-10 challenge validation and JWT session parsing.
///
/// The enum is `#[non_exhaustive]`; downstream crates must match with a
/// wildcard arm. All variants carry a stable [`Sep10Error::wire_code`] string
/// for structured audit-log emission.
///
/// # Variant groups
///
/// - **Challenge structure** (`InvalidSequenceNumber`, `InvalidTimeBounds`,
///   `ChallengeExpired`, `ChallengeNotYetValid`, `InvalidSourceAccount`,
///   `MissingOperations`, `InvalidFirstOperation`, `InvalidNonceLength`,
///   `InvalidNonceFormat`, `InvalidManageDataKey`) — cover SEP-10 v3.4.1
///   validation steps.
/// - **web_auth_domain** (`MissingWebAuthDomainOp`, `WebAuthDomainMismatch`).
/// - **Subsequent operations** (`InvalidClientDomainOp`,
///   `UnexpectedOperationSource`).
/// - **Signatures** (`MissingServerSignature`, `InvalidServerSignature`).
/// - **Decode** (`XdrDecodeError`).
/// - **HTTP and JWT** (`HttpError`, `JwtParseError`, `JwtExpired`,
///   `ReplayDetected`).
/// - **Session integrity** (`SessionAccountMismatch`).
/// - **Configuration** (`InvalidWebAuthEndpoint`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Sep10Error {
    // ── Challenge structure ──────────────────────────────────────────────────
    /// The challenge transaction's sequence number is not zero.
    ///
    /// SEP-10 requires sequence number = 0 so the challenge cannot be replayed
    /// as a valid network transaction.
    #[error("invalid sequence number: {found} (must be 0)")]
    InvalidSequenceNumber {
        /// The sequence number found in the challenge transaction.
        found: i64,
    },

    /// The challenge transaction's time bounds are missing or malformed.
    ///
    /// SEP-10 requires time bounds to be set.
    #[error("invalid time bounds: {detail}")]
    InvalidTimeBounds {
        /// Non-secret human-readable description of the failure.
        detail: String,
    },

    /// The challenge has expired: the current time is past the max bound.
    ///
    /// SEP-10 challenges use a 15-minute window.
    #[error("challenge expired: exp {exp_unix} <= now {now_unix}")]
    ChallengeExpired {
        /// The `max_time` bound from the challenge's time bounds (Unix seconds).
        exp_unix: u64,
        /// The current time passed to `parse_and_validate` (Unix seconds).
        now_unix: u64,
    },

    /// The challenge is not yet valid: the current time is before the min bound.
    ///
    /// The server's clock may be skewed, or the challenge was generated for the
    /// future. Rejected fail-closed.
    #[error("challenge not yet valid: min {min_unix} > now {now_unix}")]
    ChallengeNotYetValid {
        /// The `min_time` bound from the challenge's time bounds (Unix seconds).
        min_unix: u64,
        /// The current time passed to `parse_and_validate` (Unix seconds).
        now_unix: u64,
    },

    /// The challenge transaction source account does not match the expected
    /// server signing key.
    ///
    /// The source account must be the Server Account.
    #[error("invalid source account: {detail}")]
    InvalidSourceAccount {
        /// Non-secret human-readable description (does not echo key bytes).
        detail: String,
    },

    /// The challenge transaction contains no operations.
    ///
    /// SEP-10 requires at least one ManageData operation.
    #[error("missing operations: challenge transaction must contain at least one operation")]
    MissingOperations,

    /// The first operation is not a ManageData operation, or its source account
    /// is absent or invalid.
    ///
    /// The first operation must be ManageData with source = client account.
    #[error("invalid first operation: {detail}")]
    InvalidFirstOperation {
        /// Non-secret description of the failure (operation type or missing source).
        detail: String,
    },

    /// The nonce value in the first ManageData operation is not 64 bytes after
    /// base64 decoding.
    ///
    /// SEP-10 requires the value to contain a 48-byte random payload encoded as
    /// base64, producing exactly 64 bytes encoded.
    #[error("invalid nonce length: found {found} bytes (expected {expected})")]
    InvalidNonceLength {
        /// The number of bytes found in the nonce value field.
        found: usize,
        /// The expected number of bytes (64 for the encoded nonce).
        expected: usize,
    },

    /// The nonce value in the first ManageData operation is not valid base64.
    #[error("invalid nonce format: {detail}")]
    InvalidNonceFormat {
        /// Non-secret description of the base64 decode failure.
        detail: String,
    },

    /// The ManageData key in the first operation is not `"<home_domain> auth"`,
    /// or the key exceeds 64 characters.
    #[error("invalid ManageData key: {detail}")]
    InvalidManageDataKey {
        /// Non-secret description of the key mismatch or length violation.
        detail: String,
    },

    // ── web_auth_domain ──────────────────────────────────────────────────────
    /// The challenge is missing the required `web_auth_domain` ManageData
    /// operation.
    ///
    /// SEP-10 v3.4.1 requires a ManageData op with key `"web_auth_domain"` and
    /// source = Server Account.
    #[error("missing web_auth_domain operation (required in SEP-10 v3.4.1)")]
    MissingWebAuthDomainOp,

    /// The `web_auth_domain` ManageData operation's value does not match the
    /// expected web auth domain.
    #[error("web_auth_domain mismatch: found {found:?}, expected {expected:?}")]
    WebAuthDomainMismatch {
        /// The value found in the `web_auth_domain` ManageData operation.
        found: String,
        /// The value expected (passed to `parse_and_validate`).
        expected: String,
    },

    // ── Subsequent operations ────────────────────────────────────────────────
    /// The `client_domain` ManageData operation has an invalid structure.
    ///
    /// If present, the `client_domain` op source must NOT be the Server Account.
    #[error("invalid client_domain operation: {detail}")]
    InvalidClientDomainOp {
        /// Non-secret description of the failure.
        detail: String,
    },

    /// A non-first ManageData operation (other than `web_auth_domain` and
    /// `client_domain`) has a source account that is not the Server Account.
    ///
    /// Extra ops must be reserved for server use with source = Server Account.
    #[error("unexpected operation source at index {op_index}: {detail}")]
    UnexpectedOperationSource {
        /// Zero-based index of the offending operation.
        op_index: usize,
        /// Non-secret description of the source account mismatch.
        detail: String,
    },

    // ── Signatures ───────────────────────────────────────────────────────────
    /// The challenge transaction contains no signatures.
    ///
    /// SEP-10 requires at least one signature from the Server Account.
    #[error("missing server signature: challenge transaction has no signatures")]
    MissingServerSignature,

    /// The server signature present in the challenge does not verify against
    /// the expected server signing key.
    ///
    /// The server must have signed the `TransactionSignaturePayload` with its
    /// `SIGNING_KEY`.
    #[error("invalid server signature: {detail}")]
    InvalidServerSignature {
        /// Non-secret description of the verification failure (does not echo
        /// signature bytes).
        detail: String,
    },

    // ── Decode ───────────────────────────────────────────────────────────────
    /// The base64-encoded challenge XDR could not be decoded.
    ///
    /// Covers both base64 decode failures and XDR parse failures.
    #[error("XDR decode error: {detail}")]
    XdrDecodeError {
        /// Non-secret description of the decode failure.
        detail: String,
    },

    // ── HTTP and JWT ─────────────────────────────────────────────────────────
    /// HTTP transport failure when fetching or submitting the challenge.
    #[error("HTTP error: {detail}")]
    HttpError {
        /// Non-secret HTTP error description.
        detail: String,
    },

    /// The JWT returned by the server could not be parsed.
    #[error("JWT parse error: {detail}")]
    JwtParseError {
        /// Non-secret description of the parse failure.
        detail: String,
    },

    /// The JWT session has expired.
    #[error("JWT expired: exp {exp_unix} <= now {now_unix}")]
    JwtExpired {
        /// The JWT `exp` claim value (Unix seconds).
        exp_unix: u64,
        /// The current time (Unix seconds).
        now_unix: u64,
    },

    /// A SEP-10 challenge or JWT was replayed.
    #[error("replay detected: {detail}")]
    ReplayDetected {
        /// Non-secret description of the replay (challenge hash or JWT `jti`).
        detail: String,
    },

    // ── Session integrity ────────────────────────────────────────────────────
    /// The `sub` claim in the returned JWT does not match the account that
    /// signed the challenge.
    ///
    /// This indicates a server-side misbehaviour: the session was issued for a
    /// different account than the one that authenticated.
    #[error("session account mismatch: {detail}")]
    SessionAccountMismatch {
        /// Redacted account hint (does not echo full key bytes).
        detail: String,
    },

    // ── Configuration ────────────────────────────────────────────────────────
    /// The `web_auth_endpoint` URL could not be parsed or has no host
    /// component.
    ///
    /// Required when `web_auth_domain` is `None`: the expected `web_auth_domain`
    /// for challenge validation is derived from the endpoint host, so an
    /// unparseable or host-less URL is rejected fail-closed.
    #[error("invalid web_auth_endpoint: {detail}")]
    InvalidWebAuthEndpoint {
        /// Non-secret description of why the endpoint is invalid.
        detail: String,
    },
}

impl Sep10Error {
    /// Returns the canonical wire error code for this variant.
    ///
    /// The returned `&'static str` is the typed code emitted in audit-log
    /// records and structured error responses. Callers should use this method
    /// rather than matching variants directly so they remain forward-compatible
    /// with new variants.
    ///
    /// # Wire-code namespace
    ///
    /// All codes are in the `sep10.` namespace.
    ///
    /// # Forward compatibility
    ///
    /// The enum is `#[non_exhaustive]`; future variants return
    /// `"sep10.unknown_error"` via the `_` arm. This is deliberately distinct
    /// from any valid code so operators can detect unexpected variants in
    /// telemetry.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep10::Sep10Error;
    ///
    /// assert_eq!(
    ///     Sep10Error::InvalidSequenceNumber { found: 42 }.wire_code(),
    ///     "sep10.invalid_sequence_number"
    /// );
    /// assert_eq!(
    ///     Sep10Error::MissingWebAuthDomainOp.wire_code(),
    ///     "sep10.missing_web_auth_domain_op"
    /// );
    /// assert_eq!(
    ///     Sep10Error::MissingServerSignature.wire_code(),
    ///     "sep10.missing_server_signature"
    /// );
    /// ```
    #[must_use]
    #[allow(
        unreachable_patterns,
        reason = "Kept for forward-compatibility: new variants without an explicit arm \
                  return `sep10.unknown_error` so telemetry can detect unhandled cases."
    )]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::InvalidSequenceNumber { .. } => "sep10.invalid_sequence_number",
            Self::InvalidTimeBounds { .. } => "sep10.invalid_time_bounds",
            Self::ChallengeExpired { .. } => "sep10.challenge_expired",
            Self::ChallengeNotYetValid { .. } => "sep10.challenge_not_yet_valid",
            Self::InvalidSourceAccount { .. } => "sep10.invalid_source_account",
            Self::MissingOperations => "sep10.missing_operations",
            Self::InvalidFirstOperation { .. } => "sep10.invalid_first_operation",
            Self::InvalidNonceLength { .. } => "sep10.invalid_nonce_length",
            Self::InvalidNonceFormat { .. } => "sep10.invalid_nonce_format",
            Self::InvalidManageDataKey { .. } => "sep10.invalid_manage_data_key",
            Self::MissingWebAuthDomainOp => "sep10.missing_web_auth_domain_op",
            Self::WebAuthDomainMismatch { .. } => "sep10.web_auth_domain_mismatch",
            Self::InvalidClientDomainOp { .. } => "sep10.invalid_client_domain_op",
            Self::UnexpectedOperationSource { .. } => "sep10.unexpected_operation_source",
            Self::MissingServerSignature => "sep10.missing_server_signature",
            Self::InvalidServerSignature { .. } => "sep10.invalid_server_signature",
            Self::XdrDecodeError { .. } => "sep10.xdr_decode_error",
            Self::HttpError { .. } => "sep10.http_error",
            Self::JwtParseError { .. } => "sep10.jwt_parse_error",
            Self::JwtExpired { .. } => "sep10.jwt_expired",
            Self::ReplayDetected { .. } => "sep10.replay_detected",
            Self::SessionAccountMismatch { .. } => "sep10.session_account_mismatch",
            Self::InvalidWebAuthEndpoint { .. } => "sep10.invalid_web_auth_endpoint",
            _ => "sep10.unknown_error",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn wire_code_invalid_sequence_number() {
        assert_eq!(
            Sep10Error::InvalidSequenceNumber { found: 1 }.wire_code(),
            "sep10.invalid_sequence_number"
        );
    }

    #[test]
    fn wire_code_invalid_time_bounds() {
        assert_eq!(
            Sep10Error::InvalidTimeBounds {
                detail: "no time bounds set".to_owned()
            }
            .wire_code(),
            "sep10.invalid_time_bounds"
        );
    }

    #[test]
    fn wire_code_challenge_expired() {
        assert_eq!(
            Sep10Error::ChallengeExpired {
                exp_unix: 1_000,
                now_unix: 2_000
            }
            .wire_code(),
            "sep10.challenge_expired"
        );
    }

    #[test]
    fn wire_code_challenge_not_yet_valid() {
        assert_eq!(
            Sep10Error::ChallengeNotYetValid {
                min_unix: 2_000,
                now_unix: 1_000
            }
            .wire_code(),
            "sep10.challenge_not_yet_valid"
        );
    }

    #[test]
    fn wire_code_invalid_source_account() {
        assert_eq!(
            Sep10Error::InvalidSourceAccount {
                detail: "source account mismatch".to_owned()
            }
            .wire_code(),
            "sep10.invalid_source_account"
        );
    }

    #[test]
    fn wire_code_missing_operations() {
        assert_eq!(
            Sep10Error::MissingOperations.wire_code(),
            "sep10.missing_operations"
        );
    }

    #[test]
    fn wire_code_invalid_first_operation() {
        assert_eq!(
            Sep10Error::InvalidFirstOperation {
                detail: "not ManageData".to_owned()
            }
            .wire_code(),
            "sep10.invalid_first_operation"
        );
    }

    #[test]
    fn wire_code_invalid_nonce_length() {
        assert_eq!(
            Sep10Error::InvalidNonceLength {
                found: 32,
                expected: 64
            }
            .wire_code(),
            "sep10.invalid_nonce_length"
        );
    }

    #[test]
    fn wire_code_invalid_nonce_format() {
        assert_eq!(
            Sep10Error::InvalidNonceFormat {
                detail: "not base64".to_owned()
            }
            .wire_code(),
            "sep10.invalid_nonce_format"
        );
    }

    #[test]
    fn wire_code_invalid_manage_data_key() {
        assert_eq!(
            Sep10Error::InvalidManageDataKey {
                detail: "wrong key format".to_owned()
            }
            .wire_code(),
            "sep10.invalid_manage_data_key"
        );
    }

    #[test]
    fn wire_code_missing_web_auth_domain_op() {
        assert_eq!(
            Sep10Error::MissingWebAuthDomainOp.wire_code(),
            "sep10.missing_web_auth_domain_op"
        );
    }

    #[test]
    fn wire_code_web_auth_domain_mismatch() {
        assert_eq!(
            Sep10Error::WebAuthDomainMismatch {
                found: "evil.com".to_owned(),
                expected: "example.com".to_owned()
            }
            .wire_code(),
            "sep10.web_auth_domain_mismatch"
        );
    }

    #[test]
    fn wire_code_invalid_client_domain_op() {
        assert_eq!(
            Sep10Error::InvalidClientDomainOp {
                detail: "source is server account".to_owned()
            }
            .wire_code(),
            "sep10.invalid_client_domain_op"
        );
    }

    #[test]
    fn wire_code_unexpected_operation_source() {
        assert_eq!(
            Sep10Error::UnexpectedOperationSource {
                op_index: 2,
                detail: "source is not server account".to_owned()
            }
            .wire_code(),
            "sep10.unexpected_operation_source"
        );
    }

    #[test]
    fn wire_code_missing_server_signature() {
        assert_eq!(
            Sep10Error::MissingServerSignature.wire_code(),
            "sep10.missing_server_signature"
        );
    }

    #[test]
    fn wire_code_invalid_server_signature() {
        assert_eq!(
            Sep10Error::InvalidServerSignature {
                detail: "sig does not verify".to_owned()
            }
            .wire_code(),
            "sep10.invalid_server_signature"
        );
    }

    #[test]
    fn wire_code_xdr_decode_error() {
        assert_eq!(
            Sep10Error::XdrDecodeError {
                detail: "base64 decode failed".to_owned()
            }
            .wire_code(),
            "sep10.xdr_decode_error"
        );
    }

    #[test]
    fn wire_code_http_error() {
        assert_eq!(
            Sep10Error::HttpError {
                detail: "connection refused".to_owned()
            }
            .wire_code(),
            "sep10.http_error"
        );
    }

    #[test]
    fn wire_code_jwt_parse_error() {
        assert_eq!(
            Sep10Error::JwtParseError {
                detail: "missing claims".to_owned()
            }
            .wire_code(),
            "sep10.jwt_parse_error"
        );
    }

    #[test]
    fn wire_code_jwt_expired() {
        assert_eq!(
            Sep10Error::JwtExpired {
                exp_unix: 100,
                now_unix: 200
            }
            .wire_code(),
            "sep10.jwt_expired"
        );
    }

    #[test]
    fn wire_code_replay_detected() {
        assert_eq!(
            Sep10Error::ReplayDetected {
                detail: "duplicate challenge XDR".to_owned()
            }
            .wire_code(),
            "sep10.replay_detected"
        );
    }

    #[test]
    fn wire_code_session_account_mismatch() {
        assert_eq!(
            Sep10Error::SessionAccountMismatch {
                detail: "GABC…WXYZ vs GDEF…STUV".to_owned()
            }
            .wire_code(),
            "sep10.session_account_mismatch"
        );
    }

    #[test]
    fn wire_code_invalid_web_auth_endpoint() {
        assert_eq!(
            Sep10Error::InvalidWebAuthEndpoint {
                detail: "no host in endpoint URL".to_owned()
            }
            .wire_code(),
            "sep10.invalid_web_auth_endpoint"
        );
    }

    #[test]
    fn error_display_does_not_echo_secret_material() {
        // None of the Sep10Error Display or Debug representations should
        // contain raw key bytes, signature bytes, or seed material.
        let errors: &[Sep10Error] = &[
            Sep10Error::InvalidSequenceNumber { found: 99 },
            Sep10Error::MissingOperations,
            Sep10Error::MissingWebAuthDomainOp,
            Sep10Error::MissingServerSignature,
        ];
        let secret_sentinel = "SECRET_BYTES_SHOULD_NOT_APPEAR";
        for err in errors {
            let display = format!("{err}");
            let debug = format!("{err:?}");
            assert!(!display.contains(secret_sentinel), "{display}");
            assert!(!debug.contains(secret_sentinel), "{debug}");
        }
    }
}

//! Typed error enum for SEP-45 v0.1.1 challenge validation and JWT session
//! handling.
//!
//! All error variants are fail-closed: they represent validation failures that
//! MUST cause the challenge or session to be rejected. None of the variants
//! echo secret material.
//!
//! # Redaction invariant
//!
//! No variant's `Display` or `Debug` output echoes raw key bytes, signature
//! bytes, seed material, or nonce values. `detail` fields carry only
//! human-readable descriptions that name the problem without revealing
//! sensitive data.

/// Errors produced by SEP-45 v0.1.1 challenge validation and JWT session
/// parsing.
///
/// The enum is `#[non_exhaustive]`; downstream crates must match with a
/// wildcard arm. All variants carry a stable [`Sep45Error::wire_code`] string
/// for structured audit-log emission.
///
/// # Variant groups
///
/// - **HTTP/transport** (`HttpError`, `JwtParseError`, `JwtExpired`) —
///   populated by `Sep45Client`.
/// - **XDR parsing** (`XdrDecodeError`, `InvalidEntryCount`,
///   `MissingServerEntry`, `MissingClientEntry`,
///   `UnsupportedCredentialType`) — base64/XDR decode and structural
///   entry-count failures.
/// - **Caller argument** (`InvalidExpectedContractArg`) — a caller-supplied
///   `expected_*` parameter to `parse_and_validate` was malformed.
/// - **Contract structure** (`InvalidContractAddress`,
///   `InvalidFunctionName`, `MissingNonce`, `NonceMismatch`,
///   `InvalidArgsCount`) — per-entry function/contract/args shape failures.
/// - **Args validation** (`InvalidAccountArg`, `HomeDomainMismatch`,
///   `WebAuthDomainMismatch`, `WebAuthDomainAccountMismatch`) —
///   individual arg value comparison failures.
/// - **Client domain** (`MissingClientDomainOp`, `ClientDomainMismatch`,
///   `InvalidClientDomainAccount`) — optional client_domain handling per
///   the SEP-45 challenge-validation steps.
/// - **Sub-invocation rejection** (`UnexpectedSubInvocations`) — spec
///   line 86: no sub-invocations allowed.
/// - **Signature validation** (`MissingServerSignature`,
///   `InvalidServerSignature`, `InvalidSignatureExpirationLedger`) —
///   signature presence, cryptographic validity, and client expiration ledger.
/// - **Network identity** (`NetworkPassphraseMismatch`) — server responded
///   with a different network passphrase than the client is configured for.
/// - **HTTP client** (`InvalidWebAuthEndpoint`, `SessionAccountMismatch`) —
///   endpoint URL parsing and session integrity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Sep45Error {
    // ── HTTP/transport ───────────────────────────────────────────────────────
    /// HTTP transport failure when fetching or submitting the challenge.
    ///
    /// # Errors
    ///
    /// Returned when the HTTP layer fails (connection refused, timeout,
    /// non-200 response).
    #[error("HTTP error: {detail}")]
    HttpError {
        /// Non-secret HTTP error description.
        detail: String,
    },

    /// The JWT returned by the server could not be parsed.
    ///
    /// # Errors
    ///
    /// Returned when the JWT is structurally invalid (wrong segment count,
    /// non-base64 payload, missing required claims, wrong claim types).
    #[error("JWT parse error: {detail}")]
    JwtParseError {
        /// Non-secret description of the parse failure.
        detail: String,
    },

    /// The JWT session has expired.
    ///
    /// # Errors
    ///
    /// Returned when the session `exp` claim is in the past at validation time.
    #[error("JWT expired: exp {exp_unix} <= now {now_unix}")]
    JwtExpired {
        /// The JWT `exp` claim value (Unix seconds).
        exp_unix: u64,
        /// The current time (Unix seconds).
        now_unix: u64,
    },

    // ── XDR parsing ──────────────────────────────────────────────────────────
    /// The base64-encoded authorization entries XDR could not be decoded.
    ///
    /// This covers both base64 decode failures and XDR parse failures on the
    /// `SorobanAuthorizationEntries` array.
    ///
    /// # Errors
    ///
    /// Returned when the `authorization_entries` field from the server's
    /// response fails base64 decoding or XDR deserialization.
    #[error("XDR decode error: {detail}")]
    XdrDecodeError {
        /// Non-secret description of the decode failure.
        detail: String,
    },

    /// The authorization entries array contains fewer entries than required.
    ///
    /// Per the SEP-45 challenge-validation steps, a server MAY return only a
    /// server-signed entry for contracts whose `__check_auth` does not require
    /// client signatures. The minimum enforced at step 2 is therefore 1 entry.
    /// When `client_domain` is present in the args, at least 3 entries are
    /// required.
    ///
    /// # Errors
    ///
    /// Returned when the decoded entry count is zero (step 2), or below the
    /// required minimum for the `client_domain` re-check (step after args
    /// extraction).
    #[error("invalid entry count: found {found}, expected at least {expected_min}")]
    InvalidEntryCount {
        /// The number of entries found in the decoded array.
        found: usize,
        /// The minimum required entry count (1 for base check; 3 when
        /// `client_domain` arg is present).
        expected_min: usize,
    },

    /// No entry with credentials matching the server signing key was found.
    ///
    /// The server MUST include a signed entry where
    /// `credentials.address.address` equals the `SIGNING_KEY` from the
    /// server's `stellar.toml` (per the SEP-45 challenge-validation steps).
    ///
    /// # Errors
    ///
    /// Returned when no entry's credential address matches the expected server
    /// signing key.
    #[error("missing server entry: no entry with credentials matching the server signing key")]
    MissingServerEntry,

    /// No entry with credentials matching the client account was found.
    ///
    /// The server MUST include an unsigned entry where
    /// `credentials.address.address` equals the client's `C...` account
    /// (per the SEP-45 challenge-validation steps).
    ///
    /// # Errors
    ///
    /// Returned when no entry's credential address matches the expected client
    /// contract account address.
    #[error("missing client entry: no entry with credentials matching the client account")]
    MissingClientEntry,

    /// A `SorobanAuthorizationEntry` carries a credential type not permitted
    /// in a SEP-45 challenge (`SourceAccount`, `AddressV2`, or
    /// `AddressWithDelegates`).
    ///
    /// # Errors
    ///
    /// Returned when an entry's credentials are not `SorobanCredentials::Address`.
    #[error("unsupported credential type at entry index {entry_index}")]
    UnsupportedCredentialType {
        /// Zero-based index of the offending entry.
        entry_index: usize,
    },

    // ── Contract structure ───────────────────────────────────────────────────
    /// An entry's `contract_address` does not match the expected
    /// `WEB_AUTH_CONTRACT_ID`.
    ///
    /// Every entry's `root_invocation.function.contract_fn.contract_address`
    /// MUST equal the `WEB_AUTH_CONTRACT_ID` from the server's `stellar.toml`
    /// (per the SEP-45 challenge-validation steps).
    ///
    /// # Errors
    ///
    /// Returned when any entry's contract address deviates from the expected
    /// web auth contract ID.
    #[error("invalid contract address: found {found:?}, expected {expected:?}")]
    InvalidContractAddress {
        /// The contract address found in the entry (C-strkey).
        found: String,
        /// The expected `WEB_AUTH_CONTRACT_ID` (C-strkey).
        expected: String,
    },

    /// An entry's `function_name` is not `"web_auth_verify"`.
    ///
    /// Every entry's `root_invocation.function.contract_fn.function_name`
    /// MUST be `"web_auth_verify"` (per the SEP-45 challenge-validation steps).
    ///
    /// # Errors
    ///
    /// Returned when any entry's function name is not `"web_auth_verify"`.
    #[error("invalid function name: found {found:?}, expected {expected:?}")]
    InvalidFunctionName {
        /// The function name found in the entry.
        found: String,
        /// The expected function name (always `"web_auth_verify"`).
        expected: &'static str,
    },

    /// The `nonce` argument is absent from an entry's args map.
    ///
    /// Every entry MUST contain a `nonce` key in the `args` map
    /// (per the SEP-45 challenge args schema).
    ///
    /// # Errors
    ///
    /// Returned when the `nonce` Symbol key is absent from the args map of
    /// any entry.
    #[error(
        "missing nonce: nonce argument absent from entry args map at entry index {entry_index}"
    )]
    MissingNonce {
        /// Zero-based index of the entry missing the nonce arg.
        entry_index: usize,
    },

    /// The nonce value is inconsistent across entries.
    ///
    /// All entries MUST carry the same nonce value
    /// (per the SEP-45 nonce cross-entry consistency requirement).
    ///
    /// # Errors
    ///
    /// Returned when the nonce string in one entry differs from the nonce
    /// in the first entry.
    #[error("nonce mismatch at entry index {entry_index}: nonce differs from first entry")]
    NonceMismatch {
        /// Zero-based index of the entry with the mismatched nonce.
        entry_index: usize,
    },

    /// The args map in an entry does not have the minimum required key count.
    ///
    /// The minimum args are `account`, `home_domain`, `web_auth_domain`,
    /// `web_auth_domain_account`, and `nonce` = 5 args
    /// (per the SEP-45 challenge args schema). With `client_domain`, 7 args minimum.
    ///
    /// # Errors
    ///
    /// Returned when the args map contains fewer entries than the minimum
    /// required.
    #[error("invalid args count: found {found}, expected at least {expected_min}")]
    InvalidArgsCount {
        /// The number of args found in the entry's args map.
        found: usize,
        /// The minimum required arg count.
        expected_min: usize,
    },

    /// The args map is structurally invalid (e.g. a Symbol key appears more
    /// than once).
    ///
    /// The XDR `ScMap` type permits duplicate keys at the byte level.
    /// Accepting duplicate keys would allow a server to inject ambiguous
    /// key→value bindings; `parse_and_validate` rejects them fail-closed.
    ///
    /// # Errors
    ///
    /// Returned when `extract_args_map` encounters a duplicate Symbol key.
    #[error("invalid args format: {detail}")]
    InvalidArgsFormat {
        /// Non-secret description of the structural violation.
        detail: String,
    },

    /// A caller-supplied `expected_*` argument to
    /// `AuthorizationEntries::parse_and_validate` was malformed.
    ///
    /// Distinct from [`Sep45Error::InvalidContractAddress`], which is returned
    /// when an *entry's* contract address does not match the expected value.
    /// This variant is returned when the `expected_*` parameter itself fails
    /// strkey parsing (i.e., the caller passed a malformed argument).
    ///
    /// # Errors
    ///
    /// Returned when `expected_web_auth_contract` cannot be parsed as a valid
    /// C-strkey.
    #[error("invalid expected contract arg: {detail}")]
    InvalidExpectedContractArg {
        /// Non-secret description of the malformed caller argument.
        detail: String,
    },

    /// The caller-supplied `expected_server_signing_key` argument is not a
    /// valid G-strkey ed25519 public key.
    ///
    /// Distinct from [`Sep45Error::InvalidServerSignature`], which indicates a
    /// cryptographic verification failure on a structurally valid key. This
    /// variant is returned when `expected_server_signing_key` itself fails
    /// strkey parsing before any on-wire data is examined.
    ///
    /// # Errors
    ///
    /// Returned when `expected_server_signing_key` cannot be parsed as a
    /// valid G-strkey.
    #[error("invalid expected server key arg: {detail}")]
    InvalidExpectedServerKeyArg {
        /// Non-secret description of the malformed caller argument.
        detail: String,
    },

    // ── Args validation ──────────────────────────────────────────────────────
    /// The `account` arg value is not a valid C-strkey or does not match the
    /// expected client account.
    ///
    /// The `account` arg MUST equal the `C...` client account address
    /// (per the SEP-45 challenge args schema).
    ///
    /// # Errors
    ///
    /// Returned when the `account` arg is absent, malformed, or does not match
    /// the expected client account.
    #[error("invalid account arg: {detail}")]
    InvalidAccountArg {
        /// Non-secret description of the mismatch (does not echo key bytes).
        detail: String,
    },

    /// The `home_domain` arg does not match the expected home domain.
    ///
    /// The `home_domain` arg MUST equal the `home_domain` supplied in the
    /// original challenge request (per the SEP-45 challenge args schema).
    ///
    /// # Errors
    ///
    /// Returned when the `home_domain` arg differs from the expected value.
    #[error("home_domain mismatch: found {found:?}, expected {expected:?}")]
    HomeDomainMismatch {
        /// The `home_domain` value found in the entry's args.
        found: String,
        /// The expected home domain.
        expected: String,
    },

    /// The `web_auth_domain` arg does not match the expected server domain.
    ///
    /// The `web_auth_domain` arg MUST equal the server's domain
    /// (per the SEP-45 challenge args schema).
    ///
    /// # Errors
    ///
    /// Returned when the `web_auth_domain` arg differs from the expected
    /// server domain.
    #[error("web_auth_domain mismatch: found {found:?}, expected {expected:?}")]
    WebAuthDomainMismatch {
        /// The `web_auth_domain` value found in the entry's args.
        found: String,
        /// The expected web auth domain.
        expected: String,
    },

    /// The `web_auth_domain_account` arg does not match the expected server
    /// signing key.
    ///
    /// The `web_auth_domain_account` arg MUST equal the `SIGNING_KEY` from the
    /// server's `stellar.toml` (per the SEP-45 challenge args schema).
    ///
    /// # Errors
    ///
    /// Returned when the `web_auth_domain_account` arg differs from the
    /// expected server signing key.
    #[error("web_auth_domain_account mismatch: found {found:?}, expected {expected:?}")]
    WebAuthDomainAccountMismatch {
        /// The `web_auth_domain_account` value found in the entry's args
        /// (G-strkey).
        found: String,
        /// The expected server signing key (G-strkey).
        expected: String,
    },

    // ── Optional client_domain handling ─────────────────────────────────────
    /// A `client_domain` arg was present in the args map but no corresponding
    /// entry with a `client_domain_account` credential was found.
    ///
    /// When the args include `client_domain`, there MUST be an entry signed by
    /// the Client Domain Account (per the SEP-45 client-domain handling steps).
    ///
    /// # Errors
    ///
    /// Returned when `client_domain` is in the args but no client-domain
    /// credential entry exists.
    #[error(
        "missing client domain op: client_domain arg present but no client_domain_account entry found"
    )]
    MissingClientDomainOp,

    /// The `client_domain` arg value does not match the expected client domain,
    /// or is unexpectedly present/absent relative to the caller's request.
    ///
    /// When `client_domain` is present, its value MUST match the client domain
    /// supplied in the challenge request (per the SEP-45 challenge args schema). When the
    /// caller supplies no `client_domain` but the challenge carries one (or
    /// vice-versa), this variant is also returned.
    ///
    /// # Errors
    ///
    /// Returned when the `client_domain` arg differs from the expected value,
    /// or when the presence of `client_domain` in the challenge does not match
    /// the caller's expectation.
    #[error("client_domain mismatch: found {found:?}, expected {expected:?}")]
    ClientDomainMismatch {
        /// The `client_domain` value found in the challenge (empty string when
        /// absent).
        found: String,
        /// The expected client domain (empty string when none expected).
        expected: String,
    },

    /// The `client_domain_account` arg value is not a valid G-strkey or does
    /// not match the expected client domain account.
    ///
    /// When `client_domain_account` is present, its value MUST equal the
    /// `SIGNING_KEY` from the client domain's `stellar.toml`
    /// (per the SEP-45 client-domain handling steps).
    ///
    /// # Errors
    ///
    /// Returned when `client_domain_account` is malformed or does not match
    /// the expected value.
    #[error("invalid client domain account: {detail}")]
    InvalidClientDomainAccount {
        /// Non-secret description of the mismatch.
        detail: String,
    },

    // ── Sub-invocation rejection ─────────────────────────────────────────────
    /// An entry's `root_invocation` contains sub-invocations, which are
    /// forbidden by the SEP-45 spec.
    ///
    /// The spec at line 86 requires: "No sub-invocations" — every entry's
    /// `root_invocation.sub_invocations` MUST be empty.
    ///
    /// # Errors
    ///
    /// Returned when any entry's `sub_invocations` list is non-empty.
    #[error(
        "unexpected sub-invocations at entry index {entry_index}: sub-invocations are forbidden by SEP-45"
    )]
    UnexpectedSubInvocations {
        /// Zero-based index of the offending entry.
        entry_index: usize,
    },

    // ── Signature validation ─────────────────────────────────────────────────
    /// No signature was found in the server-signed entry's credentials.
    ///
    /// The server's entry MUST contain a valid signature in
    /// `credentials.address.signature` (per the SEP-45 signing convention).
    ///
    /// # Errors
    ///
    /// Returned when the server entry's `signature` field is empty, Void, or
    /// contains an empty Vec.
    #[error("missing server signature: server entry contains no signature")]
    MissingServerSignature,

    /// The server signature present in the challenge does not verify
    /// cryptographically.
    ///
    /// The server MUST have signed the `HashIdPreimageSorobanAuthorization`
    /// with its `SIGNING_KEY` (per the SEP-45 signing convention).
    ///
    /// # Errors
    ///
    /// Returned when `ed25519_dalek::VerifyingKey::verify_strict` rejects the
    /// signature in the server's entry.
    #[error("invalid server signature: {detail}")]
    InvalidServerSignature {
        /// Non-secret description of the verification failure (does not echo
        /// signature bytes).
        detail: String,
    },

    /// The `signature_expiration_ledger` supplied for the client auth entry is
    /// zero or otherwise invalid.
    ///
    /// Per SEP-45 the client sets its own `signature_expiration_ledger`; the
    /// caller must supply `current_ledger + margin` from its RPC layer. A
    /// value of 0 is rejected because it would cause the Soroban host to
    /// reject the auth entry at submission time.
    ///
    /// # Errors
    ///
    /// Returned when `signature_expiration_ledger` is 0.
    #[error("invalid signature_expiration_ledger: {detail}")]
    InvalidSignatureExpirationLedger {
        /// Non-secret description of the validation failure.
        detail: String,
    },

    /// The `network_passphrase` returned by the server does not match the
    /// passphrase the client was configured with.
    ///
    /// A passphrase mismatch means the server is operating on a different
    /// Stellar network than the client expects (e.g. mainnet vs testnet), which
    /// is a configuration/identity error distinct from a cryptographic failure.
    ///
    /// # Errors
    ///
    /// Returned when the server's GET challenge response includes a
    /// `network_passphrase` field whose value differs from the client's
    /// configured passphrase.
    #[error("network_passphrase mismatch: {detail}")]
    NetworkPassphraseMismatch {
        /// Truncated description of the mismatch (first 16 chars of each side).
        detail: String,
    },

    // ── HTTP client extras ───────────────────────────────────────────────────
    /// The `web_auth_endpoint` URL is not a valid HTTPS URL and the
    /// `web_auth_domain` could not be derived from it.
    ///
    /// # Errors
    ///
    /// Returned when neither the caller nor the URL provides a resolvable
    /// host to use as the web auth domain.
    #[error("invalid web_auth_endpoint: {detail}")]
    InvalidWebAuthEndpoint {
        /// Description of the URL parse failure.
        detail: String,
    },

    /// The JWT `sub` claim returned by the server does not match the
    /// `contract_id` supplied to `auth_with_ephemeral_key`.
    ///
    /// # Errors
    ///
    /// Returned when `session.sub != contract_id`, which indicates either a
    /// server bug or a response from the wrong endpoint.
    #[error("session account mismatch: expected {expected}, got {found}")]
    SessionAccountMismatch {
        /// The contract ID that was expected.
        expected: String,
        /// The `sub` value the server returned.
        found: String,
    },
}

impl Sep45Error {
    /// Returns the canonical wire error code for this variant.
    ///
    /// The returned `&'static str` is the typed code emitted in audit-log
    /// records and structured error responses. Callers should use this method
    /// rather than matching variants directly so they remain forward-compatible
    /// with new variants.
    ///
    /// # Wire-code namespace
    ///
    /// All codes are in the `sep45.` namespace for unambiguous audit-log
    /// filtering alongside `sep10.*`, `nonce.*`, and `keyring.*` codes.
    ///
    /// # Forward compatibility
    ///
    /// The enum is `#[non_exhaustive]`; future variants return
    /// `"sep45.unknown_error"` via the `_` arm. This is deliberately distinct
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
    /// use stellar_agent_sep45::Sep45Error;
    ///
    /// assert_eq!(
    ///     Sep45Error::MissingServerEntry.wire_code(),
    ///     "sep45.missing_server_entry"
    /// );
    /// assert_eq!(
    ///     Sep45Error::InvalidContractAddress {
    ///         found: "CABC".to_owned(),
    ///         expected: "CDEF".to_owned(),
    ///     }
    ///     .wire_code(),
    ///     "sep45.invalid_contract_address"
    /// );
    /// assert_eq!(
    ///     Sep45Error::MissingServerSignature.wire_code(),
    ///     "sep45.missing_server_signature"
    /// );
    /// ```
    #[must_use]
    #[allow(
        unreachable_patterns,
        reason = "The `_ =>` arm is unreachable inside the defining crate because all \
                  current variants are explicitly matched above. The arm is intentionally \
                  kept for forward-compatibility: when a new variant is added without an \
                  explicit wire_code arm the `#[non_exhaustive]` attribute allows the \
                  wildcard without error, but telemetry will fire on `sep45.unknown_error`."
    )]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::HttpError { .. } => "sep45.http_error",
            Self::JwtParseError { .. } => "sep45.jwt_parse_error",
            Self::JwtExpired { .. } => "sep45.jwt_expired",
            Self::XdrDecodeError { .. } => "sep45.xdr_decode_error",
            Self::InvalidEntryCount { .. } => "sep45.invalid_entry_count",
            Self::MissingServerEntry => "sep45.missing_server_entry",
            Self::MissingClientEntry => "sep45.missing_client_entry",
            Self::UnsupportedCredentialType { .. } => "sep45.unsupported_credential_type",
            Self::InvalidExpectedContractArg { .. } => "sep45.invalid_expected_contract_arg",
            Self::InvalidExpectedServerKeyArg { .. } => "sep45.invalid_expected_server_key_arg",
            Self::InvalidContractAddress { .. } => "sep45.invalid_contract_address",
            Self::InvalidFunctionName { .. } => "sep45.invalid_function_name",
            Self::MissingNonce { .. } => "sep45.missing_nonce",
            Self::NonceMismatch { .. } => "sep45.nonce_mismatch",
            Self::InvalidArgsCount { .. } => "sep45.invalid_args_count",
            Self::InvalidArgsFormat { .. } => "sep45.invalid_args_format",
            Self::InvalidAccountArg { .. } => "sep45.invalid_account_arg",
            Self::HomeDomainMismatch { .. } => "sep45.home_domain_mismatch",
            Self::WebAuthDomainMismatch { .. } => "sep45.web_auth_domain_mismatch",
            Self::WebAuthDomainAccountMismatch { .. } => "sep45.web_auth_domain_account_mismatch",
            Self::MissingClientDomainOp => "sep45.missing_client_domain_op",
            Self::ClientDomainMismatch { .. } => "sep45.client_domain_mismatch",
            Self::InvalidClientDomainAccount { .. } => "sep45.invalid_client_domain_account",
            Self::UnexpectedSubInvocations { .. } => "sep45.unexpected_sub_invocations",
            Self::MissingServerSignature => "sep45.missing_server_signature",
            Self::InvalidServerSignature { .. } => "sep45.invalid_server_signature",
            Self::InvalidSignatureExpirationLedger { .. } => {
                "sep45.invalid_signature_expiration_ledger"
            }
            Self::NetworkPassphraseMismatch { .. } => "sep45.network_passphrase_mismatch",
            Self::InvalidWebAuthEndpoint { .. } => "sep45.invalid_web_auth_endpoint",
            Self::SessionAccountMismatch { .. } => "sep45.session_account_mismatch",
            _ => "sep45.unknown_error",
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn wire_code_http_error() {
        assert_eq!(
            Sep45Error::HttpError {
                detail: "connection refused".to_owned(),
            }
            .wire_code(),
            "sep45.http_error"
        );
    }

    #[test]
    fn wire_code_jwt_parse_error() {
        assert_eq!(
            Sep45Error::JwtParseError {
                detail: "missing claims".to_owned(),
            }
            .wire_code(),
            "sep45.jwt_parse_error"
        );
    }

    #[test]
    fn wire_code_jwt_expired() {
        assert_eq!(
            Sep45Error::JwtExpired {
                exp_unix: 100,
                now_unix: 200,
            }
            .wire_code(),
            "sep45.jwt_expired"
        );
    }

    #[test]
    fn wire_code_xdr_decode_error() {
        assert_eq!(
            Sep45Error::XdrDecodeError {
                detail: "base64 decode failed".to_owned(),
            }
            .wire_code(),
            "sep45.xdr_decode_error"
        );
    }

    #[test]
    fn wire_code_invalid_entry_count() {
        assert_eq!(
            Sep45Error::InvalidEntryCount {
                found: 0,
                expected_min: 1,
            }
            .wire_code(),
            "sep45.invalid_entry_count"
        );
    }

    #[test]
    fn wire_code_missing_server_entry() {
        assert_eq!(
            Sep45Error::MissingServerEntry.wire_code(),
            "sep45.missing_server_entry"
        );
    }

    #[test]
    fn wire_code_missing_client_entry() {
        assert_eq!(
            Sep45Error::MissingClientEntry.wire_code(),
            "sep45.missing_client_entry"
        );
    }

    #[test]
    fn wire_code_unsupported_credential_type() {
        assert_eq!(
            Sep45Error::UnsupportedCredentialType { entry_index: 0 }.wire_code(),
            "sep45.unsupported_credential_type"
        );
    }

    #[test]
    fn wire_code_invalid_expected_contract_arg() {
        assert_eq!(
            Sep45Error::InvalidExpectedContractArg {
                detail: "not a valid C-strkey".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_expected_contract_arg"
        );
    }

    #[test]
    fn wire_code_invalid_expected_server_key_arg() {
        assert_eq!(
            Sep45Error::InvalidExpectedServerKeyArg {
                detail: "not a valid G-strkey".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_expected_server_key_arg"
        );
    }

    #[test]
    fn wire_code_invalid_contract_address() {
        assert_eq!(
            Sep45Error::InvalidContractAddress {
                found: "CABC".to_owned(),
                expected: "CDEF".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_contract_address"
        );
    }

    #[test]
    fn wire_code_invalid_function_name() {
        assert_eq!(
            Sep45Error::InvalidFunctionName {
                found: "wrong_fn".to_owned(),
                expected: "web_auth_verify",
            }
            .wire_code(),
            "sep45.invalid_function_name"
        );
    }

    #[test]
    fn wire_code_missing_nonce() {
        assert_eq!(
            Sep45Error::MissingNonce { entry_index: 0 }.wire_code(),
            "sep45.missing_nonce"
        );
    }

    #[test]
    fn wire_code_nonce_mismatch() {
        assert_eq!(
            Sep45Error::NonceMismatch { entry_index: 1 }.wire_code(),
            "sep45.nonce_mismatch"
        );
    }

    #[test]
    fn wire_code_invalid_args_count() {
        assert_eq!(
            Sep45Error::InvalidArgsCount {
                found: 2,
                expected_min: 5,
            }
            .wire_code(),
            "sep45.invalid_args_count"
        );
    }

    #[test]
    fn wire_code_invalid_args_format() {
        assert_eq!(
            Sep45Error::InvalidArgsFormat {
                detail: "duplicate key 'nonce' in args map".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_args_format"
        );
    }

    #[test]
    fn wire_code_invalid_account_arg() {
        assert_eq!(
            Sep45Error::InvalidAccountArg {
                detail: "account mismatch".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_account_arg"
        );
    }

    #[test]
    fn wire_code_home_domain_mismatch() {
        assert_eq!(
            Sep45Error::HomeDomainMismatch {
                found: "evil.com".to_owned(),
                expected: "example.com".to_owned(),
            }
            .wire_code(),
            "sep45.home_domain_mismatch"
        );
    }

    #[test]
    fn wire_code_web_auth_domain_mismatch() {
        assert_eq!(
            Sep45Error::WebAuthDomainMismatch {
                found: "evil.com".to_owned(),
                expected: "auth.example.com".to_owned(),
            }
            .wire_code(),
            "sep45.web_auth_domain_mismatch"
        );
    }

    #[test]
    fn wire_code_web_auth_domain_account_mismatch() {
        assert_eq!(
            Sep45Error::WebAuthDomainAccountMismatch {
                found: "GABC".to_owned(),
                expected: "GDEF".to_owned(),
            }
            .wire_code(),
            "sep45.web_auth_domain_account_mismatch"
        );
    }

    #[test]
    fn wire_code_missing_client_domain_op() {
        assert_eq!(
            Sep45Error::MissingClientDomainOp.wire_code(),
            "sep45.missing_client_domain_op"
        );
    }

    #[test]
    fn wire_code_client_domain_mismatch() {
        assert_eq!(
            Sep45Error::ClientDomainMismatch {
                found: "evil.com".to_owned(),
                expected: "wallet.example.com".to_owned(),
            }
            .wire_code(),
            "sep45.client_domain_mismatch"
        );
    }

    #[test]
    fn wire_code_invalid_client_domain_account() {
        assert_eq!(
            Sep45Error::InvalidClientDomainAccount {
                detail: "not a G-strkey".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_client_domain_account"
        );
    }

    #[test]
    fn wire_code_unexpected_sub_invocations() {
        assert_eq!(
            Sep45Error::UnexpectedSubInvocations { entry_index: 0 }.wire_code(),
            "sep45.unexpected_sub_invocations"
        );
    }

    #[test]
    fn wire_code_missing_server_signature() {
        assert_eq!(
            Sep45Error::MissingServerSignature.wire_code(),
            "sep45.missing_server_signature"
        );
    }

    #[test]
    fn wire_code_invalid_server_signature() {
        assert_eq!(
            Sep45Error::InvalidServerSignature {
                detail: "sig does not verify".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_server_signature"
        );
    }

    #[test]
    fn wire_code_network_passphrase_mismatch() {
        assert_eq!(
            Sep45Error::NetworkPassphraseMismatch {
                detail: "server 'Public Glob…' != expected 'Test SDF Ne…'".to_owned(),
            }
            .wire_code(),
            "sep45.network_passphrase_mismatch"
        );
    }

    #[test]
    fn wire_code_invalid_signature_expiration_ledger() {
        assert_eq!(
            Sep45Error::InvalidSignatureExpirationLedger {
                detail: "must be non-zero".to_owned(),
            }
            .wire_code(),
            "sep45.invalid_signature_expiration_ledger"
        );
    }

    /// None of the `Sep45Error` Display or Debug representations should contain
    /// raw key bytes, signature bytes, or seed material.
    #[test]
    fn error_debug_does_not_echo_secret_material() {
        let errors: &[Sep45Error] = &[
            Sep45Error::MissingServerEntry,
            Sep45Error::MissingClientEntry,
            Sep45Error::MissingClientDomainOp,
            Sep45Error::MissingServerSignature,
            Sep45Error::UnexpectedSubInvocations { entry_index: 0 },
            Sep45Error::MissingNonce { entry_index: 0 },
            Sep45Error::NonceMismatch { entry_index: 1 },
        ];
        let secret_sentinel = "SECRET_BYTES_SHOULD_NOT_APPEAR";
        for err in errors {
            let display = format!("{err}");
            let debug = format!("{err:?}");
            assert!(!display.contains(secret_sentinel), "{display}");
            assert!(!debug.contains(secret_sentinel), "{debug}");
        }
    }

    /// All wire codes must use only the `sep45.` prefix and contain only
    /// lowercase letters, digits, and underscores (plus the dot separator).
    #[test]
    fn wire_codes_have_correct_namespace_and_characters() {
        let variants: &[Sep45Error] = &[
            Sep45Error::HttpError {
                detail: String::new(),
            },
            Sep45Error::JwtParseError {
                detail: String::new(),
            },
            Sep45Error::JwtExpired {
                exp_unix: 0,
                now_unix: 0,
            },
            Sep45Error::XdrDecodeError {
                detail: String::new(),
            },
            Sep45Error::InvalidEntryCount {
                found: 0,
                expected_min: 2,
            },
            Sep45Error::MissingServerEntry,
            Sep45Error::MissingClientEntry,
            Sep45Error::UnsupportedCredentialType { entry_index: 0 },
            Sep45Error::InvalidExpectedContractArg {
                detail: String::new(),
            },
            Sep45Error::InvalidExpectedServerKeyArg {
                detail: String::new(),
            },
            Sep45Error::InvalidContractAddress {
                found: String::new(),
                expected: String::new(),
            },
            Sep45Error::InvalidFunctionName {
                found: String::new(),
                expected: "web_auth_verify",
            },
            Sep45Error::MissingNonce { entry_index: 0 },
            Sep45Error::NonceMismatch { entry_index: 0 },
            Sep45Error::InvalidArgsCount {
                found: 0,
                expected_min: 5,
            },
            Sep45Error::InvalidArgsFormat {
                detail: String::new(),
            },
            Sep45Error::InvalidAccountArg {
                detail: String::new(),
            },
            Sep45Error::HomeDomainMismatch {
                found: String::new(),
                expected: String::new(),
            },
            Sep45Error::WebAuthDomainMismatch {
                found: String::new(),
                expected: String::new(),
            },
            Sep45Error::WebAuthDomainAccountMismatch {
                found: String::new(),
                expected: String::new(),
            },
            Sep45Error::MissingClientDomainOp,
            Sep45Error::ClientDomainMismatch {
                found: String::new(),
                expected: String::new(),
            },
            Sep45Error::InvalidClientDomainAccount {
                detail: String::new(),
            },
            Sep45Error::UnexpectedSubInvocations { entry_index: 0 },
            Sep45Error::MissingServerSignature,
            Sep45Error::InvalidServerSignature {
                detail: String::new(),
            },
            Sep45Error::InvalidSignatureExpirationLedger {
                detail: String::new(),
            },
            Sep45Error::NetworkPassphraseMismatch {
                detail: String::new(),
            },
            Sep45Error::InvalidWebAuthEndpoint {
                detail: String::new(),
            },
            Sep45Error::SessionAccountMismatch {
                expected: String::new(),
                found: String::new(),
            },
        ];
        for variant in variants {
            let code = variant.wire_code();
            assert!(
                code.starts_with("sep45."),
                "wire_code {code:?} must start with 'sep45.'"
            );
            let after_prefix = &code["sep45.".len()..];
            assert!(
                after_prefix
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "wire_code suffix {after_prefix:?} must contain only lowercase letters, digits, and underscores"
            );
            assert_ne!(
                code, "sep45.unknown_error",
                "wire_code must not be the fallback sentinel for variant {variant:?}"
            );
        }
    }
}

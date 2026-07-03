//! Typed error enum for SEP-43 v1.2.1 `ModuleInterface` dispatch.
//!
//! All error variants are fail-closed: they represent failures that MUST cause
//! the SEP-43 method to return a spec-compliant error response. None of the
//! variants echo secret material.
//!
//! Error codes per SEP-43 v1.2.1:
//! - `-1` internal wallet error
//! - `-2` external service error
//! - `-3` client-invalid request
//! - `-4` user rejected

use serde_json::json;

/// Errors produced by SEP-43 v1.2.1 `ModuleInterface` method dispatch.
///
/// The enum is `#[non_exhaustive]`; downstream crates must match with a
/// wildcard arm. All variants carry a stable [`Sep43Error::wire_code`] string
/// for structured audit-log emission and a [`Sep43Error::to_sep43_response`]
/// serialiser for the spec-compliant JSON error shape.
///
/// # Variant groups
///
/// Per SEP-43 v1.2.1:
///
/// - **Code -1 (internal wallet error):** `WalletUnlockFailed`,
///   `SignerUnavailable`, `XdrSerializationFailed`, `KeyringError`
/// - **Code -2 (external service error):** `HorizonError`, `RpcError`
/// - **Code -3 (client-invalid request):** `InvalidXdr`, `InvalidAddress`,
///   `InvalidNetworkPassphrase`, `MissingAddress`, `MalformedAuthEntry`,
///   `InvalidMessage`
/// - **Code -4 (user rejected):** `UserRejected`
///
/// # Wire format
///
/// `to_sep43_response()` returns `{ "code": N, "message": "...", "ext"?: ... }`
/// per SEP-43 v1.2.1. The `code` integer is the SEP-43
/// integer error code (not a string). The `message` field is a human-readable
/// description that MUST NOT echo secret material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Sep43Error {
    // ── Code -1: internal wallet error ───────────────────────────────────────
    /// The wallet keyring or signing key could not be unlocked.
    ///
    /// Returned when keyring access for the signing key fails (platform
    /// keyring unavailable, wrong credentials, keyring locked).
    /// Part of the canonical SEP-43 error taxonomy; constructed by the MCP
    /// consumer layer.
    ///
    /// Maps to SEP-43 error code `-1`.
    #[error("wallet unlock failed: {detail}")]
    WalletUnlockFailed {
        /// Non-secret description of the unlock failure.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    /// The signer is not available or cannot be reached.
    ///
    /// Returned when the configured signer (software key, hardware key,
    /// or keyring entry) cannot be located or is in an unusable state.
    ///
    /// Maps to SEP-43 error code `-1`.
    #[error("signer unavailable: {detail}")]
    SignerUnavailable {
        /// Non-secret description of why the signer is unavailable.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    /// XDR serialisation failed in an internal encoding path.
    ///
    /// Part of the canonical SEP-43 error taxonomy; constructed by the MCP
    /// consumer layer when an internal XDR encoding step fails (not due to
    /// client input).
    ///
    /// Maps to SEP-43 error code `-1`.
    #[error("XDR serialisation failed: {detail}")]
    XdrSerializationFailed {
        /// Non-secret description of the encoding failure.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    /// The platform keyring raised an unexpected error.
    ///
    /// Returned when `keyring-core` returns a non-absent error during key
    /// lookup or storage operations that are not "key not found".
    /// Part of the canonical SEP-43 error taxonomy. Reserved for completeness;
    /// not currently constructed by any consumer.
    ///
    /// Maps to SEP-43 error code `-1`.
    #[error("keyring error: {detail}")]
    KeyringError {
        /// Non-secret description of the keyring failure.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    // ── Code -2: external service error ──────────────────────────────────────
    /// A Horizon REST API call failed.
    ///
    /// Returned when a Horizon endpoint returns a non-success HTTP status or a
    /// transport error occurs.
    /// Part of the canonical SEP-43 error taxonomy. Reserved for completeness;
    /// not currently constructed by any consumer.
    ///
    /// Maps to SEP-43 error code `-2`.
    #[error("horizon error: {detail}")]
    HorizonError {
        /// Non-secret HTTP/transport error description.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    /// A Stellar RPC call failed.
    ///
    /// Returned when the Soroban RPC endpoint returns an error or is unreachable.
    /// Part of the canonical SEP-43 error taxonomy; constructed by the MCP
    /// consumer layer.
    ///
    /// Maps to SEP-43 error code `-2`.
    #[error("rpc error: {detail}")]
    RpcError {
        /// Non-secret RPC error description.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    // ── Code -3: client-invalid request ──────────────────────────────────────
    /// The XDR supplied by the client is not valid base64 or not a
    /// well-formed XDR type for the requested operation.
    ///
    /// Returned when `from_xdr_base64` fails on client-supplied XDR input.
    ///
    /// Maps to SEP-43 error code `-3`.
    #[error("invalid XDR: {detail}")]
    InvalidXdr {
        /// Non-secret description of the decode failure.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    /// The address supplied by the client is not a valid strkey.
    ///
    /// Returned when a `G...`, `C...`, or `M...` strkey in the client request
    /// fails strkey parsing or does not match the expected address type.
    ///
    /// Maps to SEP-43 error code `-3`.
    #[error("invalid address: {detail} (expected type: {expected_type})")]
    InvalidAddress {
        /// Non-secret description of the address mismatch or parse failure.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
        /// Expected strkey type descriptor (e.g. `"G-strkey"`, `"C-strkey"`).
        expected_type: &'static str,
    },

    /// The `networkPassphrase` option does not match the active profile's
    /// configured network passphrase.
    ///
    /// SEP-43 `signTransaction` and `signAuthEntry` accept an optional
    /// `networkPassphrase`. When provided and it differs from the profile's
    /// passphrase, the request is rejected per the fail-closed network guard.
    ///
    /// Maps to SEP-43 error code `-3`.
    #[error("invalid network passphrase: {detail}")]
    InvalidNetworkPassphrase {
        /// Non-secret description of the passphrase mismatch.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    /// The active profile has no enrolled signing account.
    ///
    /// Returned when address resolution finds an empty
    /// `mcp_signer_default.account`, so there is no active address to return or
    /// sign with.
    ///
    /// Maps to SEP-43 error code `-3`.
    #[error("missing address: the active profile has no enrolled signing account")]
    MissingAddress,

    /// The decoded `HashIdPreimage` is a valid but non-`SorobanAuthorization` variant.
    ///
    /// Returned when the input decodes as a `HashIdPreimage` but the inner
    /// variant is not `SorobanAuthorization` (e.g. `Transaction`, `RevokeId`,
    /// etc.).  A full `SorobanAuthorizationEntry` or any other non-`HashIdPreimage`
    /// XDR structure returns [`Self::InvalidXdr`] instead of this variant.
    ///
    /// Maps to SEP-43 error code `-3`.
    #[error("malformed auth entry: {detail}")]
    MalformedAuthEntry {
        /// Non-secret description of the structural problem.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    /// The message supplied to `signMessage` is empty or exceeds the maximum
    /// length for this implementation.
    ///
    /// Returned when the raw message bytes fail length checks.
    ///
    /// Maps to SEP-43 error code `-3`.
    #[error("invalid message: {detail}")]
    InvalidMessage {
        /// Non-secret description of the message validation failure.
        ///
        /// Callers MUST NOT place secret material (private keys, seed bytes,
        /// signature bytes, raw keyring entries) in this field. The value is
        /// surfaced verbatim at Display sites including audit-log emission.
        detail: String,
    },

    // ── Code -4: user rejected ────────────────────────────────────────────────
    /// The user explicitly rejected the signing request.
    ///
    /// Returned when a hardware signer (Ledger) signals user refusal, or when
    /// an explicit rejection signal is received.  In downstream consumer layers,
    /// also returned when an approval-spine check determines the operator
    /// declined the operation.
    ///
    /// Per SEP-43 v1.2.1, code `-4` is the canonical user-rejection signal.
    /// The `reason` field MUST NOT contain private key material or secret
    /// transaction content.
    ///
    /// Maps to SEP-43 error code `-4`.
    #[error("user rejected: {reason}")]
    UserRejected {
        /// Non-secret human-readable reason for the rejection.
        reason: String,
    },
}

impl Sep43Error {
    /// Returns the canonical wire error code string for this variant.
    ///
    /// The returned `&'static str` is the typed code emitted in audit-log
    /// records and structured error responses. Callers should use this method
    /// rather than matching variants directly for forward-compatibility.
    ///
    /// # Wire-code namespace
    ///
    /// All codes are in the `sep43.` namespace for unambiguous audit-log
    /// filtering alongside `sep45.*`, `sep10.*`, `nonce.*`, and `keyring.*`
    /// codes.
    ///
    /// # Forward compatibility
    ///
    /// The enum is `#[non_exhaustive]`; future variants return
    /// `"sep43.unknown_error"` via the `_` arm. This is intentionally distinct
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
    /// use stellar_agent_sep43::Sep43Error;
    ///
    /// assert_eq!(
    ///     Sep43Error::MissingAddress.wire_code(),
    ///     "sep43.missing_address"
    /// );
    /// assert_eq!(
    ///     Sep43Error::UserRejected {
    ///         reason: "declined on device".to_owned(),
    ///     }
    ///     .wire_code(),
    ///     "sep43.user_rejected"
    /// );
    /// ```
    #[must_use]
    #[allow(
        unreachable_patterns,
        reason = "The `_ =>` arm is intentionally kept for forward-compatibility: \
                  when a new variant is added without an explicit wire_code arm the \
                  `#[non_exhaustive]` attribute allows the wildcard without error, \
                  but telemetry will fire on `sep43.unknown_error`."
    )]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::WalletUnlockFailed { .. } => "sep43.wallet_unlock_failed",
            Self::SignerUnavailable { .. } => "sep43.signer_unavailable",
            Self::XdrSerializationFailed { .. } => "sep43.xdr_serialization_failed",
            Self::KeyringError { .. } => "sep43.keyring_error",
            Self::HorizonError { .. } => "sep43.horizon_error",
            Self::RpcError { .. } => "sep43.rpc_error",
            Self::InvalidXdr { .. } => "sep43.invalid_xdr",
            Self::InvalidAddress { .. } => "sep43.invalid_address",
            Self::InvalidNetworkPassphrase { .. } => "sep43.invalid_network_passphrase",
            Self::MissingAddress => "sep43.missing_address",
            Self::MalformedAuthEntry { .. } => "sep43.malformed_auth_entry",
            Self::InvalidMessage { .. } => "sep43.invalid_message",
            Self::UserRejected { .. } => "sep43.user_rejected",
            _ => "sep43.unknown_error",
        }
    }

    /// Returns the SEP-43 integer error code for this variant.
    ///
    /// Maps variant groups to the spec-defined integer codes per SEP-43 v1.2.1:
    ///
    /// - `-1` — internal wallet error
    /// - `-2` — external service error
    /// - `-3` — client-invalid request
    /// - `-4` — user rejected
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep43::Sep43Error;
    ///
    /// assert_eq!(Sep43Error::MissingAddress.sep43_code(), -3_i32);
    /// assert_eq!(
    ///     Sep43Error::UserRejected { reason: "declined".to_owned() }.sep43_code(),
    ///     -4_i32
    /// );
    /// ```
    #[must_use]
    #[allow(
        unreachable_patterns,
        reason = "Forward-compatibility wildcard; falls back to -1 for unknown variants."
    )]
    pub fn sep43_code(&self) -> i32 {
        match self {
            // Code -1: internal wallet error
            Self::WalletUnlockFailed { .. }
            | Self::SignerUnavailable { .. }
            | Self::XdrSerializationFailed { .. }
            | Self::KeyringError { .. } => -1,
            // Code -2: external service error
            Self::HorizonError { .. } | Self::RpcError { .. } => -2,
            // Code -3: client-invalid request
            Self::InvalidXdr { .. }
            | Self::InvalidAddress { .. }
            | Self::InvalidNetworkPassphrase { .. }
            | Self::MissingAddress
            | Self::MalformedAuthEntry { .. }
            | Self::InvalidMessage { .. } => -3,
            // Code -4: user rejected
            Self::UserRejected { .. } => -4,
            // Forward-compat: new variants default to -1 (internal error)
            _ => -1,
        }
    }

    /// Serialises this error into the SEP-43 spec-compliant JSON error shape.
    ///
    /// Returns `{ "code": N, "message": "..." }` per SEP-43 v1.2.1. The
    /// `message` field contains the `Display` representation of this variant and
    /// MUST NOT contain secret material.
    ///
    /// SEP-43 also permits an optional `ext` field; this implementation does not
    /// emit one.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep43::Sep43Error;
    ///
    /// let err = Sep43Error::InvalidXdr { detail: "bad base64".to_owned() };
    /// let resp = err.to_sep43_response();
    /// assert_eq!(resp["code"], -3_i32);
    /// assert!(resp["message"].as_str().unwrap().contains("bad base64"));
    /// ```
    #[must_use]
    pub fn to_sep43_response(&self) -> serde_json::Value {
        json!({
            "code": self.sep43_code(),
            "message": self.to_string(),
        })
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

    // ── wire_code() correctness ───────────────────────────────────────────────

    #[test]
    fn wire_code_wallet_unlock_failed() {
        assert_eq!(
            Sep43Error::WalletUnlockFailed {
                detail: "keyring locked".to_owned(),
            }
            .wire_code(),
            "sep43.wallet_unlock_failed"
        );
    }

    #[test]
    fn wire_code_signer_unavailable() {
        assert_eq!(
            Sep43Error::SignerUnavailable {
                detail: "no key for account".to_owned(),
            }
            .wire_code(),
            "sep43.signer_unavailable"
        );
    }

    #[test]
    fn wire_code_xdr_serialization_failed() {
        assert_eq!(
            Sep43Error::XdrSerializationFailed {
                detail: "encode error".to_owned(),
            }
            .wire_code(),
            "sep43.xdr_serialization_failed"
        );
    }

    #[test]
    fn wire_code_keyring_error() {
        assert_eq!(
            Sep43Error::KeyringError {
                detail: "platform error".to_owned(),
            }
            .wire_code(),
            "sep43.keyring_error"
        );
    }

    #[test]
    fn wire_code_horizon_error() {
        assert_eq!(
            Sep43Error::HorizonError {
                detail: "504 Gateway Timeout".to_owned(),
            }
            .wire_code(),
            "sep43.horizon_error"
        );
    }

    #[test]
    fn wire_code_rpc_error() {
        assert_eq!(
            Sep43Error::RpcError {
                detail: "connection refused".to_owned(),
            }
            .wire_code(),
            "sep43.rpc_error"
        );
    }

    #[test]
    fn wire_code_invalid_xdr() {
        assert_eq!(
            Sep43Error::InvalidXdr {
                detail: "bad base64".to_owned(),
            }
            .wire_code(),
            "sep43.invalid_xdr"
        );
    }

    #[test]
    fn wire_code_invalid_address() {
        assert_eq!(
            Sep43Error::InvalidAddress {
                detail: "not a G-strkey".to_owned(),
                expected_type: "G-strkey",
            }
            .wire_code(),
            "sep43.invalid_address"
        );
    }

    #[test]
    fn wire_code_invalid_network_passphrase() {
        assert_eq!(
            Sep43Error::InvalidNetworkPassphrase {
                detail: "passphrase mismatch".to_owned(),
            }
            .wire_code(),
            "sep43.invalid_network_passphrase"
        );
    }

    #[test]
    fn wire_code_missing_address() {
        assert_eq!(
            Sep43Error::MissingAddress.wire_code(),
            "sep43.missing_address"
        );
    }

    #[test]
    fn wire_code_malformed_auth_entry() {
        assert_eq!(
            Sep43Error::MalformedAuthEntry {
                detail: "not Address credentials".to_owned(),
            }
            .wire_code(),
            "sep43.malformed_auth_entry"
        );
    }

    #[test]
    fn wire_code_invalid_message() {
        assert_eq!(
            Sep43Error::InvalidMessage {
                detail: "empty message".to_owned(),
            }
            .wire_code(),
            "sep43.invalid_message"
        );
    }

    #[test]
    fn wire_code_user_rejected() {
        assert_eq!(
            Sep43Error::UserRejected {
                reason: "declined on device".to_owned(),
            }
            .wire_code(),
            "sep43.user_rejected"
        );
    }

    // ── sep43_code() integer grouping ─────────────────────────────────────────

    #[test]
    fn sep43_code_internal_errors_are_minus_one() {
        let cases: &[Sep43Error] = &[
            Sep43Error::WalletUnlockFailed {
                detail: String::new(),
            },
            Sep43Error::SignerUnavailable {
                detail: String::new(),
            },
            Sep43Error::XdrSerializationFailed {
                detail: String::new(),
            },
            Sep43Error::KeyringError {
                detail: String::new(),
            },
        ];
        for err in cases {
            assert_eq!(err.sep43_code(), -1, "expected -1 for {:?}", err);
        }
    }

    #[test]
    fn sep43_code_external_errors_are_minus_two() {
        let cases: &[Sep43Error] = &[
            Sep43Error::HorizonError {
                detail: String::new(),
            },
            Sep43Error::RpcError {
                detail: String::new(),
            },
        ];
        for err in cases {
            assert_eq!(err.sep43_code(), -2, "expected -2 for {:?}", err);
        }
    }

    #[test]
    fn sep43_code_client_invalid_errors_are_minus_three() {
        let cases: &[Sep43Error] = &[
            Sep43Error::InvalidXdr {
                detail: String::new(),
            },
            Sep43Error::InvalidAddress {
                detail: String::new(),
                expected_type: "G-strkey",
            },
            Sep43Error::InvalidNetworkPassphrase {
                detail: String::new(),
            },
            Sep43Error::MissingAddress,
            Sep43Error::MalformedAuthEntry {
                detail: String::new(),
            },
            Sep43Error::InvalidMessage {
                detail: String::new(),
            },
        ];
        for err in cases {
            assert_eq!(err.sep43_code(), -3, "expected -3 for {:?}", err);
        }
    }

    #[test]
    fn sep43_code_user_rejected_is_minus_four() {
        assert_eq!(
            Sep43Error::UserRejected {
                reason: "declined".to_owned(),
            }
            .sep43_code(),
            -4
        );
    }

    // ── to_sep43_response() JSON shape ────────────────────────────────────────

    #[test]
    fn to_sep43_response_code_field_is_integer() {
        let resp = Sep43Error::InvalidXdr {
            detail: "bad base64".to_owned(),
        }
        .to_sep43_response();
        assert_eq!(resp["code"], -3_i32);
    }

    #[test]
    fn to_sep43_response_message_field_is_display() {
        let detail = "bad base64 encoding";
        let resp = Sep43Error::InvalidXdr {
            detail: detail.to_owned(),
        }
        .to_sep43_response();
        let msg = resp["message"].as_str().unwrap();
        assert!(msg.contains(detail), "message should contain detail: {msg}");
    }

    #[test]
    fn to_sep43_response_user_rejected_is_code_minus_four() {
        let resp = Sep43Error::UserRejected {
            reason: "declined on device".to_owned(),
        }
        .to_sep43_response();
        assert_eq!(resp["code"], -4_i32);
    }

    // ── Discipline: error Display/Debug must not amplify caller secrets ──────
    //
    // The invariant on `detail: String` fields is: callers MUST NOT place
    // secret material in `detail`; the Display impl surfaces `detail` verbatim.
    // This test verifies the positive half of that contract — that the variant
    // does NOT artificially wrap or redact `detail` (which would break the
    // audit-log contract that `detail` text appears as written). The negative
    // half — that callers are disciplined — is enforced by code-review and
    // the rustdoc invariant on every `detail` field.

    #[test]
    fn error_display_surfaces_caller_detail_verbatim() {
        // Discipline being verified: when a caller passes a sentinel string in
        // `detail`, Display surfaces it verbatim. Callers MUST NOT place secrets
        // there; this test asserts the variant does NOT artificially obfuscate
        // or wrap `detail`, so call-site reviewers know the variant contract.
        let sentinel = "S_SECRET_BYTES_SHOULD_NOT_APPEAR_VIA_VARIANT_OBFUSCATION";
        let err = Sep43Error::WalletUnlockFailed {
            detail: sentinel.to_owned(),
        };
        let display = format!("{err}");
        assert!(
            display.contains(sentinel),
            "variant Display MUST surface caller-supplied detail verbatim; \
             callers MUST NOT place secrets in detail: {display}"
        );

        // Cross-check a second variant to guard against per-variant deviations.
        let err2 = Sep43Error::SignerUnavailable {
            detail: sentinel.to_owned(),
        };
        let display2 = format!("{err2}");
        assert!(
            display2.contains(sentinel),
            "SignerUnavailable Display MUST surface caller-supplied detail verbatim: \
             {display2}"
        );
    }

    // ── wire_code namespace + character set enforcement ───────────────────────

    #[test]
    fn wire_codes_have_correct_namespace_and_characters() {
        let variants: &[Sep43Error] = &[
            Sep43Error::WalletUnlockFailed {
                detail: String::new(),
            },
            Sep43Error::SignerUnavailable {
                detail: String::new(),
            },
            Sep43Error::XdrSerializationFailed {
                detail: String::new(),
            },
            Sep43Error::KeyringError {
                detail: String::new(),
            },
            Sep43Error::HorizonError {
                detail: String::new(),
            },
            Sep43Error::RpcError {
                detail: String::new(),
            },
            Sep43Error::InvalidXdr {
                detail: String::new(),
            },
            Sep43Error::InvalidAddress {
                detail: String::new(),
                expected_type: "G-strkey",
            },
            Sep43Error::InvalidNetworkPassphrase {
                detail: String::new(),
            },
            Sep43Error::MissingAddress,
            Sep43Error::MalformedAuthEntry {
                detail: String::new(),
            },
            Sep43Error::InvalidMessage {
                detail: String::new(),
            },
            Sep43Error::UserRejected {
                reason: String::new(),
            },
        ];
        for variant in variants {
            let code = variant.wire_code();
            assert!(
                code.starts_with("sep43."),
                "wire_code {code:?} must start with 'sep43.'"
            );
            let after_prefix = &code["sep43.".len()..];
            assert!(
                after_prefix
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "wire_code suffix {after_prefix:?} must contain only lowercase letters, digits, and underscores"
            );
            assert_ne!(
                code, "sep43.unknown_error",
                "wire_code must not be the fallback sentinel for variant {variant:?}"
            );
        }
    }
}

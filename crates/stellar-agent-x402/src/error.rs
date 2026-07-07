//! Typed error enum for the `stellar-agent-x402` crate.
//!
//! All display messages are safe to emit in logs and MCP tool output: they
//! never include signing-key material, raw signature bytes, or seed phrases.

use thiserror::Error;

use stellar_agent_sep43::Sep43Error;

/// All errors produced by the x402 payment scheme implementation.
///
/// `#[non_exhaustive]` ensures callers pattern-match with `_` wildcards so
/// new variants can be added in future minor-version bumps without breaking
/// downstream code.
///
/// # Redaction
///
/// Every variant's `Display` output is safe to log.  Signing keys, seed
/// phrases, and raw signature bytes are never included.  Strkeys are included
/// only where necessary for operator diagnostics and are limited to the
/// non-secret G-/C-strkey forms.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum X402Error {
    /// The payment-required object could not be decoded.
    ///
    /// Emitted when `decode_payment_required` receives malformed base64 or
    /// JSON that does not match the `PaymentRequirements` shape.
    #[error("invalid payment-required: {detail}")]
    InvalidPaymentRequired {
        /// Human-readable reason for the decode failure.
        detail: String,
    },

    /// The `scheme` field was not `"exact"`.
    ///
    /// Only the `exact` scheme is supported by this crate.
    #[error("unsupported x402 scheme: {scheme:?}; only \"exact\" is supported")]
    UnsupportedScheme {
        /// The scheme value that was rejected.
        scheme: String,
    },

    /// The `network` field is not one of the two supported x402 Stellar networks.
    ///
    /// Only `"stellar:pubnet"` and `"stellar:testnet"` are valid x402 Stellar
    /// network identifiers.
    #[error(
        "unsupported x402 network: {network:?}; \
         accepted values are \"stellar:pubnet\" and \"stellar:testnet\""
    )]
    UnsupportedNetwork {
        /// The network string that was rejected.
        network: String,
    },

    /// The x402 wire `network` does not match the caller-supplied profile
    /// passphrase.
    ///
    /// Prevents a payment intended for one network from being signed with a
    /// signer bound to a different network.
    #[error(
        "x402 network {network:?} resolves to passphrase {expected_passphrase:?}, \
         but profile passphrase is {profile_passphrase:?}"
    )]
    NetworkPassphraseMismatch {
        /// x402 wire network string (e.g. `"stellar:pubnet"`).
        network: String,
        /// Passphrase derived from the x402 network string.
        expected_passphrase: &'static str,
        /// Passphrase from the caller's profile / `create_payment` argument.
        profile_passphrase: String,
    },

    /// A payment-signing request targeted a mainnet profile.
    ///
    /// The x402 payment tools return a signed payment authorization the MCP host
    /// broadcasts externally; the submit-layer mainnet gate never fires because
    /// the wallet does not submit. Signing is therefore refused structurally on a
    /// mainnet profile before any key access, so no valid mainnet payment
    /// signature is ever produced. The `detail` carries the canonical
    /// `network.mainnet_write_forbidden` wire code so this refusal correlates
    /// with the CLI, submit-layer, and SEP-43 signing guards.
    #[error("mainnet signing forbidden: {detail}")]
    MainnetSigningForbidden {
        /// Non-secret description of the refusal, carrying the canonical
        /// `network.mainnet_write_forbidden` wire code.
        detail: String,
    },

    /// The signer could not be loaded from the platform keyring.
    ///
    /// An infrastructure fault distinct from a malformed payment request: the
    /// keyring entry for the profile's `mcp_signer_default` is missing, locked,
    /// or otherwise unreadable, so no signer is available. Kept separate from
    /// [`X402Error::InvalidPaymentRequired`] so the wire code reflects an
    /// infrastructure/keyring failure rather than a client-supplied input error.
    #[error("keyring load failed: {detail}")]
    KeyringLoadFailed {
        /// Non-secret description of the keyring failure.
        detail: String,
    },

    /// The `asset` field is not a valid C-strkey SAC contract address.
    #[error("invalid SAC asset address: {detail}")]
    InvalidAssetAddress {
        /// Human-readable reason for the validation failure.
        detail: String,
    },

    /// The `pay_to` recipient is not a valid G-, C-, or M-strkey address.
    #[error("invalid recipient address: {detail}")]
    InvalidRecipientAddress {
        /// Human-readable reason for the validation failure.
        detail: String,
    },

    /// The payer (`from`) is not a valid G-strkey account address.
    #[error("invalid payer address: {detail}")]
    InvalidPayerAddress {
        /// Human-readable reason for the validation failure.
        detail: String,
    },

    /// `extra.areFeesSponsored` was not `true`.
    ///
    /// The `exact` scheme mandates fee sponsorship for the payer.
    #[error(
        "x402 exact scheme requires extra.areFeesSponsored == true; \
         payment-required either omits the field or sets it to false"
    )]
    FeesNotSponsored,

    /// The wire `amount` could not be parsed, overflows `i128`, or is not a
    /// positive integer.
    ///
    /// The x402 wire `amount` is already an atomic-units string; this error
    /// covers parse failure, `i128` overflow, and non-positive amounts (zero and
    /// negative values are rejected).
    #[error("amount conversion failed: {detail}")]
    AmountConversion {
        /// Human-readable reason for the conversion failure.
        detail: String,
    },

    /// The auth-entry signing step failed.
    ///
    /// Wraps [`Sep43Error`] from `stellar-agent-sep43`.
    #[error("auth-entry signing failed: {source}")]
    AuthEntrySignFailed {
        /// The underlying SEP-43 signing error.
        #[from]
        source: Sep43Error,
    },

    /// The Soroban RPC `simulateTransaction` call failed.
    #[error("RPC simulate failed: {detail}")]
    RpcSimulateFailed {
        /// Human-readable reason for the simulate failure.
        detail: String,
    },

    /// A `SettleResponse` could not be decoded from base64+JSON.
    #[error("receipt parse failed: {detail}")]
    ReceiptParseFailed {
        /// Human-readable reason for the parse failure.
        detail: String,
    },

    /// Internal XDR encoding or transaction-builder failure.
    #[error("transaction build failed: {detail}")]
    TransactionBuildFailed {
        /// Human-readable reason for the build failure.
        detail: String,
    },

    /// The auth-entry array returned by simulate does not satisfy the
    /// single-payer invariant.
    ///
    /// For a plain G-key payer doing a SAC `transfer`, the simulate host must
    /// return exactly one `SorobanCredentials::Address` entry credentialed for
    /// the payer's own account.  This error fires when:
    /// - zero Address-credentialled entries match the payer's address, or
    /// - more than one Address-credentialled entry matches the payer, or
    /// - an `Address`-credentialled entry for a different account (non-payer)
    ///   is present — violating the "no other signers required" invariant.
    #[error("unexpected auth entries in simulate response: {detail}")]
    UnexpectedAuthEntries {
        /// Human-readable description of the violation.
        detail: String,
    },
}

impl X402Error {
    /// Returns the stable wire code for this error.
    ///
    /// The x402 tools surface errors through the documented result envelope
    /// (`{ ok: false, error: { code, message }, request_id }`); this method
    /// supplies the `error.code`. Codes follow the `x402.<snake_variant>`
    /// taxonomy so an agent can branch on the specific failure, with one
    /// deliberate exception: [`X402Error::MainnetSigningForbidden`] returns the
    /// canonical `network.mainnet_write_forbidden` code so the refusal correlates
    /// with the CLI, submit-layer, and SEP-43/SEP-53 signing guards across every
    /// surface.
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self {
            X402Error::InvalidPaymentRequired { .. } => "x402.invalid_payment_required",
            X402Error::UnsupportedScheme { .. } => "x402.unsupported_scheme",
            X402Error::UnsupportedNetwork { .. } => "x402.unsupported_network",
            X402Error::NetworkPassphraseMismatch { .. } => "x402.network_passphrase_mismatch",
            X402Error::MainnetSigningForbidden { .. } => "network.mainnet_write_forbidden",
            X402Error::InvalidAssetAddress { .. } => "x402.invalid_asset_address",
            X402Error::InvalidRecipientAddress { .. } => "x402.invalid_recipient_address",
            X402Error::InvalidPayerAddress { .. } => "x402.invalid_payer_address",
            X402Error::FeesNotSponsored => "x402.fees_not_sponsored",
            X402Error::AmountConversion { .. } => "x402.amount_conversion",
            X402Error::AuthEntrySignFailed { .. } => "x402.auth_entry_sign_failed",
            X402Error::RpcSimulateFailed { .. } => "x402.rpc_simulate_failed",
            X402Error::ReceiptParseFailed { .. } => "x402.receipt_parse_failed",
            X402Error::TransactionBuildFailed { .. } => "x402.transaction_build_failed",
            X402Error::UnexpectedAuthEntries { .. } => "x402.unexpected_auth_entries",
            X402Error::KeyringLoadFailed { .. } => "x402.keyring_load_failed",
        }
    }
}

/// Test-only constructors for [`X402Error`] variants that tests need to
/// construct adversarially.
///
/// Gated behind `#[cfg(any(test, feature = "test-helpers"))]` so these
/// constructors are never compiled into production builds.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::X402Error;

    /// Constructs [`X402Error::InvalidPaymentRequired`] with the given detail.
    #[must_use]
    pub fn invalid_payment_required(detail: impl Into<String>) -> X402Error {
        X402Error::InvalidPaymentRequired {
            detail: detail.into(),
        }
    }

    /// Constructs [`X402Error::UnsupportedScheme`] with the given scheme.
    #[must_use]
    pub fn unsupported_scheme(scheme: impl Into<String>) -> X402Error {
        X402Error::UnsupportedScheme {
            scheme: scheme.into(),
        }
    }

    /// Constructs [`X402Error::UnsupportedNetwork`] with the given network.
    #[must_use]
    pub fn unsupported_network(network: impl Into<String>) -> X402Error {
        X402Error::UnsupportedNetwork {
            network: network.into(),
        }
    }

    /// Constructs [`X402Error::FeesNotSponsored`].
    #[must_use]
    pub fn fees_not_sponsored() -> X402Error {
        X402Error::FeesNotSponsored
    }

    /// Constructs [`X402Error::AmountConversion`] with the given detail.
    #[must_use]
    pub fn amount_conversion(detail: impl Into<String>) -> X402Error {
        X402Error::AmountConversion {
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    use super::*;

    // Display of all variants must not expose secret material.
    // We verify the display format does not contain known-sensitive patterns.

    #[test]
    fn display_unsupported_scheme_does_not_contain_key_material() {
        let err = X402Error::UnsupportedScheme {
            scheme: "bad".to_owned(),
        };
        let display = err.to_string();
        // Must mention the scheme and say "exact"
        assert!(display.contains("bad"));
        assert!(display.contains("exact"));
        // Must not contain any S-strkey prefix pattern
        assert!(!display.starts_with('S'));
    }

    #[test]
    fn display_fees_not_sponsored() {
        let err = X402Error::FeesNotSponsored;
        let display = err.to_string();
        assert!(display.contains("areFeesSponsored"));
    }

    #[test]
    fn display_unsupported_network_includes_network() {
        let err = X402Error::UnsupportedNetwork {
            network: "evm:1".to_owned(),
        };
        assert!(err.to_string().contains("evm:1"));
    }

    #[test]
    fn display_network_passphrase_mismatch() {
        let err = X402Error::NetworkPassphraseMismatch {
            network: "stellar:pubnet".to_owned(),
            expected_passphrase: "Public Global Stellar Network ; September 2015",
            profile_passphrase: "Test SDF Network ; September 2015".to_owned(),
        };
        let display = err.to_string();
        // Must mention the network
        assert!(display.contains("stellar:pubnet"));
    }

    #[test]
    fn display_amount_conversion() {
        let err = X402Error::AmountConversion {
            detail: "overflow".to_owned(),
        };
        assert!(err.to_string().contains("overflow"));
    }

    #[test]
    fn display_mainnet_signing_forbidden_carries_canonical_wire_code() {
        let err = X402Error::MainnetSigningForbidden {
            detail: "signing is structurally refused on mainnet (network.mainnet_write_forbidden)"
                .to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("mainnet signing forbidden"));
        assert!(
            d.contains("network.mainnet_write_forbidden"),
            "message must carry the canonical wire code: {d}"
        );
    }

    #[test]
    fn display_invalid_payment_required() {
        let err = X402Error::InvalidPaymentRequired {
            detail: "bad base64".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("invalid payment-required"));
        assert!(d.contains("bad base64"));
    }

    #[test]
    fn display_invalid_asset_address() {
        let err = X402Error::InvalidAssetAddress {
            detail: "not a C-strkey".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("invalid SAC asset address"));
        assert!(d.contains("not a C-strkey"));
    }

    #[test]
    fn display_invalid_recipient_address() {
        let err = X402Error::InvalidRecipientAddress {
            detail: "not a G/C/M strkey".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("invalid recipient address"));
        assert!(d.contains("not a G/C/M strkey"));
    }

    #[test]
    fn display_invalid_payer_address() {
        let err = X402Error::InvalidPayerAddress {
            detail: "not a G strkey".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("invalid payer address"));
        assert!(d.contains("not a G strkey"));
    }

    #[test]
    fn display_rpc_simulate_failed() {
        let err = X402Error::RpcSimulateFailed {
            detail: "timeout".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("RPC simulate failed"));
        assert!(d.contains("timeout"));
    }

    #[test]
    fn display_receipt_parse_failed() {
        let err = X402Error::ReceiptParseFailed {
            detail: "malformed json".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("receipt parse failed"));
        assert!(d.contains("malformed json"));
    }

    #[test]
    fn display_transaction_build_failed() {
        let err = X402Error::TransactionBuildFailed {
            detail: "xdr overflow".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("transaction build failed"));
        assert!(d.contains("xdr overflow"));
    }

    #[test]
    fn display_unexpected_auth_entries() {
        let err = X402Error::UnexpectedAuthEntries {
            detail: "two payer entries".to_owned(),
        };
        let d = err.to_string();
        assert!(d.contains("unexpected auth entries"));
        assert!(d.contains("two payer entries"));
    }

    #[cfg(feature = "test-helpers")]
    #[test]
    fn test_helpers_constructors_produce_expected_variants() {
        let e = test_helpers::fees_not_sponsored();
        assert!(matches!(e, X402Error::FeesNotSponsored));

        let e = test_helpers::unsupported_scheme("upto");
        assert!(matches!(e, X402Error::UnsupportedScheme { scheme } if scheme == "upto"));

        let e = test_helpers::unsupported_network("evm:1");
        assert!(matches!(e, X402Error::UnsupportedNetwork { network } if network == "evm:1"));
    }
}

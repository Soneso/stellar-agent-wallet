//! Typed error enum for the `stellar-agent-x402` crate.
//!
//! All display messages are safe to emit in logs and MCP tool output: they
//! never include signing-key material, raw signature bytes, or seed phrases.

use thiserror::Error;

use stellar_agent_core::error::WalletError;
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
    #[error("unsupported x402 scheme: {scheme}; only \"exact\" is supported")]
    UnsupportedScheme {
        /// The rejected scheme value, stored quoted, escaped, and bounded by
        /// `stellar_agent_network::quote_server_text`.
        scheme: String,
    },

    /// The `network` field is not one of the two supported x402 Stellar networks.
    ///
    /// Only `"stellar:pubnet"` and `"stellar:testnet"` are valid x402 Stellar
    /// network identifiers.
    #[error(
        "unsupported x402 network: {network}; \
         accepted values are \"stellar:pubnet\" and \"stellar:testnet\""
    )]
    UnsupportedNetwork {
        /// The rejected network value, stored quoted, escaped, and bounded by
        /// `stellar_agent_network::quote_server_text`.
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

    /// A payment-signing request targeted mainnet.
    ///
    /// A signed payment authorization is submitted by another party, not by the
    /// wallet, so no submit-layer mainnet gate stands between it and mainnet.
    /// [`crate::exact::create_payment`] raises this variant for a mainnet
    /// passphrase or a mainnet-pattern RPC URL, before any key access and any
    /// request. The MCP payment tools also refuse a mainnet profile at entry.
    /// The `detail` carries the canonical `network.mainnet_write_forbidden`
    /// wire code, so this refusal correlates with the CLI, submit-layer, and
    /// SEP-43 signing guards.
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

    /// A simulation answer carries authorization entries the payment flow does
    /// not sign or accept.
    ///
    /// Before anything is signed, the first simulation of
    /// [`crate::exact::create_payment`] must return exactly one entry for a G-key
    /// payer's SAC `transfer`. This error fires when that entry:
    /// - is missing, or other entries accompany it;
    /// - has credentials other than legacy `SorobanCredentials::Address`, or
    ///   credentials for an account other than the payer;
    /// - has a non-zero `signature_expiration_ledger` or a signature;
    /// - has a root invocation other than the `transfer` the wallet built, or
    ///   one with nested calls.
    ///
    /// It also fires when the signed re-simulation returns authorization
    /// entries that are neither empty nor equal to the signed entries. The
    /// `detail` names the failed check and carries no value from the answer.
    #[error("unexpected auth entries in simulate response: {detail}")]
    UnexpectedAuthEntries {
        /// Human-readable description of the violation.
        detail: String,
    },

    /// The configured RPC endpoint failed the endpoint identity check that
    /// [`crate::exact::create_payment`] runs before its first simulation.
    ///
    /// The endpoint reports another network than the profile's, reports
    /// mainnet, runs a protocol the release refuses, or could not be
    /// identified before the caller's deadline. Nothing was simulated or
    /// signed. The inner error is the check's own, unchanged; its URL is
    /// authority-only.
    #[error("RPC endpoint identity check failed: {0}")]
    EndpointIdentity(WalletError),

    /// The cross-check witness of [`crate::exact::create_payment`] refused
    /// before anything was signed.
    ///
    /// The oracle's simulation disagrees with the primary's, the witness could
    /// not be obtained, or the oracle refused the credential. The inner error
    /// is the witness's own, unchanged, and so are its code and its text.
    #[error(transparent)]
    CrossCheck(WalletError),

    /// The transmit gate of [`crate::exact::create_payment`] refused, so the
    /// signed authorization was never sent.
    ///
    /// A host whose gate refuses for its own reason keeps that reason beside
    /// the gate and reports it with its own code. This variant's code reaches a
    /// caller only from a gate that keeps no such reason.
    #[error("transmit gate refused: {detail}")]
    TransmitGateRefused {
        /// Non-secret description of the refusal.
        detail: String,
    },
}

impl X402Error {
    /// Returns the stable wire code for this error.
    ///
    /// The x402 tools surface errors through the documented result envelope
    /// (`{ ok: false, error: { code, message }, request_id }`); this method
    /// supplies the `error.code`. Codes follow the `x402.<snake_variant>`
    /// taxonomy so an agent can branch on the specific failure, with these
    /// deliberate exceptions. [`X402Error::MainnetSigningForbidden`] returns the
    /// canonical `network.mainnet_write_forbidden` code so the refusal correlates
    /// with the CLI, submit-layer, and SEP-43/SEP-53 signing guards across every
    /// surface. [`X402Error::EndpointIdentity`] and [`X402Error::CrossCheck`]
    /// return the code of the wallet error they carry, such as
    /// `network.endpoint_network_mismatch` or `simulation.divergence`, the code
    /// every other signing path answers for the same refusal.
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
            X402Error::TransmitGateRefused { .. } => "x402.transmit_gate_refused",
            X402Error::EndpointIdentity(inner) | X402Error::CrossCheck(inner) => inner.code(),
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

    /// Constructs [`X402Error::UnsupportedScheme`] with the given scheme,
    /// stored quoted the way the validation stores it.
    #[must_use]
    pub fn unsupported_scheme(scheme: impl AsRef<str>) -> X402Error {
        X402Error::UnsupportedScheme {
            scheme: stellar_agent_network::quote_server_text(scheme.as_ref()),
        }
    }

    /// Constructs [`X402Error::UnsupportedNetwork`] with the given network,
    /// stored quoted the way the validation stores it.
    #[must_use]
    pub fn unsupported_network(network: impl AsRef<str>) -> X402Error {
        X402Error::UnsupportedNetwork {
            network: stellar_agent_network::quote_server_text(network.as_ref()),
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
    fn transmit_gate_refused_carries_its_own_wire_code() {
        let err = X402Error::TransmitGateRefused {
            detail: "audit row not written".to_owned(),
        };
        assert_eq!(err.wire_code(), "x402.transmit_gate_refused");
        let d = err.to_string();
        assert!(d.contains("transmit gate refused"));
        assert!(d.contains("audit row not written"));
    }

    #[test]
    fn cross_check_carries_the_wire_code_and_text_of_its_wallet_error() {
        use stellar_agent_core::cross_check::{WitnessEntry, WitnessField};
        use stellar_agent_core::error::{NetworkError, WitnessUnavailableReason};
        let cases = [
            WalletError::Network(NetworkError::WitnessDivergence {
                entry: WitnessEntry::SorobanSimulation,
                field: WitnessField::Expiration,
                sequence_delta: None,
            }),
            WalletError::Network(NetworkError::WitnessUnavailable {
                reason: WitnessUnavailableReason::InvalidAnswer {
                    authority: "https://oracle.example".to_owned(),
                },
            }),
            WalletError::Network(NetworkError::RpcCredentialRejected {
                url: "https://oracle.example".to_owned(),
                status: 401,
            }),
        ];
        for inner in cases {
            let code = inner.code();
            let text = inner.to_string();
            let err = X402Error::CrossCheck(inner);
            assert_eq!(err.wire_code(), code);
            assert_eq!(err.to_string(), text);
        }
    }

    #[test]
    fn endpoint_identity_carries_the_wire_code_of_its_wallet_error() {
        use stellar_agent_core::error::NetworkError;
        let cases = [
            (
                WalletError::Network(NetworkError::EndpointNetworkMismatch {
                    expected: "Test SDF Network ; September 2015".to_owned(),
                    server: stellar_agent_core::error::ReportedPassphrase::from_reported(
                        "Test SDF Future Network ; October 2022",
                    ),
                }),
                "network.endpoint_network_mismatch",
            ),
            (
                WalletError::Network(NetworkError::MainnetWriteForbidden),
                "network.mainnet_write_forbidden",
            ),
            (
                WalletError::Network(NetworkError::EndpointIdentityUnavailable {
                    url: "https://rpc.example.com".to_owned(),
                }),
                "network.endpoint_identity_unavailable",
            ),
        ];
        for (inner, code) in cases {
            let message = inner.to_string();
            let err = X402Error::EndpointIdentity(inner);
            assert_eq!(err.wire_code(), code);
            let display = err.to_string();
            assert!(
                display.starts_with("RPC endpoint identity check failed: "),
                "{display}"
            );
            assert!(display.ends_with(&message), "{display}");
        }
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
        assert!(matches!(e, X402Error::UnsupportedScheme { scheme } if scheme == "\"upto\""));

        let e = test_helpers::unsupported_network("evm:1");
        assert!(matches!(e, X402Error::UnsupportedNetwork { network } if network == "\"evm:1\""));
    }
}

//! SEP-29 memo-required enforcement via on-chain `config.memo_required` data entry.
//!
//! Exposes [`check_memo_required`], which looks up the `config.memo_required`
//! data entry on the destination account. If the entry exists and its value
//! equals ASCII `"1"`, the account requires a memo. Callers that have not
//! supplied a memo receive [`WalletError::Validation`] wrapping
//! [`ValidationError::MemoRequired`].
//!
//! # Error propagation
//!
//! Transient RPC errors propagate to the caller (fail-closed). An absent
//! `config.memo_required` entry is fail-open: no memo is required.
//!
//! # Scope boundary
//!
//! Only on-chain `LedgerKey::Data` lookup is implemented here. The
//! `stellar.toml` home-domain SEP-29 hint path is not implemented; callers
//! relying on that signal must handle it separately.

use crate::cross_check::MemoObservation;
use stellar_agent_core::error::{ValidationError, WalletError};

use crate::account::fetch_data_entry;
use crate::client::StellarRpcClient;

/// Returns `true` if the raw `config.memo_required` bytes signal memo-required.
///
/// Only ASCII `"1"` (`b"1"`) signals required per SEP-29; any other value
/// (absent, unexpected bytes) is treated as not-required.
pub(crate) fn normalise_memo_required(value: &Option<Vec<u8>>) -> bool {
    matches!(value, Some(bytes) if bytes.as_slice() == b"1")
}

/// Checks whether the destination account requires a memo per SEP-29.
///
/// Reads the flag on the primary when the envelope carries no memo.
/// The returned observation lets a commit witness compare the same decision.
///
/// # Errors
/// Refuses a required missing memo and propagates primary read or decode failures.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::{StellarRpcClient, sep29::check_memo_required};
///
/// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")?;
/// check_memo_required(&client, "GABC...XYZ", false).await?;
/// # Ok(()) }
/// ```
pub async fn check_memo_required(
    client: &StellarRpcClient,
    destination: &str,
    memo_present: bool,
) -> Result<MemoObservation, WalletError> {
    // Fast-path: if a memo is already supplied, no check is needed regardless
    // of the data entry value.
    if memo_present {
        return Ok(MemoObservation::NotRead);
    }

    // `fetch_data_entry` returns `None` for absent entries including absent
    // accounts. The caller's own `fetch_account` call in the payment build
    // path surfaces the typed `AccountNotFound` error.
    let primary_value = fetch_data_entry(client, destination, "config.memo_required").await?;

    match primary_value {
        Some(ref bytes) if bytes == b"1" => {
            Err(WalletError::Validation(ValidationError::MemoRequired {
                destination: destination.to_owned(),
            }))
        }
        Some(ref bytes) => {
            // Warn when the entry exists with an unexpected value.
            // Aids ops debugging of mis-configured counterparties without
            // silently bypassing SEP-29 (the spec is strict: only b"1" triggers).
            // The value is bytes the RPC endpoint chose, so the line carries
            // only its length and the entry kind, never the bytes.
            tracing::warn!(
                destination = %stellar_agent_core::observability::redact_strkey_first5_last5(destination),
                entry_kind = "data",
                value_len = bytes.len(),
                "sep29: config.memo_required entry exists with unexpected value (not b\"1\"); \
                treating as memo-not-required per SEP-29 spec"
            );
            Ok(MemoObservation::Read(false))
        }
        // Entry absent — SEP-29 does not apply.
        None => Ok(MemoObservation::Read(false)),
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
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::normalise_memo_required;
    use stellar_agent_core::error::{ErrorCategory, NetworkError, ValidationError, WalletError};

    /// MemoRequired has the correct code.
    // The memo-present fast-path is covered by the payment integration tests
    // (sep29_memo_present_fast_path_no_rpc).
    #[test]
    fn memo_required_code() {
        let e = WalletError::Validation(ValidationError::MemoRequired {
            destination: "GABC".to_owned(),
        });
        assert_eq!(e.code(), "validation.memo_required");
        assert_eq!(e.category(), ErrorCategory::Validation);
        assert!(e.message().contains("GABC"));
    }

    /// `NetworkError::RpcDivergence` has the correct wire code.
    ///
    /// The code is `"network.rpc_divergence"`.
    #[test]
    fn rpc_divergence_code() {
        let e = WalletError::Network(NetworkError::RpcDivergence {
            context: "SEP-29 config.memo_required".to_owned(),
        });
        assert_eq!(e.code(), "network.rpc_divergence");
        assert_eq!(e.category(), ErrorCategory::Network);
        // The message is descriptive only — it must NOT impersonate a wire
        // code (the typed code above is the single code surface).
        assert!(
            !e.message().contains("simulation.divergence"),
            "RpcDivergence message must not embed a wire-code-like prefix; got: {}",
            e.message()
        );
        assert!(
            e.message()
                .contains("differs between primary and secondary RPC"),
            "RpcDivergence message must describe the divergence; got: {}",
            e.message()
        );
    }

    /// The warning for a `config.memo_required` entry with an unexpected
    /// value names the entry kind and the value length, and carries none of
    /// the bytes the endpoint returned.
    #[tokio::test(flavor = "current_thread")]
    async fn unexpected_value_warning_logs_length_and_kind_only() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer};
        const DESTINATION: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let marker = b"endpoint-chosen-marker-bytes".to_vec();
        let pk = stellar_strkey::ed25519::PublicKey::from_string(DESTINATION).unwrap();
        let account = stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::Uint256(pk.0),
        ));
        let name: stellar_xdr::String64 =
            stellar_xdr::StringM::<64>::try_from(b"config.memo_required".to_vec())
                .unwrap()
                .into();
        let key = stellar_xdr::LedgerKey::Data(stellar_xdr::LedgerKeyData {
            account_id: account.clone(),
            data_name: name.clone(),
        });
        let data = stellar_xdr::LedgerEntryData::Data(stellar_xdr::DataEntry {
            account_id: account,
            data_name: name,
            data_value: marker.clone().try_into().unwrap(),
            ext: stellar_xdr::DataEntryExt::V0,
        });
        use stellar_xdr::WriteXdr;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(stellar_agent_test_support::EchoIdResponder::new(
                serde_json::json!({
                    "entries": [{
                        "key": key.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
                        "xdr": data.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
                        "lastModifiedLedgerSeq": 5,
                    }],
                    "latestLedger": 6,
                }),
            ))
            .mount(&server)
            .await;
        let client = crate::client::StellarRpcClient::new(&server.uri()).unwrap();
        let (outcome, logs) = crate::cross_check::log_capture::capture_logs(
            tracing::Level::WARN,
            super::check_memo_required(&client, DESTINATION, false),
        )
        .await;
        assert_eq!(
            outcome.unwrap(),
            crate::cross_check::MemoObservation::Read(false)
        );
        assert_eq!(logs.lines().count(), 1, "{logs}");
        assert!(logs.contains("entry_kind=\"data\""), "{logs}");
        assert!(
            logs.contains(&format!("value_len={}", marker.len())),
            "{logs}"
        );
        let shown = String::from_utf8(marker.clone()).unwrap();
        assert!(!logs.contains(&shown), "{logs}");
        assert!(!logs.contains(&format!("{:?}", marker)), "{logs}");
    }

    /// `normalise_memo_required` returns `true` only for `Some(b"1")`.
    #[test]
    fn normalise_memo_required_cases() {
        // ASCII "1" → required.
        assert!(normalise_memo_required(&Some(b"1".to_vec())));
        // Absent → not required.
        assert!(!normalise_memo_required(&None));
        // Any other value → not required.
        assert!(!normalise_memo_required(&Some(b"0".to_vec())));
        assert!(!normalise_memo_required(&Some(b"true".to_vec())));
        assert!(!normalise_memo_required(&Some(b"".to_vec())));
    }
}

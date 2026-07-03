//! SEP-29 memo-required enforcement via on-chain `config.memo_required` data entry.
//!
//! Exposes [`check_memo_required`], which looks up the `config.memo_required`
//! data entry on the destination account. If the entry exists and its value
//! equals ASCII `"1"`, the account requires a memo. Callers that have not
//! supplied a memo receive [`WalletError::Validation`] wrapping
//! [`ValidationError::MemoRequired`].
//!
//! When a `secondary_rpc` is configured, both RPCs are consulted and their
//! results are compared before the memo-required gate runs.  A mismatch returns
//! [`NetworkError::RpcDivergence`].
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

use stellar_agent_core::error::{NetworkError, ValidationError, WalletError};

use crate::account::fetch_data_entry;
use crate::client::StellarRpcClient;

/// Returns `true` if the raw `config.memo_required` bytes signal memo-required.
///
/// Only ASCII `"1"` (`b"1"`) signals required per SEP-29; any other value
/// (absent, unexpected bytes) is treated as not-required.
fn normalise_memo_required(value: &Option<Vec<u8>>) -> bool {
    matches!(value, Some(bytes) if bytes.as_slice() == b"1")
}

/// Checks whether the destination account requires a memo per SEP-29.
///
/// Fetches the `config.memo_required` data entry from the destination
/// account on-chain.  If `secondary_rpc` is `Some`, the same entry is
/// fetched from both RPCs and the normalised results are compared before
/// the memo-required gate runs.  A mismatch returns
/// `WalletError::Network(NetworkError::RpcDivergence)` — the caller MUST
/// re-simulate after the disagreement clears.
///
/// When the entry exists and equals ASCII `"1"`, and `memo_present` is
/// `false`, returns
/// `WalletError::Validation(ValidationError::MemoRequired)`.
///
/// Transient RPC errors propagate to the caller (fail-closed).
/// An absent entry is fail-open: no memo is required.
///
/// `AccountNotFound` is surfaced by `fetch_data_entry` returning `None`
/// (or an RPC error) when the account does not exist; the caller's own
/// `fetch_account` call in the payment path handles the typed error surface.
///
/// # Errors
///
/// - `WalletError::Network(NetworkError::RpcDivergence)` if `secondary_rpc`
///   is configured and the two RPCs disagree on the memo-required flag.
/// - [`WalletError::Validation`] wrapping [`ValidationError::MemoRequired`]
///   if the destination requires a memo and none was supplied.
/// - [`WalletError::Network`] or [`WalletError::Protocol`] for RPC or XDR
///   failures (fail-closed; transient errors are not silenced).
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::{StellarRpcClient, sep29::check_memo_required};
///
/// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")?;
/// check_memo_required(&client, None, "GABC...XYZ", false).await?;
/// # Ok(()) }
/// ```
pub async fn check_memo_required(
    client: &StellarRpcClient,
    secondary_rpc: Option<&StellarRpcClient>,
    destination: &str,
    memo_present: bool,
) -> Result<(), WalletError> {
    // Fast-path: if a memo is already supplied, no check is needed regardless
    // of the data entry value.
    if memo_present {
        return Ok(());
    }

    // `fetch_data_entry` returns `None` for absent entries including absent
    // accounts. The caller's own `fetch_account` call in the payment build
    // path surfaces the typed `AccountNotFound` error.
    let primary_value = fetch_data_entry(client, destination, "config.memo_required").await?;

    // Cross-RPC consistency check: if a secondary RPC is configured, fetch
    // the same entry from it and compare the normalised results.  A mismatch
    // returns `NetworkError::RpcDivergence` — the divergence is fail-closed
    // regardless of which RPC is more restrictive.
    //
    //   - Secondary RPC absent → skip cross-check (fail open).
    //   - Secondary RPC fails → divergence error (cannot complete cross-check;
    //     fail-closed rather than silently degrading to primary-only).
    //   - Both agree → continue with the primary value.
    if let Some(secondary) = secondary_rpc {
        // A failing secondary RPC is classified as divergence: the cross-check
        // cannot be completed, so the fail-closed direction refuses rather than
        // silently degrading to primary-only.
        let secondary_value = fetch_data_entry(secondary, destination, "config.memo_required")
            .await
            .map_err(|e| {
                WalletError::Network(NetworkError::RpcDivergence {
                    context: format!("SEP-29 config.memo_required secondary fetch failed: {e}"),
                })
            })?;
        let primary_required = normalise_memo_required(&primary_value);
        let secondary_required = normalise_memo_required(&secondary_value);
        if primary_required != secondary_required {
            tracing::warn!(
                destination = %stellar_agent_core::observability::redact_strkey_first5_last5(destination),
                primary_required = %primary_required,
                secondary_required = %secondary_required,
                "sep29: config.memo_required divergence between primary and secondary RPC"
            );
            return Err(WalletError::Network(NetworkError::RpcDivergence {
                context: "SEP-29 config.memo_required".to_owned(),
            }));
        }
    }

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
            tracing::warn!(
                destination = %stellar_agent_core::observability::redact_strkey_first5_last5(destination),
                value = ?bytes,
                "sep29: config.memo_required entry exists with unexpected value (not b\"1\"); \
                treating as memo-not-required per SEP-29 spec"
            );
            Ok(())
        }
        // Entry absent — SEP-29 does not apply.
        None => Ok(()),
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

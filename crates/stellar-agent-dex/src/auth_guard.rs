//! Multi-auth-entry guard for the Soroswap ROUTER-DIRECT swap submit path.
//!
//! # What this module does
//!
//! After a simulate and before signing, counts the
//! `SorobanAuthorizationEntry` values whose
//! `SorobanCredentials::Address(c).address` matches the wallet smart-account
//! [`ScAddress`], and refuses (fail-closed) unless the count is EXACTLY 1.
//!
//! # Rationale
//!
//! The swap is submitted ROUTER-DIRECT: `InvokeContract(router,
//! "swap_exact_tokens_for_tokens", [amount_in, amount_out_min, path,
//! to=wallet, deadline])`.  The router calls `to.require_auth()` in
//! `soroswap-core contracts/router/src/lib.rs`.  The SAC
//! `transfer(from=wallet, to=pair, amount_in)` is a sub-invocation
//! COVERED by that single root entry — identical to the Blend / DeFindex auth
//! model.  This guard verifies the expected 1-entry shape before signing:
//!
//! - 0 entries → `Err(AuthGuardError::NoWalletEntry)` (cannot sign).
//! - 1 entry  → `Ok(1)` (proceed).
//! - >1 entries → `Err(AuthGuardError::UnexpectedMultipleEntries)` (refuse).
//!
//! A multi-entry result would indicate an unexpected contract shape change that
//! is outside the scope of `submit_signed_invoke`; the guard enforces the
//! invariant fail-closed before any signing occurs.
//!
//! # Does NOT modify submit.rs / managers / auth_entry.rs
//!
//! This guard is entirely self-contained in `stellar-agent-dex`.  It is
//! read-only: it builds its own simulate envelope and calls the Soroban RPC
//! `simulateTransaction` via
//! `stellar_rpc_client::Client::simulate_transaction_envelope` directly (rather
//! than the shared quote scaffold) because it needs the `auth` entries from the
//! simulate response, which that scaffold does not surface.  It does NOT touch
//! the `stellar-agent-smart-account` submit path or any shared primitive.

use stellar_rpc_client::Client;
use stellar_xdr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, ScAddress, ScSymbol, ScVal, SequenceNumber,
    SorobanCredentials, StringM, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, VecM,
};
use tracing::{debug, warn};

// ─────────────────────────────────────────────────────────────────────────────
// AuthGuardError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by the multi-auth-entry guard.
///
/// All variants carry non-sensitive diagnostic information.  The `Display`
/// impl never leaks a full `C…` address.
///
/// # Sibling-variant Display audit
///
/// Every variant is reviewed: none echoes a full smart-account address.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthGuardError {
    /// The wallet smart-account address is not a valid C-strkey.
    #[error("multi-auth guard: wallet address is not a valid C-strkey: {reason}")]
    InvalidWalletAddress {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The simulate call failed.
    #[error("multi-auth guard: simulate failed: {reason}")]
    SimulateFailed {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The simulate returned no auth entries credentialled against the wallet.
    ///
    /// Expected exactly 1 for ROUTER-DIRECT `to.require_auth()`
    /// (`soroswap-core contracts/router/src/lib.rs`).
    #[error(
        "multi-auth guard: simulate returned 0 wallet-credentialled root auth entries; \
         expected exactly 1 for a Soroswap ROUTER-DIRECT swap"
    )]
    NoWalletEntry,

    /// The simulate returned more than 1 wallet-credentialled root auth entry.
    ///
    /// The ROUTER-DIRECT path MUST produce exactly 1.  A multi-entry response
    /// signals an unexpected contract shape; the swap is refused fail-closed.
    #[error(
        "multi-auth guard: simulate returned {count} wallet-credentialled root auth entries; \
         expected exactly 1 for a Soroswap ROUTER-DIRECT swap — refusing (unexpected contract shape)"
    )]
    UnexpectedMultipleEntries {
        /// Number of wallet-credentialled root entries observed.
        count: usize,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// count_wallet_auth_entries
// ─────────────────────────────────────────────────────────────────────────────

/// Performs a ROUTER-DIRECT simulate of `router.swap_exact_tokens_for_tokens(
/// amount_in, amount_out_min, path, to=wallet, deadline)` and counts the root
/// `SorobanAuthorizationEntry` values whose credentials address the wallet
/// smart-account, then enforces the count == 1 invariant.
///
/// The ROUTER-DIRECT pattern: the router calls `to.require_auth()` in
/// `soroswap-core contracts/router/src/lib.rs`.  The SAC
/// `transfer(from=wallet, to=pair, amount_in)` is a sub-invocation
/// COVERED by that single root entry.  This produces exactly 1
/// wallet-credentialled root auth entry in simulate — same as Blend/DeFindex.
///
/// Returns `Ok(1)` when exactly one wallet-credentialled root entry is present.
///
/// # Arguments
///
/// - `wallet_address` — the wallet smart-account C-strkey (`to` arg in the swap).
/// - `router_address` — the Soroswap router C-strkey (invocation target).
/// - `swap_args` — the encoded `ScVal` argument list (positional, already built
///   by `encode_swap_args` with `to=wallet_address`).
/// - `rpc_url` — primary Soroban RPC URL.
///
/// # Errors
///
/// Returns [`AuthGuardError`] when:
/// - `wallet_address` is not a valid C-strkey.
/// - The simulate call fails.
/// - The auth-entry count is not exactly 1.
pub async fn count_wallet_auth_entries(
    wallet_address: &str,
    router_address: &str,
    swap_args: &[ScVal],
    rpc_url: &str,
) -> Result<usize, AuthGuardError> {
    // Parse wallet address to ScAddress for comparison (used to identify the
    // wallet-credentialled auth entry in the simulate response).
    let wallet_bytes = stellar_strkey::Contract::from_string(wallet_address).map_err(|e| {
        AuthGuardError::InvalidWalletAddress {
            reason: format!("wallet address parse failed: {e}"),
        }
    })?;
    let wallet_sc_addr = ScAddress::Contract(ContractId(Hash(wallet_bytes.0)));

    // Parse router address — this is the INVOCATION TARGET for ROUTER-DIRECT.
    let router_bytes = stellar_strkey::Contract::from_string(router_address).map_err(|e| {
        AuthGuardError::InvalidWalletAddress {
            reason: format!("router address parse failed: {e}"),
        }
    })?;
    let router_sc_addr = ScAddress::Contract(ContractId(Hash(router_bytes.0)));

    // Build InvokeContractArgs for ROUTER-DIRECT:
    //   router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to=wallet, deadline)
    //
    // The router calls `to.require_auth()` — that is the single
    // wallet-credentialled root auth entry the guard expects.  The SAC
    // `transfer(from=wallet)` is a sub-invocation covered by the
    // root entry and does NOT appear as a separate root entry.
    //
    // Cited: soroswap-core contracts/router/src/lib.rs.
    let swap_fn_sym: StringM<32> =
        "swap_exact_tokens_for_tokens"
            .try_into()
            .map_err(|_| AuthGuardError::SimulateFailed {
                reason: "SWAP_FN symbol too long (unexpected)".to_owned(),
            })?;

    // swap args are already positional-encoded with to=wallet_address.
    let swap_args_vecm: VecM<ScVal> =
        swap_args
            .to_vec()
            .try_into()
            .map_err(|_| AuthGuardError::SimulateFailed {
                reason: "swap args VecM overflow (unexpected)".to_owned(),
            })?;

    let invoke_args = InvokeContractArgs {
        contract_address: router_sc_addr,
        function_name: ScSymbol(swap_fn_sym),
        args: swap_args_vecm,
    };

    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke_args),
            auth: VecM::default(),
        }),
    };

    // Dummy source account for the simulate.
    // G-strkey GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF decodes
    // to 32 zero bytes; confirmed via stellar-strkey's base32-checksum round-trip.
    let operations: VecM<Operation, 100> =
        vec![operation]
            .try_into()
            .map_err(|_| AuthGuardError::SimulateFailed {
                reason: "operations VecM conversion failed (unexpected)".to_owned(),
            })?;

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
        fee: 100,
        seq_num: SequenceNumber(0),
        cond: Preconditions::None,
        memo: Memo::None,
        operations,
        ext: TransactionExt::V0,
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let client = Client::new(rpc_url).map_err(|e| AuthGuardError::SimulateFailed {
        reason: format!("RPC client construction failed: {e}"),
    })?;

    let simulate_response = client
        .simulate_transaction_envelope(&envelope, None)
        .await
        .map_err(|e| AuthGuardError::SimulateFailed {
            reason: format!("simulate_transaction_envelope failed: {e}"),
        })?;

    if let Some(err_msg) = &simulate_response.error {
        return Err(AuthGuardError::SimulateFailed {
            reason: format!("simulation returned error: {err_msg}"),
        });
    }

    // Collect auth entries from the simulate response via `.results()`.
    // An absent or empty results list yields an empty auth list.
    let auth_entries: Vec<_> = simulate_response
        .results()
        .ok()
        .and_then(|rs| rs.into_iter().next())
        .map(|r| r.auth)
        .unwrap_or_default();

    let wallet_credentialled_count =
        count_wallet_credentialled_entries(&auth_entries, &wallet_sc_addr);

    debug!(
        wallet_credentialled_count,
        total_auth_entries = auth_entries.len(),
        "multi-auth guard: auth-entry count from simulate"
    );

    let result = classify_auth_entry_count(wallet_credentialled_count);
    match &result {
        Ok(_) => debug!("multi-auth guard: exactly 1 wallet-credentialled root entry — OK"),
        Err(AuthGuardError::NoWalletEntry) => warn!(
            total_entries = auth_entries.len(),
            "multi-auth guard: 0 wallet-credentialled root entries; expected 1"
        ),
        Err(AuthGuardError::UnexpectedMultipleEntries { count }) => warn!(
            count = *count,
            "multi-auth guard: unexpected multi-entry auth; refusing (unexpected contract shape)"
        ),
        Err(_) => {}
    }
    result
}

/// Counts the root auth entries whose credentials address the wallet
/// smart-account.
///
/// An entry counts only when its credentials are
/// `SorobanCredentials::Address` and the credential address equals
/// `wallet_sc_addr`.
fn count_wallet_credentialled_entries(
    entries: &[stellar_xdr::SorobanAuthorizationEntry],
    wallet_sc_addr: &ScAddress,
) -> usize {
    entries
        .iter()
        .filter(|entry| match &entry.credentials {
            SorobanCredentials::Address(creds) => &creds.address == wallet_sc_addr,
            // Exhaustive (no wildcard) so a future stellar-xdr credential variant
            // forces a decision here.  Only `Address` credentials are countable:
            // the smart-account submit path signs `Address`-credentialled entries
            // only and rejects `AddressV2`/`AddressWithDelegates`, so counting
            // those here would admit an entry the submit path cannot sign.
            SorobanCredentials::SourceAccount
            | SorobanCredentials::AddressV2(_)
            | SorobanCredentials::AddressWithDelegates(_) => false,
        })
        .count()
}

/// Enforces the ROUTER-DIRECT count invariant: exactly 1 wallet-credentialled
/// root auth entry.
///
/// - `0` → [`AuthGuardError::NoWalletEntry`]
/// - `1` → `Ok(1)`
/// - `n > 1` → [`AuthGuardError::UnexpectedMultipleEntries`]
fn classify_auth_entry_count(count: usize) -> Result<usize, AuthGuardError> {
    match count {
        0 => Err(AuthGuardError::NoWalletEntry),
        1 => Ok(1),
        n => Err(AuthGuardError::UnexpectedMultipleEntries { count: n }),
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
        reason = "test-only fixture construction"
    )]

    use super::*;
    use stellar_xdr::{
        InvokeContractArgs, SorobanAddressCredentials, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    };

    // ── Helpers ──────────────────────────────────────────────────────────────

    const TEST_WALLET: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";

    fn make_wallet_sc_addr() -> ScAddress {
        let bytes = stellar_strkey::Contract::from_string(TEST_WALLET)
            .expect("valid C-strkey")
            .0;
        ScAddress::Contract(ContractId(Hash(bytes)))
    }

    fn make_other_sc_addr() -> ScAddress {
        // Different address — not the wallet.
        let bytes = stellar_strkey::Contract::from_string(
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        )
        .expect("valid C-strkey")
        .0;
        ScAddress::Contract(ContractId(Hash(bytes)))
    }

    fn make_auth_entry_for(addr: ScAddress) -> SorobanAuthorizationEntry {
        let dummy_invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: addr.clone(),
                function_name: ScSymbol(StringM::default()),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        };
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: addr,
                nonce: 0,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: dummy_invocation,
        }
    }

    // ── Unit tests for the production counting + classification logic ─────────

    /// Exactly 1 wallet-credentialled entry → count = 1 (pass).
    #[test]
    fn one_wallet_entry_returns_one() {
        let wallet_addr = make_wallet_sc_addr();
        let entries = vec![make_auth_entry_for(wallet_addr.clone())];
        let count = count_wallet_credentialled_entries(&entries, &wallet_addr);
        assert_eq!(count, 1, "one wallet entry must yield count=1");
    }

    /// 2 wallet-credentialled entries → count = 2 (guard would refuse).
    #[test]
    fn two_wallet_entries_returns_two() {
        let wallet_addr = make_wallet_sc_addr();
        let entries = vec![
            make_auth_entry_for(wallet_addr.clone()),
            make_auth_entry_for(wallet_addr.clone()),
        ];
        let count = count_wallet_credentialled_entries(&entries, &wallet_addr);
        assert_eq!(count, 2, "two wallet entries must yield count=2");
        let result = classify_auth_entry_count(count);
        assert!(
            matches!(
                result,
                Err(AuthGuardError::UnexpectedMultipleEntries { count: 2 })
            ),
            "two entries must produce UnexpectedMultipleEntries(2)"
        );
    }

    /// 0 wallet-credentialled entries (different address only) → count = 0 (guard would refuse).
    #[test]
    fn no_wallet_entries_returns_zero() {
        let wallet_addr = make_wallet_sc_addr();
        let other_addr = make_other_sc_addr();
        let entries = vec![make_auth_entry_for(other_addr)];
        let count = count_wallet_credentialled_entries(&entries, &wallet_addr);
        assert_eq!(count, 0, "non-wallet entry must not count");
        let result = classify_auth_entry_count(count);
        assert!(
            matches!(result, Err(AuthGuardError::NoWalletEntry)),
            "zero wallet entries must produce NoWalletEntry"
        );
    }

    /// Mixed: 1 wallet + 1 non-wallet → count = 1 (only wallet-credentialled root entries count).
    #[test]
    fn mixed_entries_counts_only_wallet_credentialled() {
        let wallet_addr = make_wallet_sc_addr();
        let other_addr = make_other_sc_addr();
        let entries = vec![
            make_auth_entry_for(wallet_addr.clone()),
            make_auth_entry_for(other_addr),
        ];
        let count = count_wallet_credentialled_entries(&entries, &wallet_addr);
        assert_eq!(count, 1, "only wallet-credentialled root entries count");
        let result = classify_auth_entry_count(count);
        assert!(result.is_ok(), "one wallet entry among others must pass");
    }

    /// SourceAccount credentials are never counted — only `Address`-credentialled
    /// root entries count toward the wallet total.
    #[test]
    fn source_account_credential_not_counted() {
        let wallet_addr = make_wallet_sc_addr();
        let source_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: wallet_addr.clone(),
                    function_name: ScSymbol(StringM::default()),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        };
        let entries = vec![source_entry, make_auth_entry_for(wallet_addr.clone())];
        // Only the Address-credentialled entry counts; the SourceAccount one is excluded.
        assert_eq!(
            count_wallet_credentialled_entries(&entries, &wallet_addr),
            1
        );
    }

    // ── Error Display audit ──────────────────────────────────────────────────

    #[test]
    fn no_wallet_entry_display_no_address_leak() {
        let err = AuthGuardError::NoWalletEntry;
        let display = err.to_string();
        // Must not echo a full C-strkey.
        assert!(
            !display.contains(TEST_WALLET),
            "NoWalletEntry display must not leak full address"
        );
    }

    #[test]
    fn multi_entry_display_contains_count() {
        let err = AuthGuardError::UnexpectedMultipleEntries { count: 3 };
        let display = err.to_string();
        assert!(display.contains('3'), "display must contain count");
        assert!(
            !display.contains(TEST_WALLET),
            "display must not leak full wallet address"
        );
    }
}

//! Adversarial / wiring fixture: `SignersManager::get_spending_limit_data`.
//!
//! Proves the read path end-to-end through a mocked RPC (not just the isolated
//! `decode_spending_limit_data` unit tests, which never touch the
//! `simulate_read_only_with_ledger` call site): a full `SpendingLimitData`
//! simulation response decodes correctly AND carries the `as_of_ledger`
//! through, and an on-chain `SmartAccountNotInstalled` (code 3220) simulation
//! error maps to the typed `SpendingLimitNotInstalled`, not a raw decode error.

use std::sync::Arc;

use stellar_agent_smart_account::error::SaError;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::rpc_mock_helpers::{
    SOURCE_G, SorobanRpcDispatcher, build_ledger_entries_account, manager_one_url,
    policy_sc_address, tmp_audit_writer, zero_sc_address,
};

// ── ScVal fixture builder ─────────────────────────────────────────────────────

/// Builds a well-formed `SpendingLimitData` `ScVal::Map` (alphabetical key
/// order: `cached_total_spent`, `period_ledgers`, `spending_history`,
/// `spending_limit`) and encodes it to XDR base64, matching the on-chain
/// `#[contracttype]` layout (`packages/accounts/src/policies/spending_limit.rs:99-108`,
/// SHA `a9c4216`).
fn build_spending_limit_data_scval_xdr(
    spending_limit: i128,
    period_ledgers: u32,
    history: &[(i128, u32)],
    cached_total_spent: i128,
) -> String {
    use stellar_xdr::{
        Int128Parts, Limits, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, VecM, WriteXdr,
    };

    let sym = |s: &str| ScVal::Symbol(ScSymbol(s.as_bytes().to_vec().try_into().expect("fits")));
    let i128_val = |v: i128| {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "canonical i128 -> Int128Parts split"
        )]
        ScVal::I128(Int128Parts {
            hi: (v >> 64) as i64,
            lo: v as u64,
        })
    };

    let entry_vals: VecM<ScVal> = history
        .iter()
        .map(|&(amount, seq)| {
            let entries: VecM<ScMapEntry> = vec![
                ScMapEntry {
                    key: sym("amount"),
                    val: i128_val(amount),
                },
                ScMapEntry {
                    key: sym("ledger_sequence"),
                    val: ScVal::U32(seq),
                },
            ]
            .try_into()
            .expect("fits");
            ScVal::Map(Some(ScMap(entries)))
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("fits");

    let map: VecM<ScMapEntry> = vec![
        ScMapEntry {
            key: sym("cached_total_spent"),
            val: i128_val(cached_total_spent),
        },
        ScMapEntry {
            key: sym("period_ledgers"),
            val: ScVal::U32(period_ledgers),
        },
        ScMapEntry {
            key: sym("spending_history"),
            val: ScVal::Vec(Some(ScVec(entry_vals))),
        },
        ScMapEntry {
            key: sym("spending_limit"),
            val: i128_val(spending_limit),
        },
    ]
    .try_into()
    .expect("fits");

    ScVal::Map(Some(ScMap(map)))
        .to_xdr_base64(Limits::none())
        .expect("SpendingLimitData ScVal must encode")
}

/// Builds a `simulateTransaction` JSON-RPC result with the given `return_xdr`
/// and `latest_ledger`.
fn build_simulate_response_with_ledger(return_xdr: &str, latest_ledger: u32) -> serde_json::Value {
    serde_json::json!({
        "transactionData": "",
        "minResourceFee": "1000",
        "results": [
            {
                "auth": [],
                "xdr": return_xdr
            }
        ],
        "latestLedger": latest_ledger
    })
}

/// Builds a `simulateTransaction` JSON-RPC result carrying a simulation `error`
/// string (no `results`), the shape `SimulateTransactionResponse::error`
/// deserializes from.
fn build_simulate_error_response(error_message: &str, latest_ledger: u32) -> serde_json::Value {
    serde_json::json!({
        "error": error_message,
        "latestLedger": latest_ledger
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Happy path: a full `SpendingLimitData` return value decodes correctly and
/// the simulation's `latestLedger` is carried through as `as_of_ledger`.
#[tokio::test]
async fn get_spending_limit_data_decodes_full_response_and_carries_ledger() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let policy = policy_sc_address();
    let smart_account = zero_sc_address();

    let return_xdr =
        build_spending_limit_data_scval_xdr(10_000_000, 17_280, &[(1_000_000, 500)], 1_000_000);
    let sim = build_simulate_response_with_ledger(&return_xdr, 12_345);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(
            build_ledger_entries_account(SOURCE_G),
            sim,
        ))
        .mount(&mock_server)
        .await;

    let manager = manager_one_url(
        &mock_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let (data, as_of_ledger) = manager
        .get_spending_limit_data(
            policy,
            1,
            smart_account,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await
        .expect("well-formed response must decode");

    assert_eq!(data.spending_limit, 10_000_000);
    assert_eq!(data.period_ledgers, 17_280);
    assert_eq!(data.spending_history.len(), 1);
    assert_eq!(data.spending_history[0].amount, 1_000_000);
    assert_eq!(data.spending_history[0].ledger_sequence, 500);
    assert_eq!(data.cached_total_spent, 1_000_000);
    assert_eq!(
        as_of_ledger, 12_345,
        "as_of_ledger must equal the simulation's latestLedger"
    );
}

/// On-chain `SmartAccountNotInstalled` (code 3220) maps to the typed
/// `SpendingLimitNotInstalled`, not a raw decode/simulate error.
#[tokio::test]
async fn get_spending_limit_data_maps_3220_to_spending_limit_not_installed() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let policy = policy_sc_address();
    let smart_account = zero_sc_address();

    // Soroban-RPC surfaces contract panics as `Error(Contract, #<code>)` text.
    let sim = build_simulate_error_response("HostError: Error(Contract, #3220)", 12_345);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(
            build_ledger_entries_account(SOURCE_G),
            sim,
        ))
        .mount(&mock_server)
        .await;

    let manager = manager_one_url(
        &mock_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let result = manager
        .get_spending_limit_data(
            policy,
            7,
            smart_account,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SpendingLimitNotInstalled { rule_id: 7, .. })
        ),
        "on-chain error 3220 must map to SpendingLimitNotInstalled, not a raw decode error; \
         got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.spending_limit_not_installed"
    );
}

/// A simulation error unrelated to code 3220 propagates as the generic
/// `DeploymentFailed`, NOT `SpendingLimitNotInstalled` — the 3220 mapping must
/// not over-match arbitrary simulate failures.
#[tokio::test]
async fn get_spending_limit_data_other_simulate_errors_are_not_remapped() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let policy = policy_sc_address();
    let smart_account = zero_sc_address();

    let sim = build_simulate_error_response("HostError: Error(Contract, #3221)", 12_345);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(
            build_ledger_entries_account(SOURCE_G),
            sim,
        ))
        .mount(&mock_server)
        .await;

    let manager = manager_one_url(
        &mock_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let result = manager
        .get_spending_limit_data(
            policy,
            7,
            smart_account,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(result, Err(SaError::DeploymentFailed { .. })),
        "a non-3220 simulate error must propagate as DeploymentFailed; got: {result:?}"
    );
}

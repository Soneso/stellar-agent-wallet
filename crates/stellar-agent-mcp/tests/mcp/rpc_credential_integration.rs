//! The classic read tools send the profile's primary credential, and a
//! missing credential reaches the agent as the keyring code.
//!
//! The mock endpoint answers HTTP 401 to any request without the credential,
//! so a read whose client lost it gets no answer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use serial_test::serial;
use stellar_agent_core::profile::schema::{Profile, ProviderRole};
use stellar_agent_mcp::server::{
    StellarBalancesArgs, StellarFeeStatsArgs, StellarPayArgs, StellarTransactionStatusArgs,
    WalletServer,
};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_balance, account_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer};

const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

fn profile_on(rpc_url: &str) -> Profile {
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = rpc_url.to_owned();
    crate::common::install_test_audit_key(&mut profile);
    profile
}

async fn keyed_endpoint() -> MockServer {
    let server = MockServer::start().await;
    crate::common::require_rpc_credential(&server).await;
    Mock::given(method("POST"))
        .respond_with(crate::common::TimeoutRpc::new(vec![(
            account_ledger_key_xdr(SOURCE_G),
            account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
        )]))
        .mount(&server)
        .await;
    server
}

/// Runs the three read tools on `server` and returns their results.
async fn run_reads(server: &WalletServer) -> Vec<(&'static str, rmcp::model::CallToolResult)> {
    vec![
        (
            "stellar_balances",
            server
                .call_stellar_balances(StellarBalancesArgs {
                    chain_id: "stellar:testnet".to_owned(),
                    account_id: SOURCE_G.to_owned(),
                    assets: Vec::new(),
                })
                .await
                .expect("no protocol error"),
        ),
        (
            "stellar_transaction_status",
            server
                .call_stellar_transaction_status(StellarTransactionStatusArgs {
                    chain_id: "stellar:testnet".to_owned(),
                    tx_hash: "cd".repeat(32),
                })
                .await
                .expect("no protocol error"),
        ),
        (
            "stellar_fee_stats",
            server
                .call_stellar_fee_stats(StellarFeeStatsArgs {
                    chain_id: "stellar:testnet".to_owned(),
                    rpc_url: None,
                })
                .await
                .expect("no protocol error"),
        ),
    ]
}

/// Each read tool sends the primary credential and gets its answer; without
/// the credential each read goes out bare and is refused.
#[tokio::test]
#[serial]
async fn read_tools_send_the_primary_credential() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let endpoint = keyed_endpoint().await;
    let mut profile = profile_on(&endpoint.uri());
    crate::common::bind_rpc_credential(&mut profile, ProviderRole::Primary, true);
    let server = WalletServer::new(profile).expect("WalletServer::new");
    for (tool, result) in run_reads(&server).await {
        assert_ne!(result.is_error, Some(true), "{tool}: {result:?}");
    }
    let trace = crate::common::credential_trace(&endpoint).await;
    let methods: Vec<&str> = trace.iter().map(|(method, _)| method.as_str()).collect();
    for read in ["getLedgerEntries", "getTransaction", "getFeeStats"] {
        assert!(methods.contains(&read), "{read}: {trace:?}");
    }
    assert!(trace.iter().all(|(_, keyed)| *keyed), "{trace:?}");

    let endpoint = keyed_endpoint().await;
    let server = WalletServer::new(profile_on(&endpoint.uri())).expect("WalletServer::new");
    for (tool, result) in run_reads(&server).await {
        assert_eq!(result.is_error, Some(true), "{tool}: {result:?}");
    }
    let trace = crate::common::credential_trace(&endpoint).await;
    assert!(!trace.is_empty());
    assert!(trace.iter().all(|(_, keyed)| !keyed), "{trace:?}");
}

/// A credential the profile names but the keyring lacks reaches the agent as
/// `auth.keyring_not_found` naming the entry, from a prepare tool and from a
/// read tool, and no request leaves.
#[tokio::test]
#[serial]
async fn missing_primary_credential_reports_keyring_not_found() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let endpoint = keyed_endpoint().await;
    let mut profile = profile_on(&endpoint.uri());
    crate::common::bind_rpc_credential(&mut profile, ProviderRole::Primary, false);
    let server = WalletServer::new(profile).expect("WalletServer::new");
    let pay = server
        .call_stellar_pay(StellarPayArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE_G.to_owned(),
            destination: DEST_G.to_owned(),
            amount: Some(serde_json::from_str(r#""10 XLM""#).unwrap()),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            classic_base: None,
        })
        .await
        .expect("a credential failure is a tool result, not a protocol error");
    let balances = server
        .call_stellar_balances(StellarBalancesArgs {
            chain_id: "stellar:testnet".to_owned(),
            account_id: SOURCE_G.to_owned(),
            assets: Vec::new(),
        })
        .await
        .expect("a credential failure is a tool result, not a protocol error");
    for result in [pay, balances] {
        let (code, message, _text) = crate::common::assert_business_envelope(&result);
        assert_eq!(code, "auth.keyring_not_found");
        assert!(
            message.contains("stellar-agent-rpc-mcp-test/primary"),
            "{message}"
        );
    }
    assert!(crate::common::received_methods(&endpoint).await.is_empty());
}

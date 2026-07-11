//! `submit_signed_invoke`'s `SubmitInvokeArgs::sequence_floor` threading.
//!
//! `submit_signed_invoke` is the SHARED free function every DeFi adapter
//! family (`stellar-agent-blend`, `stellar-agent-dex`, `stellar-agent-defindex`)
//! calls to submit its signed `InvokeHostFunction`. Proving the hook is wired
//! correctly HERE — once, at the shared substrate — covers all adapter
//! families without duplicating a full per-protocol simulate/auth/submit mock
//! harness that does not exist anywhere else in this codebase (every adapter
//! crate's OWN full-submit success path is validated by a LIVE testnet
//! acceptance test, never wiremock; see `stellar-agent-blend`'s
//! `blend_lend_testnet_acceptance.rs` module doc). A live confirmed submit
//! recording into the hook is covered by
//! `stellar-agent-blend/tests/blend_supply_submit_testnet_acceptance.rs`.
//!
//! # Coverage map
//!
//! | Test | Mechanism | Coverage |
//! |------|-----------|----------|
//! | [`initial_fetch_consults_the_sequence_floor_hook`] | wiremock (`SorobanRpcDispatcher`) | Step 1's account fetch calls `hook.floor()` before Step 2 (simulate) runs — proven by short-circuiting at a `simulateTransaction` error response right after the fetch |
//! | [`no_hook_reproduces_plain_fetch_behaviour`] | wiremock | `sequence_floor: None` (the default every non-DeFi caller uses) takes the identical code path with zero hook calls — back-compat proof |

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction"
)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::submit::{SubmitInvokeArgs, submit_signed_invoke};
use stellar_xdr::{ContractId, Hash, HostFunction, InvokeContractArgs, ScAddress, ScSymbol, VecM};
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use rpc_mock_helpers::{SOURCE_G, SorobanRpcDispatcher, build_ledger_entries_account};

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";

/// A well-formed, zero-hash C-strkey. `target_contract` requires a C-strkey
/// (unlike `SOURCE_G`, the source account's G-strkey); the tests here never
/// reach on-chain resolution of this address, only its strkey-to-`ScAddress`
/// parse at the top of `submit_signed_invoke`.
const DUMMY_C_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// Stub signer whose public key is the all-zero pubkey `SOURCE_G` decodes to.
/// Only `public_key()` is exercised — the tests here short-circuit at the
/// simulate stage, before any signing call.
struct AllZeroPubkeySigner;

#[async_trait::async_trait]
impl stellar_agent_network::signing::Signer for AllZeroPubkeySigner {
    async fn sign_tx_payload(
        &self,
        _: &[u8; 32],
    ) -> Result<[u8; 64], stellar_agent_core::error::WalletError> {
        unimplemented!("not exercised before the simulate short-circuit")
    }
    async fn sign_auth_digest(
        &self,
        _: &[u8; 32],
    ) -> Result<[u8; 64], stellar_agent_core::error::WalletError> {
        unimplemented!("not exercised before the simulate short-circuit")
    }
    async fn sign_soroban_address_auth_payload(
        &self,
        _: &[u8; 32],
    ) -> Result<[u8; 64], stellar_agent_core::error::WalletError> {
        unimplemented!("not exercised before the simulate short-circuit")
    }
    async fn sign_webauthn_assertion(
        &self,
        _: &[u8; 32],
        _: &[u8],
    ) -> Result<stellar_agent_network::WebAuthnAssertion, stellar_agent_core::error::WalletError>
    {
        unimplemented!("not exercised before the simulate short-circuit")
    }
    async fn public_key(
        &self,
    ) -> Result<stellar_strkey::ed25519::PublicKey, stellar_agent_core::error::WalletError> {
        Ok(stellar_strkey::ed25519::PublicKey([0u8; 32]))
    }
}

/// Spy [`stellar_agent_network::SequenceFloorHook`] recording every `floor`
/// call (proving the hook was consulted) and every `record_confirmed` call.
#[derive(Default)]
struct SpyHook {
    floor_calls: AtomicUsize,
    recorded: Mutex<Vec<(String, i64)>>,
}

#[async_trait::async_trait]
impl stellar_agent_network::SequenceFloorHook for SpyHook {
    async fn floor(&self, _account_id: &str) -> Option<i64> {
        self.floor_calls.fetch_add(1, Ordering::Relaxed);
        None
    }

    async fn record_confirmed(&self, account_id: &str, consumed_sequence: i64) {
        self.recorded
            .lock()
            .expect("lock")
            .push((account_id.to_owned(), consumed_sequence));
    }
}

fn dummy_host_function() -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash([0x55u8; 32]))),
        function_name: ScSymbol::try_from("noop").expect("valid symbol"),
        args: VecM::default(),
    })
}

/// Step 1's account fetch calls `hook.floor()` — proven by mounting a
/// `simulateTransaction` ERROR response (Step 2) so `submit_signed_invoke`
/// returns promptly right after the fetch, without needing a full
/// simulate/auth/submit success fixture.
#[tokio::test]
async fn initial_fetch_consults_the_sequence_floor_hook() {
    let server = MockServer::start().await;
    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let simulate_error = serde_json::json!({
        "error": "Error(Contract, #9999)",
        "latestLedger": 1000
    });
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_error))
        .mount(&server)
        .await;

    let signer = AllZeroPubkeySigner;
    let hook = SpyHook::default();
    let auth_rule_ids = [ContextRuleId::new(0)];

    let result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(DUMMY_C_STRKEY)
            .auth_rule_ids(&auth_rule_ids)
            .host_function(dummy_host_function())
            .signer(&signer)
            .primary_rpc_url(server.uri().as_str())
            .network_passphrase(NETWORK_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(std::time::Duration::from_secs(10))
            .op_label("test_sequence_floor")
            .sequence_floor(&hook)
            .build(),
    )
    .await;

    assert!(
        matches!(
            result,
            Err(SaError::DeploymentFailed {
                phase: "simulate",
                ..
            })
        ),
        "expected the simulate-error short-circuit; got {result:?}"
    );
    assert_eq!(
        hook.floor_calls.load(Ordering::Relaxed),
        1,
        "the Step-1 account fetch must consult the sequence-floor hook exactly once"
    );
    assert!(
        hook.recorded.lock().expect("lock").is_empty(),
        "a submit that never reaches confirmation must never record a consumed sequence"
    );
}

/// `sequence_floor: None` (every caller other than the DeFi adapter submit
/// paths) reproduces the identical error and consults no hook — the
/// back-compat default.
#[tokio::test]
async fn no_hook_reproduces_plain_fetch_behaviour() {
    let server = MockServer::start().await;
    let ledger_resp = build_ledger_entries_account(SOURCE_G);
    let simulate_error = serde_json::json!({
        "error": "Error(Contract, #9999)",
        "latestLedger": 1000
    });
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new(ledger_resp, simulate_error))
        .mount(&server)
        .await;

    let signer = AllZeroPubkeySigner;
    let auth_rule_ids = [ContextRuleId::new(0)];

    let result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(DUMMY_C_STRKEY)
            .auth_rule_ids(&auth_rule_ids)
            .host_function(dummy_host_function())
            .signer(&signer)
            .primary_rpc_url(server.uri().as_str())
            .network_passphrase(NETWORK_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(std::time::Duration::from_secs(10))
            .op_label("test_sequence_floor_none")
            .build(),
    )
    .await;

    assert!(
        matches!(
            result,
            Err(SaError::DeploymentFailed {
                phase: "simulate",
                ..
            })
        ),
        "sequence_floor: None must reproduce the identical simulate-error outcome; got {result:?}"
    );
}

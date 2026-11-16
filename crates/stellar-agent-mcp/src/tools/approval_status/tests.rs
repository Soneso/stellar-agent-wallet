#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures and assertions"
)]

use super::*;
use serde_json::{Value, json};
use serial_test::serial;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use stellar_agent_core::{
    approval::{PendingApprovalStore, fixtures, mainnet_fixtures::ALLOWED_DESTINATION},
    policy::{
        Decision, DenyReason, PolicyEngine, PolicyError, ToolDescriptor, ToolValueKind,
        v1::{
            PolicyStateStore,
            criteria::state_store::{StateKey, WindowEntry, WindowLimit},
        },
    },
    profile::schema::Profile,
};
use stellar_agent_network::policy_state::PersistedWindowStore;

struct Engine {
    state: PolicyStateStore,
    decision: AtomicUsize,
    calls: AtomicUsize,
}
impl PolicyEngine for Engine {
    fn evaluate_in_snapshot(
        &self,
        inputs: stellar_agent_core::policy::PolicyEvaluationInputs<'_>,
        snapshot: &stellar_agent_core::policy::PolicyEvaluationSnapshot,
    ) -> Result<stellar_agent_core::policy::Evaluation, PolicyError> {
        self.evaluate_full(
            inputs.tool,
            inputs.args,
            inputs.profile,
            inputs.account_view,
            inputs.identity_view,
            inputs.counterparty_cache,
            inputs.sep10_sessions,
            inputs.sep45_sessions,
            snapshot.now_ms(),
        )
    }

    fn evaluate(
        &self,
        _: &ToolDescriptor,
        _: &Value,
        _: &Profile,
        _: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        _: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
        _: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView>,
        _: Option<&dyn stellar_agent_core::policy::v1::Sep10SessionView>,
        _: Option<&dyn stellar_agent_core::policy::v1::Sep45SessionView>,
        now: u64,
    ) -> Result<Decision, PolicyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            self.state
                .query_window(&StateKey::new("snapshot", 1, "native", 3600), now)
                .unwrap()
                .0,
            7,
            "dispatch uses facade-derived counters"
        );
        match self.decision.load(Ordering::SeqCst) {
            0 => Ok(Decision::Allow),
            1 => Ok(Decision::Deny(DenyReason::NoMatchingRule)),
            _ => Err(PolicyError::CriterionEvaluationFailed {
                detail: "fixture refusal".into(),
            }),
        }
    }
    fn window_state_store(&self) -> Option<&PolicyStateStore> {
        Some(&self.state)
    }
}

fn value(result: &CallToolResult) -> Value {
    serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
}

#[tokio::test]
#[serial(keyring)]
#[serial]
async fn approval_status_dispatch_uses_one_snapshot_and_preserves_refusals() {
    let root = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(root.path());
    let profile =
        Profile::builder_testnet_named("snapshot", "snapshot-sign", "key", "snapshot-nonce", "key")
            .with_noop_engine()
            .build();
    let reads = Arc::new(AtomicUsize::new(0));
    let counter = reads.clone();
    let key = &profile.policy_window_state_key_id;
    stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
        stellar_agent_test_support::keyring_mock::ReadHook::new(
            &key.service,
            &key.account,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        ),
    ])
    .unwrap();
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let store = PersistedWindowStore::for_profile("snapshot");
    let state_key = StateKey::new("snapshot", 1, "native", 3600);
    store
        .record_and_persist(
            &profile,
            &[WindowEntry::new(
                state_key.clone(),
                now,
                7,
                WindowLimit::Amount {
                    asset: "native".into(),
                    window: "1h".into(),
                    max_stroops: 100,
                },
            )],
        )
        .unwrap();
    let entry = fixtures::payment_pending(
        ALLOWED_DESTINATION,
        ALLOWED_DESTINATION,
        "XLM",
        10,
        None,
        100,
        7,
        "123".into(),
        600_000,
    );
    let mut server = WalletServer::new(profile.clone()).unwrap();
    let inbox = server.resolve_approval_dir().unwrap().join("snapshot.toml");
    PendingApprovalStore::open(inbox.clone())
        .unwrap()
        .insert(entry.clone(), now)
        .unwrap();
    let engine = Arc::new(Engine {
        state: PolicyStateStore::new(),
        decision: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
    });
    server.set_policy_engine_for_test(engine.clone());
    let window_before = std::fs::read(store.path()).unwrap();
    let inbox_before = std::fs::read(&inbox).unwrap();
    for (decision, code) in [
        (0, None),
        (1, Some("policy.deny.no_matching_rule")),
        (2, Some("policy.engine_required")),
    ] {
        engine.state.append(&state_key, now, 99).unwrap();
        engine.decision.store(decision, Ordering::SeqCst);
        reads.store(0, Ordering::SeqCst);
        let result = server
            .approval_status_for_test(entry.approval_nonce.clone())
            .await
            .unwrap();
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "one authenticated snapshot including dispatch"
        );
        assert_eq!(result.is_error == Some(true), code.is_some());
        match code {
            Some(code) => assert_eq!(
                value(&result)["error"]["code"],
                code,
                "status preserves policy refusals"
            ),
            None => assert_eq!(value(&result)["data"]["state"], "pending"),
        }
        assert_eq!(
            std::fs::read(store.path()).unwrap(),
            window_before,
            "status leaves window bytes unchanged"
        );
        assert_eq!(std::fs::read(&inbox).unwrap(), inbox_before);
    }
    assert_eq!(engine.calls.load(Ordering::SeqCst), 3);
    engine.decision.store(0, Ordering::SeqCst);
    reads.store(0, Ordering::SeqCst);
    assert!(
        server
            .dispatch_gate(
                "stellar_fee_stats",
                &json!({"chain_id":"stellar:testnet"}),
                "stellar:testnet"
            )
            .await
            .is_ok()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2, "other gates still hydrate");
    let mut corrupt = window_before.clone();
    corrupt[0] ^= 1;
    std::fs::write(store.path(), corrupt).unwrap();
    let before = engine.calls.load(Ordering::SeqCst);
    let result = server
        .approval_status_for_test(entry.approval_nonce.clone())
        .await
        .unwrap();
    assert_eq!(
        value(&result)["error"]["code"],
        "policy.engine_required",
        "hydration failures retain the existing gate mapping"
    );
    assert_eq!(
        engine.calls.load(Ordering::SeqCst),
        before,
        "unverified state never reaches evaluation"
    );
    std::fs::write(store.path(), window_before).unwrap();
    assert_ne!(
        server
            .approval_status_for_test(entry.approval_nonce.clone())
            .await
            .unwrap()
            .is_error,
        Some(true)
    );
    struct FailedClock;
    impl stellar_agent_core::timefmt::Clock for FailedClock {
        fn now_unix_ms(&self) -> Result<u64, stellar_agent_core::wallet::WalletLifecycleError> {
            Err(
                stellar_agent_core::wallet::WalletLifecycleError::ClockError {
                    detail: "unrepresentable clock".into(),
                    source: None,
                },
            )
        }
    }
    server.set_clock_for_test(Arc::new(FailedClock));
    reads.store(0, Ordering::SeqCst);
    let result = server
        .approval_status_for_test(entry.approval_nonce)
        .await
        .unwrap();
    assert_eq!(
        value(&result)["error"]["code"],
        "wallet.clock_error",
        "clock failure remains typed"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[serial(keyring)]
#[serial]
async fn approval_status_retires_an_earlier_build_window_in_memory() {
    let root = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(root.path());
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let profile =
        Profile::builder_testnet_named("snapshot", "snapshot-sign", "key", "snapshot-nonce", "key")
            .with_noop_engine()
            .build();
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let store = PersistedWindowStore::for_profile("snapshot");
    store
        .record_and_persist(
            &profile,
            &[WindowEntry::new(
                StateKey::new("snapshot", 1, "native", 3600),
                now,
                7,
                WindowLimit::Amount {
                    asset: "native".into(),
                    window: "1h".into(),
                    max_stroops: 100,
                },
            )],
        )
        .unwrap();
    store.seal_earlier_build_for_test(&profile, None).unwrap();
    let entry = fixtures::payment_pending(
        ALLOWED_DESTINATION,
        ALLOWED_DESTINATION,
        "XLM",
        10,
        None,
        100,
        7,
        "123".into(),
        600_000,
    );
    let mut server = WalletServer::new(profile.clone()).unwrap();
    let inbox = server.resolve_approval_dir().unwrap().join("snapshot.toml");
    PendingApprovalStore::open(inbox)
        .unwrap()
        .insert(entry.clone(), now)
        .unwrap();
    let engine = Arc::new(Engine {
        state: PolicyStateStore::new(),
        decision: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
    });
    server.set_policy_engine_for_test(engine.clone());
    let earlier = std::fs::read(store.path()).unwrap();
    let result = server
        .approval_status_for_test(entry.approval_nonce.clone())
        .await
        .unwrap();
    assert_eq!(value(&result)["data"]["state"], "pending");
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read(store.path()).unwrap(),
        earlier,
        "status retires an earlier build only in memory"
    );

    store
        .seal_earlier_build_for_test(&profile, Some(6))
        .unwrap();
    let unpinned = std::fs::read(store.path()).unwrap();
    let result = server
        .approval_status_for_test(entry.approval_nonce)
        .await
        .unwrap();
    assert_eq!(
        value(&result)["error"]["code"],
        "policy.total_epoch_unavailable",
        "earlier total history without a pin refuses before evaluation"
    );
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(store.path()).unwrap(), unpinned);
}

#[test]
fn approval_status_metadata_and_schema() {
    let descriptor = crate::tools::common::build_tool_registry()
        .unwrap()
        .remove("stellar_approval_status")
        .unwrap();
    assert!(
        descriptor.read_only_hint,
        "approval status declares read-only metadata"
    );
    assert!(!descriptor.destructive_hint);
    assert_eq!(descriptor.value_kind, ToolValueKind::ReadOnly);
    assert!(
        !crate::server::halt_check_applies(Some(&descriptor)),
        "inspection stays available while halted"
    );
    assert!(
        stellar_agent_core::policy::v1::mainnet_minimum::MAINNET_READ_ONLY_TOOLS
            .contains(&"stellar_approval_status"),
        "mainnet read-only inventory includes status"
    );
    let tool = WalletServer::all_registered_tools()
        .into_iter()
        .find(|tool| tool.name == "stellar_approval_status")
        .unwrap();
    assert_eq!(tool.input_schema["required"], json!(["approval_id"]));
    assert_eq!(
        tool.input_schema["properties"].as_object().unwrap().len(),
        1,
        "chain comes only from the profile"
    );
    assert_eq!(tool.input_schema["additionalProperties"], false);
    assert!(
        serde_json::from_value::<ApprovalStatusArgs>(
            json!({"approval_id":"x", "chain_id":"stellar:testnet"})
        )
        .is_err()
    );
}

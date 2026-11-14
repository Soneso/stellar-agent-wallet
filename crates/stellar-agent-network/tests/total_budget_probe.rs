//! Total-budget accounting on the testnet route: the in-memory gate of an
//! engine hydrated from the persisted window store, and the reservation
//! write a CLI or MCP pay makes after it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly"
)]

use ed25519_dalek::{Signer as _, SigningKey};
use serial_test::serial;
use stellar_agent_core::policy::pin::{self, Pin, PinScope};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::policy::v1::canonical::canonical_bytes;
use stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test;
use stellar_agent_core::policy::v1::loader::load_signed_policy_text;
use stellar_agent_core::policy::v1::signature::digest;
use stellar_agent_core::policy::v1::value::{ActionKind, ValueClass, ValueLeg};
use stellar_agent_core::policy::v1::{PolicyEngineV1, PolicyStateStore, SizingOutcome};
use stellar_agent_core::policy::{
    Decision, DenyReason, McpToolRegistration, PolicyEngine as _, ToolDescriptor, ToolValueKind,
};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::mainnet::clock::set_now_ms_for_test;
use stellar_agent_network::policy_state::{
    ChainScope, PersistedWindowStore, SubmissionHold, WindowStoreError,
};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;

const T0: u64 = 1_800_000_000_000;
const MAX_TIME_S: u64 = T0 / 1000 + 300;
const LATE: u64 = T0 + 40 * 86_400_000;
const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const NAME: &str = "tbprobe";

fn owner() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

fn profile() -> Profile {
    let mut p = Profile::builder_testnet(NAME, "acct", "n-svc", "n-acct").build();
    p.policy_window_state_key_id = KeyringEntryRef::default_policy_window_state_key(NAME);
    p
}

/// A signed v2 policy with a native `total_budget` of 10, and its digest.
fn signed_policy() -> (String, [u8; 32]) {
    let body = format!(
        "version = 2\nscope = \"profile:{NAME}\"\nsequence = 1\n\n\
         [[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"*\" }}\n\
         criteria = [{{ kind = \"total_budget\", asset = \"native\", max_stroops = 10 }}]\n\
         decision = \"allow\"\n"
    );
    let d = digest(&canonical_bytes(&body).unwrap());
    let key = owner();
    let text = format!(
        "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
        stellar_agent_core::hex::encode(&key.sign(&d).to_bytes())
    );
    (text, d)
}

fn hydrated(store: &PersistedWindowStore, profile: &Profile) -> PolicyEngineV1 {
    let memory = PolicyStateStore::new();
    store.load_into(NAME, profile, &memory).unwrap();
    let (text, d) = signed_policy();
    let document = load_signed_policy_text(
        &text,
        NAME,
        &owner().verifying_key().to_bytes(),
        &profile.network_passphrase,
    )
    .unwrap();
    PolicyEngineV1::new_with_store(document, NAME.to_owned(), memory).with_policy_digest_for_test(d)
}

/// Writes the pin of the signed policy for `store`.
fn pin_policy(store: &PersistedWindowStore, profile: &Profile) {
    let lock =
        WindowStoreLock::acquire_for(store.path(), &profile.policy_window_state_key_id).unwrap();
    pin::write_for_test(
        &lock,
        &PinScope::for_profile(store.path(), profile),
        &Pin::new(1, signed_policy().1, owner().verifying_key().to_bytes()).unwrap(),
    )
    .unwrap();
}

fn pay_tool() -> ToolDescriptor {
    ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    })
}

fn payment(amount: i128) -> ValueClass {
    ValueClass::single(ValueLeg {
        kind: ActionKind::Payment,
        amount: Some(amount),
        asset: Some("native".to_owned()),
        destination: Some(DEST.to_owned()),
    })
}

fn gate(engine: &PolicyEngineV1, profile: &Profile, amount: i128, now: u64) -> Decision {
    engine
        .evaluate_with_value_full(
            &pay_tool(),
            &serde_json::Value::Null,
            profile,
            payment(amount),
            None,
            None,
            None,
            None,
            None,
            now,
        )
        .unwrap()
        .decision
}

fn hold(n: u8) -> SubmissionHold {
    SubmissionHold {
        chain_scope: ChainScope::for_chain(Caip2::Testnet),
        submission_anchor: None,
        id: format!("{n:02x}").repeat(32),
        tx_hash: format!("{:02x}", n ^ 0x80).repeat(32),
        source: "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM".to_owned(),
        sequence: 100 + i64::from(n),
        max_time: MAX_TIME_S,
        pending_since_ms: T0,
        submission_ledger: 1,
        operator_required: false,
    }
}

/// One testnet pay of 6: the gate, the recorder's sizing, and the
/// reservation write.
fn pay(
    store: &PersistedWindowStore,
    engine: &PolicyEngineV1,
    profile: &Profile,
    n: u8,
    now: u64,
) -> (Decision, Result<(), WindowStoreError>) {
    let _q = set_query_time_for_test(now);
    let decision = gate(engine, profile, 6, now);
    let SizingOutcome::Sized(sizing) = engine
        .record_confirmed_checked(&pay_tool(), profile, &payment(6))
        .unwrap()
    else {
        panic!("the pay sizes no entry");
    };
    let entries = sizing.entries().to_vec();
    let reserved = store.record_pending(profile, &entries, &hold(n)).map(drop);
    (decision, reserved)
}

/// Pays 6, confirms it, then pays 6 again after a fresh hydration past
/// every horizon: both the gate and the reservation refuse.
#[test]
#[serial]
fn testnet_total_survives_hydration() {
    keyring_mock::install().unwrap();
    let clock = set_now_ms_for_test(T0);
    let dir = TempDir::new().unwrap();
    let profile = profile();
    let store = PersistedWindowStore::at_path(dir.path().join("probe.window"));
    pin_policy(&store, &profile);
    let engine = hydrated(&store, &profile);
    let (decision, reserved) = pay(&store, &engine, &profile, 1, T0);
    assert_eq!(decision, Decision::Allow);
    reserved.unwrap();
    clock.set(T0 + 100);
    store
        .confirm(&profile, &"01".repeat(32), Some(1_800_000_000))
        .unwrap();

    clock.set(LATE);
    let reopened = PersistedWindowStore::at_path(store.path().to_owned());
    let late_engine = hydrated(&reopened, &profile);
    let (decision, reserved) = pay(&reopened, &late_engine, &profile, 2, LATE);
    assert!(
        matches!(
            decision,
            Decision::Deny(DenyReason::TotalBudgetExhausted { .. })
        ),
        "the hydrated gate admits: {decision:?}"
    );
    assert!(
        matches!(
            &reserved,
            Err(WindowStoreError::PolicyDenied { reason })
                if matches!(**reason, DenyReason::TotalBudgetExhausted { .. })
        ),
        "the reservation admits: {reserved:?}"
    );
}

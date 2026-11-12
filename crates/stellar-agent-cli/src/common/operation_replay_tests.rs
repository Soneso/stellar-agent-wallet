//! Business ids at the CLI value verbs.
//!
//! A mainnet value run names its operation with `--business-id`. The record
//! opens before the confirmation ceremony. A retry under a retained id
//! prints the stored state and runs no confirmation ceremony, signs nothing
//! and sends nothing. Another intent under the same id refuses, and a
//! mainnet run without an id refuses. Off mainnet the id is validated and
//! echoed, and no record exists. The rows drive `pay`, `claim`,
//! `accounts create` and `trustline` on the routed fixture.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction and assertions"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use stellar_agent_network::policy_state::{
    BusinessId, OperationId, OperationResult, OperationState, OperationView, SlotKind,
};

use crate::commands::accounts::create::tests::mainnet_full as create;
use crate::commands::claim::tests::mainnet_full as claim;
use crate::commands::pay::tests::mainnet_full as pay;
use crate::commands::trustline::tests::mainnet_full as trustline;
use crate::common::business_entry::{
    fresh_business_id, replay_exit_code, take_printed_replays_for_test,
};
use crate::common::mainnet_write_fixture::{
    AGENT_SEED, AGENT_VAR, DESTINATION, ISSUER, MainnetFixture, Spec, TRUSTLINE_ASSET, claim_rule,
    create_rule, pay_rule, trustline_rule,
};
use crate::test_rpc::ClassicRpc;

/// One of the four classic value verbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verb {
    Pay,
    Claim,
    CreateAccount,
    Trustline,
}

/// Which test a fixture serves; every fixture names its own profile.
#[derive(Clone, Copy, Debug)]
enum Row {
    Replay,
    Conflict,
    Required,
    Testnet,
    Ceremony,
}

/// What a run asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Intent {
    /// The fixture's default action.
    Default,
    /// The default action with one fact changed.
    Other,
}

/// One run of a verb: its exit code and the envelope it printed.
struct VerbRun {
    code: i32,
    envelope: Value,
}

impl VerbRun {
    fn error_code(&self) -> &str {
        self.envelope["error"]["code"].as_str().unwrap_or("")
    }
}

impl Verb {
    const ALL: [Self; 4] = [Self::Pay, Self::Claim, Self::CreateAccount, Self::Trustline];

    /// The profile name of the fixture serving `row`, unique in the
    /// process because the audit writer registry is process-wide.
    fn name(self, row: Row) -> &'static str {
        match (row, self) {
            (Row::Replay, Self::Pay) => "replay-pay",
            (Row::Replay, Self::Claim) => "replay-claim",
            (Row::Replay, Self::CreateAccount) => "replay-create",
            (Row::Replay, Self::Trustline) => "replay-trustline",
            (Row::Conflict, Self::Pay) => "conflict-pay",
            (Row::Conflict, Self::Claim) => "conflict-claim",
            (Row::Conflict, Self::CreateAccount) => "conflict-create",
            (Row::Conflict, Self::Trustline) => "conflict-trustline",
            (Row::Required, Self::Pay) => "required-pay",
            (Row::Required, Self::Claim) => "required-claim",
            (Row::Required, Self::CreateAccount) => "required-create",
            (Row::Required, Self::Trustline) => "required-trustline",
            (Row::Testnet, Self::Pay) => "testnet-echo-pay",
            (Row::Testnet, Self::Claim) => "testnet-echo-claim",
            (Row::Testnet, Self::CreateAccount) => "testnet-echo-create",
            (Row::Testnet, Self::Trustline) => "testnet-echo-trustline",
            (Row::Ceremony, Self::Pay) => "ceremony-pay",
            (Row::Ceremony, Self::Claim) => "ceremony-claim",
            (Row::Ceremony, Self::CreateAccount) => "ceremony-create",
            (Row::Ceremony, Self::Trustline) => "ceremony-trustline",
        }
    }

    /// The mainnet fixture of the verb for `row`.
    async fn mainnet(self, row: Row) -> MainnetFixture {
        let name = self.name(row);
        match self {
            Self::Pay | Self::CreateAccount => Spec::new(name),
            Self::Claim => claim::spec(name),
            Self::Trustline => trustline::spec(name),
        }
        .build()
        .await
    }

    /// The testnet fixture of the verb, its rules on `stellar:testnet`.
    async fn testnet(self) -> MainnetFixture {
        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        let spec = Spec::new(self.name(Row::Testnet)).testnet().rules(vec![
            pay_rule("allow", ""),
            create_rule("allow", ""),
            claim_rule("allow", ""),
            trustline_rule("allow", ""),
        ]);
        match self {
            Self::Pay => spec.primary(ClassicRpc::testnet(&[&agent, DESTINATION])),
            Self::CreateAccount => {
                spec.primary(ClassicRpc::testnet(&[&agent, DESTINATION, ISSUER]))
            }
            Self::Claim => spec.primary(claim::ledger(false, 100_000_000)),
            Self::Trustline => spec.primary(trustline::ledger(false, 0)).rules(vec![
                trustline_rule("allow", "").replace(TRUSTLINE_ASSET, &testnet_asset()),
            ]),
        }
        .build()
        .await
    }

    /// Runs the verb on `fixture` under `business_id` for `intent`; a
    /// testnet fixture signs from the seed in [`AGENT_VAR`].
    async fn run(
        self,
        fixture: &MainnetFixture,
        business_id: Option<&str>,
        intent: Intent,
        testnet: bool,
    ) -> VerbRun {
        let business_id = business_id.map(str::to_owned);
        let other = intent == Intent::Other;
        let signer = testnet.then(|| AGENT_VAR.to_owned());
        let (code, envelope) = match self {
            Self::Pay => {
                let mut args = pay::mainnet_args(fixture);
                args.business_id = business_id;
                args.secret_env = signer;
                if other {
                    args.amount = "2 XLM".to_owned();
                }
                let run = pay::run(fixture, &args).await;
                (run.code, run.envelope)
            }
            Self::Claim => {
                let mut args = claim::mainnet_args(fixture);
                args.business_id = business_id;
                args.secret_env = signer;
                if other {
                    // A claim is named by its balance; another one is
                    // another claim.
                    args.balance_id = "cd".repeat(32);
                }
                let run = claim::run(fixture, &args).await;
                (run.code, run.envelope)
            }
            Self::CreateAccount => {
                let mut args = create::mainnet_args(fixture);
                args.business_id = business_id;
                args.secret_env = signer;
                if other {
                    args.starting_balance = Some("3 XLM".to_owned());
                }
                let run = create::run(fixture, &args).await;
                (run.code, run.envelope)
            }
            Self::Trustline => {
                let mut args = trustline::mainnet_args(fixture);
                args.business_id = business_id;
                if testnet {
                    args.asset = testnet_asset();
                }
                if other {
                    args.limit_stroops = Some(10_000_000);
                }
                let run = trustline::run(fixture, &args).await;
                (run.code, run.envelope)
            }
        };
        VerbRun { code, envelope }
    }

    /// Runs the verb on `fixture` under `business_id` with table output and
    /// returns its exit code and the text it printed. A verb whose one output
    /// form is its JSON envelope gives `None`.
    async fn run_text(self, fixture: &MainnetFixture, business_id: &str) -> Option<(i32, String)> {
        use stellar_agent_core::envelope::OutputFormat;
        let business_id = Some(business_id.to_owned());
        take_printed_replays_for_test();
        Some(match self {
            Self::Pay => {
                let mut args = pay::mainnet_args(fixture);
                args.business_id = business_id;
                args.output = OutputFormat::Table;
                let code = pay::run_code(fixture, &args).await;
                (code, take_printed_replays_for_test().join("\n"))
            }
            Self::Claim => {
                let mut args = claim::mainnet_args(fixture);
                args.business_id = business_id;
                args.output = OutputFormat::Table;
                claim::run_text(fixture, &args).await
            }
            Self::CreateAccount => {
                let mut args = create::mainnet_args(fixture);
                args.business_id = business_id;
                args.output = OutputFormat::Table;
                let code = create::run_code(fixture, &args).await;
                (code, take_printed_replays_for_test().join("\n"))
            }
            Self::Trustline => return None,
        })
    }
}

/// The USDC asset of the testnet issuer the wallet pins.
fn testnet_asset() -> String {
    format!("USDC:{}", trustline::TESTNET_ISSUER)
}

/// The operations section of the fixture's window file, `null` without one.
fn operations(fixture: &MainnetFixture) -> Value {
    if !fixture.window_path().exists() {
        return Value::Null;
    }
    fixture.window_body()["operations"].clone()
}

/// The one operation record under `business_id`.
fn record(fixture: &MainnetFixture, business_id: &str) -> Value {
    let found: Vec<Value> = operations(fixture)["records"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|record| record["business_id"] == business_id)
        .collect();
    assert_eq!(found.len(), 1, "one record under {business_id}: {found:?}");
    found[0].clone()
}

/// Everything a run that does no new work leaves as it is.
#[derive(Debug, PartialEq)]
struct Effects {
    ceremonies: usize,
    summaries: Vec<String>,
    pending_entries: usize,
    sent: usize,
    audit_rows: usize,
    operations: Value,
}

impl Effects {
    async fn of(fixture: &MainnetFixture) -> Self {
        Self {
            ceremonies: fixture.ceremonies().len(),
            summaries: fixture.summaries(),
            pending_entries: fixture.pending_entries().len(),
            sent: fixture.sent_envelopes().await.len(),
            audit_rows: fixture.audit_row_count(),
            operations: operations(fixture),
        }
    }
}

/// The primary requests a rerun sends before its lookup answers. They are the
/// endpoint identity and readiness checks, then the reads each verb makes under
/// the readiness deadline. A payment and a claim, whose identity the arguments
/// name, read nothing. An account creation reads the sponsor, and a trustline
/// reads the issuer and the source.
fn methods_before_lookup(verb: Verb) -> Vec<String> {
    let checks = ["getNetwork", "getHealth", "getLedgers"];
    let reads: &[&str] = match verb {
        Verb::Pay | Verb::Claim => &[],
        Verb::CreateAccount => &["getLedgerEntries"],
        Verb::Trustline => &["getLedgerEntries"; 2],
    };
    checks
        .iter()
        .chain(reads)
        .map(|method| (*method).to_owned())
        .collect()
}

/// A rerun of each value verb under the business id of its completed run prints
/// the stored state with the verb's exit code for it. It prints its JSON
/// envelope and, with table output, one line. It runs no confirmation ceremony:
/// no summary, no pending entry, no send, no audit row and no record change
/// follow the first run, and the rerun builds nothing.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_replays_its_business_id() {
    for verb in Verb::ALL {
        let fixture = verb.mainnet(Row::Replay).await;
        let id = fresh_business_id();
        let first = verb.run(&fixture, Some(&id), Intent::Default, false).await;
        assert_eq!(first.code, 0, "{verb:?}: {}", first.envelope);
        assert_eq!(fixture.ceremonies().len(), 1, "{verb:?}");
        let stored = record(&fixture, &id);
        let before = Effects::of(&fixture).await;
        let requests = fixture.primary_methods().await.len();

        let retried = verb.run(&fixture, Some(&id), Intent::Default, false).await;
        assert_eq!(
            fixture.primary_methods().await[requests..],
            methods_before_lookup(verb),
            "{verb:?}: the rerun builds nothing"
        );
        let data = &retried.envelope["data"];
        assert_eq!(
            retried.envelope["ok"], true,
            "{verb:?}: {}",
            retried.envelope
        );
        assert_eq!(data["status"], "replayed", "{verb:?}");
        assert_eq!(data["business_id"], id.as_str(), "{verb:?}");
        assert_eq!(data["operation"]["id"], stored["id"], "{verb:?}");
        assert_eq!(data["operation"]["state"], stored["state"], "{verb:?}");
        assert_eq!(stored["state"], "sent_outcome_unknown", "{verb:?}");
        assert_eq!(data["next"], "wait", "{verb:?}");
        assert_eq!(retried.code, 1, "{verb:?}: the unknown-outcome exit code");
        assert_eq!(Effects::of(&fixture).await, before, "{verb:?}");

        if let Some((code, text)) = verb.run_text(&fixture, &id).await {
            let tx_hash = stellar_agent_network::submit::redact_tx_hash(
                stored["result"]["tx_hash"].as_str().unwrap(),
            );
            assert_eq!(
                text.trim_end(),
                format!(
                    "Operation replayed: business_id {id}  state sent_outcome_unknown  \
                     tx_hash {tx_hash}  next wait"
                ),
                "{verb:?}: one line"
            );
            assert_eq!(code, 1, "{verb:?}: the unknown-outcome exit code");
            assert_eq!(Effects::of(&fixture).await, before, "{verb:?}");
        }
    }
}

/// The state of the record under `business_id` in the window file at
/// `path`; `None` without a file or a record.
fn stored_state(path: &std::path::Path, business_id: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let body: Value = serde_json::from_slice(bytes.get(32..)?).ok()?;
    body["operations"]["records"]
        .as_array()?
        .iter()
        .find(|record| record["business_id"] == business_id)
        .and_then(|record| record["state"].as_str().map(str::to_owned))
}

/// Each value verb opens its operation record before the confirmation ceremony.
/// A probe inside the ceremony reads the window file and finds the record under
/// the run's business id `prepared` before the ceremony answers.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_opens_the_record_before_the_ceremony() {
    for verb in Verb::ALL {
        let mut fixture = verb.mainnet(Row::Ceremony).await;
        let id = fresh_business_id();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&seen);
        let path = fixture.window_path();
        let probe_id = id.clone();
        let mut answer = crate::common::mainnet_presence::driver::fixture_credential();
        fixture.present_with(move |ceremony| {
            observed
                .lock()
                .unwrap()
                .push(stored_state(&path, &probe_id));
            answer(ceremony)
        });

        let run = verb.run(&fixture, Some(&id), Intent::Default, false).await;
        assert_eq!(run.code, 0, "{verb:?}: {}", run.envelope);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![Some("prepared".to_owned())],
            "{verb:?}: the record is open when the ceremony runs"
        );
        assert_eq!(record(&fixture, &id)["state"], "sent_outcome_unknown");
    }
}

/// An endpoint holding the agent's claimable balance until `gone` is set,
/// and answering every later read of it with no entry.
fn vanishing_balance(gone: &Arc<AtomicBool>) -> ClassicRpc {
    use stellar_xdr::{LedgerKey, Limits, ReadXdr as _};
    let gone = Arc::clone(gone);
    claim::ledger(true, 100_000_000).with_script(move |method, _, body| {
        let reads_the_balance = body["params"]["keys"].as_array().is_some_and(|keys| {
            keys.iter().any(|key| {
                key.as_str().is_some_and(|key| {
                    matches!(
                        LedgerKey::from_xdr_base64(key, Limits::none()),
                        Ok(LedgerKey::ClaimableBalance(_))
                    )
                })
            })
        });
        (gone.load(Ordering::SeqCst) && method == "getLedgerEntries" && reads_the_balance)
            .then(|| json!({ "entries": [], "latestLedger": 1001 }))
    })
}

/// A claim rerun after its balance left the ledger prints the stored claim
/// under its business id and does no new work. A claim under an unknown id
/// keeps the ledger's refusal.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_claim_rerun_after_its_balance_left_replays_the_stored_claim() {
    let gone = Arc::new(AtomicBool::new(false));
    let fixture = Spec::new("replay-absent-claim")
        .primary(vanishing_balance(&gone))
        .oracle(vanishing_balance(&gone))
        .build()
        .await;
    let id = fresh_business_id();
    let first = Verb::Claim
        .run(&fixture, Some(&id), Intent::Default, false)
        .await;
    assert_eq!(first.code, 0, "{}", first.envelope);
    let stored = record(&fixture, &id);
    gone.store(true, Ordering::SeqCst);
    let before = Effects::of(&fixture).await;

    let retried = Verb::Claim
        .run(&fixture, Some(&id), Intent::Default, false)
        .await;
    assert_eq!(
        retried.envelope["data"]["status"], "replayed",
        "{}",
        retried.envelope
    );
    assert_eq!(retried.envelope["data"]["operation"]["id"], stored["id"]);
    assert_eq!(
        retried.envelope["data"]["operation"]["state"],
        stored["state"]
    );
    assert_eq!(retried.code, replay_exit_code_of(&stored));
    assert_eq!(Effects::of(&fixture).await, before);

    let other = Verb::Claim
        .run(&fixture, Some(&fresh_business_id()), Intent::Default, false)
        .await;
    assert_eq!(other.code, 1, "{}", other.envelope);
    assert_eq!(
        other.error_code(),
        "claim.balance_not_found",
        "{}",
        other.envelope
    );
    assert_eq!(fixture.ceremonies().len(), before.ceremonies);
    assert_eq!(fixture.sent_envelopes().await.len(), before.sent);
    assert_eq!(operations(&fixture), before.operations, "no record opens");
}

/// An endpoint holding the agent's claimable balance, whose claimant
/// predicate reads as expired once `expired` is set.
fn expiring_balance(expired: &Arc<AtomicBool>) -> ClassicRpc {
    use stellar_xdr::{
        AccountId, ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt,
        ClaimableBalanceId, Claimant, ClaimantV0, Hash, LedgerEntryData, LedgerKey, Limits,
        PublicKey, ReadXdr as _, Uint256, WriteXdr as _,
    };
    let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
    let destination = stellar_strkey::ed25519::PublicKey::from_string(&agent).unwrap();
    let expired_entry = LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32])),
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(destination.0))),
            predicate: ClaimPredicate::BeforeAbsoluteTime(1),
        })]
        .try_into()
        .unwrap(),
        asset: stellar_xdr::Asset::Native,
        amount: 100_000_000,
        ext: ClaimableBalanceEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let expired = Arc::clone(expired);
    claim::ledger(true, 100_000_000).with_script(move |method, _, body| {
        let key = body["params"]["keys"].as_array().and_then(|keys| {
            keys.iter().find_map(|key| {
                let text = key.as_str()?;
                matches!(
                    LedgerKey::from_xdr_base64(text, Limits::none()),
                    Ok(LedgerKey::ClaimableBalance(_))
                )
                .then(|| text.to_owned())
            })
        })?;
        (expired.load(Ordering::SeqCst) && method == "getLedgerEntries").then(|| {
            json!({
                "entries": [{"key": key, "xdr": expired_entry, "lastModifiedLedgerSeq": 1000}],
                "latestLedger": 1001
            })
        })
    })
}

/// A claim rerun under the business id of its run of unknown outcome prints the
/// stored claim once the claimant predicate expired. The lookup precedes the
/// balance read and the predicate check, whose answer changed once the claim
/// ran. A claim under an unknown id keeps the predicate refusal.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn claim_replays_its_business_id_after_the_predicate_expires() {
    let expired = Arc::new(AtomicBool::new(false));
    let fixture = Spec::new("replay-expired-claim")
        .primary(expiring_balance(&expired))
        .oracle(expiring_balance(&expired))
        .build()
        .await;
    let id = fresh_business_id();
    let first = Verb::Claim
        .run(&fixture, Some(&id), Intent::Default, false)
        .await;
    assert_eq!(first.code, 0, "{}", first.envelope);
    let stored = record(&fixture, &id);
    assert_eq!(stored["state"], "sent_outcome_unknown");
    expired.store(true, Ordering::SeqCst);
    let before = Effects::of(&fixture).await;
    let requests = fixture.primary_methods().await.len();

    let retried = Verb::Claim
        .run(&fixture, Some(&id), Intent::Default, false)
        .await;
    let data = &retried.envelope["data"];
    assert_eq!(data["status"], "replayed", "{}", retried.envelope);
    assert_eq!(data["operation"]["id"], stored["id"]);
    assert_eq!(data["operation"]["state"], "sent_outcome_unknown");
    assert_eq!(data["next"], "wait");
    assert_eq!(retried.code, 1, "the unknown-outcome exit code");
    assert_eq!(
        fixture.primary_methods().await[requests..],
        methods_before_lookup(Verb::Claim),
        "the balance is not read"
    );
    assert_eq!(Effects::of(&fixture).await, before);

    let other = Verb::Claim
        .run(&fixture, Some(&fresh_business_id()), Intent::Default, false)
        .await;
    assert_eq!(other.code, 1, "{}", other.envelope);
    assert_eq!(
        other.error_code(),
        "claim.predicate_not_satisfied",
        "{}",
        other.envelope
    );
    assert_eq!(fixture.ceremonies().len(), before.ceremonies);
    assert_eq!(operations(&fixture), before.operations, "no record opens");
}

/// The exit code a replay of the stored record `stored` returns.
fn replay_exit_code_of(stored: &Value) -> i32 {
    i32::from(stored["state"] != "succeeded")
}

/// Another intent under the business id of a completed run refuses with
/// `operation.business_id_conflict` before the confirmation ceremony:
/// nothing is signed or sent and the record stays as it is.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_refuses_another_intent_under_its_business_id() {
    for verb in Verb::ALL {
        let fixture = verb.mainnet(Row::Conflict).await;
        let id = fresh_business_id();
        let first = verb.run(&fixture, Some(&id), Intent::Default, false).await;
        assert_eq!(first.code, 0, "{verb:?}: {}", first.envelope);
        let before = Effects::of(&fixture).await;

        let other = verb.run(&fixture, Some(&id), Intent::Other, false).await;
        assert_eq!(other.code, 1, "{verb:?}: {}", other.envelope);
        assert_eq!(
            other.error_code(),
            "operation.business_id_conflict",
            "{verb:?}: {}",
            other.envelope
        );
        assert_eq!(Effects::of(&fixture).await, before, "{verb:?}");
    }
}

/// A mainnet run without a business id refuses with
/// `validation.business_id_required`, and one with a malformed id with
/// `validation.business_id_invalid`. Both refuse before the confirmation
/// ceremony and without a record, a signature or a send.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_value_verb_refuses_mainnet_without_a_business_id() {
    for verb in Verb::ALL {
        let fixture = verb.mainnet(Row::Required).await;
        for (raw, code) in [
            (None, "validation.business_id_required"),
            (Some(""), "validation.business_id_required"),
            (Some("two words"), "validation.business_id_invalid"),
        ] {
            let run = verb.run(&fixture, raw, Intent::Default, false).await;
            assert_eq!(run.code, 1, "{verb:?} {raw:?}: {}", run.envelope);
            assert_eq!(run.error_code(), code, "{verb:?} {raw:?}: {}", run.envelope);
            assert!(fixture.ceremonies().is_empty(), "{verb:?} {raw:?}");
            assert!(fixture.pending_entries().is_empty(), "{verb:?} {raw:?}");
            assert!(
                fixture.sent_envelopes().await.is_empty(),
                "{verb:?} {raw:?}"
            );
            assert!(operations(&fixture).is_null(), "{verb:?} {raw:?}");
        }
    }
}

/// On testnet each value verb validates a supplied business id, echoes it
/// in its result, and keeps no record of it; a malformed id refuses before
/// anything is sent.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn testnet_verbs_echo_the_business_id() {
    for verb in Verb::ALL {
        let fixture = verb.testnet().await;
        let run = verb
            .run(&fixture, Some("order-7"), Intent::Default, true)
            .await;
        assert_eq!(run.code, 0, "{verb:?}: {}", run.envelope);
        assert_eq!(
            run.envelope["data"]["business_id"], "order-7",
            "{verb:?}: {}",
            run.envelope
        );
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{verb:?}");
        assert!(operations(&fixture).is_null(), "{verb:?}: no record");

        let refused = verb
            .run(&fixture, Some("two words"), Intent::Default, true)
            .await;
        assert_eq!(refused.code, 1, "{verb:?}: {}", refused.envelope);
        assert_eq!(
            refused.error_code(),
            "validation.business_id_invalid",
            "{verb:?}: {}",
            refused.envelope
        );
        assert_eq!(fixture.sent_envelopes().await.len(), 1, "{verb:?}");
    }
}

/// The exit code of a replayed run: `0` for a succeeded operation, the
/// unknown-outcome code `1` while the outcome is open, and `1` for every
/// other state.
#[test]
fn replay_exit_codes_follow_the_state() {
    for state in OperationState::ALL {
        let view = OperationView {
            operation_id: OperationId::from_bytes([0x5a; 16]),
            business_id: BusinessId::parse("order-7").unwrap(),
            state,
            tool: None,
            kind: None,
            slot_kind: SlotKind::Envelope,
            intent_digest: [1; 32],
            attempts: 1,
            result: Some(OperationResult::default()),
            created_at_ms: None,
            closed_at_ms: None,
            waiting_expires_at_ms: None,
            execution_expires_at_ms: None,
            compacted: false,
            history_incomplete: false,
        };
        let expected = i32::from(state != OperationState::Succeeded);
        assert_eq!(replay_exit_code(&view), expected, "{state:?}");
    }
}

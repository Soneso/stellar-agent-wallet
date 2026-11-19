//! The approval status, the operation status and the audit outbox at
//! shutdown for each CLI row of the release proof matrix on the mainnet
//! fixture.
//!
//! Each test iterates the four classic value verbs. A verb runs through its
//! command entry on a fixture whose rules require approval, with the
//! fixture's presence driver answering the consent ceremony. `approve
//! status` and `tx status` run through their own dispatch.
//!
//! The holder of the outbox test is a draining writer the test opens in the
//! same process under another registry name, standing in for the writer a
//! running `stellar-agent-mcp` server holds; its exit drain is
//! [`AuditWriterRegistry::drain_cached_outboxes`], which the server runs
//! after its transport returns.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]

use serde_json::{Value, json};
use stellar_agent_core::audit_log::{AuditWriterRegistry, inspect_outbox};

use crate::commands::accounts::create::tests::mainnet_full as create;
use crate::commands::claim::tests::mainnet_full as claim;
use crate::commands::pay::tests::mainnet_full as pay;
use crate::commands::trustline::tests::mainnet_full as trustline;
use crate::common::mainnet_presence::driver;
use crate::common::mainnet_write_fixture::{AGENT_SEED, DESTINATION, ISSUER, MainnetFixture, Spec};
use crate::test_rpc::ClassicRpc;

/// One classic CLI value verb.
#[derive(Clone, Copy, Debug)]
enum Verb {
    Pay,
    Claim,
    Create,
    Trustline,
}

impl Verb {
    const ALL: [Self; 4] = [Self::Pay, Self::Claim, Self::Create, Self::Trustline];

    /// The matrix row id.
    fn id(self) -> &'static str {
        match self {
            Self::Pay => "cli.pay",
            Self::Claim => "cli.claim",
            Self::Create => "cli.accounts_create",
            Self::Trustline => "cli.trustline",
        }
    }

    /// A profile name unique to this verb and `case`; the audit writer
    /// registry is process-wide.
    fn name(self, case: usize) -> &'static str {
        const NAMES: [[&str; 5]; 4] = [
            [
                "row-approval-pay",
                "row-operation-pay",
                "row-outbox-pay",
                "row-outcome-pay",
                "row-valid-pay",
            ],
            [
                "row-approval-claim",
                "row-operation-claim",
                "row-outbox-claim",
                "row-outcome-claim",
                "row-valid-claim",
            ],
            [
                "row-approval-create",
                "row-operation-create",
                "row-outbox-create",
                "row-outcome-create",
                "row-valid-create",
            ],
            [
                "row-approval-trustline",
                "row-operation-trustline",
                "row-outbox-trustline",
                "row-outcome-trustline",
                "row-valid-trustline",
            ],
        ];
        let index = match self {
            Self::Pay => 0,
            Self::Claim => 1,
            Self::Create => 2,
            Self::Trustline => 3,
        };
        NAMES[index][case]
    }

    /// The approval kind the verb's consent stores.
    fn kind(self) -> &'static str {
        match self {
            Self::Pay | Self::Create => "PaymentSimulated",
            Self::Claim => "ClaimSimulated",
            Self::Trustline => "TrustlineSimulated",
        }
    }

    fn ledger(self) -> ClassicRpc {
        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        match self {
            Self::Pay | Self::Create => ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]),
            Self::Claim => claim::ledger(true, 100_000_000),
            Self::Trustline => trustline::ledger(true, 0),
        }
    }

    /// The default fixture, whose rules require approval for every verb.
    fn spec(self, name: &'static str) -> Spec {
        Spec::new(name).primary(self.ledger()).oracle(self.ledger())
    }

    /// Runs the verb through its command entry under `business_id`.
    async fn run(self, fixture: &MainnetFixture, business_id: &str) -> (i32, Value) {
        let id = Some(business_id.to_owned());
        match self {
            Self::Pay => {
                let mut args = pay::mainnet_args(fixture);
                args.business_id = id;
                let r = pay::run(fixture, &args).await;
                (r.code, r.envelope)
            }
            Self::Claim => {
                let mut args = claim::mainnet_args(fixture);
                args.business_id = id;
                let r = claim::run(fixture, &args).await;
                (r.code, r.envelope)
            }
            Self::Create => {
                let mut args = create::mainnet_args(fixture);
                args.business_id = id;
                let r = create::run(fixture, &args).await;
                (r.code, r.envelope)
            }
            Self::Trustline => {
                let mut args = trustline::mainnet_args(fixture);
                args.business_id = id;
                let r = trustline::run(fixture, &args).await;
                (r.code, r.envelope)
            }
        }
    }
}

/// Answers every later presence ceremony with the fixture credential under
/// `flags`: 5 is a verified assertion, 1 lacks user verification.
fn present(fixture: &mut MainnetFixture, flags: u8) {
    fixture.present_with(driver::credential(
        stellar_agent_test_support::webauthn::fixture_authenticator(),
        flags,
    ));
}

/// Runs `stellar-agent <words>` through the parsed command's dispatch and
/// returns its exit code and envelope.
async fn dispatch(words: &[&str]) -> (i32, Value) {
    use clap::Parser as _;
    let parsed =
        crate::Cli::try_parse_from(std::iter::once("stellar-agent").chain(words.iter().copied()))
            .unwrap();
    crate::common::render::take_rendered_for_test();
    let code = match parsed.command {
        crate::Commands::Approve(args) => crate::commands::approve::dispatch(args).await,
        crate::Commands::Tx(args) => crate::commands::tx::run(&args).await,
        _ => panic!("not a status command: {words:?}"),
    };
    let envelope = crate::common::render::take_rendered_for_test()
        .pop()
        .unwrap();
    (code, envelope)
}

/// Every file of the data root with its bytes.
fn data_root() -> Vec<(std::path::PathBuf, Vec<u8>)> {
    crate::common::test_support::tree(
        &stellar_agent_core::profile::schema::canonical_data_root().unwrap(),
    )
}

/// `view` without its per-call request id.
fn without_request_id(mut view: Value) -> Value {
    view["request_id"] = Value::Null;
    view
}

/// The failed checks of a verb loop, each naming its verb, so one run
/// reports every failing verb and asserts once.
#[derive(Default)]
struct Checks(Vec<String>);

impl Checks {
    /// Records that `what` of `verb` is `actual` where `expected` holds.
    fn eq(&mut self, verb: Verb, what: &str, actual: &Value, expected: &Value) {
        if actual != expected {
            self.0.push(format!(
                "{}: {what}: {actual}, expected {expected}",
                verb.id()
            ));
        }
    }

    /// Records that `what` of `verb` does not hold.
    fn holds(&mut self, verb: Verb, what: &str, held: bool) {
        if !held {
            self.0.push(format!("{}: {what}", verb.id()));
        }
    }

    /// Fails with every recorded check.
    fn assert_none(self) {
        assert!(self.0.is_empty(), "{}", self.0.join("\n"));
    }
}

/// Installs on `fixture` a presence driver that, during the consent wait,
/// hands the profile's audit writer to a draining writer opened under the
/// holder's registry name in `held`, and then answers with a verified
/// assertion.
fn present_while_another_process_holds_the_writer(
    fixture: &mut MainnetFixture,
    name: &'static str,
    held: &std::rc::Rc<std::cell::RefCell<Option<HeldWriter>>>,
) {
    let slot = std::rc::Rc::clone(held);
    let holder = fixture.profile();
    let mut answer = driver::credential(
        stellar_agent_test_support::webauthn::fixture_authenticator(),
        5,
    );
    fixture.present_with(move |ceremony| {
        AuditWriterRegistry::remove_for_test(name);
        *slot.borrow_mut() = Some(open_holder(&holder, name));
        answer(ceremony)
    });
}

/// Releases the holder's writer and its registry entry.
fn release_holder(held: &std::rc::Rc<std::cell::RefCell<Option<HeldWriter>>>) {
    held.borrow_mut().take();
    AuditWriterRegistry::remove_for_test(HOLDER);
}

// ─────────────────────────────────────────────────────────────────────────────
// status.approval_view
// ─────────────────────────────────────────────────────────────────────────────

/// For each verb, a run whose presence assertion lacks user verification
/// parks its approval. `approve status` reports it `pending`, with the
/// verb's approval kind, its operation and a supported verification that is
/// not valid. Two status calls answer the same view and change no file of
/// the data root. A rerun under the same business id with a verified
/// assertion consumes that same approval, and the status reports it
/// `consumed` with the sent hash.
///
/// A CLI run attests and consumes its approval in one process, so a valid
/// approval is observable only when the run stops between the two. In a
/// second fixture, a draining writer opened in the same process under
/// another registry name takes the audit writer during the consent wait, as
/// another process's server holds it: the verb attests, then refuses before the
/// signer and consumes nothing, and `approve status` reports the approval
/// `attested` with a supported, valid verification.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_cli_row_reports_its_approval_without_consuming_it() {
    let mut checks = Checks::default();
    for verb in Verb::ALL {
        let name = verb.name(0);
        let mut fixture = verb.spec(name).build().await;
        let business_id = crate::common::business_entry::fresh_business_id();
        present(&mut fixture, 1);
        let (code, refused) = verb.run(&fixture, &business_id).await;
        checks.eq(verb, "parking run", &json!(code), &json!(1));
        checks.eq(
            verb,
            "parking refusal",
            &refused["error"]["code"],
            &json!("approval.presence_invalid"),
        );
        let entries = fixture.pending_entries();
        assert_eq!(entries.len(), 1, "{}: {entries:?}", verb.id());
        let nonce = entries[0].approval_nonce.clone();

        let before = data_root();
        let (code, first) = dispatch(&["approve", "status", &nonce, "--profile", name]).await;
        let (_, second) = dispatch(&["approve", "status", &nonce, "--profile", name]).await;
        let data = &first["data"];
        checks.eq(verb, "status exit", &json!(code), &json!(0));
        checks.eq(verb, "state", &data["state"], &json!("pending"));
        checks.eq(verb, "kind", &data["kind"], &json!(verb.kind()));
        checks.eq(
            verb,
            "business id",
            &data["business_id"],
            &json!(business_id),
        );
        checks.eq(
            verb,
            "verification",
            &data["verification"],
            &json!({"supported": true, "valid": false, "reason": "attestation_invalid"}),
        );
        checks.eq(verb, "reusable", &data["reusable"], &json!(false));
        checks.holds(
            verb,
            "a second status call answers the same view",
            without_request_id(first.clone()) == without_request_id(second),
        );
        checks.holds(
            verb,
            "the status calls change no file",
            data_root() == before,
        );

        present(&mut fixture, 5);
        let (code, sent) = verb.run(&fixture, &business_id).await;
        checks.eq(verb, "consuming run", &json!(code), &json!(0));
        let (_, after) = dispatch(&["approve", "status", &nonce, "--profile", name]).await;
        checks.eq(
            verb,
            "state after",
            &after["data"]["state"],
            &json!("consumed"),
        );
        checks.eq(
            verb,
            "sent hash",
            &after["data"]["tx_hash"],
            &sent["data"]["tx_hash"],
        );
        checks.eq(
            verb,
            "verification after",
            &after["data"]["verification"],
            &json!({"supported": true, "valid": false, "reason": "consumed"}),
        );
        drop(fixture);

        let name = verb.name(4);
        let mut fixture = verb.spec(name).build().await;
        let held = std::rc::Rc::new(std::cell::RefCell::new(None));
        present_while_another_process_holds_the_writer(&mut fixture, name, &held);
        let (code, refused) = verb.run(&fixture, &business_id).await;
        checks.eq(verb, "attesting run", &json!(code), &json!(1));
        checks.holds(
            verb,
            "the attesting run refuses before the signer",
            refused["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("audit.writer_locked")),
        );
        let entries = fixture.pending_entries();
        assert_eq!(entries.len(), 1, "{}: {entries:?}", verb.id());
        let nonce = entries[0].approval_nonce.clone();
        let (_, valid) = dispatch(&["approve", "status", &nonce, "--profile", name]).await;
        checks.eq(
            verb,
            "attested state",
            &valid["data"]["state"],
            &json!("attested"),
        );
        checks.eq(
            verb,
            "attested verification",
            &valid["data"]["verification"],
            &json!({"supported": true, "valid": true, "reason": "ok"}),
        );
        release_holder(&held);
    }
    checks.assert_none();
}

// ─────────────────────────────────────────────────────────────────────────────
// status.operation_view
// ─────────────────────────────────────────────────────────────────────────────

/// For each verb, a consented run whose transaction stays unconfirmed times
/// out. `tx status --business-id` then reports the state
/// `sent_outcome_unknown`, the one attempt with the sent hash, that
/// transition, and the attempt's recovery result with its next action,
/// `TargetedStatus`.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_cli_row_reports_its_operation_and_next_step() {
    let mut checks = Checks::default();
    for verb in Verb::ALL {
        let name = verb.name(1);
        let mut fixture = verb
            .spec(name)
            .submit_timeout_seconds(1)
            .primary(verb.ledger().with_script(|method, _, _| {
                (method == "getTransaction")
                    .then(|| json!({"status":"NOT_FOUND", "latestLedger":1002, "oldestLedger":1}))
            }))
            .build()
            .await;
        present(&mut fixture, 5);
        let business_id = crate::common::business_entry::fresh_business_id();
        let (code, sent) = verb.run(&fixture, &business_id).await;
        checks.eq(verb, "sending run", &json!(code), &json!(1));
        checks.eq(
            verb,
            "send",
            &sent["error"]["code"],
            &json!("submission.tx_timeout"),
        );
        let tx_hash = sent["error"]["details"]["tx_hash"].clone();

        let (code, view) = dispatch(&[
            "tx",
            "status",
            "--business-id",
            &business_id,
            "--profile",
            name,
        ])
        .await;
        let operation = &view["data"]["operation"];
        checks.eq(verb, "status exit", &json!(code), &json!(0));
        checks.eq(
            verb,
            "state",
            &operation["state"],
            &json!("sent_outcome_unknown"),
        );
        checks.eq(
            verb,
            "attempt count",
            &json!(operation["attempts"].as_array().map_or(0, Vec::len)),
            &json!(1),
        );
        let attempt = &operation["attempts"][0];
        checks.eq(
            verb,
            "attempt state",
            &attempt["state"],
            &json!("sent_outcome_unknown"),
        );
        checks.eq(verb, "attempt hash", &attempt["tx_hash"], &tx_hash);
        checks.eq(
            verb,
            "last transition",
            &operation["last_transition"]["kind"],
            &json!("sent_outcome_unknown"),
        );
        let recovery = &view["data"]["recovery"]["attempts"][0];
        checks.eq(verb, "recovery hash", &recovery["tx_hash"], &tx_hash);
        checks.eq(
            verb,
            "recovery result",
            &recovery["result"],
            &json!("NeedsEvidence"),
        );
        checks.eq(
            verb,
            "next action",
            &recovery["next_action"],
            &json!("TargetedStatus"),
        );
    }
    checks.assert_none();
}

// ─────────────────────────────────────────────────────────────────────────────
// audit.outbox_at_shutdown
// ─────────────────────────────────────────────────────────────────────────────

/// For each verb, a draining writer opened in the same process under another
/// registry name takes the profile's audit writer during the presence wait,
/// as another process's server holds it. The verb queues its consent row in
/// the outbox, then refuses before the signer because it cannot acquire the
/// writer: it resolves no signer and sends nothing. The queued row persists
/// after the verb returns and is absent from the log. The holder's exit
/// drain then delivers it and empties the outbox.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_cli_row_keeps_its_queued_consent_row_until_the_holder_drains() {
    let mut checks = Checks::default();
    for verb in Verb::ALL {
        let name = verb.name(2);
        let mut fixture = verb.spec(name).build().await;
        let profile = fixture.profile();
        let held = std::rc::Rc::new(std::cell::RefCell::new(None));
        present_while_another_process_holds_the_writer(&mut fixture, name, &held);
        let business_id = crate::common::business_entry::fresh_business_id();
        let signers = crate::common::signer_ceremony::signer_resolutions_on_this_thread();
        let (code, refused) = verb.run(&fixture, &business_id).await;
        checks.eq(
            verb,
            "signer resolutions of the refused run",
            &json!(crate::common::signer_ceremony::signer_resolutions_on_this_thread() - signers),
            &json!(0),
        );
        checks.holds(verb, "the holder took the writer", held.borrow().is_some());
        checks.eq(verb, "refused run", &json!(code), &json!(1));
        checks.holds(
            verb,
            "the run refuses on the locked writer",
            refused["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("audit.writer_locked")),
        );
        checks.holds(
            verb,
            "nothing is sent",
            fixture.sent_envelopes().await.is_empty(),
        );
        let pending = || inspect_outbox(&profile.audit_log_path).unwrap().pending;
        checks.eq(
            verb,
            "the consent row persists after the verb returns",
            &json!(pending()),
            &json!(1),
        );
        checks.eq(
            verb,
            "consent rows in the log before the drain",
            &json!(fixture.audit_rows("approval_attested").len()),
            &json!(0),
        );

        checks.eq(
            verb,
            "the holder's exit drain checks its writer",
            &json!(AuditWriterRegistry::drain_cached_outboxes()),
            &json!(1),
        );
        checks.eq(
            verb,
            "the exit drain empties the outbox",
            &json!(pending()),
            &json!(0),
        );
        checks.eq(
            verb,
            "consent rows in the log after the drain",
            &json!(fixture.audit_rows("approval_attested").len()),
            &json!(1),
        );
        release_holder(&held);
    }
    checks.assert_none();
}

// ─────────────────────────────────────────────────────────────────────────────
// audit.outcome_row on mainnet
// ─────────────────────────────────────────────────────────────────────────────

/// For each verb on mainnet, a consented run that the endpoint reports
/// applied writes exactly one value audit row: the `value_action_pending`
/// row the mainnet recorder writes with its anchored facts before the send.
/// The reported answer writes no further value row.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn every_cli_row_writes_one_value_row_on_mainnet() {
    let mut failures = Vec::new();
    for verb in Verb::ALL {
        let name = verb.name(3);
        let mut fixture = verb.spec(name).build().await;
        present(&mut fixture, 5);
        let business_id = crate::common::business_entry::fresh_business_id();
        let (code, sent) = verb.run(&fixture, &business_id).await;
        let counts: Vec<usize> = [
            "value_action_pending",
            "value_action_submitted",
            "value_action_failed",
        ]
        .iter()
        .map(|kind| fixture.audit_rows(kind).len())
        .collect();
        if code != 0 || counts != [1, 0, 0] {
            failures.push(format!(
                "{}: exit {code}, pending/submitted/failed rows {counts:?}: {sent}",
                verb.id()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every matrix cell that names a test of this module lists exactly the
/// verbs of the verb table, and every row test of this module is named by a
/// cell.
#[test]
fn the_verb_table_matches_its_matrix_cells() {
    const MODULE: &str = "common::proof_row_status_tests::";
    const TESTS: [&str; 4] = [
        "every_cli_row_reports_its_approval_without_consuming_it",
        "every_cli_row_reports_its_operation_and_next_step",
        "every_cli_row_keeps_its_queued_consent_row_until_the_holder_drains",
        "every_cli_row_writes_one_value_row_on_mainnet",
    ];
    let matrix: toml::Table = toml::from_str(include_str!(
        "../../../../.github/scripts/proof-matrix.toml"
    ))
    .unwrap();
    let mut ids: Vec<String> = Verb::ALL.iter().map(|verb| verb.id().to_owned()).collect();
    ids.sort();
    let mut named = std::collections::BTreeSet::new();
    for cell in matrix["cell"].as_array().unwrap() {
        let cell = cell.as_table().unwrap();
        let Some(tests) = cell.get("tests").and_then(toml::Value::as_array) else {
            continue;
        };
        let mut rows: Vec<String> = cell["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row.as_str().unwrap().to_owned())
            .collect();
        rows.sort();
        for test in tests {
            let name = test["name"].as_str().unwrap();
            let Some(test) = name.strip_prefix(MODULE) else {
                continue;
            };
            assert!(TESTS.contains(&test), "{name} has no verb table");
            assert_eq!(rows, ids, "{}: {name}", cell["claim"]);
            named.insert(test);
        }
    }
    let tested: std::collections::BTreeSet<&str> = TESTS.into_iter().collect();
    assert_eq!(named, tested, "every row test is named by a cell");
}

/// The registry name of the holder's draining writer.
const HOLDER: &str = "row-outbox-holder";

/// The holder's draining writer.
type HeldWriter = std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>;

/// Opens in this process the holder's draining writer for `profile` under
/// its own registry name, as a running server holds it.
// The audit-path scan reads each file up to its first `#[cfg(test)]` and does not see the parent module's gate.
#[cfg(test)]
fn open_holder(profile: &stellar_agent_core::profile::schema::Profile, name: &str) -> HeldWriter {
    AuditWriterRegistry::get_or_open_keyed(
        HOLDER,
        &profile.audit_log_path,
        stellar_agent_network::keyring::keyed_audit_access(
            profile,
            name,
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        )
        .unwrap(),
    )
    .unwrap()
}

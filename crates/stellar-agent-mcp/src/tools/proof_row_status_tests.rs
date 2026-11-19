//! The approval status, the operation status and the audit outbox at
//! shutdown for each MCP row of the release proof matrix on a routed
//! mainnet fixture.
//!
//! Each test iterates the rows of one matrix cell: the four classic commit
//! tools, the x402 payment and the authenticated x402 payment, each prepared
//! under a rule that requires approval and attested as the operator does.
//! The status tools answer through their own handlers under allowing rules.
//!
//! The exit drain of the server process is
//! [`AuditWriterRegistry::drain_cached_outboxes`], which `serve` runs after
//! the transport returns; the outbox test calls it in place of that exit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction and assertions"
)]

use std::sync::atomic::Ordering;

use serde_json::{Value, json};
use stellar_agent_core::audit_log::{AuditEntry, AuditOutbox, AuditWriterRegistry, inspect_outbox};

use super::common::tests::mainnet::{
    ClassicRun, Fixture, Tool, X402Run, approval_business_id, ledger, wire, x402_args,
};
use super::x402_authenticated_mainnet_tests::{
    HOME, Run as AuthenticatedRun, authenticated_policy,
};
use crate::server::{StellarTransactionStatusArgs, WalletServer};

/// One MCP row of a status or outbox cell.
#[derive(Clone, Copy, Debug)]
enum Row {
    Classic(Tool),
    X402,
    Authenticated,
}

impl Row {
    /// The rows of the cells whose claim every MCP value row shows.
    const ALL: [Self; 6] = [
        Self::Classic(Tool::Pay),
        Self::Classic(Tool::CreateAccount),
        Self::Classic(Tool::Claim),
        Self::Classic(Tool::Trustline),
        Self::X402,
        Self::Authenticated,
    ];

    /// The matrix row id.
    fn id(self) -> &'static str {
        match self {
            Self::Classic(Tool::Pay) => "mcp.pay_commit",
            Self::Classic(Tool::CreateAccount) => "mcp.create_account_commit",
            Self::Classic(Tool::Claim) => "mcp.claim_commit",
            Self::Classic(Tool::Trustline) => "mcp.trustline_commit",
            Self::X402 => "mcp.x402_create_payment",
            Self::Authenticated => "mcp.x402_authenticated_payment",
        }
    }

    /// The tool that consumes the row's approval.
    fn tool(self) -> &'static str {
        match self {
            Self::Classic(tool) => tool.commit_name(),
            Self::X402 => "stellar_x402_create_payment",
            Self::Authenticated => "stellar_x402_authenticated_payment",
        }
    }

    /// The approval kind the row's preparation stores.
    fn kind(self) -> &'static str {
        match self {
            Self::Classic(Tool::Pay | Tool::CreateAccount) => "PaymentSimulated",
            Self::Classic(Tool::Claim) => "ClaimSimulated",
            Self::Classic(Tool::Trustline) => "TrustlineSimulated",
            Self::X402 | Self::Authenticated => "X402Payment",
        }
    }
}

/// The fixture's policy with allowing rules for the two status tools.
fn status_rules(mut raw: String) -> String {
    for tool in ["stellar_transaction_status", "stellar_approval_status"] {
        raw.push_str(&format!(
            "\n[[rules]]\nmatch = {{tool = \"{tool}\", chain = \"stellar:mainnet\"}}\n\
             criteria = []\ndecision = \"allow\"\n"
        ));
    }
    raw
}

/// One row prepared under a rule that requires approval, attested, and ready
/// for its consuming call.
enum Prepared {
    Classic(Box<ClassicRun>),
    X402(Box<X402Run>),
    Authenticated(Box<AuthenticatedRun>, (String, String)),
}

impl Prepared {
    /// Prepares `row`; a classic submission stays unconfirmed when
    /// `unknown` is set.
    async fn new(row: Row, unknown: bool) -> Self {
        match row {
            Row::Classic(tool) => {
                let run = ClassicRun::with(
                    tool,
                    status_rules,
                    |profile| profile.submit_timeout_seconds = Some(1),
                    |_| {},
                )
                .await;
                run.control
                    .transaction_unknown
                    .store(unknown, Ordering::SeqCst);
                Self::Classic(Box::new(run))
            }
            Row::X402 => Self::X402(Box::new(X402Run::with(status_rules).await)),
            Row::Authenticated => {
                let run =
                    AuthenticatedRun::with(|raw| status_rules(authenticated_policy(&raw))).await;
                let approval = run.prepare().await;
                Self::Authenticated(Box::new(run), approval)
            }
        }
    }

    fn fixture(&self) -> &Fixture {
        match self {
            Self::Classic(run) => &run.f,
            Self::X402(run) => &run.f,
            Self::Authenticated(run, _) => &run.f,
        }
    }

    fn server(&self) -> &WalletServer {
        &self.fixture().server
    }

    fn nonce(&self) -> String {
        match self {
            Self::Classic(run) => run.entry.approval_nonce.clone(),
            Self::X402(run) => run.nonce.clone(),
            Self::Authenticated(_, approval) => approval.0.clone(),
        }
    }

    /// The business id of the row's operation, read while it awaits its
    /// approval.
    fn business_id(&self) -> String {
        match self {
            Self::Classic(run) => run.args["business_id"].as_str().unwrap().to_owned(),
            _ => approval_business_id(self.fixture(), &self.nonce()).unwrap(),
        }
    }

    /// The consuming call: the commit, or the x402 payment with the proof.
    async fn consume(&self) -> Value {
        match self {
            Self::Classic(run) => run.commit().await,
            Self::X402(run) => {
                run.pay_with(x402_args(&run.f, Some((&run.nonce, &run.attestation))))
                    .await
            }
            Self::Authenticated(run, approval) => run.pay(HOME, approval).await,
        }
    }
}

async fn approval_status(server: &WalletServer, nonce: &str) -> Value {
    wire(
        &server
            .approval_status_for_test(nonce.to_owned())
            .await
            .unwrap(),
    )
}

async fn operation_status(server: &WalletServer, business_id: &str) -> Value {
    wire(
        &server
            .call_stellar_transaction_status(StellarTransactionStatusArgs {
                chain_id: "stellar:mainnet".to_owned(),
                tx_hash: None,
                business_id: Some(business_id.to_owned()),
                retry_recovery: false,
            })
            .await
            .unwrap(),
    )
}

/// The durable state a status call could consume: the authenticated
/// window, the profile's approval inbox and the audit log.
fn durable_state(f: &Fixture) -> (Option<Value>, Vec<u8>, Vec<u8>) {
    let inbox = f
        .server
        .resolve_approval_dir()
        .unwrap()
        .join(format!("{}.toml", f.server.profile_name_for_approval()));
    (
        ledger(f),
        std::fs::read(inbox).unwrap(),
        std::fs::read(&f.server.security_profile().audit_log_path).unwrap(),
    )
}

/// The failed checks of a row loop, each naming its row, so one run reports
/// every failing row and asserts once.
#[derive(Default)]
struct Checks(Vec<String>);

impl Checks {
    /// Records that `what` of `row` is `actual` where `expected` holds.
    fn eq(&mut self, row: Row, what: &str, actual: &Value, expected: &Value) {
        if actual != expected {
            self.0.push(format!(
                "{}: {what}: {actual}, expected {expected}",
                row.id()
            ));
        }
    }

    /// Records that `what` of `row` does not hold.
    fn holds(&mut self, row: Row, what: &str, held: bool) {
        if !held {
            self.0.push(format!("{}: {what}", row.id()));
        }
    }

    /// Fails with every recorded check.
    fn assert_none(self) {
        assert!(self.0.is_empty(), "{}", self.0.join("\n"));
    }
}

/// `view` without its per-call request id.
fn without_request_id(mut view: Value) -> Value {
    view["request_id"] = Value::Null;
    view
}

// ─────────────────────────────────────────────────────────────────────────────
// status.approval_view
// ─────────────────────────────────────────────────────────────────────────────

/// For each MCP value row, the approval status of its attested approval
/// reports the state `attested`, the row's approval kind, its operation and
/// a supported, valid verification. Two status calls answer the same view
/// and leave the window, the approval inbox and the audit log unchanged.
/// The row's consuming call then succeeds on that approval, and the status
/// reports it `consumed` and no longer valid.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn every_mcp_row_reports_its_approval_without_consuming_it() {
    let mut checks = Checks::default();
    for row in Row::ALL {
        let prepared = Prepared::new(row, false).await;
        let server = prepared.server();
        let nonce = prepared.nonce();
        let business_id = prepared.business_id();
        let before = durable_state(prepared.fixture());

        let first = approval_status(server, &nonce).await;
        let second = approval_status(server, &nonce).await;
        let data = &first["data"];
        checks.eq(row, "ok", &first["ok"], &json!(true));
        checks.eq(row, "state", &data["state"], &json!("attested"));
        checks.eq(row, "kind", &data["kind"], &json!(row.kind()));
        checks.eq(
            row,
            "business id",
            &data["business_id"],
            &json!(business_id),
        );
        checks.eq(
            row,
            "verification",
            &data["verification"],
            &json!({"supported": true, "valid": true, "reason": "ok"}),
        );
        checks.eq(row, "reusable", &data["reusable"], &json!(false));
        checks.holds(
            row,
            "an expiry ahead",
            data["expires_at_ms"]
                .as_u64()
                .is_some_and(|at| at > stellar_agent_core::timefmt::now_unix_ms().unwrap()),
        );
        checks.holds(
            row,
            "a second status call answers the same view",
            without_request_id(first.clone()) == without_request_id(second),
        );
        checks.holds(
            row,
            "the status calls change no durable state",
            durable_state(prepared.fixture()) == before,
        );

        let consumed = prepared.consume().await;
        checks.eq(row, "consuming call", &consumed["ok"], &json!(true));
        let after = approval_status(server, &nonce).await;
        checks.eq(
            row,
            "state after",
            &after["data"]["state"],
            &json!("consumed"),
        );
        checks.eq(
            row,
            "verification after",
            &after["data"]["verification"],
            &json!({"supported": true, "valid": false, "reason": "consumed"}),
        );
    }
    checks.assert_none();
}

// ─────────────────────────────────────────────────────────────────────────────
// status.operation_view
// ─────────────────────────────────────────────────────────────────────────────

/// For each classic MCP commit row, the operation status of its business id
/// reports the operation awaiting its pending approval with no attempt. After
/// a commit whose transaction stays unconfirmed, it reports the state
/// `sent_outcome_unknown`, the one attempt with the sent hash, that
/// transition, and the attempt's recovery result with its next action,
/// `TargetedStatus`.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn every_classic_mcp_row_reports_its_operation_and_next_step() {
    let mut checks = Checks::default();
    for tool in Tool::ALL {
        let row = Row::Classic(tool);
        let prepared = Prepared::new(row, true).await;
        let server = prepared.server();
        let business_id = prepared.business_id();

        let waiting = operation_status(server, &business_id).await;
        let operation = &waiting["data"]["operation"];
        checks.eq(row, "waiting ok", &waiting["ok"], &json!(true));
        checks.eq(
            row,
            "waiting state",
            &operation["state"],
            &json!("awaiting_approval"),
        );
        checks.eq(row, "waiting attempts", &operation["attempts"], &json!([]));
        checks.eq(
            row,
            "waiting approval",
            &operation["approval"]["state"],
            &json!("pending"),
        );

        let sent = prepared.consume().await;
        checks.eq(
            row,
            "commit",
            &sent["error"]["code"],
            &json!("submission.tx_timeout"),
        );
        let tx_hash = sent["error"]["details"]["tx_hash"].clone();
        let view = operation_status(server, &business_id).await;
        let operation = &view["data"]["operation"];
        checks.eq(row, "ok", &view["ok"], &json!(true));
        checks.eq(
            row,
            "state",
            &operation["state"],
            &json!("sent_outcome_unknown"),
        );
        checks.eq(
            row,
            "attempt count",
            &json!(operation["attempts"].as_array().map_or(0, Vec::len)),
            &json!(1),
        );
        let attempt = &operation["attempts"][0];
        checks.eq(
            row,
            "attempt state",
            &attempt["state"],
            &json!("sent_outcome_unknown"),
        );
        checks.eq(row, "attempt hash", &attempt["tx_hash"], &tx_hash);
        checks.eq(
            row,
            "last transition",
            &operation["last_transition"]["kind"],
            &json!("sent_outcome_unknown"),
        );
        let recovery = &view["data"]["recovery"]["attempts"][0];
        checks.eq(row, "recovery hash", &recovery["tx_hash"], &tx_hash);
        checks.eq(
            row,
            "recovery result",
            &recovery["result"],
            &json!("NeedsEvidence"),
        );
        checks.eq(
            row,
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

/// Queues an `approval_attested` row for `prepared`'s approval in the
/// outbox beside its audit log, as `stellar-agent approve` does while this
/// server holds the writer, with `marker` as its request id.
fn queue_approval_row(prepared: &Prepared, row: Row, marker: &str) {
    let profile = prepared.server().security_profile();
    AuditOutbox::for_log(
        &profile.audit_log_path,
        stellar_agent_network::keyring::KeyringTipAnchorStore::shared(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        ),
    )
    .append(&AuditEntry::new_approval_attested(
        row.kind(),
        row.tool(),
        None,
        &prepared.nonce(),
        "cli",
        marker,
    ))
    .unwrap();
}

/// The number of rows queued beside `prepared`'s audit log.
fn queued(prepared: &Prepared) -> usize {
    inspect_outbox(&prepared.server().security_profile().audit_log_path)
        .unwrap()
        .pending
}

/// Whether `prepared`'s audit log holds the approval row of `row` that
/// `marker` names as its request id.
fn delivered(prepared: &Prepared, row: Row, marker: &str) -> bool {
    std::fs::read_to_string(&prepared.server().security_profile().audit_log_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|entry| {
            entry["kind"] == "approval_attested"
                && entry["request_id"] == marker
                && entry["gated_tool"] == row.tool()
        })
}

/// For each MCP value row, an approval row queued for the row's approval
/// while the server holds its writer reaches the log at the server's exit
/// drain and leaves the outbox empty. A row queued after the process lost
/// its cached writer stays in the outbox through the exit drain; the row's
/// consuming call, the next draining writer, delivers it.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn every_mcp_row_drains_or_keeps_its_queued_approval_row_at_shutdown() {
    let mut checks = Checks::default();
    for row in Row::ALL {
        let prepared = Prepared::new(row, false).await;
        let server = prepared.server();
        let name = server.profile_name_for_approval();
        drop(server.write_audit().unwrap());

        queue_approval_row(&prepared, row, "queued-while-held");
        checks.eq(
            row,
            "queued while held",
            &json!(queued(&prepared)),
            &json!(1),
        );
        checks.holds(
            row,
            "the exit drain checks the cached writer",
            AuditWriterRegistry::drain_cached_outboxes() >= 1,
        );
        checks.eq(
            row,
            "the exit drain empties the outbox",
            &json!(queued(&prepared)),
            &json!(0),
        );
        checks.holds(
            row,
            "the exit drain delivers the queued row",
            delivered(&prepared, row, "queued-while-held"),
        );

        AuditWriterRegistry::remove_for_test(&name);
        queue_approval_row(&prepared, row, "queued-without-writer");
        // Other cached writers may still drain; this profile has none.
        let _ = AuditWriterRegistry::drain_cached_outboxes();
        checks.eq(
            row,
            "the row persists without a cached writer",
            &json!(queued(&prepared)),
            &json!(1),
        );
        checks.holds(
            row,
            "the persisted row is not yet in the log",
            !delivered(&prepared, row, "queued-without-writer"),
        );

        let consumed = prepared.consume().await;
        checks.eq(row, "consuming call", &consumed["ok"], &json!(true));
        checks.eq(
            row,
            "queued after the next draining writer",
            &json!(queued(&prepared)),
            &json!(0),
        );
        checks.holds(
            row,
            "the next draining writer delivers the persisted row",
            delivered(&prepared, row, "queued-without-writer"),
        );
    }
    checks.assert_none();
}

// ─────────────────────────────────────────────────────────────────────────────
// audit.outcome_row on mainnet
// ─────────────────────────────────────────────────────────────────────────────

/// The value audit rows of `prepared`'s log, by kind, in log order.
fn value_rows(prepared: &Prepared) -> Vec<String> {
    const KINDS: [&str; 5] = [
        "value_action_pending",
        "value_action_submitted",
        "value_action_failed",
        "x402_payment_authorized",
        "x402_authorization_withheld",
    ];
    std::fs::read_to_string(&prepared.server().security_profile().audit_log_path)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|entry| entry["kind"].as_str().map(str::to_owned))
        .filter(|kind| KINDS.contains(&kind.as_str()))
        .collect()
}

/// For each MCP value row on mainnet, the consuming call of an approved
/// preparation completes and writes exactly one value audit row: the
/// `value_action_pending` row the mainnet recorder writes with its anchored
/// facts before the send for a classic commit, and the
/// `x402_payment_authorized` row for an x402 payment. The preparation writes
/// none.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn every_mcp_row_writes_one_value_row_on_mainnet() {
    let mut failures = Vec::new();
    for row in Row::ALL {
        let prepared = Prepared::new(row, false).await;
        let before = value_rows(&prepared);
        let consumed = prepared.consume().await;
        let expected = match row {
            Row::Classic(_) => "value_action_pending",
            Row::X402 | Row::Authenticated => "x402_payment_authorized",
        };
        let after = value_rows(&prepared);
        if consumed["ok"] != true || !before.is_empty() || after != [expected] {
            failures.push(format!(
                "{}: before {before:?}, after {after:?}: {consumed}",
                row.id()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every matrix cell that names a test of this module lists exactly the rows
/// that test iterates, and every row test of this module is named by a cell.
#[test]
fn the_row_tables_match_their_matrix_cells() {
    const MODULE: &str = "tools::proof_row_status_tests::";
    let matrix: toml_edit::DocumentMut =
        include_str!("../../../../.github/scripts/proof-matrix.toml")
            .parse()
            .unwrap();
    let sorted = |mut rows: Vec<String>| {
        rows.sort();
        rows
    };
    let all = sorted(Row::ALL.iter().map(|row| row.id().to_owned()).collect());
    let classic = sorted(
        Tool::ALL
            .iter()
            .map(|tool| Row::Classic(*tool).id().to_owned())
            .collect(),
    );
    let tables: [(&str, &Vec<String>); 4] = [
        (
            "every_mcp_row_reports_its_approval_without_consuming_it",
            &all,
        ),
        (
            "every_classic_mcp_row_reports_its_operation_and_next_step",
            &classic,
        ),
        (
            "every_mcp_row_drains_or_keeps_its_queued_approval_row_at_shutdown",
            &all,
        ),
        ("every_mcp_row_writes_one_value_row_on_mainnet", &all),
    ];
    let mut named = std::collections::BTreeSet::new();
    for cell in matrix["cell"].as_array_of_tables().unwrap() {
        let Some(tests) = cell.get("tests").and_then(|tests| tests.as_array()) else {
            continue;
        };
        let rows = sorted(
            cell["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row.as_str().unwrap().to_owned())
                .collect(),
        );
        for test in tests {
            let name = test.as_inline_table().unwrap()["name"].as_str().unwrap();
            let Some(test) = name.strip_prefix(MODULE) else {
                continue;
            };
            let (_, table) = tables
                .iter()
                .find(|(table, _)| *table == test)
                .unwrap_or_else(|| panic!("{name} has no row table"));
            assert_eq!(&rows, *table, "{}: {name}", cell["claim"]);
            named.insert(test);
        }
    }
    let tested: std::collections::BTreeSet<&str> = tables.iter().map(|(test, _)| *test).collect();
    assert_eq!(named, tested, "every row test is named by a cell");
}

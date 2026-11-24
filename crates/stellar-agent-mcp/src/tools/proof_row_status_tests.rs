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

// ─────────────────────────────────────────────────────────────────────────────
// sizing.accounting_inputs_mainnet
// ─────────────────────────────────────────────────────────────────────────────
//
// On mainnet an unlisted payment beyond a budget bound escalates to a
// per-payment approval, so an allowing rule answers `policy.approval_required`.
// A debit beyond the total budget of the policy's epoch refuses
// `policy.deny.total_budget_exhausted`, and a balance the observed account,
// the retained native obligations and the call's debit and fee take below the
// floor refuses `account.floor_refused`.

/// The balance of every account of the mainnet fixture's ledger.
const FIXTURE_BALANCE: i64 = 100_000_000_000;

/// One accounting input of `sizing.accounting_inputs_mainnet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    Unlisted,
    Total,
    Floor,
}

impl Input {
    fn name(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Total => "total",
            Self::Floor => "floor",
        }
    }

    /// The refusal of a call of `row` over the input on mainnet. An x402
    /// payment that requires approval queues it and answers its pending
    /// approval without a payment payload, as its preparation call does.
    fn refusal(self, row: Row) -> &'static str {
        match self {
            Self::Unlisted if matches!(row, Row::Classic(_)) => "policy.approval_required",
            Self::Unlisted => "approval queued",
            Self::Total => "policy.deny.total_budget_exhausted",
            Self::Floor => "account.floor_refused",
        }
    }
}

/// What a call answered: its error code, `approval queued` for an x402
/// answer that names a pending approval and carries no payment payload, the
/// error code of a refused preparation, or `paid`.
fn answered(envelope: &Value) -> String {
    let data = &envelope["data"];
    if let Some(code) = envelope["error"]["code"]
        .as_str()
        .or_else(|| envelope["preparation_refused"]["error"]["code"].as_str())
    {
        code.to_owned()
    } else if data["approval"]["approval_nonce"].is_string()
        && data.get("paymentSignature").is_none()
    {
        "approval queued".to_owned()
    } else {
        "paid".to_owned()
    }
}

impl Input {
    /// The inputs that can refuse a call of `row`. A claim and a trustline
    /// debit nothing, so neither budget can be exceeded by them; the floor
    /// counts their fee.
    fn of(row: Row) -> &'static [Self] {
        match row {
            Row::Classic(Tool::Claim | Tool::Trustline) => &[Self::Floor],
            _ => &[Self::Unlisted, Self::Total, Self::Floor],
        }
    }
}

impl Row {
    /// The rules that carry the row's accounting criteria: the commit rule
    /// of a classic row, and the floor also on its preparation rule, whose
    /// paired evaluation reads the same floor; the payment rule of an x402
    /// row.
    fn accounting_rules(self, input: Input) -> Vec<&'static str> {
        match self {
            Self::Classic(tool) if input == Input::Floor => {
                vec![tool.prepare_name(), tool.commit_name()]
            }
            Self::Classic(tool) => vec![tool.commit_name()],
            _ => vec![self.tool()],
        }
    }

    /// The asset the row debits and the amount of one call: the fixture's
    /// 10-stroop payment, its 1 XLM creation, and its 10-unit x402 payment
    /// in the fixture's token.
    fn debit(self) -> (String, i64) {
        match self {
            Self::Classic(Tool::CreateAccount) => ("native".to_owned(), 10_000_000),
            Self::Classic(_) => ("native".to_owned(), 10),
            Self::X402 | Self::Authenticated => (
                stellar_strkey::Contract([3; 32]).to_string().to_string(),
                10,
            ),
        }
    }

    /// The floor that admits one call of the row and refuses a second whose
    /// first call's native debit and fee stay retained: the balance less one
    /// and a half calls. An x402 payment debits no native stroops and pays no
    /// fee, so its floor is the balance itself, which the native obligation
    /// of a sent payment of the same account crosses.
    fn floor(self) -> i64 {
        match self {
            Self::Classic(Tool::CreateAccount) => FIXTURE_BALANCE - 15_000_150,
            Self::Classic(Tool::Pay) => FIXTURE_BALANCE - 165,
            Self::Classic(_) => FIXTURE_BALANCE - 150,
            Self::X402 | Self::Authenticated => FIXTURE_BALANCE,
        }
    }
}

/// `raw` with `input` sized for one call of `row` on each of the row's
/// accounting rules.
fn accounting_policy(raw: &str, row: Row, input: Input) -> String {
    let (asset, amount) = row.debit();
    let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
    let names = row.accounting_rules(input);
    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
        if !rule["match"]["tool"]
            .as_str()
            .is_some_and(|tool| names.contains(&tool))
        {
            continue;
        }
        let criteria = rule["criteria"].as_array_mut().unwrap();
        let mut added = toml_edit::InlineTable::new();
        match input {
            Input::Unlisted => {
                for criterion in criteria.iter_mut() {
                    let criterion = criterion.as_inline_table_mut().unwrap();
                    if criterion["kind"].as_str() == Some("counterparty_allowlist") {
                        criterion.insert(
                            "allowlist",
                            toml_edit::Value::Array(toml_edit::Array::new()),
                        );
                        let mut budget = toml_edit::InlineTable::new();
                        budget.insert("mode", "budget".into());
                        budget.insert("asset", asset.as_str().into());
                        budget.insert("window", "1d".into());
                        budget.insert("per_tx_stroops", amount.into());
                        budget.insert("per_period_stroops", amount.into());
                        criterion.insert("unlisted", budget.into());
                    }
                }
                continue;
            }
            Input::Total => {
                added.insert("kind", "total_budget".into());
                added.insert("asset", asset.as_str().into());
                added.insert("max_stroops", amount.into());
            }
            Input::Floor => {
                added.insert("kind", "balance_floor".into());
                added.insert("min_stroops", row.floor().to_string().into());
            }
        }
        criteria.push(added);
    }
    doc.to_string()
}

/// The number of records of each bucket of `f`'s window.
fn bucket_rows(f: &Fixture) -> std::collections::BTreeMap<String, usize> {
    ledger(f).map_or_else(Default::default, |state| {
        state["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|bucket| {
                (
                    bucket["bucket"].as_str().unwrap().to_owned(),
                    bucket["records"].as_array().unwrap().len(),
                )
            })
            .collect()
    })
}

/// One MCP row on a routed mainnet fixture whose rules allow its calls under
/// one accounting input.
enum Accounting {
    Classic(Box<ClassicRun>),
    X402 {
        f: Box<Fixture>,
        rpc: wiremock::MockServer,
        control: std::sync::Arc<super::common::tests::mainnet::RpcControl>,
        _unenforced:
            Vec<stellar_agent_network::policy_state::approvals::ConsentEvidenceDisableGuard>,
    },
    Authenticated(Box<AuthenticatedRun>),
}

impl Accounting {
    /// The fixture of `row` under `input`. A classic row's first call is
    /// prepared; a floor run's window covers the endpoint's balance reads.
    async fn new(row: Row, input: Input) -> Self {
        use super::common::tests::mainnet::{cover_native_history, mount_rpc, routed_fixture};
        let policy = move |raw: String| accounting_policy(&raw, row, input);
        let accounting = match row {
            Row::Classic(tool) => Self::Classic(Box::new(
                ClassicRun::build(
                    tool,
                    None,
                    policy,
                    |_| {},
                    |args| {
                        if input == Input::Floor {
                            args["cover_native_history"] = json!(true);
                        }
                    },
                )
                .await,
            )),
            Row::X402 => {
                let rpc = wiremock::MockServer::start().await;
                let f = routed_fixture(policy, &rpc);
                let control = mount_rpc(&f, &rpc).await;
                Self::X402 {
                    _unenforced: super::common::tests::mainnet::unenforced(&f),
                    f: Box::new(f),
                    rpc,
                    control,
                }
            }
            Row::Authenticated => Self::Authenticated(Box::new(
                AuthenticatedRun::build(move |raw| {
                    accounting_policy(&authenticated_policy(&raw), row, input)
                })
                .await,
            )),
        };
        if input == Input::Floor && !matches!(accounting, Self::Classic(_)) {
            cover_native_history(accounting.fixture());
        }
        accounting
    }

    fn fixture(&self) -> &Fixture {
        match self {
            Self::Classic(run) => &run.f,
            Self::X402 { f, .. } => f,
            Self::Authenticated(run) => &run.f,
        }
    }

    /// The primary endpoint's sent transactions since the last clear.
    fn sent(&self) -> usize {
        match self {
            Self::Classic(run) => run.control.sent().len(),
            Self::X402 { control, .. } => control.sent().len(),
            Self::Authenticated(run) => run.control.sent().len(),
        }
    }

    /// A second preparation of a classic row, before its first commit,
    /// with the commit arguments of its envelope.
    async fn prepare_second(&self) -> Option<Value> {
        let Self::Classic(run) = self else {
            return None;
        };
        let args = run.tool.prepare_args(&run.f);
        let prepared = wire(&run.tool.prepare(&run.f.server, &args).await);
        let mut commit = args;
        for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
            commit[field] = prepared["data"][field].clone();
        }
        Some(if prepared["ok"] == true {
            commit
        } else {
            json!({ "preparation_refused": prepared })
        })
    }

    /// The row's call: the commit of `commit`, or the run's own first
    /// commit, for a classic row; the payment without a proof for an x402
    /// row.
    async fn call(&self, commit: Option<Value>) -> Value {
        match self {
            Self::Classic(run) => match commit {
                Some(commit) if commit.get("preparation_refused").is_some() => {
                    run.control.clear();
                    commit
                }
                Some(commit) => run.commit_with(commit).await,
                None => run.commit().await,
            },
            Self::X402 { f, control, .. } => {
                control.clear();
                wire(
                    &f.server
                        .call_stellar_x402_create_payment(x402_args(f, None))
                        .await
                        .unwrap(),
                )
            }
            Self::Authenticated(run) => {
                run.control.clear();
                run.call(run.args(HOME, None)).await
            }
        }
    }

    /// Sends a native payment of the fixture's account, whose debit and fee
    /// the floor counts as a retained obligation.
    async fn pay(&self) -> Value {
        let f = self.fixture();
        let args = Tool::Pay.prepare_args(f);
        let prepared = wire(&Tool::Pay.prepare(&f.server, &args).await);
        let mut commit = args;
        for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
            commit[field] = prepared["data"][field].clone();
        }
        wire(&Tool::Pay.commit(&f.server, commit).await.unwrap())
    }

    /// Starts a new server on the current files and keyring in place of the
    /// running one, as a restart of the wallet process does.
    fn restart(&mut self) {
        match self {
            Self::Classic(run) => run.restart().unwrap(),
            Self::X402 { f, rpc, .. } => {
                f.server = WalletServer::new_with_selection_and_routes_for_test(
                    (*f.server.profile).clone(),
                    stellar_agent_core::profile::name::ProfileNameSource::Flag,
                    &stellar_agent_core::profile::schema::default_profile_dir().unwrap(),
                    &[
                        ("rpc.example.invalid", rpc.uri().as_str()),
                        ("oracle.example.invalid", rpc.uri().as_str()),
                    ],
                )
                .unwrap();
            }
            Self::Authenticated(run) => run.restart().unwrap(),
        }
    }
}

/// For each MCP value row on mainnet, the unlisted counter, the budget epoch
/// and the balance floor size the call from persisted accounting.
///
/// Each row runs under each input that can refuse it, on its own fixture
/// whose allowing rules carry that input sized for one call. A classic row
/// prepares both calls first; its first call commits and sends, the server
/// restarts, and the second commit refuses with the input's refusal and
/// sends nothing. An x402 row pays once, restarts, and its second payment
/// refuses. Under the floor the second call's own debit and fee fit the
/// floor, and the first call's retained obligation, read from the window
/// after the restart, crosses it; an x402 payment carries no native
/// obligation, so a native payment of the same account sends between its
/// two calls. Every bucket of the window keeps the one record of each sent
/// call, and the refusal adds none.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn every_mcp_row_sizes_its_second_call_from_persisted_accounting() {
    let mut checks = Checks::default();
    for row in Row::ALL {
        for &input in Input::of(row) {
            let what = |step: &str| format!("{} {step}", input.name());
            let mut accounting = Accounting::new(row, input).await;
            let second = accounting.prepare_second().await;
            let first = accounting.call(None).await;
            let first_sent = accounting.sent();
            checks.eq(row, &what("first call"), &first["ok"], &json!(true));
            if matches!(row, Row::Classic(_)) {
                checks.eq(
                    row,
                    &what("first call sends"),
                    &json!(first_sent),
                    &json!(1),
                );
            }
            if input == Input::Floor && !matches!(row, Row::Classic(_)) {
                let paid = accounting.pay().await;
                checks.eq(row, &what("native payment"), &paid["ok"], &json!(true));
            }
            let sent = bucket_rows(accounting.fixture());
            accounting.restart();
            let refused = accounting.call(second).await;
            checks.eq(
                row,
                &what("second call after the restart"),
                &json!(answered(&refused)),
                &json!(input.refusal(row)),
            );
            checks.eq(
                row,
                &what("second call sends"),
                &json!(accounting.sent()),
                &json!(0),
            );
            // The x402 floor run's two sent calls share the call-count
            // bucket of the profile; every other bucket counts one of them.
            let shared = |bucket: &str| {
                input == Input::Floor && !matches!(row, Row::Classic(_)) && bucket == "rate_limit"
            };
            checks.holds(
                row,
                &format!(
                    "{}: one record per sent call in each bucket: {sent:?}",
                    what("window")
                ),
                !sent.is_empty()
                    && sent
                        .iter()
                        .all(|(bucket, records)| *records == if shared(bucket) { 2 } else { 1 }),
            );
            checks.holds(
                row,
                &what("the refusal adds no record"),
                bucket_rows(accounting.fixture()) == sent,
            );
        }
    }
    checks.assert_none();
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
    let tables: [(&str, &Vec<String>); 5] = [
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
        (
            "every_mcp_row_sizes_its_second_call_from_persisted_accounting",
            &all,
        ),
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

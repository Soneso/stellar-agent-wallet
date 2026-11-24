//! Proof-matrix rows of the toolset payment commit,
//! `stellar_toolset_invoke/stellar_pay_commit`, on testnet in both builds.
//!
//! Each test drives the toolset route through the parent module's `Harness`
//! with the payment toolset installed, and asserts one claim of the release
//! proof matrix for that row.

use super::*;

/// A harness whose testnet rules require approval for every tool, the
/// toolset invocation included, with the payment toolset installed and its
/// grant recorded for [`DEST`].
async fn toolset_harness(name: &str, outcome: Outcome) -> Harness {
    let mut h =
        Harness::with_policy_chain(name, "require_approval", outcome, "", "stellar:testnet").await;
    h.install_payment_toolset();
    h
}

/// [`Harness::restart`] with the payment toolset bound to the new server.
fn restart_toolset(h: &mut Harness) {
    h.restart();
    h.bind_payment_toolset();
}

/// The kinds of the value rows of `h`'s audit log, in order.
fn value_row_kinds(h: &Harness) -> Vec<String> {
    crate::common::audit_rows(&h.profile)
        .iter()
        .filter_map(|row| row["kind"].as_str())
        .filter(|kind| kind.starts_with("value_action") || kind.starts_with("x402_"))
        .map(str::to_owned)
        .collect()
}

/// One `stellar_transaction_status` call of `tx_hash` on `h`'s server.
async fn transaction_status(h: &Harness, tx_hash: &str) -> Value {
    result_json(
        &h.server
            .call_stellar_transaction_status(StellarTransactionStatusArgs {
                chain_id: "stellar:testnet".to_owned(),
                tx_hash: Some(tx_hash.to_owned()),
                business_id: None,
                retry_recovery: false,
            })
            .await
            .unwrap(),
    )
}

/// The status of every window record of `h` that carries a submission, for
/// each submission id in id order. The store's decoder is private to its
/// crate, so this reads the JSON body after the store's authentication tag;
/// the body starts at the first offset whose rest parses as JSON.
fn hold_statuses(h: &Harness) -> Vec<Vec<String>> {
    let bytes = std::fs::read(PersistedWindowStore::for_profile(&h.name).path()).unwrap();
    let body: Value = (0..bytes.len())
        .filter(|&at| bytes[at] == b'{')
        .find_map(|at| serde_json::from_slice(&bytes[at..]).ok())
        .unwrap();
    let mut statuses: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for record in body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|bucket| bucket["records"].as_array().unwrap())
    {
        let Some(id) = record["id"].as_str().filter(|id| !id.is_empty()) else {
            continue;
        };
        statuses
            .entry(id.to_owned())
            .or_default()
            .push(record["status"].as_str().unwrap().to_owned());
    }
    statuses.into_values().collect()
}

/// An approval of the toolset commit keeps its state and its lifetime window
/// across a restart. The toolset preparation queues a pending approval,
/// which stays pending across a restart and refuses a toolset commit without
/// proof. Attested, it stays attested across a restart, refuses at the end of
/// its stored window under the restarted server, and commits inside it on
/// the toolset route after another restart. Consumed, it stays consumed
/// across a restart and refuses a second toolset commit. Each restart leaves
/// every stored fact of the approval unchanged, and only one send happens.
#[tokio::test]
#[serial]
async fn the_toolset_commit_keeps_its_approval_state_and_window_across_restart() {
    let mut h = toolset_harness("cell-durable-toolset", Outcome::Success).await;
    let first = h.simulate_pay_route(AMOUNT, true).await;
    let nonce = approval_nonce(&first);
    let path = h.store_path();
    let data = first["data"].clone();

    let pending = stored_at(&path, &nonce);
    restart_toolset(&mut h);
    assert_eq!(stored_at(&path, &nonce), pending, "pending across restart");
    let refused = h
        .commit_pay_route(h.pay_args(&data, AMOUNT, None), true)
        .await;
    assert_eq!(
        refused["error"]["code"], "policy.approval_required",
        "pending after restart: {refused}"
    );

    let approval = h.attest(&data);
    let attested = stored_at(&path, &nonce);
    restart_toolset(&mut h);
    assert_eq!(
        stored_at(&path, &nonce),
        attested,
        "attested across restart"
    );
    let end = PendingApprovalStore::open(path.clone())
        .unwrap()
        .get(&nonce)
        .unwrap()
        .expires_at_unix_ms;
    h.server
        .set_clock_for_test(Arc::new(MockClock::new(move || Ok(end))));
    let refused = h
        .commit_pay_route(h.pay_args(&data, AMOUNT, Some(approval.clone())), true)
        .await;
    assert_eq!(
        refused["error"]["code"], "policy.approval_required",
        "at the end of the stored window: {refused}"
    );
    assert!(h.sends.lock().unwrap().is_empty(), "no send");
    assert_eq!(stored_at(&path, &nonce), attested, "nothing spent");

    restart_toolset(&mut h);
    let result = h
        .commit_pay_route(h.pay_args(&data, AMOUNT, Some(approval.clone())), true)
        .await;
    assert_eq!(result["ok"], true, "inside the window: {result}");
    let consumed = stored_at(&path, &nonce);
    assert!(consumed_at(&path, &nonce));
    restart_toolset(&mut h);
    assert_eq!(
        stored_at(&path, &nonce),
        consumed,
        "consumed across restart"
    );
    // A smaller payment stays inside the rule's period cap beside the sent one.
    let third = h.simulate_pay_route(AMOUNT / 4, true).await;
    assert_eq!(third["ok"], true, "{third}");
    let refused = h
        .commit_pay_route(h.pay_args(&third["data"], AMOUNT / 4, Some(approval)), true)
        .await;
    assert_eq!(
        refused["error"]["code"], "policy.approval_consumed",
        "consumed after restart: {refused}"
    );
    assert_eq!(h.sends.lock().unwrap().len(), 1, "one send");
}

/// The approval status of a toolset-queued approval reports its state and
/// validity and consumes nothing. Pending, two status calls report it pending
/// and not valid; attested, two calls report it attested and valid; each
/// pair answers the same view and leaves the inbox entry unchanged. The
/// attested toolset commit then spends it, and the status reports it
/// consumed and no longer valid.
#[tokio::test]
#[serial]
async fn the_toolset_commit_approval_status_reports_without_consuming() {
    let h = toolset_harness("cell-status-toolset", Outcome::Success).await;
    let first = h.simulate_pay_route(AMOUNT, true).await;
    let nonce = approval_nonce(&first);
    let path = h.store_path();
    let strip = |mut view: Value| {
        view["request_id"] = Value::Null;
        view
    };
    let mut approval = None;
    for (state, verification) in [
        (
            "pending",
            json!({"supported": true, "valid": false, "reason": "attestation_invalid"}),
        ),
        (
            "attested",
            json!({"supported": true, "valid": true, "reason": "ok"}),
        ),
    ] {
        if state == "attested" {
            approval = Some(h.attest(&first["data"]));
        }
        let before = stored_at(&path, &nonce);
        let once = approval_status(&h, &nonce).await;
        let twice = approval_status(&h, &nonce).await;
        assert_eq!(once["ok"], true, "{state}: {once}");
        assert_eq!(once["data"]["state"], state, "{state}: {once}");
        assert_eq!(once["data"]["kind"], "PaymentSimulated", "{state}: {once}");
        assert_eq!(
            once["data"]["verification"], verification,
            "{state}: {once}"
        );
        assert_eq!(once["data"]["reusable"], false, "{state}: {once}");
        assert!(
            once["data"]["expires_at_ms"]
                .as_u64()
                .is_some_and(|at| at > now_unix_ms().unwrap()),
            "{state}: {once}"
        );
        assert_eq!(strip(once), strip(twice), "{state}: the same view");
        assert_eq!(
            stored_at(&path, &nonce),
            before,
            "{state}: nothing consumed"
        );
    }
    let result = h
        .commit_pay_route(h.pay_args(&first["data"], AMOUNT, approval), true)
        .await;
    assert_eq!(result["ok"], true, "{result}");
    let after = approval_status(&h, &nonce).await;
    assert_eq!(after["data"]["state"], "consumed", "{after}");
    assert_eq!(
        after["data"]["verification"],
        json!({"supported": true, "valid": false, "reason": "consumed"}),
        "{after}"
    );
}

/// One `stellar_approval_status` call of `nonce` on `h`'s server.
async fn approval_status(h: &Harness, nonce: &str) -> Value {
    result_json(
        &h.server
            .approval_status_for_test(nonce.to_owned())
            .await
            .unwrap(),
    )
}

/// Every terminal outcome of the toolset commit writes one audit row. An
/// attested toolset commit that the endpoint applies, that times out, that
/// fails on chain, or whose send the endpoint refuses leaves exactly one
/// `value_action_pending` row, the row the recorder writes before the send,
/// and no other value row.
#[tokio::test]
#[serial]
async fn every_toolset_commit_outcome_writes_one_audit_row() {
    for (outcome, name, code) in [
        (Outcome::Success, "applied", None),
        (Outcome::Timeout, "timed-out", Some("submission.tx_timeout")),
        (Outcome::Failed, "failed", Some("ledger.op_failed")),
        (Outcome::Refused, "refused", Some("submission.tx_malformed")),
    ] {
        let h = toolset_harness(&format!("cell-outcome-toolset-{name}"), outcome).await;
        let sim = h.simulate_pay_route(AMOUNT, true).await;
        let approval = h.attest(&sim["data"]);
        let result = h
            .commit_pay_driven(
                h.pay_args(&sim["data"], AMOUNT, Some(approval)),
                false,
                true,
            )
            .await;
        match code {
            None => assert_eq!(result["ok"], true, "{name}: {result}"),
            Some(code) => assert_eq!(result["error"]["code"], code, "{name}: {result}"),
        }
        assert_eq!(h.sends.lock().unwrap().len(), 1, "{name}: one send");
        assert_eq!(
            value_row_kinds(&h),
            ["value_action_pending"],
            "{name}: one value row"
        );
    }
}

/// A sent toolset commit's hold is never released without evidence. The
/// attested toolset commit times out with one pending hold. Reconciliations
/// of its hash that meet `NOT_FOUND` and then `FAILED` keep the hold pending;
/// once the endpoint reports `SUCCESS`, the same reconciliation turns it into
/// an exposure. No reconciliation sends.
#[tokio::test]
#[serial]
async fn the_toolset_commit_settles_its_hold_only_on_outcome_evidence() {
    let h = toolset_harness("cell-hold-toolset", Outcome::Timeout).await;
    let sim = h.simulate_pay_route(AMOUNT, true).await;
    let approval = h.attest(&sim["data"]);
    let result = h
        .commit_pay_driven(
            h.pay_args(&sim["data"], AMOUNT, Some(approval)),
            false,
            true,
        )
        .await;
    assert_eq!(result["error"]["code"], "submission.tx_timeout", "{result}");
    let tx_hash = result["error"]["details"]["tx_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let pending = vec![vec!["pending".to_owned()]];
    assert_eq!(hold_statuses(&h), pending, "the sent call holds");
    let missing = transaction_status(&h, &tx_hash).await;
    assert_eq!(hold_statuses(&h), pending, "NOT_FOUND keeps it: {missing}");
    *h.outcomes.lock().unwrap() = Outcome::Failed;
    let failed = transaction_status(&h, &tx_hash).await;
    assert_eq!(hold_statuses(&h), pending, "FAILED keeps it: {failed}");
    *h.outcomes.lock().unwrap() = Outcome::Success;
    let applied = transaction_status(&h, &tx_hash).await;
    assert_eq!(
        hold_statuses(&h),
        vec![vec!["exposure".to_owned()]],
        "SUCCESS turns it into an exposure: {applied}"
    );
    assert_eq!(h.sends.lock().unwrap().len(), 1, "no status call sends");
}

/// The transaction status reconciles the receipt and the hold of a sent
/// toolset commit. After the attested toolset commit times out, the status
/// of its hash reports the pending receipt beside its open hold; once the
/// endpoint reports the transaction applied, it records the success on the
/// receipt and keeps the hold. No status call sends.
#[tokio::test]
#[serial]
async fn the_toolset_commit_status_reconciles_its_receipt_and_hold() {
    let h = toolset_harness("cell-reconcile-toolset", Outcome::Timeout).await;
    let sim = h.simulate_pay_route(AMOUNT, true).await;
    let approval = h.attest(&sim["data"]);
    let result = h
        .commit_pay_driven(
            h.pay_args(&sim["data"], AMOUNT, Some(approval)),
            false,
            true,
        )
        .await;
    assert_eq!(result["error"]["code"], "submission.tx_timeout", "{result}");
    let details = &result["error"]["details"];
    let tx_hash = details["tx_hash"].as_str().unwrap();
    let envelope_hash = details["envelope_hash"].as_str().unwrap();
    let reconciled = |view: &Value, status: &str| {
        let data = &view["data"];
        assert_eq!(view["ok"], true, "{status}: {view}");
        assert_eq!(data["record"]["envelope_hash"], envelope_hash, "{view}");
        assert_eq!(data["record"]["status"], status, "{view}");
        assert_eq!(data["record"]["reservation_open"], true, "{view}");
        assert_eq!(
            data["reservation"]["envelope_hash"], envelope_hash,
            "{view}"
        );
        assert_eq!(data["reservation"]["operator_required"], false, "{view}");
    };
    let before = transaction_status(&h, tx_hash).await;
    reconciled(&before, "pending");
    *h.outcomes.lock().unwrap() = Outcome::Success;
    let after = transaction_status(&h, tx_hash).await;
    assert_eq!(after["data"]["chain_status"], "SUCCESS", "{after}");
    reconciled(&after, "success");
    assert_eq!(h.window().pending, 1, "the hold stays open");
    assert_eq!(h.sends.lock().unwrap().len(), 1, "no status call sends");
}

/// Queues an `approval_attested` row for the toolset approval `nonce` in the
/// outbox beside `h`'s audit log, as `stellar-agent approve` does while the
/// server holds the writer, with `marker` as its request id.
fn queue_approval_row(h: &Harness, nonce: &str, marker: &str) {
    stellar_agent_core::audit_log::AuditOutbox::for_log(
        &h.profile.audit_log_path,
        stellar_agent_network::keyring::KeyringTipAnchorStore::shared(
            &h.profile.audit_log_hash_chain_key_id,
            &h.profile.audit_log_path,
        ),
    )
    .append(
        &stellar_agent_core::audit_log::AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            nonce,
            "cli",
            marker,
        ),
    )
    .unwrap();
}

/// The number of rows queued beside `h`'s audit log.
fn queued(h: &Harness) -> usize {
    stellar_agent_core::audit_log::inspect_outbox(&h.profile.audit_log_path)
        .unwrap()
        .pending
}

/// Whether `h`'s audit log holds the approval row `marker` names.
fn delivered(h: &Harness, marker: &str) -> bool {
    crate::common::audit_rows(&h.profile)
        .iter()
        .any(|row| row["kind"] == "approval_attested" && row["request_id"] == marker)
}

/// Queued approval audit rows of the toolset commit drain or persist at
/// shutdown. An earlier toolset payment leaves the server holding the
/// profile's writer. An approval row queued for the next toolset-queued
/// approval while the server holds the writer reaches the log at the exit
/// drain and leaves the outbox empty. A row queued after the process lost
/// its cached writer stays in the outbox through the exit drain, and the
/// attested toolset commit, the next draining writer, delivers it.
#[tokio::test]
#[serial]
async fn the_toolset_commit_queued_approval_row_drains_or_persists_at_shutdown() {
    use stellar_agent_core::audit_log::AuditWriterRegistry;
    let h = toolset_harness("cell-outbox-toolset", Outcome::Success).await;
    let earlier = h.simulate_pay_route(AMOUNT / 4, true).await;
    let approval = h.attest(&earlier["data"]);
    let sent = h
        .commit_pay_route(
            h.pay_args(&earlier["data"], AMOUNT / 4, Some(approval)),
            true,
        )
        .await;
    assert_eq!(sent["ok"], true, "the earlier payment: {sent}");

    let next = h.simulate_pay_route(AMOUNT / 4, true).await;
    let nonce = approval_nonce(&next);
    queue_approval_row(&h, &nonce, "queued-while-held");
    assert_eq!(queued(&h), 1, "queued while held");
    assert!(!delivered(&h, "queued-while-held"));
    assert!(
        AuditWriterRegistry::drain_cached_outboxes() >= 1,
        "the exit drain checks the cached writer"
    );
    assert_eq!(queued(&h), 0, "the exit drain empties the outbox");
    assert!(
        delivered(&h, "queued-while-held"),
        "the exit drain delivers the queued row"
    );

    AuditWriterRegistry::remove_for_test(&h.name);
    queue_approval_row(&h, &nonce, "queued-without-writer");
    // Other cached writers may still drain; this profile has none.
    let _ = AuditWriterRegistry::drain_cached_outboxes();
    assert_eq!(queued(&h), 1, "the row persists without a cached writer");
    assert!(!delivered(&h, "queued-without-writer"));

    let approval = h.attest(&next["data"]);
    let consumed = h
        .commit_pay_route(h.pay_args(&next["data"], AMOUNT / 4, Some(approval)), true)
        .await;
    assert_eq!(
        consumed["ok"], true,
        "the consuming toolset commit: {consumed}"
    );
    assert_eq!(queued(&h), 0, "the next draining writer empties the outbox");
    assert!(
        delivered(&h, "queued-without-writer"),
        "the next draining writer delivers the persisted row"
    );
}

/// The number of records of each bucket of `h`'s window store, read as
/// [`hold_statuses`] reads it; empty before the store's first write.
fn bucket_rows(h: &Harness) -> std::collections::BTreeMap<String, usize> {
    let Ok(bytes) = std::fs::read(PersistedWindowStore::for_profile(&h.name).path()) else {
        return std::collections::BTreeMap::new();
    };
    let body: Value = (0..bytes.len())
        .filter(|&at| bytes[at] == b'{')
        .find_map(|at| serde_json::from_slice(&bytes[at..]).ok())
        .unwrap();
    body["entries"]
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
}

/// The error code of a preparation or commit answer.
fn code(answer: &Value) -> &str {
    answer["error"]["code"].as_str().unwrap_or("")
}

/// The unlisted counter, the budget epoch and the balance floor size the
/// toolset commit from persisted accounting on testnet.
///
/// Each input runs on its own harness, whose signed version 2 policy allows
/// every testnet tool, the toolset invocation included, under that input
/// sized for one payment of [`AMOUNT`]. Two payments are prepared through
/// the toolset. The first toolset commit sends; the server restarts; the
/// second toolset commit refuses with the input's code and sends nothing,
/// and the window keeps the one record of the sent commit in each bucket.
/// Off mainnet an unlisted payment beyond its budget is denied
/// `policy.deny.unlisted_budget_exceeded`, and a debit beyond the total
/// budget `policy.deny.total_budget_exhausted`. The floor reads no observed
/// account off mainnet, so under it every toolset call refuses
/// `account.unread` before any send.
#[tokio::test]
#[serial]
async fn the_toolset_commit_sizes_its_second_payment_from_persisted_accounting() {
    let mut failures = Vec::new();
    for (input, criterion, refusal) in [
        (
            "unlisted",
            format!(
                "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [], \
                 unlisted = {{ mode = \"budget\", asset = \"native\", per_tx_stroops = {AMOUNT}, \
                 per_period_stroops = {AMOUNT}, window = \"1d\" }} }}"
            ),
            "policy.deny.unlisted_budget_exceeded",
        ),
        (
            "total",
            format!("{{ kind = \"total_budget\", asset = \"native\", max_stroops = {AMOUNT} }}"),
            "policy.deny.total_budget_exhausted",
        ),
        (
            "floor",
            "{ kind = \"balance_floor\", min_stroops = \"1\" }".to_owned(),
            "account.unread",
        ),
    ] {
        let rules = format!(
            r#"[[rules]]
match = {{ tool = "stellar_transaction_status", chain = "*" }}
criteria = []
decision = "allow"
[[rules]]
match = {{ tool = "*", chain = "stellar:testnet" }}
criteria = [{criterion}]
decision = "allow"
"#
        );
        let mut h = Harness::with_versioned_rules(
            &format!("cell-accounting-toolset-{input}"),
            Outcome::Success,
            2,
            &rules,
        )
        .await;
        h.install_payment_toolset();
        let first = h.simulate_pay_route(AMOUNT, true).await;
        let second = h.simulate_pay_route(AMOUNT, true).await;
        if input == "floor" {
            // Each call refuses before any send, before and after a restart.
            let before = [code(&first).to_owned(), code(&second).to_owned()];
            restart_toolset(&mut h);
            let after = code(&h.simulate_pay_route(AMOUNT, true).await).to_owned();
            if before != [refusal, refusal]
                || after != refusal
                || !h.sends.lock().unwrap().is_empty()
                || !bucket_rows(&h).is_empty()
            {
                failures.push(format!(
                    "floor: {before:?} then {after}, {} sent, window {:?}",
                    h.sends.lock().unwrap().len(),
                    bucket_rows(&h)
                ));
            }
            continue;
        }
        if first["ok"] != true || second["ok"] != true {
            failures.push(format!("{input}: preparations: {first} and {second}"));
            continue;
        }
        let sent = h
            .commit_pay_driven(h.pay_args(&first["data"], AMOUNT, None), false, true)
            .await;
        let sends = h.sends.lock().unwrap().len();
        let window = bucket_rows(&h);
        restart_toolset(&mut h);
        let refused = h
            .commit_pay_driven(h.pay_args(&second["data"], AMOUNT, None), false, true)
            .await;
        if sent["ok"] != true || sends != 1 {
            failures.push(format!(
                "{input}: first toolset commit, {sends} sent: {sent}"
            ));
        }
        if code(&refused) != refusal || h.sends.lock().unwrap().len() != sends {
            failures.push(format!(
                "{input}: second toolset commit after the restart: {refused}"
            ));
        }
        let counted = window
            .keys()
            .any(|bucket| bucket.starts_with(&format!("{input}:")));
        if !counted || window.values().any(|records| *records != 1) {
            failures.push(format!("{input}: window after the sent commit {window:?}"));
        }
        if bucket_rows(&h) != window {
            failures.push(format!(
                "{input}: the refusal changed the window {window:?} to {:?}",
                bucket_rows(&h)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

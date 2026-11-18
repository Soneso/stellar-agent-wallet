//! Public payment retries across process exits at durable write boundaries.

use super::*;
use std::path::Path;
use std::sync::Mutex;
use stellar_agent_core::approval::fixtures::{restore_process_keyring, save_process_keyring};
use stellar_agent_core::approval::store::persist_test_seam::{self, Step};
use stellar_agent_core::profile::{loader, receipt::ReceiptStore};
use stellar_agent_network::policy_state::{BusinessId, OperationStatus};
use stellar_agent_test_support::StellarAgentHomeGuard;

async fn call(
    server: &crate::server::WalletServer,
    action: &str,
    args: Value,
    toolset: bool,
) -> Value {
    if toolset {
        wire(
            &server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: TOOLSET.into(),
                    action: action.into(),
                    chain_id: Some("stellar:mainnet".into()),
                    args,
                })
                .await
                .unwrap(),
        )
    } else if action == "stellar_pay" {
        wire(&Tool::Pay.prepare(server, &args).await)
    } else {
        wire(&Tool::Pay.commit(server, args).await.unwrap())
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn child_server(root: &Path) -> crate::server::WalletServer {
    let config = read_json(&root.join("process.json"));
    let profiles = stellar_agent_core::profile::loader::default_profile_dir().unwrap();
    let profile = loader::load_from_dir("operator", &profiles, None).unwrap();
    let primary = url::Url::parse(&profile.rpc_url).unwrap();
    let oracle = profile.oracle_provider_url.as_ref().unwrap();
    let mut server = crate::server::WalletServer::new_with_selection_and_routes_for_test(
        profile.clone(),
        stellar_agent_core::profile::name::ProfileNameSource::Flag,
        &profiles,
        &[
            (
                primary.host_str().unwrap(),
                config["primary"].as_str().unwrap(),
            ),
            (
                oracle.host_str().unwrap(),
                config["oracle"].as_str().unwrap(),
            ),
        ],
    )
    .unwrap();
    server.set_toolsets_root_for_test(config["toolsets"].as_str().unwrap().into());
    server.set_grant_store_path_for_test(config["grants"].as_str().unwrap().into());
    server.set_toolset_pin_key_for_test(PinKey::from_bytes(zeroize::Zeroizing::new([0x63; 32])));
    server
}

async fn fixture() -> (Run, Value) {
    let run = Run::with_recording(
        "require_approval",
        "require_approval",
        &["propose-transaction", "sign-payment"],
        |raw| raw,
        true,
    )
    .await;
    run.grant(DESTINATIONS[0].0);
    let mut args = Tool::Pay.prepare_args(&run.f);
    args["destination"] = DESTINATIONS[2].0.into();
    args["memo_id"] = 7.into();
    let root = run.f._dir.path();
    write_json(&root.join("request.json"), &args);
    write_json(
        &root.join("process.json"),
        &serde_json::json!({
            "primary": run._primary.uri(), "oracle": run._oracle.uri(),
            "toolsets": run.root.path(), "grants": run.grants,
        }),
    );
    save_process_keyring(&root.join("keys.json"), run.f.key_changes.as_ref().unwrap());
    (run, args)
}

async fn run_child(
    run: &Run,
    route: bool,
    cut: Option<usize>,
    output: &str,
) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "tools::toolsets_mainnet_tests::process::public_payment_crashes_preserve_recovery_at_every_durable_write", "--nocapture"])
        .env("TOOLSET_PAYMENT_PROCESS_ROOT", run.f._dir.path())
        .env("TOOLSET_PAYMENT_PROCESS_ROUTE", route.to_string())
        .env("TOOLSET_PAYMENT_PROCESS_CUT", cut.map_or_else(|| "none".into(), |n| n.to_string()))
        .env("TOOLSET_PAYMENT_PROCESS_OUTPUT", output);
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

fn successful(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "child payment: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_payment_crashes_preserve_recovery_at_every_durable_write() {
    if let Ok(root) = std::env::var("TOOLSET_PAYMENT_PROCESS_ROOT") {
        let root = std::path::PathBuf::from(root);
        assert!(
            root.join(stellar_agent_test_support::sandbox::MARKER)
                .is_file()
        );
        let _home = StellarAgentHomeGuard::new(&root);
        let changes = restore_process_keyring(&root.join("keys.json"));
        let server = child_server(&root);
        let cut = std::env::var("TOOLSET_PAYMENT_PROCESS_CUT")
            .unwrap()
            .parse::<usize>()
            .ok();
        let output = std::env::var("TOOLSET_PAYMENT_PROCESS_OUTPUT").unwrap();
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let approval = server.resolve_approval_dir().unwrap().join("operator.toml");
        let receipt = ReceiptStore::open("operator").unwrap().file_path().unwrap();
        let window = server.window_store.path().to_owned();
        let observe = {
            let root = root.clone();
            let changes = changes.clone();
            let events = events.clone();
            let approval = approval.clone();
            Arc::new(move |label: String| {
                let mut events = events.lock().unwrap();
                events.push(label.clone());
                write_json(&root.join("events.json"), &*events);
                save_process_keyring(&root.join("keys.json"), &changes);
                if label == "approval/DirectorySynced" {
                    let doc: toml_edit::DocumentMut =
                        std::fs::read_to_string(&approval).unwrap().parse().unwrap();
                    assert_eq!(
                        doc.get("payment_recovery")
                            .and_then(toml_edit::Item::as_array_of_tables)
                            .map_or(0, |rows| rows.len()),
                        1,
                        "published payment consent retains its recovery binding"
                    );
                }
                if cut == Some(events.len() - 1) {
                    std::process::exit(81);
                }
            })
        };
        for (kind, path, steps) in [
            (
                "approval",
                approval,
                vec![
                    Step::TemporarySynced,
                    Step::Renamed,
                    Step::FileSynced,
                    Step::DirectorySynced,
                ],
            ),
            (
                "receipt",
                receipt,
                vec![Step::TemporarySynced, Step::Renamed, Step::DirectorySynced],
            ),
        ] {
            for step in steps {
                for _ in 0..32 {
                    let observe = observe.clone();
                    persist_test_seam::on_step(&path, step, move || {
                        observe(format!("{kind}/{step:?}"))
                    });
                }
            }
        }
        let _observer = stellar_agent_network::policy_state::store::commit_faults::observe_commit(
            move |point| {
                let bytes = std::fs::read(&window).unwrap();
                let file: Value = serde_json::from_slice(&bytes[32..]).unwrap();
                let selected = if point == 5 { &file["prepared"] } else { &file };
                let state = selected["operations"]["records"][0]["state"]
                    .as_str()
                    .unwrap_or("absent");
                observe(format!("window/{point}/{state}"));
            },
        );
        let route = std::env::var("TOOLSET_PAYMENT_PROCESS_ROUTE").unwrap() == "true";
        let mut args = read_json(&root.join("request.json"));
        let prepared = call(&server, "stellar_pay", args.clone(), route).await;
        // A minted authorization consumed the linked approval: the
        // preparation answers that refusal, which the parent classifies.
        assert!(
            prepared["ok"] == true || prepared["error"]["code"] == "policy.approval_consumed",
            "recovery preparation: {prepared}"
        );
        let result = if prepared["data"]["envelope_xdr"].is_string() {
            for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
                args[field] = prepared["data"][field].clone();
            }
            let nonce = prepared["data"]["approval"]["approval_nonce"]
                .as_str()
                .unwrap();
            let entry = {
                let store = PendingApprovalStore::open(
                    server.resolve_approval_dir().unwrap().join("operator.toml"),
                )
                .unwrap();
                store.get(nonce).unwrap().clone()
            };
            args["approval_nonce"] = nonce.into();
            args["approval_attestation"] = entry
                .attestation_blob_b64
                .clone()
                .unwrap_or_else(|| {
                    Fixture::attest_server(&server, &entry, "operator", "stellar:mainnet")
                })
                .into();
            call(&server, "stellar_pay_commit", args, route).await
        } else {
            prepared
        };
        save_process_keyring(&root.join("keys.json"), &changes);
        write_json(&root.join(output), &result);
        return;
    }
    let mut violations = Vec::new();
    let mut refused_cuts = Vec::new();
    for first_toolset in [false, true] {
        let (baseline, _) = fixture().await;
        successful(&run_child(&baseline, first_toolset, None, "baseline.json").await);
        let body = read_json(&baseline.f._dir.path().join("baseline.json"));
        assert_eq!(
            body["ok"], true,
            "the intact public payment succeeds: {body}"
        );
        assert_eq!(baseline.control.sent().len(), 1);
        let trace: Vec<String> =
            serde_json::from_value(read_json(&baseline.f._dir.path().join("events.json"))).unwrap();
        #[allow(clippy::print_stderr, reason = "process-cut evidence count")]
        {
            eprintln!("toolset_first={first_toolset} durable_cuts={}", trace.len());
        }
        for required in [
            "approval/DirectorySynced",
            "receipt/DirectorySynced",
            "window/5/sending",
            "window/5/sent_outcome_unknown",
        ] {
            assert!(
                trace.iter().any(|event| event == required),
                "durable boundary {required} is reached: {trace:?}"
            );
        }
        drop(baseline);
        for (cut, expected) in trace.iter().enumerate() {
            let (run, args) = fixture().await;
            let exited = run_child(&run, first_toolset, Some(cut), "lost.json").await;
            assert_eq!(
                exited.status.code(),
                Some(81),
                "cut {cut}/{expected}: {} {}",
                String::from_utf8_lossy(&exited.stdout),
                String::from_utf8_lossy(&exited.stderr)
            );
            let observed: Vec<String> =
                serde_json::from_value(read_json(&run.f._dir.path().join("events.json"))).unwrap();
            assert_eq!(
                observed.last(),
                Some(expected),
                "the same public write boundary is cut"
            );
            let old_nonce = {
                let path = run
                    .f
                    .server
                    .resolve_approval_dir()
                    .unwrap()
                    .join("operator.toml");
                if path.exists() {
                    let store = PendingApprovalStore::open(path).unwrap();
                    store
                        .snapshot(now_unix_ms().unwrap())
                        .first()
                        .map(|entry| entry.approval_nonce.clone())
                } else {
                    None
                }
            };
            successful(&run_child(&run, !first_toolset, None, "retry.json").await);
            let first_sends = run.control.sent().len();
            successful(&run_child(&run, first_toolset, None, "repeat.json").await);
            assert_eq!(
                run.control.sent().len(),
                first_sends,
                "repeating a recovered business operation adds no send"
            );
            assert!(
                first_sends <= 1,
                "a crash permits at most the original payment effect"
            );
            restore_process_keyring(&run.f._dir.path().join("keys.json"));
            let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
            let stored =
                OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                    .view(&id)
                    .unwrap()
                    .unwrap();
            assert_eq!(
                stored.destinations,
                stellar_agent_core::profile::receipt::PaymentDestinations::Single(
                    DESTINATIONS[2].0.into()
                ),
                "recovery retains the original complete destination"
            );
            let stored_hash = stored
                .result
                .as_ref()
                .and_then(|result| result.tx_hash)
                .map(|hash| stellar_agent_core::hex::encode(&hash));
            let retry = read_json(&run.f._dir.path().join("retry.json"));
            let repeat = read_json(&run.f._dir.path().join("repeat.json"));
            let stored_answer = (
                serde_json::json!("replayed"),
                serde_json::json!(stored.operation_id.to_hex()),
                serde_json::json!(stored.state.wire_name()),
                serde_json::json!(stored_hash),
            );
            let answer = |body: &Value| {
                (
                    body["data"]["status"].clone(),
                    body["data"]["operation"]["id"].clone(),
                    body["data"]["operation"]["state"].clone(),
                    body["data"]["operation"]["tx_hash"].clone(),
                )
            };
            // The retry either submits under the stored operation's hash or
            // answers that operation; the repeat answers it.
            let retry_holds = retry["ok"] == true
                && if retry["data"]["status"] == "replayed" {
                    answer(&retry) == stored_answer
                } else {
                    retry["data"]["tx_hash"] == serde_json::json!(stored_hash)
                };
            let repeat_holds = repeat["ok"] == true && answer(&repeat) == stored_answer;
            // Two cuts stop the payment unsent, and the retry and the repeat
            // give the same typed refusal. A cut inside the operator's
            // consent write leaves the inbox attested and the durable record
            // without consent. A cut after the authorization mint and before
            // its attempt leaves the approval consumed by an unclaimed
            // authorization, which expiry or invalidation releases.
            let unsent =
                stored_hash.is_none() && first_sends == 0 && repeat["error"] == retry["error"];
            let consent_unrecorded = unsent
                && stored.state.wire_name() == "awaiting_approval"
                && authorizations(&run.f).is_empty()
                && retry["error"]["code"] == "network.mainnet_authorization_refused";
            let unclaimed = unsent
                && stored.state.wire_name() == "authorized"
                && authorizations(&run.f).len() == 1
                && retry["error"]["code"] == "policy.approval_consumed";
            if consent_unrecorded || unclaimed {
                refused_cuts.push(format!(
                    "toolset_first={first_toolset} {expected} {}",
                    retry["error"]["code"].as_str().unwrap()
                ));
            } else if !(retry_holds && repeat_holds) {
                violations.push(format!(
                    "toolset_first={first_toolset} cut {cut}/{expected}: stored {stored_answer:?}; retry {retry}; repeat {repeat}"
                ));
            }
            let state =
                stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new();
            run.f
                .server
                .window_store
                .load_into_at(
                    "operator",
                    run.f.server.security_profile(),
                    &state,
                    now_unix_ms().unwrap(),
                )
                .unwrap();
            let key = stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                "operator", 1, "native", 86_400,
            );
            let counted = state.query_window(&key, now_unix_ms().unwrap()).unwrap();
            assert!(
                matches!(counted, (0, 0) | (10, 1)),
                "one crash-safe payment debit: {counted:?}"
            );
            assert!(authorizations(&run.f).len() <= 1);
            if first_sends == 1 {
                assert_eq!(counted, (10, 1), "sent uncertainty remains counted");
                let receipts = ReceiptStore::open("operator").unwrap().all().unwrap();
                assert_eq!(receipts.len(), 1);
                assert!(receipts[0].submitted, "the sent receipt retains exposure");
            }
            if let Some(nonce) = old_nonce {
                assert_eq!(run.pending().len(), 1);
                assert_eq!(
                    run.pending()[0].approval_nonce,
                    nonce,
                    "a restart never replaces retained consent"
                );
            }
        }
    }
    assert!(
        violations.is_empty(),
        "every retry and repeat answers the stored operation:\n{}",
        violations.join("\n")
    );
    assert_eq!(
        refused_cuts,
        [false, true]
            .into_iter()
            .flat_map(|first| {
                [
                    "approval/Renamed network.mainnet_authorization_refused",
                    "approval/FileSynced network.mainnet_authorization_refused",
                    "approval/DirectorySynced network.mainnet_authorization_refused",
                    "window/4/awaiting_approval network.mainnet_authorization_refused",
                    "window/5/awaiting_approval policy.approval_consumed",
                    "window/4/awaiting_approval policy.approval_consumed",
                ]
                .map(|cut| format!("toolset_first={first} {cut}"))
            })
            .collect::<Vec<_>>(),
        "only the unrecorded consent and the unclaimed authorization refuse the retry"
    );
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_stale_process_gate_cannot_overwrite_a_competing_payment() {
    use std::io::{BufRead, Write};
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    if let Ok(root) = std::env::var("TOOLSET_PAYMENT_STALE_ROOT") {
        let root = std::path::PathBuf::from(root);
        assert!(
            root.join(stellar_agent_test_support::sandbox::MARKER)
                .is_file()
        );
        let _home = StellarAgentHomeGuard::new(&root);
        let changes = restore_process_keyring(&root.join("keys.json"));
        let mut server = child_server(&root);
        let mut args = read_json(&root.join("request.json"));
        let prepared = call(&server, "stellar_pay", args.clone(), true).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
            args[field] = prepared["data"][field].clone();
        }
        let nonce = prepared["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap();
        let entry = {
            let store = PendingApprovalStore::open(
                server.resolve_approval_dir().unwrap().join("operator.toml"),
            )
            .unwrap();
            store.get(nonce).unwrap().clone()
        };
        args["approval_nonce"] = nonce.into();
        args["approval_attestation"] =
            Fixture::attest_server(&server, &entry, "operator", "stellar:mainnet").into();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let arrivals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        server.payment_proof_barrier = Some((barrier.clone(), arrivals.clone()));
        let mints = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = mints.clone();
        let _seam = stellar_agent_network::policy_state::ledger::mint_test_seam::before_next_mint(
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
            },
        );
        let peer = async {
            while arrivals.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            save_process_keyring(&root.join("keys.json"), &changes);
            stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
            writeln!(std::io::stdout(), "STALE_GATE_READY").unwrap();
            std::io::stdout().flush().unwrap();
            tokio::task::spawn_blocking(|| {
                let mut signal = String::new();
                std::io::stdin().read_line(&mut signal).unwrap();
                assert_eq!(signal, "continue\n");
            })
            .await
            .unwrap();
            restore_process_keyring(&root.join("keys.json"));
            stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
            barrier.wait().await;
        };
        let (result, ()) = tokio::join!(call(&server, "stellar_pay_commit", args, true), peer);
        assert_eq!(
            mints.load(Ordering::SeqCst),
            0,
            "the stale public gate is reevaluated before mint after the competing debit"
        );
        assert_eq!(
            result["error"]["code"], "policy.deny.per_period_cap_exceeded",
            "the stale public gate refuses the competing debit: {result}"
        );
        save_process_keyring(&root.join("keys.json"), &changes);
        write_json(&root.join("stale-result.json"), &result);
        return;
    }
    for first_toolset in [false, true] {
        let run = Run::with_recording(
            "require_approval",
            "require_approval",
            &["propose-transaction", "sign-payment"],
            |raw| {
                let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
                for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                    if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke") {
                        for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                            let criterion = criterion.as_inline_table_mut().unwrap();
                            if criterion["kind"].as_str() == Some("per_period_cap") {
                                criterion.insert("max_stroops", toml_edit::Value::from("100"));
                            }
                        }
                    }
                }
                doc.to_string()
            },
            true,
        )
        .await;
        run.grant(DESTINATIONS[0].0);
        run.f
            .server
            .window_store
            .record_authorized(
                run.f.server.security_profile(),
                &[WindowEntry::new(
                    StateKey::new("operator", 1, "native", 86_400),
                    now_unix_ms().unwrap(),
                    40,
                    WindowLimit::Amount {
                        asset: "native".into(),
                        window: "1d".into(),
                        max_stroops: 200,
                    },
                )],
            )
            .unwrap();
        let mut first_args = Tool::Pay.prepare_args(&run.f);
        first_args["amount_in_stroops"] = "50".into();
        first_args["memo_id"] = 1.into();
        let prepared = run.prepare_route(&first_args, first_toolset).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let first_entry = run.pending().pop().unwrap();
        let mut commit = run.commit_args(first_args, &prepared);
        commit["approval_nonce"] = first_entry.approval_nonce.clone().into();
        commit["approval_attestation"] = run.f.attest(&first_entry).into();
        let mut rival = Tool::Pay.prepare_args(&run.f);
        rival["amount_in_stroops"] = "50".into();
        rival["memo_id"] = 2.into();
        let root = run.f._dir.path().to_owned();
        write_json(&root.join("request.json"), &rival);
        write_json(
            &root.join("process.json"),
            &serde_json::json!({
                "primary": run._primary.uri(), "oracle": run._oracle.uri(),
                "toolsets": run.root.path(), "grants": run.grants,
            }),
        );
        save_process_keyring(&root.join("keys.json"), run.f.key_changes.as_ref().unwrap());
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "tools::toolsets_mainnet_tests::process::public_stale_process_gate_cannot_overwrite_a_competing_payment", "--nocapture"])
            .env("TOOLSET_PAYMENT_STALE_ROOT", &root)
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = tokio::task::spawn_blocking(move || {
            let mut child = command.spawn().unwrap();
            let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "the peer reaches its policy gate: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                if line.trim() == "STALE_GATE_READY" {
                    break;
                }
            }
            child.stdout = Some(reader.into_inner());
            child
        })
        .await
        .unwrap();
        let changes = restore_process_keyring(&root.join("keys.json"));
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
        let result = run.commit_route(commit, first_toolset).await;
        assert_eq!(
            result["ok"], true,
            "the competing public payment succeeds: {result}"
        );
        assert_eq!(recorded_amount(&run, "native"), (90, 2));
        assert_eq!(run.control.sent().len(), 1);
        save_process_keyring(&root.join("keys.json"), &changes);
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        let output = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
            .await
            .unwrap();
        successful(&output);
        restore_process_keyring(&root.join("keys.json"));
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
        assert_eq!(
            recorded_amount(&run, "native"),
            (90, 2),
            "the stale process adds no partial hold"
        );
        assert_eq!(authorizations(&run.f).len(), 1);
        assert_eq!(run.control.sent().len(), 1);
        run.source_sequence(2);
        let mut independent = Tool::Pay.prepare_args(&run.f);
        independent["memo_id"] = 3.into();
        let prepared = run.invoke("stellar_pay", independent.clone()).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let nonce = prepared["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap();
        let entry = run
            .pending()
            .into_iter()
            .find(|entry| entry.approval_nonce == nonce)
            .unwrap();
        let mut commit = run.commit_args(independent, &prepared);
        commit["approval_nonce"] = entry.approval_nonce.clone().into();
        commit["approval_attestation"] = run.f.attest(&entry).into();
        let result = run.invoke("stellar_pay_commit", commit).await;
        assert_eq!(
            result["ok"], true,
            "exact remaining headroom still permits an independent payment: {result}"
        );
        assert_eq!(recorded_amount(&run, "native"), (100, 3));
        assert_eq!(authorizations(&run.f).len(), 2);
        assert_eq!(run.control.sent().len(), 2);
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_noninclusion_after_restart_releases_only_the_original_payment() {
    if let Ok(root) = std::env::var("TOOLSET_PAYMENT_ABSENT_ROOT") {
        let root = std::path::PathBuf::from(root);
        assert!(
            root.join(stellar_agent_test_support::sandbox::MARKER)
                .is_file()
        );
        let _home = StellarAgentHomeGuard::new(&root);
        let changes = restore_process_keyring(&root.join("keys.json"));
        let server = child_server(&root);
        let info = read_json(&root.join("absence.json"));
        let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(
            info["now"].as_u64().unwrap(),
        );
        let mut result = Value::Null;
        for _ in 0..4 {
            result = wire(
                &server
                    .call_stellar_transaction_status(crate::server::StellarTransactionStatusArgs {
                        chain_id: "stellar:mainnet".into(),
                        tx_hash: Some(info["hash"].as_str().unwrap().into()),
                        business_id: None,
                        retry_recovery: true,
                    })
                    .await
                    .unwrap(),
            );
            assert_eq!(result["ok"], true, "{result}");
            if result["data"]["recovery"]["attempts"][0]["result"] == "NeverApplicable" {
                break;
            }
        }
        assert_eq!(
            result["data"]["recovery"]["attempts"][0]["result"], "NeverApplicable",
            "public status proves non-inclusion from both endpoint observations: {result}"
        );
        save_process_keyring(&root.join("keys.json"), &changes);
        write_json(&root.join("absence-result.json"), &result);
        return;
    }
    for first_toolset in [false, true] {
        let run = Run::with_recording("allow", "allow", &["propose-transaction", "sign-payment"],
            |raw| raw + "\n[[rules]]\nmatch = { tool = \"stellar_transaction_status\", chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n", true).await;
        run.grant(DESTINATIONS[0].0);
        run.control
            .transaction_unknown
            .store(true, Ordering::SeqCst);
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["destination"] = DESTINATIONS[2].0.into();
        let prepared = run.prepare_route(&args, first_toolset).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let result = run
            .commit_route(run.commit_args(args.clone(), &prepared), first_toolset)
            .await;
        assert_eq!(result["error"]["code"], "submission.tx_timeout", "{result}");
        assert_eq!(run.control.sent().len(), 1);
        assert_eq!(recorded_amount(&run, "native"), (10, 1));
        let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
        let status = || {
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .view(&id)
                .unwrap()
                .unwrap()
        };
        let original = status();
        let hash =
            stellar_agent_core::hex::encode(&original.result.as_ref().unwrap().tx_hash.unwrap());
        let now = now_unix_ms().unwrap() + 600_000;
        let future = Arc::new(std::sync::atomic::AtomicBool::new(true));
        serve_absence(&run, &hash, now, &future).await;
        for _ in 0..2 {
            prove_absence(&run).await;
            let view = status();
            assert_eq!(view.state.wire_name(), "not_included");
            assert_eq!(view.operation_id, original.operation_id);
            assert_eq!(view.destinations, original.destinations);
            assert_eq!(
                view.result.as_ref().unwrap().tx_hash,
                original.result.as_ref().unwrap().tx_hash
            );
            let state =
                stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new();
            run.f
                .server
                .window_store
                .load_into_at("operator", run.f.server.security_profile(), &state, now)
                .unwrap();
            let key = stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                "operator", 1, "native", 86_400,
            );
            assert_eq!(
                state.query_window(&key, now).unwrap(),
                (0, 0),
                "proved non-inclusion releases this payment's debit once"
            );
            assert_eq!(run.control.sent().len(), 1);
        }
        future.store(false, Ordering::SeqCst);
        run.control
            .transaction_unknown
            .store(false, Ordering::SeqCst);
        let mut independent = Tool::Pay.prepare_args(&run.f);
        independent["memo_id"] = 7.into();
        let prepared = run.prepare_route(&independent, !first_toolset).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let result = run
            .commit_route(run.commit_args(independent, &prepared), !first_toolset)
            .await;
        assert_eq!(
            result["ok"], true,
            "a proved absent payment leaves headroom for an independent payment: {result}"
        );
        assert_eq!(run.control.sent().len(), 2);
        assert_eq!(recorded_amount(&run, "native"), (10, 1));
    }
}

/// Serves both endpoints the observations that prove `hash` absent at `now`
/// while `future` holds, and writes the files the absence child reads.
async fn serve_absence(
    run: &Run,
    hash: &str,
    now: u64,
    future: &Arc<std::sync::atomic::AtomicBool>,
) {
    {
        for endpoint in [&run._primary, &run._oracle] {
            let answer = serde_json::json!({"status":"NOT_FOUND", "latestLedger":102, "oldestLedger":1, "oldestLedgerCloseTime":1, "latestLedgerCloseTime":now/1000});
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::body_partial_json(
                    serde_json::json!({"method":"getTransaction", "params":{"hash":hash}}),
                ))
                .respond_with(move |request: &wiremock::Request| {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    wiremock::ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "result":answer}),
                    )
                })
                .with_priority(1)
                .mount(endpoint)
                .await;
            let health_future = future.clone();
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::body_partial_json(serde_json::json!({"method":"getHealth"})))
                .respond_with(move |request: &wiremock::Request| {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    let close = if health_future.load(Ordering::SeqCst) { now / 1000 } else { now_unix_ms().unwrap() / 1000 };
                    wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"jsonrpc":"2.0", "id":body["id"],
                        "result":{"status":"healthy", "latestLedger":102, "oldestLedger":1, "ledgerRetentionWindow":102,
                        "oldestLedgerCloseTime":1, "latestLedgerCloseTime":close}}))
                }).with_priority(1).mount(endpoint).await;
            let entries = super::super::common::tests::mainnet::fixture_entries(&run.f);
            let page_future = future.clone();
            let page = serde_json::json!({"latestLedger":102, "latestLedgerCloseTime":now/1000,
            "oldestLedger":1, "oldestLedgerCloseTime":1, "cursor":"102", "ledgers":[{
                "sequence":102, "ledgerCloseTime":(now/1000).to_string(), "hash":"00".repeat(32),
                "headerXdr":"", "metadataXdr":""
            }]});
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::body_partial_json(
                    serde_json::json!({"method":"getLedgers"}),
                ))
                .respond_with(move |request: &wiremock::Request| {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    let mut page = page.clone();
                    if !page_future.load(Ordering::SeqCst) {
                        let close = now_unix_ms().unwrap() / 1000;
                        page["latestLedgerCloseTime"] = close.into();
                        page["ledgers"][0]["ledgerCloseTime"] = close.to_string().into();
                    }
                    wiremock::ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "result":page}),
                    )
                })
                .with_priority(1)
                .mount(endpoint)
                .await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::body_partial_json(serde_json::json!({"method":"getLedgerEntries"})))
                .respond_with(move |request: &wiremock::Request| {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    let keys = body["params"]["keys"].as_array().unwrap();
                    wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"jsonrpc":"2.0", "id":body["id"],
                        "result":{"entries":entries.iter().filter(|entry| keys.contains(&entry["key"])).collect::<Vec<_>>(), "latestLedger":102}}))
                }).with_priority(1).mount(endpoint).await;
        }
    }
    let root = run.f._dir.path().to_owned();
    write_json(
        &root.join("process.json"),
        &serde_json::json!({
            "primary":run._primary.uri(), "oracle":run._oracle.uri(), "toolsets":run.root.path(), "grants":run.grants,
        }),
    );
    write_json(
        &root.join("absence.json"),
        &serde_json::json!({"hash":hash, "now":now}),
    );
    save_process_keyring(&root.join("keys.json"), run.f.key_changes.as_ref().unwrap());
}

/// Proves the payment [`serve_absence`] names absent through a status
/// query in a child process.
async fn prove_absence(run: &Run) {
    let root = run.f._dir.path().to_owned();
    stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "tools::toolsets_mainnet_tests::process::public_noninclusion_after_restart_releases_only_the_original_payment"])
        .env("TOOLSET_PAYMENT_ABSENT_ROOT", &root);
    let output = tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap();
    successful(&output);
    restore_process_keyring(&root.join("keys.json"));
    stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
}

/// A consumed preparation entry refuses a proofless toolset commit with
/// `nonce.replayed` before any queue write. The entry is reachable once its
/// operation resumes, here after proved non-inclusion.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_consumed_preparation_refuses_before_queueing() {
    let run = Run::with_recording("require_approval", "allow", &["propose-transaction", "sign-payment"],
        |raw| raw + "\n[[rules]]\nmatch = { tool = \"stellar_transaction_status\", chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n", true).await;
    let args = Tool::Pay.prepare_args(&run.f);
    run.grant(args["destination"].as_str().unwrap());
    run.control
        .transaction_unknown
        .store(true, Ordering::SeqCst);
    let prepared = run.prepare_route(&args, false).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    let proofless = run.commit_args(args.clone(), &prepared);
    let queued = run.invoke("stellar_pay_commit", proofless.clone()).await;
    assert_eq!(
        queued["error"]["code"], "policy.approval_required",
        "{queued}"
    );
    let entry = run.pending().remove(0);
    let mut commit = proofless.clone();
    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let sent = run.invoke("stellar_pay_commit", commit).await;
    assert_eq!(sent["error"]["code"], "submission.tx_timeout", "{sent}");
    assert_eq!(run.control.sent().len(), 1);
    let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
    let status = || {
        OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
            .view(&id)
            .unwrap()
            .unwrap()
    };
    let hash = stellar_agent_core::hex::encode(&status().result.unwrap().tx_hash.unwrap());
    let future = Arc::new(std::sync::atomic::AtomicBool::new(true));
    serve_absence(&run, &hash, now_unix_ms().unwrap() + 600_000, &future).await;
    prove_absence(&run).await;
    assert_eq!(status().state.wire_name(), "not_included");
    future.store(false, Ordering::SeqCst);
    run.control
        .transaction_unknown
        .store(false, Ordering::SeqCst);

    let pending = run.pending();
    let refused = run.invoke("stellar_pay_commit", proofless).await;
    assert_eq!(
        refused["error"]["code"], "nonce.replayed",
        "a consumed entry refuses before queueing: {refused}"
    );
    assert_eq!(
        run.pending()
            .iter()
            .map(|entry| &entry.approval_nonce)
            .collect::<Vec<_>>(),
        pending
            .iter()
            .map(|entry| &entry.approval_nonce)
            .collect::<Vec<_>>(),
        "a consumed entry queues nothing"
    );
    assert_eq!(run.control.sent().len(), 1);
}

/// A preparation's operation facts live in the preparing process. A
/// proofless toolset commit in a fresh process therefore refuses
/// `nonce.expired` before any queue write, and the agent prepares again.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_proofless_commit_in_a_fresh_process_refuses_before_queueing() {
    if let Ok(root) = std::env::var("TOOLSET_PAYMENT_RESTART_ROOT") {
        let root = std::path::PathBuf::from(root);
        assert!(
            root.join(stellar_agent_test_support::sandbox::MARKER)
                .is_file()
        );
        let _home = StellarAgentHomeGuard::new(&root);
        let changes = restore_process_keyring(&root.join("keys.json"));
        let server = child_server(&root);
        let prepared = call(
            &server,
            "stellar_pay",
            read_json(&root.join("request.json")),
            false,
        )
        .await;
        save_process_keyring(&root.join("keys.json"), &changes);
        write_json(&root.join("prepared.json"), &prepared);
        return;
    }
    let run = Run::with_recording(
        "require_approval",
        "allow",
        &["propose-transaction", "sign-payment"],
        |raw| raw,
        true,
    )
    .await;
    let args = Tool::Pay.prepare_args(&run.f);
    run.grant(args["destination"].as_str().unwrap());
    let root = run.f._dir.path().to_owned();
    write_json(&root.join("request.json"), &args);
    write_json(
        &root.join("process.json"),
        &serde_json::json!({
            "primary": run._primary.uri(), "oracle": run._oracle.uri(),
            "toolsets": run.root.path(), "grants": run.grants,
        }),
    );
    save_process_keyring(&root.join("keys.json"), run.f.key_changes.as_ref().unwrap());
    stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "tools::toolsets_mainnet_tests::process::public_proofless_commit_in_a_fresh_process_refuses_before_queueing",
        ])
        .env("TOOLSET_PAYMENT_RESTART_ROOT", &root);
    successful(
        &tokio::task::spawn_blocking(move || command.output().unwrap())
            .await
            .unwrap(),
    );
    restore_process_keyring(&root.join("keys.json"));
    stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
    let prepared = read_json(&root.join("prepared.json"));
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert!(prepared["data"]["approval"].is_null(), "{prepared}");

    let nonce_reads = run.f.nonce_reads.load(Ordering::SeqCst);
    let refused = run
        .f
        .server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: TOOLSET.into(),
            action: "stellar_pay_commit".into(),
            chain_id: Some("stellar:mainnet".into()),
            args: run.commit_args(args.clone(), &prepared),
        })
        .await
        .map(|result| wire(&result)["error"].clone())
        .map_err(|error| error.message.to_string());
    assert_eq!(
        refused,
        Ok(serde_json::json!({
            "code": "nonce.expired",
            "message": "nonce expired or invalid; re-simulate to obtain a fresh nonce",
        })),
        "a preparation of an earlier process refuses before queueing"
    );
    assert!(run.pending().is_empty(), "the refusal queues nothing");
    assert!(run.f.server.replay_window.lock().await.is_empty());
    assert_eq!(run.f.nonce_reads.load(Ordering::SeqCst), nonce_reads);
    assert!(authorizations(&run.f).is_empty());
    assert!(run.control.sent().is_empty());

    let again = run.prepare_route(&args, false).await;
    assert_eq!(again["ok"], true, "{again}");
    let queued = run
        .invoke("stellar_pay_commit", run.commit_args(args, &again))
        .await;
    assert_eq!(
        queued["error"]["code"], "policy.approval_required",
        "a preparation in this process queues the consent: {queued}"
    );
    assert_eq!(run.pending().len(), 1);
    assert!(run.control.sent().is_empty());
}

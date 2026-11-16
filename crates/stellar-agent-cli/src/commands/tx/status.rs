//! `stellar-agent tx status <HASH>` — reconcile one submitted transaction
//! against the chain.
//!
//! # What it is for
//!
//! A value verb records its submission before the transaction is sent, so a
//! submission whose confirmation never arrived leaves a receipt behind. It
//! also leaves a spending-window reservation when the policy produced window
//! entries for the submission. Those hold the operator's caps and the
//! wallet's duplicate check. This verb asks the endpoint what became of the
//! transaction. It records a reported success on the receipt and classifies
//! a missing transaction against the endpoint's retention. Accounting expiry
//! ends the reservation independently of any answer.
//!
//! It is also the answer to `submission.tx_timeout`: rebuilding and
//! re-submitting the same intent is never the answer, because the sequence the
//! transaction consumes may already be spent by it.
//!
//! # What it changes
//!
//! - `SUCCESS` is recorded on the receipt as a report, unless the receipt of
//!   an untimed hold already records another network answer, which it keeps.
//!   The reservation keeps counting through the transaction's accounting
//!   horizon. No submitted row is written, and the pending row stays open.
//! - A reported failure or missing transaction does not release possible
//!   spending. `FAILED`, and `NOT_FOUND` with a consumed sequence or a ledger
//!   close time past the time bound, keep the reservation, preserve the
//!   existing receipt status, and owe no `value_action_failed` row.
//! - The accounting horizon is the later of the signed time bound and the
//!   first local success observation, plus each affected window's duration.
//!   Once it has passed on this host's clock, the reservation ends with the
//!   outcome unknown, and no failed row is owed. A `pending` or `ambiguous`
//!   receipt is marked ambiguous with `release_code`
//!   `submission.accounting_expired`; a receipt with another status keeps its
//!   status and code. Every projected receipt carries the decision
//!   identifier. The expiry owes one `submission_accounting_expired` audit event,
//!   which this verb delivers from the verified window state. An absent
//!   receipt is rebuilt from the committed expiry.
//! - The receipt is display data. `record` carries
//!   `settlement_evidence: "unavailable"`, and no receipt status writes an
//!   audit row.
//! - When the submission ledger predates the endpoint's retention floor,
//!   `NOT_FOUND` proves nothing, so the reservation stands. A `pending` or
//!   `ambiguous` receipt is marked ambiguous and keeps any release evidence
//!   it already carries; `tx receipt clear` resolves it. The receipt of an
//!   untimed hold keeps a recorded network answer. Any other receipt refuses
//!   the transition, which the verb logs as a receipt write failure. An
//!   absent receipt leaves an authenticated hold marked `operator_required`
//!   unless the hold records a reported success.
//!
//! No step sends the transaction again.
//!
//! # Recovery results
//!
//! For a managed mainnet attempt, `recovery` carries each attempt's typed
//! result (`Included`, `NeverApplicable` or `NeedsEvidence`), its retry
//! class, earliest retry time and next action, plus any refusal code.
//! `--retry-recovery` starts one new bounded evidence run for a stopped
//! attempt, also before its retry time or after `RetriesExhausted`. That run
//! resets the attempt's run count to one, so at most 15 automatic runs
//! follow. It refuses a live lease, an earlier clock and unusable metadata.
//! It collects evidence only: it never resubmits and authorizes no
//! successor.
//!
//! # Concurrency
//!
//! Delivering an accounting audit event needs the audit writer's exclusive
//! lock, and the verb acquires the writer only for an unacknowledged event.
//! While an MCP server holds that profile's writer, the verb still reconciles
//! and reports. The event stays owed, and the refusal is logged at WARN. Stop
//! that server and run the verb again to deliver it. The server acquires its
//! writer when needed, including for V1 reservation reconciliation during
//! simulation. The registry normally retains it until exit. A replaced-file
//! refusal during acquisition marks it for eviction; a later acquisition
//! drops it once callers release it.
//!
//! # Exit codes
//!
//! - 0 when the lookup completes, whatever the chain reported.
//! - 1 when the profile, the record, or the endpoint could not be reached.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReleaseEvidence, SubmissionReceipt};
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::submission_flow::{self, StatusFailure, StatusRequest, is_tx_hash};

use crate::common::profile_access::load_profile_or_synthesize_testnet;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

/// Arguments for the `tx status` subcommand.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct StatusArgs {
    /// Transaction hash to reconcile, 64 lowercase hex characters.
    ///
    /// This is the `details.tx_hash` a `submission.tx_timeout` response
    /// carries.
    #[arg(value_name = "HASH")]
    pub tx_hash: String,

    /// Profile whose submission records and spending window are reconciled.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Output format.
    #[arg(long, value_parser = OutputFormat::parse, default_value = "json")]
    pub output: OutputFormat,

    /// Start one new bounded recovery run for this hash's stopped mainnet
    /// attempt, also before its retry time or after its runs are exhausted.
    /// The run collects evidence only and never sends a transaction.
    #[arg(long)]
    pub retry_recovery: bool,
}

/// The wallet's record of one submission, as reported to the operator.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct RecordView {
    /// The envelope hash the record is stored under. `tx receipt clear` takes
    /// this value.
    envelope_hash: String,
    /// The receipt's settled status.
    status: String,
    /// Stable wire code for a failed submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    /// The ledger the transaction confirmed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<u32>,
    /// The source account, redacted first-5-last-5.
    source_redacted: String,
    /// The sequence number the transaction consumes.
    sequence: i64,
    /// Whether the transaction was sent.
    submitted: bool,
    /// Whether a spending-window reservation is still open for it.
    reservation_open: bool,
    /// A display observation or the accounting disposition, such as
    /// `submission.accounting_expired`. Absent when the receipt records none.
    #[serde(skip_serializing_if = "Option::is_none")]
    release_code: Option<&'static str>,
    /// Always `"unavailable"`: no receipt field authenticates a settlement.
    settlement_evidence: &'static str,
    /// The authenticated accounting decision a projection recorded. A copied
    /// identifier proves nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement_decision_id: Option<String>,
    /// Complete payment provenance carried by the receipt.
    #[serde(flatten)]
    destinations: stellar_agent_core::profile::receipt::DestinationFields,
}

/// Authenticated hold identity, available even when its receipt is absent.
#[derive(Debug, Serialize)]
struct ReservationView {
    envelope_hash: String,
    operator_required: bool,
}

/// Success payload for the `tx status` envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct StatusData {
    /// The transaction hash that was reconciled.
    tx_hash: String,
    /// What the endpoint reported (`SUCCESS`, `FAILED` or `NOT_FOUND`); for a
    /// managed mainnet attempt, the cached recovery result or `UNKNOWN`.
    chain_status: String,
    /// The ledger the endpoint reports the transaction in.
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<u32>,
    /// The wallet's record of the submission, when it holds one.
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<RecordView>,
    /// A held debit, including an orphan requiring operator recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    reservation: Option<ReservationView>,
    /// Typed recovery results and any refusal for managed mainnet attempts.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery: Option<serde_json::Value>,
}

/// Runs `tx status`.
///
/// Returns an exit code: `0` on success, `1` on any error.
pub async fn run(args: &StatusArgs) -> i32 {
    if !is_tx_hash(&args.tx_hash) {
        render_json(&Envelope::<()>::err_raw(
            "validation.address_invalid",
            "HASH must be 64 lowercase hex characters",
        ));
        return 1;
    }

    let resolved = resolve_profile_name(args.profile.as_deref());
    // The same origin rule the value verbs use. A zero-config operator's
    // submission is recorded on a synthesized profile, and the verb that
    // settles it has to be runnable on that same profile: refusing here would
    // leave a dropped submission holding its sequence with nothing able to
    // free it.
    let (profile, origin) = match load_profile_or_synthesize_testnet(&resolved) {
        Ok(p) => p,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(e.code(), e.message()));
            return 1;
        }
    };

    if let Err(e) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let window = PersistedWindowStore::for_profile(&resolved.name);

    let context = crate::common::network::profile_network_context(&profile);
    let client = match context.primary_client() {
        Ok(c) => c,
        Err(e) => {
            // An unreadable window file refuses before a client failure, as
            // the window is read first.
            if let Err(error) = window.pending_reservations(&profile) {
                render_json(&status_error_envelope(StatusFailure::WindowUnreadable(
                    error,
                )));
            } else {
                render_json(&Envelope::<()>::err(&e));
            }
            return 1;
        }
    };

    let oracle = crate::commands::submission_record::settlement_oracle_in(&profile, &context);
    let outcome = match submission_flow::transaction_status(
        status_request(
            args,
            &profile,
            &resolved.name,
            &window,
            &client,
            oracle.as_ref(),
        ),
        stellar_agent_core::profile::schema::default_approval_dir,
        || {
            crate::commands::submission_record::accounting_audit_writer(
                &profile,
                &resolved.name,
                origin,
            )
        },
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            render_json(&status_error_envelope(error));
            return 1;
        }
    };
    render_json(&Envelope::ok(status_data(args, outcome)));
    0
}

fn status_request<'a>(
    args: &'a StatusArgs,
    profile: &'a stellar_agent_core::profile::schema::Profile,
    profile_name: &'a str,
    window: &'a PersistedWindowStore,
    client: &'a stellar_agent_network::StellarRpcClient,
    oracle: Option<&'a stellar_agent_network::StellarRpcClient>,
) -> StatusRequest<'a> {
    StatusRequest {
        profile,
        profile_name,
        tx_hash: &args.tx_hash,
        window,
        client,
        oracle,
        retry_recovery: args.retry_recovery,
    }
}

fn status_data(args: &StatusArgs, outcome: submission_flow::StatusOutcome) -> StatusData {
    StatusData {
        tx_hash: args.tx_hash.clone(),
        record: outcome
            .record
            .as_ref()
            .map(|settled| record_view(settled, outcome.reservation_open)),
        recovery: outcome.recovery.status_json(),
        chain_status: outcome.chain_status,
        ledger: outcome.ledger,
        reservation: outcome.reservation.map(|r| ReservationView {
            envelope_hash: r.id,
            operator_required: r.operator_required,
        }),
    }
}

fn record_view(receipt: &SubmissionReceipt, reservation_open: bool) -> RecordView {
    RecordView {
        envelope_hash: receipt.envelope_hash.clone(),
        status: receipt.status.label().to_owned(),
        failure_code: match &receipt.status {
            ReceiptStatus::Failed { code } => Some(code.clone()),
            _ => None,
        },
        ledger: receipt.ledger,
        source_redacted: stellar_agent_core::observability::redact_strkey_first5_last5(
            &receipt.source,
        ),
        sequence: receipt.sequence,
        submitted: receipt.submitted,
        reservation_open,
        release_code: receipt.release_code.map(ReleaseEvidence::code),
        settlement_evidence: "unavailable",
        settlement_decision_id: receipt.settlement_decision_id.clone(),
        destinations: stellar_agent_core::profile::receipt::DestinationFields(
            receipt.destinations.clone(),
        ),
    }
}

#[cfg(test)]
pub(super) fn destination_shapes() -> Vec<stellar_agent_core::profile::receipt::PaymentDestinations>
{
    use stellar_agent_core::profile::receipt::{OperationDestination, PaymentDestinations};
    let g = format!("{}", stellar_strkey::ed25519::PublicKey([7; 32]));
    let m = format!(
        "{}",
        stellar_strkey::ed25519::MuxedAccount {
            ed25519: [7; 32],
            id: u64::MAX
        }
    );
    vec![
        PaymentDestinations::None,
        PaymentDestinations::Single(m.clone()),
        PaymentDestinations::PerOperation(vec![
            OperationDestination {
                operation: 0,
                destination: g,
            },
            OperationDestination {
                operation: 2,
                destination: m,
            },
        ]),
    ]
}

fn status_error_envelope(error: StatusFailure) -> Envelope<()> {
    match error {
        StatusFailure::WindowUnreadable(e) => Envelope::err_raw(
            e.submission_code(),
            format!("the spending-window file could not be read: {e}"),
        ),
        StatusFailure::ReceiptStoreOpen { detail } => {
            Envelope::err_raw("submission.record_unavailable", detail)
        }
        StatusFailure::ApprovalDirUnavailable(e) => {
            Envelope::err_raw("submission.record_unavailable", e.to_string())
        }
        StatusFailure::ReceiptStoreRead(e) => Envelope::err_raw(
            "submission.record_unavailable",
            format!("the submission receipt store could not be read: {e}"),
        ),
        StatusFailure::ClockUnavailable(e) => {
            Envelope::err_raw("wallet.clock_error", e.to_string())
        }
        StatusFailure::ReconcileRefused(e) => Envelope::err_raw(e.submission_code(), e.to_string()),
        StatusFailure::RepairRefused(e) => Envelope::err(&e),
        StatusFailure::ChainQueryFailed(e) => Envelope::err(&WalletError::Network(e)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, reason = "test assertions")]

    const HASH: &str = "abababababababababababababababababababababababababababababababab";

    fn parse(extra: &[&str]) -> Result<super::StatusArgs, clap::Error> {
        use clap::Parser as _;
        let argv = ["stellar-agent", "tx", "status", HASH].iter().chain(extra);
        let crate::Commands::Tx(tx) = crate::Cli::try_parse_from(argv)?.command else {
            panic!("tx command")
        };
        let crate::commands::tx::TxSubcommand::Status(args) = tx.subcommand else {
            panic!("status subcommand")
        };
        Ok(args)
    }

    /// The real parser defaults the flag to false and forwards it into the
    /// library request; the payload is the shared recovery projection.
    #[test]
    #[serial_test::serial]
    fn status_recovery_result_and_retry_flag() {
        use stellar_agent_network::policy_state::{
            PersistedWindowStore, RecoveryRefusal, RecoveryReport,
        };
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().expect("sandbox");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
            "svc", "acct", "n-svc", "n-acct",
        )
        .with_noop_engine()
        .build();
        let window = PersistedWindowStore::for_profile("status-flag");
        let client =
            stellar_agent_network::StellarRpcClient::new("http://127.0.0.1:1").expect("client");
        for (extra, expected) in [(&[][..], false), (&["--retry-recovery"][..], true)] {
            let args = parse(extra).expect("parse");
            assert_eq!(args.retry_recovery, expected);
            let request = super::status_request(&args, &profile, "p", &window, &client, None);
            assert_eq!(request.retry_recovery, expected);
        }
        assert!(parse(&["--retry-recovery=true"]).is_err());
        let args = parse(&[]).expect("parse");
        let mut recovery = RecoveryReport::default();
        let outcome = |recovery| stellar_agent_network::submission_flow::StatusOutcome {
            recovery,
            chain_status: "UNKNOWN".to_owned(),
            ledger: None,
            record: None,
            reservation: None,
            reservation_open: false,
        };
        let value = serde_json::to_value(super::status_data(&args, outcome(recovery.clone())))
            .expect("payload");
        assert!(value.get("recovery").is_none(), "unmanaged: {value}");
        recovery.refusal = Some(RecoveryRefusal {
            code: "submission.record_unavailable",
            state_unavailable: true,
        });
        let value = serde_json::to_value(super::status_data(&args, outcome(recovery.clone())))
            .expect("payload");
        assert_eq!(value["chain_status"], "UNKNOWN");
        assert_eq!(value["recovery"], recovery.status_json().expect("refusal"));
        assert_eq!(
            value["recovery"]["refusal"],
            serde_json::json!({"code": "submission.record_unavailable", "state_unavailable": true})
        );
    }

    /// The real `tx status` handler and the real MCP tool on one managed
    /// mainnet attempt that recovery stopped: the default replays the stop
    /// with no request, the explicit flag starts one bounded run, nothing is
    /// sent, the MCP gate refuses another chain, and both surfaces render the
    /// same recovery object.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_handlers_forward_retry_on_a_managed_attempt() {
        use crate::commands::pay::tests::mainnet_full as pay;
        use crate::common::mainnet_write_fixture::{
            AGENT_SEED, DESTINATION, ISSUER, ORACLE_HOST, PRIMARY_HOST, Spec, pay_rule,
        };
        use crate::test_rpc::{ClassicRpc, last_rendered};
        use stellar_agent_core::envelope::OutputFormat;

        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        let endpoints = [
            ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]),
            ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]),
        ];
        let status_rule = "[[rules]]\nmatch = { tool = \"stellar_transaction_status\", \
                           chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n";
        let fixture = Spec::new("status-retry-handlers")
            .rules(vec![
                pay_rule("require_approval", ""),
                status_rule.to_owned(),
            ])
            .primary(endpoints[0].clone())
            .oracle(endpoints[1].clone())
            .build()
            .await;
        let paid = pay::run(&fixture, &pay::mainnet_args(&fixture)).await;
        assert_eq!(paid.code, 0, "{}", paid.envelope);
        let tx_hash = paid.envelope["data"]["tx_hash"]
            .as_str()
            .expect("hash")
            .to_owned();
        let record = |fixture: &crate::common::mainnet_write_fixture::MainnetFixture| {
            fixture.window_body()["operations"]["records"][0].clone()
        };
        assert_eq!(record(&fixture)["state"], "sent_outcome_unknown");
        let max_time =
            record(&fixture)["attempts"][0]["exposure"]["identity"]["classic"]["max_time"]
                .as_u64()
                .expect("max time");
        let due_ms = (max_time + 6) * 1_000;
        let system_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(due_ms + 1_000);
        for endpoint in &endpoints {
            endpoint.close_health_ahead(due_ms / 1_000 + 1 - system_secs);
        }
        let cli = |retry_recovery| {
            let tx_hash = tx_hash.clone();
            async move {
                crate::common::render::take_rendered_for_test();
                let code = super::run(&super::StatusArgs {
                    tx_hash,
                    profile: Some(fixture.name.to_owned()),
                    output: OutputFormat::Json,
                    retry_recovery,
                })
                .await;
                (code, last_rendered())
            }
        };
        let server =
            stellar_agent_mcp::server::WalletServer::new_with_selection_and_routes_for_test(
                fixture.profile(),
                stellar_agent_core::profile::name::ProfileNameSource::Flag,
                &stellar_agent_core::profile::schema::default_profile_dir().expect("profile dir"),
                &[
                    (PRIMARY_HOST, &fixture.primary.uri()),
                    (ORACLE_HOST, &fixture.oracle.uri()),
                ],
            )
            .expect("server");
        let mcp = |chain_id: &str, retry_recovery| {
            let args = stellar_agent_mcp::server::StellarTransactionStatusArgs {
                chain_id: chain_id.to_owned(),
                tx_hash: tx_hash.clone(),
                retry_recovery,
            };
            let server = &server;
            async move {
                server
                    .call_stellar_transaction_status(args)
                    .await
                    .map(|result| {
                        let text = result.content[0].as_text().expect("text").text.clone();
                        serde_json::from_str::<serde_json::Value>(&text).expect("envelope")
                    })
            }
        };
        let run_of = |fixture: &crate::common::mainnet_write_fixture::MainnetFixture| {
            record(fixture)["attempts"][0]["recovery_run"].clone()
        };

        // The first status at the due time runs recovery once and stops it.
        let (code, first) = cli(false).await;
        assert_eq!(code, 0, "{first}");
        let stopped = run_of(&fixture);
        assert_eq!(stopped["phase"], "stopped", "{stopped}");
        assert_eq!(stopped["automatic_runs"], 1, "{stopped}");
        let methods = fixture.primary_methods().await.len();
        let sends = fixture.sent_envelopes().await.len();

        // The default replays the stop on both surfaces without a request.
        let (code, cli_default) = cli(false).await;
        assert_eq!(code, 0, "{cli_default}");
        let mcp_default = mcp("stellar:mainnet", false).await.expect("tool result");
        assert_eq!(mcp_default["ok"], true, "{mcp_default}");
        assert_eq!(fixture.primary_methods().await.len(), methods);
        assert_eq!(run_of(&fixture), stopped);
        let recovery = &cli_default["data"]["recovery"];
        assert_eq!(
            recovery["attempts"][0]["tx_hash"],
            tx_hash.as_str(),
            "{recovery}"
        );
        assert_eq!(recovery["attempts"][0]["reservations"], 1, "{recovery}");
        assert_eq!(recovery["attempts"][0]["next_action"], "Wait", "{recovery}");
        assert_eq!(*recovery, mcp_default["data"]["recovery"]);
        assert_eq!(cli_default["data"]["chain_status"], "UNKNOWN");
        assert_eq!(mcp_default["data"]["chain_status"], "UNKNOWN");

        // The MCP gate refuses another chain before any recovery work.
        let gated = mcp("stellar:testnet", true)
            .await
            .expect_err("the gate refuses");
        assert!(gated.message.contains("chain_id mismatch"), "{gated:?}");
        assert_eq!(fixture.primary_methods().await.len(), methods);
        assert_eq!(run_of(&fixture), stopped);

        // The explicit flag starts one bounded run on each surface.
        for surface in ["cli", "mcp"] {
            let before = fixture.primary_methods().await;
            let explicit = if surface == "cli" {
                let (code, envelope) = cli(true).await;
                assert_eq!(code, 0, "{envelope}");
                envelope
            } else {
                mcp("stellar:mainnet", true).await.expect("tool result")
            };
            let sent = fixture.primary_methods().await[before.len()..].to_vec();
            let count = |name: &str| sent.iter().filter(|method| *method == name).count();
            assert_eq!(count("getTransaction"), 1, "{surface}: {sent:?} {explicit}");
            assert!(sent.len() <= 2 + 24, "{surface}: {sent:?}");
            let run = run_of(&fixture);
            assert_eq!(
                (&run["automatic_runs"], &run["consecutive_stops"]),
                (&serde_json::json!(1), &serde_json::json!(1)),
                "{surface}: {run}"
            );
            let recovery = &explicit["data"]["recovery"];
            assert_eq!(
                recovery["attempts"][0]["reservations"], 1,
                "{surface}: {recovery}"
            );
            assert_eq!(
                recovery["refusal"]["code"], "recovery.needs_evidence",
                "{surface}: {recovery}"
            );
        }
        assert_eq!(
            fixture.sent_envelopes().await.len(),
            sends,
            "no transaction is sent"
        );
    }

    #[test]
    fn status_help_names_recovery_retry() {
        let help = parse(&["--help"]).expect_err("help").to_string();
        for phrase in [
            "--retry-recovery",
            "Start one new bounded recovery run",
            "never sends a transaction",
            "`recovery` reports the typed recovery result",
            "it never resubmits",
        ] {
            assert!(help.contains(phrase), "{phrase}: {help}");
        }
    }

    #[test]
    fn receipt_views_show_every_destination() {
        use stellar_agent_core::profile::receipt::{PaymentDestinations, ReceiptStore};
        for destinations in super::destination_shapes() {
            let dir = tempfile::tempdir().expect("directory");
            let store = ReceiptStore::open_at(dir.path(), "view").expect("receipt store");
            store
                .try_begin_to("a", "b", "", 1, 0, 1, &destinations)
                .expect("claim");
            let receipt = store.get("a").expect("read").expect("receipt");
            let value = serde_json::to_value(super::record_view(&receipt, false)).expect("view");
            match destinations {
                PaymentDestinations::None => {
                    assert!(value.get("destination").is_none());
                    assert!(value.get("destinations").is_none());
                }
                PaymentDestinations::Single(destination) => {
                    assert_eq!(value["destination"], destination);
                    assert!(value.get("destinations").is_none());
                }
                PaymentDestinations::PerOperation(entries) => {
                    assert_eq!(value["destinations"], serde_json::json!(entries));
                    assert!(value.get("destination").is_none());
                }
            }
        }
    }
}

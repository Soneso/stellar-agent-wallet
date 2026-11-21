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
//! # Mainnet enablement
//!
//! On mainnet the steps above run only after the enablement verifies, with
//! clients built from the profile whose primary and oracle hosts the signed
//! policy binds. When the signed policy has a `[mainnet]` table and the
//! enablement does not verify, the verb refuses with
//! `profile.mainnet_enablement_invalid` before any client is built. When the
//! owner key or the signed policy does not load and the installation holds an
//! enablement nonce, or its nonce entry is unreadable, the verb refuses with
//! that load's code before any client is built. A profile without an
//! enablement record, because its verified policy has no `[mainnet]` table
//! or its installation holds no enablement nonce, runs no reconciliation,
//! recovery or release, and `--retry-recovery` has no effect. Its answer
//! comes from the stored state and the primary endpoint's lookup.
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
//! # Selectors
//!
//! `HASH`, `--business-id`, or both select the submission. Neither refuses
//! with `validation.usage_error`. On mainnet the selectors resolve from the
//! authenticated window before recovery: both must name one operation, an
//! unknown business id refuses with `operation.unknown`, and a business id
//! alone targets the operation's latest exposed classic hash, or reads no
//! network when it has none. `operation` projects the stored state,
//! attempts, last transition, bucket hold, awaiting approval and result, or
//! is null for a hash no operation exposed. On testnet a business id is
//! checked and echoed, since testnet keeps no operation records.
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
use stellar_agent_network::policy_state::{
    BusinessId, OperationProjection, PersistedWindowStore, StatusSelectors,
};
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
    /// carries. Optional when `--business-id` is given.
    #[arg(value_name = "HASH")]
    pub tx_hash: Option<String>,

    /// Business id of the mainnet operation to report. With HASH, both must
    /// name the same operation. On testnet it is checked and echoed only.
    #[arg(long = "business-id", value_name = "ID")]
    pub business_id: Option<String>,

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
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
struct StatusData {
    /// The transaction hash that was reconciled; absent when a business id
    /// names an operation with no exposed hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    /// The business id the call named.
    #[serde(skip_serializing_if = "Option::is_none")]
    business_id: Option<BusinessId>,
    /// What the endpoint reported (`SUCCESS`, `FAILED` or `NOT_FOUND`); for a
    /// managed mainnet attempt, the cached recovery result or `UNKNOWN`.
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_status: Option<String>,
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
    /// The stored mainnet operation the selectors name; null otherwise.
    operation: Option<OperationProjection>,
}

/// Runs `tx status`.
///
/// Returns an exit code: `0` on success, `1` on any error.
pub async fn run(args: &StatusArgs) -> i32 {
    if args
        .tx_hash
        .as_deref()
        .is_some_and(|hash| !is_tx_hash(hash))
    {
        render_json(&Envelope::<()>::err_raw(
            "validation.address_invalid",
            "HASH must be 64 lowercase hex characters",
        ));
        return 1;
    }
    let selectors =
        match StatusSelectors::parse(args.tx_hash.as_deref(), args.business_id.as_deref()) {
            Ok(selectors) => selectors,
            Err(e) => {
                render_json(&Envelope::<()>::err(&e));
                return 1;
            }
        };

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
    if !profile.chain_id.is_mainnet()
        && let (None, Some(business_id)) = (&selectors.tx_hash, &selectors.business_id)
    {
        render_json(&Envelope::ok(serde_json::json!({
            "business_id": business_id,
            "operation": null,
            "chain": null,
            "receipt": null,
            "reservation": null,
        })));
        return 0;
    }

    if let Err(e) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let window = PersistedWindowStore::for_profile(&resolved.name);
    // On mainnet only a verified enablement settles: the record binds the
    // primary and oracle hosts the clients below are built from. A profile
    // without a record answers from the stored state and the primary.
    let settle = if profile.chain_id.is_mainnet() {
        match crate::commands::policy_engine::settlement_enablement(
            "tx status",
            &resolved,
            &profile,
            window.path(),
        ) {
            Ok(record) => record.is_some(),
            Err(refusal) => {
                render_json(&refusal);
                return 1;
            }
        }
    } else {
        true
    };
    let target = match submission_flow::select_status(&profile, &window, &selectors) {
        Ok(target) => target,
        Err(error) => {
            render_json(&status_error_envelope(error));
            return 1;
        }
    };
    let data = match target.tx_hash.as_deref() {
        Some(tx_hash) => {
            match hash_status(
                args,
                tx_hash,
                &profile,
                &resolved.name,
                origin,
                &window,
                settle,
            )
            .await
            {
                Ok(data) => data,
                Err(code) => return code,
            }
        }
        None => StatusData::default(),
    };
    match submission_flow::operation_projection(&profile, &window, &target) {
        Ok(operation) => {
            render_json(&Envelope::ok(StatusData {
                business_id: selectors.business_id,
                operation,
                ..data
            }));
            0
        }
        Err(error) => {
            render_json(&status_error_envelope(error));
            1
        }
    }
}

/// Reconciles `tx_hash` into its hash view, or renders the refusal and
/// returns its exit code. Without `settle` the lookup runs no
/// reconciliation, recovery stage, or release.
async fn hash_status(
    args: &StatusArgs,
    tx_hash: &str,
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    origin: stellar_agent_core::profile::loader::ProfileOrigin,
    window: &PersistedWindowStore,
    settle: bool,
) -> Result<StatusData, i32> {
    let context = crate::common::network::profile_network_context(profile);
    let client = match context.primary_client() {
        Ok(c) => c,
        Err(e) => {
            // An unreadable window file refuses before a client failure, as
            // the window is read first.
            if let Err(error) = window.pending_reservations(profile) {
                render_json(&status_error_envelope(StatusFailure::WindowUnreadable(
                    error,
                )));
            } else {
                render_json(&Envelope::<()>::err(&e));
            }
            return Err(1);
        }
    };

    let writer = || {
        crate::commands::submission_record::accounting_audit_writer(profile, profile_name, origin)
    };
    let approval_dir = stellar_agent_core::profile::schema::default_approval_dir;
    let outcome = if settle {
        let oracle = crate::commands::submission_record::settlement_oracle_in(profile, &context);
        let request = status_request(
            args,
            tx_hash,
            profile,
            profile_name,
            window,
            &client,
            oracle.as_ref(),
        );
        submission_flow::transaction_status(request, approval_dir, writer).await
    } else {
        let request = status_request(args, tx_hash, profile, profile_name, window, &client, None);
        submission_flow::transaction_status_unsettled(request, approval_dir, writer).await
    }
    .map_err(|error| {
        render_json(&status_error_envelope(error));
        1
    })?;
    Ok(status_data(tx_hash, outcome))
}

fn status_request<'a>(
    args: &'a StatusArgs,
    tx_hash: &'a str,
    profile: &'a stellar_agent_core::profile::schema::Profile,
    profile_name: &'a str,
    window: &'a PersistedWindowStore,
    client: &'a stellar_agent_network::StellarRpcClient,
    oracle: Option<&'a stellar_agent_network::StellarRpcClient>,
) -> StatusRequest<'a> {
    StatusRequest {
        profile,
        profile_name,
        tx_hash,
        window,
        client,
        oracle,
        retry_recovery: args.retry_recovery,
    }
}

fn status_data(tx_hash: &str, outcome: submission_flow::StatusOutcome) -> StatusData {
    StatusData {
        tx_hash: Some(tx_hash.to_owned()),
        record: outcome
            .record
            .as_ref()
            .map(|settled| record_view(settled, outcome.reservation_open)),
        recovery: outcome.recovery.status_json(),
        chain_status: Some(outcome.chain_status),
        ledger: outcome.ledger,
        reservation: outcome.reservation.map(|r| ReservationView {
            envelope_hash: r.id,
            operator_required: r.operator_required,
        }),
        ..StatusData::default()
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
        StatusFailure::SelectorRefused(e) => Envelope::err(&e),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, reason = "test assertions")]

    const HASH: &str = "abababababababababababababababababababababababababababababababab";

    #[test]
    fn status_progress_refusal_contract() {
        use stellar_agent_network::policy_state::WindowStoreError;
        use stellar_agent_network::submission_flow::StatusFailure;
        for error in [
            WindowStoreError::ChainMismatch,
            WindowStoreError::Invalid {
                detail: "unreadable: 状態".to_owned(),
            },
        ] {
            let code = error.submission_code();
            let value = serde_json::to_value(super::status_error_envelope(
                StatusFailure::WindowUnreadable(error),
            ))
            .expect("envelope");
            assert_eq!(
                value["error"]["code"], code,
                "typed progress read code crosses CLI"
            );
            assert!(value.get("progress").is_none());
        }
    }

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
            let request = super::status_request(&args, HASH, &profile, "p", &window, &client, None);
            assert_eq!(request.retry_recovery, expected);
        }
        assert!(parse(&["--retry-recovery=true"]).is_err());
        let mut recovery = RecoveryReport::default();
        let outcome = |recovery| stellar_agent_network::submission_flow::StatusOutcome {
            recovery,
            progress: None,
            chain_status: "UNKNOWN".to_owned(),
            ledger: None,
            record: None,
            reservation: None,
            reservation_open: false,
        };
        let value = serde_json::to_value(super::status_data(HASH, outcome(recovery.clone())))
            .expect("payload");
        assert!(value.get("recovery").is_none(), "unmanaged: {value}");
        recovery.refusal = Some(RecoveryRefusal {
            code: "submission.record_unavailable",
            state_unavailable: true,
        });
        let value = serde_json::to_value(super::status_data(HASH, outcome(recovery.clone())))
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
    #[serial_test::serial(mainnet_clock)]
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
                    tx_hash: Some(tx_hash),
                    business_id: None,
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
                tx_hash: Some(tx_hash.clone()),
                business_id: None,
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

    /// Runs `tx status` and `stellar_transaction_status` with the same
    /// selectors and returns the CLI exit code with its envelope, then the
    /// MCP error flag with its envelope.
    #[cfg(feature = "mainnet-write")]
    async fn both_surfaces(
        fixture: &crate::common::mainnet_write_fixture::MainnetFixture,
        tx_hash: Option<&str>,
        business_id: Option<&str>,
    ) -> ((i32, serde_json::Value), (bool, serde_json::Value)) {
        use crate::common::mainnet_write_fixture::{ORACLE_HOST, PRIMARY_HOST};
        crate::common::render::take_rendered_for_test();
        let code = super::run(&super::StatusArgs {
            tx_hash: tx_hash.map(str::to_owned),
            business_id: business_id.map(str::to_owned),
            profile: Some(fixture.name.to_owned()),
            output: stellar_agent_core::envelope::OutputFormat::Json,
            retry_recovery: false,
        })
        .await;
        let cli = (code, crate::test_rpc::last_rendered());
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
        let result = server
            .call_stellar_transaction_status(
                stellar_agent_mcp::server::StellarTransactionStatusArgs {
                    chain_id: fixture.profile().chain_id.to_string(),
                    tx_hash: tx_hash.map(str::to_owned),
                    business_id: business_id.map(str::to_owned),
                    retry_recovery: false,
                },
            )
            .await
            .expect("tool result");
        let text = &result.content[0].as_text().expect("text").text;
        let mcp = (
            result.is_error == Some(true),
            serde_json::from_str(text).expect("envelope"),
        );
        (cli, mcp)
    }

    /// On testnet a business id is checked and echoed with the fixed null
    /// keys, with no request and no window file; a hash keeps its lookup and
    /// adds `operation: null`; both surfaces refuse the same malformed or
    /// missing selectors with the same code.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_selector_matrix_testnet() {
        use crate::common::mainnet_write_fixture::{DESTINATION, ISSUER, Spec, pay_rule};
        use crate::test_rpc::ClassicRpc;
        let status_rule = "[[rules]]\nmatch = { tool = \"stellar_transaction_status\", \
                           chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n";
        let fixture = Spec::new("status-selectors-testnet")
            .testnet()
            .rules(vec![pay_rule("allow", ""), status_rule.to_owned()])
            .primary(ClassicRpc::testnet(&[DESTINATION, ISSUER]))
            .build()
            .await;
        let window = fixture.window_path().exists();
        let methods = fixture.primary_methods().await.len();
        let ((code, cli), (failed, mcp)) = both_surfaces(&fixture, None, Some("Order-7")).await;
        let echo = serde_json::json!({
            "business_id": "Order-7",
            "operation": null,
            "chain": null,
            "receipt": null,
            "reservation": null,
        });
        assert_eq!((code, &cli["data"]), (0, &echo), "{cli}");
        assert_eq!((failed, &mcp["data"]), (false, &echo), "{mcp}");
        assert_eq!(fixture.primary_methods().await.len(), methods, "no request");
        assert_eq!(fixture.window_path().exists(), window, "no storage");

        for (tx_hash, business_id, expected) in [
            (None, None, "validation.usage_error"),
            (None, Some("has space"), "validation.business_id_invalid"),
            (
                None,
                Some("\u{0}\u{1F600}"),
                "validation.business_id_invalid",
            ),
            (Some(&*"AB".repeat(32)), None, "validation.address_invalid"),
        ] {
            let ((code, cli), (failed, mcp)) = both_surfaces(&fixture, tx_hash, business_id).await;
            assert_eq!(
                (code, &cli["error"]["code"]),
                (1, &serde_json::json!(expected))
            );
            assert_eq!(
                (failed, &mcp["error"]["code"]),
                (true, &serde_json::json!(expected))
            );
        }

        let hash = "ab".repeat(32);
        let ((code, cli), (failed, mcp)) =
            both_surfaces(&fixture, Some(&hash), Some("Order-7")).await;
        assert_eq!((code, failed), (0, false), "{cli} {mcp}");
        for view in [&cli["data"], &mcp["data"]] {
            assert_eq!(view["tx_hash"], hash.as_str(), "{view}");
            assert_eq!(view["business_id"], "Order-7", "{view}");
            assert!(
                view["chain_status"].is_string(),
                "the hash lookup ran: {view}"
            );
            assert_eq!(
                view.get("operation"),
                Some(&serde_json::Value::Null),
                "{view}"
            );
        }
    }

    /// On mainnet the selectors resolve before recovery. A business id
    /// alone, both selectors, and the hash alone report the same stored
    /// operation on both surfaces; the managed attempt's chain status comes
    /// from cached recovery evidence with no request. A mismatched hash and
    /// an unknown business id refuse typed; an unrecorded hash keeps its
    /// lookup and reports `operation: null`.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_selector_matrix_mainnet() {
        use crate::commands::pay::tests::mainnet_full as pay;
        use crate::common::mainnet_write_fixture::{
            AGENT_SEED, DESTINATION, ISSUER, Spec, pay_rule,
        };
        use crate::test_rpc::ClassicRpc;
        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        let status_rule = "[[rules]]\nmatch = { tool = \"stellar_transaction_status\", \
                           chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n";
        let fixture = Spec::new("status-selectors-mainnet")
            .rules(vec![
                pay_rule("require_approval", ""),
                status_rule.to_owned(),
            ])
            .primary(ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]))
            .oracle(ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]))
            .build()
            .await;
        let args = pay::mainnet_args(&fixture);
        let business_id = args.business_id.clone().expect("business id");
        let paid = pay::run(&fixture, &args).await;
        assert_eq!(paid.code, 0, "{}", paid.envelope);
        let tx_hash = paid.envelope["data"]["tx_hash"]
            .as_str()
            .expect("hash")
            .to_owned();
        let methods = fixture.primary_methods().await.len();
        let mut operations = Vec::new();
        for (hash, id) in [
            (None, Some(business_id.as_str())),
            (Some(tx_hash.as_str()), Some(business_id.as_str())),
            (Some(tx_hash.as_str()), None),
        ] {
            let ((code, cli), (failed, mcp)) = both_surfaces(&fixture, hash, id).await;
            assert_eq!((code, failed), (0, false), "{cli} {mcp}");
            assert_eq!(cli["data"]["operation"], mcp["data"]["operation"], "parity");
            for view in [&cli["data"], &mcp["data"]] {
                assert_eq!(view["tx_hash"], tx_hash.as_str(), "{view}");
                assert_eq!(view["chain_status"], "UNKNOWN", "cached evidence: {view}");
                assert_eq!(view.get("business_id").and_then(|v| v.as_str()), id);
            }
            operations.push(cli["data"]["operation"].clone());
        }
        assert_eq!(
            fixture.primary_methods().await.len(),
            methods,
            "a managed attempt sends no lookup for its hash"
        );
        let operation = &operations[0];
        assert!(operations.iter().all(|other| other == operation));
        assert_eq!(operation["business_id"], business_id.as_str());
        assert_eq!(operation["state"], "sent_outcome_unknown");
        assert_eq!(operation["compacted"], false);
        assert_eq!(operation["attempts"][0]["tx_hash"], tx_hash.as_str());
        assert_eq!(
            operation["attempts"][0]["auth_entry_sha256"],
            serde_json::Value::Null
        );
        assert_eq!(
            operation["hold"],
            serde_json::json!({"held": false}),
            "a criteria-free rule holds no bucket: {operation}"
        );

        let other = "cd".repeat(32);
        for (hash, id, expected) in [
            (
                Some(other.as_str()),
                Some(business_id.as_str()),
                "validation.usage_error",
            ),
            (None, Some("never-opened"), "operation.unknown"),
        ] {
            let ((code, cli), (failed, mcp)) = both_surfaces(&fixture, hash, id).await;
            assert_eq!(
                (code, &cli["error"]["code"]),
                (1, &serde_json::json!(expected))
            );
            assert_eq!(
                (failed, &mcp["error"]["code"]),
                (true, &serde_json::json!(expected))
            );
        }
        assert_eq!(
            fixture.primary_methods().await.len(),
            methods,
            "refusals read no network"
        );

        let ((code, cli), (failed, mcp)) = both_surfaces(&fixture, Some(&other), None).await;
        assert_eq!((code, failed), (0, false), "{cli} {mcp}");
        for view in [&cli["data"], &mcp["data"]] {
            assert_eq!(
                view.get("operation"),
                Some(&serde_json::Value::Null),
                "{view}"
            );
        }
        let sent = fixture.primary_methods().await[methods..].to_vec();
        assert_eq!(
            sent.iter()
                .filter(|method| *method == "getTransaction")
                .count(),
            2,
            "an unrecorded hash keeps one lookup per surface: {sent:?}"
        );
    }

    /// The envelope hash of the hold the settlement tests seed.
    #[cfg(feature = "mainnet-write")]
    const SEEDED_HOLD: &str = "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7";
    /// The transaction hash of the hold the settlement tests seed.
    #[cfg(feature = "mainnet-write")]
    const SEEDED_TX: &str = "b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8";

    /// A mainnet fixture whose policy allows the status tool, with an
    /// expired hold seeded, and `pre_enable` applied when `enabled` is false.
    #[cfg(feature = "mainnet-write")]
    async fn settlement_fixture(
        name: &'static str,
        enabled: bool,
    ) -> crate::common::mainnet_write_fixture::MainnetFixture {
        use crate::common::mainnet_write_fixture::{
            AGENT_SEED, DESTINATION, ISSUER, Spec, pay_rule,
        };
        use crate::test_rpc::ClassicRpc;
        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        let status_rule = "[[rules]]\nmatch = { tool = \"stellar_transaction_status\", \
                           chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n";
        let mut spec = Spec::new(name)
            .rules(vec![
                pay_rule("require_approval", ""),
                status_rule.to_owned(),
            ])
            .primary(ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]))
            .oracle(ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER]));
        if !enabled {
            spec = spec.pre_enable();
        }
        let fixture = spec.build().await;
        fixture.seed_expired_hold(SEEDED_HOLD, SEEDED_TX);
        fixture
    }

    /// The envelope hash of the second hold the restored half seeds.
    #[cfg(feature = "mainnet-write")]
    const SECOND_HOLD: &str = "c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9";
    /// The transaction hash of the second hold.
    #[cfg(feature = "mainnet-write")]
    const SECOND_TX: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

    /// Whether the stored window still holds the seeded reservation.
    #[cfg(feature = "mainnet-write")]
    fn holds_seeded(fixture: &crate::common::mainnet_write_fixture::MainnetFixture) -> bool {
        holds(fixture, SEEDED_HOLD)
    }

    /// Whether the stored window still holds the reservation `id`.
    #[cfg(feature = "mainnet-write")]
    fn holds(fixture: &crate::common::mainnet_write_fixture::MainnetFixture, id: &str) -> bool {
        super::PersistedWindowStore::for_profile(fixture.name)
            .pending_reservations(&fixture.profile())
            .expect("window")
            .iter()
            .any(|hold| hold.id == id)
    }

    /// The startup MCP server of `fixture`, routed to its endpoints.
    #[cfg(feature = "mainnet-write")]
    fn status_server(
        fixture: &crate::common::mainnet_write_fixture::MainnetFixture,
    ) -> stellar_agent_mcp::server::WalletServer {
        use crate::common::mainnet_write_fixture::{ORACLE_HOST, PRIMARY_HOST};
        stellar_agent_mcp::server::WalletServer::new_with_selection_and_routes_for_test(
            fixture.profile(),
            stellar_agent_core::profile::name::ProfileNameSource::Flag,
            &stellar_agent_core::profile::schema::default_profile_dir().expect("profile dir"),
            &[
                (PRIMARY_HOST, &fixture.primary.uri()),
                (ORACLE_HOST, &fixture.oracle.uri()),
            ],
        )
        .expect("server")
    }

    /// Runs `tx status` on the seeded hold.
    #[cfg(feature = "mainnet-write")]
    async fn cli_status(
        fixture: &crate::common::mainnet_write_fixture::MainnetFixture,
    ) -> (i32, serde_json::Value) {
        crate::common::render::take_rendered_for_test();
        let code = super::run(&super::StatusArgs {
            tx_hash: Some(SEEDED_TX.to_owned()),
            business_id: None,
            profile: Some(fixture.name.to_owned()),
            output: stellar_agent_core::envelope::OutputFormat::Json,
            retry_recovery: false,
        })
        .await;
        (code, crate::test_rpc::last_rendered())
    }

    /// Calls `stellar_transaction_status` on `tx_hash` and returns the error
    /// flag with the envelope.
    #[cfg(feature = "mainnet-write")]
    async fn mcp_status(
        server: &stellar_agent_mcp::server::WalletServer,
        tx_hash: &str,
    ) -> (bool, serde_json::Value) {
        let result = server
            .call_stellar_transaction_status(
                stellar_agent_mcp::server::StellarTransactionStatusArgs {
                    chain_id: "stellar:mainnet".to_owned(),
                    tx_hash: Some(tx_hash.to_owned()),
                    business_id: None,
                    retry_recovery: false,
                },
            )
            .await
            .expect("tool result");
        let text = &result.content[0].as_text().expect("text").text;
        (
            result.is_error == Some(true),
            serde_json::from_str(text).expect("envelope"),
        )
    }

    /// After the enablement, a stored `oracle_provider_url` moved to another
    /// host, and separately a moved `rpc_url`, refuse `tx status` with the
    /// enablement refusal and the running server's status tool with the
    /// freshness refusal. Neither endpoint receives a request, the expired
    /// hold stays, and no outcome row is written. With the URL put back,
    /// both surfaces settle the hold.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_refuses_a_moved_endpoint_before_any_settlement() {
        use crate::common::mainnet_write_fixture::{ORACLE_HOST, PRIMARY_HOST};
        for (name, binding) in [
            ("status-moved-oracle", "on_disk_oracle_host"),
            ("status-moved-primary", "on_disk_host"),
        ] {
            let fixture = settlement_fixture(name, true).await;
            let server = status_server(&fixture);
            let moved = |fixture: &crate::common::mainnet_write_fixture::MainnetFixture,
                         moved: bool| {
                match (binding, moved) {
                    ("on_disk_host", true) => {
                        fixture.set_stored_rpc_url("https://moved-primary.example.invalid");
                    }
                    ("on_disk_host", false) => {
                        fixture.set_stored_rpc_url(&format!("https://{PRIMARY_HOST}"));
                    }
                    (_, true) => {
                        fixture.set_stored_oracle_url("https://moved-oracle.example.invalid");
                    }
                    (_, false) => fixture.set_stored_oracle_url(&format!("https://{ORACLE_HOST}")),
                }
            };
            moved(&fixture, true);
            let primary = fixture.primary_methods().await.len();
            let oracle = fixture.oracle_methods().await.len();
            let audit = fixture.audit_row_count();

            let (code, cli) = cli_status(&fixture).await;
            assert_eq!(code, 1, "{binding}: {cli}");
            assert_eq!(
                cli["error"]["code"], "profile.mainnet_enablement_invalid",
                "{binding}: {cli}"
            );
            let message = cli["error"]["message"].as_str().expect("message");
            assert!(message.ends_with(binding), "{message}");
            let (failed, mcp) = mcp_status(&server, SEEDED_TX).await;
            assert!(failed, "{binding}: {mcp}");
            assert_eq!(
                mcp["error"]["code"], "network.mainnet_write_forbidden",
                "{binding}: {mcp}"
            );

            assert_eq!(fixture.primary_methods().await.len(), primary, "{binding}");
            assert_eq!(fixture.oracle_methods().await.len(), oracle, "{binding}");
            assert!(holds_seeded(&fixture), "{binding}: the hold stays");
            assert_eq!(
                fixture.audit_row_count(),
                audit,
                "{binding}: no outcome row"
            );

            moved(&fixture, false);
            let (code, cli) = cli_status(&fixture).await;
            assert_eq!(code, 0, "{binding} restored: {cli}");
            assert!(
                !holds_seeded(&fixture),
                "{binding} restored: the CLI lookup settles"
            );
            fixture.seed_expired_hold(SECOND_HOLD, SECOND_TX);
            let (failed, mcp) = mcp_status(&server, SECOND_TX).await;
            assert!(!failed, "{binding} restored: {mcp}");
            assert!(
                !holds(&fixture, SECOND_HOLD),
                "{binding} restored: the MCP lookup settles"
            );
        }
    }

    /// A mainnet profile whose signed policy has no `[mainnet]` table holds
    /// no enablement record: `tx status` and the status tool run no
    /// settlement step. The expired hold stays pending, the oracle is not
    /// asked, no outcome row is written, and both answers still come back
    /// from the stored state and the primary's lookup.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_without_an_enablement_record_settles_nothing() {
        let fixture = settlement_fixture("status-no-record", false).await;
        let server = status_server(&fixture);
        let oracle = fixture.oracle_methods().await.len();
        let audit = fixture.audit_row_count();

        let (code, cli) = cli_status(&fixture).await;
        let (failed, mcp) = mcp_status(&server, SEEDED_TX).await;

        assert_eq!(code, 0, "{cli}");
        assert!(!failed, "{mcp}");
        for view in [&cli["data"], &mcp["data"]] {
            assert_eq!(view["tx_hash"], SEEDED_TX, "{view}");
            assert_eq!(view["record"]["status"], "pending", "{view}");
            assert_eq!(view["record"]["reservation_open"], true, "{view}");
            assert!(view["chain_status"].is_string(), "{view}");
        }
        assert!(holds_seeded(&fixture), "the hold stays pending");
        assert_eq!(
            fixture.oracle_methods().await.len(),
            oracle,
            "no oracle request"
        );
        assert_eq!(fixture.audit_row_count(), audit, "no outcome row");
        let asked = fixture.primary_methods().await;
        assert!(
            asked.iter().any(|method| method == "getTransaction"),
            "the answer comes from the primary's lookup: {asked:?}"
        );
    }

    /// Breaks the owner key of `fixture` when `owner_removed` is set, and
    /// otherwise flips one digit of its policy signature.
    #[cfg(feature = "mainnet-write")]
    fn break_policy_load(
        fixture: &crate::common::mainnet_write_fixture::MainnetFixture,
        owner_removed: bool,
    ) {
        if owner_removed {
            fixture.delete_keyring_entry(&fixture.profile().policy_owner_key_id);
        } else {
            fixture.tamper_policy_signature();
        }
    }

    /// On an enabled profile, a signed policy that no longer verifies, and
    /// separately a missing owner key, refuse `tx status` with that load's
    /// own code before any client is built. Neither endpoint receives a
    /// request, the expired hold stays, and no outcome row is written.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_refuses_an_unloadable_policy_or_owner_key_with_its_load_code() {
        for (name, owner_removed, load_code) in [
            (
                "status-tampered-policy",
                false,
                "policy.owner_signature_invalid",
            ),
            ("status-no-owner", true, "policy.engine_unavailable"),
        ] {
            let fixture = settlement_fixture(name, true).await;
            break_policy_load(&fixture, owner_removed);
            let primary = fixture.primary_methods().await.len();
            let oracle = fixture.oracle_methods().await.len();
            let audit = fixture.audit_row_count();

            let (code, cli) = cli_status(&fixture).await;

            assert_eq!(code, 1, "{name}: {cli}");
            assert_eq!(cli["error"]["code"], load_code, "{name}: {cli}");
            assert_eq!(fixture.primary_methods().await.len(), primary, "{name}");
            assert_eq!(fixture.oracle_methods().await.len(), oracle, "{name}");
            assert!(holds_seeded(&fixture), "{name}: the hold stays");
            assert_eq!(fixture.audit_row_count(), audit, "{name}: no outcome row");
        }
    }

    /// On an installation that holds no enablement nonce, a signed policy
    /// that no longer verifies, and separately a missing owner key, leave the
    /// profile without an enablement record: `tx status` answers from the
    /// stored state and the primary's lookup and settles nothing.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_of_an_unloadable_policy_without_an_enablement_nonce_settles_nothing() {
        for (name, owner_removed) in [
            ("status-no-nonce-tampered", false),
            ("status-no-nonce-no-owner", true),
        ] {
            let fixture = settlement_fixture(name, false).await;
            break_policy_load(&fixture, owner_removed);
            let oracle = fixture.oracle_methods().await.len();
            let audit = fixture.audit_row_count();

            let (code, cli) = cli_status(&fixture).await;

            assert_eq!(code, 0, "{name}: {cli}");
            assert_eq!(cli["data"]["record"]["status"], "pending", "{name}: {cli}");
            assert!(holds_seeded(&fixture), "{name}: the hold stays pending");
            assert_eq!(fixture.oracle_methods().await.len(), oracle, "{name}");
            assert_eq!(fixture.audit_row_count(), audit, "{name}: no outcome row");
            let asked = fixture.primary_methods().await;
            assert!(
                asked.iter().any(|method| method == "getTransaction"),
                "{name}: the answer comes from the primary's lookup: {asked:?}"
            );
        }
    }

    /// An unreadable enablement nonce entry does not show that the
    /// installation was never enabled: a signed policy that no longer
    /// verifies refuses `tx status` with that load's code before any client
    /// is built, and the expired hold stays.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn status_of_an_unloadable_policy_with_an_unreadable_nonce_refuses() {
        let fixture = settlement_fixture("status-unreadable-nonce", false).await;
        break_policy_load(&fixture, false);
        let nonce = stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
            &fixture.profile().policy_window_state_key_id,
        );
        stellar_agent_test_support::keyring_mock::inject_error(
            &nonce.service,
            &nonce.account,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("locked"))),
        )
        .expect("inject");
        let primary = fixture.primary_methods().await.len();
        let oracle = fixture.oracle_methods().await.len();
        let audit = fixture.audit_row_count();

        let (code, cli) = cli_status(&fixture).await;

        assert_eq!(code, 1, "{cli}");
        assert_eq!(
            cli["error"]["code"], "policy.owner_signature_invalid",
            "{cli}"
        );
        assert_eq!(fixture.primary_methods().await.len(), primary);
        assert_eq!(fixture.oracle_methods().await.len(), oracle);
        assert!(holds_seeded(&fixture), "the hold stays");
        assert_eq!(fixture.audit_row_count(), audit, "no outcome row");
    }

    /// A testnet fixture whose policy allows the status tool, with an expired
    /// hold seeded under `SEEDED_HOLD`.
    #[cfg(feature = "mainnet-write")]
    async fn testnet_settlement_fixture(
        name: &'static str,
    ) -> crate::common::mainnet_write_fixture::MainnetFixture {
        use crate::common::mainnet_write_fixture::{
            AGENT_SEED, DESTINATION, ISSUER, Spec, pay_rule,
        };
        use crate::test_rpc::ClassicRpc;
        let agent = stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
        let status_rule = "[[rules]]\nmatch = { tool = \"stellar_transaction_status\", \
                           chain = \"stellar:mainnet\" }\ncriteria = []\ndecision = \"allow\"\n";
        let fixture = Spec::new(name)
            .testnet()
            .rules(vec![
                pay_rule("require_approval", ""),
                status_rule.to_owned(),
            ])
            .primary(ClassicRpc::testnet(&[&agent, DESTINATION, ISSUER]))
            .build()
            .await;
        fixture.seed_expired_hold(SEEDED_HOLD, SEEDED_TX);
        fixture
    }

    /// On testnet `tx status` needs no enablement: its reconciliation ends
    /// the expired hold.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn testnet_status_settles_without_an_enablement() {
        let fixture = testnet_settlement_fixture("status-testnet-cli").await;

        let (code, cli) = cli_status(&fixture).await;

        assert_eq!(code, 0, "{cli}");
        assert!(!holds_seeded(&fixture), "the reconciliation ends the hold");
    }

    /// On testnet the status tool needs no enablement: its reconciliation
    /// ends the expired hold.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn testnet_status_tool_settles_without_an_enablement() {
        let fixture = testnet_settlement_fixture("status-testnet-mcp").await;
        let server = status_server(&fixture);

        let result = server
            .call_stellar_transaction_status(
                stellar_agent_mcp::server::StellarTransactionStatusArgs {
                    chain_id: "stellar:testnet".to_owned(),
                    tx_hash: Some(SEEDED_TX.to_owned()),
                    business_id: None,
                    retry_recovery: false,
                },
            )
            .await
            .expect("tool result");

        assert_ne!(result.is_error, Some(true), "{result:?}");
        assert!(!holds_seeded(&fixture), "the reconciliation ends the hold");
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
            "--business-id",
            "both must name the same operation",
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

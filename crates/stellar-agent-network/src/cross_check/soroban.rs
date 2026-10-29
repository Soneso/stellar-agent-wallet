//! Comparison of an oracle's simulation with the primary's for one unsigned
//! Soroban transaction.
//!
//! The oracle simulates the envelope the primary simulated. Its answer is
//! compared, never signed, and never used in place of the primary's: the
//! nonce and the resource data a payment carries come from the primary. The
//! oracle's error text is read for its presence only and never rendered.

use super::{SorobanWitnessInputs, inputs::invalid_observation, unavailable};
use stellar_agent_core::{
    cross_check::{WitnessEntry, WitnessField},
    error::{NetworkError, WalletError, WitnessUnavailableReason as Reason},
};
use stellar_rpc_client::SimulateTransactionResponse;
use stellar_xdr::{ScVal, SorobanAuthorizationEntry, SorobanCredentials};

/// Ledgers the oracle's simulation ledger may trail the primary's.
///
/// Load-balanced backends of one provider differ by one ledger; two
/// providers polled a moment apart differ by one or two more. An oracle
/// further behind cannot vouch for the ledger the primary reports, the
/// ledger the signature expiration derives from.
const MAX_ORACLE_LAG_LEDGERS: u32 = 2;

/// The primary's authorization entries, decoded once.
pub(super) struct Primary {
    /// The authorization entries of the primary's single result, in order.
    pub(super) auth: Vec<SorobanAuthorizationEntry>,
}

impl Primary {
    /// Decodes the primary's answer, which holds exactly one result.
    ///
    /// # Errors
    /// An invalid-observation error when the answer does not decode or does
    /// not hold exactly one result: the caller's flow checks both before it
    /// asks for the witness.
    pub(super) fn decode(inputs: &SorobanWitnessInputs<'_>) -> Result<Self, WalletError> {
        let results = inputs
            .primary
            .results()
            .map_err(|_| invalid_observation())?;
        let [result] = <[_; 1]>::try_from(results).map_err(|_| invalid_observation())?;
        Ok(Self { auth: result.auth })
    }
}

fn divergence(field: WitnessField) -> WalletError {
    NetworkError::WitnessDivergence {
        entry: WitnessEntry::SorobanSimulation,
        field,
        sequence_delta: None,
    }
    .into()
}

/// Compares the oracle's answer with the primary's, in a fixed order, and
/// refuses at the first disagreement.
///
/// 1. The answer carries no error and no restore preamble.
/// 2. It decodes to exactly one result with as many authorization entries as
///    the primary's result.
/// 3. Entry by entry, both carry `Address` credentials for the same address,
///    the oracle's signature is `Void`, and the root invocations are equal.
///    The nonce and the signature expiration ledger are not compared.
/// 4. Its minimum resource fee lies in `1..=resource_fee_ceiling`.
/// 5. Its ledger trails the primary's by at most two ledgers. An oracle ahead
///    of the primary is bounded by check 6 alone: a retried answer arrives
///    several ledgers after the primary's simulation.
/// 6. Its ledger lies before the signature expiration ledger.
///
/// Checks 5 and 6 are [`compare_ledger`].
///
/// # Errors
/// `simulation.divergence` naming the Soroban simulation and the field of the
/// failed check; `network.witness_unavailable` with `InvalidAnswer` for an
/// answer whose results do not decode.
pub(super) fn compare(
    primary: &Primary,
    inputs: &SorobanWitnessInputs<'_>,
    oracle: &SimulateTransactionResponse,
    authority: &str,
) -> Result<(), WalletError> {
    use WitnessField as F;
    if oracle.error.is_some() || oracle.restore_preamble.is_some() {
        return Err(divergence(F::SimulationResult));
    }
    let results = oracle.results().map_err(|_| {
        unavailable(Reason::InvalidAnswer {
            authority: authority.to_owned(),
        })
    })?;
    let [result] = results.as_slice() else {
        return Err(divergence(F::AuthorizationCount));
    };
    if result.auth.len() != primary.auth.len() {
        return Err(divergence(F::AuthorizationCount));
    }
    for (ours, theirs) in primary.auth.iter().zip(&result.auth) {
        let (
            SorobanCredentials::Address(ours_credentials),
            SorobanCredentials::Address(theirs_credentials),
        ) = (&ours.credentials, &theirs.credentials)
        else {
            return Err(divergence(F::Credentials));
        };
        if ours_credentials.address != theirs_credentials.address {
            return Err(divergence(F::Address));
        }
        if theirs_credentials.signature != ScVal::Void {
            return Err(divergence(F::Signature));
        }
        if ours.root_invocation != theirs.root_invocation {
            return Err(divergence(F::Invocation));
        }
    }
    if oracle.min_resource_fee == 0 || oracle.min_resource_fee > inputs.resource_fee_ceiling {
        return Err(divergence(F::ResourceFee));
    }
    compare_ledger(
        inputs.primary.latest_ledger,
        oracle.latest_ledger,
        inputs.expiration_ledger,
    )
}

/// Compares the oracle's ledger with the primary's simulation ledger and the
/// signature expiration ledger derived from it, and refuses at the first
/// disagreement.
///
/// 1. `oracle_ledger` trails `primary_ledger` by at most two ledgers. An
///    oracle ahead of the primary is bounded by check 2 alone: a retried
///    answer arrives several ledgers after the primary's simulation.
/// 2. `oracle_ledger` lies before `expiration_ledger`.
///
/// A primary that reports an inflated ledger fails check 1, so the signed
/// window stays bounded by the oracle's view of the network.
///
/// # Errors
/// `simulation.divergence` naming the Soroban simulation and
/// [`WitnessField::LedgerSkew`] or [`WitnessField::Expiration`].
pub(super) fn compare_ledger(
    primary_ledger: u32,
    oracle_ledger: u32,
    expiration_ledger: u32,
) -> Result<(), WalletError> {
    if oracle_ledger.saturating_add(MAX_ORACLE_LAG_LEDGERS) < primary_ledger {
        return Err(divergence(WitnessField::LedgerSkew));
    }
    if oracle_ledger >= expiration_ledger {
        return Err(divergence(WitnessField::Expiration));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]
    use super::super::*;
    use super::*;
    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::{
        asset_id::CanonicalAsset,
        cross_check::CrossCheckThresholds,
        profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE},
    };
    use stellar_agent_test_support::EchoIdResponder;
    use stellar_xdr::{
        AccountId, ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp,
        Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey, ScAddress,
        ScSymbol, SequenceNumber, SorobanAddressCredentials, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, Transaction, TransactionExt, TransactionV1Envelope, Uint256,
        VecM, WriteXdr,
    };
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const PRIMARY_LEDGER: u32 = 1000;
    const EXPIRATION: u32 = 1060;
    const CEILING: u64 = 10_000_000;
    /// The native asset's contract on testnet.
    const NATIVE_SAC: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
    /// A token contract with no threshold unless a test sets one.
    const TOKEN: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

    fn account(n: u8) -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([n; 32]))))
    }

    fn transfer(amount: i128) -> InvokeContractArgs {
        let contract = stellar_strkey::Contract::from_string(NATIVE_SAC).unwrap();
        InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract.0))),
            function_name: ScSymbol("transfer".try_into().unwrap()),
            args: vec![
                ScVal::Address(account(5)),
                ScVal::Address(account(6)),
                ScVal::from(amount),
            ]
            .try_into()
            .unwrap(),
        }
    }

    fn entry_with(
        nonce: i64,
        expiration: u32,
        signature: ScVal,
        amount: i128,
    ) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: account(5),
                nonce,
                signature_expiration_ledger: expiration,
                signature,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(transfer(amount)),
                sub_invocations: VecM::default(),
            },
        }
    }

    fn entry() -> SorobanAuthorizationEntry {
        entry_with(7, 0, ScVal::Void, 10_000_000)
    }

    fn envelope(fee: u32) -> TransactionEnvelope {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: MuxedAccount::Ed25519(Uint256([0; 32])),
                fee,
                seq_num: SequenceNumber(0),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                        host_function: HostFunction::InvokeContract(transfer(10_000_000)),
                        auth: VecM::default(),
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionExt::V0,
            },
            signatures: VecM::default(),
        })
    }

    fn answer(auth: &[SorobanAuthorizationEntry], ledger: u32) -> serde_json::Value {
        let auth: Vec<String> = auth
            .iter()
            .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
            .collect();
        json!({
            "transactionData": "AAAA",
            "minResourceFee": "1000",
            "results": [{
                "auth": auth,
                "xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),
            }],
            "latestLedger": ledger,
        })
    }

    fn primary() -> SimulateTransactionResponse {
        serde_json::from_value(answer(&[entry()], PRIMARY_LEDGER)).unwrap()
    }

    fn inputs<'a>(
        envelope: &'a TransactionEnvelope,
        primary: &'a SimulateTransactionResponse,
    ) -> SorobanWitnessInputs<'a> {
        SorobanWitnessInputs {
            envelope,
            primary,
            expiration_ledger: EXPIRATION,
            resource_fee_ceiling: CEILING,
        }
    }

    fn profile(oracle: &MockServer) -> Profile {
        Profile::builder_testnet("signer", "witness", "nonce", "witness")
            .rpc_url("https://primary.example/rpc")
            .oracle_provider_url(url::Url::parse(&format!("{}/oracle", oracle.uri())).unwrap())
            .build()
    }

    fn prepare(profile: &Profile) -> SorobanCrossCheck {
        SorobanCrossCheck::prepare(
            profile,
            &NetworkContext::from_profile(profile),
            CrossCheckValue::Unvalued,
            "test_witness",
        )
        .unwrap()
    }

    fn timing() -> WitnessTiming {
        WitnessTiming {
            attempt_budget: Duration::from_millis(300),
            retry_backoff: Duration::from_millis(1),
        }
    }

    async fn oracle_with_network(passphrase: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(EchoIdResponder::new(
                stellar_agent_test_support::signed_envelope::get_network_result(passphrase),
            ))
            .mount(&server)
            .await;
        server
    }

    async fn oracle_answering(simulation: impl Respond + 'static) -> MockServer {
        let server = oracle_with_network(TESTNET_PASSPHRASE).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "simulateTransaction"})))
            .respond_with(simulation)
            .mount(&server)
            .await;
        server
    }

    async fn methods(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    async fn witness_from(server: &MockServer) -> Result<CrossCheckOutcome, WalletError> {
        let envelope = envelope(100);
        let primary = primary();
        prepare(&profile(server))
            .witness_with_timing(inputs(&envelope, &primary), timing())
            .await
    }

    /// Answers `simulateTransaction` with the HTTP status `failing` for the
    /// first `failures` requests and with `answer` afterwards.
    struct FailingThen {
        failures: usize,
        failing: u16,
        answer: serde_json::Value,
        seen: std::sync::atomic::AtomicUsize,
    }

    impl FailingThen {
        fn new(failures: usize, failing: u16, answer: serde_json::Value) -> Self {
            Self {
                failures,
                failing,
                answer,
                seen: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl Respond for FailingThen {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let seen = self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if seen < self.failures {
                ResponseTemplate::new(self.failing)
            } else {
                EchoIdResponder::new(self.answer.clone()).respond(request)
            }
        }
    }

    fn assert_unavailable(error: &WalletError, expected: fn(&Reason) -> bool) {
        assert_eq!(error.code(), "network.witness_unavailable", "{error}");
        let WalletError::Network(NetworkError::WitnessUnavailable { reason }) = error else {
            panic!("{error:?}");
        };
        assert!(expected(reason), "{reason:?}");
    }

    #[tokio::test]
    async fn soroban_witness_passes_with_the_oracle_ledger_and_the_simulated_envelope() {
        let server = oracle_answering(EchoIdResponder::new(answer(&[entry()], 1001))).await;
        let envelope = envelope(100);
        let primary = primary();
        let outcome = prepare(&profile(&server))
            .witness_with_timing(inputs(&envelope, &primary), timing())
            .await
            .unwrap();
        let witness = outcome.witness().unwrap();
        assert_eq!(witness.authority(), server.uri());
        assert_eq!(witness.oracle_ledger(), 1001);
        assert_eq!(witness.kinds(), &[WitnessEntry::SorobanSimulation]);
        assert_eq!(
            witness.inputs_digest_hex(),
            crate::submit::bytes_to_hex(
                &digest::soroban_inputs_digest(&envelope, &[entry()], PRIMARY_LEDGER).unwrap()
            )
        );
        assert_eq!(
            methods(&server).await,
            ["getNetwork", "simulateTransaction"]
        );
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(
            body["params"]["transaction"],
            envelope.to_xdr_base64(Limits::none()).unwrap()
        );
        assert!(body["params"].get("authMode").is_none(), "{body}");
    }

    #[tokio::test]
    async fn soroban_witness_refuses_two_primary_results_before_any_oracle_request() {
        let server = oracle_answering(EchoIdResponder::new(answer(&[entry()], 1001))).await;
        let envelope = envelope(100);
        let mut answer = answer(&[entry()], PRIMARY_LEDGER);
        let result = answer["results"][0].clone();
        answer["results"] = json!([result.clone(), result]);
        let primary = serde_json::from_value(answer).unwrap();
        let error = prepare(&profile(&server))
            .witness(inputs(&envelope, &primary))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WalletError::Protocol(stellar_agent_core::error::ProtocolError::XdrCodecFailed { .. })
        ));
        assert_eq!(error.code(), "protocol.xdr_codec_failed");
        assert!(methods(&server).await.is_empty(), "no oracle request");
    }

    #[tokio::test]
    async fn soroban_witness_identity_mismatch_is_witness_unavailable() {
        for passphrase in ["Test SDF Future Network ; October 2022", MAINNET_PASSPHRASE] {
            let server = oracle_with_network(passphrase).await;
            let error = witness_from(&server).await.unwrap_err();
            assert_unavailable(&error, |reason| {
                matches!(reason, Reason::IdentityNetworkMismatch { .. })
            });
            assert_eq!(methods(&server).await, ["getNetwork"]);
        }
    }

    #[tokio::test]
    async fn soroban_witness_identity_timeout_is_identity_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(move |request: &Request| {
                EchoIdResponder::new(
                    stellar_agent_test_support::signed_envelope::get_network_result(
                        TESTNET_PASSPHRASE,
                    ),
                )
                .respond(request)
                .set_delay(Duration::from_millis(900))
            })
            .mount(&server)
            .await;
        let error = witness_from(&server).await.unwrap_err();
        assert_unavailable(&error, |reason| {
            matches!(reason, Reason::IdentityUnavailable { .. })
        });
        assert!(
            methods(&server)
                .await
                .iter()
                .all(|method| method == "getNetwork")
        );
    }

    #[tokio::test]
    async fn soroban_witness_credential_refusal_keeps_its_code_after_one_attempt() {
        for status in [401, 403] {
            let server = oracle_answering(ResponseTemplate::new(status)).await;
            let error = witness_from(&server).await.unwrap_err();
            assert_eq!(error.code(), "network.rpc_credential_refused");
            assert_eq!(
                error.to_string(),
                format!(
                    "RPC endpoint '{}' answered a request with HTTP {status}; \
                     check the credential the profile configures for this endpoint",
                    server.uri()
                )
            );
            assert_eq!(
                methods(&server).await,
                ["getNetwork", "simulateTransaction"]
            );
        }
    }

    #[tokio::test]
    async fn soroban_witness_retries_two_transport_failures_then_passes() {
        let server =
            oracle_answering(FailingThen::new(2, 503, answer(&[entry()], PRIMARY_LEDGER))).await;
        let outcome = witness_from(&server).await.unwrap();
        assert!(outcome.witness().is_some());
        assert_eq!(
            methods(&server).await,
            [
                "getNetwork",
                "simulateTransaction",
                "simulateTransaction",
                "simulateTransaction"
            ]
        );
    }

    /// A retried answer arrives ledgers after the primary's simulation; an
    /// oracle four ledgers ahead of the primary passes while the signature
    /// window allows it.
    #[tokio::test]
    async fn soroban_witness_retried_answer_ahead_of_the_primary_passes() {
        let server = oracle_answering(FailingThen::new(
            1,
            503,
            answer(&[entry()], PRIMARY_LEDGER + 4),
        ))
        .await;
        let outcome = witness_from(&server).await.unwrap();
        assert_eq!(
            outcome.witness().unwrap().oracle_ledger(),
            PRIMARY_LEDGER + 4
        );
        assert_eq!(
            methods(&server).await,
            ["getNetwork", "simulateTransaction", "simulateTransaction"]
        );
    }

    #[tokio::test]
    async fn soroban_witness_three_transport_failures_are_witness_unavailable() {
        let server =
            oracle_answering(FailingThen::new(3, 503, answer(&[entry()], PRIMARY_LEDGER))).await;
        let error = witness_from(&server).await.unwrap_err();
        assert_unavailable(&error, |reason| {
            matches!(reason, Reason::Transport { attempts: 3, .. })
        });
        assert_eq!(
            methods(&server)
                .await
                .iter()
                .filter(|method| *method == "simulateTransaction")
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn soroban_witness_never_retries_a_divergence() {
        // The first answer disagrees on the authorization count and every
        // later answer agrees, so a retry after the divergence would pass.
        let server = oracle_with_network(TESTNET_PASSPHRASE).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "simulateTransaction"})))
            .respond_with(EchoIdResponder::new(answer(&[], PRIMARY_LEDGER)))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "simulateTransaction"})))
            .respond_with(EchoIdResponder::new(answer(&[entry()], PRIMARY_LEDGER)))
            .mount(&server)
            .await;
        let error = witness_from(&server).await.unwrap_err();
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessDivergence {
                    entry: WitnessEntry::SorobanSimulation,
                    field: WitnessField::AuthorizationCount,
                    sequence_delta: None,
                })
            ),
            "{error}"
        );
        assert_eq!(
            methods(&server).await,
            ["getNetwork", "simulateTransaction"]
        );
    }

    #[tokio::test]
    async fn soroban_witness_never_retries_an_invalid_answer() {
        for body in [
            ResponseTemplate::new(200).set_body_string("hostile-body"),
            ResponseTemplate::new(404),
        ] {
            let server = oracle_answering(body).await;
            let error = witness_from(&server).await.unwrap_err();
            assert_unavailable(&error, |reason| {
                matches!(reason, Reason::InvalidAnswer { .. })
            });
            assert!(!error.to_string().contains("hostile-body"));
            assert_eq!(
                methods(&server).await,
                ["getNetwork", "simulateTransaction"]
            );
        }
    }

    #[tokio::test]
    async fn soroban_witness_undecodable_oracle_results_are_invalid_answers() {
        let mut bad_auth = answer(&[entry()], PRIMARY_LEDGER);
        bad_auth["results"][0]["auth"][0] = json!("AAAA");
        let mut bad_value = answer(&[entry()], PRIMARY_LEDGER);
        bad_value["results"][0]["xdr"] = json!("not-xdr");
        for body in [bad_auth, bad_value] {
            let server = oracle_answering(EchoIdResponder::new(body)).await;
            let error = witness_from(&server).await.unwrap_err();
            assert_unavailable(&error, |reason| {
                matches!(reason, Reason::InvalidAnswer { .. })
            });
            assert_eq!(
                methods(&server).await,
                ["getNetwork", "simulateTransaction"]
            );
        }
    }

    /// Runs `future` under the wallet's own subscriber stack with `filter` as
    /// the operator's filter value, and returns the output with the text the
    /// stack wrote.
    async fn wallet_logs<F: std::future::Future>(filter: &str, future: F) -> (F::Output, String) {
        use stellar_agent_core::observability::{
            FormatChoice, SubscriberConfig, subscriber_for_tests,
        };
        use tracing::instrument::WithSubscriber as _;
        let capture = stellar_agent_test_support::CaptureWriter::new();
        let writer = capture.clone();
        let subscriber = subscriber_for_tests(
            SubscriberConfig::default()
                .with_filter_override(Some(tracing_subscriber::EnvFilter::new(filter)))
                .with_format_override(Some(FormatChoice::Pretty))
                .with_writer_factory(Some(Box::new(move || Box::new(writer.clone())))),
        )
        .unwrap();
        // An inert dispatcher kept alive for the capture makes `tracing`
        // compute every callsite's interest from the registered dispatchers,
        // and the rebuild refreshes callsites cached before this capture.
        let inert = stellar_agent_test_support::inert_dispatcher();
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let output = future.with_subscriber(dispatch).await;
        drop(inert);
        (output, capture.captured_str())
    }

    /// The oracle's simulation error text and a JSON-RPC error text, both
    /// within the first 1,024 characters of the answer the transport reads,
    /// reach neither the refusal nor the wallet's log at any filter value.
    /// The wallet's own event about the failed read stays.
    #[tokio::test(flavor = "current_thread")]
    async fn soroban_witness_renders_no_oracle_text() {
        let hostile =
            "https://user:credential-marker@example.invalid/private-path?token=secret-marker";
        let mut with_error = answer(&[entry()], PRIMARY_LEDGER);
        with_error["error"] = json!(hostile);
        let rpc_error = move |request: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({"jsonrpc": "2.0",
                "id": body["id"], "error": {"code": -32603, "message": hostile}}))
        };
        let simulation_error = oracle_answering(EchoIdResponder::new(with_error)).await;
        let rpc_error = oracle_answering(rpc_error).await;
        for filter in [
            "trace",
            "jsonrpsee=trace,stellar_agent_network=trace",
            "jsonrpsee-http=trace,stellar_agent_network=trace",
            "[method_call]=trace,stellar_agent_network=trace",
        ] {
            for (server, code) in [
                (&simulation_error, "simulation.divergence"),
                (&rpc_error, "network.witness_unavailable"),
            ] {
                let (result, logs) = wallet_logs(filter, witness_from(server)).await;
                let error = result.unwrap_err();
                assert_eq!(error.code(), code);
                let text = format!("{error} {error:?}");
                for forbidden in [
                    "credential-marker",
                    "secret-marker",
                    "private-path",
                    "user:",
                ] {
                    assert!(!text.contains(forbidden), "{text}");
                    assert!(!logs.contains(forbidden), "{filter}: {logs}");
                }
                if code == "network.witness_unavailable" {
                    assert!(
                        logs.contains("oracle witness read failed")
                            && logs.contains("invalid_answer"),
                        "{filter}: the wallet's own event stays: {logs}"
                    );
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn soroban_prepare_logs_the_skip_and_the_shared_host() {
        use super::super::log_capture::capture_logs;
        let unconfigured =
            Profile::builder_testnet("signer", "witness", "nonce", "witness").build();
        let (prepared, logs) = capture_logs(tracing::Level::WARN, async {
            SorobanCrossCheck::prepare(
                &unconfigured,
                &NetworkContext::from_profile(&unconfigured),
                CrossCheckValue::Unvalued,
                "test_witness",
            )
        })
        .await;
        assert!(matches!(
            prepared.unwrap(),
            SorobanCrossCheck::Skipped(CrossCheckSkip::OracleNotConfigured)
        ));
        for expected in [
            " WARN ",
            "policy.cross_check",
            "cross-check skipped; configure the oracle and asset threshold in the profile",
            "tool=\"test_witness\"",
            "reason=OracleNotConfigured",
        ] {
            assert!(logs.contains(expected), "{expected}: {logs}");
        }

        let server =
            oracle_answering(EchoIdResponder::new(answer(&[entry()], PRIMARY_LEDGER))).await;
        let mut shared = profile(&server);
        shared.rpc_url = format!("{}/primary", server.uri());
        let (prepared, logs) = capture_logs(tracing::Level::WARN, async {
            SorobanCrossCheck::prepare(
                &shared,
                &NetworkContext::from_profile(&shared),
                CrossCheckValue::Unvalued,
                "test_witness",
            )
        })
        .await;
        assert!(matches!(
            prepared.unwrap(),
            SorobanCrossCheck::Required { .. }
        ));
        assert!(
            logs.contains(
                "oracle_provider_url shares the provider host of rpc_url; \
                 cross-check is degraded to single-RPC verification"
            ),
            "{logs}"
        );
        assert!(logs.contains("tool=\"test_witness\""), "{logs}");
        assert!(methods(&server).await.is_empty(), "prepare sends nothing");
    }

    fn threshold(profile: &mut Profile, asset: &str, value: i128) {
        profile.cross_check_thresholds = CrossCheckThresholds::new(
            [(CanonicalAsset::contract(asset).unwrap(), value)]
                .into_iter()
                .collect(),
        )
        .unwrap();
    }

    /// The rule decides from the profile's thresholds and oracle, and only a
    /// required witness builds a client.
    #[tokio::test(flavor = "current_thread")]
    async fn soroban_prepare_applies_the_rule_before_building_a_client() {
        let server = oracle_with_network(TESTNET_PASSPHRASE).await;
        let token = CanonicalAsset::contract(TOKEN).unwrap();
        let native_sac = CanonicalAsset::contract(NATIVE_SAC).unwrap();
        let mut with_oracle = profile(&server);
        threshold(&mut with_oracle, TOKEN, 500);
        let mut without_oracle = with_oracle.clone();
        without_oracle.oracle_provider_url = None;
        let unthresholded = profile(&server);
        let cases: [(&Profile, &CanonicalAsset, i128, &str, usize); 6] = [
            (&with_oracle, &token, 500, "required", 1),
            (&with_oracle, &token, 499, "not_required", 0),
            (&without_oracle, &token, 500, "oracle_not_configured", 0),
            (
                &unthresholded,
                &token,
                i128::MAX,
                "no_threshold_for_asset",
                0,
            ),
            (&with_oracle, &native_sac, 9_999_999_999, "not_required", 0),
            (&with_oracle, &native_sac, 10_000_000_000, "required", 1),
        ];
        for (profile, asset, amount, expected, clients) in cases {
            #[cfg(feature = "test-hooks")]
            let before = crate::client::constructions_on_this_thread();
            let prepared = SorobanCrossCheck::prepare(
                profile,
                &NetworkContext::from_profile(profile),
                CrossCheckValue::Amount {
                    asset,
                    base_units: amount,
                },
                "test_witness",
            )
            .unwrap();
            let got = match prepared {
                SorobanCrossCheck::NotRequired => "not_required",
                SorobanCrossCheck::Skipped(CrossCheckSkip::OracleNotConfigured) => {
                    "oracle_not_configured"
                }
                SorobanCrossCheck::Skipped(CrossCheckSkip::NoThresholdForAsset) => {
                    "no_threshold_for_asset"
                }
                SorobanCrossCheck::Required { .. } => "required",
            };
            assert_eq!(got, expected, "{asset:?} {amount}");
            #[cfg(feature = "test-hooks")]
            assert_eq!(
                crate::client::constructions_on_this_thread() - before,
                clients,
                "{asset:?} {amount}"
            );
            #[cfg(not(feature = "test-hooks"))]
            let _ = clients;
        }
        assert!(methods(&server).await.is_empty(), "prepare sends nothing");
    }

    #[tokio::test]
    async fn soroban_prepare_refuses_an_oracle_client_that_cannot_be_built() {
        let mut profile = Profile::builder_testnet("signer", "witness", "nonce", "witness")
            .oracle_provider_url(
                url::Url::parse("ftp://user:credential-marker@example.invalid/private-path")
                    .unwrap(),
            )
            .build();
        let Err(error) = SorobanCrossCheck::prepare(
            &profile,
            &NetworkContext::from_profile(&profile),
            CrossCheckValue::Unvalued,
            "test_witness",
        ) else {
            panic!("an ftp oracle builds no client");
        };
        assert_unavailable(&error, |reason| {
            matches!(reason, Reason::ClientConstruction { .. })
        });
        assert_eq!(
            error.to_string(),
            "cross-check unavailable: the client for oracle 'ftp://example.invalid' \
             could not be built; correct oracle_provider_url in the profile file"
        );
        profile.oracle_provider_url = None;
        assert!(matches!(
            SorobanCrossCheck::prepare(
                &profile,
                &NetworkContext::from_profile(&profile),
                CrossCheckValue::Unvalued,
                "test_witness",
            ),
            Ok(SorobanCrossCheck::Skipped(
                CrossCheckSkip::OracleNotConfigured
            ))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn soroban_prepare_keeps_the_oracle_credential_code() {
        use stellar_agent_core::profile::schema::{
            KeyringEntryRef, ProviderRecord, Providers, RpcCredentialPlacement,
        };
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let server = oracle_with_network(TESTNET_PASSPHRASE).await;
        let mut profile = profile(&server);
        profile
            .providers
            .get_or_insert_with(Providers::default)
            .oracle = Some(
            ProviderRecord::new("Oracle RPC", "127.0.0.1", true).with_credential(
                KeyringEntryRef::new("stellar-agent-soroban-witness-test", "oracle"),
                RpcCredentialPlacement::Header {
                    name: "X-API-Key".into(),
                },
            ),
        );
        let Err(error) = SorobanCrossCheck::prepare(
            &profile,
            &NetworkContext::from_profile(&profile),
            CrossCheckValue::Unvalued,
            "test_witness",
        ) else {
            panic!("a missing oracle credential refuses");
        };
        assert_eq!(error.code(), "auth.keyring_not_found");
        assert!(methods(&server).await.is_empty());
    }

    #[tokio::test]
    async fn soroban_not_required_and_skipped_send_nothing() {
        let envelope = envelope(100);
        let primary = primary();
        for (prepared, status) in [
            (SorobanCrossCheck::NotRequired, "not_required"),
            (
                SorobanCrossCheck::Skipped(CrossCheckSkip::NoThresholdForAsset),
                "skipped",
            ),
        ] {
            let outcome = prepared.witness(inputs(&envelope, &primary)).await.unwrap();
            assert_eq!(outcome.view().status, status);
            assert!(outcome.witness().is_none());
        }
    }

    // ── Digest ───────────────────────────────────────────────────────────────

    fn framed(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// The digest follows the documented layout: the prefix, tag 9, the
    /// framed SHA-256 of the envelope, each normalized entry framed, and the
    /// primary ledger.
    #[test]
    fn soroban_digest_known_answer() {
        let envelope = envelope(100);
        let mut preimage = b"stellar-agent/cross-check/v1\0".to_vec();
        preimage.push(9);
        framed(
            &mut preimage,
            &Sha256::digest(envelope.to_xdr(Limits::none()).unwrap()),
        );
        framed(
            &mut preimage,
            &entry_with(0, 0, ScVal::Void, 10_000_000)
                .to_xdr(Limits::none())
                .unwrap(),
        );
        preimage.extend_from_slice(&[0, 0, 0x03, 0xe8]);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(
            digest::soroban_inputs_digest(&envelope, &[entry()], PRIMARY_LEDGER).unwrap(),
            expected
        );
    }

    #[test]
    fn soroban_digest_changes_with_the_envelope() {
        assert_ne!(
            digest::soroban_inputs_digest(&envelope(100), &[entry()], PRIMARY_LEDGER).unwrap(),
            digest::soroban_inputs_digest(&envelope(101), &[entry()], PRIMARY_LEDGER).unwrap()
        );
    }

    #[test]
    fn soroban_digest_changes_with_the_ledger() {
        assert_ne!(
            digest::soroban_inputs_digest(&envelope(100), &[entry()], PRIMARY_LEDGER).unwrap(),
            digest::soroban_inputs_digest(&envelope(100), &[entry()], PRIMARY_LEDGER + 1).unwrap()
        );
    }

    #[test]
    fn soroban_digest_changes_with_the_invocation() {
        assert_ne!(
            digest::soroban_inputs_digest(&envelope(100), &[entry()], PRIMARY_LEDGER).unwrap(),
            digest::soroban_inputs_digest(
                &envelope(100),
                &[entry_with(7, 0, ScVal::Void, 10_000_001)],
                PRIMARY_LEDGER
            )
            .unwrap()
        );
    }

    #[test]
    fn soroban_digest_normalizes_nonce_expiration_and_signature() {
        let signed = ScVal::Bytes(vec![1_u8; 64].try_into().unwrap());
        assert_eq!(
            digest::soroban_inputs_digest(
                &envelope(100),
                &[entry_with(7, 0, ScVal::Void, 10_000_000)],
                PRIMARY_LEDGER
            )
            .unwrap(),
            digest::soroban_inputs_digest(
                &envelope(100),
                &[entry_with(-9, 1060, signed, 10_000_000)],
                PRIMARY_LEDGER
            )
            .unwrap()
        );
    }

    /// The `simulation.divergence` field of a refused ledger comparison.
    fn ledger_divergence(result: Result<(), WalletError>) -> WitnessField {
        match result {
            Err(WalletError::Network(NetworkError::WitnessDivergence {
                entry: WitnessEntry::SorobanSimulation,
                field,
                sequence_delta: None,
            })) => field,
            other => panic!("expected a Soroban simulation divergence, got {other:?}"),
        }
    }

    #[test]
    fn compare_ledger_accepts_an_oracle_two_ledgers_behind() {
        compare_ledger(PRIMARY_LEDGER, PRIMARY_LEDGER - 2, EXPIRATION).unwrap();
        compare_ledger(PRIMARY_LEDGER, PRIMARY_LEDGER, EXPIRATION).unwrap();
    }

    #[test]
    fn compare_ledger_refuses_an_oracle_three_ledgers_behind() {
        assert_eq!(
            ledger_divergence(compare_ledger(
                PRIMARY_LEDGER,
                PRIMARY_LEDGER - 3,
                EXPIRATION
            )),
            WitnessField::LedgerSkew
        );
    }

    #[test]
    fn compare_ledger_accepts_an_oracle_ahead_of_the_primary() {
        compare_ledger(PRIMARY_LEDGER, PRIMARY_LEDGER + 5, EXPIRATION).unwrap();
        compare_ledger(PRIMARY_LEDGER, EXPIRATION - 1, EXPIRATION).unwrap();
    }

    #[test]
    fn compare_ledger_refuses_an_oracle_at_or_past_the_expiration() {
        for oracle in [EXPIRATION, EXPIRATION + 1] {
            assert_eq!(
                ledger_divergence(compare_ledger(PRIMARY_LEDGER, oracle, EXPIRATION)),
                WitnessField::Expiration,
                "oracle at {oracle}"
            );
        }
    }
}

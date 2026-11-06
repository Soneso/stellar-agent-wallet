//! Production submission recorder state for the protocol acceptance suites.
//!
//! The DEX and DeFindex testnet acceptance suites record each submission the
//! way the CLI records it. This module holds the one copy of that wallet state.
//! It is gated behind the `test-helpers` feature and never reaches a release
//! binary.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "acceptance fixtures fail the test on a broken precondition"
)]

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use stellar_agent_core::policy::v1::{PolicyEngineV1, ValueEffects};
use stellar_agent_core::profile::receipt::{ReceiptStore, SubmissionReceipt};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::policy_state::{PersistedWindowStore, SignedIntentView};
use stellar_agent_network::{AuditWriterHandle, WalletSubmissionRecorder};

/// The daily `native` cap the acceptance policies size an action against: 100 XLM.
///
/// The cap is far above the actions, so it never refuses. Its role is to give
/// the debit leg a window entry, which the recorder charges as the signed
/// intent before the first signature.
pub const NATIVE_DAILY_CAP_STROOPS: i128 = 1_000_000_000;

/// Wallet state the production submission recorder writes for one submission.
///
/// The receipt store and the spending-window file live in a directory the
/// state owns, and the window store's key lives in the in-memory keyring.
/// The run never touches an operator's wallet state.
///
/// The recorder is built the way the CLI builds it: the policy engine sizes the
/// gate's value effects. That sizing is both the recorder's window entries and
/// its signing admission.
pub struct SubmissionRecordState {
    dir: tempfile::TempDir,
    profile: Profile,
    profile_name: String,
    chain_id: String,
    engine: PolicyEngineV1,
}

impl SubmissionRecordState {
    /// Creates the state for `profile_name` on `chain_id`, auditing to
    /// `audit_log_path`.
    ///
    /// The first call in a process installs the in-memory keyring. The policy
    /// allows every tool on every chain under the daily `native` cap
    /// [`NATIVE_DAILY_CAP_STROOPS`].
    ///
    /// # Panics
    ///
    /// Panics when the in-memory keyring cannot be installed or the record
    /// directory cannot be created.
    #[must_use]
    pub fn new(profile_name: &str, chain_id: &str, audit_log_path: &Path) -> Self {
        use stellar_agent_core::policy::{
            Decision,
            v1::{
                PolicyDocument, PolicyRule, RuleMatch, ScopeId,
                criteria::per_period_cap::{PerPeriodCapCriterion, Window},
            },
        };

        static KEYRING: std::sync::Once = std::sync::Once::new();
        KEYRING.call_once(|| {
            stellar_agent_test_support::keyring_mock::install()
                .expect("install the in-memory keyring");
        });
        let dir = tempfile::Builder::new()
            .prefix(profile_name)
            .tempdir()
            .expect("create the record directory");
        let profile = Profile::builder_testnet(
            "stellar-agent-signer",
            profile_name,
            "stellar-agent-nonce",
            profile_name,
        )
        .audit_log_path(audit_log_path)
        .build();
        let engine = PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                signature: None,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "*".into(),
                        chain: "*".into(),
                    },
                    criteria: vec![Box::new(PerPeriodCapCriterion::new(
                        "native".into(),
                        Window::parse("1d").expect("a one-day window"),
                        NATIVE_DAILY_CAP_STROOPS,
                    ))],
                    decision: Decision::Allow,
                    allow_opaque_signing: false,
                }],
            },
            profile_name.to_owned(),
        );
        Self {
            dir,
            profile,
            profile_name: profile_name.to_owned(),
            chain_id: chain_id.to_owned(),
            engine,
        }
    }

    fn window_store(&self) -> PersistedWindowStore {
        PersistedWindowStore::at_path(self.dir.path().join("policy-window-state.json"))
    }

    /// Builds the recorder for one submission of `tool` with `effects`.
    ///
    /// # Panics
    ///
    /// Panics when the acceptance policy does not size `effects`, or when the
    /// receipt store or the clock cannot be read.
    #[must_use]
    pub fn recorder(
        &self,
        tool: &'static str,
        effects: &ValueEffects,
        audit: AuditWriterHandle,
    ) -> WalletSubmissionRecorder<'_> {
        use stellar_agent_core::policy::{
            McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind,
            v1::{SizingOutcome, ValueClass},
        };

        let mut descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
            name: tool,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        });
        descriptor.chain_id = self.chain_id.clone();
        let sizing = match self
            .engine
            .record_confirmed_checked(
                &descriptor,
                &self.profile,
                &ValueClass::Value(effects.clone()),
            )
            .expect("the acceptance policy sizes the action")
        {
            SizingOutcome::Sized(sizing) => sizing,
            other => panic!("the acceptance policy must size the action, got {other:?}"),
        };
        let legs = effects.legs().iter().map(Into::into).collect();
        let window_entries = sizing.entries().to_vec();
        WalletSubmissionRecorder::new(
            &self.profile,
            self.profile_name.clone(),
            tool,
            Some(self.chain_id.clone()),
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            legs,
            window_entries,
            ReceiptStore::open_at(self.dir.path(), &self.profile_name)
                .expect("open the receipt store"),
            self.window_store(),
            Some(audit),
            None,
            format!("{}-{}", self.profile_name, now_secs()),
            stellar_agent_core::timefmt::now_unix_ms().expect("read the clock"),
        )
        .with_signing_sizing(sizing)
    }

    /// The amount and call count the durable window holds under the daily
    /// `native` cap, read back the way the policy gate reads it.
    ///
    /// # Panics
    ///
    /// Panics when the window state cannot be loaded or queried.
    #[must_use]
    pub fn native_window(&self) -> (i128, u32) {
        let state = stellar_agent_core::policy::v1::PolicyStateStore::new();
        self.window_store()
            .load_into(&self.profile_name, &self.profile, &state)
            .expect("load the window state");
        state
            .query_window(
                &stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                    &self.profile_name,
                    1,
                    "native",
                    86_400,
                ),
                stellar_agent_core::timefmt::now_unix_ms().expect("read the clock"),
            )
            .expect("query the window")
    }

    /// The reservations the window still holds open.
    ///
    /// # Panics
    ///
    /// Panics when the window state cannot be read.
    #[must_use]
    pub fn pending_reservations(&self) -> usize {
        self.window_store()
            .pending_reservations(&self.profile)
            .expect("read the pending reservations")
            .len()
    }

    /// The receipt the recorder keeps for `envelope_hash`, read back from the
    /// state's receipt store.
    ///
    /// # Panics
    ///
    /// Panics when the receipt store cannot be opened or read, and panics with
    /// the hash when the store holds no receipt for `envelope_hash`.
    #[must_use]
    pub fn receipt(&self, envelope_hash: &str) -> SubmissionReceipt {
        ReceiptStore::open_at(self.dir.path(), &self.profile_name)
            .expect("open the receipt store")
            .get(envelope_hash)
            .expect("read the receipt store")
            .unwrap_or_else(|| panic!("no receipt for envelope hash {envelope_hash}"))
    }

    /// The signed intents the window holds, in admission order.
    ///
    /// # Panics
    ///
    /// Panics when the window state cannot be read or does not authenticate.
    #[must_use]
    pub fn signed_intents(&self) -> Vec<SignedIntentView> {
        self.window_store()
            .signed_intents(&self.profile_name, &self.profile)
            .expect("read the signed intents")
    }
}

/// The current UNIX time in seconds, which keeps request ids distinct per run.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must work")
        .as_secs()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]

    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::json;
    use stellar_agent_core::audit_log::AuditWriter;
    use stellar_agent_core::policy::v1::{ActionKind, ValueEffects, ValueLeg};
    use stellar_agent_core::profile::receipt::ReceiptStatus;
    use stellar_agent_network::signing::envelope_signing::attach_signature;
    use stellar_agent_network::submit::{envelope_hash_hex, submit_transaction_and_wait_sent_by};
    use stellar_agent_network::{
        SignedIntentPlan, SoftwareSigningKey, StellarRpcClient, SubmissionRecorder, intent_xdr_hash,
    };
    use stellar_agent_test_support::EchoIdResponder;
    use stellar_agent_test_support::signed_envelope::{
        TESTNET_PASSPHRASE, account_id_for_seed, get_network_result, ledger_entries_result_for,
        public_key_for_seed, transaction_hash_hex,
    };
    use stellar_xdr::{Limits, WriteXdr};
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer};
    use zeroize::Zeroizing;

    use super::{NATIVE_DAILY_CAP_STROOPS, SubmissionRecordState};

    /// The native debit the recorder charges: 1 XLM, far below the daily cap.
    const DEBIT_STROOPS: i128 = 10_000_000;

    // The acceptance policy sizes the debit only while it stays under the cap.
    const _: () = assert!(DEBIT_STROOPS < NATIVE_DAILY_CAP_STROOPS);

    /// The ledger the mocked endpoint confirms the submission in.
    const CONFIRMED_LEDGER: u32 = 1_002;

    /// How long the submit layer waits for the confirmation.
    const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

    /// The router address the debit leg names as its destination.
    const ROUTER: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";

    /// The seed of the account that signs and submits the invocation.
    const SOURCE_SEED: [u8; 32] = [0x31; 32];

    /// A keyed audit writer over `path`, as the protocol acceptance suites open it.
    fn audit_writer(path: &std::path::Path) -> Arc<Mutex<AuditWriter>> {
        Arc::new(Mutex::new(
            AuditWriter::open_keyed_unanchored_for_test(
                path.to_owned(),
                Zeroizing::new([0x11u8; 32]),
            )
            .expect("open the audit writer"),
        ))
    }

    /// One native debit leg, built the way the DEX trade derives its leg.
    fn native_debit(amount: i128) -> ValueEffects {
        ValueEffects::single(ValueLeg {
            kind: ActionKind::DexTrade,
            amount: Some(amount),
            asset: Some("native".to_owned()),
            destination: Some(ROUTER.to_owned()),
        })
    }

    /// A contract invocation from `seed`'s account at sequence 1, its signing
    /// plan, and the envelope signed by that account's key under testnet.
    ///
    /// The envelope carries no authorization entries, so the plan's authority
    /// is the source account itself, which the binding recomputes from the bytes.
    async fn signed_invocation(seed: [u8; 32]) -> (SignedIntentPlan, String) {
        use stellar_xdr::{
            ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Memo,
            MuxedAccount, Operation, OperationBody, Preconditions, ScAddress, ScSymbol,
            SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
            TransactionV1Envelope, Uint256,
        };
        let host = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
            function_name: ScSymbol::try_from("call").unwrap(),
            args: Default::default(),
        });
        let source = account_id_for_seed(seed);
        let plan = SignedIntentPlan::new(
            TESTNET_PASSPHRASE,
            &source,
            &source,
            1,
            intent_xdr_hash(&host).unwrap(),
            Vec::new(),
            None,
        )
        .unwrap()
        .classify_purpose(&host, None)
        .unwrap();
        let unsigned = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: MuxedAccount::Ed25519(Uint256(public_key_for_seed(seed))),
                fee: 100,
                seq_num: SequenceNumber(1),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                        host_function: host,
                        auth: Default::default(),
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionExt::V0,
            },
            signatures: Default::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let signed = attach_signature(
            &unsigned,
            &SoftwareSigningKey::new_from_bytes(seed),
            TESTNET_PASSPHRASE,
        )
        .await
        .unwrap();
        (plan, signed)
    }

    /// An endpoint that reports testnet, the source account's signers, a
    /// pending send and a confirmation in [`CONFIRMED_LEDGER`].
    async fn confirming_endpoint(source: &str, envelope_xdr: &str) -> MockServer {
        let server = MockServer::start().await;
        let mut ledger_entries = ledger_entries_result_for(&[source]);
        ledger_entries
            .as_object_mut()
            .expect("the ledger entries result is an object")
            .insert("latestLedger".to_owned(), json!(1_000));
        for (rpc_method, result) in [
            ("getNetwork", get_network_result(TESTNET_PASSPHRASE)),
            ("getLedgerEntries", ledger_entries),
            (
                "sendTransaction",
                json!({
                    "hash": transaction_hash_hex(envelope_xdr, TESTNET_PASSPHRASE),
                    "status": "PENDING",
                    "latestLedger": 1_001,
                    "latestLedgerCloseTime": "1699999999",
                }),
            ),
            (
                "getTransaction",
                json!({
                    "status": "SUCCESS",
                    "latestLedger": CONFIRMED_LEDGER,
                    "ledger": CONFIRMED_LEDGER,
                }),
            ),
        ] {
            Mock::given(method("POST"))
                .and(body_partial_json(json!({ "method": rpc_method })))
                .respond_with(EchoIdResponder::new(result))
                .mount(&server)
                .await;
        }
        server
    }

    #[tokio::test]
    async fn a_confirmed_submission_records_its_receipt_window_charge_and_signed_intent() {
        let audit_dir = tempfile::tempdir().unwrap();
        let audit_log_path = audit_dir.path().join("audit.jsonl");
        let audit = audit_writer(&audit_log_path);
        let state = SubmissionRecordState::new("recorder-unit", "stellar:testnet", &audit_log_path);
        let effects = native_debit(DEBIT_STROOPS);
        let recorder = state.recorder("stellar_dex_trade", &effects, Arc::clone(&audit));

        // The signing admission charges the sized debit leg before the first
        // signature, and the store's admission of the frozen plan exposes it.
        let (plan, envelope_xdr) = signed_invocation(SOURCE_SEED).await;
        let admitted = recorder.admit_signed_intent(&plan).await.unwrap().expose();
        assert!(
            admitted.intent_id().is_some(),
            "a sized admission names its intent"
        );
        let exposure = state
            .window_store()
            .admit_signed_intent(&state.profile, admitted.plan())
            .unwrap()
            .expose();
        assert_eq!(exposure.intent_id(), admitted.intent_id());

        // The submit layer derives the intent from the envelope, binds it to
        // the exposed intent before the send and settles it on the confirmation.
        let server = confirming_endpoint(&account_id_for_seed(SOURCE_SEED), &envelope_xdr).await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let result = submit_transaction_and_wait_sent_by(
            &client,
            &envelope_xdr,
            tokio::time::Instant::now() + SUBMIT_TIMEOUT,
            SUBMIT_TIMEOUT,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
            Some(&exposure),
        )
        .await
        .unwrap();
        assert_eq!(result.ledger, CONFIRMED_LEDGER);

        let receipt = state.receipt(&envelope_hash_hex(&envelope_xdr));
        assert_eq!(receipt.status, ReceiptStatus::Success, "{receipt:?}");
        assert_eq!(receipt.ledger, Some(CONFIRMED_LEDGER), "{receipt:?}");
        // The bound submission is charged once, and the confirmation keeps its
        // exposure open until authenticated settlement.
        assert_eq!(state.native_window(), (DEBIT_STROOPS, 1));
        assert_eq!(state.pending_reservations(), 1);
        let intents = state.signed_intents();
        assert_eq!(intents.len(), 1, "{intents:?}");
        assert_eq!(
            intents[0].status, "authorization exposed, submission bound",
            "{intents:?}"
        );
    }

    #[test]
    #[should_panic(expected = "no receipt for envelope hash")]
    fn receipt_refuses_an_envelope_hash_the_store_does_not_hold() {
        let audit_dir = tempfile::tempdir().unwrap();
        let state = SubmissionRecordState::new(
            "recorder-unknown",
            "stellar:testnet",
            &audit_dir.path().join("audit.jsonl"),
        );
        let _ = state.receipt(&"0".repeat(64));
    }
}

//! Shared authenticated intent fixtures for command and tool views.
#![allow(clippy::unwrap_used, clippy::panic, reason = "fixture invariants")]

use crate::policy_state::PersistedWindowStore;
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::profile::schema::Profile;
use stellar_xdr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, Limits, ScAddress, ScSymbol, ScVal,
    WriteXdr,
};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

/// The retention interval in milliseconds.
pub const RETENTION: u64 = 604_800_000;
/// The explanation for an open intent without an authenticated purpose.
pub const PERMANENT: &str = "An open intent without an authenticated purpose permanently blocks reset for this profile. Continue with a new profile.";
/// The explanation for an open intent whose stored secondary is absent.
pub const SECONDARY: &str = "Retained intents close only through the profile's stored secondary endpoint. Add one to the profile.";
/// The explanation for an open intent whose stored endpoints do not load.
pub const UNREADABLE: &str = "The profile's stored endpoint configuration is unreadable. Retained intents close only through stored endpoints that load.";

/// Owns the store, endpoint, and guards for one intent view case.
pub struct IntentViewFixture {
    /// The loaded fixture profile.
    pub profile: Profile,
    /// The authenticated fixture store.
    pub store: PersistedWindowStore,
    mode: &'static str,
    profile_path: std::path::PathBuf,
    primary: String,
    stored: String,
    timelock: String,
    before: Vec<u8>,
    hmac: keyring_core::Entry,
    generation: keyring_core::Entry,
    key_before: String,
    generation_before: String,
    #[cfg(feature = "test-hooks")]
    clients_before: usize,
    endpoint: MockServer,
    expected_requests: usize,
    _clock: crate::mainnet::clock::TestClockGuard,
    _home: stellar_agent_test_support::StellarAgentHomeGuard,
    _dir: tempfile::TempDir,
}

impl IntentViewFixture {
    /// Seeds an invocation, terminal schedule, or unclassified intent.
    ///
    /// # Panics
    /// Panics if fixture construction or observation fails.
    pub async fn new(mode: &'static str) -> Self {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
        std::fs::create_dir_all(&scratch).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("intent-view-")
            .tempdir_in(scratch)
            .unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
        let endpoint = MockServer::start().await;
        let state = ScVal::U32(u32::from(mode == "done"))
            .to_xdr_base64(Limits::none())
            .unwrap();
        Mock::given(method("POST")).respond_with(move |request: &wiremock::Request| {
            let request: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let result = match request["method"].as_str().unwrap() {
                "getNetwork" => stellar_agent_test_support::signed_envelope::get_network_result(TESTNET_PASSPHRASE),
                "getLatestLedger" => serde_json::json!({"id": "ab".repeat(32), "sequence": 101, "protocolVersion": 27}),
                "simulateTransaction" => serde_json::json!({
                    "latestLedger": 102, "minResourceFee": "100", "transactionData": "",
                    "results": [{"auth": [], "xdr": state}],
                }),
                method => panic!("unexpected fixture request {method}"),
            };
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0", "id": request["id"], "result": result,
            }))
        }).mount(&endpoint).await;
        let primary = endpoint.uri();
        let secondary = stellar_agent_test_support::second_loopback_host(&primary);
        let profile =
            Profile::builder_testnet_named("intent", "view", "account", "view-nonce", "account")
                .with_noop_engine()
                .rpc_url(primary.clone())
                .secondary_rpc_url(secondary.clone())
                .build();
        let profiles = stellar_agent_core::profile::loader::default_profile_dir().unwrap();
        std::fs::create_dir_all(&profiles).unwrap();
        let stored = format!(
            "version = 2\nchain_id = \"stellar:testnet\"\nrpc_url = {primary:?}\nsecondary_rpc_url = {secondary:?}\n"
        );
        let profile_path = profiles.join("intent.toml");
        std::fs::write(&profile_path, &stored).unwrap();
        let store = PersistedWindowStore::for_profile("intent");
        let schedule = mode == "done" || mode == "unset";
        let host = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
            function_name: ScSymbol::try_from(if schedule {
                "schedule"
            } else if mode == "unclassified" {
                "approve"
            } else {
                "call"
            })
            .unwrap(),
            args: Default::default(),
        });
        let source = stellar_strkey::ed25519::PublicKey([0; 32])
            .to_string()
            .to_string();
        let timelock = stellar_strkey::Contract([1; 32]).to_string().to_string();
        let (fixture, _) = crate::signed_intent::test_helpers::intent_fixture_plan(1, 60);
        let plan = crate::SignedIntentPlan::new(
            TESTNET_PASSPHRASE,
            &source,
            &source,
            1,
            crate::intent_xdr_hash(&host).unwrap(),
            vec![],
            None,
        )
        .unwrap()
        .with_envelope_max_ledger(100)
        .unwrap()
        .classify_purpose(&host, schedule.then_some((timelock.as_str(), [8; 32])))
        .unwrap();
        let plan = crate::signed_intent::test_helpers::with_legs(&plan, fixture.legs());
        let exposure = store.admit_signed_intent(&profile, &plan).unwrap().expose();
        assert!(exposure.intent_id().is_some());
        clock.set(2000);
        if mode != "unclassified" {
            store.observe_before_policy(&profile).await;
        }
        let expected_requests = if schedule {
            6
        } else if mode == "invoke" {
            4
        } else {
            0
        };
        assert_eq!(
            endpoint.received_requests().await.unwrap().len(),
            expected_requests
        );

        let before = std::fs::read(store.path()).unwrap();
        let key = &profile.policy_window_state_key_id;
        let hmac = keyring_core::Entry::new(&key.service, &key.account).unwrap();
        let generation = keyring_core::Entry::new(
            &key.service,
            &stellar_agent_core::profile::schema::generation_account(&key.account),
        )
        .unwrap();
        let key_before = hmac.get_password().unwrap();
        let generation_before = generation.get_password().unwrap();
        #[cfg(feature = "test-hooks")]
        let clients_before = crate::client::constructions_on_this_thread();
        clock.set(2000 + RETENTION + 1);
        Self {
            profile,
            store,
            mode,
            profile_path,
            primary,
            stored,
            timelock,
            before,
            hmac,
            generation,
            key_before,
            generation_before,
            #[cfg(feature = "test-hooks")]
            clients_before,
            endpoint,
            expected_requests,
            _clock: clock,
            _home,
            _dir: dir,
        }
    }

    /// Writes the selected stored endpoint configuration.
    ///
    /// # Panics
    /// Panics if the fixture profile cannot be written.
    pub fn set_endpoints(&self, state: &str) {
        let text = match state {
            "missing" => format!(
                "version = 2\nchain_id = \"stellar:testnet\"\nrpc_url = {:?}\n",
                self.primary
            ),
            "unreadable" => "invalid profile".into(),
            _ => self.stored.clone(),
        };
        std::fs::write(&self.profile_path, text).unwrap();
    }

    /// Checks the common horizon fields of the surface's intent array.
    ///
    /// # Panics
    /// Panics if the surface omits or changes an authenticated field.
    pub fn assert_view(&self, value: &serde_json::Value, endpoint_state: &str) {
        let mode = self.mode;
        let schedule = mode == "done" || mode == "unset";
        let intents = value.as_array().unwrap();
        assert_eq!(intents.len(), 1, "{value}");
        let intent = &intents[0];
        assert_eq!(intent["greatest_expiration_ledger"], 100);
        assert_eq!(intent["admitted_at_ms"], 1000);
        assert_eq!(intent["legs"].as_array().unwrap().len(), 2);
        assert_eq!(
            intent["status"],
            "authorization exposed, submission unknown"
        );
        if mode == "unclassified" {
            assert_eq!(intent["accounting_horizon"], "open");
            assert!(intent["expiry_observed_at_ms"].is_null());
            assert!(intent["retained_until_ms"].is_null());
            assert!(intent["purpose"].is_null());
            assert!(intent["schedule_terminal"].is_null());
        } else {
            assert_eq!(intent["accounting_horizon"], "62000");
            assert_eq!(intent["expiry_observed_at_ms"], 2000);
            assert_eq!(intent["retained_until_ms"], 2000 + RETENTION);
            if schedule {
                assert_eq!(
                    intent["purpose"],
                    serde_json::json!({"TimelockSchedule": {"timelock": self.timelock, "operation_id": "08".repeat(32)}})
                );
                assert_eq!(intent["schedule_terminal"], mode);
            } else {
                assert_eq!(intent["purpose"], "Invoke");
                assert!(intent["schedule_terminal"].is_null());
            }
        }
        let mut explanations = Vec::new();
        if mode == "unclassified" {
            explanations.push(PERMANENT);
        }
        if mode == "unclassified" {
            match endpoint_state {
                "missing" => explanations.push(SECONDARY),
                "unreadable" => explanations.push(UNREADABLE),
                _ => {}
            }
        }
        assert_eq!(
            intent["reset_explanations"],
            serde_json::json!(explanations)
        );
    }

    /// Checks that listing preserves store bytes and shared resources.
    ///
    /// # Panics
    /// Panics if listing mutates state or starts a client or request.
    pub async fn assert_unchanged(&self) {
        assert_eq!(std::fs::read(self.store.path()).unwrap(), self.before);
        self.assert_resources_unchanged().await;
    }

    /// Checks keyring values and network activity without reading store bytes.
    ///
    /// # Panics
    /// Panics if listing mutates a key or starts a client or request.
    pub async fn assert_resources_unchanged(&self) {
        assert_eq!(
            self.generation.get_password().unwrap(),
            self.generation_before
        );
        assert_eq!(self.hmac.get_password().unwrap(), self.key_before);
        #[cfg(feature = "test-hooks")]
        assert_eq!(
            crate::client::constructions_on_this_thread(),
            self.clients_before
        );
        assert_eq!(
            self.endpoint.received_requests().await.unwrap().len(),
            self.expected_requests
        );
    }

    /// Corrupts or moves the authenticated store for refusal checks.
    ///
    /// # Panics
    /// Panics if the fixture store cannot be changed.
    pub fn damage_store(&self, missing: bool) {
        if missing {
            std::fs::rename(
                self.store.path(),
                self.store.path().with_extension("deleted"),
            )
            .unwrap();
        } else {
            let mut corrupt = self.before.clone();
            corrupt[0] ^= 1;
            std::fs::write(self.store.path(), corrupt).unwrap();
        }
    }
}

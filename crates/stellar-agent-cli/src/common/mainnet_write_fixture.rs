//! The mainnet write fixture of the CLI verb tests.
//!
//! A [`MainnetFixture`] isolates the data root, the profile selection and the
//! keyring in a temporary home. It saves a stored mainnet profile whose
//! primary and oracle records name two hosts of their own, carries the
//! profile through the enrollment ceremony with the public `profile`
//! runners, and routes the two hosts to two mocked endpoints through the
//! test route map of [`crate::common::mainnet_write`]. The keyring is a fresh
//! in-memory mock store that every keyring initialization keeps, so the
//! runners' own initialization and the verbs' initializer reach the same
//! entries. It is not a headless store, so the mainnet keyring-backend check
//! passes as it does on the platform keyring. The terminal check passes and the
//! confirmation answers the profile name unless a test says otherwise.
//!
//! Every test that builds a fixture is `#[serial]`: the data root, the
//! environment, the keyring store and the mainnet clock are process-global.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixture; a failed setup step fails the calling test loudly"
)]

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use clap::Parser as _;
use serde_json::Value;
use sha2::Digest as _;
use stellar_agent_core::approval::view::PendingApprovalView;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::loader::{self, ProfileLoadError};
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PolicyEngineKind, PrimaryProviderRecord, Profile, ProviderRecord,
    default_approval_dir, default_policy_dir, default_profile_dir,
};
use stellar_agent_network::policy_state::{OpenAuthorization, PersistedWindowStore};
use stellar_agent_network::{Signer, WebAuthnAssertion};
use stellar_agent_test_support::{ProfileEnvVarGuard, StellarAgentHomeGuard};
use wiremock::MockServer;

use crate::commands::profile::{
    enable_mainnet, enroll_owner_key, enroll_signer, rotate_attestation_key, rotate_audit_key,
    rotate_nonce_key, sign_policy,
};
use crate::common::mainnet_confirm::{ConfirmationInputGuard, set_confirmation_input};
use crate::common::mainnet_write::{TestRoutesGuard, set_test_routes};
use crate::common::signer_ceremony::{LedgerSignerFactoryGuard, set_ledger_signer_factory};
use crate::common::tty::tests::{TestTty, test_tty, tty_checks_on_this_thread};
use crate::test_rpc::{ClassicRpc, EnvSigner, methods};

/// The host of the profile's primary endpoint.
pub(crate) const PRIMARY_HOST: &str = "rpc.example.invalid";
/// The host of the profile's oracle endpoint.
pub(crate) const ORACLE_HOST: &str = "oracle.example.invalid";
/// The seed of the enrolled agent signer.
pub(crate) const AGENT_SEED: [u8; 32] = [0x41; 32];
/// The variable holding the agent seed for `--secret-env`.
pub(crate) const AGENT_VAR: &str = "STELLAR_AGENT_MAINNET_FIXTURE_AGENT_SK";
/// The seed of the enrolled policy owner.
const OWNER_SEED: [u8; 32] = [0x42; 32];
/// The variable holding the owner seed for the policy signature.
const OWNER_VAR: &str = "STELLAR_AGENT_MAINNET_FIXTURE_OWNER_SK";
/// The allowlisted payment destination.
pub(crate) const DESTINATION: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
/// The allowlisted account a sponsored create opens.
pub(crate) const NEW_ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
/// The mainnet issuer the wallet pins for USDC.
pub(crate) const ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// The pinned trustline asset.
pub(crate) const TRUSTLINE_ASSET: &str =
    "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// The native cross-check threshold, the 1000 XLM floor a signed threshold
/// may not undercut: the 1 XLM payment and the 2 XLM create stay below it.
pub(crate) const NATIVE_THRESHOLD_STROOPS: i64 = 10_000_000_000;

/// The minimal valid native-pay rule: one pinned asset, an allowlisted
/// destination, both caps and a rate limit, with `decision`.
pub(crate) fn pay_rule(decision: &str, extra: &str) -> String {
    format!(
        "[[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"stellar:mainnet\" }}\n\
         criteria = [\n\
         {{ kind = \"asset_allowlist\", assets = [\"native\"] }},\n\
         {{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{DESTINATION}\"] }},\n\
         {{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1000000000\" }},\n\
         {{ kind = \"per_period_cap\", window = \"1d\", asset = \"native\", max_stroops = \"10000000000\" }},\n\
         {{ kind = \"rate_limit\", window = \"1d\", max_calls = 100 }},\n\
         {extra}]\ndecision = \"{decision}\"\n{}",
        if decision == "require_approval" {
            "ttl_secs = 300\n"
        } else {
            ""
        }
    )
}

/// The native-pay rule with the amount cap and the call cap given.
pub(crate) fn pay_rule_capped(period_cap_stroops: i64, max_calls: u32) -> String {
    format!(
        "[[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"stellar:mainnet\" }}\n\
         criteria = [\n\
         {{ kind = \"asset_allowlist\", assets = [\"native\"] }},\n\
         {{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{DESTINATION}\"] }},\n\
         {{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1000000000\" }},\n\
         {{ kind = \"per_period_cap\", window = \"1d\", asset = \"native\", max_stroops = \"{period_cap_stroops}\" }},\n\
         {{ kind = \"rate_limit\", window = \"1d\", max_calls = {max_calls} }},\n\
         ]\ndecision = \"allow\"\n"
    )
}

/// The minimal valid sponsored-create rule, with `extra` criteria.
pub(crate) fn create_rule(extra: &str) -> String {
    format!(
        "[[rules]]\nmatch = {{ tool = \"stellar_create_account\", chain = \"stellar:mainnet\" }}\n\
         criteria = [\n\
         {{ kind = \"asset_allowlist\", assets = [\"native\"] }},\n\
         {{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{NEW_ACCOUNT}\"] }},\n\
         {{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1000000000\" }},\n\
         {{ kind = \"per_period_cap\", window = \"1d\", asset = \"native\", max_stroops = \"10000000000\" }},\n\
         {{ kind = \"rate_limit\", window = \"1d\", max_calls = 100 }},\n\
         {extra}]\ndecision = \"allow\"\n"
    )
}

/// The claim rule whose one window criterion is a rate limit, with `extra`
/// criteria.
pub(crate) fn claim_rule(extra: &str) -> String {
    format!(
        "[[rules]]\nmatch = {{ tool = \"stellar_claim\", chain = \"stellar:mainnet\" }}\n\
         criteria = [\n\
         {{ kind = \"rate_limit\", window = \"1d\", max_calls = 100 }},\n\
         {extra}]\ndecision = \"allow\"\n"
    )
}

/// The trustline rule pinning [`TRUSTLINE_ASSET`], with `extra` criteria.
pub(crate) fn trustline_rule(extra: &str) -> String {
    format!(
        "[[rules]]\nmatch = {{ tool = \"stellar_trustline\", chain = \"stellar:mainnet\" }}\n\
         criteria = [\n\
         {{ kind = \"asset_allowlist\", assets = [\"{TRUSTLINE_ASSET}\"] }},\n\
         {extra}]\ndecision = \"allow\"\n"
    )
}

/// A `minimum_reserve` criterion with `margin_stroops` above the protocol
/// reserve.
pub(crate) fn minimum_reserve(margin_stroops: i64) -> String {
    format!("{{ kind = \"minimum_reserve\", margin_stroops = {margin_stroops} }},\n")
}

/// How the fixture's profile and policy are set up.
pub(crate) struct Spec {
    name: &'static str,
    rules: Vec<String>,
    enable: bool,
    engine: PolicyEngineKind,
    profile_fee_cap: Option<u32>,
    signed_fee_cap: u32,
    authorization_ttl_seconds: i64,
    primary: Option<ClassicRpc>,
    oracle: Option<ClassicRpc>,
    testnet: bool,
}

impl Spec {
    /// The default fixture of the profile `name`: one allowing rule per verb,
    /// the full ceremony, a profile fee cap of 1000 stroops, a signed cap of
    /// 500, a 60-second authorization lifetime and the native threshold of
    /// [`NATIVE_THRESHOLD_STROOPS`].
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            rules: vec![
                pay_rule("allow", ""),
                create_rule(""),
                claim_rule(""),
                trustline_rule(""),
            ],
            enable: true,
            engine: PolicyEngineKind::V1,
            profile_fee_cap: Some(1000),
            signed_fee_cap: 500,
            authorization_ttl_seconds: 60,
            primary: None,
            oracle: None,
            testnet: false,
        }
    }

    /// A testnet profile reading through the primary endpoint at its own
    /// URL, with the ceremony up to the signed version 1 policy and every
    /// rule on `stellar:testnet`. The oracle endpoint is started and
    /// unused.
    pub(crate) fn testnet(mut self) -> Self {
        self.testnet = true;
        self.enable = false;
        self
    }

    /// Replaces the policy rules.
    pub(crate) fn rules(mut self, rules: Vec<String>) -> Self {
        self.rules = rules;
        self
    }

    /// Stops the ceremony before `profile enable-mainnet`, so the signed
    /// policy has no `[mainnet]` table.
    pub(crate) fn pre_enable(mut self) -> Self {
        self.enable = false;
        self
    }

    /// Saves the profile with the Noop engine and runs no ceremony.
    pub(crate) fn noop_engine(mut self) -> Self {
        self.engine = PolicyEngineKind::Noop;
        self
    }

    /// Sets the profile's classic fee cap per operation.
    pub(crate) fn profile_fee_cap(mut self, cap: Option<u32>) -> Self {
        self.profile_fee_cap = cap;
        self
    }

    /// Sets the signed `[mainnet]` fee cap per operation.
    pub(crate) fn signed_fee_cap(mut self, cap: u32) -> Self {
        self.signed_fee_cap = cap;
        self
    }

    /// Serves the primary endpoint with `rpc`.
    pub(crate) fn primary(mut self, rpc: ClassicRpc) -> Self {
        self.primary = Some(rpc);
        self
    }

    /// Serves the oracle endpoint with `rpc`.
    pub(crate) fn oracle(mut self, rpc: ClassicRpc) -> Self {
        self.oracle = Some(rpc);
        self
    }

    /// Sets up the fixture.
    pub(crate) async fn build(self) -> MainnetFixture {
        MainnetFixture::new(self).await
    }
}

/// Installs a fresh in-memory mock store and makes every keyring
/// initialization keep it until dropped, then reinstalls a fresh mock store
/// so no later test reaches this fixture's entries.
struct MockKeyringScope;

impl MockKeyringScope {
    fn set() -> Self {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        stellar_agent_network::keyring::KEEP_REGISTERED_STORE
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for MockKeyringScope {
    fn drop(&mut self) {
        stellar_agent_network::keyring::KEEP_REGISTERED_STORE
            .store(false, std::sync::atomic::Ordering::SeqCst);
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
    }
}

/// A stored mainnet profile after the enrollment ceremony, with its primary
/// and oracle hosts routed to mocked endpoints.
pub(crate) struct MainnetFixture {
    /// The profile name.
    pub(crate) name: &'static str,
    /// The enrolled agent signer; its seed is in [`AGENT_VAR`].
    pub(crate) agent: EnvSigner,
    /// The primary endpoint.
    pub(crate) primary: MockServer,
    /// The oracle endpoint.
    pub(crate) oracle: MockServer,
    calls: Rc<Cell<usize>>,
    prompts: Rc<RefCell<Vec<String>>>,
    confirmation: Option<ConfirmationInputGuard>,
    tty: Option<TestTty>,
    tty_checks_at_start: u64,
    _routes: TestRoutesGuard,
    _owner: EnvSigner,
    _keyring: MockKeyringScope,
    _profile_var: ProfileEnvVarGuard,
    _home: StellarAgentHomeGuard,
    _dir: tempfile::TempDir,
}

/// Fails the fixture when a ceremony runner exited non-zero, with what it
/// rendered.
fn require_runner(step: &str, code: i32) {
    let rendered = crate::common::render::take_rendered_for_test();
    assert_eq!(code, 0, "{step} failed: {rendered:?}");
}

impl MainnetFixture {
    async fn new(mut spec: Spec) -> Self {
        crate::common::render::take_rendered_for_test();
        let home = tempfile::tempdir().unwrap();
        let home_guard = StellarAgentHomeGuard::new(home.path());
        let profile_var = ProfileEnvVarGuard::cleared();
        let keyring = MockKeyringScope::set();
        let agent = EnvSigner::new(AGENT_SEED, AGENT_VAR);
        let owner = EnvSigner::new(OWNER_SEED, OWNER_VAR);
        let name = spec.name;

        let primary_rpc = spec
            .primary
            .take()
            .unwrap_or_else(|| ClassicRpc::mainnet(&[&agent.g, DESTINATION, ISSUER]));
        let oracle_rpc = spec
            .oracle
            .take()
            .unwrap_or_else(|| ClassicRpc::mainnet(&[&agent.g, DESTINATION, ISSUER]));
        let primary = primary_rpc.serve().await;
        let oracle = oracle_rpc.serve().await;
        let routes =
            set_test_routes(&[(PRIMARY_HOST, &primary.uri()), (ORACLE_HOST, &oracle.uri())]);

        let signer = KeyringEntryRef::default_signer(name);
        let nonce = KeyringEntryRef::default_nonce(name);
        if spec.testnet {
            spec.rules = spec
                .rules
                .iter()
                .map(|rule| rule.replace("stellar:mainnet", "stellar:testnet"))
                .collect();
            let profile = Profile::builder_testnet_named(
                name,
                &signer.service,
                &signer.account,
                &nonce.service,
                &nonce.account,
            )
            .rpc_url(primary.uri())
            .audit_log_path(home.path().join("audit.jsonl"))
            .classic_max_fee_per_op_stroops(spec.profile_fee_cap)
            .policy_engine(PolicyEngineKind::V1)
            .build();
            loader::save_to_dir(name, &profile, &default_profile_dir().unwrap()).unwrap();
            Self::ceremony(&spec, &agent, &owner).await;
            return Self::assemble(
                name,
                agent,
                owner,
                primary,
                oracle,
                routes,
                keyring,
                profile_var,
                home_guard,
                home,
            );
        }
        let mut builder = Profile::builder_mainnet_named(
            name,
            format!("https://{PRIMARY_HOST}"),
            &signer.service,
            &signer.account,
            &nonce.service,
            &nonce.account,
        )
        .oracle_provider_url(url::Url::parse(&format!("https://{ORACLE_HOST}")).unwrap())
        .primary_provider(PrimaryProviderRecord::new(
            "Fixture primary operator",
            PRIMARY_HOST,
        ))
        .oracle_provider(ProviderRecord::new(
            "Fixture oracle operator",
            ORACLE_HOST,
            true,
        ))
        .audit_log_path(home.path().join("audit.jsonl"))
        .classic_max_fee_per_op_stroops(spec.profile_fee_cap)
        .policy_engine(spec.engine);
        if spec.engine == PolicyEngineKind::Noop {
            builder = builder.with_noop_engine();
        }
        let profile = builder.build();
        loader::save_to_dir(name, &profile, &default_profile_dir().unwrap()).unwrap();

        if spec.engine == PolicyEngineKind::V1 {
            Self::ceremony(&spec, &agent, &owner).await;
        }
        Self::assemble(
            name,
            agent,
            owner,
            primary,
            oracle,
            routes,
            keyring,
            profile_var,
            home_guard,
            home,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the guards are moved into the fixture in their drop order"
    )]
    fn assemble(
        name: &'static str,
        agent: EnvSigner,
        owner: EnvSigner,
        primary: MockServer,
        oracle: MockServer,
        routes: TestRoutesGuard,
        keyring: MockKeyringScope,
        profile_var: ProfileEnvVarGuard,
        home_guard: StellarAgentHomeGuard,
        home: tempfile::TempDir,
    ) -> Self {
        let calls = Rc::new(Cell::new(0));
        let prompts = Rc::new(RefCell::new(Vec::new()));
        let confirmation = Self::answering(&prompts, name.to_owned());
        Self {
            name,
            agent,
            primary,
            oracle,
            calls,
            prompts,
            confirmation: Some(confirmation),
            tty: Some(test_tty(true, true)),
            tty_checks_at_start: tty_checks_on_this_thread(),
            _routes: routes,
            _owner: owner,
            _keyring: keyring,
            _profile_var: profile_var,
            _home: home_guard,
            _dir: home,
        }
    }

    /// Runs the enrollment ceremony through the public runners.
    async fn ceremony(spec: &Spec, agent: &EnvSigner, owner: &EnvSigner) {
        let name = spec.name;
        let profile = Some(name.to_owned());
        require_runner(
            "rotate-audit-key",
            rotate_audit_key::run(&rotate_audit_key::RotateAuditKeyArgs {
                name: None,
                profile: profile.clone(),
            })
            .await,
        );
        require_runner(
            "enroll-signer",
            enroll_signer::run(&enroll_signer::EnrollSignerArgs {
                profile: profile.clone(),
                secret_env: Some(AGENT_VAR.to_owned()),
                expected_address: Some(agent.g.clone()),
                force: false,
                repair_identity: false,
            })
            .await,
        );
        require_runner(
            "rotate-nonce-key",
            rotate_nonce_key::run(&rotate_nonce_key::RotateNonceKeyArgs {
                name: None,
                profile: profile.clone(),
            })
            .await,
        );
        require_runner(
            "enroll-owner-key",
            enroll_owner_key::run(&enroll_owner_key::EnrollOwnerKeyArgs {
                profile: profile.clone(),
                secret_env: OWNER_VAR.to_owned(),
                expected_address: Some(owner.g.clone()),
                force: false,
            })
            .await,
        );
        require_runner(
            "rotate-attestation-key",
            rotate_attestation_key::run(&rotate_attestation_key::RotateAttestationKeyArgs {
                name: None,
                profile: profile.clone(),
            })
            .await,
        );

        let mut document = format!("version = 1\nscope = \"profile:{name}\"\n");
        for rule in &spec.rules {
            document.push('\n');
            document.push_str(rule);
        }
        let policy_path = Self::policy_path_of(name);
        std::fs::create_dir_all(policy_path.parent().unwrap()).unwrap();
        std::fs::write(&policy_path, document).unwrap();
        let sign = sign_policy::SignPolicyArgs {
            profile: profile.clone(),
            secret_env: OWNER_VAR.to_owned(),
            file: None,
        };
        require_runner("sign-policy", sign_policy::run(&sign).await);
        if !spec.enable {
            return;
        }

        #[derive(clap::Parser)]
        struct EnableMainnet {
            #[command(flatten)]
            args: enable_mainnet::EnableMainnetArgs,
        }
        let enable = EnableMainnet::try_parse_from(["enable-mainnet", "--profile", name]).unwrap();
        require_runner("enable-mainnet", enable_mainnet::run(&enable.args));

        let raw = std::fs::read_to_string(&policy_path).unwrap();
        let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
        doc.remove("signature");
        doc["mainnet"]["classic_max_fee_per_op_stroops"] =
            toml_edit::value(i64::from(spec.signed_fee_cap));
        doc["mainnet"]["authorization_ttl_seconds"] =
            toml_edit::value(spec.authorization_ttl_seconds);
        let mut thresholds = toml_edit::Table::new();
        thresholds.insert(
            "native",
            toml_edit::value(NATIVE_THRESHOLD_STROOPS.to_string()),
        );
        doc["mainnet"]["cross_check_thresholds"] = toml_edit::Item::Table(thresholds);
        let sequence = doc
            .get("sequence")
            .and_then(toml_edit::Item::as_integer)
            .unwrap_or(1);
        doc["sequence"] = toml_edit::value(sequence + 1);
        std::fs::write(&policy_path, doc.to_string()).unwrap();
        require_runner(
            "sign-policy after enable-mainnet",
            sign_policy::run(&sign).await,
        );
    }

    /// Installs a confirmation that records the prompt and answers `line`.
    fn answering(prompts: &Rc<RefCell<Vec<String>>>, line: String) -> ConfirmationInputGuard {
        let prompts = Rc::clone(prompts);
        set_confirmation_input(Box::new(move |prompt| {
            prompts.borrow_mut().push(prompt.to_owned());
            Ok(Some(line.clone()))
        }))
    }

    /// Answers every later confirmation through `input`; the prompts are
    /// still recorded.
    pub(crate) fn answer_with(
        &mut self,
        mut input: impl FnMut(&str) -> std::io::Result<Option<String>> + 'static,
    ) {
        let prompts = Rc::clone(&self.prompts);
        // The previous guard clears the input when it drops, so it goes
        // before the new input is set.
        self.confirmation = None;
        self.confirmation = Some(set_confirmation_input(Box::new(move |prompt| {
            prompts.borrow_mut().push(prompt.to_owned());
            input(prompt)
        })));
    }

    /// Reports `stdin` and `stderr` as the terminal state.
    pub(crate) fn terminal(&mut self, stdin: bool, stderr: bool) {
        // The previous guard restores the state it replaced when it drops,
        // so it goes before the new state is set.
        self.tty = None;
        self.tty = Some(test_tty(stdin, stderr));
    }

    /// The prompts the confirmation rendered, oldest first.
    pub(crate) fn prompts(&self) -> Vec<String> {
        self.prompts.borrow().clone()
    }

    /// How often the mainnet terminal check ran since the fixture was built.
    pub(crate) fn terminal_checks(&self) -> u64 {
        tty_checks_on_this_thread() - self.tty_checks_at_start
    }

    /// Fails unless the run neither checked the terminal nor rendered a
    /// prompt.
    pub(crate) fn assert_terminal_untouched(&self) {
        assert_eq!(self.terminal_checks(), 0, "the terminal is never checked");
        assert!(self.prompts().is_empty(), "the terminal is never asked");
    }

    fn policy_path_of(name: &str) -> PathBuf {
        default_policy_dir().unwrap().join(format!("{name}.toml"))
    }

    /// The signed policy file.
    pub(crate) fn policy_path(&self) -> PathBuf {
        Self::policy_path_of(self.name)
    }

    /// The profile loader the verbs' production `run` uses, over the
    /// fixture's profile directory.
    pub(crate) fn loader(&self) -> impl Fn(&str) -> Result<Profile, ProfileLoadError> + use<> {
        let dir = default_profile_dir().unwrap();
        move |name| loader::load_from_dir(name, &dir, None)
    }

    /// The keyring initializer the verbs' production `run` uses, counting its
    /// calls.
    pub(crate) fn initializer(&self) -> impl Fn() -> Result<(), WalletError> + use<> {
        let calls = Rc::clone(&self.calls);
        move || {
            calls.set(calls.get() + 1);
            stellar_agent_network::keyring::init_platform_keyring_store()
        }
    }

    /// How often the initializer of [`Self::initializer`] ran.
    pub(crate) fn initializer_calls(&self) -> usize {
        self.calls.get()
    }

    /// The stored profile.
    pub(crate) fn profile(&self) -> Profile {
        loader::load_from_dir(self.name, &default_profile_dir().unwrap(), None).unwrap()
    }

    /// Rewrites the stored profile's signer coordinate to the placeholder
    /// `profile init` writes, so the enrolled pin is unusable.
    pub(crate) fn unpin_signer(&self) {
        let mut profile = self.profile();
        profile.mcp_signer_default = KeyringEntryRef::default_signer(self.name);
        loader::save_to_dir(self.name, &profile, &default_profile_dir().unwrap()).unwrap();
    }

    /// Flips one hex digit of the policy signature.
    pub(crate) fn tamper_policy_signature(&self) {
        let raw = std::fs::read_to_string(self.policy_path()).unwrap();
        let start = raw.find("sig = \"").unwrap() + "sig = \"".len();
        let mut bytes = raw.into_bytes();
        bytes[start] = if bytes[start] == b'0' { b'1' } else { b'0' };
        std::fs::write(self.policy_path(), bytes).unwrap();
    }

    /// Deletes the keyring entry at `coordinate`.
    pub(crate) fn delete_keyring_entry(&self, coordinate: &KeyringEntryRef) {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .delete_credential()
            .unwrap();
    }

    /// The approval store file of the profile.
    pub(crate) fn approval_store_path(&self) -> PathBuf {
        default_approval_dir()
            .unwrap()
            .join(format!("{}.toml", self.name))
    }

    /// The entries of the profile's pending-approval store.
    pub(crate) fn pending_entries(&self) -> Vec<PendingApprovalView> {
        let path = self.approval_store_path();
        if !path.exists() {
            return Vec::new();
        }
        let store = open_with_retry(&path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF).unwrap();
        store.snapshot(stellar_agent_core::timefmt::now_unix_ms().unwrap())
    }

    /// The authorizations effective at `now_ms`.
    pub(crate) fn open_authorizations(&self, now_ms: u64) -> Vec<OpenAuthorization> {
        PersistedWindowStore::for_profile(self.name)
            .open_authorizations(&self.profile(), now_ms)
            .unwrap()
    }

    /// The number of submissions whose window rows are still pending, not
    /// settled against the network's answer.
    pub(crate) fn pending_reservations(&self) -> usize {
        PersistedWindowStore::for_profile(self.name)
            .pending_reservations(&self.profile())
            .unwrap()
            .len()
    }

    /// The window store file of the profile.
    pub(crate) fn window_path(&self) -> PathBuf {
        stellar_agent_core::profile::schema::default_policy_window_state_path_for(self.name)
    }

    /// The window store's JSON body after its 32-byte HMAC tag.
    pub(crate) fn window_body(&self) -> Value {
        let bytes = std::fs::read(self.window_path()).unwrap();
        serde_json::from_slice(&bytes[32..]).unwrap()
    }

    /// The audit rows of `kind`, oldest first.
    pub(crate) fn audit_rows(&self, kind: &str) -> Vec<Value> {
        crate::test_rpc::audit_rows(&self.profile(), kind)
    }

    /// The JSON-RPC methods the primary received.
    pub(crate) async fn primary_methods(&self) -> Vec<String> {
        methods(&self.primary).await
    }

    /// The JSON-RPC methods the oracle received.
    pub(crate) async fn oracle_methods(&self) -> Vec<String> {
        methods(&self.oracle).await
    }

    /// The envelopes the primary was asked to send, base64.
    pub(crate) async fn sent_envelopes(&self) -> Vec<String> {
        self.primary
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| serde_json::from_slice::<Value>(&request.body).unwrap())
            .filter(|body| body["method"] == "sendTransaction")
            .map(|body| body["params"]["transaction"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Asserts that `envelope` carries exactly one signature, verifying
    /// under the enrolled agent key over the mainnet payload.
    pub(crate) fn assert_signed_by_agent(&self, envelope: &str) {
        use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
        let TransactionEnvelope::Tx(v1) =
            TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
        else {
            panic!("not a v1 envelope");
        };
        assert_eq!(v1.signatures.len(), 1, "one signature");
        let payload = stellar_xdr::TransactionSignaturePayload {
            network_id: stellar_xdr::Hash(
                sha2::Sha256::digest(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE).into(),
            ),
            tagged_transaction: stellar_xdr::TransactionSignaturePayloadTaggedTransaction::Tx(
                v1.tx.clone(),
            ),
        };
        let digest: [u8; 32] = sha2::Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into();
        let key = ed25519_dalek::SigningKey::from_bytes(&AGENT_SEED).verifying_key();
        let signature =
            ed25519_dalek::Signature::from_slice(v1.signatures[0].signature.0.as_slice()).unwrap();
        use ed25519_dalek::Verifier as _;
        key.verify(&digest, &signature).unwrap();
        assert_eq!(
            v1.signatures[0].hint.0,
            key.as_bytes()[28..32],
            "the hint is the agent key's"
        );
    }
}

/// The calls a [`LedgerDouble`] received, in order.
pub(crate) type LedgerCalls = Arc<Mutex<Vec<&'static str>>>;

/// Runs inside the double's transaction signing call, before it signs.
pub(crate) type BeforeSign = Arc<dyn Fn() -> Result<(), WalletError> + Send + Sync>;

/// A Ledger in place of the device, holding the agent key.
///
/// Its constructor runs the test's `construct` hook, which may refuse with a
/// device error, and records `construct`; its public key is the agent key;
/// its transaction signing call records `sign_tx_payload`, runs the test's
/// `before_sign` hook, which may refuse, and signs with the agent key.
struct LedgerDouble {
    key: ed25519_dalek::SigningKey,
    calls: LedgerCalls,
    before_sign: BeforeSign,
}

#[async_trait::async_trait]
impl Signer for LedgerDouble {
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        self.calls.lock().unwrap().push("sign_tx_payload");
        (self.before_sign)()?;
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(payload).to_bytes())
    }

    async fn sign_auth_digest(&self, _digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        panic!("the classic verbs sign no auth digest")
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        _payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        panic!("the classic verbs sign no Soroban payload")
    }

    async fn sign_webauthn_assertion(
        &self,
        _auth_digest: &[u8; 32],
        _credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        panic!("the classic verbs sign no WebAuthn assertion")
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        self.calls.lock().unwrap().push("public_key");
        Ok(stellar_strkey::ed25519::PublicKey(
            self.key.verifying_key().to_bytes(),
        ))
    }
}

/// Makes the mainnet Ledger signer on this thread a [`LedgerDouble`] of the
/// agent key until the guard drops, and returns the guard with the double's
/// call record.
///
/// `construct` runs when the signer is constructed and refuses the
/// construction with its error; `before_sign` runs inside every transaction
/// signing call.
pub(crate) fn install_ledger_double(
    construct: impl Fn() -> Result<(), WalletError> + 'static,
    before_sign: impl Fn() -> Result<(), WalletError> + Send + Sync + 'static,
) -> (LedgerSignerFactoryGuard, LedgerCalls) {
    let calls: LedgerCalls = Arc::default();
    let before_sign: BeforeSign = Arc::new(before_sign);
    let record = Arc::clone(&calls);
    let guard = set_ledger_signer_factory(Rc::new(move |_account_index, _source| {
        record.lock().unwrap().push("construct");
        construct()?;
        Ok(Box::new(LedgerDouble {
            key: ed25519_dalek::SigningKey::from_bytes(&AGENT_SEED),
            calls: Arc::clone(&record),
            before_sign: Arc::clone(&before_sign),
        }) as Box<dyn Signer + Send + Sync>)
    }));
    (guard, calls)
}

/// The authorizations of the stored profile `name` effective at `now_ms`,
/// for a hook that runs while a verb holds the fixture.
pub(crate) fn open_authorizations_of(name: &str, now_ms: u64) -> Vec<OpenAuthorization> {
    let profile = loader::load_from_dir(name, &default_profile_dir().unwrap(), None).unwrap();
    PersistedWindowStore::for_profile(name)
        .open_authorizations(&profile, now_ms)
        .unwrap()
}

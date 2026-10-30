//! Test fixture: an enabled mainnet profile whose owner-signed policy admits
//! one WebAuthn approval credential, under a temporary `STELLAR_AGENT_HOME`.
//!
//! Compiled only under `#[cfg(test)]` or the `test-helpers` feature.
//! [`MainnetConsentFixture`] writes what the production loaders read: the
//! profile under `profiles/`, the owner public key, attestation key and
//! enablement nonce in the mock keyring, and a policy signed by a fixed owner
//! seed under `policies/`, pinned by a first load. Every consent it produces
//! runs the production path: a challenge from [`super::issue_mainnet_presence`],
//! an assertion from the test-support authenticator over that challenge, and
//! [`super::verify_mainnet_presence`]. Nothing here builds a verified value
//! directly.
//!
//! The fixture sets a process-wide environment variable and installs a fresh
//! mock keyring, so a test that uses it runs under `#[serial]`.

#![allow(
    clippy::expect_used,
    reason = "test fixture: a failed setup step is a bug in the calling test"
)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::Digest as _;
use stellar_agent_test_support::StellarAgentHomeGuard;
use stellar_agent_test_support::webauthn::{
    FLAG_UP, FLAG_UV, TestAssertion, TestAuthenticator, fixture_authenticator,
};

use super::AssertionInput;
use super::attest::{ConsentAudit, ConsentAuthorization, Surface, attest_and_persist};
use super::attestation::AttestationBinding;
use super::presence::{
    PendingMainnetPresence, VerifiedMainnetPresence, issue_mainnet_presence,
    mainnet_presence_origin, verify_mainnet_presence,
};
use super::presence_policy::MainnetApprovalAuthority;
use super::store::{PendingApproval, PendingApprovalStore};
use crate::audit_log::writer::AuditWriter;
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::profile::schema::{KeyringEntryRef, Profile};

/// The endpoint host the fixture profile and policy name.
pub const ENDPOINT_HOST: &str = "rpc.example.invalid";

/// The listener port of the fixture's expected origin.
pub const ORIGIN_PORT: u16 = 4100;

/// The fixed attestation key the fixture stores.
pub const ATTESTATION_KEY: [u8; 32] = [0x5a; 32];

/// The owner seed that signs the fixture's policies.
const OWNER_SEED: [u8; 32] = [11; 32];

/// The enablement nonce of the fixture installation.
pub const ENABLEMENT_NONCE: &str = "mainnet-consent-fixture-nonce";

/// The account the fixture policy allows payments to.
pub const ALLOWED_DESTINATION: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// An enabled mainnet profile with a signed policy, under a temporary home.
pub struct MainnetConsentFixture {
    home: tempfile::TempDir,
    _guard: StellarAgentHomeGuard,
    name: String,
    profile: Profile,
    owner: ed25519_dalek::SigningKey,
    sequence: i64,
}

impl std::fmt::Debug for MainnetConsentFixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetConsentFixture")
            .field("name", &self.name)
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

fn put(entry: &KeyringEntryRef, text: &str) {
    keyring_core::Entry::new(&entry.service, &entry.account)
        .expect("keyring entry")
        .set_password(text)
        .expect("keyring write");
}

/// The unsigned version 2 policy body of the mainnet profile `name` at
/// `sequence`, bound to `endpoint_host` and the digest of
/// [`ENABLEMENT_NONCE`], admitting `credentials` as approval credentials,
/// with one require-approval payment rule to [`ALLOWED_DESTINATION`].
#[must_use]
pub fn policy_body_for(
    name: &str,
    endpoint_host: &str,
    sequence: i64,
    credentials: &[&TestAuthenticator],
) -> String {
    let digest = crate::hex::encode(&sha2::Sha256::digest(ENABLEMENT_NONCE.as_bytes()));
    let entries: String = credentials
        .iter()
        .map(|credential| {
            format!(
                "    {{ credential_id_b64url = \"{}\", public_key_sec1_b64url = \"{}\" }},\n",
                credential.credential_id_b64url(),
                credential.public_key_sec1_b64url()
            )
        })
        .collect();
    let rules = [
        "[[rules]]".to_owned(),
        "match = { tool = \"stellar_pay\", chain = \"stellar:mainnet\" }".to_owned(),
        "criteria = [".to_owned(),
        "    { kind = \"asset_allowlist\", assets = [\"native\"] },".to_owned(),
        format!(
            "    {{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{ALLOWED_DESTINATION}\"] }},"
        ),
        "    { kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"100\" },".to_owned(),
        "    { kind = \"per_period_cap\", window = \"1d\", asset = \"native\", max_stroops = \"200\" },"
            .to_owned(),
        "    { kind = \"rate_limit\", window = \"1d\", max_calls = 10 },".to_owned(),
        "]".to_owned(),
        "decision = \"require_approval\"".to_owned(),
        "allow_opaque_signing = false".to_owned(),
        "ttl_secs = 3600".to_owned(),
    ]
    .join("\n");
    format!(
        "version = 2\nscope = \"profile:{name}\"\nsequence = {sequence}\n\n[mainnet]\n\
         endpoint_host = \"{endpoint_host}\"\nprofile = \"{name}\"\n\
         installation_nonce_sha256 = \"{digest}\"\n\
         classic_max_fee_per_op_stroops = 500\nauthorization_ttl_seconds = 60\n\
         approval_credentials = [\n{entries}]\n\
         [mainnet.cross_check_thresholds]\nnative = \"10000000000\"\n\n{rules}\n"
    )
}

/// `body` signed by `owner`, as the policy file holds it.
///
/// # Panics
///
/// Panics when `body` has no canonical form.
#[must_use]
pub fn signed_policy_text(body: &str, owner: &ed25519_dalek::SigningKey) -> String {
    use crate::policy::v1::{canonical, signature};
    let canonical = canonical::canonical_bytes(body).expect("canonical fixture policy");
    let sig = signature::sign(&signature::digest(&canonical), owner);
    format!(
        "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
        crate::hex::encode(&sig)
    )
}

impl MainnetConsentFixture {
    /// An enabled mainnet profile `name` whose policy at sequence 1 admits
    /// the test-support fixture credential.
    ///
    /// # Panics
    ///
    /// Panics when a setup step fails.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self::with_profile(name, |_| {})
    }

    /// [`Self::new`] with `edit` applied to the profile before it is saved.
    ///
    /// # Panics
    ///
    /// Panics when a setup step fails.
    #[must_use]
    pub fn with_profile(name: &str, edit: impl FnOnce(&mut Profile)) -> Self {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let home = tempfile::TempDir::new().expect("temporary home");
        let guard = StellarAgentHomeGuard::new(home.path());
        let mut profile = Profile::builder_mainnet_named(
            name,
            format!("https://{ENDPOINT_HOST}"),
            &format!("stellar-agent-signer-{name}"),
            "default",
            &format!("stellar-agent-nonce-{name}"),
            "default",
        )
        .build();
        profile.audit_log_path = home.path().join("audit").join(format!("{name}.jsonl"));
        edit(&mut profile);
        let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
        put(
            &profile.policy_owner_key_id,
            &stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string(),
        );
        put(
            &profile.attestation_key_id,
            &URL_SAFE_NO_PAD.encode(ATTESTATION_KEY),
        );
        crate::profile::loader::save_to_dir(name, &profile, &home.path().join("profiles"))
            .expect("save fixture profile");
        let mut fixture = Self {
            home,
            _guard: guard,
            name: name.to_owned(),
            profile,
            owner,
            sequence: 0,
        };
        fixture.sign_policy(&[&fixture_authenticator()]);
        let path = fixture.policy_path();
        let window = crate::profile::schema::default_policy_window_state_path_for(name);
        std::fs::create_dir_all(window.parent().expect("window directory"))
            .expect("create window directory");
        crate::policy::v1::verified::load_verified_policy(
            &crate::policy::v1::verified::PolicyLoad {
                path: &path,
                profile: &fixture.profile,
                profile_name: name,
                owner_pubkey: &fixture.owner.verifying_key().to_bytes(),
                owner_source: crate::policy::v1::verified::OwnerKeySource::Keyring,
                window_path: &window,
            },
            crate::policy::v1::PolicyStateStore::new(),
            crate::policy::v1::verified::PinMode::Advance,
        )
        .expect("first policy load pins the fixture policy");
        put(
            &crate::profile::schema::mainnet_enablement_entry_ref(
                &fixture.profile.policy_window_state_key_id,
            ),
            ENABLEMENT_NONCE,
        );
        fixture
    }

    /// The temporary `STELLAR_AGENT_HOME`.
    #[must_use]
    pub fn home(&self) -> &Path {
        self.home.path()
    }

    /// The profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The persisted profile.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The signed sequence of the current policy file.
    #[must_use]
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// The binding of the fixture profile on mainnet.
    #[must_use]
    pub fn binding(&self) -> AttestationBinding<'_> {
        AttestationBinding::new(&self.name, super::presence::MAINNET_CHAIN_ID)
    }

    /// The expected origin of the fixture's ceremonies.
    #[must_use]
    pub fn origin() -> String {
        mainnet_presence_origin(ORIGIN_PORT)
    }

    /// The pending store path of the fixture profile.
    #[must_use]
    pub fn store_path(&self) -> PathBuf {
        self.home
            .path()
            .join("approvals")
            .join(format!("{}.toml", self.name))
    }

    /// The signed policy file path.
    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.home
            .path()
            .join("policies")
            .join(format!("{}.toml", self.name))
    }

    /// The audit log path of the fixture profile.
    #[must_use]
    pub fn audit_path(&self) -> PathBuf {
        self.profile.audit_log_path.clone()
    }

    /// A writer over the fixture's audit log.
    ///
    /// # Panics
    ///
    /// Panics when the log cannot be opened.
    #[must_use]
    pub fn audit_writer(&self) -> AuditWriter {
        AuditWriter::open(self.audit_path(), None).expect("fixture audit writer")
    }

    /// The approval authority of the fixture profile.
    ///
    /// # Panics
    ///
    /// Panics when the name is refused, which no fixture name is.
    #[must_use]
    pub fn authority(&self) -> MainnetApprovalAuthority {
        MainnetApprovalAuthority::for_profile(&self.name).expect("fixture profile name")
    }

    /// The current verified policy, loaded as a challenge issuer loads it.
    ///
    /// # Panics
    ///
    /// Panics when the policy does not load.
    #[must_use]
    pub fn current_policy(&self) -> VerifiedPolicy {
        self.authority()
            .load_current()
            .expect("fixture policy loads")
            .into_policy()
    }

    /// The unsigned policy body at `sequence` admitting `credentials`.
    #[must_use]
    pub fn policy_body(&self, sequence: i64, credentials: &[&TestAuthenticator]) -> String {
        policy_body_for(&self.name, ENDPOINT_HOST, sequence, credentials)
    }

    /// Signs `body` with the fixture owner and writes it as the policy file.
    ///
    /// # Panics
    ///
    /// Panics when `body` has no canonical form or the file cannot be written.
    pub fn write_signed(&self, body: &str) {
        self.write_signed_by(body, &self.owner);
    }

    /// Signs `body` with `owner` and writes it as the policy file.
    ///
    /// # Panics
    ///
    /// Panics when `body` has no canonical form or the file cannot be written.
    pub fn write_signed_by(&self, body: &str, owner: &ed25519_dalek::SigningKey) {
        let path = self.policy_path();
        std::fs::create_dir_all(path.parent().expect("policy directory"))
            .expect("create policy directory");
        std::fs::write(&path, signed_policy_text(body, owner)).expect("write fixture policy");
    }

    /// Signs a policy at the next sequence that admits `credentials` and
    /// writes it.
    pub fn sign_policy(&mut self, credentials: &[&TestAuthenticator]) {
        self.sequence += 1;
        let body = self.policy_body(self.sequence, credentials);
        self.write_signed(&body);
    }

    /// An unattested payment of 10 stroops to [`ALLOWED_DESTINATION`] that
    /// lives `ttl_ms` from now.
    ///
    /// # Panics
    ///
    /// Panics when the process UID cannot be read.
    #[must_use]
    pub fn payment(&self, ttl_ms: u64) -> PendingApproval {
        let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
        super::fixtures::payment_pending(
            &source,
            ALLOWED_DESTINATION,
            "XLM",
            10,
            Some("approved"),
            100,
            7,
            super::process_uid_for_attestation().expect("process uid"),
            ttl_ms,
        )
    }

    /// A challenge for `entry` under `policy`, issued now at the fixture
    /// origin.
    ///
    /// # Panics
    ///
    /// Panics when the issuer refuses.
    #[must_use]
    pub fn challenge(
        &self,
        entry: &PendingApproval,
        policy: &VerifiedPolicy,
    ) -> PendingMainnetPresence {
        let now_ms = crate::timefmt::now_unix_ms().expect("clock");
        issue_mainnet_presence(
            entry,
            &self.binding(),
            policy,
            &Self::origin(),
            now_ms,
            Instant::now(),
        )
        .expect("issue a challenge")
    }

    /// The challenge bytes `pending` asks the authenticator to sign.
    ///
    /// # Panics
    ///
    /// Panics when the options carry no canonical challenge.
    #[must_use]
    pub fn challenge_bytes(pending: &PendingMainnetPresence) -> [u8; 32] {
        URL_SAFE_NO_PAD
            .decode(pending.options().challenge)
            .expect("canonical challenge")
            .try_into()
            .expect("32-byte challenge")
    }

    /// `authenticator`'s assertion with UP and UV over `pending`'s challenge
    /// at the fixture origin.
    #[must_use]
    pub fn sign(
        authenticator: &TestAuthenticator,
        pending: &PendingMainnetPresence,
    ) -> TestAssertion {
        authenticator.assert(
            Self::challenge_bytes(pending),
            &Self::origin(),
            super::presence::MAINNET_APPROVAL_RP_ID,
            FLAG_UP | FLAG_UV,
            1,
        )
    }

    /// The assertion input of a test assertion.
    ///
    /// # Panics
    ///
    /// Panics when the assertion's signature is not a valid compact
    /// signature.
    #[must_use]
    pub fn input(assertion: &TestAssertion) -> AssertionInput {
        AssertionInput::new(
            assertion.credential_id.clone(),
            assertion.authenticator_data.clone(),
            assertion.client_data_json.clone(),
            assertion.signature_compact.clone(),
        )
        .expect("assertion input")
    }

    /// A verified presence for `entry` under `policy`, signed by
    /// `authenticator`: issue, sign, verify.
    ///
    /// # Panics
    ///
    /// Panics when any step refuses.
    #[must_use]
    pub fn presence_by(
        &self,
        entry: &PendingApproval,
        policy: &VerifiedPolicy,
        authenticator: &TestAuthenticator,
    ) -> VerifiedMainnetPresence {
        let pending = self.challenge(entry, policy);
        let assertion = Self::sign(authenticator, &pending);
        verify_mainnet_presence(
            pending,
            Self::input(&assertion),
            crate::timefmt::now_unix_ms().expect("clock"),
            Instant::now(),
        )
        .expect("verified presence")
    }

    /// [`Self::presence_by`] with the fixture credential.
    #[must_use]
    pub fn presence(
        &self,
        entry: &PendingApproval,
        policy: &VerifiedPolicy,
    ) -> VerifiedMainnetPresence {
        self.presence_by(entry, policy, &fixture_authenticator())
    }

    /// Inserts `entry` into the fixture store, consents to it through the
    /// production attester with a verified presence under the current
    /// policy, and returns the store and the surfaced attestation.
    ///
    /// # Panics
    ///
    /// Panics when any step refuses.
    #[must_use]
    pub fn consent(&self, entry: &PendingApproval) -> (PendingApprovalStore, Option<String>) {
        let mut store = PendingApprovalStore::open(self.store_path()).expect("fixture store");
        store
            .insert(entry.clone(), crate::timefmt::now_unix_ms().expect("clock"))
            .expect("insert entry");
        let policy = self.current_policy();
        let presence = self.presence(entry, &policy);
        let mut writer = self.audit_writer();
        let surfaced = attest_and_persist(
            &mut store,
            entry,
            &ATTESTATION_KEY,
            &self.binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            },
            |_, _| Err("no toolset grant in a mainnet consent".to_owned()),
        )
        .expect("mainnet consent");
        (store, surfaced)
    }
}

//! Mainnet authorizations over directly assembled facts, and a mainnet
//! profile with its ledger, receipt store, and keyed audit writer, for this
//! crate's tests of the paths that consume them.
//!
//! The authorization types have no constructor outside this crate's
//! resolvers, so these tests assemble the header themselves. A ledger-backed
//! authorization is minted through
//! [`crate::policy_state::PersistedWindowStore::mint_authorization`] and its
//! header carries the minted identity, lifetime, reservation, and bindings
//! digest, so its consumption is the production one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures; a failed setup is a failed test"
)]

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::audit_log::PolicyDecision;
use stellar_agent_core::audit_log::tip_anchor::{
    InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore,
};
use stellar_agent_core::audit_log::writer::VerifiedTipFacts;
use stellar_agent_core::policy::pin::{self, Pin, PinScope};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::caip2::{Caip2, MAINNET_PASSPHRASE};
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_test_support::signed_envelope::SignedTestEnvelope;
use tempfile::TempDir;

use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

use super::audit_readiness::AuditReadiness;
use super::authorization::{
    ApprovalBinding, EndpointBinding, Header, MainnetTxSignAuthorization, PolicyBinding,
    SignerBinding, TxSignInner,
};
use super::clock::{TestClockGuard, set_now_ms_for_test};
use super::digest::{BindingFacts, approval_subject_classic};
use super::{AuthorizationDomain, AuthorizationId, MainnetConsumer, SignerRole};
use crate::policy_state::{DomainBinding, MintRequest, PersistedWindowStore};
use crate::submission_record::{AuditWriterHandle, SubmissionIntent, WalletSubmissionRecorder};
use crate::submit::envelope_hash_hex;

/// The seed of the source account and agent signer every fixture uses.
pub(crate) const SIGNER_SEED: [u8; 32] = [0x2a; 32];

/// The sequence every fixture transaction consumes.
pub(crate) const SEQUENCE: i64 = 42;

/// The policy the fixtures pin and bind.
const POLICY_SEQUENCE: i64 = 7;
const POLICY_DIGEST: [u8; 32] = [0x71; 32];
const POLICY_OWNER: [u8; 32] = [0x01; 32];

/// The authorization lifetime and approval window, in milliseconds.
pub(crate) const TTL_MS: u64 = 60_000;
const APPROVAL_WINDOW_MS: u64 = 600_000;

/// The public key of `seed`.
pub(crate) fn public_key(seed: [u8; 32]) -> [u8; 32] {
    stellar_agent_test_support::signed_envelope::public_key_for_seed(seed)
}

/// The G-strkey of `seed`.
pub(crate) fn account(seed: [u8; 32]) -> String {
    stellar_agent_test_support::signed_envelope::account_id_for_seed(seed)
}

/// A keyed, anchored audit writer over a fresh log at `path`, with the
/// in-memory anchor store it writes to.
pub(crate) fn keyed_writer(
    path: &std::path::Path,
) -> (AuditWriterHandle, Arc<InMemoryTipAnchorStore>) {
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let access = KeyedAuditAccess::new(
        zeroize::Zeroizing::new([0x5c; 32]),
        Arc::clone(&store) as Arc<dyn TipAnchorStore>,
    );
    let writer = AuditWriter::open(path.to_path_buf(), Some(access)).unwrap();
    (Arc::new(Mutex::new(writer)), store)
}

/// The verified facts of `writer`'s tip.
pub(crate) fn tip_facts(writer: &AuditWriterHandle) -> VerifiedTipFacts {
    writer.lock().unwrap().verified_tip_facts().unwrap()
}

/// The facts a transaction authorization binds about its envelope.
pub(crate) fn tx_binding(unsigned_xdr: &str, tx_hash_hex: &str) -> DomainBinding {
    DomainBinding::Transaction {
        unsigned_envelope_sha256: approval_subject_classic(unsigned_xdr),
        tx_hash: stellar_agent_core::hex::decode_hex32(tx_hash_hex).unwrap(),
        source: account(SIGNER_SEED),
        sequence: SEQUENCE,
    }
}

/// A header with every fact valid at `now`: the mainnet chain, the
/// `CliPay` consumer, `endpoint`, the fixture's agent signer, an audit proof
/// over `facts` of `writer`, issued at `now` and expiring after [`TTL_MS`].
pub(crate) fn header(
    profile: &str,
    endpoint: Option<(String, u64)>,
    writer: &AuditWriterHandle,
    facts: VerifiedTipFacts,
    now: u64,
) -> Header {
    Header {
        id: AuthorizationId::from_bytes([0xab; 32]),
        profile: profile.to_owned(),
        chain: Caip2::Mainnet,
        domain: AuthorizationDomain::Transaction,
        consumer: MainnetConsumer::CliPay,
        endpoint: endpoint.map(|(authority, client_id)| EndpointBinding {
            authority,
            client_id,
        }),
        signer: SignerBinding {
            public_key: public_key(SIGNER_SEED),
            role: SignerRole::AgentSigner,
        },
        policy: PolicyBinding {
            sequence: POLICY_SEQUENCE,
            digest: POLICY_DIGEST,
        },
        enablement_nonce_digest: [3; 32],
        approval: ApprovalBinding {
            nonce: "fixture-approval".to_owned(),
            expires_at_ms: now + APPROVAL_WINDOW_MS,
        },
        reservation: None,
        witness_subject: None,
        audit: AuditReadiness::for_crate_tests(profile, facts, now, Arc::clone(writer)),
        issued_at_ms: now,
        expires_at_ms: now + TTL_MS,
        bindings_digest: [0; 32],
    }
}

/// A transaction authorization over `header` and `binding`.
pub(crate) fn tx_authorization(
    header: Header,
    binding: DomainBinding,
) -> MainnetTxSignAuthorization {
    MainnetTxSignAuthorization::for_crate_tests(TxSignInner {
        header,
        binding,
        entries: vec![],
    })
}

/// An unsigned mainnet transaction envelope from the fixture's source.
pub(crate) fn unsigned_envelope() -> SignedTestEnvelope {
    SignedTestEnvelope::builder(SIGNER_SEED)
        .network_passphrase(MAINNET_PASSPHRASE)
        .sequence(SEQUENCE)
        .unsigned()
        .build()
}

/// A mainnet transaction envelope signed by the fixture's source.
pub(crate) fn signed_envelope() -> SignedTestEnvelope {
    SignedTestEnvelope::builder(SIGNER_SEED)
        .network_passphrase(MAINNET_PASSPHRASE)
        .sequence(SEQUENCE)
        .build()
}

/// One window entry of `amount` stroops for `profile`, dated `now`.
pub(crate) fn hold(profile: &str, now: u64, amount: i128) -> WindowEntry {
    WindowEntry::new(
        StateKey::new(profile, 1, "native", 86_400),
        now,
        amount,
        WindowLimit::Amount {
            asset: "native".to_owned(),
            window: "1d".to_owned(),
            max_stroops: 1_000_000_000,
        },
    )
}

/// The submission intent of `envelope`, recorded against ledger 100.
pub(crate) fn intent(envelope: &SignedTestEnvelope) -> SubmissionIntent {
    let decoded =
        TransactionEnvelope::from_xdr_base64(envelope.envelope_xdr(), Limits::none()).unwrap();
    SubmissionIntent {
        envelope_hash: envelope_hash_hex(envelope.envelope_xdr()),
        tx_hash: envelope.tx_hash_hex().to_owned(),
        source: envelope.source().to_owned(),
        sequence: envelope.sequence(),
        max_time: crate::idempotent_submit::extract_max_time(&decoded),
        submission_ledger: 100,
    }
}

/// A mainnet profile with its window store, policy pin, receipt store, and
/// keyed audit writer, in a temporary directory, with the mainnet clock fixed
/// at the fixture's `now`.
///
/// Installs the in-memory keyring and fixes the process-wide clock; tests
/// that use it run serially.
pub(crate) struct LedgerFixture {
    pub(crate) dir: TempDir,
    pub(crate) name: String,
    pub(crate) profile: Profile,
    pub(crate) window: PersistedWindowStore,
    pub(crate) receipts: ReceiptStore,
    pub(crate) writer: AuditWriterHandle,
    pub(crate) anchors: Arc<InMemoryTipAnchorStore>,
    pub(crate) now: u64,
    /// The guard of the fixed clock; tests move it with `set`.
    pub(crate) clock: TestClockGuard,
}

impl LedgerFixture {
    /// A fixture whose stores are fresh at `now`.
    pub(crate) fn new(label: &str, now: u64) -> Self {
        let clock = set_now_ms_for_test(now);
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut profile = Profile::builder_mainnet_named(
            label,
            "https://rpc.example",
            "fixture-signer",
            &account(SIGNER_SEED),
            "fixture-nonce",
            "nonce",
        )
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let name = stellar_agent_core::profile::name::profile_name_for_approval(&profile);
        let window_path = dir.path().join("state.window");
        {
            let lock =
                WindowStoreLock::acquire_for(&window_path, &profile.policy_window_state_key_id)
                    .unwrap();
            pin::write(
                &lock,
                &PinScope::for_profile(&window_path, &profile),
                &Pin::new(POLICY_SEQUENCE, POLICY_DIGEST, POLICY_OWNER).unwrap(),
            )
            .unwrap();
        }
        let window = PersistedWindowStore::at_path(window_path);
        let receipts = ReceiptStore::open_at(dir.path(), &name).unwrap();
        let (writer, anchors) = keyed_writer(&profile.audit_log_path);
        Self {
            dir,
            name,
            profile,
            window,
            receipts,
            writer,
            anchors,
            now,
            clock,
        }
    }

    /// Mints a transaction authorization over `binding` holding `holds`, for
    /// `endpoint`, under the approval `nonce`, and returns it with its header
    /// built from the minted record and an audit proof of the fixture's
    /// writer.
    pub(crate) fn mint(
        &self,
        binding: DomainBinding,
        holds: &[WindowEntry],
        endpoint: Option<(String, u64)>,
        nonce: &str,
    ) -> MainnetTxSignAuthorization {
        self.mint_with_facts(binding, holds, endpoint, nonce, tip_facts(&self.writer))
    }

    /// [`Self::mint`] with an audit proof over `facts`.
    pub(crate) fn mint_with_facts(
        &self,
        binding: DomainBinding,
        holds: &[WindowEntry],
        endpoint: Option<(String, u64)>,
        nonce: &str,
        facts: VerifiedTipFacts,
    ) -> MainnetTxSignAuthorization {
        let mut header = header(&self.name, endpoint, &self.writer, facts, self.now);
        let minted = self
            .window
            .mint_authorization(
                &self.profile,
                &MintRequest {
                    chain: Caip2::Mainnet,
                    binding: binding.clone(),
                    consumer: header.consumer,
                    policy_sequence: POLICY_SEQUENCE,
                    policy_digest: POLICY_DIGEST,
                    approval_nonce: nonce.to_owned(),
                    approval_expires_at_ms: header.approval.expires_at_ms,
                    authorization_ttl_ms: TTL_MS,
                    bindings: BindingFacts {
                        endpoint: Some([1; 32]),
                        signer: [2; 32],
                        policy: [3; 32],
                        enablement: [4; 32],
                        witness: None,
                        reservation: None,
                        approval: [5; 32],
                        audit: [6; 32],
                    },
                    holds: holds.to_vec(),
                    parent: None,
                },
            )
            .unwrap();
        header.id = minted.id;
        header.approval.nonce = nonce.to_owned();
        header.reservation = minted.reservation;
        header.issued_at_ms = minted.issued_at_ms;
        header.expires_at_ms = minted.expires_at_ms;
        header.bindings_digest = minted.bindings_digest;
        MainnetTxSignAuthorization::for_crate_tests(TxSignInner {
            header,
            binding,
            entries: holds.to_vec(),
        })
    }

    /// The wallet recorder of a `stellar_pay_commit` submission sizing
    /// `entries`, writing through `writer`.
    pub(crate) fn recorder(
        &self,
        entries: Vec<WindowEntry>,
        writer: Option<AuditWriterHandle>,
    ) -> WalletSubmissionRecorder<'_> {
        WalletSubmissionRecorder::new(
            &self.profile,
            self.name.clone(),
            "stellar_pay_commit",
            Some("stellar:pubnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            entries,
            self.receipts.clone(),
            self.window.clone(),
            writer,
            None,
            "request",
            self.now,
        )
    }

    /// Whether the ledger still lists `id` as open.
    pub(crate) fn is_open(&self, id: AuthorizationId) -> bool {
        self.window
            .open_authorizations(&self.profile, self.now)
            .unwrap()
            .iter()
            .any(|open| open.id == id)
    }

    /// Asserts the durable consumption and the absence of authorization holds.
    pub(crate) fn assert_used_without_holds(&self, id: AuthorizationId) {
        // The store prefixes its JSON body with a 32-byte HMAC tag.
        let bytes = std::fs::read(self.dir.path().join("state.window")).unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
        let id = serde_json::to_value(id).unwrap();
        let record = wire["authorizations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["id"] == id)
            .unwrap();
        assert_eq!(record["state"], "used");
        assert!(!record["consumption"].is_null());
        assert!(
            wire["holds"]
                .as_array()
                .is_none_or(|holds| holds.iter().all(|hold| hold["authorization_id"] != id))
        );
    }

    /// The audit rows the fixture's log holds, by kind.
    pub(crate) fn audit_kinds(&self) -> Vec<String> {
        std::fs::read_to_string(&self.profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }
}

/// Resolver inputs produced by the signed-policy, enrollment, approval, and audit verifiers.
pub(crate) struct ResolverFixture {
    pub(crate) dir: TempDir,
    pub(crate) profile: Profile,
    pub(crate) context: crate::MainnetWriteContext,
    pub(crate) policy: stellar_agent_core::mainnet::verified_policy::VerifiedPolicy,
    pub(crate) enablement: stellar_agent_core::mainnet::enablement::EnablementRecord,
    pub(crate) signer: crate::keyring::EnrolledSigner,
    pub(crate) window: PersistedWindowStore,
    pub(crate) envelope: String,
    pub(crate) source: SignedTestEnvelope,
    pub(crate) now: u64,
    pub(crate) clock: TestClockGuard,
    pub(crate) anchor_failure: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ResolverFixture {
    pub(crate) fn new() -> Self {
        Self::configured(|_| {}, str::to_owned)
    }

    pub(crate) fn configured(
        profile_edit: impl FnOnce(&mut Profile),
        policy_edit: impl FnOnce(&str) -> String,
    ) -> Self {
        use stellar_agent_core::{
            policy::v1::{
                canonical, signature,
                verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
            },
            profile::{
                loader,
                schema::{KeyringEntryRef, signer_identity_entry_ref},
                signer_identity::SignerIdentityRecord,
            },
        };
        use stellar_xdr::{Memo, WriteXdr as _};
        #[cfg(feature = "test-helpers")]
        stellar_agent_core::audit_log::writer::AuditWriterRegistry::remove_for_test("operator");
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap() - 300_000;
        let clock = set_now_ms_for_test(now);
        // The served source account is at sequence 1, so its next
        // transaction carries sequence 2.
        let source = SignedTestEnvelope::builder(SIGNER_SEED)
            .network_passphrase(MAINNET_PASSPHRASE)
            .amount_stroops(10)
            .sequence(2)
            .unsigned()
            .build();
        let mut decoded =
            TransactionEnvelope::from_xdr_base64(source.envelope_xdr(), Limits::none()).unwrap();
        let TransactionEnvelope::Tx(tx) = &mut decoded else {
            unreachable!()
        };
        tx.tx.memo = Memo::Text(b"approved".to_vec().try_into().unwrap());
        let envelope = decoded.to_xdr_base64(Limits::none()).unwrap();
        let mut profile = Profile::builder_mainnet_named(
            "operator",
            "https://rpc.example.invalid",
            "stellar-agent-signer-operator",
            source.source(),
            "stellar-agent-nonce-operator",
            "default",
        )
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        profile_edit(&mut profile);
        let anchor = crate::keyring::KeyringTipAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        )
        .anchor_entry_ref()
        .clone();
        let anchor_failure =
            stellar_agent_test_support::keyring_mock::install_with_write_failure_switch(
                &anchor.service,
                &anchor.account,
            )
            .unwrap();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let put = |entry: &KeyringEntryRef, text: &str| {
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .set_password(text)
                .unwrap();
        };
        put(
            &profile.policy_owner_key_id,
            &stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string(),
        );
        put(
            &signer_identity_entry_ref(&profile.mcp_signer_default),
            &SignerIdentityRecord::agent(public_key(SIGNER_SEED)).render(),
        );
        for key in [
            &profile.policy_window_state_key_id,
            &profile.audit_log_hash_chain_key_id,
            &profile.attestation_key_id,
        ] {
            crate::keyring::rotate_keyring_secret_32(&key.service, &key.account).unwrap();
        }
        loader::save_to_dir("operator", &profile, &dir.path().join("profiles")).unwrap();
        let nonce = "installation-nonce";
        put(
            &stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
                &profile.policy_window_state_key_id,
            ),
            nonce,
        );
        let digest = stellar_agent_core::hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(
            nonce.as_bytes(),
        ));
        let raw = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml")
            .replace(&"0".repeat(64), &digest)
            .replace(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                source.destination(),
            )
            .replace("decision = \"require_approval\"", "decision = \"allow\"")
            .replace("ttl_secs = 3600", "")
            .replace("reason = \"review\"", "");
        let raw = policy_edit(&raw);
        let canonical = canonical::canonical_bytes(&raw).unwrap();
        let signature = signature::sign(&signature::digest(&canonical), &owner);
        let policy_path = dir.path().join("policy.toml");
        std::fs::write(
            &policy_path,
            format!(
                "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
                stellar_agent_core::hex::encode(&signature)
            ),
        )
        .unwrap();
        let window_path = dir.path().join("state.window");
        let policy = load_verified_policy(
            &PolicyLoad {
                path: &policy_path,
                profile: &profile,
                profile_name: "operator",
                owner_pubkey: &owner.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: &window_path,
            },
            stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
        let enablement = stellar_agent_core::mainnet::enablement::verify_enablement(
            &policy,
            "operator",
            stellar_agent_core::profile::name::ProfileNameSource::Flag,
            &profile,
            &dir.path().join("profiles"),
            &|_| Ok(nonce.to_owned()),
        )
        .unwrap();
        let signer = crate::keyring::enrolled_signer(
            "operator",
            &dir.path().join("profiles"),
            &profile,
            crate::keyring::EnrolledRole::Agent,
            &public_key(SIGNER_SEED),
        )
        .unwrap();
        let context = crate::NetworkContext::mainnet_write(
            &profile,
            &stellar_agent_core::profile::name::ResolvedProfileName::from_flag("operator"),
            &dir.path().join("profiles"),
            crate::MainnetEndpointFlags::default(),
        )
        .unwrap();
        Self {
            dir,
            profile,
            context,
            policy,
            enablement,
            signer,
            window: PersistedWindowStore::at_path(window_path),
            envelope,
            source,
            now,
            clock,
            anchor_failure,
        }
    }

    pub(crate) fn approval(
        &self,
        envelope: &str,
        created: u64,
        ttl: u64,
    ) -> stellar_agent_core::approval::witness::ApprovalWitness {
        self.approval_under(envelope, created, ttl, &self.profile, "operator")
    }

    /// The classic payment approval of `envelope`, created at `created` and
    /// expiring `ttl` later, attested and verified at `created` for `profile`
    /// under `name`.
    pub(crate) fn approval_under(
        &self,
        envelope: &str,
        created: u64,
        ttl: u64,
        profile: &Profile,
        name: &str,
    ) -> stellar_agent_core::approval::witness::ApprovalWitness {
        use stellar_agent_core::approval::PendingApproval;
        let args = stellar_agent_core::envelope_decode::decode_authoritative_args(
            envelope,
            "stellar_pay_commit",
        )
        .unwrap();
        let mut entry = PendingApproval::new_payment_pending(
            envelope.to_owned(),
            envelope.as_bytes(),
            args["destination"].as_str().unwrap().to_owned(),
            args["amount_stroops"].as_str().unwrap().parse().unwrap(),
            "XLM".to_owned(),
            Some("approved".to_owned()),
            100,
            1,
            "1000".into(),
            ttl,
        )
        .unwrap();
        entry.created_at_unix_ms = created;
        entry.expires_at_unix_ms = created + ttl;
        self.attested(
            &entry,
            profile,
            name,
            stellar_agent_core::approval::witness::ApprovedKind::Payment,
            stellar_agent_core::approval::subject::approval_subject_classic(envelope),
            created,
        )
    }

    pub(crate) fn attested(
        &self,
        entry: &stellar_agent_core::approval::PendingApproval,
        profile: &Profile,
        name: &str,
        kind: stellar_agent_core::approval::witness::ApprovedKind,
        subject: [u8; 32],
        now: u64,
    ) -> stellar_agent_core::approval::witness::ApprovalWitness {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            AttestationBinding, ConsentAudit, PendingApprovalStore, Surface, attest_and_persist,
            load_attestation_key,
            witness::{ApprovalExpectation, verify_approval},
        };
        let path = self.dir.path().join(format!(
            "{}-{}.toml",
            entry.approval_nonce,
            stellar_agent_core::hex::encode(&subject)
        ));
        let mut store = PendingApprovalStore::open(path).unwrap();
        store.insert(entry.clone(), now).unwrap();
        let audit = self.audit();
        let key = load_attestation_key(
            &profile.attestation_key_id,
            &stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(name, profile),
        )
        .unwrap();
        attest_and_persist(
            &mut store,
            entry,
            &key,
            &AttestationBinding::new(name, profile.chain_id.caip2_str()),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit.writer().lock().unwrap()),
            None,
            |_, _| Err("unexpected grant".to_owned()),
        )
        .unwrap();
        let encoded = store
            .get(&entry.approval_nonce)
            .unwrap()
            .attestation_blob_b64
            .as_ref()
            .unwrap();
        let blob: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap()
            .try_into()
            .unwrap();
        verify_approval(
            &store,
            profile,
            name,
            &entry.approval_nonce,
            &blob,
            &ApprovalExpectation { kind, subject },
            now,
        )
        .unwrap()
    }

    pub(crate) fn context_with_routes(
        &self,
        routes: &[(&str, &str)],
    ) -> crate::MainnetWriteContext {
        crate::NetworkContext::mainnet_write(
            &self.profile,
            &stellar_agent_core::profile::name::ResolvedProfileName::from_flag("operator"),
            &self.dir.path().join("profiles"),
            crate::MainnetEndpointFlags::default(),
        )
        .unwrap()
        .with_test_transport_routes(routes)
    }

    pub(crate) fn wire(&self) -> serde_json::Value {
        let path = self.dir.path().join("state.window");
        if !path.exists() {
            return serde_json::json!({});
        }
        let bytes = std::fs::read(path).unwrap();
        serde_json::from_slice(&bytes[32..]).unwrap()
    }

    pub(crate) fn audit(&self) -> AuditReadiness {
        super::audit_readiness::audit_readiness(&self.profile, "operator").unwrap()
    }

    pub(crate) async fn server(&self) -> wiremock::MockServer {
        use stellar_agent_test_support::{EchoIdResponder, signed_envelope::get_network_result};
        use wiremock::matchers::{body_partial_json, method};
        use wiremock::{Mock, MockServer};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "getNetwork"}),
            ))
            .respond_with(EchoIdResponder::new(get_network_result(MAINNET_PASSPHRASE)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "getLedgerEntries"}),
            ))
            .respond_with(EchoIdResponder::new(self.source.ledger_entries_result()))
            .mount(&server)
            .await;
        server
    }
}

/// The home domain the message fixtures approve and challenge.
pub(crate) const MESSAGE_HOME_DOMAIN: &str = "anchor.example.com";

/// The token contract the x402 fixtures pay in.
pub(crate) fn x402_token() -> String {
    stellar_strkey::Contract([3; 32]).to_string().to_string()
}

/// `raw` with its rule moved to the two x402 tools over the fixture's token:
/// the create tool's rule as it is, and the authenticated tool's rule after
/// `authenticated` edits it.
pub(crate) fn x402_policy(raw: &str, authenticated: impl FnOnce(String) -> String) -> String {
    let token = x402_token();
    let raw = raw
        .replace("\"native\"", &format!("\"{token}\""))
        .replace("native =", &format!("\"{token}\" ="));
    let start = raw.find("[[rules]]").unwrap();
    let rule = &raw[start..];
    format!(
        "{}{}\n{}",
        &raw[..start],
        rule.replace("stellar_pay", "stellar_x402_create_payment"),
        authenticated(rule.replace("stellar_pay", "stellar_x402_authenticated_payment"))
    )
}

/// A resolver fixture whose policy evaluates both x402 tools.
pub(crate) fn x402_fixture() -> ResolverFixture {
    ResolverFixture::configured(|_| {}, |raw| x402_policy(raw, |rule| rule))
}

/// The payment root of the x402 fixtures: a transfer of 10 of the token from
/// the fixture's signer to its destination, with no sub-invocations.
pub(crate) fn x402_root(f: &ResolverFixture) -> stellar_xdr::SorobanAuthorizedInvocation {
    use stellar_xdr::{
        AccountId, ContractId, Hash, Int128Parts, InvokeContractArgs, PublicKey, ScAddress, ScVal,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256,
    };
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
            function_name: "transfer".try_into().unwrap(),
            args: vec![
                ScVal::Address(ScAddress::Account(AccountId(
                    PublicKey::PublicKeyTypeEd25519(Uint256(f.signer.public_key())),
                ))),
                ScVal::Address(ScAddress::Account(AccountId(
                    PublicKey::PublicKeyTypeEd25519(Uint256(
                        stellar_strkey::ed25519::PublicKey::from_string(f.source.destination())
                            .unwrap()
                            .0,
                    )),
                ))),
                ScVal::I128(Int128Parts { hi: 0, lo: 10 }),
            ]
            .try_into()
            .unwrap(),
        }),
        sub_invocations: vec![].try_into().unwrap(),
    }
}

/// The mainnet intent of `root` for `consumer`.
pub(crate) fn x402_intent(
    root: &stellar_xdr::SorobanAuthorizedInvocation,
    consumer: MainnetConsumer,
) -> super::resolve::SorobanIntent<'_> {
    use sha2::Digest as _;
    super::resolve::SorobanIntent {
        consumer,
        root_invocation: root,
        network_id: sha2::Sha256::digest(MAINNET_PASSPHRASE.as_bytes()).into(),
    }
}

/// Message facts for the fixture's home domain, its web authentication
/// domain and server key, with `content` and `key`.
pub(crate) fn message_facts(content: [u8; 32], key: [u8; 32]) -> super::message::MessageFacts {
    super::message::MessageFacts {
        domain: super::MessageDomain {
            home_domain: MESSAGE_HOME_DOMAIN.to_owned(),
            web_auth_domain: "auth.anchor.example.com".to_owned(),
            server_key: [0x5e; 32],
        },
        content_digest: content,
        ephemeral_public_key: key,
    }
}

impl ResolverFixture {
    /// The operator's approval of the x402 payment `root`, for the
    /// authenticated subject over `home_domain` or the plain subject without
    /// one, created at `created` and expiring 600 seconds later, attested and
    /// verified at `created` through the real producers.
    pub(crate) fn x402_approval(
        &self,
        root: &stellar_xdr::SorobanAuthorizedInvocation,
        home_domain: Option<&str>,
        created: u64,
    ) -> stellar_agent_core::approval::witness::ApprovalWitness {
        use stellar_agent_core::approval::subject::{
            approval_subject_x402, approval_subject_x402_authenticated, soroban_intent_digest,
        };
        let intent = x402_intent(root, MainnetConsumer::X402Authenticated);
        let mut entry = stellar_agent_core::approval::PendingApproval::new_x402_pending(
            &intent.network_id,
            root,
            home_domain.map(str::to_owned),
            "1000".into(),
            600_000,
        )
        .unwrap();
        entry.created_at_unix_ms = created;
        entry.expires_at_unix_ms = created + 600_000;
        let digest = soroban_intent_digest(&intent.network_id, root).unwrap();
        self.attested(
            &entry,
            &self.profile,
            "operator",
            stellar_agent_core::approval::witness::ApprovedKind::X402Payment,
            home_domain.map_or_else(
                || approval_subject_x402(&digest),
                |domain| approval_subject_x402_authenticated(&digest, domain),
            ),
            created,
        )
    }

    /// The message signing request over this fixture's proofs.
    pub(crate) fn message_request<'a>(
        &'a self,
        intent: &'a super::resolve::SorobanIntent<'a>,
        message: &'a super::message::MessageFacts,
        approval: &'a stellar_agent_core::approval::witness::ApprovalWitness,
    ) -> super::resolve::MessageSignRequest<'a> {
        super::resolve::MessageSignRequest {
            context: &self.context,
            consumer: MainnetConsumer::X402Authenticated,
            intent,
            message,
            policy: &self.policy,
            enablement: &self.enablement,
            approval,
            audit: self.audit(),
            store: &self.window,
        }
    }

    /// The receipt of a message authorization for `message`, resolved and
    /// consumed over a fresh approval of the payment `root` for the
    /// message's home domain.
    pub(crate) fn message_receipt(
        &self,
        root: &stellar_xdr::SorobanAuthorizedInvocation,
        message: &super::message::MessageFacts,
    ) -> super::message::MessageUseReceipt {
        let approval = self.x402_approval(root, Some(&message.domain.home_domain), self.now);
        self.message_receipt_for(root, message, &approval)
    }

    /// The receipt of a message authorization for `message`, resolved under
    /// `approval` and consumed.
    pub(crate) fn message_receipt_for(
        &self,
        root: &stellar_xdr::SorobanAuthorizedInvocation,
        message: &super::message::MessageFacts,
        approval: &stellar_agent_core::approval::witness::ApprovalWitness,
    ) -> super::message::MessageUseReceipt {
        let intent = x402_intent(root, MainnetConsumer::X402Authenticated);
        let authorization =
            super::resolve::resolve_message_sign(self.message_request(&intent, message, approval))
                .unwrap();
        super::resolve::consume_message_sign(&self.context, authorization, &self.window).unwrap()
    }
}

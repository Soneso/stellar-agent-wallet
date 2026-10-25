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
    MainnetTxSignAuthorization::for_crate_tests(TxSignInner { header, binding })
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
        tx_authorization(header, binding)
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

//! Offline fixtures shared by the two message-signing tool test modules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use base64::Engine as _;
use stellar_agent_core::profile::loader::{load_with_overlay_from_dir, save_to_dir};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, signer_identity_entry_ref};
use stellar_agent_core::profile::signer_identity::SignerIdentityRecord;
use stellar_agent_test_support::StellarAgentHomeGuard;

pub(super) const MESSAGE: &str = "synthetic message signing challenge";
const SEED: [u8; 32] = [0x63; 32];

pub(super) struct Fixture {
    _home: StellarAgentHomeGuard,
    pub dir: tempfile::TempDir,
    pub profile: Profile,
    pub account: String,
    name: String,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = StellarAgentHomeGuard::new(dir.path());
        let account = stellar_strkey::ed25519::PublicKey(
            ed25519_dalek::SigningKey::from_bytes(&SEED)
                .verifying_key()
                .to_bytes(),
        )
        .to_string()
        .to_string();
        let name = format!("message-{}", uuid::Uuid::new_v4().simple());
        let signer = KeyringEntryRef::default_signer(&name);
        let nonce = KeyringEntryRef::default_nonce(&name);
        let profile = Profile::builder_testnet_named(
            &name,
            &signer.service,
            &account,
            &nonce.service,
            &nonce.account,
        )
        .with_noop_engine()
        .audit_log_path(dir.path().join("audit.jsonl"))
        .build();
        save_to_dir(&name, &profile, &dir.path().join("profiles")).unwrap();
        Self {
            _home: home,
            dir,
            profile,
            account,
            name,
        }
    }

    pub fn mainnet_sibling(&self, shared_coordinate: bool) -> Profile {
        let signer = KeyringEntryRef::default_signer("main");
        let nonce = KeyringEntryRef::default_nonce("main");
        let mut sibling = Profile::builder_mainnet_named(
            "main",
            "https://rpc.example.invalid",
            &signer.service,
            &self.account,
            &nonce.service,
            &nonce.account,
        )
        .build();
        if shared_coordinate {
            sibling.mcp_signer_default = self.profile.mcp_signer_default.clone();
        }
        save_to_dir("main", &sibling, &self.dir.path().join("profiles")).unwrap();
        sibling
    }

    pub fn overlay_mainnet_signer(&mut self) {
        let sibling = self.mainnet_sibling(false);
        self.profile = load_with_overlay_from_dir(
            &self.name,
            &self.dir.path().join("profiles"),
            std::collections::HashMap::from([(
                "mcp_signer_default",
                serde_json::json!(sibling.mcp_signer_default),
            )]),
            None,
        )
        .unwrap();
        assert!(self.profile.is_overlaid("mcp_signer_default"));
    }

    /// Stores the signer seed and its identity record, as an enrollment does.
    pub fn seed_signer(&self) {
        self.seed_signer_without_identity();
        self.seed_identity();
    }

    /// Stores the signer's identity record alone, without its seed.
    pub fn seed_identity(&self) {
        super::identity_fixture::store_signer_identity(&self.profile, SEED);
    }

    /// Stores the signer seed alone, as an interrupted enrollment leaves it.
    pub fn seed_signer_without_identity(&self) {
        let entry = &self.profile.mcp_signer_default;
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(
                &stellar_strkey::ed25519::PrivateKey(SEED)
                    .as_unredacted()
                    .to_string(),
            )
            .unwrap();
    }

    /// Points this testnet profile at the canonical signer coordinate of
    /// mainnet profile `v`, whose seed is stored with a record bound to `v`
    /// and its owner, and moves `v.toml` out of the profiles directory.
    /// Returns the count of reads of the seed entry.
    pub fn transplant_from_mainnet_victim(&mut self) -> Arc<AtomicUsize> {
        self.profile.mcp_signer_default.service = "stellar-agent-signer-v".into();
        let name = stellar_agent_core::profile::name::profile_name_for_approval(&self.profile);
        save_to_dir(&name, &self.profile, &self.dir.path().join("profiles")).unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reads);
        let seed = self.profile.mcp_signer_default.clone();
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                &seed.service,
                &seed.account,
                Arc::new(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                }),
            ),
        ])
        .unwrap();
        self.seed_signer_without_identity();
        self.seed_audit();
        let victim = Profile::builder_mainnet_named(
            "v",
            "https://rpc.example.invalid",
            "stellar-agent-signer-v",
            &self.account,
            "stellar-agent-nonce-v",
            "default",
        )
        .build();
        save_to_dir("v", &victim, &self.dir.path().join("profiles")).unwrap();
        std::fs::rename(
            self.dir.path().join("profiles/v.toml"),
            self.dir.path().join("v.toml"),
        )
        .unwrap();
        let record = SignerIdentityRecord::signed_for_test(
            stellar_strkey::ed25519::PublicKey::from_string(&self.account)
                .unwrap()
                .0,
            "v",
            &victim,
            &ed25519_dalek::SigningKey::from_bytes(&[11; 32]),
        );
        stellar_agent_network::keyring::write_keyring_string(
            &signer_identity_entry_ref(&seed),
            &record.render().unwrap(),
        )
        .unwrap();
        assert!(!self.dir.path().join("profiles/v.toml").exists());
        reads
    }

    pub fn seed_audit(&self) {
        let entry = &self.profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x41; 32]))
            .unwrap();
    }

    pub fn server(&self) -> crate::server::WalletServer {
        crate::server::WalletServer::new(self.profile.clone()).unwrap()
    }

    pub fn assert_signed_row(
        &self,
        result: &rmcp::model::CallToolResult,
        tool: &str,
        signature_field: &str,
        signer_field: &str,
    ) {
        let text = &result.content.first().unwrap().as_text().unwrap().text;
        assert_ne!(result.is_error, Some(true), "{text}");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        let signature_b64 = response["data"][signature_field].as_str().unwrap();
        let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(response["data"][signer_field], self.account);
        stellar_agent_sep53::verify_message(
            MESSAGE.as_bytes(),
            &signature,
            &stellar_strkey::ed25519::PublicKey::from_string(&self.account).unwrap(),
        )
        .unwrap();
        let log = std::fs::read_to_string(&self.profile.audit_log_path).unwrap();
        let rows: Vec<serde_json::Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|row: &serde_json::Value| row["kind"] == "opaque_payload_signed")
            .collect();
        assert_eq!(rows.len(), 1, "{log}");
        let row = &rows[0];
        assert_eq!(row["tool"], tool);
        assert_eq!(row["chain_id"], "stellar:testnet");
        let digest = hex::encode(stellar_agent_sep53::message_digest(MESSAGE.as_bytes()));
        assert_eq!(
            row["payload_sha256_redacted"],
            stellar_agent_network::submit::redact_tx_hash(&digest)
        );
        assert_eq!(
            row["signer_redacted"],
            serde_json::to_value(
                stellar_agent_core::observability::RedactedStrkey::from_full(&self.account)
            )
            .unwrap()
        );
        uuid::Uuid::parse_str(row["request_id"].as_str().unwrap()).unwrap();
        for private in [
            MESSAGE,
            signature_b64,
            &hex::encode(signature),
            &digest,
            &self.account,
        ] {
            assert!(!log.contains(private), "audit contains unredacted material");
        }
    }
}

pub(super) fn assert_refusal(result: &rmcp::model::CallToolResult, expected: &str) {
    let (code, _, text) = crate::tools::common::assert_business_envelope(result);
    assert_eq!(code, expected);
    assert!(!text.contains("\"signature\"") && !text.contains("\"signedMessage\""));
    assert!(!text.contains("unlock") && !text.contains("keyring load failed"));
}

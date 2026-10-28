//! Offline fixtures shared by the two message-signing tool test modules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::Engine as _;
use stellar_agent_core::profile::loader::{load_with_overlay_from_dir, save_to_dir};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
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

    pub fn seed_signer(&self) {
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

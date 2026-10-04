//! The audit binding on the MCP surface: a value tool refuses a changed
//! binding before anything is signed or sent, and an unnamed start over an
//! existing `default.toml` records and enforces the binding.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serial_test::serial;
use stellar_agent_core::audit_log::AuditBinding;
use stellar_agent_core::profile::loader::ProfileOrigin;
use stellar_agent_core::profile::name::{ProfileNameSource, ResolvedProfileName};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_mcp::server::{WalletServer, X402CreatePaymentArgs};
use stellar_agent_mcp::transport;
use stellar_agent_network::keyring::KeyringAuditBindingStore;
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const RECIPIENT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

fn x402_args() -> X402CreatePaymentArgs {
    X402CreatePaymentArgs {
        chain_id: "stellar:testnet".into(),
        address: None,
        payment_required: serde_json::json!({
            "scheme": "exact", "network": "stellar:testnet", "asset": CONTRACT,
            "amount": "10000000", "payTo": RECIPIENT, "maxTimeoutSeconds": 300,
            "extra": { "areFeesSponsored": true }
        })
        .to_string(),
    }
}

/// A value tool whose profile names a log other than its recorded binding
/// refuses with `audit.log_binding_changed`, and no request reaches the RPC.
#[tokio::test]
#[serial]
async fn a_value_tool_refuses_a_changed_binding_and_sends_nothing() {
    const PROFILE: &str = "binding-x402";
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().unwrap();
    let seed = [0x6f; 32];
    let payer = stellar_strkey::ed25519::PublicKey(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    )
    .to_string()
    .to_string();
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let mut profile =
        Profile::builder_testnet_named(PROFILE, "binding-x402-svc", &payer, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    profile.rpc_url = mock.uri();
    common::install_test_audit_key(&mut profile);
    let mut recorded = profile.clone();
    recorded.audit_log_path = home.path().join("elsewhere.jsonl");
    KeyringAuditBindingStore::for_profile(PROFILE)
        .store(&AuditBinding::for_profile(&recorded))
        .unwrap();
    let server = WalletServer::new(profile.clone()).unwrap();
    assert_eq!(server.profile_name_for_approval(), PROFILE);

    let result = server
        .call_stellar_x402_create_payment(x402_args())
        .await
        .unwrap();
    let (code, message, text) = common::assert_business_envelope(&result);
    assert_eq!(code, "audit.log_binding_changed", "{text}");
    assert!(
        message.contains("--acknowledge-binding-change"),
        "{message}"
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "nothing is signed or sent"
    );
    assert!(!text.contains("paymentSignature\":\""), "{text}");
}

/// Starts a server the way an unnamed `stellar-agent-mcp` start does and
/// returns the code its x402 tool answers.
async fn unnamed_start_x402_code() -> String {
    let unnamed = ResolvedProfileName {
        name: "default".to_owned(),
        source: ProfileNameSource::Default,
    };
    let (profile, origin) = transport::load_selected_profile(&unnamed).unwrap();
    assert_eq!(origin, ProfileOrigin::Persisted);
    let server = transport::build_server(profile, origin.binding_check()).unwrap();
    let result = server
        .call_stellar_x402_create_payment(x402_args())
        .await
        .unwrap();
    common::assert_business_envelope(&result).0
}

/// An unnamed start over an existing `default.toml` serves a persisted
/// profile, and its first keyed use records the binding. A later start over
/// the same file with another `audit_log_path` refuses with the binding code
/// and creates nothing at the new path.
#[tokio::test]
#[serial]
async fn an_unnamed_start_over_an_existing_default_toml_records_and_enforces_the_binding() {
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().unwrap();
    let profile_dir = stellar_agent_core::profile::schema::default_profile_dir().unwrap();
    std::fs::create_dir_all(&profile_dir).unwrap();
    let toml = stellar_agent_test_support::profile_fixtures::noop_profile_toml(
        "default",
        "stellar:testnet",
        "http://127.0.0.1:1",
    );
    let write_default = |log: &std::path::Path| {
        std::fs::write(
            profile_dir.join("default.toml"),
            format!("audit_log_path = {:?}\n{toml}", log.display().to_string()),
        )
        .unwrap();
    };
    let audit_key = KeyringEntryRef::default_audit_key("default");
    keyring_core::Entry::new(&audit_key.service, &audit_key.account)
        .unwrap()
        .set_password(&URL_SAFE_NO_PAD.encode([0x2a; 32]))
        .unwrap();
    let binding = || {
        KeyringAuditBindingStore::for_profile("default")
            .load_raw()
            .unwrap()
    };

    let first_log = home.path().join("audit").join("default.jsonl");
    write_default(&first_log);
    assert!(binding().is_none(), "nothing recorded yet");
    let first = unnamed_start_x402_code().await;
    assert_ne!(first, "audit.log_binding_changed", "{first}");
    let loaded =
        stellar_agent_core::profile::loader::load_from_dir("default", &profile_dir, None).unwrap();
    assert!(
        binding() == Some(AuditBinding::for_profile(&loaded).to_keyring_value()),
        "a persisted default.toml records the binding at its first keyed use"
    );

    let moved_dir = home.path().join("moved");
    write_default(&moved_dir.join("default.jsonl"));
    assert_eq!(unnamed_start_x402_code().await, "audit.log_binding_changed");
    assert!(!moved_dir.exists(), "nothing is created at the new path");
}

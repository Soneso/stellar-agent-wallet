//! Rotation and cache refresh share the profile's counterparty key reference.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]

#[tokio::test]
#[serial_test::serial]
async fn rotation_and_refresh_use_the_same_explicit_reference() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;
    use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
    use stellar_agent_network::counterparty::CounterpartyResolver as _;
    use stellar_agent_network::counterparty::cache::StellarTomlResolver;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let home = tempfile::tempdir().unwrap();
    let _guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let backend_key = [0x4b; 32];
    keyring_core::set_default_store(Arc::new(
        stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.path().join("headless-keyring/store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(backend_key),
            )),
        ),
    ));
    let name = "counterparty-rotation";
    let mut profile = Profile::builder_testnet_named(name, "signer", "account", "nonce", "account")
        .with_noop_engine()
        .audit_log_path(home.path().join("audit.jsonl"))
        .build();
    profile.counterparty_cache_key_id = KeyringEntryRef::new("custom-cache", "custom-account");
    stellar_agent_core::profile::loader::save_to_dir(name, &profile, &home.path().join("profiles"))
        .unwrap();
    // The resolver writes into an existing directory; the refresh and
    // warm-up commands create it before they construct the resolver.
    let cache_dir = home.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("VERSION = \"2.0.0\"\n"))
        .mount(&server)
        .await;
    let resolver = StellarTomlResolver::with_test_base_url(
        name,
        profile.counterparty_cache_key_id.clone(),
        cache_dir,
        Duration::from_secs(3600),
        reqwest::Client::new(),
        server.uri(),
    );
    resolver.refresh("counterparty.example").await.unwrap();
    let before =
        stellar_agent_network::keyring::load_hmac_key_32(&profile.counterparty_cache_key_id)
            .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["profile", "rotate-counterparty-key", name])
        .env("STELLAR_AGENT_HOME", home.path())
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(backend_key),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let after =
        stellar_agent_network::keyring::load_hmac_key_32(&profile.counterparty_cache_key_id)
            .unwrap();
    assert_ne!(before.as_ref(), after.as_ref());
    assert!(resolver.list_cached().await.unwrap().is_empty());
    resolver.refresh("counterparty.example").await.unwrap();
    assert_eq!(resolver.list_cached().await.unwrap().len(), 1);
}

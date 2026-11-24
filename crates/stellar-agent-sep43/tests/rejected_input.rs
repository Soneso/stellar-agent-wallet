//! Network passphrase refusals preserve their wire codes without echoing input.
#![allow(clippy::expect_used, reason = "test assertions")]

use stellar_agent_test_support::rejected_value::{assert_refusal_text, capture_refusal};

#[test]
#[serial_test::serial]
fn rejected_input_network_passphrase() {
    let storage_sandbox =
        stellar_agent_test_support::sandbox::StateSandbox::new().expect("fixture sandbox");
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    capture_refusal(|| {
        runtime.block_on(async {
            let signer =
                stellar_agent_network::signing::SoftwareSigningKey::new_from_bytes([1; 32]);
            let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
                "test", "test", "nonce", "test",
            )
            .build();
            let expected_signer = stellar_strkey::ed25519::PublicKey([2; 32]);
            let passphrase = &profile.network_passphrase;
            let classic = stellar_agent_sep43::signing::sign_classic_transaction(
                "AAAA",
                &signer,
                passphrase,
                Some("CREDMARKER7"),
            )
            .await
            .expect_err("wrong network");
            let auth = stellar_agent_sep43::signing::sign_soroban_auth_entry(
                "AAAA",
                &signer,
                &expected_signer,
                passphrase,
                Some("CREDMARKER7"),
            )
            .await
            .expect_err("wrong network");
            let message = stellar_agent_sep43::module::sign_message::dispatch(
                &profile,
                &signer,
                "hello",
                Some("CREDMARKER7"),
                None,
            )
            .await
            .expect_err("wrong network");
            for error in [classic, auth, message] {
                assert_eq!(error.wire_code(), "sep43.invalid_network_passphrase");
                assert_eq!(error.sep43_code(), -3);
                assert_refusal_text(
                    &error,
                    "invalid network passphrase: network_passphrase must match the configured \
                     profile network; expected \"Test SDF Network ; September 2015\"",
                );
            }
        })
    });
}

#[test]
#[serial_test::serial]
fn rejected_input_auth_preimage_base64() {
    let storage_sandbox =
        stellar_agent_test_support::sandbox::StateSandbox::new().expect("fixture sandbox");
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    capture_refusal(|| {
        let signer = stellar_agent_network::signing::SoftwareSigningKey::new_from_bytes([1; 32]);
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
            "test", "test", "nonce", "test",
        )
        .build();
        let expected_signer = stellar_strkey::ed25519::PublicKey([2; 32]);
        let error = runtime
            .block_on(stellar_agent_sep43::signing::sign_soroban_auth_entry(
                "CREDMARKER7!",
                &signer,
                &expected_signer,
                &profile.network_passphrase,
                None,
            ))
            .expect_err("invalid base64 preimage");
        assert_eq!(error.wire_code(), "sep43.invalid_xdr");
        assert_eq!(error.sep43_code(), -3);
        assert_refusal_text(
            &error,
            "invalid XDR: authorization entry preimage must be base64-encoded XDR",
        );
    });
}

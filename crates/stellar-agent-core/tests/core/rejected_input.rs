//! Rejected parser inputs are absent from every diagnostic surface.
#![allow(clippy::expect_used, reason = "test assertions")]

use stellar_agent_core::amount::{AnchorAmount, AnchorAmountError};
use stellar_agent_core::envelope_decode::{EnvelopeDecodeError, decode_authoritative_args};
use stellar_agent_test_support::rejected_value::{
    CREDENTIAL_MARKER, assert_no_marker_in_text, assert_refusal_text, capture_refusal,
};

#[test]
fn rejected_input_anchor_amount() {
    capture_refusal(|| {
        let error = AnchorAmount::parse("12.CREDMARKER7").expect_err("invalid amount");
        assert!(matches!(
            error,
            AnchorAmountError::InvalidChar { offset: 3 }
        ));
        assert_refusal_text(
            &error,
            "anchor amount contains an invalid character at byte offset 3; only digits and '.' are allowed",
        );
        assert!(AnchorAmount::parse("12.5").is_ok());
    });
}

#[test]
fn rejected_input_envelope_tool() {
    capture_refusal(|| {
        let error = decode_authoritative_args("invalid", "CREDMARKER7").expect_err("unknown tool");
        assert!(matches!(error, EnvelopeDecodeError::UnsupportedTool));
        assert_refusal_text(
            &error,
            "unsupported tool name; expected a registered classic commit tool",
        );
    });
}

#[test]
fn rejected_input_log_filter() {
    const CHILD: &str = "STELLAR_AGENT_FILTER_REFUSAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        capture_refusal(|| {
            let error = stellar_agent_core::observability::init_subscriber_with(
                stellar_agent_core::observability::SubscriberConfig::default()
                    .with_install_panic_hook(false)
                    .with_install_log_bridge(false),
            )
            .expect_err("invalid log filter");
            assert!(matches!(
                error,
                stellar_agent_core::observability::InitError::Filter
            ));
            assert_refusal_text(
                &error,
                "STELLAR_AGENT_LOG must be a valid log-filter expression",
            );
        });
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "rejected_input::rejected_input_log_filter",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("STELLAR_AGENT_LOG", "=CREDMARKER7")
        .env_remove("RUST_LOG")
        .output()
        .expect("child runs");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 passed"), "{stdout}");
    assert_no_marker_in_text(&stdout, CREDENTIAL_MARKER);
    assert_no_marker_in_text(&String::from_utf8_lossy(&output.stderr), CREDENTIAL_MARKER);
}

#[test]
fn rejected_input_sha256() {
    capture_refusal(|| {
        let input = format!("00CREDMARKER7{}", "0".repeat(51));
        let error = stellar_agent_core::approval::attest::decode_sha256_hex(&input)
            .expect_err("invalid hex");
        assert_eq!(error.code(), "approval.sha256_hex_error");
        assert_refusal_text(
            &error,
            "SHA-256 must be hexadecimal; invalid byte pair at offset 2",
        );
        assert!(stellar_agent_core::approval::attest::decode_sha256_hex(&"aF".repeat(32)).is_ok());
    });
}

#[test]
fn rejected_input_registration_fields() {
    use stellar_agent_core::approval::{ApprovalError, RegistrationInput};
    capture_refusal(|| {
        let mut public_key = vec![0; 65];
        public_key[..11].copy_from_slice(b"CREDMARKER7");
        let error = RegistrationInput::new(vec![1; 32], public_key.clone(), None, vec![])
            .expect_err("invalid SEC1 prefix");
        assert!(matches!(error, ApprovalError::Invalid { .. }));
        assert_refusal_text(
            &error,
            "invalid approval field: public_key_uncompressed_sec1[0] must be 0x04 (uncompressed SEC1 P-256 marker)",
        );
        public_key[0] = 4;
        let error = RegistrationInput::new(
            vec![1; 32],
            public_key.clone(),
            None,
            vec!["CREDMARKER7".to_owned()],
        )
        .expect_err("invalid transport");
        assert!(matches!(error, ApprovalError::Invalid { .. }));
        assert_refusal_text(
            &error,
            "invalid approval field: transports[0] is not a valid CTAP2 transport (must be one of [\"usb\", \"internal\", \"ble\", \"nfc\", \"hybrid\"])",
        );
        assert!(
            RegistrationInput::new(vec![1; 32], public_key, None, vec!["usb".to_owned()]).is_ok()
        );
    });
}

#[test]
fn rejected_input_operator_public_key() {
    use base64::Engine as _;
    use stellar_agent_core::approval::operator_credentials::{
        OperatorApprovalCredential, OperatorApprovalCredentialStore,
    };
    capture_refusal(|| {
        let dir = tempfile::tempdir().expect("isolated store");
        let path = dir.path().join("credentials.toml");
        let store = OperatorApprovalCredentialStore::new(path.clone());
        let error = store
            .enroll(OperatorApprovalCredential {
                credential_id_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode([1; 32]),
                public_key_sec1_b64: format!("CREDMARKER7{}", "A".repeat(76)),
                rp_id: "wallet.example".to_owned(),
                label: "test".to_owned(),
                registered_at_unix_ms: 1,
                sign_count: None,
                source: stellar_agent_core::approval::OperatorCredentialSource::Enrolled,
            })
            .expect_err("invalid SEC1 prefix");
        assert!(matches!(
            error,
            stellar_agent_core::approval::ApprovalError::Invalid { .. }
        ));
        assert_refusal_text(
            &error,
            "invalid approval field: public_key_sec1_b64[0] must be 0x04 (uncompressed SEC1 P-256 marker)",
        );
        assert!(!path.exists());
    });
}

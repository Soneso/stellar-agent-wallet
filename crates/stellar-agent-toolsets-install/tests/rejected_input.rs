//! Rejected package names, shasums and attestation hex stay out of diagnostics.
#![allow(clippy::expect_used, reason = "test assertions")]
use stellar_agent_test_support::rejected_value::{assert_refusal_text, capture_refusal};
use stellar_agent_toolsets_install::attestation::ToolsetAttestation;

#[test]
fn rejected_input_attestation_hex() {
    capture_refusal(|| {
        let attestation = ToolsetAttestation {
            package: "test".to_owned(),
            version: "1.0.0".to_owned(),
            shasum: "a".repeat(64),
            capabilities: stellar_agent_toolsets::CapabilitySet::empty(),
            auditor_pubkey: [1; 32],
            signature: [2; 64],
        };
        let value = serde_json::to_value(&attestation).expect("serialize");
        assert!(serde_json::from_value::<ToolsetAttestation>(value.clone()).is_ok());
        for (field, count, message) in [
            (
                "auditor_pubkey",
                53,
                "auditor_pubkey must be a 32-byte hex string",
            ),
            ("signature", 117, "signature must be a 64-byte hex string"),
        ] {
            let mut invalid = value.clone();
            invalid[field] = serde_json::Value::String(format!("CREDMARKER7{}", "0".repeat(count)));
            let error =
                serde_json::from_value::<ToolsetAttestation>(invalid).expect_err("invalid hex");
            assert_eq!(error.classify(), serde_json::error::Category::Data);
            assert_refusal_text(&error, message);
        }
    });
}

#[test]
fn rejected_input_install_package_and_shasum() {
    use stellar_agent_toolsets_install::{
        InstallOptions, PinKey, ToolsetInstallError, install_toolset, lock_toolsets,
        validate_package_name,
    };
    capture_refusal(|| {
        let dir = tempfile::tempdir().expect("temporary toolsets");
        let lock = lock_toolsets(dir.path()).expect("lock");
        let pin_key = PinKey::from_bytes(zeroize::Zeroizing::new([0x5a; 32]));
        let shasum = format!("CREDMARKER7{}", "a".repeat(53));
        for (package, hash, expected, package_error) in [
            (
                "CREDMARKER7",
                "a".repeat(64),
                "invalid package name: package name contains an invalid character at byte offset 0; expected [a-z0-9-]",
                true,
            ),
            (
                "test",
                shasum,
                "invalid shasum: signed_shasum contains an invalid character at byte offset 0; must be 64 lowercase hex characters (0-9 a-f)",
                false,
            ),
        ] {
            let error = install_toolset(
                package,
                "1.0.0",
                &[],
                &hash,
                &[0; 64],
                &[0; 32],
                dir.path(),
                &dir.path().join("trust.txt"),
                None,
                &dir.path().join("auditor-trust.txt"),
                &InstallOptions::default(),
                &lock,
                &pin_key,
            )
            .expect_err("reject input before reading trust");
            if package_error {
                assert!(matches!(
                    error,
                    ToolsetInstallError::InvalidPackageName { .. }
                ));
            } else {
                assert!(matches!(error, ToolsetInstallError::InvalidShasum { .. }));
            }
            assert_refusal_text(&error, expected);
        }
        assert!(validate_package_name("valid-package7").is_ok());
        assert_eq!(
            validate_package_name("CREDMARKER7").expect_err("invalid package"),
            "package name contains an invalid character at byte offset 0; expected [a-z0-9-]"
        );
    });
}

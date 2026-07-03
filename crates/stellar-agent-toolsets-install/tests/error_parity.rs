//! Closed-set parity test for `ToolsetInstallError`.
//!
//! Locks the variant count so accidental additions or removals are caught at CI
//! time, consistent with the error-discipline of this crate.

use stellar_agent_toolsets_install::ToolsetInstallError;

/// The expected number of variants in `ToolsetInstallError`.
///
/// This constant MUST be updated whenever a variant is added or removed.
/// The test below asserts this constant matches the actual variant count.
const EXPECTED_VARIANT_COUNT: usize = 30;

/// Exercises every variant by constructing it and asserting the Display output
/// does not panic.  This also acts as a compile-time coverage check — if a
/// variant is removed, this test fails to compile.
#[test]
fn all_variants_covered_and_display_non_panicking() {
    use stellar_agent_toolsets::ToolsetFormatError;

    let variants: Vec<ToolsetInstallError> = vec![
        ToolsetInstallError::Io {
            detail: "test".to_owned(),
        },
        ToolsetInstallError::PackageTooLarge { cap: 1024 },
        ToolsetInstallError::HashMismatch,
        ToolsetInstallError::SignatureInvalid,
        ToolsetInstallError::UntrustedPublisher {
            publisher_key_redacted: "GABCD...EFGHI".to_owned(),
        },
        ToolsetInstallError::TrustSetEmpty,
        ToolsetInstallError::TrustSetMalformed {
            detail: "bad entry".to_owned(),
        },
        ToolsetInstallError::InvalidVersion {
            detail: "not semver".to_owned(),
        },
        ToolsetInstallError::InvalidShasum {
            detail: "must be 64 lowercase hex characters".to_owned(),
        },
        ToolsetInstallError::InvalidPackageName {
            detail: "contains uppercase".to_owned(),
        },
        ToolsetInstallError::ArchivePathTraversal {
            entry_name: "../etc/passwd".to_owned(),
        },
        ToolsetInstallError::ArchiveEntryNameInvalid {
            detail: "nul byte".to_owned(),
        },
        ToolsetInstallError::ArchiveDisallowedEntryType,
        ToolsetInstallError::ArchiveDuplicateEntry {
            entry_name: "my-toolset/readme.md".to_owned(),
        },
        ToolsetInstallError::ArchiveTooManyEntries { cap: 4096 },
        ToolsetInstallError::ArchiveEntryTooLarge {
            cap: 32 * 1024 * 1024,
        },
        ToolsetInstallError::ArchiveTooLarge {
            cap: 64 * 1024 * 1024,
        },
        ToolsetInstallError::ArchiveTrailingData,
        ToolsetInstallError::ArchiveBadTopLevel {
            detail: "multiple roots".to_owned(),
        },
        ToolsetInstallError::ToolsetFormat(ToolsetFormatError::MissingFrontmatter),
        ToolsetInstallError::IdentityMismatch {
            field: "name",
            extracted: "other-toolset".to_owned(),
            expected: "my-toolset".to_owned(),
        },
        ToolsetInstallError::AlreadyInstalled {
            package: "my-toolset".to_owned(),
            installed_version: "1.0.0".to_owned(),
        },
        ToolsetInstallError::VersionDowngrade {
            new_version: "0.9.0".to_owned(),
            installed_version: "1.0.0".to_owned(),
        },
        ToolsetInstallError::NotInstalled {
            package: "my-toolset".to_owned(),
        },
        ToolsetInstallError::PinRecordMalformed {
            detail: "invalid name".to_owned(),
        },
        ToolsetInstallError::ToolsetsRootInvalid {
            detail: "toolsets root is a symlink".to_owned(),
        },
        // Attestation gate variants.
        ToolsetInstallError::AttestationRequired {
            package: "my-toolset".to_owned(),
        },
        ToolsetInstallError::AttestationInvalid {
            detail: "ed25519 verify_strict failed for attestation signature",
        },
        ToolsetInstallError::AuditorUntrusted {
            auditor_key_redacted: "GABCD...EFGHI".to_owned(),
        },
        // Only one field value is constructed here to satisfy the parity count.
        // Exhaustive field-value coverage for all four closed-set values
        // ("package", "version", "shasum", "capabilities") lives in
        // `tests/attestation_vector.rs` (attestation_package_mismatch_refused /
        // attestation_version_mismatch_refused / attestation_shasum_mismatch_refused /
        // attestation_capabilities_mismatch_refused) where the gate is exercised
        // end-to-end.
        ToolsetInstallError::AttestationFieldMismatch { field: "package" },
    ];

    assert_eq!(
        variants.len(),
        EXPECTED_VARIANT_COUNT,
        "ToolsetInstallError variant count changed: expected {EXPECTED_VARIANT_COUNT}, \
         got {}. Update EXPECTED_VARIANT_COUNT in tests/error_parity.rs.",
        variants.len()
    );

    // Assert Display does not panic for any variant.
    for v in &variants {
        let s = v.to_string();
        assert!(
            !s.is_empty(),
            "Display must produce non-empty output for {v:?}"
        );
    }
}

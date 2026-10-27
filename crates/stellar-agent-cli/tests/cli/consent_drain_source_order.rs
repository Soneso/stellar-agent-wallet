//! CLI consumers of an approval acquire the keyed audit writer after they read
//! the approval and before they load the signing key.
//!
//! The acquisition drains consent rows `stellar-agent approve` queued while
//! this process held the writer, so the row is in the log before the key is
//! touched. The mainnet write path orders its steps the same way: the
//! confirmation, then the drain, then the readiness proof, the recorder and
//! the mint, and the signer only after the mint.

#![allow(clippy::panic, reason = "source scan assertions")]

use stellar_agent_test_support::source_order::{assert_called_between, production_half};

/// The shared mainnet steps, from the signer choice to the submit.
const MAINNET_WRITE: &str = include_str!("../../src/common/mainnet_write.rs");

/// The verb sources that carry a mainnet pipeline.
const MAINNET_VERBS: &[(&str, &str)] = &[
    ("commands/pay.rs", include_str!("../../src/commands/pay.rs")),
    (
        "commands/claim.rs",
        include_str!("../../src/commands/claim.rs"),
    ),
    (
        "commands/trustline.rs",
        include_str!("../../src/commands/trustline.rs"),
    ),
    (
        "commands/accounts/create.rs",
        include_str!("../../src/commands/accounts/create.rs"),
    ),
];

/// The start of a verb's mainnet pipeline.
const MAINNET_PIPELINE: &str = "async fn run_mainnet_pipeline<";

/// The text of the item starting at `start`, up to the next item at column 0.
fn item<'a>(file: &str, source: &'a str, start: &str) -> &'a str {
    let source = production_half(source);
    let begin = source
        .find(start)
        .unwrap_or_else(|| panic!("{file}: `{start}` not found"));
    let rest = &source[begin..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{file}: `{start}` has no end"));
    &rest[..end + 3]
}

#[test]
fn mpp_charge_authorize_acquires_the_writer_between_the_approval_read_and_the_signer() {
    assert_called_between(
        "commands/mpp.rs",
        include_str!("../../src/commands/mpp.rs"),
        "async fn commit_cli(",
        "verify_pending_approval(",
        "drain_consent_rows_before_signing(",
        "lazy_signer_from_keyring(",
    );
}

/// The trustline reads the clawback opt-in in its gate, which runs after the
/// audit pre-flight and before the signing step, and the signing step drains
/// the outbox after its witness and before the keyring signer loads.
#[test]
fn trustline_acquires_the_writer_between_the_opt_in_read_and_the_signer() {
    const TRUSTLINE: &str = include_str!("../../src/commands/trustline.rs");
    assert!(
        item("commands/trustline.rs", TRUSTLINE, "fn clawback_gate(")
            .contains("verify_attested_trustline_clawback_opt_in("),
        "commands/trustline.rs: the clawback gate reads the opt-in"
    );
    assert_called_between(
        "commands/trustline.rs",
        TRUSTLINE,
        "async fn run_with_dependencies<",
        "require_value_audit_writer(",
        "clawback_gate(",
        "sign_and_submit(",
    );
    assert_called_between(
        "commands/trustline.rs",
        TRUSTLINE,
        "async fn sign_and_submit<",
        "obtain_classic_witness(",
        "drain_consent_rows_before_signing(",
        "enrolled_keyring_signer(",
    );
}

#[test]
fn the_mainnet_confirmation_follows_the_enrolled_proof() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "enrolled_signer(",
        "confirm_mainnet_write(",
        "drain_consent_rows_before_signing(",
    );
}

#[test]
fn the_mainnet_drain_sits_between_the_confirmation_and_the_readiness_proof() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "confirm_mainnet_write(",
        "drain_consent_rows_before_signing(",
        "audit_readiness(",
    );
}

#[test]
fn the_mainnet_recorder_is_prepared_between_the_readiness_proof_and_the_mint() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "audit_readiness(",
        "prepare_mainnet_recorder(",
        "resolve_tx_sign(",
    );
}

#[test]
fn the_mainnet_signer_is_built_between_the_mint_and_the_attach() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "resolve_tx_sign(",
        "mainnet_signer(",
        "attach_signature_authorized(",
    );
}

#[test]
fn each_mainnet_pipeline_reconciles_after_its_probe_and_before_its_policy() {
    for (file, source) in MAINNET_VERBS {
        // The claim probe runs inside its envelope build.
        let after = if *file == "commands/claim.rs" {
            "build_unsigned_envelope("
        } else {
            "check_endpoint_identity("
        };
        assert_called_between(
            file,
            source,
            MAINNET_PIPELINE,
            after,
            "reconcile_open_reservations(",
            "load_mainnet_policy_engine(",
        );
    }
}

#[test]
fn each_mainnet_pipeline_checks_the_audit_writer_between_the_fee_cap_and_the_witness() {
    for (file, source) in MAINNET_VERBS {
        assert_called_between(
            file,
            source,
            MAINNET_PIPELINE,
            "check_classic_fee_cap_signed(",
            "require_value_audit_writer",
            "obtain_classic_witness_bound(",
        );
    }
}

#[test]
fn no_mainnet_step_builds_a_context_from_the_profile() {
    for (file, source) in MAINNET_VERBS {
        let pipeline = item(file, source, MAINNET_PIPELINE);
        assert!(
            !pipeline.contains("NetworkContext::from_profile("),
            "{file}: the mainnet pipeline takes its context from the write context"
        );
    }
    assert!(
        !production_half(MAINNET_WRITE).contains("NetworkContext::from_profile("),
        "common/mainnet_write.rs: the shared steps take their context from the write context"
    );
}

#[test]
fn no_mainnet_step_records_a_confirmed_window_entry_itself() {
    assert!(
        !production_half(MAINNET_WRITE).contains("record_confirmed("),
        "common/mainnet_write.rs: the window entries settle through the recorder"
    );
    let recorder = item(
        "commands/submission_record.rs",
        include_str!("../../src/commands/submission_record.rs"),
        "pub(crate) fn prepare_mainnet_recorder<",
    );
    assert!(
        !recorder.contains("record_confirmed("),
        "commands/submission_record.rs: the recorder's entries come from the authorization"
    );
}

//! CLI consumers of an approval acquire the keyed audit writer after they read
//! the approval and before they load the signing key.
//!
//! The acquisition drains consent rows `stellar-agent approve` queued while
//! this process held the writer, so the row is in the log before the key is
//! touched.

use stellar_agent_test_support::source_order::assert_called_between;

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

#[test]
fn trustline_acquires_the_writer_between_the_opt_in_read_and_the_signer() {
    assert_called_between(
        "commands/trustline.rs",
        include_str!("../../src/commands/trustline.rs"),
        "async fn run_with_dependencies<",
        "verify_attested_trustline_clawback_opt_in(",
        "drain_consent_rows_before_signing(",
        "enrolled_keyring_signer(",
    );
}

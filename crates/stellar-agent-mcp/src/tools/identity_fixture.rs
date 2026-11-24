//! The identity record an enrollment stores beside a signer seed.
//!
//! Every signing path refuses a seed whose record is absent, so a test that
//! signs with a stored seed stores the record too.

#![allow(
    clippy::expect_used,
    reason = "test-only fixture; a refused write fails the test"
)]

use stellar_agent_core::profile::{
    name::profile_name_for_approval, schema::Profile, schema::signer_identity_entry_ref,
    signer_identity::SignerIdentityRecord,
};

/// Stores the owner-free agent record of `seed` for the profile's signer
/// coordinate, bound to the profile name the server derives and to the
/// profile's chain.
///
/// # Panics
///
/// Panics if the mock keyring refuses the write.
pub(crate) fn store_signer_identity(profile: &Profile, seed: [u8; 32]) {
    let record = SignerIdentityRecord::agent(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
        profile_name_for_approval(profile),
        profile.chain_id,
    );
    write(profile, &record);
}

/// Stores the owner-free agent record of the profile's signer account, for
/// a test that stores no seed and stops before the signer loads.
///
/// # Panics
///
/// Panics if the signer account is not a G-strkey or the mock keyring
/// refuses the write.
pub(crate) fn store_signer_identity_of_account(profile: &Profile) {
    let key = stellar_strkey::ed25519::PublicKey::from_string(&profile.mcp_signer_default.account)
        .expect("the signer account is a G-strkey");
    let record =
        SignerIdentityRecord::agent(key.0, profile_name_for_approval(profile), profile.chain_id);
    write(profile, &record);
}

fn write(profile: &Profile, record: &SignerIdentityRecord) {
    stellar_agent_network::keyring::write_keyring_string(
        &signer_identity_entry_ref(&profile.mcp_signer_default),
        &record.render().expect("an agent record renders"),
    )
    .expect("the identity record is written");
}

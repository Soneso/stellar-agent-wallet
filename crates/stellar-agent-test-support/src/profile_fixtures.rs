//! Profile-TOML fixtures shared by the two binaries' process-level tests.
//!
//! The reconciliation that refuses a profile whose owner-key coordinate names
//! another profile is one implementation in `stellar-agent-core`, applied by
//! both `stellar-agent` and `stellar-agent-mcp`. Asserting the two surfaces
//! agree requires them to be given the SAME file, so the bytes are generated
//! here rather than pasted into each crate's test: two hand-copied literals
//! could drift and the parity claim would quietly stop meaning anything.

/// A minimal, valid version-2 profile TOML with the `Noop` policy engine.
///
/// `owner_profile` is the profile name every keyring coordinate is derived
/// from. It equals the file's own name for everything
/// `stellar-agent profile init` writes; passing a different value reproduces a
/// profile file copied or renamed from another profile, which is the input the
/// reconciliation refuses.
///
/// The `Noop` engine is deliberate. The name derivations the reconciliation
/// guards run for every engine kind, while the V1 policy-engine construction —
/// where an engine-coupled version of the check would sit — returns early for
/// `Noop`. A fixture on the V1 engine could not tell the two placements apart.
///
/// # Why the owner-key prefix is a literal here
///
/// This crate cannot import
/// `stellar_agent_core::profile::name::OWNER_KEY_SERVICE_PREFIX`:
/// `stellar-agent-core` already depends on this crate under its `test-helpers`
/// feature, so the reverse edge would be a dependency cycle Cargo refuses.
///
/// The literal is kept honest by the consumers instead. Both process-level
/// reconciliation suites load this fixture through the real profile loader and
/// assert the resulting `policy_owner_key_id.service` against the constant, so
/// a change to it fails there rather than silently producing fixtures that no
/// longer reproduce a mismatch.
#[must_use]
pub fn noop_profile_toml(owner_profile: &str, chain_id: &str, rpc_url: &str) -> String {
    format!(
        r#"
version = 2
chain_id = "{chain_id}"
rpc_url = "{rpc_url}"

[mcp_signer_default]
service = "stellar-agent-signer-{owner_profile}"
account = "init"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce-{owner_profile}"
account = "default"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-{owner_profile}"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-{owner_profile}"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-{owner_profile}"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-{owner_profile}"
account = "default"

[policy]
engine = "noop"
"#
    )
}

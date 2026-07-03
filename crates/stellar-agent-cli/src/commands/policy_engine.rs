//! Shared V1 policy-engine builder for value-moving CLI verbs.
//!
//! # What this module does
//!
//! Provides [`build_v1_policy_engine`]: a single fail-closed builder for
//! `PolicyEngineV1` (or `NoopPolicyEngine`) shared by the `lend`, `vault`,
//! `trade`, `bridge`, and `trustline` CLI subcommands.
//!
//! # Fail-closed invariant
//!
//! Every failure path returns `Err(message)`.  The caller MUST refuse the
//! value-moving operation and return exit code 1.  It MUST NOT fall back to a
//! permissive engine: silently dropping to `NoopPolicyEngine` on a load failure
//! would defeat the operator's configured policy on a value-moving path.
//!
//! # Invariants preserved
//!
//! - `PolicyEngineKind::Noop` → `NoopPolicyEngine` (permissive; no key fetch).
//! - `PolicyEngineKind::V1` → full owner-key fetch, base64 decode, length check,
//!   OS-state-dir resolve, and `load_signed_policy` signature verify; every
//!   failure arm returns `Err`.
//! - Unknown engine kinds → `Err` (fail-closed), matching the MCP server.
//! - The `verb` argument appears verbatim in every `Err` message so callers
//!   can attribute the failure to the right operation.

use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::{NoopPolicyEngine, PolicyEngine};
use stellar_agent_core::profile::schema::{PolicyEngineKind, default_policy_dir};

/// The service-name prefix used by
/// [`stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key`].
///
/// Must match `crates/stellar-agent-mcp/src/server.rs` `OWNER_KEY_SERVICE_PREFIX`.
pub(crate) const OWNER_KEY_SERVICE_PREFIX: &str = "stellar-agent-owner-";

/// Constructs the [`PolicyEngine`] for a value-moving CLI verb from the
/// profile's `policy.engine` kind.
///
/// `verb` is the operation name (e.g. `"lend"`, `"vault"`, `"trade"`,
/// `"bridge"`, `"trustline"`) — it appears in every error message to
/// attribute the failure.
///
/// - [`PolicyEngineKind::Noop`] → [`NoopPolicyEngine`].
/// - [`PolicyEngineKind::V1`] → derives the profile name from the owner-key
///   service entry (stripping [`OWNER_KEY_SERVICE_PREFIX`]), fetches the owner
///   public key from the OS keyring, and loads the operator-signed policy file
///   from the OS state directory.
/// - Any failure for `V1` → `Err(human-readable message)`. The caller MUST
///   refuse the value-moving operation (render the error, exit non-zero).
///   It MUST NOT fall back to a permissive engine.
/// - Unknown engine kinds → `Err` (fail-closed), matching the MCP server.
///
/// # Errors
///
/// Returns `Err(human-readable message)` on any V1 build failure or unknown
/// engine kind. The message names the verb, profile, and cause but carries no
/// secret material or account address.
pub(crate) fn build_v1_policy_engine(
    verb: &str,
    kind: &PolicyEngineKind,
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Result<Box<dyn PolicyEngine>, String> {
    use base64::Engine as _;
    use ed25519_dalek::PUBLIC_KEY_LENGTH;
    use keyring_core::Entry as KeyringEntry;
    use stellar_agent_core::policy::v1::loader::load_signed_policy;

    match kind {
        PolicyEngineKind::Noop => Ok(Box::new(NoopPolicyEngine)),
        PolicyEngineKind::V1 => {
            // Derive profile name from the service field (strips prefix).
            // `account` is always the literal "default", so we MUST use `service`.
            let service = &profile.policy_owner_key_id.service;
            let profile_name = match service.strip_prefix(OWNER_KEY_SERVICE_PREFIX) {
                Some(n) => n.to_owned(),
                None => {
                    return Err(format!(
                        "policy.engine is 'v1' but the owner-key service '{service}' does not \
                         start with the expected prefix '{OWNER_KEY_SERVICE_PREFIX}'; \
                         {verb} refuses (fail-closed)"
                    ));
                }
            };

            // Fetch the owner public key from the OS keyring.
            let entry_ref = stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key(
                &profile_name,
            );
            let raw_key = match KeyringEntry::new(&entry_ref.service, &entry_ref.account)
                .and_then(|e| e.get_password())
            {
                Ok(r) => r,
                Err(e) => {
                    return Err(format!(
                        "policy.engine is 'v1' but the owner key for profile '{profile_name}' \
                         could not be read from the keyring ({e}); {verb} refuses (fail-closed)"
                    ));
                }
            };

            let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw_key.trim());
            let key_bytes = match key_bytes {
                Ok(b) => b,
                Err(e) => {
                    return Err(format!(
                        "policy.engine is 'v1' but the owner key for profile '{profile_name}' \
                         failed base64 decode ({e}); {verb} refuses (fail-closed)"
                    ));
                }
            };

            if key_bytes.len() != PUBLIC_KEY_LENGTH {
                return Err(format!(
                    "policy.engine is 'v1' but the owner key for profile '{profile_name}' has \
                     length {} (expected {PUBLIC_KEY_LENGTH}); {verb} refuses (fail-closed)",
                    key_bytes.len()
                ));
            }
            let mut owner_pubkey = [0u8; PUBLIC_KEY_LENGTH];
            owner_pubkey.copy_from_slice(&key_bytes);

            // Resolve the policy directory.
            let policy_dir = match default_policy_dir() {
                Ok(d) => d,
                Err(e) => {
                    return Err(format!(
                        "policy.engine is 'v1' but the OS policy state directory is \
                         unavailable ({e}); {verb} refuses (fail-closed)"
                    ));
                }
            };
            let policy_path = policy_dir.join(format!("{profile_name}.toml"));

            // Load and signature-verify the operator's policy document.
            let document = match load_signed_policy(&policy_path, &profile_name, &owner_pubkey) {
                Ok(doc) => doc,
                Err(e) => {
                    return Err(format!(
                        "policy.engine is 'v1' but the policy file at {} failed to \
                         load/verify ({e}); {verb} refuses (fail-closed)",
                        policy_path.display()
                    ));
                }
            };

            Ok(Box::new(PolicyEngineV1::new(document, profile_name)))
        }
        _ => Err(format!(
            "unsupported policy engine kind {kind:?}; {verb} refuses (fail-closed)"
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};

    use super::*;

    /// Constructs a minimal testnet `Profile` whose `policy_owner_key_id.service`
    /// is set to `service`.
    ///
    /// Uses `Profile::builder_testnet` + `with_profile_name` (the only non-`#[non_exhaustive]`
    /// construction path available outside the defining crate) and then patches
    /// the service field directly on the returned profile, since the builder
    /// always derives the service name from the profile-name parameter via
    /// `KeyringEntryRef::default_owner_key`.
    fn make_profile(engine: PolicyEngineKind, service: &str) -> Profile {
        // Build a minimally valid testnet profile then override the two fields
        // the tests depend on — `policy.engine` and `policy_owner_key_id.service`.
        let mut profile = Profile::builder_testnet(
            "stellar-agent-signer",
            "default",
            "stellar-agent-nonce",
            "default",
        )
        .policy_engine(engine)
        .build();
        // Override the service name directly (the field is `pub` on Profile).
        profile.policy_owner_key_id.service = service.to_owned();
        profile
    }

    // Helper: extract the error string from a Result without requiring T: Debug.
    fn err_msg<T>(result: Result<T, String>) -> String {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(msg) => msg,
        }
    }

    // ── Noop path ────────────────────────────────────────────────────────────

    /// `PolicyEngineKind::Noop` always succeeds — no keyring or file I/O.
    #[test]
    fn noop_engine_succeeds_for_all_verbs() {
        for verb in ["lend", "vault", "trade", "bridge", "trustline"] {
            let profile = make_profile(
                PolicyEngineKind::Noop,
                &format!("{OWNER_KEY_SERVICE_PREFIX}default"),
            );
            assert!(
                build_v1_policy_engine(verb, &PolicyEngineKind::Noop, &profile).is_ok(),
                "Noop engine must succeed for verb '{verb}'"
            );
        }
    }

    // ── Fail-closed: service prefix mismatch ─────────────────────────────────

    /// When the service field does not carry `OWNER_KEY_SERVICE_PREFIX`, the
    /// builder returns `Err` and the message names the verb.
    #[test]
    fn v1_wrong_prefix_returns_err_naming_verb() {
        for verb in ["lend", "vault", "trade", "bridge", "trustline"] {
            let profile = make_profile(PolicyEngineKind::V1, "wrong-prefix-default");
            let result = build_v1_policy_engine(verb, &PolicyEngineKind::V1, &profile);
            assert!(
                result.is_err(),
                "wrong prefix must return Err for verb '{verb}'"
            );
            let msg = err_msg(result);
            assert!(
                msg.contains(verb),
                "error for verb '{verb}' must mention the verb; got: {msg}"
            );
            assert!(
                msg.contains("fail-closed"),
                "error must say fail-closed; got: {msg}"
            );
        }
    }

    // ── Fail-closed: keyring unavailable ────────────────────────────────────

    /// When the service prefix is correct but the OS keyring has no entry, the
    /// builder returns `Err` containing the verb name and "fail-closed".
    #[test]
    fn v1_missing_keyring_returns_err_naming_verb() {
        // Use a random profile name so the test is independent of any real
        // keyring state on the test machine.
        let profile_name = "test-nonexistent-profile-9f2a";
        for verb in ["lend", "vault", "trade", "bridge", "trustline"] {
            let service = format!("{OWNER_KEY_SERVICE_PREFIX}{profile_name}");
            let profile = make_profile(PolicyEngineKind::V1, &service);
            let result = build_v1_policy_engine(verb, &PolicyEngineKind::V1, &profile);
            assert!(
                result.is_err(),
                "missing keyring entry must return Err for verb '{verb}'"
            );
            let msg = err_msg(result);
            assert!(
                msg.contains(verb),
                "error for verb '{verb}' must mention the verb; got: {msg}"
            );
            assert!(
                msg.contains("fail-closed"),
                "error must say fail-closed; got: {msg}"
            );
        }
    }

    // ── Fail-closed: unknown engine kind ─────────────────────────────────────

    // Note: `PolicyEngineKind` is `#[non_exhaustive]` so we cannot construct a
    // foreign variant here.  The `_` arm is tested indirectly by the fact that
    // the match compiles with a catch-all that returns Err.

    // ── Error messages carry no secret material ───────────────────────────────

    #[test]
    fn v1_wrong_prefix_error_carries_no_key_material() {
        let profile = make_profile(PolicyEngineKind::V1, "wrong-prefix-default");
        let msg = err_msg(build_v1_policy_engine(
            "lend",
            &PolicyEngineKind::V1,
            &profile,
        ));
        // The error must not echo any strkey-shaped token (56-char base32 run,
        // the shape of S/G secret and account keys).
        let has_strkey_shaped_token = msg.split(|c: char| !c.is_ascii_alphanumeric()).any(|tok| {
            tok.len() == 56
                && tok
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
        });
        assert!(
            !has_strkey_shaped_token,
            "error must not contain a strkey-shaped token: {msg}"
        );
        // Message length is bounded — not a huge data dump.
        assert!(
            msg.len() < 512,
            "error message unexpectedly long ({} chars): {msg}",
            msg.len()
        );
    }
}

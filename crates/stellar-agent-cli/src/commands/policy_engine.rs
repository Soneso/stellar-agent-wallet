//! Shared V1 policy-engine builder for value-moving CLI verbs.
//!
//! # What this module does
//!
//! Provides [`build_v1_policy_engine`]: a single fail-closed builder for
//! `PolicyEngineV1` (or `NoopPolicyEngine`) shared by the `lend`, `vault`,
//! `trade`, `bridge`, and `trustline` CLI subcommands, as well as `pay`,
//! `claim`, and `accounts create` (sponsored mode).
//!
//! Also provides [`load_profile_or_synthesize_testnet`] (the zero-config
//! profile resolution `pay`/`claim`/`accounts create` use instead of a hard
//! `--profile` requirement), [`caip2_chain_id_for_network`] (chain-id
//! derivation for verbs that select their network via `--network` rather than
//! a profile's `chain_id`), and [`evaluate_value_moving_policy`] (the shared
//! `PolicyEngine::evaluate` call plus refusal-envelope construction).
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
//!
//! # Owner PUBLIC key source (production vs. test)
//!
//! [`build_v1_policy_engine`] resolves the owner **PUBLIC** key through
//! [`owner_pubkey_b64`], which reads it from the OS keyring in production. A
//! test-only file source, gated behind `#[cfg(any(test, feature =
//! "test-helpers"))]` and armed only when `STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE`
//! is set, exists solely so a subprocess testnet-acceptance test can supply the
//! owner public key without touching the OS keyring. There is no file-based
//! owner **seed**/secret-key source anywhere in this codebase.

use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::{
    Decision, McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor, ToolValueKind,
};
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile, default_policy_dir};

use crate::common::network::TargetNetwork;

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

            // Resolve the owner PUBLIC key (base64 URL-safe-no-pad), either from the
            // OS keyring (production) or from a gated test-only file source.
            let raw_key = owner_pubkey_b64(&profile_name, verb)?;

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

/// Resolves the operator's owner **PUBLIC** key (base64 URL-safe-no-pad,
/// untrimmed) for `profile_name`, for `PolicyEngineV1`'s owner-signature
/// verification step only.
///
/// This function supplies a PUBLIC key exclusively. It is used solely to
/// verify the operator's ed25519 signature over the policy document; there is
/// no file-based owner **seed**/secret-key source anywhere in this codebase,
/// and there must never be one — owner seeds are only ever read from the OS
/// keyring (`enroll-owner-key`) or a `--secret-env` variable at signing time
/// (`profile sign-policy`), never from a caller-supplied file path at
/// verification time.
///
/// # Test-only file override
///
/// When the environment variable `STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE` is
/// set, the owner public key is read from the file at that path instead of
/// the OS keyring. This branch is gated behind
/// `#[cfg(any(test, feature = "test-helpers"))]`: production release builds
/// never compile this branch, so `STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE` has no
/// effect in a released binary — this closes the env-injection
/// owner-key-swap surface for the policy-signature verification path. Absent
/// the env var (or outside a test/`test-helpers` build), this function reads
/// the owner public key from the OS keyring exactly as production always has.
///
/// # Errors
///
/// Returns `Err(human-readable message)` — naming `verb` and carrying no
/// secret material — when the file (test-only path) or keyring (production
/// path) cannot be read.
fn owner_pubkey_b64(profile_name: &str, verb: &str) -> Result<String, String> {
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(path) = std::env::var_os("STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE") {
        let path = std::path::PathBuf::from(path);
        return std::fs::read_to_string(&path)
            .map(|s| s.trim().to_owned())
            .map_err(|e| {
                format!(
                    "policy.engine is 'v1' but the test-only owner_pubkey file at {} could not \
                     be read ({e}); {verb} refuses (fail-closed)",
                    path.display()
                )
            });
    }

    use keyring_core::Entry as KeyringEntry;

    let entry_ref =
        stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key(profile_name);
    KeyringEntry::new(&entry_ref.service, &entry_ref.account)
        .and_then(|e| e.get_password())
        .map_err(|e| {
            format!(
                "policy.engine is 'v1' but the owner key for profile '{profile_name}' could not \
                 be read from the keyring ({e}); {verb} refuses (fail-closed)"
            )
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Zero-config profile resolution for the value-moving classic verbs
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the named profile, falling back to an in-memory `Noop`-engine
/// testnet profile when no `<name>.toml` file exists.
///
/// `pay`, `claim`, and `accounts create` operate against testnet without
/// requiring an authored profile file (see the "Set up a profile" section of
/// the getting-started guide). This preserves that zero-config invariant: the
/// permissive fallback fires ONLY on [`profile_loader::ProfileLoadError::NotFound`],
/// and is forced to [`PolicyEngineKind::Noop`] regardless of
/// [`Profile::builder_testnet`]'s own default (`V1`), so an unauthored profile
/// never triggers an owner-key/policy-file requirement the operator never
/// opted into. Once an operator persists a real profile — `V1` or `Noop` — that
/// file's configured engine governs instead.
///
/// # Errors
///
/// Returns `Err(message)` for any profile-load failure OTHER than `NotFound`
/// (a malformed TOML file, an unsupported schema version, etc.) — those are
/// genuine configuration errors the synthesis fallback must not mask.
pub(crate) fn load_profile_or_synthesize_testnet(name: &str) -> Result<Profile, String> {
    match profile_loader::load(name, None) {
        Ok(p) => Ok(p),
        Err(profile_loader::ProfileLoadError::NotFound { .. }) => {
            Ok(Profile::builder_testnet_named(
                name,
                "stellar-agent-signer",
                name,
                "stellar-agent-nonce",
                name,
            )
            .policy_engine(PolicyEngineKind::Noop)
            .build())
        }
        Err(e) => Err(format!("profile '{name}' failed to load: {e}")),
    }
}

/// Maps a CLI [`TargetNetwork`] selector to its CAIP-2 chain-id string.
///
/// `pay`, `claim`, and `accounts create` select their target network via
/// `--network` rather than a loaded profile's `chain_id` (unlike `trade` /
/// `lend` / `vault` / `trustline`, which trust `profile.chain_id`
/// exclusively). The policy gate's `ToolDescriptor::chain_id` must reflect the
/// network the transaction actually targets, so it is derived here instead of
/// from the (possibly synthesized, possibly mismatched) profile object.
#[must_use]
pub(crate) fn caip2_chain_id_for_network(network: TargetNetwork) -> &'static str {
    // Binding: these are the CAIP-2 chain identifiers and MUST stay
    // byte-identical to `Caip2::caip2_str` (profile/caip2.rs:108), the
    // authoritative source `profile.chain_id` resolves through. A drift here
    // would silently stop chain-scoped policy rules from matching the value the
    // MCP twin evaluates against.
    match network {
        TargetNetwork::Testnet => "stellar:testnet",
        TargetNetwork::Mainnet => "stellar:mainnet",
    }
}

/// Builds the `stellar_pay` policy args the dispatch gate derives the value
/// descriptor from.
///
/// Single source of truth shared by the `pay` verb call site and its parity
/// tests, byte-identical to the `stellar_pay` MCP twin's dispatch args: the
/// resolved amount as a decimal stroop string, the raw (unreformatted)
/// caller-supplied asset string (`derive_value_class` normalises it), and the
/// destination.
#[must_use]
pub(crate) fn pay_policy_args(
    amount_stroops: i64,
    asset_raw: &str,
    destination: &str,
) -> serde_json::Value {
    serde_json::json!({
        "amount_stroops": amount_stroops.to_string(),
        "asset": asset_raw,
        "destination": destination,
    })
}

/// Builds the `stellar_create_account` policy args for sponsored `create`.
///
/// `derive_value_class` forces the asset to native for account creation, so
/// only the resolved starting balance (decimal stroop string) and the
/// destination are supplied. Shared by the verb call site and its parity tests.
#[must_use]
pub(crate) fn create_policy_args(
    starting_balance_stroops: i64,
    destination: &str,
) -> serde_json::Value {
    serde_json::json!({
        "starting_balance_stroops": starting_balance_stroops.to_string(),
        "destination": destination,
    })
}

/// Builds the `stellar_claim` policy args.
///
/// `derive_value_class` ignores the args for `stellar_claim` (a claim is always
/// a non-debit `Claim` leg); the balance id is carried for audit parity with
/// the MCP twin. Shared by the verb call site and its parity tests.
#[must_use]
pub(crate) fn claim_policy_args(balance_id: &str) -> serde_json::Value {
    serde_json::json!({ "balance_id": balance_id })
}

/// Builds the `stellar_trustline` / `stellar_trustline_commit` policy args.
///
/// `derive_value_class` reads only the `asset` field for the trustline arm
/// (a `Trustline` leg carries no debit); `from` is carried for audit parity
/// with the MCP `stellar_trustline` twin's dispatch args, which supplies
/// `{chain_id, from, asset}` (`chain_id` is applied separately via
/// [`ToolDescriptor::chain_id`](stellar_agent_core::policy::ToolDescriptor),
/// so it is not duplicated here). Shared by the `trustline` CLI verb call
/// site and its parity tests.
#[must_use]
pub(crate) fn trustline_policy_args(from: &str, asset: &str) -> serde_json::Value {
    serde_json::json!({ "from": from, "asset": asset })
}

/// Evaluates operator policy for a value-moving classic verb (`pay`, `claim`,
/// `accounts create`) through the same [`PolicyEngine::evaluate`] path the
/// DeFi verbs (`trade`, `lend`, `vault`, `trustline`) already use.
///
/// Constructs the [`ToolDescriptor`] from `tool_name` / `value_kind` /
/// `chain_id`, then evaluates `policy_args` against `profile`. Returns
/// `Ok(())` on [`Decision::Allow`]; returns `Err(envelope)` — a fully-rendered
/// refusal envelope — for every other outcome, mirroring the `trade` /
/// `lend` / `vault` / `trustline` refusal-message shapes verbatim so a
/// V1-engine deny produces the identical wire code the MCP twin returns for
/// the same rule.
///
/// Callers render the envelope with their own `print_error` (JSON vs table)
/// and exit `1`.
///
/// # Errors
///
/// Returns `Err(envelope)` on `Decision::Deny`, `Decision::RequireApproval`,
/// an unexpected `Decision` variant, or a policy-engine evaluation error.
pub(crate) fn evaluate_value_moving_policy(
    policy_engine: &dyn PolicyEngine,
    profile: &Profile,
    tool_name: &'static str,
    value_kind: ToolValueKind,
    chain_id: &str,
    policy_args: &serde_json::Value,
    verb: &str,
) -> Result<(), Envelope<()>> {
    let reg = McpToolRegistration {
        name: tool_name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind,
    };
    let mut tool_descriptor = ToolDescriptor::from_registration(&reg);
    tool_descriptor.chain_id = chain_id.to_owned();

    match policy_engine.evaluate(
        &tool_descriptor,
        policy_args,
        profile,
        None,
        None,
        None,
        None,
        None,
    ) {
        Ok(Decision::Allow) => Ok(()),
        Ok(Decision::Deny(reason)) => Err(Envelope::<()>::err_raw(
            format!("policy.deny.{}", reason.code()),
            format!("{verb} operation denied by operator policy"),
        )),
        Ok(Decision::RequireApproval(_)) => Err(Envelope::<()>::err_raw(
            "policy.approval_required",
            format!(
                "{verb} operation requires approval; use the MCP server for two-phase approval"
            ),
        )),
        Ok(_) => Err(Envelope::<()>::err_raw(
            "policy.unexpected_decision",
            "unexpected policy decision — operation refused (fail-closed)".to_owned(),
        )),
        Err(e) => Err(Envelope::<()>::err_raw(
            "policy.engine_required",
            format!("{e}"),
        )),
    }
}

/// Evaluates operator policy for a value-moving DeFi verb (`trade`, `lend`,
/// `vault`) whose effect cannot be derived from pre-decode args alone —
/// mirroring the MCP DeFi tools' `WalletServer::dispatch_gate_with_value`
/// mechanism.
///
/// Constructs the same [`ToolDescriptor`] shape as
/// [`evaluate_value_moving_policy`] (`McpToolRegistration` with
/// `value_kind: ToolValueKind::MovesValue`, `ToolDescriptor::from_registration`,
/// `chain_id` set), but evaluates via
/// [`PolicyEngine::evaluate_with_value`] with the caller-supplied
/// `value_class` — the same value descriptor the CLI verb builds from the
/// SAME parsed requirements it signs (single-decode invariant) — instead of
/// [`PolicyEngine::evaluate`]'s args-derived descriptor. Returns `Ok(())` on
/// [`Decision::Allow`]; returns `Err(envelope)` for every other outcome,
/// mirroring the `evaluate_value_moving_policy` refusal-message shapes
/// verbatim so a V1-engine deny produces the identical wire code the MCP
/// twin returns for the same rule.
///
/// Callers render the envelope with their own `print_error` (JSON vs table)
/// and exit `1`.
///
/// # Errors
///
/// Returns `Err(envelope)` on `Decision::Deny`, `Decision::RequireApproval`,
/// an unexpected `Decision` variant, or a policy-engine evaluation error.
pub(crate) fn evaluate_value_moving_policy_with_value(
    policy_engine: &dyn PolicyEngine,
    profile: &Profile,
    tool_name: &'static str,
    chain_id: &str,
    policy_args: &serde_json::Value,
    value_class: stellar_agent_core::policy::v1::ValueClass,
    verb: &str,
) -> Result<(), Envelope<()>> {
    let reg = McpToolRegistration {
        name: tool_name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    };
    let mut tool_descriptor = ToolDescriptor::from_registration(&reg);
    tool_descriptor.chain_id = chain_id.to_owned();

    match policy_engine.evaluate_with_value(
        &tool_descriptor,
        policy_args,
        profile,
        value_class,
        None,
        None,
        None,
        None,
        None,
    ) {
        Ok(Decision::Allow) => Ok(()),
        Ok(Decision::Deny(reason)) => Err(Envelope::<()>::err_raw(
            format!("policy.deny.{}", reason.code()),
            format!("{verb} operation denied by operator policy"),
        )),
        Ok(Decision::RequireApproval(_)) => Err(Envelope::<()>::err_raw(
            "policy.approval_required",
            format!(
                "{verb} operation requires approval; use the MCP server for two-phase approval"
            ),
        )),
        Ok(_) => Err(Envelope::<()>::err_raw(
            "policy.unexpected_decision",
            "unexpected policy decision — operation refused (fail-closed)".to_owned(),
        )),
        Err(e) => Err(Envelope::<()>::err_raw(
            "policy.engine_required",
            format!("{e}"),
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
    ///
    /// `#[serial]`: `build_v1_policy_engine` -> `owner_pubkey_b64` reads the
    /// process-global `STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE` env var when set;
    /// serialising avoids a race against the hazard tests below that set it.
    #[test]
    #[serial_test::serial]
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

    // ── CLI-verb / MCP-twin parity (issue #19) ───────────────────────────────
    //
    // These tests drive `evaluate_value_moving_policy` directly against a
    // `PolicyEngineV1` built from a literal `PolicyDocument` (the same
    // construction convention as
    // `stellar-agent-core/tests/policy_descriptor_equivalence.rs`'s
    // `engine_derives_descriptor_and_denies_over_cap_pay`), rather than through
    // `build_v1_policy_engine`'s keyring/file-backed loader. The `policy_args`
    // literals below MUST stay byte-for-byte in sync with the shapes built by
    // `crate::commands::pay::evaluate_pay_policy`,
    // `crate::commands::claim::evaluate_claim_policy`, and
    // `crate::commands::accounts::create::evaluate_create_policy` — that
    // identity is exactly what proves the CLI verb gates like its MCP twin.

    use stellar_agent_core::policy::DenyReason;
    use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};

    const PARITY_DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

    fn parity_profile() -> stellar_agent_core::profile::schema::Profile {
        // The engine's scope resolution uses the `profile_name` bound at
        // `PolicyEngineV1::new` construction, not any field read off this
        // `Profile` value — any structurally-valid profile works here.
        Profile::builder_testnet(
            "stellar-agent-signer",
            "alice",
            "stellar-agent-nonce",
            "alice",
        )
        .build()
    }

    fn per_tx_cap_engine(tool: &str, max_stroops: i64) -> PolicyEngineV1 {
        let rule = PolicyRule {
            r#match: RuleMatch {
                tool: tool.to_owned(),
                chain: "*".to_owned(),
            },
            criteria: vec![Box::new(PerTxCapCriterion::new(
                "native".to_owned(),
                i128::from(max_stroops),
            ))],
            decision: Decision::Allow,
            allow_opaque_signing: false,
        };
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![rule],
            signature: None,
        };
        PolicyEngineV1::new(doc, "alice".to_owned())
    }

    fn envelope_code(result: &Result<(), Envelope<()>>) -> &str {
        result
            .as_ref()
            .expect_err("expected a refusal envelope")
            .error
            .as_ref()
            .expect("refusal envelope must carry an error block")
            .code
            .as_str()
    }

    #[test]
    fn pay_gate_under_cap_allows() {
        let engine = per_tx_cap_engine("stellar_pay", 1_000_000_000); // 100 XLM cap
        let profile = parity_profile();
        // Mirrors `crate::commands::pay::evaluate_pay_policy`'s policy_args shape.
        let policy_args = pay_policy_args(500_000_000, "native", PARITY_DEST_G);
        let result = evaluate_value_moving_policy(
            &engine,
            &profile,
            "stellar_pay",
            ToolValueKind::MovesValue,
            "stellar:testnet",
            &policy_args,
            "pay",
        );
        assert!(result.is_ok(), "50 XLM under a 100 XLM cap must allow");
    }

    #[test]
    fn pay_gate_over_cap_denies_with_mcp_wire_code() {
        let engine = per_tx_cap_engine("stellar_pay", 1_000_000_000); // 100 XLM cap
        let profile = parity_profile();
        let policy_args = pay_policy_args(1_500_000_000, "native", PARITY_DEST_G);
        let result = evaluate_value_moving_policy(
            &engine,
            &profile,
            "stellar_pay",
            ToolValueKind::MovesValue,
            "stellar:testnet",
            &policy_args,
            "pay",
        );
        assert_eq!(
            envelope_code(&result),
            "policy.deny.per_tx_cap_exceeded",
            "150 XLM over a 100 XLM cap must deny with the same wire code the MCP \
             `stellar_pay` twin returns for the identical rule"
        );
    }

    #[test]
    fn create_gate_under_cap_allows() {
        let engine = per_tx_cap_engine("stellar_create_account", 1_000_000_000); // 100 XLM cap
        let profile = parity_profile();
        // Mirrors `crate::commands::accounts::create::evaluate_create_policy`'s
        // policy_args shape.
        let policy_args = create_policy_args(500_000_000, PARITY_DEST_G);
        let result = evaluate_value_moving_policy(
            &engine,
            &profile,
            "stellar_create_account",
            ToolValueKind::MovesValue,
            "stellar:testnet",
            &policy_args,
            "accounts_create",
        );
        assert!(
            result.is_ok(),
            "50 XLM starting balance under a 100 XLM cap must allow"
        );
    }

    #[test]
    fn create_gate_over_cap_denies_with_mcp_wire_code() {
        let engine = per_tx_cap_engine("stellar_create_account", 1_000_000_000); // 100 XLM cap
        let profile = parity_profile();
        let policy_args = create_policy_args(1_500_000_000, PARITY_DEST_G);
        let result = evaluate_value_moving_policy(
            &engine,
            &profile,
            "stellar_create_account",
            ToolValueKind::MovesValue,
            "stellar:testnet",
            &policy_args,
            "accounts_create",
        );
        assert_eq!(
            envelope_code(&result),
            "policy.deny.per_tx_cap_exceeded",
            "150 XLM starting balance over a 100 XLM cap must deny with the same wire \
             code the MCP `stellar_create_account` twin returns for the identical rule"
        );
    }

    #[test]
    fn claim_gate_per_tx_cap_not_applicable_allows() {
        // stellar_claim derives a non-debit Claim leg (`derive_value_class`), so
        // a per_tx_cap rule never matches it — parity with the MCP twin, which
        // is equally not-applicable for the same reason.
        let engine = per_tx_cap_engine("stellar_claim", 1_000_000_000);
        let profile = parity_profile();
        // Mirrors `crate::commands::claim::evaluate_claim_policy`'s policy_args
        // shape.
        let policy_args = claim_policy_args(&"0".repeat(72));
        let result = evaluate_value_moving_policy(
            &engine,
            &profile,
            "stellar_claim",
            ToolValueKind::MovesValue,
            "stellar:testnet",
            &policy_args,
            "claim",
        );
        assert!(
            result.is_ok(),
            "a per_tx_cap rule must not apply to a non-debit claim leg"
        );
    }

    #[test]
    fn claim_gate_explicit_deny_rule_denies_with_wire_code() {
        // Proves the claim verb is genuinely wired to the engine: an explicit
        // deny-decision rule matching `stellar_claim` (no criteria — an
        // unconditional deny) must refuse the CLI call with that rule's wire
        // code, exactly as it would refuse the MCP `stellar_claim` twin.
        let rule = PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_claim".to_owned(),
                chain: "*".to_owned(),
            },
            criteria: vec![],
            decision: Decision::Deny(DenyReason::RateLimitExceeded {
                window: "rolling_1h".to_owned(),
                max_calls: 0,
                calls_in_window: 1,
            }),
            allow_opaque_signing: false,
        };
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![rule],
            signature: None,
        };
        let engine = PolicyEngineV1::new(doc, "alice".to_owned());
        let profile = parity_profile();
        let policy_args = claim_policy_args(&"0".repeat(72));
        let result = evaluate_value_moving_policy(
            &engine,
            &profile,
            "stellar_claim",
            ToolValueKind::MovesValue,
            "stellar:testnet",
            &policy_args,
            "claim",
        );
        assert_eq!(
            envelope_code(&result),
            "policy.deny.rate_limit_exceeded",
            "an explicit deny rule matching stellar_claim must refuse with its wire code"
        );
    }

    // ── evaluate_value_moving_policy_with_value: single-shot DeFi verb parity ──
    //
    // These tests drive `evaluate_value_moving_policy_with_value` against a
    // synthetic `stellar_dex_trade`-shaped rule, mirroring the pattern above
    // but through the `evaluate_with_value` path (typed `ValueClass` supplied
    // directly rather than derived from `args`), the mechanism the `trade` /
    // `lend` / `vault` CLI verbs now share with their MCP twins.

    use stellar_agent_core::policy::v1::{ActionKind, ValueClass, ValueLeg};

    fn dex_trade_leg(amount: i128) -> ValueClass {
        ValueClass::single(ValueLeg {
            kind: ActionKind::DexTrade,
            amount: Some(amount),
            asset: Some("native".to_owned()),
            destination: Some(PARITY_DEST_G.to_owned()),
        })
    }

    #[test]
    fn with_value_gate_under_cap_allows() {
        let engine = per_tx_cap_engine("stellar_dex_trade", 1_000_000_000); // 100 XLM cap
        let profile = parity_profile();
        let policy_args = serde_json::json!({ "from_address": PARITY_DEST_G });
        let result = evaluate_value_moving_policy_with_value(
            &engine,
            &profile,
            "stellar_dex_trade",
            "stellar:testnet",
            &policy_args,
            dex_trade_leg(500_000_000),
            "trade",
        );
        assert!(result.is_ok(), "50 XLM under a 100 XLM cap must allow");
    }

    #[test]
    fn with_value_gate_over_cap_denies_with_mcp_wire_code() {
        let engine = per_tx_cap_engine("stellar_dex_trade", 1_000_000_000); // 100 XLM cap
        let profile = parity_profile();
        let policy_args = serde_json::json!({ "from_address": PARITY_DEST_G });
        let result = evaluate_value_moving_policy_with_value(
            &engine,
            &profile,
            "stellar_dex_trade",
            "stellar:testnet",
            &policy_args,
            dex_trade_leg(1_500_000_000),
            "trade",
        );
        assert_eq!(
            envelope_code(&result),
            "policy.deny.per_tx_cap_exceeded",
            "150 XLM over a 100 XLM cap must deny with the same wire code the MCP \
             `stellar_dex_trade` twin returns for the identical rule"
        );
    }

    // ── trustline_policy_args: field-shape parity with the MCP twin ──────────

    #[test]
    fn trustline_policy_args_carries_from_and_asset_only() {
        let value = trustline_policy_args(PARITY_DEST_G, "USDC");
        assert_eq!(value["from"], PARITY_DEST_G);
        assert_eq!(value["asset"], "USDC");
        assert!(
            value.get("chain_id").is_none(),
            "chain_id is applied via ToolDescriptor::chain_id, not duplicated in policy_args"
        );
    }

    // ── Decision-1 hazard: fail-closed on corruption ─────────────────────────
    //
    // `load_profile_or_synthesize_testnet` must synthesize the permissive
    // `Noop` engine ONLY on `ProfileLoadError::NotFound`. A malformed profile
    // file, or a policy file with a forged/corrupted signature, must refuse
    // (`Err`) rather than silently falling through to an allow-everything
    // engine. These tests use the `STELLAR_AGENT_HOME` env-var override
    // (`stellar-agent-core`'s `default_profile_dir` / `default_policy_dir`,
    // active here via that crate's `test-helpers` dev-dependency feature) to
    // isolate `default_profile_dir` / `default_policy_dir` in a tempdir, and
    // the `STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE` override on
    // `owner_pubkey_b64` (active here via this crate's own `#[cfg(test)]`) to
    // supply the owner public key without touching the OS keyring.

    /// RAII guard for an arbitrary env var, mirroring
    /// `crate::commands::profile::sign_policy`'s test-only `EnvGuard`.
    struct TestEnvVarGuard {
        var: &'static str,
    }
    impl TestEnvVarGuard {
        fn set(var: &'static str, value: &std::ffi::OsStr) -> Self {
            #[allow(
                unsafe_code,
                reason = "test-only env mutation; serialised by #[serial]"
            )]
            // SAFETY: serialised by the caller's `#[serial]`; restored on Drop.
            unsafe {
                std::env::set_var(var, value);
            }
            Self { var }
        }
    }
    impl Drop for TestEnvVarGuard {
        fn drop(&mut self) {
            #[allow(unsafe_code, reason = "test-only env cleanup")]
            // SAFETY: same as `set`; serialised by the caller's `#[serial]`.
            unsafe {
                std::env::remove_var(self.var);
            }
        }
    }

    /// Writes a minimal, valid v2 profile TOML for `name` with
    /// `policy.engine = "v1"` into `<home>/profiles/<name>.toml`.
    fn write_v1_profile_toml(home: &std::path::Path, name: &str) {
        let dir = home.join("profiles");
        std::fs::create_dir_all(&dir).expect("create profiles dir");
        let toml = format!(
            "version = 2\n\
             chain_id = \"stellar:testnet\"\n\n\
             [mcp_signer_default]\n\
             service = \"stellar-agent-signer\"\n\
             account = \"default\"\n\n\
             [mcp_nonce_key_alias]\n\
             service = \"stellar-agent-nonce\"\n\
             account = \"default\"\n\n\
             [audit_log_hash_chain_key_id]\n\
             service = \"stellar-agent-audit-{name}\"\n\
             account = \"default\"\n\n\
             [policy_owner_key_id]\n\
             service = \"{OWNER_KEY_SERVICE_PREFIX}{name}\"\n\
             account = \"default\"\n\n\
             [attestation_key_id]\n\
             service = \"stellar-agent-attestation-{name}\"\n\
             account = \"default\"\n\n\
             [counterparty_cache_key_id]\n\
             service = \"stellar-agent-counterparty-{name}\"\n\
             account = \"default\"\n\n\
             [policy]\n\
             engine = \"v1\"\n"
        );
        std::fs::write(dir.join(format!("{name}.toml")), toml).expect("write profile toml");
    }

    /// A malformed profile TOML file must return `Err` from
    /// `load_profile_or_synthesize_testnet` — NOT the permissive `Noop`
    /// synthesis, which is reserved for the file-absent case only.
    #[test]
    #[serial_test::serial]
    fn malformed_profile_toml_returns_err_not_noop_synthesis() {
        let home = tempfile::TempDir::new().expect("tempdir");
        let profiles_dir = home.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).expect("create profiles dir");
        std::fs::write(
            profiles_dir.join("malformed-hazard.toml"),
            "this is not { valid toml [[[",
        )
        .expect("write malformed profile");

        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());

        let result = load_profile_or_synthesize_testnet("malformed-hazard");
        assert!(
            result.is_err(),
            "a malformed profile TOML must return Err, not synthesize Noop"
        );
    }

    /// A v1 profile whose policy file carries a signature that does not
    /// verify under the enrolled owner key (forged/corrupted) must refuse via
    /// `Err` from `build_v1_policy_engine` — the engine must not silently
    /// disable enforcement on a corrupted root-of-trust document.
    #[test]
    #[serial_test::serial]
    fn build_v1_policy_engine_forged_signature_fails_closed() {
        use base64::Engine as _;
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let home = tempfile::TempDir::new().expect("tempdir");
        let name = "forged-hazard";
        write_v1_profile_toml(home.path(), name);

        // The enrolled (correct) owner keypair — its PUBLIC key is what
        // `build_v1_policy_engine` verifies against via the gated
        // owner_pubkey file source below.
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes();

        // A DIFFERENT keypair, used only to forge a signature that must NOT
        // verify under `owner_pk`.
        let attacker_sk = SigningKey::generate(&mut OsRng);

        let policy_body = format!(
            "version = 1\nscope = \"profile:{name}\"\n\n[[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"*\" }}\ncriteria = []\ndecision = \"allow\"\n"
        );
        let canon = stellar_agent_core::policy::v1::canonical::canonical_bytes(&policy_body)
            .expect("canonical_bytes");
        let policy_digest = stellar_agent_core::policy::v1::signature::digest(&canon);
        let forged_sig =
            stellar_agent_core::policy::v1::signature::sign(&policy_digest, &attacker_sk);
        let sig_hex: String = forged_sig.iter().map(|b| format!("{b:02x}")).collect();
        let owner_g = stellar_strkey::ed25519::PublicKey(owner_pk)
            .to_string()
            .to_string();
        let signed_policy =
            format!("{policy_body}\n[signature]\nowner_id = \"{owner_g}\"\nsig = \"{sig_hex}\"\n");

        let policies_dir = home.path().join("policies");
        std::fs::create_dir_all(&policies_dir).expect("create policies dir");
        std::fs::write(policies_dir.join(format!("{name}.toml")), signed_policy)
            .expect("write policy toml");

        let pubkey_file = home.path().join("owner_pubkey.txt");
        std::fs::write(
            &pubkey_file,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(owner_pk),
        )
        .expect("write owner pubkey file");

        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _pubkey_guard = TestEnvVarGuard::set(
            "STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE",
            pubkey_file.as_os_str(),
        );

        let profile = load_profile_or_synthesize_testnet(name).expect("v1 profile file must load");
        let result = build_v1_policy_engine("pay", &profile.policy.engine, &profile);
        assert!(
            result.is_err(),
            "a forged/corrupted policy signature must fail closed, not silently disable \
             enforcement"
        );
    }
}
